//! A deliberately bounded SHOW GRANTS recipe, read from the server's ACL
//! representation rather than potentially unflushed mysql.* grant-table rows.
//! It proves absence of a named table action, not account/object incarnation.
use super::{MysqlRole, mysql_account_host, mysql_db_user};
use crate::core::policy::SqlAction;
use mysql_async::{Transaction, prelude::Queryable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ACCOUNTS: usize = 32;
const MAX_ROWS: usize = 128;
const MAX_BYTES: usize = 16 * 1024;
pub(super) const ENV_SQL: &str = "SELECT @@skip_grant_tables, @@mandatory_roles, @@partial_revokes";
pub(super) const CURRENT_GRANTS_SQL: &str = "SHOW GRANTS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    scope: InventoryScope,
    environment_before: Environment,
    before: Vec<AccountGrants>,
    after: Vec<AccountGrants>,
    environment_after: Environment,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InventoryScope {
    NamedAclFreshConnections,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    skip_grant_tables: bool,
    mandatory_roles: String,
    partial_revokes: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountGrants {
    account: MysqlRole,
    statements: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Name(String),
    Star,
    Dot,
    Comma,
    At,
    Open,
    Close,
}
#[derive(Debug, Clone)]
enum Grant {
    Roles(Vec<MysqlRole>),
    Privilege {
        database: Option<String>,
        table: Option<String>,
        actions: Vec<String>,
    },
}

fn tokens(s: &str) -> Option<Vec<Token>> {
    if s.is_empty() || s.len() > MAX_BYTES || !s.is_ascii() {
        return None;
    }
    let mut b = s.bytes().peekable();
    let mut out = Vec::new();
    while let Some(c) = b.next() {
        let t = match c {
            b' ' => continue,
            b'*' => Token::Star,
            b'.' => Token::Dot,
            b',' => Token::Comma,
            b'@' => Token::At,
            b'(' => Token::Open,
            b')' => Token::Close,
            b'`' => {
                let mut name = String::new();
                loop {
                    match b.next()? {
                        b'`' => break,
                        c if c.is_ascii_alphanumeric() || b"_$%:.\\-".contains(&c) => {
                            name.push(char::from(c))
                        }
                        _ => return None,
                    }
                }
                if name.is_empty() || name.len() > 255 {
                    return None;
                }
                Token::Name(name)
            }
            c if c.is_ascii_uppercase() || c == b'_' => {
                let mut word = String::from(char::from(c));
                while b
                    .peek()
                    .is_some_and(|v| v.is_ascii_uppercase() || *v == b'_')
                {
                    word.push(char::from(b.next()?));
                }
                Token::Word(word)
            }
            _ => return None,
        };
        out.push(t);
        if out.len() > 2048 {
            return None;
        }
    }
    Some(out)
}
fn account(t: &[Token]) -> Option<MysqlRole> {
    let [Token::Name(user), Token::At, Token::Name(host)] = t else {
        return None;
    };
    (mysql_db_user(user) && mysql_account_host(host)).then(|| MysqlRole {
        user: user.clone(),
        host: host.clone(),
    })
}
fn parse(s: &str, expected: &MysqlRole) -> Option<Grant> {
    let t = tokens(s)?;
    let [Token::Word(first), rest @ ..] = t.as_slice() else {
        return None;
    };
    if first != "GRANT" {
        return None;
    }
    let to = rest.iter().position(|t| *t == Token::Word("TO".into()))?;
    if account(&rest[to + 1..])?.ne(expected) {
        return None;
    }
    let body = &rest[..to];
    if matches!(body.first(), Some(Token::Name(_))) {
        let mut roles = Vec::new();
        for role in body.split(|t| *t == Token::Comma) {
            roles.push(account(role)?);
        }
        return (!roles.is_empty()).then_some(Grant::Roles(roles));
    }
    let on = body.iter().position(|t| *t == Token::Word("ON".into()))?;
    let scope = &body[on + 1..];
    let (database, table) = match scope {
        [Token::Star, Token::Dot, Token::Star] => (None, None),
        [Token::Name(db), Token::Dot, Token::Star] => (Some(db.clone()), None),
        [Token::Name(db), Token::Dot, Token::Name(table)] => {
            (Some(db.clone()), Some(table.clone()))
        }
        _ => return None,
    };
    let mut actions = Vec::new();
    let mut at = 0;
    while at < on {
        let Token::Word(word) = &body[at] else {
            return None;
        };
        let mut word = word.clone();
        at += 1;
        if word == "SHOW" && body.get(at) == Some(&Token::Word("VIEW".into())) {
            word = "SHOW VIEW".into();
            at += 1;
        }
        // Unknown/dynamic/administrative privileges, PROXY, routines, grant
        // options and partial REVOKE syntax cannot establish this profile.
        if !matches!(
            word.as_str(),
            "USAGE"
                | "SELECT"
                | "INSERT"
                | "UPDATE"
                | "DELETE"
                | "REFERENCES"
                | "INDEX"
                | "SHOW VIEW"
        ) {
            return None;
        }
        if body.get(at) == Some(&Token::Open) {
            if table.is_none()
                || !matches!(word.as_str(), "SELECT" | "INSERT" | "UPDATE" | "REFERENCES")
            {
                return None;
            }
            at += 1;
            loop {
                if !matches!(body.get(at), Some(Token::Name(_))) {
                    return None;
                }
                at += 1;
                match body.get(at) {
                    Some(Token::Comma) => at += 1,
                    Some(Token::Close) => {
                        at += 1;
                        break;
                    }
                    _ => return None,
                }
            }
        }
        actions.push(word);
        if at < on {
            if body.get(at) != Some(&Token::Comma) || at + 1 == on {
                return None;
            }
            at += 1;
        }
    }
    if actions.is_empty()
        || (actions.iter().any(|a| a == "USAGE") && (actions.len() != 1 || database.is_some()))
    {
        return None;
    }
    Some(Grant::Privilege {
        database,
        table,
        actions,
    })
}

fn inspect(accounts: &[AccountGrants], root: &MysqlRole) -> Option<Vec<Grant>> {
    if accounts.is_empty() || accounts.len() > MAX_ACCOUNTS {
        return None;
    }
    let mut map = BTreeMap::new();
    let mut rows = 0;
    let mut bytes = 0;
    for a in accounts {
        if !mysql_db_user(&a.account.user)
            || !mysql_account_host(&a.account.host)
            || a.statements.is_empty()
            || map.insert(a.account.clone(), &a.statements).is_some()
        {
            return None;
        }
        rows += a.statements.len();
        bytes += a.statements.iter().map(String::len).sum::<usize>();
    }
    if rows > MAX_ROWS || bytes > MAX_BYTES {
        return None;
    }
    let mut wanted = BTreeSet::from([root.clone()]);
    let mut seen = BTreeSet::new();
    let mut grants = Vec::new();
    while let Some(next) = wanted.pop_first() {
        if !seen.insert(next.clone()) {
            continue;
        }
        for s in map.get(&next)?.iter() {
            let grant = parse(s, &next)?;
            if let Grant::Roles(roles) = &grant {
                for role in roles {
                    if !seen.contains(role) {
                        wanted.insert(role.clone());
                    }
                }
            }
            grants.push(grant);
        }
    }
    // Unreachable records cannot substitute for a missing reachable role.
    (seen.len() == map.len()).then_some(grants)
}

async fn environment(tx: &mut Transaction<'_>) -> Option<Environment> {
    let (skip_grant_tables, mandatory_roles, partial_revokes): (bool, String, bool) =
        tx.query_first(ENV_SQL).await.ok()??;
    (mandatory_roles.len() <= 4096 && !mandatory_roles.chars().any(char::is_control)).then_some(
        Environment {
            skip_grant_tables,
            mandatory_roles,
            partial_revokes,
        },
    )
}
async fn snapshot(tx: &mut Transaction<'_>, root: &MysqlRole) -> Option<Vec<AccountGrants>> {
    let mut wanted = BTreeSet::from([root.clone()]);
    let mut accounts = BTreeMap::new();
    let mut rows = 0;
    let mut bytes = 0;
    while let Some(next) = wanted.pop_first() {
        if accounts.contains_key(&next) {
            continue;
        }
        if accounts.len() >= MAX_ACCOUNTS {
            return None;
        }
        // Role names come only from strict SHOW GRANTS parsing. Their account
        // grammar excludes quotes, backticks, whitespace and statement syntax.
        let sql = if next == *root {
            CURRENT_GRANTS_SQL.into()
        } else {
            format!("SHOW GRANTS FOR `{}`@`{}`", next.user, next.host)
        };
        // SHOW GRANTS has no LIMIT clause. Read incrementally so a large
        // response cannot allocate an unbounded Vec before checking limits.
        let mut result = tx.query_iter(sql).await.ok()?;
        let mut statements = Vec::new();
        while let Some(row) = result.next().await.ok()? {
            let statement: String = mysql_async::from_row_opt(row).ok()?;
            rows += 1;
            bytes += statement.len();
            if rows > MAX_ROWS || bytes > MAX_BYTES {
                return None;
            }
            statements.push(statement);
        }
        result.drop_result().await.ok()?;
        if statements.is_empty() {
            return None;
        }
        for s in &statements {
            if let Grant::Roles(roles) = parse(s, &next)? {
                for role in roles {
                    if !accounts.contains_key(&role) {
                        wanted.insert(role);
                    }
                }
            }
        }
        statements.sort();
        accounts.insert(next, statements);
    }
    Some(
        accounts
            .into_iter()
            .map(|(account, statements)| AccountGrants {
                account,
                statements,
            })
            .collect(),
    )
}

pub(super) async fn capture(tx: &mut Transaction<'_>, root: &MysqlRole) -> Option<Inventory> {
    let environment_before = environment(tx).await?;
    if environment_before.skip_grant_tables || environment_before.partial_revokes {
        return None;
    }
    let before = snapshot(tx, root).await?;
    let after = snapshot(tx, root).await?;
    let environment_after = environment(tx).await?;
    Some(Inventory {
        scope: InventoryScope::NamedAclFreshConnections,
        environment_before,
        before,
        after,
        environment_after,
    })
}

/// None means unavailable/unsupported/inconsistent, never an empty inventory.
/// A wildcard database grant is a MySQL LIKE pattern when partial_revokes=OFF.
fn database_matches(pattern: &str, database: &str) -> bool {
    let (p, d) = (pattern.as_bytes(), database.as_bytes());
    let mut previous = vec![false; d.len() + 1];
    previous[0] = true;
    let mut at = 0;
    while at < p.len() {
        let mut next = vec![false; d.len() + 1];
        let mut c = p[at];
        let escaped = c == b'\\' && at + 1 < p.len();
        if escaped {
            at += 1;
            c = p[at];
        }
        for k in 0..=d.len() {
            next[k] = if c == b'%' && !escaped {
                previous[k] || (k > 0 && next[k - 1])
            } else {
                k > 0 && previous[k - 1] && ((c == b'_' && !escaped) || c == d[k - 1])
            };
        }
        previous = next;
        at += 1;
    }
    previous[d.len()]
}

impl Inventory {
    pub(super) fn valid(&self, root: &MysqlRole) -> bool {
        [&self.environment_before, &self.environment_after]
            .iter()
            .all(|e| {
                e.mandatory_roles.is_empty()
                    || (e.mandatory_roles.len() <= 4096 && super::safe(&e.mandatory_roles))
            })
            && inspect(&self.before, root).is_some()
            && inspect(&self.after, root).is_some()
    }
    pub(super) fn absent(
        &self,
        root: &MysqlRole,
        database: &str,
        table: &str,
        action: SqlAction,
        active_roles: &[MysqlRole],
    ) -> bool {
        if self.environment_before != self.environment_after
            || self.environment_before.skip_grant_tables
            || self.environment_before.partial_revokes
            || self.before != self.after
        {
            return false;
        }
        let Some(grants) = inspect(&self.before, root) else {
            return false;
        };
        if active_roles
            .iter()
            .any(|role| !self.before.iter().any(|a| a.account == *role))
        {
            return false;
        }
        let action = match action {
            SqlAction::Read => "SELECT",
            SqlAction::Insert => "INSERT",
            SqlAction::Update => "UPDATE",
            SqlAction::Delete => "DELETE",
            _ => return false,
        };
        !grants.iter().any(|g| matches!(g, Grant::Privilege { database: db, table: t, actions }
            if (actions.iter().any(|a| a == action)
                && db.as_deref().is_none_or(|p| if t.is_none() { database_matches(p, database) } else { p == database })
                && t.as_deref().is_none_or(|t| t == table))
                || (actions.iter().any(|a| matches!(a.as_str(), "INSERT" | "UPDATE" | "DELETE"))
                    && db.as_deref().is_none_or(|p| if t.is_none() { database_matches(p, "mysql") } else { p == "mysql" }))))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn account(user: &str) -> MysqlRole {
        MysqlRole {
            user: user.into(),
            host: "%".into(),
        }
    }
    pub(in crate::adapters::source::aws_mysql) fn sample() -> Inventory {
        let environment = Environment {
            skip_grant_tables: false,
            mandatory_roles: String::new(),
            partial_revokes: false,
        };
        let accounts = vec![
            AccountGrants {
                account: account("billing_app"),
                statements: vec![
                    "GRANT USAGE ON *.* TO `billing_app`@`%`".into(),
                    "GRANT INSERT ON `billing`.`invoices` TO `billing_app`@`%`".into(),
                    "GRANT `reader`@`%` TO `billing_app`@`%`".into(),
                ],
            },
            AccountGrants {
                account: account("reader"),
                statements: vec![
                    "GRANT USAGE ON *.* TO `reader`@`%`".into(),
                    "GRANT SELECT ON `billing`.`other` TO `reader`@`%`".into(),
                ],
            },
        ];
        Inventory {
            scope: InventoryScope::NamedAclFreshConnections,
            environment_before: environment.clone(),
            environment_after: environment,
            before: accounts.clone(),
            after: accounts,
        }
    }
    fn absent(i: &Inventory) -> bool {
        i.absent(
            &account("billing_app"),
            "billing",
            "invoices",
            SqlAction::Read,
            &[],
        )
    }
    #[test]
    fn complete_closure_includes_inactive_mandatory_transitive_roles_and_cycles() {
        let mut i = sample();
        assert!(i.valid(&account("billing_app")));
        assert!(absent(&i));
        i.before[1]
            .statements
            .push("GRANT `billing_app`@`%` TO `reader`@`%`".into());
        i.after = i.before.clone();
        assert!(absent(&i));
        i.environment_before.mandatory_roles = "`reader`@`%`".into();
        i.environment_after = i.environment_before.clone();
        assert!(absent(&i));
        i.before[1]
            .statements
            .push("GRANT SELECT ON `billing`.`invoices` TO `reader`@`%`".into());
        i.after = i.before.clone();
        // An inactive role can become active; absence cannot be asserted.
        assert!(!absent(&i));
    }
    #[test]
    fn every_static_scope_column_and_schema_pattern_blocks_false_absence() {
        for grant in [
            "GRANT SELECT ON *.* TO `reader`@`%`",
            "GRANT SELECT ON `bill%`.* TO `reader`@`%`",
            "GRANT SELECT ON `billin_`.* TO `reader`@`%`",
            "GRANT SELECT ON `billing`.`invoices` TO `reader`@`%`",
            "GRANT SELECT (`one`, `two`) ON `billing`.`invoices` TO `reader`@`%`",
            "GRANT UPDATE ON `mysql`.* TO `reader`@`%`",
        ] {
            let mut i = sample();
            i.before[1].statements.push(grant.into());
            i.after = i.before.clone();
            assert!(i.valid(&account("billing_app")), "{grant}");
            assert!(!absent(&i), "{grant}");
        }
        assert!(database_matches("bill%", "billing"));
        assert!(database_matches("billin_", "billing"));
        assert!(!database_matches("billin\\_", "billing"));
        assert!(database_matches("billing\\_prod", "billing_prod"));
        assert!(!database_matches("billing\\_prod", "billingXprod"));
        assert!(!database_matches("Billing", "billing"));
    }
    #[test]
    fn unsupported_or_malformed_acl_is_never_a_complete_empty_result() {
        for grant in [
            "GRANT ROLE_ADMIN ON *.* TO `reader`@`%`",
            "GRANT SUPER ON *.* TO `reader`@`%`",
            "GRANT ALL PRIVILEGES ON *.* TO `reader`@`%`",
            "GRANT PROXY ON `other`@`%` TO `reader`@`%`",
            "GRANT SELECT ON `billing`.`other` TO `reader`@`%` WITH GRANT OPTION",
            "GRANT `other`@`%` TO `reader`@`%` WITH ADMIN OPTION",
            "GRANT EXECUTE ON PROCEDURE `billing`.`writer` TO `reader`@`%`",
            "REVOKE SELECT ON `billing`.* FROM `reader`@`%`",
            "GRANT SELECT () ON `billing`.`other` TO `reader`@`%`",
            "GRANT SELECT, ON `billing`.`other` TO `reader`@`%`",
            "GRANT SELECT ON `billing`.`other` TO `wrong_host`@`%`",
            "GRANT SELECT ON `billing`.`other` TO `reader`@`%`; SELECT 1",
            "GRANT SELECT ON `billing`.`other` TO `reader`@`%` password=private",
        ] {
            let mut i = sample();
            i.before[1].statements.push(grant.into());
            i.after = i.before.clone();
            assert!(!i.valid(&account("billing_app")), "{grant}");
            assert!(!absent(&i), "{grant}");
        }
    }
    #[test]
    fn missing_duplicate_unreachable_overflow_or_changed_records_are_unknown() {
        for n in 0..11 {
            let mut i = sample();
            match n {
                0 => {
                    i.before.pop();
                }
                1 => i.before.push(i.before[1].clone()),
                2 => i.before.push(AccountGrants {
                    account: account("unreachable"),
                    statements: vec!["GRANT USAGE ON *.* TO `unreachable`@`%`".into()],
                }),
                3 => i.before[1].statements.clear(),
                4 => {
                    i.before[1].statements =
                        vec!["GRANT USAGE ON *.* TO `reader`@`%`".into(); MAX_ROWS + 1]
                }
                5 => i.environment_before.partial_revokes = true,
                6 => i.environment_before.skip_grant_tables = true,
                7 => i.environment_before.mandatory_roles = "`new_role`@`%`".into(),
                8 => i.after[1]
                    .statements
                    .push("GRANT SELECT ON *.* TO `reader`@`%`".into()),
                9 => i.before[1]
                    .statements
                    .push("GRANT `missing`@`%` TO `reader`@`%`".into()),
                _ => i.before[1]
                    .statements
                    .push("GRANT SELECT ON `billing`.`invoices` TO `reader`@`%`".into()),
            }
            if matches!(n, 0..=6 | 9 | 10) {
                i.after = i.before.clone();
                i.environment_after = i.environment_before.clone();
            }
            assert!(!absent(&i), "{n}");
            if matches!(n, 0..=4 | 9) {
                assert!(!i.valid(&account("billing_app")), "{n}");
            }
        }
        assert!(!sample().absent(
            &account("billing_app"),
            "billing",
            "invoices",
            SqlAction::Read,
            &[account("missing_active_role")]
        ));
        assert!(!sample().absent(
            &account("billing_app"),
            "billing",
            "invoices",
            SqlAction::Execute,
            &[]
        ));
    }
    #[test]
    fn account_and_byte_limits_and_unknown_inventory_scope_are_rejected() {
        let mut i = sample();
        i.before.clear();
        let roles = (0..MAX_ACCOUNTS)
            .map(|n| format!("`r{n}`@`%`"))
            .collect::<Vec<_>>()
            .join(",");
        i.before.push(AccountGrants {
            account: account("billing_app"),
            statements: vec![format!("GRANT {roles} TO `billing_app`@`%`")],
        });
        for n in 0..MAX_ACCOUNTS {
            i.before.push(AccountGrants {
                account: account(&format!("r{n}")),
                statements: vec![format!("GRANT USAGE ON *.* TO `r{n}`@`%`")],
            });
        }
        i.after = i.before.clone();
        assert!(!i.valid(&account("billing_app")));
        assert!(!absent(&i));
        let mut i = sample();
        i.before[0].statements.push("X".repeat(MAX_BYTES + 1));
        i.after = i.before.clone();
        assert!(!i.valid(&account("billing_app")));
        assert!(!absent(&i));
        let mut wire = serde_json::to_value(sample()).unwrap();
        wire["scope"] = "all_existing_sessions".into();
        assert!(serde_json::from_value::<Inventory>(wire).is_err());
    }
}
