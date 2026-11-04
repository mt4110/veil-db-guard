//! PG16.15-specific selected NOLOGIN failures and read-only role observations.
//! Raw server messages are inspected transiently and never enter evidence.
use crate::core::postgres_login::{
    LoginCatalogFact, LoginCatalogTarget, PostgresLoginFailure, PostgresLoginFailureKind,
};
use tokio_postgres::{Transaction, error::Severity};

/// PG16.15 performs authentication before InitializeSessionUserId checks
/// rolcanlogin. The fixed profile uses all fields together; a generic SQLSTATE,
/// translated message, proxy-rewritten error, or missing routine stays unknown.
pub(super) fn recognize(
    error: &tokio_postgres::Error,
    db_identity: &str,
) -> Option<PostgresLoginFailure> {
    if !crate::core::postgres_login::identity(db_identity) {
        return None;
    }
    let error = error.as_db_error()?;
    (error.parsed_severity() == Some(Severity::Fatal)
        && error.code().code() == "28000"
        && error.file() == Some("miscinit.c")
        && error.routine() == Some("InitializeSessionUserId")
        && error.message() == format!("role \"{db_identity}\" is not permitted to log in"))
    .then(|| PostgresLoginFailure {
        db_identity: db_identity.into(),
        kind: PostgresLoginFailureKind::AuthenticatedNoLoginV1,
    })
}

pub(super) const LOGIN_SQL: &str =
    "SELECT oid,rolname::text,rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$1::text LIMIT 2";

/// The caller supplies an existing read-only repeatable-read transaction and
/// request-authorized selectors. Missing roles produce no fact, never absence
/// or a synthesized role identity. The core must resolve every required target.
pub(super) async fn read_catalog(
    tx: &Transaction<'_>,
    targets: &[LoginCatalogTarget],
) -> Result<Vec<LoginCatalogFact>, tokio_postgres::Error> {
    let mut facts = vec![];
    // Request validation rejects more than eight targets. Keep native work
    // bounded even if a future caller accidentally bypasses that validation.
    for target in targets
        .iter()
        .take(crate::core::evidence::MAX_CASES_PER_SOURCE)
    {
        if let Some(row) = tx.query_opt(LOGIN_SQL, &[&target.db_identity]).await? {
            let role_oid: u32 = row.try_get(0)?;
            let role_name: String = row.try_get(1)?;
            let can_login: bool = row.try_get(2)?;
            if role_oid != 0 && role_name == target.db_identity {
                facts.push(LoginCatalogFact {
                    target: target.clone(),
                    role_oid,
                    can_login,
                });
            }
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn startup_error(fields: &[(u8, &str)]) -> tokio_postgres::Error {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut body = vec![];
        for (tag, value) in fields {
            body.push(*tag);
            body.extend(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u32().await.unwrap();
            let mut startup = vec![0; len as usize - 4];
            socket.read_exact(&mut startup).await.unwrap();
            // AuthenticationOk precedes the selected post-authentication error.
            socket.write_all(b"R\0\0\0\x08\0\0\0\0").await.unwrap();
            socket.write_u8(b'E').await.unwrap();
            socket.write_u32(body.len() as u32 + 4).await.unwrap();
            socket.write_all(&body).await.unwrap();
        });
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(port).user("subject");
        let error = match config.connect(tokio_postgres::NoTls).await {
            Ok(_) => panic!("startup unexpectedly succeeded"),
            Err(error) => error,
        };
        server.await.unwrap();
        error
    }

    #[tokio::test]
    async fn actual_driver_selects_only_exact_postauth_nologin_and_discards_raw_text() {
        let fields = vec![
            (b'S', "FATAL"),
            (b'V', "FATAL"),
            (b'C', "28000"),
            (b'M', "role \"subject\" is not permitted to log in"),
            (b'F', "miscinit.c"),
            (b'R', "InitializeSessionUserId"),
            (b'D', "PRIVATE-ERROR-DETAIL-SENTINEL"),
        ];
        let error = startup_error(&fields).await;
        let selected = recognize(&error, "subject").unwrap();
        assert_eq!(selected.db_identity, "subject");
        assert_eq!(
            selected.kind,
            PostgresLoginFailureKind::AuthenticatedNoLoginV1
        );
        let serialized = serde_json::to_string(&selected).unwrap();
        for raw in [
            "PRIVATE-ERROR-DETAIL-SENTINEL",
            "miscinit.c",
            "28000",
            "not permitted",
        ] {
            assert!(!serialized.contains(raw));
        }
        assert!(recognize(&error, "another-subject").is_none());
        assert!(recognize(&error, "subject\n").is_none());
        assert!(recognize(&error, &"s".repeat(129)).is_none());
        for (tag, replacement) in [
            (b'V', "ERROR"),
            (b'C', "28P01"),
            (b'C', "42501"),
            (b'M', "password authentication failed for user \"subject\""),
            (b'M', "role \"other\" is not permitted to log in"),
            (b'M', "role \"subject\" is not permitted to log in trailing"),
            (b'F', "auth.c"),
            (b'R', "auth_failed"),
        ] {
            let mut changed = fields.clone();
            changed.iter_mut().find(|(t, _)| *t == tag).unwrap().1 = replacement;
            assert!(recognize(&startup_error(&changed).await, "subject").is_none());
        }
        for missing in *b"VFR" {
            let changed: Vec<_> = fields
                .iter()
                .copied()
                .filter(|(tag, _)| *tag != missing)
                .collect();
            assert!(recognize(&startup_error(&changed).await, "subject").is_none());
        }
    }
}
