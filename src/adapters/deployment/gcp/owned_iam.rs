use super::{ProviderError, Value, json};
use crate::{
    config::hash_bytes,
    core::owned_iam::{OwnedIamBinding, valid_etag},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Full IAM policy shape used only to certify or consume ownership. The
/// provider's original Value is used as the basis of the actual update.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IamPolicy {
    etag: String,
    version: u8,
    #[serde(default)]
    bindings: Vec<Binding>,
    #[serde(default)]
    audit_configs: Vec<AuditConfig>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    role: String,
    members: Vec<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    condition: Option<Condition>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Condition {
    title: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    description: Option<String>,
    expression: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    location: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditConfig {
    service: String,
    audit_log_configs: Vec<AuditLogConfig>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditLogConfig {
    log_type: String,
    #[serde(default)]
    exempted_members: Vec<String>,
}

pub(super) struct PolicySnapshot {
    pub(super) etag: String,
    pub(super) digest: String,
}

impl PolicySnapshot {
    pub(super) fn parse(raw: &Value) -> Result<Self, ProviderError> {
        let mut policy: IamPolicy =
            serde_json::from_value(raw.clone()).map_err(|_| ProviderError::Precondition)?;
        let bad = ProviderError::Precondition;
        let has_conditions = policy
            .bindings
            .iter()
            .any(|binding| binding.condition.is_some());
        if !valid_etag(&policy.etag)
            || (policy.version != 3 && !(policy.version == 1 && !has_conditions))
        {
            return Err(bad);
        }

        let mut bindings = BTreeSet::new();
        let mut titles = BTreeSet::new();
        let mut unconditional_roles = BTreeSet::new();
        for mut binding in policy.bindings {
            if binding.role.is_empty()
                || binding.role.contains("_withcond_")
                || binding.members.is_empty()
                || !valid_unique(&mut binding.members)
                || binding.condition.as_ref().is_some_and(|c| {
                    c.title.is_empty() || c.expression.is_empty() || !titles.insert(c.title.clone())
                })
                || (binding.condition.is_none()
                    && !unconditional_roles.insert(binding.role.clone()))
                || !bindings
                    .insert(serde_json::to_string(&binding).expect("IAM binding serializes"))
            {
                return Err(bad);
            }
        }
        policy
            .audit_configs
            .sort_by(|a, b| a.service.cmp(&b.service));
        let mut services = BTreeSet::new();
        for audit in &mut policy.audit_configs {
            if audit.service.is_empty()
                || !services.insert(audit.service.clone())
                || audit.audit_log_configs.is_empty()
            {
                return Err(bad);
            }
            audit
                .audit_log_configs
                .sort_by(|a, b| a.log_type.cmp(&b.log_type));
            let mut log_types = BTreeSet::new();
            for log in &mut audit.audit_log_configs {
                if !matches!(
                    log.log_type.as_str(),
                    "ADMIN_READ" | "DATA_READ" | "DATA_WRITE"
                ) || !log_types.insert(log.log_type.clone())
                    || !valid_unique(&mut log.exempted_members)
                {
                    return Err(bad);
                }
            }
        }
        Ok(Self {
            etag: policy.etag,
            digest: hash_bytes(
                &serde_json::to_vec(&(
                    "gcp-iam-policy-content-v1",
                    if has_conditions { 3 } else { 1 },
                    bindings,
                    policy.audit_configs,
                ))
                .expect("IAM policy snapshot serializes"),
            ),
        })
    }
}

fn valid_unique(values: &mut [String]) -> bool {
    values.sort();
    values.iter().all(|value| !value.is_empty()) && values.windows(2).all(|v| v[0] != v[1])
}

fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

pub(super) fn binding_value(binding: &OwnedIamBinding) -> Value {
    json!({"role": binding.role, "members": [binding.member], "condition": binding.condition})
}

pub(super) fn has_title(policy: &Value, title: &str) -> bool {
    policy
        .get("bindings")
        .and_then(Value::as_array)
        .is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.pointer("/condition/title").and_then(Value::as_str) == Some(title)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Value {
        json!({
            "etag": "source-etag",
            "version": 1,
            "bindings": [
                {"role":"roles/owner","members":["user:a@example.test","user:z@example.test"]},
                {"role":"roles/viewer","members":["user:b@example.test"]},
            ],
            "auditConfigs": [
                {"service":"allServices","auditLogConfigs":[{"logType":"ADMIN_READ"}]},
                {"service":"sqladmin.googleapis.com","auditLogConfigs":[
                    {"logType":"DATA_READ","exemptedMembers":["user:a@example.test","user:z@example.test"]},
                    {"logType":"DATA_WRITE"}
                ]},
            ],
        })
    }

    #[test]
    fn unordered_lists_and_unconditional_versions_have_the_same_content_digest() {
        let original = snapshot();
        let mut reordered = original.clone();
        reordered["version"] = json!(3);
        reordered["etag"] = json!("write-response-etag");
        reordered["bindings"][0]["members"]
            .as_array_mut()
            .unwrap()
            .reverse();
        reordered["bindings"].as_array_mut().unwrap().reverse();
        reordered["auditConfigs"][1]["auditLogConfigs"][0]["exemptedMembers"]
            .as_array_mut()
            .unwrap()
            .reverse();
        reordered["auditConfigs"][1]["auditLogConfigs"]
            .as_array_mut()
            .unwrap()
            .reverse();
        reordered["auditConfigs"].as_array_mut().unwrap().reverse();
        let original = PolicySnapshot::parse(&original).unwrap();
        let reordered = PolicySnapshot::parse(&reordered).unwrap();
        assert_eq!(original.digest, reordered.digest);
        assert_ne!(original.etag, reordered.etag);
    }

    #[test]
    fn unknown_duplicate_missing_and_lower_version_data_do_not_certify_ownership() {
        let mut unknown = snapshot();
        unknown["unexpected"] = json!({});
        let mut duplicate = snapshot();
        duplicate["bindings"][0]["members"][1] = duplicate["bindings"][0]["members"][0].clone();
        let mut unknown_condition = snapshot();
        unknown_condition["version"] = json!(3);
        unknown_condition["bindings"][0]["condition"] =
            json!({"title":"t","expression":"true","unknown":"unhandled"});
        let mut missing = snapshot();
        missing.as_object_mut().unwrap().remove("version");
        let mut lower_version = snapshot();
        lower_version["bindings"][0]["condition"] = json!({"title":"t","expression":"true"});
        let mut collapsed_role = snapshot();
        collapsed_role["bindings"][0]["role"] = json!("roles/viewer_withcond_hash");
        let mut null_condition = snapshot();
        null_condition["bindings"][0]["condition"] = Value::Null;
        for bad in [
            unknown,
            duplicate,
            unknown_condition,
            missing,
            lower_version,
            collapsed_role,
            null_condition,
        ] {
            assert!(PolicySnapshot::parse(&bad).is_err(), "{bad}");
        }
        assert!(
            serde_json::from_str::<IamPolicy>(r#"{"etag":"first","etag":"second","version":1}"#)
                .is_err()
        );
    }
}
