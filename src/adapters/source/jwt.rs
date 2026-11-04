//! RS256 verification delegates cryptography to ring. Google trust keys can
//! only be fetched from the fixed TLS endpoint; no runtime key/issuer override.
use super::{
    gce_host::{SourceError, trusted_program},
    process,
};
use crate::core::{admission::IssuedObservation, source::GceVmIdentity};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
use tokio_util::sync::CancellationToken;

pub(super) const MAX_TOKEN_BYTES: usize = 16 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwk {
    kid: String,
    kty: String,
    alg: String,
    r#use: String,
    n: String,
    e: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwks {
    keys: Vec<Jwk>,
}
pub(super) struct GoogleSigningKeys {
    keys: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    fetched_at: u64,
}
#[derive(Debug)]
pub(super) struct VmTokenFacts {
    pub identity: GceVmIdentity,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signing_key_id: String,
}

impl GoogleSigningKeys {
    pub(super) async fn fetch(cancel: &CancellationToken) -> Result<Self, SourceError> {
        trusted_program(Path::new("/usr/bin/curl"))?;
        let args = [
            "-q",
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--max-time",
            "10",
            "--connect-timeout",
            "5",
            "--max-filesize",
            "65536",
            "--",
            "https://www.googleapis.com/oauth2/v3/certs",
        ]
        .map(str::to_owned);
        let bytes = process::run(Path::new("/usr/bin/curl"), &args, &[], 65536, 12, cancel).await?;
        Self::parse(&bytes, crate::domain::now())
    }
    fn parse(bytes: &[u8], now: u64) -> Result<Self, SourceError> {
        if bytes.len() > 65536 {
            return Err(SourceError::Limit);
        }
        let jwks: Jwks =
            serde_json::from_slice(bytes).map_err(|_| SourceError::IdentityUnverified)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 16 {
            return Err(SourceError::IdentityUnverified);
        }
        let mut keys = BTreeMap::new();
        for key in jwks.keys {
            if !crate::core::policy::valid_id(&key.kid)
                || key.kty != "RSA"
                || key.alg != "RS256"
                || key.r#use != "sig"
                || key.n.len() > 1400
                || key.e.len() > 12
            {
                return Err(SourceError::IdentityUnverified);
            }
            let n = URL_SAFE_NO_PAD
                .decode(&key.n)
                .map_err(|_| SourceError::IdentityUnverified)?;
            let e = URL_SAFE_NO_PAD
                .decode(&key.e)
                .map_err(|_| SourceError::IdentityUnverified)?;
            if !(256..=1024).contains(&n.len())
                || n.first() == Some(&0)
                || e != [1, 0, 1]
                || keys.insert(key.kid, (n, e)).is_some()
            {
                return Err(SourceError::IdentityUnverified);
            }
        }
        Ok(Self {
            keys,
            fetched_at: now,
        })
    }
    pub(super) fn verify(
        &self,
        token: &str,
        issued: &IssuedObservation,
        now: u64,
    ) -> Result<VmTokenFacts, SourceError> {
        if now < self.fetched_at || now - self.fetched_at > 300 || token.len() > MAX_TOKEN_BYTES {
            return Err(SourceError::IdentityUnverified);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(SourceError::IdentityUnverified);
        }
        let header: Header = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|_| SourceError::IdentityUnverified)?,
        )
        .map_err(|_| SourceError::IdentityUnverified)?;
        if header.alg != "RS256" || header.typ.as_deref().is_some_and(|s| s != "JWT") {
            return Err(SourceError::IdentityUnverified);
        }
        let (n, e) = self
            .keys
            .get(&header.kid)
            .ok_or(SourceError::IdentityUnverified)?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| SourceError::IdentityUnverified)?;
        ring::signature::RsaPublicKeyComponents { n, e }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &signature,
            )
            .map_err(|_| SourceError::IdentityUnverified)?;
        let claims: Claims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|_| SourceError::IdentityUnverified)?,
        )
        .map_err(|_| SourceError::IdentityUnverified)?;
        let expected = &issued
            .snapshot
            .gce()
            .ok_or(SourceError::Unsupported)?
            .native_identity;
        let vm = &claims.google.compute_engine;
        if claims.iss != "https://accounts.google.com"
            || claims.aud != audience(issued)?
            || claims.sub != expected.service_account_id
            || claims.azp != expected.service_account_id
            || claims.email != expected.service_account
            || !claims.email_verified
            || claims.exp <= now
            || claims.iat > now.saturating_add(5)
            || claims.iat.saturating_add(5) < issued.request.issued_at
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > 3600
            || vm.project_id != expected.project_id
            || vm.project_number.to_string() != expected.project_number
            || vm.zone != expected.zone
            || vm.instance_id != expected.instance_id
            || vm.instance_creation_timestamp != expected.created_at_unix
            || vm.instance_name.len() > 128
            || vm.license_id.len() > 32
        {
            return Err(SourceError::IdentityUnverified);
        }
        Ok(VmTokenFacts {
            identity: expected.clone(),
            issued_at: claims.iat,
            expires_at: claims.exp,
            signing_key_id: header.kid,
        })
    }
}
pub(super) fn audience(i: &IssuedObservation) -> Result<String, SourceError> {
    let digest = i.request.digest().map_err(|_| SourceError::Invalid)?;
    Ok(format!(
        "urn:veil-db-guard:source:v1:{}:{digest}",
        i.request.nonce
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    azp: String,
    email: String,
    email_verified: bool,
    iat: u64,
    exp: u64,
    google: GoogleClaims,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleClaims {
    compute_engine: ComputeClaims,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeClaims {
    project_id: String,
    project_number: u64,
    zone: String,
    instance_id: String,
    instance_name: String,
    instance_creation_timestamp: u64,
    #[serde(default, rename = "instance_confidentiality")]
    _instance_confidentiality: Option<u8>,
    #[serde(default)]
    license_id: Vec<String>,
}

#[cfg(test)]
pub(super) fn test_identity(
    i: &IssuedObservation,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> (GoogleSigningKeys, String) {
    test_identity_at(i, 100, 110, mutate)
}

#[cfg(test)]
pub(super) fn test_identity_at(
    i: &IssuedObservation,
    key_fetched_at: u64,
    token_issued_at: u64,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> (GoogleSigningKeys, String) {
    use ring::signature::{RsaKeyPair, RsaPublicKeyComponents};
    static PAIR: std::sync::OnceLock<RsaKeyPair> = std::sync::OnceLock::new();
    let pair = PAIR.get_or_init(|| {
        // Ephemeral test key only, generated in memory. Never a user key or
        // persisted fixture, and this helper is absent in production builds.
        let output = std::process::Command::new("/usr/bin/openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        RsaKeyPair::from_pkcs8(&output.stdout)
            .or_else(|_| RsaKeyPair::from_der(&output.stdout))
            .unwrap()
    });
    let public: RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
    let jwks = serde_json::json!({"keys":[{"kid":"unit-test-only","alg":"RS256","use":"sig","kty":"RSA","n":URL_SAFE_NO_PAD.encode(public.n),"e":URL_SAFE_NO_PAD.encode(public.e)}]});
    let keys =
        GoogleSigningKeys::parse(&serde_json::to_vec(&jwks).unwrap(), key_fetched_at).unwrap();
    let vm = &i.snapshot.gce().unwrap().native_identity;
    let mut claims = serde_json::json!({"iss":"https://accounts.google.com","iat":token_issued_at,"exp":token_issued_at.saturating_add(3600),"aud":audience(i).unwrap(),"sub":vm.service_account_id,"azp":vm.service_account_id,
        "email":vm.service_account,"email_verified":true,"google":{"compute_engine":{"project_id":vm.project_id,"project_number":vm.project_number.parse::<u64>().unwrap(),
        "zone":vm.zone,"instance_id":vm.instance_id,"instance_name":"test-vm","instance_creation_timestamp":vm.created_at_unix}}});
    mutate(&mut claims);
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"unit-test-only","typ":"JWT"}"#);
    let message = format!(
        "{header}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut sig = vec![0; pair.public().modulus_len()];
    pair.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        message.as_bytes(),
        &mut sig,
    )
    .unwrap();
    (keys, format!("{message}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_full_vm_identity_is_request_bound_and_matches_every_registered_identity_field() {
        let (i, _) = super::super::testsupport::fixture();
        let (keys, token) = test_identity(&i, |_| {});
        assert_eq!(
            keys.verify(&token, &i, 116).unwrap().identity,
            i.snapshot.gce().unwrap().native_identity
        );
        let mut next = i.clone();
        next.request.nonce = "d".repeat(64);
        assert!(matches!(
            keys.verify(&token, &next, 116),
            Err(SourceError::IdentityUnverified)
        ));
        assert!(matches!(
            keys.verify(&token, &i, 401),
            Err(SourceError::IdentityUnverified)
        ));
    }
    #[test]
    fn signed_wrong_issuer_subject_audience_generation_and_time_are_rejected() {
        let (i, _) = super::super::testsupport::fixture();
        for case in 0..14 {
            let (keys, token) = test_identity(&i, |c| match case {
                0 => c["iss"] = serde_json::json!("https://attacker.invalid"),
                1 => c["aud"] = serde_json::json!("other-audience"),
                2 => c["sub"] = serde_json::json!("other-sa"),
                3 => c["azp"] = serde_json::json!("other-sa"),
                4 => c["email_verified"] = serde_json::json!(false),
                5 => c["exp"] = serde_json::json!(115),
                6 => c["iat"] = serde_json::json!(200),
                7 => c["google"]["compute_engine"]["instance_id"] = serde_json::json!("other-vm"),
                8 => c["google"]["compute_engine"]["zone"] = serde_json::json!("other-zone"),
                9 => c["google"]["compute_engine"]["project_number"] = serde_json::json!(42),
                10 => {
                    c["google"]["compute_engine"]["instance_creation_timestamp"] =
                        serde_json::json!(2)
                }
                11 => {
                    c["google"]["compute_engine"]["project_id"] = serde_json::json!("other-project")
                }
                12 => {
                    c["email"] =
                        serde_json::json!("other@vdg-example-000000.iam.gserviceaccount.com")
                }
                _ => {
                    c.as_object_mut().unwrap().remove("google");
                }
            });
            assert!(
                matches!(
                    keys.verify(&token, &i, 116),
                    Err(SourceError::IdentityUnverified)
                ),
                "case {case}"
            );
        }
    }
    #[test]
    fn tampering_alg_confusion_remote_key_headers_and_unbounded_tokens_are_rejected_without_echo() {
        let (i, _) = super::super::testsupport::fixture();
        let (keys, token) = test_identity(&i, |_| {});
        for header in [
            serde_json::json!({"alg":"none","kid":"unit-test-only"}),
            serde_json::json!({"alg":"HS256","kid":"unit-test-only"}),
            serde_json::json!({"alg":"RS256","kid":"unit-test-only","jku":"https://attacker.invalid"}),
            serde_json::json!({"alg":"RS256","kid":"unknown"}),
        ] {
            let rest = token.split_once('.').unwrap().1;
            let forged = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                rest
            );
            assert!(keys.verify(&forged, &i, 116).is_err());
        }
        let error = keys
            .verify(&"SENSITIVE".repeat(MAX_TOKEN_BYTES), &i, 116)
            .unwrap_err();
        assert!(!format!("{error:?}").contains("SENSITIVE"));
    }
    #[test]
    fn key_sets_reject_duplicate_kids_and_non_rsa_key_material() {
        for value in [
            serde_json::json!({"keys":[]}),
            serde_json::json!({"keys":[{"kid":"a","kty":"oct","alg":"HS256","use":"sig","n":"a","e":"a"}]}),
            serde_json::json!({"keys":[],"url":"https://attacker.invalid"}),
        ] {
            assert!(GoogleSigningKeys::parse(&serde_json::to_vec(&value).unwrap(), 100).is_err());
        }
        let (i, _) = super::super::testsupport::fixture();
        let (keys, _) = test_identity(&i, |_| {});
        let (n, e) = keys.keys.get("unit-test-only").unwrap();
        let key = serde_json::json!({"kid":"same","kty":"RSA","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(n),"e":URL_SAFE_NO_PAD.encode(e)});
        assert!(
            GoogleSigningKeys::parse(
                &serde_json::to_vec(&serde_json::json!({"keys":[key.clone(),key]})).unwrap(),
                100
            )
            .is_err()
        );
    }
}
