//! EC2 IID /signature verification against the AWS-published Tokyo RSA key.
//! /rsa2048 is PKCS7 and is deliberately not accepted by this raw-RSA recipe.
//! The IID has no request nonce or IAM role: freshness comes from the pinned
//! SSH request/context capture, and credential/principal assurance stays Unknown.
use super::gce_host::SourceError;
use crate::core::source::AwsEc2Identity;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html
// ap-northeast-1 RSA certificate SHA256: 67d28c01fc23c2f0df9a084ab39219dc
// e4c279ab26efa50aa4a30e733685e03b (valid 2024-04-29..2029-04-28).
// AWS's /signature certificate is 1024-bit; ring's legacy verification-only
// algorithm is required. Never substitute the distinct RSA-2048 PKCS7 key.
const TOKYO_RSA_PKCS1: &str = "MIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrDjbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJLXeE4hwvo0sD4f3j9AgMBAAE=";
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    account_id: String,
    region: String,
    availability_zone: String,
    instance_id: String,
    image_id: String,
    pending_time: String,
    private_ip: std::net::IpAddr,
}
pub(super) fn verify(
    document: &str,
    signature: &str,
    expected: &AwsEc2Identity,
    now: u64,
) -> Result<(), SourceError> {
    // Bounded, pinned certificate lifetime. Rotation requires a reviewed build.
    if !(1_714_393_390..1_872_073_390).contains(&now) {
        return Err(SourceError::IdentityUnverified);
    }
    verify_key(
        document,
        signature,
        expected,
        &STANDARD
            .decode(TOKYO_RSA_PKCS1)
            .map_err(|_| SourceError::Integrity)?,
    )
}
fn verify_key(
    document: &str,
    signature: &str,
    expected: &AwsEc2Identity,
    key: &[u8],
) -> Result<(), SourceError> {
    if document.is_empty() || document.len() > 16384 || signature.len() > 2048 {
        return Err(SourceError::Limit);
    }
    let sig = STANDARD
        .decode(signature.trim())
        .map_err(|_| SourceError::IdentityUnverified)?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        key,
    )
    .verify(document.as_bytes(), &sig)
    .map_err(|_| SourceError::IdentityUnverified)?;
    let d: Document =
        serde_json::from_str(document).map_err(|_| SourceError::IdentityUnverified)?;
    if d.account_id != expected.account_id
        || d.region != expected.region
        || d.availability_zone != expected.availability_zone
        || d.instance_id != expected.instance_id
        || d.image_id != expected.image_id
        || d.pending_time != expected.pending_time
        || d.private_ip != expected.private_ip
    {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn test_identity(expected: &AwsEc2Identity) -> (Vec<u8>, String, String) {
    use ring::signature::{KeyPair, RsaKeyPair};
    static KEY: std::sync::LazyLock<RsaKeyPair> = std::sync::LazyLock::new(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        RsaKeyPair::from_der(&out.stdout)
            .or_else(|_| RsaKeyPair::from_pkcs8(&out.stdout))
            .unwrap()
    });
    let doc = serde_json::json!({"accountId":expected.account_id,"region":expected.region,"availabilityZone":expected.availability_zone,"instanceId":expected.instance_id,"imageId":expected.image_id,"pendingTime":expected.pending_time,"privateIp":expected.private_ip,"architecture":"arm64","version":"2017-09-30"}).to_string();
    let mut sig = vec![0; KEY.public().modulus_len()];
    KEY.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        doc.as_bytes(),
        &mut sig,
    )
    .unwrap();
    (
        KEY.public_key().as_ref().to_vec(),
        doc,
        STANDARD.encode(sig),
    )
}
#[cfg(test)]
pub(super) fn verify_test_key(
    doc: &str,
    sig: &str,
    expected: &AwsEc2Identity,
    key: &[u8],
) -> Result<(), SourceError> {
    verify_key(doc, sig, expected, key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_signature_and_every_registered_field_are_required_but_never_nonce_or_role_proof() {
        let expected = AwsEc2Identity {
            account_id: "123456789012".into(),
            region: "ap-northeast-1".into(),
            availability_zone: "ap-northeast-1a".into(),
            instance_id: "i-0123456789abcdef0".into(),
            image_id: "ami-0123456789abcdef0".into(),
            pending_time: "2026-11-03T00:00:00Z".into(),
            private_ip: "10.0.0.10".parse().unwrap(),
        };
        let (key, doc, sig) = test_identity(&expected);
        verify_key(&doc, &sig, &expected, &key).unwrap();
        assert!(verify_key(&(doc.clone() + " "), &sig, &expected, &key).is_err());
        assert!(verify_key(&doc, "PRIVATE_TOKEN_SENTINEL", &expected, &key).is_err());
        for field in [
            "account_id",
            "region",
            "availability_zone",
            "instance_id",
            "image_id",
            "pending_time",
            "private_ip",
        ] {
            let mut value = serde_json::to_value(&expected).unwrap();
            value[field] = serde_json::json!(if field == "private_ip" {
                "10.0.0.11"
            } else {
                "different"
            });
            let other = serde_json::from_value(value).unwrap();
            assert!(verify_key(&doc, &sig, &other, &key).is_err(), "{field}");
        }
        // A key accepted by a unit fixture is not a production trust override.
        assert!(verify(&doc, &sig, &expected, 1_793_664_000).is_err());
    }
}
