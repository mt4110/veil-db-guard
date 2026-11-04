use super::auth::*;
use crate::domain::*;
use std::time::{Duration, SystemTime};

#[test]
fn signed_url_preserves_user_and_session_token_without_plaintext_secret_key() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let endpoint = Endpoint {
        host: "fixture.synthetic.rds.amazonaws.com".into(),
        port: 5432,
    };
    let credentials = aws_credential_types::Credentials::new(
        "DUMMY_ACCESS",
        "DUMMY_SECRET",
        Some("DUMMY_SESSION".into()),
        None,
        "fixture",
    );
    let token =
        sign_iam_token(credentials, &endpoint, "User + & ?", "ap-northeast-1", now).unwrap();
    let url = url::Url::parse(&format!("https://{}", token.expose())).unwrap();
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert!(
        pairs
            .get("DBUser")
            .is_some_and(|value| value == "User + & ?")
    );
    assert!(
        pairs
            .get("X-Amz-Expires")
            .is_some_and(|value| value == "900")
    );
    assert!(
        pairs
            .get("X-Amz-Security-Token")
            .is_some_and(|value| value == "DUMMY_SESSION")
    );
    assert!(
        pairs
            .get("X-Amz-Signature")
            .is_some_and(|value| value.len() == 64)
    );
    assert!(!token.expose().contains("DUMMY_SECRET"));
}

#[tokio::test]
async fn fresh_tokens_and_intentionally_expired_signatures_have_distinct_times() {
    let endpoint = Endpoint {
        host: "fixture.synthetic.rds.amazonaws.com".into(),
        port: 5432,
    };
    let provider = SigningTokenProvider {
        credentials: aws_credential_types::Credentials::new(
            "DUMMY", "DUMMY", None, None, "fixture",
        ),
        region: "ap-northeast-1".into(),
    };
    let fresh = provider
        .token(&endpoint, "vdg_probe", TokenMode::Valid)
        .await
        .unwrap();
    let expired = provider
        .token(&endpoint, "vdg_probe", TokenMode::Expired)
        .await
        .unwrap();
    let value = |token: &SecretToken| {
        url::Url::parse(&format!("https://{}", token.expose()))
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "X-Amz-Date")
            .unwrap()
            .1
            .into_owned()
    };
    assert!(value(&expired) < value(&fresh));
    let invalid = provider
        .token(&endpoint, "vdg_probe", TokenMode::BadSignature)
        .await
        .unwrap();
    assert!(fresh.expose() != invalid.expose());
}
