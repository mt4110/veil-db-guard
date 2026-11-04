//! Credential acquisition is explicit. Tokens never implement revealing Debug or Serialize.
use crate::domain::{Endpoint, ReasonCode};
use aws_credential_types::{Credentials, provider::ProvideCredentials};
use aws_sigv4::{
    http_request::{SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign},
    sign::v4,
};
use std::{
    future::Future,
    pin::Pin,
    process::Stdio,
    time::{Duration, SystemTime},
};
use tokio::io::AsyncReadExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenMode {
    Valid,
    Missing,
    BadSignature,
    Expired,
}

pub struct SecretToken(String);
impl SecretToken {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
/// Holds one explicitly captured token for an expiry/new-session experiment only.
pub struct HeldTokenProvider {
    token: SecretToken,
}
impl HeldTokenProvider {
    pub fn new(token: SecretToken) -> Self {
        Self { token }
    }
}
impl TokenProvider for HeldTokenProvider {
    fn token<'a>(&'a self, _: &'a Endpoint, _: &'a str, mode: TokenMode) -> TokenFuture<'a> {
        Box::pin(async move {
            if mode != TokenMode::Valid {
                return Err(ReasonCode::UnsupportedCase);
            }
            Ok(SecretToken(self.token.0.clone()))
        })
    }
}
impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretToken([REDACTED])")
    }
}
pub type TokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SecretToken, ReasonCode>> + Send + 'a>>;
pub trait TokenProvider: Send + Sync {
    fn local_only(&self) -> bool {
        false
    }
    fn token<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        user: &'a str,
        mode: TokenMode,
    ) -> TokenFuture<'a>;
}

/// Signing performs no network I/O. Callers supply an explicit credential provider.
pub fn sign_iam_token(
    credentials: Credentials,
    endpoint: &Endpoint,
    user: &str,
    region: &str,
    now: SystemTime,
) -> Result<SecretToken, ReasonCode> {
    if credentials.expiry().is_some_and(|expiry| expiry <= now) {
        return Err(ReasonCode::IamDenied);
    }
    let mut url = url::Url::parse(&format!("https://{}:{}/", endpoint.host, endpoint.port))
        .map_err(|_| ReasonCode::ConfigInvalid)?;
    url.query_pairs_mut()
        .append_pair("Action", "connect")
        .append_pair("DBUser", user);
    let identity = credentials.into();
    let mut settings = SigningSettings::default();
    settings.expires_in = Some(Duration::from_secs(900));
    settings.signature_location = SignatureLocation::QueryParams;
    let parameters = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("rds-db")
        .time(now)
        .settings(settings)
        .build()
        .map_err(|_| ReasonCode::Unknown)?;
    let request = SignableRequest::new(
        "GET",
        url.as_str(),
        std::iter::empty(),
        SignableBody::Bytes(&[]),
    )
    .map_err(|_| ReasonCode::Unknown)?;
    let (instructions, _) = sign(request, &parameters.into())
        .map_err(|_| ReasonCode::Unknown)?
        .into_parts();
    for (name, value) in instructions.params() {
        url.query_pairs_mut().append_pair(name, value);
    }
    let token = url
        .as_str()
        .strip_prefix("https://")
        .ok_or(ReasonCode::Unknown)?
        .to_owned();
    Ok(SecretToken(token))
}

pub struct SigningTokenProvider<P> {
    pub credentials: P,
    pub region: String,
}
impl<P: ProvideCredentials + Send + Sync> TokenProvider for SigningTokenProvider<P> {
    fn token<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        user: &'a str,
        mode: TokenMode,
    ) -> TokenFuture<'a> {
        Box::pin(async move {
            if mode == TokenMode::Missing {
                return Ok(SecretToken(String::new()));
            }
            let credentials = self
                .credentials
                .provide_credentials()
                .await
                .map_err(|_| ReasonCode::IamDenied)?;
            if credentials
                .expiry()
                .is_some_and(|expiry| expiry <= SystemTime::now())
            {
                return Err(ReasonCode::IamDenied);
            }
            let now = if mode == TokenMode::Expired {
                SystemTime::now() - Duration::from_secs(901)
            } else {
                SystemTime::now()
            };
            let mut token = sign_iam_token(credentials, endpoint, user, &self.region, now)?;
            if mode == TokenMode::BadSignature {
                corrupt_signature(&mut token)?;
            }
            Ok(token)
        })
    }
}

fn corrupt_signature(token: &mut SecretToken) -> Result<(), ReasonCode> {
    let start = token
        .0
        .find("X-Amz-Signature=")
        .ok_or(ReasonCode::Unknown)?
        + "X-Amz-Signature=".len();
    let byte = token
        .0
        .as_bytes()
        .get(start)
        .copied()
        .ok_or(ReasonCode::Unknown)?;
    token
        .0
        .replace_range(start..start + 1, if byte == b'0' { "1" } else { "0" });
    Ok(())
}

/// AWS CLI owns its credential chain. Only the fixed local signing command is invoked.
/// This provider is never constructed by local-lab execution.
pub struct AwsCliTokenProvider {
    pub region: String,
    pub profile: Option<String>,
}
impl TokenProvider for AwsCliTokenProvider {
    fn token<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        user: &'a str,
        mode: TokenMode,
    ) -> TokenFuture<'a> {
        Box::pin(async move {
            if mode == TokenMode::Missing {
                return Ok(SecretToken(String::new()));
            }
            let mut command = tokio::process::Command::new("aws");
            command.args([
                "rds",
                "generate-db-auth-token",
                "--hostname",
                &endpoint.host,
                "--port",
                &endpoint.port.to_string(),
                "--username",
                user,
                "--region",
                &self.region,
            ]);
            if let Some(profile) = &self.profile {
                command.arg("--profile").arg(profile);
            }
            command
                .env("AWS_PAGER", "")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::piped())
                .kill_on_drop(true);
            let mut child = command.spawn().map_err(|_| ReasonCode::IamDenied)?;
            let stdout = child.stdout.take().ok_or(ReasonCode::Unknown)?;
            let mut bytes = Vec::new();
            stdout
                .take(65_537)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| ReasonCode::IamDenied)?;
            if bytes.len() > 65_536 {
                return Err(ReasonCode::LimitExceeded);
            }
            if !child
                .wait()
                .await
                .map_err(|_| ReasonCode::IamDenied)?
                .success()
            {
                return Err(ReasonCode::IamDenied);
            }
            let value = String::from_utf8(bytes).map_err(|_| ReasonCode::Unknown)?;
            let mut token = SecretToken(value.trim_end_matches(['\r', '\n']).to_owned());
            if token.0.is_empty() {
                return Err(ReasonCode::IamDenied);
            }
            if mode == TokenMode::BadSignature {
                corrupt_signature(&mut token)?;
            }
            // Only runners with an explicit long-test profile can request this mode.
            // Cancellation/deadline outside the provider drops this future and kills any child.
            if mode == TokenMode::Expired {
                tokio::time::sleep(Duration::from_secs(901)).await;
            }
            Ok(token)
        })
    }
}

/// A local test password is injected only by the local test harness, never config/CLI.
pub struct LocalPasswordProvider {
    secret: SecretToken,
}
impl LocalPasswordProvider {
    pub fn new(value: String) -> Self {
        Self {
            secret: SecretToken(value),
        }
    }
}
impl TokenProvider for LocalPasswordProvider {
    fn local_only(&self) -> bool {
        true
    }
    fn token<'a>(&'a self, _: &'a Endpoint, _: &'a str, mode: TokenMode) -> TokenFuture<'a> {
        Box::pin(async move {
            match mode {
                TokenMode::Valid => Ok(SecretToken(self.secret.0.clone())),
                TokenMode::Missing => Ok(SecretToken(String::new())),
                // A local password server does not validate SigV4 or IAM expiry.
                _ => Err(ReasonCode::UnsupportedCase),
            }
        })
    }
}
