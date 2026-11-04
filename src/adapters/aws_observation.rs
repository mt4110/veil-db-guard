//! Current read-only AWS connection observations. Only typed summaries and
//! artifact hashes leave this module; credentials/tokens/errors are not logged.
use super::{
    deployment::aws::{
        Access, AwsObserver, ConnectionEvidence, ProviderError, RevocationEvidence,
        generation_fingerprint,
    },
    engine::postgres::aws::{AwsCliPgAuthProvider, AwsPgTargetBinding},
};
use crate::{
    core::{change::PreparedChange, policy::*},
    domain::Endpoint,
    probe::auth::sign_iam_token,
    store::{RunStatus, RunWriter},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsProfileBinding {
    pub subject_id: String,
    pub profile: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOutcome {
    Refused,
    Connected,
    Timeout,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub subject_id: String,
    pub principal: String,
    pub db_user: String,
    pub identity_verified: bool,
    pub tls_verified: bool,
    pub access: Access,
    pub iam_denial: bool,
    pub reason: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AwsAccessCapture {
    pub schema_version: u32,
    pub policy_revision_hash: String,
    pub target_id: String,
    pub generation: String,
    pub proxy_arn: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub complete: bool,
    pub direct: DirectOutcome,
    pub observations: Vec<AccessRecord>,
}
pub struct AwsLiveObserver {
    pub aws: PathBuf,
    pub profiles: Vec<AwsProfileBinding>,
    pub root_ca: Vec<u8>,
    pub work_dir: PathBuf,
    pub cancel: CancellationToken,
}
fn endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint {
        host: host.into(),
        port,
    }
}
pub fn target_binding(target: &Target) -> Result<AwsPgTargetBinding, ProviderError> {
    let b = target.aws.as_ref().ok_or(ProviderError::Precondition)?;
    let port = native_db_port(target.engine.family).ok_or(ProviderError::Precondition)?;
    Ok(AwsPgTargetBinding {
        db_instance_arn: target.resource.native_id.clone(),
        dbi_resource_id: b.db_resource_id.clone(),
        db_endpoint: endpoint(&b.db_endpoint, port),
        database: target.engine.database.clone(),
        management_endpoint: endpoint(&b.proxy_endpoint, port),
        proxy_arn: Some(b.proxy_arn.clone()),
        proxy_name: Some(b.proxy_name.clone()),
        proxy_role_arn: Some(b.proxy_role_arn.clone()),
        proxy_role_id: Some(b.proxy_role_id.clone()),
    })
}
fn tls(pem: &[u8]) -> Result<rustls::ClientConfig, ProviderError> {
    let mut roots = rustls::RootCertStore::empty();
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProviderError::Precondition)?;
    if certificates.is_empty() || pem.len() > 1024 * 1024 {
        return Err(ProviderError::Precondition);
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| ProviderError::Precondition)?;
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ProviderError::Precondition)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
fn iam_denial(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("rds-db:connect")
        && (message.contains("not authorized") || message.contains("access denied"))
}
impl AwsLiveObserver {
    fn capture(
        &self,
        c: &PreparedChange,
        t: &Target,
    ) -> Result<(AwsAccessCapture, Vec<String>), ProviderError> {
        c.verify().map_err(|_| ProviderError::Precondition)?;
        if self.profiles.len() > 16 {
            return Err(ProviderError::Precondition);
        }
        let native = t.aws.as_ref().ok_or(ProviderError::Precondition)?;
        let binding = target_binding(t)?;
        let tls = tls(&self.root_ca)?;
        let mut subjects = BTreeMap::<String, String>::new();
        for grant in c.policy.grants.iter().filter(|g| g.target == t.id) {
            if let Some(old) = subjects.insert(grant.subject.clone(), grant.db_identity.clone())
                && old != grant.db_identity
            {
                return Err(ProviderError::Precondition);
            }
            let profile = c
                .policy
                .protection_profiles
                .iter()
                .find(|p| p.id == grant.profile)
                .ok_or(ProviderError::Precondition)?;
            for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
                subjects.insert(
                    exception.subject.clone(),
                    native.management_db_identity.clone(),
                );
            }
        }
        if subjects.is_empty() || subjects.len() > 8 {
            return Err(ProviderError::Precondition);
        }
        let started_at = crate::domain::now();
        let cancel = self.cancel.clone();
        let (observations, direct) = std::thread::scope(|scope| {
            scope.spawn(||{
            let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|ProviderError::Unavailable)?;
            rt.block_on(async {
                let deadline=tokio::time::Instant::now()+Duration::from_secs(120);let mut observations=vec![];
                for (id,user) in &subjects {
                    let subject=c.policy.subjects.iter().find(|s|&s.id==id).ok_or(ProviderError::Precondition)?;
                    let rows=self.profiles.iter().filter(|p|&p.subject_id==id).collect::<Vec<_>>();
                    if rows.len()!=1{return Err(ProviderError::Precondition);}
                    let auth=AwsCliPgAuthProvider::new(self.aws.clone(),rows[0].profile.clone(),subject.identity.principal.clone(),subject.identity.immutable_id.clone().ok_or(ProviderError::Precondition)?,cancel.clone()).map_err(|_|ProviderError::Precondition)?;
                    let mut record=AccessRecord{subject_id:id.clone(),principal:subject.identity.principal.clone(),db_user:user.clone(),identity_verified:false,tls_verified:false,access:Access::Unknown,iam_denial:false,reason:"unavailable".into()};
                    let attempt=async {
                        // Metadata is checked under management credentials by
                        // the deployment adapter before/after the observer.
                        let credentials=auth.role_credentials(&t.placement.region).await.map_err(|_|ProviderError::Unavailable)?;
                        record.identity_verified=true;
                        if t.engine.family == EngineFamily::MySql {
                            use super::engine::mysql::aws::{probe_mysql_iam,MysqlAccessProbe};
                            let mysql=t.mysql.as_ref().ok_or(ProviderError::Precondition)?;
                            let host=if user==&native.management_db_identity { &mysql.management_account_host } else { &mysql.account_host };
                            let remaining=deadline.saturating_duration_since(tokio::time::Instant::now());
                            let result=probe_mysql_iam(&binding.management_endpoint,&t.engine.database,&t.engine.version,user,host,
                                &t.placement.region,credentials,&self.root_ca,remaining,cancel.clone()).await;
                            if result==MysqlAccessProbe::Allowed {
                                record.tls_verified=true;record.access=Access::Allowed;record.reason="verified_proxy_sql".into();
                            } else { record.reason="mysql_connection_cause_unconfirmed".into(); }
                            return Ok(());
                        }
                        let token=sign_iam_token(credentials,&binding.management_endpoint,user,&t.placement.region,SystemTime::now()).map_err(|_|ProviderError::Unavailable)?;
                        let mut config=tokio_postgres::Config::new();config.host(&binding.management_endpoint.host).port(5432).user(user).dbname(&t.engine.database).password(token.expose()).connect_timeout(Duration::from_secs(10)).ssl_mode(tokio_postgres::config::SslMode::Require);
                        let connected=config.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls.clone())).await;
                        let (client,connection)=match connected{Ok(v)=>v,Err(error)=>{
                            if let Some(db)=error.as_db_error(){record.tls_verified=true;record.iam_denial=matches!(db.code().code(),"28000"|"28P01")&&iam_denial(db.message());record.access=if record.iam_denial{Access::Denied}else{Access::Unknown};record.reason=if record.iam_denial{"iam_connect_denied"}else{"authentication_cause_unconfirmed"}.into();}
                            return Ok(());
                        }};
                        record.tls_verified=true;
                        let task=tokio::spawn(async move{let _=connection.await;});
                        struct Task(tokio::task::JoinHandle<()>);impl Drop for Task{fn drop(&mut self){self.0.abort();}}
                        let _task=Task(task);
                        let row=client.query_one("SELECT current_user::text, current_database()::text, current_setting('server_version'), (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid())",&[]).await.map_err(|_|ProviderError::Unavailable)?;
                        if row.get::<_,String>(0)==*user&&row.get::<_,String>(1)==t.engine.database&&row.get::<_,String>(2).split_whitespace().next()==Some(t.engine.version.as_str())&&row.get::<_,bool>(3){record.access=Access::Allowed;record.reason="verified_proxy_sql".into();}
                        Ok(())
                    };
                    let result:Result<(),ProviderError>=tokio::select!{biased;_=cancel.cancelled()=>Err(ProviderError::Unavailable),r=tokio::time::timeout_at(deadline,attempt)=>r.unwrap_or(Err(ProviderError::Unavailable))};
                    if result.is_err(){record.reason="unavailable_or_timeout".into();}
                    observations.push(record);
                }
                let direct=tokio::select! {biased;_=cancel.cancelled()=>DirectOutcome::Unknown,result=tokio::time::timeout(Duration::from_secs(5),tokio::net::TcpStream::connect((native.db_endpoint.as_str(),binding.db_endpoint.port)))=>match result{Ok(Ok(stream))=>{drop(stream);DirectOutcome::Connected},Ok(Err(error)) if error.kind()==std::io::ErrorKind::ConnectionRefused=>DirectOutcome::Refused,Err(_)=>DirectOutcome::Timeout,_=>DirectOutcome::Unknown}};
                Ok((observations,direct))
            })
        }).join().map_err(|_|ProviderError::Unavailable)
        })??;
        let complete = observations.iter().all(|r| r.identity_verified);
        let capture = AwsAccessCapture {
            schema_version: 1,
            policy_revision_hash: c.plan.policy_revision_hash.clone(),
            target_id: t.id.clone(),
            generation: generation_fingerprint(
                &t.placement.account_id,
                &t.placement.region,
                &t.resource.native_id,
                &native.db_resource_id,
            ),
            proxy_arn: native.proxy_arn.clone(),
            started_at,
            finished_at: crate::domain::now(),
            complete,
            direct,
            observations,
        };
        let mut writer = RunWriter::create_for_config(
            &self
                .work_dir
                .join(format!("aws-access-{}", crate::store::new_run_id())),
            &t.id,
            &c.policy,
            "aws-guard-check",
            8 * 1024 * 1024,
            false,
        )
        .map_err(|_| ProviderError::Unavailable)?;
        writer
            .write_json("aws-access.json", &capture)
            .map_err(|_| ProviderError::Unavailable)?;
        writer
            .finish(if complete {
                RunStatus::Complete
            } else {
                RunStatus::Partial
            })
            .map_err(|_| ProviderError::Unavailable)?;
        let refs = writer
            .manifest
            .artifacts
            .iter()
            .filter(|a| a.name == "aws-access.json")
            .map(|a| a.sha256.clone())
            .collect();
        Ok((capture, refs))
    }
}
impl AwsObserver for AwsLiveObserver {
    fn connections(
        &mut self,
        c: &PreparedChange,
        t: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        let (capture, evidence_refs) = self.capture(c, t)?;
        let allowed = capture
            .observations
            .iter()
            .filter(|r| r.access == Access::Allowed)
            .map(|r| r.principal.clone())
            .collect();
        // The CLI host is not authenticated as every policy workload source.
        // Record its raw transport outcome without upgrading it to those scopes.
        let denied = BTreeSet::new();
        Ok(Some(ConnectionEvidence {
            generation: capture.generation,
            observed_at: capture.started_at,
            proxy_allowed_principals: allowed,
            direct_denied_principals: denied,
            evidence_refs,
        }))
    }
    fn revocation(
        &mut self,
        c: &PreparedChange,
        t: &Target,
        g: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        let (capture, evidence_refs) = self.capture(c, t)?;
        let subject = c
            .policy
            .subjects
            .iter()
            .find(|s| s.id == g.subject)
            .ok_or(ProviderError::Precondition)?;
        let row = capture
            .observations
            .iter()
            .find(|r| r.subject_id == g.subject)
            .ok_or(ProviderError::Precondition)?;
        let allowed = capture
            .observations
            .iter()
            .filter(|r| r.access == Access::Allowed)
            .map(|r| r.principal.clone())
            .collect();
        let denied = BTreeSet::new();
        Ok(Some(RevocationEvidence {
            complete: capture.complete,
            generation: capture.generation,
            observed_at: capture.started_at,
            denied_principal: subject.identity.principal.clone(),
            access: row.access,
            iam_connect_denied: row.iam_denial,
            proxy_allowed_principals: allowed,
            direct_denied_principals: denied,
            evidence_refs,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_authentication_never_becomes_iam_denial() {
        assert!(!iam_denial("PAM authentication failed for user"));
        assert!(!iam_denial("permission denied for table"));
        assert!(!iam_denial("connection timed out"));
        assert!(iam_denial("not authorized to perform rds-db:connect"));
    }
}
