//! Bounded, explicit probes. Local observations cannot become AWS connection evidence.
pub mod auth;
#[cfg(test)]
mod auth_tests;
pub mod performance;
pub mod sql;
pub mod transport;

use crate::{
    config::{self, GuardError},
    domain::*,
};
use auth::{TokenMode, TokenProvider};
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use transport::{ProbeFailure, TlsMode};

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub run_id: String,
    pub source_id: String,
    pub allow_network: bool,
    pub allow_test_writes: bool,
    pub local_lab: bool,
    pub aws_profile: Option<String>,
}

/// Local CLI use has no ambient credential/password fallback. Tests explicitly inject a provider.
pub async fn run(
    config: &TargetConfig,
    snapshot: &InventorySnapshot,
    suite: Suite,
    options: &ProbeOptions,
    cancel: CancellationToken,
) -> Result<Vec<Observation>, GuardError> {
    run_until(
        config,
        snapshot,
        suite,
        options,
        cancel,
        Instant::now() + Duration::from_millis(config.limits.total_timeout_ms),
    )
    .await
}

/// Shares the caller's deadline with inventory rechecks and other surrounding work.
pub async fn run_until(
    config: &TargetConfig,
    snapshot: &InventorySnapshot,
    suite: Suite,
    options: &ProbeOptions,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<Vec<Observation>, GuardError> {
    if options.local_lab {
        return Err(GuardError::PermissionRequired);
    }
    let provider = auth::AwsCliTokenProvider {
        region: config.target.region.clone(),
        profile: options.aws_profile.clone(),
    };
    run_with_provider_until(
        config, snapshot, suite, options, cancel, &provider, deadline,
    )
    .await
}

pub async fn run_with_provider(
    config: &TargetConfig,
    snapshot: &InventorySnapshot,
    suite: Suite,
    options: &ProbeOptions,
    cancel: CancellationToken,
    provider: &dyn TokenProvider,
) -> Result<Vec<Observation>, GuardError> {
    run_with_provider_until(
        config,
        snapshot,
        suite,
        options,
        cancel,
        provider,
        Instant::now() + Duration::from_millis(config.limits.total_timeout_ms),
    )
    .await
}

pub async fn run_with_provider_until(
    config: &TargetConfig,
    snapshot: &InventorySnapshot,
    suite: Suite,
    options: &ProbeOptions,
    cancel: CancellationToken,
    provider: &dyn TokenProvider,
    deadline: Instant,
) -> Result<Vec<Observation>, GuardError> {
    if !options.allow_network {
        return Err(GuardError::PermissionRequired);
    }
    if !options.local_lab && provider.local_only() {
        return Err(GuardError::PermissionRequired);
    }
    if options
        .aws_profile
        .as_ref()
        .is_some_and(|profile| !config::safe_id(profile) || profile.starts_with('-'))
    {
        return Err(GuardError::ConfigInvalid);
    }
    config::validate_config(config)?;
    config::validate_snapshot(config, snapshot)?;
    if !config::safe_id(&options.run_id)
        || snapshot.db.is_none()
        || snapshot.proxy.is_none()
        || snapshot
            .retrievals
            .iter()
            .any(|r| r.status != RetrievalStatus::Complete)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let source = config
        .sources
        .iter()
        .find(|s| s.id == options.source_id)
        .ok_or(GuardError::ConfigInvalid)?;
    if options.local_lab {
        if source.kind != SourceKind::LocalLab
            || !matches!(
                snapshot.evidence_kind,
                EvidenceKind::LocalFixture | EvidenceKind::LocalConnection
            )
        {
            return Err(GuardError::PermissionRequired);
        }
        // Refuse a non-loopback literal/name before attempting DNS, credentials, or any socket.
        for endpoint in [
            &snapshot.db.as_ref().unwrap().endpoint,
            &snapshot.proxy.as_ref().unwrap().endpoint,
        ] {
            if endpoint.host != "localhost"
                && !endpoint
                    .host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            {
                return Err(GuardError::TargetMismatch);
            }
        }
    } else if snapshot.evidence_kind != EvidenceKind::AwsConfiguration
        || source.kind == SourceKind::LocalLab
    {
        return Err(GuardError::EvidenceIncompatible);
    } else {
        if config.target.account_id == "000000000000" {
            return Err(GuardError::PermissionRequired);
        }
        let suffix = format!(".{}.rds.amazonaws.com", config.target.region);
        let db_name = config
            .target
            .db_instance_arn
            .rsplit(":db:")
            .next()
            .ok_or(GuardError::TargetMismatch)?;
        let db_host = &snapshot.db.as_ref().unwrap().endpoint.host;
        let proxy_host = &snapshot.proxy.as_ref().unwrap().endpoint.host;
        if !db_host.starts_with(&format!("{db_name}."))
            || !db_host.ends_with(&suffix)
            || !proxy_host.starts_with(&format!("{}.proxy-", config.target.proxy_name))
            || !proxy_host.ends_with(&suffix)
        {
            return Err(GuardError::TargetMismatch);
        }
    }
    let paths: Vec<_> = config
        .paths
        .iter()
        .filter(|p| p.source_id == options.source_id)
        .collect();
    if paths.is_empty() {
        return Err(GuardError::ConfigInvalid);
    }
    let cases_per_path = match suite {
        Suite::Positive => 20,
        Suite::AuthNegative => 6,
        Suite::TlsNegative => 4,
        Suite::DirectPath => 1,
        Suite::Recovery => 15,
        Suite::Performance => 6,
    };
    let selected_paths = paths
        .iter()
        .filter(|path| {
            if suite == Suite::DirectPath {
                path.destination == Destination::Database && path.expected == Expectation::Deny
            } else {
                path.expected == Expectation::Allow
            }
        })
        .count();
    if selected_paths.saturating_mul(cases_per_path) > config.limits.max_results {
        return Err(GuardError::LimitExceeded);
    }
    let mut runner = Runner {
        config,
        snapshot,
        options,
        provider,
        cancel,
        deadline: deadline
            .min(Instant::now() + Duration::from_millis(config.limits.total_timeout_ms)),
        results: Vec::new(),
    };
    for path in paths {
        if runner.stopped() {
            runner.interrupted(path);
            break;
        }
        if suite == Suite::DirectPath {
            if path.destination == Destination::Database && path.expected == Expectation::Deny {
                runner.direct(path).await;
            }
            continue;
        }
        if path.expected != Expectation::Allow {
            continue;
        }
        match suite {
            Suite::Positive => runner.positive(path).await,
            Suite::AuthNegative => runner.auth_negative(path).await,
            Suite::TlsNegative => runner.tls_negative(path).await,
            Suite::Recovery => runner.recovery(path).await,
            Suite::Performance => runner.performance(path).await,
            Suite::DirectPath => {}
        }
    }
    if runner.results.len() > config.limits.max_results
        || serde_json::to_vec(&runner.results)
            .map_err(|_| GuardError::OperationFailed)?
            .len()
            > config.limits.max_bytes
    {
        return Err(GuardError::LimitExceeded);
    }
    Ok(runner.results)
}

struct Runner<'a> {
    config: &'a TargetConfig,
    snapshot: &'a InventorySnapshot,
    options: &'a ProbeOptions,
    provider: &'a dyn TokenProvider,
    cancel: CancellationToken,
    deadline: Instant,
    results: Vec<Observation>,
}
impl Runner<'_> {
    fn stopped(&self) -> bool {
        self.cancel.is_cancelled()
            || Instant::now() >= self.deadline
            || self.results.len() >= self.config.limits.max_results
    }
    fn endpoint(&self, path: &PathSpec) -> &Endpoint {
        match path.destination {
            Destination::Database => &self.snapshot.db.as_ref().unwrap().endpoint,
            Destination::Proxy => &self.snapshot.proxy.as_ref().unwrap().endpoint,
        }
    }
    fn observation(&self, path: &PathSpec, case: &str) -> Observation {
        let verification = case.split('.').next().unwrap_or("V11");
        let mut observation = Observation::new(
            self.config,
            &self.options.run_id,
            verification,
            case,
            &path.source_id,
            &path.id,
            if self.options.local_lab {
                EvidenceKind::LocalConnection
            } else {
                EvidenceKind::AwsConnection
            },
        );
        observation.attempt_id = config::hash_bytes(
            format!("{}\0{}\0{}", self.options.run_id, path.id, case).as_bytes(),
        );
        observation.snapshot_hash = config::snapshot_hash(self.snapshot);
        observation.requirement_ids = match verification {
            "V06" => vec!["R03"],
            "V07" => vec!["R04"],
            "V08" => vec!["R06"],
            "V09" => vec!["R05", "R08"],
            "V10" => vec!["R07"],
            "V11" => vec!["R03", "R07", "R13"],
            "V13" => vec!["R10"],
            "V16" => vec!["R03", "R07", "R10"],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        observation
    }
    fn push(&mut self, o: Observation) {
        if self.results.len() < self.config.limits.max_results {
            self.results.push(o);
        }
    }
    fn interrupted(&mut self, path: &PathSpec) {
        let mut o = self.observation(path, "V11.cancellation");
        o.execution = if self.cancel.is_cancelled() {
            Execution::Cancelled
        } else {
            Execution::Timeout
        };
        o.outcome = Outcome::Interrupted;
        o.reason_code = if self.cancel.is_cancelled() {
            ReasonCode::Cancelled
        } else {
            ReasonCode::ConnectTimeout
        };
        self.push(o);
    }
    fn unsupported(&mut self, path: &PathSpec, case: &str) {
        let mut o = self.observation(path, case);
        o.reason_code = ReasonCode::UnsupportedCase;
        self.push(o);
    }
    fn failure(&mut self, path: &PathSpec, case: &str, failure: ProbeFailure, start: Instant) {
        let mut o = self.observation(path, case);
        o.duration_ms = start.elapsed().as_millis() as u64;
        o.execution = failure.execution;
        let auth_negative = case.starts_with("V07.") || case == "V10.expired_new_connection";
        let tls_negative = matches!(
            case,
            "V08.tls_disabled" | "V08.untrusted_ca" | "V08.wrong_hostname"
        );
        if (auth_negative && failure.reason == ReasonCode::DbAuthFailed)
            || (tls_negative && failure.reason == ReasonCode::TlsRejected)
        {
            o.execution = Execution::Completed;
        }
        o.path_stages = failure.stages;
        o.reason_code = failure.reason;
        o.outcome = match failure.reason {
            ReasonCode::DbAuthFailed => Outcome::AuthenticationRejected,
            ReasonCode::TlsRejected => Outcome::TlsRejected,
            ReasonCode::Cancelled => Outcome::Interrupted,
            _ => Outcome::ConnectionNotEstablished,
        };
        self.push(o);
    }
    fn successful(
        &mut self,
        path: &PathSpec,
        case: &str,
        session: &transport::Session,
        facts: Vec<Fact>,
        matched: bool,
        start: Instant,
    ) {
        let mut o = self.observation(path, case);
        o.duration_ms = start.elapsed().as_millis() as u64;
        o.execution = Execution::Completed;
        o.path_stages = session.stages.clone();
        o.outcome = if matched {
            if case == "V08.verified_client_tls" {
                Outcome::Authenticated
            } else {
                Outcome::PostconditionMatched
            }
        } else {
            Outcome::CheckViolated
        };
        o.reason_code = ReasonCode::None;
        o.facts = if matched { facts } else { vec![] };
        if matched {
            o.facts.extend([
                Fact::ChainVerified,
                Fact::HostnameVerified,
                Fact::PostconditionVerified,
            ]);
            o.facts.sort();
            o.facts.dedup();
        }
        o.details = Some(ProbeDetails {
            resolved_addresses: session.addresses.clone(),
            connection_mode: Some(path.destination),
            ..Default::default()
        });
        self.push(o);
    }
    async fn connect(
        &self,
        path: &PathSpec,
        mode: TokenMode,
        tls: TlsMode,
        user: &str,
    ) -> Result<transport::Session, ProbeFailure> {
        transport::connect(
            self.config,
            self.endpoint(path),
            path,
            self.provider,
            transport::ConnectOptions {
                token_mode: mode,
                tls_mode: tls,
                user,
                local: self.options.local_lab,
                total_deadline: self.deadline,
                cancel: &self.cancel,
            },
        )
        .await
    }
    fn long_expiry_enabled(&self) -> bool {
        self.config
            .recovery_profile
            .as_ref()
            .is_some_and(|p| p.allow_token_expiry_wait)
            && self.config.limits.total_timeout_ms >= 905_000
    }
    async fn direct(&mut self, path: &PathSpec) {
        let start = Instant::now();
        let deadline = self
            .deadline
            .min(start + Duration::from_millis(self.config.limits.connect_timeout_ms));
        match transport::tcp_probe(
            self.endpoint(path),
            path.address_family,
            self.options.local_lab,
            deadline,
            &self.cancel,
        )
        .await
        {
            Ok(addresses) => {
                let mut o = self.observation(path, "V09.application_db_transport");
                o.execution = Execution::Completed;
                o.outcome = Outcome::TcpReachable;
                o.path_stages.transport_reachable = Stage::ObservedTrue;
                o.reason_code = ReasonCode::None;
                o.duration_ms = start.elapsed().as_millis() as u64;
                o.details = Some(ProbeDetails {
                    resolved_addresses: addresses,
                    connection_mode: Some(path.destination),
                    ..Default::default()
                });
                self.push(o);
            }
            Err(failure) => self.failure(path, "V09.application_db_transport", failure, start),
        }
    }
    async fn control(&mut self, path: &PathSpec) -> Option<transport::Session> {
        let start = Instant::now();
        match self
            .connect(
                path,
                TokenMode::Valid,
                TlsMode::Verified,
                &self.config.auth.db_user,
            )
            .await
        {
            Ok(session) => {
                self.successful(
                    path,
                    "V08.verified_client_tls",
                    &session,
                    vec![Fact::ChainVerified, Fact::HostnameVerified],
                    true,
                    start,
                );
                Some(session)
            }
            Err(error) => {
                self.failure(path, "V08.verified_client_tls", error, start);
                None
            }
        }
    }
    async fn positive(&mut self, path: &PathSpec) {
        let Some(session) = self.control(path).await else {
            return;
        };
        let start = Instant::now();
        let runtime=sql::query(session.client.query_one("SELECT current_user::text,current_database()::text,current_setting('rds.force_ssl',true),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())",&[]),self.config,self.deadline,&self.cancel).await;
        match runtime {
            Ok(row) => {
                let user: String = row.get(0);
                let database: String = row.get(1);
                let matched = user == self.config.auth.db_user
                    && self
                        .config
                        .test_scope
                        .as_ref()
                        .is_none_or(|s| database == s.database);
                self.successful(
                    path,
                    "V16.protocol",
                    &session,
                    vec![Fact::ProtocolV3, Fact::TargetMatched],
                    matched,
                    start,
                );
                let force_ssl: Option<String> = row.get(2);
                let backend_tls: Option<bool> = row.get(3);
                // SQL observes this backend only. It is never substituted for client->Proxy TLS.
                if force_ssl.is_some() && backend_tls.is_some() {
                    self.successful(
                        path,
                        "V08.proxy_db_tls",
                        &session,
                        vec![Fact::RuntimeTlsRequired, Fact::BackendTlsObserved],
                        matches!(force_ssl.as_deref(), Some("on" | "1"))
                            && backend_tls == Some(true),
                        start,
                    );
                } else {
                    self.unsupported(path, "V08.proxy_db_tls");
                }
                if !matched {
                    return;
                }
            }
            Err(reason) => {
                self.failure(
                    path,
                    "V16.protocol",
                    ProbeFailure::new(reason, session.stages.clone()),
                    start,
                );
                return;
            }
        }
        if !self.options.allow_test_writes
            || self
                .config
                .test_scope
                .as_ref()
                .is_none_or(|s| s.db_user != self.config.auth.db_user)
        {
            for case in [
                "V06.insert_read",
                "V06.update_read",
                "V06.delete_read",
                "V06.commit",
                "V06.rollback",
                "V06.error_rollback",
                "V06.session_isolation",
            ] {
                self.unsupported(path, case);
            }
            return;
        }
        if self.stopped() {
            return;
        }
        let second = match self
            .connect(
                path,
                TokenMode::Valid,
                TlsMode::Verified,
                &self.config.auth.db_user,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                self.failure(path, "V06.session_isolation", e, Instant::now());
                return;
            }
        };
        let progress = sql::positive(
            &session,
            &second,
            self.config,
            &self.options.run_id,
            &path.id,
            self.deadline,
            &self.cancel,
        )
        .await;
        for case in progress.cases {
            self.successful(path, case.case, &session, case.facts, case.matched, start);
            if let Some(o) = self.results.last_mut() {
                o.details.as_mut().unwrap().retained_schema = Some(progress.schema.clone());
            }
        }
        if progress.commit_uncertain {
            // Drop the uncertain connection before reconnecting. Never issue a second write.
            drop(session);
            let mut o = self.observation(path, "V11.ambiguous_commit");
            o.outcome = Outcome::WriteOutcomeUnknown;
            o.execution = Execution::Error;
            o.reason_code = ReasonCode::WriteOutcomeUnknown;
            o.facts = vec![Fact::NoWriteReplay];
            o.details = Some(ProbeDetails {
                retained_schema: Some(progress.schema.clone()),
                ..Default::default()
            });
            if !self.stopped()
                && let Ok(fresh) = self
                    .connect(
                        path,
                        TokenMode::Valid,
                        TlsMode::Verified,
                        &self.config.auth.db_user,
                    )
                    .await
                && let Ok(true) = sql::reconcile_commit(
                    &fresh,
                    &progress.schema,
                    self.config,
                    self.deadline,
                    &self.cancel,
                )
                .await
            {
                o.execution = Execution::Completed;
                o.outcome = Outcome::PostconditionMatched;
                o.reason_code = ReasonCode::None;
                o.path_stages = fresh.stages.clone();
                o.facts.extend([
                    Fact::PostconditionVerified,
                    Fact::ChainVerified,
                    Fact::HostnameVerified,
                ]);
                o.details.as_mut().unwrap().protocol = Some(ObservationProtocol {
                    operation: Some(OperationPostcondition {
                        operation_id: format!("{}:committed-operation", progress.schema),
                        fault: Some(FaultKind::AmbiguousCommit),
                        expected_rows: 1,
                        observed_rows: 1,
                        write_attempts: 1,
                        replay_attempts: 0,
                    }),
                    ..Default::default()
                });
            }
            self.push(o);
        } else if let Some(reason) = progress.failure {
            self.failure(
                path,
                "V06.commit",
                ProbeFailure::new(reason, session.stages.clone()),
                start,
            );
            if let Some(o) = self.results.last_mut() {
                o.details = Some(ProbeDetails {
                    retained_schema: Some(progress.schema.clone()),
                    ..Default::default()
                });
            }
            return;
        }
        if self.stopped() {
            return;
        }
        let reset_start = Instant::now();
        match sql::reset_session(&second, self.config, self.deadline, &self.cancel).await {
            Ok(matched) => self.successful(
                path,
                "V16.pool_reset",
                &second,
                vec![Fact::PoolResetVerified],
                matched,
                reset_start,
            ),
            Err(reason) => {
                self.failure(
                    path,
                    "V16.pool_reset",
                    ProbeFailure::new(reason, second.stages.clone()),
                    reset_start,
                );
                return;
            }
        }
        if let Some(profile) = &self.config.recovery_profile {
            let long_start = Instant::now();
            match sql::long_transaction(
                &second,
                profile.long_transaction_ms,
                self.config,
                self.deadline,
                &self.cancel,
            )
            .await
            {
                Ok(matched) => self.successful(
                    path,
                    "V16.long_transaction",
                    &second,
                    vec![Fact::LongTransactionVerified],
                    matched,
                    long_start,
                ),
                Err(reason) => self.failure(
                    path,
                    "V16.long_transaction",
                    ProbeFailure::new(reason, second.stages.clone()),
                    long_start,
                ),
            }
        } else {
            self.unsupported(path, "V16.long_transaction");
        }
        self.unsupported(path, "V16.pinning");
    }
    async fn auth_negative(&mut self, path: &PathSpec) {
        let Some(control) = self.control(path).await else {
            return;
        };
        drop(control);
        for (case, mode) in [
            ("V07.missing_auth", TokenMode::Missing),
            ("V07.bad_signature", TokenMode::BadSignature),
            ("V07.expired_new_connection", TokenMode::Expired),
        ] {
            if self.stopped() {
                self.interrupted(path);
                return;
            }
            if mode == TokenMode::Expired && !self.long_expiry_enabled() {
                self.unsupported(path, case);
                continue;
            }
            let start = Instant::now();
            match self
                .connect(path, mode, TlsMode::Verified, &self.config.auth.db_user)
                .await
            {
                Ok(session) => self.successful(path, case, &session, vec![], false, start),
                Err(failure) => {
                    let attempted = failure.stages.db_authenticated == Stage::ObservedFalse;
                    self.failure(path, case, failure, start);
                    if mode == TokenMode::Expired
                        && attempted
                        && let Some(o) = self.results.last_mut()
                    {
                        o.facts.push(Fact::ExpiredTokenUsed);
                    }
                }
            }
        }
        // Different principals/users require a pre-authorized negative actor; never invent a DB username.
        if self.stopped() {
            return;
        }
        if let Some(profile) = self
            .config
            .auth_negative
            .as_ref()
            .and_then(|p| p.unauthorized_aws_profile.clone())
        {
            if self.options.local_lab {
                self.unsupported(path, "V07.unauthorized_principal");
            } else {
                let provider = auth::AwsCliTokenProvider {
                    region: self.config.target.region.clone(),
                    profile: Some(profile),
                };
                let start = Instant::now();
                match transport::connect(
                    self.config,
                    self.endpoint(path),
                    path,
                    &provider,
                    transport::ConnectOptions {
                        token_mode: TokenMode::Valid,
                        tls_mode: TlsMode::Verified,
                        user: &self.config.auth.db_user,
                        local: false,
                        total_deadline: self.deadline,
                        cancel: &self.cancel,
                    },
                )
                .await
                {
                    Ok(session) => self.successful(
                        path,
                        "V07.unauthorized_principal",
                        &session,
                        vec![],
                        false,
                        start,
                    ),
                    Err(failure) => {
                        self.failure(path, "V07.unauthorized_principal", failure, start)
                    }
                }
            }
        } else {
            self.unsupported(path, "V07.unauthorized_principal");
        }
        if let Some(user) = self
            .config
            .auth_negative
            .as_ref()
            .and_then(|p| p.unauthorized_db_user.clone())
        {
            let start = Instant::now();
            match self
                .connect(path, TokenMode::Valid, TlsMode::Verified, &user)
                .await
            {
                Ok(session) => self.successful(
                    path,
                    "V07.unauthorized_user",
                    &session,
                    vec![],
                    false,
                    start,
                ),
                Err(failure) => self.failure(path, "V07.unauthorized_user", failure, start),
            }
        } else {
            self.unsupported(path, "V07.unauthorized_user");
        }
    }
    async fn tls_negative(&mut self, path: &PathSpec) {
        let Some(control) = self.control(path).await else {
            return;
        };
        drop(control);
        for (case, tls) in [
            ("V08.tls_disabled", TlsMode::Disabled),
            ("V08.untrusted_ca", TlsMode::UntrustedCa),
            ("V08.wrong_hostname", TlsMode::WrongHostname),
        ] {
            if self.stopped() {
                self.interrupted(path);
                return;
            }
            let start = Instant::now();
            match self
                .connect(path, TokenMode::Valid, tls, &self.config.auth.db_user)
                .await
            {
                Ok(session) => self.successful(path, case, &session, vec![], false, start),
                Err(failure) => self.failure(path, case, failure, start),
            }
        }
    }
    async fn recovery(&mut self, path: &PathSpec) {
        let Some(initial) = self.control(path).await else {
            return;
        };
        initial.close();
        if self.stopped() {
            self.interrupted(path);
            return;
        }
        let start = Instant::now();
        match self
            .connect(
                path,
                TokenMode::Valid,
                TlsMode::Verified,
                &self.config.auth.db_user,
            )
            .await
        {
            Ok(session) => {
                self.successful(
                    path,
                    "V11.disconnect",
                    &session,
                    vec![Fact::NoWriteReplay],
                    true,
                    start,
                );
                if !self.options.local_lab {
                    self.successful(
                        path,
                        "V10.new_token",
                        &session,
                        vec![Fact::TokenRefreshed],
                        true,
                        start,
                    );
                } else {
                    self.unsupported(path, "V10.new_token");
                }
            }
            Err(failure) => self.failure(path, "V11.disconnect", failure, start),
        }
        if !self.stopped() {
            self.read_fault(path, false).await;
        }
        if !self.stopped() {
            self.read_fault(path, true).await;
        }
        if self.long_expiry_enabled() && !self.options.local_lab && !self.stopped() {
            self.expiry_trial(path).await;
        } else {
            for case in ["V10.expired_new_connection", "V10.existing_after_expiry"] {
                self.unsupported(path, case);
            }
        }
        for case in [
            "V10.aws_credential_expiry",
            "V11.dns_failure",
            "V11.unreachable",
            "V11.ambiguous_commit",
        ] {
            self.unsupported(path, case);
        }
    }
    async fn read_fault(&mut self, path: &PathSpec, cancellation: bool) {
        let case = if cancellation {
            "V11.cancellation"
        } else {
            "V11.deadline"
        };
        let start = Instant::now();
        let session = match self
            .connect(
                path,
                TokenMode::Valid,
                TlsMode::Verified,
                &self.config.auth.db_user,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                self.failure(path, case, e, start);
                return;
            }
        };
        let child = self.cancel.child_token();
        let trigger = if cancellation {
            let child = child.clone();
            Some(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                child.cancel();
            }))
        } else {
            None
        };
        let deadline = if cancellation {
            self.deadline
        } else {
            self.deadline
                .min(Instant::now() + Duration::from_millis(10))
        };
        let fault = sql::sleep_read(&session, self.config, deadline, &child).await;
        drop(session);
        if let Some(trigger) = trigger {
            trigger.abort();
        }
        let expected = if cancellation {
            ReasonCode::Cancelled
        } else {
            ReasonCode::QueryTimeout
        };
        if fault != Err(expected) {
            self.unsupported(path, case);
            return;
        }
        // Cancellation was a deliberate child fault. A cancellation of the run itself forbids recovery work.
        if self.stopped() {
            self.interrupted(path);
            return;
        }
        match self
            .connect(
                path,
                TokenMode::Valid,
                TlsMode::Verified,
                &self.config.auth.db_user,
            )
            .await
        {
            Ok(fresh) => {
                let verified = sql::query(
                    fresh.client.query_one("SELECT 1::integer", &[]),
                    self.config,
                    self.deadline,
                    &self.cancel,
                )
                .await
                .is_ok_and(|row| row.get::<_, i32>(0) == 1);
                self.successful(
                    path,
                    case,
                    &fresh,
                    vec![
                        if cancellation {
                            Fact::CancellationRespected
                        } else {
                            Fact::DeadlineRespected
                        },
                        Fact::NoWriteReplay,
                    ],
                    verified,
                    start,
                );
                if verified
                    && let Some(details) = self.results.last_mut().and_then(|o| o.details.as_mut())
                {
                    details.protocol = Some(ObservationProtocol {
                        operation: Some(OperationPostcondition {
                            operation_id: config::hash_bytes(
                                format!("{}:{case}", self.options.run_id).as_bytes(),
                            ),
                            fault: Some(if cancellation {
                                FaultKind::Cancellation
                            } else {
                                FaultKind::Deadline
                            }),
                            expected_rows: 1,
                            observed_rows: 1,
                            write_attempts: 0,
                            replay_attempts: 0,
                        }),
                        ..Default::default()
                    });
                }
            }
            Err(failure) => self.failure(path, case, failure, start),
        }
    }
    async fn expiry_trial(&mut self, path: &PathSpec) {
        let start = Instant::now();
        let token = match transport::bounded(
            self.provider.token(
                self.endpoint(path),
                &self.config.auth.db_user,
                TokenMode::Valid,
            ),
            self.deadline,
            &self.cancel,
            ReasonCode::ConnectTimeout,
        )
        .await
        {
            Ok(Ok(token)) => token,
            _ => {
                self.unsupported(path, "V10.existing_after_expiry");
                return;
            }
        };
        let held = auth::HeldTokenProvider::new(token);
        let session = match transport::connect(
            self.config,
            self.endpoint(path),
            path,
            &held,
            transport::ConnectOptions {
                token_mode: TokenMode::Valid,
                tls_mode: TlsMode::Verified,
                user: &self.config.auth.db_user,
                local: false,
                total_deadline: self.deadline,
                cancel: &self.cancel,
            },
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                self.failure(path, "V10.existing_after_expiry", e, start);
                return;
            }
        };
        if let Err(reason) = transport::bounded(
            tokio::time::sleep(Duration::from_secs(901)),
            self.deadline,
            &self.cancel,
            ReasonCode::QueryTimeout,
        )
        .await
        {
            self.failure(
                path,
                "V10.existing_after_expiry",
                ProbeFailure::new(reason, session.stages.clone()),
                start,
            );
            return;
        }
        match sql::query(
            session.client.query_one("SELECT 1::integer", &[]),
            self.config,
            self.deadline,
            &self.cancel,
        )
        .await
        {
            Ok(row) => self.successful(
                path,
                "V10.existing_after_expiry",
                &session,
                vec![Fact::ExistingSessionAfterExpiry],
                row.get::<_, i32>(0) == 1,
                start,
            ),
            Err(reason) => self.failure(
                path,
                "V10.existing_after_expiry",
                ProbeFailure::new(reason, session.stages.clone()),
                start,
            ),
        }
        if self.stopped() {
            return;
        }
        let start = Instant::now();
        match transport::connect(
            self.config,
            self.endpoint(path),
            path,
            &held,
            transport::ConnectOptions {
                token_mode: TokenMode::Valid,
                tls_mode: TlsMode::Verified,
                user: &self.config.auth.db_user,
                local: false,
                total_deadline: self.deadline,
                cancel: &self.cancel,
            },
        )
        .await
        {
            Ok(fresh) => self.successful(
                path,
                "V10.expired_new_connection",
                &fresh,
                vec![Fact::ExpiredTokenUsed],
                false,
                start,
            ),
            Err(failure) => {
                let attempted = failure.stages.db_authenticated == Stage::ObservedFalse;
                self.failure(path, "V10.expired_new_connection", failure, start);
                if attempted && let Some(o) = self.results.last_mut() {
                    o.facts.push(Fact::ExpiredTokenUsed);
                }
            }
        }
    }
    async fn performance(&mut self, path: &PathSpec) {
        let Some(profile) = self.config.performance_profile.as_ref() else {
            self.unsupported(path, "V13.bounded_samples");
            return;
        };
        if profile.workload_id != "fixed-select-v1" {
            self.unsupported(path, "V13.bounded_samples");
            return;
        }
        let Some(session) = self.control(path).await else {
            return;
        };
        let engine_version = match sql::query(
            session
                .client
                .query_one("SELECT current_setting('server_version')", &[]),
            self.config,
            self.deadline,
            &self.cancel,
        )
        .await
        {
            Ok(row) => row.get::<_, String>(0),
            Err(reason) => {
                self.failure(
                    path,
                    "V13.bounded_samples",
                    ProbeFailure::new(reason, session.stages.clone()),
                    Instant::now(),
                );
                return;
            }
        };
        let mut connection_samples = Vec::new();
        let mut samples = Vec::new();
        let mut errors = 0;
        let mut connection_errors = 0;
        for index in 0..profile.warmup.saturating_add(profile.samples) {
            if self.stopped() {
                self.interrupted(path);
                break;
            }
            let start = Instant::now();
            let result = sql::query(
                session.client.query_one("SELECT 1::integer", &[]),
                self.config,
                self.deadline,
                &self.cancel,
            )
            .await;
            match result {
                Ok(row) if row.get::<_, i32>(0) == 1 => {
                    if index >= profile.warmup {
                        samples.push(start.elapsed().as_millis() as u64);
                    }
                }
                _ => {
                    errors += 1;
                    break;
                }
            }
            if self.stopped() {
                break;
            }
            let start = Instant::now();
            match self
                .connect(
                    path,
                    TokenMode::Valid,
                    TlsMode::Verified,
                    &self.config.auth.db_user,
                )
                .await
            {
                Ok(fresh) => {
                    if index >= profile.warmup {
                        connection_samples.push(start.elapsed().as_millis() as u64);
                    }
                    drop(fresh);
                }
                Err(_) => {
                    connection_errors += 1;
                    break;
                }
            }
        }
        for (case, data, count) in [
            ("V13.pooled_query", samples, errors),
            (
                "V13.connection_setup",
                connection_samples,
                connection_errors,
            ),
        ] {
            let mut o = self.observation(path, case);
            o.execution = Execution::Completed;
            o.path_stages = session.stages.clone();
            o.outcome = Outcome::Measured;
            o.reason_code = ReasonCode::None;
            o.details = Some(performance::summarize(
                data,
                count,
                path.destination,
                &profile.workload_id,
            ));
            o.details.as_mut().unwrap().protocol = Some(ObservationProtocol {
                measurement: Some(MeasurementConditions {
                    workload_id: profile.workload_id.clone(),
                    workload_hash: config::hash_bytes(b"SELECT 1::integer"),
                    driver_version: performance::driver_version(),
                    db_resource_id: self.snapshot.db.as_ref().unwrap().resource_id.clone(),
                    db_instance_class: self.snapshot.db.as_ref().unwrap().instance_class.clone(),
                    availability_zone: self.snapshot.db.as_ref().unwrap().availability_zone.clone(),
                    runner_os: Some(std::env::consts::OS.into()),
                    runner_arch: Some(std::env::consts::ARCH.into()),
                    runner_identity_hash: None,
                    engine_version: engine_version.clone(),
                    db_user: self.config.auth.db_user.clone(),
                    concurrency: 1,
                    warmup: profile.warmup,
                    retries: 0,
                    tls_verified: true,
                    kind: if case == "V13.connection_setup" {
                        MeasurementKind::ConnectionSetup
                    } else {
                        MeasurementKind::PooledQuery
                    },
                    pinning: None,
                }),
                ..Default::default()
            });
            self.push(o);
        }
        let complete = self
            .results
            .iter()
            .filter(|o| {
                o.path_id == path.id
                    && matches!(
                        o.case_id.as_str(),
                        "V13.pooled_query" | "V13.connection_setup"
                    )
            })
            .all(|o| {
                o.details
                    .as_ref()
                    .is_some_and(|d| d.sample_count == profile.samples)
            });
        let detail = self
            .results
            .iter()
            .find(|o| o.path_id == path.id && o.case_id == "V13.pooled_query")
            .and_then(|o| o.details.clone());
        let mut bounded = self.observation(path, "V13.bounded_samples");
        bounded.execution = if self.stopped() {
            Execution::Timeout
        } else {
            Execution::Completed
        };
        bounded.outcome = if complete {
            Outcome::Measured
        } else {
            Outcome::Unsupported
        };
        bounded.reason_code = if complete {
            ReasonCode::None
        } else {
            ReasonCode::MissingEvidence
        };
        bounded.path_stages = session.stages.clone();
        bounded.facts = vec![Fact::SamplesBounded];
        bounded.details = detail;
        self.push(bounded);
        let attempts = self
            .results
            .iter()
            .filter(|o| {
                o.path_id == path.id
                    && matches!(
                        o.case_id.as_str(),
                        "V13.connection_setup" | "V13.pooled_query"
                    )
            })
            .filter_map(|o| o.details.as_ref())
            .map(|d| d.sample_count)
            .sum::<usize>();
        let acceptable = attempts > 0
            && (errors + connection_errors) as f64 / attempts as f64 <= profile.max_error_rate;
        self.successful(
            path,
            "V13.errors",
            &session,
            vec![Fact::SamplesBounded],
            acceptable,
            Instant::now(),
        );
        self.unsupported(path, "V13.pinning");
    }
}
