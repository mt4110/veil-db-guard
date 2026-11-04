//! Offline K10 -> K11 work handoff. It creates no approval or dispatch ticket.
use crate::{
    adapters::{evidence::RunEvidenceArchive, source},
    config::GuardError,
    core::k11_handoff,
    domain::now,
    evidence_store::EvidenceStore,
    store::{RunStatus, RunWriter},
};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct K11ReadinessArgs {
    #[arg(long)]
    plan_run: PathBuf,
    #[arg(long, requires_all=["context","archive"])]
    ledger: Option<PathBuf>,
    #[arg(long, requires_all=["ledger","archive"])]
    context: Option<String>,
    #[arg(long, requires_all=["ledger","context"])]
    archive: Option<PathBuf>,
    #[arg(long = "request", requires = "archive")]
    requests: Vec<String>,
    #[arg(long)]
    out: PathBuf,
}
pub(crate) fn execute(args: K11ReadinessArgs) -> Result<i32, GuardError> {
    let change = crate::guard_cli::load_change_run(&args.plan_run)?;
    if change.policy.schema_version != 2 {
        return Err(GuardError::EvidenceIncompatible);
    }
    let at = now();
    let qualification = crate::qualification_cli::report(&change)?;
    let state = if let (Some(path), Some(context), Some(archive)) =
        (&args.ledger, &args.context, &args.archive)
    {
        let mut ledger = EvidenceStore::open_existing(path)?;
        if ledger.context_change(context)?.change_hash != change.change_hash {
            return Err(GuardError::EvidenceIncompatible);
        }
        let archive = RunEvidenceArchive::open(archive)?;
        source::state::read_local(&mut ledger, &archive, &change, context, &args.requests, at)?
    } else {
        source::state::empty(&change, "k11-design-handoff", at)?
    };
    let mut handoff = k11_handoff::prepare(&change, &state.effective, at)
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    if !qualification.is_qualified() {
        // Do not label a statically unsupported selected change ready merely
        // because its generic source/evaluation shape can be represented.
        handoff.k11_implementation_can_start = false;
    }
    let code = if handoff.k11_implementation_can_start {
        0
    } else {
        3
    };
    let mut run = RunWriter::create_for_config(
        &args.out,
        &change.policy.policy_id,
        &change.policy,
        "guard-k11-handoff",
        8 * 1024 * 1024,
        true,
    )?;
    run.write_json("k11-handoff.json", &handoff)?;
    run.write_json("source-state.json", &state)?;
    run.write_json("intent-qualification.json", &qualification)?;
    let text = format!(
        "# K11 implementation handoff\n\nIntegration contract compatible: {}. This is implementation planning, not native execution readiness or proof of current protection.\n\nPolicy: {}\nChange: {}\nRuntime binding requirements: {}\nUnsatisfied native effects: {}\n\nNo native queries, approval, dispatch, or desired-head changes. Unknown and historical evidence remain insufficient for closure.\n",
        handoff.k11_implementation_can_start,
        handoff.policy_revision_hash,
        handoff.change_hash,
        handoff.runtime_requirements.len(),
        handoff.native_closure_gaps.len()
    );
    run.write_bytes("report.md", text.as_bytes())?;
    run.finish(RunStatus::Complete)?;
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"handoff":handoff,"intent_qualification":qualification,"source_coverage":state.source_coverage,"native_queries_performed":false,"native_dispatch_available":false})).map_err(|_|GuardError::StorageFailed)?);
    Ok(code)
}
