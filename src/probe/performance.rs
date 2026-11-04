use crate::domain::*;

pub fn driver_version() -> String {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"));
    for package in lock.split("[[package]]") {
        if package
            .lines()
            .any(|line| line == "name = \"tokio-postgres\"")
            && let Some(version) = package.lines().find_map(|line| {
                line.strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
            && !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return format!("tokio-postgres:{version}");
        }
    }
    "tokio-postgres:unknown".into()
}

/// Nearest-rank empirical quantiles. Tail estimates require enough observations in that tail.
pub fn summarize(
    samples: Vec<u64>,
    errors: usize,
    destination: Destination,
    workload: &str,
) -> ProbeDetails {
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let quantile = |percent: usize, minimum: usize| -> Option<u64> {
        if sorted.len() < minimum {
            return None;
        }
        let rank = (sorted.len() * percent).div_ceil(100).saturating_sub(1);
        sorted.get(rank).copied()
    };
    ProbeDetails {
        sample_count: samples.len() + errors,
        samples_ms: samples,
        error_count: errors,
        p50_ms: quantile(50, 2),
        p95_ms: quantile(95, 20),
        p99_ms: quantile(99, 100),
        connection_mode: Some(destination),
        workload_id: Some(workload.into()),
        ..Default::default()
    }
}
