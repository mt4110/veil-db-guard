//! Fixed GCE/EC2 host-network source profiles. No installation or cloud mutation.
pub mod aws;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod aws_host;
mod aws_iid;
pub mod aws_mysql;
pub(crate) mod aws_native;
pub mod aws_postgres;
pub mod aws_runtime_cutover;
mod collector;
pub mod execution;
pub mod gce_host;
mod jwt;
pub mod native_gate;
pub mod postgres;
mod postgres_login;
mod postgres_native;
pub(crate) use postgres_native::{bootstrap_runtime_connector, recheck_runtime_connector};
mod process;
pub mod requests;
pub mod state;
pub mod support;
pub use collector::{read_local_context, run_collector_stdio};
#[cfg(test)]
mod testsupport;

pub mod deferred_route;
mod denial;
pub(crate) mod iam_inventory;

mod backend_tls;

pub mod route_denial;

pub mod origin;
pub mod runtime;
pub mod runtime_unix;
pub mod runtime_witness;

mod aws_iam_inventory;

#[cfg(all(test, target_os = "linux"))]
mod runtime_checkout_test;
