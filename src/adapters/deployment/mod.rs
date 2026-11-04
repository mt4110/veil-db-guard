//! Native deployment executors. Provider ports are trusted Rust code, never
//! receipt or command payloads deserialized from an operator's file.
pub mod gcp;

pub mod aws;
