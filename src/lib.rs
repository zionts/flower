pub mod consensus;
pub(crate) mod crypto;
pub mod evaluator;
pub mod service;
pub(crate) mod sql_commit;

pub mod telemetry;
pub mod transport;

#[cfg(test)]
pub(crate) mod allocation_probe;
#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: allocation_probe::Allocator = allocation_probe::Allocator;
