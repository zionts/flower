pub mod consensus;
pub(crate) mod crypto;
pub mod evaluator;
pub mod service;

pub mod telemetry;
pub mod transport;

#[cfg(all(test, feature = "sql"))]
pub(crate) mod allocation_probe;
#[cfg(all(test, feature = "sql"))]
#[global_allocator]
static SQL_TEST_ALLOCATOR: allocation_probe::Allocator = allocation_probe::Allocator;
