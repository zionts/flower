#![allow(dead_code, unexpected_cfgs, unused_imports)]
// Independent-only entry point; no root Cargo/shared file changes required.
#[path = "../../evaluator/sql_frame.rs"]
pub(crate) mod sql_frame;
#[path = "../../evaluator/sqlite/mod.rs"]
mod sqlite;
mod evaluator {
    pub(crate) use crate::sql_frame;
}
#[path = "../sql_managed.rs"]
mod sql_managed;
#[cfg(test)]
mod ordinary_reference {
    include!(concat!(env!("OUT_DIR"), "/ordinary_reference.rs"));
}

#[cfg(test)]
#[path = "../../allocation_probe.rs"]
pub(crate) mod allocation_probe;
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: allocation_probe::Allocator = allocation_probe::Allocator;
