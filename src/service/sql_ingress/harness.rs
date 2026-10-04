#![allow(dead_code)]
#[path = "../../allocation_probe.rs"]
mod allocation_probe;
#[global_allocator]
static ALLOCATOR: allocation_probe::Allocator = allocation_probe::Allocator;
#[path = "../sql_ingress.rs"]
mod sql_ingress;

mod evaluator {
    pub(crate) mod metadata_reference {
        include!(env!("SQL_INGRESS_REFERENCE"));
    }
}
