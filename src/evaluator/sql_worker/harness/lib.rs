#![allow(dead_code)]
mod sqlite {
    include!(concat!(env!("OUT_DIR"), "/error.rs"));
}
#[path = "../../sql_control.rs"]
mod sql_control;
#[path = "../../sql_worker.rs"]
mod sql_worker;

#[cfg(feature = "mimalloc-probe")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
