//! Exact-layout fixtures, NOT actual NativeBaselineLease/USER/kernel proof.
use super::*;
use crate::allocation_probe;

struct FortyEightByteFixtureLease([usize; 6]);
struct FortyEightByteFixtureAdmission;
impl RegistryAdmission for FortyEightByteFixtureAdmission {
    type Lease = FortyEightByteFixtureLease;
    fn try_reserve(&self, bytes: usize, cells: usize) -> Result<Self::Lease, RegistryError> {
        Ok(FortyEightByteFixtureLease([bytes, cells, 0, 0, 0, 0]))
    }
}
#[repr(align(64))]
struct AlignedFixtureLease([u8; 65]);
struct AlignedFixtureAdmission;
impl RegistryAdmission for AlignedFixtureAdmission {
    type Lease = AlignedFixtureLease;
    fn try_reserve(&self, _: usize, _: usize) -> Result<Self::Lease, RegistryError> {
        Ok(AlignedFixtureLease([0; 65]))
    }
}
fn maximal<A: RegistryAdmission>(limits: RegistryPoolLimits) {
    let plan = RegistryPool::derive_directory_plan::<A>(limits).unwrap();
    let layout = plan.layout();
    assert_eq!(layout.cells, plan.pool_limits().cells);
    assert_eq!(layout.heads, layout.cells);
    assert_eq!(layout.key_bytes, plan.directory_limits().key_bytes);
    assert!(layout.mapped_bytes <= limits.bytes);
    assert_eq!(layout.mapped_bytes % layout.page_bytes, 0);
    let increased = RegistryPoolLayout::combined::<A::Lease>(
        plan.pool_limits(),
        Some(RegistryDirectoryLimits {
            heads: layout.heads,
            key_bytes: layout.key_bytes + 1,
        }),
    );
    assert!(
        increased.is_err() || increased.unwrap().cells < layout.cells,
        "K must be MAXIMUM for the chosen actual C"
    );
    if layout.cells < limits.cells {
        let next_cells = layout.cells + 1;
        let larger = RegistryPoolLayout::combined::<A::Lease>(
            RegistryPoolLimits {
                cells: next_cells,
                ..limits
            },
            Some(RegistryDirectoryLimits {
                heads: next_cells,
                key_bytes: 0,
            }),
        );
        assert!(
            larger.is_err() || larger.unwrap().cells < next_cells,
            "C must be MAXIMUM before choosing K"
        );
    }
}
#[test]
fn sql_registry_derived_plan_maximizes_actual_cells_then_exact_remaining_key_bytes_no_heap() {
    for bytes in [
        64 * 1024,
        128 * 1024 + 91,
        1024 * 1024,
        16 * 1024 * 1024 - 8193,
        16 * 1024 * 1024,
    ] {
        let limits = RegistryPoolLimits { bytes, cells: 256 };
        let (result, operations, allocated) = allocation_probe::measure(|| {
            RegistryPool::derive_directory_plan::<FortyEightByteFixtureAdmission>(limits)
        });
        let layout = result.unwrap().layout();
        assert_eq!((operations, allocated), (0, 0));
        assert_eq!(
            layout.lease_bytes,
            std::mem::size_of::<FortyEightByteFixtureLease>()
        );
        assert_eq!(layout.lease_bytes, 48);
        maximal::<FortyEightByteFixtureAdmission>(limits);
        maximal::<AlignedFixtureAdmission>(limits);
    }
}
#[test]
fn sql_registry_derived_plan_lower_byte_limits_never_advertise_unbacked_heads_or_cells() {
    let limits = RegistryPoolLimits {
        bytes: 64 * 1024,
        cells: 256,
    };
    let plan =
        RegistryPool::derive_directory_plan::<FortyEightByteFixtureAdmission>(limits).unwrap();
    assert!(plan.layout().cells < 256);
    assert_eq!(plan.layout().heads, plan.layout().cells);
    let expected = plan.layout();
    let pool = RegistryPool::admit_directory_plan(&FortyEightByteFixtureAdmission, plan, || Ok(()))
        .unwrap();
    assert_eq!(pool.capacity(), expected.cells);
    assert_eq!(pool.mapped_bytes(), expected.mapped_bytes);
    assert_eq!(
        pool.header().directory_layout.unwrap().heads,
        expected.heads
    );
    assert_eq!(
        pool.header().directory_layout.unwrap().key_bytes,
        expected.key_bytes
    );
    let directory = pool.directory().unwrap();
    directory.prepare_store_native(1).unwrap();
    directory.ready_store_native(1).unwrap();
    directory.retire_store_native(1).unwrap();
}
#[test]
fn sql_registry_derived_plan_invalid_or_insufficient_dimensions_refuse_without_fake_zero_room() {
    for limits in [
        RegistryPoolLimits { bytes: 0, cells: 1 },
        RegistryPoolLimits {
            bytes: 16 * 1024 * 1024 + 1,
            cells: 1,
        },
        RegistryPoolLimits {
            bytes: 16 * 1024 * 1024,
            cells: 0,
        },
        RegistryPoolLimits {
            bytes: 16 * 1024 * 1024,
            cells: 257,
        },
    ] {
        assert!(matches!(
            RegistryPool::derive_directory_plan::<FortyEightByteFixtureAdmission>(limits),
            Err(RegistryError::Invalid)
        ));
    }
    assert!(matches!(
        RegistryPool::derive_directory_plan::<FortyEightByteFixtureAdmission>(RegistryPoolLimits {
            bytes: 4096,
            cells: 256
        }),
        Err(RegistryError::Capacity)
    ));
}
