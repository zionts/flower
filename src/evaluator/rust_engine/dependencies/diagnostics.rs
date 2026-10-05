//! Default-off, bounded observations of already rejected mutation certificates.
//! This module has no authority to accept or repair a candidate.
use super::*;
use serde::Serialize;
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

const MAX_NAMES: usize = 16;
const MAX_NAME_BYTES: usize = 64;
const DEFAULT_CHECKS: usize = 4096;
const MAX_CHECKS: usize = 65_536;
const DEFAULT_EVENTS: usize = 1000;
const MAX_EVENTS: usize = 10_000;
const TARGET: &str = "flower::conflicts";

struct Name {
    name: String,
    first_component: String,
    scalar: String,
}
impl Name {
    fn matches(&self, id: &str) -> bool {
        // Only inspect a bounded prefix; never parse/copy arguments or row keys.
        // Names have no JSON escapes, so generated identities match exactly.
        [
            "source:",
            "cell:",
            "index-entries:",
            "index-range:",
            "index-bucket:",
        ]
        .iter()
        .any(|prefix| {
            id.strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with(&self.first_component))
        }) || ["collection:", "keys:"].iter().any(|prefix| {
            id.strip_prefix(prefix)
                .is_some_and(|tail| tail == self.scalar)
        })
    }
}
struct Config {
    names: Vec<Name>,
    max_checks: usize,
    max_events: usize,
    events: AtomicUsize,
}
impl Config {
    fn parse(names: &str, checks: Option<&str>, events: Option<&str>) -> Option<Self> {
        if names.len() > MAX_NAMES * (MAX_NAME_BYTES + 1) {
            return None;
        }
        let mut configured: Vec<Name> = Vec::new();
        if !names.is_empty() {
            for name in names.split(',') {
                if name.is_empty()
                    || name.len() > MAX_NAME_BYTES
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || configured.len() == MAX_NAMES
                    || configured.iter().any(|known| known.name == name)
                {
                    return None;
                }
                configured.push(Name {
                    name: name.into(),
                    first_component: format!("[\"{name}\","),
                    scalar: format!("\"{name}\""),
                });
            }
        }
        fn bound(value: Option<&str>, default: usize, max: usize) -> Option<usize> {
            let value = value.map_or(Some(default), |text| {
                (text.len() <= 8)
                    .then(|| text.parse::<usize>().ok())
                    .flatten()
            })?;
            (1..=max).contains(&value).then_some(value)
        }
        Some(Self {
            names: configured,
            max_checks: bound(checks, DEFAULT_CHECKS, MAX_CHECKS)?,
            max_events: bound(events, DEFAULT_EVENTS, MAX_EVENTS)?,
            events: AtomicUsize::new(0),
        })
    }
    fn from_env() -> Option<Self> {
        if std::env::var("FLOWER_CONFLICT_DIAGNOSTICS").ok().as_deref() != Some("1") {
            return None;
        }
        // Invalid/unicode configuration fails closed. Never echo supplied text.
        let get = |key| match std::env::var(key) {
            Ok(value) => Some(Some(value)),
            Err(std::env::VarError::NotPresent) => Some(None),
            Err(_) => None,
        };
        let names = get("FLOWER_CONFLICT_DIAGNOSTICS_NAMES")?;
        let checks = get("FLOWER_CONFLICT_DIAGNOSTICS_MAX_CHECKS")?;
        let events = get("FLOWER_CONFLICT_DIAGNOSTICS_MAX_EVENTS")?;
        Self::parse(
            names.as_deref().unwrap_or(""),
            checks.as_deref(),
            events.as_deref(),
        )
    }
    fn reserve_event(&self) -> Option<usize> {
        let mut count = self.events.load(Ordering::Relaxed);
        while count < self.max_events {
            // Strong CAS: every retry observes real monotonic progress, and
            // the counter cannot advance past the finite allowance.
            match self.events.compare_exchange(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(count + 1),
                Err(current) => count = current,
            }
        }
        None
    }
}

struct Budget {
    inspected: usize,
    limit: usize,
    truncated: bool,
}
impl Budget {
    fn inspect(&mut self) -> Option<()> {
        if self.inspected == self.limit {
            self.truncated = true;
            return None;
        }
        self.inspected += 1;
        Some(())
    }
}

#[derive(Clone, Copy)]
enum Family {
    SourceRecord,
    CellRecord,
    OtherRecord,
    Marker,
    Window,
}

#[derive(Default, Serialize)]
struct Families {
    source_record: usize,
    cell_record: usize,
    other_record: usize,
    marker: usize,
    window: usize,
    invalid_depth: usize,
    invalid_source_ids: usize,
    invalid_graph_pointer: usize,
    invalid_reactive_index: usize,
    invalid_clock: usize,
    graph_shape: usize,
    clock_bound: usize,
}
impl Families {
    fn non_cell(&self) -> usize {
        self.source_record
            + self.other_record
            + self.marker
            + self.window
            + self.invalid_depth
            + self.invalid_source_ids
            + self.invalid_graph_pointer
            + self.invalid_reactive_index
            + self.invalid_clock
            + self.graph_shape
            + self.clock_bound
    }
}
#[derive(Default, Serialize)]
struct Named<'a> {
    name: &'a str,
    source_record: usize,
    cell_record: usize,
    marker: usize,
    window: usize,
}
#[derive(Serialize)]
struct Report<'a> {
    version: u8,
    diagnostic_only: bool,
    claim: &'static str,
    event: usize,
    event_limit: usize,
    event_limit_reached: bool,
    check_limit: usize,
    checks_inspected: usize,
    dependency_checks_total: usize,
    dependency_checks_inspected: usize,
    truncated: bool,
    window_marker_unavailable: bool,
    ignoring_all_cell_versions_upper_bound: &'static str,
    mismatches: Families,
    names: Vec<Named<'a>>,
}
impl Report<'_> {
    fn emit(&self) {
        // No ambient request span, raw identity, method, error or payload field.
        // Only these explicitly serialized fields are written, not Debug(self).
        tracing::debug!(target: TARGET, parent: None,
            "flower_conflict_diagnostic {}", serde_json::to_string(self).expect("diagnostic fields"));
    }
}

impl MutationCertificate {
    pub(crate) fn log_conflicts(&self, data: &Records) {
        static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
        let Some(config) = CONFIG.get_or_init(Config::from_env) else {
            return;
        };
        if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            return;
        }
        let Some(event) = config.reserve_event() else {
            return;
        };
        self.conflicts(data, config, event).emit();
    }

    fn conflicts<'a>(&self, data: &Records, config: &'a Config, event: usize) -> Report<'a> {
        let mut budget = Budget {
            inspected: 0,
            limit: config.max_checks,
            truncated: false,
        };
        let mut mismatches = Families::default();
        // The same state predicates as valid_records and valid, without &&.
        // Each is individually charged, even after another has failed.
        macro_rules! inspect {
            ($field:ident, $valid:expr) => {
                if budget.inspect().is_some() && !$valid {
                    mismatches.$field += 1;
                }
            };
        }
        inspect!(invalid_depth, data.has_valid_depth());
        inspect!(invalid_source_ids, data.has_valid_source_ids());
        inspect!(invalid_graph_pointer, data.has_valid_graph_pointer());
        inspect!(invalid_reactive_index, data.reactive().validate().is_ok());
        inspect!(
            invalid_clock,
            data.get("clock")
                .is_none_or(|value| safe_time(value, "Stored clock").is_ok())
        );
        inspect!(graph_shape, self.graph_matches(data));
        inspect!(clock_bound, self.clock_matches(data));
        let mut names: Vec<_> = config
            .names
            .iter()
            .map(|name| Named {
                name: &name.name,
                ..Named::default()
            })
            .collect();
        let mut dependencies = 0;
        let mut window_marker_unavailable = false;
        for (id, stamp) in &self.reads.checks {
            if budget.inspect().is_none() {
                break;
            }
            dependencies += 1;
            let (valid, family, name_id) = match stamp {
                Stamp::Record(expected) => {
                    let family = if id.starts_with("source:") {
                        Family::SourceRecord
                    } else if id.starts_with("cell:") {
                        Family::CellRecord
                    } else {
                        Family::OtherRecord
                    };
                    (Some(*expected == data.version(id)), family, id.as_str())
                }
                Stamp::Marker(expected) => (
                    Some(*expected == data.generation(id)),
                    Family::Marker,
                    id.as_str(),
                ),
                Stamp::Window {
                    index,
                    marker,
                    lower,
                    upper,
                    entries,
                } => {
                    let current = data.generation(index);
                    // Do not adopt: observation must not change later validation.
                    let valid = match marker.try_lock() {
                        Ok(marker) => {
                            let unchanged = *marker == current;
                            drop(marker);
                            if unchanged {
                                Some(true)
                            } else {
                                window_versions_match(data, lower, upper, entries, || {
                                    budget.inspect()
                                })
                            }
                        }
                        Err(_) => {
                            // A diagnostic must not wait on or panic at a lock
                            // the rejecting short-circuit may never have reached.
                            budget.truncated = true;
                            window_marker_unavailable = true;
                            None
                        }
                    };
                    (valid, Family::Window, index.as_str())
                }
            };
            let Some(valid) = valid else {
                break;
            };
            if valid {
                continue;
            }
            match family {
                Family::SourceRecord => mismatches.source_record += 1,
                Family::CellRecord => mismatches.cell_record += 1,
                Family::OtherRecord => mismatches.other_record += 1,
                Family::Marker => mismatches.marker += 1,
                Family::Window => mismatches.window += 1,
            }
            for (allowed, counts) in config.names.iter().zip(&mut names) {
                if allowed.matches(name_id) {
                    match family {
                        Family::SourceRecord => counts.source_record += 1,
                        Family::CellRecord => counts.cell_record += 1,
                        Family::Marker => counts.marker += 1,
                        Family::Window => counts.window += 1,
                        Family::OtherRecord => {}
                    }
                }
            }
        }
        Report {
            version: 1,
            diagnostic_only: true,
            claim: "not_safe_repairability",
            event,
            event_limit: config.max_events,
            event_limit_reached: event == config.max_events,
            check_limit: config.max_checks,
            checks_inspected: budget.inspected,
            dependency_checks_total: self.reads.checks.len(),
            dependency_checks_inspected: dependencies,
            truncated: budget.truncated,
            window_marker_unavailable,
            ignoring_all_cell_versions_upper_bound: if budget.truncated {
                "unknown"
            } else if mismatches.non_cell() == 0 {
                "yes"
            } else {
                "no"
            },
            mismatches,
            names,
        }
    }
    #[cfg(test)]
    pub(crate) fn conflict_diagnostic_for_test(&self, data: &Records, max_checks: usize) -> Value {
        let mut config = Config::parse("", None, None).unwrap();
        config.max_checks = max_checks;
        serde_json::to_value(self.conflicts(data, &config, 1)).unwrap()
    }
}

#[cfg(test)]
mod tests;
