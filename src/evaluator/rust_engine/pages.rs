//! Bounded inventory pages in physical source-ID order, not logical key order.
//! This is deliberately separate from source-key scans and ordered index ranges.
use super::*;
use std::{cell::RefCell, ops::Bound};

pub(super) struct SourcePage {
    pub collection: String,
    limit: usize,
    after: Option<String>,
    prefix: String,
    upper: String,
    scope: String,
}

impl SourcePage {
    pub(super) fn parse(value: &Value) -> EngineResult<Self> {
        let invalid = || {
            EngineError::new(
                "INVALID_REFERENCE",
                "Invalid source page reference or cursor",
            )
        };
        let reference = value.as_object().ok_or_else(invalid)?;
        if reference.len() != 3 || value["kind"] != "sourcePage" {
            return Err(invalid());
        }
        let collection = value["collection"].as_str().ok_or_else(invalid)?.to_owned();
        let options = value["options"].as_object().ok_or_else(invalid)?;
        if options
            .keys()
            .any(|key| !["limit", "after"].contains(&key.as_str()))
        {
            return Err(invalid());
        }
        let limit = options
            .get("limit")
            .and_then(Value::as_f64)
            .filter(|n| {
                n.is_finite() && *n > 0.0 && *n <= 9_007_199_254_740_991.0 && n.fract() == 0.0
            })
            .and_then(|n| usize::try_from(n as u64).ok())
            .ok_or_else(invalid)?;
        let scope = canonical_json(&json!(["sourcePage", collection]));
        let after = match options.get("after") {
            None => None,
            Some(Value::String(encoded)) => {
                let cursor: Value = serde_json::from_str(encoded).map_err(|_| invalid())?;
                if cursor.as_object().is_none_or(|cursor| cursor.len() != 3)
                    || cursor["version"] != 1
                    || cursor["scope"] != scope
                    || canonical_json(&cursor) != *encoded
                {
                    return Err(invalid());
                }
                let last = cursor["last"]
                    .as_str()
                    .filter(|last| last.starts_with("source:"))
                    .ok_or_else(invalid)?;
                let (name, key) = source_pair(last).map_err(|_| invalid())?;
                if name != collection || source_id(&collection, &key) != last {
                    return Err(invalid());
                }
                Some(last.to_owned())
            }
            _ => return Err(invalid()),
        };
        let prefix = format!("source:[{},", canonical_json(&json!(collection)));
        // Every member starts with `prefix`. Replacing its final comma by the
        // next ASCII byte is an exclusive bound, even for escaped/Unicode names.
        let upper = format!("{}-", &prefix[..prefix.len() - 1]);
        Ok(Self {
            collection,
            limit,
            after,
            prefix,
            upper,
            scope,
        })
    }
}

#[cfg(test)]
thread_local! {
    static VISITS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
pub(super) fn take_visits() -> (usize, usize) {
    VISITS.replace((0, 0))
}

fn visit(_stored: bool) {
    #[cfg(test)]
    VISITS.set({
        let (stored, pending) = VISITS.get();
        (
            stored + usize::from(_stored),
            pending + usize::from(!_stored),
        )
    });
}

/// The ordinary policy evaluator, with short-lived point reads. Using the
/// engine's memoizing point lookup here would retain every hidden row's ACL
/// target across pages. Only the read IDs and decisions need to survive.
struct PageLookup<'e, 'a> {
    engine: &'e Engine<'a>,
    room: usize,
    seen: RefCell<BTreeMap<String, bool>>,
    bytes: std::cell::Cell<usize>,
    error: RefCell<Option<EngineError>>,
}

impl PageLookup<'_, '_> {
    fn into_reads(self) -> EngineResult<Vec<String>> {
        match self.error.into_inner() {
            Some(error) => Err(error),
            None => Ok(self.seen.into_inner().into_keys().collect()),
        }
    }
}

impl access::Rows for PageLookup<'_, '_> {
    fn readable(&self, collection: &str, key: &str, visible: &dyn Fn(&Value) -> bool) -> bool {
        if self.error.borrow().is_some() {
            return false;
        }
        let id = source_id(collection, key);
        if let Some(&shown) = self.seen.borrow().get(&id) {
            return shown;
        }
        let result = (|| {
            self.engine.check_fatal()?;
            let value = match self.engine.writes.get(&id) {
                Some(value) => value.clone(),
                None => self
                    .engine
                    .staged
                    .entries((Bound::Included(id.as_str()), Bound::Included(id.as_str())))
                    .next()
                    .map(|(_, value)| value),
            };
            let bytes = self
                .bytes
                .get()
                .saturating_add(256)
                .saturating_add(id.len().saturating_mul(2));
            if bytes.saturating_add(value.as_ref().map_or(0, |value| allocation_cost(value)))
                > self.room
            {
                return Err(EngineError::new(
                    "EVALUATION_BUDGET",
                    "Source page access lookup exceeds Rust memory budget",
                ));
            }
            self.bytes.set(bytes);
            Ok(value.is_some_and(|value| visible(&value)))
        })();
        match result {
            Ok(shown) => {
                self.seen.borrow_mut().insert(id, shown);
                shown
            }
            Err(error) => {
                *self.error.borrow_mut() = Some(error);
                false
            }
        }
    }
}

struct PageRows {
    rows: Vec<(String, Arc<Value>)>,
    cursor: Option<String>,
    looked_up: BTreeSet<String>,
}

impl Engine<'_> {
    pub(super) fn source_page(&mut self, query: &SourcePage, caller: bool) -> EngineResult<Reply> {
        self.marker_read(collection_id(&query.collection));
        let access = caller
            .then(|| self.read_access(&query.collection))
            .flatten();
        // Iterators borrow the pending writes; defer certificate bookkeeping
        // until the immutable traversal ends. In particular, keep budget errors
        // sticky even if application code catches a failed page request.
        let page = match self.source_page_rows(query, access.as_deref()) {
            Ok(page) => page,
            Err(error) if error.code == "EVALUATION_BUDGET" => {
                self.fatal.get_or_insert(error.clone());
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        self.record_lookups(page.looked_up.into_iter().collect())?;
        for (key, _) in &page.rows {
            self.record_read(source_id(&query.collection, key));
        }
        if let Some(access) = access {
            self.settle_access(&access)?;
        }
        self.page_for_host(page.rows, page.cursor)
    }

    fn source_page_rows(
        &self,
        query: &SourcePage,
        access: Option<&access::Access>,
    ) -> EngineResult<PageRows> {
        self.check_fatal()?;
        let lower = query
            .after
            .as_deref()
            .map_or(Bound::Included(query.prefix.as_str()), Bound::Excluded);
        let bounds = (lower, Bound::Excluded(query.upper.as_str()));
        // Unlike range_shared, entries does not memoize every skipped backing
        // value in Records. A hidden row therefore does not stay retained for
        // the rest of the invocation. Both paths seek straight to the cursor.
        let mut stored = self
            .staged
            .entries(bounds)
            .map(|(id, value)| {
                visit(true);
                let bytes = 256usize
                    .saturating_add(id.len())
                    .saturating_add(allocation_cost(&value));
                (id, value, bytes)
            })
            .peekable();
        let mut pending = self
            .writes
            .range::<str, _>(bounds)
            .inspect(|_| visit(false))
            .peekable();
        let mut rows = Vec::new();
        let mut looked_up = BTreeSet::new();
        let mut bytes = 512usize;
        let mut last = None;
        let mut more = false;
        let budget = |bytes: usize| {
            if self.total_retained_bytes().saturating_add(bytes) > self.retained_limit {
                Err(EngineError::new(
                    "EVALUATION_BUDGET",
                    "Source page exceeds Rust memory budget",
                ))
            } else {
                self.check_fatal()
            }
        };
        loop {
            self.check_fatal()?;
            if let Some((_, _, held)) = stored.peek() {
                // The merge may peek at a stored row while consuming earlier
                // overlay rows. That one pending value counts too.
                budget(bytes.saturating_add(*held))?;
            }
            let take_pending = match (pending.peek(), stored.peek()) {
                (Some((pending, _)), Some((stored, _, _))) => pending.as_str() <= stored.as_str(),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let (id, value, buffered_bytes) = if take_pending {
                let (id, value) = pending.next().expect("pending source");
                let buffered_bytes = match stored.peek() {
                    Some((stored_id, _, _)) if stored_id == id => {
                        stored.next();
                        0
                    }
                    Some((_, _, bytes)) => *bytes,
                    None => 0,
                };
                let Some(value) = value else { continue };
                (id.clone(), Arc::clone(value), buffered_bytes)
            } else {
                let (id, value, _) = stored.next().expect("stored source");
                (id, value, 0)
            };
            let (collection, key) = source_pair(&id)?;
            if collection != query.collection || source_id(&collection, &key) != id {
                return Err(EngineError::new(
                    "INPUT_INVALID",
                    "Malformed stored source key",
                ));
            }
            let candidate_bytes = 256usize
                .saturating_add(buffered_bytes)
                .saturating_add(id.len())
                .saturating_add(key.len())
                .saturating_add(allocation_cost(&value));
            budget(bytes.saturating_add(candidate_bytes))?;
            let lookup = PageLookup {
                engine: self,
                room: self
                    .retained_limit
                    .saturating_sub(self.total_retained_bytes())
                    .saturating_sub(bytes.saturating_add(candidate_bytes)),
                seen: RefCell::new(BTreeMap::new()),
                bytes: std::cell::Cell::new(0),
                error: RefCell::new(None),
            };
            let visible = access.is_none_or(|access| access.visible(&key, &value, &[], &lookup));
            // The lookahead proves only that a further visible row exists. Do
            // not redact it, return it, or expose its ID as a cursor.
            let shown = (visible && rows.len() < query.limit).then(|| {
                access.map_or_else(
                    || Arc::clone(&value),
                    |access| access.redact(&key, &value, &lookup),
                )
            });
            for read in lookup.into_reads()? {
                if !looked_up.contains(&read) {
                    // Keep only dependency IDs; the policy's point-read values
                    // were released before advancing the source iterator.
                    bytes = bytes
                        .saturating_add(256)
                        .saturating_add(read.len().saturating_mul(2));
                    looked_up.insert(read);
                }
            }
            budget(bytes.saturating_add(candidate_bytes))?;
            if !visible {
                continue;
            }
            if let Some(shown) = shown {
                bytes = bytes
                    .saturating_add(256)
                    .saturating_add(key.len())
                    .saturating_add(allocation_cost(&shown));
                budget(bytes)?;
                rows.push((key, shown));
                last = Some(id);
            } else {
                more = true;
                break;
            }
        }
        let cursor = more.then(|| {
            canonical_json(
                &json!({"version":1,"scope":query.scope,"last":last.expect("nonempty page")}),
            )
        });
        if let Some(cursor) = &cursor {
            budget(bytes.saturating_add(cursor.len()))?;
        }
        Ok(PageRows {
            rows,
            cursor,
            looked_up,
        })
    }
}
