//! Closed metadata parser only. Publication/envelope/stamp/absence proofs are
//! owned by the source Store, not by any descriptor, enum or numeric flag here.
use super::scanner::Scanner;
use super::{
    Check, Error, KEY_SLOTS, Limits, MAX_DEPTH, MAX_NAME_BYTES, MAX_NODES, NameLookup, Preflight,
    Span,
};

const MAX_REGISTRY_BYTES: usize = 32 * 1024;
const MAX_ALIASES: usize = 32;
const MAX_FINALIZER_BYTES: usize = 384;
const MAX_CATALOG_BYTES: usize = 63;
const MAX_SIGNERS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Query,
    Explain,
    Catalog,
    Cancel,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelResultShape {
    Boolean,
    Cancelled,
}

/// No public constructor/fields/Clone/Debug or authority marker. All offsets
/// refer to the supplied immutable registry after WHOLE-document validation.
/// Holding this does not hold a Snapshot, source reference or key capability.
pub(crate) struct TerminalHeader<'registry> {
    raw: &'registry [u8],
    method: Span,
    terminal: Span,
    signing_keys: Option<Span>,
    alias: [u8; MAX_NAME_BYTES],
    name: [u8; MAX_NAME_BYTES],
    catalog: [u8; MAX_CATALOG_BYTES],
    finalizer: [u8; MAX_FINALIZER_BYTES],
    alias_len: usize,
    name_len: usize,
    catalog_len: usize,
    finalizer_len: usize,
    operation: Operation,
    cancel_result: Option<CancelResultShape>,
}
impl TerminalHeader<'_> {
    pub(crate) fn alias(&self) -> &str {
        text(&self.alias[..self.alias_len])
    }
    pub(crate) fn name(&self) -> &str {
        text(&self.name[..self.name_len])
    }
    pub(crate) fn catalog(&self) -> &str {
        text(&self.catalog[..self.catalog_len])
    }
    pub(crate) fn finalizer(&self) -> &str {
        text(&self.finalizer[..self.finalizer_len])
    }
    pub(crate) fn operation(&self) -> Operation {
        self.operation
    }
    /// None preserves the actual SDK default (Boolean for Cancel), rather than
    /// fabricating a serialized cancelResult property that was not present.
    pub(crate) fn cancel_result(&self) -> Option<CancelResultShape> {
        self.cancel_result
    }
    pub(crate) fn encoded_method_json(&self) -> &[u8] {
        self.method.slice(self.raw)
    }
    pub(crate) fn encoded_terminal_json(&self) -> &[u8] {
        self.terminal.slice(self.raw)
    }
    /// Metadata ONLY: all original signer values, not a selected key/grant.
    /// Missing signingKeys has the actual serde default, the empty array.
    pub(crate) fn signing_keys_json(&self) -> &[u8] {
        self.signing_keys.map_or(b"[]", |span| span.slice(self.raw))
    }
}
fn text(bytes: &[u8]) -> &str {
    // Fixed arrays are populated solely by the strict bounded Unicode decoder.
    unsafe { std::str::from_utf8_unchecked(bytes) }
}

/// Informational result only; only the source's actual validated Published
/// guard can bind this to its private envelope/cell/revision/bundle/schema.
pub(crate) struct ClassifiedRegistry<'registry> {
    terminal: Option<TerminalHeader<'registry>>,
}
impl<'registry> ClassifiedRegistry<'registry> {
    pub(crate) fn terminal(&self) -> Option<&TerminalHeader<'registry>> {
        self.terminal.as_ref()
    }
    pub(crate) fn is_ordinary(&self) -> bool {
        self.terminal.is_none()
    }
    pub(crate) fn into_terminal(self) -> Option<TerminalHeader<'registry>> {
        self.terminal
    }
}

/// Concrete opaque parser, borrowing the actual complete name witness and SAME
/// Preflight work/scratch. Healthy retries spend more of that one ledger. The
/// source, not this parser, must require a genuinely changed Published version.
pub(crate) struct RegistryClassifier<'borrow, 'pool, 'body> {
    preflight: &'borrow mut Preflight<'pool>,
    lookup: &'borrow NameLookup<'body>,
    check: &'borrow dyn Check,
}
impl<'borrow, 'pool, 'body> RegistryClassifier<'borrow, 'pool, 'body> {
    // Only the parent ingress module constructs this; not crate-wide.
    pub(super) fn new(
        preflight: &'borrow mut Preflight<'pool>,
        lookup: &'borrow NameLookup<'body>,
        check: &'borrow dyn Check,
    ) -> Self {
        Self {
            preflight,
            lookup,
            check,
        }
    }
    pub(crate) fn classify<'registry>(
        &mut self,
        raw_native_registry: &'registry [u8],
    ) -> Result<ClassifiedRegistry<'registry>, Error> {
        if let Some(error) = self.preflight.failed {
            return Err(error);
        }
        let result = (|| {
            self.check.check()?;
            if raw_native_registry.len() > MAX_REGISTRY_BYTES {
                return Err(Error::Capacity);
            }
            let limits = Limits {
                body_bytes: MAX_REGISTRY_BYTES,
                depth: MAX_DEPTH,
                // Metadata has its own fixed document shape, not the eventual
                // request-envelope's decoded tree cap. Use ALL existing slots:
                // arbitrary bounded signer Value can exceed4096 object keys.
                keys: KEY_SLOTS,
                nodes: MAX_NODES,
                number_bytes: 1024,
                work: self.preflight.limits.work,
            };
            self.preflight.keys_dirty = true;
            let mut scanner = Scanner::new(
                raw_native_registry,
                &mut self.preflight.levels,
                &mut self.preflight.keys,
                limits,
                &mut self.preflight.remaining,
                self.check,
            );
            let root = scanner.complete()?;
            let fields = scanner.fields_at(root, ["format", "methods"])?;
            if !scanner.raw_equals(fields[0].ok_or(Error::Invalid)?, b"1")? {
                return Err(Error::Unsupported);
            }
            let mut methods = scanner.object(fields[1].ok_or(Error::Invalid)?)?;
            let mut count = 0usize;
            let mut terminal = None;
            while let Some((alias_span, method_span)) = scanner.object_next(&mut methods)? {
                scanner.debit(1)?;
                count += 1;
                if count > MAX_ALIASES {
                    return Err(Error::Capacity);
                }
                let mut alias = [0u8; MAX_NAME_BYTES];
                let alias_len = scanner.decode(alias_span, &mut alias)?;
                let header = parse_method(
                    &mut scanner,
                    raw_native_registry,
                    method_span,
                    alias,
                    alias_len,
                )?;
                // Only actual public alias keys participate. A private callback
                // name/finalizer never becomes an ordinary/terminal lookup key.
                scanner.debit(alias_len)?;
                if self
                    .lookup
                    .bounded_name()
                    .is_some_and(|name| name.as_bytes() == &header.alias[..header.alias_len])
                {
                    terminal = Some(header);
                }
            }
            scanner.check()?;
            // Even an overlong invocation is Ordinary only now: every alias
            // was verified <=256, all descriptors healthy and whole EOF proven.
            Ok(ClassifiedRegistry { terminal })
        })();
        if let Err(error) = result {
            self.preflight.failed = Some(error);
        }
        result
    }
}

fn parse_method<'registry>(
    scanner: &mut Scanner<'_, '_>,
    raw: &'registry [u8],
    method: Span,
    alias: [u8; MAX_NAME_BYTES],
    alias_len: usize,
) -> Result<TerminalHeader<'registry>, Error> {
    let fields = scanner.fields_at(
        method,
        [
            "name",
            "kind",
            "consistency",
            "receipt",
            "terminal",
            "cache",
            "watch",
        ],
    )?;
    let mut name = [0u8; MAX_NAME_BYTES];
    let name_len = scanner.decode(fields[0].ok_or(Error::Invalid)?, &mut name)?;
    if !scanner.string_equals(fields[1].ok_or(Error::Invalid)?, b"query")?
        || fields[3].is_some()
        || !scanner.raw_equals(fields[5].ok_or(Error::Invalid)?, b"false")?
        || !scanner.raw_equals(fields[6].ok_or(Error::Invalid)?, b"false")?
    {
        return Err(Error::Invalid);
    }
    if let Some(consistency) = fields[2]
        && !scanner.string_equals(consistency, b"linearizable")?
    {
        return Err(Error::Invalid);
    }
    // terminalMethods is produced only from HttpMethods with a terminal.
    // Missing/null descriptors are invalid metadata, never Ordinary.
    let terminal = fields[4].ok_or(Error::Invalid)?;
    let fields = scanner.fields_at(
        terminal,
        [
            "catalog",
            "operation",
            "cancelResult",
            "finalizer",
            "signingKeys",
        ],
    )?;
    let mut catalog = [0u8; MAX_CATALOG_BYTES];
    let catalog_len = scanner.decode(fields[0].ok_or(Error::Invalid)?, &mut catalog)?;
    scanner.debit(catalog_len)?;
    if !identifier(&catalog[..catalog_len]) {
        return Err(Error::Invalid);
    }
    let operation = operation(scanner, fields[1].ok_or(Error::Invalid)?)?;
    let cancel_result = match fields[2] {
        None => None,
        Some(span) if scanner.raw_equals(span, b"null")? => None,
        Some(span) if scanner.string_equals(span, b"boolean")? => Some(CancelResultShape::Boolean),
        Some(span) if scanner.string_equals(span, b"cancelled")? => {
            Some(CancelResultShape::Cancelled)
        }
        Some(_) => return Err(Error::Invalid),
    };
    if operation != Operation::Cancel && cancel_result.is_some() {
        return Err(Error::Invalid);
    }
    let mut finalizer = [0u8; MAX_FINALIZER_BYTES];
    let finalizer_len = scanner.decode(fields[3].ok_or(Error::Invalid)?, &mut finalizer)?;
    if finalizer_len == 0 {
        return Err(Error::Invalid);
    }
    let signers = fields[4]
        .map(|span| signing_keys(scanner, span))
        .transpose()?
        .unwrap_or(0);
    if operation == Operation::Cancel && signers != 0 {
        return Err(Error::Invalid);
    }
    Ok(TerminalHeader {
        raw,
        method,
        terminal,
        signing_keys: fields[4],
        alias,
        name,
        catalog,
        finalizer,
        alias_len,
        name_len,
        catalog_len,
        finalizer_len,
        operation,
        cancel_result,
    })
}
fn operation(scanner: &mut Scanner<'_, '_>, span: Span) -> Result<Operation, Error> {
    for (name, operation) in [
        (b"query".as_slice(), Operation::Query),
        (b"explain", Operation::Explain),
        (b"catalog", Operation::Catalog),
        (b"cancel", Operation::Cancel),
    ] {
        if scanner.string_equals(span, name)? {
            return Ok(operation);
        }
    }
    Err(Error::Invalid)
}
fn identifier(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CATALOG_BYTES
        && name[0].is_ascii_lowercase()
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && ![
            b"sql_tables".as_slice(),
            b"sql_columns",
            b"sql_relationships",
            b"sqlite_master",
            b"sqlite_schema",
            b"sqlite_temp_master",
            b"sqlite_temp_schema",
        ]
        .contains(&name)
}
fn signing_keys(scanner: &mut Scanner<'_, '_>, span: Span) -> Result<usize, Error> {
    let mut array = scanner.array(span)?;
    let mut names = [None; MAX_SIGNERS];
    let mut count = 0usize;
    while let Some(key) = scanner.array_next(&mut array)? {
        scanner.debit(1)?;
        if count >= MAX_SIGNERS {
            return Err(Error::Capacity);
        }
        // Actual TerminalMethod::validate checks only the string-name distinct
        // set and that usages contains "sign". Other Value members/values are
        // arbitrary bounded JSON, not invented key-algorithm/authority grants.
        let mut object = scanner.object(key)?;
        let mut name = None;
        let mut usages = None;
        while let Some((field, value)) = scanner.object_next(&mut object)? {
            if scanner.string_equals(field, b"name")? && scanner.first(value) == Some(b'"') {
                name = Some(value);
            }
            if scanner.string_equals(field, b"usages")? {
                usages = Some(value);
            }
        }
        let mut array = scanner.array(usages.ok_or(Error::Invalid)?)?;
        let mut signs = false;
        while let Some(usage) = scanner.array_next(&mut array)? {
            // Visit every usage even after sign: malformed tails never escape.
            signs |= scanner.string_equals(usage, b"sign")?;
        }
        if !signs {
            return Err(Error::Invalid);
        }
        if let Some(name) = name {
            for previous in names[..count].iter().flatten() {
                if scanner.same_string(name, *previous)? {
                    return Err(Error::Duplicate);
                }
            }
        }
        names[count] = name;
        count += 1;
    }
    Ok(count)
}

// Inline controls/results/constructor temporaries reuse the existing 16KiB
// allowance. These are representation checks, NOT native stack/backing proofs.
// Enumerate real fixed representations for selected/returned/constructor
// staging and helper records. Compiler/native call stacks remain separately HOLD.
const CONTROL_LAYOUT_BYTES: usize = 3 * size_of::<TerminalHeader<'static>>()
    + size_of::<ClassifiedRegistry<'static>>()
    + 2 * size_of::<Scanner<'static, 'static>>()
    + 2 * size_of::<Preflight<'static>>()
    + size_of::<NameLookup<'static>>()
    + size_of::<super::Header<'static>>()
    + size_of::<RegistryClassifier<'static, 'static, 'static>>()
    + size_of::<[u8; MAX_NAME_BYTES]>() * 2
    + size_of::<[u8; MAX_CATALOG_BYTES]>()
    + size_of::<[u8; MAX_FINALIZER_BYTES]>()
    + super::scanner::borrowed_control_layout_bytes();
const _: () = assert!(CONTROL_LAYOUT_BYTES <= super::CONTROL_BYTES);
#[cfg(test)]
pub(super) const fn control_layout_bytes() -> usize {
    CONTROL_LAYOUT_BYTES
}
