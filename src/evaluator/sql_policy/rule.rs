use super::*;

#[derive(Clone, Copy)]
pub(super) struct PolicyParts<'a> {
    pub read: Option<ArenaValue<'a>>,
    pub fields: Option<ArenaValue<'a>>,
}
pub(super) fn policy_parts<'a>(
    policy: Option<ArenaValue<'a>>,
    work: &mut Work<'_>,
) -> Result<PolicyParts<'a>, PolicyError> {
    let Some(policy) = policy else {
        return Ok(PolicyParts {
            read: None,
            fields: None,
        });
    };
    require_kind(policy, ArenaKind::Object)?;
    let mut result = PolicyParts {
        read: None,
        fields: None,
    };
    let mut iter = policy.children();
    while let Some(entry) = work.next(&mut iter)? {
        match entry.key.ok_or(PolicyError::Unsupported)? {
            "read" => result.read = Some(entry.value),
            "fields" => {
                require_kind(entry.value, ArenaKind::Object)?;
                result.fields = Some(entry.value);
            }
            // Captured trusted schema already validates write-only scopes.
            // This read-only engine never evaluates or grants a write rule.
            "insert" | "update" | "delete" => {
                validate_write_shape(entry.value, work)?;
            }
            _ => return Err(PolicyError::Unsupported),
        }
    }
    if let Some(fields) = result.fields {
        let mut iter = fields.children();
        let mut count = 0;
        while let Some(entry) = work.next(&mut iter)? {
            count += 1;
            if count > MAX_RULE_NODES {
                return Err(PolicyError::Capacity);
            }
            if entry.key.is_none_or(str::is_empty) {
                return Err(PolicyError::Unsupported);
            }
            field_read(entry.value, work)?;
        }
    }
    Ok(result)
}
fn field_read<'a>(
    field: ArenaValue<'a>,
    work: &mut Work<'_>,
) -> Result<Option<ArenaValue<'a>>, PolicyError> {
    require_kind(field, ArenaKind::Object)?;
    let mut iter = field.children();
    let mut read = None;
    let mut any = false;
    while let Some(entry) = work.next(&mut iter)? {
        any = true;
        match entry.key.ok_or(PolicyError::Unsupported)? {
            "read" => read = Some(entry.value),
            "write" => {
                validate_write_shape(entry.value, work)?;
            }
            _ => return Err(PolicyError::Unsupported),
        }
    }
    if !any {
        return Err(PolicyError::Unsupported);
    }
    Ok(read)
}
pub(super) fn validate_policy_reads(
    parts: PolicyParts<'_>,
    support: CapturedSupport<'_>,
    native_keys: bool,
    work: &mut Work<'_>,
) -> Result<(), PolicyError> {
    if let Some(read) = parts.read {
        validate_rule(read, support, false, native_keys, work)?;
    }
    if let Some(fields) = parts.fields {
        let mut iter = fields.children();
        while let Some(entry) = work.next(&mut iter)? {
            if let Some(read) = field_read(entry.value, work)? {
                validate_rule(read, support, false, native_keys, work)?;
            }
        }
    }
    Ok(())
}
fn require_kind(value: ArenaValue<'_>, kind: ArenaKind) -> Result<(), PolicyError> {
    if value.kind() != kind {
        return Err(PolicyError::Unsupported);
    }
    Ok(())
}
fn singleton<'a>(
    value: ArenaValue<'a>,
    work: &mut Work<'_>,
) -> Result<ArenaEntry<'a>, PolicyError> {
    require_kind(value, ArenaKind::Object)?;
    let mut iter = value.children();
    let entry = work.next(&mut iter)?.ok_or(PolicyError::Unsupported)?;
    if work.next(&mut iter)?.is_some() {
        return Err(PolicyError::Unsupported);
    }
    Ok(entry)
}
fn pair<'a>(
    value: ArenaValue<'a>,
    work: &mut Work<'_>,
) -> Result<(ArenaValue<'a>, ArenaValue<'a>), PolicyError> {
    require_kind(value, ArenaKind::Array)?;
    let mut iter = value.children();
    let left = work.next(&mut iter)?.ok_or(PolicyError::Unsupported)?.value;
    let right = work.next(&mut iter)?.ok_or(PolicyError::Unsupported)?.value;
    if work.next(&mut iter)?.is_some() {
        return Err(PolicyError::Unsupported);
    }
    Ok((left, right))
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Op {
    Eq,
    Ne,
    In,
    Lt,
    Lte,
    Gt,
    Gte,
    StartsWith,
}
impl Op {
    pub(super) fn swapped(self) -> Self {
        match self {
            Self::Lt => Self::Gt,
            Self::Lte => Self::Gte,
            Self::Gt => Self::Lt,
            Self::Gte => Self::Lte,
            op => op,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Root {
    Principal,
    Row,
    Key,
    Now,
}
#[derive(Clone, Copy)]
pub(super) enum Operand<'a> {
    Literal(ArenaValue<'a>),
    Ref(Root, ArenaValue<'a>),
}
impl Operand<'_> {
    fn clock(self) -> bool {
        matches!(self, Self::Ref(Root::Now, _))
    }
}
fn operand<'a>(value: ArenaValue<'a>, work: &mut Work<'_>) -> Result<Operand<'a>, PolicyError> {
    let entry = singleton(value, work)?;
    match entry.key.ok_or(PolicyError::Unsupported)? {
        "value" => Ok(Operand::Literal(entry.value)),
        "ref" => {
            require_kind(entry.value, ArenaKind::Array)?;
            let mut iter = entry.value.children();
            let root = work
                .next(&mut iter)?
                .and_then(|entry| entry.value.as_str())
                .ok_or(PolicyError::Unsupported)?;
            let root = match root {
                "principal" => Root::Principal,
                "row" => Root::Row,
                "key" => Root::Key,
                "now" => Root::Now,
                _ => return Err(PolicyError::Unsupported),
            };
            let mut rest = 0;
            let mut first = "";
            while let Some(segment) = work.next(&mut iter)? {
                rest += 1;
                if rest > 63 {
                    return Err(PolicyError::Unsupported);
                }
                let segment = segment
                    .value
                    .as_str()
                    .filter(|segment| !segment.is_empty())
                    .ok_or(PolicyError::Unsupported)?;
                if rest == 1 {
                    first = segment;
                }
            }
            let valid = match root {
                Root::Principal => {
                    (rest == 1 && matches!(first, "subject" | "tenant" | "claims"))
                        || (rest > 1 && first == "claims")
                }
                Root::Row => rest > 0,
                Root::Key => true,
                Root::Now => rest == 0,
            };
            if !valid {
                return Err(PolicyError::Unsupported);
            }
            Ok(Operand::Ref(root, entry.value))
        }
        _ => Err(PolicyError::Unsupported),
    }
}
#[derive(Clone, Copy)]
enum Node<'a> {
    Const(bool),
    All(ArenaValue<'a>),
    Any(ArenaValue<'a>),
    Not(ArenaValue<'a>),
    Exists(Operand<'a>),
    Compare(Op, Operand<'a>, Operand<'a>),
    Readable(&'a str, Operand<'a>),
}
fn node<'a>(rule: ArenaValue<'a>, work: &mut Work<'_>) -> Result<Node<'a>, PolicyError> {
    let entry = singleton(rule, work)?;
    Ok(match entry.key.ok_or(PolicyError::Unsupported)? {
        "const" => Node::Const(entry.value.as_bool().ok_or(PolicyError::Unsupported)?),
        "all" => {
            require_kind(entry.value, ArenaKind::Array)?;
            Node::All(entry.value)
        }
        "any" => {
            require_kind(entry.value, ArenaKind::Array)?;
            Node::Any(entry.value)
        }
        "not" => Node::Not(entry.value),
        "exists" => Node::Exists(operand(entry.value, work)?),
        "readable" => {
            let (collection, key) = pair(entry.value, work)?;
            let collection = collection
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or(PolicyError::Unsupported)?;
            Node::Readable(collection, operand(key, work)?)
        }
        name => {
            let op = match name {
                "eq" => Op::Eq,
                "ne" => Op::Ne,
                "in" => Op::In,
                "lt" => Op::Lt,
                "lte" => Op::Lte,
                "gt" => Op::Gt,
                "gte" => Op::Gte,
                "startsWith" => Op::StartsWith,
                _ => return Err(PolicyError::Unsupported),
            };
            let (left, right) = pair(entry.value, work)?;
            Node::Compare(op, operand(left, work)?, operand(right, work)?)
        }
    })
}
enum Children<'a> {
    Many(ArenaIter<'a>),
    One(Option<ArenaValue<'a>>),
}
impl<'a> Children<'a> {
    fn next(&mut self, work: &mut Work<'_>) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        match self {
            Self::Many(iter) => Ok(work.next(iter)?.map(|entry| entry.value)),
            Self::One(value) => {
                work.debit(1)?;
                Ok(value.take())
            }
        }
    }
}
/// Validate the complete tree before evaluation, using fixed depth storage.
/// Targets validate their read rule with readable forbidden; nesting is at most
/// this one target-validation call, never an arbitrary policy graph recursion.
fn validate_rule(
    rule: ArenaValue<'_>,
    support: CapturedSupport<'_>,
    forbid_readable: bool,
    native_keys: bool,
    work: &mut Work<'_>,
) -> Result<bool, PolicyError> {
    let mut levels: [Option<Children<'_>>; MAX_RULE_DEPTH] = std::array::from_fn(|_| None);
    let mut level = 0;
    let mut current = Some(rule);
    let mut nodes = 0;
    let mut clock = false;
    let mut compound = false;
    loop {
        if let Some(rule) = current.take() {
            work.debit(1)?;
            nodes += 1;
            if nodes > MAX_RULE_NODES || level + 1 > MAX_RULE_DEPTH {
                return Err(PolicyError::RuleLimit);
            }
            let children = match node(rule, work)? {
                Node::All(value) | Node::Any(value) => {
                    compound = true;
                    Some(Children::Many(value.children()))
                }
                Node::Not(value) => {
                    compound = true;
                    Some(Children::One(Some(value)))
                }
                Node::Exists(operand) => {
                    validate_key_operand(operand, native_keys, work)?;
                    clock |= operand.clock();
                    None
                }
                Node::Compare(_, left, right) => {
                    validate_key_operand(left, native_keys, work)?;
                    validate_key_operand(right, native_keys, work)?;
                    clock |= left.clock() || right.clock();
                    None
                }
                Node::Readable(collection, operand) => {
                    validate_key_operand(operand, native_keys, work)?;
                    if forbid_readable {
                        return Err(PolicyError::Unsupported);
                    }
                    if operand.clock() {
                        return Err(PolicyError::UncertifiedTemporal);
                    }
                    let target = support
                        .collection(collection, work)?
                        .ok_or(PolicyError::Unsupported)?;
                    let target = policy_parts(Some(target), work)?;
                    if let Some(read) = target.read {
                        clock |= validate_rule(read, support, true, native_keys, work)?;
                    }
                    None
                }
                Node::Const(_) => None,
            };
            if let Some(children) = children {
                levels[level] = Some(children);
                level += 1;
            }
        }
        while level > 0 {
            let children = levels[level - 1].as_mut().ok_or(PolicyError::Unsupported)?;
            if let Some(child) = children.next(work)? {
                current = Some(child);
                break;
            }
            levels[level - 1] = None;
            level -= 1;
        }
        if current.is_none() {
            break;
        }
    }
    if clock && compound {
        return Err(PolicyError::UncertifiedTemporal);
    }
    Ok(clock)
}

fn validate_key_operand(
    operand: Operand<'_>,
    native: bool,
    work: &mut Work<'_>,
) -> Result<(), PolicyError> {
    if !native && let Operand::Ref(Root::Key, path) = operand {
        let mut iter = path.children();
        work.next(&mut iter)?;
        if work.next(&mut iter)?.is_some() {
            return Err(PolicyError::Unsupported);
        }
    }
    Ok(())
}
fn native_index(segment: &str, work: &mut Work<'_>) -> Result<Option<usize>, PolicyError> {
    let text = segment.strip_prefix('+').unwrap_or(segment);
    if text.is_empty() {
        return Ok(None);
    }
    let mut index = 0usize;
    let mut valid = true;
    for chunk in text.as_bytes().chunks(1024) {
        work.debit(chunk.len())?;
        for &byte in chunk {
            if !byte.is_ascii_digit() {
                valid = false;
            }
            if valid {
                match index
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(usize::from(byte - b'0')))
                {
                    Some(n) => index = n,
                    None => valid = false,
                }
            }
        }
    }
    Ok(valid.then_some(index))
}

#[derive(Clone, Copy)]
pub(super) struct Subject<'a> {
    pub engine: PolicyEngine<'a>,
    pub key: &'a str,
    pub parts: Option<ArenaValue<'a>>,
    pub native: bool,
    pub row: ArenaValue<'a>,
}
#[derive(Clone, Copy)]
pub(super) enum Resolved<'a> {
    Missing,
    Json(ArenaValue<'a>),
    Key(&'a str),
    Now(u64),
}
impl<'a> Resolved<'a> {
    pub(super) fn present(self) -> bool {
        !matches!(self, Self::Missing) && !matches!(self, Self::Json(value) if value.is_null())
    }
    pub(super) fn text(self) -> Option<&'a str> {
        match self {
            Self::Key(key) => Some(key),
            Self::Json(value) => value.as_str(),
            _ => None,
        }
    }
}
fn resolve<'a>(
    operand: Operand<'a>,
    subject: Subject<'a>,
    work: &mut Work<'_>,
) -> Result<Resolved<'a>, PolicyError> {
    let (root, path) = match operand {
        Operand::Literal(value) => return Ok(Resolved::Json(value)),
        Operand::Ref(root, path) => (root, path),
    };
    match root {
        Root::Key => {
            let mut iter = path.children();
            work.next(&mut iter)?;
            if work.next(&mut iter)?.is_none() {
                return Ok(Resolved::Key(subject.key));
            }
            if !subject.native {
                return Err(PolicyError::Unsupported);
            }
            if subject.parts.is_none() {
                return Ok(Resolved::Missing);
            }
        }
        Root::Now => return Ok(Resolved::Now(subject.engine.now)),
        _ => {}
    }
    let mut iter = path.children();
    work.next(&mut iter)?; // validated root
    let mut value = match root {
        Root::Principal if !subject.engine.principal.object => return Ok(Resolved::Missing),
        Root::Principal => subject.engine.principal.value,
        Root::Row => subject.row,
        Root::Key => subject.parts.ok_or(PolicyError::Unsupported)?,
        _ => return Err(PolicyError::Unsupported),
    };
    let mut first = true;
    while let Some(segment) = work.next(&mut iter)? {
        let segment = segment.value.as_str().ok_or(PolicyError::Unsupported)?;
        if first
            && matches!(root, Root::Principal)
            && subject.engine.principal.anonymous
            && segment != "tenant"
        {
            return Ok(Resolved::Missing);
        }
        first = false;
        let next = match value.kind() {
            ArenaKind::Object => work.get(value, segment)?,
            ArenaKind::Array => {
                // Preserve the old string host's admitted subset; the checked
                // native API alone widens to exact arbitrary-leading-zero usize.
                if !subject.native && segment.len() > 20 {
                    return Err(PolicyError::Unsupported);
                }
                match native_index(segment, work)? {
                    Some(index) => work.frame(value.at(index))?,
                    None => None,
                }
            }
            _ => None,
        };
        let Some(next) = next else {
            return Ok(Resolved::Missing);
        };
        value = next;
    }
    Ok(Resolved::Json(value))
}
struct EvalLevel<'a> {
    children: Children<'a>,
    mode: Mode,
    validity: Validity,
}
#[derive(Clone, Copy)]
enum Mode {
    All,
    Any,
    Not,
}
pub(super) fn evaluate_optional(
    rule: Option<ArenaValue<'_>>,
    default: bool,
    subject: Subject<'_>,
    work: &mut Work<'_>,
) -> Result<Decision, PolicyError> {
    let Some(rule) = rule else {
        return Ok(Decision {
            allowed: default,
            validity: Validity::Independent,
        });
    };
    evaluate(rule, subject, work)
}
fn evaluate<'a>(
    rule: ArenaValue<'a>,
    subject: Subject<'a>,
    work: &mut Work<'_>,
) -> Result<Decision, PolicyError> {
    let mut stack: [Option<EvalLevel<'a>>; MAX_RULE_DEPTH] = std::array::from_fn(|_| None);
    let mut depth = 0;
    let mut current = rule;
    loop {
        work.debit(1)?;
        let mut result = match node(current, work)? {
            Node::All(value) | Node::Any(value) => {
                let mode = if matches!(node(current, work)?, Node::All(_)) {
                    Mode::All
                } else {
                    Mode::Any
                };
                let mut children = Children::Many(value.children());
                if let Some(child) = children.next(work)? {
                    if depth == MAX_RULE_DEPTH {
                        return Err(PolicyError::RuleLimit);
                    }
                    stack[depth] = Some(EvalLevel {
                        children,
                        mode,
                        validity: Validity::Independent,
                    });
                    depth += 1;
                    current = child;
                    continue;
                }
                Decision {
                    allowed: matches!(mode, Mode::All),
                    validity: Validity::Independent,
                }
            }
            Node::Not(child) => {
                if depth == MAX_RULE_DEPTH {
                    return Err(PolicyError::RuleLimit);
                }
                stack[depth] = Some(EvalLevel {
                    children: Children::One(None),
                    mode: Mode::Not,
                    validity: Validity::Independent,
                });
                depth += 1;
                current = child;
                continue;
            }
            Node::Const(allowed) => Decision {
                allowed,
                validity: Validity::Independent,
            },
            Node::Exists(operand) => {
                let value = resolve(operand, subject, work)?;
                Decision {
                    allowed: value.present(),
                    validity: if operand.clock() {
                        Validity::ClockInvariant
                    } else {
                        Validity::Independent
                    },
                }
            }
            Node::Compare(op, left, right) => {
                let (left, right) = (
                    resolve(left, subject, work)?,
                    resolve(right, subject, work)?,
                );
                compare::decide(op, left, right, work)?
            }
            Node::Readable(collection, key) => {
                let key = resolve(key, subject, work)?;
                if subject.native {
                    typed::readable(collection, key, subject, work)?
                } else {
                    if matches!(key, Resolved::Json(value) if matches!(value.kind(), ArenaKind::Array | ArenaKind::Object))
                    {
                        return Err(PolicyError::Unsupported);
                    }
                    if let Some(key) = key.text() {
                        let policy = subject
                            .engine
                            .support
                            .collection(collection, work)?
                            .ok_or(PolicyError::Unsupported)?;
                        let parts = policy_parts(Some(policy), work)?;
                        match subject.engine.support.row(collection, key, work)? {
                            Some(row) => evaluate_optional(
                                parts.read,
                                false,
                                Subject {
                                    key,
                                    parts: None,
                                    row,
                                    ..subject
                                },
                                work,
                            )?,
                            None => Decision {
                                allowed: false,
                                validity: Validity::Independent,
                            },
                        }
                    } else {
                        Decision {
                            allowed: false,
                            validity: Validity::Independent,
                        }
                    }
                }
            }
        };
        loop {
            if depth == 0 {
                return Ok(result);
            }
            let frame = stack[depth - 1].as_mut().ok_or(PolicyError::Unsupported)?;
            frame.validity = frame.validity.intersect(result.validity);
            let stop = match frame.mode {
                Mode::Not => {
                    result.allowed = !result.allowed;
                    true
                }
                Mode::All => !result.allowed,
                Mode::Any => result.allowed,
            };
            if !stop && let Some(child) = frame.children.next(work)? {
                current = child;
                break;
            }
            result.validity = frame.validity;
            stack[depth - 1] = None;
            depth -= 1;
        }
    }
}
pub(super) fn field_decision(
    fields: Option<ArenaValue<'_>>,
    name: &str,
    subject: Subject<'_>,
    work: &mut Work<'_>,
) -> Result<Decision, PolicyError> {
    let rule = if let Some(fields) = fields {
        work.get(fields, name)?
            .map(|field| field_read(field, work))
            .transpose()?
            .flatten()
    } else {
        None
    };
    evaluate_optional(rule, true, subject, work)
}

/// Syntax/limits only for trusted captured write scopes; never evaluate/grant a
/// write. This prevents ignored write fields from hiding malformed/unknown ASTs,
/// while allowing ordinary next/key-part syntax that reads do not implement.
fn validate_write_shape(rule: ArenaValue<'_>, work: &mut Work<'_>) -> Result<(), PolicyError> {
    let mut levels: [Option<Children<'_>>; MAX_RULE_DEPTH] = std::array::from_fn(|_| None);
    let mut level = 0;
    let mut current = Some(rule);
    let mut nodes = 0;
    loop {
        if let Some(rule) = current.take() {
            nodes += 1;
            work.debit(1)?;
            if nodes > MAX_RULE_NODES || level + 1 > MAX_RULE_DEPTH {
                return Err(PolicyError::RuleLimit);
            }
            let entry = singleton(rule, work)?;
            let children = match entry.key.ok_or(PolicyError::Unsupported)? {
                "const" => {
                    entry.value.as_bool().ok_or(PolicyError::Unsupported)?;
                    None
                }
                "all" | "any" => {
                    require_kind(entry.value, ArenaKind::Array)?;
                    Some(Children::Many(entry.value.children()))
                }
                "not" => Some(Children::One(Some(entry.value))),
                "exists" => {
                    write_operand_shape(entry.value, work)?;
                    None
                }
                "eq" | "ne" | "in" | "lt" | "lte" | "gt" | "gte" | "startsWith" => {
                    let (left, right) = pair(entry.value, work)?;
                    write_operand_shape(left, work)?;
                    write_operand_shape(right, work)?;
                    None
                }
                "readable" => {
                    let (collection, key) = pair(entry.value, work)?;
                    collection
                        .as_str()
                        .filter(|name| !name.is_empty())
                        .ok_or(PolicyError::Unsupported)?;
                    write_operand_shape(key, work)?;
                    None
                }
                _ => return Err(PolicyError::Unsupported),
            };
            if let Some(children) = children {
                levels[level] = Some(children);
                level += 1;
            }
        }
        while level > 0 {
            let children = levels[level - 1].as_mut().ok_or(PolicyError::Unsupported)?;
            if let Some(child) = children.next(work)? {
                current = Some(child);
                break;
            }
            levels[level - 1] = None;
            level -= 1;
        }
        if current.is_none() {
            break;
        }
    }
    Ok(())
}
fn write_operand_shape(value: ArenaValue<'_>, work: &mut Work<'_>) -> Result<(), PolicyError> {
    let entry = singleton(value, work)?;
    match entry.key.ok_or(PolicyError::Unsupported)? {
        "value" => Ok(()),
        "ref" => {
            require_kind(entry.value, ArenaKind::Array)?;
            let mut iter = entry.value.children();
            let root = work
                .next(&mut iter)?
                .and_then(|entry| entry.value.as_str())
                .ok_or(PolicyError::Unsupported)?;
            if !matches!(root, "row" | "next" | "principal" | "key" | "now") {
                return Err(PolicyError::Unsupported);
            }
            let mut count = 0;
            let mut first = "";
            while let Some(segment) = work.next(&mut iter)? {
                count += 1;
                if count > 63 {
                    return Err(PolicyError::Unsupported);
                }
                let text = segment
                    .value
                    .as_str()
                    .filter(|segment| !segment.is_empty())
                    .ok_or(PolicyError::Unsupported)?;
                if count == 1 {
                    first = text;
                }
            }
            let valid = match root {
                "principal" => {
                    (count == 1 && matches!(first, "subject" | "tenant" | "claims"))
                        || (count > 1 && first == "claims")
                }
                "now" => count == 0,
                "key" => true,
                "row" | "next" => count > 0,
                _ => false,
            };
            if !valid {
                return Err(PolicyError::Unsupported);
            }
            Ok(())
        }
        _ => Err(PolicyError::Unsupported),
    }
}
