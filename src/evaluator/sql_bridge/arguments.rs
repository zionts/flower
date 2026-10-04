//! Concatenated native host arguments: one parser/key table, no ARRAY header.
//! Reuses every admitted primitive in codec::Decoder instead of copying bytes or
//! independently decoding roots (which would incorrectly forget KEY ordinals).
use super::*;

impl WireArena {
    pub(crate) const MAX_ARGUMENTS: usize = 8;

    pub(crate) fn decode_arguments(&mut self, bytes: &[u8]) -> Result<WireId, WireError> {
        self.decode_arguments_checked(bytes, &mut || Ok(()))
    }

    /// The synthetic array root consumes a node and a depth level. All native
    /// argument roots share this call's key intern table and cumulative work.
    pub(crate) fn decode_arguments_checked(
        &mut self,
        bytes: &[u8],
        check: &mut Check<'_>,
    ) -> Result<WireId, WireError> {
        self.ready()?;
        let result = Decoder::arguments(self, bytes, check);
        self.complete(result)
    }
}

impl<'a> Decoder<'a> {
    fn arguments(
        arena: &'a mut WireArena,
        input: &'a [u8],
        check: &mut Check<'_>,
    ) -> Result<WireId, WireError> {
        arena.ready()?;
        check()?;
        if input.len() > arena.limits.message_bytes {
            return Err(WireError::Capacity);
        }
        if arena.decoded || arena.node_len != 0 {
            return Err(WireError::Invalid("decode needs a reset arena"));
        }
        let root = arena.new_node(Kind::Array, check)?;
        let mut parser = Self {
            arena,
            input,
            position: 0,
            stack: [Level::default(); MAX_DEPTH],
            depth: 0,
        };
        while parser.position != input.len() {
            if parser.arena.nodes[root as usize].count as usize >= WireArena::MAX_ARGUMENTS {
                return Err(WireError::Capacity);
            }
            let (argument, count, object) = parser.node(2, check)?;
            parser.arena.link(root, argument, TextRef::default());
            if let Some(remaining) = count {
                parser.stack[0] = Level {
                    parent: argument,
                    remaining,
                    object,
                };
                parser.depth = 1;
            }
            while parser.depth != 0 {
                let level = parser.stack[parser.depth - 1];
                if level.remaining == 0 {
                    parser.depth -= 1;
                    if parser.depth != 0 {
                        let parent = parser.stack[parser.depth - 1].parent;
                        let height = parser.arena.nodes[level.parent as usize].height + 1;
                        parser.arena.nodes[parent as usize].height =
                            parser.arena.nodes[parent as usize].height.max(height);
                    }
                    continue;
                }
                // Stack depth 1 describes an argument container at tree depth
                // 2. The synthetic root is included in the normal depth bound.
                let depth = parser.depth + 2;
                if depth > parser.arena.limits.depth {
                    return Err(WireError::Capacity);
                }
                let key = if level.object {
                    parser.key(level.parent, check)?
                } else {
                    TextRef::default()
                };
                let (child, count, object) = parser.node(depth, check)?;
                parser.arena.link(level.parent, child, key);
                parser.arena.nodes[level.parent as usize].height =
                    parser.arena.nodes[level.parent as usize].height.max(2);
                parser.stack[parser.depth - 1].remaining -= 1;
                if let Some(remaining) = count {
                    if parser.depth >= MAX_DEPTH {
                        return Err(WireError::Capacity);
                    }
                    parser.stack[parser.depth] = Level {
                        parent: child,
                        remaining,
                        object,
                    };
                    parser.depth += 1;
                }
            }
            parser.arena.nodes[root as usize].height = parser.arena.nodes[root as usize]
                .height
                .max(parser.arena.nodes[argument as usize].height + 1);
        }
        parser.arena.decoded = true;
        check()?;
        Ok(parser.arena.id(root))
    }
}

#[cfg(test)]
#[path = "arguments_tests.rs"]
mod tests;
