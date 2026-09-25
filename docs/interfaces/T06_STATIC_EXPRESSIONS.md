# T06 static expressions

The existing schema-1 complete online rule API appends `expression_length:u32`
and `expression[64]` to each direct rule. All components must be built together;
the generated VAPI message CRC rejects mixed versions. No pointer crosses the
boundary. Rust/Java adapt transient requests; VPP owns validation, saved source,
identity assignment, compilation and publication. Workers borrow immutable
snapshot-owned copies for one packet.

The optional seventeenth diagnostic rule-text field is hexadecimal source
bytecode. It uses postfix notation, little-endian numeric operands, and the
following byte opcodes. This is a bounded data format, not user executable code.

| Opcode | Predicate / operands |
| --- | --- |
| 1 / 2 / 3 | binary AND / binary OR / unary NOT |
| 4 | family equality: one byte, 4 or 6 |
| 5 | IP protocol equality: one byte |
| 6 | device direction equality: one byte, input=1 or output=3 |
| 7 / 8 | network-context / interface equality: u32 |
| 9 / 10 | current source / destination CIDR: family byte, prefix byte, 16 network-order address bytes |
| 11 / 12 | current source / destination port inclusive range: u16 first, u16 last |

IPv4 uses the first four address bytes and requires the other twelve zero.
The existing direct predicates AND the optional expression; length zero means
no extra condition. Application selection remains the existing direct/group
binding, not a negatable missing UID. To express arbitrary Boolean conditions,
use wildcard direct predicates. NOT preserves unavailable input; AND is false
if any branch is false, OR true if any branch is true, otherwise unavailable
propagates. Only a proven true complete rule wins. Ports are unavailable without
available TCP/UDP transport facts. Platform and direction availability comes
from the existing packet projection. Source/destination never swap for replies.

Each source expression is at most 64 bytes. Structural errors, invalid operands,
nonzero unused bytes or overlong input reject before saving (`INVALID=1`).
Syntactically valid expressions deeper than eight nodes save normally but fail
compilation (`COMPILE=5`, compiler capacity error and source error index), leaving
the prior active snapshot intact. Existing effective-rule bound 128 limits total
worst-case expression visits to 8192 bytes per lookup. There is no DNF expansion,
heap allocation or partial-result success during matching; query-local value
storage is 64 bytes. Snapshot copies include the complete expressions.

Persistence writes `SKRULE04`, adding 68 explicit bytes per source entry; old
versions 1–3 remain readable with empty expressions. Expression content participates
in identity conflicts, revision progression and source hashing. Existing save,
publication and startup-repair contracts remain unchanged. Result exposes the
same logical winner/version, Rank, action, mode and source graph as other rules.
