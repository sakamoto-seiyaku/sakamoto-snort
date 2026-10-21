# Documentation map

Begin with [the current mainline](current/README.md), then read only the material
needed for the task. Implementation facts, product goals and historical evidence
are different kinds of authority.

| Need | Entry | Meaning |
| --- | --- | --- |
| Current implementation and limits | [Current mainline](current/README.md) | Short dated baseline, source map and explicit acceptance limits |
| Product goals / UI / release | [Product docs](product/README.md) | Intended product; not proof that every capability is implemented |
| Architecture | [Decision map](decisions/README.md), [ADRs](adr/) | Accepted constraints; historical decisions are labelled separately |
| Interfaces | [Interface map](INTERFACE_SPECIFICATION.md) | Routes to current typed source contracts |
| Tests and evidence | [Testing](testing/README.md), [test source map](../tests/README.md) | Runbooks and dated, bounded observations |
| Build / device operations | [Tooling](tooling/README.md), [dev helpers](../dev/README.md) | Current commands and safety boundaries |
| Agent workflow | [Domain routing](agents/domain.md), [document maintenance](agents/doc-maintenance.md) | Task-specific reading and classification |

## Long-form context and history

[CONTEXT](../CONTEXT.md), [implementation roadmap](IMPLEMENTATION_ROADMAP.md)
and [Android/VPP handoff](ANDROID_VPP_CURRENT_STATE_HANDOFF.md) contain accumulated
terminology, plans and point-in-time records. Consult the relevant section; they
are not a mandatory linear reading list or an alternative to current source and
dated acceptance evidence. Older “not implemented” statements may describe an
earlier phase. Product plans likewise do not establish current readiness.

[Reviews](reviews/), [reference studies](reference/), [archived docs](archived/)
and [POCs](../experiments/README.md) are supporting evidence, not implementation templates.
OpenSpec under `archive/openspec/` is historical only; inspect it only when requested.
Open work belongs to Plane ([tracker rules](agents/issue-tracker.md)).

The [Root NFQUEUE verdict optimization memo](memos/ROOT_NFQUEUE_VERDICT_OPTIMIZATION_MEMO.md)
records the current batch experiments, corrected CPU attribution and bounded Netlink datagram
candidate. Its research findings do not establish implementation or performance adoption.

See the [reference/POC organization record](maintenance/2026-09-13_REFERENCE_AND_POC_ORGANIZATION.md)
and the [preceding repository cleanup](maintenance/2026-09-13_REPOSITORY_ORGANIZATION.md)
for path, naming and preservation decisions.
