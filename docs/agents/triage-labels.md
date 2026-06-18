# Triage Labels

The skills use five canonical triage roles. Map them to Plane labels with the same strings in the default `SNORT` project. Label IDs live in the global `plane-ops` skill defaults, not in repo docs.

| Label in mattpocock/skills | Label in Plane | Meaning |
| -------------------------- | -------------- | ------- |
| `needs-triage` | `needs-triage` | Maintainer needs to evaluate this item |
| `needs-info` | `needs-info` | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent` | Fully specified, ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | Requires human implementation or judgment |
| `wontfix` | `wontfix` | Will not be actioned |

When a skill mentions a role, use the corresponding Plane label. If a different Plane project is selected for a task, first list that project's labels and create any missing labels with the same strings.
