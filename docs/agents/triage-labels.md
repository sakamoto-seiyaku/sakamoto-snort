# Triage Labels

The skills use five canonical triage roles. Map them to Plane labels with the same strings in the default `SNORT` project.

| Label in mattpocock/skills | Label in Plane | Plane label ID | Meaning |
| -------------------------- | -------------- | -------------- | ------- |
| `needs-triage` | `needs-triage` | `56d93c95-bad5-4324-9aa3-bcb56437b212` | Maintainer needs to evaluate this item |
| `needs-info` | `needs-info` | `e23fe2d8-0135-4534-bd6a-bbce4a5c8531` | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent` | `df5da287-ecb4-4c0d-823c-38f0feeae442` | Fully specified, ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | `1428e8a0-0591-4e6b-890c-d227608fffd0` | Requires human implementation or judgment |
| `wontfix` | `wontfix` | `06cbe24f-b4d1-417a-a7a9-592570096302` | Will not be actioned |

When a skill mentions a role, use the corresponding Plane label. If a different Plane project is selected for a task, first list that project's labels and create any missing labels with the same strings.
