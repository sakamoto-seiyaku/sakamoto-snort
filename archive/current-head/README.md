# Current-Head Source Archive

Status: reference-only archive, created 2026-06-20.

This directory preserves the previous `src/` tree at the start of the
SNORT-10 mainline reconstruction branch.

Rules:

- Do not add files under `archive/current-head/src/` to active CMake targets.
- Do not treat archived code as an active compatibility layer.
- Later module slices may copy or adapt small, reviewed pieces back into the
  new `src/` layout when they match the current SNORT-10 contracts.
- Old legacy control, old direct mutation surfaces, DNS/domain stream code,
  CT runtime, Flow Telemetry producers, and datapath code stay archived until
  their owning SNORT-12+ slice explicitly reintroduces them.
