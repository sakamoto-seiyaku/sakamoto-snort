
## Agent skills

### Issue tracker

Issues and PRDs are tracked in Plane through the global `plane-ops` skill, using its default project. Do not use Plane MCP. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default five-role triage vocabulary in Plane. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context repo; read root/domain docs plus `docs/decisions/` before architectural work. OpenSpec is historical archive only. See `docs/agents/domain.md`.

### Android device operations

Use repo-local `./dev/adb` for all Android device and app operations. Do not call Windows `adb.exe` directly or depend on the sibling `sakamoto-app` checkout. Existing device helpers select this wrapper automatically. See `dev/README.md`.
