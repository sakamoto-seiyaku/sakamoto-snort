
## Agent skills

### Build cache and disk usage

Compilation caches must be reused across repeated builds and experiment output
directories. Use the Product builders' persistent cache; do not create fresh
CMake/Cargo dependency builds under each `/tmp` or evidence directory. Verify an
unchanged second build has no compilation before repeating expensive work.
Preserve raw evidence and exact artifact identities during cleanup. See
`docs/agents/build-cache.md` for cache isolation, verification and retention rules.

### Issue tracker

Issues and PRDs are tracked in Plane through the global `plane-ops` skill, using its default project. Do not use Plane MCP. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default five-role triage vocabulary in Plane. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context repo; read root/domain docs plus `docs/decisions/` before architectural work. OpenSpec is historical archive only. See `docs/agents/domain.md`.

### Android device operations

Use repo-local `./dev/adb` for all Android device and app operations. Do not call Windows `adb.exe` directly or depend on the sibling `sakamoto-app` checkout. Existing device helpers select this wrapper automatically. See `dev/README.md`.
For KernelSU root acceptance, remember that uninstall/reinstall can reset the
app's Superuser grant. Confirm or restore the grant in KernelSU Manager before
treating `root_authorization_required` as a product failure; use `./dev/adb`
screenshots and UIAutomator XML for the CLI-guided flow.

### Product implementation boundary

The Snort C++ daemon, host model, tests, NDK artifact, and archived source were removed by ADR-0008. Do not recreate, port, use as a reference, or add a C++ compatibility fallback for them. The only product packet-domain target is the VPP-native C mainline defined by ADR-0006 and ADR-0007. C/VPP POCs are evidence inputs, not source to import directly.
