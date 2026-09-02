# Android Runtime incubator

> **Current state:** ADR-0008 removed the C++ daemon and its APK artifact.
> S171-S196 now provide the VPP-native Product Core runtime and lifecycle
> contract. `build-debug-apk.sh` stages `libvpp_runtime.so` with
> `libproduct_core_plugin.so`; current acceptance boundaries are recorded in
> `docs/testing/SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md`.

`app/android-runtime/` is the forward implementation slice for SAKAMOTO-67.
It is separate from `experiments/vpp-nfq-poc/android/vpn-lite/`, which remains
migration evidence and a disposable harness.

`RuntimeService` is the sole lifecycle authority. `DebugControlActivity` only
sends the versioned `android-runtime-control/v1` start/query/stop request and
renders the durable bounded snapshot. Root and VPN select one profile-owned VPP
core directory and one artifact identity contract; only one profile can be
active at a time. S171-S196 evidence covers the current Root/VPN Product Core
adapter and lifecycle contracts; release/OEM/long-soak claims remain separate.

The build refuses to claim core readiness when the packaged VPP binary hash or
generated-VAPI control identity does not match the manifest. Adapter readiness
is reported from the Product Core VAPI status and is not inferred from plugin
presence alone.

The default build input is `build-output/android-vpp-runtime/stage`. When that
stage is incomplete, the repository-local staging boundary consumes the pinned
VPP source and stages only the VPP core, diagnostics CLI, client libraries, and
generated-VAPI build inputs. The experiment tree remains migration evidence;
its packet Adapter artifacts are not packaged or promoted by this app. An
explicit stage path is checked but never supplemented implicitly.

Build with the default stage when it is available:

```sh
app/android-runtime/scripts/build-debug-apk.sh
```

Host contract coverage is in `tests/android/android-runtime-contract-test.sh`.

SAKAMOTO-50 begins the Local Product Backend boundary in this active app:
`RuntimeService` owns the backend-side Product Store writer, selected
Runtime Profile persistence, complete-Linux-UID `ApplicationSubjectId`, and
the PackageManager-backed Application Catalog provider seam. `ProductStateStore`
persists policy/config state under `product-state/`; bounded Activity uses a
separate lossy repository seam and must not become policy/config authority.
