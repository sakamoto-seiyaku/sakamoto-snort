# Android Runtime incubator

`app/android-runtime/` is the forward implementation slice for SAKAMOTO-67.
It is separate from `experiments/vpp-nfq-poc/android/vpn-lite/`, which remains
migration evidence and a disposable harness.

`RuntimeService` is the sole lifecycle authority. `DebugControlActivity` only
sends the versioned `android-runtime-control/v1` start/query/stop request and
renders the durable bounded snapshot. Root and VPN select one profile-owned VPP
core directory and one artifact identity contract; only one profile can be
active at a time. SAKAMOTO-67 does not claim either packet Adapter is ready.

The build refuses to claim core readiness when the packaged VPP binary hash or
generated-VAPI control identity does not match the manifest. Adapter readiness
is explicitly `unavailable`; plugin presence is not a readiness signal.

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
