# Android Runtime incubator

`app/android-runtime/` is the forward implementation slice for SAKAMOTO-67.
It is separate from `experiments/vpp-nfq-poc/android/vpn-lite/`, which remains
migration evidence and a disposable harness.

`RuntimeService` is the sole lifecycle authority. `DebugControlActivity` only
sends the versioned `android-runtime-control/v1` start/query/stop request and
renders the durable bounded snapshot. Root/NFQUEUE and VPN/TUN use one
profile-owned VPP directory and one artifact identity contract; only one
profile can be active at a time.

The build refuses to claim readiness when the packaged VPP binary hash,
profile adapter plugin, or VPP health handshake does not match the manifest.
Missing adapter artifacts therefore produce an actionable error rather than a
pass-through or old-daemon substitution.

The default build input is `build-output/android-vpp-runtime/stage`. When that
stage is incomplete, the build invokes the repository-local staging boundary
at `experiments/vpp-nfq-poc/android/vpn-lite/scripts/stage-vpp-runtime.sh`.
That boundary consumes the pinned POC VPP source under
`experiments/vpp-nfq-poc/work/vpp`, applies the incubator overlay, builds the
VPP core plus the `nfqueue_poc_plugin` and `tun_poc_plugin` targets, and stages
their real output. The POC tree and its stages remain migration evidence, not
the production source identity; a missing source, build target, or staged
adapter or startup plugin declaration fails the APK build rather than selecting
an arbitrary stale artifact. The default stage boundary refreshes artifacts
when its configured build outputs are newer; an explicit stage path is checked
but never refreshed implicitly.

The POC stage names plugins without the Android `lib` prefix. The APK boundary
renames those same bytes to the `lib*.so` names declared by `RuntimeProfile`;
the host artifact seam and RuntimeService both require these names to agree.
An explicitly supplied `VPP_RUNTIME_STAGE_DIR` is never supplemented or
repaired implicitly and must already contain both adapters.

Build with the default stage when it is available:

```sh
app/android-runtime/scripts/build-debug-apk.sh
```

Host contract coverage is in `tests/android/android-runtime-contract-test.sh`.
