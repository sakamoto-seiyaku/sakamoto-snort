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

Build with a pinned VPP stage when it is available:

```sh
app/android-runtime/scripts/build-debug-apk.sh
```

Host contract coverage is in `tests/android/android-runtime-contract-test.sh`.
