---
status: accepted
date: 2026-07-21
---

# Tauri UI shell, Android foreground runtime boundary

Sakamoto uses the standard Tauri 2 mobile shape for its shared Android/Linux Product UI instead of making
the WebView, Activity, or a Tauri mobile plugin own persistent packet protection. On Android, Tauri compiles
the Rust mobile entry point as a library loaded by the platform application, and native mobile integration is
provided through the generated Android project and Kotlin plugin bridge. These are UI and platform-call
surfaces, not a substitute for Android Service lifecycle.

Persistent Android protection is owned by a started foreground RuntimeService/VpnService boundary with the
required Visible Runtime Notification. The service may also be bound for product control and status, but it
does not stop merely because the Tauri Activity/WebView is closed or reclaimed. Android runtime work stays
off the Activity main thread. The target Android layout isolates the runtime service boundary in its own app
process where practical; control-plane IPC may cross that boundary, while packet bytes do not traverse UI
IPC.

RuntimeService is the single lifecycle authority for the active mutually exclusive Runtime Profile:

```text
Tauri Activity/WebView
  -> Tauri Rust commands / Kotlin mobile bridge
       -> versioned product-control IPC
            -> foreground RuntimeService or VpnService
                 -> supervised VPP runtime
                      Root: root UID + NFQUEUE Adapter
                      VPN: app UID + TUN Adapter + HEV transport
```

Root and VPN use the same VPP build, Sakamoto graph, worker ownership, compiled policy semantics, and
control contract. Their process credentials, Android permission acquisition, Packet capture Adapter, and
transport completion differ. Root may require a privileged child process; VPN retains Android ownership of
the TUN and `protect()` responsibilities. These platform facts do not move policy verdict ownership into
Kotlin or the UI.

The shared Local Product Backend remains separate from presentation state. Android service integration may
reuse shared Rust product-core crates through a narrow native bridge, while Linux may host those crates in
its normal Tauri-side product process. The frontend stores only presentation state and communicates through
the same product-facing Interface; it never becomes the authoritative policy database merely because Tauri
loads its mobile Rust entry in the Activity application.

On Android, the RuntimeService side owns the Local Product Backend telemetry consumer and the single writer
for the bounded Activity Store under the ordinary application identity. VPP exports bounded facts and
counters but does not write the product database, including when the Root Profile runs VPP with elevated
credentials. Activity ingestion therefore continues while the Tauri Activity is absent and does not depend
on WebView lifecycle.

This follows Tauri's documented mobile project/plugin structure and Android's foreground-service lifecycle:

- https://v2.tauri.app/start/project-structure/
- https://v2.tauri.app/develop/plugins/develop-mobile/
- https://developer.android.com/develop/background-work/services/fgs
- https://developer.android.com/guide/components/processes-and-threads

## Consequences

- Closing or recreating the Tauri Activity does not stop active protection.
- A user pause cleanly stops VPP and releases the active profile's NFQUEUE or TUN/VPN resources; it is not
  an in-process pass-through mode. Persisted profile and policy state survive for a later restart.
- Runtime startup must originate from an Android-legal foreground context and publish the ongoing
  notification according to current platform requirements.
- Kotlin/Tauri mobile code can request permissions, bind services, and project status, but cannot evaluate
  packet policy or own VPP worker state.
- Root and VPN remain one product with one policy authority; process isolation does not create separate
  databases or feature sets.
- Binder/native IPC carries commands, snapshots, and bounded product events rather than per-packet payloads.
- The UI queries Activity projections; it neither consumes runtime telemetry nor owns durable history.
- The old Compose UI is a product-reference source, not the runtime architecture for the new shared UI.
- Exact service classes, Binder method shapes, and generated-project wiring remain implementation details
  constrained by this boundary.
