# Platform Runtime KISS best-practices research

Date: 2026-08-26  
Status: decision input, not architecture authority

## Question and source boundary

What is the smallest defensible Platform Runtime recovery scope for the
VPP-native mainline, considering Android `RuntimeService`/`VpnService`, a visible
foreground service, mutually exclusive Root/VPN profiles, native packaging and
readiness, platform TUN/`protect()` facts, cleanup, and VPP process/plugin
lifecycle?

This note uses current repository ADRs/contracts plus Android, Google Play, and
FD.io VPP first-party documentation/source. It does **not** select the final
scope. POC results are bounded evidence, not reusable product source.

## Facts that constrain the decision

### Android lifecycle

- Persistent protection is legitimate foreground-service work because it is
  ongoing and user-noticeable. Android requires the app to start it through an
  allowed foreground context, promote it promptly, use a valid declared service
  type/permission, and keep a visible notification. Background starts are
  restricted from Android 12 onward. The service callback itself runs on its
  process main thread, so blocking launch, health, and cleanup work must run off
  that thread. [FGS overview](https://developer.android.com/develop/background-work/services/fgs),
  [launch rules](https://developer.android.com/develop/background-work/services/fgs/launch),
  [Service reference](https://developer.android.com/reference/android/app/Service.html)
- A started service can outlive the Activity; a bound-only service normally
  cannot. Therefore UI binding may be an optional control/status channel, not
  the protection lifetime owner. [`started + bound` lifecycle](https://developer.android.com/develop/background-work/services/bound-services#Lifecycle)
- `VpnService.prepare()` is the authorization gate. Only one app is prepared at
  a time; authorization can be revoked. `onRevoke()` requires closing the TUN fd
  and graceful shutdown. `Builder.establish()` creates the TUN; `protect()` only
  excludes an app-created socket from the VPN and does not forward a TUN packet.
  [VpnService reference](https://developer.android.com/reference/android/net/VpnService),
  [VPN developer guide](https://developer.android.com/develop/connectivity/vpn)
- A valid foreground-service type is a release/platform detail, not one
  cross-profile architectural constant. `specialUse` needs a manifest subtype
  explanation and store review. `systemExempted` is permitted only under listed
  conditions, including an active VPN app; Root mode cannot assume that VPN
  exemption. [FGS service types](https://developer.android.com/develop/background-work/services/fgs/service-types)
- Android can kill app processes. `START_STICKY` requests service recreation but
  does not reconstruct VPP resources, packet obligations, or a profile
  generation. Semantic reconciliation must therefore remain product-owned.
  [Service restart constants](https://developer.android.com/reference/android/app/Service.html#START_STICKY),
  [process lifecycle](https://developer.android.com/guide/components/activities/process-lifecycle)

### Native artifact and VPP boundaries

- APK native code belongs under `lib/<abi>/lib<name>.so`; Package Manager selects
  the device ABI and exposes installed native code through `nativeLibraryDir`.
  Android 10+ forbids directly executing files copied into the writable app home
  directory. A supervised executable must therefore remain APK-installed code,
  not a mutable private-file copy. [Android ABI packaging](https://developer.android.com/ndk/guides/abis#native-code-in-app-packages),
  [Android 10 W^X rule](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission)
- VPP supports explicit startup configuration and plugin paths. Its production
  configuration can disable plugins by default and enable only named plugins.
  `nodaemon` is the documented form for a process monitor to retain ownership.
  [VPP configuration reference](https://docs.fd.io/vpp/25.06/configuration/reference.html#the-plugins-section),
  [VPP Unix configuration](https://docs.fd.io/vpp/17.04/syscfg_src_vlib_unix.html)
- In the pinned VPP source, early plugin loading reads `vlib_plugin_path` before
  ordinary startup config processing. This agrees with the repo POC finding that
  `plugin_path` must be a launch argument. VPP provides init and main-loop-exit
  hooks, but `SIGKILL` cannot run exit hooks; Android/platform residue still
  needs supervisor-owned cleanup. [pinned `main.c`](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vpp/vnet/main.c),
  [pinned plugin loader](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/unix/plugin.c),
  [pinned lifecycle macros](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/init.h)
- Plugin discovery/load is not product readiness. The current repo contract
  already separates core health from Adapter readiness and requires a versioned
  control handshake; this is a Sakamoto product invariant, not a general VPP
  guarantee. See ADR-0002, ADR-0006, `app/android-runtime/README.md`, and
  `RuntimeSnapshot`.

## KISS-shaped minimum recovery candidate

The evidence supports discussing the following as the **minimum candidate**,
subject to the Wayfinder decision:

1. **One Android lifecycle authority, one active profile.** Serialize
   `start(profile)`, `stop`, and `switch`; never run Root and VPN VPP runtimes at
   once. UI closure must not stop protection. No automatic profile fallback.
2. **Legal foreground envelope.** Promote immediately with a visible ongoing
   notification and a valid profile-appropriate FGS declaration. Execute all
   native/process work on one bounded lifecycle executor, not the service main
   thread.
3. **One pinned, ABI-complete artifact set.** Package the VPP executable/core,
   required shared libraries, generated control identity, and only the selected
   product plugins. Verify ABI/provenance before launch; pass an explicit plugin
   path and enable only required plugins. Never package POC plugins as readiness
   evidence.
4. **Coarse readiness, not a framework.** A runtime becomes `running` only after
   the supervised process is alive and a versioned handshake proves expected
   artifact/control identity, core health, selected Adapter identity, and
   Adapter readiness. A boolean plus stable reason code is enough initially;
   plugin presence, PID existence, or socket existence alone is insufficient.
5. **Thin Android platform bridge.** Platform Runtime owns permission/root
   authorization, TUN creation and fd lifetime, current underlay snapshot, and
   bind/`protect()` broker operations. It passes resources/facts across a
   coarse-grained seam. It does not parse packets, own policy verdicts, or own
   per-flow transport state.
6. **Generation-safe stop/switch/crash cleanup.** Stop admission; keep completion
   paths alive for one bounded drain; close/abort VPN transport sessions;
   reclaim outstanding buffers; release TUN or NFQUEUE resources; gracefully
   terminate VPP; use a bounded forced-termination fallback; then verify and
   remove profile-owned sockets/PID/runtime residue. Start the other profile only
   after this barrier succeeds. No token, callback, fd, or packet crosses a
   generation.
7. **Small durable projection.** Persist only selected profile, generation, and a
   bounded state/health/error snapshot sufficient to reconcile after Android or
   native-process death. Ambiguity fails closed and asks for explicit recovery;
   `START_STICKY` is not treated as proof that the old runtime resumed.

These seven items recover Platform Runtime capability. Packet graph, Adapter
internals, policy, worker topology, lwIP flow behavior, and evidence matrices
belong to their respective architecture domains.

## Mechanisms not justified as recovery-baseline requirements

- Always-on VPN, lockdown, boot auto-start, seamless network migration, and OEM
  background-survival matrices. They add product/release semantics beyond basic
  lifecycle recovery.
- A generalized multi-attempt exponential restart framework. ADR-0007 currently
  specifies one bounded VPN Flow Stack restart before tearing down the unusable
  VPN runtime; ADR-0006 leaves broader supervisor/restart policy as a release
  gate. Root/VPP auto-restart therefore needs a separate decision.
- Multiple supervisors, dual dataplanes, automatic Root↔VPN fallback, or a
  compatibility daemon. They violate the accepted single-authority/shared-VPP
  boundary.
- Mandatory separate Android process, elaborate Binder/AIDL surface, or replicated
  state stores solely as “best practice.” Android defaults components to one
  process and notes that most apps do not change it; ADR-0002 says isolation
  “where practical.” Existing process isolation may remain, but it need not be a
  recovery acceptance gate absent measured isolation value.
- Dynamic plugin discovery, hot plugin reload, runtime worker resizing, adaptive
  capacity, per-packet Java/Rust IPC, or a broad health subsystem. These enlarge
  lifecycle state without closing the minimum capability loop.
- Release signing/key rotation, Play declarations, upgrade/rollback, long Doze,
  tombstones, soak, power/thermal, multi-OEM, and full capacity tuning. They are
  real release gates, but the Wayfinder map explicitly places release matrices
  beyond this recovery plan.

## Decision-sensitive boundaries

- Whether Root and VPN share one concrete `VpnService` subclass or use two thin
  Android service entry points over one supervisor core is not resolved by the
  official guidance. The invariant is one lifecycle authority and one active
  profile, not a class count.
- Whether VPP is an app-UID or root child differs by profile. Packaging,
  writable runtime directories, sockets, and privilege handoff must be proven
  for each profile without changing the shared artifact/control identity.
- Process isolation and automatic restart are useful only when their failure and
  resource costs are measured. Neither should be smuggled into the minimum scope
  under the label “best practice.”
