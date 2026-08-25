# SAKAMOTO-141 B1 TCP Underlay-network Selection Hotspot

Date: 2026-08-24
Status: CLOSED_FOR_POC; source fix and Pixel regression passed

## Outcome

The next minimal B1 cell (real IPv4 TCP from the default-route OI3 TUN to the
WSL2 fixed-response server) failed before physical Wi-Fi egress.  The endpoint
and UID controls passed, and the OI3 owner reached `direct-send`, but Pixel
`wlan0` emitted no packet for `192.168.4.5:38080`.  The VpnService broker had
bound and protected the fd successfully; it had selected the wrong Android
`Network`.

## Evidence

- The same Pixel shell UID TCP control reached the fixed-response server:
  `RX ('192.168.4.151', 53842) 0` followed by the expected HTTP body.
- The failing app run recorded `Network.bindSocket=true` and
  `VpnService.protect=true`, then `oi3 connector-connect result=-1 errno=115`
  and `oi3 direct-send length=71`; it ended with
  `oi3 connector-wake cause=2` and
  `oi3_cleanup result=FAIL ... direct=0 ... error=tun-flow-output-not-a-direct-return`.
- A bounded root `tcpdump` on Pixel `wlan0`, filtered to the exact WSL2 host and
  port, produced no packet lines during the run.  This rules out a server-side
  listener or return-only readiness failure.
- While the VPN was active, `dumpsys connectivity` showed Wi-Fi network 100
  (`handle=432902426637`) and a separate `VPN CONNECTED` network 107
  (`handle=462967197709`, `tun0`, UID 12628, underlying network `[100]`).
  Earlier OI3 broker logs recorded `getActiveNetwork()` handles such as
  `458672230413`, which did not match the Wi-Fi handle.

## Root cause

`ConnectivityManager.getActiveNetwork()` is UID-scoped.  After this package
establishes its VPN, that call can return the package's own VPN network rather
than the physical Wi-Fi underlay.  The old broker then called
`Network.bindSocket()` on that VPN network and only afterwards called
`VpnService.protect()`.  The socket was therefore eligible and “protected” at
the API boundary but had no physical `wlan0` egress; the OI3 owner could still
produce synthetic TUN handshake/output packets, which obscured the failure as
a HEV readiness timeout.

## Correction

`SnortVpnService.bindAndProtectSocketForNative()` now enumerates
`ConnectivityManager.getAllNetworks()`, rejects `TRANSPORT_VPN` and any network
without `NET_CAPABILITY_NOT_VPN`, scores validated Internet/Wi-Fi candidates,
logs every candidate and the selected handle, and binds/protects only the
selected non-VPN underlay.  No unprotected fallback or second datapath is
introduced.

## Regression gate

One post-build device cell must show:

1. selected handle is the non-VPN Wi-Fi network (not the VPN handle);
2. `Network.bindSocket=true` and `VpnService.protect=true` for the broker fd;
3. a physical-egress observation contains the TCP exchange and the WSL2 server
   receives the request.  The post-build `wlan0` tcpdump session did not flush
   packet text, but the Wi-Fi route was selected and the fixed-response server
   recorded `RX ('192.168.4.151', 43336) 78`;
4. OI3 records `direct-recv`, rewritten TUN output, App receipt, and exact
   cleanup (`buffers allocated/freed`, `residue=0`).

The post-build APK was SHA-256
`9b52fdc62c2fd335897d7f3e40e03140cc2f22cdfc736827f10c346388df3996` for both
debug output aliases.  The selected non-VPN handle was `432902426637`, while
the UID-scoped VPN active handle was `467262165005`; the app received 88 bytes
in `2604 ms`.  OI3 recorded `direct-send length=78`, `direct-recv length=88`,
`rewritten=2`, `buffers=149/149`, and `residue=0` with cleanup `PASS`.

If the selected non-VPN network is unavailable, the broker must fail closed
with an explicit bind result; it must not retry on the UID-scoped VPN network.

## Planning consequence

The B1 plan gains a mandatory **underlay identity gate** between artifact/UID
preflight and every real-network cell.  A successful `bindSocket/protect` pair
without a non-VPN selected handle is invalid evidence.  The existing LAN
same-UID control remains necessary but is not sufficient to prove that the
connector used the physical underlay.
