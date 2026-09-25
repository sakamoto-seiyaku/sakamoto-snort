# R2 mail and file recognition contract

Uses the R1 owner-identify/resolution path and T12 window: 20 payload attempts,
32 KiB, synchronous borrowed payload, no byte cache or packet holding. Existing
facts remain a union; correction applies only before this attempt is published.

Selected catalog: 1007 `smtp`, 1008 `ftp-control`, 1009 `ftp-data`, 1010 `ftps`.
SMTP/FTP line inspection is bounded to the first printable-ASCII CRLF line (512 bytes including CRLF).
220 banners with separate case-insensitive SMTP/ESMTP or FTP/FTPD tokens correct
ambiguous base guesses on any port; conflicting tokens publish neither label.
Unmarked 220 banners alone are insufficient. EHLO/HELO command plus opposite
250 reply identifies SMTP; selected unambiguous FTP commands plus opposite
100–599 reply identify FTP control (excluding mail ports 25/110/587). Full-line
AUTH TLS on port21 or established FTP control (including a corrected FTP banner
on a mail port) starts the explicit-upgrade state;
opposite 234 accepts it. Only a subsequent handshake record from the requesting
side with valid TLS record framing publishes FTPS and TLS together. Implicit
control FTPS uses TCP 990 plus that same TLS record framing; neither control nor
data label follows automatically. Port989/encrypted data, passive data correlation,
split lines/records, AUTH SSL and tunneled parsing are outside this initial subset.
FTP data recognizes nonempty TCP 20 payload when no stronger current detector
matches; this is a port heuristic, not proof of associated FTP control or transfer.

Four direction/stage bytes (within the previous alignment padding) belong to existing LPI state and reset with Flow slot.
Policy updates retain them. TLS/FTPS coexistence has two explicit pieces of
evidence (FTP context/990 and valid handshake record); they are resolved together
then each mapped once through the same catalog, not a second guessing path.
All other results remain the R1 single resolved alias. No historical retraction.

Tests use the already authorized management API + actual packet outcome seam,
existing owner lifecycle seam, and independent compiler/matcher oracle. Expected
protocol sets are hand-calibrated literals; never production detector outputs.

Primary reference: ntop/nDPI commit
`4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b`,
`src/lib/protocols/{mail_smtp,ftp_control,ftp_data}.c`, LGPL-3.0-or-later.
Selected direction/command and known-data-port ideas are independently written;
no nDPI source/runtime is imported. Banner token and implicit FTPS selection also
assess fork `837432be3b6cf496755cfa27b7cca439734eb726` as evidence only.
Broad substring matching, file-magic guessing and credentials capture are excluded.

## Coverage matrix

| Fact / selected detector | Ports, direction, timing | Overlap and limits | Positive / negative evidence |
| --- | --- | --- | --- |
| SMTP 1007 `smtp`: banner token | TCP any port, either first-observed direction, first complete CRLF line at most 512 bytes; token SMTP or ESMTP in 220 reply | Wins over this attempt's LPI guess. Token boundaries are spaces; case-insensitive ASCII. Ambiguous unmarked 220, substring lookalikes, conflicting FTP/SMTP tokens and split lines do not publish. | Host `mail_banner`, `mail_boundaries`; actual Linux2525 EHLO/NOOP dialogue. |
| SMTP 1007: command/reply | Complete EHLO/HELO with argument then opposite 250 within common window; any TCP port | Only direction/stage retained. No general mail parser or SMTPS465 inference. A later valid TLS handshake record may add TLS to already published SMTP; encrypted mail contents stay opaque. | Host plain unmarked banner→EHLO→250, same-direction/error/lookalike negatives and SMTP→TLS union. |
| FTP-control 1008 `ftp-control`: banner token | TCP any port/either observed direction, complete 220 line with FTP or FTPD token | Replaces an unpublished SMTP guess, even on a mail port. No library-name-only mapping and no historical withdrawal. | Host FTPd vs SMTP/ESMTP conflicts/near-misses; actual Linux2121 and40612; Android40612. |
| FTP-control 1008: command/reply | SYST/FEAT/PASV/EPSV without arguments or RETR/STOR with argument; USER/PASS only on 21 or after FTP fact; opposite100–599 reply | Commands on 25/110/587 are excluded. Nonstandard commands above do not need a port heuristic. This is a two-message heuristic, not an authenticated login claim. | Host SYST pair, wrong direction, SYSTEM, mail port and unassociated USER; actual FTP login/control. |
| FTP-data 1009 `ftp-data` | Nonempty TCP payload with either 20 endpoint, at any attempt in window | Below stronger mapped base/current supplemental results. Retained nDPI known-port heuristic, no control-flow correlation or automatic passive/high-port/tunnel coverage. Broad file magic and listing guesses excluded. | Host 20/non20/UDP/empty and stronger FTP banner; Linux actual paced PASV/RETR data connection with server 20 and exact file chunks. |
| FTPS 1010 `ftps`: explicit | Complete AUTH TLS on 21 or existing FTP control; opposite final 234-space reply; subsequent requesting-side TLS handshake record |234 continuation alone is insufficient. Failed replies, wrong direction, AUTH TLSX, unknown nonstandard context and split-record forms do not produce FTPS. TLS record envelope must fit current payload, version 3.0–3.3, handshake typeClient/ServerHello and bounded declared lengths. Header evidence is not full Hello validation. | Host positive standard/nonstandard upgrade and listed negatives; Linux and AndroidRoot/VPN real OpenSSL/Conscrypt TLS 1.2 with preserved FTP-control/TLS/FTPS union. |
| FTPS 1010: implicit | Either TCP 990 plus same complete handshake-record envelope | Publishes FTPS and TLS together from distinct port-context and record evidence; no FTP-control fact from encrypted banner.989, arbitrary TLS ports and port-only opaque bytes do not produce FTPS. | Host 990 both directions/families,989/443/malformed/truncated negatives; Linux real 990 TLS 1.2 and decrypted FTP session. |

Every row shares T12 identities, attempts/bytes, availability, budget stop,
publication retention, current-rule cache guards and FlowEnd/reuse. Host verifies
pending AUTH cannot leak across a reused slot or restart after budget exhaustion.
The independent full-winner oracle includes all ten published IDs through three
plans, PRE/POST, cold/hot and changed availability/sets; no detector computes the
expected sets. Actual packet accounting and complete API queries are checked
against saved configuration and an independent logical rule evaluator.

The previous six facts remain covered by the R1 matrix and current Host
regression: DNS, HTTP→TLS, QUICv1/v2, SSH and mDNS positive/negative cases.
There is no SNI implementation to newly claim or query here; T13 remains separate.
No new normal-observation statistics store, application brand taxonomy, full
nDPI engine or GB/T32960 is added. Supplemental calls are bounded by the existing
20-attempt/32-KiB window; no bytes, heap allocation or second flow table are added.

Reference URLs are pinned to
[nDPI SMTP](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/mail_smtp.c),
[FTP control](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/ftp_control.c),
and [FTP data](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/ftp_data.c).
All three files carry LGPL-3.0-or-later notices. nDPI's SMTP multi-clue scoring,
FTP credential metadata and TLS-buffer ownership are deliberately not imported.
Wire interpretation follows RFC5321 SMTP command/reply lines, RFC959 FTP command,
reply and transfer roles, RFC4217 AUTH TLS/234, and TLS record framing. Independent
implementation carries the repository Apache-2.0 notice; existing LPI packaging
and relink materials are unchanged.
