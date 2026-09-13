# VPP/NFQUEUE experiment archive and evidence map

Status: **historical experiment lane, not the Product mainline**. Original source,
patches, registrations and raw records are retained for provenance; C/VPP POC source
must not be imported into Product code. Use [current mainline](../../docs/current/README.md)
for implemented behavior and [Product testing](../../docs/testing/README.md) for acceptance.

The old [one-command README](archive/README_ORIGINAL.md) and
[status/known-gaps table](archive/POC_STATUS_ORIGINAL.md) are archived intact.
Their “current”, “next” and PASS/HOLD wording refers to the recorded campaign,
not today's Product or Plane state. Do not execute a historical recipe merely
because it appears in those documents.

## Directory roles

| Location | Retained purpose |
| --- | --- |
| [src](src/), [overlay](overlay/), [minimal-runtime](minimal-runtime/) | Historical NFQUEUE/TUN/external-driver C/VPP implementations, not Product sources |
| [patches](patches/) | Experimental HEV patch lineage; not the Product patch series |
| [clients](clients/), [configs](configs/) | Historical control clients and startup/traffic recipes |
| [android/vpn-lite](android/vpn-lite/README.md) | POC Android shell and staging; not the Product RuntimeService |
| [android/a2-traffic-adapter](android/a2-traffic-adapter/README.md) | POC-only two-UID traffic generator |
| [prototypes](prototypes/) | Owner-inline OI1/2/4/5, UID attribution, conditional-wake and A2 state/litmus experiments |
| [scripts](scripts/), [tests](tests/) | Historical collectors, builders, verifiers and fixtures; no default Product gate |
| [evidence](evidence/), [results](results/) | Dated evidence, including failed attempts; do not purge or relabel |
| Root journals, plans and handoffs | Campaign history; select a dated record, not an accumulated default reading list |

## Later focused observations

- [S245/S246 registration](s245-s246/README.md) and [results](s245-s246/RESULTS.md):
  single-owner UDP4 input/output copy lifetimes and controlled failure cells.
- [S247 registration](s247/README.md) and [results](s247/RESULTS.md): simultaneous
  pbuf/native-buffer/credit limits. It does not establish W2, full network transition,
  release performance or general transport behavior.

These directories and their verifier/build dependencies keep their bytes and paths.
The Product joint matrix is separate and is linked from the current testing map.

## Known retained references

The older `tests/android/android-runtime-hardening-contract-test.sh` still examines
`android/vpn-lite/scripts/stage-vpp-runtime.sh`; the old S55 device harness points
to `scripts/android-build-socks5-smoke-server.sh`. Their targets remain in place.
Neither old consumer is a current root CTest/device acceptance entry. The catalog
records these compatibility references without promoting them to Product dependencies.

See the [complete experiment map](../README.md) and [machine-readable catalog](../catalog.json).
New replay work requires explicit scope and fresh provenance; this organization
does not restart old device campaigns or the deferred 24-hour test.
