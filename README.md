# Sakamoto Snort

Android privacy firewall with a **VPP-native C packet domain**, Rust control
plane and Java RuntimeService. The former Snort C++ implementation was removed
by [ADR-0008](docs/adr/0008-remove-snort-cpp-mainline.md); do not restore it or
import POC source into the product.

Start with [current implementation and boundaries](docs/current/README.md).
The current baseline includes unified rules, Root/VPN DNS filtering and proxying,
answer caching, DoT/DoH and connection-domain facts. The accepted
[DNS combined qualification](docs/testing/2026-11-01_S328_DNS_COMBINED.md) retains
explicit limits; association enforcement and Product Activity integration remain
separate from the delivered DNS scope. This is not a product release announcement.

- [Documentation map](docs/README.md): current facts, product goals and history.
- [Tests](tests/README.md): Host checks, device runners and independent evidence.
- [Build/tooling](docs/tooling/README.md) and [Android device wrapper](dev/README.md).

Open work and acceptance decisions live in Plane, not in a second Markdown backlog.
