# Sakamoto Snort

Android privacy firewall with a **VPP-native C packet domain**, Rust control
plane and Java RuntimeService. The former Snort C++ implementation was removed
by [ADR-0008](docs/adr/0008-remove-snort-cpp-mainline.md); do not restore it or
import POC source into the product.

Start with [current implementation and boundaries](docs/current/README.md).
The foundation integration has scoped `PASS_WITH_EXPLICIT_LIMITS` evidence;
it is not a product release gate or ordinary-user VPN protection claim.

- [Documentation map](docs/README.md): current facts, product goals and history.
- [Tests](tests/README.md): Host checks, device runners and independent evidence.
- [Build/tooling](docs/tooling/README.md) and [Android device wrapper](dev/README.md).

Open work and acceptance decisions live in Plane, not in a second Markdown backlog.
