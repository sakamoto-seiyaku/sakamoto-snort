---
status: accepted
date: 2026-09-24
---

# Unified rule semantics and VPP-owned online configuration

Sakamoto uses one ordered effective rule set per application, with VPP compiling
whole rules into safe pre-flow and post-flow programs. Execution position does
not confer priority: the winner follows priority, explicit order and stable rule
identity. Rules may combine packet, platform, CT, published LPI and TLS/QUIC SNI
facts, subject to their availability and applicability. This replaces the
stage-owned precedence and special Network Gate design in ADR-0001 so that
optimization cannot silently change the user's rule meaning.

VPP owns online rule/group/binding management and the single persistent
configuration file. Its main thread expands and compiles the source model;
workers read a consistently published immutable Runtime Snapshot. Rust retains
request adaptation, basic validation/import preparation and the separate normal
observation store and incremental traffic views. Keeping rule management,
compilation and saving together avoids duplicate editable models and a
cross-process rule-synchronization design. Configuration is not required to be
managed while VPP is stopped.

## Consequences

- Application network disabling is a highest-priority ordinary DROP maintained
  by its configuration entrypoint. Groups organize reuse rather than choosing
  winners. Complete NoMatch defaults to ALLOW; explicit default denial is an
  ordinary lowest-priority DROP.
- A whole SNI-containing rule requires published TLS/QUIC recognition. Missing
  input cannot be negated into a match; a valid parse confirming no SNI is an
  available result. Packets are not held waiting for recognition or SNI.
- Compilation preserves full logical winner, action, effective mode and
  attribution under identical inputs. Conservative placement, bounded
  expansion/factorization and worker-private caches are internal execution
  choices under that invariant.
- One packet uses one protected immutable snapshot. Updating policy invalidates
  cached decisions lazily without resetting flow identity, CT/LPI facts or
  cumulative counters. True pre-flow DROP does not enter Flow processing.
- A complete configuration is saved before compilation. Save failure prevents
  compilation; compilation failure retains the new saved configuration and any
  existing active snapshot. Saved and active versions and errors are reported
  separately. This is not an atomic transaction across disk and worker memory.
- On startup without a valid snapshot, compilation is a prerequisite to product
  traffic capture. Configuration failure preserves healthy VPP management APIs
  for user correction but does not report protection running. RuntimeService
  retains lifecycle ownership and other platform/Adapter prerequisites. A VPP
  crash or unavailable control infrastructure cannot promise API availability.
- Normal observation is bounded and loss-tolerant. VPP basic accounting and
  packet progress do not wait for export or Rust. Rust incrementally maintains
  the agreed views, recent attribution and coarser history in storage separate
  from configuration. UI lifecycle does not own ingestion.
- Prior draft/checkpoint workflows and a single physical Product Store are not
  implicit requirements of this revision. Full historical conditions are
  available only when their corresponding source material still exists.
  Concrete UI and debug interaction design remain deferred.

## Scope and supersession

The [unified rule-engine specification](../product/UNIFIED_RULE_ENGINE_SPEC.md)
defines behavior, adjustable defaults and verification. This ADR records accepted
design intent; current Gate/L4 code and past acceptance evidence do not prove
the new engine or management lifecycle has been implemented.

ADR-0001 is superseded only for separate policy precedence/families, Gate
privilege, early ALLOW meaning and the policy/observation choices replaced here.
Its unaffected worker, steering and packet-resource constraints remain valid.
ADR-0002's RuntimeService and frontend lifecycle separation remains; its
product-database wording must distinguish VPP's configuration file from Rust's
observation storage. ADR-0006, ADR-0007 and ADR-0008 remain fully in force:
VPP-native C is the packet-domain target, and the removed C++ product and POC
source are not implementation templates.
