# Reference naming and provenance

Sakamoto defines its own product/domain terms. A reference implementation's
plugin, class or feature-arc name does not become a Product module or contract.

- **Product/glossary/ADR prose:** state the project's semantic rule directly.
  Put implementation lineage in a focused reference record, not in the term's name.
- **External evidence:** preserve real repository-relative filenames, API symbols,
  CLI strings, environment variables, output keys, revisions and hashes. Mark them
  as external identifiers. Do not invent a renamed external API for readability.
- **Local paths:** a machine-specific reference root may be represented as
  `<reference-root>` or supplied through the real `VPP_REFERENCE_ROOT` override.
  Keep the path below that root exact. A placeholder is not an executable path.
- **Document names:** neutral titles/filenames are fine; retain redirects for
  existing links. This does not rename the observed source or tool.
- **Readiness:** an external recognizer's behavior, a historical probe PASS and
  a Product constraint are three different claims. Neither proves current runtime
  integration. Do not erase the original evidence's scope when shortening prose.

For example, this reference fork exposes `stellar_lpi_enable_disable` and
`set stellar-lpi interface`; the inventory script accepts `VPP_STELLAR_LPI_ROOT`.
Those identifiers belong only to reference/probe records. Product L4 priority
and packet byte-movement rules are defined independently in the project glossary.

The historical source/runner observations remain in the [LPI control record](PROTOCOL_IDENTIFICATION_VPP_LPI_CONTROL_AND_RUNNER_CONTRACT.md).
Use [current mainline](../current/README.md) for implemented Product capability.
