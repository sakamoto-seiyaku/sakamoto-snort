#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 "$repo_root/tests/catalog/application_protocol_catalog_contract_test.py"

grep -q 'ApplicationProtocolCatalog' \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationProtocolCatalog.java"
grep -q 'ApplicationProtocolId' \
  "$repo_root/src/core/protocol/ApplicationProtocolCatalog.hpp"
grep -q 'APPLICATION_PROTOCOL_CATALOG_VERSION' \
  "$repo_root/generated/rust/application_protocol_catalog.rs"
grep -q '"protocolKey"' \
  "$repo_root/docs/api/application-protocol-catalog.schema.json"
grep -q 'not runtime hot-loaded' \
  "$repo_root/resources/application-protocol-catalog/README.md"
grep -q 'Provider aliases map recognizer evidence' \
  "$repo_root/resources/application-protocol-catalog/README.md"
grep -q 'IP protocol numbers' \
  "$repo_root/resources/application-protocol-catalog/README.md"

echo "s60 application protocol catalog contract: PASS"
