# Pinned HEV dependency

`upstream/` is an offline, unmodified source export from the exact Git commits
in `upstream-manifest.json`. The export was made from a freshly fetched, clean
checkout, not `/tmp/hev-3911f79`, an experiment source tree or an experiment DSO.
The manifest records selected paths, tree IDs, archive hashes and every exported
file/symlink. Unused CI, applications and Windows binaries are not imported.

| Repository | Commit |
| --- | --- |
| heiher/hev-socks5-tunnel | `3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70` |
| heiher/hev-socks5-core | `ee0f24505d344f14b14624fa2249e6ccfaed138b` |
| heiher/hev-task-system | `b1afa0e21fb4ed5a69560e78e54baf0efdebe171` |
| heiher/lwip | `8c69dfbe537835d5f2a5fd8c08c859f667b108ea` |
| heiher/yaml | `efa36117a8646d26d12b58e05bac472d7854a70d` |

All four submodule commits are those recorded by the parent commit, not the
newer submodule checkouts found in earlier local fixtures. Git object content
was fetched and checked; this is not a verified signing-trust claim.

The HEV repositories and YAML carry MIT license text; lwIP carries its BSD
three-clause license and file-specific notices. Original license files and
headers remain in the export. A Product fork must preserve those notices.

The Product-specific implementation belongs in `product/`, with narrowly scoped
changes to upstream files represented by `patches/`. Builds must verify the
offline manifest and apply the recorded patches into a build directory. They
must not download dependencies, find a `/tmp` fixture, or load an experimental
library. S237 adds UDP4 and S238 adds UDP6 on one active owner; this export alone makes no transport
or readiness claim.

Refresh is an explicit maintenance operation:

```sh
python3 tools/product/vendor-hev.py --checkout <clean-recursive-pinned-checkout> \
  --destination <new-export-directory>
```

S245–S247 provide ownership/error/stop evidence, not source to import. See
`docs/testing/2026-09-09_IMPLEMENTATION_SPEC.md` §8 and ADR-0007.
