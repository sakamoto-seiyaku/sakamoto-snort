# Design notes

## Invariants
- BlockingList/DomainList `blockMask` MUST be a single bit from `{1,2,4,8,16,32,64}`.
- `128` (`Settings::customListBit`) is reserved for App behavior (`useCustomList`) and MUST NOT be used by any blocking list.
- App `BLOCKMASK` MAY be any combination of the allowed list bits.
- Reinforced mode MUST include standard mode via appMask normalization: if an app mask contains `8`, it MUST also contain `1`.

## Rationale: no cross-listId dedupe
`DomainList` maintains per-list domain sets and publishes an aggregated snapshot `domain -> OR(mask)` for fast hot-path lookups.

Any cross-listId "skip write" dedupe makes a list's contents depend on other lists. This breaks independent list lifecycle:
- if list A and B both contain `x.com`, but B skipped writing due to A already having it;
- disabling/removing A removes `x.com` from the aggregated snapshot even if B remains enabled,
  because B never stored `x.com` itself.

Therefore, only per-listId dedupe is allowed; cross-listId dedupe is prohibited.

## Lookup strategy
Keep `DomainList::blockMask` behavior unchanged (exact match first, then suffix first-hit) to avoid increasing hash lookups
in the DNS decision hot path. Union semantics across multiple suffix matches are explicitly out-of-scope for this change.

## Non-goals: backend color/统计分组不扩展
The backend `Stats::Color` classification remains unchanged (it currently maps only bit `1`/`8` to BLACK/WHITE and everything
else to GREY). Clients that need per-chain visualization SHOULD use the already-exposed `domMask`/`appMask` fields and map
bits to UI colors on the frontend.
