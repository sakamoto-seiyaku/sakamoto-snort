export const entryKey = (entry) => entry.mode + ":" + entry.name.toLowerCase();
export const entryMatches = (entry, name) =>
  name.toLowerCase() === entry.name.toLowerCase() ||
  (entry.mode === "descendants" &&
    name.toLowerCase().endsWith("." + entry.name.toLowerCase()));
export function sourceEntries(list) {
  return list.subscription?.sourceEntries || list.entries;
}
export function listEntries(list) {
  if (!list.subscription) return list.entries;
  return [
    ...new Map(
      [...sourceEntries(list), ...(list.localAdditions || [])].map((entry) => [
        entryKey(entry),
        entry,
      ]),
    ).values(),
  ];
}
export function listMatches(list, name) {
  if (!list) return false;
  if (
    (list.localExclusions || []).some((entry) =>
      entryMatches(
        typeof entry === "string" ? { name: entry, mode: "exact" } : entry,
        name,
      ),
    )
  )
    return false;
  return list.entries.some((entry) => entryMatches(entry, name));
}
export function listReferences(id, config) {
  const references = (node) =>
    node.type === "leaf"
      ? node.field === "domain_list" && node.value === id
      : node.children.some(references);
  return config.rules.filter((rule) => references(rule.conditions));
}
export function entryChanges(before, after) {
  const a = new Set(before.map(entryKey)),
    b = new Set(after.map(entryKey));
  return {
    added: after.filter((e) => !a.has(entryKey(e))),
    removed: before.filter((e) => !b.has(entryKey(e))),
  };
}
