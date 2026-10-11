import { conditionText, subjectName } from "./model.js";
import { ruleUse } from "./rule-use.js";
import { esc } from "./ui.js";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, stable(value[k])]),
    );
  return value;
}
const same = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
const names = (ids, items) =>
  (ids || [])
    .map((id) => items.find((x) => x.id === id)?.name || id)
    .join("、") || "无";
const channels = (r) =>
  (r.channels || ["connection"])
    .map((c) => (c === "dns" ? "域名查询" : "连接"))
    .join("与");
const entries = (list) =>
  (list.entries || [])
    .map(
      (e) =>
        e.name + (e.mode === "descendants" ? "（含子域名）" : "（仅此名称）"),
    )
    .join("\n") || "无条目";
export function addressImpact(before, after) {
  if (!before || !after) return "";
  if (
    before.type === "and" &&
    after.type === "and" &&
    before.children.length === after.children.length
  ) {
    const changed = before.children
      .map((node, index) => (same(node, after.children[index]) ? -1 : index))
      .filter((index) => index >= 0);
    return changed.length === 1
      ? addressImpact(before.children[changed[0]], after.children[changed[0]])
      : "";
  }
  if (
    before.type !== "leaf" ||
    after.type !== "leaf" ||
    before.field !== "destination" ||
    after.field !== "destination"
  )
    return "";
  const match = String(before.value).match(
    /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/,
  );
  if (
    after.value === "0.0.0.0/0" &&
    match &&
    match[1].split(".").every((n) => +n <= 255) &&
    +(match[2] ?? 32) > 0 &&
    +(match[2] ?? 32) <= 32
  )
    return `目的地址条件的范围扩大：从 ${before.value} 改为所有 IPv4 地址。其他匹配条件保持不变。`;
  return "";
}
function describe(kind, item, cfg) {
  if (!item) return {};
  if (kind === "rules")
    return {
      名称: item.name,
      规则定义: item.action === "drop" ? "阻止" : "允许",
      适用活动: channels(item),
      匹配条件: conditionText(item.conditions, cfg),
      应用与执行方式: ruleUse(item, cfg).summary || "未分配，不参与判断",
      优先级: String(item.priority),
      明确顺序: String(item.order),
      来源: item.source || "未填写",
    };
  if (kind === "groups")
    return {
      名称: item.name,
      直接规则: names(item.rules, cfg.rules),
      包含规则组: names(item.groups, cfg.groups),
    };
  if (kind === "bindings")
    return {
      分配内容:
        (item.kind === "group" ? "规则组：" : "规则：") +
        names([item.target], item.kind === "group" ? cfg.groups : cfg.rules),
      应用: item.subjects.map(subjectName).join("、"),
      执行方式:
        item.mode === "observe" ? "仅观察，实际允许" : "执行规则定义的动作",
    };
  return {
    名称: item.name,
    有效条目: entries(item),
    来源: item.source || "未填写",
    维护方式: item.subscription
      ? "订阅"
      : item.sourceKind === "import"
        ? "一次性导入"
        : "手动维护",
    订阅地址: item.subscription?.url || "无",
    订阅状态: item.subscription
      ? item.subscription.stopped
        ? "已停止，现有资料保留"
        : "已启用"
      : "不适用",
    发现新版本: item.subscription
      ? item.subscription.updateMode === "automatic"
        ? "自动采用更新"
        : "先审阅，再采用"
      : "不适用",
    文件格式: item.subscription
      ? {
          plain: "每行一个精确域名",
          native: "名称与子域名范围",
          adblock: "Adblock 域名条目",
          clash: "Clash 域名条目",
        }[item.subscription.format || "native"]
      : "不适用",
    资料版本: item.subscription?.version || "无",
    自动检查: item.subscription
      ? item.subscription.automatic
        ? `每 ${item.subscription.intervalHours || 24} 小时`
        : "已暂停"
      : "不适用",
    本地补充: entries({ entries: item.localAdditions || [] }),
    本地排除: entries({
      entries: (item.localExclusions || []).map((e) =>
        typeof e === "string" ? { name: e, mode: "exact" } : e,
      ),
    }),
  };
}
export function configChanges(before, after) {
  const changes = [];
  for (const kind of ["rules", "groups", "bindings", "lists"]) {
    const oldItems = new Map(before[kind].map((x) => [x.id, x]));
    const newItems = new Map(after[kind].map((x) => [x.id, x]));
    for (const id of new Set([...newItems.keys(), ...oldItems.keys()])) {
      const old = oldItems.get(id),
        next = newItems.get(id);
      const a = describe(kind, old, before),
        b = describe(kind, next, after);
      if (same(old, next) && same(a, b)) continue;
      const status = !old ? "added" : !next ? "removed" : "changed";
      const fields = [...new Set([...Object.keys(a), ...Object.keys(b)])]
        .filter((key) => !same(a[key], b[key]))
        .map((label) => ({
          label,
          before: a[label] ?? "无",
          after: b[label] ?? "无",
        }));
      const impacted =
        kind === "rules"
          ? [
              ...new Set(
                [
                  ...(old ? ruleUse(old, before).subjects : []),
                  ...(next ? ruleUse(next, after).subjects : []),
                ].map((s) => s.name),
              ),
            ].join("、")
          : "";
      changes.push({
        kind,
        id,
        status,
        title: next?.name || old?.name || "应用分配 " + id,
        fields,
        impacted,
        impact:
          kind === "rules"
            ? addressImpact(old?.conditions, next?.conditions)
            : "",
        before: old,
        after: next,
      });
    }
  }
  return changes;
}
export function renderConfigChanges(before, after) {
  const changes = configChanges(before, after);
  if (!changes.length)
    return '<div class="card import-no-change"><h2>与已保存配置相同</h2><p class="help">规则、作用对象、列表及其他配置内容都没有变化。</p></div>';
  const statuses = { changed: "已改变", added: "新增", removed: "删除" };
  const kinds = {
    rules: "规则",
    groups: "规则组",
    bindings: "分配",
    lists: "域名列表",
  };
  return (
    `<div class="change-summary" role="status">${Object.entries(statuses)
      .map(
        ([k, v]) =>
          `<span><strong>${changes.filter((c) => c.status === k).length}</strong> ${v}</span>`,
      )
      .join("")}</div><p class="note">涉及的应用已包含规则组的分配。</p>` +
    ["changed", "added", "removed"]
      .map((status) => {
        const items = changes.filter((c) => c.status === status);
        if (!items.length) return "";
        return `<section class="change-section"><h2>${statuses[status]} <span>${items.length}</span></h2>${items.map((c) => `<article class="config-change" data-change-id="${esc(c.id)}"><header><span class="eyebrow">${kinds[c.kind]}</span><h3>${esc(c.title)}</h3>${c.impacted ? `<p>涉及应用：${esc(c.impacted)}</p>` : ""}${c.impact ? `<p class="change-impact">${esc(c.impact)}</p>` : ""}</header>${c.fields.map((f) => `<div class="change-field"><h4>${f.label}</h4><div class="change-values"><div><span>当前</span><p>${esc(f.before)}</p></div><div><span>导入后</span><p>${esc(f.after)}</p></div></div></div>`).join("")}${!c.fields.length ? '<p class="note">其他配置字段发生变化，请展开原文核对。</p>' : ""}<details class="change-raw"><summary>查看完整配置原文 · ${esc(c.id)}</summary><div class="change-values"><div><span>当前</span><pre>${esc(JSON.stringify(c.before ?? null, null, 2))}</pre></div><div><span>导入后</span><pre>${esc(JSON.stringify(c.after ?? null, null, 2))}</pre></div></div></details></article>`).join("")}</section>`;
      })
      .join("")
  );
}
