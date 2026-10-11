import {
  S,
  params,
  platform,
  allSubjects,
  subjectName,
  subjectRules,
  rule,
  bindingsFor,
  groupRules,
  conditionText,
  fields,
  choices,
  label,
  newDraft,
  draftConfig,
  clone,
  commit,
  persist,
  validDomain,
} from "./model.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  here,
  ruleCard,
  empty,
  toast,
  dialog,
  saving,
  row,
  showError,
} from "./ui.js";
import { subjectChecks, selectedSubjects } from "./apps.js";
import { ruleUse } from "./rule-use.js";
const outcome = async (next, message, returnTo) => {
  await commit(next, { message, returnTo });
  go("config-result.html");
};
function assignmentRows(list) {
  return list
    .map(
      (b) =>
        `<a class="list-row" href="${url("binding-edit.html", { id: b.id, from: here() })}"><span class="tile-icon">${icon(b.mode === "observe" ? "eye" : "users")}</span><span class="grow"><span class="title">${esc(b.subjects.map(subjectName).join("、"))}</span><span class="subtitle">${b.mode === "observe" ? "仅观察 · 命中后实际允许" : "执行规则"}${b.kind === "group" ? " · 通过规则组" : ""}</span></span>${icon("chevron-right")}</a>`,
    )
    .join("");
}
function ruleDetails(r, compact = false, active = false) {
  const cfg = active ? S.active : S.config;
  const assignments = bindingsFor(r.id, cfg);
  const use = ruleUse(r, cfg, params.get("app"));
  return `<header class="page-intro"><span class="badge ${use.tone}">${use.label}</span><h1 style="margin-top:17px;font-size:${compact ? "24" : "28"}px">${esc(r.name)}</h1><p class="effective-rule-use">${esc(use.summary || "尚未选择应用，不参与访问判断。")}</p><p class="rule-definition">${use.definition} · ${r.channels?.length === 2 ? "域名查询与连接" : r.channels?.[0] === "dns" ? "域名查询" : "连接"}</p></header><div class="${compact ? "" : "desktop-grid"}"><section><div class="card"><div class="eyebrow">匹配范围</div><p class="rule-summary" style="font-size:17px">${esc(conditionText(r.conditions, cfg))}</p></div><p class="source-line">优先级 ${r.priority} · 明确顺序 ${r.order}<br>来源：${esc(r.source)}<br>规则 ID：${r.id} · ${active ? "当前生效版本 " + S.activeVersion : "当前已保存版本 " + S.savedVersion}</p></section><section><div class="section-heading"><h2>分配与执行方式</h2><a class="text-link" href="${url("binding-edit.html", { rule: r.id, from: "rule-detail.html?id=" + r.id })}">添加</a></div><div class="inset-list">${assignmentRows(assignments) || '<div class="list-row"><span class="subtitle">尚未分配，不参与访问判断。</span></div>'}</div></section></div>`;
}
export function rules() {
  const app = params.get("app");
  const sorted = [...(app ? subjectRules(app, S.config) : S.config.rules)].sort(
    (a, b) => a.priority - b.priority || a.order - b.order,
  );
  if (app) {
    $(".page-intro h1").textContent = subjectName(app) + "的规则";
    $(".page-intro p").textContent = "当前设置；活动仍保留当时的处理结果。";
    if (params.get("from")) {
      const back = document.createElement("a");
      back.className = "text-link";
      back.href = url(params.get("from"));
      back.textContent = "返回" + subjectName(app);
      $(".page-intro").prepend(back);
    }
  }
  $("#rule-count").textContent =
    sorted.length + " 条规则 · 已保存 v" + S.savedVersion;
  $("#rules-list").innerHTML =
    sorted
      .map((r) =>
        ruleCard(r).replace(
          'class="rule-item"',
          `class="rule-item" data-rule-select="${r.id}"`,
        ),
      )
      .join("") ||
    empty(
      "让第一条规则开始工作",
      "从具体目标开始，也可以从访问记录创建。",
      `<a class="btn primary" href="${url("rule-edit.html", { new: 1 })}">新建规则</a>`,
    );
  function side(id) {
    const r = rule(id);
    $("#rule-side-detail").innerHTML = r
      ? ruleDetails(r, true) +
        `<a class="btn primary full" href="${url("rule-detail.html", { id: r.id, app, from: here() })}">打开规则详情 ${icon("arrow-right")}</a>`
      : "";
  }
  side(S.selectedRule || sorted[0]?.id);
  $$("[data-rule-select]").forEach(
    (a) =>
      (a.onclick = (e) => {
        if (innerWidth >= 700) {
          e.preventDefault();
          S.selectedRule = a.dataset.ruleSelect;
          persist();
          side(S.selectedRule);
        }
      }),
  );
}
export function ruleDetail() {
  const active = params.get("active") === "1";
  const r = rule(params.get("id") || "r1", active ? S.active : S.config);
  if (!r) {
    $("#rule-detail-content").innerHTML = empty(
      "规则已不存在",
      "历史访问仍保留原来的规则名称。",
      `<a class="btn" href="${url("rules.html")}">返回规则库</a>`,
    );
    $("#edit-rule").hidden = true;
    return;
  }
  $("#rule-detail-content").innerHTML =
    ruleDetails(r, false, active) +
    `<div class="inset-list gap-top"><button class="list-row" id="duplicate-rule"><span class="grow"><span class="title">复制为新规则</span><span class="subtitle">保留条件，重新选择分配对象</span></span>${icon("copy")}</button><a class="list-row" href="${url("preview.html", { subject: bindingsFor(r.id)[0]?.subjects[0] || "s1" })}"><span class="grow"><span class="title">预演一次访问</span><span class="subtitle">使用明确输入检查预期结果</span></span>${icon("flask-conical")}</a><button class="list-row" id="delete-rule"><span class="grow"><span class="title" style="color:var(--red)">删除规则</span><span class="subtitle">同时移除直接分配，历史记录保留</span></span>${icon("trash-2")}</button></div>`;
  if (active && S.savedVersion !== S.activeVersion) {
    $("#edit-rule").textContent = "打开已保存版本进行编辑";
    $("#rule-detail-content").insertAdjacentHTML(
      "afterbegin",
      '<div class="notice warn"><p>当前展示正在使用的 v' +
        S.activeVersion +
        "。已保存版本为 v" +
        S.savedVersion +
        "，编辑会打开已保存的版本。</p></div>",
    );
  }
  $("#edit-rule").onclick = () =>
    go("rule-edit.html", { id: r.id, from: "rule-detail.html?id=" + r.id });
  $("#duplicate-rule").onclick = () => {
    const d = newDraft({ id: r.id });
    d.id = "r" + ++S.counter;
    d.name += " 副本";
    d.subjects = [];
    S.draft = d;
    persist();
    go("rule-edit.html", { resume: 1, from: "rules.html" });
  };
  $("#delete-rule").onclick = () => {
    const refs = S.config.groups.filter((g) => g.rules.includes(r.id));
    if (refs.length) {
      dialog({
        title: "先处理规则组中的引用",
        body:
          "「" +
          esc(r.name) +
          "」仍用于 " +
          refs.map((g) => esc(g.name)).join("、") +
          "。打开规则组移除它后，再删除。",
        confirm: "查看规则组",
        onConfirm: () => go("group-detail.html", { id: refs[0].id }),
      });
      return;
    }
    dialog({
      title: "删除这条规则？",
      body: "删除「" + esc(r.name) + "」及它的直接分配。历史访问记录保留。",
      confirm: "删除规则",
      danger: true,
      onConfirm: () => {
        const next = clone(S.config);
        next.rules = next.rules.filter((x) => x.id !== r.id);
        next.bindings = next.bindings.filter(
          (b) => !(b.kind === "rule" && b.target === r.id),
        );
        return outcome(next, "规则已删除", "rules.html");
      },
    });
  };
}
function nodeAt(path) {
  return path
    ? path.split(".").reduce((n, x) => n.children[+x], S.draft.conditions)
    : S.draft.conditions;
}
function nodeControl(n, path) {
  if (n.type === "leaf") {
    const options =
      n.field === "domain_list"
        ? S.config.lists.map((l) => [l.id, l.name])
        : choices[n.field]?.map((v) => [v, label(n.field, v)]);
    return `<div class="condition-leaf"><select class="leaf-kind" data-field="${path}" aria-label="条件类型">${Object.entries(
      fields,
    )
      .map(
        ([v, t]) =>
          `<option value="${v}" ${v === n.field ? "selected" : ""}>${t}</option>`,
      )
      .join(
        "",
      )}</select><button type="button" class="delete-condition" data-delete="${path}" aria-label="删除条件">${icon("x", "sm")}</button>${options ? `<select data-value="${path}" aria-label="${fields[n.field]}"><option value="">请选择</option>${options.map(([v, t]) => `<option value="${esc(v)}" ${v === n.value ? "selected" : ""}>${esc(t)}</option>`).join("")}</select>` : `<input data-value="${path}" value="${esc(n.value)}" aria-label="${fields[n.field]}" placeholder="${n.field.includes("port") ? "443 或 8000-8080" : n.field === "interface" ? "接口名称，例如 wlan0" : "例如 192.168.0.0/16"}">`}</div>`;
  }
  return `<div class="condition-group"><div class="condition-group-head"><select data-group="${path}" aria-label="条件组合方式"><option value="and" ${n.type === "and" ? "selected" : ""}>满足全部条件 · AND</option><option value="or" ${n.type === "or" ? "selected" : ""}>满足任一条件 · OR</option><option value="not" ${n.type === "not" ? "selected" : ""}>不满足以下条件 · NOT</option></select>${path ? `<button type="button" data-delete="${path}" class="icon-button" aria-label="删除条件组">${icon("x", "sm")}</button>` : ""}</div>${n.children.map((c, i) => nodeControl(c, path ? path + "." + i : String(i))).join("")}${!n.children.length ? '<p class="help" style="padding:10px">没有附加条件，匹配全部访问。</p>' : ""}${n.type === "not" && n.children.length ? "" : `<div class="condition-actions"><button type="button" data-add="${path}">＋ 添加条件</button><button type="button" data-add-group="${path}">＋ 添加条件组</button></div>`}</div>`;
}
export function ruleEdit() {
  if (!params.has("resume") || !S.draft)
    newDraft({
      id: params.get("id"),
      fromEvent: params.get("event"),
      fromList: params.get("list"),
      fromProtocol: params.get("protocol"),
      objectId: params.get("subject"),
    });
  const d = S.draft,
    origin = params.get("from") || "rule-detail.html?id=" + d.id;
  S.draftReturn = origin;
  persist();
  $("#rule-name").value = d.name;
  $("#rule-action").value = d.action;
  $("#rule-priority").value = d.priority;
  $("#rule-order").value = d.order;
  $("#rule-source").value = d.source;
  $("#rule-channels").value =
    d.channels?.length === 2 ? "both" : d.channels?.[0] || "connection";
  const inherited = bindingsFor(d.id).filter((b) => b.kind === "group");
  $("#scope-summary").textContent =
    (d.subjects.length
      ? d.subjects.map(subjectName).join("、") +
        " · " +
        (d.mode === "observe" ? "仅观察" : "执行规则")
      : "没有直接分配") + (inherited.length ? " · 另有规则组分配" : "");
  const scopeNotice = $("#scope-link").nextElementSibling;
  scopeNotice.className = "note";
  if (d.subjects.length && !inherited.length) scopeNotice.hidden = true;
  if (inherited.length)
    scopeNotice.innerHTML =
      "<p>通过规则组作用于 " +
      esc(
        [...new Set(inherited.flatMap((b) => b.subjects))]
          .map(subjectName)
          .join("、"),
      ) +
      "。这里仅编辑直接分配，不会解除组分配。</p>";
  $("#scope-link").href = url("rule-scope.html", {
    from: "rule-edit.html?resume=1&from=" + encodeURIComponent(origin),
  });
  const sync = () => {
    d.name = $("#rule-name").value;
    d.action = $("#rule-action").value;
    d.priority = +$("#rule-priority").value;
    d.order = +$("#rule-order").value;
    d.source = $("#rule-source").value;
    d.channels =
      $("#rule-channels").value === "both"
        ? ["dns", "connection"]
        : [$("#rule-channels").value];
    persist();
    $("#live-summary").textContent =
      (d.action === "drop" ? "阻止" : "允许") +
      " " +
      ([...new Set([...d.subjects, ...inherited.flatMap((b) => b.subjects)])]
        .length
        ? [...new Set([...d.subjects, ...inherited.flatMap((b) => b.subjects)])]
            .map(subjectName)
            .join("、")
        : "未分配对象") +
      " 中，" +
      conditionText(d.conditions) +
      "的访问。" +
      (d.mode === "observe" ? "当前仅观察，实际允许。" : "");
  };
  const advanced = $(".advanced");
  $("#live-summary").closest(".card").after(advanced);
  function draw() {
    $("#condition-tree").innerHTML = nodeControl(d.conditions, "");
    $$("[data-field]").forEach(
      (el) =>
        (el.onchange = () => {
          const n = nodeAt(el.dataset.field);
          n.field = el.value;
          n.value =
            n.field === "domain_list"
              ? S.config.lists[0]?.id || ""
              : choices[n.field]?.[0] || "";
          draw();
        }),
    );
    $$("[data-value]").forEach(
      (el) =>
        (el.oninput = () => {
          nodeAt(el.dataset.value).value = el.value;
          sync();
        }),
    );
    $$("[data-group]").forEach(
      (el) =>
        (el.onchange = () => {
          const n = nodeAt(el.dataset.group);
          if (el.value === "not" && n.children.length > 1) {
            n.children = [{ type: n.type, children: clone(n.children) }];
          }
          n.type = el.value;
          draw();
        }),
    );
    $$("[data-add]").forEach(
      (b) =>
        (b.onclick = () => {
          nodeAt(b.dataset.add).children.push({
            type: "leaf",
            field: "destination",
            value: "",
          });
          draw();
        }),
    );
    $$("[data-add-group]").forEach(
      (b) =>
        (b.onclick = () => {
          nodeAt(b.dataset.addGroup).children.push({
            type: "or",
            children: [{ type: "leaf", field: "l7", value: "TLS" }],
          });
          draw();
        }),
    );
    $$("[data-delete]").forEach(
      (b) =>
        (b.onclick = () => {
          const path = b.dataset.delete.split("."),
            i = +path.pop();
          nodeAt(path.join(".")).children.splice(i, 1);
          draw();
        }),
    );
    sync();
  }
  [
    "rule-name",
    "rule-action",
    "rule-priority",
    "rule-order",
    "rule-source",
    "rule-channels",
  ].forEach((id) => ($("#" + id).oninput = sync));
  $("#rule-form").onsubmit = (e) => e.preventDefault();
  $("#condition-help").onclick = () =>
    dialog({
      title: "把复杂条件说清楚",
      body: "AND 要求全部满足，OR 要求至少一个满足。NOT 表达不满足一个条件或分组；缺失事实不会因 NOT 变成已证实匹配。设备方向和连接发起/响应方向是不同的条件。",
      confirm: "知道了",
      cancel: "返回编辑",
    });
  $("#save-rule").onclick = (e) =>
    saving(e.currentTarget, async () => {
      sync();
      await outcome(draftConfig(), "规则已保存", origin);
    });
  draw();
}
export function ruleScope() {
  if (!S.draft) newDraft();
  $("#scope-subjects").innerHTML = subjectChecks(S.draft.subjects);
  $(`input[name="rule-mode"][value="${S.draft.mode}"]`).checked = true;
  if (platform === "linux")
    $(".page-intro p").textContent = "选择这条设置要应用的程序。";
  $("#save-scope").onclick = () => {
    S.draft.subjects = selectedSubjects();
    S.draft.mode = $('input[name="rule-mode"]:checked').value;
    persist();
    go("rule-edit.html", { resume: 1, from: S.draftReturn || "rules.html" });
  };
}
export function groups() {
  $("#groups-list").innerHTML =
    S.config.groups
      .map(
        (g) =>
          `<a class="rule-item" href="${url("group-detail.html", { id: g.id })}"><span class="tile-icon">${icon("layers")}</span><h3>${esc(g.name)}</h3><p>${g.rules.length} 条直接规则 · ${g.groups.length} 个嵌套组</p><div class="rule-foot"><span>${S.config.bindings.filter((b) => b.kind === "group" && b.target === g.id).length} 项分配</span>${icon("chevron-right")}</div></a>`,
      )
      .join("") ||
    empty("把常用规则组织起来", "创建一个规则组，就能在多个对象间复用。");
  $("#group-bindings").innerHTML =
    `<div class="inset-list">${assignmentRows(S.config.bindings.filter((b) => b.kind === "group")) || '<p class="note">尚未分配规则组。</p>'}</div>`;
}
export function groupDetail() {
  const g = S.config.groups.find((x) => x.id === (params.get("id") || "g1"));
  if (!g) {
    $("#group-detail-main").innerHTML = empty(
      "规则组已不存在",
      "返回规则组列表查看当前内容。",
    );
    $("#delete-group").hidden = true;
    return;
  }
  $("#group-detail-main").innerHTML =
    `<header class="page-intro"><div class="eyebrow">共享规则组</div><h1>${esc(g.name)}</h1><p>${groupRules(g.id).length} 条规则，包括嵌套内容</p></header>`;
  $("#group-edit-link").href = url("group-edit.html", {
    id: g.id,
    from: here(),
  });
  $("#group-assign-link").href = url("binding-edit.html", {
    group: g.id,
    from: here(),
  });
  $("#group-members").innerHTML =
    g.rules
      .map((id) => rule(id))
      .filter(Boolean)
      .map(ruleCard)
      .join("") +
    g.groups
      .map((id) =>
        row(
          S.config.groups.find((x) => x.id === id)?.name || id,
          "嵌套规则组",
          "group-detail.html?id=" + id,
        ),
      )
      .join("");
  $("#group-assignments").innerHTML =
    `<div class="inset-list">${assignmentRows(S.config.bindings.filter((b) => b.kind === "group" && b.target === g.id)) || '<p class="note">尚未分配到任何对象。</p>'}</div>`;
  $("#delete-group").onclick = () => {
    if (S.config.groups.some((x) => x.groups.includes(g.id))) {
      showError("这个组仍被其他组引用，请先移除引用。");
      return;
    }
    dialog({
      title: "删除规则组？",
      body: "移除这个组及它的直接分配；组中的规则本身保留。",
      confirm: "删除规则组",
      danger: true,
      onConfirm: () => {
        const n = clone(S.config);
        n.groups = n.groups.filter((x) => x.id !== g.id);
        n.bindings = n.bindings.filter(
          (b) => !(b.kind === "group" && b.target === g.id),
        );
        return outcome(n, "规则组已删除", "groups.html");
      },
    });
  };
}
export function groupEdit() {
  const g = clone(
    S.config.groups.find((x) => x.id === params.get("id")) || {
      id: "g" + ++S.counter,
      name: "",
      rules: [],
      groups: [],
    },
  );
  $("#group-name").value = g.name;
  $("#group-rule-choices").innerHTML = S.config.rules
    .map(
      (r) =>
        `<label class="choice"><input type="checkbox" name="group-rule" value="${r.id}" ${g.rules.includes(r.id) ? "checked" : ""}><span class="grow"><strong>${esc(r.name)}</strong><small>${r.action === "drop" ? "阻止" : "允许"} · 优先级 ${r.priority}</small></span></label>`,
    )
    .join("");
  $("#group-group-choices").innerHTML =
    S.config.groups
      .filter((x) => x.id !== g.id)
      .map(
        (x) =>
          `<label class="choice"><input type="checkbox" name="group-group" value="${x.id}" ${g.groups.includes(x.id) ? "checked" : ""}><span class="grow"><strong>${esc(x.name)}</strong><small>${x.rules.length} 条直接规则</small></span></label>`,
      )
      .join("") ||
    '<p class="note">没有其他规则组可包含。可以先创建，再编辑组合。</p>';
  $("#save-group").onclick = (e) =>
    saving(e.currentTarget, async () => {
      g.name = $("#group-name").value.trim();
      g.rules = selectedSubjects("group-rule");
      g.groups = selectedSubjects("group-group");
      const n = clone(S.config),
        i = n.groups.findIndex((x) => x.id === g.id);
      if (i < 0) n.groups.push(g);
      else n.groups[i] = g;
      await outcome(n, "规则组已保存", "group-detail.html?id=" + g.id);
    });
}
export function bindingEdit() {
  const existing = S.config.bindings.find((b) => b.id === params.get("id"));
  let b = clone(
    existing || {
      id: "b" + ++S.counter,
      kind: params.has("group") ? "group" : "rule",
      target:
        params.get("group") || params.get("rule") || S.config.rules[0]?.id,
      subjects: params.has("subject") ? [params.get("subject")] : [],
      mode: "enforce",
    },
  );
  $("#binding-kind").value = b.kind;
  $("#binding-mode").value = b.mode;
  $("#binding-subjects").innerHTML = subjectChecks(b.subjects);
  function targets() {
    const kind = $("#binding-kind").value;
    $("#binding-target").innerHTML = (
      kind === "rule" ? S.config.rules : S.config.groups
    )
      .map((x) => `<option value="${x.id}">${esc(x.name)}</option>`)
      .join("");
    if (
      (kind === "rule" ? S.config.rules : S.config.groups).some(
        (x) => x.id === b.target,
      )
    )
      $("#binding-target").value = b.target;
  }
  targets();
  $("#binding-kind").onchange = targets;
  $("#save-binding").onclick = (e) =>
    saving(e.currentTarget, async () => {
      b.kind = $("#binding-kind").value;
      b.target = $("#binding-target").value;
      b.subjects = selectedSubjects();
      b.mode = $("#binding-mode").value;
      const n = clone(S.config);
      n.bindings = n.bindings.filter((x) => x.id !== b.id);
      n.bindings.push(b);
      await outcome(
        n,
        "分配已更新",
        params.get("from") || "rule-detail.html?id=" + b.target,
      );
    });
  $("#remove-binding").hidden = !existing;
  $("#remove-binding").onclick = () =>
    dialog({
      title: "解除分配？",
      body: "规则资产会保留，这项分配中的对象将不再通过它应用规则。",
      confirm: "解除分配",
      danger: true,
      onConfirm: () => {
        const n = clone(S.config);
        n.bindings = n.bindings.filter((x) => x.id !== b.id);
        return outcome(n, "分配已解除", params.get("from") || "rules.html");
      },
    });
}
export { domains, domainDetail, domainEdit } from "./domains.js";
function parseDomains() {
  const text = $("#domain-import-text").value,
    format = $("#domain-format").value;
  const lines = text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!lines.length) throw Error("请填写至少一个域名条目。");
  return lines.map((line, i) => {
    let name = "",
      mode = "exact",
      m;
    if (format === "plain") name = line;
    else if (
      format === "native" &&
      (m = line.match(/^(exact|descendants) (\S+)$/))
    ) {
      mode = m[1];
      name = m[2];
    } else if (format === "adblock" && (m = line.match(/^\|\|([^\^]+)\^$/))) {
      mode = "descendants";
      name = m[1];
    } else if (
      format === "clash" &&
      (m = line.match(/^(DOMAIN|DOMAIN-SUFFIX),([^,]+)$/))
    ) {
      mode = m[1] === "DOMAIN" ? "exact" : "descendants";
      name = m[2];
    } else throw Error(`第 ${i + 1} 行不符合所选格式，不会忽略额外选项。`);
    if (!validDomain(name)) throw Error(`第 ${i + 1} 行的域名无效。`);
    return { name: name.toLowerCase(), mode };
  });
}
export function domainImport() {
  let reviewed = "";
  $("#domain-format").onchange = () => {
    $("#domain-format-help").textContent = {
      plain: "每行一个域名，精确匹配。",
      native: "例如：descendants example.net",
      adblock: "只接受 ||example.net^ 形式，不支持额外选项。",
      clash: "只接受 DOMAIN,example.net 或 DOMAIN-SUFFIX,example.net。",
    }[$("#domain-format").value];
    reviewed = "";
    $("#domain-import-review").innerHTML = "";
  };
  $("#review-domain-import").onclick = () => {
    try {
      const entries = parseDomains();
      $("#form-error").textContent = "";
      reviewed = JSON.stringify(entries);
      $("#domain-import-review").innerHTML =
        '<h2 class="section-label">将导入 ' +
        entries.length +
        ' 个条目</h2><div class="inset-list">' +
        entries
          .map(
            (e) =>
              `<div class="list-row"><span class="grow"><span class="title">${esc(e.name)}</span><span class="subtitle">${e.mode === "exact" ? "仅此名称" : "名称及子域名"}</span></span>${icon("check")}</div>`,
          )
          .join("") +
        "</div>";
    } catch (e) {
      showError(e.message);
    }
  };
  $("#save-domain-import").onclick = (e) =>
    saving(e.currentTarget, async () => {
      const entries = parseDomains();
      if (JSON.stringify(entries) !== reviewed)
        throw Error("请先预览当前条目，再保存。");
      const l = {
        id: "d" + ++S.counter,
        name: $("#domain-import-name").value.trim(),
        source: "本地导入",
        sourceKind: "import",
        entries,
      };
      const n = clone(S.config);
      n.lists.push(l);
      await outcome(n, "域名列表已导入", "domain-detail.html?id=" + l.id);
    });
}
