import {
  S,
  params,
  clone,
  commit,
  persist,
  delay,
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
  showError,
} from "./ui.js";
import { ruleUse } from "./rule-use.js";
import { seedConfig, seedSubscriptionUpdate } from "./seed.js";
import {
  sourceEntries,
  listEntries,
  listReferences,
  entryChanges,
  entryKey,
  entryMatches,
} from "./domain-lists.js";

const getList = (id = params.get("id") || "d1") =>
  S.config.lists.find((l) => l.id === id);
const matchLabel = (entry) =>
  entry.mode === "descendants" ? "名称及子域名" : "仅此名称";
const sourceLabel = (l) =>
  l.subscription
    ? l.subscription.stopped
      ? "已停止的订阅"
      : "订阅"
    : l.sourceKind === "import"
      ? "一次性导入"
      : "手动维护";
let reviewing = params.get("review") === "update";
let firstDetail = true;

async function saveList(list, message) {
  const next = clone(S.config);
  const index = next.lists.findIndex((l) => l.id === list.id);
  if (index < 0) next.lists.push(list);
  else next.lists[index] = list;
  await commit(next, { message, returnTo: "domain-detail.html?id=" + list.id });
}
function consumerText(list, config = S.config) {
  const refs = listReferences(list.id, config);
  const people = [
    ...new Set(
      refs.flatMap((r) => ruleUse(r, config).subjects.map((s) => s.name)),
    ),
  ];
  return people.length
    ? "涉及应用：" + people.join("、")
    : refs.length
      ? "引用规则尚未分配给应用"
      : "尚未用于规则";
}
function entryRows(entries, origin = "", exclusions = []) {
  return entries
    .map((entry) => {
      const whole = exclusions.some(
        (exception) =>
          (exception.mode === "descendants" || entry.mode === "exact") &&
          entryMatches(exception, entry.name),
      );
      const partial = whole
        ? []
        : exclusions.filter((exception) => entryMatches(entry, exception.name));
      return `<div class="list-row ${whole ? "locally-excluded" : ""}"><span class="grow"><span class="title">${esc(entry.name)}${whole ? '<small class="badge gray">已从本列表排除</small>' : ""}</span><span class="subtitle">${matchLabel(entry)}${origin ? " · " + origin : ""}</span>${partial.length ? `<span class="entry-exception">本地例外：${partial.map((e) => `${esc(e.name)}（${matchLabel(e)}）`).join("、")}</span>` : ""}</span>${icon("globe")}</div>`;
    })
    .join("");
}
function checkState(list) {
  const sub = list.subscription;
  const check = S.subscriptionChecks[list.id];
  if (sub.stopped)
    return {
      label: "已停止订阅",
      tone: "gray",
      detail: "现有资料、本地补充与排除继续保留；不再检查更新。",
    };
  if (check?.status === "checking")
    return { label: "正在检查…", tone: "blue", detail: "现有资料继续使用。" };
  if (check?.status === "failed")
    return { label: "检查失败", tone: "amber", detail: check.message };
  if (check?.status === "save-failed")
    return { label: "更新尚未保存", tone: "amber", detail: check.message };
  if (S.subscriptionCandidates[list.id])
    return {
      label: "新版本可用",
      tone: "blue",
      detail: "先核对条目变化与使用范围，再决定是否采用。",
    };
  if (check?.status === "applied") {
    const used =
      S.running &&
      listReferences(list.id, S.active).some(
        (r) => ruleUse(r, S.active).subjects.length,
      );
    const pending = S.savedVersion !== S.activeVersion;
    return {
      label: pending
        ? "已保存，等待生效"
        : used
          ? "新版本已开始使用"
          : "新版本已保存",
      tone: pending ? "amber" : "blue",
      detail: pending
        ? "新资料尚未开始使用；当前规则保留之前的资料与本地修改。"
        : used
          ? `正在使用 ${sub.version} · 配置 v${S.activeVersion}。本地补充与排除已保留。`
          : S.running
            ? "还没有规则使用这份列表。资料与本地修改已保留。"
            : "当前未运行；资料与本地修改已保留，恢复后可继续使用。",
    };
  }
  return {
    label: check ? "没有新版本" : sub.version ? "资料已保留" : "还未取得资料",
    tone: "gray",
    detail: !sub.automatic
      ? "自动检查已暂停，仍可手动检查。"
      : "更新时保留你的本地补充与排除。",
  };
}
function nextCheck(sub) {
  if (sub.stopped) return "已停止";
  if (!sub.automatic) return "已暂停";
  return `每 ${sub.intervalHours || 24} 小时 · ${sub.nextCheck || "明天 08:30"}`;
}
function nextCheckTime(hours) {
  const minutes = 9 * 60 + 41 + hours * 60,
    days = Math.floor(minutes / 1440);
  return `${days === 0 ? "今天" : days === 1 ? "明天" : "后天"} ${String(Math.floor(minutes / 60) % 24).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}`;
}
function drawSource(list) {
  const sub = list.subscription,
    check = S.subscriptionChecks[list.id];
  const box = $("#domain-source-panel");
  if (!sub) {
    box.innerHTML = `<section class="list-source"><h2>来源与维护</h2><p>${sourceLabel(list)} · ${esc(list.source || "本地列表")}</p><p class="note">条目由你维护，不会从远程来源自动更新。</p></section>`;
    return;
  }
  const state = checkState(list);
  const active = S.active.lists.find((l) => l.id === list.id);
  const pending = S.savedVersion !== S.activeVersion;
  const appliedText = `资料修改已保存，配置尚未生效。${active?.subscription?.version ? "当前规则仍使用此前的资料与本地修改（" + active.subscription.version + "）。" : "当前规则尚未使用这份资料。"}`;
  const candidate = S.subscriptionCandidates[list.id];
  const using =
    S.running &&
    listReferences(list.id, S.active).some(
      (r) => ruleUse(r, S.active).subjects.length,
    );
  const currentVersion = active?.subscription?.version || "尚无资料";
  const origin = new URL(sub.url).host;
  const detail =
    check || candidate || sub.stopped
      ? `<p class="source-state-detail" role="status">${esc(state.detail)}</p>`
      : "";
  const toggle = `<button class="btn" id="toggle-subscription">${sub.automatic ? "暂停自动检查" : "恢复自动检查"}</button>`;
  box.innerHTML = `<section class="list-source compact-source"><div class="section-heading"><h2>来源与更新</h2><a class="text-link" href="${url("domain-subscription.html", { id: list.id, from: here() })}">管理来源</a></div><span class="badge ${state.tone}">${state.label}</span>${detail}
    <div class="source-brief-facts"><strong>${using ? "正在使用资料 " + esc(currentVersion) : S.running ? "尚无规则使用" : "当前未运行"}</strong>${!using || pending ? `<span>已保存资料 ${esc(sub.version || "尚无资料")}</span>` : ""}<span>最近检查 ${esc(check?.at || sub.lastCheck || sub.lastUpdate || "尚未检查")} · <a title="${esc(sub.url)}" href="${url("domain-subscription.html", { id: list.id, from: here() })}">${esc(origin)}</a></span></div>
    ${sub.dataUrl && sub.dataUrl !== sub.url ? `<p class="note">来源已修改；现有资料仍来自 ${esc(sub.dataUrl)}，新来源尚未采用。</p>` : ""}
    <p class="list-apply-state ${pending ? "pending" : ""}">${pending ? appliedText : ""}<a class="text-link" href="${url("config.html", { from: here() })}">${pending ? "查看生效状态" : "查看使用配置 v" + S.activeVersion}</a></p>
    <div class="source-actions">${sub.stopped ? '<button class="btn primary" id="resume-subscription">重新启用订阅</button>' : candidate ? '<button class="btn primary" id="review-subscription">审阅更新</button><button class="btn" id="check-subscription">再次检查</button>' : `<button class="btn primary" id="check-subscription" ${check?.status === "checking" ? "disabled" : ""}>${check?.status === "checking" ? "正在检查…" : "立即检查更新"}</button>${toggle}`}</div>
    <details class="subscription-more"><summary>检查安排与停止订阅</summary><dl class="detail-pairs subscription-facts"><dt>完整地址</dt><dd class="subscription-url">${esc(sub.url)}</dd><dt>资料更新</dt><dd>${esc(sub.lastUpdate || "尚未更新")}</dd><dt>自动检查</dt><dd>${nextCheck(sub)}</dd><dt>发现新版本</dt><dd>${sub.updateMode === "automatic" ? "自动采用，保留本地补充与排除" : "先审阅，再采用"}</dd></dl>${candidate && !sub.stopped ? toggle : ""}${!sub.stopped ? '<button class="text-link stop-subscription" id="stop-subscription">停止订阅，保留现有资料</button>' : ""}</details></section>`;
  $("#check-subscription")?.addEventListener("click", () =>
    checkSubscription(list.id),
  );
  $("#review-subscription")?.addEventListener("click", () => {
    reviewing = true;
    drawUpdateReview(list);
    $("#subscription-review-title")?.focus();
  });
  $("#toggle-subscription")?.addEventListener("click", (e) =>
    saving(e.currentTarget, async () => {
      const next = clone(getList(list.id));
      next.subscription.automatic = !sub.automatic;
      await saveList(
        next,
        next.subscription.automatic ? "已恢复自动检查" : "已暂停自动检查",
      );
      domainDetail();
      toast("现有资料与本地修改保持不变");
    }),
  );
  $("#resume-subscription")?.addEventListener("click", (e) =>
    saving(e.currentTarget, async () => {
      const next = clone(getList(list.id));
      next.subscription.stopped = false;
      next.subscription.automatic = true;
      await saveList(next, "已重新启用订阅");
      domainDetail();
    }),
  );
  $("#stop-subscription")?.addEventListener("click", () =>
    dialog({
      title: "停止这个订阅？",
      body: `现有资料、本地补充与排除会保留，使用它的规则保持原样。停止后不再检查更新。<br>${esc(consumerText(list))}`,
      confirm: "停止订阅并保留资料",
      onConfirm: async () => {
        const next = clone(getList(list.id));
        next.subscription.stopped = true;
        next.subscription.automatic = false;
        await saveList(next, "已停止订阅，资料保留");
        delete S.subscriptionCandidates[list.id];
        persist();
        reviewing = false;
        domainDetail();
      },
    }),
  );
}
export function domains() {
  $("#domain-lists").innerHTML =
    S.config.lists
      .map((list) => {
        const check = list.subscription ? checkState(list) : null;
        return `<a class="rule-item domain-list-card" href="${url("domain-detail.html", { id: list.id, from: here() })}"><div class="between"><span class="tile-icon">${icon(list.subscription ? "refresh-cw" : "globe")}</span><span class="badge ${check?.tone || "gray"}">${sourceLabel(list)}</span></div><h3>${esc(list.name)}</h3><p>${list.entries.length} 条匹配条目${list.localExclusions?.length ? " · " + list.localExclusions.length + " 项本地排除" : ""}</p>${check ? `<p class="subscription-list-state">${check.label} · ${esc(list.subscription.version || "尚无资料")}</p>` : ""}<div class="rule-foot"><span>${esc(consumerText(list))}</span>${icon("chevron-right")}</div></a>`;
      })
      .join("") ||
    empty("还没有域名列表", "新建一个列表、导入条目，或添加订阅。");
}
export function domainDetail() {
  const list = getList();
  if (!list) {
    $("#domain-detail-main").innerHTML = empty(
      "列表已不存在",
      "返回域名列表查看当前内容。",
    );
    $("#domain-create-rule").hidden = true;
    $("#delete-domain").hidden = true;
    return;
  }
  const refs = listReferences(list.id, S.config);
  $("#domain-detail-main").innerHTML =
    `<header class="page-intro"><div class="eyebrow">${sourceLabel(list)}</div><h1>${esc(list.name)}</h1><p>${esc(consumerText(list))}</p>${refs[0] ? `<a class="domain-rule-preview" href="${url("rule-detail.html", { id: refs[0].id, from: here() })}"><span>${esc(refs[0].name)}</span><small>${ruleUse(refs[0], S.config).label}</small>${icon("chevron-right")}</a>` : ""}</header>`;
  drawSource(list);
  $("#domain-edit-link").href = url("domain-edit.html", {
    id: list.id,
    from: here(),
  });
  $("#domain-edit-link").textContent = list.subscription
    ? "编辑本地补充与排除"
    : "编辑";
  const additions = new Set((list.localAdditions || []).map(entryKey));
  $("#domain-entries").innerHTML =
    list.entries
      .map((entry) =>
        entryRows(
          [entry],
          list.subscription
            ? additions.has(entryKey(entry))
              ? "本地补充"
              : "订阅来源"
            : "",
          list.localExclusions || [],
        ),
      )
      .join("") ||
    empty(
      "还没有匹配条目",
      list.subscription
        ? "检查订阅取得资料，或添加本地补充。"
        : "编辑列表，加入需要的域名。",
    );
  $("#domain-local-exclusions").innerHTML = list.localExclusions?.length
    ? `<section class="local-exclusions"><h3>从本列表排除</h3><p class="note">这些名称不匹配本列表；其他列表和规则仍会独立判断。</p><div class="inset-list">${entryRows(list.localExclusions)}</div></section>`
    : "";
  $("#domain-references").innerHTML =
    refs.map((r) => ruleCard(r)).join("") ||
    empty("还没有规则使用它", "可以用这个列表创建查询规则或连接规则。");
  const create = $("#domain-create-rule"),
    footer = create.closest(".footer-action");
  if (footer) {
    create.className = "btn full gap-top";
    $("#domain-references").after(create);
    footer.remove();
  }
  $("#domain-create-rule").onclick = () =>
    go("rule-edit.html", { list: list.id, new: 1, from: here() });
  $("#delete-domain").onclick = () => {
    if (refs.length) {
      showError(`「${refs[0].name}」仍使用这个列表。先修改引用规则，再删除。`);
      return;
    }
    dialog({
      title: "删除这个域名列表？",
      body: "条目、本地修改和订阅设置将被移除。",
      confirm: "删除列表",
      danger: true,
      onConfirm: async () => {
        const next = clone(S.config);
        next.lists = next.lists.filter((l) => l.id !== list.id);
        await commit(next, {
          message: "域名列表已删除",
          returnTo: "domains.html",
        });
        go("config-result.html");
      },
    });
  };
  drawUpdateReview(list);
  if (firstDetail && reviewing)
    requestAnimationFrame(() => $("#subscription-review-title")?.focus());
  firstDetail = false;
  if (params.get("check") === "1" && !S.subscriptionChecks[list.id])
    checkSubscription(list.id);
}
function drawUpdateReview(list) {
  const candidate = S.subscriptionCandidates[list.id];
  const box = $("#domain-update-review");
  if (!candidate || !reviewing) {
    box.innerHTML = "";
    return;
  }
  const changes = entryChanges(sourceEntries(list), candidate.sourceEntries);
  box.innerHTML = `<section class="subscription-review"><h2 id="subscription-review-title" tabindex="-1">核对订阅更新</h2><p>${esc(list.subscription.version || "尚无资料")} → ${esc(candidate.version)}</p><p class="note">${esc(consumerText(list))}</p><div class="subscription-entry-diff"><h3>新增 ${changes.added.length} 条</h3><div class="inset-list">${entryRows(changes.added) || '<p class="note">没有新增条目</p>'}</div><h3>移除 ${changes.removed.length} 条</h3><div class="inset-list">${entryRows(changes.removed) || '<p class="note">没有移除条目</p>'}</div></div><div class="preserved-local"><strong>你的本地修改会保留</strong><p>${list.localAdditions?.length || 0} 条补充 · ${list.localExclusions?.length || 0} 项排除</p>${[...(list.localAdditions || []), ...(list.localExclusions || [])].length ? `<p class="note">${esc([...(list.localAdditions || []), ...(list.localExclusions || [])].map((e) => e.name).join("、"))}</p>` : ""}</div><p class="note">采用后，引用本列表的规则将按新资料判断后续活动。历史记录保留当时的结果。</p><div class="source-actions"><button class="btn primary" id="apply-subscription-update">使用这个版本</button><button class="btn" id="defer-subscription-update">暂不更新</button></div></section>`;
  $("#apply-subscription-update").onclick = (e) =>
    saving(e.currentTarget, () => applySubscriptionUpdate(list.id));
  $("#defer-subscription-update").onclick = () => {
    reviewing = false;
    drawUpdateReview(list);
    $("#review-subscription")?.focus();
  };
}
async function applySubscriptionUpdate(id) {
  const list = clone(getList(id)),
    candidate = S.subscriptionCandidates[id];
  if (!candidate || candidate.url !== list.subscription.url)
    throw Error("订阅来源已改变，请重新检查后再采用。");
  list.subscription.sourceEntries = clone(candidate.sourceEntries);
  list.subscription.version = candidate.version;
  list.subscription.lastUpdate = "今天 09:41";
  list.subscription.lastCheck = "今天 09:41";
  list.subscription.dataUrl = candidate.url;
  list.subscription.dataFormat = candidate.format || list.subscription.format;
  list.subscription.nextCheck = nextCheckTime(
    list.subscription.intervalHours || 24,
  );
  list.entries = listEntries(list);
  await saveList(list, "订阅资料已更新，本地修改已保留");
  delete S.subscriptionCandidates[id];
  S.subscriptionChecks[id] = { status: "applied", at: "今天 09:41" };
  reviewing = false;
  persist();
  domainDetail();
}
export async function checkSubscription(id, scheduled = false) {
  const list = getList(id),
    sub = list?.subscription;
  if (!sub || sub.stopped || (scheduled && !sub.automatic)) return;
  S.subscriptionChecks[id] = { status: "checking", at: "今天 09:41" };
  persist();
  drawSource(list);
  await delay(520);
  const response = S.subscriptionResponses[id];
  delete S.subscriptionResponses[id];
  if (response === "failure") {
    S.subscriptionChecks[id] = {
      status: "failed",
      at: "今天 09:41",
      message: "订阅服务器暂时无法连接。现有资料和本地修改仍保留。",
    };
  } else {
    if (
      response === "update" ||
      !sub.version ||
      (sub.dataUrl && sub.dataUrl !== sub.url) ||
      (sub.dataFormat && sub.dataFormat !== sub.format)
    ) {
      const sample = !sub.version
        ? {
            version: "2026.09.29.1",
            sourceEntries: seedConfig().lists[0].entries,
          }
        : seedSubscriptionUpdate();
      const incoming = sample.sourceEntries.map((entry) => ({
        ...entry,
        mode:
          sub.format === "plain"
            ? "exact"
            : sub.format === "adblock"
              ? "descendants"
              : entry.mode,
      }));
      S.subscriptionCandidates[id] = {
        ...sample,
        sourceEntries: incoming,
        url: sub.url,
        format: sub.format,
      };
    }
    S.subscriptionChecks[id] = {
      status: S.subscriptionCandidates[id] ? "available" : "current",
      at: "今天 09:41",
    };
    if (sub.updateMode === "automatic" && S.subscriptionCandidates[id]) {
      try {
        await applySubscriptionUpdate(id);
        return;
      } catch (error) {
        S.subscriptionChecks[id] = {
          status: "save-failed",
          at: "今天 09:41",
          message: "新资料尚未保存：" + error.message,
        };
      }
    }
  }
  persist();
  domainDetail();
}

export function domainEdit() {
  const original = getList(params.get("id"));
  const list = clone(
    original || {
      id: "d" + ++S.counter,
      name: "",
      source: "手动维护",
      sourceKind: "manual",
      entries: [],
    },
  );
  const subscription = !!list.subscription;
  const edited = subscription ? (list.localAdditions ||= []) : list.entries;
  const excluded = (list.localExclusions ||= []);
  $("#domain-name").value = list.name;
  $("#domain-source").value = list.source || "手动维护";
  $(".page-intro h1").textContent = subscription
    ? "本地补充与排除"
    : original
      ? "编辑域名列表"
      : "新建域名列表";
  $(".page-intro .eyebrow").textContent = original?.name || "手动维护";
  $(".page-intro p").textContent = subscription
    ? "订阅更新保留这些修改；排除只作用于本列表。"
    : "填写域名和匹配范围，再选择哪些规则使用它。";
  $("#domain-source").closest(".field").hidden = subscription;
  $(".section-label").textContent = subscription ? "本地补充" : "匹配条目";
  $("#save-domain").textContent = subscription
    ? "保存本地修改"
    : "保存域名列表";
  if (subscription) {
    const panel = document.createElement("section");
    panel.className = "local-exclusion-editor";
    panel.innerHTML =
      '<h2 class="section-label">从本列表排除</h2><p class="note">排除优先于本列表的来源条目与本地补充。其他列表和规则继续独立判断。</p><div id="domain-edit-exclusions"></div><button id="add-domain-exclusion" class="btn full">添加排除</button>';
    $("#add-domain-entry").after(panel);
  }
  function drawEntries(container, entries, exclusion = false) {
    const valueAttr = exclusion ? "exclusion-value" : "domain-value";
    container.innerHTML =
      entries
        .map(
          (entry, i) =>
            `<div class="domain-entry-editor"><div class="between"><select class="input" data-entry-mode="${i}" aria-label="${exclusion ? "排除" : "匹配"}范围"><option value="exact" ${entry.mode === "exact" ? "selected" : ""}>仅此名称</option><option value="descendants" ${entry.mode === "descendants" ? "selected" : ""}>名称及子域名</option></select><button class="icon-button" data-entry-remove="${i}" aria-label="移除${exclusion ? "排除" : "条目"}">${icon("x")}</button></div><label><span class="sr-only">域名</span><input class="input" data-${valueAttr}="${i}" value="${esc(entry.name)}" placeholder="example.net"></label></div>`,
        )
        .join("") ||
      `<p class="note">${exclusion ? "没有本地排除" : "还没有本地补充"}</p>`;
    $$("[data-entry-mode]", container).forEach(
      (el) =>
        (el.onchange = () => (entries[+el.dataset.entryMode].mode = el.value)),
    );
    $$(`[data-${valueAttr}]`, container).forEach(
      (el) =>
        (el.oninput = () =>
          (entries[+el.getAttribute("data-" + valueAttr)].name = el.value
            .trim()
            .toLowerCase())),
    );
    $$("[data-entry-remove]", container).forEach(
      (el) =>
        (el.onclick = () => {
          entries.splice(+el.dataset.entryRemove, 1);
          drawEntries(container, entries, exclusion);
        }),
    );
  }
  drawEntries($("#domain-edit-entries"), edited);
  $("#add-domain-entry").onclick = () => {
    edited.push({ name: "", mode: "exact" });
    drawEntries($("#domain-edit-entries"), edited);
    $$("[data-domain-value]").at(-1).focus();
  };
  if (subscription) {
    drawEntries($("#domain-edit-exclusions"), excluded, true);
    $("#add-domain-exclusion").onclick = () => {
      excluded.push({ name: "", mode: "exact" });
      drawEntries($("#domain-edit-exclusions"), excluded, true);
      $$("[data-exclusion-value]").at(-1).focus();
    };
  }
  $("#save-domain").onclick = (e) =>
    saving(e.currentTarget, async () => {
      list.name = $("#domain-name").value.trim();
      if (!subscription) list.source = $("#domain-source").value.trim();
      list.entries = listEntries(list);
      await saveList(
        list,
        subscription ? "本地补充与排除已保存" : "域名列表已保存",
      );
      go(params.get("from") || "domain-detail.html", { id: list.id });
    });
}

export function domainSubscription() {
  const original = params.get("id") ? getList(params.get("id")) : null;
  const list = clone(
    original || {
      id: "d" + ++S.counter,
      name: "",
      source: "订阅文件",
      sourceKind: "subscription",
      entries: [],
      localAdditions: [],
      localExclusions: [],
    },
  );
  const sub = list.subscription || {
    url: "",
    automatic: true,
    intervalHours: 24,
    format: "plain",
    updateMode: "review",
    sourceEntries: [],
    version: null,
  };
  $(".page-intro h1").textContent = original ? "管理订阅来源" : "添加订阅";
  $(".page-intro .eyebrow").textContent = original?.name || "域名列表";
  $("#subscription-name").value = list.name;
  $("#subscription-url").value = sub.url;
  $("#subscription-format").value = sub.format || "native";
  $("#subscription-interval").value = String(sub.intervalHours || 24);
  $("#subscription-automatic").checked = sub.automatic && !sub.stopped;
  $("#subscription-automatic").disabled = !!sub.stopped;
  $("#subscription-update-mode").value = sub.updateMode || "review";
  function adoptionChoice(updateUI = true) {
    const candidate = S.subscriptionCandidates[list.id];
    const adopt =
      !sub.stopped &&
      candidate &&
      $("#subscription-update-mode").value === "automatic" &&
      $("#subscription-url").value.trim() === sub.url &&
      $("#subscription-format").value === (sub.format || "native");
    if (updateUI) {
      $("#subscription-adoption").hidden = !adopt && !sub.stopped;
      $("#subscription-adoption").textContent = sub.stopped
        ? "此订阅已停止。保存来源不会重新启用；回到列表后可以明确重新启用。"
        : adopt
          ? `已检查到 ${candidate.version}。保存时将一并采用这一版，以后检查到新版本时自动采用。本地补充与排除保留。`
          : "";
      $("#save-subscription").textContent = adopt
        ? "保存并采用待更新版本"
        : "保存订阅";
    }
    return adopt;
  }
  [
    "#subscription-update-mode",
    "#subscription-url",
    "#subscription-format",
  ].forEach((selector) => {
    $(selector).addEventListener("input", adoptionChoice);
    $(selector).addEventListener("change", adoptionChoice);
  });
  adoptionChoice();
  $("#save-subscription").onclick = (e) =>
    saving(e.currentTarget, async () => {
      list.name = $("#subscription-name").value.trim();
      const address = $("#subscription-url").value.trim();
      let parsed;
      try {
        parsed = new URL(address);
      } catch {
        throw Error(
          "请填写完整的订阅文件地址，例如 https://lists.example.org/privacy.txt。",
        );
      }
      if (!["https:", "http:"].includes(parsed.protocol))
        throw Error("订阅地址需要以 https:// 或 http:// 开头。");
      const changed =
        address !== sub.url ||
        $("#subscription-format").value !== (sub.format || "native");
      const adopt = adoptionChoice(false);
      list.subscription = {
        ...sub,
        url: address,
        format: $("#subscription-format").value,
        dataFormat: sub.dataFormat || sub.format,
        intervalHours: +$("#subscription-interval").value,
        automatic: $("#subscription-automatic").checked,
        updateMode: $("#subscription-update-mode").value,
        stopped: !!sub.stopped,
      };
      list.sourceKind = "subscription";
      if (adopt) {
        const candidate = S.subscriptionCandidates[list.id];
        Object.assign(list.subscription, {
          sourceEntries: clone(candidate.sourceEntries),
          version: candidate.version,
          lastUpdate: "今天 09:41",
          lastCheck: "今天 09:41",
          dataUrl: address,
          dataFormat: list.subscription.format,
          nextCheck: nextCheckTime(list.subscription.intervalHours),
        });
        list.entries = listEntries(list);
      }
      await saveList(list, "订阅设置已保存");
      if (changed || !original) {
        delete S.subscriptionChecks[list.id];
        delete S.subscriptionCandidates[list.id];
      }
      if (adopt) {
        delete S.subscriptionCandidates[list.id];
        S.subscriptionChecks[list.id] = { status: "applied", at: "今天 09:41" };
      }
      persist();
      go(params.get("from") || "domain-detail.html", {
        id: list.id,
        check: changed || !original ? 1 : null,
      });
    });
}
