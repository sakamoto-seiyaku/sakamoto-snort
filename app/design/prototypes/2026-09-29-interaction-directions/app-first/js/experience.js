import { ruleUse } from "./rule-use.js";
import {
  normalizeOutcome,
  outcomeOptions,
  matchesOutcome,
  outcomeLabel,
} from "./activity-filters.js";
import {
  connectionFacts,
  connectionRow,
  connectionSummary,
  connectionOverview,
  connectionTools,
  matchConnection,
  isHeld,
  stamp,
} from "./connection-view.js";
import {
  S,
  params,
  platform,
  allSubjects,
  subject,
  subjectName,
  subjectRules,
  bindingsFor,
  quickBlock,
  setBlock,
  clone,
  commit,
  persist,
  selectRange,
  bytes,
  rule,
  conditionText,
  delay,
} from "./model.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  here,
  appIcon,
  empty,
  toast,
} from "./ui.js";
import {
  connections,
  queries,
  activity,
  appMetrics,
  record,
  clock,
  periodText,
  saveDecision,
  sampleNewActivity,
  directionBytes,
  coverageGaps,
} from "./network-data.js";
import {
  appRow,
  graph,
  bindGraph,
  identity,
  bindPeriod,
  sheet,
  closeSheet,
  recordRow,
  resultText,
  channelLabel,
  currentRules,
  controlSummary,
  rememberScroll,
} from "./experience-ui.js";
const selectedApp = () =>
  subject(params.get("app") || params.get("id") || S.selected) || subject("s4");
function setBack(file, label = "返回") {
  const b = $(".topbar .back");
  if (b) {
    b.href = url(file);
    b.innerHTML = icon("chevron-left") + esc(label);
  }
}
function link(id, file, values = {}) {
  const a = $("#" + id);
  if (a) a.href = url(file, values);
}
function countLine(app) {
  const m = appMetrics(app);
  return `${m.connections} 条连接 · ${m.queries} 次域名查询`;
}
function appliedEntries(app) {
  const rs = currentRules(app);
  return (
    rs
      .map((r) => {
        const use = ruleUse(r, S.active, app);
        return `<a class="applied-control" href="${url("rule-detail.html", { id: r.id, app, active: 1, from: here() })}"><span class="record-mark ${use.tone === "red" ? "blocked" : ""}">${icon(use.icon)}</span><span class="grow"><h3>${esc(r.name)}</h3><p class="effective-rule-use">${use.label}</p><p>${channelLabel(r)} · ${use.subjects.some((s) => s.viaGroup) ? "通过规则组使用" : "用于这个应用"}${use.mode === "observe" ? " · " + use.definition : ""}</p></span>${icon("chevron-right")}</a>`;
      })
      .join("") || '<p class="note">尚未为这个应用设置单独规则。</p>'
  );
}
function pendingNotice() {
  return S.savedVersion !== S.activeVersion
    ? `<div class="persistent-result pending">有修改已保存，尚未开始使用。<br><a href="${url("config.html")}">查看并处理</a></div>`
    : "";
}
export function home() {
  function draw() {
    const list = allSubjects()
      .map((a) => ({ a, m: appMetrics(a.id) }))
      .sort((a, b) => a.m.latest - b.m.latest);
    const total = appMetrics("all");
    $("#period-picker").textContent = periodText();
    $("#device-summary").innerHTML =
      `${periodText()}收发 <strong>${bytes(total.bytes)}</strong><span class="summary-status"><span class="dot"></span>${S.running ? "联网设置正在执行" : "运行已暂停，保留已有活动"}</span>`;
    $("#home-apps").innerHTML = list.map((x) => appRow(x.a)).join("");
    $("#device-chart").innerHTML =
      `<span class="traffic-label">全部应用的传输变化</span>${graph("all")}<p class="graph-hint">点一个时段，看看哪些应用有活动。</p>`;
    const top = [...list].sort((a, b) => b.m.bytes - a.m.bytes)[0];
    $("#device-observation").innerHTML =
      `<div class="insight-note">${icon("activity")}<p>${top?.m.bytes ? `这段时间，${esc(top.a.name)} 的流量最多。<br><a class="text-link" href="${url("app-detail.html", { id: top.a.id })}">看看它的联网情况 ${icon("arrow-right", "sm")}</a>` : "暂时没有保留的活动。"}</p></div>${pendingNotice()}`;
    bindGraph();
    bindPeriod(draw);
  }
  draw();
  rememberScroll();
}
export function apps() {
  let query = "",
    filter = "all";
  function draw() {
    const list = allSubjects().filter(
      (a) =>
        a.name.toLowerCase().includes(query.toLowerCase()) &&
        (filter !== "active" ||
          appMetrics(a.id).connections + appMetrics(a.id).queries > 0) &&
        (filter !== "limited" ||
          currentRules(a.id).some(
            (r) =>
              r.action === "drop" &&
              ruleUse(r, S.active, a.id).mode === "enforce",
          )),
    );
    $("#all-apps").innerHTML =
      list.map(appRow).join("") ||
      empty("没有找到应用", "试试其他名称，或切回全部应用。");
    $$("[data-app-filter]").forEach((b) =>
      b.classList.toggle("active", b.dataset.appFilter === filter),
    );
    bindPeriod(draw);
  }
  $("#app-search").oninput = (e) => {
    query = e.target.value;
    draw();
  };
  $$("[data-app-filter]").forEach(
    (b) =>
      (b.onclick = () => {
        filter = b.dataset.appFilter;
        draw();
      }),
  );
  draw();
  rememberScroll();
}
export function application() {
  const a = selectedApp();
  S.selected = a.id;
  persist();
  setBack(params.get("from") || "home.html", "应用");
  function draw() {
    const m = appMetrics(a.id);
    $("#application-heading").innerHTML = identity(
      a,
      S.running ? "连接、流量与联网设置" : "当前已暂停新增记录",
    );
    $(".topbar-title").textContent = a.name;
    $("#app-traffic").innerHTML =
      `<div class="traffic-label">${periodText()} · 收发流量</div><div class="traffic-total">${bytes(m.bytes).split(" ")[0]} <small>${bytes(m.bytes).split(" ")[1]}</small></div><div class="traffic-directions"><span>↓ 接收 ${bytes(m.received)}</span><span>↑ 发送 ${bytes(m.sent)}</span></div>${m.connections ? graph(a.id) : empty("暂无传输记录", "域名查询与连接分别记录。")}`;
    $("#app-counts").innerHTML =
      `<a href="${url("activity.html", { app: a.id, type: "connection", from: here() })}"><strong>${m.connections}</strong><span>条连接</span><small>${m.blockedConnections ? m.blockedConnections + " 条记录显示被阻止" : "查看连接与传输"}</small></a><a href="${url("activity.html", { app: a.id, type: "dns", from: here() })}"><strong>${m.queries}</strong><span>次域名查询</span><small>${m.blockedQueries ? m.blockedQueries + " 次查询被阻止" : "查看名称查询的结果"}</small></a>`;
    const cs = connectionOverview(m.c);
    $("#app-connection-preview").innerHTML =
      `<div class="section-heading"><h2>连接去向</h2><a class="text-link" href="${url("activity.html", { app: a.id, type: "connection", from: here() })}">查看全部 ${m.connections}</a></div><p class="connection-preview-caption">09:41 快照 · ${cs.held} 条仍保持${cs.ended ? " · " + cs.ended + " 条已结束" : ""}${cs.unestablished ? " · " + cs.unestablished + " 次未建立" : ""}</p>${
        [...m.c]
          .sort(
            (x, y) =>
              Number(isHeld(y)) - Number(isHeld(x)) || x.minute - y.minute,
          )
          .slice(0, 2)
          .map((e) => connectionRow(e, { compact: true, from: here() }))
          .join("") ||
        empty(
          "这个时段没有连接记录",
          m.queries ? "域名查询单独记录在下面。" : "可以查看其他时段。",
        )
      }`;
    $("#app-control-summary").textContent = controlSummary(a.id);
    link("app-controls-link", "app-controls.html", { app: a.id, from: here() });
    link("app-activity-link", "activity.html", {
      app: a.id,
      type: "dns",
      from: here(),
    });
    link("app-stats-link", "stats.html", { app: a.id, from: here() });
    link("app-map-link", "map.html", { app: a.id, from: here() });
    link("app-rules-link", "app-controls.html", { app: a.id, from: here() });
    $("#app-recent-activity").innerHTML =
      activity(a.id, "dns")
        .slice(0, 3)
        .map((e) => recordRow(e, { from: here() }))
        .join("") || empty("还没有保留的活动", "有新的记录时，会在这里出现。");
    $("#app-last-decision").innerHTML = pendingNotice();
    bindPeriod(draw);
    bindGraph();
  }
  draw();
  rememberScroll();
}
function filters(app, type, redraw) {
  const current = new URLSearchParams(location.search);
  sheet(
    `<h2 id="sheet-title">查看哪些活动</h2><div class="field" style="margin-top:20px"><label for="sheet-app">应用</label><select id="sheet-app"><option value="all">全部应用</option>${allSubjects()
      .map(
        (a) =>
          `<option value="${a.id}" ${a.id === app ? "selected" : ""}>${esc(a.name)}</option>`,
      )
      .join(
        "",
      )}<option value="unknown" ${app === "unknown" ? "selected" : ""}>归属未确定</option></select></div><div class="field"><label for="sheet-outcome">处理结果</label><select id="sheet-outcome">${outcomeOptions()}</select></div><a class="text-link" href="${url("activity-filter.html", { app, type, result: S.activityOutcome, state: current.get("state"), q: current.get("q"), search: current.get("search"), after: current.get("after"), from: here() })}">更多筛选：类型、状态与时间</a><div class="sheet-buttons"><button class="btn full" id="apply-activity-filter">查看结果</button></div>`,
  );
  $("#sheet-outcome").value = S.activityOutcome || "all";
  $("#apply-activity-filter").onclick = () => {
    S.activityOutcome = $("#sheet-outcome").value;
    persist();
    go("activity.html", {
      app: $("#sheet-app").value,
      type,
      from: params.get("from") || "home.html",
      result: S.activityOutcome,
      state: current.get("state"),
      q: current.get("q"),
      search: current.get("search"),
      after: current.get("after"),
    });
  };
}
export function activityPage() {
  S.activityOutcome = normalizeOutcome(params.get("result"));
  const app = params.get("app") || "all";
  let type = params.get("type") || "all";
  let connectionFilter = params.get("state") || "all",
    connectionQuery = params.get("q") || "";
  function draw() {
    const a =
      subject(app) ||
      (app === "unknown" ? { id: app, name: "归属未确定" } : null);
    $("#activity-heading").innerHTML = a
      ? identity(a, "详细活动", true)
      : `<header class="experience-head"><div><p class="eyebrow">全部应用</p><h1>联网活动</h1></div><button class="period-button" id="period-picker">${periodText()}</button></header>`;
    if (type === "connection") {
      $("#activity-heading h1").textContent = a
        ? a.name + "的连接"
        : "连接记录";
      const subtitle = $("#activity-heading .context-heading p");
      if (subtitle) subtitle.textContent = "状态、去向与收发";
    }
    setBack(
      params.get("from") || (a ? "app-detail.html?id=" + app : "home.html"),
      a ? a.name : "应用",
    );
    let es = activity(app, type)
      .filter(
        (e) => !params.has("search") || e.target.includes(params.get("search")),
      )
      .filter(
        (e) =>
          !params.has("after") || e.observedAt >= S.lastDecision?.appliedAt,
      )
      .filter((e) => matchesOutcome(e, S.activityOutcome));
    document.body.classList.toggle("connection-mode", type === "connection");
    const allConnections = es;
    $("#connection-tools").innerHTML =
      type === "connection"
        ? connectionTools(allConnections, connectionFilter, connectionQuery)
        : "";
    if (type === "connection")
      es = es.filter((e) =>
        matchConnection(e, connectionFilter, connectionQuery),
      );
    $("#activity-count").innerHTML =
      `${params.has("after") ? "设置生效后" : periodText()} · ${type === "dns" ? es.length + " 次域名查询" : type === "connection" ? es.length + " 条连接记录" : es.filter((e) => e.recordType === "connection").length + " 条连接 · " + es.filter((e) => e.recordType === "dns").length + " 次域名查询"}${S.timeSlice ? ` · <button class="whole-period-link" id="clear-time-slice">查看完整时段</button>` : ""}`;
    $("#activity-count").insertAdjacentHTML(
      "beforeend",
      `${params.has("search") ? `<br>目标：${esc(params.get("search"))} <a class="whole-period-link" href="${url("activity.html", { app, type, result: S.activityOutcome, from: params.get("from"), search: null })}">清除目标</a>` : ""}${S.activityOutcome === "blocked" ? " · 仅被阻止的记录" : S.activityOutcome !== "all" ? " · " + outcomeLabel(S.activityOutcome) : ""}${coverageGaps().length ? "<br>这个时段记录不完整；这里只显示已保留的记录。" : ""}`,
    );
    if (S.scenario === "error") {
      $("#experience-activity-list").innerHTML = empty(
        "暂时没有读到记录",
        "你的联网设置仍在运行。",
        '<button class="btn" id="retry-query">重新读取</button>',
      );
      $("#retry-query").onclick = () => {
        S.scenario = "normal";
        persist();
        draw();
      };
      $("#activity-preview").innerHTML = "";
      return;
    }
    if (S.scenario === "empty") es.length = 0;
    $("#experience-activity-list").innerHTML =
      es.map((e) => recordRow(e, { showApp: !a })).join("") ||
      empty(
        params.has("after")
          ? "设置生效后，还没有新记录"
          : "这段时间没有符合条件的活动",
        params.has("after")
          ? "设置已开始使用。出现新的访问后，可以在这里核对结果。"
          : "可以调整时间范围或筛选条件。",
      );
    const chosen = es.find((e) => e.id === S.selectedEvent) || es[0];
    $("#activity-preview").innerHTML = chosen
      ? previewRecord(chosen)
      : '<p class="note">选择一条活动，在这里继续查看。</p>';
    $$("[data-record-type]").forEach((b) => {
      b.classList.toggle("active", b.dataset.recordType === type);
      b.onclick = () => {
        type = b.dataset.recordType;
        const u = new URL(location.href);
        u.searchParams.set("type", type);
        history.replaceState({}, "", u);
        draw();
      };
    });
    $$("#experience-activity-list [data-record]").forEach(
      (row) =>
        (row.onclick = (e) => {
          if (innerWidth >= 800) {
            e.preventDefault();
            S.selectedEvent = row.dataset.record;
            $$("#experience-activity-list [data-record]").forEach((x) =>
              x.classList.toggle("selected", x === row),
            );
            persist();
            $("#activity-preview").innerHTML = previewRecord(
              record(S.selectedEvent),
            );
            bindPreviewAction();
          }
        }),
    );
    if (type === "connection") {
      $$("[data-connection-filter]").forEach(
        (b) =>
          (b.onclick = () => {
            connectionFilter = b.dataset.connectionFilter;
            const u = new URL(location.href);
            u.searchParams.set("state", connectionFilter);
            history.replaceState({}, "", u);
            draw();
          }),
      );
      $("#connection-search").oninput = (e) => {
        const start = e.target.selectionStart;
        connectionQuery = e.target.value;
        const u = new URL(location.href);
        connectionQuery
          ? u.searchParams.set("q", connectionQuery)
          : u.searchParams.delete("q");
        history.replaceState({}, "", u);
        draw();
        const input = $("#connection-search");
        input.focus({ preventScroll: true });
        try {
          input.setSelectionRange(start, start);
        } catch {}
      };
    }
    $$("#experience-activity-list [data-record]").forEach((row) =>
      row.classList.toggle(
        "selected",
        innerWidth >= 800 && row.dataset.record === chosen?.id,
      ),
    );
    bindPreviewAction();
    if ($("#clear-time-slice"))
      $("#clear-time-slice").onclick = () => {
        selectRange();
        draw();
      };
    $("#activity-filter-button").onclick = () => filters(app, type, draw);
    bindPeriod(draw);
    $("#new-activity-status").innerHTML = S.running
      ? '<button class="record-refresh" id="refresh-activity">' +
        icon("refresh-cw") +
        "读取新的活动</button>"
      : '<p class="note">运行已暂停。这里保留之前的记录。</p>';
    if ($("#refresh-activity"))
      $("#refresh-activity").onclick = async (e) => {
        e.currentTarget.disabled = true;
        e.currentTarget.textContent = "正在读取…";
        await delay(400);
        const id = a?.id || "s4";
        draw();
        toast("已读取当前记录");
      };
  }
  addEventListener("prototype-new-activity", () => {
    $("#new-activity-status").innerHTML =
      '<button class="record-refresh" id="show-new-activity">有新的活动，点此查看</button>';
    $("#show-new-activity").onclick = draw;
  });
  function bindPreviewAction() {
    const btn = $("#peek-adjust");
    if (btn)
      btn.onclick = () => decisionSheet(record(btn.dataset.id), () => draw());
  }
  draw();
  rememberScroll();
}
function reasonText(e) {
  if (e.ruleName)
    return e.recordType === "dns"
      ? `按照「${esc(e.ruleName)}」处理这次域名查询。`
      : `这次访问按「${esc(e.ruleName)}」处理。`;
  return e.recordType === "dns"
    ? "这次查询没有受到你的规则限制。"
    : "这次访问没有命中阻止规则。";
}
function previewRecord(e) {
  if (e.recordType === "connection")
    return `<div class="connection-inspector-owner">${appIcon(subject(e.subject))}<span>${esc(subjectName(e.subject))}<small>这条连接</small></span></div>${connectionSummary(e, true)}<a class="text-link inspector-detail-link" href="${url("connection.html", { id: e.id, app: e.subject, from: here() })}">连接经过与处理依据 ${icon("arrow-right")}</a>${S.lastDecision?.app === e.subject && S.lastDecision?.target === e.target ? `<p class="connection-snapshot-note">${S.lastDecision.applied ? "规则已生效；这里仍是09:41的连接快照。" : "修改已保存，尚未生效。"}</p>` : ""}<div class="record-action"><button class="btn full" id="peek-adjust" ${subject(e.subject) ? "" : "disabled"} data-id="${e.id}">调整这类访问</button></div>`;
  return `<div class="row" style="margin-bottom:19px">${appIcon(subject(e.subject))}<div><strong>${esc(subjectName(e.subject))}</strong><p class="caption">${clock(e.minute)} · ${e.recordType === "dns" ? "域名查询" : "连接"}</p></div></div><div class="record-result"><span class="record-mark ${e.result === "drop" ? "blocked" : ""}">${icon(e.result === "drop" ? "ban" : e.recordType === "dns" ? "globe" : "arrow-up-right")}</span><h2>${resultText(e)}</h2><p>${reasonText(e)}</p></div><div class="record-facts"><h3>${e.recordType === "dns" ? "查询的名称" : "连接的目标"}</h3><div class="record-target">${esc(e.target)}</div><p class="fact-subline">${e.recordType === "dns" ? (e.answers.length ? e.answers.join("、") : "这次查询没有返回地址") : e.ip + ":" + e.port + " · " + bytes(e.bytes)}</p></div><a class="text-link" href="${url("connection.html", { id: e.id, app: e.subject, from: here() })}">查看完整详情 ${icon("arrow-right", "sm")}</a>${S.lastDecision?.app === e.subject && S.lastDecision?.target === e.target ? `<div class="persistent-result ${S.lastDecision.applied ? "" : "pending"}">${S.lastDecision.applied ? "新设置已生效，原记录不变。" : "新设置已保存，尚未生效。"}</div>` : ""}<div class="record-action"><button class="btn full" id="peek-adjust" ${subject(e.subject) ? "" : "disabled"} data-id="${e.id}">调整以后的访问</button></div>`;
}
export function connectionPage() {
  const e = record(params.get("id")) || record("s4-blocked-0");
  const a = subject(e.subject) || { id: "unknown", name: "归属未确定" };
  S.selected = a.id;
  persist();
  setBack(params.get("from") || "activity.html?app=" + a.id, "返回");
  $(".topbar-title").textContent = a.name;
  $("#record-heading").innerHTML =
    `<div class="context-heading">${appIcon(a)}<div class="grow"><h1>${esc(a.name)}</h1><p>${periodText()}<br>${clock(e.minute)} · 一次${e.recordType === "dns" ? "域名查询" : "连接"}</p></div></div>`;
  const targetLine =
    e.recordType === "dns"
      ? e.answers.length
        ? "返回了 " + e.answers.length + " 个地址"
        : "这次查询没有返回地址"
      : (e.kind === "live"
          ? "正在进行"
          : e.kind === "ended"
            ? "已结束"
            : "访问被规则阻止") +
        " · " +
        bytes(e.bytes);
  $("#record-summary").innerHTML =
    `<div class="record-result"><span class="record-mark ${e.result === "drop" ? "blocked" : ""}">${icon(e.result === "drop" ? "ban" : e.recordType === "dns" ? "globe" : "arrow-up-right")}</span><h2>${resultText(e)}</h2><p>${reasonText(e)}</p></div><div class="record-facts"><h3>${e.recordType === "dns" ? "查询的名称" : "连接的目标"}</h3><div class="record-target">${esc(e.target)}</div><p class="fact-subline">${targetLine}</p></div>${e.recordType === "connection" ? `<div class="app-counts"><div><strong>${bytes(directionBytes(e, "received"))}</strong><small>接收</small></div><div><strong>${bytes(directionBytes(e, "sent"))}</strong><small>发送</small></div></div>` : ""}<details class="advanced"><summary>详细信息</summary><dl class="detail-pairs">${(e.recordType ===
    "dns"
      ? [
          ["查询类型", e.type],
          ["网络", networkName(e.network)],
          ["耗时", e.duration + " ms"],
          ["返回地址", e.answers.join("、") || "没有返回地址"],
        ]
      : [
          ["IP 地址", e.ip],
          ["目的端口", e.port],
          ["协议", e.labels.join(" / ")],
          ["网络", networkName(e.network)],
          [
            "规则处理",
            e.result === "drop"
              ? "阻止"
              : e.result === "observe"
                ? "仅观察，实际允许"
                : "允许",
          ],
        ]
    )
      .map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`)
      .join("")}</dl></details>`;
  if (e.recordType === "connection") {
    document.body.classList.add("connection-observation");
    $("#record-heading p").textContent = periodText() + " · 连接快照";
    $("#record-summary").innerHTML = connectionSummary(e);
    $(".record-action p").textContent =
      "修改规则后，需用后续活动核对处理结果。";
  }
  const related =
    e.recordType === "dns"
      ? e.connection
        ? record(e.connection)
        : null
      : e.queryId
        ? record(e.queryId)
        : null;
  $("#record-context").innerHTML =
    `<div class="section-heading"><h2>和这次活动有关</h2></div>${related ? `<a class="related-step" href="${url("connection.html", { id: related.id, app: a.id, from: here() })}"><span class="step-symbol">${icon(related.recordType === "dns" ? "globe" : "network", "sm")}</span><span class="grow"><h3>${related.recordType === "dns" ? "它先查询了这个名称" : "查看相关连接"}</h3><p>${related.recordType === "connection" ? (connectionFacts(related).startEvidence === "established" ? "建立于 " : "首次记录于 ") + stamp(connectionFacts(related).openedMinute) : "查询于 " + stamp(related.minute)} · ${esc(related.target)}</p></span>${icon("chevron-right")}</a>` : `<p class="note">${e.recordType === "dns" ? "这次查询没有关联的连接记录。" : "没有可关联的域名查询记录。"}</p>`}<div class="section-heading"><h2>当时的处理依据</h2></div><div class="reason-entry"><strong>${e.ruleName ? esc(e.ruleName) : "按默认设置处理"}</strong><p>${e.ruleName ? "记录保留当时使用的设置。" : "当时没有匹配到需要阻止这项活动的设置。"}</p>${e.rule ? `<a class="text-link" href="${url("rule-detail.html", { id: e.rule, from: here() })}">查看这项设置 ${icon("chevron-right", "sm")}</a>` : ""}${e.list ? `<a class="text-link" style="display:flex" href="${url("domain-detail.html", { id: e.list, from: here() })}">查看使用的名单 ${icon("chevron-right", "sm")}</a>` : ""}</div><a class="text-link" href="${url("app-controls.html", { app: a.id, from: here() })}">管理${esc(a.name)}的联网设置 ${icon("arrow-right", "sm")}</a>`;
  if (e.recordType === "connection")
    $("#record-context").insertAdjacentHTML(
      "afterbegin",
      `<a class="connection-same-target" href="${url("activity.html", { app: a.id, type: "connection", search: e.target, from: here() })}">${icon("network")}此目标的全部连接 ${icon("chevron-right")}</a>`,
    );
  $("#adjust-record").textContent = "调整" + a.name + "的访问规则";
  $("#adjust-record").onclick = () => decisionSheet(e, drawDecisionResult);
  if (a.id === "unknown") {
    $("#adjust-record").disabled = true;
    $("#adjust-record").textContent = "应用归属未确定";
    $(".record-action p").textContent = "确认应用后，才能为它调整联网设置。";
    $("#record-context").querySelector('a[href*="app-controls"]')?.remove();
  }
  function drawDecisionResult() {
    const d = S.lastDecision;
    if (d) {
      d.applied =
        S.activeVersion >= d.savedVersion &&
        S.active.rules.some((r) => r.id === d.id);
    }
    if (d?.app !== a.id || d.target !== e.target) {
      $("#record-decision-status").innerHTML = "";
      return;
    }
    $("#record-decision-status").innerHTML =
      `<div class="persistent-result ${d.applied ? "" : "pending"}">${d.applied ? "新设置已开始使用。这条记录仍保留当时的结果。" : "新设置已保存，还没有开始使用。"}<br><a href="${url(d.applied ? "app-controls.html" : "config.html", { app: a.id, decision: d.id, from: here() })}">${d.applied ? "查看我的设置" : "查看原因并处理"}</a>${d.applied ? '<br><button id="check-next-activity">查看后续活动</button>' : ""}</div>`;
    if (e.recordType === "connection") {
      $("#record-summary").querySelector(".connection-snapshot-note")?.remove();
      $("#record-summary").insertAdjacentHTML(
        "afterbegin",
        `<p class="connection-snapshot-note">${d.applied ? "规则已生效；此处仍显示09:41的连接快照，后续处理结果待观察。" : "修改尚未生效；此处仍显示09:41的连接快照。"}</p>`,
      );
    }
    const inspect = () => {
      const origin = here();
      go("activity.html", {
        app: a.id,
        type: "all",
        after: d.id,
        window: "all",
        from: origin,
      });
    };
    if ($("#check-next-activity")) $("#check-next-activity").onclick = inspect;
    const action = $("#adjust-record");
    action.textContent = d.applied
      ? "新设置已生效 · 查看后续活动"
      : "修改尚未生效 · 查看原因";
    action.onclick = d.applied
      ? inspect
      : () => go("config.html", { decision: d.id, from: here() });
    $(".record-action p").innerHTML =
      '<span class="decision-recap">' +
      esc(d.name || "天气的联网设置已更新") +
      '</span><button class="text-link" id="readjust-record">再调整这项设置</button>';
    $("#readjust-record").onclick = () => decisionSheet(e, drawDecisionResult);
  }
  drawDecisionResult();
  rememberScroll();
}
function networkName(v) {
  return { Wired: "有线网络", Mobile: "移动网络" }[v] || v;
}
export function decisionSheet(e, onDone) {
  if (!subject(e.subject)) return toast("应用归属未确定，暂时无法按应用调整");
  const previous =
    S.lastDecision?.app === e.subject && S.lastDecision?.target === e.target
      ? S.lastDecision
      : null;
  let action = previous?.action || (e.result === "drop" ? "allow" : "drop"),
    channel =
      previous?.channel ||
      (e.result === "drop"
        ? rule(e.rule)?.channels?.length === 2
          ? "both"
          : rule(e.rule)?.channels?.[0] ||
            (e.recordType === "dns" ? "dns" : "connection")
        : "both");
  const app = subject(e.subject);
  sheet(
    `<div class="sheet-context">${appIcon(app)}<span>${esc(app.name)}的联网设置</span></div><h2 id="sheet-title">${e.result === "drop" ? "调整这项阻止" : "以后怎样处理这类访问"}</h2><p class="decision-target">${esc(e.target)}${e.result === "drop" && e.ruleName ? "<br><small>当前由「" + esc(e.ruleName) + "」阻止" + (e.list ? " · 名单：" + esc(S.config.lists.find((l) => l.id === e.list)?.name || e.list) : "") + "</small>" : ""}</p><div class="decision-action"><button class="active" data-decision-action="drop">阻止</button><button data-decision-action="allow">允许</button></div><div class="decision-scope">${icon("sliders-horizontal")}<span id="decision-sentence"></span></div><details><summary>调整范围</summary><div class="field"><label for="decision-channel">应用到哪些活动</label><select id="decision-channel"><option value="dns">域名查询</option><option value="connection">连接</option><option value="both">域名查询和连接</option></select></div><label class="check-row"><input type="checkbox" id="decision-descendants"> 包含这个名称下的子域名</label><p class="help">其他应用和订阅名单保持不变。已有的其他联网限制仍适用。</p></details><div class="inline-error" id="decision-error" role="alert"></div><div class="sheet-buttons"><button class="btn" data-close-sheet>取消</button><button class="btn primary" id="save-decision">开始阻止</button></div>`,
    "decision-sheet",
  );
  if (e.recordType === "connection") {
    $("#sheet-title").textContent = "接下来怎样处理这类访问";
    $("#decision-sentence").parentElement.insertAdjacentHTML(
      "afterend",
      '<p class="connection-impact">新规则也可能影响这条连接接下来的收发。是否继续传输，需要后续记录核对。</p>',
    );
  }
  $("#decision-channel").value = channel;
  function wording() {
    $("#decision-sentence").textContent =
      "只为" +
      app.name +
      (action === "drop" ? "阻止" : "允许") +
      "这个" +
      ($("#decision-descendants").checked ? "名称及子域名" : "名称") +
      "的" +
      (channel === "both"
        ? "查询与可确认关联的连接"
        : channel === "dns"
          ? "查询"
          : "连接") +
      "。";
    $("#save-decision").textContent =
      action === "drop" ? "开始阻止" : "保存允许设置";
  }
  $$("[data-decision-action]").forEach(
    (b) =>
      (b.onclick = () => {
        action = b.dataset.decisionAction;
        $$("[data-decision-action]").forEach((x) =>
          x.classList.toggle("active", x === b),
        );
        wording();
      }),
  );
  $("#decision-channel").onchange = () => {
    channel = $("#decision-channel").value;
    wording();
  };
  $("#decision-descendants").onchange = wording;
  const save = async () => {
    const button = $("#save-decision");
    button.disabled = true;
    button.textContent = "正在应用…";
    try {
      await saveDecision(
        {
          app: app.id,
          target: e.target,
          channel,
          action,
          descendants: $("#decision-descendants").checked,
          ruleId: previous?.id,
        },
        here(),
      );
      closeSheet();
      onDone?.();
    } catch (error) {
      $("#decision-error").textContent = error.message;
      if (["save-error", "conflict"].includes(S.scenario)) {
        const b = document.createElement("button");
        b.className = "text-link";
        b.textContent =
          S.scenario === "conflict" ? "保留选择，读取后重试" : "重试";
        b.onclick = () => {
          S.scenario = "normal";
          persist();
          save();
        };
        $("#decision-error").append(document.createElement("br"), b);
      }
      button.disabled = false;
      wording();
    }
  };
  $("#save-decision").onclick = save;
  $$("[data-decision-action]").forEach((b) =>
    b.classList.toggle("active", b.dataset.decisionAction === action),
  );
  wording();
}
export function controls() {
  const a = selectedApp();
  S.selected = a.id;
  persist();
  setBack(params.get("from") || "app-detail.html?id=" + a.id, a.name);
  function draw() {
    $("#controls-heading").innerHTML =
      `<div class="application-identity">${appIcon(a, true)}<div><h1>${esc(a.name)}</h1><p>我的联网设置</p></div></div>`;
    $(".topbar-title").textContent = a.name;
    const nets =
      platform === "linux"
        ? [
            ["Wired", "限制有线网络"],
            ["Wi-Fi", "限制 Wi-Fi"],
            ["VPN", "限制 VPN 网络"],
          ]
        : [
            ["Wi-Fi", "限制 Wi-Fi"],
            ["Mobile", "限制移动网络"],
            ["VPN", "限制 VPN 网络"],
          ];
    $("#basic-controls").innerHTML = [["all", "限制所有联网"], ...nets]
      .map(
        ([v, t]) =>
          `<div class="control-line"><span class="grow"><h3>${t}</h3><p>${v === "all" ? "用于" + esc(a.name) + "的查询与连接。" : quickBlock(a.id, v) ? "已添加快捷限制。" : "未设置这项快捷限制。"}</p></span><button class="switch" role="switch" aria-label="${t}" aria-checked="${!!quickBlock(a.id, v)}" data-quick="${v}"></button></div>`,
      )
      .join("");
    $("#app-applied-controls").innerHTML = appliedEntries(a.id);
    $("#controls-pending").innerHTML = pendingNotice();
    $$("[data-quick]").forEach(
      (button) =>
        (button.onclick = async () => {
          button.disabled = true;
          const network = button.dataset.quick,
            next = clone(S.config),
            blocked = !!quickBlock(a.id, network);
          setBlock(next, a.id, network, !blocked);
          try {
            await commit(next, { returnTo: here(), message: "联网设置已更新" });
            $("#controls-error").textContent = "";
            draw();
            toast(
              S.savedVersion === S.activeVersion
                ? "已更新" + a.name + "的联网设置"
                : "已保存，尚未开始使用",
            );
          } catch (e) {
            $("#controls-error").textContent = e.message;
            button.disabled = false;
          }
        }),
    );
    link("advanced-app-rules", "rules.html", { app: a.id, from: here() });
    $("#new-app-rule").onclick = () =>
      go("rule-edit.html", { subject: a.id, new: 1, from: here() });
  }
  draw();
  rememberScroll();
}

export function statistics() {
  const app = params.get("app") || "all",
    a = subject(app);
  function draw() {
    const m = appMetrics(app);
    $("#statistics-heading").innerHTML = a
      ? identity(a, "联网统计", true)
      : `<header class="experience-head"><div><p class="eyebrow">全部应用</p><h1>联网统计</h1></div><button class="period-button" id="period-picker">${periodText()}</button></header>`;
    setBack(
      params.get("from") || (a ? "app-detail.html?id=" + app : "home.html"),
      a ? a.name : "应用",
    );
    $("#statistics-traffic").innerHTML =
      `<span class="traffic-label">${periodText()} · 收发流量</span><div class="traffic-total">${bytes(m.bytes).split(" ")[0]} <small>${bytes(m.bytes).split(" ")[1]}</small></div><div class="traffic-directions"><span>↓ 接收 ${bytes(m.received)}</span><span>↑ 发送 ${bytes(m.sent)}</span></div>${m.connections ? graph(app) : empty("暂无传输记录", "查询与连接分别记录。")}`;
    $("#statistics-counts").innerHTML =
      `<a href="${url("activity.html", { app, type: "connection", from: here() })}" class="statistic-block"><span>连接</span><strong>${m.connections}<small> 条</small></strong><p>${m.blockedConnections} 条记录显示被规则阻止</p></a><a href="${url("activity.html", { app, type: "dns", from: here() })}" class="statistic-block"><span>域名查询</span><strong>${m.queries}<small> 次</small></strong><p>${m.blockedQueries} 次查询被阻止</p></a>`;
    const groups = new Map();
    m.c.forEach((e) => {
      const n = groups.get(e.target) || { bytes: 0, queries: 0 };
      n.bytes += e.bytes;
      groups.set(e.target, n);
    });
    m.q.forEach((e) => {
      const n = groups.get(e.target) || { bytes: 0, queries: 0 };
      n.queries++;
      groups.set(e.target, n);
    });
    $("#statistics-targets").innerHTML =
      [...groups]
        .sort((x, y) => y[1].bytes - x[1].bytes)
        .map(
          ([target, n]) =>
            `<a class="related-step" href="${url("activity.html", { app, search: target, from: here() })}"><span class="grow"><h3>${esc(target)}</h3><p>${n.queries} 次域名查询</p></span><strong style="font-size:12px">${bytes(n.bytes)}</strong>${icon("chevron-right")}</a>`,
        )
        .join("") || empty("暂无目标记录", "这个范围内还没有保留的记录。");
    bindPeriod(draw);
    bindGraph();
  }
  draw();
  rememberScroll();
}
