import {
  S,
  params,
  platform,
  allSubjects,
  subject,
  subjectName,
  events,
  filteredEvents,
  persist,
  bytes,
  protocols,
  rule,
} from "./model.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  here,
  eventRow,
  empty,
  badge,
  chart,
  trafficChart,
  appIcon,
  dialog,
  toast,
  row,
} from "./ui.js";
function peek(e) {
  return `<div class="card"><div class="between">${badge(e.result)}<span class="caption">${e.time}</span></div><h2 style="margin:17px 0 7px;font-size:19px;overflow-wrap:anywhere">${esc(e.target)}</h2><p class="help">${esc(subjectName(e.subject))} · ${e.protocol} / ${e.port}</p><div class="divider"></div><p class="help">${e.ruleName ? "当时命中「" + esc(e.ruleName) + "」" : "没有规则命中，使用默认允许。"}</p><a class="btn full gap-top" href="${url("connection.html", { id: e.id, from: here() })}">查看访问详情 ${icon("arrow-right")}</a></div>`;
}
export function activity() {
  if (params.has("subject")) S.filters.subject = params.get("subject");
  if (params.has("result")) S.filters.result = params.get("result");
  $("#activity-search").value = S.filters.query;
  function draw() {
    persist();
    const list = filteredEvents();
    $("#activity-summary").textContent =
      (S.filters.range === "1440"
        ? "今天"
        : "最近 " + S.filters.range + " 分钟") +
      " · " +
      list.length +
      " 条记录";
    if (S.scenario === "error") {
      $("#activity-list").innerHTML = empty(
        "暂时无法读取记录",
        "运行控制没有受到影响。可以重新读取。",
        '<button class="btn" id="retry-records">重新读取</button>',
      );
      $("#retry-records").onclick = () => {
        S.scenario = "normal";
        persist();
        draw();
      };
      $("#activity-side-detail").innerHTML = "";
      return;
    }
    if (S.scenario === "loading") {
      $("#activity-list").innerHTML = empty(
        "正在读取记录",
        "请稍候，保留数据尚未返回。",
      );
      setTimeout(() => {
        S.scenario = "normal";
        draw();
      }, 900);
      return;
    }
    $("#activity-list").innerHTML =
      S.scenario === "empty"
        ? empty("还没有访问记录", "当前范围内没有已保留的访问。")
        : list
            .map((e) =>
              eventRow(e).replace(
                'class="activity-row"',
                `class="activity-row" data-peek-event="${e.id}"`,
              ),
            )
            .join("") ||
          empty(
            "没有符合条件的访问",
            "调整筛选条件，或等待新的连接。",
            `<a class="btn" href="${url("activity-filter.html")}">调整筛选</a>`,
          );
    $("#activity-side-detail").innerHTML = list.length
      ? peek(list.find((e) => e.id === S.selectedEvent) || list[0])
      : "";
    $$("[data-result]").forEach((b) =>
      b.classList.toggle("active", b.dataset.result === S.filters.result),
    );
    $$("[data-peek-event]").forEach(
      (a) =>
        (a.onclick = (e) => {
          if (innerWidth >= 700) {
            e.preventDefault();
            S.selectedEvent = a.dataset.peekEvent;
            persist();
            $("#activity-side-detail").innerHTML = peek(
              events.find((x) => x.id === S.selectedEvent),
            );
          }
        }),
    );
  }
  $("#activity-search").oninput = (e) => {
    S.filters.query = e.target.value;
    draw();
  };
  $$("[data-result]").forEach(
    (b) =>
      (b.onclick = () => {
        S.filters.result = b.dataset.result;
        draw();
      }),
  );
  draw();
}
export { activityFilterPage as activityFilter } from "./activity-filters.js";
export function connection() {
  const e = events.find((x) => x.id === params.get("id")) || events[0];
  $("#connection-main").innerHTML =
    `<header class="page-intro">${badge(e.result)}<h1 style="font-size:26px;margin-top:17px;overflow-wrap:anywhere">${esc(e.target)}</h1><p>${esc(subjectName(e.subject))} · ${e.time}</p></header>`;
  const sni = e.labels.some((x) => ["TLS", "QUIC"].includes(x))
    ? e.target.match(/[a-z]/i)
      ? e.target
      : "未取得名称"
    : e.labels.length
      ? "不适用（非 TLS / QUIC）"
      : "协议事实不足";
  const facts = [
    ["目标地址", e.ip],
    ["目的端口", e.port],
    ["IP 协议", e.protocol],
    ["协议标签", e.labels.join(" · ") || "尚未识别"],
    ["SNI 名称事实", sni],
    [
      "网络",
      e.network === "Wired"
        ? "有线网络"
        : e.network === "Mobile"
          ? "移动网络"
          : e.network,
    ],
    ["设备方向", e.direction],
    [
      "记录类型",
      e.kind === "live"
        ? "当前连接"
        : e.kind === "blocked"
          ? "建连前阻止"
          : "已结束",
    ],
    ["已观察流量", bytes(e.bytes)],
  ];
  $("#connection-facts").innerHTML = facts
    .map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`)
    .join("");
  $("#connection-source").textContent =
    "记录发生时 · 配置 v42。此处的名称和结果属于当时，不会被新规则改写。";
  $("#connection-reason").innerHTML =
    `<div class="card"><h3>${e.ruleName ? esc(e.ruleName) : "默认允许"}</h3><p class="help" style="margin-top:12px">${e.result === "observe" ? "当时的规则声明阻止；该分配为仅观察，所以实际允许。" : e.ruleName ? "符合当时规则的条件，执行" + (e.result === "drop" ? "阻止" : "允许") + "动作。" : "没有显式规则命中这次访问，使用默认允许。"}</p>${e.rule ? `<a class="text-link gap-top" href="${url("rule-detail.html", { id: e.rule, from: here() })}">查看当前规则 ${icon("chevron-right", "sm")}</a><p class="help">当前规则条件可能已改变，不能代替当时完整条件。</p>` : ""}</div>`;
  $("#connection-links").innerHTML =
    (e.subject
      ? row(
          "查看控制对象",
          subjectName(e.subject),
          "app-detail.html?id=" + e.subject,
        )
      : `<div class="list-row"><span class="subtitle">归属未知。创建规则时请明确选择作用对象。</span></div>`) +
    row(
      "在地图中查看",
      e.country,
      "location.html?region=" +
        e.region +
        "&from=" +
        encodeURIComponent(here()),
    ) +
    row("调整后查看新访问", "原记录将继续保留当时的结果", "activity.html");
  $("#rule-from-event").onclick = () =>
    go("rule-edit.html", {
      event: e.id,
      from: "connection.html?id=" + e.id,
      new: 1,
    });
}
export function stats() {
  let range = "60",
    kind = "objects";
  function draw() {
    const es = filteredEvents({
        subject: "all",
        result: "all",
        kind: "all",
        query: "",
        range,
      }),
      total = es.reduce((n, e) => n + e.bytes, 0);
    $("#stats-metrics").innerHTML =
      `<div class="metric"><div class="metric-label">访问记录</div><div class="metric-value">${es.length}</div><div class="metric-foot">${es.filter((e) => e.result === "drop").length} 次实际阻止</div></div><div class="metric"><div class="metric-label">已观察流量</div><div class="metric-value" style="font-size:26px">${bytes(total)}</div><div class="metric-foot">当前保留明细的合计</div></div>`;
    $("#stats-chart").innerHTML = es.length
      ? trafficChart(es, +range)
      : empty("暂无趋势", "当前范围没有保留的访问记录。");
    const buckets = {};
    es.forEach((e) => {
      const labels =
        kind === "objects"
          ? [subjectName(e.subject)]
          : kind === "rules"
            ? [e.ruleName || "默认允许"]
            : e.labels.length
              ? e.labels
              : ["未识别"];
      labels.forEach((name) => (buckets[name] = (buckets[name] || 0) + 1));
    });
    $("#stats-distribution").innerHTML =
      Object.entries(buckets)
        .sort((a, b) => b[1] - a[1])
        .map(
          ([n, c]) =>
            `<a class="list-row" href="${url(kind === "protocols" ? "protocols.html" : "activity.html")}"><span class="grow"><span class="title">${esc(n)}</span><span class="mini-progress"><span style="width:${(c / Math.max(1, es.length)) * 100}%"></span></span></span><span class="value">${c} 次</span>${icon("chevron-right")}</a>`,
        )
        .join("") || empty("暂无统计", "当前范围内没有保留的记录。");
    $("#stats-note").textContent =
      kind === "protocols"
        ? "一条连接可以带有多个协议标签，各项可能重叠。"
        : "这里只统计当前保留的访问样例，不代表全库历史排行。";
    $$("[data-stat-range]").forEach((b) =>
      b.classList.toggle("active", b.dataset.statRange === range),
    );
    $$("[data-stat-kind]").forEach((b) =>
      b.classList.toggle("active", b.dataset.statKind === kind),
    );
  }
  $$("[data-stat-range]").forEach(
    (b) =>
      (b.onclick = () => {
        range = b.dataset.statRange;
        draw();
      }),
  );
  $$("[data-stat-kind]").forEach(
    (b) =>
      (b.onclick = () => {
        kind = b.dataset.statKind;
        draw();
      }),
  );
  draw();
}
export function protocolList() {
  function draw() {
    const list = protocols.filter((x) =>
      x.toLowerCase().includes($("#protocol-search").value.toLowerCase()),
    );
    $("#protocol-list").innerHTML =
      list
        .map(
          (x) =>
            `<button class="list-row" data-protocol="${x}"><span class="tile-icon">${icon("network")}</span><span class="grow"><span class="title">${x}</span><span class="subtitle">${["TLS", "QUIC"].includes(x) ? "可发布协议与名称事实" : x === "DTLS" ? "不提供 TLS SNI 名称" : "协议识别标签"}</span></span>${icon("chevron-right")}</button>`,
        )
        .join("") || empty("没有找到协议", "试试 TLS、DNS 或 SSH。");
    $$("[data-protocol]").forEach(
      (b) =>
        (b.onclick = () =>
          dialog({
            title: b.dataset.protocol,
            body: "协议标签描述观察到的报文特征。同一连接可以包含多个标签，不表示认证或连接已经成功。",
            confirm: "创建协议规则",
            cancel: "返回目录",
            onConfirm: () =>
              go("rule-edit.html", {
                protocol: b.dataset.protocol,
                new: 1,
                from: "protocols.html",
              }),
          })),
    );
  }
  $("#protocol-search").oninput = draw;
  draw();
}
