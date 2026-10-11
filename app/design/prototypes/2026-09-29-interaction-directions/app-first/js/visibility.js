import {
  S,
  params,
  platform,
  allSubjects,
  subject,
  subjectName,
  bytes,
  selectRange,
} from "./model.js";
import { $, $$, esc, icon, url, here, go, appIcon, empty } from "./ui.js";
import {
  appMetrics,
  activity,
  clock,
  periodText,
  limit,
  currentSpan,
  coverageGaps,
} from "./network-data.js";
import {
  bindPeriod,
  rememberScroll,
  resultText,
  periodActivityText,
  latestActivityText,
} from "./experience-ui.js";

const spanText = ([a, b]) => `${clock(b)}–${clock(a)}`;
const metricName = {
  bytes: "收发",
  sent: "发出",
  received: "收到",
  queries: "查询",
};
function contributors(app = "all") {
  const ids =
    app === "all" ? [...allSubjects().map((a) => a.id), "unknown"] : [app];
  return ids
    .map((id) => ({ id, a: subject(id), m: appMetrics(id) }))
    .filter((x) => x.m.connections || x.m.queries);
}
export function coverageNote() {
  const gaps = coverageGaps();
  if (gaps.length)
    return `<div class="coverage-note">${icon("circle-help")}<span>${gaps.map(spanText).join("、")} 记录不完整<span>图和数字只包含已记录的活动。</span></span></div>`;
  return "";
}
export function timeline(app = "all", selected = false) {
  const span = [0, limit()],
    count = 6,
    step = span[1] / count;
  const bins = Array.from({ length: count }, (_, i) => {
    const a = Math.round(span[1] - (i + 1) * step),
      b = Math.round(span[1] - i * step);
    return {
      a,
      b,
      m: appMetrics(app, [a, b]),
      gap: coverageGaps([a, b]).length > 0,
    };
  });
  const scale = Math.max(1, ...bins.flatMap((b) => [b.m.sent, b.m.received]));
  const total = appMetrics(app, selected ? currentSpan() : span);
  return `<div class="network-totals"><div><span class="receive-key">↓ 收到</span><strong>${bytes(total.received)}</strong></div><div><span class="send-key">↑ 发出</span><strong>${bytes(total.sent)}</strong></div><small>${coverageGaps(selected ? currentSpan() : span).length ? "已记录部分" : "已记录传输"}</small></div>
    <div class="time-plot" role="group" aria-label="按时段查看应用贡献，收发使用相同刻度">
    <span class="plot-scale">收发使用同一刻度</span>
    ${bins.map((b) => `<button class="time-column ${selected && S.timeSlice && b.a === S.timeSlice[0] && b.b === S.timeSlice[1] ? "selected" : ""} ${b.gap ? "has-gap" : ""}" data-time-low="${b.a}" data-time-high="${b.b}" aria-label="查看 ${spanText([b.a, b.b])}：收到 ${bytes(b.m.received)}，发出 ${bytes(b.m.sent)}，${b.m.blockedQueries} 次查询被阻止${b.gap ? "，记录不完整" : ""}"><span class="bar-half receive"><i style="height:${b.m.received ? Math.max(2, (b.m.received / scale) * 56) : 0}px"></i></span><span class="bar-half send"><i style="height:${b.m.sent ? Math.max(2, (b.m.sent / scale) * 56) : 0}px"></i></span><span class="plot-events">${b.m.blockedQueries ? '<i class="query-dot"></i>' : ""}${b.m.blockedConnections ? '<i class="connection-dot"></i>' : ""}${b.gap ? '<span class="gap-mark">∕</span>' : ""}</span><span class="time-column-label">${clock(b.b)}</span></button>`).join("")}
    </div><div class="plot-foot"><span>${S.timeSlice && selected ? spanText(S.timeSlice) + " 已选" : "点一个时段，看看哪些应用在联网"}</span><span>${clock(0)}</span></div>`;
}
function bindTimeline(app, isContribution, draw) {
  $$("[data-time-low]").forEach(
    (b) =>
      (b.onclick = () => {
        if (isContribution) {
          selectRange([+b.dataset.timeLow, +b.dataset.timeHigh]);
          draw();
          document
            .getElementById("contribution-title")
            ?.focus({ preventScroll: true });
        } else {
          go("contributions.html", {
            app,
            window: [b.dataset.timeLow, b.dataset.timeHigh].join(","),
            from: here(),
          });
        }
      }),
  );
}
function resultLinks(app, m) {
  return `<div class="network-outcomes"><a class="query-outcome" href="${url("activity.html", { app, type: "dns", result: m.blockedQueries ? "blocked" : "all", from: here() })}"><span class="query-dot"></span><span>${m.blockedQueries ? `<strong>${m.blockedQueries}</strong> 次查询被阻止` : `<strong>${m.queries}</strong> 次域名查询`}</span>${icon("chevron-right")}</a><a href="${url("activity.html", { app, type: "connection", result: "all", from: here() })}"><span><strong>${m.connections}</strong> 条连接记录${m.blockedConnections ? `<small>${m.blockedConnections} 次被阻止</small>` : ""}</span>${icon("chevron-right")}</a></div>`;
}
function contributionRows(items, metric = "bytes") {
  const sorted = [...items].sort(
    (a, b) => b.m[metric] - a.m[metric] || a.m.latest - b.m.latest,
  );
  const total = sorted.reduce((n, x) => n + x.m[metric], 0);
  return (
    sorted
      .map(({ id, a, m }) => {
        const href =
          id === "unknown"
            ? url("activity.html", { app: id, from: here() })
            : url("app-detail.html", { id, from: here() });
        const last = activity(id)[0];
        return `<a class="contributor-row" href="${href}" data-contributor="${id}">${appIcon(a)}<span class="grow"><strong>${esc(a?.name || "归属未确定")}</strong><small>${S.timeSlice ? periodActivityText(m) : id === "unknown" ? "保留原始记录，尚未确认应用" : latestActivityText(last)}</small><span class="contribution-track"><i style="width:${total ? (m[metric] / total) * 100 : 0}%"></i></span></span><span class="contribution-value">${metric === "queries" ? m.queries + " 次" : bytes(m[metric])}<small>${metricName[metric]}${total ? " · " + Math.round((m[metric] / total) * 100) + "%" : ""}</small></span>${icon("chevron-right")}</a>`;
      })
      .join("") ||
    empty(
      "这段时间没有记录到活动",
      S.running
        ? "正在记录；也可以查看其他时段。"
        : "记录已暂停，已有历史仍可查看。",
    )
  );
}
export function networkHome() {
  function draw() {
    const total = appMetrics("all"),
      items = contributors();
    $("#network-status").innerHTML =
      `<span class="status-dot ${S.running ? "" : "paused"}"></span>${S.running ? "正在记录 · 最新至 09:41" : "记录已暂停 · 历史仍可查看"}<span>${platform === "linux" ? "有线网络" : "Wi-Fi"}</span>`;
    $("#network-timeline").innerHTML = timeline("all", !!S.timeSlice);
    $("#network-outcomes").innerHTML =
      resultLinks("all", total) + coverageNote();
    $("#network-apps").innerHTML = contributionRows(items);
    $("#network-app-count").textContent =
      `${items.filter((x) => x.a).length} 个应用${items.some((x) => !x.a) ? " · 含未确定归属" : ""}`;
    $("#open-contributions").href = url("contributions.html", {
      app: "all",
      from: here(),
    });
    $("#open-all-apps").href = url("apps.html", { from: here() });
    $("#network-more").innerHTML =
      `<a href="${url("stats.html", { app: "all", from: here() })}">${icon("chart-no-axes-combined")}联网统计</a><a href="${url("map.html", { app: "all", from: here() })}">${icon("map")}连接地图</a><a href="${url("activity.html", { app: "all", from: here() })}">${icon("list")}全部记录</a>`;
    bindTimeline("all", false, draw);
    bindPeriod(draw);
  }
  draw();
  rememberScroll();
}
export function contributionPage() {
  const app = params.get("app") || "all";
  let metric =
    params.get("metric") ||
    (appMetrics(app).bytes === 0 && appMetrics(app).queries
      ? "queries"
      : "bytes");
  if (!metricName[metric]) metric = "bytes";
  function draw() {
    const m = appMetrics(app);
    $("#contribution-title").textContent =
      app === "all" ? "这段时间的联网" : subjectName(app) + "的联网";
    $("#contribution-context").innerHTML =
      `<span>${app === "all" ? "这台设备" : esc(subjectName(app))}</span>${app !== "all" ? `<a href="${url("contributions.html", { app: "all", from: params.get("from") || "home.html" })}">查看全部应用</a>` : ""}`;
    $("#contribution-timeline").innerHTML = timeline(app, true);
    $("#contribution-outcomes").innerHTML =
      resultLinks(app, m) + coverageNote();
    $("#contribution-list").innerHTML = contributionRows(
      contributors(app),
      metric,
    );
    $("#contribution-scope").textContent =
      periodText() + " · " + (app === "all" ? "全部应用" : subjectName(app));
    $("#clear-contribution-time").hidden = !S.timeSlice;
    $("#clear-contribution-time").onclick = () => {
      selectRange();
      draw();
    };
    $$("[data-contribution-metric]").forEach((b) => {
      b.classList.toggle("active", b.dataset.contributionMetric === metric);
      b.setAttribute("aria-pressed", b.dataset.contributionMetric === metric);
      b.onclick = () => {
        metric = b.dataset.contributionMetric;
        const u = new URL(location.href);
        u.searchParams.set("metric", metric);
        history.replaceState({}, "", u);
        draw();
      };
    });
    $("#contribution-links").innerHTML =
      `<a href="${url("activity.html", { app, from: here(), result: "all" })}">查看详细记录 ${icon("arrow-right")}</a><a href="${url("stats.html", { app, from: here() })}">按去向查看 ${icon("arrow-right")}</a><a href="${url("map.html", { app, from: here() })}">连接地图 ${icon("arrow-right")}</a>`;
    bindTimeline(app, true, draw);
    bindPeriod(draw);
  }
  draw();
  rememberScroll();
}
