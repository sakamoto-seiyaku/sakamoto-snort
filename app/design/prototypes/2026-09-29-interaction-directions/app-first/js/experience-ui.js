import {
  connectionLabel,
  connectionRow,
  connectionFacts,
} from "./connection-view.js";
import {
  S,
  allSubjects,
  subject,
  subjectRules,
  quickBlock,
  bytes,
  persist,
  selectRange,
} from "./model.js";
import { $, $$, esc, icon, url, appIcon, go, here } from "./ui.js";
import {
  appMetrics,
  periodText,
  clock,
  limit,
  activity,
} from "./network-data.js";
export function currentRules(app) {
  return subjectRules(app, S.active);
}
export function controlSummary(app) {
  if (quickBlock(app)) return "所有联网已限制";
  const rs = currentRules(app);
  return rs.length ? rs.length + " 项设置正在使用" : "按默认设置联网";
}
function binsFor(app, count = 12) {
  const span = S.timeSlice || [0, limit()],
    step = (span[1] - span[0]) / count;
  return Array.from(
    { length: count },
    (_, i) =>
      appMetrics(app, [span[0] + i * step, span[0] + (i + 1) * step]).bytes,
  ).reverse();
}
function points(values, width, height, pad = 2) {
  const max = Math.max(...values, 1);
  return values.map((v, i) => [
    pad + (i * (width - 2 * pad)) / (values.length - 1),
    height - pad - (v / max) * (height - 2 * pad),
  ]);
}
function line(points) {
  return points
    .map(([x, y], i) => (i ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1))
    .join(" ");
}
export function sparkline(app) {
  return `<svg class="mini-app-chart" viewBox="0 0 60 30" aria-hidden="true"><path d="${line(points(binsFor(app), 60, 30, 2))}"/></svg>`;
}
export function appRow(a) {
  const m = appMetrics(a.id),
    last = activity(a.id)[0],
    max = Math.max(1, ...allSubjects().map((x) => appMetrics(x.id).bytes));
  return `<a class="application-row" href="${url("app-detail.html", { id: a.id, from: location.pathname.split("/").pop() + location.search })}" data-app-row="${a.id}">${appIcon(a)}<span class="grow"><h2>${esc(a.name)}</h2><p>${S.timeSlice ? periodActivityText(m) : latestActivityText(last)}</p><span class="app-share-track"><span style="width:${(m.bytes / max) * 100}%"></span></span></span><span class="app-volume">${bytes(m.bytes)}</span>${icon("chevron-right")}</a>`;
}
export function periodActivityText(m) {
  return `本时段 · ${m.connections} 条连接记录${m.queries ? ` · ${m.queries} 次查询` : m.bytes === 0 ? " · 未记录收发" : ""}`;
}
export function latestActivityText(e) {
  if (!e) return "暂无保留活动";
  return e.recordType === "connection"
    ? `${connectionFacts(e).captured.slice(0, 5)} 快照 · ${resultText(e)}`
    : `${clock(e.minute)} 查询 · ${resultText(e)}`;
}
export function graph(app, interactive = true) {
  const values = binsFor(app),
    pts = points(values, 360, 125, 3),
    path = line(pts),
    span = S.timeSlice || [0, limit()],
    step = (span[1] - span[0]) / 6;
  return `<div class="traffic-graph"><svg viewBox="0 0 360 130" preserveAspectRatio="none" aria-hidden="true"><defs><linearGradient id="graph-shade" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#78a6e0" stop-opacity=".21"/><stop offset="100%" stop-color="#78a6e0" stop-opacity=".015"/></linearGradient></defs><path class="grid" d="M0 30H360M0 77H360M0 126H360"/><path class="area" d="${path}L357 127L3 127Z"/><path class="curve" d="${path}"/></svg>${
    interactive
      ? `<div class="graph-touches">${Array.from({ length: 6 }, (_, i) => {
          const low = Math.round(span[1] - (i + 1) * step),
            high = Math.round(span[1] - i * step);
          return `<button data-graph-app="${app}" data-low="${low}" data-high="${high}" aria-label="查看 ${clock(high)} 至 ${clock(low)} 的活动"></button>`;
        }).join("")}</div>`
      : ""
  }</div><div class="graph-times"><span>${clock(span[1])}</span><span>${clock((span[0] + span[1]) / 2)}</span><span>${clock(span[0])}</span></div>`;
}
export function bindGraph() {
  $$("[data-graph-app]").forEach(
    (b) =>
      (b.onclick = () => {
        selectRange([+b.dataset.low, +b.dataset.high]);
        go("contributions.html", {
          app: b.dataset.graphApp,
          from: location.pathname.split("/").pop() + location.search,
        });
      }),
  );
}
export function identity(a, subtitle, small = false) {
  return `<div class="${small ? "context-heading" : "application-identity"}">${appIcon(a, !small)}<div class="grow"><h1>${esc(a.name)}${small ? "的活动" : ""}</h1><p>${esc(subtitle)}</p></div><button class="period-button" id="period-picker">${periodText()}</button></div>`;
}
let before;
export function closeSheet() {
  const el = $("#experience-sheet");
  if (el) {
    el.remove();
    before?.focus?.();
  }
}
export function sheet(content, cls = "") {
  closeSheet();
  before = document.activeElement;
  const overlay = document.createElement("div");
  overlay.className = "modal-backdrop";
  overlay.id = "experience-sheet";
  overlay.innerHTML = `<section class="sheet ${cls}" role="dialog" aria-modal="true" aria-labelledby="sheet-title">${content}</section>`;
  $(".device").append(overlay);
  overlay.addEventListener("click", (e) => {
    if (e.target.closest("[data-close-sheet]")) closeSheet();
  });
  overlay.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeSheet();
    }
    if (e.key === "Tab") {
      const nodes = $$(
          "button:not(:disabled),a[href],input,select,summary",
          overlay,
        ),
        i = nodes.indexOf(document.activeElement);
      if (e.shiftKey && i <= 0) {
        e.preventDefault();
        nodes.at(-1)?.focus();
      } else if (!e.shiftKey && i === nodes.length - 1) {
        e.preventDefault();
        nodes[0]?.focus();
      }
    }
  });
  $("button,select,input", overlay)?.focus();
  return overlay;
}
export function bindPeriod(redraw) {
  const b = $("#period-picker");
  if (!b) return;
  b.textContent = periodText();
  b.onclick = () => {
    sheet(
      `<h2 id="sheet-title">查看哪段时间</h2><div class="period-choices"><button data-period="recent" class="${S.period === "recent" && !S.timeSlice ? "active" : ""}">最近 30 分钟</button><button data-period="today" class="${S.period === "today" && !S.timeSlice ? "active" : ""}">今天</button><button data-period="hour" class="${S.period === "hour" && !S.timeSlice ? "active" : ""}">最近 1 小时</button></div><button class="btn full" data-close-sheet>保持当前范围</button>`,
    );
    $$("[data-period]").forEach(
      (b) =>
        (b.onclick = () => {
          selectRange(null, b.dataset.period);
          closeSheet();
          redraw();
        }),
    );
  };
}
export function channelLabel(r) {
  const c = r.channels || ["connection"];
  return c.length === 2
    ? "域名查询与连接"
    : c[0] === "dns"
      ? "域名查询"
      : "连接";
}
export function resultText(e) {
  if (e.recordType === "dns")
    return e.result === "drop"
      ? "查询被阻止"
      : e.outcome === "failed"
        ? "查询未成功"
        : "查到了网络地址";
  return connectionLabel(e);
}
export function recordRow(e, options = {}) {
  if (e.recordType === "connection") return connectionRow(e, options);
  const a = subject(e.subject);
  return `<a class="network-record" href="${url("connection.html", { id: e.id, app: e.subject, from: options.from || location.pathname.split("/").pop() + location.search })}" data-record="${e.id}"><span class="record-mark ${e.result === "drop" ? "blocked" : ""}">${icon(e.recordType === "dns" ? "globe" : e.result === "drop" ? "ban" : "arrow-up-right")}</span><span class="grow">${options.showApp ? `<span class="row-app">${appIcon(a)}${esc(a?.name || "归属未确定")}</span>` : ""}<h3>${resultText(e)}</h3><span class="target">${esc(e.target)}</span><span class="record-meta">${e.sample ? "样例新活动 · " : ""}${e.recordType === "dns" ? (e.result === "drop" ? "按你的联网设置处理" : "返回 " + e.answers.length + " 个地址") : e.result === "drop" ? "连接规则已执行" : bytes(e.bytes) + " · " + (e.labels || []).join(" / ")}</span></span><time>${clock(e.minute)}</time></a>`;
}
export function rememberScroll() {
  const key = () => {
    const u = new URL(url(here()), location.href);
    u.searchParams.sort();
    return u.pathname + u.search;
  };
  requestAnimationFrame(() => {
    if (S.scroll?.[key()] != null) $(".screen").scrollTop = S.scroll[key()];
  });
  addEventListener(
    "pagehide",
    () => {
      S.scroll = S.scroll || {};
      S.scroll[key()] = $(".screen").scrollTop;
      persist();
    },
    { once: true },
  );
}
