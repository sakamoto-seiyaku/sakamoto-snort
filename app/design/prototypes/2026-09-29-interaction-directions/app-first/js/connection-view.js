import { S, subject, subjectName, bytes } from "./model.js";
import { esc, icon, appIcon, url, here } from "./ui.js";
import { directionBytes, transferInSpan } from "./network-data.js";

export function connectionFacts(e) {
  return (
    e.connectionState || {
      state:
        e.result === "drop"
          ? "blocked"
          : e.kind === "live"
            ? "connected"
            : e.kind === "failed"
              ? "failed"
              : "ended",
      captured: "09:41:00",
      openedMinute: null,
      lastTransferMinute: null,
      endedMinute: null,
      rateSent: null,
      rateReceived: null,
      transport: e.protocol === "UDP" ? "UDP 会话" : "TCP 连接",
    }
  );
}
export function isHeld(e) {
  return ["transferring", "idle", "connected"].includes(
    connectionFacts(e).state,
  );
}
export function connectionLabel(e) {
  const f = connectionFacts(e);
  if (f.state === "transferring")
    return f.rateReceived > f.rateSent * 2
      ? "正在接收"
      : f.rateSent > f.rateReceived * 2
        ? "正在发送"
        : "正在传输";
  return (
    {
      idle: "保持连接 · 暂无传输",
      connected: "保持连接",
      ended: "已结束",
      blocked: "被规则阻止",
      failed: "未能建立",
    }[f.state] || "状态未记录"
  );
}
export function stamp(minute) {
  if (minute == null) return "未记录";
  const s = Math.round(9 * 3600 + 41 * 60 - minute * 60);
  return [Math.floor(s / 3600), Math.floor(s / 60) % 60, s % 60]
    .map((x) => String(x).padStart(2, "0"))
    .join(":");
}
function duration(e) {
  const f = connectionFacts(e);
  if (f.openedMinute == null) return "持续时间未记录";
  const seconds = Math.max(
    0,
    Math.round((f.openedMinute - (f.endedMinute ?? 0)) * 60),
  );
  return seconds < 60
    ? seconds + " 秒"
    : Math.floor(seconds / 60) + " 分 " + (seconds % 60) + " 秒";
}
const lifetime = (e, d) => e.lifetime?.[d] ?? directionBytes(e, d);
function durationLabel(e) {
  const f = connectionFacts(e),
    measured = f.startEvidence === "established";
  if (f.openedMinute == null) return "持续时间未记录";
  return (
    (isHeld(e)
      ? measured
        ? "已连接 "
        : "已观察至少 "
      : measured
        ? "持续 "
        : "首次记录至结束 ") + duration(e)
  );
}
function rate(n) {
  return n == null ? "未记录" : bytes(n) + "/s";
}
function recent(e) {
  const f = connectionFacts(e);
  if (f.state === "idle") return "近 10 秒没有收发数据";
  if (f.state === "transferring")
    return `↓ ${rate(f.rateReceived)}　↑ ${rate(f.rateSent)}`;
  if (f.state === "blocked") return "规则已阻止这次尝试，未建立连接";
  if (f.state === "failed") return f.failure || "没有建立成功的记录";
  if (f.state === "ended")
    return f.endedMinute != null
      ? stamp(f.endedMinute) + " 结束"
      : "已记录的连接已结束";
  return "近期传输速率未记录";
}
export function connectionRow(
  e,
  {
    showApp = false,
    from = here(),
    compact = false,
    timeContext = !!S.timeSlice,
  } = {},
) {
  const f = connectionFacts(e),
    a = subject(e.subject),
    held = isHeld(e);
  if (timeContext) {
    const t = transferInSpan(e);
    return `<a class="network-record connection-row period-connection ${compact ? "compact" : ""}" href="${url("connection.html", { id: e.id, app: e.subject, from })}" data-record="${e.id}"><span class="connection-presence">${icon("activity")}</span><span class="grow">${showApp ? `<span class="row-app">${appIcon(a)}${esc(a?.name || "归属未确定")}</span>` : ""}<strong class="connection-period-target">${esc(e.target)}</strong><span class="connection-period-facts"><span>本时段${["blocked", "failed"].includes(f.state) ? " · 未建立连接" : " · 有连接记录"}</span><strong>↓ ${bytes(t.received)}　↑ ${bytes(t.sent)}</strong></span><span class="connection-latest-facts"><span>最新快照 ${f.captured.slice(0, 5)} · ${connectionLabel(e)}</span><span>${recent(e)}${f.state === "transferring" ? " · 近 10 秒平均" : ""}</span><span>${["blocked", "failed"].includes(f.state) ? "" : `整条累计 ↓ ${bytes(lifetime(e, "received"))}　↑ ${bytes(lifetime(e, "sent"))}`}</span></span></span>${icon("chevron-right")}</a>`;
  }
  return `<a class="network-record connection-row ${compact ? "compact" : ""}" href="${url("connection.html", { id: e.id, app: e.subject, from })}" data-record="${e.id}"><span class="connection-presence ${f.state}">${icon(f.state === "blocked" ? "ban" : f.state === "failed" ? "circle-alert" : held ? "activity" : "check")}</span><span class="grow">${showApp ? `<span class="row-app">${appIcon(a)}${esc(a?.name || "归属未确定")}</span>` : ""}<span class="connection-row-title"><strong>${esc(e.target)}${e.sample ? '<small class="sample-connection">样例新活动</small>' : ""}</strong><span class="connection-state ${f.state}">${connectionLabel(e)}</span></span><span class="connection-recent">${recent(e)}${f.state === "transferring" ? "<small>近 10 秒平均</small>" : ""}</span><span class="connection-total">${["blocked", "failed"].includes(f.state) ? esc(f.transport) : `累计 ↓ ${bytes(lifetime(e, "received"))}　↑ ${bytes(lifetime(e, "sent"))}`}<span>${held || f.state === "ended" ? durationLabel(e) : ""}</span></span></span>${icon("chevron-right")}</a>`;
}
export function connectionOverview(es) {
  return {
    held: es.filter(isHeld).length,
    transferring: es.filter((e) => connectionFacts(e).state === "transferring")
      .length,
    ended: es.filter((e) => connectionFacts(e).state === "ended").length,
    unestablished: es.filter((e) =>
      ["blocked", "failed"].includes(connectionFacts(e).state),
    ).length,
  };
}
export function connectionTools(es, filter = "all", query = "") {
  const c = connectionOverview(es);
  return `<div class="connection-reading"><span>连接快照 · 09:41</span><span>${S.running ? "最近记录" : "记录已暂停"}</span></div><div class="connection-filters" aria-label="查看哪些连接">${[
    ["all", "全部", es.length],
    ["held", "仍保持", c.held],
    ["ended", "已结束", c.ended],
    ["unestablished", "未建立", c.unestablished],
  ]
    .map(
      ([id, label, n]) =>
        `<button data-connection-filter="${id}" class="${filter === id ? "active" : ""}" aria-pressed="${filter === id}">${label}<small>${n}</small></button>`,
    )
    .join(
      "",
    )}</div><label class="connection-search">${icon("search")}<input id="connection-search" type="search" value="${esc(query)}" placeholder="搜索去向、应用或 IP" aria-label="搜索连接"></label>`;
}
export function matchConnection(e, filter, query = "") {
  const f = connectionFacts(e);
  const match =
    filter === "held"
      ? isHeld(e)
      : filter === "ended"
        ? f.state === "ended"
        : filter === "unestablished"
          ? ["blocked", "failed"].includes(f.state)
          : true;
  return (
    match &&
    `${e.target} ${e.ip} ${subjectName(e.subject)}`
      .toLowerCase()
      .includes(query.toLowerCase())
  );
}
export function connectionSummary(e, compact = false) {
  const f = connectionFacts(e),
    a = subject(e.subject),
    held = isHeld(e),
    noConnection = ["blocked", "failed"].includes(f.state);
  return `<div class="connection-story ${compact ? "in-inspector" : ""}"><div class="connection-story-top"><span class="connection-state ${f.state}"><i></i>${connectionLabel(e)}</span><time>记录于 ${f.captured}</time></div><h2 class="connection-destination">${esc(e.target)}</h2><p class="connection-destination-meta">${esc(f.transport)} · ${esc(e.network === "Wired" ? "有线网络" : e.network === "Mobile" ? "移动网络" : e.network)}${e.region && e.region !== "unknown" && e.region !== "local" ? " · " + esc(e.country) : ""}</p>
    <div class="connection-recent-panel"><span>${held ? "最近一次观测" : "这次连接的结果"}</span><strong>${recent(e)}</strong><small>${held ? (f.rateSent == null ? "没有近期速率记录" : "09:40:50–09:41:00 · 10 秒平均") : f.state === "blocked" ? "没有建立连接，也没有传输记录" : f.state === "failed" ? "规则允许；连接未建立成功，不等于规则阻止" : "累计量保留，不代表此刻仍在传输"}</small></div>
    <div class="connection-relationship ${noConnection ? "not-established" : ""}"><div class="connection-owner">${appIcon(a)}<span>${esc(a?.name || "归属未确定")}</span></div><div class="connection-directions">${noConnection ? `<span class="broken-connection">${icon(f.state === "blocked" ? "ban" : "circle-alert")} 未建立</span>` : `<span class="receive-direction">← <span>累计收到 <strong>${bytes(lifetime(e, "received"))}</strong></span></span><span class="send-direction"><span>累计发出 <strong>${bytes(lifetime(e, "sent"))}</strong></span> →</span>`}</div><div class="connection-remote">${icon("globe")}<span>目标服务器</span></div></div>
    ${compact ? "" : `<div class="connection-life"><h3>这条连接的经过</h3>${noConnection ? `<div><time>${stamp(f.openedMinute)}</time><span>发起连接尝试</span></div><div><time>${stamp(e.minute)}</time><span>${f.state === "blocked" ? "被规则阻止，未建立" : esc(f.failure || "未能建立")}</span></div>` : `<div><time>${stamp(f.openedMinute)}</time><span>${f.startEvidence === "established" ? "连接建立" : "首次观察到会话"}</span></div><div><time>${stamp(f.lastTransferMinute)}</time><span>最后记录到收发数据</span></div><div><time>${f.endedMinute == null ? f.captured : stamp(f.endedMinute)}</time><span>${held ? "这次快照中仍保持连接" : "连接结束"}<small>${durationLabel(e)}</small></span></div>`}</div><details class="connection-technical"><summary>地址与协议</summary><dl class="detail-pairs"><dt>应用地址</dt><dd>${f.localAddress ? esc(f.localAddress + ":" + f.localPort) : "未记录"}</dd><dt>目标地址</dt><dd>${esc(e.ip + ":" + e.port)}</dd><dt>传输协议</dt><dd>${esc(e.protocol)}</dd><dt>已识别协议</dt><dd>${esc((e.labels || []).join(" / ") || "未识别")}</dd><dt>目标位置</dt><dd>${e.region === "unknown" ? "没有可靠位置资料" : esc(e.country || "未记录")}<small>按 IP 资料标注</small></dd><dt>当时规则处理</dt><dd>${e.result === "drop" ? "阻止" : e.result === "observe" ? "仅观察，实际允许" : "允许"}</dd></dl></details>`}
    </div>`;
}
