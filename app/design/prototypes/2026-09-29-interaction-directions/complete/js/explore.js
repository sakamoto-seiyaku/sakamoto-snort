import {
  S,
  params,
  platform,
  allSubjects,
  subjectName,
  subjectRules,
  bindingsFor,
  events,
  filteredEvents,
  persist,
  bytes,
  conditionText,
} from "./model.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  eventRow,
  empty,
  toast,
  dialog,
  showError,
  row,
} from "./ui.js";
const regions = {
  ams: { name: "荷兰", city: "阿姆斯特丹", x: 370, y: 75 },
  tokyo: { name: "日本", city: "东京", x: 639, y: 108 },
  sf: { name: "美国", city: "旧金山", x: 115, y: 104 },
  local: { name: "本地网络", city: "私有地址" },
  unknown: { name: "位置未知", city: "没有可靠位置资料" },
};
export function map() {
  S.mapRange = S.mapRange || "60";
  function draw() {
    const es = filteredEvents({
      subject: "all",
      result: "all",
      kind: "all",
      query: "",
      range: S.mapRange,
    });
    const keys = [...new Set(es.map((e) => e.region))];
    $("#world-map").innerHTML =
      `<svg viewBox="0 0 720 360" aria-label="目的地区的示例分布"><image href="assets/world.svg" width="720" height="360"/>${keys
        .filter((k) => regions[k].x)
        .map((k) => {
          const r = regions[k];
          return `<a href="${url("location.html", { region: k })}" aria-label="查看${r.name}的访问"><circle cx="${r.x}" cy="${r.y}" r="32" fill="transparent"/><circle cx="${r.x}" cy="${r.y}" r="17" fill="#2865e81c"/><circle cx="${r.x}" cy="${r.y}" r="7" fill="#2865e8" stroke="#fff" stroke-width="3"/><text x="${r.x + 12}" y="${r.y - 13}" font-size="15" fill="#365773">${r.city}</text></a>`;
        })
        .join("")}</svg><span class="map-label">目的地区 · 示例地理信息</span>`;
    $("#map-count").textContent = es.length + " 条访问";
    $("#map-locations").innerHTML =
      keys
        .map((k) => {
          const list = es.filter((e) => e.region === k);
          return row(
            regions[k].name,
            regions[k].city +
              " · " +
              bytes(list.reduce((n, e) => n + e.bytes, 0)),
            "location.html?region=" + k,
            "chevron-right",
            list.length + " 次",
          );
        })
        .join("") || empty("没有可展示的位置", "当前范围没有保留的访问记录。");
    $$("[data-map-range]").forEach((b) =>
      b.classList.toggle("active", b.dataset.mapRange === S.mapRange),
    );
    persist();
  }
  $$("[data-map-range]").forEach(
    (b) =>
      (b.onclick = () => {
        S.mapRange = b.dataset.mapRange;
        draw();
      }),
  );
  draw();
}
export function locationPage() {
  const key = regions[params.get("region")] ? params.get("region") : "tokyo",
    r = regions[key];
  const list = filteredEvents({
    subject: "all",
    result: "all",
    kind: "all",
    query: "",
    range: S.mapRange || "60",
  }).filter((e) => e.region === key);
  $("#location-title").innerHTML =
    `<header class="page-intro"><div class="eyebrow">目的地区</div><h1>${r.name}</h1><p>${r.city}${r.x ? " · 示例地理标注" : ""}</p></header>`;
  $("#location-summary").innerHTML =
    `<div class="metrics" style="gap:30px"><div><div class="metric-label">访问记录</div><div class="metric-value">${list.length}</div></div><div><div class="metric-label">已观察流量</div><div class="metric-value" style="font-size:23px">${bytes(list.reduce((n, e) => n + e.bytes, 0))}</div></div></div>`;
  $("#location-events").innerHTML =
    list.map(eventRow).join("") ||
    empty("没有保留的访问", "可以返回地图调整时间范围。");
}
function within(ip, cidr) {
  if (
    !/^\d+\.\d+\.\d+\.\d+$/.test(ip) ||
    !/^\d+\.\d+\.\d+\.\d+(?:\/\d+)?$/.test(cidr)
  )
    return null;
  const [base, mask = "32"] = cidr.split("/");
  if (+mask < 0 || +mask > 32) return null;
  const num = (s) =>
    s.split(".").reduce((n, b) => n * 256 + Number(b), 0) >>> 0;
  const m = +mask === 0 ? 0 : (0xffffffff << (32 - +mask)) >>> 0;
  return (num(ip) & m) === (num(base) & m);
}
function matches(n, f) {
  if (n.type === "leaf") {
    const v = n.value;
    switch (n.field) {
      case "domain_list": {
        if (f.protocol === "unknown" || !["TLS", "QUIC"].includes(f.protocol))
          return null;
        const list = S.config.lists.find((l) => l.id === v);
        if (!list) return null;
        return list.entries.some(
          (e) =>
            f.target === e.name ||
            (e.mode === "descendants" && f.target.endsWith("." + e.name)),
        );
      }
      case "l7":
        return f.protocol === "unknown" ? null : f.protocol === v;
      case "destination":
        return within(f.target, v);
      case "destination_port": {
        const [a, b = a] = v.split(/[-–]/).map(Number);
        return +f.port >= a && +f.port <= b;
      }
      case "protocol":
        return f.transport === v;
      case "network":
        return f.network === v;
      case "family":
        return f.target.includes(":")
          ? v === "IPv6"
          : /^\d+\.\d+\.\d+\.\d+$/.test(f.target)
            ? v === "IPv4"
            : null;
      default:
        return null;
    }
  }
  const parts = n.children.map((x) => matches(x, f));
  if (n.type === "not") return parts[0] == null ? null : !parts[0];
  if (n.type === "and") {
    if (parts.includes(false)) return false;
    return parts.includes(null) ? null : true;
  }
  if (parts.includes(true)) return true;
  return parts.includes(null) ? null : false;
}
function evaluate(f) {
  const rs = subjectRules(f.subject),
    steps = [];
  let uncertain = false,
    winner = null,
    result = "allow",
    observe = false;
  for (const r of rs) {
    const value = matches(r.conditions, f);
    steps.push({
      id: r.id,
      title: r.name,
      description: conditionText(r.conditions),
      value,
    });
    if (value === null) uncertain = true;
    if (value === true) {
      if (uncertain) result = "unknown";
      else {
        winner = r;
        const b = bindingsFor(r.id).find((b) => b.subjects.includes(f.subject));
        observe = b?.mode === "observe";
        result = observe ? "allow" : r.action;
      }
      break;
    }
  }
  if (!winner && uncertain) result = "unknown";
  return {
    facts: f,
    steps,
    winner: winner
      ? { id: winner.id, name: winner.name, action: winner.action }
      : null,
    result,
    observe,
    version: S.savedVersion,
  };
}
function defaultFacts() {
  return {
    subject: "s1",
    target: "metrics.example.net",
    port: "443",
    transport: "TCP",
    protocol: "TLS",
    network: "Wi-Fi",
  };
}
export function preview() {
  const f = S.preview?.facts || defaultFacts();
  $("#preview-subject").innerHTML = allSubjects()
    .map((o) => `<option value="${o.id}">${esc(o.name)}</option>`)
    .join("");
  if (platform === "linux")
    $("#preview-network").innerHTML =
      '<option value="Wired">有线网络</option><option value="Wi-Fi">Wi-Fi</option><option value="VPN">VPN 网络</option>';
  else $('#preview-network option[value="Wired"]').remove();
  for (const k of [
    "subject",
    "target",
    "port",
    "transport",
    "protocol",
    "network",
  ]) {
    const el = $("#preview-" + k);
    if (
      el.querySelector?.('option[value="' + f[k] + '"]') ||
      el.tagName !== "SELECT"
    )
      el.value = f[k];
  }
  if (params.get("subject"))
    $("#preview-subject").value = params.get("subject");
  $("#run-preview").onclick = () => {
    const facts = {};
    for (const k of [
      "subject",
      "target",
      "port",
      "transport",
      "protocol",
      "network",
    ])
      facts[k] = $("#preview-" + k).value.trim();
    if (
      !facts.target ||
      +facts.port < 1 ||
      +facts.port > 65535 ||
      !Number.isInteger(+facts.port)
    ) {
      showError("填写一个目标，以及 1–65535 之间的目的端口。");
      return;
    }
    S.preview = evaluate(facts);
    persist();
    go("preview-result.html");
  };
}
export function previewResult() {
  const p = S.preview || evaluate(defaultFacts());
  const unknown = p.result === "unknown",
    blocked = p.result === "drop";
  $("#preview-result-main").innerHTML =
    `<div class="result-hero"><span class="result-symbol ${unknown ? "warn" : blocked ? "red" : ""}">${icon(unknown ? "circle-help" : blocked ? "ban" : "check")}</span><h1>${unknown ? "当前事实不足。" : blocked ? "预计阻止。" : "预计允许。"}</h1><p>${esc(subjectName(p.facts.subject))}<br>${esc(p.facts.target)}:${esc(p.facts.port)} · ${p.facts.protocol === "unknown" ? "协议未知" : esc(p.facts.protocol)}</p></div><div class="card"><span class="eyebrow">合成输入 · 已保存配置 v${p.version}</span><p class="help" style="margin-top:12px">${unknown ? "较早的规则存在未提供或未支持的事实，不能断言最后动作。" : p.winner ? `命中「${esc(p.winner.name)}」。${p.observe ? "此分配为仅观察，声明动作仍为阻止，实际允许。" : ""}` : "没有显式规则命中，使用默认允许。"}</p></div>`;
  $("#preview-steps").innerHTML =
    p.steps
      .map(
        (s) =>
          `<div class="timeline-item"><h3>${esc(s.title)}</h3><p>${esc(s.description)}</p><span class="badge ${s.value === null ? "amber" : s.value ? "blue" : "gray"}" style="margin-top:8px">${s.value === null ? "事实不足 / 模拟暂不支持" : s.value ? "符合条件" : "不符合条件"}</span></div>`,
      )
      .join("") || '<p class="note">此对象尚未分配规则，使用默认允许。</p>';
  $("#preview-result-links").innerHTML = p.winner
    ? row("查看匹配规则", p.winner.name, "rule-detail.html?id=" + p.winner.id)
    : row(
        "检查作用对象的规则",
        subjectName(p.facts.subject),
        "app-detail.html?id=" + p.facts.subject,
      );
  $("#adjust-preview").onclick = () => go("preview.html");
}
const focusLabels = {
  connection: "连接未能建立",
  rule: "规则判断",
  runtime: "运行中断",
};
export function debug() {
  $("#debug-subject").innerHTML = allSubjects()
    .map((o) => `<option value="${o.id}">${esc(o.name)}</option>`)
    .join("");
  if (S.debug.status === "running") {
    $("#start-debug").textContent = "返回进行中的会话";
    $("#start-debug").onclick = () => go("debug-session.html");
    return;
  }
  $("#start-debug").onclick = () => {
    if (!S.running) {
      showError("先恢复防火墙运行，再开始诊断会话。");
      return;
    }
    S.debug = {
      status: "running",
      started: Date.now(),
      duration: +$("#debug-duration").value,
      subject: $("#debug-subject").value,
      focus: $("#debug-focus").value,
      events: [],
    };
    persist();
    go("debug-session.html");
  };
}
function sessionEvents(d, elapsed) {
  const candidates = events.filter((e) => e.subject === d.subject);
  const base = [
    {
      time: 0,
      title: "会话已开始",
      detail: subjectName(d.subject) + " · " + focusLabels[d.focus],
      kind: "session",
    },
    {
      time: 1,
      title: "运行状态已确认",
      detail:
        (platform === "linux"
          ? "Linux 主机"
          : S.mode === "vpn"
            ? "VPN"
            : "Root") +
        " · 当前配置 v" +
        S.activeVersion,
      kind: "runtime",
    },
  ];
  for (
    let i = 0;
    i < Math.min(candidates.length, Math.floor(elapsed / 3));
    i++
  ) {
    const e = candidates[i];
    base.push({
      time: 3 * (i + 1),
      title: e.target,
      detail: e.ruleName
        ? (e.result === "drop" ? "实际阻止" : "实际允许") + " · " + e.ruleName
        : "默认允许 · " + e.protocol + "/" + e.port,
      kind: "rule",
      event: e.id,
    });
  }
  if (elapsed >= 12 && !candidates.length)
    base.push({
      time: 12,
      title: "当前没有该对象的访问",
      detail: "等待样例中符合此对象的记录；不会把没有记录当作失败。",
      kind: "empty",
    });
  return base.filter((x) => x.time <= elapsed);
}
export function debugSession() {
  if (S.debug.status === "idle") {
    $("#debug-session-heading").innerHTML =
      '<header class="page-intro"><h1>还没有开始会话</h1><p>选择一个对象和问题，再开始观察。</p></header>';
    $("#session-actions").innerHTML =
      `<a class="btn primary full" href="${url("debug.html")}">配置诊断会话</a>`;
    $("#session-scope").textContent = "尚未采集任何会话样例";
    return;
  }
  const d = S.debug;
  $("#debug-session-heading").innerHTML =
    `<header class="page-intro"><div class="eyebrow">诊断会话</div><h1>${esc(subjectName(d.subject))}</h1><p>${focusLabels[d.focus]}</p></header>`;
  function draw() {
    let elapsed =
      d.status === "running"
        ? Math.floor((Date.now() - d.started) / 1000)
        : d.elapsed || 0;
    if (elapsed >= d.duration) {
      elapsed = d.duration;
      d.status = "ended";
      d.elapsed = elapsed;
      d.endReason = "达到设定时限";
    }
    d.events = sessionEvents(d, elapsed);
    $("#session-clock").textContent =
      String(Math.floor(elapsed / 60)).padStart(2, "0") +
      ":" +
      String(elapsed % 60).padStart(2, "0");
    $("#debug-session-state").textContent =
      d.status === "running"
        ? "正在观察 · 最长 " + d.duration + " 秒"
        : "会话已结束";
    $("#session-scope").textContent =
      d.status === "running"
        ? "切换页面不会结束会话；可以随时停止。"
        : (d.endReason || "已手动停止") + "。防火墙继续运行。";
    $("#session-event-count").textContent = d.events.length + " 条过程";
    $("#session-events").innerHTML = d.events
      .map(
        (e) =>
          `<div class="timeline-item"><time>00:${String(e.time).padStart(2, "0")}</time><h3>${esc(e.title)}</h3><p>${esc(e.detail)}</p>${e.event ? `<a class="text-link" href="${url("connection.html", { id: e.event, from: "debug-session.html" })}">查看访问 ${icon("chevron-right", "sm")}</a>` : ""}</div>`,
      )
      .join("");
    $("#session-actions").innerHTML =
      d.status === "running"
        ? '<button class="btn full" id="stop-debug">停止诊断会话</button>'
        : `<a class="btn primary full" href="${url("diagnostics.html", { from: "debug-session.html" })}">查看并导出报告 ${icon("arrow-right")}</a><a class="btn full" href="${url("debug.html")}">新建会话</a>`;
    if ($("#stop-debug"))
      $("#stop-debug").onclick = () => {
        d.status = "ended";
        d.elapsed = Math.floor((Date.now() - d.started) / 1000);
        d.endReason = "已手动停止";
        persist();
        draw();
      };
    persist();
  }
  draw();
  const timer = setInterval(draw, 1000);
  addEventListener("pagehide", () => clearInterval(timer), { once: true });
}
