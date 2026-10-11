import {
  S,
  params,
  platform,
  scope,
  persist,
  subjectName,
  bytes,
  bindingsFor,
  rule,
  conditionText,
  delay,
} from "./model.js";
export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
export const icon = (name, cls = "") =>
  `<svg class="icon ${cls}" aria-hidden="true"><use href="assets/icons.svg#${name}"></use></svg>`;
export function url(file, values = {}) {
  const u = new URL(file, location.href);
  if (
    u.origin !== location.origin ||
    !u.pathname.startsWith(
      location.pathname.slice(0, location.pathname.lastIndexOf("/") + 1),
    )
  )
    return url("home.html");
  u.searchParams.set("platform", platform);
  u.searchParams.set("scope", scope);
  if (params.get("embed")) u.searchParams.set("embed", params.get("embed"));
  Object.entries(values).forEach(([k, v]) =>
    v == null ? u.searchParams.delete(k) : u.searchParams.set(k, v),
  );
  return u.pathname + u.search;
}
export function go(file, values = {}) {
  location.href = url(file, values);
}
export function here() {
  return location.pathname.split("/").pop() + location.search;
}
export const row = (title, subtitle, href, ic = "chevron-right", value = "") =>
  `<a class="list-row" href="${url(href)}"><span class="grow"><span class="title">${title}</span>${subtitle ? `<span class="subtitle">${subtitle}</span>` : ""}</span>${value ? `<span class="value">${value}</span>` : ""}${icon(ic)}</a>`;
export function appIcon(o, large = false) {
  const content =
    platform === "android" && ["s1", "s2"].includes(o.id)
      ? `<img src="assets/${o.id === "s1" ? "firefox" : "signal"}.svg" alt="" onerror="this.hidden=true;this.parentElement.textContent='${o.letter}'">`
      : icon(
          platform === "linux"
            ? "user"
            : o.id === "s3"
              ? "music-2"
              : o.id === "s4"
                ? "cloud-sun"
                : "folder",
        );
  return `<span class="app-icon ${large ? "large" : ""} ${platform === "android" && o.id === "s1" ? "brand-firefox" : platform === "android" && o.id === "s2" ? "brand-signal" : ""}">${content}</span>`;
}
export function badge(result) {
  return `<span class="badge ${result === "drop" ? "red" : result === "observe" ? "blue" : ""}">${result === "drop" ? "已阻止" : result === "observe" ? "观察 · 允许" : "已允许"}</span>`;
}
export function ruleCard(r, active = false) {
  return `<a class="rule-item" href="${url("rule-detail.html", { id: r.id, active: active === true ? 1 : null })}"><div class="topline"><span class="badge ${r.action === "drop" ? "red" : "blue"}">${r.action === "drop" ? "阻止" : "允许"}</span><span>优先级 ${r.priority}</span></div><h3>${esc(r.name)}</h3><p>${esc(conditionText(r.conditions))}</p><div class="rule-foot"><span>${new Set(bindingsFor(r.id).flatMap((b) => b.subjects)).size} 个控制对象</span>${icon("chevron-right", "sm")}</div></a>`;
}
export function eventRow(e) {
  return `<a class="activity-row" href="${url("connection.html", { id: e.id, from: here() })}"><span class="event-symbol ${e.result === "drop" ? "red" : e.result === "observe" ? "blue" : ""}">${icon(e.result === "drop" ? "ban" : e.result === "observe" ? "eye" : "arrow-up-right", "sm")}</span><div class="grow"><h3>${esc(e.target)}</h3><p>${esc(subjectName(e.subject))} · ${e.labels.join(" / ") || "未识别"} · ${e.kind === "blocked" ? "建连前阻止" : e.kind === "live" ? "当前连接" : "已结束"}</p></div><time>${e.time}</time></a>`;
}
export function empty(title, body, action = "") {
  return `<div class="empty">${icon("search")}<h2>${title}</h2><p>${body}</p>${action}</div>`;
}
export function toast(message, action) {
  $("#toast")?.remove();
  const el = document.createElement("div");
  el.id = "toast";
  el.className = "toast";
  el.role = "status";
  el.innerHTML =
    esc(message) +
    (action ? `<a href="${url(action.href)}">${esc(action.label)}</a>` : "");
  $(".device").append(el);
  setTimeout(() => el.remove(), 3800);
}
export function dialog({
  title,
  body,
  confirm = "确认",
  danger = false,
  onConfirm,
  onCancel,
  cancel = "取消",
}) {
  closeDialog();
  const el = document.createElement("div");
  el.className = "modal-backdrop";
  el.id = "dialog";
  el.innerHTML = `<section class="sheet" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(title)}</h2><p>${body}</p><button class="btn full ${danger ? "danger" : "primary"}" id="dialog-confirm">${esc(confirm)}</button><button class="btn full" id="dialog-cancel">${esc(cancel)}</button></section>`;
  $(".device").append(el);
  $("#dialog-cancel").onclick = () => {
    onCancel?.();
    closeDialog();
  };
  $("#dialog-confirm").onclick = async () => {
    const b = $("#dialog-confirm");
    b.disabled = true;
    try {
      await onConfirm?.();
      closeDialog();
    } catch (e) {
      b.disabled = false;
      toast(e.message);
    }
  };
  $("#dialog-cancel").focus();
  el.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDialog();
    if (e.key === "Tab") {
      const nodes = $$("button:not(:disabled),a,input,select", el),
        i = nodes.indexOf(document.activeElement);
      if (e.shiftKey && i <= 0) {
        e.preventDefault();
        nodes.at(-1).focus();
      } else if (!e.shiftKey && i === nodes.length - 1) {
        e.preventDefault();
        nodes[0].focus();
      }
    }
  });
}
let focusBefore;
export function closeDialog() {
  if ($("#dialog")) {
    $("#dialog").remove();
    focusBefore?.focus?.();
  }
}
export function showError(message) {
  let el = $("#form-error");
  if (!el) {
    el = document.createElement("div");
    el.id = "form-error";
    el.className = "form-error";
    el.role = "alert";
    $(".screen").append(el);
  }
  el.textContent = message;
  el.scrollIntoView({ block: "nearest" });
  return el;
}
export async function saving(button, operation) {
  const label = button.innerHTML;
  button.disabled = true;
  button.innerHTML = icon("loader-circle") + "正在保存…";
  if ($("#form-error")) $("#form-error").textContent = "";
  try {
    await operation();
  } catch (e) {
    const el = showError(e.message);
    if (["save-error", "conflict"].includes(S.scenario)) {
      const retry = document.createElement("button");
      retry.className = "text-link";
      retry.textContent =
        S.scenario === "conflict" ? "读取最新版本并重试" : "重试保存";
      retry.style.display = "block";
      retry.onclick = () => {
        S.scenario = "normal";
        persist();
        saving(button, operation);
      };
      el.append(retry);
    }
  } finally {
    button.disabled = false;
    button.innerHTML = label;
  }
}
export function download(name, data) {
  const a = document.createElement("a"),
    u = URL.createObjectURL(
      new Blob(
        [typeof data === "string" ? data : JSON.stringify(data, null, 2)],
        { type: "application/json" },
      ),
    );
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 3000);
}
export function chart(
  values = [
    20, 34, 27, 46, 40, 22, 38, 57, 48, 67, 52, 34, 65, 89, 73, 62, 48, 33, 55,
    70, 83, 58, 43, 31,
  ],
) {
  return `<div class="chart" aria-label="样例访问趋势">${values.map((v, i) => `<span class="bar" style="height:${v}%;--blocked:${12 + ((i * 7) % 25)}%"></span>`).join("")}</div><div class="chart-labels"><span>08:40</span><span>09:10</span><span>09:40</span></div>`;
}
export function trafficChart(list, range = 60) {
  const bins = Array.from({ length: 12 }, () => ({ total: 0, blocked: 0 }));
  list.forEach((e) => {
    const b = bins[Math.min(11, Math.floor(e.minute / (range / 12)))];
    b.total++;
    if (e.result === "drop") b.blocked++;
  });
  const max = Math.max(1, ...bins.map((b) => b.total));
  const now = 9 * 60 + 40,
    start = (now - range + 1440) % 1440,
    format = (n) =>
      String(Math.floor(n / 60)).padStart(2, "0") +
      ":" +
      String(n % 60).padStart(2, "0");
  return `<div class="chart" aria-label="当前保留记录的访问趋势">${bins
    .reverse()
    .map(
      (b) =>
        `<span class="bar" style="height:${(b.total / max) * 100}%;min-height:${b.total ? 3 : 0}px;--blocked:${b.total ? (b.blocked / b.total) * 100 : 0}%" title="${b.total} 次访问，${b.blocked} 次阻止"></span>`,
    )
    .join(
      "",
    )}</div><div class="chart-labels"><span>${range >= 1440 ? "今天" : format(start)}</span><span>${range >= 1440 ? "" : format((start + range / 2) % 1440)}</span><span>09:40</span></div>`;
}
export function mount() {
  document.body.dataset.platform = platform;
  document.body.classList.toggle("gallery-mode", params.has("embed"));
  applyAppearance();
  const nav = document.body.dataset.nav || "home";
  const back = document.body.dataset.back;
  const title = document.body.dataset.title || "Sakamoto";
  const items = [
    ["home", "概览", "house"],
    ["apps", "控制", "layout-grid"],
    ["activity", "活动", "activity"],
    ["rules", "规则", "sliders-horizontal"],
    ["settings", "设置", "settings-2"],
  ];
  $(".statusbar").innerHTML =
    '<span>9:41</span><span class="island"></span><span class="status-icons">' +
    icon("signal") +
    icon("wifi") +
    icon("battery-full") +
    "</span>";
  $(".topbar").innerHTML =
    (back
      ? `<a class="back" href="${url(params.get("from") || back)}" aria-label="返回">${icon("chevron-left")}返回</a>`
      : `<span class="eyebrow" style="margin:0 8px">SAKAMOTO</span>`) +
    `<span class="topbar-title">${back ? esc(title) : ""}</span>` +
    `<a href="${url("runtime.html")}" class="status-pill"><span class="dot"></span>${S.running ? "运行中" : S.scenario === "permission" ? "待授权" : S.scenario === "intervention" ? "需处理" : "已暂停"}</a>`;
  $(".bottom-nav").innerHTML = items
    .map(
      ([id, t, i]) =>
        `<a class="${nav === id ? "active" : ""}" href="${url(id + ".html")}" ${nav === id ? 'aria-current="page"' : ""}>${icon(i)}<span>${t}</span></a>`,
    )
    .join("");
  $(".desktop-nav").innerHTML =
    `<a class="desktop-brand" href="${url("home.html")}"><span class="tile-icon">${icon("shield")}</span>sakamoto</a>` +
    items
      .map(
        ([id, t, i]) =>
          `<a class="${nav === id ? "active" : ""}" href="${url(id + ".html")}">${icon(i)}<span>${t}</span></a>`,
      )
      .join("") +
    `<div class="nav-caption">深入了解</div><a href="${url("stats.html")}">${icon("chart-no-axes-combined")}<span>统计</span></a><a href="${url("extensions.html")}">${icon("flask-conical")}<span>探索工具</span></a><footer>${platform === "linux" ? "Linux · 本机" : "Android · 本机"}<br>所有记录保存在本机</footer>`;
  const notice = $(".status-strip");
  if (S.savedVersion !== S.activeVersion)
    notice.innerHTML = `<span>修改已保存，尚未生效</span><a href="${url("config.html")}">查看并处理</a>`;
  else if (["intervention", "recovering", "startup"].includes(S.scenario))
    notice.innerHTML = `<span>${S.scenario === "recovering" ? "正在恢复运行" : S.scenario === "startup" ? "配置需要修复" : "防火墙需要处理"}</span><a href="${url(S.scenario === "startup" ? "config.html" : "recovery.html")}">查看原因</a>`;
  $$("[data-icon]").forEach((e) => (e.innerHTML = icon(e.dataset.icon)));
  $$("a[data-page]").forEach((e) => (e.href = url(e.dataset.page)));
  $$("[data-platform-label]").forEach(
    (e) =>
      (e.textContent =
        platform === "linux" ? e.dataset.linux : e.dataset.android),
  );
  document.title = title + " · Sakamoto";
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDialog();
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("button,a"))
      focusBefore = e.target.closest("button,a");
  });
}
export function applyAppearance() {
  document.body.dataset.theme =
    S.theme === "system"
      ? matchMedia("(prefers-color-scheme:dark)").matches
        ? "dark"
        : "light"
      : S.theme;
  document.body.dataset.text = S.text;
  document.documentElement.style.setProperty("--accent", S.accent);
}
