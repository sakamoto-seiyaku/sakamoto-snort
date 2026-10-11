import {
  subjects,
  seedConfig,
  seedEvents,
  seedSubscriptionUpdate,
} from "./seed.js";
import { listEntries, entryKey } from "./domain-lists.js";
export const params = new URLSearchParams(location.search);
export const platform =
  params.get("platform") === "linux" ? "linux" : "android";
export const scope = params.get("scope") || "walkthrough";
const key =
  "sakamoto-trust-v4:" +
  platform +
  ":" +
  scope +
  ":" +
  (params.get("view") || "normal");
export const clone = (x) => JSON.parse(JSON.stringify(x));
function initial() {
  return {
    config: seedConfig(),
    period: "recent",
    viewCase: params.get("view") || "normal",
    activityType: "all",
    selectedEvent: null,
    addedConnections: [],
    addedQueries: [],
    scroll: {},
    active: seedConfig(),
    savedVersion: 42,
    activeVersion: 42,
    running: true,
    mode: platform === "linux" ? "host" : "root",
    preferredMode: platform === "linux" ? "host" : "root",
    permission: true,
    notificationPermission: true,
    notification: true,
    autostart: false,
    retention: "7",
    historyCleared: false,
    theme: "light",
    accent: "#2865e8",
    text: "standard",
    scenario: params.get("scenario") || "normal",
    draft: null,
    result: null,
    imported: null,
    subscriptionChecks: {},
    subscriptionCandidates: {},
    subscriptionResponses: {},
    filters: {
      subject: "all",
      result: "all",
      kind: "all",
      range: "60",
      query: "",
    },
    selected: "s1",
    debug: { status: "idle", started: 0, events: [] },
    preview: null,
    counter: 100,
  };
}
let saved;
try {
  saved = JSON.parse(sessionStorage.getItem(key));
} catch {}
export const S = saved || initial();
S.subscriptionChecks ||= {};
S.subscriptionCandidates ||= {};
S.subscriptionResponses ||= {};
if (!saved && params.get("subscription") === "failed")
  S.subscriptionChecks.d1 = {
    status: "failed",
    at: "今天 09:41",
    message: "订阅服务器暂时无法连接。现有资料仍保留。",
  };
if (!saved && params.get("subscription") === "update") {
  S.subscriptionCandidates.d1 = {
    ...seedSubscriptionUpdate(),
    url: S.config.lists[0].subscription.url,
  };
  S.subscriptionChecks.d1 = { status: "available", at: "今天 09:41" };
}
if (!saved && params.get("configcase") === "expanded-scope") {
  S.imported = clone(S.config);
  S.imported.rules.find((r) => r.id === "r2").conditions.children[0].value =
    "0.0.0.0/0";
}
if (!saved && params.get("localcase") === "modified") {
  const list = S.config.lists.find((l) => l.id === "d1");
  list.localAdditions = [{ name: "local.example.net", mode: "exact" }];
  list.localExclusions = [{ name: "api.metrics.example.net", mode: "exact" }];
  list.entries = listEntries(list);
  S.active = clone(S.config);
}
if (["recent", "hour", "today"].includes(params.get("period")))
  S.period = params.get("period");
if (params.has("window")) {
  const w = params.get("window").split(",").map(Number);
  S.timeSlice =
    w.length === 2 && w.every(Number.isFinite) && w[0] >= 0 && w[1] > w[0]
      ? w
      : null;
}
export function selectRange(slice = null, period = S.period) {
  S.period = period;
  S.timeSlice = slice;
  params.set("period", period);
  params.set("window", slice ? slice.join(",") : "all");
  const u = new URL(location.href);
  u.searchParams.set("period", period);
  u.searchParams.set("window", slice ? slice.join(",") : "all");
  history.replaceState({}, "", u);
  persist();
}
export const observationGaps = () =>
  ["gap", "dns-gap"].includes(S.viewCase) ? [[15, 17]] : [];
export const isRecorded = (e) =>
  !observationGaps().some(([a, b]) => e.minute >= a && e.minute < b);
if (
  !saved &&
  ["paused", "permission", "recovering", "intervention", "startup"].includes(
    S.scenario,
  )
)
  S.running = false;
if (!saved && S.scenario === "permission") S.permission = false;
if (!saved && ["startup", "unapplied"].includes(S.scenario)) {
  S.savedVersion++;
  S.config.rules[0].name += "（待生效）";
}
if (!saved && params.get("example") === "1")
  S.debug = {
    status: "running",
    started: Date.now() - 14000,
    duration: 60,
    subject: "s1",
    focus: "connection",
    events: [],
  };
if (!saved && S.scenario === "dns") S.dnsRestart = true;
if (!saved && params.get("example") === "saved") {
  S.savedVersion = 43;
  S.activeVersion = 43;
  S.result = {
    applied: true,
    returnTo: "rules.html",
    message: "演示保存成功",
    demo: true,
  };
}
if (
  S.debug.status === "running" &&
  (Date.now() - S.debug.started) / 1000 >= S.debug.duration
) {
  S.debug.status = "ended";
  S.debug.elapsed = S.debug.duration;
  S.debug.endReason = "达到设定时限";
}
export function persist() {
  try {
    sessionStorage.setItem(key, JSON.stringify(S));
  } catch {}
  window.dispatchEvent(new Event("prototype-state-change"));
}
export function reset() {
  sessionStorage.removeItem(key);
  location.reload();
}
export function allSubjects() {
  return subjects[platform];
}
export function subject(id) {
  return allSubjects().find((o) => o.id === id);
}
export function subjectName(id) {
  return subject(id)?.name || "归属未知";
}
const rawEvents = seedEvents();
const viewEvents = ["dns-only", "dns-gap", "no-activity"].includes(S.viewCase)
  ? []
  : S.viewCase === "quiet"
    ? [
        {
          ...rawEvents[0],
          id: "quiet-c",
          minute: 25,
          bytes: 800,
          sent: 260,
          received: 540,
          kind: "ended",
          queryId: null,
          transferLog: [{ minute: 25, sent: 260, received: 540 }],
          connectionState: {
            state: "ended",
            captured: "09:41:00",
            openedMinute: 26,
            lastTransferMinute: 25,
            endedMinute: 25,
            rateSent: null,
            rateReceived: null,
            transport: "QUIC 会话",
          },
        },
      ]
    : rawEvents;
export const events = viewEvents.filter(isRecorded).map((e) =>
  platform === "linux"
    ? {
        ...e,
        network:
          e.network === "Wi-Fi"
            ? "Wired"
            : e.network === "Mobile"
              ? "Wi-Fi"
              : e.network,
      }
    : e,
);
export function rule(id, config = S.config) {
  return config.rules.find((r) => r.id === id);
}
export function groupRules(id, cfg = S.config, seen = new Set()) {
  if (seen.has(id)) return [];
  seen.add(id);
  const g = cfg.groups.find((g) => g.id === id);
  return g
    ? [
        ...g.rules,
        ...g.groups.flatMap((x) => groupRules(x, cfg, new Set(seen))),
      ]
    : [];
}
export function bindingsFor(id, cfg = S.config) {
  return cfg.bindings.filter((b) =>
    b.kind === "rule"
      ? b.target === id
      : groupRules(b.target, cfg).includes(id),
  );
}
export function subjectRules(id, cfg = S.config) {
  return cfg.rules
    .filter((r) => bindingsFor(r.id, cfg).some((b) => b.subjects.includes(id)))
    .sort((a, b) => a.priority - b.priority || a.order - b.order);
}
export function quickBlock(id, network = "all", cfg = S.active) {
  return cfg.rules.find(
    (r) => r.quickSubject === id && (r.quickNetwork || "all") === network,
  );
}
export function setBlock(cfg, id, network, blocked) {
  const found = quickBlock(id, network, cfg);
  if (found) {
    cfg.rules = cfg.rules.filter((r) => r.id !== found.id);
    cfg.bindings = cfg.bindings.filter(
      (b) => !(b.kind === "rule" && b.target === found.id),
    );
  }
  if (blocked) {
    const rid = "r" + ++S.counter;
    cfg.rules.push({
      id: rid,
      name:
        subjectName(id) +
        (network === "all" ? " · 暂停联网" : " · 限制" + network),
      action: "drop",
      priority: 0,
      order: 0,
      source: "快捷控制",
      quickSubject: id,
      channels: ["dns", "connection"],
      quickNetwork: network,
      conditions: {
        type: "and",
        children:
          network === "all"
            ? []
            : [{ type: "leaf", field: "network", value: network }],
      },
    });
    cfg.bindings.push({
      id: "b" + ++S.counter,
      kind: "rule",
      target: rid,
      subjects: [id],
      mode: "enforce",
    });
  }
}
export const protocols = [
  "DNS",
  "HTTP",
  "TLS",
  "QUIC",
  "SSH",
  "mDNS",
  "SMTP",
  "FTP control",
  "FTP data",
  "FTPS",
  "OpenVPN",
  "WireGuard",
  "SOCKS4",
  "SOCKS5",
  "RDP",
  "STUN",
  "RTP",
  "RTCP",
  "SIP",
  "DTLS",
];
export const fields = {
  destination: "目的地址 / CIDR",
  source: "源地址 / CIDR",
  destination_port: "目的端口",
  source_port: "源端口",
  protocol: "IP 协议",
  family: "IP 版本",
  direction: "设备方向",
  network: "网络类型",
  interface: "网络接口",
  ct: "连接状态",
  flow_direction: "流方向",
  l7: "应用协议",
  domain_list: "域名列表",
  sni_absent: "确认无 SNI",
};
export const choices = {
  protocol: ["TCP", "UDP", "ICMP", "ICMPv6"],
  family: ["IPv4", "IPv6"],
  direction: ["输出", "输入"],
  network:
    platform === "linux"
      ? ["Wired", "Wi-Fi", "VPN"]
      : ["Wi-Fi", "Mobile", "VPN"],
  ct: ["NEW", "ESTABLISHED", "INVALID"],
  flow_direction: ["ORIG", "REPLY"],
  l7: protocols,
  sni_absent: ["是"],
};
export function label(field, value) {
  return (
    {
      network: { Mobile: "移动网络", Wired: "有线网络" },
      ct: { NEW: "新建连接", ESTABLISHED: "已建立连接", INVALID: "无效连接" },
      flow_direction: { ORIG: "发起方向", REPLY: "响应方向" },
    }[field]?.[value] || value
  );
}
export function conditionText(n, cfg = S.config) {
  if (
    n.type === "leaf" &&
    ["destination", "source"].includes(n.field) &&
    ["0.0.0.0/0", "::/0"].includes(n.value)
  )
    return `${n.field === "destination" ? "目的" : "源"}地址为所有 ${n.value === "::/0" ? "IPv6" : "IPv4"} 地址（${n.value}）`;
  if (n.type === "leaf")
    return (
      fields[n.field] +
      "为" +
      (n.field === "domain_list"
        ? cfg.lists.find((l) => l.id === n.value)?.name || "未选择"
        : label(n.field, n.value))
    );
  if (!n.children.length) return "全部访问";
  return (
    (n.type === "not" ? "不满足 " : "") +
    "（" +
    n.children
      .map((child) => conditionText(child, cfg))
      .join(n.type === "or" ? " 或 " : " 且 ") +
    "）"
  );
}
export function validDomain(x) {
  return (
    typeof x === "string" &&
    x.length < 254 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(x) &&
    x.includes(".") &&
    !x.includes("..")
  );
}
export function validate(cfg) {
  if (!cfg || typeof cfg !== "object")
    throw Error("配置缺少 configuration 内容，请检查文件后重试。");
  const at = (message, section, id) =>
    Object.assign(new Error(message), { section, itemId: id });
  for (const name of ["rules", "groups", "bindings", "lists"]) {
    if (!Array.isArray(cfg[name])) throw Error("配置缺少 " + name + " 列表。");
    const ids = cfg[name].map((x) => x.id);
    if (
      ids.some((x) => typeof x !== "string" || !x) ||
      new Set(ids).size !== ids.length
    )
      throw Error("配置中有重复或缺失的身份。");
  }
  function cond(n, depth = 0) {
    if (!n || typeof n !== "object") throw Error("条件格式不完整。");
    if (depth > 6) throw Error("条件分组最多嵌套 6 层。");
    if (n.type === "leaf") {
      if (!fields[n.field] || !String(n.value || "").trim())
        throw Error("请补全每个条件。");
      if (n.field === "domain_list" && !cfg.lists.some((x) => x.id === n.value))
        throw Error("请选择存在的域名列表。");
      if (
        n.field.includes("port") &&
        !/^(\d{1,5})(?:[-–](\d{1,5}))?$/.test(n.value)
      )
        throw Error("端口填写数字或范围，例如 443、8000-8080。");
      if (
        n.field.includes("port") &&
        n.value.split(/[-–]/).some((x) => Number(x) > 65535)
      )
        throw Error("端口不能大于 65535。");
    } else {
      if (!["and", "or", "not"].includes(n.type) || !Array.isArray(n.children))
        throw Error("条件格式不完整。");
      if (n.type === "not" && n.children.length !== 1)
        throw Error("「不满足」内需要恰好一个条件或条件组。");
      n.children.forEach((x) => cond(x, depth + 1));
    }
  }
  cfg.rules.forEach((r, index) => {
    try {
      if (!r.name?.trim()) throw Error("给这条规则起个名字。");
      if (!["allow", "drop"].includes(r.action))
        throw Error("请选择允许或阻止。");
      if (
        !Number.isInteger(+r.priority) ||
        +r.priority < 0 ||
        !Number.isInteger(+r.order) ||
        +r.order < 0
      )
        throw Error("优先级和顺序应为非负整数。");
      cond(r.conditions);
    } catch (error) {
      throw at(
        `规则「${r.name || r.id}」（rules[${index}]）：${error.message}`,
        "rules",
        r.id,
      );
    }
  });
  function visit(id, path = []) {
    if (path.includes(id)) throw Error("规则组不能相互包含。请移除循环引用。");
    if (path.length > 8) throw Error("规则组嵌套过深。");
    const g = cfg.groups.find((x) => x.id === id);
    if (!g) throw Error("引用的规则组不存在。");
    if (!g.name?.trim()) throw Error("请填写规则组名称。");
    const missing = g.rules.find((x) => !cfg.rules.some((r) => r.id === x));
    if (missing)
      throw at(
        `规则组「${g.name}」引用的规则 ${missing} 不存在。恢复该规则，或从组中移除这项引用。`,
        "groups",
        g.id,
      );
    g.groups.forEach((x) => visit(x, [...path, id]));
  }
  cfg.groups.forEach((g) => visit(g.id));
  const modes = new Map();
  cfg.bindings.forEach((b, index) => {
    if (!b.subjects?.length || b.subjects.some((id) => !subject(id)))
      throw Error("请至少选择一个有效控制对象。");
    if (!["enforce", "observe"].includes(b.mode)) throw Error("执行方式无效。");
    if (!["rule", "group"].includes(b.kind)) throw Error("分配类型无效。");
    if (
      !(b.kind === "rule" ? cfg.rules : cfg.groups).some(
        (x) => x.id === b.target,
      )
    )
      throw at(
        `分配 ${b.id}（bindings[${index}]）引用的${b.kind === "rule" ? "规则" : "规则组"} ${b.target} 不存在。恢复缺失内容，或修改这项分配的 target。`,
        "bindings",
        b.id,
      );
    (b.kind === "rule" ? [b.target] : groupRules(b.target, cfg)).forEach((r) =>
      b.subjects.forEach((s) => {
        const k = r + ":" + s;
        if (modes.has(k) && modes.get(k) !== b.mode)
          throw Error(
            "同一对象上的共享规则存在执行与观察冲突。请调整重复分配。",
          );
        modes.set(k, b.mode);
      }),
    );
  });
  cfg.lists.forEach((l) => {
    try {
      if (!l.name?.trim() || !Array.isArray(l.entries))
        throw Error("请填写列表名称与条目。");
      if (
        l.entries.some(
          (e) =>
            !validDomain(e.name) || !["exact", "descendants"].includes(e.mode),
        )
      )
        throw Error("域名填写名称本身，不含网址、路径或通配符。");
      for (const [key, label] of [
        ["localAdditions", "本地补充"],
        ["localExclusions", "本地排除"],
      ]) {
        if (
          l[key] &&
          (!Array.isArray(l[key]) ||
            l[key].some(
              (e) =>
                !validDomain(e.name) ||
                !["exact", "descendants"].includes(e.mode),
            ))
        )
          throw Error(`${label}需要填写有效域名与匹配范围。`);
      }
      if (l.subscription) {
        let address;
        try {
          address = new URL(l.subscription.url);
        } catch {
          throw Error("请填写完整的订阅文件地址。");
        }
        if (!["http:", "https:"].includes(address.protocol))
          throw Error("订阅地址需要以 http:// 或 https:// 开头。");
        if (
          l.subscription.sourceEntries &&
          (!Array.isArray(l.subscription.sourceEntries) ||
            l.subscription.sourceEntries.some(
              (e) =>
                !validDomain(e.name) ||
                !["exact", "descendants"].includes(e.mode),
            ))
        )
          throw Error("订阅来源包含无效条目。");
        if (
          l.subscription.updateMode &&
          !["review", "automatic"].includes(l.subscription.updateMode)
        )
          throw Error("请选择先审阅或自动采用更新。");
        if (
          l.subscription.intervalHours &&
          ![6, 12, 24, 48].includes(l.subscription.intervalHours)
        )
          throw Error("请选择 6、12、24 或 48 小时的检查频率。");
        if (
          JSON.stringify(listEntries(l).map(entryKey).sort()) !==
          JSON.stringify(l.entries.map(entryKey).sort())
        )
          throw Error(
            "匹配条目应与订阅来源及本地补充一致，请检查 entries、subscription.sourceEntries 和 localAdditions。",
          );
      }
    } catch (error) {
      throw at(`列表「${l.name || l.id}」：${error.message}`, "lists", l.id);
    }
  });
  return true;
}
export const delay = (ms) => new Promise((r) => setTimeout(r, ms));
export async function commit(
  cfg,
  { returnTo = "rules.html", message = "修改已生效" } = {},
) {
  validate(cfg);
  if (!S.running && S.scenario !== "startup")
    throw Error("防火墙已暂停。请先恢复运行，本次输入会保留。");
  await delay(480);
  if (S.scenario === "save-error")
    throw Error("保存失败，输入已保留。之前的配置仍然有效。");
  if (S.scenario === "conflict")
    throw Error("配置在编辑期间已更新。输入已保留，请读取最新版本后重试。");
  S.config = clone(cfg);
  S.savedVersion++;
  const applied = S.scenario !== "unapplied";
  if (applied) {
    S.active = clone(cfg);
    S.activeVersion = S.savedVersion;
  }
  const repaired = S.scenario === "startup";
  if (repaired) {
    S.scenario = "normal";
    S.running = false;
    S.awaitingStart = true;
  }
  S.result = { applied, repaired, message, returnTo };
  persist();
  return S.result;
}
export function newDraft({
  id,
  fromEvent,
  fromList,
  fromProtocol,
  objectId,
} = {}) {
  let r = id ? clone(rule(id)) : null;
  if (!r)
    r = {
      id: "r" + ++S.counter,
      name: "",
      action: "drop",
      priority: 10,
      order: S.config.rules.length,
      source: "手动创建",
      conditions: {
        type: "and",
        children: [{ type: "leaf", field: "destination", value: "" }],
      },
    };
  const direct = S.config.bindings.filter(
    (b) => b.kind === "rule" && b.target === id,
  );
  r.subjects = direct.flatMap((b) => b.subjects);
  r.mode = direct[0]?.mode || "enforce";
  if (objectId) r.subjects = [objectId];
  if (fromList) {
    r.name = "阻止 " + S.config.lists.find((l) => l.id === fromList)?.name;
    r.conditions = {
      type: "and",
      children: [{ type: "leaf", field: "domain_list", value: fromList }],
    };
  }
  if (fromProtocol) {
    r.name = "控制 " + fromProtocol + " 访问";
    r.conditions = {
      type: "and",
      children: [{ type: "leaf", field: "l7", value: fromProtocol }],
    };
  }
  if (fromEvent) {
    const e = events.find((x) => x.id === fromEvent);
    r.name = "控制 " + e.target;
    r.subjects = e.subject ? [e.subject] : [];
    r.source = "来自访问记录";
    r.conditions = {
      type: "and",
      children: [
        {
          type: "leaf",
          field: "destination",
          value: e.ip + (e.ip.includes(":") ? "/128" : "/32"),
        },
        { type: "leaf", field: "protocol", value: e.protocol },
        { type: "leaf", field: "destination_port", value: String(e.port) },
      ],
    };
    r.originEvent = e.id;
  }
  S.draft = r;
  persist();
  return r;
}
export function draftConfig() {
  const d = clone(S.draft),
    subjects = d.subjects,
    mode = d.mode;
  delete d.subjects;
  delete d.mode;
  const next = clone(S.config);
  const i = next.rules.findIndex((r) => r.id === d.id);
  if (i < 0) next.rules.push(d);
  else next.rules[i] = d;
  next.bindings = next.bindings.filter(
    (b) => !(b.kind === "rule" && b.target === d.id),
  );
  if (subjects.length)
    next.bindings.push({
      id: "b" + ++S.counter,
      kind: "rule",
      target: d.id,
      subjects,
      mode,
    });
  return next;
}
export function filteredEvents(filters = S.filters) {
  if (S.historyCleared) return [];
  return events.filter(
    (e) =>
      (filters.subject === "all" || e.subject === filters.subject) &&
      (filters.result === "all" || e.result === filters.result) &&
      (filters.kind === "all" || e.kind === filters.kind) &&
      e.minute <= +filters.range &&
      (!S.timeSlice ||
        (e.minute >= S.timeSlice[0] && e.minute < S.timeSlice[1])) &&
      (!filters.query ||
        (
          e.target +
          " " +
          e.ip +
          " " +
          subjectName(e.subject) +
          " " +
          e.labels.join(" ")
        )
          .toLowerCase()
          .includes(filters.query.toLowerCase())),
  );
}
export function bytes(v) {
  return v >= 1048576
    ? (v / 1048576).toFixed(1) + " MB"
    : v >= 1024
      ? (v / 1024).toFixed(v > 10240 ? 0 : 1) + " KB"
      : v + " B";
}
persist();
