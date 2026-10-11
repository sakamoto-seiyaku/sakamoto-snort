import { subjects, seedConfig, seedEvents } from "./seed.js";
export const params = new URLSearchParams(location.search);
export const platform =
  params.get("platform") === "linux" ? "linux" : "android";
export const scope = params.get("scope") || "walkthrough";
const key = "sakamoto-design-complete-v3:" + platform + ":" + scope;
export const clone = (x) => JSON.parse(JSON.stringify(x));
function initial() {
  return {
    config: seedConfig(),
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
export const events = seedEvents().map((e) =>
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
export function conditionText(n) {
  if (n.type === "leaf")
    return (
      fields[n.field] +
      "为" +
      (n.field === "domain_list"
        ? S.config.lists.find((l) => l.id === n.value)?.name || "未选择"
        : label(n.field, n.value))
    );
  if (!n.children.length) return "全部访问";
  return (
    (n.type === "not" ? "不满足 " : "") +
    "（" +
    n.children.map(conditionText).join(n.type === "or" ? " 或 " : " 且 ") +
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
  cfg.rules.forEach((r) => {
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
  });
  function visit(id, path = []) {
    if (path.includes(id)) throw Error("规则组不能相互包含。请移除循环引用。");
    if (path.length > 8) throw Error("规则组嵌套过深。");
    const g = cfg.groups.find((x) => x.id === id);
    if (!g) throw Error("引用的规则组不存在。");
    if (!g.name?.trim()) throw Error("请填写规则组名称。");
    if (g.rules.some((x) => !cfg.rules.some((r) => r.id === x)))
      throw Error("规则组中有不存在的规则。");
    g.groups.forEach((x) => visit(x, [...path, id]));
  }
  cfg.groups.forEach((g) => visit(g.id));
  const modes = new Map();
  cfg.bindings.forEach((b) => {
    if (!b.subjects?.length || b.subjects.some((id) => !subject(id)))
      throw Error("请至少选择一个有效控制对象。");
    if (!["enforce", "observe"].includes(b.mode)) throw Error("执行方式无效。");
    if (!["rule", "group"].includes(b.kind)) throw Error("分配类型无效。");
    if (
      !(b.kind === "rule" ? cfg.rules : cfg.groups).some(
        (x) => x.id === b.target,
      )
    )
      throw Error("分配引用的内容不存在。");
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
    if (!l.name?.trim() || !Array.isArray(l.entries))
      throw Error("请填写列表名称与条目。");
    if (
      l.entries.some(
        (e) =>
          !validDomain(e.name) || !["exact", "descendants"].includes(e.mode),
      )
    )
      throw Error("域名填写名称本身，不含网址、路径或通配符。");
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
