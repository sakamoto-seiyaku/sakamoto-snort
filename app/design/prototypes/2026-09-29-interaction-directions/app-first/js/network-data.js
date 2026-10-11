import {
  S,
  platform,
  events,
  allSubjects,
  subjectRules,
  bindingsFor,
  conditionText,
  persist,
  clone,
  commit,
  isRecorded,
  observationGaps,
} from "./model.js";
import { seedQueries } from "./seed.js";
import { listMatches } from "./domain-lists.js";
export const cloneData = clone;
export function connections() {
  return S.historyCleared ? [] : [...(S.addedConnections || []), ...events];
}
export function queries() {
  return S.historyCleared
    ? []
    : [
        ...(S.addedQueries || []),
        ...seedQueries()
          .filter(
            (q) =>
              isRecorded(q) &&
              (S.viewCase === "quiet" || S.viewCase === "no-activity"
                ? false
                : ["dns-only", "dns-gap"].includes(S.viewCase)
                  ? q.result === "drop"
                  : true),
          )
          .map((q) =>
            platform === "linux"
              ? { ...q, network: q.network === "Mobile" ? "Wi-Fi" : "Wired" }
              : q,
          ),
      ];
}
export const limit = () =>
  S.period === "recent" ? 30 : S.period === "hour" ? 60 : 581;
export const currentSpan = () => S.timeSlice || [0, limit()];
export const directionBytes = (e, direction) =>
  e[direction] ??
  (direction === "sent"
    ? Math.round(e.bytes * 0.14)
    : e.bytes - Math.round(e.bytes * 0.14));
export function coverageGaps(span = currentSpan()) {
  return observationGaps().filter(([a, b]) => a < span[1] && b > span[0]);
}
export function connectionInSpan(e, span = currentSpan()) {
  const f = e.connectionState;
  if (!f || ["blocked", "failed"].includes(f.state))
    return e.minute >= span[0] && e.minute < span[1];
  return f.openedMinute >= span[0] && (f.endedMinute ?? 0) < span[1];
}
export function transferInSpan(e, span = currentSpan()) {
  const logs = e.transferLog || [
    {
      minute: e.minute,
      sent: directionBytes(e, "sent"),
      received: directionBytes(e, "received"),
    },
  ];
  return logs
    .filter((x) => x.minute >= span[0] && x.minute < span[1] && isRecorded(x))
    .reduce(
      (n, x) => ({ sent: n.sent + x.sent, received: n.received + x.received }),
      { sent: 0, received: 0 },
    );
}
export function inRange(e) {
  const span = currentSpan();
  return e.kind
    ? connectionInSpan(e, span)
    : e.minute >= span[0] && e.minute < span[1];
}
export function activity(app = "all", type = "all") {
  return [
    ...(type === "dns"
      ? []
      : connections().map((e) => ({ ...e, recordType: "connection" }))),
    ...(type === "connection"
      ? []
      : queries().map((e) => ({ ...e, recordType: "dns" }))),
  ]
    .filter((e) => (app === "all" || e.subject === app) && inRange(e))
    .sort((a, b) => a.minute - b.minute);
}
export function appMetrics(app, span = currentSpan()) {
  const within = (e) => e.minute >= span[0] && e.minute < span[1];
  const c = connections()
      .filter(
        (e) =>
          (app === "all" || e.subject === app) && connectionInSpan(e, span),
      )
      .map((e) => {
        const t = transferInSpan(e, span);
        return {
          ...e,
          lifetime: {
            sent: directionBytes(e, "sent"),
            received: directionBytes(e, "received"),
          },
          sent: t.sent,
          received: t.received,
          bytes: t.sent + t.received,
        };
      }),
    q = queries().filter(
      (e) => (app === "all" || e.subject === app) && within(e),
    );
  return {
    connections: c.length,
    queries: q.length,
    bytes: c.reduce((n, e) => n + e.bytes, 0),
    received: c.reduce((n, e) => n + directionBytes(e, "received"), 0),
    sent: c.reduce((n, e) => n + directionBytes(e, "sent"), 0),
    blockedConnections: c.filter((e) => e.result === "drop").length,
    blockedQueries: q.filter((e) => e.result === "drop").length,
    latest: Math.min(...c.map((e) => e.minute), ...q.map((e) => e.minute)),
    c,
    q,
  };
}
export function record(id) {
  return (
    activity("all", "all").find((e) => e.id === id) ||
    connections()
      .map((e) => ({ ...e, recordType: "connection" }))
      .find((e) => e.id === id) ||
    queries()
      .map((e) => ({ ...e, recordType: "dns" }))
      .find((e) => e.id === id)
  );
}
export function clock(minute) {
  const n = Math.floor(9 * 60 + 41 - minute);
  return (
    String(Math.floor(n / 60)).padStart(2, "0") +
    ":" +
    String(((n % 60) + 60) % 60).padStart(2, "0")
  );
}
export function periodText() {
  return S.timeSlice
    ? clock(S.timeSlice[1]) + "–" + clock(S.timeSlice[0])
    : S.period === "recent"
      ? "最近 30 分钟"
      : S.period === "hour"
        ? "最近 1 小时"
        : "今天";
}
function domainMatch(target, id, cfg) {
  const list = cfg.lists.find((l) => l.id === id);
  return listMatches(list, target);
}
function match(n, info, cfg) {
  if (n.type === "leaf") {
    switch (n.field) {
      case "domain_list":
        return domainMatch(info.target, n.value, cfg);
      case "network":
        return n.value === info.network;
      case "l7":
        return info.labels?.includes(n.value) || false;
      case "protocol":
        return info.protocol === n.value;
      case "destination_port":
        return String(info.port) === n.value;
      case "destination":
        return n.value.split("/")[0] === info.ip;
      default:
        return false;
    }
  }
  const bits = n.children.map((c) => match(c, info, cfg));
  return n.type === "and"
    ? bits.every(Boolean)
    : n.type === "or"
      ? bits.some(Boolean)
      : !bits[0];
}
export function evaluate(info, channel) {
  const rules = subjectRules(info.subject, S.active).filter((r) =>
    (r.channels || ["connection"]).includes(channel),
  );
  for (const r of rules) {
    if (match(r.conditions, info, S.active)) {
      const b = bindingsFor(r.id, S.active).find((b) =>
        b.subjects.includes(info.subject),
      );
      return {
        result: b?.mode === "observe" ? "observe" : r.action,
        rule: r.id,
        ruleName: r.name,
      };
    }
  }
  return { result: "allow", rule: null, ruleName: null };
}
export function sampleNewActivity(app, target = "api.weather.example") {
  if (!S.running) return null;
  const number = ++S.counter,
    id = "q-new-" + number,
    base = {
      id,
      subject: app,
      target,
      type: "A",
      network: platform === "linux" ? "Wired" : "Wi-Fi",
      minute: 0,
      duration: 14,
    };
  const result = evaluate(base, "dns");
  const q = {
    ...base,
    ...result,
    sample: true,
    observedAt: Date.now(),
    outcome: result.result === "drop" ? "blocked" : "resolved",
    answers: result.result === "drop" ? [] : ["192.0.2.88"],
    connection: result.result === "drop" ? null : "c-new-" + number,
  };
  S.addedQueries.unshift(q);
  if (q.outcome !== "blocked") {
    const cbase = {
      id: q.connection,
      subject: app,
      target,
      ip: "192.0.2.88",
      port: 443,
      protocol: "TCP",
      labels: ["TLS"],
      network: q.network,
      bytes: 14720,
      sent: 2600,
      received: 12120,
      packets: 14,
      time: "刚刚",
      minute: 0,
      kind: "live",
      direction: "输出",
      country: "日本",
      region: "tokyo",
      queryId: q.id,
      ageSeconds: 1,
    };
    const decision = evaluate(cbase, "connection");
    S.addedConnections.unshift({
      ...cbase,
      ...decision,
      sample: true,
      observedAt: Date.now(),
      kind: decision.result === "drop" ? "blocked" : "live",
      bytes: decision.result === "drop" ? 0 : cbase.bytes,
      sent: decision.result === "drop" ? 0 : cbase.sent,
      received: decision.result === "drop" ? 0 : cbase.received,
    });
  }
  persist();
  return q;
}
export async function saveDecision(
  { app, target, channel, action, descendants = false, ruleId },
  returnTo,
) {
  const cfg = clone(S.config);
  let r = cfg.rules.find((r) => r.id === ruleId);
  if (!r) {
    const id = "r" + ++S.counter,
      listId = "d" + ++S.counter;
    cfg.lists.push({
      id: listId,
      name: target,
      source: "来自应用活动",
      entries: [{ mode: descendants ? "descendants" : "exact", name: target }],
    });
    r = {
      id,
      name:
        (action === "drop" ? "阻止" : "允许") +
        allSubjects().find((a) => a.id === app).name +
        (channel === "dns"
          ? "查询 "
          : channel === "connection"
            ? "连接 "
            : "访问 ") +
        target,
      action,
      channels: channel === "both" ? ["dns", "connection"] : [channel],
      priority: action === "allow" ? 1 : 5,
      order: S.counter,
      source: "应用联网设置",
      conditions: {
        type: "and",
        children: [{ type: "leaf", field: "domain_list", value: listId }],
      },
    };
    cfg.rules.push(r);
    cfg.bindings.push({
      id: "b" + ++S.counter,
      kind: "rule",
      target: r.id,
      subjects: [app],
      mode: "enforce",
    });
  } else {
    r.name =
      (action === "drop" ? "阻止" : "允许") +
      allSubjects().find((a) => a.id === app).name +
      (channel === "dns"
        ? "查询 "
        : channel === "connection"
          ? "连接 "
          : "访问 ") +
      target;
    r.action = action;
    r.channels = channel === "both" ? ["dns", "connection"] : [channel];
    const node = r.conditions.children.find((n) => n.field === "domain_list");
    const list = node && cfg.lists.find((l) => l.id === node.value);
    if (list)
      list.entries = [
        { name: target, mode: descendants ? "descendants" : "exact" },
      ];
  }
  await commit(cfg, { returnTo, message: "联网设置已更新" });
  S.lastDecision = {
    id: r.id,
    app,
    target,
    action,
    channel,
    name: r.name,
    appliedAt: Date.now(),
    savedVersion: S.savedVersion,
    applied: S.savedVersion === S.activeVersion,
  };
  persist();
  return r;
}
