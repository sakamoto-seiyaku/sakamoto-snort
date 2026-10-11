/* UI fixtures, never production data. */
export const subjects = {
  android: [
    {
      id: "s1",
      name: "Firefox",
      sub: "个人 · 浏览器",
      uid: 10142,
      color: "#bc7951",
      letter: "F",
    },
    {
      id: "s2",
      name: "Signal",
      sub: "个人 · 通讯",
      uid: 10186,
      color: "#5477a1",
      letter: "S",
    },
    {
      id: "s3",
      name: "音乐",
      sub: "个人 · 媒体",
      uid: 10204,
      color: "#96719b",
      letter: "♪",
    },
    {
      id: "s4",
      name: "天气",
      sub: "个人 · 生活",
      uid: 10238,
      color: "#7e9b84",
      letter: "☀",
    },
    {
      id: "s5",
      name: "文件",
      sub: "工作资料 · 工具",
      uid: 1010188,
      color: "#93845b",
      letter: "▱",
    },
  ],
  linux: [
    {
      id: "s1",
      name: "Firefox",
      sub: "本机应用",
      uid: 1000,
      color: "#bc7951",
      letter: "F",
    },
    {
      id: "s2",
      name: "Signal",
      sub: "本机应用",
      uid: 1000,
      color: "#5477a1",
      letter: "S",
    },
    {
      id: "s3",
      name: "音乐",
      sub: "本机应用",
      uid: 1000,
      color: "#96719b",
      letter: "♪",
    },
    {
      id: "s4",
      name: "天气",
      sub: "本机应用",
      uid: 1000,
      color: "#7e9b84",
      letter: "☀",
    },
    {
      id: "s5",
      name: "文件",
      sub: "本机应用",
      uid: 1000,
      color: "#93845b",
      letter: "▱",
    },
  ],
};
const leaf = (field, value) => ({ type: "leaf", field, value });
const group = (...children) => ({ type: "and", children });
function baseConfig() {
  return {
    rules: [
      {
        id: "r1",
        name: "阻止统计域名",
        action: "drop",
        priority: 10,
        order: 0,
        source: "手动创建",
        conditions: group(leaf("domain_list", "d1")),
      },
      {
        id: "r2",
        name: "允许局域网发现",
        action: "allow",
        priority: 20,
        order: 1,
        source: "手动创建",
        conditions: group(
          leaf("destination", "192.168.0.0/16"),
          leaf("protocol", "UDP"),
        ),
      },
      {
        id: "r3",
        name: "允许已建立连接的响应",
        action: "allow",
        priority: 30,
        order: 2,
        source: "手动创建",
        conditions: group(
          leaf("ct", "ESTABLISHED"),
          leaf("flow_direction", "REPLY"),
        ),
      },
      {
        id: "r4",
        name: "观察远程访问",
        action: "drop",
        priority: 40,
        order: 3,
        source: "导入示例",
        conditions: group(leaf("l7", "SSH")),
      },
    ],
    groups: [
      { id: "g1", name: "日常联网", rules: ["r1", "r2", "r3"], groups: [] },
    ],
    bindings: [
      {
        id: "b1",
        kind: "group",
        target: "g1",
        subjects: ["s1", "s2"],
        mode: "enforce",
      },
      {
        id: "b2",
        kind: "rule",
        target: "r4",
        subjects: ["s1"],
        mode: "observe",
      },
    ],
    lists: [
      {
        id: "d1",
        name: "统计与测量",
        source: "本地维护",
        entries: [
          { mode: "descendants", name: "metrics.example.net" },
          { mode: "exact", name: "events.example.org" },
        ],
      },
      {
        id: "d2",
        name: "工作服务",
        source: "手动维护",
        entries: [{ mode: "descendants", name: "work.example.com" }],
      },
    ],
  };
}
function earlierEvents() {
  return [
    {
      id: "e1",
      subject: "s1",
      target: "metrics.example.net",
      ip: "203.0.113.18",
      port: 443,
      protocol: "TCP",
      labels: ["TLS"],
      network: "Wi-Fi",
      result: "drop",
      rule: "r1",
      ruleName: "阻止统计域名",
      bytes: 1240,
      packets: 3,
      time: "刚刚",
      minute: 1,
      kind: "blocked",
      direction: "输出",
      country: "荷兰",
      region: "ams",
    },
    {
      id: "e2",
      subject: "s2",
      target: "chat.example.org",
      ip: "198.51.100.42",
      port: 443,
      protocol: "UDP",
      labels: ["QUIC"],
      network: "Wi-Fi",
      result: "allow",
      rule: null,
      ruleName: null,
      bytes: 46200,
      packets: 39,
      time: "12 秒前",
      minute: 3,
      kind: "live",
      direction: "输出",
      country: "日本",
      region: "tokyo",
    },
    {
      id: "e3",
      subject: "s1",
      target: "docs.example.com",
      ip: "192.0.2.70",
      port: 443,
      protocol: "TCP",
      labels: ["TLS", "HTTP"],
      network: "Wi-Fi",
      result: "allow",
      rule: null,
      ruleName: null,
      bytes: 182400,
      packets: 154,
      time: "28 秒前",
      minute: 7,
      kind: "live",
      direction: "输出",
      country: "美国",
      region: "sf",
    },
    {
      id: "e4",
      subject: "s1",
      target: "192.168.1.42",
      ip: "192.168.1.42",
      port: 5353,
      protocol: "UDP",
      labels: ["mDNS"],
      network: "Wi-Fi",
      result: "allow",
      rule: "r2",
      ruleName: "允许局域网发现",
      bytes: 2460,
      packets: 8,
      time: "1 分钟前",
      minute: 10,
      kind: "ended",
      direction: "输出",
      country: "本地网络",
      region: "local",
    },
    {
      id: "e5",
      subject: "s3",
      target: "media.example.net",
      ip: "198.51.100.88",
      port: 443,
      protocol: "UDP",
      labels: ["QUIC"],
      network: "Mobile",
      result: "allow",
      rule: null,
      ruleName: null,
      bytes: 586300,
      packets: 459,
      time: "3 分钟前",
      minute: 22,
      kind: "ended",
      direction: "输出",
      country: "日本",
      region: "tokyo",
    },
    {
      id: "e6",
      subject: "s1",
      target: "192.0.2.22",
      ip: "192.0.2.22",
      port: 22,
      protocol: "TCP",
      labels: ["SSH"],
      network: "Wi-Fi",
      result: "observe",
      rule: "r4",
      ruleName: "观察远程访问",
      bytes: 8360,
      packets: 21,
      time: "5 分钟前",
      minute: 38,
      kind: "live",
      direction: "输出",
      country: "位置未知",
      region: "unknown",
    },
    {
      id: "e7",
      subject: null,
      target: "203.0.113.61",
      ip: "203.0.113.61",
      port: 123,
      protocol: "UDP",
      labels: [],
      network: "未知",
      result: "allow",
      rule: null,
      ruleName: null,
      bytes: 152,
      packets: 2,
      time: "8 分钟前",
      minute: 58,
      kind: "ended",
      direction: "输入",
      country: "位置未知",
      region: "unknown",
    },
  ];
}

export function seedConfig() {
  const c = baseConfig();
  c.rules.forEach((r) => (r.channels = ["connection"]));
  c.rules.push({
    id: "r5",
    name: "拦截跟踪域名查询",
    action: "drop",
    channels: ["dns"],
    priority: 10,
    order: 5,
    source: "我的隐私设置",
    conditions: {
      type: "and",
      children: [{ type: "leaf", field: "domain_list", value: "d1" }],
    },
  });
  c.bindings.push({
    id: "b5",
    kind: "rule",
    target: "r5",
    subjects: ["s4"],
    mode: "enforce",
  });
  c.lists[0].subscription = {
    url: "https://lists.example.org/privacy.txt",
    automatic: true,
    lastUpdate: "今天 08:30",
    status: "current",
    version: "2026.09.29.1",
    intervalHours: 24,
    dataUrl: "https://lists.example.org/privacy.txt",
    format: "native",
    dataFormat: "native",
    updateMode: "review",
    nextCheck: "明天 08:30",
    sourceEntries: c.lists[0].entries.map((e) => ({ ...e })),
  };
  c.lists[0].sourceKind = "subscription";
  c.lists[0].localAdditions = [];
  c.lists[0].localExclusions = [];
  c.lists[0].name = "跟踪域名";
  c.lists[0].source = "隐私名单订阅";
  return c;
}
export function seedSubscriptionUpdate() {
  return {
    version: "2026.09.29.2",
    checkedAt: "今天 09:41",
    sourceEntries: [
      { mode: "descendants", name: "metrics.example.net" },
      { mode: "exact", name: "cdn-metrics.example.org" },
    ],
  };
}

export function seedEvents() {
  const names = {
    s1: ["docs.example.com", "assets.example.com", "metrics.example.net"],
    s2: ["chat.example.org", "cdn.example.org"],
    s3: ["media.example.net", "artwork.example.net"],
    s4: ["api.weather.example", "maps.weather.example"],
    s5: ["files.example.org", "sync.example.org"],
  };
  const events = [];
  Object.entries(names).forEach(([subject, targets], appIndex) => {
    for (let i = 0; i < 10; i++) {
      const minute = [
          [3, 6, 24, 37, 75, 142, 248, 320, 452, 540],
          [5, 7, 19, 40, 130, 185, 240, 330, 445, 500],
          [7, 14, 28, 32, 45, 61, 88, 110, 135, 180],
          [3, 18, 65, 105, 145, 202, 285, 369, 461, 539],
          [11, 30, 90, 125, 150, 240, 350, 440, 470, 550],
        ][appIndex][i],
        target = targets[i % targets.length],
        blocked = subject === "s1" && target === "metrics.example.net";
      events.push({
        id: subject + "-c" + i,
        subject,
        target,
        ip: "192.0.2." + (20 + appIndex * 20 + i),
        port: 443,
        protocol: i % 3 === 0 ? "UDP" : "TCP",
        labels: [i % 3 === 0 ? "QUIC" : "TLS"],
        network: i % 5 === 0 ? "Mobile" : "Wi-Fi",
        result: blocked ? "drop" : "allow",
        rule: blocked ? "r1" : null,
        ruleName: blocked ? "阻止统计域名" : null,
        bytes: blocked
          ? 0
          : Math.round(
              [320000, 32000, 1800000, 7200, 140000][appIndex] *
                (1 + (i % 4) * 0.7),
            ),
        packets: 24 + i * 11,
        time: minute + " 分钟前",
        minute,
        kind: blocked ? "blocked" : i < 2 ? "live" : "ended",
        direction: "输出",
        country: ["美国", "日本", "日本", "日本", "德国"][appIndex],
        region: ["sf", "tokyo", "tokyo", "tokyo", "ams"][appIndex],
        queryId: subject + "-q" + i,
        ageSeconds: 42 + i * 17,
      });
    }
  });
  const upload = events.find((e) => e.id === "s4-c1");
  upload.bytes = 1400000;
  events.forEach((e) => {
    const ratios = { s1: 0.18, s2: 0.35, s3: 0.025, s4: 0.94, s5: 0.9 };
    e.sent = Math.round(e.bytes * ratios[e.subject]);
    e.received = e.bytes - e.sent;
  });
  events.push({
    ...events[0],
    id: "unattributed-c",
    subject: "unknown",
    minute: 17.5,
    target: "192.0.2.240",
    ip: "192.0.2.240",
    bytes: 100000,
    sent: 94000,
    received: 6000,
    queryId: null,
    kind: "ended",
    region: "unknown",
    country: "位置未知",
  });
  // Explicit, frozen observation samples for the connection experience.
  // Zero rates are observations, not an inference from lifetime byte totals.
  events.forEach((e) => {
    const i = Number(e.id.match(/-c(\d+)$/)?.[1] ?? 9);
    const rates = {
      s1: [640, 16000],
      s2: [180, 1050],
      s3: [640, 112000],
      s4: [180, 12],
      s5: [8500, 120],
    };
    const failed = e.id === "s5-c3";
    if (failed) {
      e.kind = "failed";
      e.bytes = 0;
      e.sent = 0;
      e.received = 0;
    }
    const state =
      e.result === "drop"
        ? "blocked"
        : failed
          ? "failed"
          : e.kind === "live"
            ? i === 0
              ? "transferring"
              : "idle"
            : "ended";
    const opened =
      e.result === "drop"
        ? e.minute
        : failed
          ? e.minute + 0.25
          : e.minute + (i < 2 ? 12 : 3);
    e.connectionState = {
      state,
      captured: "09:41:00",
      openedMinute: opened,
      startEvidence: ["blocked", "failed"].includes(state)
        ? "attempt"
        : e.protocol === "UDP"
          ? "observed"
          : "established",
      lastTransferMinute: ["blocked", "failed"].includes(state)
        ? null
        : state === "transferring"
          ? 0.04
          : e.minute,
      endedMinute: state === "ended" ? e.minute : null,
      rateSent:
        state === "transferring"
          ? (rates[e.subject]?.[0] ?? 0)
          : state === "idle"
            ? 0
            : null,
      rateReceived:
        state === "transferring"
          ? (rates[e.subject]?.[1] ?? 0)
          : state === "idle"
            ? 0
            : null,
      rateWindowSeconds: 10,
      transport: e.protocol === "UDP" ? "QUIC 会话" : "TCP 连接",
      failure: failed ? "连接建立超时" : null,
      localAddress: "10.0.0.18",
      localPort:
        48000 + i * 17 + ["s1", "s2", "s3", "s4", "s5"].indexOf(e.subject),
    };
    const recentSent =
      state === "transferring" ? e.connectionState.rateSent * 10 : 0;
    const recentReceived =
      state === "transferring" ? e.connectionState.rateReceived * 10 : 0;
    e.transferLog = [
      {
        minute: e.minute,
        sent: e.sent - recentSent,
        received: e.received - recentReceived,
      },
      ...(state === "transferring"
        ? [{ minute: 0.04, sent: recentSent, received: recentReceived }]
        : []),
    ];
  });
  return events;
}
export function seedQueries() {
  const queries = seedEvents()
    .filter((e) => e.queryId)
    .map((e, i) => ({
      id: e.queryId,
      subject: e.subject,
      target: e.target,
      type: "A",
      result: "allow",
      outcome: "resolved",
      rule: null,
      ruleName: null,
      list: null,
      answers: [e.ip],
      network: e.network,
      minute: (e.connectionState?.openedMinute ?? e.minute) + 0.1,
      duration: 8 + ((i * 7) % 42),
      connection: e.id,
    }));
  for (let i = 0; i < 20; i++)
    queries.push({
      id: "s4-blocked-" + i,
      subject: "s4",
      target: "metrics.example.net",
      type: "A",
      result: "drop",
      outcome: "blocked",
      rule: "r5",
      ruleName: "拦截跟踪域名查询",
      list: "d1",
      answers: [],
      network: "Wi-Fi",
      minute: 1 + i * 0.95,
      duration: 1,
      connection: null,
    });
  return queries;
}
