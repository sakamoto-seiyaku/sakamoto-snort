import {
  S,
  params,
  platform,
  clone,
  commit,
  validate,
  persist,
  delay,
  events,
  subjectName,
  bytes,
} from "./model.js";
import { seedConfig } from "./seed.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  here,
  row,
  empty,
  toast,
  dialog,
  saving,
  showError,
  download,
  applyAppearance,
} from "./ui.js";
const configExport = () => ({
  format: "sakamoto-ui-prototype-v1",
  platform,
  sample: true,
  configuration: clone(S.config),
});
const exportConfig = () => {
  download("sakamoto-demo-configuration.json", configExport());
  toast("配置样例已导出");
};
const pair = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
export async function retryApply() {
  await delay(650);
  S.active = clone(S.config);
  S.activeVersion = S.savedVersion;
  S.scenario = "normal";
  persist();
}
export function config() {
  const applied = S.savedVersion === S.activeVersion;
  $("#config-state").innerHTML =
    `<div class="card"><span class="badge ${applied ? "" : "amber"}">${applied ? "配置一致" : "已保存，尚未生效"}</span><h2 style="margin-top:18px">${applied ? "每项修改，已在使用。" : "新修改仍在等待。"}</h2><dl class="detail-pairs gap-top">${pair("已保存配置", "v" + S.savedVersion)}${pair("正在使用", "v" + S.activeVersion)}</dl>${!applied ? `<div class="notice warn">${icon("info")}<p>${S.scenario === "startup" ? "启动时无法编译已保存配置，防火墙尚未运行。修复后需要显式启动。" : "保存已完成，编译未成功。保护继续使用之前的配置。"}</p></div><button class="btn primary full" id="retry-apply">${S.scenario === "startup" ? "打开规则，修复配置" : "重新尝试生效"}</button><a class="text-link" href="${url("rules.html")}">检查已保存的规则</a>` : ""}</div>`;
  $("#config-counts").innerHTML = [
    ["规则", "rules"],
    ["规则组", "groups"],
    ["分配", "bindings"],
    ["域名列表", "lists"],
  ]
    .map(([t, k]) =>
      row(
        t,
        "",
        k === "bindings"
          ? "groups.html"
          : (k === "lists" ? "domains" : k) + ".html",
        "chevron-right",
        String(S.config[k].length),
      ),
    )
    .join("");
  if ($("#retry-apply"))
    $("#retry-apply").onclick = async (e) => {
      if (S.scenario === "startup") {
        go("rules.html");
        return;
      }
      e.currentTarget.disabled = true;
      e.currentTarget.textContent = "正在重新编译…";
      await retryApply();
      config();
      $(".status-strip").innerHTML = "";
      toast("已保存的配置现在已生效");
    };
  const exp = $('a[data-page="config.html?action=export"]');
  exp.href = "#";
  exp.onclick = (e) => {
    e.preventDefault();
    exportConfig();
  };
  if (params.get("action") === "export") exportConfig();
  $("#clear-config").onclick = () =>
    dialog({
      title: "清空当前规则配置？",
      body: "将移除所有规则、规则组、分配和域名列表。没有规则命中时，访问默认允许。历史记录保持不变。",
      confirm: "清空配置",
      danger: true,
      onConfirm: async () => {
        await commit(
          { rules: [], groups: [], bindings: [], lists: [] },
          { returnTo: "config.html", message: "配置已清空" },
        );
        go("config-result.html");
      },
    });
}
export function configImport() {
  if (S.importText) $("#config-json").value = S.importText;
  $("#config-json").oninput = () => {
    S.importText = $("#config-json").value;
    persist();
  };
  $("#config-file").onchange = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 1024 * 1024) {
      showError("请选择小于 1 MB 的配置样例。");
      return;
    }
    const text = await f.text();
    $("#config-json").value = text;
    S.importText = text;
    persist();
    $("#import-file-name").textContent = f.name + " · " + bytes(f.size);
  };
  $("#use-sample-config").onclick = () => {
    const sample = seedConfig();
    sample.rules = sample.rules.slice(0, 3);
    sample.bindings = sample.bindings.filter((b) => b.target !== "r4");
    sample.rules[0].name = "工作环境 · 阻止统计域名";
    $("#config-json").value = JSON.stringify(
      { format: "sakamoto-ui-prototype-v1", platform, configuration: sample },
      null,
      2,
    );
    S.importText = $("#config-json").value;
    persist();
    toast("已载入演示配置，尚未提交");
  };
  $("#review-config-import").onclick = () => {
    try {
      const data = JSON.parse($("#config-json").value);
      if (data.format !== "sakamoto-ui-prototype-v1")
        throw Error("请选择本原型导出的配置。产品配置格式不在此模拟中处理。");
      if (data.platform && data.platform !== platform)
        throw Error("样例配置的平台身份不一致，请导入当前平台的样例。");
      validate(data.configuration);
      S.imported = data.configuration;
      S.importText = $("#config-json").value;
      persist();
      go("config-review.html");
    } catch (e) {
      showError(
        e instanceof SyntaxError
          ? "JSON 格式无法读取。请检查内容后重试。"
          : e.message,
      );
    }
  };
}
export function configReview() {
  const incoming = S.imported || seedConfig();
  $("#config-import-comparison").innerHTML = `<div class="inset-list">${[
    ["规则", "rules"],
    ["规则组", "groups"],
    ["分配", "bindings"],
    ["域名列表", "lists"],
  ]
    .map(
      ([t, k]) =>
        `<div class="list-row"><span class="grow"><span class="title">${t}</span></span><span class="value">${S.config[k].length} → ${incoming[k].length}</span></div>`,
    )
    .join(
      "",
    )}</div><div class="card gap-top"><h3>导入后的规则</h3><p class="help" style="margin-top:12px">${incoming.rules.map((r) => esc(r.name)).join("<br>") || "没有规则"}</p></div>`;
  $("#export-before-import").href = "#";
  $("#export-before-import").onclick = (e) => {
    e.preventDefault();
    exportConfig();
  };
  $("#confirm-import").onclick = (e) =>
    saving(e.currentTarget, async () => {
      await commit(incoming, {
        returnTo: "config.html",
        message: "导入的配置已保存",
      });
      S.imported = null;
      persist();
      go("config-result.html");
    });
}
export function configResult() {
  if (!S.result) {
    $("#save-result").innerHTML = empty(
      "还没有提交修改",
      "从规则或配置管理完成一次保存后，这里会显示保存与生效的结果。",
    );
    $("#finish-save").textContent = "前往规则";
    $("#finish-save").onclick = () => go("rules.html");
    return;
  }
  const r = S.result;
  const repaired = r.repaired;
  $("#save-result").innerHTML =
    `${r.demo ? '<div class="eyebrow">演示 · 保存成功状态</div>' : ""}<div class="result-hero"><span class="result-symbol ${r.applied ? "" : "warn"}">${icon(r.applied ? "check-check" : "circle-alert")}</span><h1>${repaired ? "配置已修复" : r.applied ? "已保存，已生效。" : "已保存，尚未生效。"}</h1><p>${repaired ? "防火墙尚未启动。确认准备好后，再开始运行。" : r.applied ? "新的配置已成为当前使用的配置。历史访问记录保留当时的结果。" : "这次输入没有丢失。当前仍使用旧配置，待处理后可以重新尝试生效。"}</p></div><div class="card"><dl class="detail-pairs">${pair("已保存配置", "v" + S.savedVersion)}${pair("正在使用", "v" + S.activeVersion)}${pair("运行状态", S.running ? "运行中" : "尚未启动")}</dl></div>${!r.applied ? `<button class="btn primary full gap-top" id="result-retry">重新尝试生效</button><a class="btn full gap-top" href="${url("config.html")}">查看配置详情</a>` : ""}${repaired ? `<a class="btn primary full gap-top" href="${url("runtime.html")}">前往启动</a>` : ""}`;
  $("#finish-save").textContent = (r.returnTo || "").startsWith("connection")
    ? "返回原访问记录"
    : "完成，返回";
  $("#finish-save").onclick = () => go(r.returnTo || "rules.html");
  $(".topbar .back").href = url(r.returnTo || "rules.html");
  if ($("#result-retry"))
    $("#result-retry").onclick = async (e) => {
      e.currentTarget.disabled = true;
      e.currentTarget.textContent = "正在使配置生效…";
      await retryApply();
      S.result.applied = true;
      persist();
      configResult();
      $(".status-strip").innerHTML = "";
    };
}
const modeName = (m) =>
  m === "host" ? "Linux 主机" : m === "vpn" ? "VPN" : "Root";
async function startRuntime(button) {
  if (!S.permission) {
    go("permissions.html");
    return;
  }
  if (S.savedVersion !== S.activeVersion || S.scenario === "startup") {
    go("config.html");
    return;
  }
  button.disabled = true;
  button.textContent = "正在准备运行…";
  await delay(450);
  S.running = true;
  S.scenario = "normal";
  S.awaitingStart = false;
  persist();
  go("runtime.html");
}
export function runtime() {
  const stateText = S.running
    ? "正在运行"
    : S.scenario === "permission"
      ? "等待授权"
      : S.scenario === "recovering"
        ? "正在恢复"
        : S.scenario === "intervention"
          ? "需要处理"
          : "已暂停";
  $("#runtime-summary").innerHTML =
    `<span class="tile-icon">${icon(S.running ? "shield-check" : "pause")}</span><h2 class="runtime-large" style="font-size:32px">${stateText}</h2><p class="help">${S.running ? "当前规则正在判断新访问。" : S.awaitingStart ? "配置已修复，请显式启动。" : "当前不执行网络控制，也不记录新访问。"}</p><dl class="detail-pairs gap-top">${pair("实际运行方式", S.running ? modeName(S.mode) : "未运行")}${pair("已选择的方式", modeName(S.preferredMode))}${pair("正在使用配置", "v" + S.activeVersion)}</dl>`;
  $("#runtime-actions").innerHTML = S.running
    ? '<button class="btn full" id="pause-runtime">暂停防火墙</button>'
    : `<button class="btn primary full" id="resume-runtime">${S.scenario === "permission" ? "继续授权" : S.scenario === "startup" ? "先修复配置" : "恢复运行"}</button>`;
  if ($("#pause-runtime"))
    $("#pause-runtime").onclick = () =>
      dialog({
        title: "暂停防火墙？",
        body: "暂停会停止保护和新增记录，已有配置与记录保留。你可以随时恢复。",
        confirm: "暂停",
        onConfirm: async () => {
          await delay(300);
          S.running = false;
          S.scenario = "paused";
          persist();
          go("runtime.html");
        },
      });
  if ($("#resume-runtime"))
    $("#resume-runtime").onclick = (e) => startRuntime(e.currentTarget);
  $("#runtime-background-note").textContent =
    platform === "linux"
      ? "本原型将窗口与本地运行分开。Linux 安装、权限提升和退出后的承载行为仍需正式产品接入。"
      : "关闭界面后，Android 运行服务继续管理连接。暂停会停止保护和新增记录。";
}
export function setup() {
  const opts =
    platform === "linux"
      ? [["host", "Linux 主机", "使用主机运行承载，按系统用户 UID 管理访问。"]]
      : [
          ["root", "Root 模式", "需要超级用户授权，直接管理设备的网络访问。"],
          [
            "vpn",
            "VPN 模式",
            "使用 Android VPN 授权；普通转发覆盖 IPv4/IPv6 TCP、UDP。",
          ],
        ];
  $("#runtime-mode-options").innerHTML = opts
    .map(
      ([v, t, s]) =>
        `<label class="choice"><span class="tile-icon">${icon(v === "vpn" ? "network" : "shield")}</span><span class="grow"><strong>${t}</strong><small>${s}</small></span><input type="radio" name="runtime-mode" value="${v}" ${S.preferredMode === v ? "checked" : ""}></label>`,
    )
    .join("");
  $("#continue-setup").onclick = () => {
    S.preferredMode = $('input[name="runtime-mode"]:checked').value;
    persist();
    go("permissions.html", { setup: 1, from: "setup.html" });
  };
}
function grants() {
  if (!S.grants)
    S.grants = { root: S.permission, vpn: false, host: S.permission };
  return S.grants;
}
export function permissions() {
  const mode = S.preferredMode,
    granted = grants()[mode];
  const title =
    mode === "host"
      ? "本机运行权限"
      : mode === "vpn"
        ? "Android VPN 授权"
        : "Root 超级用户授权";
  $("#permission-list").innerHTML =
    `<button class="list-row" id="grant-runtime"><span class="tile-icon">${icon("key-round")}</span><span class="grow"><span class="title">${title}</span><span class="subtitle">${mode === "root" ? "由 KernelSU 等授权管理器确认" : mode === "vpn" ? "需要你确认系统 VPN 连接请求" : "使用 Linux 主机的权限与运行承载"}</span></span><span class="badge ${granted ? "" : "amber"}">${granted ? "已授权" : "待授权"}</span>${icon("chevron-right")}</button><button class="list-row" id="grant-notification"><span class="tile-icon neutral">${icon("bell")}</span><span class="grow"><span class="title">${platform === "android" ? "运行通知" : "桌面通知"}</span><span class="subtitle">让运行状态与故障处理保持可见</span></span><span class="badge ${S.notificationPermission ? "" : "amber"}">${S.notificationPermission ? "已允许" : "待允许"}</span>${icon("chevron-right")}</button>`;
  $("#permission-details").innerHTML =
    `<p class="note">${mode === "root" ? "卸载重装后，超级用户授权可能需要重新确认。" : mode === "vpn" ? "授权可以取消。尚未授权时，规则和输入仍会保留。" : "这里演示本机授权与启动流程，不实际请求管理员权限。"}</p>`;
  $("#grant-runtime").onclick = () =>
    dialog({
      title: granted ? "运行权限已授予" : title,
      body: granted
        ? "此处可以演示授权被撤销后的状态；不会更改真实系统授权。"
        : "正式产品会打开相应系统授权入口。这里用前端模拟确认或取消后的状态。",
      confirm: granted ? "模拟撤销授权" : "允许本次演示",
      cancel: "稍后再说",
      onConfirm: () => {
        S.grants[mode] = !granted;
        S.permission = !granted;
        persist();
        permissions();
      },
    });
  $("#grant-notification").onclick = () =>
    dialog({
      title: "运行状态通知",
      body: "允许后可以收到运行变化与需要处理的提示。此操作只更新原型中的授权状态。",
      confirm: S.notificationPermission ? "模拟关闭通知权限" : "允许通知",
      onConfirm: () => {
        S.notificationPermission = !S.notificationPermission;
        persist();
        permissions();
      },
    });
  $("#start-with-permissions").onclick = async (e) => {
    if (!grants()[mode]) {
      showError("先完成运行授权，再开始。你的配置仍然保留。");
      return;
    }
    if (S.scenario === "startup" || S.savedVersion !== S.activeVersion) {
      go("config.html");
      return;
    }
    const b = e.currentTarget;
    b.disabled = true;
    b.textContent =
      S.running && S.mode !== mode ? "正在停止旧方式…" : "正在初始化…";
    await delay(400);
    if (S.running && S.mode !== mode) {
      S.running = false;
      persist();
      b.textContent = "旧方式已清理，正在启动…";
      await delay(550);
    }
    S.mode = mode;
    S.permission = true;
    S.running = true;
    S.scenario = "normal";
    persist();
    go("runtime.html");
  };
}
export function recovery() {
  const bad = ["intervention", "recovering"].includes(S.scenario);
  $("#recovery-main").innerHTML =
    `<div class="card"><span class="tile-icon">${icon(bad ? "refresh-cw" : "shield-check")}</span><h2 style="margin-top:20px">${S.scenario === "recovering" ? "正在尝试恢复" : bad ? "恢复需要你的帮助" : "运行没有待处理故障"}</h2><p class="help" style="margin-top:12px">${bad ? "运行承载已停止。配置仍在，当前不继续保护或记录。" : "此处保留运行过程，出现中断时说明影响和可采取的动作。"}</p></div>`;
  $("#recovery-timeline").innerHTML = [
    ["09:40", "状态检查", bad ? "检测到运行承载中断" : "运行与记录状态正常"],
    ["09:40", "保留当前配置", "配置 v" + S.savedVersion + " 仍然保留"],
    [
      "现在",
      S.scenario === "recovering"
        ? "等待有限重试"
        : bad
          ? "自动恢复已停止"
          : "无需操作",
      bad ? "不会无限重启，需要检查条件。" : "防火墙继续判断访问。",
    ],
  ]
    .map(
      ([t, h, p]) =>
        `<div class="timeline-item"><time>${t}</time><h3>${h}</h3><p>${p}</p></div>`,
    )
    .join("");
  $("#recovery-actions").innerHTML = bad
    ? `<button class="btn primary full" id="retry-runtime">${S.scenario === "recovering" ? "立即重试" : "重新检查并启动"}</button><button class="btn full" id="cancel-recovery">停止恢复，保持暂停</button>`
    : `<a class="btn full" href="${url("runtime.html")}">查看运行状态</a>`;
  if ($("#retry-runtime"))
    $("#retry-runtime").onclick = async (e) => {
      const b = e.currentTarget;
      b.disabled = true;
      b.textContent = "正在检查授权与配置…";
      await delay(650);
      if (!S.permission) {
        go("permissions.html");
        return;
      }
      if (S.savedVersion !== S.activeVersion) {
        go("config.html");
        return;
      }
      S.scenario = "normal";
      S.running = true;
      persist();
      go("runtime.html");
    };
  if ($("#cancel-recovery"))
    $("#cancel-recovery").onclick = () => {
      S.scenario = "paused";
      S.running = false;
      persist();
      go("runtime.html");
    };
}
export function network() {
  const linux = platform === "linux";
  if (linux) {
    $(".page-intro p").textContent = "查看主机当前的网络接口与名称服务信息。";
    $(".notice p").textContent =
      "主机网络接口与 DNS 信息分别显示；重新检查会更新本页的网络快照。";
  }
  $("#network-current").innerHTML =
    `<span class="tile-icon">${icon(linux ? "ethernet-port" : "wifi")}</span><h2 style="margin:16px 0 8px">${S.networkOffline ? "当前网络不可用" : linux ? "有线网络已连接" : "Wi-Fi 已连接"}</h2><p class="help">${linux ? "enp3s0 · 192.168.1.20" : "家庭网络 · 192.168.1.38"}</p>`;
  $("#network-interfaces").innerHTML =
    `<div class="list-row"><span class="grow"><span class="title">${linux ? "enp3s0" : "wlan0"}</span><span class="subtitle">当前承载网络 · IPv4 / IPv6</span></span><span class="badge">可用</span></div><div class="list-row"><span class="grow"><span class="title">${linux ? "lo" : "rmnet_data0"}</span><span class="subtitle">${linux ? "本机回环" : "移动网络 · 未作为当前承载"}</span></span><span class="badge gray">${linux ? "本机" : "备用"}</span></div>`;
  $("#dns-state").innerHTML =
    `<span class="badge ${S.dnsRestart ? "amber" : "blue"}">${S.dnsRestart ? "等待重启更新" : "与本次启动一致"}</span><h3 style="margin-top:16px">192.168.1.1</h3><p class="help" style="margin:9px 0 18px">${linux ? "名称服务信息来自当前主机网络样例。" : "当前运行使用启动时绑定的 DNS 信息。"}</p><button class="btn full" id="refresh-network">重新检查网络</button>${S.dnsRestart ? '<button class="btn primary full gap-top" id="restart-dns">重启以更新 DNS</button>' : ""}`;
  $("#refresh-network").onclick = async (e) => {
    e.currentTarget.disabled = true;
    e.currentTarget.textContent = "检查中…";
    await delay(550);
    network();
    toast("网络信息已更新");
  };
  if ($("#restart-dns"))
    $("#restart-dns").onclick = () =>
      dialog({
        title: "重启以更新 DNS？",
        body: "先停止并清理旧运行，再使用当前网络的 DNS 配置启动。期间会短暂中断保护。",
        confirm: "重启",
        onConfirm: async () => {
          S.running = false;
          persist();
          await delay(600);
          S.dnsRestart = false;
          S.running = true;
          persist();
          network();
          toast("DNS 已更新，防火墙已恢复");
        },
      });
}
export function appearance() {
  function draw() {
    applyAppearance();
    $$("[data-theme]")
      .filter((e) => e.tagName === "BUTTON")
      .forEach((b) =>
        b.classList.toggle("active", b.dataset.theme === S.theme),
      );
    $$("[data-accent]").forEach((b) =>
      b.setAttribute("aria-checked", b.dataset.accent === S.accent),
    );
    $$("button[data-text]").forEach((b) =>
      b.classList.toggle("active", b.dataset.text === S.text),
    );
  }
  $$("button[data-theme]").forEach(
    (b) =>
      (b.onclick = () => {
        S.theme = b.dataset.theme;
        persist();
        draw();
      }),
  );
  $$("[data-accent]").forEach(
    (b) =>
      (b.onclick = () => {
        S.accent = b.dataset.accent;
        persist();
        draw();
      }),
  );
  $$("button[data-text]").forEach(
    (b) =>
      (b.onclick = () => {
        S.text = b.dataset.text;
        persist();
        draw();
      }),
  );
  draw();
}
export function storage() {
  $("#retention").value = S.retention;
  if (S.historyCleared) $("#storage-size").innerHTML = "0 <small>KB</small>";
  $("#retention").onchange = () => {
    const value = $("#retention").value;
    dialog({
      title: "调整记录保留范围？",
      body:
        "设置为最近 " +
        value +
        " 天。到期明细将被整理；规则配置不受影响。原型只更新偏好，不清理设备文件。",
      confirm: "保存保留范围",
      onCancel: () => {
        $("#retention").value = S.retention;
      },
      onConfirm: () => {
        S.retention = value;
        persist();
        toast("保留范围已更新");
      },
    });
  };
  $("#export-history").onclick = () =>
    dialog({
      title: "导出保留的访问记录？",
      body: "文件包含对象、目标地址、协议标签和当时结果。此处导出的是当前原型样例。",
      confirm: "导出记录",
      onConfirm: () => {
        download("sakamoto-demo-history.json", {
          sample: true,
          records: S.historyCleared ? [] : events,
        });
        toast("访问记录已导出");
      },
    });
  $("#clear-history").onclick = () =>
    dialog({
      title: "清空访问记录？",
      body: "当前保留的访问明细和对应统计将被清除。规则和域名列表不会改变。",
      confirm: "清空记录",
      danger: true,
      onConfirm: () => {
        S.historyCleared = true;
        persist();
        $("#storage-size").innerHTML = "0 <small>KB</small>";
        toast("记录已清空", { href: "activity.html", label: "查看" });
      },
    });
}
export function notifications() {
  const settings = [
    ["notification", "状态变化提醒", "提示中断、恢复与需要处理的情况"],
    [
      "autostart",
      platform === "linux" ? "登录后启动" : "设备开机后启动",
      platform === "linux"
        ? "桌面会话启动时恢复运行"
        : "按已选择的方式启动，仍需有效授权",
    ],
  ];
  $("#notification-controls").innerHTML = settings
    .map(
      ([k, t, p]) =>
        `<div class="list-row"><span class="grow"><span class="title">${t}</span><span class="subtitle">${p}</span></span><button class="switch" role="switch" aria-label="${t}" data-setting="${k}" aria-checked="${!!S[k]}"></button></div>`,
    )
    .join("");
  $$("[data-setting]").forEach(
    (b) =>
      (b.onclick = () => {
        S[b.dataset.setting] = !S[b.dataset.setting];
        persist();
        notifications();
        toast("偏好已更新");
      }),
  );
  $("#background-explanation").textContent =
    platform === "linux"
      ? "通知显示在桌面会话中。登录启动与后台承载在本原型中仅模拟偏好，正式实现需连接 Linux 生命周期。"
      : "Android 前台运行通知用于保持运行可见。这里的提醒偏好不会代替系统授权；开机启动为待接入的产品设计。";
}
export function diagnosticData() {
  return {
    format: "sakamoto-ui-diagnostic-v1",
    sample: true,
    platform,
    running: S.running,
    mode: S.mode,
    savedVersion: S.savedVersion,
    activeVersion: S.activeVersion,
    scenario: S.scenario,
    session: S.debug,
    includes: ["runtime status", "configuration versions", "session metadata"],
    payload: "not collected",
    keys: "not collected",
  };
}
export function diagnostics() {
  const data = diagnosticData();
  $("#diagnostic-facts").innerHTML =
    pair("设备平台", platform === "linux" ? "Linux" : "Android") +
    pair("运行状态", S.running ? "运行中" : "未运行") +
    pair("当前配置", "v" + S.activeVersion) +
    pair("已保存配置", "v" + S.savedVersion) +
    pair(
      "诊断会话",
      S.debug.status === "idle"
        ? "未开始"
        : S.debug.status === "running"
          ? "进行中"
          : "已结束",
    );
  $("#diagnostic-json").textContent = JSON.stringify(data, null, 2);
  $("#export-diagnostic").onclick = () => {
    download("sakamoto-demo-diagnostic.json", diagnosticData());
    toast("本地诊断文件已生成");
  };
}
