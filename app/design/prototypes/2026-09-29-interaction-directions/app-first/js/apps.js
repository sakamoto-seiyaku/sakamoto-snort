import {
  S,
  params,
  platform,
  allSubjects,
  subject,
  subjectName,
  subjectRules,
  quickBlock,
  setBlock,
  commit,
  clone,
  persist,
  events,
  bytes,
  filteredEvents,
  newDraft,
} from "./model.js";
import {
  $,
  $$,
  esc,
  icon,
  url,
  go,
  here,
  appIcon,
  ruleCard,
  eventRow,
  empty,
  toast,
  dialog,
  saving,
  chart,
  trafficChart,
  badge,
} from "./ui.js";
export function subjectChecks(selected = [], name = "subjects") {
  return allSubjects()
    .map(
      (o) =>
        `<label class="choice">${appIcon(o)}<span class="grow"><strong>${esc(o.name)}</strong><small>${esc(o.sub)} · UID ${o.uid}</small></span><input type="checkbox" name="${name}" value="${o.id}" ${selected.includes(o.id) ? "checked" : ""}></label>`,
    )
    .join("");
}
export const selectedSubjects = (name = "subjects") =>
  $$(`input[name="${name}"]:checked`).map((e) => e.value);
function identity(o) {
  return `<div class="avatar-title">${appIcon(o, true)}<div><h1>${esc(o.name)}</h1><p>${esc(o.sub)} · UID ${o.uid}</p></div></div>`;
}
function side(o) {
  return (
    identity(o) +
    `<div class="card"><div class="between"><h3>当前控制</h3><span class="badge ${quickBlock(o.id) ? "red" : "blue"}">${quickBlock(o.id) ? "已限制联网" : "按规则处理"}</span></div><p class="help" style="margin:14px 0">${subjectRules(o.id, S.active).length} 条规则适用于这个${platform === "linux" ? "系统用户" : "应用身份"}。</p><a class="btn full" href="${url("app-detail.html", { id: o.id })}">管理访问与分配 ${icon("arrow-right")}</a></div><h2 class="section-label">最近访问</h2>` +
    (S.historyCleared ? [] : events.filter((e) => e.subject === o.id))
      .slice(0, 3)
      .map(eventRow)
      .join("") +
    (S.historyCleared ? empty("暂无保留记录", "新的访问会在这里出现。") : "")
  );
}
export function home() {
  const list = filteredEvents({
    subject: "all",
    result: "all",
    kind: "all",
    range: "60",
    query: "",
  });
  $("#home-events").innerHTML =
    list.slice(0, 3).map(eventRow).join("") ||
    empty("还没有访问记录", "有新的连接时，会出现在这里。");
  $("#home-count").textContent = list.length;
  $("#home-blocked").innerHTML =
    list.filter((e) => e.result === "drop").length + " <small>次</small>";
  $("#home-chart").innerHTML = list.length
    ? trafficChart(list, 60)
    : empty("暂无趋势", "当前没有保留的访问记录。");
  $("#home-runtime").textContent =
    (platform === "linux"
      ? "Linux 主机"
      : S.mode === "vpn"
        ? "VPN 模式"
        : "Root 模式") +
    " · " +
    (S.running ? "规则正在生效" : "配置已保留");
  if (!S.running) {
    $("#home-status").textContent =
      "● " +
      (S.scenario === "permission"
        ? "还需要运行授权"
        : S.scenario === "recovering"
          ? "正在恢复运行"
          : "防火墙尚未运行");
    $("#home-headline").innerHTML =
      S.scenario === "permission"
        ? "准备好授权，<br>再开始保护。"
        : "保护暂停，<br>规则仍然保留。";
    const a = $(".hero .btn");
    a.href = url(
      S.scenario === "permission"
        ? "permissions.html"
        : S.scenario === "startup"
          ? "config.html"
          : S.scenario === "intervention"
            ? "recovery.html"
            : "runtime.html",
    );
    a.textContent =
      S.scenario === "permission"
        ? "继续授权"
        : S.scenario === "startup"
          ? "修复配置"
          : "查看并恢复";
  } else if (S.savedVersion !== S.activeVersion) {
    $("#home-headline").innerHTML = "新修改已保存，<br>仍需完成生效。";
    $(".hero .btn").href = url("config.html");
    $(".hero .btn").textContent = "处理未生效的修改";
  }
}
export function apps() {
  let filter = "all";
  S.appQuery = S.appQuery || "";
  $("#app-search").value = S.appQuery;
  function draw() {
    const list = allSubjects().filter(
      (o) =>
        (o.name + " " + o.sub + " " + o.uid)
          .toLowerCase()
          .includes(S.appQuery.toLowerCase()) &&
        (filter === "all" ||
          subjectRules(o.id, S.active).some((r) => r.action === "drop")),
    );
    $("#apps-list").innerHTML =
      list
        .map(
          (o) =>
            `<a class="list-row" data-select-object="${o.id}" href="${url("app-detail.html", { id: o.id })}">${appIcon(o)}<span class="grow"><span class="title">${esc(o.name)}</span><span class="subtitle">${esc(o.sub)} · ${subjectRules(o.id, S.active).length} 条规则</span></span>${quickBlock(o.id) ? '<span class="badge red">限制</span>' : icon("chevron-right")}</a>`,
        )
        .join("") || empty("没有找到对象", "试试名称、UID，或切回全部。");
    $("#app-side-detail").innerHTML = side(
      subject(S.selected) || allSubjects()[0],
    );
    $$("[data-select-object]").forEach(
      (a) =>
        (a.onclick = (e) => {
          if (innerWidth >= 700) {
            e.preventDefault();
            S.selected = a.dataset.selectObject;
            persist();
            draw();
          }
        }),
    );
  }
  $("#app-search").oninput = (e) => {
    S.appQuery = e.target.value;
    persist();
    draw();
  };
  $$("[data-app-filter]").forEach(
    (b) =>
      (b.onclick = () => {
        filter = b.dataset.appFilter;
        $$("[data-app-filter]").forEach((x) =>
          x.classList.toggle("active", x === b),
        );
        draw();
      }),
  );
  $("#identity-note").textContent =
    platform === "linux"
      ? "当前按系统用户 UID 管理。同一用户启动的程序共享控制范围。"
      : "范围为此设备可见的应用身份；共享 UID 的应用共用规则。";
  draw();
}
export function appDetail() {
  const id = params.get("id") || S.selected || "s1",
    o = subject(id) || allSubjects()[0];
  S.selected = o.id;
  persist();
  $("#app-identity").innerHTML = identity(o);
  $("#app-current-rules-title").textContent = "当前生效 · v" + S.activeVersion;
  const refresh = () => {
    const blocked = quickBlock(o.id);
    $("#app-access-switch").setAttribute("aria-checked", String(!!blocked));
    $("#app-access-note").textContent = blocked
      ? "全网络快捷限制已生效"
      : "未限制，交由其他规则判断";
    $("#app-rules").innerHTML =
      subjectRules(o.id, S.active)
        .map((r) => ruleCard(r, true))
        .join("") ||
      empty("还没有分配规则", "可以新建规则，或复用已有规则组。");
    $("#app-events").innerHTML =
      (S.historyCleared ? [] : events.filter((e) => e.subject === o.id))
        .slice(0, 3)
        .map(eventRow)
        .join("") || empty("暂无访问", "此对象还没有保留的访问记录。");
  };
  $("#app-access-switch").onclick = () => {
    const blocked = !!quickBlock(o.id);
    dialog({
      title: blocked ? "解除快捷限制？" : "限制所有网络访问？",
      body: blocked
        ? "解除后，其他适用规则仍会判断访问。"
        : "将为「" +
          esc(o.name) +
          "」添加一条全网络阻止规则。" +
          (platform === "linux" ? "此 UID 下的所有程序都会受到影响。" : ""),
      confirm: blocked ? "解除限制" : "添加限制",
      danger: !blocked,
      onConfirm: async () => {
        const next = clone(S.config);
        setBlock(next, o.id, "all", !blocked);
        await commit(next, { returnTo: "app-detail.html?id=" + o.id });
        refresh();
        toast(
          S.savedVersion === S.activeVersion
            ? "网络访问已更新"
            : "已保存，尚未生效",
          { href: "config.html", label: "查看配置" },
        );
      },
    });
  };
  $$(
    'a[data-page="app-networks.html"],a[data-page="binding-edit.html"]',
  ).forEach((a) => {
    a.href = url(a.dataset.page, {
      id: a.dataset.page === "app-networks.html" ? o.id : null,
      subject: o.id,
      from: "app-detail.html?id=" + o.id,
    });
    if (platform === "linux" && a.dataset.page === "app-networks.html")
      $(".subtitle", a).textContent = "分别设置有线网络、Wi-Fi 与 VPN";
  });
  $("#app-all-activity").href = url("activity.html", { subject: o.id });
  $("#app-create-rule").onclick = () =>
    go("rule-edit.html", {
      subject: o.id,
      from: "app-detail.html?id=" + o.id,
      new: 1,
    });
  refresh();
}
export function appNetworks() {
  const o = subject(params.get("id") || S.selected) || allSubjects()[0];
  $("#network-subject").innerHTML = identity(o);
  if (platform === "linux")
    $(".notice p").textContent =
      "限制按当前连接的网络类型判断。同一系统用户 UID 下的程序共用这些快捷规则。";
  $(".topbar .back").href = url("app-detail.html", { id: o.id });
  const nets =
    platform === "linux"
      ? [
          ["Wired", "有线网络", "ethernet-port"],
          ["Wi-Fi", "Wi-Fi", "wifi"],
          ["VPN", "VPN 网络", "shield"],
        ]
      : [
          ["Wi-Fi", "Wi-Fi", "wifi"],
          ["Mobile", "移动网络", "signal"],
          ["VPN", "VPN 网络", "shield"],
        ];
  $("#network-switches").innerHTML = nets
    .map(
      ([v, t, i]) =>
        `<div class="list-row"><span class="tile-icon">${icon(i)}</span><span class="grow"><span class="title">${t}</span><span class="subtitle">${quickBlock(o.id, v, S.config) ? "快捷限制" : "交由规则判断"}</span></span><button class="switch" data-network="${v}" role="switch" aria-label="限制${t}" aria-checked="${!!quickBlock(o.id, v, S.config)}"></button></div>`,
    )
    .join("");
  $$("[data-network]").forEach(
    (b) =>
      (b.onclick = () => {
        const enabled = b.getAttribute("aria-checked") !== "true";
        b.setAttribute("aria-checked", enabled);
        $(".subtitle", b.parentElement).textContent = enabled
          ? "快捷限制"
          : "交由规则判断";
      }),
  );
  $("#save-networks").onclick = (e) =>
    saving(e.currentTarget, async () => {
      const next = clone(S.config);
      $$("[data-network]").forEach((b) =>
        setBlock(
          next,
          o.id,
          b.dataset.network,
          b.getAttribute("aria-checked") === "true",
        ),
      );
      await commit(next, {
        returnTo: "app-detail.html?id=" + o.id,
        message: "网络限制已更新",
      });
      go("config-result.html");
    });
}
export function appSelection() {
  $("#batch-subjects").innerHTML = subjectChecks();
  $("#save-batch").onclick = async (e) => {
    const ids = selectedSubjects();
    if (!ids.length) {
      toast("先选择至少一个控制对象");
      return;
    }
    e.currentTarget.disabled = true;
    $("#batch-results").innerHTML =
      '<h2 class="section-label">逐项处理结果</h2>';
    let ok = 0;
    for (const id of ids) {
      try {
        const next = clone(S.config);
        setBlock(next, id, "all", $("#batch-mode").value === "block");
        await commit(next, { returnTo: "apps.html" });
        ok++;
        $("#batch-results").insertAdjacentHTML(
          "beforeend",
          `<div class="list-row"><span class="grow">${esc(subjectName(id))}</span><span class="badge ${S.savedVersion === S.activeVersion ? "" : "amber"}">${S.savedVersion === S.activeVersion ? "已生效" : "已保存，未生效"}</span></div>`,
        );
      } catch (error) {
        $("#batch-results").insertAdjacentHTML(
          "beforeend",
          `<div class="list-row"><span class="grow"><span class="title">${esc(subjectName(id))}</span><span class="subtitle">${esc(error.message)}</span></span><span class="badge red">未完成</span></div>`,
        );
      }
    }
    e.currentTarget.disabled = false;
    toast(`已保存 ${ok} / ${ids.length} 项`);
    $("#batch-results").scrollIntoView({ block: "nearest" });
  };
}
