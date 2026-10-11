import { S } from "./model.js";

// One projection for the status badge, runtime page and recovery page.
export function runtimeState(state = S) {
  const pending = state.savedVersion !== state.activeVersion;
  const stopped =
    "当前未执行网络控制，也不记录新活动。已有配置和历史记录保留。";
  if (state.running)
    return {
      id: pending ? "pending" : "running",
      label: pending ? "旧设置仍在运行" : "正在运行",
      short: pending ? "有待生效修改" : "运行中",
      tone: pending ? "amber" : "green",
      icon: "shield-check",
      impact: `正在使用配置 v${state.activeVersion}，持续判断访问并记录活动。`,
      detail: pending
        ? `配置 v${state.savedVersion} 已保存，还没有开始使用。`
        : "当前没有需要处理的运行问题。",
      action: pending ? "查看待生效修改" : "查看运行状态",
      page: pending ? "config.html" : "runtime.html",
    };
  if (!state.permission)
    return {
      id: "permission",
      label: "等待运行授权",
      short: "待授权",
      tone: "amber",
      icon: "key-round",
      impact: stopped,
      detail: "完成运行授权后，再开始控制与记录。",
      action: "继续授权",
      page: "permissions.html",
    };
  if (pending || state.scenario === "startup")
    return {
      id: "configuration",
      label: "配置需要处理",
      short: "配置待处理",
      tone: "amber",
      icon: "circle-alert",
      impact: stopped,
      detail: `配置 v${state.savedVersion} 还未准备好。修复后由你明确启动。`,
      action: "处理配置",
      page: "config.html",
    };
  if (state.scenario === "recovering")
    return {
      id: "recovering",
      label: "正在尝试恢复",
      short: "恢复中",
      tone: "amber",
      icon: "refresh-cw",
      impact: stopped,
      detail: "运行发生中断，正在等待有限重试；恢复成功前仍不执行控制。",
      action: "立即重试",
    };
  if (state.scenario === "intervention")
    return {
      id: "intervention",
      label: "恢复需要你的帮助",
      short: "需处理",
      tone: "red",
      icon: "circle-alert",
      impact: stopped,
      detail: "自动恢复已停止。检查授权和配置后，可以重新启动。",
      action: "重新检查并启动",
    };
  return {
    id: state.awaitingStart ? "ready" : "paused",
    label: state.awaitingStart ? "已准备好，等待启动" : "已暂停",
    short: state.awaitingStart ? "待启动" : "已暂停",
    tone: "gray",
    icon: "pause",
    impact: stopped,
    detail: state.awaitingStart
      ? "配置已修复；准备好后再开始运行。"
      : "你可以保持暂停，或恢复使用当前配置。",
    action: state.awaitingStart ? "开始运行" : "恢复运行",
  };
}
