import { S, params, allSubjects } from "./model.js";
import { $, esc, go, url, here } from "./ui.js";
import { periodText } from "./network-data.js";

const outcomes = [
  ["all", "全部结果"],
  ["blocked", "被阻止"],
  ["allowed", "规则允许"],
  ["observe", "仅观察，实际允许"],
  ["other", "未被规则阻止"],
];
export const normalizeOutcome = (value) =>
  ({ drop: "blocked", allow: "allowed" })[value] ||
  (outcomes.some(([id]) => id === value) ? value : "all");
export const outcomeOptions = () =>
  outcomes
    .map(([id, label]) => `<option value="${id}">${label}</option>`)
    .join("");
export const outcomeLabel = (value) =>
  outcomes.find(([id]) => id === normalizeOutcome(value))[1];
export function matchesOutcome(event, value) {
  const outcome = normalizeOutcome(value);
  return (
    outcome === "all" ||
    (outcome === "blocked"
      ? event.result === "drop"
      : outcome === "allowed"
        ? event.result === "allow"
        : outcome === "observe"
          ? event.result === "observe"
          : event.result !== "drop")
  );
}
export function activityFilterPage() {
  $("#filter-subject").innerHTML =
    '<option value="all">全部应用</option>' +
    allSubjects()
      .map((a) => `<option value="${a.id}">${esc(a.name)}</option>`)
      .join("") +
    '<option value="unknown">归属未确定</option>';
  $("#filter-subject").value = params.get("app") || "all";
  $("#filter-result").innerHTML = outcomeOptions();
  $("#filter-result").value = normalizeOutcome(params.get("result"));
  $("#filter-type").value = params.get("type") || "all";
  $("#filter-kind").value = params.get("state") || "all";
  if (S.timeSlice)
    $("#filter-range").insertAdjacentHTML(
      "beforeend",
      `<option value="selected">${periodText()}（保持选区）</option>`,
    );
  $("#filter-range").value = S.timeSlice
    ? "selected"
    : S.period === "today"
      ? "1440"
      : S.period === "hour"
        ? "60"
        : "30";
  $("#filter-type").onchange = () => {
    $("#filter-kind").disabled = $("#filter-type").value === "dns";
    if ($("#filter-kind").disabled) $("#filter-kind").value = "all";
  };
  $("#filter-type").onchange();
  $("#filter-kind").onchange = () => {
    if ($("#filter-kind").value !== "all")
      $("#filter-type").value = "connection";
  };
  $("#reset-filters").onclick = () => {
    ["subject", "result", "type", "kind"].forEach(
      (key) => ($("#filter-" + key).value = "all"),
    );
    $("#filter-range").value = "30";
    $("#filter-kind").disabled = false;
  };
  const origin = params.get("from");
  $(".topbar .back").href = url(origin || "activity.html", {
    app: params.get("app") || "all",
    type: params.get("type") || "all",
    result: normalizeOutcome(params.get("result")),
    state: params.get("state"),
  });
  $("#apply-filters").onclick = () => {
    const range = $("#filter-range").value;
    const values = {
      app: $("#filter-subject").value,
      type: $("#filter-type").value,
      result: $("#filter-result").value,
      state: $("#filter-kind").value,
      period:
        range === "selected"
          ? S.period
          : range === "1440"
            ? "today"
            : range === "60"
              ? "hour"
              : "recent",
      window:
        range === "selected"
          ? S.timeSlice.join(",")
          : range === "15"
            ? "0,15"
            : "all",
      search: params.get("search"),
      q: params.get("q"),
      after: params.get("after"),
    };
    values.from = url("activity-filter.html", { ...values, from: origin });
    go("activity.html", values);
  };
}
