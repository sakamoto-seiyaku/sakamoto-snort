import { S, bindingsFor, subjectName } from "./model.js";

// A rule's definition and its effective mode are separate facts.
export function ruleUse(rule, config = S.config, app = null) {
  const assignments = bindingsFor(rule.id, config);
  const subjects = [...new Set(assignments.flatMap((b) => b.subjects))]
    .filter((id) => !app || id === app)
    .map((id) => {
      const bindings = assignments.filter((b) => b.subjects.includes(id));
      const modes = new Set(bindings.map((b) => b.mode));
      const mode = modes.size > 1 ? "conflict" : [...modes][0];
      return {
        id,
        name: subjectName(id),
        mode,
        viaGroup: bindings.some((b) => b.kind === "group"),
        label:
          mode === "conflict"
            ? "分配冲突，需处理"
            : mode === "observe"
              ? "仅观察 · 实际允许"
              : rule.action === "drop"
                ? "命中后阻止"
                : "命中后允许",
      };
    });
  const modes = new Set(subjects.map((s) => s.mode));
  const mode = !subjects.length
    ? "unused"
    : modes.size > 1
      ? "mixed"
      : [...modes][0];
  const label =
    mode === "unused"
      ? "未分配 · 不参与判断"
      : mode === "mixed"
        ? "执行方式因应用而异"
        : mode === "conflict"
          ? "分配冲突，需处理"
          : subjects[0].label;
  return {
    subjects,
    mode,
    label,
    tone:
      mode === "unused"
        ? "gray"
        : mode === "conflict"
          ? "amber"
          : mode === "enforce" && rule.action === "drop"
            ? "red"
            : "blue",
    icon:
      mode === "observe"
        ? "eye"
        : mode === "enforce" && rule.action === "drop"
          ? "ban"
          : "check",
    definition: `规则定义：${rule.action === "drop" ? "阻止" : "允许"}`,
    summary: subjects.map((s) => `${s.name}：${s.label}`).join("；"),
  };
}
