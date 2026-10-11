import { mount, $, toast } from "./ui.js";
import * as apps from "./apps.js";
import * as activity from "./activity.js";
import * as rules from "./rules.js";
import * as manage from "./manage.js";
import * as explore from "./explore.js";
import * as experience from "./experience.js";
import * as visibility from "./visibility.js";
import { activityFilterPage } from "./activity-filters.js";
import { domainSubscription } from "./domains.js";
mount();
const pages = {
  home: visibility.networkHome,
  contributions: visibility.contributionPage,
  apps: experience.apps,
  "app-detail": experience.application,
  "app-controls": experience.controls,
  "app-networks": apps.appNetworks,
  "app-selection": apps.appSelection,
  activity: experience.activityPage,
  "activity-filter": activityFilterPage,
  connection: experience.connectionPage,
  stats: experience.statistics,
  protocols: activity.protocolList,
  rules: rules.rules,
  "rule-detail": rules.ruleDetail,
  "rule-edit": rules.ruleEdit,
  "rule-scope": rules.ruleScope,
  groups: rules.groups,
  "group-detail": rules.groupDetail,
  "group-edit": rules.groupEdit,
  "binding-edit": rules.bindingEdit,
  domains: rules.domains,
  "domain-detail": rules.domainDetail,
  "domain-edit": rules.domainEdit,
  "domain-import": rules.domainImport,
  "domain-subscription": domainSubscription,
  config: manage.config,
  "config-import": manage.configImport,
  "config-review": manage.configReview,
  "config-result": manage.configResult,
  runtime: manage.runtime,
  setup: manage.setup,
  permissions: manage.permissions,
  recovery: manage.recovery,
  network: manage.network,
  appearance: manage.appearance,
  storage: manage.storage,
  notifications: manage.notifications,
  diagnostics: manage.diagnostics,
  map: explore.map,
  location: explore.locationPage,
  preview: explore.preview,
  "preview-result": explore.previewResult,
  debug: explore.debug,
  "debug-session": explore.debugSession,
};
const init = pages[document.body.dataset.page];
if (init) init();
window.__prototypeReady = true;

window.addEventListener("message", async (e) => {
  if (e.origin !== location.origin || e.data?.type !== "sakamoto:sample")
    return;
  const { S, persist, params } = await import("./model.js");
  const { sampleNewActivity } = await import("./network-data.js");
  const app = params.get("app") || S.selected || "s4";
  const targets = {
    s1: "docs.example.com",
    s2: "chat.example.org",
    s3: "media.example.net",
    s4: "api.weather.example",
    s5: "files.example.org",
  };
  const q = sampleNewActivity(
    app,
    S.lastDecision?.app === app ? S.lastDecision.target : targets[app],
  );
  persist();
  window.dispatchEvent(new Event("prototype-new-activity"));
  e.source?.postMessage({ type: "sakamoto:sample-result", ok: !!q }, e.origin);
});

if (
  new URLSearchParams(location.search).get("open") === "decision" &&
  document.body.dataset.page === "connection"
)
  document.getElementById("adjust-record")?.click();

// Gallery-only sample controls set a local response; no subscription URL is fetched.
window.addEventListener("message", async (e) => {
  if (
    e.origin !== location.origin ||
    e.data?.type !== "sakamoto:subscription-sample" ||
    document.body.dataset.page !== "domain-detail"
  )
    return;
  const { S, params, persist } = await import("./model.js");
  const id = params.get("id") || "d1";
  if (!["failure", "update"].includes(e.data.outcome)) return;
  S.subscriptionResponses[id] = e.data.outcome;
  persist();
  if (e.data.scheduled) {
    const { checkSubscription } = await import("./domains.js");
    await checkSubscription(id, true);
  }
  e.source?.postMessage(
    { type: "sakamoto:subscription-sample-result", ok: true },
    e.origin,
  );
});
