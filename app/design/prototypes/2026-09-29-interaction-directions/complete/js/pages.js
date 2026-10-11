import { mount, $, toast } from "./ui.js";
import * as apps from "./apps.js";
import * as activity from "./activity.js";
import * as rules from "./rules.js";
import * as manage from "./manage.js";
import * as explore from "./explore.js";
mount();
const pages = {
  home: apps.home,
  apps: apps.apps,
  "app-detail": apps.appDetail,
  "app-networks": apps.appNetworks,
  "app-selection": apps.appSelection,
  activity: activity.activity,
  "activity-filter": activity.activityFilter,
  connection: activity.connection,
  stats: activity.stats,
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
