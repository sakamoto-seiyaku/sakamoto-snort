/* Throwaway V4 study. A: request an access result. B: shared content + local differences.
   The finite evaluator and action modifiers are proposed prototype semantics, not a Product API. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const clone = value => structuredClone(value);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const apps = {weather:'天气', reader:'阅读', podcast:'播客', music:'音乐'};
  const networks = {wifi:'Wi-Fi', mobile:'移动网络', wired:'有线', vpn:'VPN'};
  const actions = {allow:'允许', deny:'禁止'};
  const paths = {
    home:'<path d="M3 11 12 3l9 8M5 10v11h5v-7h4v7h5V10"/>',
    rules:'<path d="M8 4h12M8 12h12M8 20h12"/><circle cx="3" cy="4" r="1"/><circle cx="3" cy="12" r="1"/><circle cx="3" cy="20" r="1"/>',
    settings:'<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2" fill="currentColor"/><circle cx="15" cy="12" r="2" fill="currentColor"/><circle cx="8" cy="18" r="2" fill="currentColor"/>',
    weather:'<circle cx="10" cy="9" r="4"/><path d="M10 1v2M10 15v2M2 9H0M18 9h2M4 3l2 2M14 13l2 2M16 3l-2 2M5 14l-2 2M9 19h10a3 3 0 0 0 0-6 5 5 0 0 0-9 2 2 2 0 0 0-1 4"/>',
    reader:'<path d="M12 5C9 2 5 3 2 4v15c4-1 7-1 10 2 3-3 6-3 10-2V4c-3-1-7-2-10 1v16"/>',
    podcast:'<circle cx="12" cy="10" r="2"/><path d="M8 20v-5a4 4 0 0 1 8 0v5M6 14a8 8 0 1 1 12 0M9 13a4 4 0 1 1 6 0"/>',
    music:'<path d="M9 18V5l11-2v13M9 9l11-2"/><ellipse cx="5" cy="18" rx="4" ry="3"/><ellipse cx="16" cy="16" rx="4" ry="3"/>',
    check:'<path d="m5 12 4 4L19 6"/>',
    deny:'<circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/>',
    arrow:'<path d="m9 5 7 7-7 7"/>',
    close:'<path d="m6 6 12 12M18 6 6 18"/>',
    plus:'<path d="M12 5v14M5 12h14"/>',
    link:'<path d="m10 13 4-4M8 16l-2 2a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0M14 8l2-2a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/>',
    info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/>',
    edit:'<path d="m15 4 5 5M3 21l5-1L21 7a3 3 0 0 0-4-4L4 16l-1 5Z"/>',
  };
  const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.info}</svg>`;
  const avatar = app => `<span class="app-avatar ${app}">${icon(app)}</span>`;
  const person = app => `<div class="app-person">${avatar(app)}<strong>${apps[app]}</strong></div>`;
  const chip = app => `<span class="person-chip">${avatar(app)}${apps[app]}</span>`;
  const button = (label, action, data = '', kind = '') => `<button class="button ${kind}" data-action="${action}" ${data}>${label}</button>`;
  const result = action => `<span class="result-action ${action}">${icon(action === 'allow' ? 'check' : action === 'deny' ? 'deny' : 'info')}${actions[action] || '结果因情况而异'}</span>`;
  let serial = 10;
  const leaf = (field, value) => ({id:`n${++serial}`, field, value});
  const group = (op, children) => ({id:`n${++serial}`, op, children});
  const fact = (app, domain, network = 'wifi', protocol = 'tcp', port = 443) => ({app, domain, network, protocol, port});
  let state, modal = null, activeRule = 'privacy', selectedApp = 'weather', activeNetwork = 'wifi';
  let variant = new URLSearchParams(location.search).get('variant') === 'B' ? 'B' : 'A';
  let view = new URLSearchParams(location.search).get('view') || 'rules';
  if (!['rules','app','home','settings'].includes(view)) view = 'rules';
  let toastTimer;

  function matches(node, context, source = state) {
    if (node.op === 'and') return node.children.every(child => matches(child, context, source));
    if (node.op === 'or') return node.children.some(child => matches(child, context, source));
    if (node.op === 'not') return !matches(node.children[0], context, source);
    if (node.field === 'list') return (source.lists[node.value] || []).includes(context.domain);
    if (node.field === 'app') return (Array.isArray(node.value) ? node.value : [node.value]).includes(context.app);
    if (node.field === 'port') return Number(node.value) === Number(context.port);
    return context[node.field] === node.value;
  }

  function ordered(source = state) {
    return [...source.rules].sort((a, b) => a.priority - b.priority || a.order - b.order || a.id.localeCompare(b.id));
  }

  function evaluate(context, source = state) {
    const rule = ordered(source).find(rule => rule.enabled && matches(rule.expr, context, source));
    if (!rule) return {action:'allow', id:null, name:'默认允许', version:source.version, modifier:null};
    const modifier = rule.modifiers.find(m => m.app === context.app && m.domain === context.domain && m.networks.includes(context.network));
    return {action:modifier?.action || rule.action, id:rule.id, name:rule.name, version:source.version, modifier:modifier?.id || null};
  }

  function eachNode(node, fn) {
    fn(node);
    (node.children || []).forEach(child => eachNode(child, fn));
  }

  // Exact finite partition for the fields available in this prototype: each named port + one other port.
  function contexts(app, domain, network, source = state) {
    const ports = new Set([53,80,443,853]);
    source.rules.forEach(rule => eachNode(rule.expr, node => { if (node.field === 'port') ports.add(Number(node.value)); }));
    let other = 65000;
    while (ports.has(other)) other--;
    ports.add(other);
    return ['tcp','udp'].flatMap(protocol => [...ports].map(port => fact(app, domain, network, protocol, port)));
  }

  function summary(app, domain, network, source = state) {
    const outcomes = contexts(app, domain, network, source).map(context => evaluate(context, source));
    const action = outcomes.every(item => item.action === outcomes[0].action) ? outcomes[0].action : 'mixed';
    const names = [...new Set(outcomes.map(item => item.name))];
    return {action, names, outcomes, modified:outcomes.some(item => item.modifier)};
  }

  function sourceLabel(outcome) {
    return esc(outcome.names?.join('、') || outcome.name) + (outcome.modified || outcome.modifier ? ' · 有单独调整' : '');
  }

  function makeState(scenario = 'privacy') {
    const members = ['weather','reader','podcast'];
    const rule = (id, name, action, priority, enabled, expr) => ({id,name,action,priority,order:serial++,enabled,expr,modifiers:[]});
    const initial = {
      scenario, version:1, lists:{L:['api.weather.example','metrics.example','stats.example']}, changes:[], records:[],
      rules:[
        rule('privacy','隐私名单',scenario === 'inverse' ? 'allow' : 'deny',100,true,group('and',[leaf('app',members),leaf('list','L')])),
        rule('mobile','移动网络保护','deny',20,scenario === 'priority',group('and',[leaf('app',clone(members)),leaf('network','mobile')])),
        rule('complex','两个不同的情况','deny',80,false,group('or',[
          group('and',[leaf('app',['weather']),leaf('list','L')]),
          group('and',[leaf('network','wifi'),leaf('protocol','udp'),leaf('port',443)]),
        ])),
      ],
    };
    Object.keys(apps).forEach(app => {
      ['api.weather.example','metrics.example','cdn.example','203.0.113.42'].forEach((domain,index) => {
        const context = fact(app, domain, index % 2 ? 'mobile' : 'wifi');
        const outcome = evaluate(context, initial);
        initial.records.push({id:`e${serial++}`, context, ...outcome, time:`10:${String(32-index*4).padStart(2,'0')}`, bytes:outcome.action === 'deny' ? 0 : (index+1)*32768, sampled:false});
      });
    });
    return initial;
  }

  function reset(scenario) {
    state = makeState(scenario);
    activeRule = 'privacy'; selectedApp = 'weather'; activeNetwork = 'wifi'; modal = null;
    $('scenario').value = scenario;
    render();
  }

  function changed(message) {
    state.version++;
    state.changes.push({version:state.version, message});
  }

  function notify(message) {
    clearTimeout(toastTimer);
    $('toast').textContent = message;
    $('toast').classList.add('visible');
    toastTimer = setTimeout(() => $('toast').classList.remove('visible'), 2600);
  }

  function updateURL() {
    const url = new URL(location.href);
    url.searchParams.set('variant', variant);
    url.searchParams.set('view', view);
    history.replaceState(null, '', url);
  }

  function switchVariant(next) {
    if (next === variant) return;
    const discarded = modal && !['complete','state','record','checks'].includes(modal.type);
    modal = null; variant = next; updateURL(); render();
    console.info(`V4 ${next}: committed sample state`,clone(state));
    notify(discarded ? `切到 ${next}；已提交修改保留，未提交草稿已放下` : `切到 ${next}；已提交修改保留`);
  }

  function titleText(node) {
    if (node.op) {
      if (node.op === 'not') return `不是（${titleText(node.children[0])}）`;
      return node.children.map(child => child.op ? `（${titleText(child)}）` : titleText(child)).join(node.op === 'and' ? '，并且 ' : '；或者 ');
    }
    const labels = {
      app:() => `应用为 ${(Array.isArray(node.value) ? node.value : [node.value]).map(app => apps[app]).join('、') || '空选择'}`,
      list:() => `目标在名单 ${node.value} 中`, domain:() => `目标为 ${node.value || '空域名'}`,
      network:() => `网络为 ${networks[node.value]}`, protocol:() => `协议为 ${String(node.value).toUpperCase()}`,
      port:() => `目标端口为 ${node.value}`,
    };
    return labels[node.field]?.() || '';
  }

  function membershipNode(rule) {
    if (rule.expr.op === 'and') return rule.expr.children.find(child => child.field === 'app');
    return rule.expr.field === 'app' ? rule.expr : null;
  }

  function relevantApps(rule, source = state) {
    const namedDomains = [];
    eachNode(rule.expr,node => { if (node.field === 'domain') namedDomains.push(node.value); });
    const domains = [...new Set(['api.weather.example','metrics.example','other.example',...Object.values(source.lists).flat(),...namedDomains])];
    return Object.keys(apps).filter(app => domains.some(domain => Object.keys(networks).some(network => contexts(app,domain,network,source).some(context => matches(rule.expr,context,source)))));
  }

  const nav = mobile => `<${mobile ? 'nav' : 'aside'} class="${mobile ? 'mobile-nav' : 'sidebar'}" aria-label="主导航">
    ${mobile ? '' : '<div class="brand"><i></i>Sakamoto</div>'}
    ${[['home','首页'],['rules','规则'],['settings','设置']].map(([key,label]) => `<button class="${mobile ? '' : 'nav-item'} ${view === key || view === 'app' && key === 'home' ? 'selected' : ''}" data-action="nav" data-view="${key}">${icon(key)}${label}</button>`).join('')}
    ${mobile ? '' : '<div class="sidebar-foot"><span class="online-dot"></span>本页交互样例</div>'}
  </${mobile ? 'nav' : 'aside'}>`;

  function render() {
    document.querySelectorAll('[data-variant]').forEach(element => {
      const selected = element.dataset.variant === variant;
      element.classList.toggle('selected',selected);
      element.setAttribute('aria-pressed',String(selected));
    });
    const crumbs = view === 'app' ? `<button data-action="nav" data-view="home">首页</button><span>／ ${apps[selectedApp]}</span>` : esc({home:'我的网络',rules:'规则',settings:'设置'}[view]);
    const page = view === 'rules' ? (variant === 'A' ? renderA() : renderB()) : view === 'app' ? renderApp() : view === 'home' ? renderHome() : renderSettings();
    $('app').innerHTML = `${nav(false)}<div class="app-content"><header class="app-top"><div class="breadcrumb">${crumbs}</div><div class="status"><span class="online-dot"></span>当前安排</div></header><main class="main">${page}</main><div class="state-note"><span>样例版本 ${state.version} · ${state.changes.length} 次已提交修改</span><button data-action="state">查看样例状态</button></div>${nav(true)}</div>`;
    renderModal();
  }

  function renderA() {
    const rows = [
      ['weather','api.weather.example'],['reader','api.weather.example'],['podcast','api.weather.example'],
      ['weather','metrics.example'],['podcast','stats.example'],
    ];
    return `<div class="page-intro"><div><h1>怎样联网</h1><p>先看现在的结果。想改变时，直接告诉 Sakamoto 你希望怎样。</p></div><div class="page-actions">${button(`${icon('plus')}改变联网结果`,'goal','','primary')}</div></div>
      <div class="filter-line"><div class="segmented">${['wifi','mobile'].map(network => `<button class="${activeNetwork === network ? 'selected' : ''}" data-action="network" data-network="${network}">${networks[network]}</button>`).join('')}</div><span>几个已知目标 · 当前政策结果</span></div>
      <div class="effective-table"><div class="table-heading"><span>应用与目标</span><span>${networks[activeNetwork]}下的结果</span><span>改变</span></div>
      ${rows.map(([app,domain]) => {
        const outcome = summary(app,domain,activeNetwork);
        return `<div class="effective-row" data-case="${app}:${domain}"><div class="app-person">${avatar(app)}<div><div class="target-name">${domain}</div><div class="target-meta">${apps[app]} · 目标连接</div></div></div><div class="result-info">${result(outcome.action)}<span class="result-source">${sourceLabel(outcome)}</span></div>${button('改变结果','goal',`data-app="${app}" data-domain="${domain}"`,'small')}</div>`;
      }).join('')}</div>
      <p class="tip">这里看的是当前政策。实际传输与过去的拦截记录，在应用活动中查看。</p>
      <div class="foot-row">${button('核对几种情况','checks','','quiet')}<span class="muted small">允许与禁止都能作为希望的结果</span></div>
      <div class="result-links"><div class="section-head"><h3>已有内容</h3><span class="muted">用于这些结果的共同内容</span></div>
      ${state.rules.map(rule => `<button class="library-link" data-action="shared" data-rule="${rule.id}"><div><strong>${esc(rule.name)}</strong><div class="muted">${actions[rule.action]} · ${rule.enabled ? '使用中' : '待用'} · ${rule.modifiers.length ? `${rule.modifiers.length} 项单独调整` : '没有单独调整'}</div></div>${icon('arrow')}</button>`).join('')}</div>`;
  }

  function renderB() {
    const rule = state.rules.find(rule => rule.id === activeRule) || state.rules[0];
    const members = relevantApps(rule);
    const app = members.includes(selectedApp) ? selectedApp : members[0] || 'weather';
    const differences = rule.modifiers.filter(m => m.app === app);
    const initialText = rule.id === 'privacy' ? `${actions[rule.action]}这些应用联系<span class="token" role="button" tabindex="0" data-action="list">名单 L 中的目标</span>。` : `${actions[rule.action]}满足下列条件的连接。`;
    return `<div class="page-intro"><div><h1>共同内容</h1><p>一起用同一份内容。个别应用的调整留在原处，也能随时回到共同内容。</p></div><div class="page-actions">${button(`${icon('plus')}新建内容`,'new','','primary')}</div></div>
      <div class="source-picker" aria-label="选择内容">${state.rules.map(item => `<button class="${item.id === rule.id ? 'selected' : ''}" data-action="source" data-rule="${item.id}">${esc(item.name)}${item.enabled ? '' : ' · 待用'}</button>`).join('')}</div>
      <div class="shared-layout"><section class="shared-document"><div class="document-title"><div><h2>${esc(rule.name)}</h2><p class="muted">共同内容 · 当前版本 ${state.version}</p></div><span class="pill ${rule.enabled ? 'green' : ''}">${rule.enabled ? '使用中' : '待用'}</span></div>
      <div class="document-sentence"><span class="${rule.action}">${initialText}</span></div>
      ${rule.id === 'privacy' ? `<p class="muted small">名单 L · ${state.lists.L.length} 个目标${state.lists.L.includes('api.weather.example') ? ' · 包含 api.weather.example' : ' · 已移除 api.weather.example'}</p>` : `<div class="condition-preview">${esc(titleText(rule.expr))}</div>`}
      <div class="member-line"><p>${rule.expr.op === 'or' ? '完整条件可能作用于这些应用；每一支保留自己的应用范围' : '当前作用应用'}</p><div class="people">${members.map(chip).join('') || '<span class="muted small">当前条件不作用于样例应用</span>'}</div></div>
      <div class="document-footer">${button('修改共同内容','shared',`data-rule="${rule.id}"`,'small')}<button class="button quiet small" data-action="pause" data-rule="${rule.id}">${rule.enabled ? '暂停使用' : '开始使用'}</button></div>
      <div class="foot-row"><button class="button quiet small" data-action="members" data-rule="${rule.id}">${membershipNode(rule) ? '选择作用应用' : '编辑每一支的应用条件'}</button><button class="button quiet small" data-action="order">查看优先顺序</button></div></section>
      <section class="usage-column"><h3>在各应用中的使用</h3>${members.map(member => {
        const diffs = rule.modifiers.filter(m => m.app === member);
        return `<div class="usage-row ${member === app ? 'selected' : ''} ${diffs.length ? 'difference' : ''}"><button data-action="usage" data-app="${member}">${avatar(member)}<span class="usage-text"><strong>${apps[member]}</strong><span class="muted">${diffs.length ? `${diffs.length} 项单独调整` : '跟随共同内容'}</span></span><span class="chevron">›</span></button></div>`;
      }).join('')}</section>
      <section class="local-panel"><div class="local-header"><div><h3>${apps[app]}怎样使用这份内容</h3><p class="muted">单独调整只在这份内容适用时发生。</p></div>${button('为此应用单独调整','local',`data-rule="${rule.id}" data-app="${app}"`,'small')}</div>
      ${differences.length ? differences.map(diff => {
        const applies = diff.networks.some(network => contexts(app,diff.domain,network).some(context => rule.enabled && matches(rule.expr,context)));
        return `<div class="difference-card"><div><strong>${esc(diff.domain)} · 单独${actions[diff.action]}</strong><p class="muted">${diff.networks.map(network => networks[network]).join('、')} · ${!applies ? '当前共同条件不适用，调整暂不起作用' : diff.action === rule.action ? '与当前共同动作相同，仍保留为单独设置' : `共同内容为${actions[rule.action]}`}</p></div><div class="actions">${button('修改','local',`data-rule="${rule.id}" data-app="${app}" data-domain="${esc(diff.domain)}"`,'small')}${button('恢复跟随','restore',`data-rule="${rule.id}" data-modifier="${diff.id}"`,'small')}</div></div>`;
      }).join('') : `<div class="follows-line">${icon('link')}没有单独调整，跟随当前共同内容。</div>`}
      ${['wifi','mobile'].map(network => {
        const context = fact(app,'api.weather.example',network);
        const outcome = evaluate(context);
        return `<div class="scope-result"><div><strong>api.weather.example</strong><span class="muted"> · ${networks[network]} · TCP 443</span><p class="result-source">当前采用：${sourceLabel(outcome)}</p></div>${result(outcome.action)}</div>`;
      }).join('')}
      <div class="foot-row">${button('核对几种情况','checks','','quiet')}${button('看应用活动','app',`data-app="${app}"`,'quiet')}</div></section></div>`;
  }

  function renderHome() {
    return `<div class="page-intro"><div><h1>我的网络</h1><p>最近一小时，应用已有的活动与流量。</p></div><span class="pill blue">最近一小时</span></div>
      <div class="home-total">2.4<span>MB · 样例连接流量</span></div><div class="home-chart" aria-label="样例流量曲线">${[20,32,26,57,47,22,34,72,89,63,42,35,67,92,50,37,24,48,76,55,25,17].map(n => `<i style="height:${n}%"></i>`).join('')}</div>
      <div class="section-head"><h3>同一时段的应用</h3><span class="muted">点应用看实际活动</span></div>
      ${Object.keys(apps).map(app => `<button class="library-link" data-action="app" data-app="${app}">${avatar(app)}<div><strong>${apps[app]}</strong><div class="muted">${state.records.filter(record => record.context.app === app).length} 条样例连接记录</div></div>${icon('arrow')}</button>`).join('')}`;
  }

  function renderApp() {
    const app = selectedApp;
    const records = state.records.filter(record => record.context.app === app);
    const outcome = summary(app,'api.weather.example','wifi');
    return `<div class="page-intro"><div><div class="app-person">${avatar(app)}<h1>${apps[app]}</h1></div><p>已有连接与活动 · 最近一小时</p></div><div class="page-actions">${button(variant === 'A' ? '改变联网结果' : '单独调整','app-edit',`data-app="${app}"`,'primary')}</div></div>
      <div class="app-scope-summary"><h3>当前联网安排</h3><p class="muted">api.weather.example · Wi-Fi：${actions[outcome.action] || '随完整情况变化'}。${sourceLabel(outcome)}</p><div class="foot-row">${button('去规则Tab修改共同内容','app-shared','','quiet')}</div></div>
      <div class="section-head"><h3>已有活动</h3><span class="muted">记录保留当时的判断</span></div>
      ${records.map(record => `<button class="library-link app-flow-row" data-action="record" data-record="${record.id}"><div><div class="target-name">${esc(record.context.domain)}</div><div class="flow-meta">${record.time} · ${networks[record.context.network]} · ${record.context.protocol.toUpperCase()} ${record.context.port}${record.context.domain.startsWith('203.') ? ' · 名称未识别' : ''}</div><div class="flow-meta">${record.action === 'deny' ? '拦截记录' : record.sampled ? '放行记录 · 传输未模拟' : '有传输'} · 当时版本 ${record.version}</div></div><span class="flow-bytes">${record.bytes === null ? '—' : record.bytes === 0 ? '0 B' : `${(record.bytes / 1024).toFixed(0)} KB`}</span></button>`).join('')}
      <p class="tip">修改当前安排不会生成新活动。记录上的字节属于这一条样例连接。</p>`;
  }

  function renderSettings() {
    return `<div class="page-intro"><div><h1>设置</h1><p>本轮集中比较规则Tab的操作方式。</p></div></div><div class="settings-row"><strong>样例数据</strong><span>页内内存，刷新重置</span></div><div class="settings-row"><strong>当前版本</strong><span>${state.version}</span></div><div class="settings-row"><strong>样例默认</strong><span>没有匹配时允许</span></div><div class="foot-row">${button('查看样例状态','state','','quiet')}${button('核对几种情况','checks','','quiet')}</div>`;
  }

  function dialog(title, subtitle, body, footer, wide = false) {
    return `<div class="dialog-backdrop"><section class="dialog ${wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><header class="dialog-head"><div><h2 id="dialog-title">${title}</h2><p>${subtitle}</p></div><button class="icon-button" data-action="close" aria-label="关闭">${icon('close')}</button></header><div class="dialog-body">${body}</div><footer class="dialog-foot">${footer}</footer></section></div>`;
  }

  function openModal(next) {
    modal = next;
    renderModal();
    requestAnimationFrame(() => $('overlay-root').querySelector('[data-action="close"]')?.focus());
  }

  function openGoal(app = selectedApp, domain = 'api.weather.example') {
    openModal({type:'goal', step:'choose', app, domain, networks:['wifi','mobile'], desired:state.scenario === 'inverse' ? 'deny' : 'allow', proposals:[], selected:[]});
  }

  function addModifier(source, proposal) {
    const rule = source.rules.find(rule => rule.id === proposal.rule);
    rule.modifiers = rule.modifiers.flatMap(modifier => {
      if (modifier.app !== proposal.app || modifier.domain !== proposal.domain) return [modifier];
      const remaining = modifier.networks.filter(network => !proposal.networks.includes(network));
      return remaining.length ? [{...modifier,networks:remaining}] : [];
    });
    rule.modifiers.push({id:`m${serial++}`,app:proposal.app,domain:proposal.domain,networks:clone(proposal.networks),action:proposal.action});
  }

  function applyProposals(source, proposals) {
    proposals.forEach(proposal => {
      if (proposal.kind === 'modifier') addModifier(source,proposal);
      else source.rules.push({id:proposal.id,name:proposal.name,action:proposal.action,priority:200,order:serial++,enabled:true,modifiers:[],expr:group('and',[leaf('app',[proposal.app]),leaf('domain',proposal.domain),group('or',proposal.networks.map(network => leaf('network',network)))])});
    });
    return source;
  }

  function planGoal() {
    if (!modal.domain.trim() || !modal.networks.length) return notify('请填写目标，并选择网络');
    modal.domain = modal.domain.trim();
    const wrong = new Map();
    modal.networks.forEach(network => contexts(modal.app,modal.domain,network).forEach(context => {
      const outcome = evaluate(context);
      if (outcome.action === modal.desired) return;
      const key = outcome.id || 'default';
      if (!wrong.has(key)) wrong.set(key,new Set());
      wrong.get(key).add(network);
    }));
    modal.proposals = [...wrong].map(([id,nets],index) => id === 'default' ? {
      kind:'new',id:`new${serial++}`,name:`${apps[modal.app]} · ${modal.domain}`,app:modal.app,domain:modal.domain,networks:[...nets],action:modal.desired,key:index,
    } : {kind:'modifier',rule:id,app:modal.app,domain:modal.domain,networks:[...nets],action:modal.desired,key:index});
    modal.selected = modal.proposals.map(item => item.key);
    modal.step = 'plan';
    renderModal();
  }

  function selectedPlan() { return modal.proposals.filter(item => modal.selected.includes(item.key)); }
  function previewPlan() { return applyProposals(clone(state),selectedPlan()); }
  function planAchieved(source) { return modal.networks.every(network => summary(modal.app,modal.domain,network,source).action === modal.desired); }

  function compareRows(before,after,app,domain,nets = ['wifi','mobile']) {
    return `<div class="compare-label"><span>核对当前政策结果</span><span>修改前 → 修改后</span></div><div class="compare-list">${nets.map(network => {
      const a = summary(app,domain,network,before), b = summary(app,domain,network,after);
      return `<div class="compare-row ${a.action !== b.action ? 'changed' : ''}"><div>${apps[app]} · ${networks[network]}<p class="small muted">${sourceLabel(b)}</p></div><span>${actions[a.action] || '因情况而异'}</span><span>→</span><span>${actions[b.action] || '因情况而异'}</span></div>`;
    }).join('')}</div>`;
  }

  function goalDialog() {
    const choose = modal.step === 'choose';
    const overview = `${person(modal.app)}<div class="target-name">${esc(modal.domain || '输入目标')}</div><p class="muted small">只改变所选应用。其他应用保留各自的安排。</p><div class="goal-scope">${modal.networks.map(network => networks[network]).join('、')} · 希望${actions[modal.desired]}</div>`;
    if (choose) return dialog('你希望怎样联网？','选择应用、目标和希望的结果。',`<div class="goal-layout"><div class="goal-overview">${overview}</div><div><div class="field"><label for="goal-app">应用</label><select id="goal-app" data-field="app">${Object.entries(apps).map(([app,name]) => `<option value="${app}" ${app === modal.app ? 'selected' : ''}>${name}</option>`).join('')}</select></div><div class="field"><label for="goal-domain">目标</label><input id="goal-domain" data-field="domain" value="${esc(modal.domain)}" spellcheck="false" autocomplete="off"></div><div class="field"><label>网络</label><div class="chips">${Object.entries(networks).map(([network,label]) => `<button class="${modal.networks.includes(network) ? 'selected' : ''}" data-action="goal-network" data-network="${network}">${label}</button>`).join('')}</div></div>${actionChoices(modal.desired,'goal-action')}</div></div>`,`<span class="muted">下一步先看所需修改与其他应用的结果。</span><div class="actions">${button('取消','close')}${button('看看需要怎样改','goal-plan','','primary')}</div>`);
    const preview = previewPlan(), achieved = planAchieved(preview);
    return dialog('为这个结果，需要这些修改',`${apps[modal.app]} · ${esc(modal.domain)} · 希望${actions[modal.desired]}`,`<div class="goal-layout"><div class="goal-overview">${overview}${compareRows(state,preview,modal.app,modal.domain,modal.networks)}<p class="tip">这是政策核对，允许不代表已经传输成功。</p></div><div><h3>${modal.proposals.length ? '只修改需要改变的内容' : '当前已经是希望的结果'}</h3>
      ${modal.proposals.map(proposal => {
        const rule = state.rules.find(rule => rule.id === proposal.rule);
        return `<label class="plan-row"><input type="checkbox" data-plan="${proposal.key}" ${modal.selected.includes(proposal.key) ? 'checked' : ''}><div><strong>${proposal.kind === 'new' ? '新增这条专属内容' : `在“${esc(rule.name)}”中单独调整`}</strong><div class="arrow-change"><span>${apps[proposal.app]} · ${proposal.networks.map(network => networks[network]).join('、')}</span><span>→</span><strong>${actions[proposal.action]}</strong></div><p class="muted">${proposal.kind === 'new' ? '明确的应用与目标条件；放在优先级 200。' : '保留共同内容、其他应用和原优先级；只在原内容适用时调整动作。'}</p></div></label>`;
      }).join('')}
      <div class="section-head"><h3>其他应用</h3><span class="muted">同一目标 · 所选网络</span></div>${Object.keys(apps).filter(app => app !== modal.app).map(app => compareRows(state,preview,app,modal.domain,modal.networks)).join('')}
      <div class="notice ${achieved ? 'green' : 'amber'}">${icon(achieved ? 'check' : 'info')}<div><strong>${achieved ? '所选网络下的希望结果都已满足' : '只应用所选修改，仍有情况达不到希望结果'}</strong>${achieved ? '提交后直接看当前结果，仍能找到刚修改的原内容。' : '核对上面的修改前后结果。取消选中不会被当作已经允许。'}</div></div></div></div>`,`<span class="muted">选择哪些修改，就提交哪些修改。</span><div class="actions">${button('返回调整','goal-back')}${button(!modal.proposals.length ? '完成' : achieved ? `应用修改，${actions[modal.desired]}此目标` : '仅应用所选修改','goal-commit','','primary')}</div>`,true);
  }

  function actionChoices(value,action) {
    return `<div class="field"><label>动作</label><div class="choice-row">${['allow','deny'].map(item => `<button class="choice ${item} ${value === item ? 'selected' : ''}" data-action="${action}" data-value="${item}">${icon(item === 'allow' ? 'check' : 'deny')}${actions[item]}访问</button>`).join('')}</div></div>`;
  }

  function openLocal(ruleId = activeRule,app = selectedApp,domain = 'api.weather.example') {
    const rule = state.rules.find(rule => rule.id === ruleId);
    const existing = rule.modifiers.find(m => m.app === app && m.domain === domain);
    openModal({type:'local',rule:ruleId,app,domain,desired:existing?.action || (rule.action === 'deny' ? 'allow' : 'deny'),networks:existing ? clone(existing.networks) : ['wifi','mobile']});
  }

  function localDialog() {
    const rule = state.rules.find(rule => rule.id === modal.rule);
    return dialog(`只调整${apps[modal.app]}`,`共同内容：${esc(rule.name)} · 其他应用保持原样`,`${person(modal.app)}<div class="field" style="margin-top:20px"><label for="local-domain">目标</label><input id="local-domain" data-field="domain" value="${esc(modal.domain)}" spellcheck="false"></div><div class="field"><label>网络</label><div class="chips">${Object.entries(networks).map(([network,label]) => `<button class="${modal.networks.includes(network) ? 'selected' : ''}" data-action="goal-network" data-network="${network}">${label}</button>`).join('')}</div></div>${actionChoices(modal.desired,'goal-action')}
      <p class="muted small">共同动作为${actions[rule.action]}。本次调整属于这份内容，沿用它的优先级。</p><div id="local-preview">${localPreview()}</div>`,
      `<span class="muted">保存调整后，看清当前真正采用的结果。</span><div class="actions">${button('取消','close')}${button('保存单独调整','local-save','','primary')}</div>`);
  }

  function localPreview() {
    const rule = state.rules.find(rule => rule.id === modal.rule);
    const proposal = {kind:'modifier',rule:rule.id,app:modal.app,domain:modal.domain,networks:modal.networks,action:modal.desired};
    const preview = applyProposals(clone(state),[proposal]);
    const hiddenByOther = modal.networks.map(network => ({network,outcome:evaluate(fact(modal.app,modal.domain,network),preview)})).filter(item => item.outcome.id !== rule.id);
    return `${compareRows(state,preview,modal.app,modal.domain)}${hiddenByOther.map(item => `<div class="notice amber" style="margin-top:10px">${icon('info')}<div><strong>${networks[item.network]}下当前采用“${esc(item.outcome.name)}”</strong>这份单独调整不会覆盖更优先的内容。${item.outcome.id ? `<button class="button quiet small" data-action="shared" data-rule="${item.outcome.id}">去修改${esc(item.outcome.name)}</button>` : '当前共同内容不适用。'}</div></div>`).join('')}`;
  }

  function openShared(id,fromApp = false) {
    const rule = state.rules.find(rule => rule.id === id);
    openModal({type:'shared',rule:id,draft:clone(rule),returnApp:fromApp,subview:'simple'});
  }

  function sharedDialog() {
    const draft = modal.draft;
    const preview = clone(state);
    const index = preview.rules.findIndex(rule => rule.id === draft.id);
    if (index === -1) preview.rules.push(clone(draft)); else preview.rules[index] = clone(draft);
    const members = relevantApps(draft,preview);
    return dialog(modal.type === 'new' ? '写一份新的内容' : '修改共同内容',`${esc(draft.name)} · 作用范围由完整条件决定`,
      `<div class="fields-two"><div class="field"><label for="shared-name">名称</label><input id="shared-name" data-field="name" value="${esc(draft.name)}"></div><div class="field"><label for="shared-priority">优先级 · 较小值先判断</label><input id="shared-priority" type="number" min="0" max="10000" data-field="priority" value="${draft.priority}"></div></div>
      ${actionChoices(draft.action,'shared-action')}<div class="condition-preview"><strong>完整内容读法</strong><p id="condition-read" style="margin-top:7px">${actions[draft.action]}满足以下条件的连接：${esc(titleText(draft.expr))}。</p></div>
      <div class="field"><label>当前条件可能作用的应用</label><div class="people" id="shared-members">${members.map(chip).join('') || '<span class="muted small">没有样例应用符合条件</span>'}</div></div>
      ${modal.subview === 'tree' ? `<h3>完整条件</h3>${renderTree(draft.expr)}<p class="tip">应用也是条件。一支中的应用选择不会偷偷限制另一支。</p>` : `${button('编辑完整条件','tree-open','','small')}${draft.id === 'privacy' ? ` ${button('编辑名单 L','list','','small')}` : ''}`}
      <label class="checkbox-line"><input type="checkbox" data-field="enabled" ${draft.enabled ? 'checked' : ''}>保存后使用；取消选中可保存待用</label>
      ${draft.modifiers.length ? `<div class="notice">${icon('link')}<div><strong>保留 ${draft.modifiers.length} 项单独调整</strong>共同动作改变后，明确设置的单独动作继续保留；恢复跟随后采用新的共同内容。条件不再适用时，调整暂不起作用。</div></div>` : ''}
      <div class="section-head"><h3>修改前后</h3><span class="muted">api.weather.example · Wi-Fi与移动网络</span></div><div id="shared-preview">${Object.keys(apps).map(app => compareRows(state,preview,app,'api.weather.example')).join('')}</div>`,
      `<span class="muted">${modal.returnApp ? '保存后回到发起应用；共同修改仍按全部作用对象执行。' : '此处修改共同内容，包括当前应用以外的作用对象。'}</span><div class="actions">${button('取消','close')}${button(draft.enabled ? '保存并使用' : '保存待用','shared-save','','primary')}</div>`,true);
  }

  const fieldLabels = {app:'应用',domain:'目标域名',list:'域名名单',network:'网络',protocol:'协议',port:'目标端口'};
  function renderTree(node,root = true) {
    if (node.op) return `<div class="tree-box"><div class="tree-heading"><strong>${node.op === 'and' ? '以下全部满足（AND）' : node.op === 'or' ? '以下任一种满足（OR）' : '以下情况不满足（NOT）'}</strong><div class="tree-actions">${node.op === 'not' ? '' : `<button data-action="tree-op" data-node="${node.id}" data-op="${node.op === 'and' ? 'or' : 'and'}">改为${node.op === 'and' ? '任一种' : '全部'}</button><button data-action="tree-add" data-node="${node.id}">加条件</button><button data-action="tree-group" data-node="${node.id}">加一组情况</button>`}<button data-action="tree-not" data-node="${node.id}">${node.op === 'not' ? '去掉NOT' : '套入NOT'}</button>${root ? '' : `<button data-action="tree-delete" data-node="${node.id}">移除</button>`}</div></div>${node.children.map(child => renderTree(child,false)).join('')}</div>`;
    const options = node.field === 'app' ? Object.entries(apps) : node.field === 'network' ? Object.entries(networks) : node.field === 'protocol' ? [['tcp','TCP'],['udp','UDP']] : node.field === 'list' ? [['L','名单 L']] : null;
    return `<div class="tree-leaf"><select aria-label="条件类型" data-tree-field="${node.id}">${Object.entries(fieldLabels).map(([field,label]) => `<option value="${field}" ${field === node.field ? 'selected' : ''}>${label}</option>`).join('')}</select>
      ${options ? `<select aria-label="${fieldLabels[node.field]}条件值" ${node.field === 'app' ? 'multiple size="3"' : ''} data-tree-value="${node.id}">${options.map(([value,label]) => `<option value="${value}" ${(Array.isArray(node.value) ? node.value.includes(value) : value === node.value) ? 'selected' : ''}>${label}</option>`).join('')}</select>` : `<input aria-label="${fieldLabels[node.field]}条件值" data-tree-value="${node.id}" type="${node.field === 'port' ? 'number' : 'text'}" ${node.field === 'port' ? 'min="1" max="65535"' : ''} value="${esc(node.value)}">`}
      <div class="tree-actions"><button data-action="tree-not" data-node="${node.id}">NOT</button>${root ? `<button data-action="tree-wrap" data-node="${node.id}">添加组合</button>` : `<button data-action="tree-delete" data-node="${node.id}">移除</button>`}</div></div>`;
  }

  function findNode(root,id) {
    if (root.id === id) return root;
    for (const child of root.children || []) { const found = findNode(child,id); if (found) return found; }
    return null;
  }
  function replaceNode(root,id,replacement) {
    if (root.id === id) return replacement;
    if (root.children) root.children = root.children.map(child => replaceNode(child,id,replacement)).filter(Boolean);
    return root;
  }

  function checksDialog() {
    const rows = modal.rows.map((row,index) => {
      const outcome = evaluate(row);
      const correct = row.expected === 'unspecified' || row.expected === outcome.action;
      return `<tr><td><select aria-label="情况${index+1}应用" data-check="${index}:app">${Object.entries(apps).map(([app,label]) => `<option value="${app}" ${row.app === app ? 'selected' : ''}>${label}</option>`).join('')}</select><input aria-label="情况${index+1}目标" data-check="${index}:domain" value="${esc(row.domain)}"><div class="check-context"><select aria-label="情况${index+1}网络" data-check="${index}:network">${Object.entries(networks).map(([net,label]) => `<option value="${net}" ${row.network === net ? 'selected' : ''}>${label}</option>`).join('')}</select><select aria-label="情况${index+1}协议" data-check="${index}:protocol"><option ${row.protocol === 'tcp' ? 'selected' : ''} value="tcp">TCP</option><option ${row.protocol === 'udp' ? 'selected' : ''} value="udp">UDP</option></select><input aria-label="情况${index+1}端口" type="number" min="1" max="65535" data-check="${index}:port" value="${row.port}"></div></td><td class="expected"><select aria-label="情况${index+1}希望结果" data-check="${index}:expected">${[['unspecified','未指定'],['allow','允许'],['deny','禁止']].map(([value,label]) => `<option ${row.expected === value ? 'selected' : ''} value="${value}">${label}</option>`).join('')}</select></td><td>${result(outcome.action)}<div class="case-key">${sourceLabel(outcome)}</div>${row.expected === 'unspecified' ? '' : `<span class="pill ${correct ? 'green' : 'amber'}">${correct ? '与希望一致' : '与希望不同'}</span>`}</td></tr>`;
    }).join('');
    return dialog('核对几种情况','假设这些连接发生，当前会怎样判断？',`<div class="notice">${icon('info')}<div>这些是假设情况，不会产生实际活动。少量例子帮助检查边界，不能证明所有未来连接。</div></div><table class="check-table"><thead><tr><th>情况</th><th class="expected">希望</th><th>当前结果</th></tr></thead><tbody>${rows}</tbody></table><div class="foot-row">${button('再加一种情况','check-add','','quiet')}</div>`,`<span class="muted">更改希望结果只用于核对，不会修改规则。</span><div class="actions">${button('完成核对','close','','primary')}</div>`,true);
  }

  function renderModal() {
    if (!modal) { $('overlay-root').innerHTML = ''; document.body.classList.remove('modal-open'); return; }
    document.body.classList.add('modal-open');
    const renderers = {
      goal:goalDialog, local:localDialog, shared:sharedDialog, new:sharedDialog, checks:checksDialog,
      complete:() => dialog(modal.title,'本次修改已完成',`<div class="plan-complete"><div class="complete-symbol">${icon('check')}</div><h2>${modal.title}</h2><p class="muted">${modal.message}</p></div>${modal.details || ''}`,`<span class="muted">当前版本 ${state.version}；过去的活动保留原判断。</span><div class="actions">${button('看当前结果','close','','primary')}</div>`),
      restore:() => {
        const rule = state.rules.find(rule => rule.id === modal.rule), diff = rule.modifiers.find(m => m.id === modal.modifier);
        const preview = clone(state); preview.rules.find(item => item.id === rule.id).modifiers = rule.modifiers.filter(item => item.id !== diff.id);
        return dialog('恢复跟随当前共同内容',`${apps[diff.app]} · ${esc(diff.domain)}`,`<div class="notice">${icon('link')}<div><strong>移除这项单独调整</strong>采用现在的共同内容：${actions[rule.action]}。不恢复到创建调整时的旧版本。</div></div>${compareRows(state,preview,diff.app,diff.domain,diff.networks)}`,`<span class="muted">其他单独调整保留。</span><div class="actions">${button('取消','close')}${button('恢复跟随','restore-save','','primary')}</div>`);
      },
      list:() => dialog('名单 L','共同材料 · 修改会作用于使用此名单的全部内容',`<div class="field"><label for="list-items">每行一个完整域名</label><textarea id="list-items" data-field="items" rows="6">${esc(modal.items.join('\n'))}</textarea></div><div class="notice">${icon('info')}<div>移除目标后，依赖名单条件的单独调整暂不起作用；加回目标时它仍然保留。</div></div><div class="section-head"><h3>当前引用这份名单</h3></div><div class="people">${state.rules.filter(rule => { let found=false; eachNode(rule.expr,node => {if(node.field === 'list' && node.value === 'L') found=true;}); return found; }).map(rule => `<span class="person-chip">${esc(rule.name)}</span>`).join('')}</div>`,`<span class="muted">这是共同名单维护。</span><div class="actions">${button('取消','close')}${button('保存名单','list-save','','primary')}</div>`),
      members:() => dialog('选择作用应用',`共同内容：${esc(state.rules.find(rule => rule.id === modal.rule).name)}`,`<p class="muted small">这是完整条件中的应用选择。移出应用会使其对应的单独调整暂不起作用；重新选入后保留。</p>${Object.entries(apps).map(([app,name]) => `<label class="checkbox-line">${avatar(app)}<input type="checkbox" data-member="${app}" ${modal.members.includes(app) ? 'checked' : ''}>${name}</label>`).join('')}`,`<span class="muted">新加入应用跟随共同内容，不复制其他应用的调整。</span><div class="actions">${button('取消','close')}${button('保存作用应用','members-save','','primary')}</div>`),
      order:() => dialog('当前优先顺序','较小的优先级先判断；不是所有禁止都拥有否决权。',`<div class="notice">${icon('info')}<div>只采用第一项匹配内容。单独调整沿用所属内容的位置，没有自动升到最前。</div></div>${ordered().map((rule,index) => `<div class="order-row"><span class="order-num">${rule.priority}</span><div><strong>${esc(rule.name)}</strong><div class="muted">${rule.enabled ? '使用中' : '待用'} · ${actions[rule.action]} · ${esc(titleText(rule.expr))}</div></div><div class="moves"><button data-action="order-move" data-rule="${rule.id}" data-direction="-1" ${index === 0 ? 'disabled' : ''} aria-label="将${esc(rule.name)}提前">↑</button><button data-action="order-move" data-rule="${rule.id}" data-direction="1" ${index === state.rules.length-1 ? 'disabled' : ''} aria-label="将${esc(rule.name)}延后">↓</button></div></div>`).join('')}`,`<span class="muted">箭头是本次明确的顺序修改，立即更新样例。</span><div class="actions">${button('完成','close','','primary')}</div>`),
      state:() => dialog('样例状态','原型观察工具 · 所有修改都在内存中',`<pre class="state-json">${esc(JSON.stringify(state,null,2))}</pre>`,`<span class="muted">生成一次样例连接，才新增一条活动。</span><div class="actions">${button('生成天气样例连接','sample')}${button('关闭','close','','primary')}</div>`,true),
      record:() => {
        const record = state.records.find(record => record.id === modal.record);
        const now = evaluate(record.context);
        return dialog('这条活动当时怎样处理',`${apps[record.context.app]} · ${esc(record.context.domain)}`,`<div class="condition-preview">${networks[record.context.network]} · ${record.context.protocol.toUpperCase()} ${record.context.port} · ${record.time}</div><div class="section-head"><h3>当时版本 ${record.version}</h3>${result(record.action)}</div><p class="muted small">当时采用：${sourceLabel(record)}。${record.sampled ? '传输未模拟。' : `这一条连接的样例字节：${record.bytes} B。`}</p><div class="section-head"><h3>当前同一种情况</h3>${result(now.action)}</div><p class="muted small">当前采用：${sourceLabel(now)} · 版本 ${state.version}</p>`,`<span class="muted">当前修改不改写过去的判断。</span><div class="actions">${button('返回活动','close','','primary')}</div>`);
      },
    };
    $('overlay-root').innerHTML = renderers[modal.type]();
  }

  function complete(title,message,details = '') { openModal({type:'complete',title,message,details}); }

  function refreshDraftSummary() {
    const preview=clone(state), draft=modal.draft, index=preview.rules.findIndex(rule => rule.id === draft.id);
    if (index === -1) preview.rules.push(clone(draft)); else preview.rules[index]=clone(draft);
    $('condition-read').textContent=`${actions[draft.action]}满足以下条件的连接：${titleText(draft.expr)}。`;
    $('shared-members').innerHTML=relevantApps(draft,preview).map(chip).join('') || '<span class="muted small">没有样例应用符合条件</span>';
    $('shared-preview').innerHTML=Object.keys(apps).map(app => compareRows(state,preview,app,'api.weather.example')).join('');
  }

  document.addEventListener('click',event => {
    const element = event.target.closest('[data-action]');
    if (!element) return;
    const {action,app,domain,rule:ruleId,network,value,node:id} = element.dataset;
    const rule = state.rules.find(item => item.id === (ruleId || activeRule));
    switch (action) {
      case 'nav': view=element.dataset.view; modal=null; updateURL(); render(); break;
      case 'network': activeNetwork=network; render(); break;
      case 'goal': openGoal(app || selectedApp,domain); break;
      case 'goal-network': modal.networks = modal.networks.includes(network) ? modal.networks.filter(item => item !== network) : [...modal.networks,network]; renderModal(); break;
      case 'goal-action': modal.desired=value; renderModal(); break;
      case 'goal-plan': planGoal(); break;
      case 'goal-back': modal.step='choose'; renderModal(); break;
      case 'goal-commit': {
        const before=clone(state), proposals=selectedPlan(), achieved=planAchieved(previewPlan());
        if (proposals.length) { applyProposals(state,proposals); changed(`为${apps[modal.app]}${actions[modal.desired]}${modal.domain}，提交${proposals.length}项修改`); }
        const details=compareRows(before,state,modal.app,modal.domain,modal.networks);
        const title=achieved ? `当前已${actions[modal.desired]}这个目标` : '所选修改已保存';
        complete(title,achieved ? '所选网络下的政策结果符合希望。其他应用保持原样。' : '还有情况没有达到希望结果，可回到结果继续调整。',details); render(); break;
      }
      case 'close': {
        const parent=modal?.parent, returnApp=modal?.returnApp;
        modal=parent || null;
        if (returnApp) { view='app'; updateURL(); render(); } else renderModal();
        break;
      }
      case 'source': activeRule=ruleId; render(); break;
      case 'usage': selectedApp=app; render(); break;
      case 'local': openLocal(ruleId,app,domain); break;
      case 'local-save': {
        if (!modal.domain.trim() || !modal.networks.length) return notify('请填写目标，并选择网络');
        const before=clone(state);
        addModifier(state,{rule:modal.rule,app:modal.app,domain:modal.domain.trim(),networks:modal.networks,action:modal.desired});
        changed(`在${state.rules.find(item => item.id === modal.rule).name}中为${apps[modal.app]}单独${actions[modal.desired]}${modal.domain}`);
        const details=compareRows(before,state,modal.app,modal.domain,modal.networks);
        complete('单独调整已保存','共同内容和其他应用保持原样。下面显示当前真正采用的结果。',details); render(); break;
      }
      case 'shared': {
        const returnApp=view === 'app' || modal?.returnApp || false;
        if (view === 'app') { view='rules'; modal=null; updateURL(); render(); }
        openShared(ruleId || 'privacy',returnApp); break;
      }
      case 'shared-action': modal.draft.action=value; renderModal(); break;
      case 'shared-save': {
        const draft=modal.draft;
        if (!draft.name.trim() || !Number.isFinite(draft.priority) || draft.priority < 0) return notify('请填写名称与有效优先级');
        let valid=true;
        eachNode(draft.expr,node => { if (node.op && !node.children.length || node.field === 'domain' && !node.value.trim() || node.field === 'port' && (!Number.isInteger(Number(node.value)) || Number(node.value)<1 || Number(node.value)>65535)) valid=false; });
        if (!valid) return notify('请补全条件；每一组至少保留一个条件，端口为1到65535');
        const index=state.rules.findIndex(item => item.id === draft.id), returnApp=modal.returnApp;
        if (index === -1) state.rules.push(clone(draft)); else state.rules[index]=clone(draft);
        activeRule=draft.id; changed(`保存${draft.name}的共同内容${draft.enabled ? '并使用' : '待用'}`); modal=null;
        if (returnApp) view='app'; updateURL(); render(); notify(draft.enabled ? '共同内容已保存并使用，单独调整保留' : '内容已保存待用'); break;
      }
      case 'new': openModal({type:'new',draft:{id:`new${serial++}`,name:'新的联网内容',action:'deny',priority:150,order:serial++,enabled:true,modifiers:[],expr:group('and',[leaf('app',['weather']),leaf('list','L')])},subview:'tree'}); break;
      case 'pause': rule.enabled=!rule.enabled; changed(`${rule.enabled ? '使用' : '暂停'}${rule.name}`); render(); notify(rule.enabled ? '恢复使用，原有单独调整保留' : '已暂停；所属调整随此内容暂停'); break;
      case 'restore': openModal({type:'restore',rule:ruleId,modifier:element.dataset.modifier}); break;
      case 'restore-save': {
        const parent=state.rules.find(item => item.id === modal.rule);
        parent.modifiers=parent.modifiers.filter(item => item.id !== modal.modifier);
        changed(`恢复跟随${parent.name}的当前内容`); modal=null; render(); notify('已恢复跟随当前共同内容'); break;
      }
      case 'list': openModal({type:'list',items:clone(state.lists.L),parent:['shared','new'].includes(modal?.type) ? clone(modal) : null}); break;
      case 'list-save': {
        state.lists.L=[...new Set(modal.items.map(item => item.trim()).filter(Boolean))];
        changed('更新共同名单L'); modal=modal.parent || null; render();
        notify('共同名单已独立保存；单独调整保留'); break;
      }
      case 'members': {
        const node=membershipNode(rule);
        if (!node) { openShared(ruleId); modal.subview='tree'; renderModal(); break; }
        openModal({type:'members',rule:ruleId,members:clone(node.value)}); break;
      }
      case 'members-save': {
        const parent=state.rules.find(item => item.id === modal.rule);
        membershipNode(parent).value=clone(modal.members); changed(`更新${parent.name}的作用应用`); modal=null; render(); notify('作用应用已保存，新应用跟随共同内容'); break;
      }
      case 'tree-open': modal.subview='tree'; renderModal(); break;
      case 'tree-op': findNode(modal.draft.expr,id).op=element.dataset.op; renderModal(); break;
      case 'tree-add': findNode(modal.draft.expr,id).children.push(leaf('domain','other.example')); renderModal(); break;
      case 'tree-group': findNode(modal.draft.expr,id).children.push(group('and',[leaf('network','wifi'),leaf('protocol','udp')])); renderModal(); break;
      case 'tree-wrap': modal.draft.expr=group('and',[modal.draft.expr,leaf('domain','other.example')]); renderModal(); break;
      case 'tree-not': {
        const node=findNode(modal.draft.expr,id);
        modal.draft.expr=replaceNode(modal.draft.expr,id,node.op === 'not' ? node.children[0] : group('not',[clone(node)])); renderModal(); break;
      }
      case 'tree-delete': {
        let parent=null; eachNode(modal.draft.expr,node => {if(node.children?.some(child => child.id === id)) parent=node;});
        if (parent.children.length<2) return notify('每组至少保留一个条件；可以移除整组');
        modal.draft.expr=replaceNode(modal.draft.expr,id,null); renderModal(); break;
      }
      case 'order': openModal({type:'order'}); break;
      case 'order-move': {
        const current=ordered(), index=current.findIndex(item => item.id === ruleId), target=index+Number(element.dataset.direction);
        [current[index],current[target]]=[current[target],current[index]];
        current.forEach((item,i) => {item.priority=(i+1)*20;item.order=i;});
        changed(`明确调整${rule.name}的优先顺序`); render(); break;
      }
      case 'checks': openModal({type:'checks',rows:[{...fact('weather','api.weather.example'),expected:'allow'},{...fact('weather','api.weather.example','mobile'),expected:'allow'},{...fact('music','other.example','wifi','udp'),expected:'unspecified'},{...fact('reader','metrics.example','mobile'),expected:'deny'}]}); break;
      case 'check-add': modal.rows.push({...fact('weather','other.example'),expected:'unspecified'}); renderModal(); break;
      case 'app': selectedApp=app; view='app'; modal=null; updateURL(); render(); break;
      case 'app-edit': variant === 'A' ? openGoal(app) : openLocal('privacy',app); break;
      case 'app-shared': view='rules'; activeRule='privacy'; updateURL(); render(); openShared('privacy',true); break;
      case 'state': openModal({type:'state'}); break;
      case 'sample': {
        const context=fact('weather','api.weather.example','wifi'), outcome=evaluate(context);
        state.records.unshift({id:`e${serial++}`,context,...outcome,time:'刚刚',bytes:outcome.action === 'deny' ? 0 : null,sampled:true});
        render(); notify('已新增一条明确生成的样例连接记录'); break;
      }
      case 'record': openModal({type:'record',record:element.dataset.record}); break;
    }
  });

  document.addEventListener('input',event => {
    if (!modal) return;
    if (modal.draft && event.target.dataset.treeValue && event.target.tagName === 'INPUT') {
      const node=findNode(modal.draft.expr,event.target.dataset.treeValue);
      node.value=node.field === 'port' ? Number(event.target.value) : event.target.value;
      refreshDraftSummary(); return;
    }
    const field=event.target.dataset.field;
    if (!field || event.target.tagName === 'SELECT' || event.target.type === 'checkbox') return;
    if (field === 'items') modal.items=event.target.value.split('\n');
    else if (modal.draft) modal.draft[field]=field === 'priority' ? Number(event.target.value) : event.target.value;
    else modal[field]=event.target.value;
    if (modal.type === 'local' && field === 'domain') $('local-preview').innerHTML=localPreview();
    if (modal.draft && field === 'priority') refreshDraftSummary();
  });

  document.addEventListener('change',event => {
    if (!modal) return;
    const element=event.target;
    if (element.dataset.field) {
      const target=modal.draft || modal;
      target[element.dataset.field]=element.dataset.field === 'items' ? element.value.split('\n') : element.type === 'checkbox' ? element.checked : element.dataset.field === 'priority' ? Number(element.value) : element.value;
      if (element.tagName === 'SELECT' || element.type === 'checkbox') renderModal();
    } else if (element.dataset.plan) {
      const key=Number(element.dataset.plan);
      modal.selected=element.checked ? [...modal.selected,key] : modal.selected.filter(item => item !== key); renderModal();
    } else if (element.dataset.member) {
      const app=element.dataset.member;
      modal.members=element.checked ? [...modal.members,app] : modal.members.filter(item => item !== app); renderModal();
    } else if (element.dataset.treeField) {
      const node=findNode(modal.draft.expr,element.dataset.treeField);
      node.field=element.value; node.value={app:['weather'],domain:'other.example',list:'L',network:'wifi',protocol:'tcp',port:443}[node.field]; renderModal();
    } else if (element.dataset.treeValue) {
      const node=findNode(modal.draft.expr,element.dataset.treeValue);
      node.value=node.field === 'app' ? [...element.selectedOptions].map(option => option.value) : node.field === 'port' ? Number(element.value) : element.value;
      if (element.tagName === 'INPUT') refreshDraftSummary(); else renderModal();
    } else if (element.dataset.check) {
      const [index,field]=element.dataset.check.split(':');
      modal.rows[Number(index)][field]=field === 'port' ? Number(element.value) : element.value; renderModal();
    }
  });

  document.addEventListener('keydown',event => {
    if (event.key === 'Escape' && modal) { $('overlay-root').querySelector('[data-action="close"]')?.click(); return; }
    if (event.key === 'Tab' && modal) {
      const focusable=[...$('overlay-root').querySelectorAll('button:not(:disabled),input,select,textarea,a[href],[tabindex="0"]')];
      const first=focusable[0], last=focusable[focusable.length-1];
      if (!$('overlay-root').contains(document.activeElement)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
    if (['ArrowLeft','ArrowRight'].includes(event.key) && !event.target.closest('input,select,textarea,[contenteditable]')) {
      event.preventDefault(); switchVariant(variant === 'A' ? 'B' : 'A');
    }
    if ((event.key === 'Enter' || event.key === ' ') && event.target.matches('[role="button"][data-action]')) { event.preventDefault(); event.target.click(); }
  });

  $('prev-variant').addEventListener('click',() => switchVariant(variant === 'A' ? 'B' : 'A'));
  $('next-variant').addEventListener('click',() => switchVariant(variant === 'A' ? 'B' : 'A'));
  document.querySelectorAll('[data-variant]').forEach(element => element.addEventListener('click',() => switchVariant(element.dataset.variant)));
  $('scenario').addEventListener('change',event => reset(event.target.value));
  $('reset').addEventListener('click',() => { reset($('scenario').value); notify('当前案例已重置'); });
  window.addEventListener('popstate',() => {
    const params=new URLSearchParams(location.search); variant=params.get('variant') === 'B' ? 'B' : 'A'; view=params.get('view') || 'rules'; modal=null; render();
  });
  // Read-only review access. No Product API and no persisted intent store.
  window.v4 = {getState:() => clone(state), evaluate:context => clone(evaluate(context)), summary:(app,domain,network) => clone(summary(app,domain,network)), getModal:() => clone(modal)};
  reset('privacy'); updateURL();
})();
