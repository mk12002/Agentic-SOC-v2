// CyberDome (NAM build): Dome Comply, the pilot scorecard, the Dome Score weights and cross-tool cases.
// Every figure is the server's; the console only lays them out. Loaded after views.js.

// ================================================================= Dome Score weights (on the Dome Score screen)
const DOMAIN_ORDER = ['identity', 'privileged_access', 'endpoint', 'data_protection', 'web'];
const DOMAIN_LABEL = {identity: 'Identity', privileged_access: 'Privileged access', endpoint: 'Endpoint', data_protection: 'Data protection', web: 'Web (WAF)'};
async function weightsCard() {
  const el = $('#ciso-weights'); if (!el) return;
  const w = await api('/api/v1/posture/weights');
  window.__w = w;
  const mayPropose = (can('approve_policy') || can('propose_policy')) && inDomain('*');
  const total = DOMAIN_ORDER.reduce((a, d) => a + w.active.weights[d], 0) || 1;
  const bars = DOMAIN_ORDER.map(d => `<div class="list-row small"><span style="min-width:130px">${esc(DOMAIN_LABEL[d])}</span><div class="grow">${scoreBar(100 * w.active.weights[d] / total)}</div><span class="score">${esc(w.active.weights[d])}</span></div>`).join('');
  const pens = Object.entries(w.active.penalties).map(([k, v]) => `<div class="list-row small"><span class="grow">${esc(w.penalty_labels[k] || k)}</span><span class="muted">-${esc(v.points)} each, at most -${esc(v.cap)}</span></div>`).join('');
  const p = w.pending;
  const pend = p ? `<div class="callout info stackc" style="margin-top:10px"><div class="small strong">Proposed by ${esc(p.proposed_by)}: ${esc(p.reason)}</div>
      <div class="small">${DOMAIN_ORDER.map(d => `${esc(DOMAIN_LABEL[d])} ${esc(w.active.weights[d])} → <b>${esc(p.document.weights[d])}</b>`).join(' · ')}</div>
      <div class="small">Score now ${esc(p.preview.current.score ?? '–')} → <b>${esc(p.preview.proposed.score ?? '–')}</b> under the proposed weights</div>
      <div class="inline" style="gap:6px;margin-top:6px">${can('approve_policy') && p.proposed_by !== ME.id ? btn('Approve', 'wStep', [p.id, 'approve'], 'sm primary') + btn('Reject', 'wStep', [p.id, 'reject'], 'sm') : ''}${p.proposed_by === ME.id ? btn('Withdraw', 'wStep', [p.id, 'reject'], 'sm') : ''}</div></div>` : '';
  const editor = mayPropose && !p ? `<details style="margin-top:10px"><summary class="small strong">Change the weights</summary>
      <div class="grid g-5" style="margin-top:8px">${DOMAIN_ORDER.map(d => `<label class="small">${esc(DOMAIN_LABEL[d])}<input class="input sm" type="number" min="0" max="100" step="1" id="w-${d}" value="${esc(w.active.weights[d])}" aria-label="Weight of ${esc(DOMAIN_LABEL[d])}"></label>`).join('')}</div>
      <div class="grid g-5" style="margin-top:8px">${Object.entries(w.active.penalties).map(([k, v]) => `<label class="small" title="${esc(w.penalty_labels[k] || k)}">${esc((w.penalty_labels[k] || k).split(' (')[0])}<span class="inline" style="gap:4px"><input class="input sm" type="number" min="0" max="25" id="wp-${k}" value="${esc(v.points)}" aria-label="Points per item: ${esc(w.penalty_labels[k] || k)}"><input class="input sm" type="number" min="0" max="50" id="wc-${k}" value="${esc(v.cap)}" aria-label="Cap: ${esc(w.penalty_labels[k] || k)}"></span></label>`).join('')}</div>
      <input class="input" style="margin-top:8px;width:100%" maxlength="2000" id="w-reason" placeholder="Why the weights should change (shown to the approver)" aria-label="Reason for the change">
      <div class="inline" style="gap:6px;margin-top:6px">${btn('Preview', 'wPreview', [], 'sm')}${btn('Propose', 'wPropose', [], 'sm primary')}<span id="w-preview" class="small"></span></div>
      <div class="t-sub">Penalties: points per item, then the cap. A second lead approves; the score uses the new weights from then on.</div></details>` : '';
  el.innerHTML = card('Score formula', `<div class="small" style="margin-bottom:6px">Weights ${w.source.version ? `agreed: version ${esc(w.source.version)}, approved by ${esc(w.source.approved_by)} ${dt(w.source.approved_at)}` : '<b>draft</b> - to be agreed with the CISO'}. Only measured domains count; their weights are renormalised.</div>
    ${bars}<div class="t-sub" style="margin:8px 0 2px">Points taken off</div>${pens}${pend}${editor}`, {sub: 'weights per domain'});
}
function wDoc() {
  const weights = Object.fromEntries(DOMAIN_ORDER.map(d => [d, Number($('#w-' + d).value)]));
  const penalties = Object.fromEntries(Object.keys(window.__w.active.penalties).map(k => [k, {points: Number($('#wp-' + k).value), cap: Number($('#wc-' + k).value)}]));
  return {weights, penalties};
}
async function wPreview() {
  const r = await post('/api/v1/posture/weights/preview', {document: wDoc()});
  $('#w-preview').textContent = `Score now ${r.current.score ?? '–'} → ${r.proposed.score ?? '–'} under these weights`;
}
async function wPropose() {
  await post('/api/v1/posture/weights', {document: wDoc(), reason: $('#w-reason').value});
  toast('Proposed: a second lead approves it'); weightsCard();
}
async function wStep(id, verb) {
  await post(`/api/v1/posture/weights/${id}/${verb}`, {note: verb === 'reject' ? 'Not agreed' : ''});
  toast(verb === 'approve' ? 'Approved: the Dome Score uses the new weights' : 'Done'); render();
}

// ================================================================= cross-tool cases (on the Dome Score screen)
async function crossCard() {
  const el = $('#ciso-cross'); if (!el) return;
  let x;
  try { x = await api('/api/v1/crosstool'); } catch (e) { el.innerHTML = ''; return; }
  el.innerHTML = card('Cross-tool cases', x.cases.map(c => `<div class="list-row click" data-fn="goTo" data-args="${arg('#/cases/' + c.case_id)}">${chip(c.severity)}<div class="grow"><div class="t-title">${esc(c.title)}</div>
    <div class="t-sub">${esc(c.rules.map(r => r.id + ' ' + r.text).join(' · '))}</div><div class="t-sub">${esc(c.tools.map(toolName).join(' + '))} · ${esc(cap(c.status))}</div></div></div>`).join('')
    || empty('No person has signals from two or more tools.'), {sub: 'one case per person; severity from how many tools agree'});
}

// ================================================================= pilot scorecard
const PILOT_K = {met: 'ok', improving: 'info', not_improved: 'high', no_baseline: 'medium', no_target: 'medium', no_data: 'info', not_met: 'high'};
const fmtU = (v, u) => v == null ? '–' : u === '%' ? v + '%' : u === 'USD' ? '$' + Number(v).toFixed(4) : nf(v) + (u ? ' ' + u : '');
async function Pilot() {
  const __g = GEN;
  const [sc, outs] = await Promise.all([api('/api/v1/pilot'), api('/api/v1/pilot/outages')]);
  const lead = can('approve_policy');
  const rows = sc.kpis.map(k => `<tr><td class="t-title" style="white-space:normal">${esc(k.label)}<div class="t-sub">${esc(k.measured_from)}</div></td>
    <td class="num">${fmtU(k.baseline, k.unit)}${k.baseline_note ? `<div class="t-sub">${esc(k.baseline_note)}</div>` : ''}</td><td class="num strong">${fmtU(k.current, k.unit)}</td><td class="num">${fmtU(k.target, k.unit)}</td>
    <td>${status(PILOT_K[k.status] || 'info', cap(k.status))}${k.change_pct != null ? `<div class="t-sub">${esc(k.change_pct > 0 ? '+' : '')}${esc(k.change_pct)}% vs baseline</div>` : ''}</td>
    <td>${lead ? `<span class="inline" style="gap:4px">${k.current != null ? btn('Use as baseline', 'pilotBaseline', [k.id], 'sm') : ''}<input class="input sm" style="width:80px" type="number" min="0" step="any" id="pt-${esc(k.id)}" placeholder="target" aria-label="Target for ${esc(k.label)}">${btn('Set', 'pilotTarget', [k.id], 'sm')}</span>` : ''}</td></tr>`);
  const agree = sc.ai_agreement.map(a => `<tr><td class="t-title" style="white-space:normal">${esc(a.label)}</td><td>${ladder(a.stage)}</td><td class="num">${nf(a.sample)}</td>
    <td class="num strong">${a.current == null ? '–' : esc(a.current) + '%'}</td><td class="num">${a.target == null ? '<span class="muted">not set</span>' : esc(a.target) + '%'}</td><td>${status(PILOT_K[a.status] || 'info', cap(a.status))}</td></tr>`);
  const q = sc.qa_rechecks;
  const outRows = outs.items.map(o => `<div class="list-row small"><div class="grow">${esc(toolName(o.tool))} · ${esc(o.summary || '')}<div class="t-sub">${dt(o.found_at)} · recorded by ${esc(o.recorded_by)}</div></div>${status(o.found_by === 'users' ? 'high' : 'ok', o.found_by === 'users' ? 'Users found it' : 'Platform found it')}</div>`).join('');
  setMainG(__g, page('Pilot scorecard', 'What the pilot set out to change, against NAM\'s own baseline (capture it in week 2). No target is preset: the SOC lead sets each one. Every figure is computed from the platform\'s records or the outage log.',
    btn('Refresh', 'refreshPage', [], 'ghost', 'refresh'),
    `<div class="grid g-kpi">${['met', 'improving', 'not_improved', 'no_baseline', 'no_target', 'no_data'].map(st => kpi(cap(st), nf(sc.statuses[st] || 0), 'KPIs')).join('')}</div>
    <div class="mt">${card('Pilot KPIs', table(['KPI', {h: 'Baseline', num: 1}, {h: 'Now', num: 1}, {h: 'Target', num: 1}, 'Status', ''], rows), {flush: true})}</div>
    <div class="mt">${card('AI agreement per decision type', table(['Decision type', 'Stage', {h: 'Decided by analysts', num: 1}, {h: 'Agreement', num: 1}, {h: 'Target', num: 1}, 'Status'], agree), {flush: true, sub: 'targets are set on Data protection (earned autonomy)'})}</div>
    <div class="grid g-2e mt">
      ${card('Re-checks of the AI\'s closures', `<div class="list-row small"><span class="grow">The AI would close and a person also ruled</span><span class="score">${nf(q.ai_would_close_and_person_ruled)}</span></div>
        <div class="list-row small"><span class="grow">The person disagreed</span><span class="score">${nf(q.person_disagreed)}</span></div><div class="t-sub" style="margin-top:6px">${esc(q.note)}</div>`, {sub: 'reported apart from agreement'})}
      ${card('Outage log', `${outRows || empty('No outage logged in 90 days.')}${can('investigate') ? `<div class="inline" style="gap:4px;margin-top:8px;flex-wrap:wrap"><input class="input sm" style="width:120px" maxlength="64" id="po-tool" placeholder="Tool" aria-label="Tool"><select class="input sm" id="po-by" aria-label="Found by"><option value="users">Users found it</option><option value="platform">Platform found it</option></select><input class="input sm" style="width:160px" maxlength="500" id="po-sum" placeholder="What happened" aria-label="What happened">${btn('Log outage', 'pilotOutage', [], 'sm')}</div>` : ''}`, {sub: 'who found each outage first'})}
    </div>`));
}
async function pilotBaseline(kpiId) { await post('/api/v1/pilot/baseline/' + encodeURIComponent(kpiId)); toast('Baseline captured'); render(); }
async function pilotTarget(kpiId) {
  const v = ($('#pt-' + kpiId) || {}).value;
  if (v === '' || v == null) { toast('Enter a target first', true); return; }
  await post('/api/v1/pilot/figures', {kpi: kpiId, kind: 'target', value: Number(v), note: 'set on the pilot scorecard'}); toast('Target set'); render();
}
async function pilotOutage() {
  await post('/api/v1/pilot/outages', {tool: $('#po-tool').value, found_by: $('#po-by').value, summary: $('#po-sum').value});
  toast('Outage logged'); render();
}

// ================================================================= Dome Comply
const CTL_K = {pass: 'ok', fail: 'critical', no_evidence: 'medium'};
const CTL_LABEL = {pass: 'Evidence passes', fail: 'Evidence fails', no_evidence: 'No evidence'};
const AS_K = {open: 'medium', not_reportable: 'ok', reportable: 'critical', reported: 'info'};
function clockText(c) {
  if (c.reported) return `reported ${dt(c.reported.at)} · ${esc(c.reported.reference)}`;
  if (c.hours == null) return '<span class="muted">deadline not set in the catalogue</span>';
  if (c.overdue) return `<span class="hot-text">overdue since ${dt(c.due)}</span>`;
  return `${esc(c.hours_left)} h left · due ${dt(c.due)}`;
}
async function Comply() {
  const __g = GEN;
  const d = await api('/api/v1/comply');
  const ev = d.evidence, sm = ev.summary;
  const lead = can('approve_high_impact') && inDomain('dlp');
  const regimes = Object.entries(ev.regimes).map(([id, r]) => `<div class="card"><div class="card-b"><div class="small strong">${esc(r.name)}</div>
    <div class="dom-score">${nf(r.with_evidence)}<span class="muted small">of ${nf(r.controls)} with evidence</span></div>
    <div class="t-sub">${nf(r.passing)} pass · ${nf(r.failing)} fail</div><div class="t-sub" style="white-space:normal;margin-top:4px">${esc(r.source)}</div></div></div>`).join('');
  const ctl = ev.controls.map(c => `<tr><td class="nowrap strong">${esc(c.id)}</td><td style="white-space:normal">${esc(c.title)}<div class="t-sub">${esc(c.area || '')} · ${esc((c.regimes || []).join(', '))}</div>
    <details><summary class="small">${c.tests.length} test(s)</summary>${c.tests.map(t => `<div class="small" style="margin:4px 0">${status(CTL_K[t.status], CTL_LABEL[t.status])} ${esc(t.label)}: ${esc(t.detail)}</div>`).join('')}</details></td>
    <td>${status(CTL_K[c.status], CTL_LABEL[c.status])}</td></tr>`);
  const assess = d.assessments.map(a => `<div class="card" style="margin-bottom:10px"><div class="card-b">
    <div class="inline" style="justify-content:space-between"><div><a href="#/cases/${esc(a.case_id)}" class="strong">${esc(a.case_title || a.case_id)}</a><div class="t-sub">${esc(a.data_classes.join(', ') || 'personal data')} · ${nf(a.alerts)} alert(s) · opened ${dt(a.opened_at)}</div></div>${status(AS_K[a.status], cap(a.status))}</div>
    ${a.decided_by ? `<div class="small" style="margin-top:6px">Decided by ${esc(a.decided_by)} ${dt(a.decided_at)}: ${esc(a.reason)}</div>` : ''}
    ${a.clocks.map(c => `<div class="list-row small"><span class="grow">${esc(c.label)}<div class="t-sub">${esc(c.source)}${c.verified ? '' : ' · not yet verified against the source'}</div></span><span>${clockText(c)}</span>
      ${lead && !c.reported ? `<span class="inline" style="gap:4px"><input class="input sm" style="width:110px" maxlength="120" id="rr-${a.id}-${esc(c.id)}" placeholder="Reference" aria-label="Submission reference for ${esc(c.label)}">${btn('Reported', 'asReport', [a.id, c.id], 'sm')}</span>` : ''}</div>`).join('')}
    ${a.draft ? `<details style="margin-top:6px"><summary class="small strong">Draft report (${a.draft.source === 'llm' ? 'written by the AI, every sentence cited' : 'written by rule'})</summary><p class="small" style="white-space:pre-wrap">${esc(a.draft.text)}</p>
      <div class="t-sub">${esc(a.draft.note)}</div></details>` : ''}
    ${lead ? `<div class="inline" style="gap:6px;margin-top:8px;flex-wrap:wrap">${['open', 'not_reportable'].includes(a.status) ? `<input class="input sm" style="width:220px" maxlength="2000" id="ar-${a.id}" placeholder="Reason for the decision" aria-label="Reason">${btn('Reportable', 'asDecide', [a.id, true], 'sm primary')}${btn('Not reportable', 'asDecide', [a.id, false], 'sm')}` : ''}
      ${['reportable', 'reported'].includes(a.status) ? btn(a.draft ? 'Draft again' : 'Draft the report', 'asDraft', [a.id], 'sm') : ''}</div>` : ''}</div></div>`).join('');
  setMainG(__g, page('Dome Comply', `Evidence the platform holds, mapped to SEBI CSCRF, DPDP and CERT-In control areas. ${esc(ev.wording)} Catalogue: ${esc(ev.catalogue.status)}.`,
    (can('export_evidence') ? btn('Audit pack', 'compPack', [], 'ghost', 'download') : '') + btn('Refresh', 'refreshPage', [], 'ghost', 'refresh'),
    `${ev.catalogue.note ? `<div class="callout info stackc small">${esc(ev.catalogue.note)}</div>` : ''}
    <div class="grid g-kpi mt">${kpi('Controls with current evidence', sm.evidence_percent == null ? '–' : sm.evidence_percent + '%', `${nf(sm.with_evidence)} of ${nf(sm.controls)}`)}
      ${kpi('Evidence passes', nf(sm.passing), 'controls')}${kpi('Evidence fails', nf(sm.failing), 'controls', sm.failing > 0)}
      ${kpi('No evidence', nf(sm.no_evidence.length), esc(sm.no_evidence.join(', ') || 'none'), sm.no_evidence.length > 0)}
      ${kpi('Personal-data incidents', nf(d.assessments.length), `${nf(d.assessments.filter(a => a.status === 'open').length)} awaiting a person's decision`, d.assessments.some(a => a.status === 'open'))}</div>
    <div class="grid g-3 mt">${regimes}</div>
    <div class="mt"><h2 class="section-h">Personal-data incidents: reportability</h2><div class="t-sub" style="margin-bottom:8px">A person decides whether an incident is reportable; the deadlines start at that decision. The AI only drafts; the platform sends nothing.</div>${assess || empty('No DLP case with personal data yet.')}</div>
    <div class="mt">${card('Controls', table(['Control', 'Title and tests', 'Status'], ctl), {flush: true})}</div>
    <div class="mt">${card('Deadlines in the catalogue', ev.clocks.map(c => `<div class="list-row small"><span class="grow">${esc(c.label)}<div class="t-sub">${esc(c.source)}</div></span><span>${c.hours == null ? '<span class="muted">not set</span>' : esc(c.hours) + ' h'}</span><span class="tag">${c.verified ? 'verified' : 'to verify'}</span></div>`).join(''), {sub: 'from a person\'s "reportable" decision'})}</div>`));
}
async function asDecide(id, reportable) {
  await post(`/api/v1/comply/assessments/${id}/decide`, {reportable, reason: ($('#ar-' + id) || {}).value || ''});
  toast(reportable ? 'Reportable: the deadlines run from now' : 'Recorded as not reportable'); render();
}
async function asDraft(id) { toast('Drafting…'); await post(`/api/v1/comply/assessments/${id}/draft`); render(); }
async function asReport(id, clock) {
  await post(`/api/v1/comply/assessments/${id}/report`, {clock, reference: ($(`#rr-${id}-${clock}`) || {}).value || ''});
  toast('Submission recorded'); render();
}
async function compPack() { toast('Building the audit pack…'); const r = await post('/api/v1/comply/pack'); await dl('/api/v1/reports/' + r.id + '/download'); }

Object.assign(window.VIEWS, {pilot: Pilot, comply: Comply});
Object.assign(ALLOWED, {wPreview, wPropose, wStep, pilotBaseline, pilotTarget, pilotOutage, asDecide, asDraft, asReport, compPack});
