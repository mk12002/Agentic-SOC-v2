// Browser tour of the NAM build (SOC_PRODUCT_SCOPE=nam): drives the real console in Chrome/Edge against a running
// server, loads the sample estate through the API as the scheduler would, visits every CyberDome screen, cross-checks
// every KPI on screen against the API, drives the flows a lead uses (Dome Score weights, a DLP ruling, reportability,
// the pilot baseline), probes stored XSS through every free-text field a person can fill in, checks that a
// domain-scoped analyst sees only their domain, and audits layout (1440 / 1280 / 1024 / 768 / 390 px, light + dark)
// and accessibility (axe-core, WCAG 2.1 A/AA) on every screen.
//   SOC_BASE=http://127.0.0.1:8765 node tour_nam.js      (scripts/verify_features.py --browser starts the server)
// Exit code 0 = no problems. The inherited full-scope tour is tour.js.
const {chromium} = require('playwright-core');
const fs = require('fs');
const path = require('path');
const REPO = path.resolve(__dirname, '..', '..');
const BASE = process.env.SOC_BASE || 'http://127.0.0.1:8765';
const OUT = process.env.SOC_SHOTS || path.join(REPO, 'docs', 'screenshots');
const ORG = process.env.SOC_TOUR_ORG || 'acme-demo.com';
const LEAD = `lena@${ORG}`;
const BROWSER = process.env.SOC_BROWSER || ['C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find(p => fs.existsSync(p));
fs.mkdirSync(OUT, {recursive: true});
const problems = [];
const a11yNotes = [];
const AXE = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

async function token(user, roles, domains = '') {
  return (await (await fetch(`${BASE}/api/v1/dev/token?user=${encodeURIComponent(user)}&roles=${roles}&domains=${domains}`)).json()).token;
}
async function call(tok, method, p, body, okStatuses = [200]) {
  const r = await fetch(BASE + p, {method, headers: {Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined});
  if (!okStatuses.includes(r.status)) problems.push(`${method} ${p} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.headers.get('content-type')?.includes('json') ? r.json() : null;
}
async function settle(page) {
  await page.waitForFunction(() => !document.querySelector('#main .skeleton'), null, {timeout: 90000}).catch(() => problems.push('timeout ' + page.url()));
  await page.waitForTimeout(400);
}
const AUDIT = () => {
  const out = [], vw = document.documentElement.clientWidth;
  const desc = el => `${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : ''} "${(el.textContent || '').trim().slice(0, 40)}"`;
  const inScroller = el => { for (let p = el.parentElement; p; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll') return true; } return false; };
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('svg') || el.closest('#toast')) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (!el.children.length && (el.textContent || '').trim() && cs.display !== 'inline' && r.height > 0 && r.width < 24 && el.scrollWidth > r.width + 4)
      out.push('squeezed ' + desc(el));
    if (!r.width || !r.height) continue;
    if ((cs.overflowX === 'hidden' || cs.overflowX === 'clip') && el.scrollWidth > el.clientWidth + 1 && !el.classList.contains('clamp') && el.tagName !== 'SELECT'
        && !el.closest('.sidebar'))      // the folded menu clips its own labels on purpose
      out.push('clipped ' + desc(el));
    if (r.right > vw + 1 && !inScroller(el)) out.push('off-screen ' + desc(el));
    if (!el.children.length && cs.display !== 'inline' && cs.overflowX === 'visible' && el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1 && !inScroller(el))
      out.push('text-overflow ' + desc(el));
  }
  if (vw >= 1260)
    for (const t of document.querySelectorAll('.table-wrap'))
      if (t.scrollWidth > t.clientWidth + 1) out.push(`table needs sideways scroll (${t.scrollWidth - t.clientWidth}px) ` + desc(t.querySelector('th') || t));
  return [...new Set(out)].slice(0, 12);
};
async function axe(page, label) {
  if (!(await page.evaluate(() => !!window.axe))) await page.addScriptTag({content: AXE});
  const res = await page.evaluate(() => window.axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']}}));
  for (const v of res.violations) {
    const where = v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ');
    (['serious', 'critical'].includes(v.impact) ? problems : a11yNotes).push(`${label}: a11y ${v.impact} ${v.id} (${v.nodes.length}) ${where}`);
  }
}
async function audit(page, label) { (await page.evaluate(AUDIT)).forEach(i => problems.push(`${label}: ${i}`)); }
async function junk(page, label) {
  const j = await page.evaluate(() => (document.body.innerText.match(/\[native code\]|\bundefined\b|\bNaN\b|\[object Object\]|\bnull\b/) || [''])[0]);
  if (j) problems.push(`${label}: page shows "${j}"`);
}
async function shot(page, name, full = true) {
  await audit(page, name); await junk(page, name);
  if (await page.evaluate(() => { const b = document.getElementById('sched-status'); return !!b && !b.hidden; }))
    problems.push(`${name}: scheduler banner shown although the scheduler is running`);
  await page.screenshot({path: `${OUT}/${name}.png`, fullPage: full});
  console.log('saved', name);
}
async function visit(page, hash, name, full = true) {
  await page.goto(`${BASE}/#/${hash}`);
  await settle(page);
  const t = await page.evaluate(() => { const x = document.getElementById('toast'); return x && !x.hidden && x.classList.contains('err') ? x.textContent : ''; });
  if (t) problems.push(`${hash}: ${t}`);
  const ov = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  if (ov > 2) problems.push(`${hash}: horizontal overflow ${ov}px`);
  await shot(page, name, full);
  await axe(page, hash);
}
async function signIn(page, user, role, scope) {
  await page.goto(BASE + '/');
  await page.evaluate(() => { sessionStorage.clear(); localStorage.removeItem('soc_token'); });   // a fresh sign-in
  await page.goto(BASE + '/'); await page.reload();
  await page.waitForSelector('#si-user');
  await page.fill('#si-user', user); await page.selectOption('#si-role', role);
  if (scope) await page.selectOption('#si-scope', scope);
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar'); await settle(page);
}
const kpis = page => page.$$eval('.kpi', els => Object.fromEntries(els.map(e => [e.querySelector('.label').textContent.trim(), e.querySelector('.value').textContent.trim()])));
const fmt = n => (n == null ? '–' : Number(n).toLocaleString('en-GB'));
const same = (where, label, shown, expected) => { if (String(shown) !== String(expected)) problems.push(`screen/API mismatch - ${where} "${label}": screen ${shown}, API ${expected}`); };

(async () => {
  // ---------- the sample estate through the real API, in the scheduler's order (the baseline first)
  const lead = await token(LEAD, 'lead'), lead2 = await token(`lars@${ORG}`, 'lead'), ops = await token(`otto@${ORG}`, 'automation_admin');
  const me = await call(lead, 'GET', '/api/v1/me');
  if ((me.product || {}).scope !== 'nam') problems.push(`the server runs scope ${(me.product || {}).scope}, not nam`);
  console.log('loading samples...');
  for (const j of ['inventory', 'incident', 'dlp', 'crosstool', 'posture', 'config_snapshot', 'intelligence', 'notify']) await call(ops, 'POST', `/api/v1/jobs/${j}/run`, null, [200, 404]);
  const cases = await call(lead, 'GET', '/api/v1/cases');
  const dlpCase = cases.find(c => c.domain === 'dlp');
  const crossCase = cases.find(c => c.domain === 'incident');
  if (!dlpCase || !crossCase) problems.push(`sample cases missing: dlp ${!!dlpCase}, cross-tool ${!!crossCase}`);

  const browser = await chromium.launch({executablePath: BROWSER, headless: true, ignoreDefaultArgs: ['--hide-scrollbars']});
  const ctx = await browser.newContext({viewport: {width: 1440, height: 900}, deviceScaleFactor: 1, bypassCSP: true}); // harness only: CSP blocks Playwright's eval-based waits
  const page = await ctx.newPage();
  page.on('pageerror', e => problems.push('pageerror: ' + e.message));
  page.on('dialog', d => { problems.push('XSS: a dialog opened: ' + d.message()); d.dismiss(); });
  page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  page.on('response', r => { if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`); });

  await page.goto(BASE + '/'); await page.waitForSelector('#si-user');
  await shot(page, 'n00-sign-in', false);
  await signIn(page, LEAD, 'lead');
  if (!/#\/ciso$/.test(page.url())) problems.push(`a lead lands on ${page.url()}, not the Dome Score`);
  const nav = await page.$$eval('[data-nav]', as => as.map(a => a.dataset.nav));
  for (const hidden of ['overview', 'phishing', 'vulnerabilities', 'cloud', 'coverage', 'shadow-it', 'suppliers'])
    if (nav.includes(hidden)) problems.push(`the NAM menu offers the inherited screen ${hidden}`);
  for (const want of ['ciso', 'pilot', 'dlp', 'controls', 'config', 'comply', 'cases', 'approvals', 'audit'])
    if (!nav.includes(want)) problems.push(`the NAM menu lacks ${want}`);

  // ---------- every screen, with the figures the API computes
  const ciso = await call(lead, 'GET', '/api/v1/dashboard/ciso');
  await visit(page, 'ciso', 'n01-dome-score');
  let k = await kpis(page);
  same('ciso', 'Critical cases', k['Critical cases'], fmt(ciso.cases.critical));
  const cov = await call(lead, 'GET', '/api/v1/dashboard/control-coverage');
  same('ciso', 'Full control coverage', k['Full control coverage'], cov.coverage_percent + '%');
  if (ciso.posture.score != null && !(await page.textContent('#main')).includes(String(ciso.posture.score)))
    problems.push(`Dome Score ${ciso.posture.score} is not on the screen`);
  await visit(page, 'controls', 'n02-coverage');
  k = await kpis(page);
  same('controls', 'Devices in the baseline', k['Devices in the baseline'], fmt(cov.baseline.devices));
  same('controls', 'Fully covered', k['Fully covered'], cov.coverage_percent + '%');
  same('controls', 'Short of a control', k['Short of a control'], fmt(cov.devices_short_count));
  const sm = await call(lead, 'GET', '/api/v1/dlp/summary');
  await visit(page, 'dlp', 'n03-data-protection');
  k = await kpis(page);
  same('dlp', 'Alerts', k['Alerts'], fmt(sm.alerts));
  same('dlp', 'Open cases', k['Open cases'], fmt(sm.open_cases));
  same('dlp', 'With personal data', k['With personal data'], fmt(sm.personal_data_alerts));
  same('dlp', 'Decided by the AI', k['Decided by the AI'], fmt(sm.ai_decided));
  const tun = await call(lead, 'GET', '/api/v1/dlp/tuning');
  const tuningText = await page.textContent('#main');
  if ((tun.quality || []).length && !tuningText.includes('Classification quality')) problems.push('dlp: classification-quality findings not shown');
  await visit(page, `cases/${dlpCase.id}`, 'n04-dlp-case');
  await visit(page, `cases/${crossCase.id}`, 'n05-cross-tool-case');
  if (!/tools agree/i.test(await page.textContent('#main'))) problems.push('cross-tool case does not say how many tools agree');
  await visit(page, 'config', 'n06-changes');
  const comply = await call(lead, 'GET', '/api/v1/comply');
  await visit(page, 'comply', 'n07-comply');
  k = await kpis(page);
  const es = comply.evidence.summary;
  same('comply', 'Evidence passes', k['Evidence passes'], fmt(es.passing));
  same('comply', 'Evidence fails', k['Evidence fails'], fmt(es.failing));
  same('comply', 'No evidence', k['No evidence'], fmt(es.no_evidence.length));
  same('comply', 'Personal-data incidents', k['Personal-data incidents'], fmt(comply.assessments.length));
  if (/\bis compliant\b|\bfully compliant\b/i.test(await page.textContent('#main'))) problems.push('comply: the screen claims compliance');
  await visit(page, 'pilot', 'n08-pilot');
  for (const [r, n] of [['approvals', 'n09-approvals'], ['cases', 'n10-cases'], ['intelligence', 'n11-intelligence'], ['tuning', 'n12-tuning'],
    ['integrations', 'n13-integrations'], ['policy', 'n14-policy'], ['ai-usage', 'n15-ai-usage'], ['reports', 'n16-reports'],
    ['watchlists', 'n17-watchlists'], ['access', 'n18-access'], ['audit', 'n19-audit']]) await visit(page, r, n);

  // ---------- the flows a lead uses, in the UI
  await page.goto(`${BASE}/#/ciso`); await settle(page);
  if (await page.$('#w-web')) {
    await page.click('#ciso-weights details > summary'); await page.fill('#w-web', '10'); await page.click('[data-fn="wPreview"]'); await page.waitForTimeout(800);
    await page.fill('#w-reason', 'Web is a smaller part of the estate'); await page.click('[data-fn="wPropose"]'); await page.waitForTimeout(1200);
    const w = await call(lead, 'GET', '/api/v1/posture/weights');
    if (!w.pending) problems.push('weights: proposing in the UI stored no proposal');
    else {
      if (await page.$(`[data-fn="wStep"][data-args*="approve"]`)) problems.push('weights: the proposer is offered Approve');
      await call(lead2, 'POST', `/api/v1/posture/weights/${w.pending.id}/approve`, {note: 'tour'});
      await page.goto(`${BASE}/#/ciso`); await settle(page);
      if (/draft weights/i.test(await page.textContent('#main'))) problems.push('weights: still called a draft after approval');
      await shot(page, 'n20-dome-score-agreed-weights');
    }
  } else problems.push('weights editor not on the Dome Score screen');
  await page.goto(`${BASE}/#/comply`); await settle(page);
  const open = comply.assessments.find(a => a.status === 'open');
  if (open) {
    const reason = await page.$(`#ar-${open.id}`);
    if (reason) await reason.fill('Investor PAN data left the organisation (tour)');
    await page.click(`[data-fn="asDecide"][data-args="[${open.id},true]"]`); await page.waitForTimeout(1200); await settle(page);
    const after = (await call(lead, 'GET', '/api/v1/comply')).assessments.find(a => a.id === open.id);
    if (!after || after.status !== 'reportable') problems.push(`comply: deciding in the UI left status ${after && after.status}`);
    else if (await page.$(`[data-fn="asDecide"][data-args="[${open.id},true]"]`)) problems.push('comply: a decided assessment still offers the decision');
    await shot(page, 'n21-comply-decided');
  }
  await page.goto(`${BASE}/#/pilot`); await settle(page);
  const base = await page.$('[data-fn="pilotBaseline"]');
  if (base) { await base.click(); await page.waitForTimeout(1000); await settle(page); await shot(page, 'n22-pilot-baseline'); }

  // ---------- stored XSS: hostile text in every field a person writes, then every screen that shows it
  // (entered only now, after the screenshots, so the documentation never shows the probe)
  const XSS = `<img src=x onerror="window.__xss='img'"><script>window.__xss='script'</script><svg onload="window.__xss='svg'">`;
  const analyst = await token(`dana@${ORG}`, 'analyst');
  await call(analyst, 'POST', '/api/v1/pilot/outages', {tool: 'trellix_epo', found_by: 'users', summary: 'Agents silent ' + XSS});
  const waiting = (await call(lead, 'GET', '/api/v1/dlp/alerts?limit=500')).items.find(a => !a.analyst);
  if (waiting) await call(analyst, 'POST', `/api/v1/dlp/alerts/${waiting.id}/decision`, {outcome: 'escalate', reason: 'Looks real ' + XSS});
  await call(lead, 'POST', '/api/v1/posture/weights', {document: {weights: {web: 12}}, reason: 'Board asked ' + XSS});
  const cat = (await call(lead, 'GET', '/api/v1/comply/catalogue')).active;
  await call(lead, 'POST', '/api/v1/comply/catalogue', {document: cat, reason: 'Compliance review ' + XSS});
  const decided = (await call(lead, 'GET', '/api/v1/comply')).assessments.find(a => a.status === 'reportable' && a.clocks.length);
  if (decided) await call(lead, 'POST', `/api/v1/comply/assessments/${decided.id}/report`, {clock: decided.clocks[0].id, reference: 'REF ' + XSS.slice(0, 100)});
  await call(analyst, 'POST', `/api/v1/cases/${dlpCase.id}/notes`, {text: 'Checked ' + XSS}, [200, 201, 404]);
  for (const r of ['pilot', 'comply', 'ciso', 'dlp', `cases/${dlpCase.id}`, `cases/${crossCase.id}`, 'cases', 'approvals', 'audit']) {
    await page.goto(`${BASE}/#/${r}`); await settle(page);
    const hit = await page.evaluate(() => ({flag: window.__xss || null,
      injected: document.querySelectorAll('#main img[src="x"], #main svg[onload], #main script').length}));
    if (hit.flag || hit.injected) problems.push(`XSS on ${r}: executed=${hit.flag} injected elements=${hit.injected}`);
  }
  console.log('stored-XSS probe checked');

  // ---------- a DLP-only analyst: the menu and the cross-domain screens follow the data scope
  await signIn(page, `dee@${ORG}`, 'analyst', 'dlp');
  const scopedNav = await page.$$eval('[data-nav]', as => as.map(a => a.dataset.nav));
  for (const x of ['ciso', 'pilot', 'comply']) if (scopedNav.includes(x)) problems.push(`dlp-only analyst is offered ${x}`);
  if (!scopedNav.includes('dlp')) problems.push('dlp-only analyst is not offered Data protection');
  if (!/#\/dlp$/.test(page.url())) problems.push(`a dlp-only analyst lands on ${page.url()}`);
  for (const r of ['ciso', 'comply', 'pilot']) {
    await page.goto(`${BASE}/#/${r}`); await settle(page);
    const txt = await page.textContent('#main');
    if (!txt.includes('outside your data scope') && !txt.includes('needs all-domain access')) problems.push(`dlp-only analyst: ${r} did not explain the scope`);
  }

  // ---------- layout at every width, both themes, every screen (the phone width with the menu folded)
  await signIn(page, LEAD, 'lead');
  const routes = ['ciso', 'pilot', 'dlp', `cases/${dlpCase.id}`, `cases/${crossCase.id}`, 'controls', 'config', 'comply', 'cases',
    'approvals', 'intelligence', 'tuning', 'integrations', 'policy', 'ai-usage', 'reports', 'watchlists', 'access', 'audit'];
  for (const [w, theme] of [[1280, 'light'], [1280, 'dark'], [1024, 'light'], [1024, 'dark'], [768, 'light'], [390, 'light'], [390, 'dark']]) {
    await page.setViewportSize({width: w, height: w < 500 ? 844 : 900});
    await page.evaluate(t => { document.documentElement.setAttribute('data-theme', t); }, theme);
    for (const r of routes) {
      await page.goto(`${BASE}/#/${r}`); await settle(page); await audit(page, `${w}px ${theme} ${r}`); await junk(page, `${w}px ${theme} ${r}`);
      if (w === 1280) await axe(page, `${theme} ${r}`);
      const ov = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (ov > 2) problems.push(`${w}px ${r}: page overflow ${ov}px`);
    }
    if (w === 390 && theme === 'light') await shot(page, 'n30-phone-audit', false);
    console.log('audited', w, theme, routes.length, 'screens');
  }
  // the side menu folds and opens again, and stays as chosen after a reload
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(`${BASE}/#/ciso`); await settle(page);
  const before = await page.evaluate(() => document.querySelector('.shell').classList.contains('collapsed'));
  await page.click('#side-toggle'); await page.waitForTimeout(300);
  await page.reload(); await page.waitForSelector('.sidebar'); await settle(page);
  const after = await page.evaluate(() => document.querySelector('.shell').classList.contains('collapsed'));
  if (after === before) problems.push('side menu: the fold is not kept after a reload');
  await page.click('#side-toggle'); await page.waitForTimeout(300);

  // the connectors as tiles: one tile per connector, the choice kept after a reload, laid out at a wide and a phone width
  await page.goto(`${BASE}/#/integrations`); await settle(page);
  const conns = await call(lead, 'GET', '/api/v1/dashboard/connectors');
  if (!(await page.$('[data-fn="setConnView"]'))) problems.push('integrations: no List / Tiles switch');
  else {
    await page.click('[data-fn="setConnView"][data-args*="tiles"]'); await settle(page);
    const tiles = await page.$$eval('.tiles .tile', t => t.length);
    if (tiles !== conns.length) problems.push(`integrations tiles: ${tiles} tiles for ${conns.length} connectors`);
    await page.reload(); await page.waitForSelector('.sidebar'); await settle(page);
    if (!(await page.$('.tiles .tile'))) problems.push('integrations: the tiles view is not kept after a reload');
    for (const w of [1440, 390]) {
      await page.setViewportSize({width: w, height: w < 500 ? 844 : 900}); await settle(page);
      await audit(page, `${w}px integrations tiles`); await junk(page, `${w}px integrations tiles`);
      const ov = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (ov > 2) problems.push(`${w}px integrations tiles: page overflow ${ov}px`);
    }
    await axe(page, 'integrations tiles');
    await page.setViewportSize({width: 1440, height: 900});
    await page.click('[data-fn="setConnView"][data-args*="list"]'); await settle(page);
    if (await page.$('.tiles')) problems.push('integrations: switching back to List left the tiles');
  }

  await browser.close();
  if (a11yNotes.length) console.log('\nACCESSIBILITY NOTES (moderate/minor):\n - ' + [...new Set(a11yNotes)].join('\n - '));
  console.log('\nPROBLEMS:', problems.length ? '\n - ' + problems.join('\n - ') : 'none');
  fs.writeFileSync(path.join(OUT, 'tour-result.json'), JSON.stringify({problems, scope: 'nam',
    screenshots: fs.readdirSync(OUT).filter(f => f.endsWith('.png')).length, audited_widths: [1440, 1280, 1024, 768, 390],
    a11y_notes: [...new Set(a11yNotes)]}, null, 1));
  process.exit(problems.length ? 1 : 0);
})().catch(e => { console.error('CRASH', e); console.log('PROBLEMS so far:', problems); process.exit(2); });
