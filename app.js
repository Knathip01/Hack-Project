/* ===================================================================
   Photharam Beetle Shop — Security Audit Frontend
   Displays results from /api/scan, grouped by the 4 security layers
   the shop implements.
   =================================================================== */

const $ = (id) => document.getElementById(id);

const esc = (v) =>
  String(v).replace(/[&<>'"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]
  );

// ── Category definitions ──────────────────────────────────────────────
const CATEGORIES = [
  {
    id: 'all',
    label: 'ทั้งหมด',
    icon: '📋',
    color: '#7a9bbf',
    checkIds: null, // null = all
  },
  {
    id: 'http',
    label: '🌐 HTTP Headers',
    icon: '🌐',
    color: '#f0b429',
    checkIds: [
      'strict-transport-security',
      'content-security-policy',
      'frame-protection',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
      'cross-origin-opener-policy',
      'http-to-https',
      'technology-disclosure',
    ],
  },
  {
    id: 'auth',
    label: '🔐 Authentication & Auth Gates',
    icon: '🔐',
    color: '#4d9fff',
    checkIds: [
      'cors-root',
      'cookies',
      'admin-login-separation',
      'admin-path-exposure',
      'admin-auth-',        // prefix match for all admin route checks
    ],
  },
  {
    id: 'paths',
    label: '📂 Sensitive Paths',
    icon: '📂',
    color: '#9b7fe8',
    checkIds: [
      'exposure-.env',
      'exposure-.git-head',
      'exposure-.vercel-project.json',
      'security-txt',
    ],
  },
  {
    id: 'input',
    label: '🧹 Input / Config',
    icon: '🧹',
    color: '#3dd68c',
    checkIds: [], // populated by leftover checks
  },
];

// ── Status icons per status ──────────────────────────────────────────
const STATUS_ICON = { pass: '✅', warn: '⚠️', fail: '❌', info: 'ℹ️' };
const STATUS_LABEL = { pass: 'ผ่าน', warn: 'แจ้งเตือน', fail: 'ล้มเหลว', info: 'ข้อมูล' };

// ── DOM refs ─────────────────────────────────────────────────────────
const scanForm    = $('scan-form');
const targetInput = $('target');
const tokenInput  = $('audit-token');
const adminInput  = $('admin-path');
const authBox     = $('authorized');
const scanBtn     = $('scan-btn');
const resetBtn    = $('reset-btn');
const banner      = $('status-banner');

const progressArea  = $('progress-area');
const progressLabel = $('progress-label');
const progressPct   = $('progress-pct');
const progressFill  = $('progress-fill');
const progressSteps = $('progress-steps');

const resultsArea  = $('results-area');
const ringFill     = $('ring-fill');
const scoreLabel   = $('score-label');
const metaUrl      = $('meta-url');
const metaHttp     = $('meta-http');
const verdictBadge = $('verdict-badge');
const catTabs      = $('cat-tabs');
const checksPanel  = $('checks-panel');
const statBar      = $('stat-bar');

// ── Progress helpers ──────────────────────────────────────────────────
const STEPS = [
  'ตรวจ DNS & เชื่อมต่อ',
  'HTTP → HTTPS Redirect',
  'Security Headers',
  'CSP Policy',
  'Cookie Attributes',
  'CORS Policy',
  'Sensitive Paths',
  'Admin Path',
  'Technology Disclosure',
  'สรุปผล',
];

function showProgress() {
  progressArea.style.display = 'block';
  progressSteps.innerHTML = STEPS.map(
    (s, i) => `<span class="step-pill" id="step-${i}">${s}</span>`
  ).join('');
  setProgress(0, STEPS[0]);
}

function setProgress(pct, label, doneIdx = -1) {
  progressFill.style.width = pct + '%';
  progressPct.textContent = pct + '%';
  progressLabel.textContent = label;
  STEPS.forEach((_, i) => {
    const el = document.getElementById('step-' + i);
    if (!el) return;
    el.className = 'step-pill' + (i < doneIdx ? ' done' : i === doneIdx ? ' active' : '');
  });
}

function hideProgress() {
  progressArea.style.display = 'none';
}

// ── Banner ────────────────────────────────────────────────────────────
function showBanner(type, text) {
  banner.className = type;
  banner.style.display = 'flex';
  banner.textContent = text;
}
function hideBanner() {
  banner.style.display = 'none';
}

// ── Score ring ────────────────────────────────────────────────────────
function animateScore(score) {
  const CIRC = 251.2;
  const offset = CIRC - (score / 100) * CIRC;
  ringFill.style.strokeDashoffset = offset;

  const color =
    score >= 80 ? '#3dd68c' :
    score >= 50 ? '#f0b429' : '#f06060';
  ringFill.style.stroke = color;
  scoreLabel.textContent = score;
}

// ── Render ────────────────────────────────────────────────────────────
function renderResults(report) {
  resultsArea.style.display = 'block';

  // Meta
  metaUrl.textContent  = report.url;
  metaHttp.textContent = `HTTP ${report.statusCode} · ${report.contentType}`;

  // Score
  animateScore(report.score);

  // Verdict
  const score = report.score;
  let vColor, vText, vEmoji;
  if (score >= 80)      { vColor = '#3dd68c'; vText = 'ผ่านเกณฑ์'; vEmoji = '✅'; }
  else if (score >= 50) { vColor = '#f0b429'; vText = 'ต้องปรับปรุง'; vEmoji = '⚠️'; }
  else                  { vColor = '#f06060'; vText = 'มีความเสี่ยงสูง'; vEmoji = '🚨'; }
  verdictBadge.style.display = 'inline-flex';
  verdictBadge.style.color   = vColor;
  verdictBadge.style.borderColor = vColor + '60';
  verdictBadge.style.background  = vColor + '18';
  verdictBadge.textContent = `${vEmoji} ${vText}`;

  const checks = report.checks || [];

  // Categorise
  const assigned = new Set();
  const catMap = {};
  CATEGORIES.forEach((c) => { catMap[c.id] = []; });

  CATEGORIES.filter((c) => c.id !== 'all' && c.id !== 'input').forEach((cat) => {
    checks.forEach((ch) => {
      if (cat.checkIds && cat.checkIds.some((id) => {
        // Support prefix matching (id ends with '-')
        if (id.endsWith('-')) return ch.id && ch.id.startsWith(id);
        return ch.id && ch.id.startsWith(id.replace('exposure-', 'exposure-'));
      })) {
        if (!assigned.has(ch.id)) {
          catMap[cat.id].push(ch);
          assigned.add(ch.id);
        }
      }
    });
  });

  // Leftovers -> input/config
  checks.forEach((ch) => {
    if (!assigned.has(ch.id)) {
      catMap['input'].push(ch);
      assigned.add(ch.id);
    }
  });

  // All
  catMap['all'] = checks;

  // Build tabs
  catTabs.innerHTML = '';
  CATEGORIES.forEach((cat) => {
    const items = catMap[cat.id] || [];
    const warnCount = items.filter((c) => c.status === 'warn' || c.status === 'fail').length;
    const btn = document.createElement('button');
    btn.className = 'cat-tab' + (cat.id === 'all' ? ' active' : '');
    btn.role = 'tab';
    btn.dataset.cat = cat.id;
    btn.innerHTML =
      `<span class="cat-dot" style="background:${cat.color}"></span>` +
      `${esc(cat.label)}` +
      `<span class="cat-count">${items.length}</span>` +
      (warnCount > 0 ? `<span class="cat-count" style="background:#f0b42922;border-color:#f0b42940;color:#f0b429">${warnCount}⚠</span>` : '');
    btn.addEventListener('click', () => switchTab(cat.id));
    catTabs.appendChild(btn);
  });

  // Build check groups
  checksPanel.innerHTML = '';
  CATEGORIES.forEach((cat) => {
    const items = catMap[cat.id] || [];
    const group = document.createElement('div');
    group.className = 'check-group' + (cat.id === 'all' ? ' visible' : '');
    group.dataset.group = cat.id;
    group.innerHTML = items.length
      ? items.map((ch) => checkCard(ch)).join('')
      : `<p style="color:var(--faint);font-size:.85rem;text-align:center;padding:24px 0">ไม่มีรายการในหมวดนี้</p>`;
    checksPanel.appendChild(group);
  });

  // Stat bar
  const passed = checks.filter((c) => c.status === 'pass').length;
  const warned = checks.filter((c) => c.status === 'warn').length;
  const failed = checks.filter((c) => c.status === 'fail').length;
  const info   = checks.filter((c) => c.status === 'info').length;
  statBar.innerHTML = [
    ['#3dd68c', `ผ่าน ${passed}`],
    ['#f0b429', `แจ้งเตือน ${warned}`],
    ['#f06060', `ล้มเหลว ${failed}`],
    ['#4d9fff', `ข้อมูล ${info}`],
    ['#7a9bbf',  `รวม ${checks.length} รายการ`],
  ].map(([c, t]) =>
    `<span class="stat"><span class="stat-dot" style="background:${c}"></span>${t}</span>`
  ).join('');
}

function switchTab(catId) {
  catTabs.querySelectorAll('.cat-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.cat === catId);
  });
  checksPanel.querySelectorAll('.check-group').forEach((g) => {
    g.classList.toggle('visible', g.dataset.group === catId);
  });
}

function checkCard(ch) {
  const st = ch.status || 'info';
  const icon = STATUS_ICON[st] || 'ℹ️';
  const label = STATUS_LABEL[st] || st;
  return `
    <div class="check-item ${esc(st)}">
      <div class="check-icon">${icon}</div>
      <div class="check-body">
        <div class="check-title">${esc(ch.title || ch.id)}</div>
        <div class="check-detail">${esc(ch.detail || '')}</div>
        ${ch.advice ? `<div class="check-advice">${esc(ch.advice)}</div>` : ''}
      </div>
      <span class="check-badge">${label}</span>
    </div>`;
}

// ── Reset ─────────────────────────────────────────────────────────────
function resetUI() {
  hideBanner();
  hideProgress();
  resultsArea.style.display = 'none';
  catTabs.innerHTML = '';
  checksPanel.innerHTML = '';
  statBar.innerHTML = '';
  scoreLabel.textContent = '-';
  ringFill.style.strokeDashoffset = 251.2;
  metaUrl.textContent = '-';
  metaHttp.textContent = '-';
  verdictBadge.style.display = 'none';
}

resetBtn.addEventListener('click', resetUI);

// ── Fake progress ticker ──────────────────────────────────────────────
function startFakeProgress() {
  const milestones = [
    { pct: 8,  label: 'กำลังตรวจ DNS & เชื่อมต่อ…',     step: 0 },
    { pct: 20, label: 'กำลังตรวจ HTTP → HTTPS redirect…', step: 1 },
    { pct: 35, label: 'กำลังอ่าน Security Headers…',      step: 2 },
    { pct: 50, label: 'กำลังวิเคราะห์ CSP Policy…',       step: 3 },
    { pct: 62, label: 'กำลังตรวจ Cookie Attributes…',     step: 4 },
    { pct: 72, label: 'กำลังตรวจ CORS Policy…',           step: 5 },
    { pct: 82, label: 'กำลังสแกน Sensitive Paths…',       step: 6 },
    { pct: 88, label: 'กำลังตรวจ Admin Paths…',           step: 7 },
    { pct: 94, label: 'กำลังตรวจ Technology Disclosure…', step: 8 },
    { pct: 98, label: 'กำลังสรุปผล…',                     step: 9 },
  ];
  let i = 0;
  const tid = setInterval(() => {
    if (i >= milestones.length) { clearInterval(tid); return; }
    const m = milestones[i++];
    setProgress(m.pct, m.label, m.step);
  }, 380);
  return tid;
}

// ── Form submit ───────────────────────────────────────────────────────
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!authBox.checked) {
    showBanner('error', '⚠️ กรุณายืนยันว่าคุณได้รับอนุญาตก่อนเริ่มการตรวจสอบ');
    return;
  }
  const target     = targetInput.value.trim();
  const token      = tokenInput.value.trim();
  const adminPath  = adminInput.value.trim();

  if (!target) { showBanner('error', 'กรุณาระบุ URL เป้าหมาย'); return; }
  if (!token)  { showBanner('error', 'กรุณาระบุ Audit Token'); return; }

  resetUI();
  showProgress();
  showBanner('info', '⏳ กำลังตรวจสอบความปลอดภัย กรุณารอสักครู่…');
  scanBtn.disabled = true;

  const ticker = startFakeProgress();

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Audit-Token': token,
      },
      body: JSON.stringify({ target, authorized: true, adminPath: adminPath || undefined }),
    });

    const payload = await res.json();
    clearInterval(ticker);

    if (!res.ok) throw new Error(payload.error || 'การตรวจสอบล้มเหลว');

    setProgress(100, 'เสร็จสิ้น', STEPS.length);
    await new Promise((r) => setTimeout(r, 400));
    hideProgress();
    showBanner('success', '✅ ตรวจสอบเสร็จสิ้น — ผลลัพธ์เป็น baseline เท่านั้น ไม่ใช่การรับรองว่าเว็บปลอดภัยทั้งหมด');
    renderResults(payload);
  } catch (err) {
    clearInterval(ticker);
    hideProgress();
    showBanner('error', '❌ ' + (err.message || 'ไม่สามารถตรวจสอบ URL นี้ได้'));
  } finally {
    scanBtn.disabled = false;
  }
});
