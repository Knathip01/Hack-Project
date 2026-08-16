/**
 * Photharam Beetle Shop — Security Audit API
 * Checks HTTP headers, CORS, cookies, sensitive paths, admin separation.
 * Non-invasive: no exploit payloads, no brute-force, no body reads.
 */

const dns    = require('node:dns').promises;
const net    = require('node:net');
const crypto = require('node:crypto');

const TIMEOUT_MS = 5_000;

// ── Network validation ─────────────────────────────────────────────────

function isPrivateIpv4(addr) {
  const p = addr.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return true;
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

function isPrivateIpv6(addr) {
  const v = addr.toLowerCase();
  return v === '::1' || v === '::' || v.startsWith('::ffff:') ||
    v.startsWith('fc') || v.startsWith('fd') ||
    v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb');
}

function isPublicAddress(addr) {
  const f = net.isIP(addr);
  if (f === 4) return !isPrivateIpv4(addr);
  if (f === 6) return !isPrivateIpv6(addr);
  return false;
}

async function assertAuthorizedTarget(raw, allowedHosts) {
  if (typeof raw !== 'string' || raw.length > 2048) throw new Error('กรุณาระบุ URL ที่ถูกต้อง');

  let url;
  try { url = new URL(raw.trim()); } catch { throw new Error('รูปแบบ URL ไม่ถูกต้อง'); }

  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error('รองรับเฉพาะ HTTPS URL ระดับ root (ไม่มี path, port, query, credentials)');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (['localhost', '.localhost', '.local', '.internal'].some((s) =>
    hostname === 'localhost' || hostname.endsWith(s))) {
    throw new Error('ไม่อนุญาตให้ตรวจสอบโฮสต์ภายใน');
  }
  if (!allowedHosts.includes(hostname)) {
    throw new Error(`URL นี้อยู่นอกขอบเขตที่อนุญาต (${hostname})`);
  }

  const literalIp = net.isIP(hostname);
  if (literalIp && !isPublicAddress(hostname)) throw new Error('ไม่อนุญาต IP ภายใน/พิเศษ');

  if (!literalIp) {
    let addrs;
    try { addrs = await dns.lookup(hostname, { all: true, verbatim: true }); }
    catch { throw new Error('ไม่พบ DNS ของโดเมนนี้'); }
    if (!addrs.length || addrs.some(({ address }) => !isPublicAddress(address)))
      throw new Error('โดเมนนี้ชี้ไปยังเครือข่ายภายใน');
  }

  return new URL(`https://${url.host}/`);
}

// ── Token & config ─────────────────────────────────────────────────────

function hasValidAuditToken(supplied, expected) {
  if (typeof supplied !== 'string' || !expected) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function configuredAllowedHosts() {
  return (process.env.AUDIT_ALLOWED_HOSTS || '')
    .split(',').map((h) => h.trim().toLowerCase()).filter((h) => /^[a-z0-9.-]+$/.test(h));
}

// ── HTTP fetch helpers ────────────────────────────────────────────────

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const { extraHeaders = {}, ...rest } = opts;
  try {
    const r = await fetch(url, {
      redirect: 'manual',
      signal: ctrl.signal,
      ...rest,
      headers: {
        'User-Agent': 'Photharam-Security-Audit/2.0',
        'Accept': '*/*;q=0.1',
        ...extraHeaders,
      },
    });
    void r.body?.cancel().catch(() => {});
    return r;
  } finally {
    clearTimeout(timer);
  }
}

function hdr(headers, name) { return headers.get(name) || ''; }

// ── Individual checks ─────────────────────────────────────────────────

// 1. HSTS
function checkHsts(headers) {
  const v = hdr(headers, 'strict-transport-security');
  if (!v) return { id: 'strict-transport-security', title: 'HSTS (Strict-Transport-Security)', status: 'warn',
    detail: 'ไม่พบ header นี้', advice: 'เพิ่ม Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' };
  const age = parseInt((v.match(/max-age=(\d+)/i) || [])[1] || '0', 10);
  return { id: 'strict-transport-security', title: 'HSTS (Strict-Transport-Security)',
    status: age >= 31536000 ? 'pass' : 'warn', detail: v,
    advice: age < 31536000 ? 'max-age ควรมากกว่าหรือเท่ากับ 31536000 (1 ปี)' : '' };
}

// 2. CSP
function checkCsp(headers) {
  const v = hdr(headers, 'content-security-policy');
  if (!v) return { id: 'content-security-policy', title: 'Content Security Policy (CSP)', status: 'warn',
    detail: 'ไม่พบ header นี้', advice: 'กำหนด CSP เพื่อป้องกัน XSS และสคริปต์แปลกปลอม' };
  const scriptSrc = (v.match(/(?:^|;)\s*script-src\s+([^;]+)/i) || [])[1] || '';
  const bad = ["'unsafe-inline'", "'unsafe-eval'"].filter((t) => scriptSrc.includes(t));
  return bad.length
    ? { id: 'content-security-policy', title: 'Content Security Policy (CSP)', status: 'warn',
        detail: `script-src มี: ${bad.join(', ')}`, advice: 'ย้าย inline script ออก และนำ unsafe-inline / unsafe-eval ออก' }
    : { id: 'content-security-policy', title: 'Content Security Policy (CSP)', status: 'pass',
        detail: v.length > 200 ? v.slice(0, 200) + '…' : v, advice: '' };
}

// 3. Clickjacking
function checkClickjack(headers) {
  const csp = hdr(headers, 'content-security-policy');
  const xfo = hdr(headers, 'x-frame-options');
  const fa  = /(?:^|;)\s*frame-ancestors\s+/i.test(csp);
  const ok  = xfo || fa;
  return { id: 'frame-protection', title: 'Clickjacking Protection (X-Frame-Options / frame-ancestors)',
    status: ok ? 'pass' : 'warn',
    detail: ok ? (xfo || 'CSP frame-ancestors ตั้งค่าแล้ว') : 'ไม่พบ X-Frame-Options หรือ CSP frame-ancestors',
    advice: ok ? '' : 'ตั้ง X-Frame-Options: DENY หรือเพิ่ม frame-ancestors ใน CSP' };
}

// 4. nosniff
function checkNosniff(headers) {
  const v = hdr(headers, 'x-content-type-options');
  return { id: 'x-content-type-options', title: 'MIME Sniffing Protection (X-Content-Type-Options)',
    status: v.toLowerCase().includes('nosniff') ? 'pass' : 'warn',
    detail: v || 'ไม่พบ header นี้', advice: v ? '' : 'ตั้ง X-Content-Type-Options: nosniff เพื่อป้องกัน MIME confusion attack' };
}

// 5. Referrer-Policy
function checkReferrer(headers) {
  const v = hdr(headers, 'referrer-policy');
  return { id: 'referrer-policy', title: 'Referrer Policy', status: v ? 'pass' : 'warn',
    detail: v || 'ไม่พบ header นี้', advice: v ? '' : 'ตั้ง Referrer-Policy เพื่อลดการรั่วไหลของ URL ที่ละเอียดอ่อน' };
}

// 6. Permissions-Policy
function checkPermissions(headers) {
  const v = hdr(headers, 'permissions-policy');
  if (!v) return { id: 'permissions-policy', title: 'Permissions Policy', status: 'warn',
    detail: 'ไม่พบ header นี้', advice: 'ปิด camera, microphone, geolocation ที่ไม่ได้ใช้ด้วย Permissions-Policy' };
  const blocked = ['camera', 'microphone', 'geolocation'].filter((f) => v.includes(`${f}=()`));
  return { id: 'permissions-policy', title: 'Permissions Policy',
    status: blocked.length === 3 ? 'pass' : 'warn',
    detail: v.length > 160 ? v.slice(0, 160) + '…' : v,
    advice: blocked.length < 3 ? `ควรปิด: ${['camera', 'microphone', 'geolocation'].filter((f) => !blocked.includes(f)).join(', ')}` : '' };
}

// 7. COOP
function checkCoop(headers) {
  const v = hdr(headers, 'cross-origin-opener-policy');
  return { id: 'cross-origin-opener-policy', title: 'Cross-Origin-Opener-Policy (COOP)', status: v ? 'pass' : 'info',
    detail: v || 'ไม่พบ header นี้', advice: v ? '' : 'พิจารณาเพิ่ม COOP: same-origin เพื่อ isolation ที่เข้มขึ้น' };
}

// 8. Tech disclosure
function checkTechDisclosure(headers) {
  const found = ['server', 'x-powered-by']
    .map((n) => ({ n, v: hdr(headers, n) })).filter(({ v }) => v);
  if (!found.length) return null;
  return { id: 'technology-disclosure', title: 'Technology Disclosure Headers', status: 'info',
    detail: found.map(({ n, v }) => `${n}: ${v}`).join(' · '),
    advice: 'ไม่ใช่ช่องโหว่โดยตรง แต่ควรลบ headers ที่ไม่จำเป็นเพื่อลด attack surface' };
}

// 9. Cookies
function checkCookies(headers) {
  const raw = typeof headers.getSetCookie === 'function'
    ? headers.getSetCookie()
    : (hdr(headers, 'set-cookie') ? [hdr(headers, 'set-cookie')] : []);
  if (!raw.length) return { id: 'cookies', title: 'Cookie Security Attributes', status: 'info',
    detail: 'ไม่พบ Set-Cookie บนหน้า root — ตรวจสอบที่หน้า login และ API endpoints เพิ่มเติม',
    advice: 'ตรวจสอบว่า session cookies มี Secure, HttpOnly, SameSite=Strict/Lax' };
  const missing = [];
  for (const c of raw) {
    const name = c.split('=', 1)[0] || 'cookie';
    for (const attr of ['Secure', 'HttpOnly', 'SameSite'])
      if (!new RegExp(`;\\s*${attr}(?:=|;|$)`, 'i').test(c)) missing.push(`${name}: ${attr}`);
  }
  return missing.length
    ? { id: 'cookies', title: 'Cookie Security Attributes', status: 'warn',
        detail: `ขาด attribute: ${missing.join(', ')}`, advice: 'เพิ่ม Secure, HttpOnly, SameSite บน session cookies ทุกตัว' }
    : { id: 'cookies', title: 'Cookie Security Attributes', status: 'pass',
        detail: `ตรวจพบ ${raw.length} cookie — มี attributes ครบถ้วน`, advice: '' };
}

// 10. HTTP → HTTPS redirect
async function checkHttpRedirect(target) {
  const httpUrl = new URL(target); httpUrl.protocol = 'http:';
  try {
    const r = await safeFetch(httpUrl, { method: 'HEAD' });
    const loc = hdr(r.headers, 'location');
    const ok = r.status >= 300 && r.status < 400 && loc.startsWith('https://');
    return { id: 'http-to-https', title: 'HTTP → HTTPS Redirect (HSTS Level 1)',
      status: ok ? 'pass' : 'warn',
      detail: ok ? `HTTP ${r.status} → ${loc}` : `HTTP ${r.status}${loc ? ' → ' + loc : ' (ไม่มี redirect)'}`,
      advice: ok ? '' : 'ตั้งค่า redirect จาก HTTP ไป HTTPS ที่ edge หรือ Vercel config' };
  } catch {
    return { id: 'http-to-https', title: 'HTTP → HTTPS Redirect', status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// 11. CORS with untrusted origin
async function checkCors(target) {
  try {
    const r = await safeFetch(target, { extraHeaders: { Origin: 'https://attacker.invalid' } });
    const ao = hdr(r.headers, 'access-control-allow-origin');
    const risky = ao === '*' || ao === 'https://attacker.invalid';
    return { id: 'cors-root', title: 'CORS Policy (untrusted origin test)',
      status: risky ? 'warn' : 'pass',
      detail: ao ? `Access-Control-Allow-Origin: ${ao}` : 'ไม่มี ACAO header — ดีสำหรับหน้าที่ไม่ต้องการ CORS',
      advice: risky ? 'ตรวจสอบว่า endpoint ที่มี CORS เปิดไม่ได้มี credentials หรือข้อมูลผู้ใช้' : '' };
  } catch {
    return { id: 'cors-root', title: 'CORS Policy', status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// 12. Sensitive path exposure
async function checkPath(target, pathname, label) {
  try {
    const r = await safeFetch(new URL(pathname, target), { method: 'HEAD' });
    const exposed = r.status >= 200 && r.status < 300;
    return { id: `exposure-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      title: `Sensitive Path: ${label}`,
      status: exposed ? 'warn' : 'pass',
      detail: exposed ? `HTTP ${r.status} — path นี้เข้าถึงได้สาธารณะ!` : `HTTP ${r.status} — ปิดแล้ว`,
      advice: exposed ? 'ปิดหรือป้องกัน path นี้ — อาจเปิดเผย secrets หรือ config ได้' : '' };
  } catch {
    return { id: `exposure-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      title: `Sensitive Path: ${label}`, status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// 13. security.txt
async function checkSecurityTxt(target) {
  try {
    const r = await safeFetch(new URL('/.well-known/security.txt', target), { method: 'HEAD' });
    const found = r.status >= 200 && r.status < 300;
    return { id: 'security-txt', title: 'security.txt (Vulnerability Disclosure)', status: 'info',
      detail: found ? `พบไฟล์ (HTTP ${r.status}) — นักวิจัยด้านความปลอดภัยสามารถติดต่อได้` : `ไม่พบ (HTTP ${r.status})`,
      advice: found ? '' : 'แนะนำ: เพิ่ม /.well-known/security.txt เพื่อเปิดรับการแจ้งช่องโหว่อย่างมีระบบ' };
  } catch {
    return { id: 'security-txt', title: 'security.txt', status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// 14. Admin login path separation (RBAC check)
async function checkAdminSeparation(target, adminPath) {
  if (!adminPath) {
    return { id: 'admin-login-separation', title: 'Admin Login Path Separation (RBAC)',
      status: 'info', detail: 'ไม่ได้ระบุ admin path — ข้ามการตรวจสอบ',
      advice: 'ระบุ Admin Login Path เพื่อตรวจว่าระบบแยก /login กับ /admin/login ได้จริง' };
  }
  try {
    const adminUrl = new URL(adminPath, target);
    const r = await safeFetch(adminUrl, { method: 'HEAD' });
    // A proper admin portal should either:
    // - Return 200 (page exists, secured by auth internally)
    // - Return 302/301 to itself (redirect on load)
    // Red flag: returns 200 without any auth challenge headers when accessed without session
    const accessible = r.status >= 200 && r.status < 300;
    return { id: 'admin-login-separation', title: `Admin Login Separation (${adminPath})`,
      status: accessible ? 'info' : 'pass',
      detail: `HTTP ${r.status} — ${accessible
        ? 'หน้า admin login เข้าถึงได้ (ปกติถ้ามีการตรวจ auth ภายใน)'
        : 'ไม่สามารถเข้าถึงโดยตรง'}`,
      advice: accessible
        ? 'ตรวจสอบว่าระบบ RBAC บล็อก session ที่ไม่ใช่ admin และมี lockout หลัง login ผิด 5 ครั้ง'
        : '' };
  } catch {
    return { id: 'admin-login-separation', title: 'Admin Login Separation', status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// 15. Admin path as sensitive path (should NOT expose .env-like files)
async function checkAdminPathExposure(target, adminPath) {
  if (!adminPath) return null;
  try {
    // Try a known non-existent sub-path to see if admin area leaks info
    const probeUrl = new URL(adminPath.replace(/\/?$/, '/api/health'), target);
    const r = await safeFetch(probeUrl, { method: 'HEAD' });
    const exposed = r.status >= 200 && r.status < 300;
    return { id: 'admin-path-exposure', title: 'Admin API Endpoint Exposure Check',
      status: exposed ? 'warn' : 'pass',
      detail: `${probeUrl.pathname} → HTTP ${r.status}`,
      advice: exposed ? 'ตรวจสอบว่า admin API endpoints ทุกตัวต้องการ session ที่ถูกต้องก่อนเข้าถึง' : '' };
  } catch {
    return { id: 'admin-path-exposure', title: 'Admin API Endpoint Exposure', status: 'info',
      detail: 'ตรวจสอบไม่ได้ภายในเวลาที่กำหนด', advice: '' };
  }
}

// ── Score ──────────────────────────────────────────────────────────────

function computeScore(checks) {
  const scored = checks.filter((c) => c.status !== 'info');
  if (!scored.length) return 0;
  return Math.round((scored.filter((c) => c.status === 'pass').length / scored.length) * 100);
}

// ── Main handler ───────────────────────────────────────────────────────

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'ใช้ POST เท่านั้น' });
  }

  const auditToken = process.env.AUDIT_TOKEN;
  if (!auditToken) return res.status(503).json({ error: 'ผู้ดูแลยังไม่ได้ตั้งค่า AUDIT_TOKEN บน Vercel' });

  const allowedHosts = configuredAllowedHosts();
  if (!allowedHosts.length) return res.status(503).json({ error: 'ผู้ดูแลยังไม่ได้ตั้งค่า AUDIT_ALLOWED_HOSTS บน Vercel' });

  if (!hasValidAuditToken(req.headers['x-audit-token'], auditToken))
    return res.status(403).json({ error: 'Audit token ไม่ถูกต้อง' });

  const { target, authorized, adminPath } = req.body || {};
  if (authorized !== true) return res.status(400).json({ error: 'ต้องยืนยันสิทธิ์ทดสอบก่อน' });

  let url;
  try { url = await assertAuthorizedTarget(target, allowedHosts); }
  catch (err) { return res.status(400).json({ error: err.message }); }

  try {
    // Run header checks and active checks in parallel
    const [mainResp, httpRedirect, cors, pathEnv, pathGit, pathVercel, securityTxt,
           adminSep, adminExposure] = await Promise.all([
      safeFetch(url),
      checkHttpRedirect(url),
      checkCors(url),
      checkPath(url, '/.env', '.env'),
      checkPath(url, '/.git/HEAD', '.git/HEAD'),
      checkPath(url, '/.vercel/project.json', '.vercel/project.json'),
      checkSecurityTxt(url),
      checkAdminSeparation(url, adminPath || ''),
      checkAdminPathExposure(url, adminPath || ''),
    ]);

    const { headers, status, url: finalUrl } = mainResp;

    const headerChecks = [
      checkHsts(headers),
      checkCsp(headers),
      checkClickjack(headers),
      checkNosniff(headers),
      checkReferrer(headers),
      checkPermissions(headers),
      checkCoop(headers),
      checkTechDisclosure(headers),
      checkCookies(headers),
    ].filter(Boolean);

    const activeChecks = [
      httpRedirect, cors,
      pathEnv, pathGit, pathVercel,
      securityTxt,
      adminSep,
      adminExposure,
    ].filter(Boolean);

    const checks = [...headerChecks, ...activeChecks];
    const score  = computeScore(checks);

    return res.status(200).json({
      url: finalUrl || String(url),
      statusCode: status,
      contentType: hdr(headers, 'content-type') || 'ไม่ระบุ',
      score,
      checks,
    });

  } catch (err) {
    const msg = err.name === 'AbortError' ? 'การเชื่อมต่อใช้เวลานานเกินกำหนด' : err.message || 'ไม่สามารถตรวจสอบ URL นี้ได้';
    return res.status(400).json({ error: msg });
  }
};
