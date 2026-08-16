const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const TARGET_URL = process.env.TEST_TARGET_URL || 'https://photharam-beetle-2027.vercel.app';

describe('🌐 [Layer 3] HTTP Security Headers Baseline Assurance', () => {
  it('ต้องมี X-Content-Type-Options: nosniff เพื่อป้องกัน MIME-Sniffing', async () => {
    const res = await fetch(TARGET_URL, { method: 'GET' });
    const nosniff = res.headers.get('x-content-type-options');
    assert.match(nosniff || '', /nosniff/i, 'X-Content-Type-Options ต้องเป็น nosniff');
  });

  it('ต้องมี Clickjacking Protection (X-Frame-Options หรือ CSP frame-ancestors)', async () => {
    const res = await fetch(TARGET_URL, { method: 'GET' });
    const xfo = res.headers.get('x-frame-options');
    const csp = res.headers.get('content-security-policy') || '';
    const hasProtection = (xfo && /DENY|SAMEORIGIN/i.test(xfo)) || csp.includes('frame-ancestors');
    assert.ok(hasProtection, 'ต้องมีการป้องกัน Clickjacking ด้วย X-Frame-Options หรือ CSP frame-ancestors');
  });

  it('ต้องมี Permissions-Policy ปิดกั้น hardware ที่ไม่ได้ใช้งาน (camera, microphone, geolocation)', async () => {
    const res = await fetch(TARGET_URL, { method: 'GET' });
    const permissions = res.headers.get('permissions-policy') || '';
    assert.match(permissions, /camera=\(\)/i, 'ต้องปิดการเข้าถึง camera');
    assert.match(permissions, /microphone=\(\)/i, 'ต้องปิดการเข้าถึง microphone');
    assert.match(permissions, /geolocation=\(\)/i, 'ต้องปิดการเข้าถึง geolocation');
  });

  it('ต้องมี Strict-Transport-Security (HSTS) เมื่อเข้าใช้งานผ่าน HTTPS', async () => {
    const res = await fetch(TARGET_URL, { method: 'GET' });
    const hsts = res.headers.get('strict-transport-security');
    assert.ok(hsts, 'ต้องกำหนด header Strict-Transport-Security');
    assert.match(hsts, /max-age=\d+/i, 'HSTS ต้องระบุ max-age');
  });
});