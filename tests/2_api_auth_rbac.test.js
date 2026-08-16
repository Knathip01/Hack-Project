const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const TARGET_URL = (process.env.TEST_TARGET_URL || 'https://photharam-beetle-2027.vercel.app').replace(/\/$/, '');

describe('🔐 [Layer 2] API Endpoints & RBAC Auth Gate Verification', () => {
  const protectedRoutes = [
    { method: 'GET', path: '/admin/users', label: 'Admin Users UI' },
    { method: 'GET', path: '/admin/orders', label: 'Admin Orders UI' },
    { method: 'GET', path: '/admin/dashboard', label: 'Admin Dashboard' },
    { method: 'GET', path: '/api/admin/users', label: 'Admin Users API' },
    { method: 'GET', path: '/api/admin/orders', label: 'Admin Orders API' },
    { method: 'GET', path: '/api/wallet', label: 'User Wallet API' },
    { method: 'GET', path: '/api/lucky-wheel', label: 'Lucky Wheel API' }
  ];

  for (const route of protectedRoutes) {
    it(`บล็อก Unauthenticated Request ไปยัง ${route.label} (${route.path})`, async () => {
      const url = `${TARGET_URL}${route.path}`;
      const res = await fetch(url, {
        method: route.method,
        headers: {
          'Accept': 'application/json, text/html',
          'User-Agent': 'Security-QA-Bot/1.0'
        },
        redirect: 'manual'
      });

      // ต้องไม่อนุมัติ (401 Unauthorized, 403 Forbidden หรือ 3xx Redirect ไปหน้า Login)
      const isBlocked = res.status === 401 || res.status === 403 || (res.status >= 301 && res.status <= 308);
      const isNotExposed = res.status !== 200;

      assert.ok(
        isBlocked || isNotExposed,
        `Route ${route.path} ต้องไม่เปิดให้เข้าถึงโดยไม่มี Session (ได้รับ HTTP ${res.status})`
      );
    });
  }
});