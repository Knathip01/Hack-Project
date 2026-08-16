const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

describe('🛡️ [Layer 1] Database Row Level Security (RLS) & Triggers', () => {
  it('ตรวจสอบการป้องกัน Privilege Escalation ผ่าน Supabase Client (เมื่อมีการตั้งค่า ENV)', async (t) => {
    if (!SUPABASE_URL || !ANON_KEY) {
      t.skip('ข้ามการทดสอบ: ยังไม่ได้ตั้งค่า SUPABASE_URL และ SUPABASE_ANON_KEY ใน environment');
      return;
    }

    // Direct fetch to Supabase REST endpoint using Anon Key
    const restEndpoint = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1/profiles`;
    const res = await fetch(restEndpoint, {
      method: 'PATCH',
      headers: {
        'apikey': ANON_KEY,
        'Authorization': `Bearer ${ANON_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify({ role: 'admin', points: 999999 })
    });

    // An anonymous / non-service role user should never succeed in changing all rows or escalating privileges
    assert.notEqual(res.status, 200, 'Anonymous client ต้องไม่สามารถ PATCH แก้ไข role/points ใน profiles ได้');
  });

  it('ตรวจสอบว่า security_logs ห้ามลบหรือแก้ไขโดยตรง (RLS Isolation)', async (t) => {
    if (!SUPABASE_URL || !ANON_KEY) {
      t.skip('ข้ามการทดสอบ: ยังไม่ได้ตั้งค่า SUPABASE_URL และ SUPABASE_ANON_KEY ใน environment');
      return;
    }

    const restEndpoint = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1/security_logs`;
    const res = await fetch(restEndpoint, {
      method: 'DELETE',
      headers: {
        'apikey': ANON_KEY,
        'Authorization': `Bearer ${ANON_KEY}`
      }
    });

    assert.notEqual(res.status, 200, 'Anonymous client ต้องไม่สามารถ DELETE ข้อมูลจาก security_logs ได้');
  });
});