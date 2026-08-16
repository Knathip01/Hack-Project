# 🛡️ Photharam Beetle Shop — Security Audit Tool

เครื่องมือตรวจสอบความปลอดภัยเชิงลึกสำหรับ **Photharam Beetle Shop** โดยเฉพาะ
ออกแบบมาเพื่อยืนยันว่า Multi-Layered Defense-in-Depth Architecture ทำงานครบถ้วน

> **Non-invasive**: ไม่มีการ exploit จริง, ไม่ brute-force, ไม่อ่าน response body, ไม่สแกนพอร์ต

---

## การตรวจสอบที่ครอบคลุม

### 🌐 Layer 3 — HTTP Security Headers
| Check | รายละเอียด |
|-------|-----------|
| HSTS | ตรวจว่า `max-age >= 31536000` |
| CSP | ตรวจ `unsafe-inline` / `unsafe-eval` ใน script-src |
| X-Frame-Options / frame-ancestors | ป้องกัน Clickjacking |
| X-Content-Type-Options | ต้องเป็น `nosniff` |
| Referrer-Policy | ลดการรั่วไหลของ URL |
| Permissions-Policy | ตรวจว่าปิด camera, microphone, geolocation |
| COOP | Cross-Origin-Opener-Policy isolation |
| Technology Disclosure | server, x-powered-by ที่ไม่ควรเปิดเผย |

### 🔐 Layer 2 — Authentication & RBAC
| Check | รายละเอียด |
|-------|-----------|
| HTTP → HTTPS Redirect | บังคับ HTTPS ที่ HTTP layer |
| CORS Policy | ทดสอบด้วย untrusted origin |
| Cookie Attributes | Secure, HttpOnly, SameSite |
| Admin Path Separation | ตรวจ response ของ admin login path |
| Admin API Exposure | ตรวจว่า admin endpoints ไม่เปิดเผย |

### 📂 Sensitive Path Exposure
| Check | รายละเอียด |
|-------|-----------|
| `/.env` | ห้ามเข้าถึงได้สาธารณะ |
| `/.git/HEAD` | ห้ามเปิดเผย git repository |
| `/.vercel/project.json` | ห้ามเปิดเผย Vercel config |
| `/.well-known/security.txt` | แนะนำให้มี |

---

## วิธี Deploy บน Vercel

1. นำโฟลเดอร์นี้ขึ้น GitHub แล้ว import ใน [Vercel](https://vercel.com/new)
2. ที่ **Project Settings → Environment Variables** เพิ่ม:
   - `AUDIT_TOKEN` = สตริงสุ่มยาวๆ (ใช้ `openssl rand -hex 32`)
   - `AUDIT_ALLOWED_HOSTS` = `photharam-beetle-2027.vercel.app`
3. กด **Redeploy**
4. เปิดหน้าเว็บ → กรอก URL + token + ติ๊ก consent → กด **เริ่มตรวจสอบ**

> API จะไม่ทำงานจนกว่าจะตั้งทั้ง `AUDIT_TOKEN` และ `AUDIT_ALLOWED_HOSTS`
> จึงไม่สามารถนำไปใช้เป็น public scanner ได้

---

## ผลลัพธ์

- **คะแนน ≥ 80**: ผ่านเกณฑ์ขั้นพื้นฐาน
- **คะแนน 50–79**: ต้องปรับปรุง
- **คะแนน < 50**: มีความเสี่ยงสูง ควรแก้ไขด่วน

ผลลัพธ์ `warn` อาจเป็น SPA fallback ได้ — ให้ยืนยันจาก routing config ก่อนแก้ไข
ผลลัพธ์นี้เป็น baseline เท่านั้น ไม่ใช่การรับรองว่าระบบปลอดภัยสมบูรณ์

---

## สิ่งที่เครื่องมือนี้ **ไม่** ทดสอบ

- PostgreSQL RLS / Triggers (ต้องทดสอบผ่าน Supabase Studio)
- Anti-brute force / Lockout (ทดสอบด้วยมือที่ login form)
- Race condition / FOR UPDATE (ทดสอบด้วย concurrent requests)
- File upload validation (ทดสอบด้วยไฟล์จริงใน staging)
- Slip verification / Anti-replay (ทดสอบด้วย business logic tests)
