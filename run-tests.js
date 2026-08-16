#!/usr/bin/env node

/**
 * Photharam Beetle Shop — Automated Security Invariant Test Runner
 * Runs automated QA tests verifying defense-in-depth security layers.
 */

const { spawn } = require('node:child_process');
const path = require('node:path');

// Parse CLI args (e.g. --target=https://...)
const args = process.argv.slice(2);
let targetUrl = 'https://photharam-beetle-2027.vercel.app';

for (const arg of args) {
  if (arg.startsWith('--target=')) {
    targetUrl = arg.split('=')[1].trim();
  }
}

console.log('\n=============================================================');
console.log('🛡️  Photharam Beetle Shop — Automated Security Test Suite');
console.log('=============================================================');
console.log(`🎯 Target URL: ${targetUrl}`);
console.log(`⏱️  Started at: ${new Date().toLocaleString('th-TH')}`);
console.log('-------------------------------------------------------------\n');

process.env.TEST_TARGET_URL = targetUrl;

const testFiles = [
  path.join(__dirname, 'tests', '1_database_rls.test.js'),
  path.join(__dirname, 'tests', '2_api_auth_rbac.test.js'),
  path.join(__dirname, 'tests', '3_input_validation.test.js'),
  path.join(__dirname, 'tests', '4_http_headers.test.js')
];

const runner = spawn(process.execPath, ['--test', ...testFiles], {
  stdio: 'inherit',
  env: process.env
});

runner.on('close', (code) => {
  console.log('\n-------------------------------------------------------------');
  if (code === 0) {
    console.log('🎉 ผลการทดสอบ: ผ่านเกณฑ์ความปลอดภัยทุกรายการ (ALL INVARIANTS PASSED)');
  } else {
    console.log('⚠️  ผลการทดสอบ: พบรายการที่ไม่ผ่านเกณฑ์ความปลอดภัย กรุณาตรวจสอบรายละเอียดด้านบน');
  }
  console.log('=============================================================\n');
  process.exit(code);
});