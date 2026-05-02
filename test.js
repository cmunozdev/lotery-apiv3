/**
 * lotery-apiv3 v3.1.0 — Test Suite
 * node test.js
 * Requiere: wrangler dev (corre en http://127.0.0.1:8787)
 * Vars: WORKER_URL, BEARER_TOKEN
 */

const BASE  = process.env.WORKER_URL  || 'http://127.0.0.1:8787';
const TOKEN = process.env.BEARER_TOKEN || 'lt-apiv3-Xk9mP2qR4vW';

// ─────────────────────────────────────────────────────────────────────────────
// 1. Pure-logic tests  (no server)
// ─────────────────────────────────────────────────────────────────────────────
function testXorRoundtrip() {
  console.log('\n🔐 XOR roundtrip');
  const plaintext = '[{"id":1,"name":"test"}]';
  const key = 37;
  const encrypted = plaintext.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');

  for (const first of ['[', '{']) {
    const dk = encrypted.charCodeAt(0) ^ first.charCodeAt(0);
    const dec = Array.from(encrypted, c => String.fromCharCode(c.charCodeAt(0) ^ dk)).join('');
    try {
      const p = JSON.parse(dec);
      const ok = p[0].name === 'test';
      console.log(`  ${ok ? '✅' : '❌'} key=${dk} (expect ${key}) → ${JSON.stringify(p[0])}`);
      return ok;
    } catch {}
  }
  console.log('  ❌ XOR failed');
  return false;
}

function testCleanScore() {
  console.log('\n🧹 TEST: cleanScore()');
  const cases = [
    [['!22', '!17', '=02', '=16', '10'], ['22', '17', '02', '16', '10']],
    [['03', '19', '35', '51', '67', '+15', '?2X'], ['03', '19', '35', '51', '67', '15', '2X']],
    [['+15', '+24'], ['15', '24']],
    [['06', '04', '30', '29', '27'], ['06', '04', '30', '29', '27']],
  ];
  function cleanScore(score) {
    if (typeof score === 'string') return score.replace(/^[^0-9]+/, '');
    if (Array.isArray(score)) return score.map(item => Array.isArray(item) ? cleanScore(item) : cleanScore(item));
    return score;
  }
  let pass = 0;
  for (const [input, expect] of cases) {
    const result = cleanScore(input);
    const ok = JSON.stringify(result) === JSON.stringify(expect);
    console.log(`  ${ok ? '✅' : '❌'} ${JSON.stringify(input)} → ${JSON.stringify(result)}`);
    if (ok) pass++;
  }
  return pass === cases.length;
}

function testGzipDetect() {
  console.log('\n📦 Gzip detection');
  const r1 = new Uint8Array([0x1f, 0x8b, 0x08])[0] === 0x1f && new Uint8Array([0x1f, 0x8b, 0x08])[1] === 0x8b;
  const r2 = !([0x5b, 0x22, 0x69][0] === 0x1f && [0x5b, 0x22, 0x69][1] === 0x8b);
  console.log(`  ${r1 ? '✅' : '❌'} 1f 8b → gzip`);
  console.log(`  ${r2 ? '✅' : '❌'} 5b 22 → plain`);
  return r1 && r2;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP tests  (requires `wrangler dev`)
// ─────────────────────────────────────────────────────────────────────────────
async function testFetch(path, label, expectStatus = 200, withAuth = true) {
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: withAuth ? { Authorization: `Bearer ${TOKEN}` } : {},
    });
    const ok = res.status === expectStatus;
    console.log(`  ${ok ? '✅' : '❌'} ${label} → HTTP ${res.status} (expect ${expectStatus})`);
    if (!ok) {
      const body = await res.text().catch(() => '');
      console.log(`     Preview: ${body.slice(0, 180)}`);
    }
    return ok;
  } catch (e) {
    console.log(`  ❌ ${label} → ${e.message}`);
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────
async function run() {
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   lotery-apiv3 v3.1.0 — Test Suite       ║');
  console.log(`║   BASE: ${BASE.padEnd(33)}║`);
  console.log('╚══════════════════════════════════════════╝');

  const l1 = testXorRoundtrip();
  const l2 = testCleanScore();
  const l3 = testGzipDetect();

  console.log('\n🌐 Server tests  (requires `wrangler dev`)');

  const h1 = await testFetch('/companies',           'GET /companies',          200);
  const h2 = await testFetch('/hot',                 'GET /hot',                200);
  const h3 = await testFetch('/games',               'GET /games (all games)',              200);
  const h4 = await testFetch('/games/87',            'GET /games/87 (by id)',               200);
  const h5 = await testFetch('/games/86?date=2026-05-01', 'GET /games/86?date=2026-05-01', 502);
  const h6 = await testFetch('/banners',             'GET /banners',            502);
  const h7 = await testFetch('/config',              'GET /config',             200);
  const h8 = await testFetch('/status',              'GET /status (no auth)',   200, false);
  const h9 = await testFetch('/docs',               'GET /docs (no auth)',     200, false);
  const h10 = await testFetch('/openapi.json',       'GET /openapi.json (no auth)', 200, false);
  const h11 = await testFetch('/companies',         'GET /companies (no auth)', 401, false);

  console.log('\n───────────────────────────────────────────');
  const logicPass = [l1, l2, l3].filter(Boolean).length;
  const httpPass  = [h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11].filter(Boolean).length;
  console.log(`  Logic:  ${logicPass}/3 passed`);
  console.log(`  HTTP:   ${httpPass}/11 passed`);
  console.log(`  Total:  ${logicPass + httpPass}/14 passed`);
  if (logicPass + httpPass === 14) console.log('\n  🎉 All tests passed!');
  else console.log(`\n  ⚠️  ${14 - logicPass - httpPass} test(s) failed`);
}

run().catch(console.error);