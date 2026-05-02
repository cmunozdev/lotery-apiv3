// =============================================================================
// lotery-apiv3 — Cloudflare Worker
// Proxy para loteriasdominicanas.com con descifrado XOR byte-cipher + gzip.
//
// v3.1.0
// =============================================================================

import pako from 'pako';

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────
const CFG = {
  DOMINICANA_BASE: '',  // set via env.DOMINICANA_BASE
  FALLBACK_BASE   : '',  // set via env.FALLBACK_BASE (fallback on primary failure)
  BEARER_TOKEN   : '',  // set via env.BEARER_TOKEN
  ENABLE_DOCS    : '',  // set via env.ENABLE_DOCS ("true" to enable, anything else blocks)
};

// ─────────────────────────────────────────────────────────────────────────────
// Entry Point
// ─────────────────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    CFG.BEARER_TOKEN    = env.BEARER_TOKEN    || CFG.BEARER_TOKEN;
    CFG.DOMINICANA_BASE = env.DOMINICANA_BASE || CFG.DOMINICANA_BASE;
    CFG.FALLBACK_BASE  = env.FALLBACK_BASE  || CFG.FALLBACK_BASE;
    CFG.ENABLE_DOCS     = env.ENABLE_DOCS     || CFG.ENABLE_DOCS;

    const url  = new URL(request.url);
    const path = url.pathname;

    // ── Pre-flight ───────────────────────────────────────────────────────────
    if (request.method === 'OPTIONS') return cors204();

    // ── Docs gate (ENABLE_DOCS) ───────────────────────────────────────────────
    const docsEnabled = CFG.ENABLE_DOCS === 'true';
    if (path === '/' || path === '/docs' || path === '/openapi.json') {
      if (!docsEnabled) return err(404, 'not_found', 'Documentation is disabled');
      if (path === '/') return landingPage();
      if (path === '/docs') return swaggerPage();
      if (path === '/openapi.json') return openApiSpec();
    }

    // ── Public routes ────────────────────────────────────────────────────────
    if (path === '/status'       ) return handleStatus();
    if (path === '/favicon.ico'  ) return noContent();

    // ── Auth gate ─────────────────────────────────────────────────────────────
    if (!auth(request)) return err(401, 'unauthorized', 'Bearer token required');

    // ── Dominican API routes ─────────────────────────────────────────────────
    if (path === '/companies'            ) return getCompanies(url);
    if (match(path, '/games/:id')              ) return getGameById(path, url);
    if (path === '/games'                ) return getAllGames();
    if (path === '/hot'                  ) return getHot(url);
    if (path === '/games'                ) return getGames(url);
    if (path === '/banners'              ) return getBanners(url);
    if (path === '/config'               ) return getConfig(url);

    return err(404, 'not_found', `Route not found: ${path}`);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Routing helpers
// ─────────────────────────────────────────────────────────────────────────────
function match(path, pattern) {
  const re = pattern
    .replace(':id', '(\\d+)')
    .replace('/', '\\/');
  return new RegExp(`^${re}$`).test(path);
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication
// ─────────────────────────────────────────────────────────────────────────────
function auth(request) {
  const header = request.headers.get('Authorization') ?? '';
  return header === `Bearer ${CFG.BEARER_TOKEN}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity rotation
// ─────────────────────────────────────────────────────────────────────────────
function newIdentity() {
  const octet = () => Math.floor(Math.random() * 254) + 1;
  let ip = `${octet()}.${octet()}.${octet()}.${octet()}`;
  while (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) {
    ip = `${octet()}.${octet()}.${octet()}.${octet()}`;
  }

  const major = Math.floor(Math.random() * 10) + 118;
  const build = Math.floor(Math.random() * 900) + 5000;
  const patch = Math.floor(Math.random() * 255);
  const ver   = `${major}.0.${build}.${patch}`;

  const pf = [
    { os: 'Windows NT 10.0; Win64; x64',               hint: '"Windows"' },
    { os: 'Macintosh; Intel Mac OS X 10_15_7',          hint: '"macOS"'  },
    { os: 'X11; Linux x86_64',                          hint: '"Linux"'  },
  ][Math.floor(Math.random() * 3)];

  return {
    ip,
    ua    : `Mozilla/5.0 (${pf.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36`,
    secChUa      : `"Google Chrome";v="${major}", "Chromium";v="${major}", "Not_A Brand";v="24"`,
    platformHint : pf.hint,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR Decryption — loteriasdominicanas.com: respuesta es JSON-string codificado
// con newlines/etc escapados. Flujo: raw bytes → JSON.parse → string con newlines
// reales → XOR byte-cipher → JSON.parse final
// ─────────────────────────────────────────────────────────────────────────────
async function xorDecrypt(raw) {
  // Step 1: Decodificar bytes UTF-8 → texto JSON-encoded
  const text = new TextDecoder('utf-8', { fatal: false }).decode(raw);

  // Step 2: Parsear el JSON wrapper → extraer el string con newlines reales
  // La respuesta es "..." con \\n, \\r, etc. que JSON.parse convierte a chars reales
  let inner;
  try {
    const parsed = JSON.parse(text);
    // La respuesta puede ser un string envuelto ("...") o JSON directo
    inner = typeof parsed === 'string' ? parsed : null;
  } catch {
    // No es JSON; tratar como string plano (fallback)
    inner = text;
  }

  // Si inner es null, el JSON parsed no era un string → respuesta plana, no cifrada
  if (inner === null) {
    try {
      // El resultado ya es JSON plano → retornarlo directamente
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  // Step 3: Descifrar el string interno byte-a-byte
  // La key se deriva asumiendo que el primer char descifrado es '[' o '{'
  for (const first of ['[', '{']) {
    const key = inner.charCodeAt(0) ^ first.charCodeAt(0);
    const chars = [];
    for (let i = 0; i < inner.length; i++) {
      chars.push(String.fromCharCode(inner.charCodeAt(i) ^ key));
    }
    const dec = chars.join('');
    try {
      return JSON.parse(dec);
    } catch {
      // siguiente clave
    }
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Upstream fetcher
// ─────────────────────────────────────────────────────────────────────────────
function hdrs(identity) {
  return {
    'Accept'             : 'application/json',
    'Accept-Language'   : 'es-ES,es;q=0.9,en;q=0.8',
    'Origin'             : CFG.DOMINICANA_BASE,
    'Referer'           : `${CFG.DOMINICANA_BASE}/`,
    'User-Agent'        : identity.ua,
    'X-Forwarded-For'   : identity.ip,
    'X-Real-IP'          : identity.ip,
    'sec-ch-ua'         : identity.secChUa,
    'sec-ch-ua-mobile'  : '?0',
    'sec-ch-ua-platform': identity.platformHint,
    'sec-fetch-dest'    : 'empty',
    'sec-fetch-mode'    : 'cors',
    'sec-fetch-site'    : 'same-site',
  };
}

async function fetchDominicana(path) {
  // Try primary base, then fallback if configured
  const bases = [];
  if (CFG.DOMINICANA_BASE) bases.push(CFG.DOMINICANA_BASE);
  if (CFG.FALLBACK_BASE  ) bases.push(CFG.FALLBACK_BASE);

  let lastError;

  for (const base of bases) {
    const id  = newIdentity();
    const url = `${base}${path}`;

    try {
      const res = await fetch(url, {
        headers: { ...hdrs(id), 'User-Agent': 'okhttp/4.9.2' },
      });

      // Solo 2xx es éxito. Intentar fallback para 4xx y 5xx.
      if (res.ok) {
        let bytes = new Uint8Array(await res.arrayBuffer());

        // Gzip
        if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
          bytes = pako.inflate(bytes);
        }

        const result = await xorDecrypt(bytes);
        if (result !== null) return result;
        lastError = new Error('XOR decrypt failed — API cipher may have changed');
        continue; // try next base
      }

      lastError = new Error(`HTTP ${res.status}`);
      continue; // try next base
    } catch (e) {
      lastError = e;
      continue; // try next base
    }
  }

  throw lastError || new Error('All upstream sources failed');
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — limpiar score de símbolos auxiliares (!, =, +, ?, X, etc.)
// Ejemplo: "!22" → "22", "=03" → "03", "+15" → "15"
// ─────────────────────────────────────────────────────────────────────────────
function stripHtml(html) {
  if (typeof html !== 'string') return html;
  return html.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').trim();
}

function cleanScore(score) {
  if (typeof score === 'string') {
    // Solo prefijo: "!22" → "22", "=03" → "03", "?2X" → "2X"
    return score.replace(/^[^0-9]+/, '');
  }
  if (Array.isArray(score)) {
    return score.map(item => Array.isArray(item) ? item.map(cleanScore) : cleanScore(item));
  }
  return score;
}

function cleanSession(session) {
  if (!session) return null;
  return {
    ...session,
    score: cleanScore(session.score),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalizers
// ─────────────────────────────────────────────────────────────────────────────
function normalizeCompanies(raw) {
  const list = Array.isArray(raw) ? raw : (raw.companies || raw.data || []);
  return list.map(item => {
    // Extraer todos los games con todos sus campos intactos
    const games = (item.games || []).map(game => ({
      id             : game.id,
      title          : game.title,
      quinielia      : game.quinielia ?? null,
      show_poll      : game.show_poll ?? null,
      logo           : game.logo || null,
      description    : stripHtml(game.description) || null,
      description_new: stripHtml(game.description_new) || null,
      updated_at     : game.updated_at || null,
      datetime       : game.datetime || null,
      mode           : game.mode || null,
      delay          : game.delay ?? false,
      delay_reason   : game.delay_reason || '',
      session        : cleanSession(game.session),
      sessions       : Array.isArray(game.sessions)
                         ? game.sessions.map(s => cleanSession(s))
                         : null,
    }));

    return {
      id             : item.id,
      title          : item.title,
      logo           : item.logo || null,
      description    : stripHtml(item.description) || '',
      description_new: stripHtml(item.description_new) || null,
      updated_at     : item.updated_at || null,
      datetime       : item.datetime || null,
      background_color: item.background_color || null,
      text_color      : item.text_color || null,
      games,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Route Handlers
// ─────────────────────────────────────────────────────────────────────────────
async function getCompanies(url) {
  try {
    const raw = await fetchDominicana('/companies?encrypt=true');
    return ok({ companies: normalizeCompanies(raw) });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

async function getGameById(path, url) {
  const gameId = path.split('/')[2];
  const date   = url.searchParams.get('date');

  if (!date) {
    // Solo company + game info — extraído de /companies
    try {
      const raw = await fetchDominicana('/companies?encrypt=true');
      const companies = Array.isArray(raw) ? raw : (raw.companies || []);

      for (const company of companies) {
        const gameList = Array.isArray(company.games) ? company.games : [];
        const found = gameList.find(g => String(g.id) === String(gameId));
        if (found) {
          return ok(found);
        }
      }
      return err(404, 'not_found', `Game ${gameId} not found`);
    } catch (e) {
      return err(502, 'upstream_error', e.message);
    }
  }

  // Con fecha → buscar historial vía /games?game_id=X&date=Y
  try {
    const raw = await fetchDominicana(`/games?game_id=${gameId}&date=${date}&encrypt=true`);
    return ok({ gameId: +gameId, date, data: raw });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

async function getHot(url) {
  try {
    const raw = await fetchDominicana('/hot?encrypt=true');
    return ok({ data: raw });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

async function getAllGames() {
  try {
    const raw = await fetchDominicana('/companies?encrypt=true');

    // companies viene como array directo o como { companies: [...] }
    const companies = Array.isArray(raw) ? raw : (raw.companies || []);

    // Extraer todos los games de cada compañía — array plano con todos los campos
    const allGames = [];
    for (const company of companies) {
      const gameList = Array.isArray(company.games) ? company.games : [];
      for (const game of gameList) {
        allGames.push({
          ...game,
          session : cleanSession(game.session),
          sessions: Array.isArray(game.sessions)
                      ? game.sessions.map(s => cleanSession(s))
                      : null,
        });
      }
    }

    return ok({
      total   : allGames.length,
      games   : allGames,
    });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

async function getBanners(url) {
  try {
    const raw = await fetchDominicana('/banners?encrypt');
    return ok({ data: raw });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

async function getConfig(url) {
  try {
    const raw = await fetchDominicana('/config?encrypt');
    return ok({ data: raw });
  } catch (e) {
    return err(502, 'upstream_error', e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// System
// ─────────────────────────────────────────────────────────────────────────────
async function handleStatus() {
  try {
    const id = newIdentity();
    const res = await fetch(`${CFG.DOMINICANA_BASE}/companies?encrypt=true`, {
      method: 'HEAD',
      headers: { ...hdrs(id), 'User-Agent': 'okhttp/4.9.2' },
    });
    return ok({
      service  : 'lotery-apiv3',
      version  : '3.1.0',
      upstream : 'ok',
      status   : res.status,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    return new Response(JSON.stringify({
      ok      : false,
      service : 'lotery-apiv3',
      upstream: 'error',
      error   : e.message,
      timestamp: new Date().toISOString(),
    }), { status: 503, headers: jsonHeaders() });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────
function ok(body) {
  return new Response(JSON.stringify({ ok: true, ...body }), { headers: jsonHeaders() });
}

function err(status, code, msg) {
  return new Response(JSON.stringify({ ok: false, error: { code, message: msg } }), {
    status,
    headers: jsonHeaders(),
  });
}

function jsonHeaders() {
  return {
    'Content-Type'             : 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Origin',
    'X-Content-Type-Options'   : 'nosniff',
    'X-Robots-Tag'             : 'noindex, nofollow',
  };
}

function cors204() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin' : '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Origin',
    },
  });
}

function noContent() {
  return new Response(null, { status: 204 });
}

// ─────────────────────────────────────────────────────────────────────────────
// Static Pages
// ─────────────────────────────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════════
// Landing — "Dominican Gold"
// ══════════════════════════════════════════════════════════════════════════════
function landingPage() {
  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>lotery-apiv3 · API de Loterías Dominicanas</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40'%3E%3Crect width='40' height='40' rx='8' fill='%23c9950a'/%3E%3Ctext x='20' y='28' font-size='20' text-anchor='middle' font-family='Georgia' font-weight='bold' fill='%23000'%3EL%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#ffffff;--surface:#f5f5f5;--surface2:#efefef;--border:#e0e0e0;
  --gold:#c9950a;--gold-bright:#d4a812;--gold-muted:#a07808;
  --red:#c82020;--red-bright:#e03030;
  --text:#111111;--text-secondary:#555555;--muted:#999999;
  --font-body:'DM Sans',system-ui,sans-serif;
  --font-mono:'JetBrains Mono','Fira Code',monospace;
}
html{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}
body{background:var(--bg);color:var(--text);font-family:var(--font-body);min-height:100vh}
.container{max-width:720px;margin:0 auto;padding:0 24px}

/* Header */
header{padding:48px 0 40px;border-bottom:1px solid var(--border);margin-bottom:40px}
.header-inner{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.logo-icon{width:36px;height:36px;border-radius:8px;background:var(--gold);display:flex;align-items:center;justify-content:center;font-family:Georgia,serif;font-size:18px;font-weight:bold;color:#000;flex-shrink:0}
.logo-text{font-size:18px;font-weight:600;color:var(--text)}
.version-badge{font-family:var(--font-mono);font-size:11px;background:var(--surface);border:1px solid var(--border);color:var(--text-secondary);padding:4px 10px;border-radius:20px}

/* Hero */
.hero{margin-bottom:40px}
.hero h1{font-size:clamp(28px,5vw,40px);font-weight:600;color:var(--text);margin-bottom:10px;letter-spacing:-.01em}
.hero p{color:var(--text-secondary);font-size:15px;line-height:1.6;max-width:480px}
.token-hint{display:inline-flex;align-items:center;gap:8px;margin-top:16px;
  background:#fff8e6;border:1px solid #f0d080;border-radius:8px;padding:8px 14px;
  font-family:var(--font-mono);font-size:12px;color:#7a5800}
.token-hint span{color:#b08000;font-size:11px}

/* Sections */
.section{margin-bottom:32px}
.section-title{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}

/* Endpoint rows */
.endpoint{display:flex;align-items:center;gap:12px;padding:12px 16px;
  background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:6px;
  transition:border-color .15s,box-shadow .15s}
.endpoint:hover{border-color:var(--gold);box-shadow:0 0 0 3px rgba(201,149,10,.08)}
.method{font-family:var(--font-mono);font-size:10px;font-weight:700;
  background:#e8f4ff;color:#0066cc;border:1px solid #c0d8f0;
  padding:3px 8px;border-radius:4px;flex-shrink:0;min-width:44px;text-align:center;letter-spacing:.02em}
.path{font-family:var(--font-mono);font-size:13px;color:var(--text);flex:1;word-break:break-all}
.path .param{color:var(--gold-muted)}
.tag{font-family:var(--font-mono);font-size:10px;color:var(--muted);flex-shrink:0}

/* Badges */
.badge{font-family:var(--font-mono);font-size:10px;font-weight:500;padding:3px 10px;border-radius:8px;flex-shrink:0}
.badge-xor{background:#fff0f0;color:var(--red-bright);border:1px solid #f8c0c0}
.badge-sys{background:#f0f0f0;color:var(--muted);border:1px solid #e0e0e0}

/* Divider */
.divider{border:none;border-top:1px solid var(--border);margin:32px 0}

/* Footer */
footer{text-align:center;padding:24px 0;border-top:1px solid var(--border);color:var(--muted);font-size:12px;font-family:var(--font-mono)}

@media(max-width:500px){.endpoint{flex-wrap:wrap}.path{font-size:12px}}
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="header-inner">
      <a class="logo" href="/">
        <div class="logo-icon">L</div>
        <span class="logo-text">lotery-apiv3</span>
      </a>
      <span class="version-badge">v3.1.0</span>
    </div>
  </header>

  <section class="hero">
    <h1>API de Loterías Dominicanas</h1>
    <p>Proxy con identidad anónima para loteriasdominicanas.com. Descifra respuestas XOR byte-cipher + gzip automáticamente.</p>
    <div class="token-hint">
      <span>AUTH</span>
      Authorization: Bearer &lt;token&gt;
    </div>
  </section>

  <!-- API Endpoints -->
  <section class="section">
    <div class="section-title">Endpoints</div>

    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/companies</span>
      <span class="tag">companies</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/games</span>
      <span class="tag">all games</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/games/<span class="param">:id</span></span>
      <span class="tag">by id</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/games/<span class="param">:id</span><span class="param">?date=</span></span>
      <span class="tag">by id + date</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/hot</span>
      <span class="tag">hot numbers</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/banners</span>
      <span class="tag">banners</span>
      <span class="badge badge-xor">XOR</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/config</span>
      <span class="tag">config</span>
      <span class="badge badge-xor">XOR</span>
    </div>
  </section>

  <hr class="divider">

  <!-- System -->
  <section class="section">
    <div class="section-title">System (público)</div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/status</span>
      <span class="tag">health</span>
      <span class="badge badge-sys">PUBLIC</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/docs</span>
      <span class="tag">swagger</span>
      <span class="badge badge-sys">PUBLIC</span>
    </div>
    <div class="endpoint">
      <span class="method">GET</span>
      <span class="path">/openapi.json</span>
      <span class="tag">openapi 3.0</span>
      <span class="badge badge-sys">PUBLIC</span>
    </div>
  </section>

  <footer>
    lotery-apiv3 v3.1.0 · Cloudflare Worker · XOR decryption · Identity rotation por request
  </footer>
</div>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
}

// ══════════════════════════════════════════════════════════════════════════════
// Swagger UI
// ══════════════════════════════════════════════════════════════════════════════
function swaggerPage() {
  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>lotery-apiv3 — API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <style>
    body{margin:0;background:#ffffff}
    .topbar{background:#f5f5f5!important;border-bottom:1px solid #e0e0e0!important}
    #swagger-ui{min-height:100vh}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout",
      deepLinking: true,
    });
  </script>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
}

// ══════════════════════════════════════════════════════════════════════════════
// OpenAPI 3.0 Spec
// ══════════════════════════════════════════════════════════════════════════════
function openApiSpec() {
  const spec = {
    openapi: "3.0.3",
    info: {
      title      : "lotery-apiv3",
      description: "Proxy para loteriasdominicanas.com — descifra XOR byte-cipher + gzip automáticamente.",
      version    : "3.1.0",
    },
    servers: [{ url: "/", description: "lotery-apiv3" }],
    tags: [
      { name: "System", description: "Rutas públicas" },
      { name: "Loterias Dominicanas", description: "loteriasdominicanas.com/mobile-api/v3 — cifrado XOR" },
    ],
    paths: {

      "/status": {
        get: {
          summary  : "Health check",
          tags     : ["System"],
          security : [],
          responses: {
            200: { description: "Servicio activo", content: { "application/json": { schema: { type: "object", properties: { ok: { type: "boolean" }, service: { type: "string" }, version: { type: "string" }, timestamp: { type: "string" } } } } } },
            503: { description: "Upstream caído" },
          },
        },
      },

      "/companies": {
        get: {
          summary: "Empresas de lotería — Compañías disponibles",
          tags   : ["Loterias Dominicanas"],
          responses: {
            200: { description: "Lista de compañías", content: { "application/json": { schema: { type: "object", properties: { ok: { type: "boolean" }, companies: { type: "array" } } } } } },
            502: { description: "Error upstream o fallo en descifrado" },
          },
        },
      },

      "/hot": {
        get: {
          summary: "Números calientes",
          tags   : ["Loterias Dominicanas"],
          responses: {
            200: { description: "Datos de números calientes", content: { "application/json": { schema: { type: "object" } } } },
            502: { description: "Error upstream" },
          },
        },
      },

      "/games": {
        get: {
          summary   : "Todos los juegos — extraídos de /companies",
          tags      : ["Loterias Dominicanas"],
          responses: {
            200: { description: "Todos los juegos agrupados por compañía", content: { "application/json": { schema: { type: "object", properties: { ok: { type: "boolean" }, total: { type: "integer" }, companies: { type: "array" } } } } } },
            502: { description: "Error upstream" },
          },
        },
      },

      "/games/{id}": {
        get: {
          summary   : "Un juego por ID — con historial opcional por fecha",
          tags      : ["Loterias Dominicanas"],
          parameters: [
            { name: "id",   in: "path",  required: true,  schema: { type: "integer" },             description: "Game ID" },
            { name: "date", in: "query", required: false, schema: { type: "string", format: "date" }, description: "YYYY-MM-DD — incluye historial" },
          ],
          responses : {
            200: { description: "Detalle del juego (sin fecha) o juego + historial (con fecha)" },
            404: { description: "Juego no encontrado" },
            502: { description: "Error upstream" },
          },
        },
      },

      "/banners": {
        get: {
          summary: "Banners",
          tags   : ["Loterias Dominicanas"],
          responses: {
            200: { description: "Datos de banners", content: { "application/json": { schema: { type: "object" } } } },
            502: { description: "Error upstream" },
          },
        },
      },

      "/config": {
        get: {
          summary: "Configuración",
          tags   : ["Loterias Dominicanas"],
          responses: {
            200: { description: "Configuración de la app", content: { "application/json": { schema: { type: "object" } } } },
            502: { description: "Error upstream" },
          },
        },
      },

    },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "token" },
      },
    },
    security: [{ bearerAuth: [] }],
  };

  return new Response(JSON.stringify(spec, null, 2), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}