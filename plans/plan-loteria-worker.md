# loteria-worker — Plan

## Objetivo
Refactorizar el Cloudflare Worker existente en `D:\AI CODES\loteria-worker` para que soporte **dos APIs upstream**:

1. **elboletoganador.com** — ya funciona, sin cifrado, upstream existente
2. **loteriasdominicanas.com** — endpoint `mobile-api/v3`, requiere XOR decryption byte-by-byte

## Arquitectura

```
Client ──Bearer Token──▶ Worker ──XOR decrypt──▶ loteriasdominicanas.com
                           ├── no encrypt ──────▶ elboletoganador.com
                           ├── / (docs) ─────────▶ Static HTML
                           └── /docs, /openapi ──▶ Swagger UI
```

## Rutas

| Método | Ruta | Upstream | Auth |
|--------|------|----------|------|
| GET | `/` | Static HTML | ❌ |
| GET | `/docs` | Swagger UI | ❌ |
| GET | `/openapi.json` | OpenAPI spec | ❌ |
| GET | `/status` | Health check | ❌ |
| GET | `/games` | elboletoganador `/api/companies/loterias` | ✅ |
| GET | `/games/jackpot` | elboletoganador `/api/companies/loterias` | ✅ |
| GET | `/games/:id` | elboletoganador `/api/companies/loterias` | ✅ |
| GET | `/games/:id/draws?date=` | elboletoganador `/api/sorteos/buscar/historial` | ✅ |
| GET | `/games/:id/on-this-day?date=&before=&after=&dayOfWeek=` | elboletoganador `/api/tabla/un-dia-como-hoy` | ✅ |
| GET | `/dominicana/:endpoint?encrypt=true` | loteriasdominicanas `/mobile-api/v3/:endpoint` | ✅ |
| GET | `/dominicana/companies?encrypt=true` | loteriasdominicanas `/mobile-api/v3/companies` | ✅ |

## Cambios clave

### 1. `worker.js`
- Refactorizar estructura con módulos claros (config, auth, identity, xor, fetch, handlers, helpers)
- Agregar función `xorDecrypt(encrypted)` — deriva key de `encrypted[0] XOR '['` y `'{'`
- Agregar upstream `loteriasdominicanas.com` con gzip + XOR
- Nueva ruta `/dominicana/:endpoint` para endpoints de RD
- Mantener toda la lógica existente de elboletoganador
- Landing page premium "Dominican Gold" aesthetic

### 2. `wrangler.toml`
- Agregar `BEARER_TOKEN` como var (ya existe con valor placeholder)
- Agregar dominio de upstreams como secrets o vars

### 3. Landing page `/`
- Estética "Dominican Gold" — dorado/naranja vibrante con negro profundo
- Muestra ambos proveedores: 🇩🇴 RD Lotteries + 🇩🇴 El Boleto Ganador
- Lista de endpoints dividida por proveedor
- Animaciones stagger de carga

## Decisión de diseño: XOR decryption

- La API dominicana devuelve JSON cifrado byte-by-byte con XOR
- La key se deriva: `key = encrypted[0] ^ ord('[')` o `encrypted[0] ^ ord('{')`
- Se prueban ambas; la primera que produce JSON válido gana
- Si ambas fallan → dump a `debug_encrypted.json` (en edge esto sería un log)

##验收标准

- [ ] `GET /dominicana/companies?encrypt=true` con auth retorna companies de RD
- [ ] `GET /games` retorna lista de juegos de elboletoganador
- [ ] Landing page carga con estética premium
- [ ] Swagger UI muestra spec completa
- [ ] Sin auth → 401
- [ ] Error upstream → 502 con mensaje descriptivo