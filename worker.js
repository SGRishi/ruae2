const encoder = new TextEncoder();

const COUNTDOWN_ACCESS_COOKIE_PREFIX = 'countdown_access_';
const COUNTDOWN_ACCESS_MAX_AGE_SECONDS = 60 * 60 * 24;
const COUNTDOWN_MAX_FUTURE_MS = 1000 * 60 * 60 * 24 * 365 * 5;
const COUNTDOWN_TITLE_MAX_LENGTH = 120;
const COUNTDOWN_UNITS = ['days', 'hours', 'minutes', 'seconds'];
const EVENT_RESOLVE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

const PASSWORD_SALT_BYTES = 16;
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = 'SHA-256';

const DEFAULT_ALLOWED_ORIGINS = new Set(['https://rishisubjects.co.uk', 'https://www.rishisubjects.co.uk']);
const DEV_LOCAL_ORIGINS = new Set([
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:8788',
  'http://127.0.0.1:8788',
  'http://localhost:8789',
  'http://127.0.0.1:8789',
]);

const resolveEventDateCache = new Map();

function bytesToBase64(bytes) {
  let output = '';
  for (let i = 0; i < bytes.length; i += 1) {
    output += String.fromCharCode(bytes[i]);
  }
  return btoa(output);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  const base64 = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return base64ToBytes(padded);
}

function randomToken(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function timingSafeEqual(a, b) {
  const aBytes = encoder.encode(String(a || ''));
  const bBytes = encoder.encode(String(b || ''));
  if (aBytes.length !== bBytes.length) return false;
  let mismatch = 0;
  for (let i = 0; i < aBytes.length; i += 1) {
    mismatch |= aBytes[i] ^ bBytes[i];
  }
  return mismatch === 0;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;

  for (const part of String(cookieHeader).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (!key) continue;
    if (Object.prototype.hasOwnProperty.call(cookies, key)) continue;

    const rawValue = part.slice(idx + 1).trim();
    try {
      cookies[key] = decodeURIComponent(rawValue);
    } catch {
      cookies[key] = rawValue;
    }
  }

  return cookies;
}

function parseSetCookieValue(setCookieHeader) {
  const first = String(setCookieHeader || '').split(';', 1)[0] || '';
  const idx = first.indexOf('=');
  if (idx === -1) return null;
  return {
    name: first.slice(0, idx),
    value: first.slice(idx + 1),
  };
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path || '/'}`);
  parts.push(`SameSite=${options.sameSite || 'Lax'}`);

  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }
  if (typeof options.maxAge === 'number') {
    parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  }
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure !== false) parts.push('Secure');
  if (options.priority) parts.push(`Priority=${options.priority}`);

  return parts.join('; ');
}

function secureCookieForUrl(url, env) {
  if (String(env.COOKIE_SECURE || '').toLowerCase() === 'false') return false;
  return url.protocol === 'https:';
}

function cookieDomainForUrl(url, env) {
  const explicit = String(env.COOKIE_DOMAIN || '').trim();
  if (explicit) return explicit;

  const host = String(url.hostname || '').toLowerCase();
  if (host === 'rishisubjects.co.uk' || host.endsWith('.rishisubjects.co.uk')) {
    return '.rishisubjects.co.uk';
  }

  return '';
}

function normalizeCountdownId(value) {
  const id = String(value || '').trim();
  return /^[A-Za-z0-9_-]{6,120}$/.test(id) ? id : '';
}

function normalizeToken(value) {
  const token = String(value || '').trim();
  return /^[A-Za-z0-9_-]{16,240}$/.test(token) ? token : '';
}

function normalizeCountdownTitle(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, COUNTDOWN_TITLE_MAX_LENGTH);
}

function normalizeCountdownUnits(value) {
  if (!Array.isArray(value)) return [];

  const units = [];
  for (const item of value) {
    const unit = String(item || '').trim().toLowerCase();
    if (!COUNTDOWN_UNITS.includes(unit)) continue;
    if (!units.includes(unit)) units.push(unit);
  }

  return units;
}

function normalizeOrigin(origin) {
  try {
    const parsed = new URL(String(origin || ''));
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return `${parsed.protocol}//${parsed.host}`.toLowerCase();
  } catch {
    return '';
  }
}

function configuredAllowedOrigins(env) {
  const set = new Set(DEFAULT_ALLOWED_ORIGINS);

  const raw = String(env.ALLOWED_ORIGINS || '').trim();
  if (raw) {
    for (const part of raw.split(',')) {
      const normalized = normalizeOrigin(part.trim());
      if (normalized) set.add(normalized);
    }
  }

  if (String(env.ALLOW_LOCALHOST_ORIGINS || '').toLowerCase() === 'true') {
    for (const origin of DEV_LOCAL_ORIGINS) {
      set.add(origin);
    }
  }

  return set;
}

function isOriginAllowed(origin, env) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;
  return configuredAllowedOrigins(env).has(normalized);
}

function applyCommonSecurityHeaders(headers) {
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()');
}

function appendVary(existing, value) {
  const values = String(existing || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  if (values.some((item) => item.toLowerCase() === value.toLowerCase())) {
    return values.join(', ');
  }

  values.push(value);
  return values.join(', ');
}

function addCorsHeaders(request, env, headers) {
  const origin = request.headers.get('Origin');
  if (!origin) return;
  if (!isOriginAllowed(origin, env)) return;

  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
  headers.set('Access-Control-Allow-Methods', 'GET,HEAD,POST,PATCH,OPTIONS');
  headers.set('Vary', appendVary(headers.get('Vary'), 'Origin'));
}

function appendSetCookies(headers, cookies = []) {
  for (const cookie of cookies) {
    if (!cookie) continue;
    headers.append('Set-Cookie', cookie);
  }
}

function jsonResponse(request, env, payload, status = 200, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  addCorsHeaders(request, env, headers);
  applyCommonSecurityHeaders(headers);
  appendSetCookies(headers, options.cookies || []);
  return new Response(JSON.stringify(payload), { status, headers });
}

function notFound(request, env) {
  return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
}

function methodNotAllowed(request, env, allow = []) {
  return jsonResponse(request, env, { ok: false, error: 'Method not allowed.' }, 405, {
    headers: {
      Allow: allow.join(', '),
    },
  });
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function countdownAccessCookieName(timerId) {
  const id = normalizeCountdownId(timerId);
  if (!id) return '';
  return `${COUNTDOWN_ACCESS_COOKIE_PREFIX}${id}`;
}

function buildCountdownAccessCookie(timerId, token, url, env) {
  const name = countdownAccessCookieName(timerId);
  if (!name) return '';

  return serializeCookie(name, token, {
    path: '/',
    domain: cookieDomainForUrl(url, env),
    sameSite: 'Lax',
    secure: secureCookieForUrl(url, env),
    httpOnly: true,
    maxAge: COUNTDOWN_ACCESS_MAX_AGE_SECONDS,
    priority: 'High',
  });
}

function toInt(value, fallback = Number.NaN) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function derivePasswordHash(password, saltBytes, pepper = '') {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`${String(password || '')}${String(pepper || '')}`),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: PBKDF2_HASH,
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
    },
    keyMaterial,
    256
  );

  return bytesToBase64Url(new Uint8Array(derived));
}

async function createPasswordRecord(password, env) {
  const saltBytes = new Uint8Array(PASSWORD_SALT_BYTES);
  crypto.getRandomValues(saltBytes);

  const salt = bytesToBase64Url(saltBytes);
  const hash = await derivePasswordHash(password, saltBytes, env.PASSWORD_PEPPER);

  return { salt, hash };
}

async function verifyPassword(password, salt, expectedHash, env) {
  if (!salt || !expectedHash) return false;

  let saltBytes;
  try {
    saltBytes = base64UrlToBytes(salt);
  } catch {
    return false;
  }

  const actual = await derivePasswordHash(password, saltBytes, env.PASSWORD_PEPPER);
  return timingSafeEqual(actual, expectedHash);
}

async function hmacSha256(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(String(secret || '')),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(String(message || '')));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function issueCountdownAccessToken(secret, timerId, nowSeconds) {
  const payload = {
    timerId: normalizeCountdownId(timerId),
    exp: Number(nowSeconds) + COUNTDOWN_ACCESS_MAX_AGE_SECONDS,
    nonce: randomToken(8),
  };

  const encodedPayload = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
  const signature = await hmacSha256(secret, encodedPayload);
  return `${encodedPayload}.${signature}`;
}

async function verifyCountdownAccessToken(token, secret, timerId, nowSeconds) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return false;

  const [encodedPayload, providedSignature] = parts;
  if (!encodedPayload || !providedSignature) return false;

  const expectedSignature = await hmacSha256(secret, encodedPayload);
  if (!timingSafeEqual(providedSignature, expectedSignature)) return false;

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encodedPayload)));
  } catch {
    return false;
  }

  const normalizedTimerId = normalizeCountdownId(timerId);
  if (!normalizedTimerId || payload.timerId !== normalizedTimerId) return false;

  const exp = toInt(payload.exp);
  if (!Number.isFinite(exp) || exp < Number(nowSeconds)) return false;

  return true;
}

async function hasCountdownAccess(request, env, timerId, nowSeconds) {
  if (!env.SESSION_SECRET) return false;

  const cookies = parseCookies(request.headers.get('Cookie'));
  const cookieName = countdownAccessCookieName(timerId);
  if (!cookieName) return false;

  const token = String(cookies[cookieName] || '').trim();
  if (!token) return false;

  return verifyCountdownAccessToken(token, env.SESSION_SECRET, timerId, nowSeconds);
}

function countdownUnitsForStorage(units) {
  return JSON.stringify(normalizeCountdownUnits(units));
}

function countdownUnitsFromStorage(serialized) {
  try {
    const parsed = JSON.parse(String(serialized || '[]'));
    return normalizeCountdownUnits(parsed);
  } catch {
    return [];
  }
}

function countdownRowToTimer(row) {
  if (!row || typeof row !== 'object') return null;

  const id = normalizeCountdownId(row.id);
  const token = normalizeToken(row.token);
  const startAtMs = Number(row.start_at_ms ?? row.created_at_ms);
  const deadlineMs = Number(row.deadline_ms);
  const createdAtMs = Number(row.created_at_ms ?? startAtMs);
  const updatedAtMs = Number(row.updated_at_ms ?? createdAtMs);
  const title = normalizeCountdownTitle(row.title_text || '') || 'Countdown';
  const units = countdownUnitsFromStorage(row.display_units);

  if (!id || !token || !Number.isFinite(startAtMs) || !Number.isFinite(deadlineMs)) {
    return null;
  }

  return {
    id,
    token,
    startAtMs,
    deadlineMs,
    endAtMs: deadlineMs,
    createdAtMs,
    updatedAtMs,
    title,
    units: units.length ? units : [...COUNTDOWN_UNITS],
    isPublic: Boolean(Number(row.is_public)),
    passSalt: String(row.pass_salt || ''),
    passHash: String(row.pass_hash || ''),
  };
}

function countdownHasStoredPassword(timer) {
  return Boolean(timer && timer.passSalt && timer.passHash);
}

function countdownClientTimer(timer, canEdit = false) {
  const units = normalizeCountdownUnits(timer?.units);
  return {
    id: timer.id,
    title: normalizeCountdownTitle(timer.title) || 'Countdown',
    isPublic: Boolean(timer.isPublic),
    canEdit: Boolean(canEdit),
    startAtMs: Number(timer.startAtMs),
    endAtMs: Number(timer.deadlineMs),
    deadlineMs: Number(timer.deadlineMs),
    createdAtMs: Number(timer.createdAtMs),
    updatedAtMs: Number(timer.updatedAtMs),
    units: units.length ? units : [...COUNTDOWN_UNITS],
  };
}

export function createMemoryCountdownStore() {
  const timers = new Map();

  return {
    async createTimer(input) {
      const id = normalizeCountdownId(input.id) || randomToken(9);
      const token = normalizeToken(input.token) || randomToken(24);

      const row = {
        id,
        token,
        start_at_ms: Number(input.startAtMs),
        deadline_ms: Number(input.deadlineMs),
        title_text: normalizeCountdownTitle(input.title) || 'Countdown',
        display_units: countdownUnitsForStorage(input.units),
        is_public: input.isPublic ? 1 : 0,
        pass_salt: String(input.passSalt || ''),
        pass_hash: String(input.passHash || ''),
        created_at_ms: Number(input.createdAtMs),
        updated_at_ms: Number(input.updatedAtMs),
      };

      timers.set(id, row);
      return countdownRowToTimer(row);
    },

    async getTimerById(id) {
      const normalizedId = normalizeCountdownId(id);
      if (!normalizedId) return null;

      const row = timers.get(normalizedId);
      return countdownRowToTimer(row);
    },

    async setTimerVisibility(id, isPublic, nowMs, options = {}) {
      const normalizedId = normalizeCountdownId(id);
      if (!normalizedId) return null;

      const row = timers.get(normalizedId);
      if (!row) return null;

      row.is_public = isPublic ? 1 : 0;
      row.updated_at_ms = Number(nowMs);

      if (isPublic) {
        row.pass_salt = '';
        row.pass_hash = '';
      } else if (options.passSalt && options.passHash) {
        row.pass_salt = String(options.passSalt);
        row.pass_hash = String(options.passHash);
      }

      timers.set(normalizedId, row);
      return countdownRowToTimer(row);
    },
  };
}

export function createCountdownD1Store(db) {
  let initialized = false;
  let initializing = null;

  async function tryMigration(sql) {
    try {
      await db.prepare(sql).run();
    } catch {
      // Ignore migration errors for already-applied columns.
    }
  }

  async function ensureInitialized() {
    if (initialized) return;
    if (initializing) {
      await initializing;
      return;
    }

    initializing = (async () => {
      await db.prepare(
        `CREATE TABLE IF NOT EXISTS countdown_timers (
          id TEXT PRIMARY KEY,
          token TEXT NOT NULL,
          start_at_ms INTEGER,
          deadline_ms INTEGER NOT NULL,
          title_text TEXT,
          display_units TEXT,
          is_public INTEGER NOT NULL DEFAULT 0,
          pass_salt TEXT,
          pass_hash TEXT,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        )`
      ).run();

      await db.prepare(
        `CREATE INDEX IF NOT EXISTS idx_countdown_timers_deadline
         ON countdown_timers (deadline_ms)`
      ).run();

      await tryMigration('ALTER TABLE countdown_timers ADD COLUMN start_at_ms INTEGER');
      await tryMigration('ALTER TABLE countdown_timers ADD COLUMN pass_salt TEXT');
      await tryMigration('ALTER TABLE countdown_timers ADD COLUMN pass_hash TEXT');
      await tryMigration('ALTER TABLE countdown_timers ADD COLUMN title_text TEXT');
      await tryMigration('ALTER TABLE countdown_timers ADD COLUMN display_units TEXT');

      initialized = true;
    })();

    await initializing;
    initializing = null;
  }

  return {
    async createTimer(input) {
      await ensureInitialized();

      const id = normalizeCountdownId(input.id) || randomToken(9);
      const token = normalizeToken(input.token) || randomToken(24);

      const row = {
        id,
        token,
        start_at_ms: Number(input.startAtMs),
        deadline_ms: Number(input.deadlineMs),
        title_text: normalizeCountdownTitle(input.title) || 'Countdown',
        display_units: countdownUnitsForStorage(input.units),
        is_public: input.isPublic ? 1 : 0,
        pass_salt: String(input.passSalt || ''),
        pass_hash: String(input.passHash || ''),
        created_at_ms: Number(input.createdAtMs),
        updated_at_ms: Number(input.updatedAtMs),
      };

      await db
        .prepare(
          `INSERT INTO countdown_timers (
            id,
            token,
            start_at_ms,
            deadline_ms,
            title_text,
            display_units,
            is_public,
            pass_salt,
            pass_hash,
            created_at_ms,
            updated_at_ms
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
        )
        .bind(
          row.id,
          row.token,
          row.start_at_ms,
          row.deadline_ms,
          row.title_text,
          row.display_units,
          row.is_public,
          row.pass_salt,
          row.pass_hash,
          row.created_at_ms,
          row.updated_at_ms
        )
        .run();

      return countdownRowToTimer(row);
    },

    async getTimerById(id) {
      await ensureInitialized();

      const normalizedId = normalizeCountdownId(id);
      if (!normalizedId) return null;

      const row = await db
        .prepare(
          `SELECT
             id,
             token,
             start_at_ms,
             deadline_ms,
             title_text,
             display_units,
             is_public,
             pass_salt,
             pass_hash,
             created_at_ms,
             updated_at_ms
           FROM countdown_timers
           WHERE id = ?1
           LIMIT 1`
        )
        .bind(normalizedId)
        .first();

      return countdownRowToTimer(row);
    },

    async setTimerVisibility(id, isPublic, nowMs, options = {}) {
      await ensureInitialized();

      const normalizedId = normalizeCountdownId(id);
      if (!normalizedId) return null;

      const passSalt = isPublic ? '' : String(options.passSalt || '');
      const passHash = isPublic ? '' : String(options.passHash || '');

      await db
        .prepare(
          `UPDATE countdown_timers
           SET is_public = ?1,
               pass_salt = ?2,
               pass_hash = ?3,
               updated_at_ms = ?4
           WHERE id = ?5`
        )
        .bind(isPublic ? 1 : 0, passSalt, passHash, Number(nowMs), normalizedId)
        .run();

      return this.getTimerById(normalizedId);
    },
  };
}

function normalizeQuery(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function normalizeTimeZone(value) {
  const candidate = String(value || '').trim();
  return candidate || 'Europe/London';
}

function normalizeHttpUrl(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

function extractResponsesOutputText(payload) {
  if (payload && typeof payload.output_text === 'string' && payload.output_text.trim()) {
    return payload.output_text.trim();
  }

  if (Array.isArray(payload?.output)) {
    for (const item of payload.output) {
      if (!item || !Array.isArray(item.content)) continue;
      for (const content of item.content) {
        if (!content) continue;
        if (typeof content.text === 'string' && content.text.trim()) {
          return content.text.trim();
        }
      }
    }
  }

  return '';
}

async function callResponsesApi(env, body) {
  const apiKey = String(env.OPENAI_API_KEY || '').trim();
  if (!apiKey) {
    return { ok: false, status: 503, error: 'Date resolver is not configured.' };
  }

  let response;
  try {
    response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, status: 502, error: 'Date resolver request failed.' };
  }

  if (!response.ok) {
    return { ok: false, status: 502, error: 'Date resolver request failed.' };
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    return { ok: false, status: 502, error: 'Date resolver returned malformed JSON.' };
  }

  const outputText = extractResponsesOutputText(payload);
  if (!outputText) {
    return { ok: false, status: 502, error: 'Date resolver returned no structured output.' };
  }

  try {
    const parsed = JSON.parse(outputText);
    return { ok: true, data: parsed };
  } catch {
    return { ok: false, status: 502, error: 'Date resolver returned malformed structured data.' };
  }
}

async function handleResolveDate(request, env, url, nowMs) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const query = normalizeQuery(url.searchParams.get('q'));
  if (!query) {
    return jsonResponse(request, env, { ok: false, error: 'Missing query.' }, 400);
  }

  const timeZone = normalizeTimeZone(url.searchParams.get('timezone') || url.searchParams.get('timeZone'));
  const cacheKey = `${query.toLowerCase()}|${timeZone.toLowerCase()}`;

  const cached = resolveEventDateCache.get(cacheKey);
  if (cached && cached.expiresAtMs > nowMs) {
    return jsonResponse(request, env, cached.payload, 200);
  }

  const resolveResult = await callResponsesApi(env, {
    model: String(env.OPENAI_MODEL || 'gpt-4o-mini'),
    instructions:
      'Find an authoritative source using web search and return a concrete date/time with source details. If uncertain, say no reliable source is available.',
    tools: [{ type: 'web_search_preview' }],
    input: `Query: ${query}\nTimezone: ${timeZone}`,
    text: {
      format: {
        type: 'json_schema',
        name: 'countdown_resolved_date_with_source',
        strict: false,
        schema: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            datetime_iso: { type: ['string', 'null'] },
            timezone: { type: ['string', 'null'] },
            source_url: { type: ['string', 'null'] },
            source_title: { type: ['string', 'null'] },
            confidence: { type: ['string', 'null'] },
            note: { type: ['string', 'null'] },
          },
          required: ['datetime_iso', 'source_url'],
          additionalProperties: true,
        },
      },
    },
  });

  if (!resolveResult.ok) {
    return jsonResponse(request, env, { ok: false, error: resolveResult.error }, resolveResult.status);
  }

  const raw = resolveResult.data || {};
  const datetimeIso = String(raw.datetime_iso || raw.isoUtc || '').trim();
  const sourceUrl = normalizeHttpUrl(raw.source_url || raw.sourceUrl || '');

  if (!datetimeIso || !sourceUrl) {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: 'No reliable source provided a concrete date.',
        note: String(raw.note || '').trim(),
      },
      422
    );
  }

  const payload = {
    ok: true,
    query,
    title: normalizeQuery(raw.title || query) || query,
    datetime_iso: datetimeIso,
    timezone: normalizeTimeZone(raw.timezone || timeZone),
    source_url: sourceUrl,
    source_title: normalizeQuery(raw.source_title || raw.sourceTitle || ''),
    retrieved_at_utc: new Date(nowMs).toISOString(),
    confidence: normalizeQuery(raw.confidence || 'medium').toLowerCase() || 'medium',
    note: normalizeQuery(raw.note || ''),
  };

  resolveEventDateCache.set(cacheKey, {
    payload,
    expiresAtMs: nowMs + EVENT_RESOLVE_CACHE_TTL_MS,
  });

  return jsonResponse(request, env, payload, 200);
}

async function handleResolveEventDate(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return methodNotAllowed(request, env, ['GET', 'POST']);
  }

  let query = '';
  let timeZone = '';

  if (request.method === 'GET') {
    query = normalizeQuery(url.searchParams.get('q'));
    timeZone = normalizeTimeZone(url.searchParams.get('timezone') || url.searchParams.get('timeZone'));
  } else {
    const body = await readJsonBody(request);
    query = normalizeQuery(body?.query || body?.q);
    timeZone = normalizeTimeZone(body?.timezone || body?.timeZone);
  }

  if (!query) {
    return jsonResponse(request, env, { ok: false, error: 'Missing query.' }, 400);
  }

  const resolveResult = await callResponsesApi(env, {
    model: String(env.OPENAI_MODEL || 'gpt-4o-mini'),
    instructions:
      'Resolve a real-world event date/time with a reliable source when possible. Return structured JSON only.',
    tools: [{ type: 'web_search_preview' }],
    input: `Query: ${query}\nTimezone: ${timeZone || 'Europe/London'}`,
    text: {
      format: {
        type: 'json_schema',
        name: 'countdown_event_date',
        strict: false,
        schema: {
          type: 'object',
          properties: {
            isoUtc: { type: ['string', 'null'] },
            display: { type: ['string', 'null'] },
            confidence: { type: ['string', 'null'] },
            notes: { type: ['string', 'null'] },
            ambiguous: { type: ['boolean', 'null'] },
            suggestions: { type: ['array', 'null'], items: { type: 'string' } },
          },
          additionalProperties: true,
        },
      },
    },
  });

  if (!resolveResult.ok) {
    return jsonResponse(request, env, { ok: false, error: resolveResult.error }, resolveResult.status);
  }

  const raw = resolveResult.data || {};
  return jsonResponse(request, env, {
    ok: true,
    query,
    isoUtc: String(raw.isoUtc || raw.datetime_iso || '').trim(),
    display: normalizeQuery(raw.display || ''),
    confidence: normalizeQuery(raw.confidence || 'medium').toLowerCase() || 'medium',
    notes: normalizeQuery(raw.notes || raw.note || ''),
    ambiguous: Boolean(raw.ambiguous),
    suggestions: Array.isArray(raw.suggestions)
      ? raw.suggestions.map((item) => normalizeQuery(item)).filter(Boolean)
      : [],
  });
}

async function handleCountdownTimer(request, env, countdownStore, url, nowMs, nowSeconds) {
  if (!countdownStore) {
    return jsonResponse(request, env, { ok: false, error: 'Countdown storage is not configured.' }, 503);
  }

  if (request.method === 'GET') {
    const id = normalizeCountdownId(url.searchParams.get('id'));
    if (!id) {
      return jsonResponse(request, env, { ok: false, error: 'Missing timer id.' }, 400);
    }

    const timer = await countdownStore.getTimerById(id);
    if (!timer) {
      return jsonResponse(request, env, { ok: false, error: 'That timer link is invalid. Create a new countdown.' }, 404);
    }

    const token = normalizeToken(url.searchParams.get('token'));
    const canEdit = Boolean(token && timingSafeEqual(token, timer.token));

    if (!timer.isPublic && !canEdit) {
      const unlocked = await hasCountdownAccess(request, env, id, nowSeconds);
      if (!unlocked) {
        return jsonResponse(
          request,
          env,
          {
            ok: false,
            error: 'This countdown is private. Enter the password to continue.',
            requiresPassword: true,
          },
          403
        );
      }
    }

    return jsonResponse(request, env, {
      ok: true,
      timer: countdownClientTimer(timer, canEdit),
      serverNowMs: nowMs,
      expired: nowMs >= timer.deadlineMs,
    });
  }

  if (request.method === 'POST') {
    const body = await readJsonBody(request);
    if (!body || typeof body !== 'object') {
      return jsonResponse(request, env, { ok: false, error: 'Invalid countdown timer payload.' }, 400);
    }

    const deadlineMs = Number(body.deadlineMs);
    if (!Number.isFinite(deadlineMs)) {
      return jsonResponse(request, env, { ok: false, error: 'A valid deadlineMs value is required.' }, 400);
    }
    if (deadlineMs <= nowMs) {
      return jsonResponse(request, env, { ok: false, error: 'Deadline must be in the future.' }, 400);
    }
    if (deadlineMs > nowMs + COUNTDOWN_MAX_FUTURE_MS) {
      return jsonResponse(request, env, { ok: false, error: 'Deadline is too far in the future.' }, 400);
    }

    let units = [...COUNTDOWN_UNITS];
    if (Object.prototype.hasOwnProperty.call(body, 'units')) {
      units = normalizeCountdownUnits(body.units);
      if (!units.length) {
        return jsonResponse(request, env, { ok: false, error: 'Select at least one countdown unit.' }, 400);
      }
    }

    const isPublic = Boolean(body.isPublic);
    const title = normalizeCountdownTitle(body.title) || 'Countdown';
    const password = String(body.password || '').trim();

    let passSalt = '';
    let passHash = '';

    if (!isPublic) {
      if (!password) {
        return jsonResponse(
          request,
          env,
          { ok: false, error: 'Private countdowns require a password.' },
          400
        );
      }

      const passwordRecord = await createPasswordRecord(password, env);
      passSalt = passwordRecord.salt;
      passHash = passwordRecord.hash;
    }

    const timer = await countdownStore.createTimer({
      startAtMs: nowMs,
      deadlineMs,
      title,
      units,
      isPublic,
      passSalt,
      passHash,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    });

    return jsonResponse(request, env, {
      ok: true,
      ownerToken: timer.token,
      timer: countdownClientTimer(timer, true),
      serverNowMs: nowMs,
      expired: nowMs >= timer.deadlineMs,
    });
  }

  if (request.method === 'PATCH') {
    const body = await readJsonBody(request);
    if (!body || typeof body !== 'object') {
      return jsonResponse(request, env, { ok: false, error: 'Invalid countdown timer payload.' }, 400);
    }

    const id = normalizeCountdownId(body.id);
    const token = normalizeToken(body.token);
    if (!id || !token) {
      return jsonResponse(request, env, { ok: false, error: 'Timer id and token are required.' }, 400);
    }

    const existing = await countdownStore.getTimerById(id);
    if (!existing) {
      return jsonResponse(request, env, { ok: false, error: 'That timer link is invalid. Create a new countdown.' }, 404);
    }

    if (!timingSafeEqual(token, existing.token)) {
      return jsonResponse(request, env, { ok: false, error: 'Invalid owner token.' }, 403);
    }

    if (typeof body.isPublic !== 'boolean') {
      return jsonResponse(request, env, { ok: false, error: 'A boolean isPublic value is required.' }, 400);
    }

    const nextIsPublic = Boolean(body.isPublic);
    const password = String(body.password || '').trim();

    let passSalt = '';
    let passHash = '';

    if (!nextIsPublic) {
      if (existing.isPublic && !password) {
        return jsonResponse(
          request,
          env,
          { ok: false, error: 'Private countdowns require a password.' },
          400
        );
      }

      if (!existing.isPublic && !password && !countdownHasStoredPassword(existing)) {
        return jsonResponse(
          request,
          env,
          { ok: false, error: 'Private countdowns require a password.' },
          400
        );
      }

      if (password) {
        const passwordRecord = await createPasswordRecord(password, env);
        passSalt = passwordRecord.salt;
        passHash = passwordRecord.hash;
      } else {
        passSalt = existing.passSalt;
        passHash = existing.passHash;
      }
    }

    const updated = await countdownStore.setTimerVisibility(id, nextIsPublic, nowMs, {
      passSalt,
      passHash,
    });

    if (!updated) {
      return jsonResponse(request, env, { ok: false, error: 'Unable to update countdown.' }, 500);
    }

    return jsonResponse(request, env, {
      ok: true,
      timer: countdownClientTimer(updated, true),
      serverNowMs: nowMs,
      expired: nowMs >= updated.deadlineMs,
    });
  }

  return methodNotAllowed(request, env, ['GET', 'POST', 'PATCH']);
}

async function handleCountdownAccess(request, env, countdownStore, url, nowMs, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  if (!countdownStore) {
    return jsonResponse(request, env, { ok: false, error: 'Countdown storage is not configured.' }, 503);
  }

  if (!env.SESSION_SECRET) {
    return jsonResponse(request, env, { ok: false, error: 'Countdown access signing is not configured.' }, 500);
  }

  const body = await readJsonBody(request);
  if (!body || typeof body !== 'object') {
    return jsonResponse(request, env, { ok: false, error: 'Invalid access payload.' }, 400);
  }

  const id = normalizeCountdownId(body.id);
  const password = String(body.password || '');

  if (!id || !password) {
    return jsonResponse(request, env, { ok: false, error: 'Timer id and password are required.' }, 400);
  }

  const timer = await countdownStore.getTimerById(id);
  if (!timer) {
    return jsonResponse(request, env, { ok: false, error: 'That timer link is invalid. Create a new countdown.' }, 404);
  }

  if (timer.isPublic) {
    return jsonResponse(request, env, { ok: false, error: 'This countdown is already public.' }, 400);
  }

  if (!countdownHasStoredPassword(timer)) {
    return jsonResponse(request, env, { ok: false, error: 'Password access is not configured for this countdown.' }, 400);
  }

  const valid = await verifyPassword(password, timer.passSalt, timer.passHash, env);
  if (!valid) {
    return jsonResponse(request, env, { ok: false, error: 'Incorrect password.' }, 401);
  }

  const accessToken = await issueCountdownAccessToken(env.SESSION_SECRET, timer.id, nowSeconds);
  const cookie = buildCountdownAccessCookie(timer.id, accessToken, url, env);

  return jsonResponse(
    request,
    env,
    {
      ok: true,
      timer: countdownClientTimer(timer, false),
      serverNowMs: nowMs,
      expired: nowMs >= timer.deadlineMs,
    },
    200,
    {
      cookies: [cookie],
    }
  );
}

export function createApiHandler(options = {}) {
  const now = typeof options.now === 'function' ? options.now : () => Date.now();

  return {
    async fetch(request, env = {}) {
      try {
        if (!request?.url || !request.url.startsWith('http')) {
          return new Response('Bad request', { status: 400 });
        }

        const url = new URL(request.url);
        const path = url.pathname;

        if (path === '/healthz') {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
          });
        }

        if (!path.startsWith('/api/')) {
          return notFound(request, env);
        }

        if (request.method === 'OPTIONS') {
          const origin = request.headers.get('Origin');
          if (origin && !isOriginAllowed(origin, env)) {
            return jsonResponse(request, env, { ok: false, error: 'Origin not allowed.' }, 403);
          }

          const headers = new Headers();
          addCorsHeaders(request, env, headers);
          applyCommonSecurityHeaders(headers);
          headers.set('Cache-Control', 'no-store');
          return new Response(null, { status: 204, headers });
        }

        const origin = request.headers.get('Origin');
        if (origin && !isOriginAllowed(origin, env)) {
          return jsonResponse(request, env, { ok: false, error: 'Origin not allowed.' }, 403);
        }

        if (path === '/api/health') {
          if (request.method !== 'GET') return methodNotAllowed(request, env, ['GET']);
          return jsonResponse(request, env, {
            ok: true,
            service: 'countdown-api',
            timestamp: new Date(now()).toISOString(),
          });
        }

        if (path === '/api/time') {
          if (request.method !== 'GET') return methodNotAllowed(request, env, ['GET']);
          return jsonResponse(request, env, {
            ok: true,
            nowMs: now(),
          });
        }

        if (path === '/api/resolve-date') {
          return handleResolveDate(request, env, url, now());
        }

        if (path === '/api/resolve-event-date') {
          return handleResolveEventDate(request, env, url);
        }

        const countdownStore = env.COUNTDOWN_STORE || (env.DB ? createCountdownD1Store(env.DB) : null);
        const nowMs = now();
        const nowSeconds = Math.floor(nowMs / 1000);

        if (path === '/api/countdown/timer') {
          return handleCountdownTimer(request, env, countdownStore, url, nowMs, nowSeconds);
        }

        if (path === '/api/countdown/access') {
          return handleCountdownAccess(request, env, countdownStore, url, nowMs, nowSeconds);
        }

        return notFound(request, env);
      } catch (error) {
        console.error('Unhandled API error', error);
        return jsonResponse(request, env, { ok: false, error: 'Internal server error.' }, 500);
      }
    },
  };
}

export const __test = {
  normalizeOrigin,
  isOriginAllowed,
  parseCookies,
  parseSetCookieValue,
  timingSafeEqual,
};

export default createApiHandler();
