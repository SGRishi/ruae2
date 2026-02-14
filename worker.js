import papersData from './public/data/papers.json' with { type: 'json' };

const encoder = new TextEncoder();
const SESSION_COOKIE_NAME = 'ruae_session';
const CSRF_COOKIE_NAME = 'ruae_csrf';

const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const CSRF_MAX_AGE_SECONDS = 60 * 60 * 12;
const PASSWORD_MIN_LENGTH = 12;
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = 'SHA-256';
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_HASH_BITS = 256;

const RATE_LIMIT_WINDOW_SECONDS = 10 * 60;
const RATE_LIMIT_LOGIN_IP_MAX = 10;
const RATE_LIMIT_REGISTER_IP_MAX = 6;
const RATE_LIMIT_MATCH_IP_MAX = 40;
const LOCKOUT_START_AT_FAILURE = 5;
const LOCKOUT_MAX_SECONDS = 60 * 60;
const ADMIN_REVIEW_LIMIT = 200;

const DEFAULT_ALLOWED_ORIGINS = new Set(['https://rishisubjects.co.uk']);
const DEV_LOCAL_ORIGINS = new Set([
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:8788',
  'http://127.0.0.1:8788',
]);

const RUAE_GUIDANCE = `Reading for Understanding, Analysis and Evaluation (30 marks)\n\nAs the title of the paper suggests, there are three core skills being tested in this exam:\n- your ability to read and understand an unfamiliar piece of non-fiction prose\n- your ability to analyse a range of literary devices used by a writer to create a particular effect\n- your ability to evaluate the success of the writer in employing these techniques\n\nYou will have 1 hour and 30 minutes to complete the RUAE exam. The paper is marked out of 30 and is therefore worth 30% of your overall grade.\n\nThe RUAE passage\nAt Higher you will be faced with two passages in the exam. These passages should be linked by the same topic, although the writers might take very different approaches or attitudes to the topic.\n\nThe majority of questions will deal with passage one; the final question deals with both passages. In this final question you will be asked to look at the main areas of agreement and/or disagreement between the two writers.\n\nOften, reading and understanding the passages is the trickiest bit for candidates. Passages at Higher will be full of demanding vocabulary and complicated lines of thought.\n\nThe questions\nIt is perhaps helpful to think about the three question areas in this paper in the following way:\n- what is the writer saying? (Understanding)\n- how is the writer saying it? (Analysis)\n- how well did the writer say it? (Evaluation)\n\nLanguage features\n- sentence structure\n- imagery\n- word choice\n- tone\n- linking sentences\n- turning point in argument`;

function toInt(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

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
  for (const part of cookieHeader.split(';')) {
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

function buildSessionCookie(token, url, env) {
  return serializeCookie(SESSION_COOKIE_NAME, token, {
    path: '/',
    sameSite: 'Lax',
    secure: secureCookieForUrl(url, env),
    httpOnly: true,
    maxAge: SESSION_MAX_AGE_SECONDS,
    priority: 'High',
  });
}

function clearSessionCookie(url, env) {
  return serializeCookie(SESSION_COOKIE_NAME, '', {
    path: '/',
    sameSite: 'Lax',
    secure: secureCookieForUrl(url, env),
    httpOnly: true,
    maxAge: 0,
    priority: 'High',
  });
}

function buildCsrfCookie(token, url, env) {
  return serializeCookie(CSRF_COOKIE_NAME, token, {
    path: '/',
    sameSite: 'Lax',
    secure: secureCookieForUrl(url, env),
    httpOnly: false,
    maxAge: CSRF_MAX_AGE_SECONDS,
    priority: 'High',
  });
}

function appendSetCookies(headers, cookies = []) {
  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie);
  }
}

function appendVary(existing, value) {
  const values = (existing || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.some((item) => item.toLowerCase() === value.toLowerCase())) {
    return values.join(', ');
  }
  values.push(value);
  return values.join(', ');
}

function applyCommonSecurityHeaders(headers) {
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-site');
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
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

function parseAllowedOrigins(env) {
  const exact = new Set(DEFAULT_ALLOWED_ORIGINS);
  const extraOrigins = String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((item) => normalizeOrigin(item))
    .filter(Boolean);
  for (const origin of extraOrigins) exact.add(origin);

  if (String(env.ALLOW_LOCALHOST_ORIGINS || '').toLowerCase() === 'true') {
    for (const origin of DEV_LOCAL_ORIGINS) exact.add(origin);
  }

  const projectName = String(env.PAGES_PROJECT_NAME || '').trim().toLowerCase();
  return {
    exact,
    projectName,
  };
}

function isAllowedPagesPreview(origin, projectName) {
  if (!origin || !projectName) return false;
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    const suffix = `.${projectName}.pages.dev`;
    return host.endsWith(suffix);
  } catch {
    return false;
  }
}

function isOriginAllowed(origin, env) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;
  const allowed = parseAllowedOrigins(env);
  if (allowed.exact.has(normalized)) return true;
  return isAllowedPagesPreview(normalized, allowed.projectName);
}

function getCorsOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return '';
  return isOriginAllowed(origin, env) ? normalizeOrigin(origin) : '';
}

function addCorsHeaders(request, env, headers) {
  const corsOrigin = getCorsOrigin(request, env);
  if (!corsOrigin) return;
  headers.set('Access-Control-Allow-Origin', corsOrigin);
  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, X-Admin-Token, X-Admin-Key');
  headers.set('Vary', appendVary(headers.get('Vary'), 'Origin'));
}

function jsonResponse(request, env, payload, status = 200, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  appendSetCookies(headers, options.cookies || []);
  addCorsHeaders(request, env, headers);
  applyCommonSecurityHeaders(headers);

  return new Response(JSON.stringify(payload), {
    status,
    headers,
  });
}

function methodNotAllowed(request, env, allow) {
  return jsonResponse(
    request,
    env,
    {
      ok: false,
      error: 'Method not allowed.',
    },
    405,
    {
      headers: {
        Allow: allow.join(', '),
      },
    }
  );
}

function notFound(request, env) {
  return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
}

function getClientIp(request) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  return String(ip).split(',', 1)[0].trim().slice(0, 128);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeAdminReason(value) {
  const reason = String(value || '').trim();
  if (!reason) return 'Denied by administrator.';
  return reason.slice(0, 240);
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));
}

function isValidUsername(value) {
  return /^[a-zA-Z]{2,40}$/.test(String(value || '').trim());
}

function isValidLoginIdentifier(value) {
  return isValidUsername(value) || isValidEmail(value);
}

function resolveLoginIdentifier(payload = {}) {
  return normalizeUsername(payload.username ?? payload.email);
}

function isStrongPassword(value) {
  if (typeof value !== 'string') return false;
  if (value.length < PASSWORD_MIN_LENGTH) return false;
  if (!/[a-z]/.test(value)) return false;
  if (!/[A-Z]/.test(value)) return false;
  if (!/[0-9]/.test(value)) return false;
  return true;
}

function isValidTokenShape(value) {
  return /^[A-Za-z0-9_-]{16,200}$/.test(String(value || ''));
}

async function hashSessionToken(token, sessionSecret) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${sessionSecret}\u0000${token}`));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function pbkdf2Hash(password, saltB64Url, pepper = '') {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`${password}\u0000${pepper}`),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: PBKDF2_HASH,
      salt: base64UrlToBytes(saltB64Url),
      iterations: PBKDF2_ITERATIONS,
    },
    keyMaterial,
    PASSWORD_HASH_BITS
  );

  return bytesToBase64Url(new Uint8Array(bits));
}

async function hashNewPassword(password, pepper) {
  const saltBytes = new Uint8Array(PASSWORD_SALT_BYTES);
  crypto.getRandomValues(saltBytes);
  const salt = bytesToBase64Url(saltBytes);
  const hash = await pbkdf2Hash(password, salt, pepper);
  return { salt, hash };
}

async function verifyPassword(password, salt, expectedHash, pepper) {
  const computed = await pbkdf2Hash(password, salt, pepper);
  return timingSafeEqual(computed, expectedHash);
}

function getOrCreateCsrfToken(request) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const token = cookies[CSRF_COOKIE_NAME];
  if (isValidTokenShape(token)) {
    return { token, needsCookie: false };
  }
  return { token: randomToken(24), needsCookie: true };
}

function findOriginForCsrfCheck(request) {
  const origin = request.headers.get('Origin');
  if (origin) return origin;

  const referer = request.headers.get('Referer');
  if (!referer) return '';
  try {
    return new URL(referer).origin;
  } catch {
    return '';
  }
}

function validateCsrf(request, env, submittedToken) {
  const origin = findOriginForCsrfCheck(request);
  if (!origin || !isOriginAllowed(origin, env)) {
    return { ok: false, message: 'Invalid request origin.' };
  }

  if (!isValidTokenShape(submittedToken)) {
    return { ok: false, message: 'Security check failed.' };
  }

  const cookies = parseCookies(request.headers.get('Cookie'));
  const cookieToken = cookies[CSRF_COOKIE_NAME];
  if (!isValidTokenShape(cookieToken)) {
    return { ok: false, message: 'Security check failed.' };
  }

  if (!timingSafeEqual(cookieToken, submittedToken)) {
    return { ok: false, message: 'Security check failed.' };
  }

  return { ok: true };
}

async function readJsonBody(request, maxBytes = 10_000) {
  const raw = await request.text();
  if (raw.length > maxBytes) {
    return { ok: false, status: 413, error: 'Payload too large.' };
  }
  if (!raw.trim()) {
    return { ok: true, data: {} };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, status: 400, error: 'Invalid JSON payload.' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: 'Invalid JSON payload.' };
  }
  return { ok: true, data: parsed };
}

class DuplicateRecordError extends Error {
  constructor(message = 'Duplicate record.') {
    super(message);
    this.name = 'DuplicateRecordError';
  }
}

function createD1Store(db) {
  if (!db || typeof db.prepare !== 'function') {
    throw new Error('DB binding is missing or invalid.');
  }

  return {
    async getUserByEmail(email) {
      return db.prepare(
        `SELECT id, email, pass_salt, pass_hash, status
         FROM users
         WHERE email = ?1
         LIMIT 1`
      )
        .bind(email)
        .first();
    },

    async getUserById(id) {
      return db.prepare(
        `SELECT id, email, status
         FROM users
         WHERE id = ?1
         LIMIT 1`
      )
        .bind(id)
        .first();
    },

    async createUser(record) {
      try {
        const result = await db.prepare(
          `INSERT INTO users (email, pass_salt, pass_hash, status, created_at)
           VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)`
        )
          .bind(record.email, record.passSalt, record.passHash, record.status)
          .run();

        const userId = Number(result.meta?.last_row_id || 0);
        if (userId > 0) {
          return this.getUserById(userId);
        }

        return this.getUserByEmail(record.email);
      } catch (error) {
        const message = String(error?.message || '');
        if (message.includes('UNIQUE')) {
          throw new DuplicateRecordError('User already exists.');
        }
        throw error;
      }
    },

    async createSession(session) {
      await db.prepare(
        `INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, ip_address, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
      )
        .bind(
          session.id,
          session.userId,
          session.tokenHash,
          session.createdAt,
          session.expiresAt,
          session.lastSeenAt,
          session.ipAddress,
          session.userAgent
        )
        .run();
    },

    async getSessionWithUser(tokenHash) {
      const row = await db.prepare(
        `SELECT s.id AS session_id,
                s.user_id AS session_user_id,
                s.expires_at,
                u.id AS user_id,
                u.email,
                u.status
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1
         LIMIT 1`
      )
        .bind(tokenHash)
        .first();

      if (!row) return null;

      return {
        sessionId: row.session_id,
        userId: Number(row.session_user_id),
        expiresAt: Number(row.expires_at),
        user: {
          id: Number(row.user_id),
          email: row.email,
          status: row.status,
        },
      };
    },

    async deleteSessionByTokenHash(tokenHash) {
      await db.prepare('DELETE FROM sessions WHERE token_hash = ?1')
        .bind(tokenHash)
        .run();
    },

    async deleteExpiredSessions(nowSeconds) {
      await db.prepare('DELETE FROM sessions WHERE expires_at <= ?1')
        .bind(nowSeconds)
        .run();
    },

    async incrementRateLimit(ip, action, windowStart) {
      await db.prepare(
        `INSERT INTO rate_limit (ip, action, window_start, count)
         VALUES (?1, ?2, ?3, 1)
         ON CONFLICT(ip, action, window_start)
         DO UPDATE SET count = count + 1`
      )
        .bind(ip, action, windowStart)
        .run();

      const row = await db.prepare(
        'SELECT count FROM rate_limit WHERE ip = ?1 AND action = ?2 AND window_start = ?3 LIMIT 1'
      )
        .bind(ip, action, windowStart)
        .first();

      return Number(row?.count || 0);
    },

    async deleteOldRateLimits(cutoffWindowStart) {
      await db.prepare('DELETE FROM rate_limit WHERE window_start < ?1')
        .bind(cutoffWindowStart)
        .run();
    },

    async getLoginLockout(email) {
      const row = await db.prepare(
        `SELECT failed_count, locked_until
         FROM login_lockouts
         WHERE email = ?1
         LIMIT 1`
      )
        .bind(email)
        .first();

      if (!row) return null;
      return {
        failedCount: Number(row.failed_count || 0),
        lockedUntil: Number(row.locked_until || 0),
      };
    },

    async setLoginLockout(email, failedCount, lockedUntil, updatedAt) {
      await db.prepare(
        `INSERT INTO login_lockouts (email, failed_count, locked_until, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(email)
         DO UPDATE SET failed_count = excluded.failed_count,
                       locked_until = excluded.locked_until,
                       updated_at = excluded.updated_at`
      )
        .bind(email, failedCount, lockedUntil, updatedAt)
        .run();
    },

    async clearLoginLockout(email) {
      await db.prepare('DELETE FROM login_lockouts WHERE email = ?1')
        .bind(email)
        .run();
    },

    async listPendingUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      const result = await db.prepare(
        `SELECT id, email, status, created_at
         FROM users
         WHERE status = 'pending'
           AND email NOT IN (SELECT email FROM denied_users)
         ORDER BY created_at ASC
         LIMIT ?1`
      )
        .bind(safeLimit)
        .all();

      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows.map((row) => ({
        id: Number(row.id),
        email: row.email,
        status: row.status,
        createdAt: row.created_at || null,
      }));
    },

    async listApprovedUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      const result = await db.prepare(
        `SELECT id, email, status, approved_at
         FROM users
         WHERE status = 'approved'
           AND email NOT IN (SELECT email FROM denied_users)
         ORDER BY approved_at DESC, created_at DESC
         LIMIT ?1`
      )
        .bind(safeLimit)
        .all();

      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows.map((row) => ({
        id: Number(row.id),
        email: row.email,
        status: row.status,
        approvedAt: row.approved_at || null,
      }));
    },

    async listDeniedUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      const result = await db.prepare(
        `SELECT d.email, d.reason, d.denied_at, u.id AS user_id, u.status AS user_status
         FROM denied_users d
         LEFT JOIN users u ON u.email = d.email
         ORDER BY d.denied_at DESC
         LIMIT ?1`
      )
        .bind(safeLimit)
        .all();

      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows.map((row) => ({
        email: row.email,
        reason: row.reason || '',
        deniedAt: row.denied_at || null,
        userId: row.user_id ? Number(row.user_id) : null,
        userStatus: row.user_status || null,
      }));
    },

    async getDeniedEmail(email) {
      const row = await db.prepare(
        `SELECT email, reason, denied_at
         FROM denied_users
         WHERE email = ?1
         LIMIT 1`
      )
        .bind(email)
        .first();

      if (!row) return null;
      return {
        email: row.email,
        reason: row.reason || '',
        deniedAt: row.denied_at || null,
      };
    },

    async upsertDeniedEmail(email, reason) {
      await db.prepare(
        `INSERT INTO denied_users (email, reason, denied_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(email)
         DO UPDATE SET reason = excluded.reason,
                       denied_at = excluded.denied_at`
      )
        .bind(email, reason)
        .run();
    },

    async clearDeniedEmail(email) {
      await db.prepare('DELETE FROM denied_users WHERE email = ?1')
        .bind(email)
        .run();
    },

    async setUserStatusByEmail(email, status) {
      await db.prepare(
        `UPDATE users
         SET status = ?1,
             approved_at = CASE
               WHEN ?1 = 'approved' THEN CURRENT_TIMESTAMP
               ELSE approved_at
             END
         WHERE email = ?2`
      )
        .bind(status, email)
        .run();
      return this.getUserByEmail(email);
    },

    async deleteSessionsByUserId(userId) {
      await db.prepare('DELETE FROM sessions WHERE user_id = ?1')
        .bind(userId)
        .run();
    },
  };
}

export function createMemoryStore(seed = {}) {
  let nextUserId = 1;

  const usersById = new Map();
  const usersByEmail = new Map();
  const sessionsByTokenHash = new Map();
  const rateLimit = new Map();
  const lockouts = new Map();
  const deniedByEmail = new Map();

  const initialUsers = Array.isArray(seed.users) ? seed.users : [];
  for (const user of initialUsers) {
    const id = Number(user.id || nextUserId++);
    const record = {
      id,
      email: normalizeEmail(user.email),
      pass_salt: user.pass_salt,
      pass_hash: user.pass_hash,
      status: user.status || 'approved',
    };
    usersById.set(id, record);
    usersByEmail.set(record.email, record);
    nextUserId = Math.max(nextUserId, id + 1);
  }

  function cloneUser(user) {
    if (!user) return null;
    return {
      id: Number(user.id),
      email: user.email,
      pass_salt: user.pass_salt,
      pass_hash: user.pass_hash,
      status: user.status,
    };
  }

  return {
    async getUserByEmail(email) {
      return cloneUser(usersByEmail.get(normalizeEmail(email)));
    },

    async getUserById(id) {
      const user = usersById.get(Number(id));
      if (!user) return null;
      return {
        id: Number(user.id),
        email: user.email,
        status: user.status,
      };
    },

    async createUser(record) {
      const email = normalizeEmail(record.email);
      if (usersByEmail.has(email)) {
        throw new DuplicateRecordError('User already exists.');
      }
      const user = {
        id: nextUserId++,
        email,
        pass_salt: record.passSalt,
        pass_hash: record.passHash,
        status: record.status,
      };
      usersById.set(user.id, user);
      usersByEmail.set(email, user);
      return cloneUser(user);
    },

    async createSession(session) {
      sessionsByTokenHash.set(session.tokenHash, {
        id: session.id,
        userId: Number(session.userId),
        expiresAt: Number(session.expiresAt),
      });
    },

    async getSessionWithUser(tokenHash) {
      const session = sessionsByTokenHash.get(tokenHash);
      if (!session) return null;
      const user = usersById.get(session.userId);
      if (!user) return null;
      return {
        sessionId: session.id,
        userId: session.userId,
        expiresAt: session.expiresAt,
        user: {
          id: user.id,
          email: user.email,
          status: user.status,
        },
      };
    },

    async deleteSessionByTokenHash(tokenHash) {
      sessionsByTokenHash.delete(tokenHash);
    },

    async deleteExpiredSessions(nowSeconds) {
      for (const [tokenHash, session] of sessionsByTokenHash.entries()) {
        if (session.expiresAt <= nowSeconds) {
          sessionsByTokenHash.delete(tokenHash);
        }
      }
    },

    async incrementRateLimit(ip, action, windowStart) {
      const key = `${ip}|${action}|${windowStart}`;
      const value = Number(rateLimit.get(key) || 0) + 1;
      rateLimit.set(key, value);
      return value;
    },

    async deleteOldRateLimits(cutoffWindowStart) {
      for (const key of rateLimit.keys()) {
        const parts = key.split('|');
        const windowStart = Number(parts[2] || 0);
        if (windowStart < cutoffWindowStart) {
          rateLimit.delete(key);
        }
      }
    },

    async getLoginLockout(email) {
      return lockouts.get(normalizeEmail(email)) || null;
    },

    async setLoginLockout(email, failedCount, lockedUntil) {
      lockouts.set(normalizeEmail(email), {
        failedCount,
        lockedUntil,
      });
    },

    async clearLoginLockout(email) {
      lockouts.delete(normalizeEmail(email));
    },

    async listPendingUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      const pending = Array.from(usersById.values())
        .filter((user) => user.status === 'pending' && !deniedByEmail.has(user.email))
        .sort((a, b) => Number(a.id) - Number(b.id))
        .slice(0, safeLimit)
        .map((user) => ({
          id: Number(user.id),
          email: user.email,
          status: user.status,
          createdAt: null,
        }));
      return pending;
    },

    async listApprovedUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      return Array.from(usersById.values())
        .filter((user) => user.status === 'approved' && !deniedByEmail.has(user.email))
        .sort((a, b) => Number(b.id) - Number(a.id))
        .slice(0, safeLimit)
        .map((user) => ({
          id: Number(user.id),
          email: user.email,
          status: user.status,
          approvedAt: null,
        }));
    },

    async listDeniedUsers(limit = ADMIN_REVIEW_LIMIT) {
      const safeLimit = Math.max(1, Math.min(1000, Number(limit) || ADMIN_REVIEW_LIMIT));
      return Array.from(deniedByEmail.entries())
        .slice(0, safeLimit)
        .map(([email, denied]) => {
          const user = usersByEmail.get(email) || null;
          return {
            email,
            reason: denied.reason,
            deniedAt: denied.deniedAt,
            userId: user ? Number(user.id) : null,
            userStatus: user ? user.status : null,
          };
        });
    },

    async getDeniedEmail(email) {
      const denied = deniedByEmail.get(normalizeEmail(email));
      if (!denied) return null;
      return {
        email: normalizeEmail(email),
        reason: denied.reason,
        deniedAt: denied.deniedAt,
      };
    },

    async upsertDeniedEmail(email, reason) {
      deniedByEmail.set(normalizeEmail(email), {
        reason,
        deniedAt: new Date().toISOString(),
      });
    },

    async clearDeniedEmail(email) {
      deniedByEmail.delete(normalizeEmail(email));
    },

    async setUserStatusByEmail(email, status) {
      const normalized = normalizeEmail(email);
      const user = usersByEmail.get(normalized);
      if (!user) return null;
      user.status = status;
      return cloneUser(user);
    },

    async deleteSessionsByUserId(userId) {
      const target = Number(userId);
      for (const [tokenHash, session] of sessionsByTokenHash.entries()) {
        if (Number(session.userId) === target) {
          sessionsByTokenHash.delete(tokenHash);
        }
      }
    },
  };
}

async function enforceRateLimit(store, ip, action, maxAttempts, windowSeconds, nowSeconds) {
  const windowStart = nowSeconds - (nowSeconds % windowSeconds);
  const count = await store.incrementRateLimit(ip, action, windowStart);
  await store.deleteOldRateLimits(windowStart - (windowSeconds * 24));
  return {
    allowed: count <= maxAttempts,
    retryAfter: Math.max(1, (windowStart + windowSeconds) - nowSeconds),
  };
}

async function recordFailedLogin(store, email, nowSeconds) {
  const current = await store.getLoginLockout(email);
  const failedCount = Number(current?.failedCount || 0) + 1;
  let lockedUntil = Number(current?.lockedUntil || 0);

  if (failedCount >= LOCKOUT_START_AT_FAILURE) {
    const level = failedCount - LOCKOUT_START_AT_FAILURE;
    const lockSeconds = Math.min(LOCKOUT_MAX_SECONDS, Math.pow(2, level) * 30);
    lockedUntil = Math.max(lockedUntil, nowSeconds + lockSeconds);
  }

  await store.setLoginLockout(email, failedCount, lockedUntil, nowSeconds);

  return {
    failedCount,
    lockedUntil,
    retryAfter: Math.max(0, lockedUntil - nowSeconds),
  };
}

function getSessionCookieToken(request) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  return cookies[SESSION_COOKIE_NAME] || '';
}

async function getCurrentUser(request, env, store, nowSeconds) {
  const token = getSessionCookieToken(request);
  if (!isValidTokenShape(token)) {
    return { user: null, clearSession: Boolean(token) };
  }

  const tokenHash = await hashSessionToken(token, env.SESSION_SECRET);
  const row = await store.getSessionWithUser(tokenHash);

  if (!row) {
    return { user: null, clearSession: true };
  }

  if (row.expiresAt <= nowSeconds) {
    await store.deleteSessionByTokenHash(tokenHash);
    return { user: null, clearSession: true };
  }

  return {
    user: {
      id: row.user.id,
      email: row.user.email,
      status: row.user.status,
      approved: row.user.status === 'approved',
    },
    tokenHash,
    clearSession: false,
  };
}

function extractOutputText(responseJson) {
  if (typeof responseJson?.output_text === 'string') return responseJson.output_text;
  if (!Array.isArray(responseJson?.output)) return null;

  for (const item of responseJson.output) {
    if (item.type !== 'message' || !Array.isArray(item.content)) continue;
    for (const content of item.content) {
      if (content.type === 'output_text' && typeof content.text === 'string') {
        return content.text;
      }
    }
  }

  return null;
}

function buildContext(paper, question) {
  let lines = [];

  if (question.lineRange) {
    const passageId = question.passage === 'passage2' ? 'passage2' : 'passage1';
    const passage = paper.passages.find((item) => item.id === passageId);
    if (passage) {
      const start = question.lineRange.start;
      const end = question.lineRange.end;
      let count = 0;
      for (const text of passage.lines) {
        if (text.trim() !== '') {
          count += 1;
        }
        if (count >= start && count <= end) {
          lines.push({ lineNumber: count, text });
        }
        if (count > end) break;
      }
    }
  } else if (question.passage === 'both') {
    lines = paper.passages.flatMap((passage) =>
      passage.lines.map((text, index) => ({
        lineNumber: index + 1,
        text,
        passage: passage.title,
      }))
    );
  }

  return lines;
}

function extractQuoteTokens(text) {
  const tokens = [];
  if (!text) return tokens;

  const doubleMatches = text.match(/\"([^\"]+)\"/g) || [];
  const singleMatches = text.match(/'([^']+)'/g) || [];
  const parenMatches = text.match(/\(([^)]+)\)/g) || [];

  for (const match of doubleMatches) tokens.push(match.replace(/\"/g, ''));
  for (const match of singleMatches) tokens.push(match.replace(/'/g, ''));
  for (const match of parenMatches) {
    const content = match.replace(/[()]/g, '').trim();
    const cleaned = content.replace(/["',.\s]+/g, '');
    if (cleaned) tokens.push(content);
  }

  return tokens.map((token) => token.trim()).filter(Boolean);
}

function normalizeQuote(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function isQuoteInMarkScheme(quote, markScheme) {
  const quoteNorm = normalizeQuote(quote);
  if (!quoteNorm) return false;

  for (const item of markScheme) {
    const tokens = extractQuoteTokens(item);
    if (!tokens.length) {
      const itemNorm = normalizeQuote(item);
      if (itemNorm && (itemNorm.includes(quoteNorm) || quoteNorm.includes(itemNorm))) {
        return true;
      }
      continue;
    }

    for (const token of tokens) {
      const tokenNorm = normalizeQuote(token);
      if (tokenNorm.length < 3) continue;
      if (tokenNorm.includes(quoteNorm) || quoteNorm.includes(tokenNorm)) {
        return true;
      }
    }
  }

  return false;
}

async function handleMatchWithAi(env, payload) {
  const paperId = String(payload.paperId || '').trim();
  const questionNumber = Number(payload.questionNumber);
  const answer = String(payload.answer || '').trim();
  const mode = payload.mode === 'mark' ? 'mark' : 'quote';

  if (!paperId || !Number.isFinite(questionNumber)) {
    return { status: 400, body: { ok: false, error: 'Invalid paper or question.' } };
  }

  if (!answer || answer.length > 6000) {
    return { status: 400, body: { ok: false, error: 'Answer must be between 1 and 6000 characters.' } };
  }

  const paper = papersData.papers.find((item) => item.id === paperId);
  if (!paper) {
    return { status: 404, body: { ok: false, error: 'Paper not found.' } };
  }

  const question = paper.questions.find((item) => item.number === Number(questionNumber));
  if (!question) {
    return { status: 404, body: { ok: false, error: 'Question not found.' } };
  }

  const lines = buildContext(paper, question);
  const markScheme = Array.isArray(question.markScheme) ? question.markScheme : [];
  const apiKey = String(env.OPENAI_API_KEY || '').trim();

  if (!apiKey) {
    return { status: 503, body: { ok: false, error: 'AI service is not configured.' } };
  }

  const instructions = mode === 'mark'
    ? [
        'You are grading a Higher English RUAE answer.',
        'Use the question, passage lines, mark scheme bullets, and the RUAE guidance provided.',
        'Return a score out of the maximum marks for the question.',
        'Explain clearly why marks were awarded or not awarded.',
        'Return JSON only, matching the provided schema.',
      ].join(' ')
    : [
        'You are helping a student locate the exact quotation they used from the passage lines provided.',
        'Only use the supplied lines.',
        'If the student did not use a direct quote from the lines, return quote=null and lineNumber=null.',
        'If multiple quotes appear, pick the clearest, shortest quote that appears verbatim in the lines.',
        'Return JSON only, matching the provided schema.',
      ].join(' ');

  const userInput = mode === 'mark'
    ? {
        question: question.text,
        answer,
        lines,
        markScheme,
        maxMarks: question.marks || 0,
        guidance: RUAE_GUIDANCE,
      }
    : {
        question: question.text,
        answer,
        lines,
      };

  const responseFormat = mode === 'mark'
    ? {
        type: 'json_schema',
        name: 'mark_answer',
        strict: true,
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            score: { type: 'integer' },
            max: { type: 'integer' },
            reasoning: { type: 'string' },
          },
          required: ['score', 'max', 'reasoning'],
        },
      }
    : {
        type: 'json_schema',
        name: 'quote_match',
        strict: true,
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            quote: { type: ['string', 'null'] },
            lineNumber: { type: ['integer', 'null'] },
          },
          required: ['quote', 'lineNumber'],
        },
      };

  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: String(env.OPENAI_MODEL || 'gpt-4o-mini'),
      instructions,
      input: JSON.stringify(userInput),
      temperature: 0.2,
      text: { format: responseFormat },
    }),
  });

  let responseJson;
  try {
    responseJson = await response.json();
  } catch {
    return { status: 502, body: { ok: false, error: 'AI service returned an invalid response.' } };
  }

  if (!response.ok) {
    const aiMessage = String(responseJson?.error?.message || 'AI request failed.');
    return {
      status: response.status,
      body: {
        ok: false,
        error: aiMessage.slice(0, 240),
      },
    };
  }

  const outputText = extractOutputText(responseJson);
  if (!outputText) {
    return { status: 502, body: { ok: false, error: 'AI response did not include text output.' } };
  }

  let parsed;
  try {
    parsed = JSON.parse(outputText);
  } catch {
    return { status: 502, body: { ok: false, error: 'AI response was not valid JSON.' } };
  }

  if (mode === 'mark') {
    const maxMarks = Number(question.marks || 0);
    const score = Math.max(0, Math.min(maxMarks, toInt(parsed.score, 0)));
    return {
      status: 200,
      body: {
        ok: true,
        score,
        max: maxMarks,
        reasoning: String(parsed.reasoning || '').slice(0, 2000),
      },
    };
  }

  const quote = typeof parsed.quote === 'string' ? parsed.quote : null;
  const lineNumber = Number.isInteger(parsed.lineNumber) ? parsed.lineNumber : null;

  return {
    status: 200,
    body: {
      ok: true,
      quote,
      lineNumber,
      inMarkScheme: quote ? isQuoteInMarkScheme(quote, markScheme) : false,
    },
  };
}

function extractCsrfToken(request, payload) {
  const token = payload?.csrfToken ?? payload?.csrf_token ?? request.headers.get('X-CSRF-Token');
  return String(token || '').trim();
}

function extractAdminKey(request, payload, url) {
  const fromHeader = request.headers.get('X-Admin-Key') || request.headers.get('X-Admin-Token');
  const fromPayload = payload?.adminToken ?? payload?.adminKey;
  const fromQuery = url.searchParams.get('admin_token')
    || url.searchParams.get('token')
    || url.searchParams.get('admin_key')
    || url.searchParams.get('key');
  return String(fromHeader || fromPayload || fromQuery || '').trim();
}

function validateAdminAccess(request, env, payload, url) {
  const primary = String(env.ADMIN_LINK_TOKEN || '').trim();
  const legacy = String(env.ADMIN_KEY || '').trim();
  if (!primary && !legacy) {
    return { ok: false, status: 503, error: 'Admin access is not configured.' };
  }

  const provided = extractAdminKey(request, payload, url);
  if (!provided) {
    return { ok: false, status: 401, error: 'Admin link token required.' };
  }

  const matches = (primary && timingSafeEqual(provided, primary)) || (legacy && timingSafeEqual(provided, legacy));
  if (!matches) {
    return { ok: false, status: 403, error: 'Invalid admin credentials.' };
  }

  return { ok: true };
}

function toPublicUser(user) {
  if (!user) return null;
  return {
    id: Number(user.id),
    username: user.email,
    email: user.email,
    status: user.status,
  };
}

async function handleAuthMe(request, env, store, url, nowSeconds) {
  await store.deleteExpiredSessions(nowSeconds);

  const csrfState = getOrCreateCsrfToken(request);
  const auth = await getCurrentUser(request, env, store, nowSeconds);

  const cookies = [];
  if (csrfState.needsCookie) cookies.push(buildCsrfCookie(csrfState.token, url, env));
  if (auth.clearSession) cookies.push(clearSessionCookie(url, env));

  return jsonResponse(
    request,
    env,
    {
      ok: true,
      authenticated: Boolean(auth.user),
      approved: Boolean(auth.user?.approved),
      user: auth.user
        ? {
            id: auth.user.id,
            username: auth.user.email,
            email: auth.user.email,
            status: auth.user.status,
          }
        : null,
      csrfToken: csrfState.token,
    },
    200,
    { cookies }
  );
}

async function handleAuthRegister(request, env, store, url, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const csrfToken = extractCsrfToken(request, body.data);
  const csrfCheck = validateCsrf(request, env, csrfToken);
  if (!csrfCheck.ok) {
    const replacementToken = randomToken(24);
    return jsonResponse(
      request,
      env,
      { ok: false, error: csrfCheck.message, csrfToken: replacementToken },
      403,
      { cookies: [buildCsrfCookie(replacementToken, url, env)] }
    );
  }

  const rateLimit = await enforceRateLimit(
    store,
    getClientIp(request),
    'register_ip',
    RATE_LIMIT_REGISTER_IP_MAX,
    RATE_LIMIT_WINDOW_SECONDS,
    nowSeconds
  );
  if (!rateLimit.allowed) {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: `Too many attempts. Try again in ${rateLimit.retryAfter} seconds.`,
      },
      429,
      { headers: { 'Retry-After': String(rateLimit.retryAfter) } }
    );
  }

  const username = resolveLoginIdentifier(body.data);
  const password = String(body.data.password || '');

  if (!isValidUsername(username)) {
    return jsonResponse(
      request,
      env,
      { ok: false, error: 'Please enter your first name (letters only).' },
      400
    );
  }

  const denied = await store.getDeniedEmail(username);
  if (denied) {
    return jsonResponse(
      request,
      env,
      { ok: false, error: 'This account has been denied by an administrator.' },
      403
    );
  }

  if (!isStrongPassword(password)) {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: `Use at least ${PASSWORD_MIN_LENGTH} characters with uppercase, lowercase, and a number.`,
      },
      400
    );
  }

  const passwordRecord = await hashNewPassword(password, String(env.PASSWORD_PEPPER || ''));
  const status = String(env.REQUIRE_MANUAL_APPROVAL || '').toLowerCase() === 'true'
    ? 'pending'
    : 'approved';

  try {
    const user = await store.createUser({
      email: username,
      passSalt: passwordRecord.salt,
      passHash: passwordRecord.hash,
      status,
    });

    return jsonResponse(
      request,
      env,
      {
        ok: true,
        message: status === 'pending'
          ? 'Registration successful. Account is pending approval.'
          : 'Registration successful. You can now log in.',
        user: {
          id: Number(user.id),
          username: user.email,
          email: user.email,
          status: user.status,
        },
      },
      201
    );
  } catch (error) {
    if (error instanceof DuplicateRecordError) {
      return jsonResponse(
        request,
        env,
        { ok: false, error: 'An account with that username already exists.' },
        409
      );
    }
    throw error;
  }
}

async function handleAuthLogin(request, env, store, url, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const csrfToken = extractCsrfToken(request, body.data);
  const csrfCheck = validateCsrf(request, env, csrfToken);
  if (!csrfCheck.ok) {
    const replacementToken = randomToken(24);
    return jsonResponse(
      request,
      env,
      { ok: false, error: csrfCheck.message, csrfToken: replacementToken },
      403,
      { cookies: [buildCsrfCookie(replacementToken, url, env)] }
    );
  }

  const ipRateLimit = await enforceRateLimit(
    store,
    getClientIp(request),
    'login_ip',
    RATE_LIMIT_LOGIN_IP_MAX,
    RATE_LIMIT_WINDOW_SECONDS,
    nowSeconds
  );
  if (!ipRateLimit.allowed) {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: `Too many attempts. Try again in ${ipRateLimit.retryAfter} seconds.`,
      },
      429,
      { headers: { 'Retry-After': String(ipRateLimit.retryAfter) } }
    );
  }

  const username = resolveLoginIdentifier(body.data);
  const password = String(body.data.password || '');
  if (!isValidLoginIdentifier(username) || !password) {
    return jsonResponse(request, env, { ok: false, error: 'Invalid username or password.' }, 401);
  }

  const denied = await store.getDeniedEmail(username);
  if (denied) {
    return jsonResponse(
      request,
      env,
      { ok: false, error: 'Your account has been denied by an administrator.' },
      403
    );
  }

  const user = await store.getUserByEmail(username);

  if (user) {
    const lockout = await store.getLoginLockout(username);
    if (Number(lockout?.lockedUntil || 0) > nowSeconds) {
      const retryAfter = Number(lockout.lockedUntil) - nowSeconds;
      return jsonResponse(
        request,
        env,
        { ok: false, error: `Too many failed logins. Try again in ${retryAfter} seconds.` },
        429,
        { headers: { 'Retry-After': String(retryAfter) } }
      );
    }
  }

  let isMatch = false;
  if (user) {
    isMatch = await verifyPassword(password, user.pass_salt, user.pass_hash, String(env.PASSWORD_PEPPER || ''));
  } else {
    await pbkdf2Hash(password, 'AAAAAAAAAAAAAAAAAAAAAA', String(env.PASSWORD_PEPPER || ''));
  }

  if (!user || !isMatch) {
    if (user) {
      await recordFailedLogin(store, username, nowSeconds);
    }
    return jsonResponse(request, env, { ok: false, error: 'Invalid username or password.' }, 401);
  }

  await store.clearLoginLockout(username);

  if (user.status !== 'approved') {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: 'Account is pending approval.',
      },
      403
    );
  }

  const sessionToken = randomToken(32);
  const sessionTokenHash = await hashSessionToken(sessionToken, env.SESSION_SECRET);
  await store.createSession({
    id: randomToken(16),
    userId: Number(user.id),
    tokenHash: sessionTokenHash,
    createdAt: nowSeconds,
    expiresAt: nowSeconds + SESSION_MAX_AGE_SECONDS,
    lastSeenAt: nowSeconds,
    ipAddress: getClientIp(request),
    userAgent: String(request.headers.get('User-Agent') || '').slice(0, 250),
  });

  const csrfTokenOut = randomToken(24);
  return jsonResponse(
    request,
    env,
    {
      ok: true,
      user: {
        id: Number(user.id),
        username: user.email,
        email: user.email,
        status: user.status,
      },
      csrfToken: csrfTokenOut,
    },
    200,
    {
      cookies: [
        buildSessionCookie(sessionToken, url, env),
        buildCsrfCookie(csrfTokenOut, url, env),
      ],
    }
  );
}

async function handleAuthLogout(request, env, store, url, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const csrfToken = extractCsrfToken(request, body.data);
  const csrfCheck = validateCsrf(request, env, csrfToken);
  if (!csrfCheck.ok) {
    const replacementToken = randomToken(24);
    return jsonResponse(
      request,
      env,
      { ok: false, error: csrfCheck.message, csrfToken: replacementToken },
      403,
      { cookies: [buildCsrfCookie(replacementToken, url, env)] }
    );
  }

  const token = getSessionCookieToken(request);
  if (isValidTokenShape(token)) {
    const tokenHash = await hashSessionToken(token, env.SESSION_SECRET);
    await store.deleteSessionByTokenHash(tokenHash);
  }

  await store.deleteExpiredSessions(nowSeconds);

  const replacementToken = randomToken(24);
  return jsonResponse(
    request,
    env,
    {
      ok: true,
      message: 'Logged out.',
      csrfToken: replacementToken,
    },
    200,
    {
      cookies: [
        clearSessionCookie(url, env),
        buildCsrfCookie(replacementToken, url, env),
      ],
    }
  );
}

async function handleProtectedExample(request, env, store, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await getCurrentUser(request, env, store, nowSeconds);
  if (!auth.user) {
    return jsonResponse(
      request,
      env,
      { ok: false, error: 'Authentication required.' },
      401,
      auth.clearSession ? { cookies: [clearSessionCookie(url, env)] } : {}
    );
  }

  if (!auth.user.approved) {
    return jsonResponse(request, env, { ok: false, error: 'Account is not approved.' }, 403);
  }

  return jsonResponse(request, env, {
    ok: true,
    message: 'Authenticated request successful.',
    user: {
      id: auth.user.id,
      username: auth.user.email,
      email: auth.user.email,
      status: auth.user.status,
    },
    now: new Date(nowSeconds * 1000).toISOString(),
  });
}

async function handleMatch(request, env, store, url, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request, 20_000);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const csrfToken = extractCsrfToken(request, body.data);
  const csrfCheck = validateCsrf(request, env, csrfToken);
  if (!csrfCheck.ok) {
    const replacementToken = randomToken(24);
    return jsonResponse(
      request,
      env,
      { ok: false, error: csrfCheck.message, csrfToken: replacementToken },
      403,
      { cookies: [buildCsrfCookie(replacementToken, url, env)] }
    );
  }

  const auth = await getCurrentUser(request, env, store, nowSeconds);
  if (!auth.user) {
    return jsonResponse(
      request,
      env,
      { ok: false, error: 'Authentication required.' },
      401,
      auth.clearSession ? { cookies: [clearSessionCookie(url, env)] } : {}
    );
  }

  if (!auth.user.approved) {
    return jsonResponse(request, env, { ok: false, error: 'Account is not approved.' }, 403);
  }

  const rateLimit = await enforceRateLimit(
    store,
    getClientIp(request),
    'match_ip',
    RATE_LIMIT_MATCH_IP_MAX,
    RATE_LIMIT_WINDOW_SECONDS,
    nowSeconds
  );
  if (!rateLimit.allowed) {
    return jsonResponse(
      request,
      env,
      {
        ok: false,
        error: `Too many AI requests. Try again in ${rateLimit.retryAfter} seconds.`,
      },
      429,
      { headers: { 'Retry-After': String(rateLimit.retryAfter) } }
    );
  }

  const aiResult = await handleMatchWithAi(env, body.data);
  return jsonResponse(request, env, aiResult.body, aiResult.status);
}

async function handleAdminReview(request, env, store, url) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const access = validateAdminAccess(request, env, {}, url);
  if (!access.ok) {
    return jsonResponse(request, env, { ok: false, error: access.error }, access.status);
  }

  const pendingUsers = await store.listPendingUsers(ADMIN_REVIEW_LIMIT);
  const approvedUsers = await store.listApprovedUsers(ADMIN_REVIEW_LIMIT);
  const deniedUsers = await store.listDeniedUsers(ADMIN_REVIEW_LIMIT);
  return jsonResponse(request, env, {
    ok: true,
    pendingUsers: pendingUsers.map((user) => ({
      ...user,
      username: user.username || user.email,
      email: user.email,
    })),
    approvedUsers: approvedUsers.map((user) => ({
      ...user,
      username: user.username || user.email,
      email: user.email,
    })),
    deniedUsers: deniedUsers.map((user) => ({
      ...user,
      username: user.username || user.email,
      email: user.email,
    })),
  });
}

async function handleAdminApprove(request, env, store, url) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const access = validateAdminAccess(request, env, body.data, url);
  if (!access.ok) {
    return jsonResponse(request, env, { ok: false, error: access.error }, access.status);
  }

  const username = resolveLoginIdentifier(body.data);
  if (!isValidLoginIdentifier(username)) {
    return jsonResponse(request, env, { ok: false, error: 'Please provide a valid username.' }, 400);
  }

  const user = await store.getUserByEmail(username);
  if (!user) {
    return jsonResponse(request, env, { ok: false, error: 'User not found.' }, 404);
  }

  const updated = await store.setUserStatusByEmail(username, 'approved');
  await store.clearDeniedEmail(username);
  await store.clearLoginLockout(username);

  return jsonResponse(request, env, {
    ok: true,
    message: 'User approved.',
    user: toPublicUser(updated),
  });
}

async function handleAdminDeny(request, env, store, url) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const body = await readJsonBody(request);
  if (!body.ok) {
    return jsonResponse(request, env, { ok: false, error: body.error }, body.status);
  }

  const access = validateAdminAccess(request, env, body.data, url);
  if (!access.ok) {
    return jsonResponse(request, env, { ok: false, error: access.error }, access.status);
  }

  const username = resolveLoginIdentifier(body.data);
  if (!isValidLoginIdentifier(username)) {
    return jsonResponse(request, env, { ok: false, error: 'Please provide a valid username.' }, 400);
  }

  const reason = normalizeAdminReason(body.data.reason);
  const user = await store.getUserByEmail(username);

  await store.upsertDeniedEmail(username, reason);
  await store.clearLoginLockout(username);

  if (user) {
    await store.setUserStatusByEmail(username, 'pending');
    await store.deleteSessionsByUserId(Number(user.id));
  }

  return jsonResponse(request, env, {
    ok: true,
    message: 'User denied.',
    denied: {
      username,
      email: username,
      reason,
      userExists: Boolean(user),
    },
  });
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
            service: 'ruae-api',
            timestamp: new Date(now()).toISOString(),
          });
        }

        if (!env.SESSION_SECRET) {
          return jsonResponse(request, env, { ok: false, error: 'Server auth is not configured.' }, 500);
        }

        const store = env.AUTH_STORE || (env.DB ? createD1Store(env.DB) : null);
        if (!store) {
          return jsonResponse(request, env, { ok: false, error: 'Database binding is not configured.' }, 500);
        }

        const nowSeconds = Math.floor(now() / 1000);

        if (path === '/api/admin/review') {
          return handleAdminReview(request, env, store, url, nowSeconds);
        }

        if (path === '/api/admin/approve') {
          return handleAdminApprove(request, env, store, url, nowSeconds);
        }

        if (path === '/api/admin/deny') {
          return handleAdminDeny(request, env, store, url, nowSeconds);
        }

        if (path === '/api/auth/me') {
          return handleAuthMe(request, env, store, url, nowSeconds);
        }

        if (path === '/api/auth/register') {
          return handleAuthRegister(request, env, store, url, nowSeconds);
        }

        if (path === '/api/auth/login') {
          return handleAuthLogin(request, env, store, url, nowSeconds);
        }

        if (path === '/api/auth/logout') {
          return handleAuthLogout(request, env, store, url, nowSeconds);
        }

        if (path === '/api/protected/example') {
          return handleProtectedExample(request, env, store, url, nowSeconds);
        }

        if (path === '/api/match') {
          return handleMatch(request, env, store, url, nowSeconds);
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
  isValidEmail,
  isValidUsername,
  isStrongPassword,
  isValidTokenShape,
  parseCookies,
  parseSetCookieValue,
  getOrCreateCsrfToken,
  validateCsrf,
  timingSafeEqual,
};

export default createApiHandler();
