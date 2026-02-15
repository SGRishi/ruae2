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
  headers.set('Access-Control-Allow-Methods', 'GET,HEAD,POST,OPTIONS');
  headers.set(
    'Access-Control-Allow-Headers',
    'Content-Type, Range, If-Modified-Since, If-None-Match, If-Range, X-CSRF-Token, X-Admin-Token, X-Admin-Key'
  );
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag');
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
         ORDER BY created_at DESC
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

    async clearAllDeniedEmails() {
      const result = await db.prepare('DELETE FROM denied_users').run();
      return Number(result.meta?.changes || 0);
    },

    async purgeDeniedList() {
      // Delete any user accounts tied to the denied list so a purge doesn't
      // "move" users back into pending review.
      await db.prepare(
        `DELETE FROM sessions
         WHERE user_id IN (
           SELECT id FROM users WHERE email IN (SELECT email FROM denied_users)
         )`
      ).run();
      await db.prepare(
        `DELETE FROM login_lockouts
         WHERE email IN (SELECT email FROM denied_users)`
      ).run();

      const usersResult = await db.prepare(
        `DELETE FROM users
         WHERE email IN (SELECT email FROM denied_users)`
      ).run();
      const deniedResult = await db.prepare('DELETE FROM denied_users').run();

      return {
        deletedUsers: Number(usersResult.meta?.changes || 0),
        deletedDenied: Number(deniedResult.meta?.changes || 0),
      };
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
        .sort((a, b) => Number(b.id) - Number(a.id))
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

    async clearAllDeniedEmails() {
      const removed = deniedByEmail.size;
      deniedByEmail.clear();
      return removed;
    },

    async purgeDeniedList() {
      const deniedEmails = Array.from(deniedByEmail.keys());
      let deletedUsers = 0;

      for (const email of deniedEmails) {
        const user = usersByEmail.get(email) || null;
        if (user) {
          usersById.delete(Number(user.id));
          usersByEmail.delete(email);
          await this.deleteSessionsByUserId(Number(user.id));
          deletedUsers += 1;
        }
        lockouts.delete(email);
      }

      const deletedDenied = deniedByEmail.size;
      deniedByEmail.clear();

      return {
        deletedUsers,
        deletedDenied,
      };
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

function safeLike(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[%_]/g, (match) => `\\${match}`);
}

function normalizeMathsPaperNumber(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return parsed === 1 || parsed === 2 ? parsed : null;
}

function normalizeMathsYear(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) && parsed >= 1990 && parsed <= 2100 ? parsed : null;
}

function mathsPaperLabel(paperNumber) {
  const paper = normalizeMathsPaperNumber(paperNumber);
  if (paper === 1) return 'Paper 1 (Non-Calculator)';
  if (paper === 2) return 'Paper 2 (Calculator)';
  return 'Paper';
}

function isApprovedMathsRequest(request, env, store, nowSeconds) {
  // Wrapper for readability. Returns either { ok:false, response } or { ok:true, auth }.
  return getCurrentUser(request, env, store, nowSeconds).then((auth) => {
    if (!auth.user) {
      const payload = { ok: false, error: 'Authentication required.' };
      const options = auth.clearSession ? { cookies: [clearSessionCookie(new URL(request.url), env)] } : {};
      return { ok: false, response: jsonResponse(request, env, payload, 401, options) };
    }
    if (!auth.user.approved) {
      return { ok: false, response: jsonResponse(request, env, { ok: false, error: 'Account is not approved.' }, 403) };
    }
    return { ok: true, auth };
  });
}

function buildMathsPublicUrl(storageKind, storageKey) {
  const key = String(storageKey || '').trim();
  if (!key) return '';
  if (storageKind === 'r2') {
    return `/api/maths/blob?key=${encodeURIComponent(key)}`;
  }
  return key.startsWith('/') ? key : `/${key}`;
}

function mathsPdfKey(fileId) {
  const id = String(fileId || '').trim();
  if (!id) return '';
  return `maths/pdfs/${id}.pdf`;
}

function buildMathsPdfUrl(fileId) {
  const key = mathsPdfKey(fileId);
  if (!key) return '';
  return `/api/maths/blob?key=${encodeURIComponent(key)}`;
}

function safeMathsKeyPart(value) {
  return String(value || '')
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 120);
}

function mathsCropKey(questionId, cropId, stampMillis) {
  const q = safeMathsKeyPart(questionId);
  const c = safeMathsKeyPart(cropId);
  const stamp = Number.isFinite(stampMillis) ? Math.floor(stampMillis) : Date.now();
  return `maths/crops/${q}/${c}_${stamp}.png`;
}

function mathsCropUrlById(cropId) {
  const id = String(cropId || '').trim();
  if (!id) return '';
  return `/api/maths/crops/${encodeURIComponent(id)}.png`;
}

function createMathsD1Store(db) {
  if (!db || typeof db.prepare !== 'function') {
    throw new Error('DB binding is missing or invalid.');
  }

  return {
    async listYears() {
      const result = await db.prepare('SELECT DISTINCT year FROM maths_questions WHERE year IS NOT NULL ORDER BY year DESC')
        .all();
      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows
        .map((row) => Number(row.year))
        .filter((year) => Number.isFinite(year));
    },

    async listFiles(filters = {}) {
      const type = String(filters.type || '').trim();
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);

      const where = [];
      const params = [];

      if (type) {
        where.push('type = ?');
        params.push(type);
      }
      if (year) {
        where.push('year = ?');
        params.push(year);
      }
      if (paperNumber) {
        where.push('paper_number = ?');
        params.push(paperNumber);
      }

      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const result = await db.prepare(
        `SELECT id, path, type, year, paper_number, calculator_allowed, session, page_count, created_at
         FROM maths_files
         ${whereSql}
         ORDER BY year DESC, paper_number ASC, type ASC, created_at DESC`
      )
        .bind(...params)
        .all();

      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows.map((row) => ({
        id: row.id,
        path: row.path,
        type: row.type,
        year: row.year == null ? null : Number(row.year),
        paperNumber: row.paper_number == null ? null : Number(row.paper_number),
        calculatorAllowed: row.calculator_allowed == null ? null : Boolean(row.calculator_allowed),
        session: row.session || '',
        pageCount: row.page_count == null ? null : Number(row.page_count),
        pdfUrl: buildMathsPdfUrl(row.id),
        createdAt: row.created_at,
      }));
    },

    async getFileById(fileId) {
      const id = String(fileId || '').trim();
      if (!id) return null;
      const row = await db.prepare(
        `SELECT id, path, type, year, paper_number, calculator_allowed, session, page_count, created_at
         FROM maths_files
         WHERE id = ?1
         LIMIT 1`
      )
        .bind(id)
        .first();
      if (!row) return null;
      return {
        id: row.id,
        path: row.path,
        type: row.type,
        year: row.year == null ? null : Number(row.year),
        paperNumber: row.paper_number == null ? null : Number(row.paper_number),
        calculatorAllowed: row.calculator_allowed == null ? null : Boolean(row.calculator_allowed),
        session: row.session || '',
        pageCount: row.page_count == null ? null : Number(row.page_count),
        pdfUrl: buildMathsPdfUrl(row.id),
        createdAt: row.created_at,
      };
    },

    async listQuestions(filters = {}) {
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);
      const query = safeLike(filters.query);
      const safeLimit = Math.max(1, Math.min(500, Number(filters.limit) || 200));

      const where = [];
      const params = [];

      if (year) {
        where.push('year = ?');
        params.push(year);
      }
      if (paperNumber) {
        where.push('paper_number = ?');
        params.push(paperNumber);
      }

      if (query) {
        where.push(`(lower(q_label) LIKE ? ESCAPE '\\\\' OR lower(coalesce(topic,'')) LIKE ? ESCAPE '\\\\' OR lower(coalesce(text_extracted,'')) LIKE ? ESCAPE '\\\\')`);
        const like = `%${query}%`;
        params.push(like, like, like);
      }

      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      const sql = `SELECT q.id, q.year, q.paper_number, q.q_number, q.q_label, q.topic,
                          (SELECT id FROM maths_crops c WHERE c.question_id = q.id AND c.kind = 'thumb' LIMIT 1) AS thumb_id,
                          (SELECT storage_kind FROM maths_crops c WHERE c.question_id = q.id AND c.kind = 'thumb' LIMIT 1) AS thumb_storage_kind,
                          (SELECT storage_key FROM maths_crops c WHERE c.question_id = q.id AND c.kind = 'thumb' LIMIT 1) AS thumb_storage_key
                   FROM maths_questions q
                   ${whereSql}
                   ORDER BY q.year DESC, q.paper_number ASC, q.q_number ASC
                   LIMIT ?`;

      const result = await db.prepare(sql)
        .bind(...params, safeLimit)
        .all();

      const rows = Array.isArray(result?.results) ? result.results : [];
      return rows.map((row) => ({
        id: row.id,
        year: Number(row.year),
        paperNumber: Number(row.paper_number),
        qNumber: Number(row.q_number),
        qLabel: row.q_label,
        topic: row.topic || '',
        thumbUrl: row.thumb_id ? mathsCropUrlById(row.thumb_id) : buildMathsPublicUrl(row.thumb_storage_kind || 'public', row.thumb_storage_key || ''),
      }));
    },

    async getQuestionById(id) {
      const questionId = String(id || '').trim();
      if (!questionId) return null;

      const q = await db.prepare(
        `SELECT id, year, paper_number, q_number, q_label, topic, topic_confidence, text_extracted
         FROM maths_questions
         WHERE id = ?1
         LIMIT 1`
      )
        .bind(questionId)
        .first();

      if (!q) return null;

      const cropsResult = await db.prepare(
        `SELECT id, kind, file_id, page_index, x0, y0, x1, y1, render_dpi, storage_kind, storage_key
         FROM maths_crops
         WHERE question_id = ?1
           AND kind IN ('question', 'answer')
         ORDER BY kind ASC, page_index ASC`
      )
        .bind(questionId)
        .all();

      const crops = Array.isArray(cropsResult?.results) ? cropsResult.results : [];
      const questionCrops = [];
      const answerCrops = [];

      for (const crop of crops) {
        const item = {
          id: crop.id,
          fileId: crop.file_id,
          pageIndex: Number(crop.page_index),
          x0: Number(crop.x0),
          y0: Number(crop.y0),
          x1: Number(crop.x1),
          y1: Number(crop.y1),
          renderDpi: Number(crop.render_dpi),
          storageKind: crop.storage_kind || 'public',
          storageKey: crop.storage_key,
          url: mathsCropUrlById(crop.id),
        };
        if (crop.kind === 'answer') answerCrops.push(item);
        else questionCrops.push(item);
      }

      return {
        id: q.id,
        year: Number(q.year),
        paperNumber: Number(q.paper_number),
        qNumber: Number(q.q_number),
        qLabel: q.q_label,
        topic: q.topic || '',
        topicConfidence: q.topic_confidence == null ? null : Number(q.topic_confidence),
        textExtracted: q.text_extracted || '',
        questionCrops,
        answerCrops,
      };
    },

    async getCropById(cropId) {
      const id = String(cropId || '').trim();
      if (!id) return null;
      const crop = await db.prepare(
        `SELECT id, question_id, kind, file_id, page_index, x0, y0, x1, y1, render_dpi, storage_kind, storage_key, status
         FROM maths_crops
         WHERE id = ?1
         LIMIT 1`
      )
        .bind(id)
        .first();
      if (!crop) return null;
      return {
        id: String(crop.id),
        questionId: String(crop.question_id),
        kind: String(crop.kind),
        fileId: String(crop.file_id || ''),
        pageIndex: Number(crop.page_index),
        x0: Number(crop.x0),
        y0: Number(crop.y0),
        x1: Number(crop.x1),
        y1: Number(crop.y1),
        renderDpi: Number(crop.render_dpi),
        storageKind: String(crop.storage_kind || 'public'),
        storageKey: String(crop.storage_key || ''),
        status: String(crop.status || ''),
      };
    },

    async getDatasheet(filters = {}) {
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);
      if (!year || !paperNumber) return null;

      const ds = await db.prepare(
        `SELECT d.file_id, f.year, f.paper_number
         FROM maths_datasheets d
         JOIN maths_files f ON f.id = d.file_id
         WHERE d.year = ?1 AND d.paper_number = ?2
         LIMIT 1`
      )
        .bind(year, paperNumber)
        .first();

      if (!ds) return null;

      return {
        year: Number(ds.year),
        paperNumber: Number(ds.paper_number),
        fileId: ds.file_id,
        pdfUrl: buildMathsPdfUrl(ds.file_id),
      };
    },

    async getDiagnostics() {
      const files = await db.prepare('SELECT COUNT(1) AS count FROM maths_files').first();
      const questions = await db.prepare('SELECT COUNT(1) AS count FROM maths_questions').first();
      const crops = await db.prepare('SELECT COUNT(1) AS count FROM maths_crops').first();
      const datasheets = await db.prepare('SELECT COUNT(1) AS count FROM maths_datasheets').first();
      const missingMappings = await db.prepare(
        `SELECT COUNT(1) AS count
         FROM maths_questions q
         WHERE NOT EXISTS (
           SELECT 1 FROM maths_crops c WHERE c.question_id = q.id AND c.kind = 'answer'
         )`
      ).first();

      const lastRun = await db.prepare(
        `SELECT log_text
         FROM maths_pipeline_runs
         ORDER BY started_at DESC
         LIMIT 1`
      ).first();

      const logText = String(lastRun?.log_text || '');
      const tail = logText.length > 4000 ? logText.slice(-4000) : logText;

      return {
        files: Number(files?.count || 0),
        questions: Number(questions?.count || 0),
        crops: Number(crops?.count || 0),
        datasheets: Number(datasheets?.count || 0),
        missingMappings: Number(missingMappings?.count || 0),
        lastLogTail: tail,
      };
    },

    async updateQuestion(questionId, patch = {}) {
      const id = String(questionId || '').trim();
      if (!id) return null;

      const qLabel = typeof patch.qLabel === 'string' ? patch.qLabel.trim().slice(0, 140) : null;
      const topic = typeof patch.topic === 'string' ? patch.topic.trim().slice(0, 120) : null;

      if (qLabel != null) {
        await db.prepare('UPDATE maths_questions SET q_label = ?1 WHERE id = ?2')
          .bind(qLabel, id)
          .run();
      }
      if (topic != null) {
        await db.prepare('UPDATE maths_questions SET topic = ?1 WHERE id = ?2')
          .bind(topic, id)
          .run();
      }

      return this.getQuestionById(id);
    },

    async updateCropRects(list = []) {
      const crops = Array.isArray(list) ? list : [];
      let updated = 0;
      for (const item of crops) {
        const id = String(item?.id || '').trim();
        if (!id) continue;
        const questionId = String(item?.questionId || '').trim();
        if (!questionId) continue;
        const x0 = Number(item?.x0);
        const y0 = Number(item?.y0);
        const x1 = Number(item?.x1);
        const y1 = Number(item?.y1);
        if (![x0, y0, x1, y1].every((v) => Number.isFinite(v))) continue;
        const storageKind = typeof item?.storageKind === 'string' ? item.storageKind.trim() : '';
        const storageKey = typeof item?.storageKey === 'string' ? item.storageKey.trim() : '';
        const status = typeof item?.status === 'string' ? item.status.trim() : '';

        const sets = ['x0 = ?1', 'y0 = ?2', 'x1 = ?3', 'y1 = ?4'];
        const params = [x0, y0, x1, y1];

        if (storageKind && (storageKind === 'public' || storageKind === 'r2')) {
          sets.push(`storage_kind = ?${params.length + 1}`);
          params.push(storageKind);
        }
        if (storageKey) {
          sets.push(`storage_key = ?${params.length + 1}`);
          params.push(storageKey);
        }
        if (status && (status === 'auto' || status === 'reviewed')) {
          sets.push(`status = ?${params.length + 1}`);
          params.push(status);
        }

        // Keep this column optional for backwards compatibility with older DBs.
        sets.push('updated_at = CURRENT_TIMESTAMP');

        const sql = `UPDATE maths_crops SET ${sets.join(', ')} WHERE id = ?${params.length + 1} AND question_id = ?${params.length + 2}`;
        params.push(id, questionId);

        await db.prepare(sql)
          .bind(...params)
          .run();
        updated += 1;
      }
      return { updated };
    },

    async createCrop(crop) {
      const id = String(crop?.id || '').trim();
      const questionId = String(crop?.questionId || '').trim();
      const kind = String(crop?.kind || '').trim();
      const fileId = String(crop?.fileId || '').trim();
      const pageIndex = Number(crop?.pageIndex);
      const x0 = Number(crop?.x0);
      const y0 = Number(crop?.y0);
      const x1 = Number(crop?.x1);
      const y1 = Number(crop?.y1);
      const renderDpi = Number(crop?.renderDpi);
      const storageKind = String(crop?.storageKind || 'public').trim();
      const storageKey = String(crop?.storageKey || '').trim();

      if (!id || !questionId || !fileId || !storageKey) return null;
      if (kind !== 'question' && kind !== 'answer' && kind !== 'thumb') return null;
      if (!Number.isFinite(pageIndex) || pageIndex < 0) return null;
      if (![x0, y0, x1, y1].every((v) => Number.isFinite(v))) return null;
      if (!Number.isFinite(renderDpi) || renderDpi < 36 || renderDpi > 600) return null;
      if (storageKind !== 'public' && storageKind !== 'r2') return null;

      await db.prepare(
        `INSERT INTO maths_crops (id, question_id, kind, file_id, page_index, x0, y0, x1, y1, render_dpi, storage_kind, storage_key, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
      )
        .bind(id, questionId, kind, fileId, pageIndex, x0, y0, x1, y1, renderDpi, storageKind, storageKey, 'reviewed')
        .run();

      return { id };
    },

    async deleteCrops(ids = []) {
      const list = Array.isArray(ids) ? ids : [];
      let deleted = 0;
      for (const rawId of list) {
        const id = String(rawId || '').trim();
        if (!id) continue;
        const result = await db.prepare('DELETE FROM maths_crops WHERE id = ?1')
          .bind(id)
          .run();
        if (result?.success) deleted += Number(result?.meta?.changes || 0);
      }
      return { deleted };
    },
  };
}

export function createMathsMemoryStore(seed = {}) {
  const files = new Map();
  const questions = new Map();
  const crops = new Map(); // cropId -> crop
  const datasheets = new Map(); // `${year}:${paper}` -> fileId
  const pipelineRuns = [];

  const initialFiles = Array.isArray(seed.files) ? seed.files : [];
  for (const file of initialFiles) {
    if (!file || !file.id) continue;
    files.set(String(file.id), { ...file });
  }

  const initialQuestions = Array.isArray(seed.questions) ? seed.questions : [];
  for (const q of initialQuestions) {
    questions.set(q.id, { ...q });
  }

  const initialCrops = Array.isArray(seed.crops) ? seed.crops : [];
  for (const crop of initialCrops) {
    crops.set(crop.id, { ...crop });
  }

  const initialYears = new Set();
  for (const q of questions.values()) {
    if (q.year) initialYears.add(Number(q.year));
  }

  return {
    async listYears() {
      return Array.from(initialYears.values()).sort((a, b) => b - a);
    },

    async listFiles(filters = {}) {
      const type = String(filters.type || '').trim();
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);

      let list = Array.from(files.values());
      if (type) list = list.filter((f) => String(f.type || '') === type);
      if (year) list = list.filter((f) => Number(f.year) === year);
      if (paperNumber) list = list.filter((f) => Number(f.paperNumber) === paperNumber);

      list.sort(
        (a, b) =>
          Number(b.year || 0) - Number(a.year || 0) ||
          Number(a.paperNumber || 0) - Number(b.paperNumber || 0) ||
          String(a.type || '').localeCompare(String(b.type || ''))
      );

      return list.map((row) => ({
        id: String(row.id),
        path: row.path || '',
        type: row.type || '',
        year: row.year == null ? null : Number(row.year),
        paperNumber: row.paperNumber == null ? null : Number(row.paperNumber),
        calculatorAllowed: row.calculatorAllowed == null ? null : Boolean(row.calculatorAllowed),
        session: row.session || '',
        pageCount: row.pageCount == null ? null : Number(row.pageCount),
        pdfUrl: buildMathsPdfUrl(row.id),
        createdAt: row.createdAt || '',
      }));
    },

    async getFileById(fileId) {
      const id = String(fileId || '').trim();
      if (!id) return null;
      const row = files.get(id) || null;
      if (!row) return null;
      return {
        id: String(row.id),
        path: row.path || '',
        type: row.type || '',
        year: row.year == null ? null : Number(row.year),
        paperNumber: row.paperNumber == null ? null : Number(row.paperNumber),
        calculatorAllowed: row.calculatorAllowed == null ? null : Boolean(row.calculatorAllowed),
        session: row.session || '',
        pageCount: row.pageCount == null ? null : Number(row.pageCount),
        pdfUrl: buildMathsPdfUrl(row.id),
        createdAt: row.createdAt || '',
      };
    },

    async listQuestions(filters = {}) {
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);
      const query = safeLike(filters.query);
      const limit = Math.max(1, Math.min(500, Number(filters.limit) || 200));

      let list = Array.from(questions.values());
      if (year) list = list.filter((q) => Number(q.year) === year);
      if (paperNumber) list = list.filter((q) => Number(q.paperNumber) === paperNumber);

      if (query) {
        list = list.filter((q) => {
          const text = `${q.qLabel || ''} ${q.topic || ''} ${q.textExtracted || ''}`.toLowerCase();
          return text.includes(query);
        });
      }

      list.sort((a, b) => Number(b.year) - Number(a.year) || Number(a.paperNumber) - Number(b.paperNumber) || Number(a.qNumber) - Number(b.qNumber));

      const thumbByQuestionId = new Map();
      for (const crop of crops.values()) {
        if (!crop || crop.kind !== 'thumb') continue;
        if (!crop.questionId || thumbByQuestionId.has(crop.questionId)) continue;
        thumbByQuestionId.set(String(crop.questionId), String(crop.id));
      }

      return list.slice(0, limit).map((q) => ({
        id: q.id,
        year: Number(q.year),
        paperNumber: Number(q.paperNumber),
        qNumber: Number(q.qNumber),
        qLabel: q.qLabel,
        topic: q.topic || '',
        thumbUrl: thumbByQuestionId.has(q.id) ? mathsCropUrlById(thumbByQuestionId.get(q.id)) : (q.thumbUrl || ''),
      }));
    },

    async getQuestionById(id) {
      const q = questions.get(String(id || '')) || null;
      if (!q) return null;

      const questionCrops = [];
      const answerCrops = [];
      for (const crop of crops.values()) {
        if (crop.questionId !== q.id) continue;
        if (crop.kind !== 'question' && crop.kind !== 'answer') continue;
        const item = {
          id: crop.id,
          fileId: crop.fileId || '',
          pageIndex: Number(crop.pageIndex || 0),
          x0: Number(crop.x0 || 0),
          y0: Number(crop.y0 || 0),
          x1: Number(crop.x1 || 0),
          y1: Number(crop.y1 || 0),
          renderDpi: Number(crop.renderDpi || 0),
          storageKind: crop.storageKind || 'public',
          storageKey: crop.storageKey || '',
          url: mathsCropUrlById(crop.id) || crop.url || buildMathsPublicUrl(crop.storageKind || 'public', crop.storageKey || ''),
        };
        if (crop.kind === 'answer') answerCrops.push(item);
        else questionCrops.push(item);
      }

      questionCrops.sort((a, b) => a.pageIndex - b.pageIndex);
      answerCrops.sort((a, b) => a.pageIndex - b.pageIndex);

      return {
        id: q.id,
        year: Number(q.year),
        paperNumber: Number(q.paperNumber),
        qNumber: Number(q.qNumber),
        qLabel: q.qLabel,
        topic: q.topic || '',
        topicConfidence: q.topicConfidence == null ? null : Number(q.topicConfidence),
        textExtracted: q.textExtracted || '',
        questionCrops,
        answerCrops,
      };
    },

    async getCropById(cropId) {
      const id = String(cropId || '').trim();
      if (!id) return null;
      const crop = crops.get(id) || null;
      if (!crop) return null;
      return {
        id: String(crop.id),
        questionId: String(crop.questionId || ''),
        kind: String(crop.kind || ''),
        fileId: String(crop.fileId || ''),
        pageIndex: Number(crop.pageIndex || 0),
        x0: Number(crop.x0 || 0),
        y0: Number(crop.y0 || 0),
        x1: Number(crop.x1 || 0),
        y1: Number(crop.y1 || 0),
        renderDpi: Number(crop.renderDpi || 0),
        storageKind: String(crop.storageKind || 'public'),
        storageKey: String(crop.storageKey || ''),
        status: String(crop.status || ''),
      };
    },

    async getDatasheet(filters = {}) {
      const year = normalizeMathsYear(filters.year);
      const paperNumber = normalizeMathsPaperNumber(filters.paperNumber);
      if (!year || !paperNumber) return null;

      const fileId = datasheets.get(`${year}:${paperNumber}`) || null;
      if (!fileId) return null;
      return { year, paperNumber, fileId, pdfUrl: buildMathsPdfUrl(fileId) };
    },

    async getDiagnostics() {
      const years = new Set();
      for (const q of questions.values()) years.add(Number(q.year));
      const lastRun = pipelineRuns.length ? pipelineRuns[pipelineRuns.length - 1] : null;
      const logText = String(lastRun?.logText || '');
      const tail = logText.length > 4000 ? logText.slice(-4000) : logText;

      let missingMappings = 0;
      for (const q of questions.values()) {
        const hasAnswer = Array.from(crops.values()).some((crop) => crop.questionId === q.id && crop.kind === 'answer');
        if (!hasAnswer) missingMappings += 1;
      }

      return {
        files: files.size,
        questions: questions.size,
        crops: crops.size,
        datasheets: datasheets.size,
        missingMappings,
        lastLogTail: tail,
      };
    },

    async updateQuestion(questionId, patch = {}) {
      const id = String(questionId || '').trim();
      const q = questions.get(id) || null;
      if (!q) return null;

      if (typeof patch.qLabel === 'string') {
        q.qLabel = patch.qLabel.trim().slice(0, 140);
      }
      if (typeof patch.topic === 'string') {
        q.topic = patch.topic.trim().slice(0, 120);
      }

      questions.set(id, q);
      return this.getQuestionById(id);
    },

    async updateCropRects(list = []) {
      const items = Array.isArray(list) ? list : [];
      let updated = 0;
      for (const item of items) {
        const id = String(item?.id || '').trim();
        const crop = crops.get(id) || null;
        if (!crop) continue;
        if (String(item?.questionId || '') !== String(crop.questionId || '')) continue;
        const x0 = Number(item?.x0);
        const y0 = Number(item?.y0);
        const x1 = Number(item?.x1);
        const y1 = Number(item?.y1);
        if (![x0, y0, x1, y1].every((v) => Number.isFinite(v))) continue;
        crop.x0 = x0;
        crop.y0 = y0;
        crop.x1 = x1;
        crop.y1 = y1;
        if (typeof item?.storageKind === 'string') crop.storageKind = item.storageKind;
        if (typeof item?.storageKey === 'string') crop.storageKey = item.storageKey;
        if (typeof item?.url === 'string') crop.url = item.url;
        crops.set(id, crop);
        updated += 1;
      }
      return { updated };
    },

    async createCrop(crop) {
      const id = String(crop?.id || '').trim();
      if (!id) return null;
      crops.set(id, { ...crop });
      return { id };
    },

    async deleteCrops(ids = []) {
      const list = Array.isArray(ids) ? ids : [];
      let deleted = 0;
      for (const rawId of list) {
        const id = String(rawId || '').trim();
        if (!id) continue;
        if (crops.delete(id)) deleted += 1;
      }
      return { deleted };
    },

    __unsafe_seedDatasheets(list = []) {
      for (const item of list) {
        const year = normalizeMathsYear(item?.year);
        const paperNumber = normalizeMathsPaperNumber(item?.paperNumber);
        if (!year || !paperNumber) continue;
        if (!item.fileId) continue;
        datasheets.set(`${year}:${paperNumber}`, String(item.fileId));
      }
    },

    __unsafe_seedFiles(list = []) {
      for (const file of list) {
        if (!file || !file.id) continue;
        files.set(String(file.id), { ...file });
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

async function handleAdminDenyAllPending(request, env, store, url) {
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

  const reason = normalizeAdminReason(body.data.reason);
  const pendingUsers = await store.listPendingUsers(ADMIN_REVIEW_LIMIT);

  let deniedCount = 0;
  for (const user of pendingUsers) {
    const email = normalizeEmail(user?.email || user?.username);
    if (!email) continue;
    await store.upsertDeniedEmail(email, reason);
    await store.clearLoginLockout(email);
    deniedCount += 1;
  }

  return jsonResponse(request, env, {
    ok: true,
    message: 'All pending users denied.',
    deniedCount,
  });
}

async function handleAdminClearDenied(request, env, store, url) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const access = validateAdminAccess(request, env, {}, url);
  if (!access.ok) {
    return jsonResponse(request, env, { ok: false, error: access.error }, access.status);
  }

  if (typeof store.purgeDeniedList !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Denied list purge is not supported.' }, 500);
  }

  const result = await store.purgeDeniedList();
  return jsonResponse(request, env, {
    ok: true,
    message: 'Denied list purged.',
    ...result,
  });
}

function contentTypeForKey(key) {
  const value = String(key || '').toLowerCase();
  if (value.endsWith('.png')) return 'image/png';
  if (value.endsWith('.jpg') || value.endsWith('.jpeg')) return 'image/jpeg';
  if (value.endsWith('.webp')) return 'image/webp';
  if (value.endsWith('.pdf')) return 'application/pdf';
  return 'application/octet-stream';
}

async function handleMathsYears(request, env, authStore, mathsStore, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.listYears !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const years = await mathsStore.listYears();
  return jsonResponse(request, env, { ok: true, years }, 200);
}

async function handleMathsFiles(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.listFiles !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const type = url.searchParams.get('type');
  const year = url.searchParams.get('year');
  const paper = url.searchParams.get('paper');

  const files = await mathsStore.listFiles({ type, year, paperNumber: paper });
  return jsonResponse(request, env, { ok: true, files }, 200);
}

async function handleMathsFile(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.getFileById !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const id = String(url.searchParams.get('id') || '').trim();
  if (!id) {
    return jsonResponse(request, env, { ok: false, error: 'Missing file id.' }, 400);
  }

  const file = await mathsStore.getFileById(id);
  if (!file) {
    return jsonResponse(request, env, { ok: false, error: 'File not found.' }, 404);
  }

  return jsonResponse(request, env, { ok: true, file }, 200);
}

async function handleMathsQuestions(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.listQuestions !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const year = url.searchParams.get('year');
  const paper = url.searchParams.get('paper');
  const query = url.searchParams.get('q');

  const questions = await mathsStore.listQuestions({
    year,
    paperNumber: paper,
    query,
    limit: url.searchParams.get('limit'),
  });

  return jsonResponse(request, env, { ok: true, questions }, 200);
}

async function handleMathsQuestion(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.getQuestionById !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const id = String(url.searchParams.get('id') || '').trim();
  if (!id) {
    return jsonResponse(request, env, { ok: false, error: 'Missing question id.' }, 400);
  }

  const question = await mathsStore.getQuestionById(id);
  if (!question) {
    return jsonResponse(request, env, { ok: false, error: 'Question not found.' }, 404);
  }

  return jsonResponse(request, env, { ok: true, question }, 200);
}

async function handleMathsDatasheet(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.getDatasheet !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const year = url.searchParams.get('year');
  const paper = url.searchParams.get('paper');

  const datasheet = await mathsStore.getDatasheet({ year, paperNumber: paper });
  return jsonResponse(
    request,
    env,
    { ok: true, fileId: datasheet?.fileId || null, pdfUrl: datasheet?.pdfUrl || '' },
    200
  );
}

async function handleMathsDiagnostics(request, env, authStore, mathsStore, nowSeconds) {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, env, ['GET']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.getDiagnostics !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const diagnostics = await mathsStore.getDiagnostics();
  return jsonResponse(request, env, { ok: true, ...diagnostics }, 200);
}

async function handleMathsReviewSave(request, env, authStore, mathsStore, url, nowSeconds) {
  if (request.method !== 'POST') {
    return methodNotAllowed(request, env, ['POST']);
  }

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (
    !mathsStore ||
    typeof mathsStore.updateQuestion !== 'function' ||
    typeof mathsStore.updateCropRects !== 'function' ||
    typeof mathsStore.createCrop !== 'function' ||
    typeof mathsStore.deleteCrops !== 'function'
  ) {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const body = await readJsonBody(request, 8_000_000);
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

  const questionId = String(body.data?.questionId || '').trim();
  if (!questionId) {
    return jsonResponse(request, env, { ok: false, error: 'questionId is required.' }, 400);
  }

  const patch = body.data?.question || {};
  const cropPatches = Array.isArray(body.data?.crops) ? body.data.crops : [];
  const newCrops = Array.isArray(body.data?.newCrops) ? body.data.newCrops : [];
  const deleteCropIds = Array.isArray(body.data?.deleteCropIds) ? body.data.deleteCropIds : [];

  if (deleteCropIds.length) {
    return jsonResponse(request, env, { ok: false, error: 'Deleting crops is disabled.' }, 403);
  }

  const updatedQuestion = await mathsStore.updateQuestion(questionId, {
    qLabel: patch.qLabel,
    topic: patch.topic,
  });

  if (!updatedQuestion) {
    return jsonResponse(request, env, { ok: false, error: 'Question not found.' }, 404);
  }

  const toUpload = [];
  const normalizedPatches = [];
  const normalizedCreates = [];

  for (const raw of cropPatches) {
    const id = String(raw?.id || '').trim();
    if (!id) continue;
    const x0 = Number(raw?.x0);
    const y0 = Number(raw?.y0);
    const x1 = Number(raw?.x1);
    const y1 = Number(raw?.y1);
    if (![x0, y0, x1, y1].every((v) => Number.isFinite(v))) continue;

    const item = {
      id,
      questionId,
      x0,
      y0,
      x1,
      y1,
      status: 'reviewed',
    };

    const imageBase64 = typeof raw?.imageBase64 === 'string' ? raw.imageBase64.trim() : '';
    const contentType = typeof raw?.contentType === 'string' ? raw.contentType.trim() : '';
    if (imageBase64) {
      const key = mathsCropKey(questionId, id, Date.now());
      toUpload.push({ key, imageBase64, contentType: contentType || 'image/png' });
      item.storageKind = 'r2';
      item.storageKey = key;
    }

    normalizedPatches.push(item);
  }

  for (const raw of newCrops) {
    const kind = String(raw?.kind || '').trim();
    const fileId = String(raw?.fileId || '').trim();
    const pageIndex = Number(raw?.pageIndex);
    const x0 = Number(raw?.x0);
    const y0 = Number(raw?.y0);
    const x1 = Number(raw?.x1);
    const y1 = Number(raw?.y1);
    const renderDpi = Number(raw?.renderDpi);
    const imageBase64 = typeof raw?.imageBase64 === 'string' ? raw.imageBase64.trim() : '';
    const contentType = typeof raw?.contentType === 'string' ? raw.contentType.trim() : '';
    if (!imageBase64) continue;
    if (kind !== 'question' && kind !== 'answer' && kind !== 'thumb') continue;
    if (!fileId) continue;
    if (!Number.isFinite(pageIndex) || pageIndex < 0) continue;
    if (![x0, y0, x1, y1].every((v) => Number.isFinite(v))) continue;
    if (!Number.isFinite(renderDpi) || renderDpi < 36 || renderDpi > 600) continue;

    const id = crypto.randomUUID();
    const key = mathsCropKey(questionId, id, Date.now());
    toUpload.push({ key, imageBase64, contentType: contentType || 'image/png' });
    normalizedCreates.push({
      id,
      questionId,
      kind,
      fileId,
      pageIndex,
      x0,
      y0,
      x1,
      y1,
      renderDpi,
      storageKind: 'r2',
      storageKey: key,
    });
  }

  if (toUpload.length && (!env.MATHS_BUCKET && !env.MATHS_ASSETS)) {
    return jsonResponse(request, env, { ok: false, error: 'Maths storage is not configured.' }, 503);
  }

  // Upload blobs first; DB updates should never point at missing objects.
  let uploaded = 0;
  for (const item of toUpload) {
    const rawValue = String(item.imageBase64 || '');
    const match = rawValue.match(/^data:([^;]+);base64,(.+)$/);
    const base64 = match ? match[2] : rawValue;
    const metaType = match ? match[1] : '';
    if (base64.length > 12_000_000) {
      return jsonResponse(request, env, { ok: false, error: 'Upload is too large.' }, 413);
    }
    const bytes = base64ToBytes(base64);
    const putType = String(item.contentType || metaType || '').trim();

    if (env.MATHS_BUCKET && typeof env.MATHS_BUCKET.put === 'function') {
      await env.MATHS_BUCKET.put(item.key, bytes, { httpMetadata: { contentType: putType || contentTypeForKey(item.key) } });
    } else {
      await env.MATHS_ASSETS.put(item.key, bytes, { metadata: { contentType: putType || contentTypeForKey(item.key) } });
    }
    uploaded += 1;
  }

  const deleteResult = { deleted: 0 };

  const createdCropIds = [];
  for (const crop of normalizedCreates) {
    await mathsStore.createCrop(crop);
    createdCropIds.push(crop.id);
  }

  const cropResult = await mathsStore.updateCropRects(normalizedPatches);

  return jsonResponse(request, env, {
    ok: true,
    message: 'Review saved.',
    uploaded,
    deletedCrops: deleteResult.deleted,
    createdCropIds,
    updatedCrops: cropResult.updated,
    question: await mathsStore.getQuestionById(questionId),
  });
}

function parseMathsCropIdFromPath(pathname) {
  const path = String(pathname || '');
  const prefix = '/api/maths/crops/';
  if (!path.startsWith(prefix) || !path.endsWith('.png')) return null;

  const encoded = path.slice(prefix.length, -'.png'.length);
  if (!encoded || encoded.includes('/')) return null;

  try {
    const decoded = decodeURIComponent(encoded);
    return decoded ? decoded : null;
  } catch {
    return null;
  }
}

async function handleMathsCropPng(request, env, authStore, mathsStore, cropId, nowSeconds) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return methodNotAllowed(request, env, ['GET', 'HEAD']);
  }
  const isHead = request.method === 'HEAD';

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  if (!mathsStore || typeof mathsStore.getCropById !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths database is not configured.' }, 500);
  }

  const crop = await mathsStore.getCropById(cropId);
  if (!crop) {
    return jsonResponse(request, env, { ok: false, error: 'Crop not found.' }, 404);
  }

  const key = String(crop.storageKey || '').trim();
  if (!key || !key.startsWith('maths/')) {
    return jsonResponse(request, env, { ok: false, error: 'Crop is missing storage key.' }, 404);
  }

  // Prefer R2 if configured, otherwise fall back to KV.
  if (env.MATHS_BUCKET && typeof env.MATHS_BUCKET.get === 'function') {
    const object = await env.MATHS_BUCKET.get(key);
    if (!object) {
      return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
    }

    const headers = new Headers();
    headers.set('Content-Type', 'image/png');
    headers.set('Cache-Control', 'private, no-store');
    if (Number.isFinite(object.size)) {
      headers.set('Content-Length', String(object.size));
    }
    headers.set('Accept-Ranges', 'bytes');
    addCorsHeaders(request, env, headers);
    applyCommonSecurityHeaders(headers);

    return new Response(isHead ? null : object.body, {
      status: 200,
      headers,
    });
  }

  if (!env.MATHS_ASSETS || typeof env.MATHS_ASSETS.getWithMetadata !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths storage is not configured.' }, 503);
  }

  const result = await env.MATHS_ASSETS.getWithMetadata(key, { type: 'arrayBuffer' });
  if (!result || !result.value) {
    return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
  }

  const headers = new Headers();
  headers.set('Content-Type', 'image/png');
  headers.set('Cache-Control', 'private, no-store');
  headers.set('Content-Length', String(result.value.byteLength));
  headers.set('Accept-Ranges', 'bytes');
  addCorsHeaders(request, env, headers);
  applyCommonSecurityHeaders(headers);

  return new Response(isHead ? null : result.value, { status: 200, headers });
}

async function handleMathsBlob(request, env, authStore, url, nowSeconds) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return methodNotAllowed(request, env, ['GET', 'HEAD']);
  }
  const isHead = request.method === 'HEAD';

  const auth = await isApprovedMathsRequest(request, env, authStore, nowSeconds);
  if (!auth.ok) return auth.response;

  const key = String(url.searchParams.get('key') || '').trim();
  if (!key) {
    return jsonResponse(request, env, { ok: false, error: 'Missing key.' }, 400);
  }

  if (!key.startsWith('maths/')) {
    return jsonResponse(request, env, { ok: false, error: 'Invalid key.' }, 400);
  }

  // Prefer R2 if configured, otherwise fall back to KV.
  if (env.MATHS_BUCKET && typeof env.MATHS_BUCKET.get === 'function') {
    const object = await env.MATHS_BUCKET.get(key);
    if (!object) {
      return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
    }

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || contentTypeForKey(key));
    headers.set('Cache-Control', 'private, max-age=3600');
    if (Number.isFinite(object.size)) {
      headers.set('Content-Length', String(object.size));
    }
    headers.set('Accept-Ranges', 'bytes');
    addCorsHeaders(request, env, headers);
    applyCommonSecurityHeaders(headers);

    return new Response(isHead ? null : object.body, {
      status: 200,
      headers,
    });
  }

  if (!env.MATHS_ASSETS || typeof env.MATHS_ASSETS.getWithMetadata !== 'function') {
    return jsonResponse(request, env, { ok: false, error: 'Maths storage is not configured.' }, 503);
  }

  const result = await env.MATHS_ASSETS.getWithMetadata(key, { type: 'arrayBuffer' });
  if (!result || !result.value) {
    return jsonResponse(request, env, { ok: false, error: 'Not found.' }, 404);
  }

  const headers = new Headers();
  const metaType = result.metadata && typeof result.metadata.contentType === 'string' ? result.metadata.contentType : '';
  headers.set('Content-Type', metaType || contentTypeForKey(key));
  headers.set('Cache-Control', 'private, max-age=3600');
  headers.set('Content-Length', String(result.value.byteLength));
  headers.set('Accept-Ranges', 'bytes');
  addCorsHeaders(request, env, headers);
  applyCommonSecurityHeaders(headers);

  return new Response(isHead ? null : result.value, { status: 200, headers });
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

        const mathsStore = env.MATHS_STORE || (env.DB ? createMathsD1Store(env.DB) : null);

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

        if (path === '/api/admin/pending/deny-all') {
          return handleAdminDenyAllPending(request, env, store, url, nowSeconds);
        }

        if (path === '/api/admin/denied/clear') {
          return handleAdminClearDenied(request, env, store, url, nowSeconds);
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

        const cropId = parseMathsCropIdFromPath(path);
        if (cropId) {
          return handleMathsCropPng(request, env, store, mathsStore, cropId, nowSeconds);
        }

        if (path === '/api/maths/years') {
          return handleMathsYears(request, env, store, mathsStore, nowSeconds);
        }

        if (path === '/api/maths/files') {
          return handleMathsFiles(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/file') {
          return handleMathsFile(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/questions') {
          return handleMathsQuestions(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/question') {
          return handleMathsQuestion(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/datasheet') {
          return handleMathsDatasheet(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/diagnostics') {
          return handleMathsDiagnostics(request, env, store, mathsStore, nowSeconds);
        }

        if (path === '/api/maths/review/save') {
          return handleMathsReviewSave(request, env, store, mathsStore, url, nowSeconds);
        }

        if (path === '/api/maths/blob') {
          return handleMathsBlob(request, env, store, url, nowSeconds);
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
