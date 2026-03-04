const IMAGE_ROTATION_INTERVAL_MS = 60_000;
const TICK_INTERVAL_MS = 1_000;
const OWNER_TOKEN_KEY = 'countdownOwnerTokens:v1';
const TEST_CONFIG = typeof window !== 'undefined' ? window.__COUNTDOWN_TEST__ || null : null;

const backgroundEl = document.querySelector('[data-testid="background"]');
const clockEl = document.querySelector('[data-testid="countdown-clock"]');
const statusEl = document.querySelector('[data-testid="countdown-status"]');
const formEl = document.querySelector('[data-testid="timer-form"]');
const durationInputEl = document.querySelector('[data-testid="duration-minutes"]');
const deadlineInputEl = document.querySelector('[data-testid="deadline-input"]');
const privacyToggleEl = document.querySelector('[data-testid="privacy-toggle"]');
const shareUrlEl = document.querySelector('[data-testid="share-url"]');
const copyShareUrlEl = document.querySelector('[data-testid="copy-share-url"]');
const embedCodeEl = document.querySelector('[data-testid="embed-code"]');
const copyEmbedCodeEl = document.querySelector('[data-testid="copy-embed-code"]');
const errorEl = document.querySelector('[data-testid="timer-error"]');
const audioEl = document.querySelector('[data-testid="audio-player"]');
const audioPlayEl = document.querySelector('[data-testid="audio-play-button"]');
const audioStatusEl = document.getElementById('audioStatus');
const robotsMetaEl = document.querySelector('meta[name="robots"]');

const BACKGROUND_IMAGES = [
  'https://images.unsplash.com/photo-1470770841072-f978cf4d019e?auto=format&fit=crop&w=1800&q=80',
  'https://images.unsplash.com/photo-1469474968028-56623f02e42e?auto=format&fit=crop&w=1800&q=80',
  'https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=1800&q=80',
];

let activeTimer = null;
let ownerToken = '';
let currentBackgroundIndex = 0;
let embedMode = false;
let serverTimeOffsetMs = 0;
let testNowMs =
  TEST_CONFIG && Number.isFinite(Number(TEST_CONFIG.nowMs)) ? Number(TEST_CONFIG.nowMs) : Date.now();

function normalizeBaseUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
}

function resolveApiBase() {
  const hasConfig =
    Boolean(window.__APP_CONFIG__) && Object.prototype.hasOwnProperty.call(window.__APP_CONFIG__, 'API_BASE');
  if (hasConfig) {
    return normalizeBaseUrl(window.__APP_CONFIG__.API_BASE);
  }

  const host = String(window.location?.hostname || '').toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return '';
  }

  return 'https://api.rishisubjects.co.uk';
}

const API_BASE = resolveApiBase();

function toApiUrl(path) {
  const normalizedPath = String(path || '').startsWith('/') ? path : `/${path}`;
  return `${API_BASE}${normalizedPath}`;
}

function maybeRestoreFallbackRoute() {
  const url = new URL(window.location.href);
  const path = String(url.pathname || '');
  const isFallbackPath = path === '/countdown/index.html' || path === '/countdown/' || path === '/countdown';
  if (!isFallbackPath) return;

  const rawRoute = String(url.searchParams.get('r') || '').trim();
  if (!rawRoute || !rawRoute.startsWith('/countdown/')) return;

  // When static hosting falls back unknown paths to homepage, route users back
  // through countdown and restore the original tokenized URL here.
  window.history.replaceState(null, '', rawRoute);
}

function isEmbedMode() {
  return new URL(window.location.href).searchParams.get('embed') === '1';
}

function getClientNowMs() {
  return TEST_CONFIG ? testNowMs : Date.now();
}

function syncServerClock(serverNowMs) {
  const parsed = Number(serverNowMs);
  if (!Number.isFinite(parsed)) return;
  serverTimeOffsetMs = parsed - getClientNowMs();
}

function getNowMs() {
  return getClientNowMs() + serverTimeOffsetMs;
}

function normalizeToken(value) {
  const token = String(value || '').trim();
  return /^[A-Za-z0-9_-]{16,200}$/.test(token) ? token : '';
}

function readOwnerTokenStore() {
  try {
    const raw = localStorage.getItem(OWNER_TOKEN_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function writeOwnerTokenStore(store) {
  localStorage.setItem(OWNER_TOKEN_KEY, JSON.stringify(store));
}

function getStoredOwnerToken(timerId) {
  const id = String(timerId || '').trim();
  if (!id) return '';
  const store = readOwnerTokenStore();
  return normalizeToken(store[id]);
}

function rememberOwnerToken(timerId, token) {
  const id = String(timerId || '').trim();
  const normalizedToken = normalizeToken(token);
  if (!id || !normalizedToken) return;
  const store = readOwnerTokenStore();
  store[id] = normalizedToken;
  writeOwnerTokenStore(store);
}

function toDurationString(totalMs) {
  const clamped = Math.max(0, totalMs);
  const totalSeconds = Math.floor(clamped / 1_000);
  const hours = Math.floor(totalSeconds / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, '0')).join(':');
}

function setError(message) {
  if (!errorEl) return;
  if (!message) {
    errorEl.hidden = true;
    errorEl.textContent = '';
    return;
  }
  errorEl.hidden = false;
  errorEl.textContent = message;
}

function getRouteTimerId() {
  const parts = window.location.pathname.split('/').filter(Boolean);
  if (!parts.length || parts[0] !== 'countdown') return '';
  return parts[1] ? decodeURIComponent(parts[1]) : '';
}

function getRouteToken() {
  return normalizeToken(new URL(window.location.href).searchParams.get('token'));
}

function setRobots(isPublic) {
  if (!robotsMetaEl) return;
  robotsMetaEl.setAttribute('content', isPublic ? 'index,follow' : 'noindex,nofollow');
}

function buildBaseShareUrl(timer) {
  if (!timer) return `${window.location.origin}/countdown/`;
  return `${window.location.origin}/countdown/${encodeURIComponent(timer.id)}`;
}

function buildShareUrl(timer, token = '') {
  if (!timer) return buildBaseShareUrl(null);
  const base = buildBaseShareUrl(timer);
  if (!timer.isPublic) {
    const privateToken = normalizeToken(token);
    if (privateToken) {
      return `${base}?token=${encodeURIComponent(privateToken)}`;
    }
  }
  return base;
}

function buildEmbedUrl(timer, token = '') {
  const url = new URL(buildShareUrl(timer, token));
  url.searchParams.set('embed', '1');
  return url.toString();
}

function buildEmbedCode(timer, token = '') {
  const src = buildEmbedUrl(timer, token);
  return `<iframe src="${src}" title="Countdown timer" width="100%" height="240" style="border:0;max-width:720px;overflow:hidden;" loading="lazy" allow="autoplay"></iframe>`;
}

function updateShareUi(timer) {
  const publicShareUrl = buildShareUrl(timer, ownerToken);

  if (shareUrlEl) {
    shareUrlEl.value = publicShareUrl;
  }

  if (embedCodeEl) {
    embedCodeEl.value = buildEmbedCode(timer, ownerToken);
  }
}

function updateCountdownText() {
  if (!clockEl || !statusEl) return;
  if (!activeTimer) {
    clockEl.textContent = '00:00:00';
    statusEl.textContent = 'Set a timer to begin.';
    return;
  }

  const remainingMs = Number(activeTimer.deadlineMs) - getNowMs();
  if (remainingMs <= 0) {
    clockEl.textContent = '00:00:00';
    statusEl.textContent = 'Timer complete.';
    return;
  }

  clockEl.textContent = toDurationString(remainingMs);

  if (activeTimer.isPublic) {
    statusEl.textContent = ownerToken
      ? 'Public timer. Anyone with the link can view it.'
      : 'Public timer. View-only mode.';
    return;
  }

  statusEl.textContent = 'Private timer. Exact token URL required.';
}

function setBackground(index) {
  if (!backgroundEl) return;
  const imageUrl = BACKGROUND_IMAGES[index % BACKGROUND_IMAGES.length];
  backgroundEl.style.backgroundImage = `url("${imageUrl}")`;
}

function rotateBackground() {
  currentBackgroundIndex = (currentBackgroundIndex + 1) % BACKGROUND_IMAGES.length;
  setBackground(currentBackgroundIndex);
}

function coercePositiveInteger(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (n <= 0) return null;
  return Math.floor(n);
}

function parseDeadlineInput(value) {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return parsed;
}

function syncPrivacyToggle() {
  if (!privacyToggleEl) return;
  if (activeTimer) {
    privacyToggleEl.checked = Boolean(activeTimer.isPublic);
  }
  privacyToggleEl.disabled = embedMode || Boolean(activeTimer && !ownerToken);
}

function buildPageUrl(timer, replaceForEmbed = false) {
  const url = new URL(buildShareUrl(timer, ownerToken));
  if (embedMode || replaceForEmbed) {
    url.searchParams.set('embed', '1');
  }
  return `${url.pathname}${url.search}`;
}

function applyTimer(timer, options = {}) {
  activeTimer = timer;

  const tokenCandidate = Object.prototype.hasOwnProperty.call(options, 'token') ? options.token : ownerToken;
  const normalizedToken = normalizeToken(tokenCandidate);
  ownerToken = normalizedToken;

  if (activeTimer && ownerToken) {
    rememberOwnerToken(activeTimer.id, ownerToken);
  }

  setRobots(Boolean(activeTimer?.isPublic));
  syncPrivacyToggle();
  updateShareUi(activeTimer);
  updateCountdownText();

  if (!activeTimer) return;
  const method = options.replaceHistory ? 'replaceState' : 'pushState';
  window.history[method](null, '', buildPageUrl(activeTimer));
}

function resetForNoTimer() {
  activeTimer = null;
  ownerToken = '';
  setRobots(false);
  syncPrivacyToggle();
  updateShareUi(null);
  updateCountdownText();
}

async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.json !== undefined) {
    headers.set('Content-Type', 'application/json; charset=utf-8');
  }

  const response = await fetch(toApiUrl(path), {
    method: options.method || 'GET',
    headers,
    body: options.json !== undefined ? JSON.stringify(options.json) : options.body,
    credentials: 'include',
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }

  return { response, data };
}

function messageFromError(data, fallback) {
  const message = String(data?.error || '').trim();
  return message || fallback;
}

async function initializeFromRoute() {
  const routeTimerId = String(getRouteTimerId() || '').trim();
  if (!routeTimerId) {
    resetForNoTimer();
    return;
  }

  let token = getRouteToken();
  if (!token) {
    token = getStoredOwnerToken(routeTimerId);
  }

  const query = new URLSearchParams({ id: routeTimerId });
  if (token) query.set('token', token);

  let result;
  try {
    result = await apiRequest(`/api/countdown/timer?${query.toString()}`);
  } catch {
    setError('Unable to load this timer right now.');
    resetForNoTimer();
    return;
  }

  const { response, data } = result;

  if (!response.ok) {
    setError(
      messageFromError(
        data,
        response.status === 403
          ? 'This timer is private. Use the exact private URL token.'
          : 'That timer link is invalid. Create a new countdown.'
      )
    );

    if (response.status === 403) {
      resetForNoTimer();
      setRobots(false);
      if (shareUrlEl) shareUrlEl.value = buildBaseShareUrl({ id: routeTimerId });
      if (embedCodeEl) embedCodeEl.value = '';
      return;
    }

    resetForNoTimer();
    return;
  }

  const timer = data?.timer;
  if (!timer || !timer.id) {
    setError('That timer link is invalid. Create a new countdown.');
    resetForNoTimer();
    return;
  }
  syncServerClock(data?.serverNowMs);

  const canEdit = Boolean(timer.canEdit);
  const effectiveToken = canEdit ? token : '';
  if (effectiveToken) rememberOwnerToken(timer.id, effectiveToken);

  applyTimer(timer, {
    replaceHistory: true,
    token: effectiveToken,
  });

  if (data?.expired) {
    setError('That timer has expired. Create a fresh countdown.');
  } else {
    setError('');
  }
}

async function copyShareUrl() {
  if (!shareUrlEl?.value) return;
  try {
    await navigator.clipboard.writeText(shareUrlEl.value);
    statusEl.textContent = 'Share URL copied.';
  } catch {
    statusEl.textContent = 'Copy failed. Select and copy the URL manually.';
  }
}

async function copyEmbedCode() {
  if (!embedCodeEl?.value) return;
  try {
    await navigator.clipboard.writeText(embedCodeEl.value);
    statusEl.textContent = 'Embed code copied.';
  } catch {
    statusEl.textContent = 'Copy failed. Select and copy the embed code manually.';
  }
}

async function toggleAudio() {
  if (!audioEl || !audioPlayEl || !audioStatusEl) return;

  if (!audioEl.paused) {
    audioEl.pause();
    audioPlayEl.textContent = 'Play ambience';
    audioPlayEl.dataset.state = 'paused';
    audioStatusEl.textContent = 'Ambience paused.';
    return;
  }

  audioPlayEl.dataset.state = 'requested';
  try {
    await audioEl.play();
    audioPlayEl.textContent = 'Pause ambience';
    audioPlayEl.dataset.state = 'playing';
    audioStatusEl.textContent = 'Ambience playing.';
  } catch {
    audioPlayEl.dataset.state = 'blocked';
    audioStatusEl.textContent = 'Playback blocked. Click again to retry.';
  }
}

async function onFormSubmit(event) {
  event.preventDefault();
  setError('');

  const durationMinutes = coercePositiveInteger(durationInputEl?.value || '');
  const deadlineFromInput = parseDeadlineInput(deadlineInputEl?.value || '');

  if (!durationMinutes && (!deadlineFromInput || deadlineFromInput <= getNowMs())) {
    setError('Enter a future deadline or a positive duration in minutes.');
    return;
  }

  const payload = {
    isPublic: Boolean(privacyToggleEl?.checked),
  };

  if (durationMinutes) {
    payload.durationMinutes = durationMinutes;
  } else {
    payload.deadlineMs = deadlineFromInput;
  }

  let result;
  try {
    result = await apiRequest('/api/countdown/timer', {
      method: 'POST',
      json: payload,
    });
  } catch {
    setError('Unable to create timer right now.');
    return;
  }

  const { response, data } = result;
  if (!response.ok || !data?.timer || !data?.ownerToken) {
    setError(messageFromError(data, 'Unable to create timer right now.'));
    return;
  }
  syncServerClock(data?.serverNowMs);

  applyTimer(data.timer, {
    replaceHistory: false,
    token: data.ownerToken,
  });
  setError('');
}

async function onPrivacyToggle() {
  if (!activeTimer || !ownerToken) {
    syncPrivacyToggle();
    return;
  }

  const nextIsPublic = Boolean(privacyToggleEl?.checked);

  let result;
  try {
    result = await apiRequest('/api/countdown/timer', {
      method: 'PATCH',
      json: {
        id: activeTimer.id,
        token: ownerToken,
        isPublic: nextIsPublic,
      },
    });
  } catch {
    syncPrivacyToggle();
    setError('Unable to update privacy right now.');
    return;
  }

  const { response, data } = result;
  if (!response.ok || !data?.timer) {
    syncPrivacyToggle();
    setError(messageFromError(data, 'Unable to update privacy right now.'));
    return;
  }
  syncServerClock(data?.serverNowMs);

  applyTimer(data.timer, {
    replaceHistory: true,
    token: ownerToken,
  });
  setError('');
}

function setupEvents() {
  formEl?.addEventListener('submit', onFormSubmit);
  privacyToggleEl?.addEventListener('change', onPrivacyToggle);
  copyShareUrlEl?.addEventListener('click', copyShareUrl);
  copyEmbedCodeEl?.addEventListener('click', copyEmbedCode);
  audioPlayEl?.addEventListener('click', toggleAudio);
}

function setupIntervals() {
  const tickIntervalMs =
    TEST_CONFIG && Number.isFinite(Number(TEST_CONFIG.tickIntervalMs))
      ? Number(TEST_CONFIG.tickIntervalMs)
      : TICK_INTERVAL_MS;
  const tickStepMs =
    TEST_CONFIG && Number.isFinite(Number(TEST_CONFIG.tickStepMs)) ? Number(TEST_CONFIG.tickStepMs) : 1_000;
  const imageIntervalMs =
    TEST_CONFIG && Number.isFinite(Number(TEST_CONFIG.backgroundIntervalMs))
      ? Number(TEST_CONFIG.backgroundIntervalMs)
      : IMAGE_ROTATION_INTERVAL_MS;

  setInterval(() => {
    if (TEST_CONFIG) {
      testNowMs += tickStepMs;
    }
    updateCountdownText();
  }, tickIntervalMs);

  setInterval(() => {
    rotateBackground();
  }, imageIntervalMs);
}

function setupTestApi() {
  if (!TEST_CONFIG) return;
  window.__COUNTDOWN_TEST_API__ = {
    advance(ms) {
      const delta = Number(ms);
      if (!Number.isFinite(delta)) return;
      testNowMs += delta;
      updateCountdownText();
    },
    nowMs() {
      return getNowMs();
    },
  };
}

function init() {
  maybeRestoreFallbackRoute();
  embedMode = isEmbedMode();
  if (embedMode) {
    document.body.classList.add('countdown-embed');
  }

  setBackground(currentBackgroundIndex);
  updateShareUi(null);
  setupTestApi();
  setupEvents();

  initializeFromRoute().then(() => {
    setupIntervals();
  });
}

init();
