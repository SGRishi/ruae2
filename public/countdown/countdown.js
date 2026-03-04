const IMAGE_ROTATION_INTERVAL_MS = 60_000;
const TICK_INTERVAL_MS = 250;
const OWNER_TOKEN_KEY = 'countdownOwnerTokens:v2';
const CLASSIC_FM_STREAM = 'https://ice-the.musicradio.com/ClassicFMMP3';
const TEST_CONFIG = typeof window !== 'undefined' ? window.__COUNTDOWN_TEST__ || null : null;

const BACKGROUND_IMAGES = [
  'https://images.unsplash.com/photo-1470770841072-f978cf4d019e?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1469474968028-56623f02e42e?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1472396961693-142e6e269027?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1439066615861-d1af74d74000?auto=format&fit=crop&w=2400&q=80',
  'https://images.unsplash.com/photo-1482192596544-9eb780fc7f66?auto=format&fit=crop&w=2400&q=80',
];

const backgroundEl = document.querySelector('[data-testid="bg-image"]');
const formEl = document.querySelector('[data-testid="timer-form"]');
const statusEl = document.querySelector('[data-testid="countdown-status"]');
const errorEl = document.querySelector('[data-testid="timer-error"]');
const durationInputEl = document.querySelector('[data-testid="duration-minutes"]');
const deadlineInputEl = document.querySelector('[data-testid="deadline-input"]');
const visibilityToggleEl = document.querySelector('[data-testid="visibility-toggle"]');
const setupPasswordInputEl = document.querySelector('[data-testid="setup-password-input"]');
const makePublicButtonEl = document.querySelector('[data-testid="make-public-button"]');
const publicUrlEl = document.querySelector('[data-testid="public-url"]');
const privateUrlEl = document.querySelector('[data-testid="private-url"]');
const embedUrlEl = document.querySelector('[data-testid="embed-url"]');
const passwordGateEl = document.querySelector('[data-testid="password-gate"]');
const passwordInputEl = document.querySelector('[data-testid="password-input"]');
const passwordSubmitEl = document.querySelector('[data-testid="password-submit"]');
const passwordMessageEl = document.querySelector('[data-testid="password-message"]');
const countdownDisplayEl = document.querySelector('[data-testid="countdown-display"]');
const daysEl = document.querySelector('[data-testid="countdown-days"]');
const hoursEl = document.querySelector('[data-testid="countdown-hours"]');
const minutesEl = document.querySelector('[data-testid="countdown-minutes"]');
const secondsEl = document.querySelector('[data-testid="countdown-seconds"]');
const progressBarEl = document.querySelector('[data-testid="progress-bar"]');
const progressPercentEl = document.querySelector('[data-testid="progress-percent"]');
const audioEl = document.querySelector('[data-testid="audio-element"]');
const musicPlayEl = document.querySelector('[data-testid="music-play"]');
const musicPauseEl = document.querySelector('[data-testid="music-pause"]');
const audioStatusEl = document.querySelector('[data-testid="audio-status"]');
const robotsMetaEl = document.querySelector('meta[name="robots"]');

let activeTimer = null;
let ownerToken = '';
let embedMode = false;
let currentBackgroundIndex = 0;
let serverTimeOffsetMs = 0;
let passwordGateVisible = false;
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

function normalizeToken(value) {
  const token = String(value || '').trim();
  return /^[A-Za-z0-9_-]{16,200}$/.test(token) ? token : '';
}

function normalizeTimerId(value) {
  const id = String(value || '').trim();
  return /^[A-Za-z0-9_-]{6,120}$/.test(id) ? id : '';
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
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

function getRouteTimerId() {
  const parts = window.location.pathname.split('/').filter(Boolean);
  if (!parts.length || parts[0] !== 'countdown') return '';
  return normalizeTimerId(parts[1]);
}

function getRouteToken() {
  return normalizeToken(new URL(window.location.href).searchParams.get('token'));
}

function isEmbedMode() {
  return new URL(window.location.href).searchParams.get('embed') === '1';
}

function maybeRestoreFallbackRoute() {
  const url = new URL(window.location.href);
  const path = String(url.pathname || '');
  const isFallbackPath = path === '/countdown/index.html' || path === '/countdown/' || path === '/countdown';
  if (!isFallbackPath) return;

  const rawRoute = String(url.searchParams.get('r') || '').trim();
  if (!rawRoute || !rawRoute.startsWith('/countdown/')) return;

  window.history.replaceState(null, '', rawRoute);
}

function setRobots(isPublic) {
  if (!robotsMetaEl) return;
  robotsMetaEl.setAttribute('content', isPublic ? 'index,follow' : 'noindex,nofollow');
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
  const id = normalizeTimerId(timerId);
  if (!id) return '';
  const store = readOwnerTokenStore();
  return normalizeToken(store[id]);
}

function rememberOwnerToken(timerId, token) {
  const id = normalizeTimerId(timerId);
  const normalizedToken = normalizeToken(token);
  if (!id || !normalizedToken) return;
  const store = readOwnerTokenStore();
  store[id] = normalizedToken;
  writeOwnerTokenStore(store);
}

function setError(message) {
  if (!errorEl) return;
  const text = String(message || '').trim();
  if (!text) {
    errorEl.hidden = true;
    errorEl.textContent = '';
    return;
  }
  errorEl.hidden = false;
  errorEl.textContent = text;
}

function setStatus(message) {
  if (!statusEl) return;
  statusEl.textContent = String(message || '').trim();
}

function setPasswordMessage(message, isError = false) {
  if (!passwordMessageEl) return;
  passwordMessageEl.textContent = String(message || '').trim();
  passwordMessageEl.style.color = isError ? '#ffd5dc' : '';
}

function showPasswordGate(show) {
  passwordGateVisible = Boolean(show);
  if (!passwordGateEl) return;
  passwordGateEl.hidden = !passwordGateVisible;
}

function timerPath(timerId) {
  return `/countdown/${encodeURIComponent(timerId)}`;
}

function toPublicUrl(timerId) {
  return `${window.location.origin}${timerPath(timerId)}`;
}

function toPrivateUrl(timerId) {
  const url = new URL(toPublicUrl(timerId));
  url.searchParams.set('private', '1');
  return url.toString();
}

function toEmbedUrl(timer) {
  if (!timer || !timer.id) return '';
  const url = new URL(timer.isPublic ? toPublicUrl(timer.id) : toPrivateUrl(timer.id));
  url.searchParams.set('embed', '1');
  return url.toString();
}

function updateUrlFields(timerOrId) {
  let timerId = '';
  let timer = null;
  if (typeof timerOrId === 'string') {
    timerId = normalizeTimerId(timerOrId);
  } else if (timerOrId && typeof timerOrId === 'object') {
    timer = timerOrId;
    timerId = normalizeTimerId(timer.id);
  }

  if (!timerId) {
    if (publicUrlEl) publicUrlEl.value = '';
    if (privateUrlEl) privateUrlEl.value = '';
    if (embedUrlEl) embedUrlEl.value = '';
    return;
  }

  const publicUrl = toPublicUrl(timerId);
  const privateUrl = toPrivateUrl(timerId);
  const embedUrl = timer ? toEmbedUrl(timer) : `${publicUrl}?embed=1`;

  if (publicUrlEl) publicUrlEl.value = publicUrl;
  if (privateUrlEl) privateUrlEl.value = privateUrl;
  if (embedUrlEl) embedUrlEl.value = embedUrl;
}

function normalizeTimer(timer) {
  if (!timer || typeof timer !== 'object') return null;
  const id = normalizeTimerId(timer.id);
  const startAtMs = Number(timer.startAtMs ?? timer.createdAtMs);
  const endAtMs = Number(timer.endAtMs ?? timer.deadlineMs);
  if (!id || !Number.isFinite(startAtMs) || !Number.isFinite(endAtMs)) return null;
  return {
    id,
    startAtMs,
    endAtMs,
    isPublic: Boolean(timer.isPublic),
    canEdit: Boolean(timer.canEdit),
    createdAtMs: Number(timer.createdAtMs || startAtMs),
    updatedAtMs: Number(timer.updatedAtMs || startAtMs),
  };
}

function buildHistoryUrl(timer) {
  if (!timer || !timer.id) return '/countdown/';
  const url = new URL(`${window.location.origin}${timerPath(timer.id)}`);
  if (!timer.isPublic) {
    url.searchParams.set('private', '1');
  }
  if (embedMode) {
    url.searchParams.set('embed', '1');
  }
  return `${url.pathname}${url.search}`;
}

function syncVisibilityControls() {
  if (visibilityToggleEl && activeTimer) {
    visibilityToggleEl.checked = Boolean(activeTimer.isPublic);
  }

  if (!makePublicButtonEl) return;
  const canEdit = Boolean(activeTimer && ownerToken);
  makePublicButtonEl.disabled = !canEdit;
  if (!canEdit) {
    makePublicButtonEl.textContent = 'Make public';
    return;
  }

  makePublicButtonEl.textContent = activeTimer.isPublic ? 'Make private' : 'Make public';
}

function renderCountdown() {
  if (!countdownDisplayEl || !daysEl || !hoursEl || !minutesEl || !secondsEl) return;

  if (!activeTimer) {
    daysEl.textContent = '00';
    hoursEl.textContent = '00';
    minutesEl.textContent = '00';
    secondsEl.textContent = '00';
    if (progressBarEl) {
      progressBarEl.style.width = '100%';
      progressBarEl.setAttribute('aria-valuenow', '100');
    }
    if (progressPercentEl) progressPercentEl.textContent = '100%';
    return;
  }

  const now = getNowMs();
  const remainingMs = Math.max(0, activeTimer.endAtMs - now);
  const totalSeconds = Math.floor(remainingMs / 1_000);
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;

  daysEl.textContent = String(days).padStart(2, '0');
  hoursEl.textContent = String(hours).padStart(2, '0');
  minutesEl.textContent = String(minutes).padStart(2, '0');
  secondsEl.textContent = String(seconds).padStart(2, '0');

  const rangeMs = Math.max(1, activeTimer.endAtMs - activeTimer.startAtMs);
  const ratio = clamp((activeTimer.endAtMs - now) / rangeMs, 0, 1);
  const percent = Math.round(ratio * 1_000) / 10;

  if (progressBarEl) {
    progressBarEl.style.width = `${ratio * 100}%`;
    progressBarEl.setAttribute('aria-valuenow', String(Math.round(ratio * 100)));
  }
  if (progressPercentEl) {
    progressPercentEl.textContent = `${percent.toFixed(1)}%`;
  }

  if (remainingMs <= 0) {
    setStatus('Countdown complete.');
  } else if (activeTimer.isPublic) {
    setStatus('Public countdown is live.');
  } else if (passwordGateVisible) {
    setStatus('Private countdown. Enter the password to continue.');
  } else {
    setStatus('Private countdown unlocked.');
  }
}

function setBackground(index) {
  if (!backgroundEl || !BACKGROUND_IMAGES.length) return;
  const safeIndex = ((index % BACKGROUND_IMAGES.length) + BACKGROUND_IMAGES.length) % BACKGROUND_IMAGES.length;
  const imageUrl = BACKGROUND_IMAGES[safeIndex];
  currentBackgroundIndex = safeIndex;
  backgroundEl.style.backgroundImage = `url("${imageUrl}")`;
  backgroundEl.dataset.backgroundUrl = imageUrl;
}

function rotateBackground() {
  setBackground(currentBackgroundIndex + 1);
}

function messageFromError(data, fallback) {
  const message = String(data?.error || '').trim();
  return message || fallback;
}

function coercePositiveInteger(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

function parseDeadlineInput(value) {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return parsed;
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

async function syncTimeFromServer() {
  try {
    const { response, data } = await apiRequest('/api/time');
    if (response.ok && Number.isFinite(Number(data?.nowMs))) {
      syncServerClock(data.nowMs);
    }
  } catch {
    // Keep local clock when server time endpoint is unavailable.
  }
}

function resetForNoTimer() {
  activeTimer = null;
  ownerToken = '';
  showPasswordGate(false);
  setError('');
  setRobots(false);
  updateUrlFields('');
  syncVisibilityControls();
  renderCountdown();
}

function applyTimer(timer, options = {}) {
  const normalizedTimer = normalizeTimer(timer);
  if (!normalizedTimer) {
    resetForNoTimer();
    return;
  }

  activeTimer = normalizedTimer;

  const tokenCandidate = Object.prototype.hasOwnProperty.call(options, 'token') ? options.token : ownerToken;
  ownerToken = normalizeToken(tokenCandidate);

  if (ownerToken) {
    rememberOwnerToken(activeTimer.id, ownerToken);
  }

  showPasswordGate(false);
  setPasswordMessage('');
  setRobots(activeTimer.isPublic);
  updateUrlFields(activeTimer);
  syncVisibilityControls();
  renderCountdown();

  if (options.updateHistory !== false) {
    const method = options.replaceHistory ? 'replaceState' : 'pushState';
    window.history[method](null, '', buildHistoryUrl(activeTimer));
  }
}

async function initializeFromRoute() {
  const routeTimerId = getRouteTimerId();
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
    setError('Unable to load this countdown right now.');
    updateUrlFields(routeTimerId);
    return;
  }

  const { response, data } = result;
  if (!response.ok) {
    updateUrlFields(routeTimerId);
    setRobots(false);

    if (response.status === 403 && data?.requiresPassword) {
      showPasswordGate(true);
      setPasswordMessage('Password required to access this countdown.');
      setError('');
      setStatus('Private countdown. Enter the password to continue.');
      renderCountdown();
      return;
    }

    setError(messageFromError(data, 'That countdown link is invalid.'));
    showPasswordGate(false);
    return;
  }

  syncServerClock(data?.serverNowMs);

  const timer = normalizeTimer(data?.timer);
  if (!timer) {
    setError('That countdown link is invalid.');
    return;
  }

  applyTimer(timer, {
    replaceHistory: true,
    token: timer.canEdit ? token : '',
  });
  setError('');
}

async function unlockPrivateCountdown() {
  const timerId = getRouteTimerId();
  if (!timerId) {
    setPasswordMessage('Invalid countdown URL.', true);
    return;
  }

  const password = String(passwordInputEl?.value || '');
  if (!password) {
    setPasswordMessage('Enter the password first.', true);
    return;
  }

  let result;
  try {
    result = await apiRequest('/api/countdown/access', {
      method: 'POST',
      json: {
        id: timerId,
        password,
      },
    });
  } catch {
    setPasswordMessage('Unable to verify password right now.', true);
    return;
  }

  const { response, data } = result;
  if (!response.ok) {
    setPasswordMessage(messageFromError(data, 'Access denied.'), true);
    return;
  }

  syncServerClock(data?.serverNowMs);
  const timer = normalizeTimer(data?.timer);
  if (!timer) {
    setPasswordMessage('Access was granted, but timer data was invalid.', true);
    return;
  }

  applyTimer(timer, {
    replaceHistory: true,
    token: ownerToken,
  });
  if (passwordInputEl) passwordInputEl.value = '';
  setPasswordMessage('Access granted.');
  setError('');
}

async function onFormSubmit(event) {
  event.preventDefault();
  setError('');

  const deadlineFromInput = parseDeadlineInput(deadlineInputEl?.value || '');
  const durationMinutes = coercePositiveInteger(durationInputEl?.value || '');

  let deadlineMs = null;
  if (deadlineFromInput && deadlineFromInput > getNowMs()) {
    deadlineMs = deadlineFromInput;
  } else if (durationMinutes) {
    deadlineMs = getNowMs() + durationMinutes * 60_000;
  }

  if (!deadlineMs || deadlineMs <= getNowMs()) {
    setError('Enter a future date/time or a valid duration in minutes.');
    return;
  }

  const isPublic = Boolean(visibilityToggleEl?.checked);
  const privatePassword = String(setupPasswordInputEl?.value || '').trim();

  const payload = {
    isPublic,
    deadlineMs,
  };

  if (!isPublic) {
    payload.password = privatePassword;
  }

  let result;
  try {
    result = await apiRequest('/api/countdown/timer', {
      method: 'POST',
      json: payload,
    });
  } catch {
    setError('Unable to create countdown right now.');
    return;
  }

  const { response, data } = result;
  if (!response.ok || !data?.timer || !data?.ownerToken) {
    setError(messageFromError(data, 'Unable to create countdown right now.'));
    return;
  }

  syncServerClock(data?.serverNowMs);
  applyTimer(data.timer, {
    replaceHistory: false,
    token: data.ownerToken,
  });
  setStatus('Countdown created.');
}

async function onMakePublicButtonClick() {
  if (!activeTimer || !ownerToken) return;

  const nextIsPublic = !activeTimer.isPublic;
  const privatePassword = String(setupPasswordInputEl?.value || '').trim();

  const payload = {
    id: activeTimer.id,
    token: ownerToken,
    isPublic: nextIsPublic,
  };

  if (!nextIsPublic) {
    payload.password = privatePassword;
  }

  let result;
  try {
    result = await apiRequest('/api/countdown/timer', {
      method: 'PATCH',
      json: payload,
    });
  } catch {
    setError('Unable to update countdown visibility right now.');
    return;
  }

  const { response, data } = result;
  if (!response.ok || !data?.timer) {
    setError(messageFromError(data, 'Unable to update countdown visibility right now.'));
    syncVisibilityControls();
    return;
  }

  syncServerClock(data?.serverNowMs);
  applyTimer(data.timer, {
    replaceHistory: true,
    token: ownerToken,
  });
  setStatus(nextIsPublic ? 'Countdown is now public.' : 'Countdown is now private.');
  setError('');
}

async function playAmbient() {
  if (!audioEl || !audioStatusEl) return;
  try {
    await audioEl.play();
    audioStatusEl.textContent = 'Ambient playing.';
  } catch {
    audioStatusEl.textContent = 'Playback blocked by browser. Press play again.';
  }
}

function pauseAmbient() {
  if (!audioEl || !audioStatusEl) return;
  audioEl.pause();
  audioStatusEl.textContent = 'Ambient paused.';
}

function setupEvents() {
  formEl?.addEventListener('submit', onFormSubmit);
  makePublicButtonEl?.addEventListener('click', onMakePublicButtonClick);
  passwordSubmitEl?.addEventListener('click', unlockPrivateCountdown);
  passwordInputEl?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    unlockPrivateCountdown();
  });
  musicPlayEl?.addEventListener('click', playAmbient);
  musicPauseEl?.addEventListener('click', pauseAmbient);
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
    renderCountdown();
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
      renderCountdown();
    },
    nextBackground() {
      rotateBackground();
      return currentBackgroundIndex;
    },
    nowMs() {
      return getNowMs();
    },
    backgroundUrl() {
      return String(backgroundEl?.dataset?.backgroundUrl || '');
    },
  };
}

function initializeAudio() {
  if (!audioEl) return;
  audioEl.src = CLASSIC_FM_STREAM;
}

async function init() {
  maybeRestoreFallbackRoute();
  embedMode = isEmbedMode();
  if (embedMode) {
    document.body.classList.add('countdown-embed');
  }

  setBackground(currentBackgroundIndex);
  updateUrlFields('');
  syncVisibilityControls();
  initializeAudio();
  setupTestApi();
  setupEvents();
  await syncTimeFromServer();
  await initializeFromRoute();
  setupIntervals();
}

init();
