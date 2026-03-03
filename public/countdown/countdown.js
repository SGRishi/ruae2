const STORAGE_KEY = 'countdownTimers:v1';
const IMAGE_ROTATION_INTERVAL_MS = 60_000;
const TICK_INTERVAL_MS = 1_000;
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
let currentBackgroundIndex = 0;
let testNowMs =
  TEST_CONFIG && Number.isFinite(Number(TEST_CONFIG.nowMs)) ? Number(TEST_CONFIG.nowMs) : Date.now();

function getNowMs() {
  return TEST_CONFIG ? testNowMs : Date.now();
}

function parseTimerStore() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function writeTimerStore(store) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

function randomId(prefix) {
  const rand = Math.random().toString(36).slice(2, 11);
  return `${prefix}_${rand}`;
}

function generateTimerId() {
  return randomId('tmr');
}

function generateTimerToken() {
  return randomId('tok');
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
  if (!parts.length || parts[0] !== 'countdown') return null;
  return parts[1] ? decodeURIComponent(parts[1]) : null;
}

function setRobots(isPublic) {
  if (!robotsMetaEl) return;
  robotsMetaEl.setAttribute('content', isPublic ? 'index,follow' : 'noindex,nofollow');
}

function buildShareUrl(timer) {
  if (!timer) return `${window.location.origin}/countdown/`;
  const base = `${window.location.origin}/countdown/${encodeURIComponent(timer.id)}`;
  if (timer.isPublic) return base;
  return `${base}?token=${encodeURIComponent(timer.token)}`;
}

function updateShareUi(timer) {
  if (!shareUrlEl) return;
  shareUrlEl.value = buildShareUrl(timer);
}

function updateCountdownText() {
  if (!clockEl || !statusEl) return;
  if (!activeTimer) {
    clockEl.textContent = '00:00:00';
    statusEl.textContent = 'Set a timer to begin.';
    return;
  }

  const remainingMs = activeTimer.deadlineMs - getNowMs();
  if (remainingMs <= 0) {
    clockEl.textContent = '00:00:00';
    statusEl.textContent = 'Timer complete.';
    return;
  }

  clockEl.textContent = toDurationString(remainingMs);
  statusEl.textContent = activeTimer.isPublic
    ? 'Public timer. Anyone with the link can view it.'
    : 'Private timer. Exact token URL required.';
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

function syncPrivacyToggle(isPublic) {
  if (!privacyToggleEl) return;
  privacyToggleEl.checked = Boolean(isPublic);
}

function saveTimer(timer) {
  const store = parseTimerStore();
  store[timer.id] = timer;
  writeTimerStore(store);
}

function loadTimer(timerId) {
  const store = parseTimerStore();
  return store[timerId] || null;
}

function activateTimer(timer, replaceHistory = false) {
  activeTimer = timer;
  syncPrivacyToggle(Boolean(timer?.isPublic));
  setRobots(Boolean(timer?.isPublic));
  updateShareUi(timer);
  updateCountdownText();

  if (!timer) return;
  const shareUrl = buildShareUrl(timer);
  const method = replaceHistory ? 'replaceState' : 'pushState';
  window.history[method](null, '', shareUrl);
}

function validateRouteAccess(timer) {
  if (!timer) {
    setError('That timer link is invalid. Create a new countdown.');
    activateTimer(null, true);
    return null;
  }

  if (timer.deadlineMs <= getNowMs()) {
    setError('That timer has expired. Create a fresh countdown.');
    activateTimer(timer, true);
    return null;
  }

  if (!timer.isPublic) {
    const providedToken = String(new URL(window.location.href).searchParams.get('token') || '');
    if (!providedToken || providedToken !== timer.token) {
      setError('This timer is private. Use the exact private URL token.');
      setRobots(false);
      updateShareUi(timer);
      return null;
    }
  }

  setError('');
  return timer;
}

function initializeFromRoute() {
  const routeTimerId = getRouteTimerId();
  if (!routeTimerId) {
    setRobots(false);
    updateShareUi(null);
    updateCountdownText();
    return;
  }

  const timer = loadTimer(routeTimerId);
  const accessibleTimer = validateRouteAccess(timer);
  if (!accessibleTimer) return;
  activateTimer(accessibleTimer, true);
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

function onFormSubmit(event) {
  event.preventDefault();
  setError('');

  const durationMinutes = coercePositiveInteger(durationInputEl?.value || '');
  const deadlineFromInput = parseDeadlineInput(deadlineInputEl?.value || '');

  let deadlineMs = null;
  if (durationMinutes) {
    deadlineMs = getNowMs() + durationMinutes * 60_000;
  } else if (deadlineFromInput) {
    deadlineMs = deadlineFromInput;
  }

  if (!deadlineMs || deadlineMs <= getNowMs()) {
    setError('Enter a future deadline or a positive duration in minutes.');
    return;
  }

  const timer = {
    id: generateTimerId(),
    token: generateTimerToken(),
    isPublic: Boolean(privacyToggleEl?.checked),
    deadlineMs,
    createdAtMs: getNowMs(),
  };
  saveTimer(timer);
  activateTimer(timer, false);
}

function onPrivacyToggle() {
  if (!activeTimer) return;
  activeTimer.isPublic = Boolean(privacyToggleEl?.checked);
  saveTimer(activeTimer);
  setRobots(activeTimer.isPublic);
  updateShareUi(activeTimer);
  setError('');

  // Keep the currently valid route in the address bar after toggling.
  window.history.replaceState(null, '', buildShareUrl(activeTimer));
  updateCountdownText();
}

function setupEvents() {
  formEl?.addEventListener('submit', onFormSubmit);
  privacyToggleEl?.addEventListener('change', onPrivacyToggle);
  copyShareUrlEl?.addEventListener('click', copyShareUrl);
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

function init() {
  setBackground(currentBackgroundIndex);
  setupEvents();
  initializeFromRoute();
  setupIntervals();
}

init();
