const backgroundPackRuntime =
  (typeof globalThis !== 'undefined' && globalThis.__COUNTDOWN_BACKGROUND_PACKS__) || {};
const BACKGROUND_PACKS =
  backgroundPackRuntime.packs && typeof backgroundPackRuntime.packs === 'object'
    ? backgroundPackRuntime.packs
    : {};
const BACKGROUND_PACK_OPTIONS = Array.isArray(backgroundPackRuntime.packOptions)
  ? backgroundPackRuntime.packOptions
  : [];
const DEFAULT_BACKGROUND_PACK = String(backgroundPackRuntime.defaultPack || 'legacy');
const TOTAL_BACKGROUND_COUNT = Number(backgroundPackRuntime.totalCount) || 0;

const IMAGE_ROTATION_INTERVAL_MS = 60_000;
const TICK_INTERVAL_MS = 250;
const OWNER_TOKEN_KEY = 'countdownOwnerTokens:v3';
const CLASSIC_FM_STREAM = 'https://ice-the.musicradio.com/ClassicFMMP3';
const UK_TIME_ZONE = 'Europe/London';
const UNIT_ORDER = ['days', 'hours', 'minutes', 'seconds'];
const TEST_CONFIG = typeof window !== 'undefined' ? window.__COUNTDOWN_TEST__ || null : null;
const IS_TEST_MODE = Boolean(TEST_CONFIG);

const backgroundEl = document.querySelector('[data-testid="bg-image"]');
const bgNextEl = document.querySelector('[data-testid="bg-next"]');
const bgPackSelectEl = document.querySelector('[data-testid="bg-pack-select"]');
const bgPackNoteEl = document.querySelector('[data-testid="bg-pack-note"]');
const bgPackNoteDisplayEl = document.querySelector('[data-testid="bg-pack-note-display"]');
const bgPackMenuToggleEl = document.querySelector('[data-testid="pack-menu-toggle"]');
const bgPackMenuPanelEl = document.querySelector('[data-testid="pack-menu-panel"]');
const bgPackMenuWrapEl = document.querySelector('[data-testid="pack-menu-wrap"]');
const bgPackShortcutEls = Array.from(document.querySelectorAll('[data-pack-shortcut]'));
const formEl = document.querySelector('[data-testid="timer-form"]');
const statusEl = document.querySelector('[data-testid="countdown-status"]');
const errorEl = document.querySelector('[data-testid="timer-error"]');
const countdownTitleEl = document.querySelector('[data-testid="countdown-title"]');
const titleInputEl = document.querySelector('[data-testid="title-input"]');
const deadlineDateEl = document.querySelector('[data-testid="deadline-date"]');
const deadlineTimeEl = document.querySelector('[data-testid="deadline-time"]');
const deadlineCombinedEl = document.querySelector('[data-testid="deadline-input"]');
const resolveQueryEl = document.querySelector('[data-testid="resolve-query"]');
const resolveButtonEl = document.querySelector('[data-testid="resolve-button"]');
const resolveNotesEl = document.querySelector('[data-testid="resolve-notes"]');
const resolveSuggestionsEl = document.querySelector('[data-testid="resolve-suggestions"]');
const resolvedDateDisplayEl = document.querySelector('[data-testid="resolved-date-display"]');
const resolvedSourceWrapEl = document.querySelector('[data-testid="resolved-source"]');
const resolvedSourceLinkEl = document.querySelector('[data-testid="resolved-source-link"]');
const publicCheckboxEl = document.querySelector('[data-testid="public-checkbox"]');
const privateCheckboxEl = document.querySelector('[data-testid="private-checkbox"]');
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
const volumeSliderEl = document.querySelector('[data-testid="volume-slider"]');
const audioStatusEl = document.querySelector('[data-testid="audio-status"]');
const musicErrorEl = document.querySelector('[data-testid="music-error"]');
const robotsMetaEl = document.querySelector('meta[name="robots"]');

const unitInputEls = {
  days: document.querySelector('[data-testid="units-days"]'),
  hours: document.querySelector('[data-testid="units-hours"]'),
  minutes: document.querySelector('[data-testid="units-minutes"]'),
  seconds: document.querySelector('[data-testid="units-seconds"]'),
};

const unitCardEls = {
  days: document.querySelector('.countdown-unit[data-unit="days"]'),
  hours: document.querySelector('.countdown-unit[data-unit="hours"]'),
  minutes: document.querySelector('.countdown-unit[data-unit="minutes"]'),
  seconds: document.querySelector('.countdown-unit[data-unit="seconds"]'),
};

let activeTimer = null;
let ownerToken = '';
let embedMode = false;
let activeBackgroundPack = DEFAULT_BACKGROUND_PACK;
let activeBackgroundImages = BACKGROUND_PACKS[DEFAULT_BACKGROUND_PACK] || [];
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

function normalizeTitle(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
}

function normalizeUnits(value) {
  if (!Array.isArray(value)) return [];
  const units = [];
  for (const item of value) {
    const unit = String(item || '').trim().toLowerCase();
    if (!UNIT_ORDER.includes(unit)) continue;
    if (!units.includes(unit)) units.push(unit);
  }
  return units;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function getClientNowMs() {
  return IS_TEST_MODE ? testNowMs : Date.now();
}

function syncServerClock(serverNowMs) {
  if (IS_TEST_MODE) return;
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
  syncLayoutMode();
}

function setMusicError(message) {
  if (!musicErrorEl) return;
  const text = String(message || '').trim();
  if (!text) {
    musicErrorEl.hidden = true;
    musicErrorEl.textContent = '';
    return;
  }
  musicErrorEl.hidden = false;
  musicErrorEl.textContent = text;
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

function buildEmbedIframe(embedUrl) {
  const src = String(embedUrl || '').trim();
  if (!src) return '';
  return `<iframe src="${src}" title="Countdown timer" style="width:100%;max-width:760px;height:340px;border:0;overflow:hidden;border-radius:12px;" loading="lazy" referrerpolicy="strict-origin-when-cross-origin"></iframe>`;
}

function syncLayoutMode() {
  const linkedTimerRoute = Boolean(getRouteTimerId());
  const readOnlyView =
    !embedMode && (linkedTimerRoute || passwordGateVisible || Boolean(activeTimer && !activeTimer.canEdit));
  document.body.classList.toggle('countdown-readonly', readOnlyView);
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
    if (embedUrlEl) {
      embedUrlEl.value = '';
      delete embedUrlEl.dataset.embedSrc;
    }
    return;
  }

  const publicUrl = toPublicUrl(timerId);
  const privateUrl = toPrivateUrl(timerId);
  const embedUrl = timer ? toEmbedUrl(timer) : `${publicUrl}?embed=1`;
  const embedCode = buildEmbedIframe(embedUrl);

  if (publicUrlEl) publicUrlEl.value = publicUrl;
  if (privateUrlEl) privateUrlEl.value = privateUrl;
  if (embedUrlEl) {
    embedUrlEl.value = embedCode;
    embedUrlEl.dataset.embedSrc = embedUrl;
  }
}

function getUnitsFromForm() {
  const selected = UNIT_ORDER.filter((unit) => Boolean(unitInputEls[unit]?.checked));
  return selected;
}

function setUnitsInForm(units) {
  const selected = normalizeUnits(units);
  for (const unit of UNIT_ORDER) {
    if (!unitInputEls[unit]) continue;
    unitInputEls[unit].checked = selected.includes(unit);
  }
}

function getDisplayUnits() {
  const units = normalizeUnits(activeTimer?.units);
  if (units.length) return units;
  const fromForm = getUnitsFromForm();
  return fromForm.length ? fromForm : [...UNIT_ORDER];
}

function syncUnitCards(units) {
  for (const unit of UNIT_ORDER) {
    const card = unitCardEls[unit];
    if (!card) continue;
    card.hidden = !units.includes(unit);
  }
}

function setTitleDisplay(value) {
  if (!countdownTitleEl) return;
  const title = normalizeTitle(value);
  countdownTitleEl.textContent = title || 'Countdown';
}

function toPathAndSearch(urlValue) {
  const url = new URL(urlValue);
  return `${url.pathname}${url.search}`;
}

function normalizeTimer(timer) {
  if (!timer || typeof timer !== 'object') return null;
  const id = normalizeTimerId(timer.id);
  const startAtMs = Number(timer.startAtMs ?? timer.createdAtMs);
  const endAtMs = Number(timer.endAtMs ?? timer.deadlineMs);
  const title = normalizeTitle(timer.title);
  const units = normalizeUnits(timer.units);
  if (!id || !Number.isFinite(startAtMs) || !Number.isFinite(endAtMs)) return null;
  return {
    id,
    startAtMs,
    endAtMs,
    isPublic: Boolean(timer.isPublic),
    canEdit: Boolean(timer.canEdit),
    title: title || 'Countdown',
    units: units.length ? units : [...UNIT_ORDER],
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

function syncVisibilityControls(options = {}) {
  const alignFromTimer = Boolean(options.alignFromTimer);

  if (publicCheckboxEl && privateCheckboxEl && alignFromTimer && activeTimer) {
    publicCheckboxEl.checked = Boolean(activeTimer.isPublic);
    privateCheckboxEl.checked = !activeTimer.isPublic;
  }

  if (makePublicButtonEl) {
    const canEdit = Boolean(activeTimer && ownerToken);
    makePublicButtonEl.disabled = !canEdit;
    makePublicButtonEl.textContent = activeTimer?.isPublic ? 'Make private' : 'Make public';
  }

  const shouldEnablePassword = Boolean(privateCheckboxEl?.checked);
  if (setupPasswordInputEl) {
    setupPasswordInputEl.disabled = !shouldEnablePassword;
    setupPasswordInputEl.required = shouldEnablePassword;
  }
}

function handleVisibilityCheckboxChange(changed) {
  if (!publicCheckboxEl || !privateCheckboxEl) return;
  if (changed === 'public' && publicCheckboxEl.checked) {
    privateCheckboxEl.checked = false;
  }
  if (changed === 'private' && privateCheckboxEl.checked) {
    publicCheckboxEl.checked = false;
  }
  syncVisibilityControls();
}

function getUkNumericParts(epochMs) {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: UK_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  const parts = formatter.formatToParts(new Date(epochMs));
  const map = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return {
    year: Number.parseInt(map.year || '0', 10),
    month: Number.parseInt(map.month || '0', 10),
    day: Number.parseInt(map.day || '0', 10),
    hour: Number.parseInt(map.hour || '0', 10),
    minute: Number.parseInt(map.minute || '0', 10),
  };
}

function getUkOffsetMinutes(epochMs) {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: UK_TIME_ZONE,
    timeZoneName: 'shortOffset',
    hour: '2-digit',
  });
  const parts = formatter.formatToParts(new Date(epochMs));
  const zone = String(parts.find((item) => item.type === 'timeZoneName')?.value || 'GMT');
  const match = zone.match(/(?:GMT|UTC)([+-])(\d{1,2})(?::?(\d{2}))?/i);
  if (!match) return 0;
  const sign = match[1] === '-' ? -1 : 1;
  const hours = Number.parseInt(match[2] || '0', 10);
  const minutes = Number.parseInt(match[3] || '0', 10);
  return sign * (hours * 60 + minutes);
}

function ukDateTimeToEpochMs(year, month, day, hour, minute) {
  let epochMs = Date.UTC(year, month - 1, day, hour, minute, 0, 0);

  for (let i = 0; i < 4; i += 1) {
    const offsetMinutes = getUkOffsetMinutes(epochMs);
    const nextEpoch = Date.UTC(year, month - 1, day, hour, minute, 0, 0) - offsetMinutes * 60_000;
    if (Math.abs(nextEpoch - epochMs) < 1_000) {
      epochMs = nextEpoch;
      break;
    }
    epochMs = nextEpoch;
  }

  return epochMs;
}

function parseUkDateTime(dateText, timeText) {
  const dateMatch = String(dateText || '').trim().match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!dateMatch) {
    return { ok: false, error: 'Enter a valid UK date in DD/MM/YYYY format.' };
  }

  const timeMatch = String(timeText || '').trim().match(/^([01]\d|2[0-3]):([0-5]\d)$/);
  if (!timeMatch) {
    return { ok: false, error: 'Enter a valid 24-hour time in HH:MM format.' };
  }

  const day = Number.parseInt(dateMatch[1], 10);
  const month = Number.parseInt(dateMatch[2], 10);
  const year = Number.parseInt(dateMatch[3], 10);
  const hour = Number.parseInt(timeMatch[1], 10);
  const minute = Number.parseInt(timeMatch[2], 10);

  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return { ok: false, error: 'Enter a real calendar date.' };
  }

  const epochMs = ukDateTimeToEpochMs(year, month, day, hour, minute);
  const ukParts = getUkNumericParts(epochMs);

  if (
    ukParts.year !== year
    || ukParts.month !== month
    || ukParts.day !== day
    || ukParts.hour !== hour
    || ukParts.minute !== minute
  ) {
    return { ok: false, error: 'Enter a real calendar date.' };
  }

  return { ok: true, epochMs };
}

function formatUkDateForDisplay(epochMs) {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: UK_TIME_ZONE,
      weekday: 'long',
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(new Date(epochMs));
  } catch {
    return '';
  }
}

function formatDateForDisplayInTimeZone(epochMs, timeZone = UK_TIME_ZONE) {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: String(timeZone || UK_TIME_ZONE),
      weekday: 'long',
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(new Date(epochMs));
  } catch {
    return formatUkDateForDisplay(epochMs);
  }
}

function fillInputsFromEpoch(epochMs) {
  const parts = getUkNumericParts(epochMs);
  const pad = (value) => String(value).padStart(2, '0');
  if (deadlineDateEl) {
    deadlineDateEl.value = `${pad(parts.day)}/${pad(parts.month)}/${String(parts.year).padStart(4, '0')}`;
  }
  if (deadlineTimeEl) {
    deadlineTimeEl.value = `${pad(parts.hour)}:${pad(parts.minute)}`;
  }
  if (deadlineCombinedEl) {
    deadlineCombinedEl.value = new Date(epochMs).toISOString();
  }
}

function setResolvedDateText(epochMs, resolvedLabel = '') {
  if (!resolvedDateDisplayEl) return;
  if (epochMs === null || epochMs === undefined) {
    resolvedDateDisplayEl.textContent = '';
    return;
  }
  if (!Number.isFinite(Number(epochMs))) {
    resolvedDateDisplayEl.textContent = '';
    return;
  }
  const fallback = formatUkDateForDisplay(Number(epochMs));
  const label = String(resolvedLabel || '').trim() || fallback;
  resolvedDateDisplayEl.textContent = label ? `Target date: ${label}` : '';
}

function setResolvedSource(sourceUrl = '', sourceTitle = '') {
  if (!resolvedSourceWrapEl || !resolvedSourceLinkEl) return;
  const href = String(sourceUrl || '').trim();
  if (!href) {
    resolvedSourceWrapEl.hidden = true;
    resolvedSourceLinkEl.removeAttribute('href');
    resolvedSourceLinkEl.textContent = '';
    return;
  }

  resolvedSourceWrapEl.hidden = false;
  resolvedSourceLinkEl.href = href;
  resolvedSourceLinkEl.textContent = String(sourceTitle || '').trim() || href;
}

function computeUnitValues(totalSeconds, units) {
  let remaining = Math.max(0, totalSeconds);
  const values = {
    days: 0,
    hours: 0,
    minutes: 0,
    seconds: 0,
  };

  if (units.includes('days')) {
    values.days = Math.floor(remaining / 86_400);
    remaining -= values.days * 86_400;
  }

  if (units.includes('hours')) {
    values.hours = Math.floor(remaining / 3_600);
    remaining -= values.hours * 3_600;
  }

  if (units.includes('minutes')) {
    values.minutes = Math.floor(remaining / 60);
    remaining -= values.minutes * 60;
  }

  if (units.includes('seconds')) {
    values.seconds = remaining;
  }

  return values;
}

function formatUnitValue(unit, value, isVisible) {
  if (!isVisible) return '00';
  if (unit === 'days') return String(Math.max(0, value));
  return String(Math.max(0, value)).padStart(2, '0');
}

function renderCountdown() {
  if (!countdownDisplayEl || !daysEl || !hoursEl || !minutesEl || !secondsEl) return;

  const units = getDisplayUnits();
  syncUnitCards(units);

  if (!activeTimer) {
    daysEl.textContent = formatUnitValue('days', 0, units.includes('days'));
    hoursEl.textContent = formatUnitValue('hours', 0, units.includes('hours'));
    minutesEl.textContent = formatUnitValue('minutes', 0, units.includes('minutes'));
    secondsEl.textContent = formatUnitValue('seconds', 0, units.includes('seconds'));
    if (progressBarEl) {
      progressBarEl.style.width = '100%';
      progressBarEl.setAttribute('aria-valuenow', '100');
    }
    if (progressPercentEl) progressPercentEl.textContent = '100.0%';
    return;
  }

  const now = getNowMs();
  const remainingMs = Math.max(0, activeTimer.endAtMs - now);
  const totalSeconds = Math.floor(remainingMs / 1_000);
  const values = computeUnitValues(totalSeconds, units);

  daysEl.textContent = formatUnitValue('days', values.days, units.includes('days'));
  hoursEl.textContent = formatUnitValue('hours', values.hours, units.includes('hours'));
  minutesEl.textContent = formatUnitValue('minutes', values.minutes, units.includes('minutes'));
  secondsEl.textContent = formatUnitValue('seconds', values.seconds, units.includes('seconds'));

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

function backgroundPackOption(packKey) {
  return BACKGROUND_PACK_OPTIONS.find((option) => option.key === packKey) || null;
}

function availableBackgroundPool(packKey) {
  const requested = String(packKey || '').trim();
  if (requested && Array.isArray(BACKGROUND_PACKS[requested]) && BACKGROUND_PACKS[requested].length) {
    return {
      key: requested,
      images: BACKGROUND_PACKS[requested],
    };
  }

  if (Array.isArray(BACKGROUND_PACKS[DEFAULT_BACKGROUND_PACK]) && BACKGROUND_PACKS[DEFAULT_BACKGROUND_PACK].length) {
    return {
      key: DEFAULT_BACKGROUND_PACK,
      images: BACKGROUND_PACKS[DEFAULT_BACKGROUND_PACK],
    };
  }

  const fallbackKey = String(Object.keys(BACKGROUND_PACKS)[0] || '');
  return {
    key: fallbackKey,
    images: Array.isArray(BACKGROUND_PACKS[fallbackKey]) ? BACKGROUND_PACKS[fallbackKey] : [],
  };
}

function setBackground(index) {
  if (!backgroundEl || !activeBackgroundImages.length) return;
  const safeIndex =
    ((index % activeBackgroundImages.length) + activeBackgroundImages.length) % activeBackgroundImages.length;
  const imageUrl = activeBackgroundImages[safeIndex];
  currentBackgroundIndex = safeIndex;
  backgroundEl.style.backgroundImage = `url("${imageUrl}")`;
  backgroundEl.dataset.backgroundUrl = imageUrl;
}

function renderBackgroundPackNote() {
  const option = backgroundPackOption(activeBackgroundPack);
  const packSize = activeBackgroundImages.length;
  const label = option?.label || activeBackgroundPack || 'Backgrounds';
  const detail = option?.description || 'Background pack loaded.';
  const text = `${label}: ${packSize}/${TOTAL_BACKGROUND_COUNT} images. ${detail}`;
  if (bgPackNoteEl) bgPackNoteEl.textContent = text;
  if (bgPackNoteDisplayEl) bgPackNoteDisplayEl.textContent = text;
}

function setPackMenuOpen(open) {
  if (!bgPackMenuToggleEl || !bgPackMenuPanelEl) return;
  const nextOpen = Boolean(open);
  bgPackMenuPanelEl.hidden = !nextOpen;
  bgPackMenuToggleEl.setAttribute('aria-expanded', String(nextOpen));
}

function syncPackShortcutButtons() {
  for (const button of bgPackShortcutEls) {
    const packKey = String(button?.dataset?.packShortcut || '').trim();
    const isActive = packKey === activeBackgroundPack;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
  }
}

function setBackgroundPack(packKey) {
  const next = availableBackgroundPool(packKey);
  activeBackgroundPack = next.key;
  activeBackgroundImages = next.images;
  currentBackgroundIndex = 0;

  if (bgPackSelectEl && bgPackSelectEl.value !== activeBackgroundPack) {
    bgPackSelectEl.value = activeBackgroundPack;
  }

  renderBackgroundPackNote();
  syncPackShortcutButtons();
  setBackground(0);
}

function hydrateBackgroundPackSelect() {
  if (!bgPackSelectEl) return;
  bgPackSelectEl.innerHTML = '';

  for (const option of BACKGROUND_PACK_OPTIONS) {
    const optEl = document.createElement('option');
    optEl.value = option.key;
    optEl.textContent = `${option.label} (${option.count})`;
    bgPackSelectEl.append(optEl);
  }
}

function rotateBackground() {
  setBackground(currentBackgroundIndex + 1);
}

function messageFromError(data, fallback) {
  const message = String(data?.error || '').trim();
  return message || fallback;
}

function clearResolverUi() {
  if (resolveNotesEl) resolveNotesEl.textContent = '';
  if (resolveSuggestionsEl) resolveSuggestionsEl.innerHTML = '';
  setResolvedSource('');
}

function applyResolvedIso(isoUtc, displayText = '', source = {}) {
  const parsed = Date.parse(String(isoUtc || ''));
  if (!Number.isFinite(parsed)) {
    if (resolveNotesEl) resolveNotesEl.textContent = 'Resolver did not return a valid date.';
    setResolvedSource('');
    return;
  }

  fillInputsFromEpoch(parsed);
  setResolvedDateText(parsed, displayText);
  setResolvedSource(source.url, source.title);
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
  if (IS_TEST_MODE) return;
  try {
    const { response, data } = await apiRequest('/api/time');
    if (response.ok && Number.isFinite(Number(data?.nowMs))) {
      syncServerClock(data.nowMs);
    }
  } catch {
    // Keep local clock when the server endpoint is unavailable.
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
  setTitleDisplay(titleInputEl?.value || 'Countdown');
  setResolvedDateText(null);
  setResolvedSource('');
  renderCountdown();
}

function applyTimer(timer, options = {}) {
  const normalizedTimer = normalizeTimer(timer);
  if (!normalizedTimer) {
    resetForNoTimer();
    return;
  }

  activeTimer = normalizedTimer;
  setTitleDisplay(activeTimer.title);
  if (titleInputEl) {
    titleInputEl.value = activeTimer.title;
  }

  setUnitsInForm(activeTimer.units);
  syncUnitCards(activeTimer.units);
  setResolvedDateText(activeTimer.endAtMs);
  setResolvedSource('');

  const tokenCandidate = Object.prototype.hasOwnProperty.call(options, 'token') ? options.token : ownerToken;
  ownerToken = normalizeToken(tokenCandidate);

  if (ownerToken) {
    rememberOwnerToken(activeTimer.id, ownerToken);
  }

  showPasswordGate(false);
  setPasswordMessage('');
  setRobots(activeTimer.isPublic);
  updateUrlFields(activeTimer);
  syncVisibilityControls({ alignFromTimer: true });
  fillInputsFromEpoch(activeTimer.endAtMs);
  renderCountdown();

  if (options.updateHistory !== false) {
    const method = options.replaceHistory ? 'replaceState' : 'pushState';
    window.history[method](null, '', buildHistoryUrl(activeTimer));
  }

  syncLayoutMode();
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

function validateVisibilitySelection() {
  const publicSelected = Boolean(publicCheckboxEl?.checked);
  const privateSelected = Boolean(privateCheckboxEl?.checked);

  if (!publicSelected && !privateSelected) {
    return { ok: false, error: 'You must choose public or private.' };
  }
  if (publicSelected && privateSelected) {
    return { ok: false, error: 'Choose only one: public or private.' };
  }

  return { ok: true, isPublic: publicSelected };
}

function validateUnitsSelection(units) {
  if (!Array.isArray(units) || !units.length) {
    return { ok: false, error: 'Select at least one unit.' };
  }
  return { ok: true };
}

async function onResolveDateClick() {
  setError('');
  clearResolverUi();

  const query = String(resolveQueryEl?.value || '').trim();
  if (!query) {
    if (resolveNotesEl) {
      resolveNotesEl.textContent = 'Enter an event description first.';
    }
    return;
  }

  if (resolveButtonEl) {
    resolveButtonEl.disabled = true;
  }

  let result;
  try {
    const params = new URLSearchParams();
    params.set('q', query);
    params.set('timeZone', UK_TIME_ZONE);
    result = await apiRequest(`/api/resolve-date?${params.toString()}`);
  } catch {
    if (resolveNotesEl) {
      resolveNotesEl.textContent = 'Unable to resolve a date right now.';
    }
    if (resolveButtonEl) {
      resolveButtonEl.disabled = false;
    }
    return;
  }

  const { response, data } = result;
  if (!response.ok) {
    if (resolveNotesEl) {
      resolveNotesEl.textContent = messageFromError(data, 'Unable to resolve a date right now.');
    }
    if (resolveButtonEl) {
      resolveButtonEl.disabled = false;
    }
    return;
  }

  const isoValue = String(data.datetime_iso || data.isoUtc || '').trim();
  const sourceUrl = String(data.source_url || data.sourceUrl || '').trim();
  const sourceTitle = String(data.source_title || data.sourceTitle || '').trim();
  const timeZone = String(data.timezone || UK_TIME_ZONE).trim() || UK_TIME_ZONE;
  const notes = String(data.note || data.notes || '').trim();
  const displayFromApi = String(data.display || '').trim();

  if (isoValue) {
    const parsed = Date.parse(isoValue);
    const displayText = displayFromApi
      || (Number.isFinite(parsed) ? formatDateForDisplayInTimeZone(parsed, timeZone) : '');
    applyResolvedIso(isoValue, displayText, {
      url: sourceUrl,
      title: sourceTitle,
    });
    if (resolveNotesEl) {
      resolveNotesEl.textContent = notes || 'Date resolved from a cited source.';
    }
  } else {
    if (resolveNotesEl) {
      resolveNotesEl.textContent = notes || 'Could not resolve a confident date. Enter it manually.';
    }
    setResolvedSource('');
  }

  if (resolveButtonEl) {
    resolveButtonEl.disabled = false;
  }
}

async function onFormSubmit(event) {
  event.preventDefault();
  setError('');

  const title = normalizeTitle(titleInputEl?.value || '') || 'Countdown';
  const parsedDate = parseUkDateTime(deadlineDateEl?.value || '', deadlineTimeEl?.value || '');
  if (!parsedDate.ok) {
    setError(parsedDate.error);
    return;
  }

  const deadlineMs = Number(parsedDate.epochMs);
  if (deadlineCombinedEl) {
    deadlineCombinedEl.value = new Date(deadlineMs).toISOString();
  }

  if (deadlineMs <= getNowMs()) {
    setError('Deadline must be in the future.');
    return;
  }

  const units = getUnitsFromForm();
  const unitsCheck = validateUnitsSelection(units);
  if (!unitsCheck.ok) {
    setError(unitsCheck.error);
    return;
  }

  const visibility = validateVisibilitySelection();
  if (!visibility.ok) {
    setError(visibility.error);
    return;
  }

  const privatePassword = String(setupPasswordInputEl?.value || '').trim();
  if (!visibility.isPublic && !privatePassword) {
    setError('Private timers require a password.');
    return;
  }

  const payload = {
    title,
    units,
    isPublic: visibility.isPublic,
    deadlineMs,
  };

  if (!visibility.isPublic) {
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
    updateHistory: false,
  });
  setStatus('Countdown created.');
  setError('');
}

async function onMakePublicButtonClick() {
  if (!activeTimer || !ownerToken) return;

  const nextIsPublic = !activeTimer.isPublic;
  const privatePassword = String(setupPasswordInputEl?.value || '').trim();
  if (!nextIsPublic && !privatePassword && !activeTimer.isPublic) {
    setError('Private timers require a password.');
    return;
  }

  const payload = {
    id: activeTimer.id,
    token: ownerToken,
    isPublic: nextIsPublic,
  };

  if (!nextIsPublic && privatePassword) {
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
    syncVisibilityControls({ alignFromTimer: true });
    return;
  }

  syncServerClock(data?.serverNowMs);
  applyTimer(data.timer, {
    replaceHistory: true,
    token: ownerToken,
    updateHistory: false,
  });
  setStatus(nextIsPublic ? 'Countdown is now public.' : 'Countdown is now private.');
  setError('');
}

async function playAmbient() {
  if (!audioEl || !audioStatusEl) return;
  setMusicError('');
  try {
    await audioEl.play();
    audioStatusEl.textContent = 'Ambient playing.';
  } catch (error) {
    audioStatusEl.textContent = 'Ambient paused.';
    setMusicError(String(error?.message || 'Playback blocked by browser. Click play again.'));
  }
}

function pauseAmbient() {
  if (!audioEl || !audioStatusEl) return;
  audioEl.pause();
  audioStatusEl.textContent = 'Ambient paused.';
}

function syncAmbientVolume() {
  if (!audioEl || !volumeSliderEl) return;
  const parsed = Number(volumeSliderEl.value);
  const nextVolume = Number.isFinite(parsed) ? clamp(parsed, 0, 1) : 0.7;
  audioEl.volume = nextVolume;
  volumeSliderEl.value = String(nextVolume);
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

  resolveButtonEl?.addEventListener('click', onResolveDateClick);
  musicPlayEl?.addEventListener('click', playAmbient);
  musicPauseEl?.addEventListener('click', pauseAmbient);
  volumeSliderEl?.addEventListener('input', syncAmbientVolume);
  volumeSliderEl?.addEventListener('change', syncAmbientVolume);
  bgNextEl?.addEventListener('click', () => {
    if (!IS_TEST_MODE) return;
    rotateBackground();
  });
  bgPackSelectEl?.addEventListener('change', () => {
    setBackgroundPack(bgPackSelectEl.value);
  });
  bgPackMenuToggleEl?.addEventListener('click', () => {
    const open = bgPackMenuToggleEl.getAttribute('aria-expanded') === 'true';
    setPackMenuOpen(!open);
  });
  document.addEventListener('click', (event) => {
    if (!bgPackMenuWrapEl || !bgPackMenuToggleEl || !bgPackMenuPanelEl) return;
    if (bgPackMenuPanelEl.hidden) return;
    const target = event.target;
    if (!(target instanceof Node)) return;
    if (bgPackMenuWrapEl.contains(target)) return;
    setPackMenuOpen(false);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    setPackMenuOpen(false);
  });
  for (const button of bgPackShortcutEls) {
    button.addEventListener('click', () => {
      const packKey = String(button?.dataset?.packShortcut || '').trim();
      if (!packKey) return;
      setBackgroundPack(packKey);
      setPackMenuOpen(false);
    });
  }

  titleInputEl?.addEventListener('input', () => {
    if (activeTimer) return;
    setTitleDisplay(titleInputEl.value);
  });

  for (const unit of UNIT_ORDER) {
    unitInputEls[unit]?.addEventListener('change', () => {
      renderCountdown();
      if (!getUnitsFromForm().length) {
        setError('Select at least one unit.');
      } else {
        setError('');
      }
    });
  }

  publicCheckboxEl?.addEventListener('change', () => {
    handleVisibilityCheckboxChange('public');
    setError('');
  });
  privateCheckboxEl?.addEventListener('change', () => {
    handleVisibilityCheckboxChange('private');
    setError('');
  });

  deadlineDateEl?.addEventListener('input', () => {
    if (!deadlineCombinedEl) return;
    const parsed = parseUkDateTime(deadlineDateEl.value, deadlineTimeEl?.value || '');
    deadlineCombinedEl.value = parsed.ok ? new Date(parsed.epochMs).toISOString() : '';
  });

  deadlineTimeEl?.addEventListener('input', () => {
    if (!deadlineCombinedEl) return;
    const parsed = parseUkDateTime(deadlineDateEl?.value || '', deadlineTimeEl.value);
    deadlineCombinedEl.value = parsed.ok ? new Date(parsed.epochMs).toISOString() : '';
  });
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
    if (IS_TEST_MODE) {
      testNowMs += tickStepMs;
    }
    renderCountdown();
  }, tickIntervalMs);

  setInterval(() => {
    rotateBackground();
  }, imageIntervalMs);
}

function setupTestApi() {
  if (!IS_TEST_MODE) return;

  window.__COUNTDOWN_TEST_API__ = {
    advance(ms) {
      const delta = Number(ms);
      if (!Number.isFinite(delta)) return;
      testNowMs += delta;
      renderCountdown();
    },
    setNow(ms) {
      const next = Number(ms);
      if (!Number.isFinite(next)) return;
      testNowMs = next;
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
    backgroundPack() {
      return activeBackgroundPack;
    },
    countdownPath(urlValue) {
      return toPathAndSearch(urlValue);
    },
  };

  if (bgNextEl) {
    bgNextEl.hidden = false;
  }
}

function initializeAudio() {
  if (!audioEl) return;
  audioEl.src = CLASSIC_FM_STREAM;
  syncAmbientVolume();
}

async function init() {
  maybeRestoreFallbackRoute();
  embedMode = isEmbedMode();
  if (embedMode) {
    document.body.classList.add('countdown-embed');
  }
  syncLayoutMode();

  hydrateBackgroundPackSelect();
  setBackgroundPack(DEFAULT_BACKGROUND_PACK);
  updateUrlFields('');
  syncVisibilityControls();
  setTitleDisplay(titleInputEl?.value || 'Countdown');
  initializeAudio();
  setupTestApi();
  setupEvents();
  await syncTimeFromServer();
  await initializeFromRoute();
  setupIntervals();
}

init();
