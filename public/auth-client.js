(function () {
  function normalizeBaseUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    return raw.endsWith('/') ? raw.slice(0, -1) : raw;
  }

  function buildDefaultApiBase() {
    const host = String(window.location && window.location.hostname || '').toLowerCase();
    if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') {
      return '';
    }
    return 'https://api.rishisubjects.co.uk';
  }

  function resolveApiBase() {
    const fromConfig = normalizeBaseUrl(window.__APP_CONFIG__ && window.__APP_CONFIG__.API_BASE);
    if (fromConfig) return fromConfig;
    return buildDefaultApiBase();
  }

  const state = {
    apiBase: resolveApiBase(),
    csrfToken: '',
  };

  function setCsrfToken(token) {
    state.csrfToken = String(token || '');
  }

  function getCsrfToken() {
    return state.csrfToken;
  }

  function toUrl(path) {
    const normalizedPath = String(path || '').startsWith('/') ? path : `/${path}`;
    return `${state.apiBase}${normalizedPath}`;
  }

  async function parseJson(response) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return {};
    }

    try {
      return await response.json();
    } catch {
      return {};
    }
  }

  async function apiRequest(path, options) {
    return apiRequestInternal(path, options, false);
  }

  async function refreshCsrfToken() {
    const response = await fetch(toUrl('/api/auth/me'), {
      method: 'GET',
      credentials: 'include',
    });
    const data = await parseJson(response);
    if (data && typeof data.csrfToken === 'string') {
      setCsrfToken(data.csrfToken);
    }
  }

  async function apiRequestInternal(path, options, hasRetriedCsrf) {
    const method = String((options && options.method) || 'GET').toUpperCase();
    const headers = new Headers((options && options.headers) || {});

    if (options && options.json !== undefined) {
      headers.set('Content-Type', 'application/json');
    }

    const includeCsrf = Boolean(options && options.csrf);
    if (includeCsrf && !state.csrfToken) {
      try {
        await refreshCsrfToken();
      } catch {
        // Let the main request run; server may still accept if caller supplied token in body.
      }
    }
    if (includeCsrf && state.csrfToken) {
      headers.set('X-CSRF-Token', state.csrfToken);
    }

    const response = await fetch(toUrl(path), {
      method,
      headers,
      body: options && options.json !== undefined ? JSON.stringify(options.json) : options && options.body,
      credentials: 'include',
    });

    const data = await parseJson(response);
    if (data && typeof data.csrfToken === 'string') {
      setCsrfToken(data.csrfToken);
    }

    if (
      includeCsrf &&
      !hasRetriedCsrf &&
      response.status === 403 &&
      data &&
      typeof data.error === 'string' &&
      (data.error.includes('Security check failed') || data.error.includes('Invalid request origin'))
    ) {
      await refreshCsrfToken();
      return apiRequestInternal(path, options, true);
    }

    return { response, data };
  }

  window.RuaeApi = {
    apiRequest,
    getApiBase: function () {
      return state.apiBase;
    },
    setCsrfToken,
    getCsrfToken,
  };
})();
