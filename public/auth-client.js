(function () {
  function normalizeBaseUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    return raw.endsWith('/') ? raw.slice(0, -1) : raw;
  }

  function resolveApiBase() {
    const fromConfig = normalizeBaseUrl(window.__APP_CONFIG__ && window.__APP_CONFIG__.API_BASE);
    if (fromConfig) return fromConfig;
    return '';
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
    const method = String((options && options.method) || 'GET').toUpperCase();
    const headers = new Headers((options && options.headers) || {});

    if (options && options.json !== undefined) {
      headers.set('Content-Type', 'application/json');
    }

    const includeCsrf = Boolean(options && options.csrf);
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
