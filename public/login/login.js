(function () {
  const api = window.RuaeApi;

  const pendingMessage = 'Your account is pending approval.';
  const params = new URLSearchParams(window.location.search);
  const nextPath = params.get('next') || '/ruae/';

  const signupForm = document.getElementById('signupForm');
  const loginForm = document.getElementById('loginForm');
  const logoutBtn = document.getElementById('logoutBtn');
  const statusEl = document.getElementById('status');
  const continueLink = document.getElementById('continueLink');
  const apiBaseEl = document.getElementById('apiBase');

  continueLink.href = nextPath;
  apiBaseEl.textContent = api && api.getApiBase() ? api.getApiBase() : 'same origin';

  function setStatus(message, isError) {
    statusEl.textContent = message || '';
    statusEl.className = isError ? 'error' : 'ok';
  }

  if (!api) {
    setStatus('Auth client failed to load.', true);
    return;
  }

  async function refreshMe() {
    const { response, data } = await api.apiRequest('/api/auth/me');
    if (!response.ok) {
      setStatus(data.error || 'Unable to load auth status.', true);
      return;
    }

    if (!data.authenticated) {
      setStatus('Not logged in.', false);
      return;
    }

    if (!data.approved) {
      setStatus(pendingMessage, false);
      return;
    }

    setStatus(`Logged in as ${data.user.email}.`, false);
  }

  signupForm.addEventListener('submit', async function (event) {
    event.preventDefault();

    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;

    try {
      const { response, data } = await api.apiRequest('/api/auth/register', {
        method: 'POST',
        csrf: true,
        json: { email, password },
      });

      if (!response.ok) {
        setStatus(data.error || 'Unable to create account.', true);
        return;
      }

      setStatus(data.message || 'Account created. You can log in now.', false);
      signupForm.reset();
    } catch {
      setStatus('Unable to create account right now.', true);
    }
  });

  loginForm.addEventListener('submit', async function (event) {
    event.preventDefault();

    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
      const { response, data } = await api.apiRequest('/api/auth/login', {
        method: 'POST',
        csrf: true,
        json: { email, password },
      });

      if (!response.ok) {
        setStatus(data.error || 'Login failed.', true);
        return;
      }

      setStatus('Login successful.', false);
      window.location.href = nextPath;
    } catch {
      setStatus('Unable to login right now.', true);
    }
  });

  logoutBtn.addEventListener('click', async function () {
    try {
      const { response, data } = await api.apiRequest('/api/auth/logout', {
        method: 'POST',
        csrf: true,
        json: {},
      });

      if (!response.ok) {
        setStatus(data.error || 'Unable to logout.', true);
        return;
      }

      setStatus('Logged out.', false);
    } catch {
      setStatus('Unable to logout right now.', true);
    }
  });

  refreshMe().catch(function () {
    setStatus('Unable to load login status.', true);
  });
})();
