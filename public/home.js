(function () {
  const currentPath = String(window.location.pathname || '');
  if (
    (currentPath === '/countdown' || currentPath === '/countdown/' || currentPath.startsWith('/countdown/'))
    && currentPath !== '/countdown/index.html'
  ) {
    const target = new URL('/countdown/index.html', window.location.origin);
    const routeValue = `${currentPath}${window.location.search || ''}${window.location.hash || ''}`;
    if (currentPath !== '/countdown' && currentPath !== '/countdown/') {
      target.searchParams.set('r', routeValue);
    }
    window.location.replace(target.toString());
    return;
  }

  const api = window.RuaeApi;
  if (!api || typeof api.apiRequest !== 'function') return;

  const bodyEl = document.body;
  const returningBg = document.querySelector('[data-testid="home-returning-bg"]');
  const sessionPanel = document.querySelector('[data-testid="home-session-panel"]');
  const sessionGreeting = document.querySelector('[data-testid="home-session-greeting"]');
  const guestActions = document.querySelector('[data-testid="home-guest-actions"]');
  const loginCtas = Array.from(document.querySelectorAll('[data-auth-login-link]'));

  function setLoggedOutState() {
    if (bodyEl) bodyEl.classList.remove('home--logged-in');
    if (returningBg) returningBg.hidden = true;
    if (sessionPanel) sessionPanel.hidden = true;
    if (guestActions) guestActions.hidden = false;

    for (const cta of loginCtas) {
      cta.hidden = false;
      cta.textContent = 'Create account / Login';
      cta.setAttribute('href', '/login/');
      cta.classList.add('nav-cta');
      cta.classList.remove('nav-session');
    }
  }

  function setLoggedInState(username) {
    const safeName = String(username || '').trim() || 'User';

    if (bodyEl) bodyEl.classList.add('home--logged-in');
    if (returningBg) returningBg.hidden = false;
    if (sessionPanel) sessionPanel.hidden = false;
    if (sessionGreeting) sessionGreeting.textContent = `Welcome back, ${safeName}`;
    if (guestActions) guestActions.hidden = true;

    for (const cta of loginCtas) {
      cta.hidden = false;
      cta.textContent = `Welcome back, ${safeName}`;
      cta.setAttribute('href', '/');
      cta.classList.remove('nav-cta');
      cta.classList.add('nav-session');
    }
  }

  async function refreshHomepageSession() {
    try {
      const { response, data } = await api.apiRequest('/api/auth/me');
      if (!response.ok || !data || !data.authenticated) {
        setLoggedOutState();
        return;
      }

      const username = data.user && (data.user.username || data.user.email);
      setLoggedInState(username);
    } catch {
      setLoggedOutState();
    }
  }

  refreshHomepageSession();
})();
