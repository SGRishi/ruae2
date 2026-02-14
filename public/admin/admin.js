(function () {
  const api = window.RuaeApi;
  const statusEl = document.getElementById('status');
  const apiBaseEl = document.getElementById('apiBase');
  const refreshBtn = document.getElementById('refreshBtn');
  const pendingBody = document.getElementById('pendingBody');
  const approvedBody = document.getElementById('approvedBody');
  const deniedBody = document.getElementById('deniedBody');

  let adminToken = '';

  function setStatus(message, level) {
    statusEl.textContent = message || '';
    statusEl.className = `status ${level || 'info'}`;
  }

  function toIsoOrDash(value) {
    if (!value) return '—';
    try {
      return new Date(value).toISOString();
    } catch {
      return String(value);
    }
  }

  function readTokenFromLocation() {
    const hash = String(window.location.hash || '').replace(/^#/, '');
    const hashParams = new URLSearchParams(hash);
    const queryParams = new URLSearchParams(window.location.search || '');
    const hashToken = hashParams.get('token');
    const queryToken = queryParams.get('token') || queryParams.get('admin_token');
    return String(hashToken || queryToken || '').trim();
  }

  function normalizeLocationForToken() {
    const queryParams = new URLSearchParams(window.location.search || '');
    const queryToken = queryParams.get('token') || queryParams.get('admin_token');
    if (!queryToken) return;

    const nextHash = `#token=${encodeURIComponent(queryToken)}`;
    const nextPath = window.location.pathname + nextHash;
    window.history.replaceState({}, '', nextPath);
  }

  function adminHeaders() {
    return new Headers({
      'Content-Type': 'application/json',
      'X-Admin-Token': adminToken,
    });
  }

  async function adminRequest(path, options = {}) {
    if (!api || !api.getApiBase()) {
      throw new Error('API client is unavailable.');
    }

    const response = await fetch(`${api.getApiBase()}${path}`, {
      method: options.method || 'GET',
      headers: options.headers || adminHeaders(),
      body: options.body,
      credentials: 'omit',
    });

    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }

    return { response, data };
  }

  function emptyTable(tableBody, text, colSpan) {
    tableBody.innerHTML = '';
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = colSpan;
    cell.className = 'muted';
    cell.textContent = text;
    row.appendChild(cell);
    tableBody.appendChild(row);
  }

  function userKey(user) {
    return String(user?.username || user?.email || '').trim();
  }

  async function approveUser(username) {
    const { response, data } = await adminRequest('/api/admin/approve', {
      method: 'POST',
      body: JSON.stringify({ username }),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to approve user.');
    }
  }

  async function denyUser(username) {
    const reason = window.prompt('Reason for denial (optional):', 'Denied by administrator.') || '';
    const { response, data } = await adminRequest('/api/admin/deny', {
      method: 'POST',
      body: JSON.stringify({ username, reason }),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to deny user.');
    }
  }

  function buildPendingRow(user, reload) {
    const row = document.createElement('tr');

    const username = userKey(user);
    const name = document.createElement('td');
    name.textContent = username;
    row.appendChild(name);

    const status = document.createElement('td');
    status.textContent = user.status || 'pending';
    row.appendChild(status);

    const created = document.createElement('td');
    created.textContent = toIsoOrDash(user.createdAt);
    row.appendChild(created);

    const actions = document.createElement('td');
    actions.className = 'actions';

    const approveBtn = document.createElement('button');
    approveBtn.type = 'button';
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('click', async function () {
      try {
        setStatus(`Approving ${username}...`, 'info');
        await approveUser(username);
        await reload();
        setStatus(`Approved ${username}.`, 'ok');
      } catch (error) {
        setStatus(error.message || 'Approval failed.', 'error');
      }
    });

    const denyBtn = document.createElement('button');
    denyBtn.type = 'button';
    denyBtn.className = 'danger';
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('click', async function () {
      try {
        setStatus(`Denying ${username}...`, 'info');
        await denyUser(username);
        await reload();
        setStatus(`Denied ${username}.`, 'ok');
      } catch (error) {
        setStatus(error.message || 'Deny failed.', 'error');
      }
    });

    actions.appendChild(approveBtn);
    actions.appendChild(document.createTextNode(' '));
    actions.appendChild(denyBtn);
    row.appendChild(actions);

    return row;
  }

  function buildApprovedRow(user, reload) {
    const row = document.createElement('tr');

    const username = userKey(user);
    const name = document.createElement('td');
    name.textContent = username;
    row.appendChild(name);

    const status = document.createElement('td');
    status.textContent = user.status || 'approved';
    row.appendChild(status);

    const approvedAt = document.createElement('td');
    approvedAt.textContent = toIsoOrDash(user.approvedAt);
    row.appendChild(approvedAt);

    const actions = document.createElement('td');
    actions.className = 'actions';

    const denyBtn = document.createElement('button');
    denyBtn.type = 'button';
    denyBtn.className = 'danger';
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('click', async function () {
      try {
        setStatus(`Denying ${username}...`, 'info');
        await denyUser(username);
        await reload();
        setStatus(`Denied ${username}.`, 'ok');
      } catch (error) {
        setStatus(error.message || 'Deny failed.', 'error');
      }
    });

    actions.appendChild(denyBtn);
    row.appendChild(actions);

    return row;
  }

  function buildDeniedRow(user, reload) {
    const row = document.createElement('tr');

    const username = userKey(user);
    const name = document.createElement('td');
    name.textContent = username;
    row.appendChild(name);

    const reason = document.createElement('td');
    reason.textContent = user.reason || 'Denied by administrator.';
    row.appendChild(reason);

    const deniedAt = document.createElement('td');
    deniedAt.textContent = toIsoOrDash(user.deniedAt);
    row.appendChild(deniedAt);

    const actions = document.createElement('td');
    actions.className = 'actions';

    const approveBtn = document.createElement('button');
    approveBtn.type = 'button';
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('click', async function () {
      try {
        setStatus(`Approving ${username}...`, 'info');
        await approveUser(username);
        await reload();
        setStatus(`Approved ${username}.`, 'ok');
      } catch (error) {
        setStatus(error.message || 'Approval failed.', 'error');
      }
    });

    actions.appendChild(approveBtn);
    row.appendChild(actions);

    return row;
  }

  async function loadUsers() {
    if (!adminToken) {
      setStatus('Admin link token missing. Open /admin/#token=YOUR_LONG_ADMIN_TOKEN', 'error');
      return;
    }

    const { response, data } = await adminRequest('/api/admin/review');
    if (!response.ok) {
      throw new Error(data.error || 'Unable to load review data.');
    }

    pendingBody.innerHTML = '';
    approvedBody.innerHTML = '';
    deniedBody.innerHTML = '';

    const pendingUsers = Array.isArray(data.pendingUsers) ? data.pendingUsers : [];
    const approvedUsers = Array.isArray(data.approvedUsers) ? data.approvedUsers : [];
    const deniedUsers = Array.isArray(data.deniedUsers) ? data.deniedUsers : [];

    if (!pendingUsers.length) {
      emptyTable(pendingBody, 'No pending users right now.', 4);
    } else {
      pendingUsers.forEach((user) => {
        pendingBody.appendChild(buildPendingRow(user, loadUsers));
      });
    }

    if (!approvedUsers.length) {
      emptyTable(approvedBody, 'No approved users yet.', 4);
    } else {
      approvedUsers.forEach((user) => {
        approvedBody.appendChild(buildApprovedRow(user, loadUsers));
      });
    }

    if (!deniedUsers.length) {
      emptyTable(deniedBody, 'No denied users.', 4);
    } else {
      deniedUsers.forEach((user) => {
        deniedBody.appendChild(buildDeniedRow(user, loadUsers));
      });
    }
  }

  refreshBtn.addEventListener('click', async function () {
    try {
      setStatus('Refreshing review data...', 'info');
      await loadUsers();
      setStatus('Review data refreshed.', 'ok');
    } catch (error) {
      setStatus(error.message || 'Refresh failed.', 'error');
    }
  });

  if (!api) {
    setStatus('Auth client failed to load.', 'error');
    return;
  }

  normalizeLocationForToken();
  adminToken = readTokenFromLocation();
  apiBaseEl.textContent = api.getApiBase() || 'same origin';
  refreshBtn.disabled = !adminToken;

  if (!adminToken) {
    setStatus('Admin link token missing. Open /admin/#token=YOUR_LONG_ADMIN_TOKEN', 'error');
    return;
  }

  loadUsers()
    .then(function () {
      setStatus('Connected via admin link token.', 'ok');
    })
    .catch(function (error) {
      setStatus(error.message || 'Unable to load admin data.', 'error');
    });
})();
