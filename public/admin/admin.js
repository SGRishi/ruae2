(function () {
  const api = window.RuaeApi;
  const statusEl = document.getElementById('status');
  const apiBaseEl = document.getElementById('apiBase');
  const refreshBtn = document.getElementById('refreshBtn');
  const pendingBody = document.getElementById('pendingBody');
  const approvedBody = document.getElementById('approvedBody');
  const deniedBody = document.getElementById('deniedBody');
  const denyAllBtn = document.getElementById('denyAllBtn');
  const purgeDeniedBtn = document.getElementById('purgeDeniedBtn');

  let adminToken = '';

  function setStatus(message, level) {
    statusEl.textContent = message || '';
    statusEl.className = `status ${level || 'info'}`;
  }

  function parseTimestamp(value) {
    if (!value) return null;
    if (value instanceof Date) {
      return Number.isNaN(value.getTime()) ? null : value;
    }

    if (typeof value === 'number') {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    const raw = String(value).trim();
    if (!raw) return null;

    // D1/SQLite CURRENT_TIMESTAMP is "YYYY-MM-DD HH:MM:SS" in UTC.
    const sqliteMatch = raw.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?$/);
    if (sqliteMatch) {
      const iso = `${sqliteMatch[1]}T${sqliteMatch[2]}${sqliteMatch[3] || ''}Z`;
      const date = new Date(iso);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    const dateOnlyMatch = raw.match(/^(\d{4}-\d{2}-\d{2})$/);
    if (dateOnlyMatch) {
      const date = new Date(`${dateOnlyMatch[1]}T00:00:00Z`);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    const date = new Date(raw);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function toAdminDateOrDash(value) {
    if (!value) return '—';
    const date = parseTimestamp(value);
    if (!date) return String(value);

    const datePart = new Intl.DateTimeFormat('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    }).format(date);
    return datePart;
  }

  function toSortMs(value) {
    const date = parseTimestamp(value);
    return date ? date.getTime() : 0;
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
    const apiBase = api && typeof api.getApiBase === 'function' ? String(api.getApiBase() || '') : '';
    const response = await fetch(`${apiBase}${path}`, {
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

  async function denyAllPending(reason) {
    const { response, data } = await adminRequest('/api/admin/pending/deny-all', {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to deny all pending users.');
    }
    return data;
  }

  async function clearDeniedList() {
    const { response, data } = await adminRequest('/api/admin/denied/clear', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to delete denied list.');
    }
    return data;
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
    created.textContent = toAdminDateOrDash(user.createdAt);
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
    approvedAt.textContent = toAdminDateOrDash(user.approvedAt);
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
    deniedAt.textContent = toAdminDateOrDash(user.deniedAt);
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

    pendingUsers.sort((a, b) => {
      return (
        toSortMs(b.createdAt) - toSortMs(a.createdAt)
        || Number(b.id || 0) - Number(a.id || 0)
        || userKey(b).localeCompare(userKey(a))
      );
    });

    approvedUsers.sort((a, b) => {
      return (
        toSortMs(b.approvedAt) - toSortMs(a.approvedAt)
        || Number(b.id || 0) - Number(a.id || 0)
        || userKey(b).localeCompare(userKey(a))
      );
    });

    deniedUsers.sort((a, b) => {
      return (
        toSortMs(b.deniedAt) - toSortMs(a.deniedAt)
        || Number(b.userId || 0) - Number(a.userId || 0)
        || userKey(b).localeCompare(userKey(a))
      );
    });

    if (denyAllBtn) {
      denyAllBtn.disabled = !adminToken || pendingUsers.length === 0;
    }

    if (purgeDeniedBtn) {
      purgeDeniedBtn.disabled = !adminToken || deniedUsers.length === 0;
    }

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

  if (denyAllBtn) {
    denyAllBtn.addEventListener('click', async function () {
      if (!adminToken) {
        setStatus('Admin link token missing. Open /admin/#token=YOUR_LONG_ADMIN_TOKEN', 'error');
        return;
      }

      if (!window.confirm('Deny ALL pending users?')) {
        return;
      }

      const reason = window.prompt('Reason for denial (optional):', 'Denied by administrator.') || '';

      try {
        setStatus('Denying all pending users...', 'info');
        await denyAllPending(reason);
        await loadUsers();
        setStatus('All pending users denied.', 'ok');
      } catch (error) {
        setStatus(error.message || 'Deny all failed.', 'error');
      }
    });
  }

  if (purgeDeniedBtn) {
    purgeDeniedBtn.addEventListener('click', async function () {
      if (!adminToken) {
        setStatus('Admin link token missing. Open /admin/#token=YOUR_LONG_ADMIN_TOKEN', 'error');
        return;
      }

      const confirmed = window.confirm(
        'Delete ALL denied entries and any matching user accounts?'
      );
      if (!confirmed) return;

      try {
        setStatus('Deleting denied list...', 'info');
        await clearDeniedList();
        await loadUsers();
        setStatus('Denied list deleted.', 'ok');
      } catch (error) {
        setStatus(error.message || 'Delete failed.', 'error');
      }
    });
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
  if (denyAllBtn) denyAllBtn.disabled = true;
  if (purgeDeniedBtn) purgeDeniedBtn.disabled = true;

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
