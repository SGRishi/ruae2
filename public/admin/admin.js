(function () {
  const api = window.RuaeApi;
  const statusEl = document.getElementById('status');
  const apiBaseEl = document.getElementById('apiBase');
  const adminKeyEl = document.getElementById('adminKey');
  const connectBtn = document.getElementById('connectBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  const pendingBody = document.getElementById('pendingBody');
  const deniedBody = document.getElementById('deniedBody');

  let adminKey = '';

  function setStatus(message, isError) {
    statusEl.textContent = message || '';
    statusEl.className = isError ? 'status error' : 'status ok';
  }

  function toIsoOrDash(value) {
    if (!value) return '—';
    try {
      return new Date(value).toISOString();
    } catch {
      return String(value);
    }
  }

  function adminHeaders() {
    const headers = new Headers({
      'Content-Type': 'application/json',
      'X-Admin-Key': adminKey,
    });
    return headers;
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

  async function approveUser(email) {
    const { response, data } = await adminRequest('/api/admin/approve', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to approve user.');
    }
  }

  async function denyUser(email) {
    const reason = window.prompt('Reason for denial (optional):', 'Denied by administrator.') || '';
    const { response, data } = await adminRequest('/api/admin/deny', {
      method: 'POST',
      body: JSON.stringify({ email, reason }),
    });
    if (!response.ok) {
      throw new Error(data.error || 'Failed to deny user.');
    }
  }

  function buildPendingRow(user, reload) {
    const row = document.createElement('tr');

    const email = document.createElement('td');
    email.textContent = user.email;
    row.appendChild(email);

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
        setStatus(`Approving ${user.email}...`, false);
        await approveUser(user.email);
        await reload();
        setStatus(`Approved ${user.email}.`, false);
      } catch (error) {
        setStatus(error.message || 'Approval failed.', true);
      }
    });

    const denyBtn = document.createElement('button');
    denyBtn.type = 'button';
    denyBtn.className = 'danger';
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('click', async function () {
      try {
        setStatus(`Denying ${user.email}...`, false);
        await denyUser(user.email);
        await reload();
        setStatus(`Denied ${user.email}.`, false);
      } catch (error) {
        setStatus(error.message || 'Deny failed.', true);
      }
    });

    actions.appendChild(approveBtn);
    actions.appendChild(document.createTextNode(' '));
    actions.appendChild(denyBtn);
    row.appendChild(actions);

    return row;
  }

  function buildDeniedRow(user, reload) {
    const row = document.createElement('tr');

    const email = document.createElement('td');
    email.textContent = user.email;
    row.appendChild(email);

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
        setStatus(`Approving ${user.email}...`, false);
        await approveUser(user.email);
        await reload();
        setStatus(`Approved ${user.email}.`, false);
      } catch (error) {
        setStatus(error.message || 'Approval failed.', true);
      }
    });

    actions.appendChild(approveBtn);
    row.appendChild(actions);

    return row;
  }

  async function loadUsers() {
    if (!adminKey) {
      setStatus('Enter your admin password first.', true);
      return;
    }

    const { response, data } = await adminRequest('/api/admin/review', {
      method: 'GET',
      headers: new Headers({
        'X-Admin-Key': adminKey,
      }),
    });

    if (!response.ok) {
      throw new Error(data.error || 'Unable to load review data.');
    }

    pendingBody.innerHTML = '';
    deniedBody.innerHTML = '';

    const pendingUsers = Array.isArray(data.pendingUsers) ? data.pendingUsers : [];
    const deniedUsers = Array.isArray(data.deniedUsers) ? data.deniedUsers : [];

    if (!pendingUsers.length) {
      emptyTable(pendingBody, 'No pending users right now.', 4);
    } else {
      pendingUsers.forEach((user) => {
        pendingBody.appendChild(buildPendingRow(user, loadUsers));
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

  connectBtn.addEventListener('click', async function () {
    adminKey = String(adminKeyEl.value || '').trim();
    if (!adminKey) {
      setStatus('Enter your admin password.', true);
      return;
    }
    refreshBtn.disabled = false;

    try {
      setStatus('Connecting...', false);
      await loadUsers();
      setStatus('Connected. Review data loaded.', false);
    } catch (error) {
      setStatus(error.message || 'Connection failed.', true);
    }
  });

  refreshBtn.addEventListener('click', async function () {
    try {
      setStatus('Refreshing review data...', false);
      await loadUsers();
      setStatus('Review data refreshed.', false);
    } catch (error) {
      setStatus(error.message || 'Refresh failed.', true);
    }
  });

  if (!api) {
    setStatus('Auth client failed to load.', true);
    return;
  }

  apiBaseEl.textContent = api.getApiBase() || 'same origin';
})();
