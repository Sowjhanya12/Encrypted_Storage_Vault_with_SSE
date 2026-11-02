/*
 * web/main.js -- browser UI logic.
 *
 * Section 03's "Browser UI: thin shell, no crypto" is enforced here by
 * what this file does NOT do: it never touches a key, never derives
 * anything, never talks to the cloud (port 5001) directly. Every request
 * goes to THIS page's own origin (client_app.py) as a fetch() to /api/*.
 * All cryptography happens server-side, in the trusted client process.
 *
 * Every value derived from user input (filenames, usernames, file
 * contents) is inserted with textContent via h() -- never innerHTML --
 * so a hostile filename cannot inject markup or script.
 */
'use strict';

const state = { session: null, csrf: null };

// ---------------------------------------------------------------------------
// DOM + formatting helpers
// ---------------------------------------------------------------------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

const $ = (sel, root = document) => root.querySelector(sel);

function fmtBytes(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function shortId(id, n = 10) {
  if (!id) return '—';
  return id.length > n ? id.slice(0, n) + '…' : id;
}

function spaced(hex) {
  return (hex || '').replace(/(..)(?!$)/g, '$1 ');
}

// nonce | ciphertext | tag, colour-coded consistently across all views
function segHex(nonceHex, ctHex, tagHex, truncated, tall) {
  return h('pre', { class: 'hex' + (tall ? ' tall' : '') },
    h('span', { class: 'n', text: spaced(nonceHex) }), ' ',
    h('span', { class: 'c', text: spaced(ctHex) + (truncated ? ' …' : '') }), ' ',
    h('span', { class: 't', text: spaced(tagHex) }));
}

function legend() {
  return h('div', { class: 'legend' },
    h('span', { class: 'l-n', text: 'nonce (12 B)' }),
    h('span', { class: 'l-c', text: 'ciphertext' }),
    h('span', { class: 'l-t', text: 'GCM tag (16 B)' }));
}

function stat(k, v, s, cls) {
  return h('div', { class: 'stat' + (cls ? ' ' + cls : '') },
    h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v }), s ? h('div', { class: 's', text: s }) : null);
}

function card(title, ...body) {
  return h('section', { class: 'card' }, title ? h('div', { class: 'card-head' }, h('h3', { text: title })) : null, ...body);
}

function emptyState(icon, title, text, action) {
  return h('div', { class: 'empty' }, h('div', { class: 'big', text: icon }), h('h4', { text: title }),
    h('p', { class: 'hint', text }), action ? h('div', { class: 'section-gap' }, action) : null);
}

function loading(text = 'Loading…') {
  return h('div', { class: 'loading-block' }, h('span', { class: 'spinner' }), ' ', text);
}

function errorBox(msg) {
  return h('div', { class: 'callout red' }, h('b', { text: 'Error: ' }), msg);
}

function toast(msg, kind = 'info', ms = 4500) {
  const el = h('div', { class: 'toast ' + kind, text: msg });
  $('#toasts').append(el);
  setTimeout(() => el.remove(), ms);
}

function table(headers, rows) {
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, headers.map(x => h('th', { text: x })))),
    h('tbody', null, rows)));
}

// ---------------------------------------------------------------------------
// modal + confirm
// ---------------------------------------------------------------------------

function openModal(title, body, buttons = [], narrow = false) {
  const root = $('#modalRoot');
  const close = () => { root.replaceChildren(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  const overlay = h('div', { class: 'overlay', onclick: (e) => { if (e.target === overlay) close(); } },
    h('div', { class: 'modal' + (narrow ? ' narrow' : ''), role: 'dialog', 'aria-modal': 'true' },
      h('div', { class: 'modal-head' }, h('h3', { text: title }), h('span', { class: 'spacer' }),
        h('button', { class: 'btn ghost icon-only', 'aria-label': 'Close', onclick: close, text: '×' })),
      h('div', { class: 'modal-body' }, body),
      buttons.length ? h('div', { class: 'modal-foot' }, buttons.map(b => {
        const btn = h('button', { class: 'btn ' + (b.cls || ''), text: b.label });
        btn.addEventListener('click', () => b.onclick(close, btn));
        return btn;
      })) : null));
  root.replaceChildren(overlay);
  return close;
}

function confirmDialog(title, message, confirmLabel = 'Confirm', danger = true) {
  return new Promise((resolve) => {
    const close = openModal(title, h('p', { text: message }), [
      { label: 'Cancel', cls: 'ghost', onclick: (c) => { c(); resolve(false); } },
      { label: confirmLabel, cls: danger ? 'danger solid' : 'primary', onclick: (c) => { c(); resolve(true); } },
    ], true);
    void close;
  });
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body, isForm) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET' && state.csrf) opts.headers['X-CSRF-Token'] = state.csrf;
  if (body !== undefined) {
    if (isForm) opts.body = body;
    else { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  }
  let resp;
  try {
    resp = await fetch(path, opts);
  } catch (e) {
    throw new ApiError(0, 'cannot reach the trusted client -- is client_app.py running?');
  }
  let data = null;
  try { data = await resp.json(); } catch (e) { /* no JSON body */ }
  if (!resp.ok) {
    const msg = (data && data.error) || `request failed (${resp.status})`;
    if (resp.status === 401 && /authentication required/.test(msg) && state.session) {
      sessionLost('Your session has ended (logged out or expired). Please log in again.');
    }
    throw new ApiError(resp.status, msg);
  }
  return data;
}

async function refreshSession() {
  const s = await api('GET', '/api/session');
  state.session = s.authenticated ? s : null;
  state.csrf = s.authenticated ? s.csrf_token : null;
  return s;
}

function sessionLost(message) {
  state.session = null;
  state.csrf = null;
  $('#modalRoot').replaceChildren();
  showAuth(message, 'error');
}

// ---------------------------------------------------------------------------
// auth screen
// ---------------------------------------------------------------------------

function setAuthStatus(msg, kind) {
  const el = $('#authStatus');
  el.textContent = msg || '';
  el.className = 'status-line' + (kind ? ' ' + kind : '');
}

function selectAuthTab(name) {
  document.querySelectorAll('[data-auth-tab]').forEach(b => b.classList.toggle('active', b.dataset.authTab === name));
  document.querySelectorAll('.auth-pane').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== name));
  setAuthStatus('');
}

async function showAuth(message, kind) {
  $('#appShell').classList.add('hidden');
  $('#authScreen').classList.remove('hidden');
  try {
    const s = await api('GET', '/api/session');
    $('#setupTabBtn').classList.toggle('hidden', !!s.admin_exists);
    $('#registerTabBtn').classList.toggle('hidden', s.registration_open === false);
  } catch (e) { /* show the form anyway */ }
  selectAuthTab('login');
  if (message) setAuthStatus(message, kind);
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function withBusy(btn, label, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try { return await fn(); } finally { btn.disabled = false; btn.textContent = old; }
}

function initAuthForms() {
  document.querySelectorAll('[data-auth-tab]').forEach(b => b.addEventListener('click', () => selectAuthTab(b.dataset.authTab)));

  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = formData(e.target);
    await withBusy(e.submitter || $('#loginForm button'), 'Logging in…', async () => {
      try {
        await api('POST', '/api/auth/login', { username: f.username, password: f.password });
        e.target.reset();
        await enterApp();
      } catch (err) { setAuthStatus(err.message, 'error'); }
    });
  });

  $('#registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = formData(e.target);
    if (f.password !== f.confirm) { setAuthStatus('The two passwords do not match.', 'error'); return; }
    await withBusy(e.submitter || $('#registerForm button'), 'Creating…', async () => {
      try {
        await api('POST', '/api/auth/register', { username: f.username, password: f.password });
        await api('POST', '/api/auth/login', { username: f.username, password: f.password });
        e.target.reset();
        toast('Account created. Next: choose your vault passphrase.', 'success');
        await enterApp();
      } catch (err) { setAuthStatus(err.message, 'error'); }
    });
  });

  $('#setupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = formData(e.target);
    await withBusy(e.submitter || $('#setupForm button'), 'Creating…', async () => {
      try {
        await api('POST', '/api/setup/admin', f);
        e.target.reset();
        $('#setupTabBtn').classList.add('hidden');
        selectAuthTab('login');
        setAuthStatus('Administrator created. Log in with the new credentials.', 'success');
      } catch (err) { setAuthStatus(err.message, 'error'); }
    });
  });
}

// ---------------------------------------------------------------------------
// shell, navigation, routing
// ---------------------------------------------------------------------------

const USER_ROUTES = [
  { section: 'Vault' },
  { id: 'dashboard', title: 'Dashboard', icon: '◧', render: renderDashboard },
  { id: 'files', title: 'My Files', icon: '▤', render: renderFiles },
  { id: 'upload', title: 'Upload File', icon: '⇪', render: renderUpload },
  { id: 'search', title: 'Search Files', icon: '⌕', render: renderSearch },
  { section: 'Demonstrations' },
  { id: 'lab', title: 'Encryption Transparency Lab', icon: '⇄', render: renderLab },
  { id: 'inspector', title: 'Cloud Storage Inspector', icon: '☁', render: renderInspector },
  { section: 'Account' },
  { id: 'activity', title: 'Activity History', icon: '☰', render: renderActivity },
  { id: 'system', title: 'Security & System', icon: '⚙', render: renderSystem },
];

const ADMIN_ROUTES = [
  { section: 'Administration' },
  { id: 'admin', title: 'Admin Dashboard', icon: '◧', render: renderAdminOverview },
  { id: 'accounts', title: 'Accounts', icon: '☺', render: renderAdminUsers },
  { id: 'audit', title: 'Audit Log', icon: '☰', render: renderAdminAudit },
  { id: 'admin-inspector', title: 'Cloud Storage Inspector', icon: '☁', render: renderAdminInspector },
  { section: 'System' },
  { id: 'system', title: 'Security & System', icon: '⚙', render: renderSystem },
];

const isAdmin = () => state.session && state.session.user.role === 'admin';
const routes = () => (isAdmin() ? ADMIN_ROUTES : USER_ROUTES).filter(r => r.id);

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [id, qs] = raw.split('?');
  return { id, params: new URLSearchParams(qs || '') };
}

function go(id, params) {
  const q = params ? '?' + new URLSearchParams(params).toString() : '';
  const target = `#/${id}${q}`;
  if (location.hash === target) render();
  else location.hash = target;
}

function buildNav() {
  const nav = $('#nav');
  nav.replaceChildren();
  for (const r of isAdmin() ? ADMIN_ROUTES : USER_ROUTES) {
    if (r.section) { nav.append(h('div', { class: 'nav-section', text: r.section })); continue; }
    nav.append(h('a', { href: `#/${r.id}`, 'data-route': r.id },
      h('span', { class: 'ico', text: r.icon }), h('span', { text: r.title })));
  }
}

function updateTopbar() {
  const s = state.session;
  $('#whoName').textContent = s.user.username;
  const role = $('#whoRole');
  role.textContent = s.user.role === 'admin' ? 'administrator' : 'user';
  role.className = 'badge ' + (s.user.role === 'admin' ? 'violet' : 'blue');
  const pill = $('#vaultPill');
  const lockBtn = $('#lockBtn');
  if (s.user.role === 'admin') {
    pill.className = 'pill admin';
    pill.textContent = 'No vault · metadata only';
    lockBtn.classList.add('hidden');
  } else if (s.unlocked) {
    pill.className = 'pill unlocked';
    pill.textContent = '● Vault unlocked';
    lockBtn.classList.remove('hidden');
  } else {
    pill.className = 'pill locked';
    pill.textContent = '● Vault locked';
    lockBtn.classList.add('hidden');
  }
}

let renderSeq = 0;
async function render() {
  if (!state.session) return;
  const { id, params } = parseHash();
  const list = routes();
  const route = list.find(r => r.id === id);
  if (!route) { location.replace(`#/${list[0].id}`); return; }
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.route === route.id));
  $('#viewTitle').textContent = route.title;
  $('#sidebar').classList.remove('open');
  updateTopbar();
  const seq = ++renderSeq;
  const view = $('#view');
  const container = h('div');
  view.replaceChildren(loading());
  try {
    await route.render(container, params);
    if (seq === renderSeq) view.replaceChildren(container);
  } catch (err) {
    if (seq === renderSeq) view.replaceChildren(errorBox(err.message));
  }
}

async function enterApp() {
  await refreshSession();
  if (!state.session) { showAuth(); return; }
  $('#authScreen').classList.add('hidden');
  $('#appShell').classList.remove('hidden');
  buildNav();
  const { id } = parseHash();
  if (!routes().find(r => r.id === id)) location.replace(`#/${routes()[0].id}`);
  await render();
}

function initShell() {
  $('#clientPort').textContent = location.port || (location.protocol === 'https:' ? '443' : '80');
  window.addEventListener('hashchange', render);
  $('#menuBtn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#logoutBtn').addEventListener('click', async () => {
    try { await api('POST', '/api/auth/logout'); } catch (e) { /* already gone */ }
    state.session = null; state.csrf = null;
    showAuth('Logged out. Your vault keys were wiped from the trusted client.', 'success');
  });
  $('#lockBtn').addEventListener('click', async () => {
    try {
      await api('POST', '/api/lock');
      await refreshSession();
      toast('Vault locked -- keys wiped from this session.', 'success');
      render();
    } catch (e) { toast(e.message, 'error'); }
  });
  $('#themeBtn').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('vaultTheme', next); } catch (e) { /* ignore */ }
  });
}

// ---------------------------------------------------------------------------
// vault unlock gate
// ---------------------------------------------------------------------------

async function unlockGate(container) {
  if (state.session.unlocked) return true;
  let dash = null;
  try { dash = await api('GET', '/api/dashboard'); } catch (e) { /* fall back to generic form */ }
  const initialized = !dash || dash.vault_initialized;
  const status = h('p', { class: 'status-line', 'aria-live': 'polite' });
  const pw = h('input', { type: 'password', placeholder: 'Vault passphrase', autocomplete: 'current-password', required: true });
  const pw2 = initialized ? null : h('input', { type: 'password', placeholder: 'Confirm vault passphrase', autocomplete: 'new-password', required: true });
  const btn = h('button', { class: 'btn primary', type: 'submit', text: initialized ? 'Unlock vault' : 'Create & unlock vault' });
  const form = h('form', { class: 'stack' }, pw, pw2, btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (pw2 && pw.value !== pw2.value) { status.textContent = 'Passphrases do not match.'; status.className = 'status-line error'; return; }
    await withBusy(btn, 'Deriving keys…', async () => {
      status.textContent = 'Running Argon2id (64 MiB, 3 passes) then HKDF in the trusted client -- this delay is deliberate.';
      status.className = 'status-line loading';
      try {
        await api('POST', '/api/unlock', { password: pw.value });
        pw.value = '';
        await refreshSession();
        toast('Vault unlocked.', 'success');
        render();
      } catch (err) { status.textContent = err.message; status.className = 'status-line error'; }
    });
  });

  container.append(h('div', { class: 'grid two' },
    card(initialized ? 'Unlock your vault' : 'Create your vault passphrase',
      h('p', { class: 'hint', text: initialized
        ? 'Your vault is locked. Enter your vault passphrase (separate from your account password). The trusted client derives K_file and K_index from it with Argon2id + HKDF; they stay in this server-side session only.'
        : 'This is your first unlock. The passphrase you choose derives your vault keys. It is never stored anywhere -- if you forget it, your files cannot be recovered, not even by an administrator.' }),
      h('div', { class: 'section-gap' }, form), status),
    card('Available while locked',
      h('p', { class: 'hint', text: 'You can still open the Cloud Storage Inspector and your Activity History: they show only what the cloud stores and what the audit log recorded -- no key is needed for either.' }),
      h('div', { class: 'row section-gap' },
        h('button', { class: 'btn', text: 'Open Cloud Inspector', onclick: () => go('inspector') }),
        h('button', { class: 'btn ghost', text: 'Activity History', onclick: () => go('activity') })))));

  if (!initialized) {
    try {
      const legacy = await api('GET', '/api/vault/legacy');
      if (legacy.available) container.append(legacyCard(legacy));
    } catch (e) { /* optional */ }
  }
  return false;
}

function legacyCard(legacy) {
  const pw = h('input', { type: 'password', placeholder: 'Legacy vault passphrase', required: true });
  const btn = h('button', { class: 'btn', type: 'submit', text: 'Migrate legacy vault into my account' });
  const status = h('p', { class: 'status-line' });
  const form = h('form', { class: 'row' }, pw, btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(btn, 'Verifying…', async () => {
      try {
        const r = await api('POST', '/api/vault/adopt-legacy', { password: pw.value });
        toast(`Legacy vault migrated (${r.moved.documents} document(s)). Unlock with the legacy passphrase.`, 'success');
        render();
      } catch (err) { status.textContent = err.message; status.className = 'status-line error'; }
    });
  });
  return card('Migrate the pre-multi-user vault',
    h('p', { class: 'hint', text: `A single-user vault from before accounts existed holds ${legacy.documents} encrypted document(s). Prove you know its passphrase to move it into your (still empty) vault. Rows are only re-labelled -- nothing is decrypted, re-encrypted or deleted.` }),
    h('div', { class: 'section-gap' }, form), status);
}

// ---------------------------------------------------------------------------
// shared event table
// ---------------------------------------------------------------------------

const EVENT_LABELS = {
  register: 'Account registered', login: 'Login', login_failed: 'Login failed', login_throttled: 'Login throttled',
  logout: 'Logout', session_expired: 'Session expired', vault_initialized: 'Vault created', vault_unlock: 'Vault unlocked',
  vault_unlock_failed: 'Vault unlock failed', vault_lock: 'Vault locked', vault_passphrase_change: 'Passphrase changed',
  upload: 'Upload', view: 'View', download: 'Download', delete: 'Delete', search: 'Search',
  decryption_failed: 'Decryption failed', tamper_demo: 'Tamper test', transparency_view: 'Transparency Lab',
  cloud_inspector_view: 'Cloud inspection', access_denied: 'Access denied', account_status_changed: 'Account status changed',
  admin_bootstrap: 'Admin setup', legacy_vault_adopted: 'Legacy vault migrated',
};

function outcomeBadge(e) {
  const o = e.outcome;
  let cls = 'green';
  if (['failure', 'denied', 'ACCEPTED'].includes(o)) cls = 'red';
  else if (['rejected', 'expired'].includes(o)) cls = 'amber';
  if (e.event_type === 'tamper_demo' && o === 'rejected') cls = 'green';
  return h('span', { class: 'badge ' + cls, text: o });
}

function eventsTable(events, showActor) {
  if (!events.length) return emptyState('☰', 'No events yet', 'Events appear here as soon as they happen.');
  const headers = ['Time', ...(showActor ? ['Actor'] : []), 'Event', 'Outcome', 'Target', 'Detail'];
  return table(headers, events.map(e => h('tr', null,
    h('td', { class: 'small', text: fmtDate(e.ts) }),
    showActor ? h('td', { text: e.actor_username || '(unknown)' }) : null,
    h('td', null, EVENT_LABELS[e.event_type] || e.event_type, e.is_demo ? h('span', { class: 'badge violet', text: 'demo' }) : null),
    h('td', null, outcomeBadge(e)),
    h('td', { class: 'idcell', text: e.target ? shortId(e.target, 14) : '—', title: e.target || '' }),
    h('td', { class: 'small muted', text: e.detail || '' }))));
}

// ---------------------------------------------------------------------------
// user views
// ---------------------------------------------------------------------------

async function renderDashboard(c) {
  const d = await api('GET', '/api/dashboard');
  const u = state.session.user;
  c.append(h('div', { class: 'callout teal' },
    'Signed in as ', h('b', { text: u.username }), ' (regular user). Access scope: ', h('b', { text: 'only your own vault' }),
    ' — cloud namespace ', h('code', { text: shortId(u.vault_id, 12) }), '. Other users\' files are in separate namespaces under keys you never hold.'));
  if (!d.unlocked) {
    c.append(h('div', { class: 'section-gap' }));
    const gate = h('div');
    await unlockGate(gate);
    c.append(gate);
  }
  const sec = d.counts.decryption_failures + d.counts.unlock_failures + d.counts.login_failures;
  c.append(h('div', { class: 'stats section-gap' },
    stat('Encrypted files', String(d.storage.documents), 'in your cloud vault'),
    stat('Ciphertext stored', fmtBytes(d.storage.ciphertext_bytes), `+ ${fmtBytes(d.storage.enc_name_bytes)} encrypted names`),
    stat('Index entries', String(d.storage.index_entries), '(keyword, file) pairs'),
    stat('Searches', String(d.counts.searches), 'encrypted queries run'),
    stat('Downloads / views', `${d.counts.downloads} / ${d.counts.views}`),
    stat('Security events', String(sec), 'failed unlocks, logins, decrypts', sec ? 'warn' : 'good')));

  const recent = d.unlocked
    ? (d.recent_uploads.length
      ? table(['File', 'Size', 'Uploaded'], d.recent_uploads.map(f => h('tr', null,
        h('td', { class: 'fname', text: f.filename }), h('td', { text: fmtBytes(f.size) }), h('td', { class: 'small', text: fmtDate(f.uploaded_at) }))))
      : emptyState('⇪', 'No files yet', 'Upload a file to see it encrypted.', h('button', { class: 'btn primary', text: 'Upload a file', onclick: () => go('upload') })))
    : h('p', { class: 'hint', text: 'Unlock your vault to see decrypted file names.' });

  c.append(h('div', { class: 'grid two' },
    card('Recent uploads', recent),
    card('Encryption status',
      h('dl', { class: 'kv' },
        h('dt', { text: 'Vault' }), h('dd', null, h('span', { class: 'badge ' + (d.unlocked ? 'green' : 'amber'), text: d.unlocked ? 'unlocked (keys in session memory)' : 'locked (no keys in memory)' })),
        h('dt', { text: 'Initialised' }), h('dd', { text: d.vault_initialized ? 'yes — salt + verifier stored in cloud meta' : 'no — choose a passphrase on first unlock' }),
        h('dt', { text: 'File encryption' }), h('dd', { text: 'AES-256-GCM, fresh 96-bit nonce per file and per filename' }),
        h('dt', { text: 'Key derivation' }), h('dd', { text: 'Argon2id → master key → HKDF-SHA256 → K_file, K_index' }),
        h('dt', { text: 'Search index' }), h('dd', { text: 'HMAC-SHA256 labels, AES-GCM-encrypted values' }),
        h('dt', { text: 'Last upload' }), h('dd', { text: fmtDate(d.storage.last_upload_at) })))));

  c.append(h('div', { class: 'grid two section-gap' },
    card('Recent activity', eventsTable(d.recent_activity, false)),
    card('Security events', d.security_events.length ? eventsTable(d.security_events, false)
      : emptyState('✓', 'No security events', 'No failed logins, failed unlocks, rejected decryptions or tamper tests on your account.'))));
}

function viewDocument(doc) {
  const body = h('div', null, loading('Decrypting in the trusted client…'));
  const close = openModal(doc.filename, body, [
    { label: 'Download', cls: 'primary', onclick: () => downloadDoc(doc.doc_id) },
    { label: 'Open in Transparency Lab', onclick: (cl) => { cl(); go('lab', { doc: doc.doc_id }); } },
  ]);
  void close;
  api('GET', `/api/documents/${encodeURIComponent(doc.doc_id)}`).then(d => {
    if (d.is_pdf) {
      body.replaceChildren(h('iframe', { src: `/api/documents/${encodeURIComponent(doc.doc_id)}/download?inline=1`, title: 'PDF preview' }));
    } else if (d.is_zip) {
      body.replaceChildren(h('div', { class: 'callout' }, 'ZIP archive — decrypted successfully. Download it to open its contents.'));
    } else if (d.content !== null) {
      body.replaceChildren(h('div', { class: 'callout green' }, 'AES-GCM tag verified; decrypted with K_file in the trusted client.'),
        h('div', { class: 'section-gap' }, h('pre', { class: 'plain', text: d.content })));
    } else {
      body.replaceChildren(h('p', { class: 'hint', text: 'Binary content — no preview. Use Download.' }));
    }
  }).catch(err => body.replaceChildren(errorBox(err.message)));
}

function downloadDoc(docId) {
  const a = h('a', { href: `/api/documents/${encodeURIComponent(docId)}/download`, download: '' });
  document.body.append(a);
  a.click();
  a.remove();
}

async function deleteDoc(doc, after) {
  const ok = await confirmDialog('Delete file?',
    `"${doc.filename}" will be removed from cloud storage and from the encrypted search index. This cannot be undone.`, 'Delete');
  if (!ok) return;
  try {
    await api('DELETE', `/api/documents/${encodeURIComponent(doc.doc_id)}`);
    toast(`Deleted ${doc.filename}`, 'success');
    after();
  } catch (e) { toast(e.message, 'error'); }
}

async function renderFiles(c) {
  if (!(await unlockGate(c))) return;
  const docs = await api('GET', '/api/documents');
  const filter = h('input', { type: 'search', placeholder: 'Filter by name (local, decrypted names)…' });
  const body = h('div');
  const draw = () => {
    const q = filter.value.toLowerCase();
    const list = docs.filter(d => d.filename.toLowerCase().includes(q))
      .sort((a, b) => (b.uploaded_at || '').localeCompare(a.uploaded_at || ''));
    if (!docs.length) {
      body.replaceChildren(emptyState('▤', 'Your vault is empty', 'Files you upload are encrypted before they reach the cloud.',
        h('button', { class: 'btn primary', text: 'Upload a file', onclick: () => go('upload') })));
      return;
    }
    if (!list.length) { body.replaceChildren(emptyState('⌕', 'No match', 'No file name contains that text.')); return; }
    body.replaceChildren(table(['Name', 'Size (ciphertext)', 'Uploaded', 'Encryption', ''], list.map(d => {
      const bad = d.filename.startsWith('<undecryptable');
      return h('tr', null,
        h('td', null, h('div', { class: 'fname', text: d.filename }), h('div', { class: 'idcell small', text: 'id ' + shortId(d.doc_id, 16) })),
        h('td', { text: fmtBytes(d.size) }),
        h('td', { class: 'small', text: fmtDate(d.uploaded_at) }),
        h('td', null, h('span', { class: 'badge ' + (bad ? 'red' : 'green'), text: bad ? 'name tag check failed' : 'AES-256-GCM · verified' })),
        h('td', { class: 'actions' },
          h('button', { class: 'btn small', text: 'View', onclick: () => viewDocument(d) }),
          h('button', { class: 'btn small', text: 'Download', onclick: () => downloadDoc(d.doc_id) }),
          h('button', { class: 'btn small', text: 'Lab', title: 'Compare with cloud ciphertext', onclick: () => go('lab', { doc: d.doc_id }) }),
          h('button', { class: 'btn small danger', text: 'Delete', onclick: () => deleteDoc(d, render) })));
    })));
  };
  filter.addEventListener('input', draw);
  draw();
  c.append(card(null,
    h('div', { class: 'card-head' }, h('h3', { text: `${docs.length} file(s)` }), h('span', { class: 'spacer' }),
      h('button', { class: 'btn primary small', text: '+ Upload', onclick: () => go('upload') })),
    h('div', { class: 'row' }, filter), h('div', { class: 'section-gap' }, body),
    h('p', { class: 'hint section-gap', text: 'Names are decrypted here, in the trusted client, using K_file. The cloud stores only encrypted name blobs and opaque random ids.' })));
}

async function renderUpload(c) {
  if (!(await unlockGate(c))) return;
  const input = h('input', { type: 'file', class: 'hidden', accept: '.txt,.md,.csv,.json,.pdf,.zip,text/*,application/pdf,application/zip' });
  const chosen = h('p', { class: 'hint', text: 'No file selected.' });
  const zone = h('div', { class: 'dropzone', tabindex: '0', role: 'button' },
    h('div', { class: 'big', text: '⇪' }), h('h4', { text: 'Drop a file here, or click to choose' }),
    h('p', { class: 'hint', text: 'UTF-8 text, PDF (with a text layer) or ZIP of those · max 16 MB' }));
  const btn = h('button', { class: 'btn primary', text: 'Encrypt & upload', disabled: true });
  const bar = h('i');
  const progress = h('div', { class: 'progress hidden' }, bar);
  const stagesEl = h('ol', { class: 'stages hidden' });
  const result = h('div');
  let file = null;

  const pick = (f, keepResult) => {
    file = f || null;
    chosen.textContent = file ? `${file.name} — ${fmtBytes(file.size)}` : 'No file selected.';
    btn.disabled = !file;
    if (!keepResult) result.replaceChildren();
  };
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('change', () => pick(input.files[0]));
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('drag'); pick(e.dataTransfer.files[0]); });

  const STAGES = [
    'Sending the file to the trusted client (this machine, localhost)',
    'Trusted client encrypts content + filename with AES-256-GCM (K_file, fresh nonces)',
    'Ciphertext pushed to the cloud; encrypted search index rebuilt (HMAC labels, AES-GCM values)',
  ];
  const setStage = (i, failed) => {
    stagesEl.replaceChildren(...STAGES.map((s, j) => h('li', {
      class: failed && j === i ? 'fail' : j < i ? 'done' : j === i ? 'active' : '',
      text: (j < i ? '✓ ' : failed && j === i ? '✗ ' : j === i ? '… ' : '○ ') + s,
    })));
  };

  btn.addEventListener('click', () => {
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/documents');
    xhr.setRequestHeader('X-CSRF-Token', state.csrf);
    btn.disabled = true;
    progress.classList.remove('hidden', 'indeterminate');
    stagesEl.classList.remove('hidden');
    bar.style.width = '0%';
    setStage(0);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) bar.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
    };
    xhr.upload.onload = () => { setStage(1); progress.classList.add('indeterminate'); };
    xhr.onerror = () => { setStage(0, true); progress.classList.add('hidden'); toast('Upload failed: trusted client unreachable', 'error'); btn.disabled = false; };
    xhr.onload = () => {
      progress.classList.remove('indeterminate');
      progress.classList.add('hidden');
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* none */ }
      if (xhr.status === 201) {
        setStage(3);
        toast(`${data.filename} encrypted and stored`, 'success');
        result.replaceChildren(h('div', { class: 'callout green section-gap' },
          h('b', { text: data.filename }), ' is now stored in the cloud only as ciphertext (id ', h('code', { text: shortId(data.doc_id, 16) }), ').',
          h('div', { class: 'row section-gap' },
            h('button', { class: 'btn primary small', text: 'Compare plaintext vs ciphertext', onclick: () => go('lab', { doc: data.doc_id }) }),
            h('button', { class: 'btn small', text: 'Go to My Files', onclick: () => go('files') }))));
        pick(null, true);
        input.value = '';
      } else {
        setStage(xhr.status === 401 && /authentication/.test(data.error || '') ? 0 : 1, true);
        if (xhr.status === 401 && /authentication/.test(data.error || '')) sessionLost('Your session has ended. Please log in again.');
        result.replaceChildren(errorBox(data.error || `upload failed (${xhr.status})`));
        btn.disabled = false;
      }
    };
    xhr.send(fd);
  });

  c.append(h('div', { class: 'grid two' },
    card('Upload a file', zone, input, h('div', { class: 'row section-gap' }, chosen, h('span', { class: 'spacer' }), btn), progress, stagesEl, result),
    card('What happens to your file',
      h('ol', { class: 'stages' },
        h('li', { text: '1. Bytes go from this browser to the trusted client (client_app.py) on this machine.' }),
        h('li', { text: '2. The trusted Python process encrypts the content and the filename separately with AES-256-GCM under your K_file.' }),
        h('li', { text: '3. Only nonce, ciphertext and tag (plus the encrypted name) are sent to the cloud under a random document id.' }),
        h('li', { text: '4. Keywords are extracted locally and the encrypted search index is rebuilt: HMAC-SHA256 labels, AES-GCM-encrypted document ids.' })),
      h('div', { class: 'callout amber section-gap' }, 'Encryption happens in the trusted Python client process, not in this browser. The cloud never receives the plaintext, the filename, any keyword, or any key.'))));
}

async function renderSearch(c, params) {
  if (!(await unlockGate(c))) return;
  const input = h('input', { type: 'search', placeholder: 'e.g. budget  or  quarterly report (AND)', required: true, value: params.get('q') || '' });
  const btn = h('button', { class: 'btn primary', type: 'submit', text: 'Search encrypted index' });
  const out = h('div');
  const form = h('form', { class: 'row' }, input, btn);
  const run = async () => {
    const q = input.value.trim();
    if (!q) return;
    await withBusy(btn, 'Searching…', async () => {
      out.replaceChildren(loading('Generating tokens and querying the cloud…'));
      try {
        const r = await api('POST', '/api/search', { query: q });
        out.replaceChildren(searchPipeline(q, r));
      } catch (err) { out.replaceChildren(errorBox(err.message)); }
    });
  };
  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
  c.append(card('Search your encrypted files', h('p', { class: 'hint', text: 'Keywords are turned into opaque HMAC tokens in the trusted client. Several keywords mean AND. Matching is exact-keyword (no stemming or substrings).' }),
    h('div', { class: 'section-gap' }, form)), h('div', { class: 'section-gap' }, out));
  if (input.value) run();
}

function pstep(n, kind, title, tag, ...body) {
  return h('div', { class: 'pstep ' + kind }, h('div', { class: 'pnum', text: String(n) }),
    h('div', { class: 'pbody' }, h('h4', null, title, tag), ...body));
}

const WHERE = {
  client: () => h('span', { class: 'badge teal', text: 'trusted client' }),
  cloud: () => h('span', { class: 'badge amber', text: 'untrusted cloud' }),
  wire: () => h('span', { class: 'badge blue', text: 'network → cloud' }),
};

function searchPipeline(q, r) {
  const t = r.trace;
  const steps = t.steps;
  const resultTable = r.results.length
    ? table(['File (decrypted name)', 'Document id', ''], r.results.map(x => h('tr', null,
      h('td', { class: 'fname', text: x.filename }), h('td', { class: 'idcell', text: shortId(x.doc_id, 16) }),
      h('td', { class: 'actions' },
        h('button', { class: 'btn small', text: 'View', onclick: () => viewDocument(x) }),
        h('button', { class: 'btn small', text: 'Download', onclick: () => downloadDoc(x.doc_id) }),
        h('button', { class: 'btn small', text: 'Lab', onclick: () => go('lab', { doc: x.doc_id }) })))))
    : emptyState('∅', 'No matching files', 'No document contains every keyword.');

  return h('div', null,
    card(`${r.results.length} result(s) for “${q}”`, resultTable),
    card('How this search ran — step by step (real values from this query)',
      h('div', { class: 'pipeline' },
        pstep(1, 'client', 'Query entered in the trusted client', WHERE.client(),
          h('p', null, 'Typed: ', h('code', { text: q }), ' → normalised with the same tokenizer used at upload (lowercase, alphanumeric tokens, stop-words removed):'),
          h('div', { class: 'row' }, r.keywords.map(k => h('span', { class: 'badge teal', text: k })))),
        pstep(2, 'client', 'Search token generated', WHERE.client(),
          h('p', { text: 'For each keyword w: token K1 = HMAC-SHA256(K_index, "1" ‖ w). Deterministic, so the same keyword always gives the same token; without K_index nobody can compute or invert it. K_index itself is never shown or sent.' }),
          steps.map(s => h('div', { class: 'section-gap' }, h('div', { class: 'field-label', text: `token for “${s.keyword}”` }), h('pre', { class: 'hex', text: spaced(s.token_hex) })))),
        pstep(3, 'wire', 'Request sent to the cloud', WHERE.wire(),
          h('p', { text: 'The literal request body: only the token (base64). No keyword, no filename, no key.' }),
          steps.map(s => h('pre', { class: 'hex', text: `${s.cloud_request.method} ${s.cloud_request.path}\n${JSON.stringify(s.cloud_request.body, null, 2)}` })),
          t.keywords_not_sent ? h('p', { class: 'small muted', text: `${t.keywords_not_sent} keyword(s) were never sent: the intersection was already empty.` }) : null),
        pstep(4, 'cloud', 'Cloud searches its encrypted index', WHERE.cloud(),
          h('p', { text: 'The cloud computes label_i = HMAC-SHA256(K1, i) for i = 0, 1, 2 … and looks each up in its sse_index table, stopping at the first miss. It never decrypts anything.' }),
          h('div', { class: 'row' }, steps.map(s => h('span', { class: 'badge amber', text: `${s.cloud_result_count} matching row(s)` })))),
        pstep(5, 'cloud', 'Encrypted results returned', WHERE.cloud(),
          h('p', { text: 'Each hit is an AES-GCM ciphertext of a document id (nonce ‖ ciphertext ‖ tag) — opaque to the cloud.' }),
          steps.map(s => s.encrypted_results.length
            ? h('pre', { class: 'hex', text: s.encrypted_results.map(v => `${v.hex}…  (${v.bytes} B)`).join('\n') })
            : h('p', { class: 'small muted', text: 'no rows returned' }))),
        pstep(6, 'client', 'Trusted client decrypts the results', WHERE.client(),
          h('p', { text: 'K2 = HMAC-SHA256(K_index, "2" ‖ w) is derived locally (never sent) and AES-GCM-decrypts each value into a document id. Multi-keyword AND is intersected here, on the client.' }),
          steps.map(s => h('div', { class: 'small' }, h('code', { text: s.keyword }), ' → ', s.decrypted_doc_ids.length ? s.decrypted_doc_ids.map(x => shortId(x)).join(', ') : '∅')),
          steps.length > 1 ? h('div', { class: 'small section-gap' }, 'Intersection → ', t.intersection.length ? t.intersection.map(x => shortId(x)).join(', ') : '∅') : null),
        pstep(7, 'client', 'Matching files shown', WHERE.client(),
          h('p', { text: 'Encrypted filenames for the matching ids are fetched and decrypted with K_file — the result table above.' })))),
    h('div', { class: 'grid two section-gap' },
      card('Roles of the primitives',
        h('dl', { class: 'kv' },
          h('dt', { text: 'HKDF-SHA256' }), h('dd', { text: 'Expands the Argon2id master key into independent K_file and K_index, so the search key and the file key never coincide.' }),
          h('dt', { text: 'HMAC-SHA256' }), h('dd', { text: 'PRF for deterministic tokens (K1, K2) and index labels. Determinism is what makes lookup possible.' }),
          h('dt', { text: 'AES-256-GCM' }), h('dd', { text: 'Protects each index value (a document id) and every file/filename; tampering is detected.' }))),
      card('What the cloud still learns (honest leakage)',
        h('ul', { class: 'small' },
          h('li', { text: 'Search pattern: repeating a keyword sends the identical token, so repeats are recognisable.' }),
          h('li', { text: 'Access pattern: how many rows match and which encrypted documents are fetched afterwards.' }),
          h('li', { text: 'For multi-keyword queries: that these tokens arrived together, and each one\'s match count.' }),
          h('li', { text: 'Sizes: ciphertext lengths, number of documents, total index size.' }),
          h('li', { text: 'No forward privacy: a captured token also matches files uploaded later.' })))));
}

// ---------------------------------------------------------------------------
// Encryption Transparency Lab
// ---------------------------------------------------------------------------

async function renderLab(c, params) {
  if (!(await unlockGate(c))) return;
  const docs = await api('GET', '/api/documents');
  const tab = params.get('tab') || 'compare';
  const tabs = h('div', { class: 'tabs' },
    h('button', { class: 'tab' + (tab === 'compare' ? ' active' : ''), text: 'Trusted client vs. cloud storage', onclick: () => go('lab', { tab: 'compare', doc: params.get('doc') || '' }) }),
    h('button', { class: 'tab' + (tab === 'tamper' ? ' active' : ''), text: 'Tamper detection test', onclick: () => go('lab', { tab: 'tamper' }) }));
  c.append(tabs);
  if (tab === 'tamper') { renderTamper(c, docs, params); return; }

  if (!docs.length) {
    c.append(emptyState('⇄', 'No files to compare', 'Upload a text file, then come back to see its plaintext beside the exact bytes the cloud stores.',
      h('button', { class: 'btn primary', text: 'Upload a file', onclick: () => go('upload') })));
    return;
  }
  const sorted = docs.slice().sort((a, b) => (b.uploaded_at || '').localeCompare(a.uploaded_at || ''));
  const current = params.get('doc') && docs.find(d => d.doc_id === params.get('doc')) ? params.get('doc') : sorted[0].doc_id;
  const select = h('select', null, sorted.map(d => h('option', { value: d.doc_id, selected: d.doc_id === current, text: `${d.filename}  (${fmtBytes(d.size)})` })));
  select.addEventListener('change', () => go('lab', { doc: select.value }));
  c.append(h('div', { class: 'callout amber' },
    h('b', { text: 'Trusted client vs. cloud storage. ' }),
    'Left: what the authorised uploader sees after the trusted Python client (client_app.py) decrypts the file. Right: the record exactly as the cloud API (port 5001) returns it. Encryption and decryption run in the trusted client process, not in this browser. Secret key bytes are never displayed.'),
  h('div', { class: 'row section-gap' }, h('b', { text: 'File:' }), select));

  const area = h('div', { class: 'section-gap' }, loading('Fetching the cloud record and decrypting…'));
  c.append(area);
  try {
    const d = await api('GET', `/api/transparency/${encodeURIComponent(current)}`);
    area.replaceChildren(labView(d));
  } catch (err) { area.replaceChildren(errorBox(err.message)); }
}

function flow(steps) {
  return h('div', { class: 'flow' }, steps.map(([kind, t, d]) => h('div', { class: 'flow-step ' + kind }, h('div', { class: 't', text: t }), h('div', { class: 'd', text: d }))));
}

function barRow(label, value, max, color) {
  const i = h('i', { class: color });
  i.style.width = `${max ? Math.max(1, (value / max) * 100) : 0}%`;
  return h('div', { class: 'bar-row' }, h('span', { text: label }), h('div', { class: 'bar' }, i), h('b', { text: `${value.toLocaleString()} B` }));
}

function labView(d) {
  const cl = d.client, cd = d.cloud, cmp = d.comparison;
  let preview;
  if (cl.kind === 'text') {
    preview = h('pre', { class: 'plain', text: cl.text_preview || '(empty file)' });
  } else {
    preview = h('div', { class: 'callout', text: `${cl.kind.toUpperCase()} file — decrypted successfully (${cl.size_bytes} bytes). Binary content is not shown as text; the hex below is the real decrypted prefix.` });
  }
  const max = cmp.stored_blob_bytes;

  const left = h('div', { class: 'side client' },
    h('div', { class: 'side-head' }, h('h3', { text: 'Authorised uploader · trusted client' }), h('span', { class: 'spacer' }), h('span', { class: 'badge teal', text: 'plaintext' })),
    h('div', { class: 'side-body' },
      h('dl', { class: 'kv' },
        h('dt', { text: 'Original filename' }), h('dd', { class: 'fname', text: cl.filename }),
        h('dt', { text: 'Original size' }), h('dd', { text: `${cl.size_bytes.toLocaleString()} bytes` }),
        h('dt', { text: 'Type' }), h('dd', { text: cl.kind }),
        h('dt', { text: 'SHA-256' }), h('dd', { class: 'mono small', text: cl.sha256 }),
        h('dt', { text: 'Encryption status' }), h('dd', null, h('span', { class: 'badge green', text: 'AES-256-GCM · tag verified on this read' })),
        h('dt', { text: 'Where it runs' }), h('dd', { text: 'Encrypted/decrypted in the trusted Python client process (client_app.py) with K_file' })),
      h('div', null, h('div', { class: 'field-label', text: 'Original content' + (cl.text_truncated ? ' (truncated preview)' : '') }), preview),
      h('div', null, h('div', { class: 'field-label', text: 'First 64 plaintext bytes (hex)' }), h('pre', { class: 'hex', text: spaced(cl.plaintext_hex) || '(empty)' }))));

  const right = h('div', { class: 'side cloud' },
    h('div', { class: 'side-head' }, h('h3', { text: 'Cloud storage · what is actually stored' }), h('span', { class: 'spacer' }), h('span', { class: 'badge amber', text: 'ciphertext' })),
    h('div', { class: 'side-body' },
      h('dl', { class: 'kv' },
        h('dt', { text: 'Document id' }), h('dd', { class: 'mono small', text: cd.doc_id }),
        h('dt', { text: 'Uploaded at' }), h('dd', { text: fmtDate(cd.uploaded_at) }),
        h('dt', { text: 'Size (cloud column)' }), h('dd', { text: `${cd.size.toLocaleString()} bytes of ciphertext` }),
        h('dt', { text: 'Record status' }), h('dd', null, h('span', { class: 'badge amber', text: 'opaque to the cloud — no key held' }))),
      h('div', null, h('div', { class: 'field-label', text: `Encrypted filename blob · enc_name column (${cd.enc_name.total_bytes} B)` }),
        segHex(cd.enc_name.nonce_hex, cd.enc_name.ciphertext_hex, cd.enc_name.tag_hex, cd.enc_name.ciphertext_truncated)),
      h('div', null, h('div', { class: 'field-label', text: `nonce column (${cd.content.nonce_bytes} B)` }), h('pre', { class: 'hex' }, h('span', { class: 'n', text: spaced(cd.content.nonce_hex) }))),
      h('div', null, h('div', { class: 'field-label', text: `ciphertext column (${cd.content.ciphertext_bytes.toLocaleString()} B${cd.content.ciphertext_truncated ? ', first 512 shown' : ''})` }),
        h('pre', { class: 'hex tall' }, h('span', { class: 'c', text: spaced(cd.content.ciphertext_hex) + (cd.content.ciphertext_truncated ? ' …' : '') || '(empty)' }))),
      h('div', null, h('div', { class: 'field-label', text: `tag column (${cd.content.tag_bytes} B)` }), h('pre', { class: 'hex' }, h('span', { class: 't', text: spaced(cd.content.tag_hex) }))),
      legend(),
      h('details', { class: 'raw' }, h('summary', { text: 'Raw JSON returned by the cloud API: GET /documents/<id> (base64 is only transport encoding)' }),
        h('pre', { class: 'hex tall', text: JSON.stringify(d.cloud_raw_response, null, 2) }))));

  return h('div', null,
    h('div', { class: 'field-label', text: 'Upload path' }),
    flow([
      ['client', 'Plaintext file', `${cmp.plaintext_bytes.toLocaleString()} B in the trusted client`],
      ['client', 'AES-256-GCM encrypt', 'K_file + fresh random 96-bit nonce'],
      ['client', 'nonce ‖ ciphertext ‖ tag', `${cmp.stored_blob_bytes.toLocaleString()} B (+${cmp.overhead_bytes} B)`],
      ['cloud', 'Cloud documents table', 'stored as separate nonce / ciphertext / tag columns'],
    ]),
    h('div', { class: 'lab-cols' }, left, right),
    h('div', { class: 'grid two section-gap' },
      card('Byte-size comparison (real values)',
        h('div', { class: 'bars' },
          barRow('Plaintext content', cmp.plaintext_bytes, max, 'teal'),
          barRow('Stored ciphertext', cmp.ciphertext_bytes, max, 'orange'),
          barRow('Stored blob (+nonce+tag)', cmp.stored_blob_bytes, max, 'amber'),
          barRow('Filename plaintext', cmp.filename_plaintext_bytes, max, 'teal'),
          barRow('Encrypted filename blob', cmp.filename_blob_bytes, max, 'amber')),
        h('p', { class: 'hint section-gap', text: 'GCM is a stream mode: ciphertext length equals plaintext length, so the cloud learns the file size. The fixed overhead is the 12-byte nonce plus the 16-byte authentication tag.' }),
        h('div', { class: 'callout ' + (cmp.plaintext_prefix_found_in_ciphertext ? 'red' : 'green') + ' section-gap',
          text: cmp.plaintext_prefix_found_in_ciphertext
            ? 'Warning: the first 32 plaintext bytes appear in the stored ciphertext.'
            : 'Checked: the first 32 plaintext bytes do not appear anywhere in the stored ciphertext.' })),
      card('Keys involved (names only — secret bytes are never displayed)',
        h('div', { class: 'keylist' },
          h('div', { class: 'keyitem' }, h('code', { text: 'Master key' }), h('span', { text: 'Argon2id(vault passphrase, per-vault salt). Never stored; expanded by HKDF.' }), h('span', { class: 'badge', text: 'memory only' })),
          h('div', { class: 'keyitem' }, h('code', { text: 'K_file' }), h('span', { text: 'AES-256-GCM key for file contents and filenames (this file).' }), h('span', { class: 'badge', text: 'memory only' })),
          h('div', { class: 'keyitem' }, h('code', { text: 'K_index' }), h('span', { text: 'Derives per-keyword K1 (search token) and K2 (index value key).' }), h('span', { class: 'badge', text: 'memory only' }))),
        h('p', { class: 'hint section-gap', text: 'These keys exist only in the trusted client\'s memory for your unlocked session and are wiped on lock, logout or session expiry.' }))),
    h('div', { class: 'section-gap' }),
    h('div', { class: 'field-label', text: 'Authorised viewing path (what happened to produce the left panel)' }),
    flow([
      ['cloud', 'Cloud returns record', 'nonce, ciphertext, tag (base64 over HTTP)'],
      ['client', 'Client reassembles blob', 'nonce ‖ ciphertext ‖ tag'],
      ['ok', 'GCM tag verified ✓', 'any modified bit would be rejected'],
      ['client', 'Decrypt with K_file', 'plaintext shown on the left'],
    ]));
}

function renderTamper(c, docs, params) {
  const source = h('select', null,
    h('option', { value: '', text: 'Temporary in-memory sample (never stored)' }),
    docs.map(d => h('option', { value: d.doc_id, selected: params.get('doc') === d.doc_id, text: `Copy of: ${d.filename}` })));
  const regionInputs = ['ciphertext', 'tag', 'nonce'].map((r, i) => h('label', { class: 'inline' },
    h('input', { type: 'radio', name: 'region', value: r, checked: i === 0 }), r));
  const offset = h('input', { type: 'number', min: '0', placeholder: 'random' });
  const bit = h('input', { type: 'number', min: '0', max: '7', placeholder: 'random' });
  const btn = h('button', { class: 'btn primary', type: 'submit', text: 'Flip one bit in a copy & try to decrypt' });
  const out = h('div', { class: 'section-gap' });
  const form = h('form', { class: 'stack' },
    h('label', null, 'What to test', source),
    h('div', null, h('div', { class: 'field-label', text: 'Region of nonce ‖ ciphertext ‖ tag to modify' }), h('div', { class: 'row' }, regionInputs)),
    h('div', { class: 'grid two' }, h('label', null, 'Byte offset in region (optional)', offset), h('label', null, 'Bit 0-7 (optional)', bit)),
    btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = { region: form.querySelector('input[name=region]:checked').value };
    if (source.value) body.doc_id = source.value;
    if (offset.value !== '') body.offset = parseInt(offset.value, 10);
    if (bit.value !== '') body.bit = parseInt(bit.value, 10);
    await withBusy(btn, 'Testing…', async () => {
      try {
        const r = await api('POST', '/api/tamper-demo', body);
        out.replaceChildren(tamperResult(r));
      } catch (err) { out.replaceChildren(errorBox(err.message)); }
    });
  });
  c.append(h('div', { class: 'grid two' },
    card('Tamper-detection test', form),
    card('What this demonstrates',
      h('p', { class: 'hint', text: 'AES-GCM appends a 128-bit authentication tag computed over the ciphertext with a key-dependent GHASH; the nonce feeds both the keystream and the tag. Changing any single bit makes the tag check fail, and decryption returns nothing at all (no partial plaintext).' }),
      h('div', { class: 'callout green section-gap', text: 'Safe by design: the bit is flipped in an in-memory copy inside the trusted client. Nothing is written to the cloud; the stored record is re-fetched afterwards and its SHA-256 compared to prove it is unchanged.' }))),
  out);
}

function windowHex(hex, start, pos, cls) {
  const bytes = hex.match(/../g) || [];
  return h('pre', { class: 'hex' }, bytes.map((b, i) => [
    start + i === pos ? h('span', { class: cls, text: b }) : b, i < bytes.length - 1 ? ' ' : '']));
}

function tamperResult(r) {
  const td = r.tampered_decrypt;
  return h('div', null,
    card(`Result — ${r.source}`,
      h('div', { class: 'pipeline' },
        pstep(1, 'client', 'Original encrypted blob', null,
          h('p', null, `${r.blob_bytes} bytes; ${r.region} occupies bytes ${r.region_bounds[0]}–${r.region_bounds[1] - 1}. SHA-256 `, h('code', { text: shortId(r.original_sha256, 20) }))),
        pstep(2, 'client', 'One bit flipped in a disposable copy', null,
          h('p', { text: `Byte ${r.position} (offset ${r.offset_in_region} in ${r.region}), bit ${r.bit}: ${r.original_byte} → ${r.modified_byte}` }),
          h('div', { class: 'field-label', text: 'original bytes around the change' }), windowHex(r.original_window_hex, r.window_start, r.position, 'hl-ok'),
          h('div', { class: 'field-label', text: 'modified copy' }), windowHex(r.modified_window_hex, r.window_start, r.position, 'hl')),
        pstep(3, 'client', 'Decrypt the unmodified blob', null,
          r.baseline_decrypt.ok
            ? h('div', { class: 'result-big ok' }, h('span', { class: 'ico', text: '✓' }), h('div', null, 'Tag verified, decryption succeeded', h('div', { class: 'sub', text: `${r.baseline_decrypt.plaintext_bytes} plaintext bytes` })))
            : h('div', { class: 'result-big bad' }, h('span', { class: 'ico', text: '✗' }), h('div', null, 'The stored record itself already fails verification', h('div', { class: 'sub', text: r.baseline_decrypt.error })))),
        pstep(4, 'client', 'Decrypt the modified copy', null,
          td.rejected
            ? h('div', { class: 'result-big ok' }, h('span', { class: 'ico', text: '⛔' }), h('div', null, 'Rejected by AES-GCM authentication',
              h('div', { class: 'sub', text: `${td.exception}${td.underlying ? ' ← ' + td.underlying : ''}: ${td.message}` })))
            : h('div', { class: 'result-big bad' }, h('span', { class: 'ico', text: '!' }), h('div', null, 'Modified data was ACCEPTED — this should never happen'))),
        pstep(5, 'cloud', 'Original stored record', null,
          r.original_unchanged_in_cloud === null
            ? h('p', { text: 'Not applicable: the sample was never stored anywhere.' })
            : h('div', { class: 'result-big ' + (r.original_unchanged_in_cloud ? 'ok' : 'bad') },
              h('span', { class: 'ico', text: r.original_unchanged_in_cloud ? '✓' : '✗' }),
              h('div', null, r.original_unchanged_in_cloud ? 'Unchanged in the cloud' : 'Stored record differs!',
                h('div', { class: 'sub', text: 'Re-fetched from the cloud after the test; SHA-256 compared with the original.' })))))));
}

// ---------------------------------------------------------------------------
// Cloud Storage Inspector (shared by user and admin)
// ---------------------------------------------------------------------------

function inspectorView(data, scopeNote) {
  const st = data.stats;
  const docRows = data.documents.map(d => {
    const detail = h('tr', { class: 'hidden' }, h('td', { colspan: '6' },
      h('div', { class: 'grid two' },
        h('div', null, h('div', { class: 'field-label', text: `enc_name (${d.enc_name.total_bytes} B) — encrypted filename` }),
          segHex(d.enc_name.nonce_hex, d.enc_name.ciphertext_hex, d.enc_name.tag_hex, false)),
        h('div', null, h('div', { class: 'field-label', text: 'nonce · tag' }),
          h('pre', { class: 'hex' }, h('span', { class: 'n', text: spaced(d.content.nonce_hex) }), '\n', h('span', { class: 't', text: spaced(d.content.tag_hex) })))),
      h('div', { class: 'field-label section-gap', text: `ciphertext (${d.content.ciphertext_bytes.toLocaleString()} B${d.content.ciphertext_truncated ? ', first 512 shown' : ''})` }),
      h('pre', { class: 'hex' }, h('span', { class: 'c', text: spaced(d.content.ciphertext_hex) + (d.content.ciphertext_truncated ? ' …' : '') })),
      h('div', { class: 'field-label section-gap', text: 'ciphertext as base64 (transport encoding, first 384 chars)' }),
      h('pre', { class: 'hex', text: d.content.ciphertext_b64_preview })));
    const toggle = h('button', { class: 'btn small', text: 'Bytes ▾' });
    toggle.addEventListener('click', () => { detail.classList.toggle('hidden'); toggle.textContent = detail.classList.contains('hidden') ? 'Bytes ▾' : 'Hide ▴'; });
    return [h('tr', null,
      h('td', { class: 'idcell', text: d.doc_id }),
      h('td', { class: 'small', text: fmtDate(d.uploaded_at) }),
      h('td', { text: fmtBytes(d.size) }),
      h('td', { class: 'idcell', text: shortId(d.enc_name.ciphertext_hex, 18) }),
      h('td', { class: 'idcell', text: shortId(d.content.nonce_hex, 12) }),
      h('td', { class: 'actions' }, toggle)), detail];
  });

  return h('div', null,
    h('div', { class: 'callout amber' }, h('b', { text: 'This is the cloud\'s view. ' }), scopeNote,
      ' Every value below was returned by the cloud service\'s API (port 5001); none of it is decrypted. Plaintext filenames, file contents, keywords and keys are not available here.'),
    h('div', { class: 'stats section-gap' },
      stat('Documents', String(st.documents)),
      stat('Ciphertext bytes', fmtBytes(st.ciphertext_bytes), `${st.ciphertext_bytes.toLocaleString()} B`),
      stat('Encrypted-name bytes', fmtBytes(st.enc_name_bytes)),
      stat('Index entries', String(st.index_entries), '(keyword, document) pairs'),
      stat('Meta rows', String(st.meta_keys.length), st.meta_keys.join(', ') || 'none'),
      stat('Vault created', st.vault_created_at ? fmtDate(st.vault_created_at) : '—', shortId(st.vault_id, 14))),
    card(`Encrypted document records (${data.documents_total})`,
      data.documents.length
        ? table(['Document id (random)', 'Uploaded', 'Size', 'enc_name (prefix)', 'Nonce', ''], docRows)
        : emptyState('☁', 'No documents stored', 'Nothing has been uploaded to this vault.'),
      data.documents_total > data.documents.length ? h('p', { class: 'hint section-gap', text: `Showing the first ${data.documents.length}.` }) : null),
    card(`Encrypted search index — sse_index (${data.index.total} rows)`,
      h('p', { class: 'hint', text: 'Each row is one (keyword, document) pair: label = HMAC-SHA256(K1, counter), value = AES-GCM(K2, document id). No column says which keyword a row belongs to; the total row count is visible (setup leakage).' }),
      data.index.entries.length
        ? h('div', { class: 'section-gap' }, table(['Label (HMAC output, hex)', 'Value (AES-GCM blob)', 'Bytes'], data.index.entries.map(e => h('tr', null,
          h('td', { class: 'idcell', text: e.label }), h('td', { class: 'idcell', text: shortId(e.value_hex, 40) }), h('td', { text: String(e.value_bytes) })))))
        : emptyState('∅', 'Index is empty', 'Rows appear after the first upload.'),
      data.index.total > data.index.entries.length ? h('p', { class: 'hint section-gap', text: `Showing ${data.index.entries.length} of ${data.index.total} rows (ordered by label).` }) : null));
}

async function renderInspector(c) {
  const data = await api('GET', '/api/inspector');
  c.append(inspectorView(data, 'Your own vault, fetched with your vault\'s access token — this works even while your vault is locked, because no key is needed.'));
}

// ---------------------------------------------------------------------------
// activity + system
// ---------------------------------------------------------------------------

async function renderActivity(c) {
  const d = await api('GET', '/api/activity?limit=200');
  c.append(card(`Your activity (${d.events.length} most recent)`,
    h('p', { class: 'hint', text: 'Recorded by the trusted client. Search events record only how many keywords and results there were — never the query. Passwords, keys, file contents and filenames are never logged. Demo events (tamper tests) are flagged.' }),
    h('div', { class: 'section-gap' }, eventsTable(d.events, false))));
}

async function renderSystem(c) {
  const s = await api('GET', '/api/system');
  const cr = s.crypto;
  c.append(h('div', { class: 'grid two' },
    card('Key hierarchy',
      flow([
        ['client', 'Vault passphrase', 'typed on unlock; never stored'],
        ['client', 'Argon2id', `${cr.vault_kdf_params.memory_kib / 1024} MiB · t=${cr.vault_kdf_params.time_cost} · p=${cr.vault_kdf_params.parallelism}, per-vault salt`],
        ['client', 'Master key', `${cr.key_bytes * 8}-bit`],
        ['client', 'HKDF-SHA256', 'K_file, K_index'],
      ]),
      h('p', { class: 'hint', text: 'Account login is separate: the account password is checked against an Argon2id password hash and never derives a key. An administrator therefore cannot obtain vault keys from account data.' })),
    card('Status & parameters',
      h('dl', { class: 'kv' },
        h('dt', { text: 'Cloud service' }), h('dd', null, h('span', { class: 'badge ' + (s.cloud_reachable ? 'green' : 'red'), text: s.cloud_reachable ? 'reachable' : 'unreachable' })),
        h('dt', { text: 'File encryption' }), h('dd', { text: `${cr.aead} (${cr.nonce_bytes}-byte nonce, ${cr.tag_bytes}-byte tag)` }),
        h('dt', { text: 'Search PRF' }), h('dd', { text: cr.prf }),
        h('dt', { text: 'Account passwords' }), h('dd', { text: cr.account_password_hash }),
        h('dt', { text: 'Session' }), h('dd', { text: `${s.session.cookie}; idle timeout ${Math.round(s.session.idle_timeout_seconds / 60)} min, max ${Math.round(s.session.absolute_timeout_seconds / 3600)} h` }),
        h('dt', { text: 'CSRF protection' }), h('dd', { text: s.session.csrf }),
        h('dt', { text: 'Access control' }), h('dd', { text: 'Roles enforced on the server; the cloud also requires each vault\'s access token' })))));

  c.append(card('What each party can see',
    h('div', { class: 'table-wrap leak-table' }, h('table', null,
      h('thead', null, h('tr', null, ['Data', 'Trusted client (unlocked user)', 'Cloud service', 'Administrator'].map(x => h('th', { text: x })))),
      h('tbody', null, [
        ['File contents', 'yes (decrypts)', 'ciphertext only', 'ciphertext only'],
        ['Filenames', 'yes (decrypts)', 'encrypted blob', 'encrypted blob'],
        ['Search keywords', 'yes', 'no — opaque tokens', 'no (not logged)'],
        ['Vault keys / passphrase', 'in session memory', 'never', 'never'],
        ['File sizes, counts, upload times', 'yes', 'yes', 'yes'],
        ['Search & access patterns', 'yes', 'yes (leakage)', 'event counts only'],
        ['Who owns which vault', 'own only', 'no — opaque vault ids', 'yes (account metadata)'],
      ].map(r => h('tr', null, r.map(x => h('td', { text: x }))))))),
    h('p', { class: 'hint section-gap', text: 'Assumption: the trusted client host is trusted. Whoever controls that machine could capture passphrases as they are typed — the protections here are against the cloud provider and against other application users and administrators.' })));

  if (!isAdmin()) c.append(changePassphraseCard());
}

function changePassphraseCard() {
  const cur = h('input', { type: 'password', placeholder: 'Current vault passphrase', autocomplete: 'current-password', required: true });
  const nw = h('input', { type: 'password', placeholder: 'New vault passphrase', autocomplete: 'new-password', required: true });
  const nw2 = h('input', { type: 'password', placeholder: 'Confirm new passphrase', autocomplete: 'new-password', required: true });
  const btn = h('button', { class: 'btn primary', type: 'submit', text: 'Change vault passphrase' });
  const status = h('p', { class: 'status-line' });
  const form = h('form', { class: 'stack' }, cur, nw, nw2, btn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (nw.value !== nw2.value) { status.textContent = 'New passphrases do not match.'; status.className = 'status-line error'; return; }
    if (!state.session.unlocked) { status.textContent = 'Unlock your vault first.'; status.className = 'status-line error'; return; }
    await withBusy(btn, 'Re-encrypting…', async () => {
      try {
        const r = await api('POST', '/api/change-password', { current_password: cur.value, new_password: nw.value });
        form.reset();
        status.textContent = `Done: ${r.documents_migrated} document(s) re-encrypted and the index rebuilt under the new keys.`;
        status.className = 'status-line success';
      } catch (err) { status.textContent = err.message; status.className = 'status-line error'; }
    });
  });
  return card('Change vault passphrase',
    h('p', { class: 'hint', text: 'Derives a new salt and new keys, re-encrypts every document and rebuilds the search index. Not instant; requires the vault to be unlocked and your current passphrase.' }),
    h('div', { class: 'section-gap' }, form), status);
}

// ---------------------------------------------------------------------------
// admin views
// ---------------------------------------------------------------------------

async function renderAdminOverview(c) {
  const d = await api('GET', '/api/admin/overview');
  const e = d.events;
  c.append(h('div', { class: 'callout' },
    h('b', { text: 'Administrator view — metadata only. ' }),
    'Administrators have no vault and no keys. Everything here comes from the audit log, account records, and the cloud\'s ciphertext statistics; no route available to this role can return plaintext, decrypted filenames, passphrases or keys.'));
  if (!d.cloud_reachable) c.append(h('div', { class: 'callout red section-gap', text: 'The cloud service is unreachable — storage totals are incomplete.' }));
  c.append(h('div', { class: 'stats section-gap' },
    stat('Accounts', String(d.accounts.total), `${d.accounts.users} users · ${d.accounts.admins} admins · ${d.accounts.inactive} inactive`),
    stat('Active sessions', String(d.sessions.active), `${d.sessions.unlocked_vaults} with an unlocked vault`),
    stat('Encrypted files', String(d.storage.documents)),
    stat('Ciphertext stored', fmtBytes(d.storage.ciphertext_bytes), `+ ${fmtBytes(d.storage.enc_name_bytes)} encrypted names`),
    stat('Index entries', String(d.storage.index_entries))));
  c.append(h('div', { class: 'stats' },
    stat('Uploads', String(e.uploads)), stat('Downloads', String(e.downloads)), stat('Searches', String(e.searches)),
    stat('Failed logins', String(e.login_failures), `${e.throttled_logins} throttled`, e.login_failures ? 'warn' : ''),
    stat('Failed vault unlocks', String(e.unlock_failures), null, e.unlock_failures ? 'warn' : ''),
    stat('Decryption failures', String(e.decryption_failures), 'AES-GCM tag rejected', e.decryption_failures ? 'bad' : ''),
    stat('Tamper tests rejected', String(e.tamper_rejected), `${e.tamper_accepted} accepted`, e.tamper_accepted ? 'bad' : 'good'),
    stat('Access denied', String(e.access_denied), 'blocked role violations', e.access_denied ? 'warn' : '')));
  c.append(card('Recent security events', eventsTable(d.recent_security_events, true)));
}

async function renderAdminUsers(c) {
  const d = await api('GET', '/api/admin/users');
  const me = state.session.user.id;
  const rows = d.users.map(u => h('tr', null,
    h('td', null, h('div', { class: 'fname', text: u.username }), u.vault_id ? h('div', { class: 'idcell small', text: 'vault ' + shortId(u.vault_id, 14) }) : null),
    h('td', null, h('span', { class: 'badge ' + (u.role === 'admin' ? 'violet' : 'blue'), text: u.role })),
    h('td', null, h('span', { class: 'badge ' + (u.is_active ? 'green' : 'red'), text: u.is_active ? 'active' : 'deactivated' })),
    h('td', { class: 'small', text: fmtDate(u.created_at) }),
    h('td', { class: 'small', text: fmtDate(u.last_login_at) }),
    h('td', { text: u.storage ? String(u.storage.documents) : '—' }),
    h('td', { text: u.storage ? fmtBytes(u.storage.ciphertext_bytes) : '—' }),
    h('td', { text: u.role === 'user' ? (u.vault_initialized ? 'yes' : 'not yet') : 'n/a' }),
    h('td', { class: 'actions' }, u.id === me ? h('span', { class: 'small muted', text: 'you' }) :
      h('button', {
        class: 'btn small ' + (u.is_active ? 'danger' : ''), text: u.is_active ? 'Deactivate' : 'Activate',
        onclick: async () => {
          const ok = await confirmDialog(u.is_active ? 'Deactivate account?' : 'Activate account?',
            u.is_active ? `${u.username} will be logged out immediately (their vault is locked) and cannot log in until re-activated. Their encrypted data is not touched.`
              : `${u.username} will be able to log in again.`, u.is_active ? 'Deactivate' : 'Activate', u.is_active);
          if (!ok) return;
          try {
            await api('POST', `/api/admin/users/${u.id}/status`, { active: !u.is_active });
            toast(`${u.username} ${u.is_active ? 'deactivated' : 'activated'}`, 'success');
            render();
          } catch (err) { toast(err.message, 'error'); }
        },
      }))));
  c.append(card(`Accounts (${d.users.length})`,
    h('p', { class: 'hint', text: 'Account metadata and cloud storage totals. Password hashes and cloud access tokens are never sent to the browser.' }),
    h('div', { class: 'section-gap' }, table(['Username', 'Role', 'Status', 'Created', 'Last login', 'Files', 'Ciphertext', 'Vault set up', ''], rows))));
}

async function renderAdminAudit(c, params) {
  const type = params.get('type') || '';
  const sec = params.get('security') === '1';
  const q = new URLSearchParams({ limit: '300' });
  if (type) q.set('event_type', type);
  if (sec) q.set('security_only', '1');
  const d = await api('GET', '/api/admin/audit?' + q.toString());
  const select = h('select', null, h('option', { value: '', text: 'All event types' }),
    Object.entries(EVENT_LABELS).map(([k, v]) => h('option', { value: k, selected: k === type, text: v })));
  const secBox = h('input', { type: 'checkbox', checked: sec });
  const apply = () => go('audit', Object.assign({}, select.value ? { type: select.value } : {}, secBox.checked ? { security: '1' } : {}));
  select.addEventListener('change', apply);
  secBox.addEventListener('change', apply);
  c.append(card('Audit log',
    h('div', { class: 'row' }, select, h('label', { class: 'inline' }, secBox, 'Security events only'), h('span', { class: 'spacer' }),
      h('button', { class: 'btn small', text: 'Refresh', onclick: render })),
    h('p', { class: 'hint section-gap', text: 'Generated by the trusted client\'s backend. Never contains passwords, keys, file contents, filenames or search queries. Rows marked "demo" come from the tamper-detection demonstration, not real attacks.' }),
    h('div', { class: 'section-gap' }, eventsTable(d.events, true))));
}

async function renderAdminInspector(c, params) {
  const list = await api('GET', '/api/admin/inspector');
  if (!list.vaults.length) {
    c.append(emptyState('☁', 'No user vaults yet', 'Vaults appear here once regular users register.'));
    return;
  }
  const uid = params.get('user') || String(list.vaults[0].user_id);
  const select = h('select', null, list.vaults.map(v => h('option', { value: String(v.user_id), selected: String(v.user_id) === uid, text: `${v.username} — vault ${shortId(v.vault_id, 12)}` })));
  select.addEventListener('change', () => go('admin-inspector', { user: select.value }));
  c.append(h('div', { class: 'row' }, h('b', { text: 'Vault:' }), select));
  const area = h('div', { class: 'section-gap' }, loading());
  c.append(area);
  try {
    const data = await api('GET', `/api/admin/inspector?user_id=${encodeURIComponent(uid)}`);
    area.replaceChildren(inspectorView(data, `Vault of ${data.username}, fetched through the cloud API with that vault's access token. The administrator holds no key for it.`));
  } catch (err) { area.replaceChildren(errorBox(err.message)); }
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

initAuthForms();
initShell();
enterApp().catch(err => showAuth(err.message, 'error'));
