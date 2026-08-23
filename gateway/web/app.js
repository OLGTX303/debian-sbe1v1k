/* sbegw management UI.
 *
 * Deliberately dependency-free: the gateway must be manageable when the
 * internet, the cloud and any controller are all down (spec §51), so nothing
 * here loads from a CDN and there is no build step. State comes from
 * /api/v1/* and live updates arrive over the SSE stream.
 */
'use strict';

const API = '/api/v1';

/* ------------------------------------------------------------------ helpers */

const h = (tag, attrs = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'html') el.innerHTML = value;
    else if (key.startsWith('on') && typeof value === 'function')
      el.addEventListener(key.slice(2), value);
    else if (key === 'value') el.value = value;
    else if (key === 'checked') el.checked = !!value;
    else el.setAttribute(key, value);
  }
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
};

const text = (s) => document.createTextNode(s === null || s === undefined ? '' : String(s));
const $ = (sel, root = document) => root.querySelector(sel);

const fmtBits = (bps) => {
  if (!bps || bps < 1) return '0 bps';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let i = 0, v = bps;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
};

const fmtBytes = (bytes) => {
  if (!bytes) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
};

const fmtDuration = (seconds) => {
  if (!seconds && seconds !== 0) return '—';
  const d = Math.floor(seconds / 86400), hh = Math.floor((seconds % 86400) / 3600);
  const mm = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${mm}m`;
  return `${mm}m`;
};

const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '—';
const fmtAgo = (ts) => {
  if (!ts) return '—';
  const delta = Date.now() / 1000 - ts;
  if (delta < 60) return 'just now';
  return fmtDuration(delta) + ' ago';
};
/* PHY rates arrive as floats from the driver; never show 960.6666666666666. */
const fmtMbps = (mbps) => (mbps === null || mbps === undefined)
  ? '—' : (mbps >= 100 ? Math.round(mbps) : Number(mbps.toFixed(1)));
const fmtSpeed = (mbps) => !mbps ? '—' : (mbps >= 1000 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`);
const bandLabel = (b) => ({ '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' }[b] || b || '—');

const STATE_TONE = {
  up: 'ok', enabled: 'ok', ENABLED: 'ok', online: 'ok', normal: 'ok',
  degraded: 'warn', recovering: 'warn', warning: 'warn', 'no-internet': 'warn',
  down: 'bad', failed: 'bad', critical: 'bad', 'link-down': 'bad', 'no-address': 'bad',
  disabled: 'mute', unknown: 'mute', UNKNOWN: 'mute',
};
const tone = (state) => STATE_TONE[state] || 'mute';
const pill = (label, klass) => h('span', { class: `pill ${klass || 'mute'}` },
  h('i', { class: 'dot' }), label);
const statePill = (state) => pill(state || 'unknown', tone(state));

/* --------------------------------------------------------------------- api */

const store = {
  csrf: null, user: null, dashboard: null, live: null,
  page: 'dashboard', stream: null, pending: null,
};

async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Accept': 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (store.csrf && method !== 'GET') headers['X-CSRF-Token'] = store.csrf;
  const res = await fetch(API + path, {
    method, headers, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = (data && data.error) || {};
    const detail = err.details && err.details.details ? ': ' + err.details.details.join('; ') : '';
    const error = new Error((err.message || res.statusText) + detail);
    error.code = err.code; error.status = res.status; error.details = err.details;
    throw error;
  }
  return data;
}

function toast(message, kind = '') {
  const host = $('#toasts');
  const el = h('div', { class: `toast ${kind}` }, message);
  host.append(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 9000 : 4500);
}

/* Wrap a mutating call: shows errors, refreshes, and surfaces commit warnings
 * plus the rollback confirmation the transactional config layer may require. */
async function mutate(fn, okMessage) {
  try {
    const result = await fn();
    (result && result.warnings || []).forEach((w) => toast(w, ''));
    if (result && result.confirm_pending) {
      store.pending = { txid: result.txid, deadline: result.rollback_deadline };
    }
    if (okMessage) toast(okMessage, 'ok');
    await refresh();
    return result;
  } catch (err) {
    toast(err.message, 'bad');
    throw err;
  }
}

/* ------------------------------------------------------------------- icons */

/* A small stroke-based set on a 24-unit grid, inlined as SVG. Unicode glyphs
 * (◉ ⌗ ≋) render differently on every platform and at the wrong optical weight;
 * these stay crisp and inherit currentColor. */
const ICON_PATHS = {
  dashboard: 'M3 13h8V3H3v10Zm10 8h8V11h-8v10ZM3 21h8v-6H3v6Zm10-12h8V3h-8v6Z',
  topology: 'M12 3v4m0 0-6 4m6-4 6 4M4 11h4v4H4v-4Zm12 0h4v4h-4v-4ZM10 17h4v4h-4v-4Zm2-2v2',
  clients: 'M17 20v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm11 9v-1a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  port: 'M4 8h16v8H4V8Zm3 8v3m4-3v3m4-3v3M7 8V5m10 3V5',
  wan: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm-9-9h18M12 3c2.5 2.4 4 5.6 4 9s-1.5 6.6-4 9c-2.5-2.4-4-5.6-4-9s1.5-6.6 4-9Z',
  vlan: 'M4 5h16M4 12h16M4 19h16M8 5v14m8-14v14',
  services: 'M4 7h10m4 0h2M4 17h2m4 0h10M14 4v6m-8 4v6',
  radio: 'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm4.5-6.5a6 6 0 0 1 0 9M7.5 16.5a6 6 0 0 1 0-9M20 4a11 11 0 0 1 0 16M4 20A11 11 0 0 1 4 4',
  ssid: 'M5 12.5a10 10 0 0 1 14 0M8 16a6 6 0 0 1 8 0M12 20h.01M2 9a15 15 0 0 1 20 0',
  mlo: 'M8 7h9a4 4 0 0 1 0 8h-1M7 17H6a4 4 0 0 1 0-8h1m9 12 3-3-3-3M8 4 5 7l3 3',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
  spectrum: 'M3 20V9m4 11V5m4 15v-8m4 8V7m4 13v-5m-16 5h18',
  shield: 'M12 21s7-3.5 7-9V6l-7-3-7 3v6c0 5.5 7 9 7 9Z',
  nat: 'M4 8h11l-3-3m3 3-3 3M20 16H9l3-3m-3 3 3 3',
  route: 'M6 20V9a3 3 0 0 1 3-3h6a3 3 0 0 1 3 3v3M6 20h.01M18 12v4m0 4h.01M4 20h4m8 0h4M18 4h.01',
  event: 'M4 4v16m0-16h11l-1.5 3L15 10H4M4 4h11',
  hardware: 'M6 6h12v12H6V6Zm3-3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3',
  config: 'M9 3h9a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8l5-5Zm0 0v5H4m5 5h6m-6 4h6',
  users: 'M16 20v-1a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v1M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm7 2 2 2 3-3',
  audit: 'M4 6h16M4 12h16M4 18h10',
  internet: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm-9-9h18M12 3c2.5 2.4 4 5.6 4 9s-1.5 6.6-4 9',
  gateway: 'M4 7h16v10H4V7Zm3 10v2m10-2v2M7 11h.01M11 11h.01M15 11h6',
  device: 'M7 4h10v16H7V4Zm3 14h4',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10Zm0-14v2m0 18v-2M5.6 5.6 7 7m10 10 1.4 1.4M3 12h2m18 0h-2M5.6 18.4 7 17M17 7l1.4-1.4',
  moon: 'M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6',
  power: 'M12 4v8m5.7-5.7a8 8 0 1 1-11.4 0',
  menu: 'M4 7h16M4 12h16M4 17h16',
  close: 'M6 6l12 12M18 6 6 18',
  plus: 'M12 5v14M5 12h14',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Zm5 -2 4 4',
  warn: 'M12 4l9 16H3l9-16Zm0 5v5m0 3h.01',
  error: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-13v5m0 3h.01',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-9v5m0-8h.01',
  check: 'M20 6 9 17l-5-5',
  wand: 'M15 4V2m0 20v-2m5-8h2M2 12h2m12.5-5.5L18 5M6 18l1.5-1.5M4 4l7 7m-7-7 2 6 6 2-8-8Zm9.5 9.5L21 21',
};

/* size defaults to 16 to match the nav and button metrics. */
function icon(name, size = 16, extra = '') {
  const path = ICON_PATHS[name];
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.7');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  if (extra) svg.setAttribute('class', extra);
  if (path) {
    const el = document.createElementNS(svg.namespaceURI, 'path');
    el.setAttribute('d', path);
    svg.append(el);
  }
  return svg;
}

/* ------------------------------------------------------------------- charts */

function sparkline(points, { color = 'var(--accent)', height = 42 } = {}) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'spark');
  svg.setAttribute('viewBox', `0 0 100 ${height}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  if (!points || points.length < 2) return svg;
  const values = points.map((p) => p[1]);
  const max = Math.max(...values, 1);
  const step = 100 / (points.length - 1);
  const y = (v) => height - 2 - (v / max) * (height - 6);
  const line = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(2)},${y(v).toFixed(2)}`).join(' ');
  const area = document.createElementNS(svg.namespaceURI, 'path');
  area.setAttribute('d', `${line} L100,${height} L0,${height} Z`);
  area.setAttribute('fill', color); area.setAttribute('opacity', '.13');
  const stroke = document.createElementNS(svg.namespaceURI, 'path');
  stroke.setAttribute('d', line); stroke.setAttribute('fill', 'none');
  stroke.setAttribute('stroke', color); stroke.setAttribute('stroke-width', '1.6');
  stroke.setAttribute('vector-effect', 'non-scaling-stroke');
  svg.append(area, stroke);
  return svg;
}

function meter(percent, klass) {
  const value = Math.max(0, Math.min(100, percent || 0));
  return h('div', { class: `bar ${klass || ''}` }, h('i', { style: `width:${value}%` }));
}

/* Build a table from a column spec and a row renderer.
 *
 * Composing tables by nesting h() calls directly produces expressions a dozen
 * parentheses deep, which is how several of these pages originally shipped
 * broken. Columns are `[label, {num}]` or a bare label; `renderRow` returns an
 * array of cell contents (or a <tr>, or an array of <tr> for expandable rows). */
function dataTable(columns, rows, renderRow, emptyMessage = 'Nothing to show.') {
  if (!rows || !rows.length) return h('div', { class: 'empty' }, emptyMessage);

  const head = h('tr', {}, columns.map((col) => {
    const label = Array.isArray(col) ? col[0] : col;
    const opts = (Array.isArray(col) ? col[1] : null) || {};
    return h('th', { class: opts.num ? 'num' : null }, label);
  }));

  const isRow = (node) => node instanceof Node && node.tagName === 'TR';

  const body = [];
  rows.forEach((row, index) => {
    const built = renderRow(row, index);
    const parts = Array.isArray(built) ? built : [built];
    // An array of <tr> means the renderer emitted its own rows (used for the
    // expandable per-link detail rows). Anything else is one row of cells —
    // treating cells as rows would put every column on its own line.
    if (parts.length && parts.every(isRow)) {
      body.push(...parts);
      return;
    }
    const cells = parts.map((cell, i) => {
      if (cell instanceof Node && cell.tagName === 'TD') return cell;
      const opts = (Array.isArray(columns[i]) ? columns[i][1] : null) || {};
      return h('td', { class: opts.num ? 'num' : null }, cell);
    });
    body.push(h('tr', {}, cells));
  });
  return h('table', {}, h('thead', {}, head), h('tbody', {}, body));
}

/* A card whose body is a scrollable table. */
function tableCard(title, headerExtras, table) {
  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, title), h('div', { class: 'spacer' }),
      ...[headerExtras].flat().filter(Boolean)),
    h('div', { class: 'body tight table-wrap' }, table));
}

/* ---------------------------------------------------------------- nav model */

/* UniFi Network keeps the application rail short and exposes related screens
 * as contextual tabs.  That makes the common paths one click away without
 * turning the left rail into a 20-item administration tree.  DPI remains a
 * first-class section so it can never disappear below the fold. */
const NAV = [
  { id: 'dashboard', name: 'Overview', ico: 'dashboard', items: [
    { id: 'dashboard', name: 'Overview' },
  ]},
  { id: 'internet', name: 'Internet', ico: 'internet', items: [
    { id: 'wan', name: 'Internet' },
    { id: 'ports', name: 'Ports' },
    { id: 'services', name: 'Traffic & DNS' },
    { id: 'routes', name: 'Routes' },
    { id: 'nat', name: 'NAT' },
  ]},
  { id: 'networks', name: 'Networks', ico: 'vlan', items: [
    { id: 'networks', name: 'Networks' },
    { id: 'ssids', name: 'WiFi' },
    { id: 'radios', name: 'Radios' },
    { id: 'channels', name: 'Environment' },
    { id: 'neighbors', name: 'Neighbour APs' },
  ]},
  { id: 'clients', name: 'Clients', ico: 'clients', items: [
    { id: 'clients', name: 'All Clients' },
    { id: 'wclients', name: 'WiFi Clients' },
  ]},
  { id: 'security', name: 'Security', ico: 'shield', items: [
    { id: 'firewall', name: 'Firewall' },
  ]},
  { id: 'dpi', name: 'DPI', ico: 'spectrum', featured: true, items: [
    { id: 'dpi', name: 'Traffic Identification' },
  ]},
  { id: 'insights', name: 'Insights', ico: 'topology', items: [
    { id: 'topology', name: 'Topology' },
    { id: 'events', name: 'Events' },
    { id: 'platform', name: 'Hardware' },
  ]},
  { id: 'settings', name: 'Settings', ico: 'config', settings: true, items: [
    { id: 'controller', name: 'UniFi Network' },
    { id: 'config', name: 'Configuration' },
    { id: 'users', name: 'Administrators' },
    { id: 'audit', name: 'Audit Log' },
  ]},
];

const PAGE_TITLES = Object.fromEntries(NAV.flatMap((section) =>
  section.items.map((item) => [item.id, item.name])));

function sectionForPage(page = store.page) {
  return NAV.find((section) => section.items.some((item) => item.id === page)) || NAV[0];
}

/* ============================================================ auth screens */

function renderAuth({ setup }) {
  const err = h('div', { class: 'auth-err', style: 'display:none' });
  const username = h('input', { type: 'text', autocomplete: 'username', required: 'required' });
  const password = h('input', { type: 'password', autocomplete: setup ? 'new-password' : 'current-password', required: 'required' });
  const totp = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: 'Only if MFA is enabled' });
  const submit = h('button', { class: 'primary', type: 'submit', style: 'width:100%' },
    setup ? 'Create administrator' : 'Sign in');

  const form = h('form', { onsubmit: async (event) => {
    event.preventDefault();
    err.style.display = 'none';
    submit.disabled = true;
    try {
      const payload = { username: username.value.trim(), password: password.value };
      if (!setup && totp.value.trim()) payload.totp = totp.value.trim();
      const result = await api(setup ? '/setup' : '/auth/login', { method: 'POST', body: payload });
      store.csrf = result.csrf;
      store.user = result.user;
      await boot();
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
      submit.disabled = false;
    }
  }},
    err,
    h('label', { class: 'field' }, h('span', {}, 'Username'), username),
    h('label', { class: 'field' }, h('span', {}, 'Password',
      setup ? h('span', { class: 'help' }, ' — at least 10 characters, three character classes') : null),
      password),
    setup ? null : h('label', { class: 'field' }, h('span', {}, 'MFA code'), totp),
    submit);

  return h('div', { class: 'auth-wrap' },
    h('div', { class: 'card auth-card' },
      h('div', { class: 'brand' },
        h('div', { class: 'logo unifi-mark' }, 'U'),
        h('div', {}, h('div', { class: 'name' }, 'UniFi Network'),
          h('div', { class: 'sub' }, 'SBE1V1K Gateway · IPQ9574'))),
      h('div', { class: 'body' },
        h('h2', {}, setup ? 'First-time setup' : 'Sign in'),
        h('p', { class: 'lead' }, setup
          ? 'Create the local owner account. This is stored on the device only.'
          : 'Local administration — no cloud account required.'),
        form)));
}

/* ============================================================ app shell */

function renderShell() {
  const activeSection = sectionForPage();
  const primary = NAV.filter((section) => !section.settings);
  const settings = NAV.find((section) => section.settings);
  const navItem = (section) => h('a', {
    class: `${activeSection.id === section.id ? 'active' : ''}${section.featured ? ' featured' : ''}`,
    title: section.name,
    onclick: () => go(section.items[0].id),
  }, icon(section.ico, 19, 'ico'), h('span', { class: 'nav-name' }, section.name),
  section.id === 'insights' ? badgeForEvents() : null);

  const nav = h('nav', { class: 'nav' },
    h('div', { class: 'nav-section-label' }, 'Network'),
    primary.map(navItem),
    h('div', { class: 'nav-spacer' }),
    settings ? navItem(settings) : null);

  const board = store.dashboard?.system?.board || {};
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' },
      h('div', { class: 'logo unifi-mark' }, 'U'),
      h('div', { style: 'min-width:0' },
        h('div', { class: 'name' }, 'UniFi Network'),
        h('div', { class: 'sub' }, 'SBE1V1K · ' + (board.model || 'IPQ9574')))),
    nav,
    h('div', { class: 'side-foot' },
      h('div', { class: 'avatar' }, (store.user?.name || 'A').slice(0, 1).toUpperCase()),
      h('div', { class: 'who' },
        h('b', {}, store.user ? store.user.name : ''),
        h('span', {}, store.user ? store.user.role : '')),
      h('button', { class: 'icon', title: 'Sign out', onclick: signOut },
        icon('power', 15))));

  const body = h('div', { class: 'content', id: 'page-body' });
  const sectionTabs = activeSection.items.length > 1
    ? h('nav', { class: 'section-tabs', 'aria-label': `${activeSection.name} pages` },
        activeSection.items.map((item) => h('button', {
          class: store.page === item.id ? 'on' : '', onclick: () => go(item.id),
        }, item.name)))
    : null;
  const main = h('main', { class: 'main' },
    h('header', { class: 'top' },
      h('button', { class: 'icon', onclick: () =>
        $('.app').classList.toggle('nav-open') }, icon('menu', 16)),
      h('div', { class: 'page-identity' },
        h('span', {}, activeSection.name),
        h('h1', {}, PAGE_TITLES[store.page] || 'Gateway')),
      h('div', { class: 'spacer' }),
      liveIndicator(),
      h('button', { class: 'icon', title: 'Light / dark theme',
        onclick: toggleTheme },
        icon(currentTheme() === 'dark' ? 'sun' : 'moon', 15)),
      h('button', { class: 'icon', title: 'Refresh', onclick: () => refresh(true) },
        icon('refresh', 15))),
    sectionTabs,
    body);

  const scrim = h('button', { class: 'mobile-scrim', 'aria-label': 'Close navigation',
    onclick: () => $('.app')?.classList.remove('nav-open') });
  return h('div', { class: 'app' }, side, scrim, main);
}

function badgeForEvents() {
  const counts = store.dashboard?.event_counts || {};
  const bad = (counts.error || 0) + (counts.critical || 0);
  return bad ? h('span', { class: 'badge' }, bad > 99 ? '99+' : bad) : null;
}

function liveIndicator() {
  const connected = store.stream && store.stream.readyState === 1;
  return h('span', { class: `pill ${connected ? 'ok' : 'mute'}`, title:
    connected ? 'Live telemetry connected' : 'Live telemetry disconnected' },
    h('i', { class: 'dot' }), connected ? 'Live' : 'Offline');
}

function currentTheme() {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
  try { localStorage.setItem('sbegw-theme', theme); } catch (_) {}
}

function toggleTheme() {
  applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  render();
}

async function signOut() {
  try { await api('/auth/logout', { method: 'POST' }); } catch (_) {}
  if (store.stream) store.stream.close();
  store.csrf = null; store.user = null;
  await boot();
}

function go(page) {
  store.page = page;
  location.hash = page;
  $('.app')?.classList.remove('nav-open');
  render();
}

/* ============================================================ page: banners */

function pendingBanner() {
  if (!store.pending) return null;
  const remaining = Math.max(0, Math.round(store.pending.deadline - Date.now() / 1000));
  return h('div', { class: 'banner warn' },
    icon('warn', 15, 'ico'),
    h('div', {},
      h('b', {}, 'Configuration awaiting confirmation. '),
      `If you do not confirm within ${remaining}s the change rolls back automatically. `,
      h('span', { class: 'dim' }, 'Confirm only once you are sure you can still reach this page.')),
    h('div', { class: 'spacer' }),
    h('button', { class: 'primary sm', onclick: async () => {
      await api('/config/confirm', { method: 'POST', body: { txid: store.pending.txid } });
      store.pending = null;
      toast('Change confirmed', 'ok');
      refresh();
    }}, 'Confirm'));
}

function alertBanners() {
  const alerts = store.dashboard?.alerts || [];
  return alerts.slice(0, 4).map((alert) => h('div', {
    class: `banner ${alert.severity === 'error' ? 'bad' : alert.severity === 'warning' ? 'warn' : 'info'}`,
  }, icon(alert.severity === 'error' ? 'error'
      : alert.severity === 'warning' ? 'warn' : 'info', 15, 'ico'),
    h('div', {}, h('b', {}, alert.area.toUpperCase() + ': '), alert.message)));
}

/* ============================================================ page renderers */

const pages = {};

function pageLead(title, description, actions = []) {
  return h('div', { class: 'page-lead' },
    h('div', {}, h('h2', {}, title), h('p', {}, description)),
    actions.length ? h('div', { class: 'page-actions' }, actions) : null);
}

/* ------------------------------------------------------------- dashboard */

pages.dashboard = async (root) => {
  const d = store.dashboard;
  if (!d) return root.append(h('div', { class: 'empty' }, 'No data yet.'));
  const sys = d.system || {};
  const series = (await api('/telemetry/series?prefix=wan&window=300')).series || {};
  const primary = d.internet || {};

  const wanRx = Object.entries(series).find(([k]) => k.endsWith('.rx_bps'));
  const wanTx = Object.entries(series).find(([k]) => k.endsWith('.tx_bps'));

  root.append(
    pageLead('Network overview', 'Internet, clients and gateway health at a glance.', [
      h('button', { onclick: () => go('wan') }, icon('internet', 15), 'Internet'),
      h('button', { onclick: () => go('ssids') }, icon('ssid', 15), 'WiFi'),
      h('button', { class: 'primary', onclick: () => go('dpi') },
        icon('spectrum', 15), 'Open DPI'),
    ]),
    ...alertBanners(),
    h('div', { class: 'grid c4' },
      statCard('Internet', primary.state || 'down', {
        pillState: primary.state,
        hint: primary.public_ip ? `Public ${primary.public_ip}` : 'No public address',
      }),
      statCard('Latency', primary.latency_ms != null ? primary.latency_ms : '—',
        { unit: 'ms', hint: `Loss ${primary.loss_percent ?? '—'}%` }),
      statCard('Clients', d.clients?.total ?? 0, {
        hint: `${d.clients?.wired ?? 0} wired · ${d.clients?.wireless ?? 0} Wi-Fi · ${d.clients?.mlo ?? 0} MLO`,
      }),
      statCard('Uptime', fmtDuration(sys.uptime), {
        hint: sys.board?.firmware || '' })),

    h('div', { class: 'grid c2 mt' },
      h('div', { class: 'card' },
        h('header', {}, h('h2', {}, 'WAN throughput'),
          h('div', { class: 'spacer' }),
          h('span', { class: 'dim small' }, 'last 5 min')),
        h('div', { class: 'body' },
          h('div', { class: 'small muted mb' },
            `Download ${fmtBits(wanRx?.[1]?.points?.at(-1)?.[1])} · Upload ${fmtBits(wanTx?.[1]?.points?.at(-1)?.[1])}`),
          sparkline(wanRx?.[1]?.points || [], { color: 'var(--accent)' }),
          sparkline(wanTx?.[1]?.points || [], { color: 'var(--green)' }))),

      h('div', { class: 'card' },
        h('header', {}, h('h2', {}, 'System')),
        h('div', { class: 'body' },
          resourceRow('CPU', sys.cpu_percent, '%', sys.cpu_percent),
          resourceRow('Memory', sys.memory?.used_percent, '%', sys.memory?.used_percent),
          resourceRow('Temperature', sys.thermal?.max_temperature_c, '°C',
            ((sys.thermal?.max_temperature_c || 0) / 110) * 100),
          (sys.storage || []).map((s) => resourceRow(`Storage ${s.mount}`,
            s.used_percent, '%', s.used_percent)),
          h('div', { class: 'small dim mt' },
            `Load ${(sys.load || []).map((n) => n.toFixed(2)).join(' · ')} · ${sys.cores || '?'} cores`)))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Ports')),
      h('div', { class: 'body tight table-wrap' }, portsTable(d.ports || [], true))),

    radioCards(d.wifi?.radios || [], d.wifi?.mlds || []),
    accelerationCard(d.acceleration || {}),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Recent events'),
        h('div', { class: 'spacer' }),
        h('button', { class: 'sm ghost', onclick: () => go('events') }, 'View all')),
      h('div', { class: 'body tight' }, eventsTable(d.events || []))));
};

function statCard(label, value, { unit, hint, pillState } = {}) {
  return h('div', { class: 'card' }, h('div', { class: 'body stat' },
    h('div', { class: 'label' }, label),
    pillState !== undefined
      ? h('div', { style: 'margin-top:8px' }, statePill(pillState))
      : h('div', { class: 'value' }, text(value), unit ? h('span', { class: 'unit' }, ' ' + unit) : null),
    hint ? h('div', { class: 'hint' }, hint) : null));
}

function resourceRow(label, value, unit, percent) {
  const p = percent || 0;
  const klass = p > 90 ? 'bad' : p > 75 ? 'warn' : 'ok';
  return h('div', { class: 'meter-row' },
    h('div', { class: 'top-line' },
      h('span', { class: 'muted' }, label),
      h('b', {}, value == null ? '—' : `${value}${unit}`)),
    meter(p, klass));
}

function accelerationCard(accel) {
  const flows = accel.flows || {};
  return h('div', { class: 'card mt' },
    h('header', {}, h('h2', {}, 'Hardware acceleration (NSS / PPE / PPEDS)'),
      h('div', { class: 'spacer' }),
      pill(accel.offload_enabled ? 'Offload active' : 'Software forwarding',
        accel.offload_enabled ? 'ok' : 'warn')),
    h('div', { class: 'body' },
      h('div', { class: 'grid c4' },
        ['nss', 'ppe', 'edma', 'ppeds', 'ssdk'].map((key) => h('div', { class: 'stat' },
          h('div', { class: 'label' }, key.toUpperCase()),
          h('div', { style: 'margin-top:6px' },
            pill(accel[key]?.present ? 'detected' : 'absent',
              accel[key]?.present ? 'ok' : 'mute')))),
        h('div', { class: 'stat' },
          h('div', { class: 'label' }, 'Flows'),
          h('div', { class: 'value', style: 'font-size:19px' },
            `${flows.accelerated ?? '—'} / ${flows.total ?? '—'}`),
          h('div', { class: 'hint' }, 'accelerated / total'))),
      (accel.fallback_reasons || []).length
        ? h('div', { class: 'mt small muted' },
            h('b', {}, 'Why traffic may fall back to software:'),
            h('ul', { style: 'margin:6px 0 0 18px' },
              accel.fallback_reasons.map((r) => h('li', {}, r))))
        : null));
}

/* ----------------------------------------------------------------- radios */

function radioCards(radios, mlds) {
  if (!radios.length) {
    return h('div', { class: 'card mt' }, h('div', { class: 'empty' },
      'No Wi-Fi radios detected. Check that ath12k loaded and the QCN9274 '
      + 'firmware is present.'));
  }
  return h('div', { class: 'grid c3 mt' },
    radios.map((radio) => {
      const rt = radio.runtime || {}, cfg = radio.configured || {};
      return h('div', { class: 'card' },
        h('header', {},
          h('h2', {}, radio.label || bandLabel(radio.band)),
          h('div', { class: 'spacer' }),
          statePill(radio.state)),
        h('div', { class: 'body' },
          h('div', { class: 'grid c2', style: 'gap:8px' },
            kv('Channel', rt.channel ?? cfg.channel ?? '—'),
            kv('Width', rt.channel_width ? `${rt.channel_width} MHz` : '—'),
            kv('TX power', rt.tx_power_dbm != null ? `${rt.tx_power_dbm} dBm` : '—'),
            kv('Clients', radio.client_count ?? 0),
            kv('Noise', rt.noise_dbm != null ? `${rt.noise_dbm} dBm` : '—'),
            kv('Utilisation', rt.utilisation_percent != null ? `${rt.utilisation_percent}%` : '—')),
          rt.utilisation_percent != null
            ? h('div', { class: 'mt' }, meter(rt.utilisation_percent,
                rt.utilisation_percent > 70 ? 'warn' : 'ok'))
            : null,
          radio.downgrade_reason
            ? h('div', { class: 'banner warn mt', style: 'margin-bottom:0' },
                icon('warn', 14, 'ico'), h('div', {}, radio.downgrade_reason))
            : null,
          h('div', { class: 'inline mt', style: 'gap:6px;flex-wrap:wrap' },
            radio.capabilities?.eht ? pill('Wi-Fi 7', 'info') : null,
            radio.capabilities?.he ? pill('Wi-Fi 6', 'mute') : null,
            radio.capabilities?.mlo ? pill('MLO capable', 'mlo') : null,
            radio.capabilities?.dfs ? pill('DFS', 'mute') : null,
            radio.ppeds ? pill('PPEDS', 'ok') : null)));
    }),
    mlds.map(mldCard));
}

function kv(label, value) {
  return h('div', { class: 'kv' },
    h('div', { class: 'k' }, label),
    h('div', { class: 'v' }, text(value === null || value === undefined ? '—' : value)));
}

function mldCard(mld) {
  return h('div', { class: 'card mlo-card' },
    h('header', {},
      h('h2', {}, `MLO · ${mld.name}`),
      h('div', { class: 'spacer' }),
      statePill(mld.state)),
    h('div', { class: 'body' },
      h('div', { class: 'small muted mb' },
        h('span', { class: 'mono' }, mld.mld_mac || '—'), ' · ',
        `SSID ${mld.ssid || '—'} · ${mld.links_up}/${mld.link_count} links up · `,
        `${mld.mlo_client_count ?? 0} MLO clients`),
      (mld.links || []).map((link) => h('div', { class: 'link-row' },
        h('div', {}, h('div', { class: 'lid' }, `Link ${link.link_id ?? '?'}`),
          h('div', { class: 'small dim' }, bandLabel(link.band))),
        h('div', { class: 'link-metrics' },
          h('span', { class: 'muted' }, 'Ch ', h('b', {}, link.channel ?? '—')),
          h('span', { class: 'muted' }, h('b', {}, link.channel_width ?? '—'), ' MHz'),
          h('span', { class: 'muted' }, 'Noise ', h('b', {}, link.noise_dbm ?? '—')),
          h('span', { class: 'muted' }, 'Retry ', h('b', {}, (link.retry_percent ?? 0) + '%')),
          h('span', { class: 'muted' }, h('b', {}, link.client_count ?? 0), ' sta')),
        statePill(link.state))),
      h('div', { class: 'small dim mt' },
        `Aggregate ↓ ${fmtBytes(mld.aggregate?.rx_bytes)} · ↑ ${fmtBytes(mld.aggregate?.tx_bytes)}`)));
}

/* ------------------------------------------------------------------ ports */

function portsTable(ports, compact) {
  if (!ports.length) return h('div', { class: 'empty' }, 'No ports discovered.');
  return h('table', {},
    h('thead', {}, h('tr', {},
      h('th', {}, 'Port'), h('th', {}, 'Role'), h('th', {}, 'Link'),
      h('th', {}, 'Speed'), h('th', {}, 'Duplex'),
      h('th', { class: 'num' }, '↓ Rate'), h('th', { class: 'num' }, '↑ Rate'),
      compact ? null : h('th', { class: 'num' }, 'Errors'),
      compact ? null : h('th', {}, 'PHY'))),
    h('tbody', {}, ports.map((port) => h('tr', {},
      h('td', {}, h('b', {}, port.name || port.id),
        h('div', { class: 'small dim mono' }, port.id)),
      h('td', {}, pill(port.role, port.role === 'wan' ? 'info' : 'mute')),
      h('td', {}, pill(port.link_up ? 'up' : 'down', port.link_up ? 'ok' : 'mute')),
      h('td', {}, fmtSpeed(port.speed_mbps),
        port.max_speed_mbps && port.speed_mbps && port.speed_mbps < port.max_speed_mbps
          ? h('div', { class: 'small dim' }, `of ${fmtSpeed(port.max_speed_mbps)}`) : null),
      h('td', {}, port.duplex || '—'),
      h('td', { class: 'num' }, fmtBits(port.rates?.rx_bps)),
      h('td', { class: 'num' }, fmtBits(port.rates?.tx_bps)),
      compact ? null : h('td', { class: 'num' },
        `${(port.counters?.rx_errors || 0) + (port.counters?.tx_errors || 0)}`,
        port.counters?.crc_errors
          ? h('div', { class: 'small dim' }, `${port.counters.crc_errors} CRC`) : null),
      compact ? null : h('td', { class: 'small dim' },
        port.phy?.chip || port.phy?.driver || '—')))));
}

pages.ports = async (root) => {
  const data = await api('/ports');
  const cfg = (await api('/config')).running;
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, 'Physical ports')),
      h('div', { class: 'body tight table-wrap' }, portsTable(data.items || [], false))),
    h('div', { class: 'grid c2 mt' },
      (data.items || []).map((port) => portEditor(port, cfg))));
};

function portEditor(port, cfg) {
  const role = h('select', {}, ['lan', 'wan', 'disabled'].map((r) =>
    h('option', { value: r, selected: port.role === r }, r)));
  const network = h('select', {},
    h('option', { value: '' }, '—'),
    Object.keys(cfg.networks || {}).map((nid) =>
      h('option', { value: nid, selected: port.network === nid }, nid)));
  const mtu = h('input', { type: 'number', min: '576', max: '9216', value: port.mtu || 1500 });
  const speed = h('select', {},
    h('option', { value: 'auto', selected: true }, 'auto'),
    (port.supported_speeds || []).map((s) =>
      h('option', { value: String(s) }, fmtSpeed(s))));
  const flow = h('input', { type: 'checkbox', checked: port.flow_control?.rx !== false });

  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, port.name || port.id),
      h('div', { class: 'spacer' }),
      h('span', { class: 'small dim mono' }, port.mac || '')),
    h('div', { class: 'body' },
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Role'), role),
        h('label', { class: 'field' }, h('span', {}, 'Network'), network)),
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'MTU'), mtu),
        h('label', { class: 'field' }, h('span', {}, 'Speed'), speed)),
      h('label', { class: 'field inline' }, flow,
        h('span', { style: 'margin:0' }, 'Flow control')),
      h('button', { class: 'primary sm', onclick: () => mutate(() =>
        api(`/ports/${port.id}`, { method: 'PUT', body: {
          role: role.value,
          network: role.value === 'lan' ? (network.value || null) : null,
          mtu: Number(mtu.value),
          speed: speed.value,
          flow_control: flow.checked,
        }}), `Port ${port.id} updated`) }, 'Apply')));
}

/* -------------------------------------------------------------------- wan */

pages.wan = async (root) => {
  const data = await api('/wans');
  const cfg = (await api('/config')).running;
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, 'WAN interfaces'),
        h('div', { class: 'spacer' }),
        data.primary ? pill(`Primary: ${data.primary}`, 'info') : null),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {},
            h('th', {}, 'WAN'), h('th', {}, 'Port'), h('th', {}, 'Mode'),
            h('th', {}, 'State'), h('th', {}, 'Address'), h('th', {}, 'Gateway'),
            h('th', { class: 'num' }, 'Latency'), h('th', { class: 'num' }, 'Loss'),
            h('th', { class: 'num' }, 'Priority'))),
          h('tbody', {}, (data.items || []).map(({ id, config, state }) => h('tr', {},
            h('td', {}, h('b', {}, config.name || id)),
            h('td', { class: 'mono small' }, state.interface || config.port),
            h('td', {}, config.mode),
            h('td', {}, statePill(state.state)),
            h('td', { class: 'mono small' }, (state.addresses || []).join(', ') || '—'),
            h('td', { class: 'mono small' }, state.gateway || '—'),
            h('td', { class: 'num' }, state.latency_ms != null ? `${state.latency_ms} ms` : '—'),
            h('td', { class: 'num' }, state.loss_percent != null ? `${state.loss_percent}%` : '—'),
            h('td', { class: 'num' }, config.priority)))))),
    h('div', { class: 'grid c2 mt' },
      (data.items || []).map(({ id, config }) => wanEditor(id, config, cfg)))));
};

function wanEditor(id, wan, cfg) {
  const mode = h('select', {}, ['dhcp', 'static', 'pppoe', 'disabled'].map((m) =>
    h('option', { value: m, selected: wan.mode === m }, m)));
  // Label ports with their name, not just eth0..eth3: this dropdown is what
  // actually moves the uplink, and a bare interface name gives no clue which
  // socket is the 2.5G one. Marking the non-WAN-role ports explains why
  // choosing one alone is not enough.
  const port = h('select', {}, Object.entries(cfg.ports || {}).map(([p, pc]) =>
    h('option', { value: p, selected: wan.port === p },
      `${p} — ${pc.name || p}${pc.role === 'wan' ? '' : ' (role: ' + pc.role + ')'}`)));
  const vlan = h('input', { type: 'number', min: '1', max: '4094',
    value: wan.vlan ?? '', placeholder: 'untagged' });
  const priority = h('input', { type: 'number', min: '1', max: '32', value: wan.priority ?? 1 });
  const mtu = h('input', { type: 'number', min: '576', max: '9216', value: wan.mtu ?? 1500 });
  const address = h('input', { type: 'text', value: wan.static?.address ?? '',
    placeholder: '203.0.113.10/24' });
  const gateway = h('input', { type: 'text', value: wan.static?.gateway ?? '',
    placeholder: '203.0.113.1' });
  const user = h('input', { type: 'text', value: wan.pppoe?.username ?? '' });
  const pass = h('input', { type: 'password', placeholder: 'unchanged' });
  const ipv6 = h('select', {}, ['disabled', 'dhcpv6', 'dhcpv6-pd', 'slaac', 'static']
    .map((m) => h('option', { value: m, selected: wan.ipv6?.mode === m }, m)));
  const enabled = h('input', { type: 'checkbox', checked: wan.enabled !== false });

  const staticBox = h('div', { class: 'row' },
    h('label', { class: 'field' }, h('span', {}, 'Address (CIDR)'), address),
    h('label', { class: 'field' }, h('span', {}, 'Gateway'), gateway));
  const pppoeBox = h('div', { class: 'row' },
    h('label', { class: 'field' }, h('span', {}, 'PPPoE username'), user),
    h('label', { class: 'field' }, h('span', {}, 'PPPoE password'), pass));

  const sync = () => {
    staticBox.style.display = mode.value === 'static' ? '' : 'none';
    pppoeBox.style.display = mode.value === 'pppoe' ? '' : 'none';
  };
  mode.addEventListener('change', sync);
  setTimeout(sync, 0);

  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, wan.name || id),
      h('div', { class: 'spacer' }),
      h('label', { class: 'inline small' }, enabled, 'Enabled')),
    h('div', { class: 'body' },
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Mode'), mode),
        h('label', { class: 'field' }, h('span', {}, 'Port'), port)),
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'VLAN'), vlan),
        h('label', { class: 'field' }, h('span', {}, 'Priority'), priority),
        h('label', { class: 'field' }, h('span', {}, 'MTU'), mtu)),
      staticBox, pppoeBox,
      h('label', { class: 'field' }, h('span', {}, 'IPv6 mode'), ipv6),
      h('button', { class: 'primary sm', onclick: () => {
        const body = {
          mode: mode.value, port: port.value, priority: Number(priority.value),
          mtu: Number(mtu.value), enabled: enabled.checked,
          vlan: vlan.value === '' ? null : Number(vlan.value),
          ipv6: { mode: ipv6.value },
        };
        if (mode.value === 'static') {
          body.static = { address: address.value.trim(), gateway: gateway.value.trim() };
        }
        if (mode.value === 'pppoe') {
          body.pppoe = { username: user.value.trim() };
          if (pass.value) body.pppoe.password = pass.value;
        }
        return mutate(() => api(`/wans/${id}`, { method: 'PUT', body }),
          `WAN ${id} updated`);
      }}, 'Apply')));
}

/* --------------------------------------------------------------- networks */

pages.networks = async (root) => {
  const data = await api('/networks');
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, 'Networks'),
        h('div', { class: 'spacer' }),
        h('button', { class: 'primary sm', onclick: newNetworkModal }, '+ New network')),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {},
            h('th', {}, 'Name'), h('th', {}, 'Purpose'), h('th', {}, 'Zone'),
            h('th', {}, 'VLAN'), h('th', {}, 'Subnet'), h('th', {}, 'Interface'),
            h('th', {}, 'DHCP'), h('th', { class: 'num' }, 'Leases'),
            h('th', {}, ''))),
          h('tbody', {}, (data.items || []).map(({ id, config, state }) => h('tr', {},
            h('td', {}, h('b', {}, config.name || id),
              h('div', { class: 'small dim mono' }, id)),
            h('td', {}, config.purpose),
            h('td', {}, pill(config.zone, config.zone === 'lan' ? 'info' : 'mute')),
            h('td', {}, config.vlan ?? h('span', { class: 'dim' }, 'untagged')),
            h('td', { class: 'mono small' }, config.subnet || '—'),
            h('td', { class: 'mono small' }, state.interface || '—'),
            h('td', {}, pill(config.dhcp?.enabled ? 'on' : 'off',
              config.dhcp?.enabled ? 'ok' : 'mute')),
            h('td', { class: 'num' }, state.lease_count ?? 0),
            h('td', { class: 'nowrap' },
              h('button', { class: 'sm ghost', onclick: () =>
                networkModal(id, config) }, 'Edit'),
              id === 'default' ? null : h('button', { class: 'sm ghost danger',
                onclick: () => confirmDelete(`network ${id}`, () =>
                  api(`/networks/${id}`, { method: 'DELETE' })) }, 'Delete')))))))));
};

function networkFields(config = {}) {
  const f = {
    name: h('input', { type: 'text', value: config.name || '' }),
    purpose: h('select', {}, ['corporate', 'guest', 'iot', 'voice', 'management', 'dmz']
      .map((p) => h('option', { value: p, selected: config.purpose === p }, p))),
    zone: h('select', {}, ['lan', 'guest', 'iot', 'dmz', 'management', 'vpn']
      .map((z) => h('option', { value: z, selected: config.zone === z }, z))),
    vlan: h('input', { type: 'number', min: '1', max: '4094',
      value: config.vlan ?? '', placeholder: 'untagged' }),
    subnet: h('input', { type: 'text', value: config.subnet || '',
      placeholder: '192.168.10.1/24' }),
    dhcp: h('input', { type: 'checkbox', checked: config.dhcp?.enabled !== false }),
    start: h('input', { type: 'text', value: config.dhcp?.start || '',
      placeholder: '192.168.10.100' }),
    end: h('input', { type: 'text', value: config.dhcp?.end || '',
      placeholder: '192.168.10.250' }),
    lease: h('input', { type: 'number', min: '120', value: config.dhcp?.lease_seconds || 86400 }),
    isolation: h('input', { type: 'checkbox', checked: !!config.isolation }),
    internet: h('input', { type: 'checkbox', checked: config.internet_access !== false }),
  };
  const form = h('div', {},
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Name'), f.name),
      h('label', { class: 'field' }, h('span', {}, 'Purpose'), f.purpose)),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Firewall zone'), f.zone),
      h('label', { class: 'field' }, h('span', {}, 'VLAN ID',
        h('span', { class: 'help' }, ' — blank for untagged')), f.vlan)),
    h('label', { class: 'field' }, h('span', {}, 'Gateway address / subnet'), f.subnet),
    h('label', { class: 'field inline' }, f.dhcp, h('span', { style: 'margin:0' }, 'DHCP server')),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Pool start'), f.start),
      h('label', { class: 'field' }, h('span', {}, 'Pool end'), f.end),
      h('label', { class: 'field' }, h('span', {}, 'Lease (s)'), f.lease)),
    h('div', { class: 'row' },
      h('label', { class: 'field inline' }, f.isolation,
        h('span', { style: 'margin:0' }, 'Client isolation')),
      h('label', { class: 'field inline' }, f.internet,
        h('span', { style: 'margin:0' }, 'Internet access'))));

  const collect = () => ({
    name: f.name.value.trim(), purpose: f.purpose.value, zone: f.zone.value,
    vlan: f.vlan.value === '' ? null : Number(f.vlan.value),
    subnet: f.subnet.value.trim(),
    isolation: f.isolation.checked, internet_access: f.internet.checked,
    dhcp: { enabled: f.dhcp.checked, start: f.start.value.trim(),
      end: f.end.value.trim(), lease_seconds: Number(f.lease.value) },
  });
  return { form, collect };
}

function networkModal(id, config) {
  const { form, collect } = networkFields(config);
  modal(`Edit network · ${id}`, form, () =>
    mutate(() => api(`/networks/${id}`, { method: 'PUT', body: collect() }),
      `Network ${id} updated`));
}

function newNetworkModal() {
  const idInput = h('input', { type: 'text', placeholder: 'guest', required: 'required' });
  const { form, collect } = networkFields({ purpose: 'guest', zone: 'guest' });
  modal('New network',
    h('div', {}, h('label', { class: 'field' },
      h('span', {}, 'Identifier', h('span', { class: 'help' }, ' — lowercase, no spaces')),
      idInput), form),
    () => mutate(() => api('/networks', { method: 'POST',
      body: { id: idInput.value.trim(), ...collect() } }), 'Network created'));
}

/* --------------------------------------------------------- traffic and DNS */

const listLines = (value) => String(value || '').split(/[\n,]+/)
  .map((part) => part.trim()).filter(Boolean);

pages.services = async (root) => {
  const data = await api('/services');
  const qos = data.qos || {};
  const dns = data.dns || {};
  const filtering = dns.filtering || {};
  const qstat = data.status?.qos || {};
  const dstat = data.status?.dns || {};

  const qosEnabled = h('input', { type: 'checkbox', checked: !!qos.enabled });
  const download = h('input', { type: 'number', min: '0', step: '1',
    value: (qos.download_kbps || 0) / 1000 });
  const upload = h('input', { type: 'number', min: '0', step: '1',
    value: (qos.upload_kbps || 0) / 1000 });
  const shapeFields = [download, upload];
  const syncQos = () => shapeFields.forEach((field) => { field.disabled = !qosEnabled.checked; });
  qosEnabled.addEventListener('change', syncQos);
  syncQos();

  const qosState = !qstat.requested ? pill('Off', 'mute')
    : qstat.effective ? pill('Active', 'ok')
      : pill(qstat.error ? 'Error' : 'Waiting', qstat.error ? 'bad' : 'warn');
  const qosCard = h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Smart Queues'), h('div', { class: 'spacer' }), qosState),
    h('div', { class: 'body' },
      qstat.error ? h('div', { class: 'banner bad' }, icon('error', 15),
        h('div', {}, qstat.error)) : null,
      h('p', { class: 'small dim service-copy' },
        'CAKE keeps latency predictable when the WAN is busy. Set rates slightly below the measured line speed.'),
      h('label', { class: 'field inline' }, qosEnabled,
        h('span', { style: 'margin:0' }, 'Enable Smart Queues')),
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Download',
          h('span', { class: 'help' }, ' — Mbps')), download),
        h('label', { class: 'field' }, h('span', {}, 'Upload',
          h('span', { class: 'help' }, ' — Mbps')), upload)),
      h('div', { class: 'service-runtime' }, (qstat.interfaces || []).map((entry) =>
        h('div', { class: 'small' }, h('span', { class: 'mono' }, entry.interface), ' ',
          pill(entry.download_active ? 'down shaped' : 'down direct',
            entry.download_active ? 'info' : 'mute'), ' ',
          pill(entry.upload_active ? 'up shaped' : 'up direct',
            entry.upload_active ? 'info' : 'mute')))),
      h('button', { class: 'primary sm', onclick: () => mutate(() =>
        api('/services', { method: 'PUT', body: { qos: {
          enabled: qosEnabled.checked,
          download_kbps: Math.round(Number(download.value || 0) * 1000),
          upload_kbps: Math.round(Number(upload.value || 0) * 1000),
        }} }), 'Smart Queue settings updated') }, 'Apply')));

  const upstream = h('textarea', { rows: '3', value: (dns.upstream || []).join('\n'),
    spellcheck: 'false' });
  const cache = h('input', { type: 'number', min: '0', max: '100000',
    value: dns.cache_size ?? 4096 });
  const dnssec = h('input', { type: 'checkbox', checked: !!dns.dnssec });
  const queryLog = h('input', { type: 'checkbox', checked: !!dns.query_log });
  const filterEnabled = h('input', { type: 'checkbox', checked: !!filtering.enabled });
  const blocklist = h('textarea', { rows: '4', value: (filtering.blocklist || []).join('\n'),
    spellcheck: 'false', placeholder: 'telemetry.example.com' });
  const allowlist = h('textarea', { rows: '4', value: (filtering.allowlist || []).join('\n'),
    spellcheck: 'false', placeholder: 'allowed.example.com' });
  const filterFields = [blocklist, allowlist];
  const syncFilter = () => filterFields.forEach((field) => {
    field.disabled = !filterEnabled.checked;
  });
  filterEnabled.addEventListener('change', syncFilter);
  syncFilter();

  const dnsCard = h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'DNS resolver'), h('div', { class: 'spacer' }),
      pill(dstat.running ? 'Running' : 'Stopped', dstat.running ? 'ok' : 'bad')),
    h('div', { class: 'body' },
      dstat.error ? h('div', { class: 'banner bad' }, icon('error', 15),
        h('div', {}, dstat.error)) : null,
      h('label', { class: 'field' }, h('span', {}, 'Upstream resolvers',
        h('span', { class: 'help' }, ' — one address per line')), upstream),
      h('label', { class: 'field' }, h('span', {}, 'Cache entries'), cache),
      h('div', { class: 'row' },
        h('label', { class: 'field inline' }, dnssec,
          h('span', { style: 'margin:0' }, 'Validate DNSSEC')),
        h('label', { class: 'field inline' }, queryLog,
          h('span', { style: 'margin:0' }, 'Log DNS queries'))),
      h('div', { class: 'service-divider' }),
      h('label', { class: 'field inline' }, filterEnabled,
        h('span', { style: 'margin:0' }, 'Domain filtering')),
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Blocklist'), blocklist),
        h('label', { class: 'field' }, h('span', {}, 'Allowlist'), allowlist)),
      h('button', { class: 'primary sm', onclick: () => mutate(() =>
        api('/services', { method: 'PUT', body: { dns: {
          upstream: listLines(upstream.value), cache_size: Number(cache.value),
          dnssec: dnssec.checked, query_log: queryLog.checked,
          filtering: { enabled: filterEnabled.checked,
            blocklist: listLines(blocklist.value), allowlist: listLines(allowlist.value) },
        }} }), 'DNS settings updated') }, 'Apply')));

  const records = dns.records || [];
  const recordTable = dataTable(
    ['Name', 'Type', 'Value', ''], records,
    (record, index) => h('tr', {},
      h('td', { class: 'mono small' }, record.name),
      h('td', {}, pill(record.type || 'A', 'mute')),
      h('td', { class: 'mono small' }, record.value),
      h('td', {}, h('button', { class: 'sm ghost danger', onclick: () =>
        confirmDelete(`DNS record ${record.name}`, () => api('/services', {
          method: 'PUT', body: { dns: { records: records.filter((_r, i) => i !== index) } },
        })) }, 'Delete'))),
    'No local DNS records.');
  const recordsCard = tableCard('Local DNS records',
    h('button', { class: 'primary sm', onclick: () => dnsRecordModal(records) },
      '+ New record'), recordTable);

  const forwarders = dns.conditional_forwarders || [];
  const forwarderTable = dataTable(
    ['Domain', 'Resolver', ''], forwarders,
    (entry, index) => h('tr', {},
      h('td', { class: 'mono small' }, entry.domain),
      h('td', { class: 'mono small' }, entry.server),
      h('td', {}, h('button', { class: 'sm ghost danger', onclick: () =>
        confirmDelete(`forwarder for ${entry.domain}`, () => api('/services', {
          method: 'PUT', body: { dns: { conditional_forwarders:
            forwarders.filter((_r, i) => i !== index) } },
        })) }, 'Delete'))),
    'No conditional forwarders.');
  const forwardersCard = tableCard('Conditional forwarding',
    h('button', { class: 'primary sm', onclick: () => dnsForwarderModal(forwarders) },
      '+ New forwarder'), forwarderTable);

  root.append(h('div', { class: 'grid c2 service-grid' }, qosCard, dnsCard),
    h('div', { class: 'grid c2 mt' }, recordsCard, forwardersCard));
};

/* ------------------------------------------------ traffic identification */

pages.dpi = async (root) => {
  const data = await api('/dpi');
  const cfg = data.config || {};
  const status = data.status || {};
  const applications = data.applications || [];
  const clients = data.clients || [];
  const rxBytes = applications.reduce((sum, app) => sum + Number(app.rx_bytes || 0), 0);
  const txBytes = applications.reduce((sum, app) => sum + Number(app.tx_bytes || 0), 0);
  const totalBytes = rxBytes + txBytes;
  const topApplication = applications.reduce((best, app) =>
    Number(app.rx_bytes || 0) + Number(app.tx_bytes || 0)
      > Number(best?.rx_bytes || 0) + Number(best?.tx_bytes || 0) ? app : best, null);
  const enabled = h('input', { type: 'checkbox', checked: !!cfg.enabled });
  const ipv6 = h('input', { type: 'checkbox', checked: cfg.include_ipv6 !== false });
  const retention = h('input', { type: 'number', min: '1', max: '720', step: '1',
    value: cfg.retention_hours || 24 });

  const state = !cfg.enabled ? pill('Off', 'mute')
    : status.running ? pill('Inspecting', 'ok')
      : pill(status.tool_available ? 'Stopped' : 'Suricata missing', 'bad');
  const apply = () => mutate(() => api('/dpi', { method: 'PUT', body: {
    enabled: enabled.checked, engine: 'suricata',
    retention_hours: Number(retention.value), include_ipv6: ipv6.checked,
  }}), 'DPI settings updated');

  root.append(
    pageLead('Deep Packet Inspection',
      'See which applications and clients are using the connection. DPI records flow metadata and byte counts; payloads are never stored.', [state]),
    status.error ? h('div', { class: 'banner bad' }, icon('error', 15, 'ico'),
      h('div', {}, status.error)) : null,

    h('div', { class: 'grid kpi-grid' },
      statCard('Identified traffic', fmtBytes(totalBytes), {
        hint: `↓ ${fmtBytes(rxBytes)} · ↑ ${fmtBytes(txBytes)}` }),
      statCard('Applications', applications.length, {
        hint: topApplication ? `Top: ${topApplication.name}` : 'Waiting for classified flows' }),
      statCard('Active clients', clients.length, {
        hint: `${clients.length} with identified traffic` }),
      statCard('DPI engine', status.running ? 'Running' : cfg.enabled ? 'Stopped' : 'Off', {
        hint: status.tool_available ? 'Suricata 7 · flow metadata only' : 'Suricata is unavailable' })),

    h('div', { class: 'card mt dpi-settings' },
      h('div', { class: 'body' },
        h('label', { class: 'switch-row' },
          h('div', {}, h('b', {}, 'Deep Packet Inspection'),
            h('span', {}, 'Classify application traffic across LAN networks.')),
          h('span', { class: 'switch' }, enabled, h('i', {}))),
        h('div', { class: 'settings-inline' },
          h('label', { class: 'field' }, h('span', {}, 'Data retention'),
            h('div', { class: 'input-suffix' }, retention, h('span', {}, 'hours'))),
          h('label', { class: 'switch-row compact' },
            h('div', {}, h('b', {}, 'Include IPv6'),
              h('span', {}, 'Inspect IPv4 and IPv6 flows.')),
            h('span', { class: 'switch' }, ipv6, h('i', {}))),
          h('button', { class: 'primary', onclick: apply }, 'Apply changes')))),

    h('div', { class: 'grid c2 mt dpi-tables' },
      tableCard('Applications', h('span', { class: 'header-note' },
        `${applications.length} identified`),
        dataTable(['Application', ['Traffic', { num: true }], 'Share'],
          applications, (app) => {
            const bytes = Number(app.rx_bytes || 0) + Number(app.tx_bytes || 0);
            const share = totalBytes ? Math.round(bytes * 100 / totalBytes) : 0;
            return [
              h('div', { class: 'traffic-name' },
                h('span', { class: 'app-mark' }, (app.name || '?').slice(0, 1).toUpperCase()),
                h('div', {}, h('b', {}, app.name),
                  h('span', { class: 'mono' }, app.protocol))),
              h('div', {}, h('b', {}, fmtBytes(bytes)),
                h('span', { class: 'traffic-split' },
                  `↓ ${fmtBytes(app.rx_bytes)} · ↑ ${fmtBytes(app.tx_bytes)}`)),
              h('div', { class: 'share-cell' }, h('b', {}, `${share}%`),
                h('div', { class: 'bar' }, h('i', { style: `width:${share}%` }))),
            ];
          }, 'No classified applications yet. Enable DPI and generate traffic.')),
      tableCard('Clients', h('span', { class: 'header-note' },
        `${clients.length} active`),
        dataTable(['Client', ['Traffic', { num: true }], ['Download', { num: true }],
          ['Upload', { num: true }]], clients, (client) => [
            h('div', { class: 'traffic-name' },
              h('span', { class: 'client-mark' }, icon('device', 15)),
              h('div', {}, h('b', { class: 'mono' }, client.client),
                h('span', { class: 'mono' }, client.client_ip || ''))),
            h('b', {}, fmtBytes(Number(client.rx_bytes || 0) + Number(client.tx_bytes || 0))),
            fmtBytes(client.rx_bytes), fmtBytes(client.tx_bytes),
          ], 'No client traffic identified yet.'))));
};

/* ------------------------------------------------------ UniFi controller */

pages.controller = async (root) => {
  const data = await api('/controller');
  const cfg = data.config || {};
  const state = data.state || {};
  const enabled = h('input', { type: 'checkbox', checked: !!cfg.enabled });
  const discovery = h('input', { type: 'checkbox', checked: cfg.discovery !== false });
  const sync = h('input', { type: 'checkbox', checked: !!cfg.sync_enabled });
  const verifyTls = h('input', { type: 'checkbox', checked: cfg.verify_tls !== false });
  const inform = h('input', { type: 'url', value: cfg.inform_url || '',
    placeholder: 'http://network.example:8080/inform', spellcheck: 'false' });
  const interval = h('input', { type: 'number', min: '5', max: '300', step: '1',
    value: cfg.interval_seconds || 10 });
  const apiUrl = h('input', { type: 'url', value: cfg.api_url || '',
    placeholder: 'https://console/proxy/network/integration/v1', spellcheck: 'false' });
  const site = h('input', { type: 'text', value: cfg.site_id || '',
    placeholder: 'Site UUID', spellcheck: 'false' });
  const apiKey = h('input', { type: 'password', value: '',
    placeholder: cfg.api_key === '********' ? 'Unchanged' : 'Network API key',
    autocomplete: 'new-password', spellcheck: 'false' });

  const syncFields = [apiUrl, site, apiKey, verifyTls];
  const syncControls = () => syncFields.forEach((field) => { field.disabled = !sync.checked; });
  sync.addEventListener('change', syncControls);
  syncControls();

  const apply = () => {
    const body = {
      enabled: enabled.checked, inform_url: inform.value.trim(),
      discovery: discovery.checked, interval_seconds: Number(interval.value),
      sync_enabled: sync.checked, api_url: apiUrl.value.trim(),
      site_id: site.value.trim(), verify_tls: verifyTls.checked,
    };
    if (apiKey.value) body.api_key = apiKey.value;
    return mutate(() => api('/controller', { method: 'PUT', body }),
      'Controller settings updated');
  };

  const controllerState = !cfg.enabled ? pill('Off', 'mute')
    : state.adopted ? pill('Adopted', 'ok') : pill('Waiting for adoption', 'warn');
  root.append(
    h('div', { class: 'grid c2' },
      h('div', { class: 'card' },
        h('header', {}, h('h2', {}, 'Console connection'),
          h('div', { class: 'spacer' }), controllerState),
        h('div', { class: 'body' },
          state.error ? h('div', { class: 'banner bad' }, icon('error', 15, 'ico'),
            h('div', {}, state.error)) : null,
          !data.crypto_available ? h('div', { class: 'banner warn' }, icon('warn', 15, 'ico'),
            h('div', {}, 'python3-cryptography is required for UniFi inform.')) : null,
          h('label', { class: 'field inline' }, enabled,
            h('span', { style: 'margin:0' }, 'Enable UniFi Network control')),
          h('label', { class: 'field' }, h('span', {}, 'Inform URL'), inform),
          h('div', { class: 'row' },
            h('label', { class: 'field inline' }, discovery,
              h('span', { style: 'margin:0' }, 'Layer-2 discovery')),
            h('label', { class: 'field' }, h('span', {}, 'Inform interval',
              h('span', { class: 'help' }, ' — seconds')), interval)),
          h('button', { class: 'primary sm', onclick: apply }, 'Apply'))),

      h('div', { class: 'card' },
        h('header', {}, h('h2', {}, 'Network API synchronization'),
          h('div', { class: 'spacer' }),
          cfg.sync_enabled ? pill('Enabled', 'info') : pill('Off', 'mute')),
        h('div', { class: 'body' },
          h('p', { class: 'small dim service-copy' },
            'Pulls supported networks, WiFi broadcasts and DNS policies from the documented local Network API.'),
          h('label', { class: 'field inline' }, sync,
            h('span', { style: 'margin:0' }, 'Synchronize desired state')),
          h('label', { class: 'field' }, h('span', {}, 'Integration API URL'), apiUrl),
          h('label', { class: 'field' }, h('span', {}, 'Site ID'), site),
          h('label', { class: 'field' }, h('span', {}, 'API key'), apiKey),
          h('label', { class: 'field inline' }, verifyTls,
            h('span', { style: 'margin:0' }, 'Verify controller certificate')),
          h('button', { class: 'primary sm', onclick: apply }, 'Apply')))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Controller status')),
      h('div', { class: 'body' },
        h('div', { class: 'grid c4' },
          kv('Pairing', state.adopted ? 'Adopted' : 'Not adopted'),
          kv('Last inform', fmtTime(state.last_inform)),
          kv('Last sync', fmtTime(state.last_sync)),
          kv('Response', state.last_response || '—')),
        (state.unsupported || []).length ? h('div', { class: 'banner warn mt' },
          icon('warn', 15, 'ico'), h('div', {},
            `Not applied by this gateway: ${state.unsupported.join(', ')}`)) : null,
        h('div', { class: 'row mt' },
          h('button', { class: 'sm', disabled: !cfg.enabled, onclick: () => mutate(() =>
            api('/controller/inform', { method: 'POST' }), 'Inform sent') }, 'Send inform'),
          h('button', { class: 'sm', disabled: !cfg.sync_enabled, onclick: () => mutate(() =>
            api('/controller/sync', { method: 'POST' }), 'Controller state synchronized') },
            'Sync now'),
          h('button', { class: 'sm ghost danger', onclick: () =>
            confirmAction('Reset controller pairing?',
              'The gateway will return to the pending-adoption state.', () =>
                api('/controller/reset', { method: 'POST' })) }, 'Reset pairing')))));
};

function dnsRecordModal(records) {
  const name = h('input', { type: 'text', placeholder: 'printer.lan' });
  const type = h('select', {}, ['A', 'AAAA', 'CNAME', 'SRV', 'TXT']
    .map((kind) => h('option', { value: kind }, kind)));
  const value = h('input', { type: 'text', placeholder: '192.168.2.20' });
  modal('New local DNS record', h('div', {},
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Name'), name),
      h('label', { class: 'field' }, h('span', {}, 'Type'), type)),
    h('label', { class: 'field' }, h('span', {}, 'Value'), value)),
  () => mutate(() => api('/services', { method: 'PUT', body: { dns: {
    records: [...records, { name: name.value.trim(), type: type.value,
      value: value.value.trim() }],
  }} }), 'DNS record created'));
}

function dnsForwarderModal(forwarders) {
  const domain = h('input', { type: 'text', placeholder: 'corp.example' });
  const server = h('input', { type: 'text', placeholder: '10.0.0.53' });
  modal('New conditional forwarder', h('div', { class: 'row' },
    h('label', { class: 'field' }, h('span', {}, 'Domain'), domain),
    h('label', { class: 'field' }, h('span', {}, 'Resolver'), server)),
  () => mutate(() => api('/services', { method: 'PUT', body: { dns: {
    conditional_forwarders: [...forwarders, { domain: domain.value.trim(),
      server: server.value.trim() }],
  }} }), 'Conditional forwarder created'));
}

/* ------------------------------------------------------------ wifi: radios */

pages.radios = async (root) => {
  const [radios, caps, cfg] = await Promise.all([
    api('/wifi/radios'), api('/wifi/capabilities'), api('/config')]);
  const configured = cfg.running.wifi?.radios || {};
  root.append(
    caps.mlo?.supported ? null : h('div', { class: 'banner info' },
      h('span', {}, 'ℹ'),
      h('div', {}, h('b', {}, 'MLO unavailable: '), caps.mlo?.reason || 'unknown')),
    regulatoryCard(cfg.running.wifi?.regulatory || {}),
    radioCards(radios.items || [], []),
    h('div', { class: 'grid c2 mt' },
      (radios.items || []).map((radio) => radioEditor(radio, configured[radio.id] || {}))));
};

function regulatoryCard(reg) {
  const env = h('select', {}, [
    ['indoor', 'Indoor'], ['outdoor', 'Outdoor'], ['any', 'Any environment'],
  ].map(([v, t]) => h('option', { value: v,
    selected: (reg.environment || 'indoor') === v }, t)));
  const power = h('select', {}, [
    ['lpi', 'Low Power Indoor (LPI)'],
    ['sp', 'Standard Power (needs AFC)'],
    ['vlp', 'Very Low Power (VLP)'],
  ].map(([v, t]) => h('option', { value: v,
    selected: (reg.six_ghz_power || 'lpi') === v }, t)));

  const row = (a, b, c) => h('tr', {}, h('td', {}, a),
    h('td', { class: 'num' }, b), h('td', { class: 'num' }, c));
  const measured = h('div', { class: 'mt' },
    h('div', { class: 'small muted mb' },
      'Transmit power measured on this board while beaconing. 33 dBm is not '
      + 'offered anywhere in this device\u2019s regulatory table.'),
    h('table', { class: 'tbl small' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Band / channel'),
        h('th', { class: 'num' }, 'Limit'), h('th', { class: 'num' }, 'Actual'))),
      h('tbody', {},
        row('2.4 GHz', '30 dBm', '30 dBm'),
        row('5 GHz ch36/149 (80 MHz)', '30 dBm', '28 dBm'),
        row('5 GHz ch100-144 (DFS)', '24 dBm', '24 dBm'),
        row('6 GHz 320 MHz', '30 dBm', '23 dBm'),
        row('6 GHz 160 MHz', '30 dBm', '21 dBm'),
        row('6 GHz 80 MHz', '30 dBm', '18 dBm'),
        row('6 GHz 20 MHz', '30 dBm', '13 dBm'))),
    h('div', { class: 'small muted mt' },
      '6 GHz is power-spectral-density limited, so its power rises with '
      + 'bandwidth (about +3 dB per doubling) and sits roughly 5 dB under the '
      + 'FCC low-power-indoor allowance. The 6 GHz power mode below did not '
      + 'change it on this firmware, and the driver exposes no power '
      + 'parameter. On 5 GHz the lever is the channel: 28 dBm on 36 or 149 '
      + 'against 24 dBm on the DFS channels that 240 MHz requires.'));

  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Regulatory environment'),
      h('div', { class: 'spacer' })),
    h('div', { class: 'body' },
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Environment'), env),
        h('label', { class: 'field' }, h('span', {}, '6 GHz power mode'), power)),
      measured,
      h('div', { class: 'mt' },
        h('button', { class: 'primary sm', onclick: () => mutate(
          () => api('/wifi/regulatory', { method: 'PUT', body: {
            environment: env.value, six_ghz_power: power.value } }),
          'Regulatory settings applied') }, 'Apply'))));
}

function radioEditor(radio, cfg) {
  const caps = radio.capabilities || {};
  const enabled = h('input', { type: 'checkbox', checked: cfg.enabled !== false });
  const channel = h('select', {},
    h('option', { value: 'auto', selected: cfg.channel === 'auto' }, 'auto (ACS)'),
    (caps.channels || []).map((c) => {
      const detail = (caps.channel_details || []).find((d) => d.channel === c) || {};
      const flags = [detail.dfs ? 'DFS' : null, detail.psc ? 'PSC' : null,
        detail.max_tx_power_dbm != null ? `${detail.max_tx_power_dbm} dBm` : null]
        .filter(Boolean).join(' ');
      return h('option', { value: String(c), selected: String(cfg.channel) === String(c) },
        `${c}${flags ? ' · ' + flags : ''}`);
    }));
  const width = h('select', {}, (caps.widths || [20]).map((w) =>
    h('option', { value: String(w), selected: Number(cfg.channel_width) === w },
      // 240 MHz is 320 MHz EHT with an 80 MHz puncture, not a standard width;
      // say so in the picker so the operator knows what they are choosing.
      w === 240 ? '240 MHz (punctured)'
        : w === 320 ? '320 MHz' : `${w} MHz`)));
  const power = h('select', {},
    h('option', { value: 'auto', selected: cfg.tx_power === 'auto' }, 'auto'),
    Array.from({ length: 12 }, (_, i) => 30 - i * 2).filter((p) =>
      !caps.max_tx_power_dbm || p <= caps.max_tx_power_dbm).map((p) =>
      h('option', { value: String(p), selected: String(cfg.tx_power) === String(p) },
        `${p} dBm`)));

  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, radio.label || radio.id),
      h('div', { class: 'spacer' }),
      h('span', { class: 'small dim mono' }, `${radio.phy} · ${radio.mac || ''}`)),
    h('div', { class: 'body' },
      h('label', { class: 'field inline' }, enabled,
        h('span', { style: 'margin:0' }, 'Radio enabled')),
      h('div', { class: 'row' },
        h('label', { class: 'field' }, h('span', {}, 'Channel'), channel),
        h('label', { class: 'field' }, h('span', {}, 'Width'), width),
        h('label', { class: 'field' }, h('span', {}, 'TX power'), power)),
      h('div', { class: 'small dim mb' },
        `${(caps.standards || []).join(', ')} · up to ${caps.max_nss || 1} spatial streams`
        + ` · max ${caps.max_ap_bss || 1} BSS`),
      h('div', { class: 'inline' },
        h('button', { class: 'primary sm', onclick: () => mutate(() =>
          api(`/wifi/radios/${radio.id}`, { method: 'PUT', body: {
            enabled: enabled.checked,
            channel: channel.value === 'auto' ? 'auto' : Number(channel.value),
            channel_width: Number(width.value),
            tx_power: power.value === 'auto' ? 'auto' : Number(power.value),
          }}), `${radio.label} updated`) }, 'Apply'),
        h('button', { class: 'sm ghost', title: 'Restart this radio and reapply config',
          onclick: () => mutate(() =>
            api(`/wifi/radios/${radio.id}/recover`, { method: 'POST' }),
            'Radio recovery requested') }, 'Recover'))));
}

/* ------------------------------------------------------------- wifi: ssids */

pages.ssids = async (root) => {
  const [data, cfg, radios] = await Promise.all([
    api('/wifi/networks'), api('/config'), api('/wifi/radios')]);
  // The form needs to know which bands exist and whether MLO is available.
  const caps = { radios: Object.fromEntries((radios.items || []).map(
    (r) => [r.id, { band: r.band ?? r.capabilities?.band }])),
    mlo: radios.mlo || data.mlo_capability || {} };

  const securityCell = (config) => h('div', {},
    pill(config.security?.mode || '—',
      (config.security?.mode || '').includes('wpa3') ? 'ok' : 'warn'),
    h('div', { class: 'small dim' }, `PMF ${config.security?.pmf || '—'}`));

  const bandCells = (config) => (config.bands || []).map((b) =>
    h('span', { class: 'pill mute', style: 'margin-right:4px' }, bandLabel(b)));

  const bssidCell = (bsses) => h('div', { class: 'small mono dim' },
    (bsses || []).map((b) => h('div', {}, `${b.bssid || '—'} · ${bandLabel(b.band)}`)));

  const nameCell = (id, config) => h('div', {},
    h('b', {}, config.ssid),
    h('div', { class: 'small dim' }, config.enabled === false ? 'disabled' : id),
    config.hidden ? h('div', { class: 'small dim' }, 'hidden') : null);

  const actions = (id, config) => h('div', { class: 'nowrap' },
    h('button', { class: 'sm ghost', onclick: () => ssidModal(id, config, cfg.running, caps) },
      'Edit'),
    h('button', { class: 'sm ghost danger', onclick: () =>
      confirmDelete(`SSID ${config.ssid}`, () =>
        api(`/wifi/networks/${id}`, { method: 'DELETE' })) }, 'Delete'));

  const columns = ['SSID', 'Network', 'Bands', 'Security', 'MLO',
    ['Clients', { num: true }], 'BSSIDs', ''];

  const table = dataTable(columns, data.items || [], (item) => [
    nameCell(item.id, item.config),
    // A WAN-bridged SSID is not on any of our networks, so saying "default"
    // there would be actively misleading.
    item.config.uplink === 'wan'
      ? pill('WAN bridge', 'info')
      : item.config.network,
    bandCells(item.config),
    securityCell(item.config),
    item.mld ? pill(item.mld, 'mlo')
      : item.config.mlo ? pill('pending', 'warn')
      : h('span', { class: 'dim' }, '—'),
    item.client_count ?? 0,
    bssidCell(item.bsses),
    actions(item.id, item.config),
  ], 'No wireless networks yet.');

  const newButton = h('button', { class: 'primary sm', onclick: () =>
    ssidModal(null, {}, cfg.running, caps) }, '+ New WiFi');

  root.append(tableCard('Wireless networks', newButton, table));
};

function ssidModal(id, config, cfg, caps) {
  const isNew = !id;
  const sec = config.security || {};

  /* Small builders that keep every control in the same visual language as the
     rest of the portal: a labelled block, a radio group, or a checkbox row. */
  const grp = (title, ...kids) => h('div', { class: 'wf-group' },
    h('h3', {}, title), ...kids.filter(Boolean));
  const fld = (label, control, hint) => h('label', { class: 'field' },
    h('span', {}, label), control,
    hint ? h('div', { class: 'wf-hint' }, hint) : null);

  const radioGroup = (name, options, current) => {
    const inputs = {};
    const row = h('div', { class: 'wf-radios' }, options.map(([value, text]) => {
      const input = h('input', { type: 'radio', name,
        checked: current === value });
      inputs[value] = input;
      return h('label', { class: 'wf-radio' }, input, h('span', {}, text));
    }));
    row.value = () => Object.entries(inputs).find(([, el]) => el.checked)?.[0]
      ?? options[0][0];
    row.inputs = Object.values(inputs);
    return row;
  };

  const checkRow = (label, checked, help) => {
    const input = h('input', { type: 'checkbox', checked: !!checked });
    const node = h('label', { class: 'wf-check' }, input,
      h('span', {}, label),
      help ? h('span', { class: 'wf-info', title: help }, 'i') : null);
    node.input = input;
    return node;
  };

  /* ---------------------------------------------------------------- basics */
  const idInput = h('input', { type: 'text', value: id || '', placeholder: 'main',
    disabled: !isNew });
  const name = h('input', { type: 'text', value: config.ssid || '',
    required: 'required', placeholder: '' });
  const passWrap = (() => {
    const input = h('input', { type: 'password',
      placeholder: isNew ? '' : 'unchanged' });
    const eye = h('button', { class: 'icon wf-eye', type: 'button',
      title: 'Show password',
      onclick: () => { input.type = input.type === 'password' ? 'text' : 'password'; } },
      icon('eye', 14));
    const node = h('div', { class: 'wf-password' }, input, eye);
    node.input = input;
    return node;
  })();
  /* Which side of the router this SSID's clients live on. "wan" bridges them
     onto the upstream L2 so the upstream gateway addresses them directly and
     this router does no NAT, routing, DHCP or firewalling for them — which is
     what lets an upstream proxy see and police each client individually. */
  const uplink = radioGroup(`uplink-${id || 'new'}`, [
    ['lan', 'Behind this router (NAT)'],
    ['wan', 'Bridged to WAN (upstream assigns the IP)'],
  ], config.uplink || 'lan');
  const uplinkNotice = h('div', { class: 'wf-notice', style: 'display:none' });
  const syncUplink = () => {
    const wan = uplink.value() === 'wan';
    uplinkNotice.style.display = wan ? '' : 'none';
    uplinkNotice.textContent = wan
      ? 'Clients on this SSID get their address from the upstream gateway. '
      + 'This router will not NAT, firewall or serve DHCP for them, and they '
      + 'cannot reach its management interface. The WAN port becomes a bridge, '
      + 'which needs a reboot to take effect.'
      : '';
  };
  uplink.inputs.forEach((el) => el.addEventListener('change', syncUplink));

  const network = h('select', {}, Object.keys(cfg.networks || {}).map((n) =>
    h('option', { value: n, selected: config.network === n },
      n === 'default' ? 'Native Network' : n)));
  const broadcasting = radioGroup('wf-aps',
    [['all', 'All'], ['group', 'Group'], ['specific', 'Specific']],
    config.broadcasting_aps || 'all');
  const application = radioGroup('wf-app',
    [['standard', 'Standard'], ['hotspot', 'Hotspot'], ['iot', 'IoT']],
    config.application || 'standard');

  const bandsPresent = new Set(Object.values(caps?.radios || {})
    .map((r) => r.band).filter(Boolean));
  const bands = {};
  for (const band of ['2g', '5g', '6g']) {
    bands[band] = h('input', { type: 'checkbox',
      checked: (config.bands || ['2g', '5g']).includes(band),
      disabled: bandsPresent.size ? !bandsPresent.has(band) : false });
  }
  const bandRow = h('div', { class: 'wf-bands' },
    Object.entries(bands).map(([band, el]) => h('label',
      { class: 'wf-check' + (el.disabled ? ' is-off' : '') }, el,
      h('span', {}, bandLabel(band)),
      el.disabled ? h('span', { class: 'wf-hint' }, ' no radio') : null)));

  /* -------------------------------------------------------------- advanced */
  const advanced = h('div', { class: 'wf-seg' });
  let advancedMode = config.advanced_mode || 'auto';
  const segButton = (value, text) => {
    const b = h('button', { type: 'button',
      class: 'wf-seg-btn' + (advancedMode === value ? ' is-on' : ''),
      onclick: () => { advancedMode = value; syncAdvanced(); } }, text);
    b.dataset.value = value;
    return b;
  };
  advanced.append(segButton('auto', 'Auto'), segButton('manual', 'Manual'));

  const fastRoaming = checkRow('Fast Roaming (802.11r)', config.fast_roaming,
    'Speeds up handover between APs. Some older clients dislike it.');

  const minRate = checkRow('Minimum Data Rate (Basic & Multicast)',
    config.minimum_data_rate,
    'Drops the slowest rates so distant clients cannot hold the air.');
  const mcastFilter = radioGroup('wf-mcast',
    [['off', 'Off'], ['auto', 'Auto'], ['custom', 'Custom']],
    config.multicast_filtering || 'off');
  const mcastBlocker = checkRow('Multicast and Broadcast Blocker',
    config.multicast_broadcast_blocker,
    'Stops the AP relaying multicast and broadcast to clients (disable_dgaf).');
  const mcastToUnicast = checkRow('Multicast to Unicast',
    config.multicast_to_unicast,
    'Converts multicast to unicast per client, which can be sent at a higher rate.');

  /* -------------------------------------------------------------- security */
  const protocol = h('select', {}, [
    ['wpa2-wpa3', 'WPA2/WPA3'], ['wpa3', 'WPA3'], ['wpa2', 'WPA2'],
    ['wpa3-enterprise', 'WPA3 Enterprise'], ['wpa2-enterprise', 'WPA2 Enterprise'],
    ['open', 'Open'],
  ].map(([v, t]) => h('option', { value: v,
    selected: (sec.mode || 'wpa2-wpa3') === v }, t)));
  const pmf = radioGroup('wf-pmf',
    [['required', 'Required'], ['optional', 'Optional'], ['disabled', 'Disabled']],
    sec.pmf || 'optional');
  const ppsk = checkRow('Private Pre-Shared Keys', sec.private_preshared_keys,
    'Per-client passphrases on one SSID.');
  const hidden = checkRow('Hide WiFi Name', config.hidden,
    'Stops the SSID appearing in beacons. It is not a security measure.');
  const isolation = checkRow('Client Device Isolation', config.client_isolation,
    'Clients cannot reach each other.');
  const saeClog = h('input', { type: 'number', min: '1', max: '100',
    value: sec.sae_anti_clogging_threshold ?? 5 });
  const saeSync = h('input', { type: 'number', min: '1', max: '100',
    value: sec.sae_sync ?? 5 });

  /* ------------------------------------------------------------- behaviour */
  const mloSupported = !!caps?.mlo?.supported;
  const mlo = checkRow('MLO', config.mlo,
    mloSupported
      ? 'One multi-link association across the selected bands. Needs two or more bands.'
      : (caps?.mlo?.reason || 'Not supported by this hardware.'));
  if (!mloSupported) { mlo.input.disabled = true; mlo.classList.add('is-off'); }
  const bandSteering = checkRow('Band Steering', config.band_steering !== false,
    'Nudges dual-band clients onto the faster band.');
  const proxyArp = checkRow('Proxy ARP', config.proxy_arp,
    'The AP answers ARP for sleeping clients.');
  const bssTransition = checkRow('BSS Transition', config.bss_transition !== false,
    '802.11v transition management.');
  const uapsd = checkRow('UAPSD', config.uapsd,
    'Unscheduled power save delivery; saves client battery.');
  const macFilter = checkRow('MAC Address Filter', config.mac_filter);
  const radiusMac = checkRow('RADIUS MAC Authentication', config.radius_mac_auth,
    'Needs a RADIUS profile on this SSID.');
  const speedLimit = checkRow('WiFi Speed Limit', config.speed_limit,
    'Applies the per-network bandwidth limit.');
  const autoDtim = checkRow('Auto 802.11 DTIM Period', config.auto_dtim !== false);
  const dtim = h('input', { type: 'number', min: '1', max: '255',
    value: config.dtim_period ?? 2 });
  const groupRekey = checkRow('Group Rekey Interval', config.group_rekey_interval);
  const rekeySeconds = h('input', { type: 'number', min: '30', max: '86400',
    value: config.group_rekey_seconds ?? 3600 });
  const showApName = checkRow('Show Access Point Name in Beacon',
    config.show_ap_name_in_beacon,
    'Not supported by this hostapd; the setting is stored but not applied.');
  showApName.input.disabled = true;
  showApName.classList.add('is-off');

  let blackout = !!config.blackout_schedule?.enabled;
  const blackoutSeg = h('div', { class: 'wf-seg' });
  const blackoutButton = (value, text) => h('button', { type: 'button',
    class: 'wf-seg-btn' + ((blackout === (value === 'on')) ? ' is-on' : ''),
    onclick: () => {
      blackout = value === 'on';
      blackoutSeg.querySelectorAll('.wf-seg-btn').forEach((b) =>
        b.classList.toggle('is-on', (b.textContent === 'On') === blackout));
    } }, text);
  blackoutSeg.append(blackoutButton('off', 'Off'), blackoutButton('on', 'On'));

  /* The Auto/Manual switch gates every advanced control, exactly as the
     reference portal does: in Auto the gateway picks sensible values and the
     inputs are shown but not editable, so the operator can still see them. */
  const advancedNodes = [
    fastRoaming, minRate, mcastBlocker, mcastToUnicast, ppsk, hidden, isolation,
    mlo, bandSteering, proxyArp, bssTransition, uapsd, macFilter, radiusMac,
    speedLimit, autoDtim, groupRekey, showApName,
  ];
  const advancedPlain = [protocol, saeClog, saeSync, dtim, rekeySeconds];
  function syncAdvanced() {
    const manual = advancedMode === 'manual';
    advanced.querySelectorAll('.wf-seg-btn').forEach((b) =>
      b.classList.toggle('is-on', b.dataset.value === advancedMode));
    for (const node of advancedNodes) {
      const lockedOff = node === showApName || (node === mlo && !mloSupported);
      node.input.disabled = !manual || lockedOff;
      node.classList.toggle('is-off', !manual || lockedOff);
    }
    for (const el of advancedPlain) el.disabled = !manual;
    for (const row of [mcastFilter, pmf]) {
      row.inputs.forEach((el) => { el.disabled = !manual; });
      row.classList.toggle('is-off', !manual);
    }
    dtim.disabled = !manual || autoDtim.input.checked;
    rekeySeconds.disabled = !manual || !groupRekey.input.checked;
    syncNotice();
  }
  autoDtim.input.addEventListener('change', syncAdvanced);
  groupRekey.input.addEventListener('change', syncAdvanced);

  const notice = h('div', { class: 'wf-notice' });
  function syncNotice() {
    const chosen = Object.entries(bands).filter(([, el]) => el.checked).map(([b]) => b);
    const wpa3 = ['wpa3', 'wpa3-enterprise', 'open'].includes(protocol.value);
    const msgs = [];
    if (chosen.includes('6g') && !wpa3) {
      msgs.push('6 GHz requires WPA3 or Open/OWE — the gateway will reject '
        + 'other protocols on that band.');
    } else if (chosen.includes('6g')) {
      msgs.push('6 GHz is enabled, so PMF will be forced to Required.');
    }
    if (mlo.input.checked && chosen.length < 2) {
      msgs.push('MLO needs at least two bands.');
    }
    if (!mlo.input.checked && chosen.length > 1) {
      msgs.push('Without MLO each band is a separate BSS that only shares the '
        + 'name; clients pick one.');
    }
    if (radiusMac.input.checked && !sec.radius_profile) {
      msgs.push('RADIUS MAC Authentication needs a RADIUS profile on this SSID.');
    }
    notice.textContent = msgs.join(' ');
    notice.style.display = msgs.length ? '' : 'none';
  }
  [protocol, mlo.input, radiusMac.input, ...Object.values(bands)]
    .forEach((el) => el.addEventListener('change', syncNotice));
  syncUplink();

  const form = h('div', { class: 'wf-form' },
    grp('',
      isNew ? fld('Identifier', idInput, 'Lowercase, no spaces. Cannot be changed later.') : null,
      fld('Name', name),
      fld('Password', passWrap, 'Must have at least 8 characters.'),
      fld('Network', network),
      fld('Broadcasting APs', broadcasting),
      fld('Application', application),
      fld('Radio Band', bandRow)),
    grp('Client Addressing',
        fld('Client IP source', uplink,
            'Where clients on this SSID get their address from.'),
        uplinkNotice),
    h('div', { class: 'wf-group wf-advanced-head' },
      h('h3', {}, 'Advanced'), h('div', { class: 'spacer' }), advanced),
    notice,
    grp('Roaming Assistance', fastRoaming),
    grp('Hi-Capacity Tuning', minRate,
      fld('Multicast Filtering', mcastFilter),
      mcastBlocker, mcastToUnicast),
    grp('Security',
      fld('Security Protocol', protocol),
      fld('PMF', pmf),
      ppsk, hidden, isolation,
      fld('SAE Anti-clogging', saeClog),
      fld('SAE Sync Time', saeSync)),
    grp('Behavior Controls',
      mlo, bandSteering, proxyArp, bssTransition, uapsd, macFilter, radiusMac,
      speedLimit, autoDtim,
      h('div', { class: 'wf-sub' }, fld('DTIM Period', dtim)),
      groupRekey,
      h('div', { class: 'wf-sub' }, fld('Rekey Interval (seconds)', rekeySeconds)),
      showApName,
      h('div', { class: 'wf-check' }, h('span', {}, 'WiFi Blackout Schedule'),
        h('div', { class: 'spacer' }), blackoutSeg)));

  setTimeout(syncAdvanced, 0);

  modal(isNew ? 'Create New WiFi' : `Edit ${config.ssid}`, form, () => {
    const security = {
      mode: protocol.value,
      pmf: pmf.value(),
      private_preshared_keys: ppsk.input.checked,
      sae_anti_clogging_threshold: Number(saeClog.value) || 5,
      sae_sync: Number(saeSync.value) || 5,
    };
    if (sec.radius_profile) security.radius_profile = sec.radius_profile;
    if (passWrap.input.value) security.passphrase = passWrap.input.value;
    const body = {
      ssid: name.value.trim(),
      network: network.value,
      uplink: uplink.value(),
      bands: Object.entries(bands).filter(([, el]) => el.checked).map(([b]) => b),
      security,
      enabled: config.enabled !== false,
      broadcasting_aps: broadcasting.value(),
      application: application.value(),
      advanced_mode: advancedMode,
      fast_roaming: fastRoaming.input.checked,
      minimum_data_rate: minRate.input.checked,
      multicast_filtering: mcastFilter.value(),
      multicast_broadcast_blocker: mcastBlocker.input.checked,
      multicast_to_unicast: mcastToUnicast.input.checked,
      hidden: hidden.input.checked,
      client_isolation: isolation.input.checked,
      mlo: mlo.input.checked,
      band_steering: bandSteering.input.checked,
      proxy_arp: proxyArp.input.checked,
      bss_transition: bssTransition.input.checked,
      uapsd: uapsd.input.checked,
      mac_filter: macFilter.input.checked,
      radius_mac_auth: radiusMac.input.checked,
      speed_limit: speedLimit.input.checked,
      auto_dtim: autoDtim.input.checked,
      dtim_period: Number(dtim.value) || 2,
      group_rekey_interval: groupRekey.input.checked,
      group_rekey_seconds: Number(rekeySeconds.value) || 3600,
      show_ap_name_in_beacon: showApName.input.checked,
      blackout_schedule: { ...(config.blackout_schedule || {}), enabled: blackout },
    };
    return isNew
      ? mutate(() => api('/wifi/networks', { method: 'POST',
          body: { id: idInput.value.trim(), ...body } }), 'SSID created')
      : mutate(() => api(`/wifi/networks/${id}`, { method: 'PUT', body }), 'SSID updated');
  }, isNew ? 'Create' : 'Save');
}

/* ------------------------------------------------------------ wifi clients */

pages.wclients = async (root) => {
  const data = await api('/wifi/clients?limit=500');
  root.append(h('div', { class: 'card' },
    h('header', {}, h('h2', {}, `Wi-Fi clients (${data.total || 0})`)),
    h('div', { class: 'body tight table-wrap' },
      (data.items || []).length ? h('table', {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'Client'), h('th', {}, 'SSID'), h('th', {}, 'Radio'),
          h('th', { class: 'num' }, 'RSSI'), h('th', { class: 'num' }, 'SNR'),
          h('th', {}, 'PHY'), h('th', { class: 'num' }, 'TX / RX'),
          h('th', { class: 'num' }, 'Retry'), h('th', {}, 'Health'),
          h('th', {}, 'MLO'), h('th', {}, ''))),
        h('tbody', {}, data.items.map((client) => wifiClientRow(client))))
        : h('div', { class: 'empty' }, 'No wireless clients associated.'))));
};

function wifiClientRow(c) {
  const health = c.health || {};
  const healthTone = { excellent: 'ok', good: 'ok', fair: 'warn', poor: 'bad' }[health.rating] || 'mute';
  const rows = [h('tr', {},
    h('td', {}, h('div', { class: 'mono small' }, c.mac),
      h('div', { class: 'small dim' }, fmtDuration(c.connected_seconds))),
    h('td', {}, c.ssid || '—'),
    h('td', {}, bandLabel(c.band), h('div', { class: 'small dim' }, c.radio || '')),
    h('td', { class: 'num' }, c.rssi != null ? `${c.rssi} dBm` : '—'),
    h('td', { class: 'num' }, c.snr != null ? `${c.snr} dB` : '—'),
    h('td', {}, c.phy_mode || '—',
      c.mcs != null ? h('div', { class: 'small dim' }, `MCS ${c.mcs}${c.nss ? ` · ${c.nss}ss` : ''}`) : null),
    h('td', { class: 'num' }, `${fmtMbps(c.tx_rate_mbps)} / ${fmtMbps(c.rx_rate_mbps)}`,
      h('div', { class: 'small dim' }, 'Mbps')),
    h('td', { class: 'num' }, `${c.retry_percent ?? 0}%`),
    h('td', {}, pill(health.rating || 'unknown', healthTone),
      health.reasons?.length
        ? h('div', { class: 'small dim' }, health.reasons[0]) : null),
    h('td', {}, c.is_mlo
      ? pill(`${c.links?.length || 0} links`, 'mlo')
      : h('span', { class: 'dim' }, '—')),
    h('td', { class: 'nowrap' },
      h('button', { class: 'sm ghost', onclick: () => mutate(() =>
        api(`/clients/${c.mac}/actions/disconnect`, { method: 'POST' }),
        'Disconnect sent') }, 'Kick'),
      h('button', { class: 'sm ghost danger', onclick: () => mutate(() =>
        api(`/clients/${c.mac}/actions/block`, { method: 'POST' }),
        'Client blocked') }, 'Block')))];

  if (c.is_mlo && c.links?.length) {
    rows.push(h('tr', {}, h('td', { colspan: '11', style: 'background:var(--surface-2)' },
      h('div', { class: 'small', style: 'font-weight:600;margin-bottom:6px' },
        'Per-link detail'),
      c.links.map((link) => h('div', { class: 'link-metrics',
        style: 'padding:3px 0' },
        h('span', { class: 'lid' }, `Link ${link.link_id}`),
        h('span', { class: 'muted' }, 'RSSI ', h('b', {}, link.rssi ?? '—')),
        h('span', { class: 'muted' }, 'SNR ', h('b', {}, link.snr ?? '—')),
        h('span', { class: 'muted' }, 'Rate ', h('b', {}, fmtMbps(link.tx_rate_mbps)), ' Mbps'),
        h('span', { class: 'muted' }, 'Width ', h('b', {}, link.channel_width ?? '—')),
        h('span', { class: 'muted' }, 'Retry ', h('b', {}, (link.retry_percent ?? 0) + '%')),
        h('span', { class: 'muted' }, '↓ ', h('b', {}, fmtBytes(link.rx_bytes))),
        h('span', { class: 'muted' }, '↑ ', h('b', {}, fmtBytes(link.tx_bytes))))))));
  }
  return rows;
}

/* ------------------------------------------------------ channel analyzer */

const SVG_NS = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs = {}, ...children) => {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    el.setAttribute(k, String(v));
  }
  for (const c of children.flat(3)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
};

/* A stable pastel hue per BSSID. Golden-angle stepping off a cheap string hash
 * spreads neighbouring APs apart in colour, and the same AP keeps its colour
 * between refreshes so the chart does not reshuffle under the operator. */
function hueFor(key) {
  let hash = 0;
  for (let i = 0; i < (key || '').length; i++) {
    hash = (hash * 31 + key.charCodeAt(i)) & 0x7fffffff;
  }
  return Math.round((hash * 137.508) % 360);
}
const strokeFor = (hue) => `hsl(${hue} 72% 58%)`;
const fillFor = (hue) => `hsl(${hue} 80% 62% / .20)`;

/* dBm range drawn on the Y axis. -95 is about the noise floor of these radios;
 * -30 is closer than any real neighbour, so nothing gets clipped. */
const DBM_TOP = -32;
const DBM_BOTTOM = -100;
/* Our own AP has no RSSI — we are the transmitter, not a receiver — so it is
 * anchored near the top and drawn distinctly rather than given a fake signal. */
const OWN_LEVEL = -36;

/* Host element that measures itself and draws the chart at 1:1.
 *
 * A fixed viewBox scaled to the container either shrinks the axis labels to
 * unreadable (wide cards) or letterboxes the chart with dead space. Measuring
 * the available width and building the geometry in real pixels avoids both, and
 * a ResizeObserver keeps it right when the window or sidebar changes. */
function spectrumChart(radio) {
  const host = h('div', { class: 'chart-host' });
  let lastWidth = 0;

  const draw = () => {
    const width = Math.max(320, Math.round(host.clientWidth));
    if (!width || Math.abs(width - lastWidth) < 8) return;
    lastWidth = width;
    host.textContent = '';
    host.append(spectrumSvg(radio, width, 264));
  };

  // The element is not in the document yet, so defer the first measurement.
  requestAnimationFrame(draw);
  if (typeof ResizeObserver === 'function') {
    const observer = new ResizeObserver(() => draw());
    observer.observe(host);
    // Stop observing once the node leaves the document (each render rebuilds).
    host._disconnect = () => observer.disconnect();
  }
  return host;
}

function spectrumSvg(radio, W, H) {
  const padL = 42, padR = 12, padT = 14, padB = 30;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const channels = (radio.channels || []).filter((c) => c.frequency_mhz);
  if (!channels.length) {
    return h('div', { class: 'empty' }, 'This radio reports no usable channels.');
  }

  // Work in frequency, not channel number: 2.4 GHz channels sit 5 MHz apart but
  // are 20 MHz wide, so only a frequency axis shows the overlap truthfully.
  //
  // The domain has to span the full extent of every block drawn, not just the
  // channel centres: a 160 MHz BSS on channel 36 reaches 80 MHz below 5180, and
  // deriving the domain from centres alone drew it off the left edge and over
  // the dBm labels.
  const extents = [];
  for (const entry of channels) {
    extents.push(entry.frequency_mhz - 12, entry.frequency_mhz + 12);
  }
  const addExtent = (centre, width) => {
    if (centre == null) return;
    const half = (width || 20) / 2;
    extents.push(centre - half, centre + half);
  };
  for (const n of radio.neighbours || []) {
    addExtent(n.frequency_mhz
      || (n.channel != null ? channelFreq(n.channel, radio.band) : null), n.width);
  }
  for (const slot of ownMarkers(radio)) addExtent(slot.frequency_mhz, slot.width);
  const f0 = Math.min(...extents) - 4;
  const f1 = Math.max(...extents) + 4;
  const x = (f) => padL + ((f - f0) / (f1 - f0)) * plotW;
  const y = (dbm) => padT + ((DBM_TOP - Math.max(DBM_BOTTOM,
    Math.min(DBM_TOP, dbm))) / (DBM_TOP - DBM_BOTTOM)) * plotH;
  const base = padT + plotH;

  const svg = svgEl('svg', {
    class: 'chart', viewBox: `0 0 ${W} ${H}`,
    preserveAspectRatio: 'xMidYMid meet', role: 'img',
    'aria-label': `${radio.label} spectrum`,
  });

  // --- horizontal dBm gridlines + labels
  for (let dbm = -40; dbm >= -90; dbm -= 10) {
    const yy = y(dbm);
    svg.append(svgEl('line', { class: 'grid', x1: padL, x2: padL + plotW,
      y1: yy, y2: yy }));
    svg.append(svgEl('text', { class: 'axis-text', x: padL - 6, y: yy + 4,
      'text-anchor': 'end' }, String(dbm)));
  }

  // --- vertical channel gridlines + labels (thinned out on dense bands)
  const every = radio.band === '6g' ? 4 : radio.band === '5g' ? 2 : 1;
  channels.forEach((entry, i) => {
    const xx = x(entry.frequency_mhz);
    svg.append(svgEl('line', { class: 'grid minor', x1: xx, x2: xx,
      y1: padT, y2: base }));
    if (i % every !== 0 && i !== channels.length - 1) return;
    svg.append(svgEl('text', {
      class: `chan-text${entry.dfs ? ' dfs' : ''}`,
      x: xx, y: base + 15, 'text-anchor': 'middle',
    }, String(entry.channel)));
  });

  // --- measured airtime busy, behind everything else
  for (const entry of channels) {
    if (entry.utilisation_percent == null || entry.utilisation_percent < 4) continue;
    const height = (entry.utilisation_percent / 100) * plotH;
    svg.append(svgEl('rect', {
      class: 'util', x: x(entry.frequency_mhz - 10),
      width: Math.max(2, x(entry.frequency_mhz + 10) - x(entry.frequency_mhz - 10)),
      y: base - height, height,
    }, svgEl('title', {}, `Channel ${entry.channel}: `
      + `${entry.utilisation_percent}% airtime busy`)));
  }

  svg.append(svgEl('line', { class: 'frame', x1: padL, x2: padL + plotW,
    y1: base, y2: base }));

  // --- one trapezoid per BSS: rising shoulder, flat top, falling shoulder
  const labels = [];
  const plot = (entry, mine) => {
    const centre = entry.frequency_mhz
      || (entry.channel != null ? channelFreq(entry.channel, radio.band) : null);
    if (centre == null) return;
    const width = entry.width || 20;
    const lo = x(centre - width / 2);
    const hi = x(centre + width / 2);
    const span = hi - lo;
    // Shoulder slope: a fraction of the span, so a 160 MHz block does not get a
    // near-vertical edge while a 20 MHz one looks like a spike.
    const shoulder = Math.min(span / 3, Math.max(4, span * 0.14));
    const level = mine ? OWN_LEVEL : (entry.rssi ?? -92);
    const peak = y(level);
    const hue = mine ? null : hueFor(entry.bssid || entry.ssid || '');
    const stroke = mine ? 'var(--accent)' : strokeFor(hue);
    const fill = mine ? 'var(--accent-soft)' : fillFor(hue);

    const d = `M ${lo.toFixed(1)},${base} L ${(lo + shoulder).toFixed(1)},`
            + `${peak.toFixed(1)} L ${(hi - shoulder).toFixed(1)},${peak.toFixed(1)} `
            + `L ${hi.toFixed(1)},${base} Z`;
    const label = mine
      ? entry.ssid
      : `${entry.ssid || '(hidden)'}${entry.rssi != null ? ` · ${entry.rssi} dBm` : ''}`;
    const path = svgEl('path', {
      d, fill, stroke, 'stroke-width': mine ? 2.4 : 1.8,
      'stroke-linejoin': 'round',
      'stroke-dasharray': mine ? '5 3' : null,
    }, svgEl('title', {}, `${entry.ssid || '(hidden)'} — channel ${entry.channel}, `
      + `${width} MHz${entry.rssi != null ? `, ${entry.rssi} dBm` : ''}`
      + `${mine ? ' (this AP)' : ''}`));
    svg.append(path);

    // Keep the caption inside the plot area.
    const cx = Math.min(padL + plotW - 4, Math.max(padL + 4, (lo + hi) / 2));
    const shown = label.length > 26 ? label.slice(0, 25) + '…' : label;
    labels.push({ text: shown, cx, peak, stroke,
                  // ~5.4px per character at 11px bold is close enough to lay
                  // out without measuring, which would force a reflow per label.
                  halfWidth: (shown.length * 5.4) / 2 });
  };

  // Weakest first so stronger signals draw on top; ours last of all.
  const neighbours = [...(radio.neighbours || [])]
    .sort((a, b) => (a.rssi ?? -99) - (b.rssi ?? -99));
  neighbours.forEach((n) => plot(n, false));
  for (const slot of ownMarkers(radio)) plot(slot, true);

  // Lay the captions out so overlapping APs stay readable. Two APs on the same
  // channel put their labels in the same place otherwise, and one covers the
  // other exactly where the operator most needs to read both.
  const placed = [];
  labels.sort((a, b) => a.peak - b.peak || a.cx - b.cx);
  for (const item of labels) {
    let yy = Math.max(padT + 10, item.peak - 5);
    // Clamp by the label's box, not its centre, or a long caption on an edge
    // channel runs out over the dBm axis.
    const half = Math.min(item.halfWidth, plotW / 2 - 2);
    item.cx = Math.min(padL + plotW - half - 2, Math.max(padL + half + 2, item.cx));
    const x1 = item.cx - half, x2 = item.cx + half;
    let guard = 0;
    while (guard++ < 12 && placed.some((o) =>
        Math.abs(o.y - yy) < 12 && x1 < o.x2 + 4 && x2 > o.x1 - 4)) {
      yy += 13;
    }
    // Never push a caption below the plot area.
    yy = Math.min(yy, base - 4);
    placed.push({ x1, x2, y: yy });
    svg.append(svgEl('text', {
      class: 'ssid-text', x: item.cx, y: yy, 'text-anchor': 'middle',
      fill: item.stroke,
    }, item.text));
  }

  return svg;
}

/* Our own SSIDs share a radio, so they sit on the identical channel and width.
 * Collapse them into one marker per channel/width or the labels stack. */
function ownMarkers(radio) {
  const own = new Map();
  for (const bss of radio.own_bsses || []) {
    if (bss.channel == null) continue;
    const key = `${bss.channel}/${bss.width}`;
    const slot = own.get(key) || { ...bss, ssids: [] };
    if (bss.ssid) slot.ssids.push(bss.ssid);
    own.set(key, slot);
  }
  return [...own.values()].map((slot) => ({
    ...slot,
    frequency_mhz: channelFreq(slot.channel, radio.band),
    ssid: slot.ssids.length > 1
      ? `${slot.ssids.length} SSIDs · ${slot.width || '?'} MHz`
      : `${slot.ssids[0] || 'this AP'} · ${slot.width || '?'} MHz`,
  }));
}

function channelFreq(channel, band) {
  if (channel == null) return null;
  if (band === '2g') return channel === 14 ? 2484 : 2407 + channel * 5;
  if (band === '5g') return 5000 + channel * 5;
  if (band === '6g') return 5950 + channel * 5;
  return null;
}

function rssiClass(rssi) {
  if (rssi == null) return 'weak';
  if (rssi >= -65) return 'strong';
  if (rssi >= -78) return 'mid';
  return 'weak';
}

/* The list under the chart: colour key, identity, signal and channel. */
function apList(radio) {
  const rows = [];

  for (const slot of ownMarkers(radio)) {
    rows.push(h('div', { class: 'ap-row' },
      h('i', { class: 'swatch', style: 'background:var(--accent)' }),
      h('div', { class: 'who' },
        h('b', {}, slot.ssids.join(', ') || 'this AP'),
        h('span', { class: 'sub' }, slot.bssid || '')),
      pill('this AP', 'info'),
      h('div', { class: 'meta' },
        `ch ${slot.channel} · ${slot.width || '?'} MHz`)));
  }

  const neighbours = [...(radio.neighbours || [])]
    .sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999));
  for (const n of neighbours) {
    const hue = hueFor(n.bssid || n.ssid || '');
    rows.push(h('div', { class: 'ap-row' },
      h('i', { class: 'swatch', style: `background:${strokeFor(hue)}` }),
      h('div', { class: 'who' },
        h('b', {}, n.ssid || h('span', { class: 'dim' }, '(hidden)')),
        h('span', { class: 'sub' }, n.bssid || '')),
      n.classification === 'same-ssid-unknown-bssid'
        ? pill('same SSID', 'warn')
        : h('span', { class: 'tag' }, n.security || 'open'),
      h('div', {},
        h('div', { class: `rssi ${rssiClass(n.rssi)}` },
          n.rssi != null ? `${n.rssi} dBm` : '—'),
        h('div', { class: 'meta' },
          `ch ${n.channel ?? '—'} · ${n.width || 20} MHz`))));
  }

  if (!rows.length) {
    return h('div', { class: 'empty' },
      'No other access points seen on this band.');
  }
  return h('div', { class: 'ap-list' }, rows);
}

function channelGrid(radio) {
  const rec = radio.recommendation || {};
  const scores = {};
  for (const c of rec.candidates || []) scores[c.channel] = c.score;
  const best = rec.best ? rec.best.channel : null;

  return h('div', { class: 'chan-grid' },
    (radio.channels || []).map((entry) => {
      const score = scores[entry.channel];
      const classes = ['chan'];
      if (entry.is_current_primary) classes.push('current');
      else if (entry.channel === best) classes.push('best');
      else if (entry.neighbour_count >= 3) classes.push('busy');
      if (entry.dfs) classes.push('dfs');
      const tips = [
        `Channel ${entry.channel}`,
        entry.frequency_mhz ? `${entry.frequency_mhz} MHz` : null,
        `${entry.neighbour_count} neighbour AP(s)`,
        entry.utilisation_percent != null
          ? `${entry.utilisation_percent}% busy` : 'utilisation not measured',
        entry.noise_dbm != null ? `noise ${entry.noise_dbm} dBm` : null,
        score != null ? `score ${score}` : 'not a valid primary at this width',
        entry.dfs ? 'DFS (radar detection required)' : null,
        entry.psc ? 'PSC (preferred scanning channel)' : null,
      ].filter(Boolean);
      return h('div', { class: classes.join(' '), title: tips.join('\n') },
        h('b', {}, String(entry.channel)),
        h('span', { class: 'sc' },
          score != null ? String(Math.round(score)) : '—'));
    }));
}

pages.channels = async (root) => {
  const data = await api('/wifi/channels');
  const settings = data.settings || {};
  const radios = data.radios || [];
  if (!store.channelBand) store.channelBand = 'all';

  const scanning = h('span', { class: 'small faint' });
  const scanButton = h('button', { class: 'sm' }, icon('search', 13), 'Rescan');
  scanButton.addEventListener('click', async () => {
    scanButton.disabled = true;
    scanning.textContent = ' scanning…';
    try {
      await api('/wifi/channels/scan', { method: 'POST', body: { passive: true } });
      toast('Scan complete', 'ok');
      await refresh(true);
    } catch (err) {
      toast(err.message, 'bad');
    } finally {
      scanButton.disabled = false;
      scanning.textContent = '';
    }
  });

  const optimise = (force, dryRun, only) => mutate(() =>
    api('/wifi/channels/optimize', { method: 'POST',
      body: { force, dry_run: dryRun, rescan: true,
              radios: only ? [only] : undefined } })
      .then((report) => {
        for (const entry of report.radios || []) {
          toast(`${entry.radio}: ${entry.detail}`, entry.switched ? 'ok' : '');
        }
        return report;
      }), null);

  // Band tabs, counting the APs visible on each band.
  const counts = { all: 0 };
  for (const r of radios) {
    const n = (r.neighbours || []).length + ownMarkers(r).length;
    counts[r.band] = n;
    counts.all += n;
  }
  const tabFor = (key, label) => h('button', {
    class: store.channelBand === key ? 'on' : '',
    onclick: () => { store.channelBand = key; refresh(true); },
  }, `${label} (${counts[key] ?? 0})`);
  const tabs = h('div', { class: 'tabs' },
    tabFor('all', 'All'),
    radios.map((r) => tabFor(r.band, r.label)));

  const shown = store.channelBand === 'all'
    ? radios : radios.filter((r) => r.band === store.channelBand);

  root.append(
    h('div', { class: 'card mb' },
      h('header', {},
        h('h2', {}, 'Automatic channel selection'),
        h('div', { class: 'spacer' }),
        pill(settings.enabled ? 'scheduled' : 'manual only',
          settings.enabled ? 'ok' : 'mute'),
        scanButton, scanning,
        h('button', { class: 'sm', onclick: () => optimise(false, true) },
          icon('wand', 13), 'Preview'),
        h('button', { class: 'primary sm', onclick: () => optimise(true, false) },
          icon('wand', 13), 'Optimise now')),
      h('div', { class: 'body' },
        h('div', { class: 'small muted mb' },
          'Channels are scored from measured interference, channel utilisation '
          + 'and noise. A scheduled change only happens when it beats the current '
          + 'channel by the improvement threshold and the minimum interval has '
          + 'passed — the point is to avoid flapping. "Optimise now" ignores both '
          + 'guards.'),
        channelSettingsForm(settings))),

    h('div', { class: 'card mb' },
      h('header', {}, h('h2', {}, 'Band'), h('div', { class: 'spacer' }), tabs)),

    ...shown.map((radio) => radioChannelCard(radio, optimise)));
};

function radioChannelCard(radio, optimise) {
  const rec = radio.recommendation || {};
  const best = rec.best;
  const current = rec.current;
  const age = radio.scan_age_seconds;

  const verdict = h('div', {
    class: `banner ${rec.should_switch ? 'info' : 'warn'}`,
    style: 'margin:0 0 10px',
  }, icon(rec.should_switch ? 'wand' : 'info', 15, 'ico'),
    h('div', {},
      best
        ? h('span', {}, h('b', {}, `Recommended: channel ${best.channel}`),
            ` (score ${best.score}`,
            current ? ` vs ${current.score} on channel ${current.channel}` : '',
            '). ')
        : h('b', {}, 'No recommendation available. '),
      (rec.reasons || []).join('; ')));

  return h('div', { class: 'card mt' },
    h('header', {},
      h('h2', {}, 'Spectrum'),
      h('div', { class: 'spacer' }),
      pill(`ch ${radio.current_channel ?? '—'}`, 'info'),
      pill(`${radio.current_width ?? '—'} MHz`, 'mute'),
      radio.supports_240 ? pill('240 MHz capable', 'mlo') : null,
      h('span', { class: 'small faint' },
        age == null ? 'never scanned' : `scanned ${fmtDuration(age)} ago`),
      h('span', { class: 'muted', style: 'font-weight:700' }, radio.label),
      h('button', { class: 'sm', onclick: () => optimise(true, false, radio.radio) },
        'Optimise')),
    h('div', { class: 'body' },
      verdict,
      spectrumChart(radio)),
    h('div', { class: 'body' }, apList(radio)),
    h('div', { class: 'body' },
      h('div', { class: 'small muted mb' },
        'Channel scores — higher is better. Blue is the current primary, '
        + 'green the recommendation; amber channel numbers are DFS.'),
      channelGrid(radio)),
    (radio.history || []).length
      ? h('div', { class: 'body tight' },
          dataTable(['Changed', 'From', 'To', ['Width', { num: true }],
                     'Trigger', 'Reason'],
            radio.history,
            (entry) => [
              fmtAgo(entry.ts), entry.from_channel ?? '—', entry.to_channel,
              entry.width, entry.trigger,
              h('span', { class: 'small dim' }, entry.reason)],
            'No channel changes recorded.'))
      : null);
}

function channelSettingsForm(settings) {
  const enabled = h('input', { type: 'checkbox', checked: !!settings.enabled });
  const interval = h('select', {}, [
    [1800, '30 minutes'], [3600, '1 hour'], [21600, '6 hours'],
    [43200, '12 hours'], [86400, '24 hours'], [604800, '7 days'],
  ].map(([v, l]) => h('option', { value: String(v),
    selected: Number(settings.min_interval_seconds) === v }, l)));
  const improvement = h('input', { type: 'number', min: '0', max: '100',
    value: settings.min_improvement ?? 15 });
  const hour = h('select', {}, Array.from({ length: 24 }, (_, i) => i).map((i) =>
    h('option', { value: String(i), selected: Number(settings.schedule_hour) === i },
      `${String(i).padStart(2, '0')}:00`)));
  const avoidDfs = h('input', { type: 'checkbox', checked: !!settings.avoid_dfs });
  const preferPsc = h('input', { type: 'checkbox', checked: settings.prefer_psc !== false });

  return h('div', {},
    h('div', { class: 'row' },
      h('label', { class: 'field inline' }, enabled,
        h('span', {}, 'Run on a schedule')),
      h('label', { class: 'field' }, h('span', {}, 'Run at'), hour),
      h('label', { class: 'field' }, h('span', {}, 'Minimum interval'), interval),
      h('label', { class: 'field' },
        h('span', {}, 'Improvement threshold'), improvement)),
    h('div', { class: 'row' },
      h('label', { class: 'field inline' }, avoidDfs,
        h('span', {}, 'Avoid DFS channels')),
      h('label', { class: 'field inline' }, preferPsc,
        h('span', {}, 'Prefer 6 GHz PSC channels'))),
    h('button', { class: 'primary sm', onclick: () => mutate(() =>
      api('/wifi/channels/settings', { method: 'PUT', body: {
        enabled: enabled.checked,
        min_interval_seconds: Number(interval.value),
        min_improvement: Number(improvement.value),
        schedule_hour: Number(hour.value),
        avoid_dfs: avoidDfs.checked,
        prefer_psc: preferPsc.checked,
      }}), 'Channel settings saved') }, 'Save'));
}

/* --------------------------------------------------------------- clients */

pages.clients = async (root) => {
  const query = store.clientSearch
    ? '&search=' + encodeURIComponent(store.clientSearch) : '';
  const data = await api(`/clients?limit=500${query}`);

  const search = h('input', {
    type: 'search', placeholder: 'Search name, MAC or IP',
    style: 'max-width:280px', value: store.clientSearch || '',
  });
  search.addEventListener('input', debounce(() => {
    store.clientSearch = search.value;
    refresh(true);
  }, 400));

  const identity = (c) => h('div', {},
    h('b', {}, c.name || c.mac),
    h('div', { class: 'small dim mono' }, c.mac),
    c.vendor ? h('div', { class: 'small dim' }, c.vendor) : null);

  const address = (c) => h('div', { class: 'mono small' }, c.ipv4 || '—',
    (c.ipv6 || []).length ? h('div', { class: 'small dim' }, `${c.ipv6.length} IPv6`) : null);

  const network = (c) => h('div', {}, c.network || '—',
    c.vlan ? h('div', { class: 'small dim' }, `VLAN ${c.vlan}`) : null);

  const connection = (c) => h('div', {},
    pill(c.connection, c.connection === 'wireless' ? 'info' : 'mute'),
    c.port ? h('div', { class: 'small dim mono' }, c.port) : null);

  const signal = (c) => {
    const wifi = c.wireless || {};
    if (wifi.rssi == null) return h('span', { class: 'dim' }, '—');
    return h('div', {}, `${wifi.rssi} dBm`,
      wifi.is_mlo ? h('div', {}, pill('MLO', 'mlo')) : null);
  };

  const actions = (c) => h('div', { class: 'nowrap' },
    h('button', { class: 'sm ghost', onclick: () => clientModal(c) }, 'Edit'),
    c.blocked
      ? h('button', { class: 'sm ghost', onclick: () => mutate(() =>
          api(`/clients/${c.mac}/actions/unblock`, { method: 'POST' }), 'Unblocked') },
          'Unblock')
      : h('button', { class: 'sm ghost danger', onclick: () => mutate(() =>
          api(`/clients/${c.mac}/actions/block`, { method: 'POST' }), 'Blocked') },
          'Block'));

  const columns = ['Client', 'IPv4', 'Network', 'Connection', 'Signal',
    ['↓ / ↑', { num: true }], 'Last seen', ''];

  const table = dataTable(columns, data.items || [], (c) => {
    const row = h('tr', { style: c.online ? '' : 'opacity:.55' },
      h('td', {}, identity(c)),
      h('td', {}, address(c)),
      h('td', {}, network(c)),
      h('td', {}, connection(c)),
      h('td', {}, signal(c)),
      h('td', { class: 'num' }, `${fmtBits(c.rx_rate_bps)} / ${fmtBits(c.tx_rate_bps)}`),
      h('td', { class: 'small dim' }, fmtAgo(c.last_seen)),
      h('td', {}, actions(c)));
    return row;
  }, 'No clients seen yet.');

  root.append(tableCard(`Clients (${data.total || 0})`, search, table));
};

function clientModal(client) {
  const name = h('input', { type: 'text', value: client.name || '' });
  const fixed = h('input', { type: 'text', value: client.fixed_ip || '',
    placeholder: client.ipv4 || '192.168.2.50' });
  const note = h('textarea', { rows: '2' }, client.note || '');
  const down = h('input', { type: 'number', min: '0', value: client.down_limit_kbps ?? '' });
  const up = h('input', { type: 'number', min: '0', value: client.up_limit_kbps ?? '' });

  modal(`Client · ${client.mac}`, h('div', {},
    h('label', { class: 'field' }, h('span', {}, 'Name'), name),
    h('label', { class: 'field' }, h('span', {}, 'Fixed IP',
      h('span', { class: 'help' }, ' — creates a DHCP reservation')), fixed),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Download limit (kbps)'), down),
      h('label', { class: 'field' }, h('span', {}, 'Upload limit (kbps)'), up)),
    h('label', { class: 'field' }, h('span', {}, 'Note'), note)),
    () => mutate(() => api(`/clients/${client.mac}`, { method: 'PUT', body: {
      name: name.value.trim() || null,
      fixed_ip: fixed.value.trim() || null,
      note: note.value.trim() || null,
      down_limit_kbps: down.value === '' ? null : Number(down.value),
      up_limit_kbps: up.value === '' ? null : Number(up.value),
    }}), 'Client updated'));
}

/* -------------------------------------------------------------- firewall */

pages.firewall = async (root) => {
  const data = await api('/firewall');
  const fw = data.firewall || {};
  const counters = {};
  for (const entry of data.counters || []) {
    if (entry.comment) counters[entry.comment] = entry;
  }

  const actionPill = (action) => pill(action,
    action === 'allow' ? 'ok' : action === 'reject' ? 'warn' : 'bad');

  // --- zone policy table
  const policyRows = Object.entries(fw.default_policies || {});
  const policyTable = dataTable(
    ['From → To', 'Action', ['Packets', { num: true }], ['Bytes', { num: true }]],
    policyRows,
    ([key, action]) => [
      h('span', { class: 'mono small' }, key.replace('->', ' → ')),
      actionPill(action),
      counters[key]?.packets ?? '—',
      fmtBytes(counters[key]?.bytes),
    ], 'No zone policies defined.');

  // --- rule table
  const rules = [...(fw.rules || [])].sort((a, b) => (a.index || 0) - (b.index || 0));

  const matchSummary = (rule) => {
    const parts = [
      rule.protocol !== 'any' ? rule.protocol : null,
      rule.src_address, rule.dst_address,
      rule.dst_port ? `port ${rule.dst_port}` : null,
    ].filter(Boolean);
    return parts.length ? parts.join(' · ') : h('span', { class: 'dim' }, 'any');
  };

  const ruleActions = (rule) => h('div', { class: 'nowrap' },
    h('button', { class: 'sm ghost', onclick: () => ruleModal(rule, fw) }, 'Edit'),
    h('button', { class: 'sm ghost danger', onclick: () =>
      confirmDelete(`rule ${rule.name}`, () => api('/firewall', {
        method: 'PUT', body: { rules: fw.rules.filter((r) => r.id !== rule.id) },
      })) }, 'Delete'));

  const ruleTable = dataTable(
    [['#', { num: true }], 'Name', 'Zones', 'Match', 'Action',
      ['Hits', { num: true }], ''],
    rules,
    (rule) => h('tr', { style: rule.enabled === false ? 'opacity:.5' : '' },
      h('td', { class: 'num dim' }, String(rule.index ?? '')),
      h('td', {}, h('b', {}, rule.name), h('div', { class: 'small dim mono' }, rule.id)),
      h('td', { class: 'small mono' }, `${rule.src_zone} → ${rule.dst_zone}`),
      h('td', { class: 'small' }, matchSummary(rule)),
      h('td', {}, actionPill(rule.action)),
      h('td', { class: 'num' }, String(counters[rule.id]?.packets ?? '—')),
      h('td', {}, ruleActions(rule))),
    'No custom rules. The zone policies above are in effect.');

  const newRule = h('button', { class: 'primary sm', onclick: () => ruleModal(null, fw) },
    '+ New rule');

  root.append(
    tableCard('Zone policies',
      h('span', { class: 'small dim' }, 'default action per zone pair'), policyTable),
    h('div', { class: 'mt' },
      tableCard(`Rules (${rules.length})`, newRule, ruleTable)));
};

function ruleModal(rule, fw) {
  const isNew = !rule;
  rule = rule || { action: 'drop', src_zone: 'lan', dst_zone: 'wan',
    protocol: 'any', family: 'both', enabled: true, log: false,
    index: (fw.rules || []).length + 1 };
  const zones = ['wan', 'lan', 'gateway', 'vpn', 'guest', 'iot', 'dmz', 'management'];
  const f = {
    id: h('input', { type: 'text', value: rule.id || '', disabled: !isNew,
      placeholder: 'block-iot-lan' }),
    name: h('input', { type: 'text', value: rule.name || '' }),
    index: h('input', { type: 'number', min: '1', value: rule.index }),
    action: h('select', {}, ['allow', 'reject', 'drop'].map((a) =>
      h('option', { value: a, selected: rule.action === a }, a))),
    src_zone: h('select', {}, zones.map((z) =>
      h('option', { value: z, selected: rule.src_zone === z }, z))),
    dst_zone: h('select', {}, zones.map((z) =>
      h('option', { value: z, selected: rule.dst_zone === z }, z))),
    protocol: h('select', {}, ['any', 'tcp', 'udp', 'tcp-udp', 'icmp', 'icmpv6']
      .map((p) => h('option', { value: p, selected: rule.protocol === p }, p))),
    family: h('select', {}, ['both', 'ipv4', 'ipv6'].map((v) =>
      h('option', { value: v, selected: rule.family === v }, v))),
    src_address: h('input', { type: 'text', value: rule.src_address || '',
      placeholder: '10.0.0.0/8 or blank' }),
    dst_address: h('input', { type: 'text', value: rule.dst_address || '',
      placeholder: 'blank for any' }),
    dst_port: h('input', { type: 'text', value: rule.dst_port || '',
      placeholder: '443 or 8000-8100' }),
    enabled: h('input', { type: 'checkbox', checked: rule.enabled !== false }),
    log: h('input', { type: 'checkbox', checked: !!rule.log }),
  };

  const form = h('div', {},
    h('div', { class: 'row' },
      isNew ? h('label', { class: 'field' }, h('span', {}, 'Rule id'), f.id) : null,
      h('label', { class: 'field' }, h('span', {}, 'Name'), f.name),
      h('label', { class: 'field' }, h('span', {}, 'Order'), f.index)),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'From zone'), f.src_zone),
      h('label', { class: 'field' }, h('span', {}, 'To zone'), f.dst_zone),
      h('label', { class: 'field' }, h('span', {}, 'Action'), f.action)),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Protocol'), f.protocol),
      h('label', { class: 'field' }, h('span', {}, 'Family'), f.family),
      h('label', { class: 'field' }, h('span', {}, 'Dest. port'), f.dst_port)),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Source address'), f.src_address),
      h('label', { class: 'field' }, h('span', {}, 'Dest. address'), f.dst_address)),
    h('div', { class: 'row' },
      h('label', { class: 'field inline' }, f.enabled,
        h('span', { style: 'margin:0' }, 'Enabled')),
      h('label', { class: 'field inline' }, f.log,
        h('span', { style: 'margin:0' }, 'Log matches'))));

  modal(isNew ? 'New firewall rule' : `Edit ${rule.name}`, form, () => {
    const built = {
      id: isNew ? f.id.value.trim() : rule.id,
      name: f.name.value.trim(), index: Number(f.index.value),
      action: f.action.value, src_zone: f.src_zone.value, dst_zone: f.dst_zone.value,
      protocol: f.protocol.value, family: f.family.value,
      enabled: f.enabled.checked, log: f.log.checked,
    };
    for (const key of ['src_address', 'dst_address', 'dst_port']) {
      if (f[key].value.trim()) built[key] = f[key].value.trim();
    }
    const rules = (fw.rules || []).filter((r) => r.id !== built.id);
    rules.push(built);
    return mutate(() => api('/firewall', { method: 'PUT', body: { rules } }),
      'Firewall updated');
  });
}

/* -------------------------------------------------------------------- nat */

pages.nat = async (root) => {
  const data = await api('/nat');
  const nat = data.nat || {};
  const forwards = nat.port_forwards || [];

  const deleteForward = (fwd) => confirmDelete(`forward ${fwd.name}`, () =>
    api('/nat', { method: 'PUT',
      body: { port_forwards: forwards.filter((p) => p.id !== fwd.id) } }));

  const table = dataTable(
    ['Name', 'Protocol', 'External', 'Internal', 'WAN', ''],
    forwards,
    (fwd) => h('tr', { style: fwd.enabled === false ? 'opacity:.5' : '' },
      h('td', {}, h('b', {}, fwd.name)),
      h('td', {}, fwd.protocol),
      h('td', { class: 'mono small' }, String(fwd.external_port)),
      h('td', { class: 'mono small' },
        `${fwd.internal_address}:${fwd.internal_port}`),
      h('td', {}, fwd.wan || 'any'),
      h('td', {}, h('button', { class: 'sm ghost danger',
        onclick: () => deleteForward(fwd) }, 'Delete'))),
    'No port forwards configured.');

  const badges = [
    pill(nat.masquerade ? 'Masquerade on' : 'Masquerade off',
      nat.masquerade ? 'ok' : 'warn'),
    pill(nat.hairpin ? 'Hairpin on' : 'Hairpin off', nat.hairpin ? 'ok' : 'mute'),
  ];

  const card = tableCard('NAT', badges, table);
  card.append(h('div', { class: 'body', style: 'border-top:1px solid var(--line)' },
    h('button', { class: 'primary sm', onclick: () => forwardModal(nat) },
      '+ New port forward')));

  root.append(card);
};

function forwardModal(nat) {
  const f = {
    id: h('input', { type: 'text', placeholder: 'web' }),
    name: h('input', { type: 'text', placeholder: 'Web server' }),
    protocol: h('select', {}, ['tcp', 'udp', 'tcp-udp'].map((p) =>
      h('option', { value: p }, p))),
    external_port: h('input', { type: 'text', placeholder: '443' }),
    internal_address: h('input', { type: 'text', placeholder: '192.168.2.20' }),
    internal_port: h('input', { type: 'text', placeholder: 'same as external' }),
  };
  modal('New port forward', h('div', {},
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'Id'), f.id),
      h('label', { class: 'field' }, h('span', {}, 'Name'), f.name),
      h('label', { class: 'field' }, h('span', {}, 'Protocol'), f.protocol)),
    h('div', { class: 'row' },
      h('label', { class: 'field' }, h('span', {}, 'External port'), f.external_port),
      h('label', { class: 'field' }, h('span', {}, 'Internal address'), f.internal_address),
      h('label', { class: 'field' }, h('span', {}, 'Internal port'), f.internal_port))),
    () => {
      const forwards = [...(nat.port_forwards || []), {
        id: f.id.value.trim(), name: f.name.value.trim() || f.id.value.trim(),
        protocol: f.protocol.value, enabled: true,
        external_port: f.external_port.value.trim(),
        internal_address: f.internal_address.value.trim(),
        internal_port: f.internal_port.value.trim() || f.external_port.value.trim(),
        wan: 'any',
      }];
      return mutate(() => api('/nat', { method: 'PUT',
        body: { port_forwards: forwards } }), 'Port forward created');
    });
}

/* ----------------------------------------------------------------- routes */

pages.routes = async (root) => {
  const data = await api('/routing');
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, 'Static routes')),
      h('div', { class: 'body tight table-wrap' },
        (data.routing?.static || []).length ? h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Destination'), h('th', {}, 'Type'),
            h('th', {}, 'Via'), h('th', { class: 'num' }, 'Metric'))),
          h('tbody', {}, data.routing.static.map((r) => h('tr', {},
            h('td', { class: 'mono small' }, r.destination),
            h('td', {}, r.type), h('td', { class: 'mono small' }, r.via || r.interface || '—'),
            h('td', { class: 'num' }, r.metric)))))
          : h('div', { class: 'empty' }, 'No static routes.')),
    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Kernel routing table (IPv4)')),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Destination'), h('th', {}, 'Gateway'),
            h('th', {}, 'Device'), h('th', {}, 'Protocol'), h('th', { class: 'num' }, 'Metric'))),
          h('tbody', {}, (data.table_v4 || []).map((r) => h('tr', {},
            h('td', { class: 'mono small' }, r.dst),
            h('td', { class: 'mono small' }, r.gateway || '—'),
            h('td', { class: 'mono small' }, r.dev || '—'),
            h('td', { class: 'small dim' }, r.protocol || '—'),
            h('td', { class: 'num' }, r.metric ?? '—')))))))));
};

/* -------------------------------------------------------------- neighbors */

pages.neighbors = async (root) => {
  const scanButton = h('button', { class: 'primary sm' }, 'Passive scan');
  const body = h('div', { class: 'body tight table-wrap' },
    h('div', { class: 'empty' },
      'Run a passive scan to list neighbouring access points. '
      + 'Scanning is passive so associated clients are not disrupted.'));

  const noteFor = (n) => n.classification === 'same-ssid-unknown-bssid'
    ? pill('same SSID, unknown BSSID', 'warn')
    : h('span', { class: 'dim small' }, 'neighbour');

  const render = (neighbours) => dataTable(
    ['SSID', 'BSSID', 'Band', 'Channel', ['RSSI', { num: true }], 'Security',
      'PHY', 'Note'],
    [...neighbours].sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999)),
    (n) => [
      n.ssid || h('span', { class: 'dim' }, '(hidden)'),
      h('span', { class: 'mono small' }, n.bssid),
      bandLabel(n.band),
      n.channel ?? '—',
      n.rssi != null ? `${n.rssi} dBm` : '—',
      n.security,
      h('span', { class: 'small dim' }, (n.phy_modes || []).join(', ') || '—'),
      noteFor(n),
    ], 'No neighbours found.');

  scanButton.addEventListener('click', async () => {
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning…';
    try {
      const data = await api('/wifi/neighbors?scan=1');
      body.textContent = '';
      body.append(render(data.items || []));
    } catch (err) {
      toast(err.message, 'bad');
    } finally {
      scanButton.disabled = false;
      scanButton.textContent = 'Passive scan';
    }
  });

  const card = h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Neighbouring access points'),
      h('div', { class: 'spacer' }), scanButton),
    body,
    h('div', { class: 'body small dim', style: 'border-top:1px solid var(--line)' },
      'A neighbouring AP is not automatically hostile. '
      + '"Same SSID, unknown BSSID" is worth investigating but is often another '
      + 'AP you own.'));

  root.append(card);
};

/* -------------------------------------------------------------- topology */

pages.topology = async (root) => {
  const data = await api('/topology');
  const nodes = data.nodes || [];
  const byParent = new Map();
  for (const node of nodes) {
    if (!byParent.has(node.parent)) byParent.set(node.parent, []);
    byParent.get(node.parent).push(node);
  }
  const ICONS = { internet: 'internet', gateway: 'gateway', port: 'port',
    network: 'vlan', wifi: 'ssid', client: 'device' };

  const build = (parentId) => {
    const children = byParent.get(parentId) || [];
    if (!children.length) return null;
    return h('ul', {}, children.map((node) => h('li', {},
      h('span', { class: 'node' },
        icon(ICONS[node.type] || 'device', 14, 'ico'),
        h('b', {}, node.label),
        node.state ? statePill(node.state) : null,
        node.is_mlo ? pill('MLO', 'mlo') : null,
        node.ipv4 ? h('span', { class: 'small dim mono' }, node.ipv4) : null,
        node.vlan ? h('span', { class: 'small dim' }, `VLAN ${node.vlan}`) : null,
        node.rssi != null ? h('span', { class: 'small dim' }, `${node.rssi} dBm`) : null,
        node.speed_mbps ? h('span', { class: 'small dim' }, fmtSpeed(node.speed_mbps)) : null),
      build(node.id))));
  };

  root.append(h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Topology'),
      h('div', { class: 'spacer' }),
      h('span', { class: 'small dim' }, `${nodes.filter((n) => n.type === 'client').length} clients`)),
    h('div', { class: 'body tree' }, build(null) || h('div', { class: 'empty' }, 'No data.'))));
};

/* ---------------------------------------------------------------- events */

function eventsTable(events) {
  if (!events.length) return h('div', { class: 'empty' }, 'No events.');
  const toneOf = { critical: 'bad', error: 'bad', warning: 'warn',
    notice: 'info', info: 'mute', debug: 'mute' };
  return h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Severity'),
      h('th', {}, 'Kind'), h('th', {}, 'Subsystem'), h('th', {}, 'Message'))),
    h('tbody', {}, events.map((e) => h('tr', {},
      h('td', { class: 'small nowrap dim' }, fmtAgo(e.ts)),
      h('td', {}, pill(e.severity, toneOf[e.severity] || 'mute')),
      h('td', { class: 'small mono' }, e.kind),
      h('td', { class: 'small dim' }, e.subsystem),
      h('td', {}, e.message)))));
}

pages.events = async (root) => {
  const sev = h('select', { style: 'max-width:150px' },
    h('option', { value: '' }, 'All severities'),
    ['critical', 'error', 'warning', 'notice', 'info', 'debug'].map((s) =>
      h('option', { value: s, selected: store.eventSeverity === s }, s)));
  const search = h('input', { type: 'search', placeholder: 'Search events',
    style: 'max-width:240px', value: store.eventSearch || '' });
  const apply = () => {
    store.eventSeverity = sev.value; store.eventSearch = search.value;
    refresh(true);
  };
  sev.addEventListener('change', apply);
  search.addEventListener('change', apply);

  const params = new URLSearchParams({ limit: '300' });
  if (store.eventSeverity) params.set('severity', store.eventSeverity);
  if (store.eventSearch) params.set('search', store.eventSearch);
  const data = await api('/events?' + params);

  root.append(h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Events'),
      h('div', { class: 'spacer' }), search, sev),
    h('div', { class: 'body tight table-wrap' }, eventsTable(data.items || []))));
};

/* -------------------------------------------------------------- platform */

const fmtHex = (n) => (n === null || n === undefined) ? '—' : '0x' + n.toString(16);

function identityCard(id) {
  const rows = [
    ['Model', id.model, id.model_source],
    ['Manufacturer', id.manufacturer],
    ['Serial number', id.serial, id.serial_source],
    ['Hardware revision', id.hardware_revision],
    ['Hardware variant', id.hardware_variant],
    ['Regulatory region', id.region
      ? `${id.region}${id.region_numeric ? ` (${id.region_numeric})` : ''}` : null,
      id.region ? 'ISO 3166-1 numeric, from the ART factory block' : null],
    ['Label OUI', id.oui],
    ['SoC', id.soc?.name],
    ['SoC revision', id.soc?.revision],
    ['machid', id.machid],
    ['Device-tree model', id.dt_model],
    ['Compatible', (id.compatible || []).join(', ')],
  ];

  return h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Device'),
      h('div', { class: 'spacer' }),
      id.vendor_block?.present
        ? pill('ART factory block', 'ok')
        : pill('no factory block', 'warn')),
    h('div', { class: 'body tight' },
      dataTable(['Field', 'Value', 'Source'], rows.filter((r) => r[1]),
        ([label, value, source]) => [
          h('span', { class: 'muted' }, label),
          h('b', {}, String(value)),
          h('span', { class: 'small faint' }, source || ''),
        ], 'No identity could be read.')),
    id.oui_matches_mac === false
      ? h('div', { class: 'body' },
          h('div', { class: 'banner info', style: 'margin:0' },
            icon('info', 15, 'ico'),
            h('div', {},
              h('b', {}, 'Label OUI differs from the programmed MAC. '),
              `The factory block records ${id.oui}, while the base MAC in ART `
              + `begins ${id.oui_from_base_mac}. Both are Askey allocations; the `
              + 'interfaces use the ART base MAC.')))
      : null,
    id.vendor_block?.present === false && id.vendor_block?.reason
      ? h('div', { class: 'body' },
          h('div', { class: 'banner warn', style: 'margin:0' },
            icon('warn', 15, 'ico'), h('div', {}, id.vendor_block.reason)))
      : null);
}

function artCard(id) {
  const art = id.art || {};
  const macs = art.macs || {};
  const cells = macs.cells || [];

  const macRows = [];
  if (macs.base) macRows.push(['Base MAC (ART offset 0)', macs.base, 'cell 0']);
  for (const [name, entry] of Object.entries(macs.ports || {})) {
    macRows.push([`Port group: ${name.toUpperCase()}`, entry.mac,
                  `nvmem cell ${entry.cell}`]);
  }
  for (const [name, entry] of Object.entries(macs.radios || {})) {
    macRows.push([`Radio ${name}`, entry.mac, `nvmem cell ${entry.cell}`]);
  }
  cells.forEach((mac, i) => {
    if (mac) macRows.push([`Programmed slot ${i}`, mac, `ART 0x${(i * 6).toString(16)}`]);
  });

  const cal = art.caldata || [];
  const calOk = art.radios_calibrated ?? 0;
  const calTotal = art.radios_expected ?? cal.length;

  return h('div', { class: 'card mt' },
    h('header', {}, h('h2', {}, 'ART partition'),
      h('div', { class: 'spacer' }),
      art.present ? pill(art.device, 'info') : pill('not found', 'bad'),
      art.size_bytes ? pill(fmtBytes(art.size_bytes), 'mute') : null,
      pill(`${calOk}/${calTotal} radios calibrated`,
        calOk === calTotal && calTotal > 0 ? 'ok' : 'warn')),
    h('div', { class: 'body tight' },
      dataTable(['Address', 'MAC', 'Derivation'], macRows,
        ([label, mac, note]) => [
          h('span', { class: 'muted' }, label),
          h('span', { class: 'mono' }, mac),
          h('span', { class: 'small faint' }, note),
        ], 'No MAC addresses could be read from ART.')),
    h('div', { class: 'body tight' },
      dataTable(['Radio calibration', 'ART offset', ['Size', { num: true }],
                 'Header', ['Programmed', { num: true }], 'Digest', 'State'],
        cal,
        (entry) => [
          h('span', { class: 'mono small' }, entry.firmware_name.split('/').pop()),
          h('span', { class: 'mono' }, fmtHex(entry.offset)),
          fmtBytes(entry.length),
          entry.valid_header ? pill('ath12k', 'ok') : pill('unrecognised', 'bad'),
          entry.bytes_programmed == null ? '—' : String(entry.bytes_programmed),
          h('span', { class: 'mono small faint' }, entry.sha256 || '—'),
          entry.valid_header && !entry.blank
            ? pill('valid', 'ok')
            : h('span', {},
                pill(entry.blank ? 'blank' : 'invalid', 'bad'),
                entry.reason
                  ? h('div', { class: 'small dim' }, entry.reason) : null),
        ], 'No calibration regions could be read.')),
    h('div', { class: 'body small muted' },
      'Calibration blobs are extracted to /run/firmware before the driver loads. '
      + 'A blank or unrecognised region means that radio would fall back to '
      + 'firmware defaults, giving wrong TX power and EVM.'));
}

function factoryWifiCard(id) {
  const fw = id.factory_wifi || {};
  const reveal = h('button', { class: 'sm' }, icon('search', 13), 'Reveal');
  const out = h('div');

  reveal.addEventListener('click', async () => {
    reveal.disabled = true;
    try {
      const data = await api('/platform/identity/factory-credentials');
      out.textContent = '';
      out.append(
        h('div', { class: 'banner warn', style: 'margin:10px 0 0' },
          icon('warn', 15, 'ico'),
          h('div', {}, 'Shown once, and the read is recorded in the event log. '
            + 'These are the factory values from ART — they do not reflect the '
            + 'SSIDs this gateway is currently running.')),
        dataTable(['Band', 'SSID', 'Key'],
          ['2g', '5g', '6g'],
          (band) => [
            bandLabel(band),
            h('span', { class: 'mono' }, data.ssids?.[band] || '—'),
            h('span', { class: 'mono' }, data.keys?.[band] || '—'),
          ]),
        h('div', { class: 'mt' },
          h('span', { class: 'muted' }, 'WPS PIN: '),
          h('b', { class: 'mono' }, data.wps_pin || '—')));
    } catch (err) {
      toast(err.message, 'bad');
      reveal.disabled = false;
    }
  });

  return h('div', { class: 'card mt' },
    h('header', {}, h('h2', {}, 'Factory Wi-Fi credentials'),
      h('div', { class: 'spacer' }),
      fw.key_set ? pill('key programmed', 'ok') : pill('no key', 'mute'),
      fw.wps_pin_set ? pill('WPS PIN programmed', 'ok') : null,
      reveal),
    h('div', { class: 'body' },
      dataTable(['Band', 'Factory SSID'], ['2g', '5g', '6g'],
        (band) => [bandLabel(band),
                   h('span', { class: 'mono' }, fw[`ssid_${band}`] || '—')]),
      h('div', { class: 'small muted mt' },
        'The passphrase and WPS PIN are held back from the normal hardware read '
        + 'so they cannot end up in a screenshot or a shared API response. '
        + 'Revealing them needs system.write.'),
      out));
}

function emmcCard(id) {
  const e = id.emmc || {};
  if (!e.available) {
    return h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'eMMC')),
      h('div', { class: 'empty' }, 'No eMMC device reported.'));
  }
  const rows = [
    ['Device', e.block_device], ['Name', e.name], ['Type', e.type],
    ['Capacity', e.capacity_bytes ? fmtBytes(e.capacity_bytes) : null],
    ['CID serial', e.serial], ['Manufacturer ID', e.manfid],
    ['OEM ID', e.oemid], ['Firmware rev', e.fwrev], ['Hardware rev', e.hwrev],
    ['Manufactured', e.date],
    ['Estimated life used', e.life_time], ['Pre-EOL state', e.pre_eol_info],
  ].filter((r) => r[1]);
  return h('div', { class: 'card mt' },
    h('header', {}, h('h2', {}, 'eMMC')),
    h('div', { class: 'body tight' },
      dataTable(['Field', 'Value'], rows,
        ([k, v]) => [h('span', { class: 'muted' }, k),
                     h('span', { class: 'mono' }, String(v))])));
}

function bootloaderCard(id) {
  const b = id.bootloader || {};
  const rows = [
    ['Environment partition', b.device],
    ['Environment CRC', b.crc_ok === null ? null : (b.crc_ok ? 'valid' : 'INVALID')],
    ['Variables', b.variable_count ? String(b.variable_count) : null],
    ['machid', id.machid],
    ['SoC version', b.soc_version],
    ['Flash type', b.flash_type],
    ['ethaddr', b.ethaddr],
    ['bootcmd', b.bootcmd],
    ['bootargs', b.bootargs],
  ].filter((r) => r[1]);
  return h('div', { class: 'card mt' },
    h('header', {}, h('h2', {}, 'Bootloader (U-Boot)'),
      h('div', { class: 'spacer' }),
      b.crc_ok === false ? pill('env CRC invalid', 'bad')
        : b.crc_ok ? pill('env CRC valid', 'ok') : null),
    h('div', { class: 'body tight' },
      dataTable(['Field', 'Value'], rows,
        ([k, v]) => [h('span', { class: 'muted' }, k),
                     h('span', { class: 'mono small' }, String(v))])));
}

pages.platform = async (root) => {
  const [data, id] = await Promise.all([
    api('/platform'), api('/platform/identity')]);

  root.append(
    identityCard(id),
    artCard(id),
    factoryWifiCard(id),
    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Software')),
      h('div', { class: 'body' },
        h('div', { class: 'grid c4' },
          kv('Kernel', data.board?.kernel),
          kv('Firmware', data.board?.firmware),
          kv('hostapd', data.hostapd?.mlo ? 'MLO capable' : 'no MLO'),
          kv('hostapd path', data.hostapd?.path)),
        data.hostapd?.reason
          ? h('div', { class: 'banner warn mt', style: 'margin-bottom:0' },
              icon('warn', 14, 'ico'), h('div', {}, data.hostapd.reason))
          : null)),

    accelerationCard(data.acceleration || {}),
    bootloaderCard(id),
    emmcCard(id),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Radios')),
      h('div', { class: 'body tight' },
        dataTable(['Radio', 'phy', 'MAC', 'Band', 'Standards', 'Widths',
                   ['NSS', { num: true }], 'Firmware', 'PCIe'],
          Object.values(data.radios || {}),
          (r) => [
            h('b', {}, r.id),
            h('span', { class: 'mono small' }, r.phy),
            h('span', { class: 'mono small' }, r.mac || '—'),
            bandLabel(r.band),
            h('span', { class: 'small' }, (r.standards || []).join(', ')),
            h('span', { class: 'small' }, (r.widths || []).join('/') + ' MHz'),
            r.max_nss,
            h('div', { class: 'small dim' }, r.firmware?.version || '—',
              r.firmware?.crashes
                ? h('div', {}, pill(`${r.firmware.crashes} crashes`, 'warn'))
                : null),
            h('span', { class: 'small dim mono' }, r.pcie?.slot || '—'),
          ], 'No radios detected.'))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Thermal'),
        h('div', { class: 'spacer' }),
        data.thermal?.max_temperature_c
          ? pill(`${data.thermal.max_temperature_c} °C`,
              data.thermal.state === 'normal' ? 'ok' : 'warn')
          : null),
      h('div', { class: 'body tight' },
        dataTable(['Zone', 'Type', ['Temperature', { num: true }]],
          data.thermal?.zones || [],
          (z) => [h('span', { class: 'mono small' }, z.id), z.type,
                  `${z.temperature_c} °C`],
          'No thermal zones reported.'))));
};

/* ---------------------------------------------------------------- config */

pages.config = async (root) => {
  const [pending, revisions] = await Promise.all([
    api('/config/pending'), api('/config/revisions')]);
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, `Uncommitted changes (${(pending.changes || []).length})`),
        h('div', { class: 'spacer' }),
        (pending.changes || []).length ? h('button', { class: 'sm ghost',
          onclick: () => mutate(() => api('/config/discard', { method: 'POST' }),
            'Candidate discarded') }, 'Discard') : null,
        (pending.changes || []).length ? h('button', { class: 'primary sm',
          onclick: () => mutate(() => api('/config/commit',
            { method: 'POST', body: { summary: 'manual commit' } }),
            'Committed') }, 'Commit') : null),
      h('div', { class: 'body tight table-wrap' },
        (pending.changes || []).length ? h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Path'), h('th', {}, 'Old'),
            h('th', {}, 'New'))),
          h('tbody', {}, pending.changes.map((c) => h('tr', {},
            h('td', { class: 'mono small' }, c.path),
            h('td', { class: 'mono small dim' }, JSON.stringify(c.old)),
            h('td', { class: 'mono small' }, JSON.stringify(c.new))))))
          : h('div', { class: 'empty' }, 'Running configuration matches the candidate.'))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Revision history')),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Rev'), h('th', {}, 'Time'),
            h('th', {}, 'User'), h('th', {}, 'Source'), h('th', {}, 'Summary'),
            h('th', {}, ''))),
          h('tbody', {}, (revisions.items || []).map((rev) => h('tr', {},
            h('td', { class: 'num' }, rev.id),
            h('td', { class: 'small nowrap' }, fmtTime(rev.ts)),
            h('td', {}, rev.user),
            h('td', { class: 'small dim' }, rev.source),
            h('td', { class: 'small' }, rev.summary),
            h('td', {}, h('button', { class: 'sm ghost', onclick: () =>
              confirmAction(`Roll back to revision ${rev.id}?`,
                'The gateway will re-apply that configuration and ask you to '
                + 'confirm before the rollback timer expires.',
                () => api(`/config/revisions/${rev.id}/rollback`, { method: 'POST' }))
            }, 'Roll back'))))))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Backup')),
      h('div', { class: 'body' },
        h('p', { class: 'muted small' },
          'The backup contains the full configuration including secrets. '
          + 'Radio calibration (ART) is never included — it is not user configuration.'),
        h('button', { class: 'sm', onclick: async () => {
          const data = await api('/backups/export');
          const blob = new Blob([JSON.stringify(data, null, 2)],
            { type: 'application/json' });
          const link = h('a', { href: URL.createObjectURL(blob),
            download: `sbegw-backup-${new Date().toISOString().slice(0, 10)}.json` });
          link.click(); URL.revokeObjectURL(link.href);
        }}, 'Download backup')))));
};

pages.audit = async (root) => {
  const data = await api('/audit?limit=300');
  root.append(h('div', { class: 'card' },
    h('header', {}, h('h2', {}, 'Audit trail')),
    h('div', { class: 'body tight table-wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'User'),
          h('th', {}, 'Source'), h('th', {}, 'Action'), h('th', {}, 'Result'),
          h('th', {}, 'Detail'), h('th', { class: 'num' }, 'Changes'))),
        h('tbody', {}, (data.items || []).map((entry) => h('tr', {},
          h('td', { class: 'small nowrap' }, fmtTime(entry.ts)),
          h('td', {}, entry.user),
          h('td', { class: 'small mono dim' }, entry.source_ip),
          h('td', {}, entry.action),
          h('td', {}, pill(entry.success ? 'ok' : 'failed', entry.success ? 'ok' : 'bad')),
          h('td', { class: 'small' }, entry.detail),
          h('td', { class: 'num' },
            (entry.diff || []).length
              ? h('button', { class: 'sm ghost', onclick: () =>
                  modal(`Change ${entry.txid}`, h('div', { class: 'table-wrap' },
                    h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Path'),
                      h('th', {}, 'Old'), h('th', {}, 'New'))),
                      h('tbody', {}, entry.diff.map((c) => h('tr', {},
                        h('td', { class: 'mono small' }, c.path),
                        h('td', { class: 'mono small dim' }, JSON.stringify(c.old)),
                        h('td', { class: 'mono small' }, JSON.stringify(c.new))))))))
                }, String(entry.diff.length))
              : h('span', { class: 'dim' }, '0')))))))));
};

pages.users = async (root) => {
  const [users, rbac] = await Promise.all([api('/users'), api('/rbac')]);
  root.append(
    h('div', { class: 'card' },
      h('header', {}, h('h2', {}, 'Administrators'),
        h('div', { class: 'spacer' }),
        h('button', { class: 'primary sm', onclick: () => userModal(rbac) }, '+ New user')),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Username'), h('th', {}, 'Role'),
            h('th', {}, 'MFA'), h('th', {}, 'Created'), h('th', {}, ''))),
          h('tbody', {}, (users.items || []).map((user) => h('tr', {},
            h('td', {}, h('b', {}, user.username)),
            h('td', {}, pill(user.role, user.role === 'owner' ? 'info' : 'mute')),
            h('td', {}, pill(user.mfa_enabled ? 'enabled' : 'off',
              user.mfa_enabled ? 'ok' : 'mute')),
            h('td', { class: 'small dim' }, fmtTime(user.created)),
            h('td', { class: 'nowrap' },
              h('button', { class: 'sm ghost', onclick: () =>
                passwordModal(user.username) }, 'Password'),
              user.mfa_enabled ? null : h('button', { class: 'sm ghost',
                onclick: () => enableMfa(user.username) }, 'Enable MFA'),
              user.username === store.user?.name ? null
                : h('button', { class: 'sm ghost danger', onclick: () =>
                    confirmDelete(`user ${user.username}`, () =>
                      api(`/users/${user.username}`, { method: 'DELETE' })) },
                    'Delete')))))))),

    h('div', { class: 'card mt' },
      h('header', {}, h('h2', {}, 'Roles and permissions')),
      h('div', { class: 'body tight table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Role'), h('th', {}, 'Permissions'))),
          h('tbody', {}, Object.entries(rbac.roles || {}).map(([role, perms]) =>
            h('tr', {}, h('td', {}, h('b', {}, role)),
              h('td', { class: 'small' }, perms.map((p) =>
                h('span', { class: 'pill mute', style: 'margin:2px 3px 2px 0' }, p))))))))));
};

function userModal(rbac) {
  const username = h('input', { type: 'text', required: 'required' });
  const password = h('input', { type: 'password', required: 'required' });
  const role = h('select', {}, Object.keys(rbac.roles || {}).map((r) =>
    h('option', { value: r, selected: r === 'read-only' }, r)));
  modal('New administrator', h('div', {},
    h('label', { class: 'field' }, h('span', {}, 'Username'), username),
    h('label', { class: 'field' }, h('span', {}, 'Password',
      h('span', { class: 'help' }, ' — 10+ characters, three character classes')), password),
    h('label', { class: 'field' }, h('span', {}, 'Role'), role)),
    () => mutate(() => api('/users', { method: 'POST', body: {
      username: username.value.trim(), password: password.value, role: role.value } }),
      'User created'));
}

function passwordModal(username) {
  const password = h('input', { type: 'password', required: 'required' });
  modal(`Change password · ${username}`,
    h('div', {}, h('label', { class: 'field' }, h('span', {}, 'New password'), password),
      h('div', { class: 'small muted' },
        'All existing sessions for this account are revoked.')),
    () => mutate(() => api(`/users/${username}`,
      { method: 'PUT', body: { password: password.value } }), 'Password changed'));
}

async function enableMfa(username) {
  try {
    const result = await api(`/users/${username}`,
      { method: 'PUT', body: { enable_mfa: true } });
    modal('MFA enabled', h('div', {},
      h('p', {}, 'Add this secret to your authenticator app now — it is shown once:'),
      h('p', { class: 'mono', style: 'font-size:16px;word-break:break-all' },
        result.totp_secret),
      h('p', { class: 'small muted' },
        `Account: ${username} · Issuer: SBE1V1K Gateway · TOTP, SHA1, 6 digits, 30s`)),
      null, 'Done');
    refresh();
  } catch (err) { toast(err.message, 'bad'); }
}

/* ---------------------------------------------------------------- modals */

function modal(title, bodyNode, onSubmit, submitLabel = 'Save') {
  const host = h('div', { class: 'modal-host', onclick: (e) => {
    if (e.target === host) host.remove();
  }});
  const submit = onSubmit ? h('button', { class: 'primary' }, submitLabel) : null;
  if (submit) {
    submit.addEventListener('click', async () => {
      submit.disabled = true;
      try { await onSubmit(); host.remove(); }
      catch (_) { submit.disabled = false; }
    });
  }
  host.append(h('div', { class: 'card modal' },
    h('header', {}, h('h2', {}, title), h('div', { class: 'spacer' }),
      h('button', { class: 'icon', onclick: () => host.remove() }, icon('close', 14))),
    h('div', { class: 'body' }, bodyNode),
    h('div', { class: 'body modal-foot' },
      h('button', { class: 'ghost', onclick: () => host.remove() },
        submit ? 'Cancel' : 'Close'), submit)));
  document.body.append(host);
  const firstInput = host.querySelector('input:not([disabled]), select');
  if (firstInput) firstInput.focus();
  return host;
}

function confirmDelete(what, action) {
  return confirmAction(`Delete ${what}?`, 'This cannot be undone, but the previous '
    + 'configuration remains in the revision history.', action);
}

function confirmAction(title, message, action) {
  modal(title, h('p', { class: 'muted' }, message),
    () => mutate(action, 'Done'), 'Confirm');
}

/* ------------------------------------------------------------------ debounce */

function debounce(fn, ms) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/* ----------------------------------------------------------------- render */

let rendering = false;

async function render() {
  const root = $('#root');
  if (!store.user) {
    const info = await api('/setup').catch(() => ({ setup_required: false }));
    root.textContent = '';
    root.append(renderAuth({ setup: !!info.setup_required }));
    return;
  }
  // Build the new page beside the current one and swap it in when it is ready.
  //
  // Clearing #root up front left the page blank for as long as the API took to
  // answer — the twelve-second auto-refresh made that a visible flash — and
  // rebuilding the DOM threw the scroll position away, so a long page jumped
  // back to the top every time. The staging copy is attached (so charts that
  // measure their container still get a real width) but not visible.
  const scrollY = window.scrollY;
  const previousBody = root.querySelector('#page-body');
  const bodyScroll = previousBody ? previousBody.scrollTop : 0;
  const previous = Array.from(root.children);

  const shell = renderShell();
  const body = shell.querySelector('#page-body');
  const banner = pendingBanner();
  if (banner) body.append(banner);
  if (previous.length) shell.classList.add('is-staging');
  root.append(shell);

  const page = pages[store.page] || pages.dashboard;
  try {
    await page(body);
  } catch (err) {
    if (err.status === 401) {
      store.user = null;
      shell.remove();
      return render();
    }
    body.append(h('div', { class: 'banner bad' }, icon('error', 15, 'ico'),
      h('div', {}, `Could not load this page: ${err.message}`)));
  }

  previous.forEach((node) => node.remove());
  shell.classList.remove('is-staging');
  body.scrollTop = bodyScroll;
  window.scrollTo(0, scrollY);
}

async function refresh(force = false) {
  if (rendering && !force) return;
  rendering = true;
  try {
    if (store.user) {
      store.dashboard = await api('/dashboard');
      const pending = store.dashboard.alerts?.some((a) => a.area === 'config');
      if (!pending) store.pending = null;
    }
    await render();
  } catch (err) {
    if (err.status === 401) { store.user = null; await render(); }
  } finally {
    rendering = false;
  }
}

/* Live updates: patch the cheap numbers in place so the SSE stream does not
 * cause a full re-render (which would fight with any open form). */
function connectStream() {
  if (store.stream) store.stream.close();
  const stream = new EventSource(API + '/stream');
  store.stream = stream;
  stream.addEventListener('telemetry', (message) => {
    try { store.live = JSON.parse(message.data); } catch (_) { return; }
    if (store.page === 'dashboard') patchDashboard(store.live);
  });
  stream.addEventListener('event', (message) => {
    let event;
    try { event = JSON.parse(message.data); } catch (_) { return; }
    if (['error', 'critical'].includes(event.severity)) {
      toast(`${event.kind}: ${event.message}`, 'bad');
    }
  });
  stream.onerror = () => { setTimeout(connectStream, 5000); };
}

function patchDashboard(live) {
  if (!live) return;
  const cards = document.querySelectorAll('.stat .value');
  // Only the uptime/clients tiles are safe to patch blind; the rest are
  // refreshed on the normal interval.
  const clientTile = Array.from(document.querySelectorAll('.stat'))
    .find((el) => el.querySelector('.label')?.textContent === 'Clients');
  if (clientTile && live.clients) {
    const value = clientTile.querySelector('.value');
    if (value) value.textContent = String(live.clients.total ?? 0);
  }
}

/* ------------------------------------------------------------------- boot */

async function boot() {
  // Light is the default (as in UniFi Network); dark is opt-in and remembered.
  let stored = null;
  try { stored = localStorage.getItem('sbegw-theme'); } catch (_) {}
  applyTheme(stored || 'light');

  if (location.hash) {
    const page = location.hash.slice(1);
    if (pages[page]) store.page = page;
  }
  window.addEventListener('hashchange', () => {
    const page = location.hash.slice(1);
    if (pages[page] && page !== store.page) { store.page = page; render(); }
  });

  if (!store.user) {
    try {
      const self = await api('/auth/self');
      store.user = self.user; store.csrf = self.csrf;
    } catch (_) { /* not signed in */ }
  }
  await refresh(true);
  if (store.user) {
    connectStream();
    setInterval(() => {
      if (document.hidden) return;
      if (document.querySelector('.modal-host')) return;
      // Re-rendering under someone's cursor loses what they were doing.
      const active = document.activeElement;
      if (active && ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName)) return;
      if (!window.getSelection().isCollapsed) return;
      refresh();
    }, 12000);
  }
}

boot();
