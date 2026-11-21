// Reusable Trust & Protection UI components, theme manager, and data-visualization helpers

import { esc } from './01_core_state_and_scam_detection';

export type ThemePref = 'system' | 'light' | 'dark';
export type IconName =
  | 'shield'
  | 'home'
  | 'location'
  | 'search'
  | 'card'
  | 'qr'
  | 'phone'
  | 'bell'
  | 'spark'
  | 'chart'
  | 'users'
  | 'settings'
  | 'sun'
  | 'moon'
  | 'monitor'
  | 'logout'
  | 'wifi-off'
  | 'menu'
  | 'chevron-left'
  | 'chevron-right'
  | 'globe'
  | 'activity'
  | 'x'
  | 'filter'
  | 'check'
  | 'alert-triangle'
  | 'arrow-right'
  | 'wallet'
  | 'book'
  | 'heart'
  | 'calendar'
  | 'file-text'
  | 'life-buoy'
  | 'lock'
  | 'building'
  | 'plus'
  | 'trash';

const THEME_STORAGE_KEY = 'guardian_theme';

export function getThemePref(): ThemePref {
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (raw === 'light' || raw === 'dark' || raw === 'system') return raw;
  } catch {
    // ignore storage errors
  }
  return 'system';
}

export function resolveTheme(pref: ThemePref): 'light' | 'dark' {
  if (pref === 'dark') return 'dark';
  if (pref === 'light') return 'light';
  const sysDark =
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches;
  return sysDark ? 'dark' : 'light';
}

export function applyTheme(pref: ThemePref = getThemePref()): 'light' | 'dark' {
  const resolved = resolveTheme(pref);
  const root = document.documentElement;
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-theme-pref', pref);
  if (resolved === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
  return resolved;
}

export function setThemePref(pref: ThemePref, onAfter?: () => void): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, pref);
  } catch {
    // ignore storage errors
  }
  applyTheme(pref);
  if (onAfter) onAfter();
}

export function initThemeListener(onSystemChange: () => void): () => void {
  applyTheme();
  if (typeof window.matchMedia !== 'function') return () => {};
  const mql = window.matchMedia('(prefers-color-scheme: dark)');
  const handler = () => {
    if (getThemePref() === 'system') {
      applyTheme('system');
      onSystemChange();
    }
  };
  if (typeof mql.addEventListener === 'function') {
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }
  mql.addListener(handler);
  return () => mql.removeListener(handler);
}

export function initConnectivityListener(onChange: (online: boolean) => void): () => void {
  const handleOnline = () => onChange(true);
  const handleOffline = () => onChange(false);
  window.addEventListener('online', handleOnline);
  window.addEventListener('offline', handleOffline);
  return () => {
    window.removeEventListener('online', handleOnline);
    window.removeEventListener('offline', handleOffline);
  };
}

const ICON_PATHS: Record<IconName, string> = {
  shield: '<path d="M12 2l7 3v6c0 5-3.5 9-7 11-3.5-2-7-6-7-11V5l7-3z"/><path d="M9.5 12l1.8 1.8L15 10"/>',
  home: '<path d="M3 10.5L12 3l9 7.5"/><path d="M5 9.5V20h14V9.5"/>',
  location: '<path d="M12 21s-6-5.2-6-10a6 6 0 1112 0c0 4.8-6 10-6 10z"/><circle cx="12" cy="11" r="2.2"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  card: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18"/>',
  qr: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><path d="M14 14h2v2h-2zm4 0h2v4h-4v2h4"/>',
  phone: '<path d="M6.5 4h3l1.5 4-2 1.5a12 12 0 005.5 5.5l1.5-2 4 1.5v3a2 2 0 01-2.2 2A16 16 0 014.5 6.2 2 2 0 016.5 4z"/>',
  bell: '<path d="M6 15V10a6 6 0 1112 0v5l2 2H4l2-2z"/><path d="M10 19a2 2 0 004 0"/>',
  spark: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z"/>',
  chart: '<path d="M4 19h16"/><rect x="6" y="11" width="3" height="6"/><rect x="11" y="7" width="3" height="10"/><rect x="16" y="4" width="3" height="13"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M3 19c0-3 2.7-5 6-5s6 2 6 5"/><circle cx="17" cy="9" r="2.5"/><path d="M16 14.2c2.4.4 4.5 2 4.5 4.8"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-1.8-.3 1.6 1.6 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.6 1.6 0 00-1-1.5 1.6 1.6 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.6 1.6 0 00.3-1.8 1.6 1.6 0 00-1.5-1H3a2 2 0 110-4h.1a1.6 1.6 0 001.5-1 1.6 1.6 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.6 1.6 0 001.8.3h.1a1.6 1.6 0 001-1.5V3a2 2 0 114 0v.1a1.6 1.6 0 001 1.5 1.6 1.6 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.6 1.6 0 00-.3 1.8v.1a1.6 1.6 0 001.5 1H21a2 2 0 110 4h-.1a1.6 1.6 0 00-1.5 1z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 019.5 4a7.5 7.5 0 1010.5 10.5z"/>',
  monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  logout: '<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  'wifi-off': '<path d="M2 2l20 20"/><path d="M8.5 16.5a5 5 0 017 0"/><path d="M5 12.9a10 10 0 015.2-2.6m4.6.5a10 10 0 014.2 2.1"/><circle cx="12" cy="19" r="1"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  'chevron-left': '<path d="M15 18l-6-6 6-6"/>',
  'chevron-right': '<path d="M9 18l6-6-6-6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8"/><path d="M12 3a13 13 0 000 18 13 13 0 000-18z"/>',
  activity: '<path d="M22 12h-4l-3 9-6-18-3 9H2"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4-2v-4L3 5z"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  'alert-triangle': '<path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  'arrow-right': '<path d="M5 12h14M13 5l7 7-7 7"/>',
  wallet: '<path d="M19 7V4a1 1 0 00-1-1H5a2 2 0 000 4h15a1 1 0 011 1v4h-3a2 2 0 000 4h3a1 1 0 001-1v-2a1 1 0 00-1-1"/><path d="M3 5v14a2 2 0 002 2h15a1 1 0 001-1v-4"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>',
  heart: '<path d="M20.8 4.6a5.5 5.5 0 00-7.8 0L12 5.6l-1-1a5.5 5.5 0 00-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 000-7.8z"/>',
  calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  'file-text': '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  'life-buoy': '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M4.9 4.9l4.3 4.3M14.8 14.8l4.3 4.3M19.1 4.9l-4.3 4.3M9.2 14.8l-4.3 4.3"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
  building: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M9 22v-4h6v4M8 6h.01M16 6h.01M12 6h.01M12 10h.01M12 14h.01M16 10h.01M16 14h.01M8 10h.01M8 14h.01"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>',
};

export function uiIcon(name: IconName, size = 18): string {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="flex-shrink:0">${ICON_PATHS[name]}</svg>`;
}

export function uiButton(
  label: string,
  onclick: string,
  opts: {
    variant?: 'primary' | 'secondary' | 'destructive' | 'teal';
    disabled?: boolean;
    type?: 'button' | 'submit';
    ariaLabel?: string;
    icon?: IconName;
  } = {}
): string {
  const cls =
    opts.variant === 'secondary'
      ? 's'
      : opts.variant === 'destructive'
        ? 'r'
        : opts.variant === 'teal'
          ? 't'
          : '';
  const type = opts.type || 'button';
  const attrs = [
    `type="${type}"`,
    cls ? `class="${cls}"` : '',
    onclick ? `onclick="${onclick}"` : '',
    opts.disabled ? 'disabled' : '',
    opts.ariaLabel ? `aria-label="${esc(opts.ariaLabel)}"` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<button ${attrs}>${opts.icon ? uiIcon(opts.icon, 16) : ''}${esc(label)}</button>`;
}

export function uiBadge(
  label: string,
  tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' = 'NEUTRAL'
): string {
  return `<span class="pill ${tone}">${esc(label)}</span>`;
}

export function uiSourceBadge(kind: 'actual' | 'simulated' | 'unavailable'): string {
  if (kind === 'actual') return '<span class="badge-actual">Actual</span>';
  if (kind === 'simulated') return '<span class="badge-sim">Simulated</span>';
  return '<span class="badge-unavail">Unavailable in browser</span>';
}

export function uiCard(
  title: string,
  bodyHtml: string,
  opts: {
    subtitle?: string;
    badgeHtml?: string;
    footerHtml?: string;
    extraClass?: string;
    tilt?: boolean;
  } = {}
): string {
  const classes = ['card', 'card-anim', opts.tilt ? 'tilt-card' : '', opts.extraClass || '']
    .filter(Boolean)
    .join(' ');
  return `<section class="${esc(classes)}">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h3 class="t-card" style="margin:0">${esc(title)}</h3>
        ${opts.subtitle ? `<p class="mut" style="margin:2px 0 0">${esc(opts.subtitle)}</p>` : ''}
      </div>
      ${opts.badgeHtml || ''}
    </div>
    ${bodyHtml}
    ${opts.footerHtml ? `<div style="margin-top:12px">${opts.footerHtml}</div>` : ''}
  </section>`;
}

export function uiStatCard(
  label: string,
  value: string | number,
  hint: string,
  opts: {
    source?: 'actual' | 'simulated' | 'unavailable';
    badge?: string;
    badgeTone?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL';
    icon?: IconName;
    tilt?: boolean;
    swipeCard?: boolean;
  } = {}
): string {
  const isNumeric = typeof value === 'number' && Number.isFinite(value);
  const cls = [
    opts.swipeCard ? 'swipe-card' : 'stat-card',
    'card-anim',
    opts.tilt !== false ? 'tilt-card' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<div class="${cls}">
    <div class="row" style="justify-content:space-between;gap:6px">
      <span class="t-label row" style="margin:0;color:var(--mut);gap:6px">${opts.icon ? uiIcon(opts.icon, 14) : ''}${esc(label)}</span>
      ${opts.source ? uiSourceBadge(opts.source) : opts.badge ? uiBadge(opts.badge, opts.badgeTone || 'NEUTRAL') : ''}
    </div>
    <div class="stat-val num"${isNumeric ? ` data-countup="${value}"` : ''}>${esc(value)}</div>
    <div class="mut" style="font-size:12.5px">${esc(hint)}</div>
  </div>`;
}

export function uiAlert(
  message: string,
  opts: {
    title?: string;
    tone?: 'info' | 'warn' | 'danger';
    role?: 'alert' | 'status';
    actionsHtml?: string;
  } = {}
): string {
  const cls =
    opts.tone === 'danger' ? 'alert-danger' : opts.tone === 'warn' ? 'alert-warn' : 'warn';
  const role = opts.role || (opts.tone === 'danger' || opts.tone === 'warn' ? 'alert' : 'status');
  return `<div class="${cls}" role="${role}" aria-live="polite">
    <div class="row" style="justify-content:space-between">
      <div>
        ${opts.title ? `<b>${esc(opts.title)}</b> ` : ''}<span>${esc(message)}</span>
      </div>
      ${opts.actionsHtml || ''}
    </div>
  </div>`;
}

export function uiInput(opts: {
  id: string;
  label: string;
  type?: string;
  value?: string;
  placeholder?: string;
  autocomplete?: string;
  oninput?: string;
  hint?: string;
}): string {
  return `<div>
    <label for="${esc(opts.id)}">${esc(opts.label)}</label>
    <input id="${esc(opts.id)}" type="${esc(opts.type || 'text')}" value="${esc(opts.value || '')}" placeholder="${esc(opts.placeholder || '')}"${opts.autocomplete ? ` autocomplete="${esc(opts.autocomplete)}"` : ''}${opts.oninput ? ` oninput="${opts.oninput}"` : ''}>
    ${opts.hint ? `<p class="mut" style="margin:-6px 0 10px;font-size:12.5px">${esc(opts.hint)}</p>` : ''}
  </div>`;
}

export function uiSelect(opts: {
  id: string;
  label: string;
  options: { value: string; label: string; selected?: boolean }[];
  onchange?: string;
}): string {
  return `<div>
    <label for="${esc(opts.id)}">${esc(opts.label)}</label>
    <select id="${esc(opts.id)}"${opts.onchange ? ` onchange="${opts.onchange}"` : ''}>
      ${opts.options.map((o) => `<option value="${esc(o.value)}"${o.selected ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}
    </select>
  </div>`;
}

export function uiConfirmModal(opts: {
  title: string;
  body: string;
  confirmLabel: string;
  onConfirm: string;
  onCancel: string;
}): string {
  return `<div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-dialog">
      <h3 id="modal-title" class="t-card">${esc(opts.title)}</h3>
      <p class="mut" style="margin:8px 0 16px">${esc(opts.body)}</p>
      <div class="row" style="justify-content:flex-end">
        <button type="button" class="s" onclick="${opts.onCancel}">Cancel</button>
        <button type="button" class="r" onclick="${opts.onConfirm}">${esc(opts.confirmLabel)}</button>
      </div>
    </div>
  </div>`;
}

export function uiStateBox(
  kind: 'loading' | 'empty' | 'error' | 'offline',
  title: string,
  detail: string,
  actionHtml = ''
): string {
  if (kind === 'loading') {
    return `<div class="card" aria-busy="true" aria-live="polite">
      <h3 class="t-card">${esc(title)}</h3>
      <p class="mut">${esc(detail)}</p>
      <div class="skeleton-line" style="width:80%"></div>
      <div class="skeleton-line" style="width:60%"></div>
    </div>`;
  }
  if (kind === 'error') {
    return `<div class="alert-danger" role="alert">
      <b>${esc(title)}</b>
      <p style="margin:6px 0">${esc(detail)}</p>
      ${actionHtml}
    </div>`;
  }
  if (kind === 'offline') {
    return `<div class="alert-warn" role="status">
      <div class="row" style="justify-content:space-between">
        <div class="row" style="gap:8px">${uiIcon('wifi-off', 16)}<div><b>${esc(title)}</b> <span class="mut">${esc(detail)}</span></div></div>
        ${actionHtml}
      </div>
    </div>`;
  }
  return `<div class="empty-box">
    <h3 class="t-card">${esc(title)}</h3>
    <p class="mut" style="margin:6px auto 12px;max-width:46ch">${esc(detail)}</p>
    ${actionHtml}
  </div>`;
}

export interface ChartRow {
  label: string;
  value: number;
  max: number;
  valueText?: string;
  color?: string;
}

export function uiBarChart(
  title: string,
  rows: ChartRow[],
  opts: { subtitle?: string; source?: 'actual' | 'simulated' | 'unavailable'; emptyMessage?: string } = {}
): string {
  const hasData = rows.some((r) => r.value > 0);
  const body = hasData
    ? rows
        .map((r) => {
          const pct = r.max > 0 ? Math.min(100, Math.max(0, (r.value / r.max) * 100)) : 0;
          return `<div class="chart-row">
            <span>${esc(r.label)}</span>
            <div class="chart-track"><div class="chart-fill" style="width:${pct.toFixed(1)}%;background:${r.color || 'var(--teal)'}"></div></div>
            <span class="num" style="text-align:right;font-weight:600">${esc(r.valueText !== undefined ? r.valueText : r.value)}</span>
          </div>`;
        })
        .join('')
    : `<p class="mut">${esc(opts.emptyMessage || 'No recorded data yet.')}</p>`;

  return uiCard(title, body, {
    subtitle: opts.subtitle,
    badgeHtml: opts.source ? uiSourceBadge(opts.source) : '',
  });
}

export function uiThemeSwitcher(): string {
  const pref = getThemePref();
  const resolved = resolveTheme(pref);
  return `<div>
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <b style="display:block">Appearance theme</b>
        <span class="mut" style="font-size:13px">Currently displaying: <b>${resolved === 'dark' ? 'Dark Mode' : 'Light Mode'}</b> (${pref === 'system' ? 'following system setting' : 'manual selection'})</span>
      </div>
    </div>
    <div class="seg-group" role="group" aria-label="Theme preference">
      <button type="button" class="seg-btn ${pref === 'system' ? 'on' : ''}" onclick="setTheme('system')">${uiIcon('monitor', 15)} System</button>
      <button type="button" class="seg-btn ${pref === 'light' ? 'on' : ''}" onclick="setTheme('light')">${uiIcon('sun', 15)} Light</button>
      <button type="button" class="seg-btn ${pref === 'dark' ? 'on' : ''}" onclick="setTheme('dark')">${uiIcon('moon', 15)} Dark</button>
    </div>
  </div>`;
}

export function uiHeaderThemeButton(): string {
  const pref = getThemePref();
  const resolved = resolveTheme(pref);
  const nextPref: ThemePref = pref === 'system' ? 'dark' : pref === 'dark' ? 'light' : 'system';
  const icon: IconName = pref === 'system' ? 'monitor' : resolved === 'dark' ? 'moon' : 'sun';
  const shortLabel = pref === 'system' ? 'Auto' : resolved === 'dark' ? 'Dark' : 'Light';
  const title = `Theme: ${shortLabel} (click to switch to ${nextPref})`;
  return `<button type="button" class="s icon-trigger" onclick="setTheme('${nextPref}')" aria-label="${esc(title)}" title="${esc(title)}">${uiIcon(icon, 14)}<span class="hide-xs">${shortLabel}</span></button>`;
}
