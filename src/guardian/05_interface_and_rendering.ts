// Landing page, parent dashboard, guardian dashboard, render loop and live timers

import {
  S,
  R,
  t,
  esc,
  inr,
  card,
  aiBox,
  analyze,
  inspectManualLink,
  ocrFile,
  reportScam,
  apiJson,
  syncStateFromServer,
  setRenderer,
  getOrCreateGcihDeviceId,
  loadGcihOfflineQueue,
  gcihFlushOfflineQueue,
  gcihRegisterCurrentDevice,
  gcihUpdateDevicePermissions,
  gcihRevokeDevice,
  gcihSyncNow,
  gcihSubmitEntityFeedback,
  gcihCorrectRelationship,
  gcihUpdateIncidentWorkflow,
  type QrIntelligenceReport,
  type QrSourcedField,
  type QrNotificationPrefs,
  type CwTimelineItem,
  type CwSeparateRiskAssessment,
  type LinkAnalysisResult,
  type GsiIncidentRecord,
  type GsiCapabilityHealth,
  type AlertLevel,
  type NotifDeliveryStatus,
  type GsiAlertFilter,
  type SharedIntelligenceItem,
  type GcihFamilySyncPayload,
  type GcihSyncStatus,
  type GcihSectionKey,
  type GcihIncidentWorkflowStatus,
} from './01_core_state_and_scam_detection';
import {
  demo,
  assess,
  payFill,
  askG,
  rq,
  decide,
  resubmitReq,
  escalateReq,
  proceed,
  cancelPay,
  forged,
  swSet,
  swCheck,
  fmtD,
} from './02_payment_and_guardian_approval';
import {
  callStart,
  callEnd,
  demoCall,
  payAlert,
  qrParse,
  qrFile,
  startQrCamera,
  stopQrCamera,
  openQrHistoryReport,
  loadCwOfflineQueue,
  cwConsentAction,
  cwToggleUnknownNotify,
  cwLogCall,
  cwLogPaymentMsg,
  cwDemoScenario,
  cwSubmitQuestionnaire,
  cwDismissQuestionnaire,
  cwSelectEvent,
  cwFlushOfflineQueue,
  cwScreenCallerNumber,
  cwMarkCallerTrusted,
  cwReportSuspiciousCaller,
  cwContactParent,
  cwToggleWhyFlagged,
} from './03_call_watch_and_qr_check';
import {
  chat,
  mic,
  speak,
  QZ,
  ans,
  runEval,
  login,
  reg,
  recoverAccount,
  logout,
  createInvite,
  acceptInvite,
  revokeLink,
  saveConsents,
  saveQrPrefs,
  confirmRevokeAllGuardians,
  emergencyHelpAction,
  dismissEmergencyStatus,
  OFFICIAL_CYBER_CRIME_PORTAL_URL,
  confirmDeleteAllData,
  exportData,
  markNotificationsRead,
  gsiFeedback,
} from './04_ai_assistant_and_learning';
import {
  initThemeListener,
  initConnectivityListener,
  setThemePref,
  uiIcon,
  uiButton,
  uiBadge,
  uiSourceBadge,
  uiCard,
  uiStatCard,
  uiAlert,
  uiConfirmModal,
  uiStateBox,
  uiBarChart,
  uiThemeSwitcher,
  uiHeaderThemeButton,
  type IconName,
  type ThemePref,
} from './ui';
import {
  bindEscapeDrawerHandler,
  bindTiltCards,
  runMotionEnhancements,
  scrollSwipeStrip,
} from './motionSystem';
import type { ShieldVisualInput, GlobeVisualInput, OrbVisualInput, FinanceVisualInput } from './threeVisuals';
import {
  renderLandingFeaturedShelf,
  renderDashboardRecentlyUsed,
  renderDashboardFinanceSnapshot,
  renderSearchResultsOverlay,
  renderAiToolsTab,
  renderBankTab,
  renderControlCenterTab,
} from './parentsAiViews';
import {
  loadRecentTools,
  openAiTool,
  loadParentsAiState,
  askAiToolPrompt,
  addToolWorkspaceItem,
  toggleToolWorkspaceItem,
  removeToolWorkspaceItem,
  connectBankAa,
  revokeBankConsent,
  saveFamilyBudget,
  removeBudget,
  updateFinAccess,
} from './parentsAiClient';
import { renderEmergencyPaymentProtectionTab, eppScrollToBanks } from './emergencyPaymentViews';
import {
  loadEppDashboard,
  eppSelectBank,
  eppSetBankSearch,
  eppPreviewBankService,
  eppLaunchBankService,
  eppConfirmBankCompleted,
  eppToggleApp,
  eppSelectAllApps,
  eppAddCustomApp,
  eppSetDuration,
  eppToggleAuthAck,
  eppToggleBankEditor,
  eppActivateLock,
  eppUnlockLock,
  eppSaveBankDirectoryEntry,
  eppFormatCountdown,
} from './emergencyPaymentClient';

let savedNavScroll = 0;
let tickInterval: number | null = null;
let cleanupThemeListener: (() => void) | null = null;
let cleanupConnectivityListener: (() => void) | null = null;
let threeLoadSeq = 0;

function setFontScale(scale: 'normal' | 'lg' | 'xl'): void {
  S.fontScale = scale;
  document.body.classList.remove('fs-lg', 'fs-xl');
  if (scale === 'lg') document.body.classList.add('fs-lg');
  if (scale === 'xl') document.body.classList.add('fs-xl');
  R();
}

function setTheme(pref: ThemePref): void {
  setThemePref(pref, R);
}

function toggleSidebar(): void {
  S.sidebarCollapsed = !S.sidebarCollapsed;
  try {
    window.localStorage.setItem('guardian_sidebar_collapsed', S.sidebarCollapsed ? '1' : '0');
  } catch {
    // ignore storage errors
  }
  R();
}

function toggleMobileDrawer(open?: boolean): void {
  S.mobileDrawerOpen = typeof open === 'boolean' ? open : !S.mobileDrawerOpen;
  R();
}

function toggleNotifDrawer(open?: boolean): void {
  S.notifDrawerOpen = typeof open === 'boolean' ? open : !S.notifDrawerOpen;
  R();
}

function dismissInfoNotif(id: string): void {
  const found = S.notifications.find((n) => n.id === id);
  // Critical/unread alerts must not be silently dismissed via the UI drawer
  if (!found || !found.read_at) return;
  S.dismissedNotifIds[id] = true;
  R();
}

function setTimelineFilter(filter: 'all' | 'call' | 'sms' | 'qr' | 'pay'): void {
  S.timelineFilter = filter;
  R();
}

function toggleTimelineExpand(id: string): void {
  S.expandedTimelineIds[id] = !S.expandedTimelineIds[id];
  R();
}

function selectFamilyOwner(ownerId: string): void {
  S.selectedFamilyOwnerId = ownerId || 'all';
  if (S.user?.role === 'guardian') {
    const ownerParam = S.selectedFamilyOwnerId === 'all' ? undefined : S.selectedFamilyOwnerId;
    void loadParentsAiState(ownerParam).then(() => R());
    void loadEppDashboard(ownerParam).then(() => R());
  }
  R();
}

function preserveInputRender(id: string, mutate: () => void): void {
  const el = document.getElementById(id) as HTMLInputElement | null;
  const start = el?.selectionStart ?? null;
  const end = el?.selectionEnd ?? null;
  mutate();
  R();
  const next = document.getElementById(id) as HTMLInputElement | null;
  if (next) {
    next.focus();
    if (start !== null && end !== null && typeof next.setSelectionRange === 'function') {
      try {
        next.setSelectionRange(start, end);
      } catch {
        // ignore selection errors
      }
    }
  }
}

function setGlobalSearch(val: string): void {
  preserveInputRender('pai-global-search', () => {
    S.searchQuery = val;
  });
}

function setBankSearch(val: string): void {
  preserveInputRender('pai-tx-search', () => {
    S.bankSearchQuery = val;
  });
}

function setBankCatFilter(val: string): void {
  S.bankCategoryFilter = val || 'all';
  R();
}

const getBellAlertCount = (): number => {
  const unreadNotifs = S.notifications.filter((n) => !n.read_at).length;
  const gsiList =
    S.user?.role === 'guardian'
      ? S.linkedGsiOverview?.incidents || []
      : S.gsi?.recentIncidents || [];
  const openRed = gsiList.filter(
    (i) => i.resolutionStatus === 'open' && i.acknowledgementStatus === 'unacknowledged' && i.redAlertTriggered
  ).length;
  return unreadNotifs + openRed;
};

const topTri = (): string => {
  const bellCount = S.user ? getBellAlertCount() : 0;
  return `<div class="top-tri">
    ${
      S.user
        ? `<button type="button" class="s icon-trigger" onclick="toggleNotifDrawer()" aria-label="Notifications (${bellCount})" title="Open notification center">${uiIcon('bell', 14)}${bellCount > 0 ? `<span class="notif-count-tag">${bellCount}</span>` : ''}</button>`
        : ''
    }
    ${uiHeaderThemeButton()}
    <button type="button" class="s" onclick="setFontScale('${S.fontScale === 'normal' ? 'lg' : S.fontScale === 'lg' ? 'xl' : 'normal'}')" aria-label="Text size" title="Text size">Aa<span class="hide-xs">: ${S.fontScale === 'normal' ? 'Std' : S.fontScale === 'lg' ? 'Lg' : 'XL'}</span></button>
    <button type="button" class="s" onclick="S.lang=S.lang=='en'?'hi':'en';R()" aria-label="Toggle language">${S.lang === 'en' ? 'हिन्दी' : 'English'}</button>
    ${S.user ? `<button type="button" class="s" onclick="logout()" aria-label="${esc(t('out'))}" title="${esc(t('out'))}">${uiIcon('logout', 14)}<span class="hide-xs">${esc(t('out'))}</span></button>` : ''}
  </div>`;
};

const lang = (): string =>
  `<div class="row">
    <button type="button" class="s" onclick="setFontScale('${S.fontScale === 'normal' ? 'lg' : S.fontScale === 'lg' ? 'xl' : 'normal'}')" aria-label="Text size">Aa: ${S.fontScale === 'normal' ? 'Normal' : S.fontScale === 'lg' ? 'Large' : 'XL'}</button>
    <button type="button" class="s" onclick="S.lang=S.lang=='en'?'hi':'en';R()">${S.lang === 'en' ? 'हिन्दी' : 'English'}</button>
  </div>`;

function switchTab(nextTab: string): void {
  if (S.tab === 'qr' && nextTab !== 'qr') {
    stopQrCamera(true);
  }
  S.tab = nextTab;
  S.mobileDrawerOpen = false;
  S.note = '';
  R();
}

const tabs = (a: string[]): string =>
  `<div class="nav" role="tablist" aria-label="Quick navigation">${a
    .map(
      (k) =>
        `<button type="button" role="tab" aria-selected="${S.tab === k}" class="${S.tab === k ? 'on' : ''}" onclick="switchTab('${k}')">${esc(t(k))}</button>`
    )
    .join('')}</div>`;

const note = (): string =>
  S.note ? uiAlert(S.note, { tone: 'info', role: 'status' }) : '';

const offlineBanner = (): string =>
  !S.online
    ? uiStateBox(
        'offline',
        'You are offline.',
        'Server actions and live AI insights are paused until connectivity returns. Rule-based message scoring remains available locally.',
        `<button type="button" class="s" onclick="syncStateFromServer()">Retry connection</button>`
      )
    : '';

const tips = [
  'Banks never ask for your OTP or PIN.',
  'Scanning a QR code only sends money, never receives it.',
  'Family asks for money urgently? Use the safe word and call back.',
];

function landing(): string {
  const sl = [
    ['Detect scam messages early', 'Spot fake bank, KYC, OTP, QR and family-emergency scams in plain English or Hindi.'],
    ['Verify high-risk payments', 'Connects suspicious call timing and message signals to payment amount and beneficiary checks.'],
    ['Consent-first guardian review', 'A trusted guardian reviews one flagged payment at a time. The parent remains in control.'],
  ];

  let authForm = '';
  if (S.mode === 'login') {
    authForm = `<form onsubmit="event.preventDefault();login()">
      <h2 class="t-section">Sign in</h2>
      <p class="mut" style="margin:0 0 12px">Choose your family role to open your dashboard.</p>
      <div class="seg-group" role="group" aria-label="Account role" style="margin-bottom:14px">
        <button type="button" class="seg-btn ${S.role === 'parent' ? 'on' : ''}" onclick="S.role='parent';R()">Parent</button>
        <button type="button" class="seg-btn ${S.role === 'guardian' ? 'on' : ''}" onclick="S.role='guardian';R()">Guardian</button>
      </div>
      <label for="lu">Username</label>
      <input id="lu" value="${esc(S.draftLoginUser)}" oninput="S.draftLoginUser=this.value" placeholder="Enter username (e.g. sunita or rahul)" autocomplete="username">
      <label for="lp">Password</label>
      <input id="lp" type="password" placeholder="Enter password" autocomplete="current-password">
      ${S.recoveryDisplay ? uiAlert(`Save this recovery code: ${S.recoveryDisplay}`, { tone: 'warn' }) : ''}
      ${S.err ? uiAlert(S.err, { tone: 'danger', role: 'alert' }) : ''}
      <div class="row" style="margin-top:8px">
        <button type="submit" ${S.busy.auth || !S.booted ? 'disabled' : ''}>${S.busy.auth ? 'Signing in…' : 'Sign in'}</button>
        <button type="button" class="s" onclick="S.mode='reg';S.err='';S.recoveryDisplay='';R()">Create account</button>
        <button type="button" class="s" onclick="S.mode='recover';S.err='';S.recoveryDisplay='';R()">Reset password</button>
      </div>
    </form>`;
  } else if (S.mode === 'reg') {
    authForm = `<form onsubmit="event.preventDefault();reg()">
      <h2 class="t-section">Create account</h2>
      <div class="seg-group" role="group" aria-label="Account role" style="margin-bottom:14px">
        <button type="button" class="seg-btn ${S.role === 'parent' ? 'on' : ''}" onclick="S.role='parent';R()">Parent</button>
        <button type="button" class="seg-btn ${S.role === 'guardian' ? 'on' : ''}" onclick="S.role='guardian';R()">Guardian</button>
      </div>
      <label for="rn">Full name</label>
      <input id="rn" placeholder="Full name">
      <label for="ru">Username (3–20 letters, digits, or _)</label>
      <input id="ru" placeholder="e.g. anita_sharma" autocomplete="username">
      <label for="rp">Password (8+ characters)</label>
      <input id="rp" type="password" autocomplete="new-password">
      ${S.err ? uiAlert(S.err, { tone: 'danger', role: 'alert' }) : '<p class="mut">Passwords are hashed with salted scrypt on the server. You will receive a one-time recovery code.</p>'}
      <div class="row">
        <button type="submit" ${S.busy.auth ? 'disabled' : ''}>${S.busy.auth ? 'Creating…' : 'Create account'}</button>
        <button type="button" class="s" onclick="S.mode='login';S.err='';R()">Back to sign in</button>
      </div>
    </form>`;
  } else {
    authForm = `<form onsubmit="event.preventDefault();recoverAccount()">
      <h2 class="t-section">Reset password</h2>
      <label for="rcu">Username</label>
      <input id="rcu" placeholder="Enter username">
      <label for="rcc">Recovery code</label>
      <input id="rcc" placeholder="e.g. GRD-XXXXXX-XXXX">
      <label for="rcp">New password (8+ characters)</label>
      <input id="rcp" type="password" autocomplete="new-password">
      ${S.err ? uiAlert(S.err, { tone: 'danger', role: 'alert' }) : ''}
      <div class="row">
        <button type="submit" ${S.busy.auth ? 'disabled' : ''}>Reset password</button>
        <button type="button" class="s" onclick="S.mode='login';S.err='';R()">Back to sign in</button>
      </div>
    </form>`;
  }

  return `<div class="landing-shell">
    <header class="top">
      <span class="brand"><span class="brand-mark">${uiIcon('shield', 18)}</span>Parents AI · Guardian Suite</span>
      ${topTri()}
    </header>
    ${offlineBanner()}
    <section class="hero-cyber card-anim">
      <div class="hero-cyber-grid">
        <div>
          <span class="pill LOW" style="margin-bottom:12px">Parents AI · Guardian &amp; Financial Intelligence</span>
          <h1>Smarter Parenting. Safer Futures.</h1>
          <p>${esc(t('tag'))} Luxury family protection uniting 8 practical AI tools, consent-first RBI Account Aggregator bank insights, live call timing watch, UPI QR intelligence, and single-use guardian approvals.</p>
          <div class="meta-line" style="margin-top:14px;color:#E7C98F">
            <span>8 AI Family Tools</span>
            <span aria-hidden="true">·</span>
            <span>Zero Bank PINs or Passwords</span>
            <span aria-hidden="true">·</span>
            <span>Parent-Controlled Consent</span>
          </div>
        </div>
        <div id="guardian-3d-orb" class="stage-3d-shell" aria-label="Interactive 3D Golden AI Orb"></div>
      </div>
    </section>
    <div class="g-2">
      <div>
        <div class="sl card-anim">
          <div class="s1">
            <div class="meta-line" style="margin-bottom:6px">
              <span>Pillar ${S.slide + 1} of 3</span>
              <span aria-hidden="true">·</span>
              <span>Family Protection Architecture</span>
            </div>
            <h2 class="t-section">${esc(sl[S.slide][0])}</h2>
            <p class="mut" style="margin:0">${esc(sl[S.slide][1])}</p>
          </div>
        </div>
        <div class="row" style="justify-content:space-between;margin-top:10px">
          <button type="button" class="s" onclick="S.slide=(S.slide+2)%3;R()" aria-label="Previous pillar">${uiIcon('chevron-left', 15)} Previous</button>
          <div class="dots">${[0, 1, 2].map((i) => `<b class="${i === S.slide ? 'on' : ''}" onclick="S.slide=${i};R()"></b>`).join('')}</div>
          <button type="button" class="s" onclick="S.slide=(S.slide+1)%3;R()" aria-label="Next pillar">Next ${uiIcon('chevron-right', 15)}</button>
        </div>
        <div class="card card-anim tilt-card" style="margin-top:14px">
          <h3 class="t-card">Transparent advisory &amp; RBI AA compliance</h3>
          <p class="mut" style="margin:4px 0 0">Guardian provides advisory risk signals, a consent-first RBI Account Aggregator Sample Demo financial center, and a simulated payment review workflow. No real bank credentials, PINs, or OTPs are ever collected. For cyber fraud emergencies in India, call <b>1930</b> or report at <b>cybercrime.gov.in</b>.</p>
        </div>
      </div>
      <div class="card card-anim">${authForm}</div>
    </div>
    ${renderLandingFeaturedShelf()}
  </div>`;
}

function activeCallBar(): string {
  const c = S.cur;
  if (!c) return '';
  return `<div class="alert-danger" role="status" aria-live="polite" style="margin:8px 0">
    <div class="row" style="justify-content:space-between">
      <div>
        <span class="pill HIGH">AI timing watch active</span>
        <b> Call length: <span class="num" data-cs="${c.s}">${fmtD(Date.now() - c.s)}</span></b>
        <span class="mut"> · ${c.known ? 'Saved contact' : 'Unknown number'} · Timing only (no audio, no transcription)</span>
      </div>
      <div class="row">
        <button type="button" onclick="payAlert()">Payment alert received now</button>
        <button type="button" class="r" onclick="callEnd()">End call</button>
      </div>
    </div>
    ${c.ai && c.ai.st === 'ok' ? `<p class="mut" style="margin:6px 0 0">${esc(c.ai.explanation)}</p>` : ''}
  </div>`;
}

function alertBanner(): string {
  const a = S.alert;
  if (!a || a.r.level === 'LOW') return '';
  const timingDesc = a.duringCall
    ? `during an active call (${fmtD(a.callDurMs)} so far)`
    : `${fmtD(a.gapMs)} after a ${fmtD(a.callDurMs)} call ended`;
  return `<div class="${a.r.level === 'MEDIUM' ? 'alert-warn' : 'alert-danger'}" role="alert" style="margin:8px 0">
    <div class="row" style="justify-content:space-between">
      <div>
        <span class="pill ${a.r.level}">${a.r.level} SUSPICION</span>
        <b> Pause before paying.</b> ${esc(a.r.sig[0])}. <span class="mut">(Timing: ${timingDesc})</span>
      </div>
      <div class="row">
        ${S.tab !== 'call' ? `<button type="button" class="s" onclick="S.tab='call';R()">View Call Watch</button>` : ''}
        <button type="button" class="s" onclick="S.alert=null;R()">Dismiss</button>
      </div>
    </div>
  </div>`;
}

function notificationsPanel(limit = 5): string {
  const unread = S.notifications.filter((n) => !n.read_at).length;
  if (S.notifications.length === 0) {
    return uiStateBox(
      'empty',
      'No safety notifications yet',
      'Guardian alerts, payment decisions, and timing warnings will appear here when triggered.'
    );
  }
  const items = S.notifications
    .slice(0, limit)
    .map(
      (n) =>
        `<div class="warn" style="margin:8px 0">
          <div class="row" style="justify-content:space-between">
            <b>${!n.read_at ? `${uiBadge('NEW', 'MEDIUM')} ` : ''}${esc(n.title)}</b>
            <span class="mut num" style="font-size:12px">${new Date(n.created_at).toLocaleString()}</span>
          </div>
          <p class="mut" style="margin:4px 0 0">${esc(n.body)} <span style="opacity:.75">(${esc(n.delivery_status)})</span></p>
        </div>`
    )
    .join('');

  return uiCard(
    `Notifications (${unread} unread)`,
    items,
    {
      badgeHtml: unread > 0 ? `<button type="button" class="s" onclick="markNotificationsRead()">Mark all read</button>` : uiSourceBadge('actual'),
    }
  );
}

async function saveIncident(): Promise<void> {
  const ia = document.getElementById('ia') as HTMLInputElement | null;
  const ch = document.getElementById('ic') as HTMLSelectElement | null;
  const summary = ia ? ia.value.trim() : '';
  const channel = ch ? ch.value : 'UPI';
  try {
    await apiJson('/api/incidents', {
      method: 'POST',
      body: JSON.stringify({ summary, channel }),
    });
    if (ia) ia.value = '';
    S.note = 'Incident saved securely.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save incident.';
    R();
  }
}

interface SidebarItem {
  id: string;
  label: string;
  icon: IconName;
  badge?: number;
}

function renderSidebar(groups: { title: string; items: SidebarItem[] }[]): string {
  const collapsed = S.sidebarCollapsed;
  return `<aside class="sidebar" aria-label="Primary navigation">
    <div class="sidebar-head">
      <div class="sidebar-brand">
        <span class="brand-mark">${uiIcon('shield', 17)}</span>
        <span class="sidebar-brand-text">Guardian</span>
      </div>
      <button type="button" class="sidebar-collapse-btn" onclick="toggleSidebar()" aria-expanded="${!collapsed}" aria-label="${collapsed ? 'Expand sidebar' : 'Collapse sidebar'}" title="${collapsed ? 'Expand sidebar' : 'Collapse sidebar'}">
        ${uiIcon(collapsed ? 'chevron-right' : 'chevron-left', 15)}
      </button>
    </div>
    ${groups
      .map(
        (g) => `<div class="sidebar-group">${esc(g.title)}</div>
        ${g.items
          .map(
            (item) => `<button type="button" class="side-link ${S.tab === item.id ? 'on' : ''}" onclick="switchTab('${item.id}')" title="${esc(item.label)}" aria-current="${S.tab === item.id ? 'page' : 'false'}">
              <span class="row" style="gap:9px;flex-wrap:nowrap;min-width:0">${uiIcon(item.icon, 16)}<span class="side-label">${esc(item.label)}</span></span>
              ${item.badge && item.badge > 0 ? `<span class="pill HIGH num side-badge-dot" style="padding:1px 7px">${item.badge}</span>` : ''}
            </button>`
          )
          .join('')}`
      )
      .join('')}
    <hr class="divider">
    <div style="padding:4px 6px">
      <div class="mut sidebar-user-meta" style="font-size:12px;margin-bottom:8px">Signed in as <b>${esc(S.user?.name || '')}</b> (${esc(S.user?.role || '')})</div>
      <button type="button" class="s" style="width:100%" onclick="logout()" title="${esc(t('out'))}">${uiIcon('logout', 16)}<span class="side-label">${esc(t('out'))}</span></button>
    </div>
  </aside>`;
}

function renderMobileDrawer(groups: { title: string; items: SidebarItem[] }[]): string {
  if (!S.mobileDrawerOpen) return '';
  return `<div class="drawer-backdrop" onclick="if(event.target===this)toggleMobileDrawer(false)" role="dialog" aria-modal="true" aria-label="Navigation menu">
    <nav class="drawer-panel-left" aria-label="Mobile navigation drawer">
      <div class="row" style="justify-content:space-between;padding:4px 6px 12px;border-bottom:1px solid var(--line);margin-bottom:8px">
        <span class="brand"><span class="brand-mark">${uiIcon('shield', 16)}</span>Guardian</span>
        <button type="button" class="s icon-trigger" onclick="toggleMobileDrawer(false)" aria-label="Close navigation menu">${uiIcon('x', 16)}</button>
      </div>
      ${groups
        .map(
          (g) => `<div class="sidebar-group">${esc(g.title)}</div>
          ${g.items
            .map(
              (item) => `<button type="button" class="side-link ${S.tab === item.id ? 'on' : ''}" onclick="switchTab('${item.id}')">
                <span class="row" style="gap:9px;flex-wrap:nowrap">${uiIcon(item.icon, 16)}<span>${esc(item.label)}</span></span>
                ${item.badge && item.badge > 0 ? `<span class="pill HIGH num" style="padding:1px 7px">${item.badge}</span>` : ''}
              </button>`
            )
            .join('')}`
        )
        .join('')}
      <hr class="divider">
      <div style="padding:4px 8px">
        <div class="mut" style="font-size:12.5px;margin-bottom:8px">Signed in as <b>${esc(S.user?.name || '')}</b> (${esc(S.user?.role || '')})</div>
        <button type="button" class="s" style="width:100%" onclick="logout()">${uiIcon('logout', 16)}${esc(t('out'))}</button>
      </div>
    </nav>
  </div>`;
}

function renderNotificationsDrawer(): string {
  if (!S.notifDrawerOpen || !S.user) return '';
  const isGuardian = S.user.role === 'guardian';
  const gsiIncidents = isGuardian
    ? S.linkedGsiOverview?.incidents || []
    : S.gsi?.recentIncidents || [];
  const activeReds = gsiIncidents.filter(
    (inc) =>
      inc.resolutionStatus === 'open' &&
      inc.acknowledgementStatus === 'unacknowledged' &&
      (inc.alertLevel === 'RED' || inc.alertLevel === 'CRITICAL_RED')
  );
  const unreadCount = S.notifications.filter((n) => !n.read_at).length;
  const visibleNotifs = S.notifications.filter((n) => !(n.read_at && S.dismissedNotifIds[n.id]));

  return `<div class="drawer-backdrop" onclick="if(event.target===this)toggleNotifDrawer(false)" role="dialog" aria-modal="true" aria-label="Notification center">
    <aside class="drawer-panel-right">
      <div class="row" style="justify-content:space-between;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--line)">
        <div>
          <h2 class="t-section" style="margin:0">Notification Center</h2>
          <span class="mut" style="font-size:12.5px">${unreadCount} unread · ${activeReds.length} active Smart Red Alert(s)</span>
        </div>
        <div class="row" style="gap:6px">
          ${unreadCount > 0 ? `<button type="button" class="s" style="min-height:34px;padding:4px 10px;font-size:12.5px" onclick="markNotificationsRead()">Mark all read</button>` : ''}
          <button type="button" class="s icon-trigger" onclick="toggleNotifDrawer(false)" aria-label="Close notifications">${uiIcon('x', 16)}</button>
        </div>
      </div>

      ${
        activeReds.length
          ? `<div style="margin-bottom:14px">
              <div class="t-label" style="color:var(--red);margin-bottom:6px">Active Security Red Alerts (Acknowledge required)</div>
              ${activeReds
                .map(
                  (inc) => `<div class="red-alert-card" style="padding:12px 14px;margin:6px 0">
                    <div class="row" style="justify-content:space-between;margin-bottom:4px">
                      ${alertLevelBadge(inc.alertLevel)}
                      <span class="mut num" style="font-size:11.5px">${new Date(inc.createdAt).toLocaleString()}</span>
                    </div>
                    <b style="display:block;font-size:14px">${esc(formatThreatHeadline(inc))}</b>
                    <p class="mut" style="margin:4px 0 8px;font-size:12.5px">${esc(inc.reasoningSummary)}</p>
                    <div class="row" style="gap:6px">
                      <button type="button" class="r" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="gsiFeedback('${esc(inc.incidentId)}','acknowledge')">Acknowledge</button>
                      <button type="button" class="s" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="toggleNotifDrawer(false);switchTab('${isGuardian ? 'act' : 'alerts'}')">Inspect</button>
                    </div>
                  </div>`
                )
                .join('')}
            </div>`
          : ''
      }

      <div>
        <div class="t-label" style="margin-bottom:6px">Recent Alerts &amp; Events</div>
        ${
          visibleNotifs.length
            ? visibleNotifs
                .slice(0, 20)
                .map(
                  (n) => `<div class="warn" style="margin:8px 0">
                    <div class="row" style="justify-content:space-between;gap:6px">
                      <b style="font-size:13.5px">${!n.read_at ? `${uiBadge('NEW', 'MEDIUM')} ` : ''}${esc(n.title)}</b>
                      <span class="mut num" style="font-size:11.5px">${new Date(n.created_at).toLocaleString()}</span>
                    </div>
                    <p class="mut" style="margin:4px 0 6px;font-size:13px">${esc(n.body)}</p>
                    <div class="meta-line" style="justify-content:space-between">
                      <span>Status: ${esc(n.delivery_status)}</span>
                      ${n.read_at ? `<button type="button" class="s" style="min-height:28px;padding:2px 8px;font-size:11.5px" onclick="dismissInfoNotif('${esc(n.id)}')">Dismiss</button>` : '<span>Unread</span>'}
                    </div>
                  </div>`
                )
                .join('')
            : uiStateBox('empty', 'Inbox up to date', 'No visible notifications right now. Critical alerts always remain pinned above until acknowledged.')
        }
      </div>
    </aside>
  </div>`;
}

function renderBottomNav(items: SidebarItem[]): string {
  const cols = items.length;
  return `<nav class="bottom-nav" aria-label="Mobile navigation" style="grid-template-columns:repeat(${cols},minmax(0,1fr))">
    ${items
      .map(
        (item) => `<button type="button" class="${S.tab === item.id ? 'on' : ''}" onclick="switchTab('${item.id}')">
          ${uiIcon(item.icon, 18)}
          <span>${esc(item.label)}</span>
        </button>`
      )
      .join('')}
  </nav>`;
}

function renderParentReportsContent(): string {
  const callsTotal = S.calls.length;
  const callsShort = S.calls.filter((c) => c.dur < 60_000).length;
  const callsMed = S.calls.filter((c) => c.dur >= 60_000 && c.dur < 180_000).length;
  const callsLong = S.calls.filter((c) => c.dur >= 180_000).length;
  const callsUnknown = S.calls.filter((c) => !c.known).length;

  const reqTotal = S.reqs.length;
  const reqApproved = S.reqs.filter((q) => q.st === 'approved' || q.st === 'consumed').length;
  const reqPending = S.reqs.filter((q) => q.st === 'pending' || q.st === 'verification_requested').length;
  const reqRejected = S.reqs.filter((q) => q.st === 'rejected' || q.st === 'cancelled' || q.st === 'expired').length;

  const callChart = uiBarChart(
    'Call Watch duration breakdown',
    [
      { label: 'Under 1 min', value: callsShort, max: Math.max(1, callsTotal), color: 'var(--teal)' },
      { label: '1 to 3 min', value: callsMed, max: Math.max(1, callsTotal), color: 'var(--amb)' },
      { label: '3+ minutes', value: callsLong, max: Math.max(1, callsTotal), color: 'var(--red)' },
      { label: 'Unknown caller', value: callsUnknown, max: Math.max(1, callsTotal), color: 'var(--navy)' },
    ],
    {
      subtitle: 'Based strictly on recorded Call Watch sessions (duration metadata only)',
      source: 'simulated',
      emptyMessage: 'No Call Watch sessions recorded yet. Start or demo a call in Call Watch.',
    }
  );

  const reqChart = uiBarChart(
    'Guardian approval outcomes',
    [
      { label: 'Approved / Used', value: reqApproved, max: Math.max(1, reqTotal), color: 'var(--teal)' },
      { label: 'Open / Verify', value: reqPending, max: Math.max(1, reqTotal), color: 'var(--amb)' },
      { label: 'Rejected / Closed', value: reqRejected, max: Math.max(1, reqTotal), color: 'var(--red)' },
    ],
    {
      subtitle: 'Actual approval requests stored in SQLite',
      source: 'actual',
      emptyMessage: 'No guardian payment requests submitted yet.',
    }
  );

  const z = QZ[S.q];
  const evalHtml = S.evalResult
    ? uiBarChart(
        'Scam engine benchmark metrics',
        [
          {
            label: 'Precision',
            value: Math.round(S.evalResult.precision * 100),
            max: 100,
            valueText: `${(S.evalResult.precision * 100).toFixed(1)}%`,
            color: 'var(--teal)',
          },
          {
            label: 'Recall',
            value: Math.round(S.evalResult.recall * 100),
            max: 100,
            valueText: `${(S.evalResult.recall * 100).toFixed(1)}%`,
            color: 'var(--teal)',
          },
          {
            label: 'F1 Score',
            value: Math.round(S.evalResult.f1 * 100),
            max: 100,
            valueText: `${(S.evalResult.f1 * 100).toFixed(1)}%`,
            color: 'var(--navy)',
          },
        ],
        {
          subtitle: `TP: ${S.evalResult.tp} · FP: ${S.evalResult.fp} · TN: ${S.evalResult.tn} · FN: ${S.evalResult.fn} across ${S.evalResult.total} samples`,
          source: 'actual',
        }
      )
    : '';

  return `<div class="g-2">${reqChart}${callChart}</div>
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 class="t-section" style="margin:0">Scam Trainer</h2>
          <p class="mut" style="margin:2px 0 0">Practice spotting common Indian financial scams</p>
        </div>
        <span class="pill LOW num">Score: ${S.score}</span>
      </div>
      <p style="margin:12px 0"><b>${esc(z[0])}</b></p>
      <div style="display:grid;gap:8px">
        ${z[1].map((o, i) => `<button type="button" class="s" style="justify-content:flex-start;text-align:left;white-space:normal" onclick="ans(${i})">${esc(o)}</button>`).join('')}
      </div>
    </div>
    ${note()}
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h3 class="t-card" style="margin:0">Rule Engine Evaluation (16 labelled samples)</h3>
          <p class="mut" style="margin:2px 0 0">Measures true/false positives and negatives on genuine vs. scam messages (English, Hindi, Hinglish, obfuscated).</p>
        </div>
        <button type="button" class="s" onclick="runEval()">Run evaluation</button>
      </div>
    </div>
    ${evalHtml}
    ${renderGsiReportsSection()}`;
}

function renderEmergencyStatusBanner(): string {
  const st = S.emergencyStatus;
  if (!st) return '';
  const toneClass = st.state === 'failed' ? 'alert-danger' : st.state === 'success' ? 'alert-success' : 'alert-warn';
  const titleText =
    st.state === 'success'
      ? 'Administrator Access Revoked — Official Cyber Crime Portal'
      : st.state === 'failed'
        ? 'Administrator Revocation Error — Emergency Reporting Still Available'
        : 'Initiating Emergency Help…';
  return `<section class="${toneClass}" role="status" aria-live="polite" style="margin-bottom:14px">
    <div class="row" style="justify-content:space-between;align-items:flex-start">
      <div style="flex:1;min-width:240px">
        <b style="display:block;margin-bottom:4px">${esc(titleText)}</b>
        <p style="margin:0;font-size:14px">${esc(st.message)}</p>
        ${
          st.state === 'success'
            ? '<p class="mut" style="margin:6px 0 0;font-size:13px">Select your complaint category and submit your report directly on cybercrime.gov.in. Guardian never submits complaints automatically or sends personal logs/contacts.</p>'
            : ''
        }
      </div>
      <div class="row">
        <a class="btn r" href="${esc(OFFICIAL_CYBER_CRIME_PORTAL_URL)}" target="_blank" rel="noopener noreferrer">${st.state === 'failed' ? 'Proceed to Cyber Crime Portal' : 'Open Official Cyber Crime Portal'}</a>
        ${S.tab !== 'fam' ? '<button type="button" class="s" onclick="S.tab=\'fam\';R()">Family Recovery Log</button>' : ''}
        ${st.state !== 'in_progress' ? '<button type="button" class="s" onclick="dismissEmergencyStatus()">Dismiss</button>' : ''}
      </div>
    </div>
  </section>`;
}

function gsiSevBadge(sev: string, label?: string): string {
  const tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' =
    sev === 'LOW'
      ? 'LOW'
      : sev === 'MODERATE'
        ? 'MEDIUM'
        : sev === 'HIGH'
          ? 'HIGH'
          : sev === 'CRITICAL'
            ? 'CRITICAL'
            : 'NEUTRAL';
  return uiBadge(label || sev, tone);
}

function alertLevelBadge(level: AlertLevel): string {
  if (level === 'CRITICAL_RED') return uiBadge('CRITICAL RED', 'CRITICAL');
  if (level === 'RED') return uiBadge('RED ALERT', 'HIGH');
  if (level === 'YELLOW') return uiBadge('YELLOW CAUTION', 'MEDIUM');
  return uiBadge('GREEN NORMAL', 'LOW');
}

function notifStatusBadge(roleLabel: string, status: NotifDeliveryStatus): string {
  const tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'NEUTRAL' =
    status === 'Sent'
      ? 'LOW'
      : status === 'Failed'
        ? 'HIGH'
        : status === 'Pending' || status === 'Suppressed'
          ? 'MEDIUM'
          : 'NEUTRAL';
  return uiBadge(`${roleLabel}: ${status}`, tone);
}

function formatThreatHeadline(inc: GsiIncidentRecord): string {
  const cat = inc.incidentCategory;
  if (cat.includes('phishing_credential')) return 'Phishing & OTP Credential Threat';
  if (cat.includes('call_sms_link_chain')) return 'Correlated Scam Call & Phishing SMS';
  if (cat.includes('repeat_caller_pressure')) return 'Repeated Suspicious Caller & Financial Pressure';
  if (cat.includes('qr_call_payment_context')) return 'Suspicious QR During Call / Payment';
  if (cat.includes('phishing_lookalike')) return 'Phishing Lookalike Link Detected';
  if (cat.includes('otp_related') || cat.includes('fraudulent_pattern')) return 'High-Risk Scam / OTP Disclosure Attempt';
  if (cat.includes('potential_phishing')) return 'Phishing SMS Detected';
  if (cat.includes('verified_spam') || cat.includes('high_risk')) return 'High-Confidence Spam Caller';
  return cat.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function renderSmartRedAlertBanner(incidents: GsiIncidentRecord[], isGuardian = false): string {
  const activeReds = incidents.filter(
    (inc) =>
      inc.resolutionStatus === 'open' &&
      inc.acknowledgementStatus === 'unacknowledged' &&
      (inc.alertLevel === 'RED' || inc.alertLevel === 'CRITICAL_RED')
  );

  if (activeReds.length > 0) {
    return activeReds
      .slice(0, 2)
      .map((inc) => {
        const isCritical = inc.alertLevel === 'CRITICAL_RED';
        const riskText = isCritical ? 'CRITICAL' : 'HIGH';
        return `<section class="red-alert-card ${isCritical ? 'critical' : ''}" role="alert" aria-live="assertive">
          <div class="red-alert-header">
            <div class="red-alert-kicker">
              <span class="red-alert-dot" aria-hidden="true"></span>
              <span>GUARDIAN SECURITY ALERT</span>
            </div>
            <div class="row">
              ${alertLevelBadge(inc.alertLevel)}
              ${uiBadge(`Risk: ${riskText} (${inc.riskScore}/100)`, isCritical ? 'CRITICAL' : 'HIGH')}
            </div>
          </div>
          <h2 class="t-section" style="margin:0 0 4px">${esc(formatThreatHeadline(inc))}${inc.parentName ? ` — ${esc(inc.parentName)}` : ''}</h2>
          <p class="mut" style="margin:0 0 8px;font-size:13px">
            ${inc.actorMasked ? `Caller / Sender: <b>${esc(inc.actorMasked)}</b> · ` : ''}
            Detected: <span class="num">${new Date(inc.createdAt).toLocaleString()}</span> · Confidence: <b>${esc(inc.confidence)}</b>
          </p>
          <div style="margin:8px 0">
            <b>Reason:</b>
            <ul style="margin:4px 0 0">${inc.evidence.slice(0, 4).map((e) => `<li>${esc(e)}</li>`).join('') || `<li>${esc(inc.reasoningSummary)}</li>`}</ul>
          </div>
          <p style="margin:8px 0"><b>Recommended action:</b> ${esc(inc.recommendedAction)}</p>
          <div class="red-alert-delivery">
            ${notifStatusBadge('Parent Notification', inc.parentNotifStatus)}
            ${notifStatusBadge('Child Notification', inc.childNotifStatus)}
            ${inc.childNotifStatus === 'Failed' || inc.parentNotifStatus === 'Failed' ? '<span class="mut">Delivery issue logged honestly; incident preserved in Security History.</span>' : ''}
          </div>
          <div class="row" style="margin-top:8px">
            <button type="button" class="r" style="min-height:34px;padding:4px 12px" onclick="gsiFeedback('${esc(inc.incidentId)}','acknowledge')">Acknowledge Alert</button>
            <button type="button" class="s" style="min-height:34px;padding:4px 12px" onclick="gsiFeedback('${esc(inc.incidentId)}','confirm_threat')">Confirm Threat</button>
            <button type="button" class="s" style="min-height:34px;padding:4px 12px" onclick="gsiFeedback('${esc(inc.incidentId)}','false_positive')">Mark False Positive</button>
            ${!isGuardian ? `<button type="button" class="t" style="min-height:34px;padding:4px 12px" onclick="gsiFeedback('${esc(inc.incidentId)}','resolve')">Resolve</button>` : ''}
          </div>
        </section>`;
      })
      .join('');
  }

  // Subtle YELLOW Caution bar only when no active Red Alert exists
  const activeYellow = incidents.find(
    (inc) =>
      inc.resolutionStatus === 'open' &&
      inc.acknowledgementStatus === 'unacknowledged' &&
      inc.alertLevel === 'YELLOW'
  );
  if (activeYellow) {
    return `<div class="yellow-caution-bar" role="status">
      <div class="row" style="justify-content:space-between">
        <div>
          ${alertLevelBadge('YELLOW')}
          <b> ${esc(formatThreatHeadline(activeYellow))}</b>
          ${activeYellow.actorMasked ? ` <span class="mut">(${esc(activeYellow.actorMasked)})</span>` : ''}
          <span class="mut"> — ${esc(activeYellow.reasoningSummary)}</span>
        </div>
        <button type="button" class="s" style="min-height:30px;padding:2px 10px" onclick="gsiFeedback('${esc(activeYellow.incidentId)}','acknowledge')">Dismiss Caution</button>
      </div>
    </div>`;
  }

  return '';
}

function gcihRiskTone(risk: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' {
  if (risk === 'Critical') return 'CRITICAL';
  if (risk === 'High') return 'HIGH';
  if (risk === 'Moderate') return 'MEDIUM';
  if (risk === 'Low' || risk === 'Safe') return 'LOW';
  return 'NEUTRAL';
}

function gcihVerTone(v: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' {
  if (v === 'Confirmed malicious') return 'CRITICAL';
  if (v === 'High risk') return 'HIGH';
  if (v === 'Suspicious' || v === 'Disputed' || v === 'Under review') return 'MEDIUM';
  if (v === 'Verified legitimate') return 'LOW';
  return 'NEUTRAL';
}

function gcihSyncBadge(status: GcihSyncStatus): string {
  const tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'NEUTRAL' =
    status === 'Successfully synchronised'
      ? 'LOW'
      : status === 'Pending synchronisation' || status === 'Locally detected'
        ? 'MEDIUM'
        : status === 'Synchronisation failed'
          ? 'HIGH'
          : 'NEUTRAL';
  return uiBadge(status, tone);
}

function renderSharedIntelItemsHtml(
  items: SharedIntelligenceItem[],
  heading: string,
  emptyMsg = 'No cross-section shared entities match this context yet.'
): string {
  const uniqueMap = new Map<string, SharedIntelligenceItem>();
  for (const it of items) {
    if (!uniqueMap.has(it.entityId)) uniqueMap.set(it.entityId, it);
  }
  const list = Array.from(uniqueMap.values());
  if (!list.length) {
    return `<p class="mut" style="margin:0">${esc(emptyMsg)}</p>`;
  }
  return list
    .slice(0, 8)
    .map(
      (it) => `<div class="qr-risk-panel" style="margin-bottom:8px">
        <div class="row" style="justify-content:space-between;margin-bottom:4px">
          <div class="row">
            ${uiBadge(it.entityType.replace(/_/g, ' '), 'NEUTRAL')}
            <b>${esc(it.maskedDisplay)}</b>
          </div>
          <div class="row">
            ${uiBadge(it.riskClassification, gcihRiskTone(it.riskClassification))}
            ${uiBadge(it.verificationStatus, gcihVerTone(it.verificationStatus))}
          </div>
        </div>
        <p style="margin:4px 0;font-size:13.5px"><b>Shared reason:</b> ${esc(it.reasonForSharing)}</p>
        <p class="mut" style="margin:2px 0 6px;font-size:12.5px">
          Source: <b>${esc(it.sourceModules.join(', '))}</b> · Attribution: <b>${esc(it.familyMemberAttribution)}</b> · First seen: <span class="num">${new Date(it.discoveryTimestamp).toLocaleString()}</span> · Events: <span class="num">${it.relatedEventIds.length}</span> · Incidents: <span class="num">${it.relatedIncidentIds.length}</span>
        </p>
        ${it.evidenceRefs.length ? `<p class="mut" style="margin:0 0 6px;font-size:12.5px"><b>Evidence:</b> ${esc(it.evidenceRefs.slice(0, 2).join(' | '))}</p>` : ''}
        <div class="row">
          <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(it.entityId)}','legitimate')">Verify Legitimate</button>
          <button type="button" class="r" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(it.entityId)}','suspicious')">Flag Suspicious</button>
          <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(it.entityId)}','false_positive')">False Positive</button>
          <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(it.entityId)}','request_review')">Request Review</button>
        </div>
      </div>`
    )
    .join('');
}

function renderSectionSharedIntelCard(
  sectionKey: GcihSectionKey,
  sectionLabel: string,
  directMatchedItems: SharedIntelligenceItem[] = [],
  combinedSummary?: string
): string {
  const feedItems = S.gcih?.sectionFeeds?.[sectionKey] || [];
  const merged = [...directMatchedItems, ...feedItems];
  const uniqueMap = new Map<string, SharedIntelligenceItem>();
  for (const it of merged) {
    if (!uniqueMap.has(it.entityId)) uniqueMap.set(it.entityId, it);
  }
  const uniqueList = Array.from(uniqueMap.values());
  const flaggedCount = uniqueList.filter(
    (it) =>
      it.verificationStatus !== 'Verified legitimate' &&
      ['Moderate', 'High', 'Critical'].includes(it.riskClassification)
  ).length;

  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h3 class="t-card" style="margin:0">Shared Intelligence — ${esc(sectionLabel)}</h3>
        <p class="mut" style="margin:2px 0 0">Cross-module indicators shared via Guardian Central Intelligence Hub (separated from local direct rules).</p>
      </div>
      <div class="row">
        ${gcihSyncBadge(S.gcihOfflineQueue.length > 0 ? 'Pending synchronisation' : S.gcihSyncStatus)}
        ${uiBadge(flaggedCount > 0 ? `${flaggedCount} Flagged Cross-Module` : `${uniqueList.length} Shared`, flaggedCount > 0 ? 'HIGH' : 'LOW')}
      </div>
    </div>
    ${combinedSummary ? `<div class="warn" style="margin-bottom:10px"><b>Combined Assessment:</b> ${esc(combinedSummary)}</div>` : ''}
    ${renderSharedIntelItemsHtml(uniqueList, sectionLabel)}
  </div>`;
}

function renderGcihHubSyncPanel(syncPayload: GcihFamilySyncPayload | null, isGuardian = false): string {
  const effectiveStatus: GcihSyncStatus =
    !S.online && S.gcihOfflineQueue.length > 0
      ? 'Pending synchronisation'
      : S.gcihOfflineQueue.length > 0
        ? 'Pending synchronisation'
        : syncPayload?.syncStatus || S.gcihSyncStatus;

  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h2 class="t-section" style="margin:0">Guardian Central Intelligence Hub${syncPayload ? ` — ${esc(syncPayload.familyOwnerName)}` : ''}</h2>
        <p class="mut" style="margin:2px 0 0">Bidirectional cross-module entity graph, event bus &amp; family synchronisation</p>
      </div>
      <div class="row">
        ${gcihSyncBadge(effectiveStatus)}
        <button type="button" class="s" style="min-height:34px;padding:4px 12px" onclick="gcihSyncNow()" ${S.busy.gcih ? 'disabled' : ''}>Sync Now</button>
        <button type="button" class="s" style="min-height:34px;padding:4px 12px" onclick="gcihRegisterCurrentDevice()" ${S.busy.gcih ? 'disabled' : ''}>Register Device</button>
      </div>
    </div>
    <div class="stat-grid">
      ${uiStatCard('Shared Entities', syncPayload?.entities.length ?? 0, 'Normalized & masked indicators', { source: 'actual' })}
      ${uiStatCard('Entity Links', syncPayload?.relationships.length ?? 0, 'Cross-section graph edges', { source: 'actual' })}
      ${uiStatCard('Domain Events', syncPayload?.domainEvents.length ?? 0, 'Deduplicated event bus log', { source: 'actual' })}
      ${uiStatCard('Registered Devices', syncPayload?.devices.filter((d) => d.status === 'active').length ?? 0, S.gcihOfflineQueue.length > 0 ? `${S.gcihOfflineQueue.length} queued offline` : 'Active family endpoints', { source: 'actual' })}
    </div>
    ${
      !isGuardian && S.gcihOfflineQueue.length > 0
        ? uiAlert(
            `${S.gcihOfflineQueue.length} offline intelligence event(s) waiting in local queue. ${S.online ? `<button type="button" class="s" style="min-height:30px;padding:2px 10px;margin-left:8px" onclick="gcihFlushOfflineQueue()">Flush Offline Queue Now</button>` : 'Will sync automatically when connectivity returns.'}`,
            { title: 'Pending Synchronisation:', tone: 'warn' }
          )
        : ''
    }
  </div>`;
}

function renderGcihEntitiesAndGraphPanel(syncPayload: GcihFamilySyncPayload | null, isGuardian = false): string {
  if (!syncPayload) return '';
  const entitiesHtml = syncPayload.entities.length
    ? syncPayload.entities
        .slice(0, 10)
        .map(
          (ent) => `<div class="qr-history-row">
            <div style="flex:1;min-width:220px">
              <div class="row" style="gap:6px">
                ${uiBadge(ent.entityType.replace(/_/g, ' '), 'NEUTRAL')}
                <b>${esc(ent.maskedDisplay)}</b>
                ${uiBadge(ent.riskClassification, gcihRiskTone(ent.riskClassification))}
                ${uiBadge(ent.verificationStatus, gcihVerTone(ent.verificationStatus))}
              </div>
              <div class="mut" style="font-size:12.5px;margin-top:4px">
                Modules: <b>${esc(ent.sourceModules.join(', '))}</b> · Devices: <span class="num">${ent.sourceDeviceIds.length}</span> · Events: <span class="num">${ent.relatedEventIds.length}</span> · Incidents: <span class="num">${ent.relatedIncidentIds.length}</span> · v<span class="num">${ent.version}</span>
              </div>
            </div>
            <div class="row">
              <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(ent.id)}','legitimate')">Legitimate</button>
              <button type="button" class="r" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(ent.id)}','suspicious')">Suspicious</button>
              <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(ent.id)}','false_positive')">False Positive</button>
              <button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihSubmitEntityFeedback('${esc(ent.id)}','request_review')">Review</button>
            </div>
          </div>`
        )
        .join('')
    : '<p class="mut" style="margin:0">No shared entities extracted yet. Run SMS, Link, QR, Call, or Payment checks to populate the family entity graph.</p>';

  const relsHtml = syncPayload.relationships.length
    ? syncPayload.relationships
        .slice(0, 10)
        .map(
          (rel) => `<div class="qr-history-row">
            <div style="flex:1;min-width:220px">
              <div class="row" style="gap:6px">
                <b>${esc(rel.firstEntityLabel || rel.firstEntityId)}</b>
                <span class="mut">↔</span>
                <b>${esc(rel.secondEntityLabel || rel.secondEntityId)}</b>
                ${uiBadge(rel.status, rel.status === 'active' ? 'LOW' : 'MEDIUM')}
              </div>
              <div class="mut" style="font-size:12.5px;margin-top:3px">
                Relation: ${esc(rel.relationshipType.replace(/_/g, ' '))} · Modules: ${esc(rel.sourceModules.join(', '))} · Conf: <span class="num">${Math.round(rel.confidence * 100)}%</span>
                ${rel.evidence ? ` · ${esc(rel.evidence)}` : ''}
              </div>
            </div>
            <div class="row">
              ${
                rel.status === 'active'
                  ? `<button type="button" class="s" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihCorrectRelationship('${esc(rel.id)}','dispute','Disputed by ${isGuardian ? 'guardian' : 'user'}')">Dispute Association</button>`
                  : `<button type="button" class="t" style="min-height:30px;padding:3px 9px;font-size:12.5px" onclick="gcihCorrectRelationship('${esc(rel.id)}','restore')">Restore</button>`
              }
            </div>
          </div>`
        )
        .join('')
    : '<p class="mut" style="margin:0">No cross-entity relationships linked yet.</p>';

  return `<div class="g-2">
    ${uiCard('Shared Intelligence Entities & Feedback', entitiesHtml, {
      subtitle: 'Entity feedback updates cross-module assessments without blindly whitelisting unrelated messages',
      badgeHtml: uiSourceBadge('actual'),
    })}
    ${uiCard('Cross-Section Entity Relationship Graph', relsHtml, {
      subtitle: 'Co-occurring phone numbers, UPI IDs, URLs, domains, and merchants across modules',
      badgeHtml: uiSourceBadge('actual'),
    })}
  </div>`;
}

function renderGcihDevicesAndPermissionsPanel(syncPayload: GcihFamilySyncPayload | null, isGuardian = false): string {
  const devices = syncPayload?.devices || [];
  const body = devices.length
    ? devices
        .map(
          (dev) => `<div class="qr-risk-panel" style="margin-bottom:10px">
            <div class="row" style="justify-content:space-between;margin-bottom:6px">
              <div>
                <b>${esc(dev.deviceLabel)}</b> <span class="mut">(${esc(dev.platform)} · ${esc(dev.role)})</span>
                <div class="mut" style="font-size:12px">ID: <code>${esc(dev.id)}</code> · Last seen: <span class="num">${new Date(dev.lastSeenAt).toLocaleString()}</span></div>
              </div>
              <div class="row">
                ${uiBadge(dev.status === 'active' ? 'Active' : 'Revoked', dev.status === 'active' ? 'LOW' : 'HIGH')}
                ${
                  !isGuardian && dev.status === 'active'
                    ? `<button type="button" class="r" style="min-height:30px;padding:3px 10px;font-size:12.5px" onclick="gcihRevokeDevice('${esc(dev.id)}')">Revoke Device</button>`
                    : ''
                }
              </div>
            </div>
            <div class="row" style="gap:6px;margin-bottom:8px;flex-wrap:wrap">
              ${uiBadge(`Call Log: ${dev.permissions.callMonitoring.replace(/_/g, ' ')}`, dev.permissions.callMonitoring === 'granted' ? 'LOW' : 'NEUTRAL')}
              ${uiBadge(`SMS Access: ${dev.permissions.smsMonitoring.replace(/_/g, ' ')}`, dev.permissions.smsMonitoring === 'granted' ? 'LOW' : 'NEUTRAL')}
              ${uiBadge(`Notifications: ${dev.permissions.notifications}`, dev.permissions.notifications === 'granted' ? 'LOW' : 'NEUTRAL')}
            </div>
            ${
              !isGuardian && dev.status === 'active'
                ? `<div class="g" style="gap:6px;font-size:13px">
                    <div class="sw"><input type="checkbox" ${dev.permissions.sharedEntityIndicators ? 'checked' : ''} onchange="gcihUpdateDevicePermissions('${esc(dev.id)}',{sharedEntityIndicators:this.checked})"><span>Share entity indicators</span></div>
                    <div class="sw"><input type="checkbox" ${dev.permissions.sharedRiskClassifications ? 'checked' : ''} onchange="gcihUpdateDevicePermissions('${esc(dev.id)}',{sharedRiskClassifications:this.checked})"><span>Share risk classifications</span></div>
                    <div class="sw"><input type="checkbox" ${dev.permissions.relatedEventSummaries ? 'checked' : ''} onchange="gcihUpdateDevicePermissions('${esc(dev.id)}',{relatedEventSummaries:this.checked})"><span>Share event summaries</span></div>
                    <div class="sw"><input type="checkbox" ${dev.permissions.incidentNotifications ? 'checked' : ''} onchange="gcihUpdateDevicePermissions('${esc(dev.id)}',{incidentNotifications:this.checked})"><span>Incident notifications</span></div>
                    <div class="sw"><input type="checkbox" ${dev.permissions.detailedEvidence ? 'checked' : ''} onchange="gcihUpdateDevicePermissions('${esc(dev.id)}',{detailedEvidence:this.checked})"><span>Detailed redacted evidence</span></div>
                  </div>`
                : ''
            }
          </div>`
        )
        .join('')
    : `<p class="mut" style="margin:0 0 10px">No browser or companion devices registered in Central Intelligence Hub yet.</p>`;

  return uiCard('Family Devices & Granular Sharing Controls', body, {
    subtitle: 'Browser mode truthfully reports unavailable native call/SMS OS permissions; Android companion bridge updates these states.',
    badgeHtml: `<button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="gcihRegisterCurrentDevice()">Register Current Browser</button>`,
  });
}

function renderLinkAnalysisCard(la: LinkAnalysisResult): string {
  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h3 class="t-card" style="margin:0">Automated Link Intelligence (Module C — Direct Detection)</h3>
        <p class="mut" style="margin:2px 0 0">Domain: <code>${esc(la.domain || la.scheme)}</code> · Confidence: <b>${esc(la.confidence)}</b> · Never auto-opened</p>
      </div>
      ${gsiSevBadge(la.severity, `${la.severity} · ${la.riskScore}/100`)}
    </div>
    ${
      la.ssrfBlocked
        ? uiAlert(la.ssrfReason || 'Blocked unsafe or private network address.', {
            title: 'SSRF / Scheme Protection:',
            tone: 'danger',
          })
        : la.isLookalike && la.impersonatedBrand
          ? uiAlert(`Possible lookalike domain mimicking ${la.impersonatedBrand}. Do not enter credentials or OTP.`, {
              title: 'Brand Impersonation Alert:',
              tone: 'danger',
            })
          : ''
    }
    <ul>
      ${
        la.findings.length
          ? la.findings
              .map((f) => `<li>${gsiSevBadge(f.severity)} <b>${esc(f.title)}</b> — <span class="mut">${esc(f.evidence)}</span></li>`)
              .join('')
          : '<li>No structural phishing markers detected locally.</li>'
      }
    </ul>
    ${
      la.localIntelMatch
        ? `<p class="mut" style="margin:6px 0">Local Threat Intel: <b>${esc(la.localIntelMatch.label)}</b> (${la.localIntelMatch.reportCount} report(s), ${la.localIntelMatch.falsePositiveCount} false positive(s))</p>`
        : ''
    }
    ${
      la.sharedIntelligence && la.sharedIntelligence.length
        ? `<div class="warn" style="margin:8px 0"><b>Cross-Module Link Matches:</b> ${renderSharedIntelItemsHtml(la.sharedIntelligence, 'Link Check')}</div>`
        : ''
    }
    <p style="margin:8px 0 4px"><b>Action:</b> ${esc(la.recommendedAction)}</p>
    <p class="mut" style="margin:0;font-size:12.5px">${esc(la.liveProbeNote)} ${esc(la.verificationBoundary)}</p>
  </div>`;
}

function renderGsiCapabilityCard(cap: GsiCapabilityHealth): string {
  return uiCard(
    'GSI Capability & Monitoring Health',
    `<div style="display:grid;gap:8px">
      ${cap.items
        .map((it) => {
          const tone =
            it.status === 'active' ? 'LOW' : it.status === 'degraded' || it.status === 'paused' ? 'MEDIUM' : 'NEUTRAL';
          return `<div class="qr-history-row">
            <div>
              <b>${esc(it.capability)}</b>
              <div class="mut" style="font-size:12.5px">${esc(it.detail)}</div>
            </div>
            ${uiBadge(it.status.replace(/_/g, ' '), tone)}
          </div>`;
        })
        .join('')}
    </div>`,
    {
      subtitle: `Runtime mode: ${cap.runtimeMode.replace(/_/g, ' ')}`,
      badgeHtml: uiBadge(cap.overallStatus, cap.overallStatus === 'healthy' ? 'LOW' : 'MEDIUM'),
    }
  );
}

function filterGsiIncidents(incidents: GsiIncidentRecord[], filter: GsiAlertFilter): GsiIncidentRecord[] {
  if (filter === 'active_red') {
    return incidents.filter((i) => i.resolutionStatus === 'open' && (i.alertLevel === 'RED' || i.alertLevel === 'CRITICAL_RED'));
  }
  if (filter === 'critical_red') {
    return incidents.filter((i) => i.alertLevel === 'CRITICAL_RED');
  }
  if (filter === 'yellow') {
    return incidents.filter((i) => i.alertLevel === 'YELLOW');
  }
  if (filter === 'green') {
    return incidents.filter((i) => i.alertLevel === 'GREEN');
  }
  if (filter === 'resolved') {
    return incidents.filter((i) => i.resolutionStatus !== 'open');
  }
  return incidents;
}

function renderGsiIncidentsList(incidents: GsiIncidentRecord[], isGuardian = false): string {
  const filterOptions: { id: GsiAlertFilter; label: string }[] = [
    { id: 'all', label: `All (${incidents.length})` },
    { id: 'active_red', label: `Active Red (${incidents.filter((i) => i.resolutionStatus === 'open' && i.redAlertTriggered).length})` },
    { id: 'critical_red', label: 'Critical Red' },
    { id: 'yellow', label: 'Yellow Caution' },
    { id: 'green', label: 'Green Normal' },
    { id: 'resolved', label: 'Resolved / Feedback' },
  ];

  const filterBar = `<div class="seg-group" role="group" aria-label="Filter security incidents" style="margin-bottom:12px">
    ${filterOptions
      .map(
        (opt) =>
          `<button type="button" class="seg-btn ${S.gsiAlertFilter === opt.id ? 'on' : ''}" onclick="S.gsiAlertFilter='${opt.id}';R()">${esc(opt.label)}</button>`
      )
      .join('')}
  </div>`;

  const filtered = filterGsiIncidents(incidents, S.gsiAlertFilter);

  if (!filtered.length) {
    return filterBar + uiStateBox(
      'empty',
      incidents.length ? 'No incidents match this filter' : 'No GSI security incidents recorded yet',
      incidents.length
        ? 'Try switching filters above to view other alert levels or resolved incidents.'
        : 'Calls, SMS alerts, links, QR scans, and payment checks automatically populate unified incidents here.'
    );
  }
  return filterBar + filtered
    .slice(0, 12)
    .map((inc) => {
      const fbDisabled = inc.resolutionStatus === 'false_positive' || inc.resolutionStatus === 'confirmed_threat';
      return `<div class="qr-risk-panel" style="margin-bottom:10px">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <div class="row">
            ${alertLevelBadge(inc.alertLevel)}
            ${gsiSevBadge(inc.severity, `${inc.severity} · ${inc.riskScore}/100`)}
            <b>${esc(formatThreatHeadline(inc))}</b>
            ${inc.parentName ? `<span class="mut">(${esc(inc.parentName)})</span>` : ''}
          </div>
          <div class="row">
            ${uiBadge(inc.workflowStatus || 'New', inc.workflowStatus === 'Resolved' || inc.workflowStatus === 'False positive' ? 'LOW' : 'MEDIUM')}
            ${uiBadge(inc.acknowledgementStatus, inc.acknowledgementStatus === 'acknowledged' ? 'NEUTRAL' : 'MEDIUM')}
            ${uiBadge(inc.resolutionStatus.replace(/_/g, ' '), inc.resolutionStatus === 'false_positive' ? 'NEUTRAL' : inc.resolutionStatus === 'confirmed_threat' ? 'HIGH' : 'LOW')}
            <span class="mut" style="font-size:12px">Conf: ${esc(inc.confidence)}</span>
          </div>
        </div>
        ${inc.actorMasked ? `<p class="mut" style="margin:2px 0 4px;font-size:12.5px">Caller / Sender: <b>${esc(inc.actorMasked)}</b>${inc.sourceModules?.length ? ` · Modules: <b>${esc(inc.sourceModules.join(', '))}</b>` : ''}${inc.involvedEntityIds?.length ? ` · Entities: <span class="num">${inc.involvedEntityIds.length}</span>` : ''}</p>` : inc.sourceModules?.length ? `<p class="mut" style="margin:2px 0 4px;font-size:12.5px">Modules: <b>${esc(inc.sourceModules.join(', '))}</b> · Linked Entities: <span class="num">${inc.involvedEntityIds?.length || 0}</span></p>` : ''}
        <p style="margin:4px 0"><b>Reasoning:</b> ${esc(isGuardian && inc.aiExplanation.guardianSummary ? inc.aiExplanation.guardianSummary : inc.reasoningSummary)}</p>
        ${inc.evidence.length ? `<ul style="margin:4px 0 6px">${inc.evidence.slice(0, 4).map((e) => `<li class="mut" style="font-size:13px">${esc(e)}</li>`).join('')}</ul>` : ''}
        ${
          inc.redAlertTriggered
            ? `<div class="row" style="margin:4px 0 6px;gap:6px">${notifStatusBadge('Parent Notification', inc.parentNotifStatus)} ${notifStatusBadge('Child Notification', inc.childNotifStatus)}</div>`
            : ''
        }
        <p class="mut" style="margin:0 0 8px;font-size:12.5px"><b>Action:</b> ${esc(inc.recommendedAction)} · Source: ${esc(inc.detectionSource)} · ${new Date(inc.createdAt).toLocaleString()}</p>
        <div class="row">
          ${inc.acknowledgementStatus === 'unacknowledged' ? `<button type="button" class="s" style="min-height:30px;padding:3px 10px" onclick="gsiFeedback('${esc(inc.incidentId)}','acknowledge')">Acknowledge</button>` : ''}
          ${inc.workflowStatus !== 'Investigating' && inc.resolutionStatus === 'open' ? `<button type="button" class="s" style="min-height:30px;padding:3px 10px" onclick="gcihUpdateIncidentWorkflow('${esc(inc.incidentId)}','Investigating')">Investigate</button>` : ''}
          ${!fbDisabled ? `<button type="button" class="r" style="min-height:30px;padding:3px 10px" onclick="gsiFeedback('${esc(inc.incidentId)}','confirm_threat')">Confirm Threat</button>` : ''}
          ${!fbDisabled ? `<button type="button" class="s" style="min-height:30px;padding:3px 10px" onclick="gsiFeedback('${esc(inc.incidentId)}','false_positive')">Mark False Positive</button>` : ''}
          ${!isGuardian && inc.resolutionStatus === 'open' ? `<button type="button" class="t" style="min-height:30px;padding:3px 10px" onclick="gsiFeedback('${esc(inc.incidentId)}','resolve')">Resolve</button>` : ''}
          ${inc.resolutionStatus !== 'open' ? `<button type="button" class="s" style="min-height:30px;padding:3px 10px" onclick="gcihUpdateIncidentWorkflow('${esc(inc.incidentId)}','Reopened')">Reopen</button>` : ''}
        </div>
        ${
          inc.timeline && inc.timeline.length
            ? `<details style="margin-top:8px"><summary class="mut" style="cursor:pointer;font-size:12.5px">Incident Audit Timeline (${inc.timeline.length})</summary><ul style="margin:6px 0 0">${inc.timeline
                .slice(0, 8)
                .map(
                  (tl) =>
                    `<li class="mut" style="font-size:12px"><span class="num">${new Date(tl.at).toLocaleString()}</span> · <b>${esc(tl.status)}</b> — ${esc(tl.summary)}</li>`
                )
                .join('')}</ul></details>`
            : ''
        }
      </div>`;
    })
    .join('');
}

function renderGsiReportsSection(): string {
  const gsi = S.gsi;
  if (!gsi) return '';
  const activePeriod = S.gsiReportPeriod;
  const rep = gsi.latestReports[activePeriod] || gsi.latestReports.weekly || gsi.latestReports.daily;
  return `<div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <div>
          <h2 class="t-section" style="margin:0">Automated Guardian Security Reports</h2>
          <p class="mut" style="margin:2px 0 0">Rule version ${esc(gsi.ruleVersion)} · Events (24h): <b class="num">${gsi.metrics.events24h}</b> · Confirmed threats: <b class="num">${gsi.metrics.confirmedThreatCount}</b> · False positives: <b class="num">${gsi.metrics.falsePositiveCount}</b></p>
        </div>
        <div class="seg-group" role="group" aria-label="Report period">
          ${(['daily', 'weekly', 'monthly'] as const)
            .map(
              (p) =>
                `<button type="button" class="seg-btn ${activePeriod === p ? 'on' : ''}" onclick="S.gsiReportPeriod='${p}';R()">${p[0].toUpperCase() + p.slice(1)}</button>`
            )
            .join('')}
        </div>
      </div>
      ${
        rep
          ? `<div class="warn" style="margin-bottom:10px">
              <b>${esc(rep.summaryText)}</b>
              <p class="mut" style="margin:4px 0 0">Trend vs previous window: <b class="num">${rep.trendDelta >= 0 ? '+' + rep.trendDelta : rep.trendDelta}</b> incident(s) · Resolved: <b class="num">${rep.incidentCounts.resolved}</b> · False positives: <b class="num">${rep.incidentCounts.falsePositives}</b></p>
              <ul style="margin:6px 0 0">${rep.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
            </div>`
          : ''
      }
      <h3 class="t-card" style="margin:12px 0 8px">Unified GSI Incidents &amp; Feedback</h3>
      ${renderGsiIncidentsList(gsi.recentIncidents, false)}
    </div>
    <div class="g-2">
      ${renderGsiCapabilityCard(gsi.capabilities)}
      ${uiCard(
        'Local Threat Intelligence Registry',
        gsi.threatIntel.length
          ? gsi.threatIntel
              .slice(0, 8)
              .map(
                (it) =>
                  `<div class="qr-history-row">
                    <div>
                      <b>${esc(it.indicatorDisplay)}</b> <span class="mut">(${esc(it.indicatorType.replace(/_/g, ' '))})</span>
                      <div class="mut" style="font-size:12px">${esc(it.evidenceSummary)} · Reports: ${it.reportCount} · FP: ${it.falsePositiveCount}</div>
                    </div>
                    ${uiBadge(it.reputationLabel, it.reputationLabel === 'Verified Spam' || it.reputationLabel === 'High Risk' ? 'HIGH' : it.reputationLabel === 'Suspicious' ? 'MEDIUM' : 'LOW')}
                  </div>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No local threat indicators learned yet. Confirming threats or marking false positives recalibrates local indicators.</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}
    </div>
    ${renderGcihHubSyncPanel(S.gcih, false)}
    ${renderGcihEntitiesAndGraphPanel(S.gcih, false)}`;
}

function computeParentPosture(): {
  score: number;
  shieldStatus: ShieldVisualInput['status'];
  label: string;
  openRedCount: number;
  activeGuardiansCount: number;
} {
  const activeGuardiansCount = S.links.filter((l) => l.status === 'active').length;
  const openRedCount = (S.gsi?.recentIncidents || []).filter(
    (i) => i.resolutionStatus === 'open' && i.acknowledgementStatus === 'unacknowledged' && i.redAlertTriggered
  ).length;
  const lvl = S.alert ? S.alert.r.level : S.res ? S.res.r.level : S.pay ? S.pay.level : 'LOW';

  let score = 0;
  if (!S.c.paused) score += 25;
  if (S.c.text && !S.c.paused) score += 20;
  if (S.c.calls && !S.c.paused) score += 15;
  if (S.hasSafeWord) score += 15;
  if (activeGuardiansCount > 0) score += 15;
  if (openRedCount === 0 && lvl === 'LOW') score += 10;

  if (openRedCount > 0 || lvl === 'HIGH' || lvl === 'CRITICAL') {
    return { score, shieldStatus: 'alert', label: 'Active Threat Detected', openRedCount, activeGuardiansCount };
  }
  if (!S.online) {
    return { score, shieldStatus: 'offline', label: 'Offline Local Mode', openRedCount, activeGuardiansCount };
  }
  if (S.c.paused) {
    return { score, shieldStatus: 'paused', label: 'Monitoring Paused', openRedCount, activeGuardiansCount };
  }
  if (lvl === 'MEDIUM' || !S.hasSafeWord || activeGuardiansCount === 0) {
    return { score, shieldStatus: 'caution', label: 'Setup Recommended', openRedCount, activeGuardiansCount };
  }
  return { score, shieldStatus: 'active', label: 'Protected', openRedCount, activeGuardiansCount };
}

function buildSmartRecommendations(posture: ReturnType<typeof computeParentPosture>): {
  title: string;
  detail: string;
  actionLabel: string;
  onclick: string;
  tone: 'HIGH' | 'MEDIUM' | 'LOW';
}[] {
  const recs: {
    title: string;
    detail: string;
    actionLabel: string;
    onclick: string;
    tone: 'HIGH' | 'MEDIUM' | 'LOW';
  }[] = [];

  if (posture.openRedCount > 0) {
    recs.push({
      title: 'Review Active Smart Red Alert',
      detail: `${posture.openRedCount} unacknowledged high-risk incident(s) need attention before making any transfer.`,
      actionLabel: 'Open Safety Alerts',
      onclick: "switchTab('alerts')",
      tone: 'HIGH',
    });
  }
  if (S.c.paused) {
    recs.push({
      title: 'Monitoring Is Currently Paused',
      detail: 'Message analysis and Call Watch timing alerts are turned off by your consent setting.',
      actionLabel: 'Review Settings',
      onclick: "switchTab('priv')",
      tone: 'HIGH',
    });
  }
  if (!S.hasSafeWord) {
    recs.push({
      title: 'Set a Private Family Safe Word',
      detail: 'Helps verify real relatives over the phone when someone asks for urgent money.',
      actionLabel: 'Configure Safe Word',
      onclick: "switchTab('fam')",
      tone: 'MEDIUM',
    });
  }
  if (posture.activeGuardiansCount === 0) {
    recs.push({
      title: 'Link a Trusted Family Guardian',
      detail: 'Add a primary guardian so high-risk payment checks receive single-use human verification.',
      actionLabel: 'Invite Guardian',
      onclick: "switchTab('fam')",
      tone: 'MEDIUM',
    });
  }
  const activeDevices = (S.gcih?.devices || []).filter((d) => d.status === 'active');
  if (activeDevices.length === 0) {
    recs.push({
      title: 'Register This Device in Central Hub',
      detail: 'Registers your browser endpoint transparently for cross-module intelligence sync.',
      actionLabel: 'Register Device',
      onclick: 'gcihRegisterCurrentDevice()',
      tone: 'LOW',
    });
  }
  if (recs.length === 0) {
    recs.push({
      title: 'Web Protection Controls Active',
      detail: 'Consent is active, safe word is set, and guardian review is connected with zero open red alerts.',
      actionLabel: 'Run QR or Message Check',
      onclick: "switchTab('qr')",
      tone: 'LOW',
    });
  }
  return recs;
}

interface TimelineEntry {
  id: string;
  cat: 'call' | 'sms' | 'qr' | 'pay';
  catLabel: string;
  tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL';
  title: string;
  summary: string;
  detail: string;
  at: number;
  jumpTab: string;
}

function collectSecurityTimeline(isGuardian: boolean, selectedOwnerId: string): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  const ownerObj = selectedOwnerId !== 'all' ? S.linkedParents.find((p) => p.id === selectedOwnerId) : null;
  const matchOwnerName = (name?: string | null) => {
    if (!isGuardian || selectedOwnerId === 'all' || !ownerObj) return true;
    return !name || name === ownerObj.name;
  };

  // Call Watcher events
  const cwList = isGuardian ? S.linkedCallWatcherEvents : S.callWatcher?.timeline || [];
  for (const ev of cwList.slice(0, 12)) {
    if (!matchOwnerName(ev.parentName)) continue;
    const tone: TimelineEntry['tone'] = ev.criticalWarningActive
      ? 'CRITICAL'
      : ev.callRisk.riskLevel === 'High Risk' || ev.paymentRisk.riskLevel === 'High Risk'
        ? 'HIGH'
        : ev.callRisk.riskLevel === 'Moderate Risk' || ev.paymentRisk.riskLevel === 'Moderate Risk'
          ? 'MEDIUM'
          : 'LOW';
    entries.push({
      id: `cw-${ev.correlationId}`,
      cat: 'call',
      catLabel: 'Call Watch',
      tone,
      title: `${ev.call ? ev.call.callerClassification : 'Call Timing'} · ${ev.payment ? ev.payment.paymentStatus : 'Session Logged'}`,
      summary: `${ev.parentName ? ev.parentName + ' · ' : ''}${ev.duringCall ? 'During active call' : ev.timeDiffMs !== null ? 'Gap ' + fmtD(ev.timeDiffMs) : 'Metadata logged'}`,
      detail: `${ev.callRisk.recommendedAction} ${ev.payment?.redactedSummary ? '· ' + ev.payment.redactedSummary : ''}`,
      at: ev.createdAt,
      jumpTab: isGuardian ? 'act' : 'call',
    });
  }

  // GSI SMS/Link/Combined incidents
  const gsiInc = isGuardian ? S.linkedGsiOverview?.incidents || [] : S.gsi?.recentIncidents || [];
  for (const inc of gsiInc.slice(0, 15)) {
    if (isGuardian && selectedOwnerId !== 'all' && inc.familyOwnerId && inc.familyOwnerId !== selectedOwnerId) continue;
    const isQrCat = inc.incidentCategory.includes('qr');
    const isCallCat = inc.incidentCategory.includes('call');
    const cat: TimelineEntry['cat'] = isQrCat ? 'qr' : isCallCat ? 'call' : 'sms';
    entries.push({
      id: `gsi-${inc.incidentId}`,
      cat,
      catLabel: cat === 'qr' ? 'QR' : cat === 'call' ? 'Calls' : 'SMS & Links',
      tone:
        inc.alertLevel === 'CRITICAL_RED'
          ? 'CRITICAL'
          : inc.alertLevel === 'RED'
            ? 'HIGH'
            : inc.alertLevel === 'YELLOW'
              ? 'MEDIUM'
              : 'LOW',
      title: `${formatThreatHeadline(inc)}${inc.parentName ? ' — ' + inc.parentName : ''}`,
      summary: `Score ${inc.riskScore}/100 · ${inc.acknowledgementStatus} · ${inc.resolutionStatus.replace(/_/g, ' ')}`,
      detail: `${inc.reasoningSummary} · Recommended: ${inc.recommendedAction}`,
      at: inc.createdAt,
      jumpTab: isGuardian ? 'act' : 'alerts',
    });
  }

  // QR Scan Summaries
  for (const q of S.qrScans.slice(0, 12)) {
    if (!matchOwnerName(q.parent_name)) continue;
    const atMs = new Date(q.created_at).getTime() || Date.now();
    entries.push({
      id: `qr-${q.id}`,
      cat: 'qr',
      catLabel: 'QR',
      tone:
        q.security_risk_level === 'CRITICAL'
          ? 'CRITICAL'
          : q.security_risk_level === 'HIGH'
            ? 'HIGH'
            : q.security_risk_level === 'MEDIUM'
              ? 'MEDIUM'
              : 'LOW',
      title: `QR Inspection: ${q.payee_name || q.upi_id || q.qr_classification}`,
      summary: `${q.amount !== null ? inr(q.amount) : 'Amount unspecified'} · ${q.payment_load_category} · ${q.security_risk_level} risk`,
      detail: `Format: ${q.qr_format} · UPI: ${q.upi_id || 'N/A'} · Classification: ${q.qr_classification}`,
      at: atMs,
      jumpTab: isGuardian ? 'act' : 'qr',
    });
  }

  // Payment Requests
  for (const r of S.reqs.slice(0, 12)) {
    if (isGuardian && selectedOwnerId !== 'all' && r.parentId && r.parentId !== selectedOwnerId) continue;
    const atMs = r.exp ? r.exp - 15 * 60 * 1000 : Date.now();
    entries.push({
      id: `pay-${r.id}`,
      cat: 'pay',
      catLabel: 'Payments',
      tone: r.st === 'rejected' || r.level === 'HIGH' ? 'HIGH' : r.st === 'approved' ? 'LOW' : 'MEDIUM',
      title: `Payment Review: ${inr(r.amt)} to ${r.ben}`,
      summary: `Status: ${r.st}${r.parentName ? ' · ' + r.parentName : ''}`,
      detail: r.sig.join(' · ') || 'Guardian single-use review request',
      at: atMs,
      jumpTab: isGuardian ? 'req' : 'pay',
    });
  }

  entries.sort((a, b) => b.at - a.at);
  return entries;
}

function renderSecurityTimeline(isGuardian: boolean, selectedOwnerId = 'all'): string {
  const all = collectSecurityTimeline(isGuardian, selectedOwnerId);
  const filters: { id: typeof S.timelineFilter; label: string }[] = [
    { id: 'all', label: `All (${all.length})` },
    { id: 'call', label: 'Calls' },
    { id: 'sms', label: 'SMS & Links' },
    { id: 'qr', label: 'QR' },
    { id: 'pay', label: 'Payments' },
  ];
  const visible = S.timelineFilter === 'all' ? all : all.filter((e) => e.cat === S.timelineFilter);

  const filterBar = `<div class="seg-group" role="group" aria-label="Filter security activity timeline">
    ${filters
      .map(
        (f) =>
          `<button type="button" class="seg-btn ${S.timelineFilter === f.id ? 'on' : ''}" onclick="setTimelineFilter('${f.id}')">${esc(f.label)}</button>`
      )
      .join('')}
  </div>`;

  const body = visible.length
    ? `<div class="v-timeline">
        ${visible
          .slice(0, 8)
          .map((item) => {
            const expanded = Boolean(S.expandedTimelineIds[item.id]);
            return `<div class="v-timeline-item">
              <span class="v-timeline-marker tone-${item.tone}" aria-hidden="true"></span>
              <div class="row" style="justify-content:space-between;gap:8px">
                <div style="min-width:0;flex:1">
                  <div class="meta-line" style="margin-bottom:2px">
                    <b>${esc(item.catLabel)}</b>
                    <span aria-hidden="true">·</span>
                    <span class="num">${new Date(item.at).toLocaleString()}</span>
                  </div>
                  <b style="display:block;font-size:14.5px">${esc(item.title)}</b>
                  <span class="mut" style="font-size:13px">${esc(item.summary)}</span>
                </div>
                <div class="row" style="gap:6px">
                  ${uiBadge(item.tone, item.tone)}
                  <button type="button" class="s" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="toggleTimelineExpand('${esc(item.id)}')" aria-expanded="${expanded}">${expanded ? 'Hide details' : 'Details'}</button>
                </div>
              </div>
              ${
                expanded
                  ? `<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--line);font-size:13px">
                      <p style="margin:0 0 8px">${esc(item.detail)}</p>
                      <button type="button" class="s" style="min-height:30px;padding:2px 10px;font-size:12px" onclick="switchTab('${item.jumpTab}')">Open in ${esc(item.catLabel)} workspace ${uiIcon('arrow-right', 13)}</button>
                    </div>`
                  : ''
              }
            </div>`;
          })
          .join('')}
      </div>`
    : uiStateBox(
        'empty',
        all.length ? 'No events in this category' : 'No security activity recorded yet',
        all.length
          ? 'Switch categories above to view other recorded events.'
          : 'Analyze an SMS, inspect a QR code, log a Call Watch session, or submit a payment review to build your activity timeline.'
      );

  return `<section class="card card-anim">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <div>
        <h2 class="t-section" style="margin:0">${uiIcon('activity', 18)} Security Activity Timeline</h2>
        <p class="mut" style="margin:2px 0 0">Live chronological log of calls, messages, QR inspections, and guardian payment reviews</p>
      </div>
      ${filterBar}
    </div>
    ${body}
  </section>`;
}

function buildGlobePayload(isGuardian: boolean, selectedOwnerId: string): GlobeVisualInput {
  if (!isGuardian) {
    const devices = (S.gcih?.devices || []).map((d) => ({
      id: d.id,
      label: d.deviceLabel,
      role: d.role,
      active: d.status === 'active',
    }));
    const openThreatCount = (S.gsi?.recentIncidents || []).filter(
      (i) => i.resolutionStatus === 'open' && i.redAlertTriggered
    ).length;
    return {
      devices,
      linkedCount: S.links.filter((l) => l.status === 'active').length,
      openThreatCount,
      caption: 'Family Protection Network',
    };
  }
  const payloads =
    selectedOwnerId === 'all'
      ? S.linkedGcihSync
      : S.linkedGcihSync.filter((f) => f.familyOwnerId === selectedOwnerId);
  const devices = payloads.flatMap((f) =>
    f.devices.map((d) => ({
      id: d.id,
      label: `${f.familyOwnerName}: ${d.deviceLabel}`,
      role: d.role,
      active: d.status === 'active',
    }))
  );
  const openThreatCount = (S.linkedGsiOverview?.incidents || []).filter(
    (i) =>
      (selectedOwnerId === 'all' || i.familyOwnerId === selectedOwnerId) &&
      i.resolutionStatus === 'open' &&
      i.redAlertTriggered
  ).length;
  return {
    devices,
    linkedCount: selectedOwnerId === 'all' ? S.linkedParents.length : 1,
    openThreatCount,
    caption: 'Linked Family Network',
  };
}

function parent(): string {
  const T2 = S.tab === 'learn' ? 'reports' : S.tab;
  const pend = S.reqs.filter((q) => (q.st === 'pending' || q.st === 'verification_requested') && Date.now() < q.exp).length;
  const activeGuardians = S.links.filter((l) => l.status === 'active');
  const unreadNotifs = S.notifications.filter((n) => !n.read_at).length;
  const lvl = S.alert ? S.alert.r.level : S.res ? S.res.r.level : S.pay ? S.pay.level : 'LOW';
  const alertCount = unreadNotifs + (S.alert && S.alert.r.level !== 'LOW' ? 1 : 0);

  let b = '';

  if (T2 === 'home') {
    const reqTotal = S.reqs.length;
    const reqApproved = S.reqs.filter((q) => q.st === 'approved' || q.st === 'consumed').length;
    const reqClosed = S.reqs.filter((q) => q.st === 'rejected' || q.st === 'cancelled' || q.st === 'expired').length;
    const posture = computeParentPosture();
    const recs = buildSmartRecommendations(posture);
    const activeDevices = (S.gcih?.devices || []).filter((d) => d.status === 'active');

    b = `<section class="cyber-overview-card card-anim">
        <div class="cyber-overview-grid">
          <div>
            <div class="row" style="justify-content:space-between;margin-bottom:8px">
              <span class="mut" style="font-size:13px;font-weight:600">Guardian Protection Command</span>
              ${uiBadge(lvl === 'LOW' ? t('safe') : lvl === 'MEDIUM' ? 'Verification recommended' : 'Pause and contact your guardian', lvl)}
            </div>
            <h1 class="t-page" style="margin:0;color:#FFFFFF">${esc(t('hi'))}, ${esc(S.user?.name || '')}</h1>
            <div class="cyber-score-readout">
              <span class="cyber-score-num" data-countup="${posture.score}">${posture.score}</span>
              <span class="mut" style="font-size:14px">/ 100 Posture · <b>${esc(posture.label)}</b></span>
            </div>
            <div class="meta-line" style="color:#C7DBF7;margin-bottom:14px">
              <span>Consent: <b>${S.c.paused ? 'Paused' : 'Active'}</b></span>
              <span aria-hidden="true">·</span>
              <span>Safe word: <b>${S.hasSafeWord ? 'Configured' : 'Not set'}</b></span>
              <span aria-hidden="true">·</span>
              <span>Linked guardians: <b class="num">${activeGuardians.length}</b></span>
            </div>
            <div class="row">
              ${uiButton('Check a message', "S.tab='scam';R()", { icon: 'search' })}
              ${uiButton('Assess payment', "S.tab='pay';R()", { variant: 'teal', icon: 'card' })}
              ${uiButton('Emergency Pay Lock', "switchTab('epp')", { variant: 'secondary', icon: 'lock' })}
              ${uiButton('Scan QR', "S.tab='qr';R()", { variant: 'secondary', icon: 'qr' })}
              ${!S.cur ? uiButton('Simulate incoming call', "S.tab='call';callStart('unknown')", { variant: 'secondary', icon: 'phone' }) : ''}
              ${uiButton('Emergency help', "emergencyHelpAction()", { variant: 'destructive', icon: 'shield', disabled: S.busy.emergency })}
            </div>
          </div>
          <div id="guardian-3d-shield" class="stage-3d-shell" aria-label="Interactive 3D Protection Shield"></div>
        </div>
      </section>
      ${renderEmergencyStatusBanner()}

      <div class="swipe-wrap">
        <div class="row" style="justify-content:space-between;margin-bottom:4px">
          <span class="t-label" style="margin:0;color:var(--mut)">Live Security Metrics</span>
          <div class="row" style="gap:6px">
            <button type="button" class="s" style="min-height:30px;padding:2px 8px" onclick="scrollSwipeStrip('parent-kpi-strip',-1)" aria-label="Scroll metrics left">${uiIcon('chevron-left', 14)}</button>
            <button type="button" class="s" style="min-height:30px;padding:2px 8px" onclick="scrollSwipeStrip('parent-kpi-strip',1)" aria-label="Scroll metrics right">${uiIcon('chevron-right', 14)}</button>
          </div>
        </div>
        <div id="parent-kpi-strip" class="swipe-strip kpi-4">
          ${uiStatCard('Open Payment Requests', pend, pend > 0 ? 'Awaiting guardian review or confirmation' : 'No open requests', { source: 'actual', icon: 'card', swipeCard: true })}
          ${uiStatCard('Call Watch Sessions', S.calls.length, S.cur ? 'Active call timing in progress' : 'Duration metadata only, zero audio', { source: 'simulated', icon: 'phone', swipeCard: true })}
          ${uiStatCard('Safety Alerts & Unread', alertCount, `${S.pats} timing patterns flagged in session`, { source: 'actual', icon: 'bell', swipeCard: true })}
          ${uiStatCard('Logged Incidents', S.inc.length, `${S.reports.length} masked scam reports saved`, { source: 'actual', icon: 'shield', swipeCard: true })}
        </div>
      </div>

      ${renderDashboardRecentlyUsed()}
      ${renderDashboardFinanceSnapshot()}

      <div class="swipe-wrap">
        <div class="row" style="justify-content:space-between;margin-bottom:4px">
          <span class="t-label" style="margin:0;color:var(--mut)">Quick Protection Tools</span>
          <div class="row" style="gap:6px">
            <button type="button" class="s" style="min-height:30px;padding:2px 8px" onclick="scrollSwipeStrip('parent-tools-strip',-1)" aria-label="Scroll tools left">${uiIcon('chevron-left', 14)}</button>
            <button type="button" class="s" style="min-height:30px;padding:2px 8px" onclick="scrollSwipeStrip('parent-tools-strip',1)" aria-label="Scroll tools right">${uiIcon('chevron-right', 14)}</button>
          </div>
        </div>
        <div id="parent-tools-strip" class="swipe-strip">
          <div class="swipe-card tilt-card card-anim">
            <div>
              <div class="row" style="justify-content:space-between;margin-bottom:6px"><b>QR Intelligence</b>${uiIcon('qr', 18)}</div>
              <p class="mut" style="margin:0;font-size:13px">Inspect UPI &amp; merchant QR codes, load risk, and duplicate patterns before paying.</p>
            </div>
            <button type="button" class="t" style="min-height:36px;padding:6px 12px" onclick="switchTab('qr')">Open QR Check ${uiIcon('arrow-right', 14)}</button>
          </div>
          <div class="swipe-card tilt-card card-anim">
            <div>
              <div class="row" style="justify-content:space-between;margin-bottom:6px"><b>AI Call Watcher</b>${uiIcon('phone', 18)}</div>
              <p class="mut" style="margin:0;font-size:13px">Track call duration &amp; pre-screen unknown callers safely with zero audio capture.</p>
            </div>
            <button type="button" class="s" style="min-height:36px;padding:6px 12px" onclick="switchTab('call')">Open Call Watch ${uiIcon('arrow-right', 14)}</button>
          </div>
          <div class="swipe-card tilt-card card-anim">
            <div>
              <div class="row" style="justify-content:space-between;margin-bottom:6px"><b>Scam &amp; Link Check</b>${uiIcon('search', 18)}</div>
              <p class="mut" style="margin:0;font-size:13px">Analyze suspicious SMS, WhatsApp text, screenshots, or lookalike URLs locally.</p>
            </div>
            <button type="button" class="s" style="min-height:36px;padding:6px 12px" onclick="switchTab('scam')">Check Message ${uiIcon('arrow-right', 14)}</button>
          </div>
          <div class="swipe-card tilt-card card-anim">
            <div>
              <div class="row" style="justify-content:space-between;margin-bottom:6px"><b>AI Safety Assistant</b>${uiIcon('spark', 18)}</div>
              <p class="mut" style="margin:0;font-size:13px">Ask plain-language questions about bank KYC messages, calls, or payment safety.</p>
            </div>
            <button type="button" class="s" style="min-height:36px;padding:6px 12px" onclick="switchTab('ai')">Ask Guardian AI ${uiIcon('arrow-right', 14)}</button>
          </div>
        </div>
      </div>

      <div class="g-2">
        <section class="card card-anim">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2 class="t-section" style="margin:0">${uiIcon('globe', 18)} Family Network &amp; Device Posture</h2>
              <p class="mut" style="margin:2px 0 0">Reflects registered Hub devices, linked guardians, and open red alerts</p>
            </div>
            ${uiSourceBadge('actual')}
          </div>
          <div id="guardian-3d-globe" class="stage-3d-shell stage-3d-globe"></div>
          <div class="meta-line" style="margin-top:10px">
            <span>Registered endpoints: <b class="num">${activeDevices.length}</b></span>
            <span aria-hidden="true">·</span>
            <span>Linked guardians: <b class="num">${activeGuardians.length}</b></span>
            <span aria-hidden="true">·</span>
            <span>Open red alerts: <b class="num">${posture.openRedCount}</b></span>
          </div>
        </section>

        <section class="card card-anim tilt-card">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2 class="t-section" style="margin:0">Smart Security Recommendations</h2>
              <p class="mut" style="margin:2px 0 0">Priority actions strictly derived from your real protection configuration</p>
            </div>
            ${uiBadge(recs[0]?.tone === 'HIGH' ? 'Action Needed' : recs[0]?.tone === 'MEDIUM' ? 'Recommended' : 'Good Posture', recs[0]?.tone || 'LOW')}
          </div>
          <div style="display:grid;gap:10px">
            ${recs
              .map(
                (rc) => `<div class="warn" style="margin:0">
                  <div class="row" style="justify-content:space-between;margin-bottom:4px">
                    <b>${esc(rc.title)}</b>
                    ${uiBadge(rc.tone, rc.tone)}
                  </div>
                  <p class="mut" style="margin:0 0 8px;font-size:13px">${esc(rc.detail)}</p>
                  <button type="button" class="s" style="min-height:34px;padding:4px 12px;font-size:12.5px" onclick="${rc.onclick}">${esc(rc.actionLabel)}</button>
                </div>`
              )
              .join('')}
          </div>
        </section>
      </div>

      ${renderSecurityTimeline(false)}

      <div class="g-2">
        ${notificationsPanel(4)}
        ${uiBarChart(
          'Payment Review Overview',
          [
            { label: 'Open / Verify', value: pend, max: Math.max(1, reqTotal), color: 'var(--amb)' },
            { label: 'Approved / Used', value: reqApproved, max: Math.max(1, reqTotal), color: 'var(--teal)' },
            { label: 'Rejected / Closed', value: reqClosed, max: Math.max(1, reqTotal), color: 'var(--red)' },
          ],
          {
            subtitle: 'Live SQLite payment review counts',
            source: 'actual',
            emptyMessage: 'No payment assessments sent for guardian review yet.',
          }
        )}
      </div>

      <div class="g">
        ${uiCard(
          'Location & Device Telemetry',
          `<p class="mut" style="margin:0 0 10px">Web session is <b>${S.online ? 'online' : 'offline'}</b>. Native GPS location, OS screen time, and app-usage logs are unavailable in a browser without a native companion app.</p>
          <button type="button" class="s" onclick="S.tab='device';R()">View device details</button>`,
          { badgeHtml: uiSourceBadge('unavailable'), tilt: true }
        )}
        ${uiCard(
          t('q1'),
          `<p class="mut" style="margin:0">${S.c.paused ? 'Monitoring is paused by your choice.' : 'Only the checks you consented to are active. Review anytime in Settings.'}</p>`,
          { badgeHtml: uiSourceBadge('actual'), tilt: true }
        )}
        ${uiCard(
          t('q3'),
          `<p class="mut" style="margin:0">${esc(t('a3'))}</p>`,
          { badgeHtml: uiBadge('Guidance', 'LOW'), tilt: true }
        )}
      </div>

      ${
        S.gsi
          ? `<div class="card card-anim">
              <div class="row" style="justify-content:space-between;margin-bottom:8px">
                <div>
                  <h2 class="t-section" style="margin:0">Guardian Security Intelligence (${esc(S.gsi.ruleVersion)})</h2>
                  <p class="mut" style="margin:2px 0 0">Events (24h): <b class="num">${S.gsi.metrics.events24h}</b> · Open High/Critical: <b class="num">${S.gsi.metrics.openHighCritical}</b> · Runtime: <b>${esc(S.gsi.capabilities.runtimeMode.replace(/_/g, ' '))}</b></p>
                </div>
                <div class="row">
                  ${uiBadge(S.gsi.capabilities.overallStatus, S.gsi.capabilities.overallStatus === 'healthy' ? 'LOW' : 'MEDIUM')}
                  <button type="button" class="s" onclick="switchTab('reports')">Open GSI Reports</button>
                </div>
              </div>
              <div class="row" style="gap:8px;flex-wrap:wrap">
                ${S.gsi.capabilities.items
                  .map((it) =>
                    uiBadge(
                      `${it.capability}: ${it.status.replace(/_/g, ' ')}`,
                      it.status === 'active' ? 'LOW' : it.status === 'unavailable_in_browser' ? 'NEUTRAL' : 'MEDIUM'
                    )
                  )
                  .join('')}
              </div>
            </div>`
          : ''
      }

      <div class="card card-anim">
        <div class="row" style="justify-content:space-between">
          <div>
            <b>Safety Tip <span class="num">${S.tip + 1}/3</span>:</b> ${esc(tips[S.tip])}
          </div>
          <div class="row">
            <button type="button" class="s" onclick="S.tip=(S.tip+2)%3;R()" aria-label="Previous tip">Previous</button>
            <button type="button" class="s" onclick="S.tip=(S.tip+1)%3;R()" aria-label="Next tip">Next</button>
          </div>
        </div>
      </div>`;
  }

  if (T2 === 'device') {
    b = `<div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h1 class="t-page" style="margin:0">Location &amp; Device Status</h1>
            <p class="mut" style="margin:4px 0 0">Clear separation of real browser/session telemetry, simulated Call Watch, and native OS capabilities.</p>
          </div>
          ${uiBadge(S.online ? 'Session Connected' : 'Offline', S.online ? 'LOW' : 'MEDIUM')}
        </div>
      </div>

      <div class="g-2">
        ${uiCard(
          'Browser & Protection Session',
          `<ul style="margin:0">
            <li>Connectivity: <b>${S.online ? 'Online (API & Gemini AI reachable)' : 'Offline (local rule scoring only)'}</b></li>
            <li>Message Analysis: <b>${S.c.text && !S.c.paused ? 'Enabled' : 'Paused / Off'}</b></li>
            <li>Call Watch Timing: <b>${S.c.calls && !S.c.paused ? 'Enabled (timing only)' : 'Off'}</b></li>
            <li>Guardian Alerts: <b>${S.c.galerts ? 'Enabled' : 'Off'}</b> · Single-use Approval: <b>${S.c.gapprove ? 'Enabled' : 'Off'}</b></li>
            <li>Data Retention Policy: <b class="num">${S.retentionDays} days</b></li>
          </ul>`,
          { badgeHtml: uiSourceBadge('actual') }
        )}

        ${uiCard(
          'Call Watch Timing Records',
          S.calls.length
            ? `<p class="mut" style="margin:0 0 8px">Latest recorded sessions (duration only, zero audio):</p>
               <ul style="margin:0">
                 ${S.calls
                   .slice(0, 5)
                   .map(
                     (c) =>
                       `<li><span class="num">${fmtD(c.dur)}</span> · ${c.known ? 'Saved contact' : 'Unknown number'} · ended <span class="num">${new Date(c.e).toLocaleTimeString()}</span></li>`
                   )
                   .join('')}
               </ul>`
            : `<p class="mut" style="margin:0">No simulated calls recorded yet. Use Call Watch to test incoming call duration tracking.</p>`,
          { badgeHtml: uiSourceBadge('simulated'), footerHtml: `<button type="button" class="s" onclick="S.tab='call';R()">Open Call Watch</button>` }
        )}
      </div>

      <div class="g">
        ${uiCard(
          'Live GPS Location',
          `<p class="mut" style="margin:0">Continuous background GPS coordinates and geofencing are unavailable in a standard web browser. No map coordinates or location history are fabricated.</p>`,
          { badgeHtml: uiSourceBadge('unavailable') }
        )}
        ${uiCard(
          'Screen Time Statistics',
          `<p class="mut" style="margin:0">System-wide daily screen time requires Android UsageStats or iOS Screen Time APIs via a native companion app and is unavailable here.</p>`,
          { badgeHtml: uiSourceBadge('unavailable') }
        )}
        ${uiCard(
          'App & Website Monitoring',
          `<p class="mut" style="margin:0">Inspecting activity inside other mobile banking or messaging apps requires OS-level permissions unavailable to a browser tab.</p>`,
          { badgeHtml: uiSourceBadge('unavailable') }
        )}
      </div>
      ${renderGcihHubSyncPanel(S.gcih, false)}
      ${renderGcihDevicesAndPermissionsPanel(S.gcih, false)}`;
  }

  if (T2 === 'scam') {
    b = `<div class="card">
        <div class="row" style="justify-content:space-between">
          <h1 class="t-page" style="margin:0">${esc(t('scam'))}</h1>
          ${uiSourceBadge('actual')}
        </div>
        <label for="scam-img" style="margin-top:12px">Upload suspicious screenshot (optional OCR)</label>
        <input id="scam-img" type="file" accept="image/png,image/jpeg,image/webp" onchange="ocrFile(event)" ${S.busy.ocr ? 'disabled' : ''}>
        ${S.ocrNote ? `<p class="mut" role="status">${esc(S.ocrNote)}</p>` : ''}
        <label for="st">Paste or edit extracted SMS, WhatsApp message, email or call transcript</label>
        <textarea id="st" rows="5" placeholder="Paste text here">${esc(S.ocrDraft)}</textarea>
        <div class="row">
          <button type="button" onclick="analyze()" ${S.busy.analyze ? 'disabled' : ''}>${S.busy.analyze ? 'Analyzing…' : 'Analyze'}</button>
          <button type="button" class="s" onclick="mic('st')">Speak</button>
          <button type="button" class="s" onclick="demo('kyc')">Demo: KYC</button>
          <button type="button" class="s" onclick="demo('fam')">Demo: family</button>
          <button type="button" class="s" onclick="demo('ok')">Demo: bill</button>
        </div>
        <p class="mut" style="margin:10px 0 0">Text is treated as untrusted evidence only. Numbers and IDs are masked before AI analysis.</p>
        <hr class="divider">
        <label for="gsi-link-url">Inspect a suspicious URL or shortened link safely (never auto-opened)</label>
        <div class="row">
          <input id="gsi-link-url" placeholder="e.g. https://bit.ly/sbi-kyc-update or https://sbi-kyc.xyz" style="flex:1;margin:0">
          <button type="button" class="s" onclick="inspectManualLink()" ${S.busy.analyze ? 'disabled' : ''}>Inspect Link</button>
        </div>
      </div>
      ${note()}
      ${S.linkAnalysis ? renderLinkAnalysisCard(S.linkAnalysis) : ''}
      ${
        S.res
          ? card(
              S.res.r,
              `${aiBox(S.res.ai)}<div class="row" style="margin-top:10px"><button type="button" class="s" onclick="reportScam()">Report suspicious message (masked)</button></div>`
            )
          : ''
      }
      ${S.res && S.res.r.cat === 'family_emergency' ? uiAlert('Ask for the family safe word, then call the real person on their saved number. Voice cloning cannot be ruled out by text analysis.', { tone: 'warn' }) : ''}
      ${renderSectionSharedIntelCard(
        'sms_scam',
        'SMS & Scam Check',
        [
          ...(S.linkAnalysis?.sharedIntelligence || []),
          ...(S.gcih?.sectionFeeds?.link_scam || []),
        ],
        S.res && S.linkAnalysis
          ? `Direct SMS rule score ${S.res.r.score}/100 paired with Link Intelligence score ${S.linkAnalysis.riskScore}/100.`
          : undefined
      )}
      ${
        S.reports.length
          ? uiCard(
              'Your submitted reports (masked)',
              S.reports
                .slice(0, 5)
                .map((rp) => `<p class="mut" style="margin:6px 0">${uiBadge(rp.status, 'NEUTRAL')} <b>${esc(rp.cat)}</b> · ${esc(rp.masked_excerpt)}</p>`)
                .join(''),
              { badgeHtml: uiSourceBadge('actual') }
            )
          : ''
      }`;
  }

  if (T2 === 'pay') {
    const p = S.pay;
    const q = (p && p.id && rq(p.id)) || S.reqs.find((x) => ['pending', 'verification_requested', 'approved'].includes(x.st) && x.exp > Date.now());
    const hasSecondary = activeGuardians.some((l) => Boolean(l.is_secondary));
    b = `<div class="card">
        <div class="row" style="justify-content:space-between">
          <h1 class="t-page" style="margin:0">${esc(t('pay'))}</h1>
          ${uiSourceBadge('simulated')}
        </div>
        <div class="g" style="margin-top:12px">
          <div>
            <label for="am">Amount (₹)</label>
            <input id="am" type="number" min="1" step="0.01" placeholder="e.g. 5000">
            <label for="bn">Beneficiary / UPI ID</label>
            <input id="bn" placeholder="e.g. name@bank or Electricity Board">
            <label for="kn">Beneficiary (self-declared)</label>
            <select id="kn">
              <option value="new">New / unfamiliar</option>
              <option value="known">Known to me (not independently verified)</option>
            </select>
          </div>
          <div>
            <label>Context signals</label>
            ${[
              ['cl', 'After a suspicious call or message'],
              ['ug', 'Urgency was used'],
              ['sc', 'Asked to keep it secret'],
              ['nt', 'Unusual time (night)'],
            ]
              .map((a) => `<div class="sw"><input type="checkbox" id="${a[0]}"><span>${a[1]}</span></div>`)
              .join('')}
          </div>
        </div>
        <div class="row">
          <button type="button" onclick="assess()">Assess payment</button>
          <button type="button" class="epp-btn-sapphire" onclick="switchTab('epp')">${uiIcon('lock', 15)}Emergency Payment Lock &amp; Bank Blocking</button>
          <button type="button" class="s" onclick="payFill('bad')">Demo: ₹30,000 unknown</button>
          <button type="button" class="s" onclick="payFill('ok')">Demo: electricity bill</button>
        </div>
        <p class="mut" style="margin:10px 0 0">Never enter a PIN or OTP here. Guardian does not intercept real UPI payments.</p>
      </div>
      ${note()}`;

    if (p) {
      b += card(
        p,
        `<p><b class="num">${inr(p.amt)}</b> to ${esc(p.ben)}.</p>
        ${
          p.sharedIntelligence && p.sharedIntelligence.length
            ? uiAlert(
                `Matched ${p.sharedIntelligence.length} shared indicator(s) from ${Array.from(new Set(p.sharedIntelligence.flatMap((x) => x.sourceModules))).join(', ')}. Combined Hub score: ${p.gsiRiskScore ?? p.score}/100.`,
                {
                  title: 'Cross-Section Intelligence Match:',
                  tone: p.sharedIntelligence.some((x) => x.verificationStatus !== 'Verified legitimate' && ['Moderate', 'High', 'Critical'].includes(x.riskClassification))
                    ? 'danger'
                    : 'info',
                }
              )
            : ''
        }
        <p>${p.level === 'LOW' ? 'No strong risk rules triggered. Still verify details independently.' : 'This payment follows risky signals. Pause and verify.'}</p>
        <div class="row">
          ${p.level !== 'LOW' && !p.id ? '<button type="button" class="t" onclick="askG()">Ask guardian</button>' : ''}
          <a class="btn s" href="https://cybercrime.gov.in/" target="_blank" rel="noopener">Official reporting portal</a>
          <button type="button" class="r" onclick="cancelPay('${p.id || ''}')">Cancel</button>
        </div>`
      );
    }

    b += renderSectionSharedIntelCard(
      'payment_safety',
      'Payment Safety',
      p?.sharedIntelligence || [],
      p
        ? `Direct Payment Rule Score: ${p.score}/100 · Central Hub Combined Score: ${p.gsiRiskScore ?? p.score}/100`
        : undefined
    );

    if (q) {
      const expired = Date.now() > q.exp && q.st === 'pending';
      const displayStatus = expired ? 'expired' : q.st;
      b += `<div class="card">
        <div class="row" style="justify-content:space-between">
          <h3 class="t-card" style="margin:0">Guardian Request <code>${esc(q.id)}</code></h3>
          ${uiBadge(displayStatus, q.st === 'approved' ? 'LOW' : q.st === 'rejected' ? 'HIGH' : 'MEDIUM')}
        </div>
        <p style="margin:8px 0"><b class="num">${inr(q.amt)}</b> to ${esc(q.ben)} · expires <span class="num" data-exp="${q.exp}"></span></p>
        ${q.verificationNote ? `<p class="mut">Note: ${esc(q.verificationNote)}</p>` : ''}
        ${
          q.st === 'verification_requested'
            ? `<div class="alert-warn">
                <p style="margin:0 0 8px"><b>Guardian asked for more verification.</b> Call your bank or family member on a saved number, then add a brief note to resubmit.</p>
                <input id="rn${q.id}" placeholder="e.g. Called Rahul and verified bill account">
                <div class="row">
                  <button type="button" class="t" onclick="resubmitReq('${q.id}')">Re-submit for approval</button>
                  <button type="button" class="r" onclick="cancelPay('${q.id}')">Cancel request</button>
                </div>
              </div>`
            : ''
        }
        <div class="row" style="margin-top:8px">
          ${q.st === 'approved' && !expired ? `<button type="button" onclick="proceed('${q.id}')">Proceed (simulated, single-use)</button>` : ''}
          ${q.st === 'pending' && !expired && hasSecondary && !q.escalatedToSecondary ? `<button type="button" class="s" onclick="escalateReq('${q.id}')">Escalate to secondary guardian</button>` : ''}
          <button type="button" class="s" onclick="syncStateFromServer()">Refresh status</button>
          ${['pending', 'approved', 'verification_requested'].includes(q.st) ? `<button type="button" class="r" onclick="cancelPay('${q.id}')">Cancel</button>` : ''}
        </div>
      </div>`;
    }
  }

  if (T2 === 'qr') {
    b = renderQrIntelligenceTab();
  }

  if (T2 === 'call') {
    b = renderCallWatcherTab();
  }

  if (T2 === 'alerts') {
    const a = S.alert;
    const redCount = S.gsi?.activeRedAlerts?.length ?? (S.gsi?.recentIncidents || []).filter((i) => i.resolutionStatus === 'open' && i.redAlertTriggered).length;
    b = `<div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h1 class="t-page" style="margin:0">Safety Alerts</h1>
            <p class="mut" style="margin:4px 0 0">Centralized Smart Red Alerts, call-to-payment warnings, notification inbox, and security history.</p>
          </div>
          ${uiBadge(redCount > 0 ? `${redCount} Active Red Alert(s)` : alertCount > 0 ? `${alertCount} Unread` : 'All clear', redCount > 0 ? 'HIGH' : alertCount > 0 ? 'MEDIUM' : 'LOW')}
        </div>
      </div>
      ${
        a
          ? card(
              a.r,
              `<p>${esc(a.txt)}</p>
               <p class="mut">Call length: <b class="num">${fmtD(a.callDurMs)}</b> · Gap: <b class="num">${a.duringCall ? 'During active call' : fmtD(a.gapMs)}</b></p>
               ${aiBox(a.ai)}
               <button type="button" class="s" onclick="S.alert=null;R()">Dismiss alert</button>`
            )
          : ''
      }
      ${
        S.gsi
          ? uiCard(
              'Smart Red Alert Management & Security History',
              renderGsiIncidentsList(S.gsi.recentIncidents, false),
              { badgeHtml: uiSourceBadge('actual') }
            )
          : ''
      }
      ${renderGcihHubSyncPanel(S.gcih, false)}
      ${renderGcihEntitiesAndGraphPanel(S.gcih, false)}
      ${notificationsPanel(20)}
      ${uiCard(
        'Call-to-Payment Timing History',
        S.timingEvents.length
          ? S.timingEvents
              .slice(0, 8)
              .map(
                (ev) =>
                  `<p class="mut" style="margin:6px 0">${uiBadge(`Score ${ev.score}`, ev.score >= S.highThreshold ? 'HIGH' : ev.score >= S.medThreshold ? 'MEDIUM' : 'LOW')} Call <span class="num">${fmtD(ev.callDurMs)}</span> · ${ev.duringCall ? 'During call' : `Gap ${fmtD(ev.gapMs)}`} · ${ev.known ? 'Saved contact' : 'Unknown caller'}</p>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No call-to-payment correlation events recorded in this session yet.</p>',
        { badgeHtml: uiSourceBadge('simulated') }
      )}`;
  }

  if (T2 === 'ai') {
    b = `<div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h1 class="t-page" style="margin:0">AI Insights &amp; Assistant</h1>
            <p class="mut" style="margin:4px 0 0">Ask about suspicious messages, calls, or payment requests in simple language.</p>
          </div>
          ${uiSourceBadge(S.online ? 'actual' : 'unavailable')}
        </div>
        <div role="log" aria-live="polite" style="margin:14px 0">
          ${
            S.chat
              .map(
                (m, i) =>
                  `<div class="msg ${m.r}">${m.r === 'a' && m.x !== '…' ? (m.live ? '<span class="badge-live">LIVE AI</span> ' : '<span class="badge-fb">FALLBACK</span> ') : ''}${esc(m.x)}${m.r === 'a' && m.x !== '…' ? ` <button type="button" class="s" style="min-height:30px;padding:2px 10px" onclick="speak(${i})" aria-label="Read aloud">Listen</button>` : ''}</div>`
              )
              .join('') ||
            uiStateBox(
              'empty',
              'Ask Guardian AI',
              'Describe what happened—for example: "Someone said my bank account will be blocked unless I pay ₹2,000."'
            )
          }
        </div>
        <label for="cq">Your question or situation</label>
        <textarea id="cq" rows="2" placeholder="Describe what happened"></textarea>
        <div class="row">
          <button type="button" onclick="chat()" ${S.busy.chat ? 'disabled' : ''}>${S.busy.chat ? 'Sending…' : 'Send'}</button>
          <button type="button" class="s" onclick="mic('cq')">Speak</button>
        </div>
        <p class="mut" style="margin:10px 0 0">Live answers come from Gemini when available; otherwise transparent fallback rules. Never share OTP or PIN.</p>
      </div>
      ${note()}`;
  }

  if (T2 === 'reports') {
    b = `<div class="card">
        <h1 class="t-page" style="margin:0">Activity Reports &amp; Training</h1>
        <p class="mut" style="margin:4px 0 0">Charts reflect only recorded requests, Call Watch sessions, and benchmark runs.</p>
      </div>
      ${renderParentReportsContent()}`;
  }

  if (T2 === 'fam') {
    b = `<div class="card">
        <h1 class="t-page" style="margin:0">Family Management &amp; Recovery</h1>
        <p class="mut" style="margin:4px 0 0">Manage trusted guardian links, your private family safe word, and emergency recovery records.</p>
      </div>
      ${note()}
      ${renderEmergencyStatusBanner()}
      <div class="g-2">
        <div class="card">
          <h2 class="t-section">Linked Guardians</h2>
          <p class="mut">Invite a primary or secondary guardian so they can review one flagged transaction at a time.</p>
          <div class="row" style="margin-bottom:12px">
            <button type="button" onclick="createInvite(false)">Invite primary guardian</button>
            <button type="button" class="s" onclick="createInvite(true)">Invite secondary guardian</button>
          </div>
          ${
            S.links.length
              ? S.links
                  .map(
                    (l) =>
                      `<div class="warn"><div class="row" style="justify-content:space-between"><div><code>${esc(l.invite_code)}</code> · ${l.is_secondary ? 'Secondary' : 'Primary'} · ${uiBadge(l.status, l.status === 'active' ? 'LOW' : l.status === 'pending' ? 'MEDIUM' : 'NEUTRAL')}${l.guardian_name ? ` <b>${esc(l.guardian_name)}</b>` : ''}</div>${l.status !== 'revoked' ? `<button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="revokeLink('${l.id}')">Revoke</button>` : ''}</div></div>`
                  )
                  .join('')
              : uiStateBox('empty', 'No guardian links yet', 'Create an invite code above and share it privately with your trusted family member.')
          }
        </div>

        <div class="card">
          <h2 class="t-section">Family safe word</h2>
          <p class="mut">Status: <b>${S.hasSafeWord ? 'Set (salted server hash)' : 'Not set yet'}</b>. Use 6+ characters with letters. Rate-limited after 5 failed checks.</p>
          <input id="sw" type="password" placeholder="Safe word (6+ chars, include letters)">
          <div class="row" style="margin-bottom:12px">
            <button type="button" onclick="swSet()">Save / Replace</button>
            <button type="button" class="s" onclick="swCheck()">Verify caller</button>
          </div>
          <p style="margin:0"><b>If a "family member" asks for money:</b> 1) Do not transfer. 2) Ask the safe word. 3) Hang up if unsure. 4) Call them on their saved number. 5) Ask your guardian.</p>
        </div>
      </div>

      <div class="card">
        <h2 class="t-section">Emergency recovery &amp; incident log</h2>
        <p class="mut">Guardian cannot freeze accounts or reverse payments. Contact your bank directly and report cyber fraud immediately.</p>
        <ol>
          <li>Stop further activity.</li>
          <li>Call your bank on its official number (verify it yourself).</li>
          <li>Keep transaction IDs, screenshots, and messages.</li>
          <li>Report: call <b>1930</b> or visit <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener">cybercrime.gov.in</a>.</li>
          <li>Alert your guardian.</li>
        </ol>
        <div class="g">
          <div>
            <label for="ia">Incident amount / details</label>
            <input id="ia" placeholder="e.g. ₹2,000 fake KYC">
          </div>
          <div>
            <label for="ic">Channel</label>
            <select id="ic"><option value="UPI">UPI</option><option value="Card">Card</option><option value="NetBanking">NetBanking</option><option value="Call/SMS">Call/SMS</option></select>
          </div>
        </div>
        <button type="button" onclick="saveIncident()">Save incident</button>
        ${S.inc.length ? `<div style="margin-top:12px">${S.inc.map((i) => `<p class="mut" style="margin:4px 0"><span class="num">${esc(i.d)}</span> · ${esc(i.a)} · ${uiBadge(i.s, 'NEUTRAL')}</p>`).join('')}</div>` : ''}
      </div>
      ${renderGcihDevicesAndPermissionsPanel(S.gcih, false)}`;
  }

  if (T2 === 'priv') {
    b = `<div class="card">
        <h1 class="t-page" style="margin:0">Settings &amp; Privacy</h1>
        <p class="mut" style="margin:4px 0 0">Customize theme, readability, monitoring consent, risk thresholds, and data retention.</p>
      </div>
      ${note()}
      <div class="g-2">
        <div class="card">
          <h2 class="t-section">Appearance &amp; Accessibility</h2>
          ${uiThemeSwitcher()}
          <hr class="divider">
          <div class="row" style="justify-content:space-between">
            <div>
              <b style="display:block">Language &amp; Text Size</b>
              <span class="mut" style="font-size:13px">Applies immediately across all screens</span>
            </div>
            ${lang()}
          </div>
        </div>

        <div class="card">
          <h2 class="t-section">Monitoring Consent</h2>
          ${[
            ['text', 'Allow message analysis'],
            ['galerts', 'Guardian receives alerts'],
            ['gapprove', 'Guardian may review one high-risk payment at a time'],
            ['calls', 'Allow AI call-duration timing (no audio, no transcript)'],
            ['paused', 'Pause all monitoring'],
          ]
            .map(
              (a) =>
                `<div class="sw"><input type="checkbox" ${S.c[a[0] as keyof typeof S.c] ? 'checked' : ''} onchange="S.c['${a[0]}']=this.checked;saveConsents()" aria-label="${a[1]}"><span>${a[1]}</span></div>`
            )
            .join('')}
        </div>
      </div>

      <div class="card">
        <h2 class="t-section">Thresholds, Payment Load &amp; Data Governance</h2>
        <label>Payment safety limit: <span class="num">${inr(S.limit)}</span></label>
        <input type="range" min="1000" max="100000" step="1000" value="${S.limit}" onchange="S.limit=+this.value;saveConsents()">
        <div class="g">
          <div><label>Medium risk threshold (<span class="num">${S.medThreshold}</span>)</label><input type="range" min="10" max="45" step="5" value="${S.medThreshold}" onchange="S.medThreshold=+this.value;saveConsents()"></div>
          <div><label>High risk threshold (<span class="num">${S.highThreshold}</span>)</label><input type="range" min="35" max="85" step="5" value="${S.highThreshold}" onchange="S.highThreshold=+this.value;saveConsents()"></div>
        </div>
        <div class="g">
          <div><label>Low / Moderate load boundary: <span class="num">${inr(S.loadModerateMax)}</span></label><input type="range" min="500" max="10000" step="500" value="${S.loadModerateMax}" onchange="S.loadModerateMax=+this.value;saveConsents()"></div>
          <div><label>Moderate / High load boundary: <span class="num">${inr(S.loadHighMax)}</span></label><input type="range" min="2000" max="50000" step="1000" value="${S.loadHighMax}" onchange="S.loadHighMax=+this.value;saveConsents()"></div>
          <div><label>Very High load minimum: <span class="num">${inr(S.loadVeryHighMin)}</span></label><input type="range" min="5000" max="100000" step="2500" value="${S.loadVeryHighMin}" onchange="S.loadVeryHighMin=+this.value;saveConsents()"></div>
        </div>
        <div class="g">
          <div><label>Data retention period: <span class="num">${S.retentionDays} days</span></label><input type="range" min="7" max="180" step="1" value="${S.retentionDays}" onchange="S.retentionDays=+this.value;saveConsents()"></div>
          <div><label>Red Alert notification cooldown: <span class="num">${Math.round(S.redAlertCooldownSec / 60)} min</span></label><input type="range" min="60" max="1800" step="60" value="${S.redAlertCooldownSec}" onchange="S.redAlertCooldownSec=+this.value;saveConsents()"></div>
        </div>
        <p class="mut">Stored: consent settings, masked audit metadata, approval request metadata, SHA-256 QR scan summaries, and call durations (never audio, bank history, or raw private messages). Manage linked guardians in <button type="button" class="s" style="min-height:30px;padding:2px 10px" onclick="switchTab('fam')">Family Management</button>.</p>
        <div class="row">
          <button type="button" class="s" onclick="exportData()">Export my data (JSON)</button>
          <button type="button" class="r" onclick="S.confirmAction='revoke_guardians';R()">Remove guardian access</button>
          <button type="button" class="r" onclick="S.confirmAction='delete_data';R()">Delete my data and log out</button>
        </div>
      </div>

      ${renderQrNotificationPrefsCard()}

      ${uiCard(
        'Access history (sanitized, hash-chained)',
        S.audit.length
          ? S.audit.slice(0, 12).map((a) => `<p class="mut" style="margin:5px 0"><span class="num">${esc(a.t)}</span> · ${esc(a.ev)} <code>#${esc(a.h)}</code></p>`).join('')
          : '<p class="mut" style="margin:0">No access records yet.</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}

      ${
        S.confirmAction === 'revoke_guardians'
          ? uiConfirmModal({
              title: 'Remove all guardian access?',
              body: 'All currently linked primary and secondary guardians will lose access to your alerts and approval requests immediately.',
              confirmLabel: 'Yes, remove guardian access',
              onConfirm: 'confirmRevokeAllGuardians()',
              onCancel: 'S.confirmAction=null;R()',
            })
          : S.confirmAction === 'delete_data'
            ? uiConfirmModal({
                title: 'Permanently delete your data?',
                body: 'This permanently erases your requests, calls, incidents, safe word, and audit logs from the server and logs you out.',
                confirmLabel: 'Yes, permanently delete my data',
                onConfirm: 'confirmDeleteAllData()',
                onCancel: 'S.confirmAction=null;R()',
              })
            : ''
      }`;
  }

  if (T2 === 'tools') {
    b = `${renderAiToolsTab()}${note()}`;
  } else if (T2 === 'bank') {
    b = `${renderBankTab()}${note()}`;
  } else if (T2 === 'control') {
    b = `${renderControlCenterTab()}${note()}`;
  } else if (T2 === 'epp') {
    b = `${renderEmergencyPaymentProtectionTab()}${note()}`;
  }

  const sidebarGroups = [
    {
      title: 'Overview',
      items: [
        { id: 'home', label: t('home'), icon: 'home' as IconName },
        { id: 'device', label: t('device'), icon: 'location' as IconName },
      ],
    },
    {
      title: 'Parents AI Suite',
      items: [
        { id: 'tools', label: t('tools'), icon: 'spark' as IconName },
        { id: 'bank', label: t('bank'), icon: 'building' as IconName },
        { id: 'control', label: t('control'), icon: 'lock' as IconName },
      ],
    },
    {
      title: 'Protection Tools',
      items: [
        { id: 'epp', label: t('epp'), icon: 'shield' as IconName, badge: S.epp?.activeSession ? 1 : 0 },
        { id: 'scam', label: t('scam'), icon: 'search' as IconName },
        { id: 'pay', label: t('pay'), icon: 'card' as IconName, badge: pend },
        { id: 'qr', label: t('qr'), icon: 'qr' as IconName },
        { id: 'call', label: t('call'), icon: 'phone' as IconName },
      ],
    },
    {
      title: 'Monitoring & Insights',
      items: [
        { id: 'alerts', label: t('alerts'), icon: 'bell' as IconName, badge: alertCount },
        { id: 'ai', label: t('ai'), icon: 'spark' as IconName },
        { id: 'reports', label: t('reports'), icon: 'chart' as IconName },
      ],
    },
    {
      title: 'Account',
      items: [
        { id: 'fam', label: t('fam'), icon: 'users' as IconName },
        { id: 'priv', label: t('priv'), icon: 'settings' as IconName },
      ],
    },
  ];

  const allParentTabs = ['home', 'epp', 'tools', 'bank', 'control', 'device', 'scam', 'pay', 'qr', 'call', 'alerts', 'ai', 'reports', 'fam', 'priv'];
  const bottomNavItems: SidebarItem[] = [
    { id: 'home', label: 'Home', icon: 'home' },
    { id: 'tools', label: 'AI Tools', icon: 'spark' },
    { id: 'bank', label: 'Bank', icon: 'building' },
    { id: 'alerts', label: 'Alerts', icon: 'bell' },
    { id: 'control', label: 'Control', icon: 'lock' },
  ];

  return `<div class="app-shell${S.sidebarCollapsed ? ' sidebar-collapsed' : ''}">
    ${renderSidebar(sidebarGroups)}
    <main class="main-col">
      <header class="topbar">
        <div class="row" style="gap:8px;min-width:0;flex-wrap:nowrap">
          <button type="button" class="s icon-trigger mobile-only" onclick="toggleMobileDrawer(true)" aria-label="Open navigation menu">${uiIcon('menu', 16)}</button>
          <span class="brand"><span class="brand-mark">${uiIcon('shield', 16)}</span>${esc(t(T2))}</span>
        </div>
        <div class="search-shell">
          <span class="search-shell-icon">${uiIcon('search', 14)}</span>
          <input id="pai-global-search" type="search" value="${esc(S.searchQuery)}" oninput="setGlobalSearch(this.value)" placeholder="Search AI tools, family plans, alerts…" aria-label="Global family workspace search">
        </div>
        ${topTri()}
      </header>
      <div class="mobile-only">${tabs(allParentTabs)}</div>
      ${offlineBanner()}
      ${activeCallBar()}
      ${alertBanner()}
      ${renderSmartRedAlertBanner(S.gsi?.recentIncidents || [], false)}
      ${renderSearchResultsOverlay()}
      ${b}
    </main>
    ${renderBottomNav(bottomNavItems)}
    ${renderMobileDrawer(sidebarGroups)}
    ${renderNotificationsDrawer()}
  </div>`;
}

function renderFamilySwitcherBar(): string {
  if (!S.linkedParents.length) return '';
  const selectedObj =
    S.selectedFamilyOwnerId !== 'all'
      ? S.linkedParents.find((p) => p.id === S.selectedFamilyOwnerId) || null
      : null;
  const activeName = selectedObj
    ? `${selectedObj.name} (@${selectedObj.username})`
    : `All Linked Parents (${S.linkedParents.length})`;

  return `<div class="card card-anim" style="padding:14px 18px">
    <div class="row" style="justify-content:space-between;gap:10px">
      <div>
        <span class="t-label" style="margin:0;color:var(--mut)">Viewing security data for</span>
        <b style="font-size:15px">${esc(activeName)}</b>
      </div>
      <div class="seg-group" role="group" aria-label="Switch family member">
        <button type="button" class="seg-btn ${S.selectedFamilyOwnerId === 'all' ? 'on' : ''}" onclick="selectFamilyOwner('all')">All (${S.linkedParents.length})</button>
        ${S.linkedParents
          .map(
            (p) =>
              `<button type="button" class="seg-btn ${S.selectedFamilyOwnerId === p.id ? 'on' : ''}" onclick="selectFamilyOwner('${esc(p.id)}')">${esc(p.name)}</button>`
          )
          .join('')}
      </div>
    </div>
  </div>`;
}

function guardian(): string {
  const validOwner =
    S.selectedFamilyOwnerId === 'all' ||
    S.linkedParents.some((p) => p.id === S.selectedFamilyOwnerId);
  const selectedOwnerId = validOwner ? S.selectedFamilyOwnerId : 'all';
  const selectedParentObj =
    selectedOwnerId !== 'all' ? S.linkedParents.find((p) => p.id === selectedOwnerId) || null : null;

  const filteredReqs =
    selectedOwnerId === 'all'
      ? S.reqs
      : S.reqs.filter((q) => !q.parentId || q.parentId === selectedOwnerId);
  const pendCount = filteredReqs.filter(
    (q) => (q.st === 'pending' || q.st === 'verification_requested') && Date.now() < q.exp
  ).length;
  const filteredCw =
    selectedOwnerId === 'all' || !selectedParentObj
      ? S.linkedCallWatcherEvents
      : S.linkedCallWatcherEvents.filter((ev) => !ev.parentName || ev.parentName === selectedParentObj.name);
  const filteredQr =
    selectedOwnerId === 'all' || !selectedParentObj
      ? S.qrScans
      : S.qrScans.filter((q) => !q.parent_name || q.parent_name === selectedParentObj.name);
  const filteredIncidents = (S.linkedGsiOverview?.incidents || []).filter(
    (inc) => selectedOwnerId === 'all' || !inc.familyOwnerId || inc.familyOwnerId === selectedOwnerId
  );
  const filteredGcih =
    selectedOwnerId === 'all'
      ? S.linkedGcihSync
      : S.linkedGcihSync.filter((fam) => fam.familyOwnerId === selectedOwnerId);

  let b = '';

  if (S.tab === 'req') {
    const parentNames = selectedParentObj
      ? selectedParentObj.name
      : S.linkedParents.map((p) => p.name).join(', ') || 'No linked parent yet';
    b = `<div class="card card-anim">
        <div class="row" style="justify-content:space-between">
          <div>
            <h1 class="t-page" style="margin:0">Requests for ${esc(parentNames)}</h1>
            <p class="mut" style="margin:4px 0 0">Review one transaction at a time after independent verification.</p>
          </div>
          <button type="button" class="s" onclick="syncStateFromServer()">Refresh requests</button>
        </div>
      </div>
      ${renderFamilySwitcherBar()}
      ${note()}
      ${notificationsPanel(5)}
      <div class="card card-anim">
        <label for="invCode">Accept parent invitation code</label>
        <div class="row"><input id="invCode" placeholder="e.g. INV-A1B2C3" style="flex:1;margin:0"><button type="button" onclick="acceptInvite()">Accept invite</button></div>
      </div>
      ${
        filteredReqs
          .map((q) => {
            const ex = Date.now() > q.exp && q.st === 'pending';
            const statusText = ex ? 'expired' : q.st;
            return `<div class="card card-anim tilt-card">
              <div class="row" style="justify-content:space-between">
                <div class="row">
                  ${uiBadge(q.level, q.level)}
                  <b class="num">${inr(q.amt)}</b>
                  <span>to ${esc(q.ben)}</span>
                  ${q.parentName ? `<span class="mut">(${esc(q.parentName)})</span>` : ''}
                  ${q.escalatedToSecondary ? uiBadge('Escalated', 'MEDIUM') : ''}
                </div>
                ${uiBadge(statusText, q.st === 'approved' || q.st === 'consumed' ? 'LOW' : q.st === 'rejected' ? 'HIGH' : 'MEDIUM')}
              </div>
              <ul>${q.sig.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>
              <p class="mut">Expires <span class="num" data-exp="${q.exp}"></span></p>
              ${q.verificationNote ? `<p class="mut">Verification note: ${esc(q.verificationNote)}</p>` : ''}
              ${
                q.st === 'pending' && !ex
                  ? `<div class="sw"><input type="checkbox" id="vf${q.id}"><span>I called the parent on an independently saved number</span></div>
                     <input id="gn${q.id}" placeholder="Optional note for parent">
                     <div class="row">
                       <button type="button" class="t" onclick="decide('${q.id}','approved')">Approve this request</button>
                       <button type="button" class="r" onclick="decide('${q.id}','rejected')">Reject</button>
                       <button type="button" class="s" onclick="decide('${q.id}','verification_requested')">Ask for more verification</button>
                     </div>`
                  : q.st === 'verification_requested'
                    ? `<p class="mut">Waiting for parent to complete independent verification and resubmit.</p>`
                    : ''
              }
            </div>`;
          })
          .join('') || uiStateBox('empty', 'No approval requests yet', 'Ask a linked parent to run a payment check and request guardian review.')
      }
      <div class="card card-anim">
        <h3 class="t-card">Security verification check</h3>
        <p class="mut">Verify that forged client-side approval IDs are rejected by the server.</p>
        <button type="button" class="s" onclick="forged()">Test: submit forged approval</button>
      </div>`;
  } else if (S.tab === 'act') {
    const total = filteredReqs.length;
    const approved = filteredReqs.filter((q) => q.st === 'approved' || q.st === 'consumed').length;
    const open = filteredReqs.filter((q) => q.st === 'pending' || q.st === 'verification_requested').length;
    const rejected = filteredReqs.filter((q) => q.st === 'rejected' || q.st === 'expired' || q.st === 'cancelled').length;
    const openRedAlerts = filteredIncidents.filter(
      (i) => i.resolutionStatus === 'open' && i.redAlertTriggered
    ).length;

    b = `<div class="card card-anim">
        <h1 class="t-page" style="margin:0">Family Activity</h1>
        <p class="mut" style="margin:4px 0 0">You only see metadata and intelligence explicitly shared by linked parents.</p>
      </div>
      ${renderFamilySwitcherBar()}
      <div class="swipe-wrap">
        <div id="guardian-kpi-strip" class="swipe-strip kpi-4">
          ${uiStatCard('Pending Approvals', pendCount, 'Waiting for verification', { source: 'actual', icon: 'card', swipeCard: true })}
          ${uiStatCard('Open Red Alerts', openRedAlerts, 'Unresolved high-risk alerts', { source: 'actual', icon: 'bell', swipeCard: true })}
          ${uiStatCard('Shared Call Events', filteredCw.length, 'Call & SMS correlations', { source: 'actual', icon: 'phone', swipeCard: true })}
          ${uiStatCard('Shared QR Scans', filteredQr.length, 'Privacy-preserving QR summaries', { source: 'actual', icon: 'qr', swipeCard: true })}
        </div>
      </div>
      <div class="g-2">
        <section class="card card-anim">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2 class="t-section" style="margin:0">${uiIcon('globe', 18)} Family Protection Network</h2>
              <p class="mut" style="margin:2px 0 0">Real devices &amp; open alert arcs across linked parents</p>
            </div>
            ${uiSourceBadge('actual')}
          </div>
          <div id="guardian-3d-globe" class="stage-3d-shell stage-3d-globe"></div>
        </section>
        ${uiCard(
          'Linked parents',
          S.linkedParents.length
            ? S.linkedParents
                .map(
                  (p) =>
                    `<div class="warn"><div class="row" style="justify-content:space-between"><div><b>${esc(p.name)}</b> <span class="mut">@${esc(p.username)}</span></div>${uiBadge(p.is_secondary ? 'Secondary guardian' : 'Primary guardian', 'LOW')}</div><p class="mut" style="margin:4px 0 0">Approval consent: <b>${p.guardian_approve ? 'on' : 'off'}</b> · Alerts: <b>${p.guardian_alerts ? 'on' : 'off'}</b></p></div>`
                )
                .join('')
            : uiStateBox('empty', 'No linked parent yet', 'Accept an invitation code in Approval Requests to connect with a parent.'),
          { badgeHtml: uiSourceBadge('actual'), tilt: true }
        )}
      </div>
      ${renderSecurityTimeline(true, selectedOwnerId)}
      ${uiBarChart(
        'Shared Request Breakdown',
        [
          { label: 'Approved / Used', value: approved, max: Math.max(1, total), color: 'var(--teal)' },
          { label: 'Pending / Verify', value: open, max: Math.max(1, total), color: 'var(--amb)' },
          { label: 'Rejected / Closed', value: rejected, max: Math.max(1, total), color: 'var(--red)' },
        ],
        { source: 'actual', emptyMessage: 'No shared payment requests yet.' }
      )}
      ${uiCard(
        'Shared Call Watcher Correlations',
        filteredCw.length
          ? filteredCw
              .slice(0, 10)
              .map(
                (ev) =>
                  `<div class="qr-history-row">
                    <div>
                      <b>${esc(ev.call ? ev.call.callerClassification : 'No call linked')} · ${esc(ev.payment ? ev.payment.paymentStatus : 'No payment message')}</b>
                      ${ev.parentName ? `<span class="mut"> (${esc(ev.parentName)})</span>` : ''}
                      <div class="mut" style="font-size:12.5px">${ev.payment && ev.payment.amount !== null ? inr(ev.payment.amount) + ' · ' : ''}${ev.duringCall ? 'During active call' : ev.timeDiffMs !== null ? 'Gap ' + fmtD(ev.timeDiffMs) : 'Timing pending'} · ${new Date(ev.createdAt).toLocaleString()}</div>
                    </div>
                    <div class="row">${cwRiskBadge(ev.callRisk.riskLevel, 'Call: ' + ev.callRisk.riskLevel)} ${cwRiskBadge(ev.paymentRisk.riskLevel, 'Pay: ' + ev.paymentRisk.riskLevel)}</div>
                  </div>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No Call Watcher correlation events shared yet (requires parent guardian-alert consent).</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}
      ${uiCard(
        'Shared QR scan activity',
        filteredQr.length
          ? filteredQr
              .slice(0, 10)
              .map(
                (q) =>
                  `<div class="qr-history-row">
                    <div>
                      <b>${esc(q.payee_name || q.upi_id || q.qr_classification)}</b>
                      ${q.parent_name ? `<span class="mut"> (${esc(q.parent_name)})</span>` : ''}
                      <div class="mut" style="font-size:12.5px">${esc(q.qr_classification)} · ${q.amount !== null ? inr(q.amount) : 'Amount not specified'} · ${esc(q.payment_load_category)} · ${new Date(q.created_at).toLocaleString()}</div>
                    </div>
                    <div class="row">${qrRiskBadge(q.security_risk_level)} ${qrRiskBadge(q.payment_load_risk_level, q.payment_load_category)}</div>
                  </div>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No QR scan summaries shared yet (requires parent guardian-alert consent).</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}
      ${uiCard(
        'Shared GSI Security Incidents & Feedback',
        filteredIncidents.length
          ? renderGsiIncidentsList(filteredIncidents, true)
          : '<p class="mut" style="margin:0">No GSI incidents shared yet (requires parent guardian-alert consent).</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}
      ${
        filteredGcih.length
          ? filteredGcih
              .map(
                (fam) =>
                  `${renderGcihHubSyncPanel(fam, true)}${renderGcihEntitiesAndGraphPanel(fam, true)}${renderGcihDevicesAndPermissionsPanel(fam, true)}`
              )
              .join('')
          : ''
      }
      ${
        S.linkedGsiOverview?.reports?.length
          ? uiCard(
              'Linked Family Weekly Security Summaries & Capability Health',
              S.linkedGsiOverview.reports
                .filter((rep) => selectedOwnerId === 'all' || rep.parentId === selectedOwnerId)
                .map(
                  (rep) =>
                    `<div class="qr-risk-panel" style="margin-bottom:10px">
                      <div class="row" style="justify-content:space-between;margin-bottom:4px">
                        <b>${esc(rep.parentName)}</b>
                        ${uiBadge(rep.capabilities.overallStatus, rep.capabilities.overallStatus === 'healthy' ? 'LOW' : 'MEDIUM')}
                      </div>
                      <p style="margin:4px 0">${esc(rep.weekly.summaryText)}</p>
                      <p class="mut" style="margin:0;font-size:12.5px">Runtime: ${esc(rep.capabilities.runtimeMode.replace(/_/g, ' '))} · Trend: ${rep.weekly.trendDelta >= 0 ? '+' + rep.weekly.trendDelta : rep.weekly.trendDelta}</p>
                    </div>`
                )
                .join(''),
              { badgeHtml: uiSourceBadge('actual') }
            )
          : ''
      }
      ${uiCard(
        'Security events',
        S.audit.length
          ? S.audit.slice(0, 12).map((a) => `<p class="mut" style="margin:5px 0"><span class="num">${esc(a.t)}</span> · ${esc(a.ev)} <code>#${esc(a.h)}</code></p>`).join('')
          : '<p class="mut" style="margin:0">No security events logged yet.</p>',
        { badgeHtml: uiSourceBadge('actual') }
      )}`;
  } else if (S.tab === 'tools') {
    b = `${renderFamilySwitcherBar()}${note()}${renderAiToolsTab()}`;
  } else if (S.tab === 'bank') {
    b = `${renderFamilySwitcherBar()}${note()}${renderBankTab()}`;
  } else if (S.tab === 'control') {
    b = `${renderFamilySwitcherBar()}${note()}${renderControlCenterTab()}`;
  } else if (S.tab === 'epp') {
    b = `${renderFamilySwitcherBar()}${note()}${renderEmergencyPaymentProtectionTab()}`;
  } else {
    b = `<div class="card card-anim">
        <h1 class="t-page" style="margin:0">Guardian Settings</h1>
        <p class="mut" style="margin:4px 0 0">Appearance, readability, language, and QR alert notification preferences.</p>
      </div>
      ${note()}
      <div class="card card-anim">
        <h2 class="t-section">Appearance &amp; Accessibility</h2>
        ${uiThemeSwitcher()}
        <hr class="divider">
        <div class="row" style="justify-content:space-between">
          <div>
            <b style="display:block">Language &amp; Text Size</b>
            <span class="mut" style="font-size:13px">Applies immediately across all screens</span>
          </div>
          ${lang()}
        </div>
      </div>
      ${renderQrNotificationPrefsCard()}`;
  }

  const guardianSidebar = [
    {
      title: 'Guardian Workspace',
      items: [
        { id: 'req', label: t('req'), icon: 'card' as IconName, badge: pendCount },
        { id: 'act', label: t('act'), icon: 'chart' as IconName },
        { id: 'epp', label: t('epp'), icon: 'shield' as IconName, badge: S.epp?.activeSession ? 1 : 0 },
        { id: 'gset', label: t('gset'), icon: 'settings' as IconName },
      ],
    },
    {
      title: 'Parents AI Suite',
      items: [
        { id: 'tools', label: t('tools'), icon: 'spark' as IconName },
        { id: 'bank', label: t('bank'), icon: 'building' as IconName },
        { id: 'control', label: t('control'), icon: 'lock' as IconName },
      ],
    },
  ];
  const guardianBottom: SidebarItem[] = [
    { id: 'req', label: 'Requests', icon: 'card' },
    { id: 'act', label: 'Activity', icon: 'chart' },
    { id: 'epp', label: 'Pay Lock', icon: 'shield' },
    { id: 'tools', label: 'AI Tools', icon: 'spark' },
    { id: 'control', label: 'Control', icon: 'lock' },
  ];

  return `<div class="app-shell${S.sidebarCollapsed ? ' sidebar-collapsed' : ''}">
    ${renderSidebar(guardianSidebar)}
    <main class="main-col">
      <header class="topbar">
        <div class="row" style="gap:8px;min-width:0;flex-wrap:nowrap">
          <button type="button" class="s icon-trigger mobile-only" onclick="toggleMobileDrawer(true)" aria-label="Open navigation menu">${uiIcon('menu', 16)}</button>
          <span class="brand"><span class="brand-mark">${uiIcon('shield', 16)}</span>${esc(t(S.tab))}</span>
        </div>
        <div class="search-shell">
          <span class="search-shell-icon">${uiIcon('search', 14)}</span>
          <input id="pai-global-search" type="search" value="${esc(S.searchQuery)}" oninput="setGlobalSearch(this.value)" placeholder="Search AI tools, budgets, family alerts…" aria-label="Global family workspace search">
        </div>
        ${topTri()}
      </header>
      <div class="mobile-only">${tabs(['req', 'act', 'epp', 'tools', 'bank', 'control', 'gset'])}</div>
      ${offlineBanner()}
      ${renderSmartRedAlertBanner(filteredIncidents, true)}
      ${renderSearchResultsOverlay()}
      ${b}
    </main>
    ${renderBottomNav(guardianBottom)}
    ${renderMobileDrawer(guardianSidebar)}
    ${renderNotificationsDrawer()}
  </div>`;
}

function attachNavHorizontalScroll(): void {
  const nav = document.querySelector('.nav') as HTMLElement | null;
  if (!nav) return;
  nav.scrollLeft = savedNavScroll;

  nav.addEventListener(
    'scroll',
    () => {
      savedNavScroll = nav.scrollLeft;
    },
    { passive: true }
  );

  nav.addEventListener(
    'wheel',
    (e: WheelEvent) => {
      if (nav.scrollWidth > nav.clientWidth && Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
        nav.scrollLeft += e.deltaY;
        savedNavScroll = nav.scrollLeft;
        e.preventDefault();
      }
    },
    { passive: false }
  );

  let isDown = false;
  let startX = 0;
  let startScroll = 0;
  let moved = false;

  nav.addEventListener('pointerdown', (e: PointerEvent) => {
    if (e.pointerType === 'touch') return;
    isDown = true;
    moved = false;
    startX = e.clientX;
    startScroll = nav.scrollLeft;
  });

  nav.addEventListener('pointermove', (e: PointerEvent) => {
    if (!isDown) return;
    const dx = e.clientX - startX;
    if (Math.abs(dx) > 5) moved = true;
    if (moved) {
      nav.scrollLeft = startScroll - dx;
      savedNavScroll = nav.scrollLeft;
    }
  });

  const endDrag = () => {
    isDown = false;
    if (moved) {
      window.setTimeout(() => {
        moved = false;
      }, 0);
    }
  };
  nav.addEventListener('pointerup', endDrag);
  nav.addEventListener('pointerleave', endDrag);
  nav.addEventListener(
    'click',
    (e: MouseEvent) => {
      if (moved) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    true
  );
}

export function renderApp(): void {
  const prevNav = document.querySelector('.nav') as HTMLElement | null;
  if (prevNav) {
    savedNavScroll = prevNav.scrollLeft;
  }
  const appEl = document.getElementById('app');
  if (!appEl) return;
  document.documentElement.lang = S.lang === 'hi' ? 'hi' : 'en';
  if (!S.booted) {
    appEl.innerHTML = uiStateBox(
      'loading',
      'Loading Guardian for Parents…',
      'Checking your session and restoring safety preferences.'
    );
    return;
  }
  appEl.innerHTML = !S.user ? landing() : S.user.role === 'parent' ? parent() : guardian();
  attachNavHorizontalScroll();
  tick();

  const routeKey = !S.user
    ? `landing:${S.mode}:${S.role}`
    : `${S.user.id}:${S.user.role}:${S.tab === 'learn' ? 'reports' : S.tab}:${S.selectedFamilyOwnerId}`;
  runMotionEnhancements(routeKey);

  const hasShield = Boolean(document.getElementById('guardian-3d-shield'));
  const hasGlobe = Boolean(document.getElementById('guardian-3d-globe'));
  const hasOrb = Boolean(document.getElementById('guardian-3d-orb'));
  const hasFinance = Boolean(document.getElementById('guardian-3d-finance'));
  if (hasShield || hasGlobe || hasOrb || hasFinance) {
    const loadId = ++threeLoadSeq;
    let shieldInput: ShieldVisualInput | undefined;
    if (hasShield) {
      if (!S.user) {
        shieldInput = { status: 'active', score: 100, label: 'Family Defense' };
      } else {
        const posture = computeParentPosture();
        shieldInput = {
          status: posture.shieldStatus,
          score: posture.score,
          label: posture.label,
        };
      }
    }
    const globeInput: GlobeVisualInput | undefined = hasGlobe
      ? buildGlobePayload(S.user?.role === 'guardian', S.selectedFamilyOwnerId)
      : undefined;
    const orbInput: OrbVisualInput | undefined = hasOrb
      ? {
          label: S.user ? 'Parents AI Core' : 'Parents AI Intelligence',
          sublabel: S.busy.parentsAi ? 'Analyzing family prompt…' : 'Champagne AI Engine Active',
        }
      : undefined;

    let financeInput: FinanceVisualInput | undefined;
    if (hasFinance) {
      const pai = S.parentsAi;
      const spendMap = pai?.summary?.categorySpend || {};
      const budgets = pai?.budgets || [];
      const cats = Array.from(new Set([...Object.keys(spendMap), ...budgets.map((b) => b.category)]));
      const bars = cats.slice(0, 6).map((cat) => {
        const budget = budgets.find((b) => b.category === cat);
        return {
          label: cat,
          spent: Math.max(0, Number(spendMap[cat] ?? budget?.spent ?? 0)),
          limit: Math.max(1000, Number(budget?.monthlyLimit ?? 15000)),
        };
      });
      financeInput = {
        bars: bars.length
          ? bars
          : [
              { label: 'Groceries', spent: 6400, limit: 15000 },
              { label: 'Utilities', spent: 4100, limit: 10000 },
              { label: 'Education', spent: 8500, limit: 15000 },
              { label: 'Health', spent: 2800, limit: 10000 },
            ],
        caption: !pai || Boolean(pai.summary.hasDemoConnection) || bars.length === 0
          ? 'Sample Demo Spend vs Budget Limit'
          : 'Monthly Category Spend vs Budget Limit',
      };
    }

    void import('./threeVisuals')
      .then((m) => {
        if (loadId === threeLoadSeq) {
          m.syncThreeVisuals({ shield: shieldInput, globe: globeInput, orb: orbInput, finance: financeInput });
        }
      })
      .catch(() => {
        // Safe silent fallback if WebGL / dynamic import fails
      });
  }
}

let eppReconcileLastAt = 0;

export function tick(): void {
  document.querySelectorAll<HTMLElement>('[data-cs]').forEach((e) => {
    const start = Number(e.dataset.cs || 0);
    const m = Math.max(0, Date.now() - start);
    e.textContent = fmtD(m);
  });
  document.querySelectorAll<HTMLElement>('[data-exp]').forEach((e) => {
    const m = Number(e.dataset.exp || 0) - Date.now();
    e.textContent = m > 0 ? Math.floor(m / 6e4) + 'm ' + Math.floor((m % 6e4) / 1e3) + 's' : 'expired';
  });
  let eppExpiredNow = false;
  document.querySelectorAll<HTMLElement>('[data-epp-exp]').forEach((e) => {
    const expAt = Number(e.dataset.eppExp || 0);
    if (expAt > 0) {
      e.textContent = eppFormatCountdown(expAt, false);
      if (Date.now() >= expAt) {
        eppExpiredNow = true;
      }
    }
  });
  if (eppExpiredNow && S.epp?.activeSession && Date.now() - eppReconcileLastAt > 5000) {
    eppReconcileLastAt = Date.now();
    void loadEppDashboard().then(() => R());
  }
  if (S.cur && !S.cur.known && !S.cur.warnedLong && Date.now() - S.cur.s >= 18e4) {
    S.cur.warnedLong = true;
    S.note =
      'AI Call Watch: Unknown call has lasted 3+ minutes (timing only, no audio). Do not share OTP or approve any payment during this call.';
    R();
  }
}

export function mountGuardianApp(): () => void {
  setRenderer(renderApp);
  S.recentTools = loadRecentTools();
  getOrCreateGcihDeviceId();
  loadCwOfflineQueue();
  loadGcihOfflineQueue();
  bindTiltCards();
  bindEscapeDrawerHandler(() => {
    if (S.confirmAction) {
      S.confirmAction = null;
      R();
      return true;
    }
    if (S.notifDrawerOpen) {
      S.notifDrawerOpen = false;
      R();
      return true;
    }
    if (S.mobileDrawerOpen) {
      S.mobileDrawerOpen = false;
      R();
      return true;
    }
    return false;
  });
  cleanupThemeListener = initThemeListener(R);
  cleanupConnectivityListener = initConnectivityListener((online) => {
    S.online = online;
    if (online && S.user?.role === 'parent') {
      if (S.cwOfflineQueue.length > 0) void cwFlushOfflineQueue();
      if (S.gcihOfflineQueue.length > 0) void gcihFlushOfflineQueue();
    }
    R();
  });

  Object.assign(window, {
    S,
    R,
    switchTab,
    setFontScale,
    setTheme,
    toggleSidebar,
    toggleMobileDrawer,
    toggleNotifDrawer,
    dismissInfoNotif,
    setTimelineFilter,
    toggleTimelineExpand,
    selectFamilyOwner,
    scrollSwipeStrip,
    analyze,
    ocrFile,
    reportScam,
    demo,
    assess,
    payFill,
    askG,
    decide,
    resubmitReq,
    escalateReq,
    proceed,
    cancelPay,
    forged,
    swSet,
    swCheck,
    callStart,
    callEnd,
    demoCall,
    payAlert,
    cwConsentAction,
    cwToggleUnknownNotify,
    cwLogCall,
    cwLogPaymentMsg,
    cwDemoScenario,
    cwSubmitQuestionnaire,
    cwDismissQuestionnaire,
    cwSelectEvent,
    cwFlushOfflineQueue,
    cwScreenCallerNumber,
    cwMarkCallerTrusted,
    cwReportSuspiciousCaller,
    cwContactParent,
    cwToggleWhyFlagged,
    qrParse,
    qrFile,
    startQrCamera,
    stopQrCamera,
    openQrHistoryReport,
    chat,
    mic,
    speak,
    ans,
    runEval,
    login,
    reg,
    recoverAccount,
    logout,
    createInvite,
    acceptInvite,
    revokeLink,
    saveConsents,
    saveQrPrefs,
    confirmRevokeAllGuardians,
    emergencyHelpAction,
    dismissEmergencyStatus,
    confirmDeleteAllData,
    exportData,
    markNotificationsRead,
    saveIncident,
    syncStateFromServer,
    inspectManualLink,
    gsiFeedback,
    gcihFlushOfflineQueue,
    gcihRegisterCurrentDevice,
    gcihUpdateDevicePermissions,
    gcihRevokeDevice,
    gcihSyncNow,
    gcihSubmitEntityFeedback,
    gcihCorrectRelationship,
    gcihUpdateIncidentWorkflow,
    openAiTool,
    askAiToolPrompt,
    addToolWorkspaceItem,
    toggleToolWorkspaceItem,
    removeToolWorkspaceItem,
    connectBankAa,
    revokeBankConsent,
    saveFamilyBudget,
    removeBudget,
    updateFinAccess,
    setGlobalSearch,
    setBankSearch,
    setBankCatFilter,
    loadParentsAiState,
    loadEppDashboard,
    eppSelectBank,
    eppSetBankSearch,
    eppPreviewBankService,
    eppLaunchBankService,
    eppConfirmBankCompleted,
    eppToggleApp,
    eppSelectAllApps,
    eppAddCustomApp,
    eppSetDuration,
    eppToggleAuthAck,
    eppToggleBankEditor,
    eppActivateLock,
    eppUnlockLock,
    eppSaveBankDirectoryEntry,
    eppScrollToBanks,
  });
  renderApp();
  void syncStateFromServer();
  if (tickInterval === null) {
    tickInterval = window.setInterval(tick, 1000);
  }
  return () => {
    stopQrCamera(true);
    void import('./threeVisuals')
      .then((m) => m.disposeThreeVisuals())
      .catch(() => {});
    if (tickInterval !== null) {
      window.clearInterval(tickInterval);
      tickInterval = null;
    }
    if (cleanupThemeListener) {
      cleanupThemeListener();
      cleanupThemeListener = null;
    }
    if (cleanupConnectivityListener) {
      cleanupConnectivityListener();
      cleanupConnectivityListener = null;
    }
  };
}

function qrRiskBadge(level: string, label?: string): string {
  const tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' =
    level === 'LOW' || level === 'MEDIUM' || level === 'HIGH' || level === 'CRITICAL' ? level : 'NEUTRAL';
  return uiBadge(label || level, tone);
}

function renderQrSourcedRows(fields: QrSourcedField[]): string {
  return `<div class="qr-kv-list">${fields
    .map(
      (f) =>
        `<div class="qr-kv-row">
          <div class="qr-kv-key">${esc(f.label)}</div>
          <div class="qr-kv-val">
            <span>${esc(f.displayValue)}</span>
            <span class="qr-prov">Source: ${esc(f.source)}</span>
          </div>
        </div>`
    )
    .join('')}</div>`;
}

function renderQrNotificationPrefsCard(): string {
  const items: [keyof QrNotificationPrefs, string][] = [
    ['qrScanNotify', 'Notify when any QR is scanned'],
    ['highRiskQrAlert', 'High-risk QR alert'],
    ['criticalRiskQrAlert', 'Critical-risk QR alert'],
    ['highAmountAlert', 'High payment amount alert (exceeds configured limit)'],
    ['veryHighLoadAlert', 'Very high payment load alert'],
    ['repeatedQrAlert', 'Repeated / duplicate QR scan alert'],
    ['merchantWarningAlert', 'Merchant / recipient warning alert'],
    ['suspiciousQrAlert', 'Suspicious QR indicator alert'],
  ];
  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:6px">
      <div>
        <h2 class="t-section" style="margin:0">QR Alert Notification Preferences</h2>
        <p class="mut" style="margin:2px 0 0">Choose which QR scan events generate guardian notifications (respects parent consent &amp; pause state).</p>
      </div>
      ${uiSourceBadge('actual')}
    </div>
    ${items
      .map(
        ([k, label]) =>
          `<div class="sw"><input type="checkbox" ${S.qrPrefs[k] ? 'checked' : ''} onchange="S.qrPrefs['${k}']=this.checked;saveQrPrefs()" aria-label="${esc(label)}"><span>${esc(label)}</span></div>`
      )
      .join('')}
  </div>`;
}

function renderQrIntelligenceReportHtml(r: QrIntelligenceReport): string {
  const secBadge = qrRiskBadge(r.overallAssessment.securityRiskLevel, r.overallAssessment.securityRiskLabel);
  const loadBadge = qrRiskBadge(r.overallAssessment.paymentLoadRiskLevel, r.overallAssessment.paymentLoadRiskLabel);
  const overallBadge = qrRiskBadge(r.overallAssessment.combinedLevel, r.overallAssessment.combinedLabel);

  const s1Overview = `<section class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <div>
        <h2 class="t-section" style="margin:0">1. QR Scan Overview</h2>
        <p class="mut" style="margin:2px 0 0">Scanned ${new Date(r.scannedAt).toLocaleString()} · Format: ${esc(r.extracted.qrFormat)} · Status: <b>${esc(r.extracted.decodingStatus)}</b></p>
      </div>
      ${overallBadge}
    </div>
    <div class="qr-risk-split">
      <div class="qr-risk-panel">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <b>QR Security Risk</b>
          ${secBadge}
        </div>
        <p class="mut" style="margin:0">Score <span class="num"><b>${r.security.score}/100</b></span> · ${esc(r.security.summary)}</p>
      </div>
      <div class="qr-risk-panel">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <b>Payment Load Risk</b>
          ${loadBadge}
        </div>
        <p class="mut" style="margin:0">Category: <b>${esc(r.paymentLoad.loadCategory)}</b> · Evaluated strictly by amount load (independent of fraud risk).</p>
      </div>
    </div>
    <p class="mut" style="margin:6px 0 0">${esc(r.overallAssessment.summary)} Scanning this QR never starts a payment.</p>
  </section>`;

  const s2LoadInfo = `<section class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <h2 class="t-section" style="margin:0">2. QR Load Information</h2>
      ${loadBadge}
    </div>
    <div class="qr-amount-hero">
      <span class="t-label" style="color:var(--mut);margin:0">Payment Amount</span>
      <div class="qr-amount-value">${esc(r.qrLoadInfo.paymentAmountDisplay)}</div>
      <div class="mut">Currency: <b>${esc(r.qrLoadInfo.currency)}</b> · Editability: <b>${esc(r.qrLoadInfo.amountEditability)}</b></div>
      <div class="mut" style="margin-top:4px">QR Load Category: <b>${esc(r.qrLoadInfo.qrLoadCategory)}</b> — ${esc(r.qrLoadInfo.qrLoadCategoryMessage)}</div>
    </div>
    <div class="qr-kv-list">
      <div class="qr-kv-row"><div class="qr-kv-key">Payment Type</div><div class="qr-kv-val">${esc(r.qrLoadInfo.paymentType)}</div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">Recipient Name</div><div class="qr-kv-val">${esc(r.qrLoadInfo.recipientName)}</div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">Recipient UPI ID</div><div class="qr-kv-val"><code>${esc(r.qrLoadInfo.recipientUpiId)}</code></div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">Payment Note</div><div class="qr-kv-val">${esc(r.qrLoadInfo.paymentNote)}</div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">Encoded Details</div><div class="qr-kv-val">${esc(r.qrLoadInfo.encodedPaymentDetailsSummary)}</div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">Payment Status</div><div class="qr-kv-val">${esc(r.qrLoadInfo.paymentStatus.join(' · '))}</div></div>
      <div class="qr-kv-row"><div class="qr-kv-key">AI Amount Explanation</div><div class="qr-kv-val">${esc(r.qrLoadInfo.aiAmountExplanation)}</div></div>
    </div>
  </section>`;

  const s3Extracted = `<details class="qr-details" open>
    <summary>3. Extracted QR Information <span class="mut" style="font-size:13px;font-weight:500">All fields &amp; provenance</span></summary>
    <div class="qr-details-body">
      <h3 class="t-card">Payment Details</h3>
      ${renderQrSourcedRows(r.extracted.paymentFields)}
      <h3 class="t-card" style="margin-top:16px">QR Technical Details</h3>
      ${renderQrSourcedRows(r.extracted.qrFields)}
    </div>
  </details>`;

  const merchantAlert =
    r.merchant.nameMismatchDetected || r.merchant.impersonationIndicators.length
      ? uiAlert(
          r.merchant.mismatchReason || r.merchant.impersonationIndicators.join(' '),
          { title: 'Recipient Warning:', tone: 'danger' }
        )
      : '';

  const s4Merchant = `<details class="qr-details" open>
    <summary>4. Merchant and Recipient Details</summary>
    <div class="qr-details-body">
      ${merchantAlert}
      ${renderQrSourcedRows([
        r.merchant.upiId,
        r.merchant.payeeName,
        r.merchant.merchantName,
        r.merchant.merchantCategory,
        r.merchant.paymentProvider,
        r.merchant.verifiedIdentity,
        r.merchant.reputationInfo,
        r.merchant.fraudReportsInfo,
      ])}
      <div style="margin-top:10px">${uiAlert(r.merchant.externalVerification.message, { title: 'Verification boundary:', tone: 'info' })}</div>
    </div>
  </details>`;

  const s5Security = `<details class="qr-details" open>
    <summary><span>5. Security Analysis</span> ${secBadge}</summary>
    <div class="qr-details-body">
      <p style="margin:0 0 10px"><b>Rule Risk Score: <span class="num">${r.security.score}/100</span></b> · ${esc(r.security.summary)}</p>
      ${r.security.findings
        .map(
          (f) =>
            `<div class="${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'alert-danger' : f.severity === 'MEDIUM' ? 'alert-warn' : 'warn'}">
              <div class="row" style="justify-content:space-between"><b>${esc(f.title)}</b>${qrRiskBadge(f.severity)}</div>
              <p class="mut" style="margin:4px 0 0"><b>Evidence:</b> ${esc(f.evidence)}</p>
              <p class="mut" style="margin:4px 0 0"><b>Reasoning:</b> ${esc(f.reasoning)}</p>
            </div>`
        )
        .join('')}
      <div style="margin-top:10px">${uiAlert(r.security.externalFraudIntel.message, { title: 'External intelligence boundary:', tone: 'info' })}</div>
    </div>
  </details>`;

  const s6Amount = `<details class="qr-details">
    <summary>6. Payment Amount Analysis</summary>
    <div class="qr-details-body">
      <div class="qr-kv-list">
        <div class="qr-kv-row"><div class="qr-kv-key">Amount State</div><div class="qr-kv-val">${esc(r.paymentAmountAnalysis.caseType)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Summary</div><div class="qr-kv-val">${esc(r.paymentAmountAnalysis.summary)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Editability</div><div class="qr-kv-val">${esc(r.paymentAmountAnalysis.editability)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Threshold / Anomaly Note</div><div class="qr-kv-val">${esc(r.paymentAmountAnalysis.anomalyNote)}</div></div>
      </div>
    </div>
  </details>`;

  const ea = r.paymentLoad.explanationAnswers;
  const s7Load = `<details class="qr-details" open>
    <summary><span>7. Payment Load Analysis</span> ${loadBadge}</summary>
    <div class="qr-details-body">
      <p class="mut" style="margin:0 0 10px">Configured thresholds: Safety Limit <b class="num">${inr(r.paymentLoad.configuredThresholds.paymentLimit)}</b> · Moderate ≤ <b class="num">${inr(r.paymentLoad.configuredThresholds.moderateMax)}</b> · High ≤ <b class="num">${inr(r.paymentLoad.configuredThresholds.highMax)}</b> · Very High &gt; <b class="num">${inr(r.paymentLoad.configuredThresholds.veryHighMin)}</b></p>
      ${uiAlert(r.paymentLoad.historicalComparisonMessage, { title: 'Bank history boundary:', tone: 'info' })}
      <div class="qr-kv-list" style="margin-top:10px">
        <div class="qr-kv-row"><div class="qr-kv-key">Requested amount</div><div class="qr-kv-val">${esc(ea.requestedAmountText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Load classification</div><div class="qr-kv-val">${esc(ea.loadCategoryText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Configured limit check</div><div class="qr-kv-val">${esc(ea.exceedsThresholdText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Historical bank comparison</div><div class="qr-kv-val">${esc(ea.historicalComparisonText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Repeated scan pattern</div><div class="qr-kv-val">${esc(ea.repeatedRequestsText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Cumulative scan exposure</div><div class="qr-kv-val">${esc(ea.cumulativeExposureText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Why this matters</div><div class="qr-kv-val">${esc(ea.whyPayAttentionText)}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Recommended action</div><div class="qr-kv-val">${esc(ea.recommendedActionText)}</div></div>
      </div>
    </div>
  </details>`;

  const d = r.duplicateStatus;
  const s8Duplicate = `<details class="qr-details" open>
    <summary><span>8. Duplicate QR History</span> ${uiBadge(d.isDuplicate ? 'REPEATED QR' : 'NEW PAYLOAD', d.isDuplicate ? 'MEDIUM' : 'LOW')}</summary>
    <div class="qr-details-body">
      ${d.isDuplicate ? uiAlert(d.note, { title: 'Repeated QR detected:', tone: 'warn' }) : `<p style="margin:0 0 10px">${esc(d.note)}</p>`}
      <div class="qr-kv-list">
        <div class="qr-kv-row"><div class="qr-kv-key">Payload SHA-256</div><div class="qr-kv-val"><code>${esc(d.payloadHash.slice(0, 16))}…</code></div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Prior scans of exact QR</div><div class="qr-kv-val num">${d.previousScanCount} (Total including this scan: ${d.totalScansIncludingCurrent})</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">First / Last prior scan</div><div class="qr-kv-val">${d.firstScanAt ? `${new Date(d.firstScanAt).toLocaleString()} / ${d.mostRecentPreviousScanAt ? new Date(d.mostRecentPreviousScanAt).toLocaleString() : 'N/A'}` : 'First time scanned'}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Different QRs, same UPI ID</div><div class="qr-kv-val num">${d.sameMerchantDifferentQrCount}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Field changes across merchant QRs</div><div class="qr-kv-val">${d.changesDetected.length ? esc(d.changesDetected.join(' | ')) : 'None detected'}</div></div>
      </div>
    </div>
  </details>`;

  const s9Ai = `<details class="qr-details" open>
    <summary><span>9. AI Safety Explanation</span> <span class="${r.aiReport.available ? 'badge-live' : 'badge-fb'}">${r.aiReport.available ? 'LIVE GEMINI AI' : 'FALLBACK RULES'}</span></summary>
    <div class="qr-details-body">
      <p style="margin:0 0 8px"><b>Safety Summary:</b> ${esc(r.aiReport.safetySummary)}</p>
      <p style="margin:0 0 8px"><b>Amount Explanation:</b> ${esc(r.aiReport.amountExplanation)}</p>
      <b>Important Warnings</b>
      <ul>${r.aiReport.importantWarnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>
      <b>Recommended Precautions</b>
      <ul>${r.aiReport.recommendedPrecautions.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>
      <p class="mut" style="margin:8px 0 0">${esc(r.aiReport.uncertaintyStatement)}</p>
    </div>
  </details>`;

  const pn = r.parentNotifications;
  const s10Notify = `<details class="qr-details">
    <summary>10. Parent Notification Status</summary>
    <div class="qr-details-body">
      <p style="margin:0 0 10px">${esc(pn.statusMessage)}</p>
      <div class="qr-kv-list">
        <div class="qr-kv-row"><div class="qr-kv-key">Guardian Alerts Consent</div><div class="qr-kv-val">${pn.consentEnabled ? 'Enabled' : 'Disabled'} · Monitoring Paused: ${pn.monitoringPaused ? 'Yes' : 'No'}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Active Linked Guardians</div><div class="qr-kv-val num">${pn.linkedGuardiansCount}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Evaluated Triggers</div><div class="qr-kv-val">${esc(pn.triggeredEvents.join(', ') || 'None')}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Notifications Delivered</div><div class="qr-kv-val num">${pn.notificationsSentCount}</div></div>
        <div class="qr-kv-row"><div class="qr-kv-key">Suppressed / Notes</div><div class="qr-kv-val">${esc(pn.suppressedReasons.join(' | ') || 'None')}</div></div>
      </div>
    </div>
  </details>`;

  const s11Shared = `<details class="qr-details" open>
    <summary><span>11. Cross-Section &amp; Family Shared Intelligence</span> ${uiBadge(`${r.sharedIntelligence?.length || 0} Match(es)`, (r.sharedIntelligence?.length || 0) > 0 ? 'MEDIUM' : 'LOW')}</summary>
    <div class="qr-details-body">
      ${renderSharedIntelItemsHtml([...(r.sharedIntelligence || []), ...(S.gcih?.sectionFeeds?.qr_scam || [])], 'QR Check')}
    </div>
  </details>`;

  return s1Overview + s2LoadInfo + s3Extracted + s4Merchant + s5Security + s6Amount + s7Load + s8Duplicate + s9Ai + s10Notify + s11Shared;
}

function renderQrIntelligenceTab(): string {
  const st = S.qrStatus;
  let statusHtml = '';
  if (st.state === 'camera_active') {
    statusHtml = `<div class="qr-camera-box"><video id="qr-video" autoplay playsinline muted></video></div>
      ${uiAlert(st.message || 'Camera scanning active. Align QR inside the frame.', { tone: 'info' })}`;
  } else if (st.state === 'camera_denied' || st.state === 'camera_unavailable') {
    statusHtml = uiAlert(st.message || 'Camera unavailable.', { title: 'Camera notice:', tone: 'warn' });
  } else if (st.state === 'decoding' || st.state === 'analyzing') {
    statusHtml = uiStateBox(
      'loading',
      st.state === 'decoding' ? 'Decoding QR image…' : 'Analyzing QR safety & payment load…',
      st.message || 'Validating structure, checking recipient & load indicators, and requesting AI guidance.'
    );
  } else if (st.state === 'error') {
    statusHtml = uiStateBox('error', 'QR Analysis Issue', st.message || 'Could not process this QR.');
  }

  const historyHtml = uiCard(
    'Recent QR Scan History',
    S.qrScans.length
      ? S.qrScans
          .slice(0, 10)
          .map(
            (q) =>
              `<div class="qr-history-row">
                <div>
                  <b>${esc(q.payee_name || q.upi_id || q.qr_classification)}</b>
                  <div class="mut" style="font-size:12.5px">${esc(q.qr_format)} · ${q.amount !== null ? inr(q.amount) : 'Amount not specified'} · ${esc(q.payment_load_category)} · ${new Date(q.created_at).toLocaleString()}</div>
                </div>
                <div class="row">
                  ${qrRiskBadge(q.security_risk_level)}
                  ${qrRiskBadge(q.payment_load_risk_level, q.payment_load_category)}
                  <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="openQrHistoryReport('${esc(q.id)}')">View report</button>
                </div>
              </div>`
          )
          .join('')
      : '<p class="mut" style="margin:0">No QR scans recorded yet. Scan via camera, upload a QR image, or run a sample below.</p>',
    { badgeHtml: uiSourceBadge('actual') }
  );

  return `<div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h1 class="t-page" style="margin:0">${esc(t('qr'))} Intelligence</h1>
          <p class="mut" style="margin:4px 0 0">Inspect UPI, BharatQR, and web QR payloads before paying — camera, image upload, or pasted text.</p>
        </div>
        ${uiSourceBadge('actual')}
      </div>
      <div class="row" style="margin-top:12px">
        ${
          st.state === 'camera_active'
            ? `<button type="button" class="r" onclick="stopQrCamera()">Stop Camera</button>`
            : `<button type="button" class="t" onclick="startQrCamera()">${uiIcon('qr', 16)}Scan with Live Camera</button>`
        }
      </div>
      <label for="qr-img" style="margin-top:12px">Upload QR image (PNG, JPG, WEBP)</label>
      <input id="qr-img" type="file" accept="image/png,image/jpeg,image/webp" onchange="qrFile(event)">
      <label for="qt">Or paste QR text / payload</label>
      <textarea id="qt" rows="2" placeholder="Paste UPI URI (upi://pay?...), BharatQR TLV (000201...), or web URL"></textarea>
      <div class="row">
        <button type="button" onclick="qrParse(document.getElementById('qt').value)">Analyze QR Code</button>
        <button type="button" class="s" onclick="document.getElementById('qt').value='upi://pay?pa=refund.helpdesk@okfake&pn=Quick Refund Desk&am=4999&tn=Refund processing fee';qrParse(document.getElementById('qt').value)">Demo: Refund Scam ₹4,999</button>
        <button type="button" class="s" onclick="document.getElementById('qt').value='upi://pay?pa=sharma.kirana@oksbi&pn=Sharma Kirana Store&mc=5411';qrParse(document.getElementById('qt').value)">Demo: Static Merchant</button>
        <button type="button" class="s" onclick="document.getElementById('qt').value='upi://pay?pa=bescom.bill@okicici&pn=BESCOM Utility&am=1850&cu=INR&tn=Electricity Bill&tr=TR99182&tid=TXN7721&mc=4900';qrParse(document.getElementById('qt').value)">Demo: Dynamic Bill ₹1,850</button>
        <button type="button" class="s" onclick="document.getElementById('qt').value='upi://pay?pa=apollo.pharmacy@okhdfcbank&pn=Apollo Pharmacy&am=35000&cu=INR&tn=Hospital Advance&tr=TR8812&mc=8062';qrParse(document.getElementById('qt').value)">Demo: High Load ₹35,000</button>
        <button type="button" class="s" onclick="document.getElementById('qt').value='https://bit.ly/sbi-kyc-update-alert';qrParse(document.getElementById('qt').value)">Demo: External Link</button>
      </div>
      <p class="mut" style="margin:10px 0 0">A payment is never started and external links are never opened automatically.</p>
    </div>
    ${statusHtml}
    ${
      S.qrReport
        ? renderQrIntelligenceReportHtml(S.qrReport)
        : S.qr
          ? S.qr.err
            ? uiAlert(S.qr.err, { tone: 'warn' })
            : `<div class="card"><b>Decoded QR fields</b><ul>${Object.entries(S.qr.d || {})
                .filter((e) => e[1])
                .map((e) => `<li>${esc(e[0])}: <code>${esc(e[1])}</code></li>`)
                .join('')}</ul></div>${S.qr.r ? card(S.qr.r) : ''}`
          : st.state === 'idle'
            ? uiStateBox('empty', 'Ready to inspect a QR code', 'Use live camera scanning, upload a QR screenshot, or run one of the sample QR scenarios above.')
            : ''
    }
    ${historyHtml}`;
}

function cwRiskBadge(level: string, label?: string): string {
  const tone: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEUTRAL' =
    level === 'Low Risk'
      ? 'LOW'
      : level === 'Moderate Risk'
        ? 'MEDIUM'
        : level === 'High Risk'
          ? 'HIGH'
          : level === 'Critical Risk'
            ? 'CRITICAL'
            : 'NEUTRAL';
  return uiBadge(label || level, tone);
}

function renderCwRiskPanel(title: string, r: CwSeparateRiskAssessment): string {
  return `<div class="qr-risk-panel">
    <div class="row" style="justify-content:space-between;margin-bottom:6px">
      <b>${esc(title)}</b>
      ${cwRiskBadge(r.riskLevel)}
    </div>
    <p class="mut" style="margin:0 0 6px">Category: <b>${esc(r.riskCategory)}</b></p>
    <p style="margin:0 0 6px;font-size:13.5px"><b>Action:</b> ${esc(r.recommendedAction)}</p>
    <div class="mut" style="font-size:12.5px"><b>Evidence:</b> ${esc(r.supportingEvidence.join(' · '))}</div>
    ${r.missingInformation.length ? `<div class="mut" style="font-size:12.5px;margin-top:4px"><b>Unavailable / Limits:</b> ${esc(r.missingInformation.join(' · '))}</div>` : ''}
  </div>`;
}

function renderCwEventReport(item: CwTimelineItem): string {
  const timingText = item.duringCall
    ? 'During active call (0m 0s gap)'
    : item.timeDiffMs !== null
      ? `${fmtD(item.timeDiffMs)} between call and payment message`
      : 'Single event (not paired with another event yet)';

  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h2 class="t-section" style="margin:0">Call Watcher Event Report</h2>
        <p class="mut" style="margin:2px 0 0">Event ID <code>${esc(item.correlationId)}</code> · Recorded ${new Date(item.createdAt).toLocaleString()}</p>
      </div>
      <div class="row">
        ${cwRiskBadge(item.callRisk.riskLevel, 'Call: ' + item.callRisk.riskLevel)}
        ${cwRiskBadge(item.paymentRisk.riskLevel, 'Pay: ' + item.paymentRisk.riskLevel)}
      </div>
    </div>

    ${
      item.criticalWarningActive
        ? uiAlert(
            'Do NOT share any OTP, UPI PIN, or password. Uninstall any remote-access / screen-sharing app immediately. Stop further transfers, call your bank directly, and report fraud on 1930 or cybercrime.gov.in.',
            { title: 'CRITICAL SAFETY WARNING:', tone: 'danger' }
          )
        : ''
    }

    <div class="qr-risk-split">
      ${renderCwRiskPanel('Call Risk (Caller Metadata & Timing)', item.callRisk)}
      ${renderCwRiskPanel('Payment Risk (Message & Correlation)', item.paymentRisk)}
    </div>

    <details class="qr-details" open>
      <summary><span>1. Extracted Facts, Timing &amp; Data Provenance</span> ${uiSourceBadge('actual')}</summary>
      <div class="qr-details-body">
        <div class="qr-kv-list">
          <div class="qr-kv-row"><div class="qr-kv-key">Caller Classification</div><div class="qr-kv-val">${item.call ? esc(item.call.callerClassification) : 'No linked call event'} <span class="qr-prov">Source: ${item.call ? esc(item.call.source) : 'Unavailable'}</span></div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Masked Caller &amp; Status</div><div class="qr-kv-val">${item.call ? `${esc(item.call.callerMasked || 'Hidden / Unavailable')} · ${esc(item.call.callStatus)}` : 'Unavailable'}</div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Measured Call Length</div><div class="qr-kv-val num">${item.call ? (item.call.durationMs !== null ? fmtD(item.call.durationMs) : 'Duration unavailable (not fabricated)') : 'N/A'} <span class="qr-prov">Audio &amp; speech transcripts: Never collected</span></div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Payment Message Status</div><div class="qr-kv-val">${item.payment ? esc(item.payment.paymentStatus) : 'No payment message linked yet'}</div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Extracted Amount &amp; Ref</div><div class="qr-kv-val">${item.payment ? `${item.payment.amount !== null ? inr(item.payment.amount) : 'Amount not found'} · ${esc(item.payment.txType)}${item.payment.accountMasked ? ' · ' + esc(item.payment.accountMasked) : ''}${item.payment.upiRef ? ' · Ref ' + esc(item.payment.upiRef) : ''}` : 'N/A'}</div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Sanitized SMS Excerpt</div><div class="qr-kv-val">${item.payment ? esc(item.payment.redactedSummary) : 'N/A'} <span class="qr-prov">OTPs/PINs/passwords are stripped and never stored</span></div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Timing Relationship</div><div class="qr-kv-val">${esc(timingText)} <span class="qr-prov">Safety clue only — timing never proves causation</span></div></div>
          <div class="qr-kv-row"><div class="qr-kv-key">Guardian Notification Sync</div><div class="qr-kv-val num">${item.parentNotifiedCount} alert notification(s) recorded</div></div>
        </div>
      </div>
    </details>

    <details class="qr-details" open>
      <summary><span>2. AI Safety Summary</span> <span class="${item.aiReport.available ? 'badge-live' : 'badge-fb'}">${item.aiReport.available ? 'LIVE GEMINI AI' : 'FALLBACK RULES'}</span></summary>
      <div class="qr-details-body">
        <p style="margin:0 0 8px">${esc(item.aiReport.summary.plainExplanation)}</p>
        <p style="margin:0 0 8px"><b>Timing context:</b> ${esc(item.aiReport.summary.timingRelationshipNote)}</p>
        <p style="margin:0 0 8px"><b>Caller feedback:</b> ${esc(item.aiReport.summary.questionnaireInterpretation)}</p>
        <b>Recommended Actions</b>
        <ul>${item.aiReport.summary.recommendedActions.map((act) => `<li>${esc(act)}</li>`).join('')}</ul>
        <p class="mut" style="margin:8px 0 0">${esc(item.aiReport.summary.uncertaintyStatement)}</p>
      </div>
    </details>

    <details class="qr-details" open>
      <summary><span>3. Shared Cross-Module Caller &amp; SMS Intelligence</span> ${uiBadge(`${item.sharedIntelligence?.length || 0} Match(es)`, (item.sharedIntelligence?.length || 0) > 0 ? 'MEDIUM' : 'LOW')}</summary>
      <div class="qr-details-body">
        ${renderSharedIntelItemsHtml(item.sharedIntelligence || [], 'Call Watch')}
      </div>
    </details>

    ${
      item.callRisk.riskLevel !== 'Low Risk' ||
      item.paymentRisk.riskLevel !== 'Low Risk' ||
      item.criticalWarningActive
        ? (() => {
            const firstEntityId = item.sharedIntelligence?.[0]?.entityId || '';
            const callerHash = item.call?.callerHash || '';
            const whyExpanded = S.cwWhyExpandedId === item.correlationId;
            return `<div class="qr-risk-panel" style="margin-top:12px;border-color:var(--amb)">
              <div class="row" style="justify-content:space-between;margin-bottom:6px">
                <b>Guardian Safe Decision Assistant</b>
                ${uiBadge('Advisory Only — Never Auto-Blocks', 'MEDIUM')}
              </div>
              <p class="mut" style="margin:0 0 8px;font-size:13px">Stay calm and verify independently. Never share OTP, UPI PIN, passwords, or screen-sharing apps (AnyDesk/TeamViewer). You remain in full control.</p>
              <div class="row" style="gap:8px;flex-wrap:wrap">
                <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="cwToggleWhyFlagged('${esc(item.correlationId)}')">${whyExpanded ? 'Hide why flagged' : 'View why this call was flagged'}</button>
                <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="switchTab('fam')">Verify caller (Safe Word)</button>
                <button type="button" class="r" style="min-height:32px;padding:4px 10px" onclick="cwReportSuspiciousCaller('${esc(item.correlationId)}','${esc(firstEntityId)}')" ${S.busy.cw ? 'disabled' : ''}>Report this number</button>
                <button type="button" class="t" style="min-height:32px;padding:4px 10px" onclick="cwContactParent('${esc(item.correlationId)}')" ${S.busy.cw ? 'disabled' : ''}>Contact my parent</button>
                <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="cwMarkCallerTrusted('${esc(item.correlationId)}','${esc(firstEntityId)}','${esc(callerHash)}')" ${S.busy.cw ? 'disabled' : ''}>Mark as trusted</button>
                <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="switchTab('alerts')">View related security incidents</button>
              </div>
              ${
                whyExpanded
                  ? `<div class="warn" style="margin-top:10px;font-size:13px">
                      <b>Detailed Flagging Signals:</b>
                      <ul style="margin:4px 0 0">${item.callRisk.supportingEvidence
                        .concat(item.paymentRisk.supportingEvidence)
                        .map((ev) => `<li>${esc(ev)}</li>`)
                        .join('')}</ul>
                    </div>`
                  : ''
              }
            </div>`;
          })()
        : ''
    }
  </div>`;
}

function renderCwQuestionnaireCard(item: CwTimelineItem): string {
  const id = item.correlationId;
  return `<div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:6px">
      <div>
        <h2 class="t-section" style="margin:0">Quick Unknown-Caller Safety Check</h2>
        <p class="mut" style="margin:2px 0 0">${esc(item.questionnaireReason || 'Optional check to refine Call Risk & Payment Risk accuracy.')}</p>
      </div>
      ${cwRiskBadge(item.callRisk.riskLevel)}
    </div>
    <div class="g">
      <div>
        <label for="cwq-ask-${esc(id)}">What did the caller ask you to do?</label>
        <select id="cwq-ask-${esc(id)}">
          <option value="none_or_normal">Normal conversation / delivery / no financial request</option>
          <option value="send_money">Asked me to send money or pay a fee</option>
          <option value="approve_request">Asked me to approve a UPI collect request</option>
          <option value="verify_kyc_or_bank">Claimed bank KYC / card / account would be blocked</option>
          <option value="share_otp_pin">Asked for an OTP, UPI PIN, or password</option>
          <option value="install_remote_app">Asked me to install AnyDesk / TeamViewer / screen-share app</option>
        </select>

        <label for="cwq-urg-${esc(id)}">Did they create urgency, secrecy, or threats?</label>
        <select id="cwq-urg-${esc(id)}">
          <option value="no">No urgency or threat</option>
          <option value="yes_urgent">Yes — urged immediate payment right now</option>
          <option value="yes_threatened">Yes — threatened arrest, legal action, or account freeze</option>
          <option value="unsure">Not sure</option>
        </select>
      </div>
      <div>
        <label for="cwq-crd-${esc(id)}">Did they ask for OTP, PIN, passwords, or remote screen access?</label>
        <select id="cwq-crd-${esc(id)}">
          <option value="no">No</option>
          <option value="yes_otp_pin_password">Yes — asked for OTP, UPI PIN, or password</option>
          <option value="yes_remote_access">Yes — asked for remote access / screen share</option>
        </select>

        <label for="cwq-emo-${esc(id)}">How did the call leave you feeling?</label>
        <select id="cwq-emo-${esc(id)}">
          <option value="calm">Calm / confident</option>
          <option value="worried">Slightly unsure or worried</option>
          <option value="pressured_or_confused">Pressured, rushed, or confused</option>
        </select>
      </div>
    </div>
    <div class="row">
      <button type="button" onclick="cwSubmitQuestionnaire('${esc(id)}')" ${S.busy.cw ? 'disabled' : ''}>Submit answers &amp; update assessment</button>
      <button type="button" class="s" onclick="cwDismissQuestionnaire('${esc(id)}')" ${S.busy.cw ? 'disabled' : ''}>Dismiss / Ask later</button>
    </div>
  </div>`;
}

function renderCallWatcherTab(): string {
  const cw = S.callWatcher;
  const settings = cw?.settings;
  const c = S.cur;
  const l = S.calls[0];
  const a = S.alert;

  if (!settings || !settings.consentGiven) {
    return `<div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h1 class="t-page" style="margin:0">AI Call Watcher &amp; Payment Correlation</h1>
            <p class="mut" style="margin:4px 0 0">One-time informed activation before any call timing or payment SMS correlation is enabled.</p>
          </div>
          ${cwRiskBadge(settings?.monitoringState === 'revoked' ? 'Critical Risk' : 'Inconclusive', settings?.monitoringState === 'revoked' ? 'Consent Revoked' : 'Not Activated')}
        </div>
        <div class="alert-warn" style="margin-top:12px">
          <b>Strict Audio Privacy Guarantee:</b> Guardian NEVER listens to, records, accesses call audio, or transcribes phone conversations.
        </div>
        <ul>
          <li><b>Call Metadata Used:</b> Caller status (Saved / Unknown / Private / Unavailable), timestamps, and call duration (when available).</li>
          <li><b>Payment SMS / Notification Extraction:</b> Extracts only amount, status, transaction type, and masked account/ref — raw SMS, OTPs, PINs, and passwords are never stored.</li>
          <li><b>AI Timing Correlation:</b> Detects suspicious timing windows (such as a payment alert during or right after an unknown call) as advisory safety clues, never proof of causation.</li>
          <li><b>Parent / Guardian Sharing:</b> Syncs alerts with your linked guardian only when your Guardian Alerts consent is enabled and monitoring is not paused.</li>
          <li><b>Platform &amp; Play Policy Reality:</b> A web browser cannot automatically intercept live Android/iOS calls or SMS messages; browser mode uses explicit user-assisted logging &amp; live timing tools, while native OS automation requires a separate Android Companion app with Google Play–compliant permissions.</li>
          <li><b>Full User Control:</b> Pause monitoring or revoke consent permanently at any time below.</li>
        </ul>
        <div class="row" style="margin-top:14px">
          <button type="button" class="t" onclick="cwConsentAction('activate')" ${S.busy.cw ? 'disabled' : ''}>${S.busy.cw ? 'Activating…' : 'Activate AI Call Watcher (Metadata & Timing Only)'}</button>
        </div>
      </div>
      ${note()}`;
  }

  const isPaused = settings.monitoringState === 'paused';
  const protectionStatus = !S.online
    ? 'Offline intelligence'
    : settings.protectionStatus || (isPaused ? 'Protection unavailable' : 'Protection partially active');
  const protectionTone: 'LOW' | 'MEDIUM' | 'HIGH' =
    protectionStatus === 'Protection active'
      ? 'LOW'
      : protectionStatus === 'Background execution restricted' ||
          protectionStatus === 'Permission required' ||
          protectionStatus === 'Protection unavailable'
        ? 'HIGH'
        : 'MEDIUM';
  const timeline = cw?.timeline || [];
  const selectedItem =
    timeline.find((x) => x.correlationId === S.cwSelectedId) || timeline[0] || null;
  const pendingQ = cw?.pendingQuestionnaire || null;
  const scr = S.cwScreenResult;

  return `<div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h1 class="t-page" style="margin:0">AI Call Watcher &amp; Payment Correlation</h1>
          <p class="mut" style="margin:4px 0 0">Status: <b>${esc(settings.effectiveStatusLabel)}</b> · Last event: <span class="num">${settings.lastEventAt ? new Date(settings.lastEventAt).toLocaleString() : 'None yet'}</span></p>
          <p class="mut" style="margin:2px 0 0;font-size:12.5px">${esc(!S.online ? 'Offline: using local cached caller intelligence; online guardian notifications queued.' : settings.protectionDetail || '')}</p>
        </div>
        <div class="row">
          ${uiBadge(protectionStatus, protectionTone)}
        </div>
      </div>

      <div class="qr-risk-split" style="margin-top:12px">
        <div class="qr-risk-panel">
          <b>Android &amp; Browser Protection Readiness</b>
          <ul style="margin:6px 0 0;font-size:13px">
            <li>Call Screening Role: <b>${esc((settings.callScreeningRoleState || 'unavailable_in_browser').replace(/_/g, ' '))}</b></li>
            <li>Call State Access: <b>${esc(settings.permissionCallState.replace(/_/g, ' '))}</b></li>
            <li>Call Log Duration Fallback: <b>${esc((settings.permissionCallLogState || 'unavailable_in_browser').replace(/_/g, ' '))}</b></li>
            <li>Notification Permission: <b>${esc(settings.permissionNotifState.replace(/_/g, ' '))}</b></li>
            <li>Background Execution: <b>${settings.batteryRestricted ? 'Battery restricted (may delay background work)' : esc((settings.appLifecycleState || 'web_foreground').replace(/_/g, ' '))}</b></li>
          </ul>
          <p class="mut" style="font-size:12px;margin:6px 0 0">Web browsers cannot run Android CallScreeningService automatically; use Live Timing Watch &amp; Pre-Screen below, or connect the Android companion build.</p>
        </div>
        <div class="qr-risk-panel">
          <b>Consent &amp; Controls</b>
          <div class="sw" style="margin-top:8px">
            <input type="checkbox" ${settings.notifyUnknownCalls ? 'checked' : ''} onchange="cwToggleUnknownNotify(this.checked)" aria-label="Notify on unknown incoming calls">
            <span style="font-size:13.5px">Notify me on every unknown incoming call</span>
          </div>
          <div class="row" style="margin-top:10px">
            ${
              isPaused
                ? `<button type="button" class="t" onclick="cwConsentAction('resume')" ${S.busy.cw ? 'disabled' : ''}>Resume Watcher</button>`
                : `<button type="button" class="s" onclick="cwConsentAction('pause')" ${S.busy.cw ? 'disabled' : ''}>Pause Monitoring</button>`
            }
            <button type="button" class="r" onclick="cwConsentAction('revoke')" ${S.busy.cw ? 'disabled' : ''}>Revoke Consent</button>
          </div>
        </div>
      </div>

      <div class="qr-risk-panel" style="margin-top:10px">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <b>Pre-Screen Incoming Caller (Fast Local Lookup — Never Auto-Blocks)</b>
          ${uiBadge('CallScreeningService Model', 'NEUTRAL')}
        </div>
        <div class="g" style="gap:10px">
          <div>
            <label for="cw-screen-num">Caller phone number</label>
            <input id="cw-screen-num" value="${esc(S.cwScreenNumber)}" placeholder="e.g. 9876543210">
          </div>
          <div>
            <label for="cw-screen-cls">Device contact status</label>
            <select id="cw-screen-cls">
              <option value="Unknown Number">Unknown Number</option>
              <option value="Known Contact">Known Contact</option>
              <option value="Private/Hidden Number">Private/Hidden Number</option>
              <option value="Unavailable Caller Information">Unavailable Caller Information</option>
            </select>
          </div>
        </div>
        <button type="button" class="s" onclick="cwScreenCallerNumber()" ${S.busy.cw ? 'disabled' : ''}>Screen Caller Now</button>
        ${
          scr
            ? `<div class="warn" style="margin-top:10px">
                <div class="row" style="justify-content:space-between">
                  <b>${esc(scr.callerMasked || scr.callerClassification)} · ${esc(scr.reputationClass)}</b>
                  <div class="row">
                    ${cwRiskBadge(scr.riskLevel)}
                    ${uiBadge(`${scr.lookupLatencyMs}ms local`, 'LOW')}
                  </div>
                </div>
                <p class="mut" style="margin:4px 0;font-size:13px"><b>Evidence:</b> ${esc(scr.evidence.join(' · '))}</p>
                <p style="margin:4px 0 0;font-size:13px"><b>Guidance:</b> ${esc(scr.recommendations[0] || '')}</p>
              </div>`
            : ''
        }
      </div>
    </div>

    ${
      S.cwOfflineQueue.length > 0
        ? uiAlert(
            `${S.cwOfflineQueue.length} event(s) queued offline on this device. Guardian notifications are NOT delivered while offline and will sync automatically when connectivity returns. ${S.online ? `<button type="button" class="s" style="min-height:30px;padding:2px 10px;margin-left:8px" onclick="cwFlushOfflineQueue()">Sync queued events now</button>` : ''}`,
            { title: 'Offline Queue:', tone: 'warn' }
          )
        : ''
    }

    <div class="stat-grid">
      ${uiStatCard('Recent Calls (7d)', cw.summary.recentCallsCount, 'Metadata & duration only', { source: 'actual' })}
      ${uiStatCard('Unknown Calls (7d)', cw.summary.unknownCallsCount, 'Unknown / private callers', { source: 'actual' })}
      ${uiStatCard('Payment Messages (7d)', cw.summary.paymentEventsCount, 'OTPs & PINs stripped', { source: 'actual' })}
      ${uiStatCard('Correlated Alerts', cw.summary.correlatedAlertsCount, `${cw.summary.criticalAlertsCount} critical warning(s)`, { source: 'actual' })}
    </div>

    ${note()}
    ${pendingQ ? renderCwQuestionnaireCard(pendingQ) : ''}

    <div class="g-2">
      <div class="card">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <h2 class="t-section" style="margin:0">Live Call Duration Watch</h2>
          ${uiSourceBadge('simulated')}
        </div>
        <p class="mut" style="margin:4px 0 10px">Start the timer when a call begins to measure duration only (zero audio or transcription).</p>
        ${
          c
            ? `<p><span class="pill HIGH">AI timing watch active</span> Call length: <b class="num" data-cs="${c.s}">${fmtD(Date.now() - c.s)}</b> · ${c.known ? 'saved contact' : 'unknown number'}</p>
               ${aiBox(c.ai)}
               <div class="row" style="margin-top:8px">
                 <button type="button" onclick="payAlert()">Payment alert received now</button>
                 <button type="button" class="r" onclick="callEnd()">End call</button>
               </div>`
            : `<label for="ck">Caller</label>
               <select id="ck"><option value="unknown">Unknown number</option><option value="known">Saved contact</option></select>
               <div class="row">
                 <button type="button" onclick="callStart()">Incoming call (start AI timer)</button>
                 <button type="button" class="s" onclick="demoCall()">Demo: 4m unknown call</button>
                 <button type="button" class="s" onclick="payAlert()">Payment alert now</button>
               </div>`
        }
        ${l ? `<p class="mut" style="margin:10px 0 0">Last live call: <b class="num">${fmtD(l.dur)}</b> · ${l.known ? 'saved contact' : 'unknown number'}</p>` : ''}
      </div>

      <div class="card">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <h2 class="t-section" style="margin:0">Log Call &amp; Payment SMS</h2>
          ${uiSourceBadge('actual')}
        </div>
        <div class="g" style="gap:10px">
          <div>
            <label for="cw-call-cls">Caller classification</label>
            <select id="cw-call-cls">
              <option value="Unknown Number">Unknown Number</option>
              <option value="Known Contact">Known Contact</option>
              <option value="Private/Hidden Number">Private/Hidden Number</option>
              <option value="Unavailable Caller Information">Unavailable Caller Information</option>
            </select>
          </div>
          <div>
            <label for="cw-call-status">Call status</label>
            <select id="cw-call-status">
              <option value="Answered">Answered</option>
              <option value="Missed">Missed</option>
              <option value="Rejected">Rejected</option>
              <option value="Unavailable">Unavailable</option>
            </select>
          </div>
        </div>
        <div class="g" style="gap:10px">
          <div>
            <label for="cw-caller-id">Caller number (masked &amp; hashed, optional)</label>
            <input id="cw-caller-id" placeholder="e.g. 9876543210">
          </div>
          <div>
            <label for="cw-call-dur">Duration in seconds (leave empty if unavailable)</label>
            <input id="cw-call-dur" type="number" min="0" placeholder="e.g. 210">
          </div>
        </div>
        <button type="button" class="s" onclick="cwLogCall()" ${isPaused || S.busy.cw ? 'disabled' : ''}>Record Call Metadata</button>

        <hr class="divider">
        <label for="cw-pay-sender">SMS / App Sender (optional)</label>
        <input id="cw-pay-sender" placeholder="e.g. HDFCBK or UPI Alert">
        <label for="cw-pay-msg">Share Payment SMS or Notification (OTPs/PINs auto-stripped)</label>
        <textarea id="cw-pay-msg" rows="2" placeholder="Paste bank debit SMS, UPI collect request, or alert summary"></textarea>
        <div class="row">
          <button type="button" onclick="cwLogPaymentMsg()" ${isPaused || S.busy.cw ? 'disabled' : ''}>Analyze &amp; Correlate</button>
          <button type="button" class="s" onclick="cwDemoScenario('scam_corr')" ${isPaused || S.busy.cw ? 'disabled' : ''}>Demo: Unknown Call + Collect</button>
          <button type="button" class="s" onclick="cwDemoScenario('promo')" ${isPaused || S.busy.cw ? 'disabled' : ''}>Demo: Promo SMS</button>
          <button type="button" class="s" onclick="cwDemoScenario('high_legit')" ${isPaused || S.busy.cw ? 'disabled' : ''}>Demo: High ₹32k Known</button>
        </div>
      </div>
    </div>

    ${
      a
        ? card(
            a.r,
            `<p>${esc(a.txt)}</p>
             <p class="mut">Measured call length: <b class="num">${fmtD(a.callDurMs)}</b> · Gap to payment alert: <b class="num">${a.duringCall ? '0m 0s (during active call)' : fmtD(a.gapMs)}</b> · Suspicious timing patterns detected: <b class="num">${S.pats}</b></p>
             ${aiBox(a.ai)}`
          )
        : ''
    }

    ${selectedItem ? renderCwEventReport(selectedItem) : ''}

    ${renderSectionSharedIntelCard(
      'call_scam',
      'Call Scam & Caller Watch',
      selectedItem?.sharedIntelligence || [],
      selectedItem
        ? `Call Risk: ${selectedItem.callRisk.riskLevel} · Payment Risk: ${selectedItem.paymentRisk.riskLevel}`
        : undefined
    )}

    ${uiCard(
      'Call Watcher Event Timeline',
      timeline.length
        ? timeline
            .map(
              (ev) =>
                `<div class="qr-history-row">
                  <div>
                    <b>${esc(ev.call ? ev.call.callerClassification : 'No call linked')} · ${esc(ev.payment ? ev.payment.paymentStatus : 'No payment linked')}</b>
                    <div class="mut" style="font-size:12.5px">${ev.payment && ev.payment.amount !== null ? inr(ev.payment.amount) + ' · ' : ''}${ev.duringCall ? 'During active call' : ev.timeDiffMs !== null ? 'Gap ' + fmtD(ev.timeDiffMs) : 'Timing pending'} · ${new Date(ev.createdAt).toLocaleString()}</div>
                  </div>
                  <div class="row">
                    ${cwRiskBadge(ev.callRisk.riskLevel, 'Call: ' + ev.callRisk.riskLevel)}
                    ${cwRiskBadge(ev.paymentRisk.riskLevel, 'Pay: ' + ev.paymentRisk.riskLevel)}
                    <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="cwSelectEvent('${esc(ev.correlationId)}')">Inspect</button>
                  </div>
                </div>`
            )
            .join('')
        : '<p class="mut" style="margin:0">No Call Watcher correlation events recorded yet. Log a call or share a payment SMS above, or run one of the Demo scenarios.</p>',
      { badgeHtml: uiSourceBadge('actual') }
    )}
    ${S.gsi ? renderGsiCapabilityCard(S.gsi.capabilities) : ''}`;
}
