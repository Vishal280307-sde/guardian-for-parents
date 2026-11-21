// AI chat assistant, learning quiz, login, registration, recovery, and parent-guardian linking

import {
  S,
  R,
  rules,
  ACT,
  apiJson,
  resolveApiUrl,
  syncStateFromServer,
  getSessionToken,
  setSessionToken,
} from './01_core_state_and_scam_detection';
import { evaluateScamEngine } from './scamEngine';
import { stopQrCamera } from './03_call_watch_and_qr_check';

export async function chat(): Promise<void> {
  if (S.busy.chat) return;
  const i = document.getElementById('cq') as HTMLTextAreaElement | null;
  const x = i ? i.value.trim() : '';
  if (!x) return;

  S.busy.chat = true;
  if (i) i.value = '';
  S.chat.push({ r: 'u', x });
  S.chat.push({ r: 'a', x: '…' });
  R();
  const r = rules(x, S.medThreshold, S.highThreshold);
  let out = '';
  let live = false;
  try {
    const token = getSessionToken();
    const resp = await fetch(resolveApiUrl('/api/ai/chat'), {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        history: S.chat.slice(0, -1).slice(-6),
        message: x.slice(0, 600),
        signals: r.sig,
        lang: S.lang,
      }),
    });
    if (!resp.ok) throw new Error('Chat request failed');
    const data = await resp.json();
    if (!data || typeof data.text !== 'string') throw new Error('Invalid chat response');
    out = data.text;
    live = true;
  } catch {
    out =
      (r.score >= S.medThreshold
        ? 'Please do not pay or share any code right now. ' + (ACT[r.level][1] || ACT[r.level][0])
        : 'I could not find strong warning signs, but stay careful and verify independently. ') +
      ' (Fallback guidance: live AI unavailable.)';
  } finally {
    S.busy.chat = false;
  }
  S.chat[S.chat.length - 1] = { r: 'a', x: out, live };
  R();
}

export async function mic(id: string): Promise<void> {
  const win = window as unknown as {
    SpeechRecognition?: new () => {
      lang: string;
      interimResults: boolean;
      maxAlternatives: number;
      onresult: ((ev: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
      onerror: (() => void) | null;
      start: () => void;
    };
    webkitSpeechRecognition?: new () => {
      lang: string;
      interimResults: boolean;
      maxAlternatives: number;
      onresult: ((ev: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
      onerror: (() => void) | null;
      start: () => void;
    };
  };
  const Rec = win.SpeechRecognition || win.webkitSpeechRecognition;
  if (!Rec) {
    S.note = 'Voice input is not available here. Please type.';
    R();
    return;
  }
  try {
    const rec = new Rec();
    rec.lang = S.lang === 'hi' ? 'hi-IN' : 'en-IN';
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.onresult = (ev) => {
      const text = ev.results?.[0]?.[0]?.transcript || '';
      const el = document.getElementById(id) as HTMLTextAreaElement | HTMLInputElement | null;
      if (el && text) {
        el.value += (el.value ? ' ' : '') + text;
      }
    };
    rec.onerror = () => {
      S.note = 'Voice input could not start. Please type.';
      R();
    };
    rec.start();
  } catch {
    S.note = 'Voice input is not available here. Please type.';
    R();
  }
}

export const speak = (i: number): void => {
  const m = S.chat[i];
  if (m && window.speechSynthesis) {
    const u = new SpeechSynthesisUtterance(m.x);
    u.lang = S.lang === 'hi' ? 'hi-IN' : 'en-IN';
    speechSynthesis.speak(u);
  }
};

/* ---- Learn & Evaluation ---- */
export const QZ: [string, string[], number, string][] = [
  [
    'SIMULATED: A caller says "SBI officer" and wants your OTP to avoid account blocking.',
    ['Share the OTP', 'Hang up and call the bank on its saved number', 'Pay a small fee'],
    1,
    'Banks never ask for your OTP.',
  ],
  [
    'SIMULATED: A QR code says "scan to receive your lottery prize".',
    ['Scan and enter PIN', 'Ignore it, scanning sends money', 'Forward it'],
    1,
    'You never enter a PIN to receive money.',
  ],
  [
    'SIMULATED: A voice like your son asks for ₹50,000 urgently and says keep it secret.',
    ['Ask the family safe word and call his saved number', 'Send half now', 'Send it all'],
    0,
    'Verify through a channel you trust.',
  ],
];

export function ans(i: number): void {
  const c = QZ[S.q][2] === i;
  if (c) S.score++;
  S.note = (c ? 'Correct. ' : 'Not quite. ') + QZ[S.q][3];
  S.q = (S.q + 1) % QZ.length;
  R();
}

export function runEval(): void {
  S.evalResult = evaluateScamEngine(S.medThreshold);
  R();
}

/* ---- Auth ---- */
export async function login(): Promise<void> {
  if (S.busy.auth || !S.booted) return;
  const lu = document.getElementById('lu') as HTMLInputElement | null;
  const lp = document.getElementById('lp') as HTMLInputElement | null;
  const username = lu ? lu.value.trim().toLowerCase() : S.draftLoginUser.trim().toLowerCase();
  const password = lp ? lp.value : '';

  S.draftLoginUser = username;
  if (!username || !password) {
    S.err = 'Enter both username and password.';
    R();
    return;
  }

  S.busy.auth = true;
  S.err = '';
  R();
  try {
    const res = await apiJson<{
      user: { id: string; username: string; name: string; role: 'parent' | 'guardian' };
      sessionToken?: string;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, role: S.role }),
    });
    if (res.sessionToken) {
      setSessionToken(res.sessionToken);
    }
    S.user = res.user;
    S.tab = res.user.role === 'parent' ? 'home' : 'req';
    S.recoveryDisplay = '';
    S.draftLoginUser = '';
    await syncStateFromServer(true);
  } catch (err) {
    setSessionToken(null);
    S.user = null;
    S.err = err instanceof Error ? err.message : 'Login failed.';
  } finally {
    S.busy.auth = false;
    R();
  }
}

export async function reg(): Promise<void> {
  if (S.busy.auth) return;
  const ru = document.getElementById('ru') as HTMLInputElement | null;
  const rn = document.getElementById('rn') as HTMLInputElement | null;
  const rp = document.getElementById('rp') as HTMLInputElement | null;
  const username = ru ? ru.value.trim().toLowerCase() : '';
  const name = rn ? rn.value.trim() : '';
  const password = rp ? rp.value : '';

  S.busy.auth = true;
  S.err = '';
  R();
  try {
    const res = await apiJson<{ recoveryCode: string; message: string }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, name, password, role: S.role }),
    });
    S.mode = 'login';
    S.recoveryDisplay = res.recoveryCode;
    S.err = res.message;
  } catch (err) {
    S.err = err instanceof Error ? err.message : 'Registration failed.';
  } finally {
    S.busy.auth = false;
    R();
  }
}

export async function recoverAccount(): Promise<void> {
  if (S.busy.auth) return;
  const ru = document.getElementById('rcu') as HTMLInputElement | null;
  const rc = document.getElementById('rcc') as HTMLInputElement | null;
  const rp = document.getElementById('rcp') as HTMLInputElement | null;
  S.busy.auth = true;
  S.err = '';
  R();
  try {
    const res = await apiJson<{ recoveryCode: string; message: string }>('/api/auth/recover', {
      method: 'POST',
      body: JSON.stringify({
        username: ru?.value.trim().toLowerCase() || '',
        recoveryCode: rc?.value.trim() || '',
        newPassword: rp?.value || '',
      }),
    });
    S.mode = 'login';
    S.recoveryDisplay = res.recoveryCode;
    S.err = res.message;
  } catch (err) {
    S.err = err instanceof Error ? err.message : 'Recovery failed.';
  } finally {
    S.busy.auth = false;
    R();
  }
}

export async function logout(): Promise<void> {
  try {
    await apiJson('/api/auth/logout', { method: 'POST' });
  } catch {
    // clear client session anyway
  }
  stopQrCamera(true);
  setSessionToken(null);
  S.user = null;
  S.draftLoginUser = '';
  S.reqs = [];
  S.audit = [];
  S.links = [];
  S.linkedParents = [];
  S.notifications = [];
  S.qrScans = [];
  S.qrReport = null;
  S.qrStatus = { state: 'idle' };
  S.callWatcher = null;
  S.linkedCallWatcherEvents = [];
  S.cwSelectedId = null;
  S.cwOfflineQueue = [];
  S.gsi = null;
  S.linkedGsiOverview = null;
  S.linkAnalysis = null;
  S.gsiAlertFilter = 'all';
  S.gcih = null;
  S.linkedGcihSync = [];
  S.gcihOfflineQueue = [];
  S.gcihSyncStatus = 'Locally detected';
  S.gcihFeedbackNote = '';
  S.res = null;
  S.pay = null;
  S.qr = null;
  S.cur = null;
  S.alert = null;
  S.note = '';
  S.emergencyStatus = null;
  S.busy.emergency = false;
  S.epp = null;
  S.eppSelectedBankId = '';
  S.eppBankSearch = '';
  S.eppPreviewService = null;
  S.eppAuthAck = false;
  S.eppBankEditorOpen = false;
  S.busy.epp = false;
  emergencyInFlight = null;
  R();
}

/* ---- Parent-Guardian Linking & Privacy Helpers ---- */
export async function createInvite(isSecondary = false): Promise<void> {
  try {
    const res = await apiJson<{ inviteCode: string }>('/api/links/invite', {
      method: 'POST',
      body: JSON.stringify({ isSecondary }),
    });
    S.note = `Share invite code ${res.inviteCode} privately with your ${isSecondary ? 'secondary ' : ''}guardian.`;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not create invite.';
    R();
  }
}

export async function acceptInvite(): Promise<void> {
  const el = document.getElementById('invCode') as HTMLInputElement | null;
  const inviteCode = el ? el.value.trim() : '';
  try {
    await apiJson('/api/links/accept', {
      method: 'POST',
      body: JSON.stringify({ inviteCode }),
    });
    S.note = 'Parent-guardian link verified and active.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not accept invite.';
    R();
  }
}

export async function revokeLink(id: string): Promise<void> {
  try {
    await apiJson(`/api/links/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
    S.note = 'Guardian link revoked.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not revoke link.';
    R();
  }
}

export async function saveConsents(): Promise<void> {
  // Keep thresholds monotonically ordered
  if (S.loadHighMax < S.loadModerateMax) S.loadHighMax = S.loadModerateMax;
  if (S.loadVeryHighMin < S.loadHighMax) S.loadVeryHighMin = S.loadHighMax;
  try {
    await apiJson('/api/privacy/consents', {
      method: 'PUT',
      body: JSON.stringify({
        ...S.c,
        limit: S.limit,
        medThreshold: S.medThreshold,
        highThreshold: S.highThreshold,
        retentionDays: S.retentionDays,
        loadModerateMax: S.loadModerateMax,
        loadHighMax: S.loadHighMax,
        loadVeryHighMin: S.loadVeryHighMin,
        redAlertCooldownSec: S.redAlertCooldownSec,
      }),
    });
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save privacy settings.';
    R();
  }
}

export async function saveQrPrefs(): Promise<void> {
  try {
    await apiJson('/api/qr/preferences', {
      method: 'PUT',
      body: JSON.stringify(S.qrPrefs),
    });
    S.note = 'QR notification preferences saved.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save QR notification preferences.';
    R();
  }
}

export const OFFICIAL_CYBER_CRIME_PORTAL_URL = 'https://cybercrime.gov.in/';

let emergencyInFlight: Promise<void> | null = null;
let lastPortalLaunchAt = 0;

export function openOfficialCyberCrimePortal(forceManual = false): boolean {
  if (typeof document === 'undefined' || typeof window === 'undefined') return false;
  const now = Date.now();
  if (!forceManual && now - lastPortalLaunchAt < 4000) {
    return false;
  }
  lastPortalLaunchAt = now;
  try {
    const parsed = new URL(OFFICIAL_CYBER_CRIME_PORTAL_URL);
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'cybercrime.gov.in') {
      return false;
    }
    const anchor = document.createElement('a');
    anchor.href = parsed.toString();
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    return true;
  } catch {
    return false;
  }
}

export async function confirmRevokeAllGuardians(): Promise<boolean> {
  try {
    const res = await apiJson<{ ok?: boolean }>('/api/privacy/revoke-guardians', { method: 'POST' });
    if (!res || res.ok !== true) {
      throw new Error('Administrator revocation could not be verified.');
    }
    S.confirmAction = null;
    S.note = 'All guardian access removed.';
    await syncStateFromServer();
    return true;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Failed to remove guardian access.';
    R();
    return false;
  }
}

export async function emergencyHelpAction(): Promise<void> {
  if (S.busy.emergency || emergencyInFlight) {
    return emergencyInFlight || undefined;
  }
  if (
    S.emergencyStatus?.state === 'success' &&
    Date.now() - S.emergencyStatus.updatedAt < 4000
  ) {
    return;
  }
  const run = (async () => {
    S.busy.emergency = true;
    S.emergencyStatus = {
      state: 'in_progress',
      message: 'Emergency action initiated. Revoking administrator access...',
      portalOpened: false,
      updatedAt: Date.now(),
    };
    R();
    try {
      const revoked = await confirmRevokeAllGuardians();
      if (revoked) {
        const portalOpened = openOfficialCyberCrimePortal(false);
        S.emergencyStatus = {
          state: 'success',
          message:
            'Emergency action initiated. Administrator revocation status: Successful. Redirecting you to the official Cyber Crime Portal.',
          portalOpened,
          updatedAt: Date.now(),
        };
        S.note = S.emergencyStatus.message;
      } else {
        S.emergencyStatus = {
          state: 'failed',
          message:
            'Administrator revocation could not be completed. You can still proceed to the official Cyber Crime Portal.',
          portalOpened: false,
          updatedAt: Date.now(),
        };
        S.note = S.emergencyStatus.message;
      }
    } finally {
      S.busy.emergency = false;
      emergencyInFlight = null;
      R();
    }
  })();
  emergencyInFlight = run;
  return run;
}

export function dismissEmergencyStatus(): void {
  S.emergencyStatus = null;
  R();
}

export async function confirmDeleteAllData(): Promise<void> {
  try {
    await apiJson('/api/privacy/data', { method: 'DELETE' });
    stopQrCamera(true);
    S.confirmAction = null;
    S.user = null;
    S.reqs = [];
    S.audit = [];
    S.qrScans = [];
    S.qrReport = null;
    S.qrStatus = { state: 'idle' };
    S.callWatcher = null;
    S.linkedCallWatcherEvents = [];
    S.cwSelectedId = null;
    S.cwOfflineQueue = [];
    S.gsi = null;
    S.linkedGsiOverview = null;
    S.linkAnalysis = null;
    S.gsiAlertFilter = 'all';
    S.gcih = null;
    S.linkedGcihSync = [];
    S.gcihOfflineQueue = [];
    S.gcihSyncStatus = 'Locally detected';
    S.gcihFeedbackNote = '';
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.removeItem('guardian_gcih_offline_queue');
        window.localStorage.removeItem('guardian_cw_offline_queue');
      }
    } catch {
      // ignore storage restrictions
    }
    S.emergencyStatus = null;
    S.busy.emergency = false;
    S.epp = null;
    S.eppSelectedBankId = '';
    S.eppBankSearch = '';
    S.eppPreviewService = null;
    S.eppAuthAck = false;
    S.eppBankEditorOpen = false;
    S.busy.epp = false;
    emergencyInFlight = null;
    S.res = null;
    S.pay = null;
    S.qr = null;
    S.alert = null;
    S.cur = null;
    S.calls = [];
    S.timingEvents = [];
    S.pats = 0;
    S.chat = [];
    S.inc = [];
    S.hasSafeWord = false;
    R();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not delete data.';
    R();
  }
}

export async function exportData(): Promise<void> {
  try {
    const data = await apiJson('/api/privacy/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `guardian-data-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    S.note = 'Your safety data export has downloaded.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Export failed.';
    R();
  }
}

export async function markNotificationsRead(): Promise<void> {
  try {
    await apiJson('/api/notifications/read', { method: 'POST' });
    await syncStateFromServer();
  } catch {
    // ignore
  }
}

export async function gsiFeedback(
  incidentId: string,
  action: 'acknowledge' | 'resolve' | 'confirm_threat' | 'false_positive',
  note?: string
): Promise<void> {
  try {
    await apiJson(`/api/gsi/incidents/${encodeURIComponent(incidentId)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ action, note }),
    });
    S.note =
      action === 'false_positive'
        ? 'Marked as false positive. Threat intelligence confidence has been downgraded accordingly.'
        : action === 'confirm_threat'
          ? 'Threat confirmed and recorded in local family threat intelligence.'
          : action === 'resolve'
            ? 'Incident marked resolved.'
            : 'Incident acknowledged.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update GSI incident feedback.';
    R();
  }
}
