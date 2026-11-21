// Emergency Payment Protection Client Controller, Android Capability Probe & Bank Verification Launcher

import { S, R, apiJson } from './01_core_state_and_scam_detection';

export type EppDurationOption = '30m' | '1h' | '3h' | '6h' | 'manual';
export type EppBankServiceType =
  | 'upi_block'
  | 'debit_block'
  | 'credit_block'
  | 'netbanking_security'
  | 'fraud_report';

export interface EppBankEntry {
  id: string;
  bankName: string;
  shortCode: string;
  supportPhone: string;
  upiBlockUrl: string | null;
  debitBlockUrl: string | null;
  creditBlockUrl: string | null;
  netbankingUrl: string | null;
  fraudReportUrl: string | null;
  verificationStatus: 'verified' | 'unverified' | 'phone_only';
  lastVerifiedAt: number;
  notes: string;
  updatedAt: number;
}

export interface EppAppInfo {
  packageName: string;
  label: string;
  category: 'UPI' | 'Bank' | 'Wallet';
}

export interface EppLockSessionRecord {
  id: string;
  activatedByName: string;
  activatedByRole: string;
  status: 'active' | 'unlocked' | 'expired';
  selectedApps: EppAppInfo[];
  durationOption: string;
  durationMinutes: number | null;
  manualUntilUnlock: boolean;
  osEnforcementMode: string;
  devicePlatform: string;
  deviceCapabilityNote: string;
  notifiedGuardiansCount: number;
  activatedAt: number;
  expiresAt: number | null;
  remainingMs: number | null;
  unlockedAt: number | null;
  unlockedByName: string | null;
}

export interface EppBankActionLog {
  id: string;
  bankId: string;
  bankName: string;
  serviceType: EppBankServiceType;
  launchType: 'official_url' | 'support_phone';
  bankConfirmedByUser: boolean;
  createdAt: number;
  confirmedAt: number | null;
}

export interface EppAuditEntry {
  id: string;
  actorName: string;
  action: string;
  details: string;
  hash: string;
  createdAt: number;
}

export interface EppDashboardState {
  familyOwnerId: string;
  canModify: boolean;
  supportedApps: EppAppInfo[];
  banks: EppBankEntry[];
  activeSession: EppLockSessionRecord | null;
  sessions: EppLockSessionRecord[];
  bankActions: EppBankActionLog[];
  auditTrail: EppAuditEntry[];
  familyNotificationPolicy: {
    activeGuardiansCount: number;
    guardianAlertsEnabled: boolean;
    guardianNames: string[];
  };
}

export interface EppDeviceCapability {
  osLockSupported: boolean;
  osEnforcementMode: 'native_device_owner' | 'guardian_advisory_session';
  platform: string;
  headline: string;
  disclosure: string;
  permissionsNote: string;
}

interface NativeGuardianAndroidBridge {
  isDeviceOwnerActive?: () => boolean;
  getAndroidSdkInt?: () => number;
  setPackagesSuspended?: (packagesJson: string, suspended: boolean, expiresAtMs: number) => boolean;
}

const EPP_LOCAL_LOCK_KEY = 'guardian_epp_active_session';

export function detectDevicePaymentLockCapability(): EppDeviceCapability {
  const win = typeof window !== 'undefined'
    ? (window as unknown as { GuardianAndroidBridge?: NativeGuardianAndroidBridge })
    : undefined;
  const bridge = win?.GuardianAndroidBridge;

  if (bridge && typeof bridge.isDeviceOwnerActive === 'function' && bridge.isDeviceOwnerActive()) {
    const sdk = typeof bridge.getAndroidSdkInt === 'function' ? bridge.getAndroidSdkInt() : 0;
    return {
      osLockSupported: true,
      osEnforcementMode: 'native_device_owner',
      platform: sdk ? `android_device_owner_sdk_${sdk}` : 'android_device_owner',
      headline: 'Android Device Owner Management Active',
      disclosure:
        'DevicePolicyManager can temporarily suspend selected payment apps on this managed device. Suspending an app does NOT cancel server-side UPI mandates, auto-debits, or card charges — use "Block Payments at My Bank" to freeze bank channels.',
      permissionsNote:
        'Uses legitimate Android Enterprise DevicePolicyManager.setPackagesSuspended(). Zero covert Accessibility monitoring; Emergency Dialer (112/1930) and OS Settings remain accessible.',
    };
  }

  const ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
  const isAndroidUa = /Android/i.test(ua);

  return {
    osLockSupported: false,
    osEnforcementMode: 'guardian_advisory_session',
    platform: isAndroidUa ? 'android_non_managed_browser' : 'web_browser',
    headline: isAndroidUa
      ? 'Standard Android / Non-Device-Owner Environment'
      : 'Web Browser Session (OS App Suspension Unavailable)',
    disclosure:
      'Normal Android apps and web browsers cannot block UPI payments inside PhonePe, Google Pay, or Paytm, nor suspend third-party apps without Android Enterprise Device Owner management. Activating below creates an audited Guardian Safety Lockout Window and alerts authorized family members, while real transaction freezes must be performed via "Open Bank\'s Official Blocking Options".',
    permissionsNote:
      'Guardian never abuses Accessibility Services for covert app interception and never locks emergency calling (112 / 1930) or accessibility tools.',
  };
}

function saveLocalLockSnapshot(session: EppLockSessionRecord | null): void {
  try {
    if (session && session.status === 'active') {
      window.localStorage.setItem(
        EPP_LOCAL_LOCK_KEY,
        JSON.stringify({ id: session.id, expiresAt: session.expiresAt, manualUntilUnlock: session.manualUntilUnlock })
      );
    } else {
      window.localStorage.removeItem(EPP_LOCAL_LOCK_KEY);
    }
  } catch {
    // ignore storage errors
  }
}

export async function loadEppDashboard(ownerId?: string): Promise<void> {
  if (!S.user) return;
  try {
    const target =
      ownerId || (S.user.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : '');
    const qs = target ? `?ownerId=${encodeURIComponent(target)}` : '';
    const data = await apiJson<EppDashboardState>(`/api/epp/dashboard${qs}`);
    S.epp = data;
    saveLocalLockSnapshot(data.activeSession);
    if (!S.eppSelectedBankId && data.banks.length > 0) {
      S.eppSelectedBankId = data.banks[0].id;
    }
  } catch {
    // preserve gracefully
  }
}

export function eppSelectBank(bankId: string): void {
  S.eppSelectedBankId = bankId;
  S.eppPreviewService = null;
  R();
}

export function eppSetBankSearch(q: string): void {
  const el = document.getElementById('epp-bank-search') as HTMLInputElement | null;
  const start = el?.selectionStart ?? null;
  S.eppBankSearch = q;
  R();
  const next = document.getElementById('epp-bank-search') as HTMLInputElement | null;
  if (next) {
    next.focus();
    if (start !== null && typeof next.setSelectionRange === 'function') {
      try {
        next.setSelectionRange(start, start);
      } catch {
        // ignore
      }
    }
  }
}

export function eppPreviewBankService(serviceType: EppBankServiceType | null): void {
  S.eppPreviewService = serviceType;
  R();
}

function openExternalSafeHref(href: string, isTel: boolean): boolean {
  if (typeof document === 'undefined') return false;
  try {
    if (isTel) {
      if (!/^tel:[0-9+\-\s()]+$/.test(href)) return false;
      const a = document.createElement('a');
      a.href = href;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return true;
    }
    const parsed = new URL(href);
    if (parsed.protocol !== 'https:') return false;
    const a = document.createElement('a');
    a.href = parsed.toString();
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    return true;
  } catch {
    return false;
  }
}

export async function eppLaunchBankService(
  bankId: string,
  serviceType: EppBankServiceType,
  launchType?: 'official_url' | 'support_phone'
): Promise<void> {
  S.busy.epp = true;
  S.note = '';
  R();
  try {
    const res = await apiJson<{
      id: string;
      bankName: string;
      supportPhone: string;
      serviceType: string;
      launchType: 'official_url' | 'support_phone';
      targetRef: string;
    }>('/api/epp/bank-action', {
      method: 'POST',
      body: JSON.stringify({ bankId, serviceType, launchType }),
    });

    const isTel = res.launchType === 'support_phone' || res.targetRef.startsWith('tel:');
    openExternalSafeHref(res.targetRef, isTel);

    await loadEppDashboard();
    S.eppPreviewService = null;
    S.note =
      res.launchType === 'support_phone'
        ? `Initiated official support dial (${res.supportPhone}) for ${res.bankName}. Guardian has NOT blocked your bank service — confirm directly with your bank.`
        : `Opened ${res.bankName}'s verified official portal. Guardian does NOT automatically block bank services; complete the request on your bank's page.`;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not open bank blocking service.';
  } finally {
    S.busy.epp = false;
    R();
  }
}

export async function eppConfirmBankCompleted(logId: string, confirmed: boolean): Promise<void> {
  S.busy.epp = true;
  R();
  try {
    await apiJson(`/api/epp/bank-action/${encodeURIComponent(logId)}/confirm`, {
      method: 'POST',
      body: JSON.stringify({ confirmed }),
    });
    await loadEppDashboard();
    S.note = confirmed
      ? 'Recorded that you confirmed completion directly with your bank.'
      : 'Cleared bank confirmation tag.';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update confirmation.';
  } finally {
    S.busy.epp = false;
    R();
  }
}

export function eppToggleApp(pkg: string): void {
  const cur = new Set(S.eppSelectedApps);
  if (cur.has(pkg)) {
    cur.delete(pkg);
  } else {
    cur.add(pkg);
  }
  S.eppSelectedApps = Array.from(cur);
  R();
}

export function eppSelectAllApps(selectAll: boolean): void {
  if (!selectAll) {
    S.eppSelectedApps = [];
  } else {
    S.eppSelectedApps = (S.epp?.supportedApps || []).map((a) => a.packageName);
  }
  R();
}

export function eppAddCustomApp(): void {
  const input = document.getElementById('epp-custom-pkg') as HTMLInputElement | null;
  const val = (input?.value || '').trim();
  if (!val || !/^[a-zA-Z0-9._-]{3,100}$/.test(val)) {
    S.note = 'Enter a valid Android app package ID (e.g. com.example.upi) or app identifier.';
    R();
    return;
  }
  if (/dialer|phone|emergency|accessibility|systemui/i.test(val)) {
    S.note = 'Emergency calling, phone dialer, and accessibility apps are protected and cannot be restricted.';
    R();
    return;
  }
  if (!S.eppSelectedApps.includes(val)) {
    S.eppSelectedApps = [...S.eppSelectedApps, val];
  }
  if (input) input.value = '';
  R();
}

export function eppSetDuration(opt: EppDurationOption): void {
  S.eppDuration = opt;
  R();
}

export function eppToggleAuthAck(checked: boolean): void {
  S.eppAuthAck = checked;
  R();
}

export function eppToggleBankEditor(open?: boolean): void {
  S.eppBankEditorOpen = typeof open === 'boolean' ? open : !S.eppBankEditorOpen;
  R();
}

export async function eppActivateLock(): Promise<void> {
  if (S.busy.epp) return;
  if (!S.eppSelectedApps.length) {
    S.note = 'Select at least one payment app before activating Emergency Payment Lock.';
    R();
    return;
  }
  if (!S.eppAuthAck) {
    S.note = 'Please review the device capability disclosure and check explicit authorization before activating.';
    R();
    return;
  }

  const cap = detectDevicePaymentLockCapability();
  S.busy.epp = true;
  S.note = '';
  R();
  try {
    let osMode = cap.osEnforcementMode;
    let capNote = cap.disclosure;

    const bridge = (window as unknown as { GuardianAndroidBridge?: NativeGuardianAndroidBridge }).GuardianAndroidBridge;
    if (cap.osLockSupported && bridge?.setPackagesSuspended) {
      const durMin =
        S.eppDuration === '30m'
          ? 30
          : S.eppDuration === '1h'
            ? 60
            : S.eppDuration === '3h'
              ? 180
              : S.eppDuration === '6h'
                ? 360
                : 0;
      const exp = durMin ? Date.now() + durMin * 60_000 : 0;
      const ok = bridge.setPackagesSuspended(JSON.stringify(S.eppSelectedApps), true, exp);
      if (!ok) {
        osMode = 'guardian_advisory_session';
        capNote = 'Native Android bridge declined package suspension; recorded advisory safety lockout session instead.';
      }
    }

    const res = await apiJson<{
      sessionId: string;
      deduplicated: boolean;
      notificationsSent: number;
    }>('/api/epp/lock/activate', {
      method: 'POST',
      body: JSON.stringify({
        selectedPackages: S.eppSelectedApps,
        durationOption: S.eppDuration,
        explicitConsent: true,
        osEnforcementMode: osMode,
        devicePlatform: cap.platform,
        deviceCapabilityNote: capNote,
      }),
    });

    await loadEppDashboard();
    S.eppAuthAck = false;
    S.note =
      osMode === 'native_device_owner'
        ? `Emergency Payment App Lock active on Device Owner (${res.notificationsSent} family alert(s) sent). Remember to block bank channels directly for complete protection.`
        : `Emergency Safety Lockout active (${res.notificationsSent} family alert(s) sent). OS app suspension is unavailable in browser/non-Device-Owner mode — use "Block Payments at My Bank" below for real bank freezes.`;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not activate Emergency Payment Lock.';
  } finally {
    S.busy.epp = false;
    R();
  }
}

export async function eppUnlockLock(): Promise<void> {
  if (S.busy.epp) return;
  S.busy.epp = true;
  R();
  try {
    const cap = detectDevicePaymentLockCapability();
    const bridge = (window as unknown as { GuardianAndroidBridge?: NativeGuardianAndroidBridge }).GuardianAndroidBridge;
    if (cap.osLockSupported && bridge?.setPackagesSuspended && S.epp?.activeSession) {
      const pkgs = S.epp.activeSession.selectedApps.map((a) => a.packageName);
      bridge.setPackagesSuspended(JSON.stringify(pkgs), false, 0);
    }

    await apiJson('/api/epp/lock/unlock', { method: 'POST', body: JSON.stringify({}) });
    await loadEppDashboard();
    S.note = 'Emergency Payment Lock manually unlocked. Family members have been updated.';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not unlock payment lock.';
  } finally {
    S.busy.epp = false;
    R();
  }
}

export async function eppSaveBankDirectoryEntry(): Promise<void> {
  if (S.busy.epp) return;
  const g = (id: string) => document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
  const bankId = (g('epp-ed-id')?.value || '').trim();
  const bankName = (g('epp-ed-name')?.value || '').trim();
  const shortCode = (g('epp-ed-code')?.value || '').trim();
  const supportPhone = (g('epp-ed-phone')?.value || '').trim();
  const upiBlockUrl = (g('epp-ed-upi')?.value || '').trim() || null;
  const debitBlockUrl = (g('epp-ed-debit')?.value || '').trim() || null;
  const creditBlockUrl = (g('epp-ed-credit')?.value || '').trim() || null;
  const netbankingUrl = (g('epp-ed-net')?.value || '').trim() || null;
  const fraudReportUrl = (g('epp-ed-fraud')?.value || '').trim() || null;
  const notes = (g('epp-ed-notes')?.value || '').trim();

  S.busy.epp = true;
  S.note = '';
  R();
  try {
    const endpoint = bankId ? `/api/epp/banks/${encodeURIComponent(bankId)}` : '/api/epp/banks';
    const method = bankId ? 'PUT' : 'POST';
    const res = await apiJson<{ bank: EppBankEntry }>(endpoint, {
      method,
      body: JSON.stringify({
        bankName,
        shortCode,
        supportPhone,
        upiBlockUrl,
        debitBlockUrl,
        creditBlockUrl,
        netbankingUrl,
        fraudReportUrl,
        notes,
      }),
    });
    await loadEppDashboard();
    S.eppSelectedBankId = res.bank.id;
    S.eppBankEditorOpen = false;
    S.note = `Verified & updated official URLs for ${res.bank.bankName} dynamically.`;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save verified bank URL.';
  } finally {
    S.busy.epp = false;
    R();
  }
}

export function eppFormatCountdown(expiresAt: number | null, manual: boolean): string {
  if (manual || !expiresAt) return 'UNTIL MANUAL UNLOCK';
  const diff = Math.max(0, expiresAt - Date.now());
  if (diff <= 0) return '00:00:00 (EXPIRED)';
  const totalSec = Math.floor(diff / 1000);
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  return [hrs, mins, secs].map((n) => String(n).padStart(2, '0')).join(':');
}
