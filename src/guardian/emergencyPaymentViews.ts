// Guardian Emergency Payment Protection — Premium Blue Cybersecurity Command UI

import { S, esc } from './01_core_state_and_scam_detection';
import {
  detectDevicePaymentLockCapability,
  eppFormatCountdown,
  type EppBankEntry,
  type EppBankServiceType,
  type EppDurationOption,
  type EppLockSessionRecord,
} from './emergencyPaymentClient';
import { uiAlert, uiBadge, uiCard, uiIcon, uiSourceBadge } from './ui';

interface BankServiceMeta {
  type: EppBankServiceType;
  label: string;
  shortDesc: string;
  explanation: string;
  urlField: keyof Pick<
    EppBankEntry,
    'upiBlockUrl' | 'debitBlockUrl' | 'creditBlockUrl' | 'netbankingUrl' | 'fraudReportUrl'
  >;
}

const BANK_SERVICES: BankServiceMeta[] = [
  {
    type: 'upi_block',
    label: 'UPI Blocking / Disable',
    shortDesc: 'Freeze outgoing UPI ID & handles',
    explanation:
      'Opens your selected bank’s verified UPI management / de-registration guidance or helpline so you can immediately disable UPI handles and VPA transfers at the bank.',
    urlField: 'upiBlockUrl',
  },
  {
    type: 'debit_block',
    label: 'Debit Card Blocking',
    shortDesc: 'Hotlist ATM / POS / online debit card',
    explanation:
      'Opens your selected bank’s official debit card hotlisting / instant block page or verified emergency number so stolen or compromised cards cannot be debited.',
    urlField: 'debitBlockUrl',
  },
  {
    type: 'credit_block',
    label: 'Credit Card Blocking',
    shortDesc: 'Freeze international & online card spend',
    explanation:
      'Opens your selected bank’s official credit card freeze / loss reporting channel so you can stop card-not-present or contactless transactions directly.',
    urlField: 'creditBlockUrl',
  },
  {
    type: 'netbanking_security',
    label: 'Net Banking Security',
    shortDesc: 'Lock digital banking & reset access',
    explanation:
      'Opens your bank’s official NetBanking security portal so you can suspend internet banking login, revoke active sessions, or disable third-party beneficiaries.',
    urlField: 'netbankingUrl',
  },
  {
    type: 'fraud_report',
    label: 'Bank Fraud Reporting',
    shortDesc: 'Report unauthorized debit & claim timeline',
    explanation:
      'Opens your bank’s official unauthorized transaction / cyber-fraud reporting desk. Reporting quickly helps establish RBI zero-liability dispute timestamps.',
    urlField: 'fraudReportUrl',
  },
];

const DURATION_OPTIONS: { id: EppDurationOption; label: string }[] = [
  { id: '30m', label: '30 minutes' },
  { id: '1h', label: '1 hour' },
  { id: '3h', label: '3 hours' },
  { id: '6h', label: '6 hours' },
  { id: 'manual', label: 'Until manually unlocked' },
];

export function eppScrollToBanks(): void {
  const el = document.getElementById('epp-bank-section');
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function renderActiveSessionBanner(
  active: EppLockSessionRecord | null,
  canModify: boolean
): string {
  const cap = detectDevicePaymentLockCapability();
  const isActive = Boolean(active && active.status === 'active');
  const countdownText = isActive && active
    ? eppFormatCountdown(active.expiresAt, active.manualUntilUnlock)
    : 'INACTIVE';

  return `<section class="epp-cyber-hero card-anim">
    <div class="epp-hero-grid">
      <div>
        <div class="row" style="justify-content:space-between;margin-bottom:10px">
          <span class="epp-status-banner ${isActive ? 'active' : ''}">
            ${uiIcon('shield', 15)}
            ${isActive ? 'PROTECTION ACTIVE' : 'PROTECTION INACTIVE'}
          </span>
          ${uiBadge(
            cap.osLockSupported ? 'Device Owner OS Suspension' : 'Advisory Safety Lockout Mode',
            cap.osLockSupported ? 'LOW' : 'MEDIUM'
          )}
        </div>
        <h1 class="t-page" style="margin:0 0 8px;color:#FFFFFF">Guardian Emergency Payment Protection</h1>
        <p class="mut" style="margin:0 0 14px">
          Rapid emergency response to pause payment app usage during scam pressure and jump straight to your bank’s verified official payment-blocking channels — without ever collecting banking PINs, passwords, or OTPs.
        </p>
        <div class="row">
          <button type="button" class="epp-btn-sapphire" onclick="eppScrollToBanks()">
            ${uiIcon('building', 16)}Open Bank's Official Blocking Options
          </button>
          <a class="btn r" href="tel:1930" title="Call India National Cyber Crime Helpline 1930">
            ${uiIcon('phone', 16)}Helpline 1930
          </a>
          ${
            isActive && canModify
              ? `<button type="button" class="s" onclick="eppUnlockLock()" ${S.busy.epp ? 'disabled' : ''}>${uiIcon('lock', 15)}Manual Early Unlock</button>`
              : ''
          }
        </div>
      </div>

      <div class="epp-countdown-box ${isActive ? 'active epp-ring-glow' : ''}">
        <div class="t-label" style="color:#93C5FD;margin:0">
          ${isActive ? 'Emergency Lockout Countdown' : 'Current Lock Status'}
        </div>
        <div class="epp-countdown-time" ${
          isActive && active && !active.manualUntilUnlock && active.expiresAt
            ? `data-epp-exp="${active.expiresAt}"`
            : ''
        }>${esc(countdownText)}</div>
        <div class="mut" style="font-size:12.5px">
          ${
            isActive && active
              ? `Activated by <b>${esc(active.activatedByName)}</b> · ${new Date(active.activatedAt).toLocaleTimeString()} · ${active.selectedApps.length} app(s) selected`
              : 'No active payment lockout window. Activate below or open official bank blocking immediately.'
          }
        </div>
      </div>
    </div>
  </section>`;
}

function renderActiveSessionDetails(
  active: EppLockSessionRecord,
  canModify: boolean
): string {
  const isDeviceOwner = active.osEnforcementMode === 'native_device_owner';
  return `<section class="epp-panel epp-ring-glow card-anim" style="border-color:#2563EB">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h2 class="t-section" style="margin:0">${uiIcon('lock', 18)} Active Emergency Payment Lock Session</h2>
        <p class="mut" style="margin:2px 0 0">
          Activated by <b>${esc(active.activatedByName)}</b> on <span class="num">${new Date(active.activatedAt).toLocaleString()}</span> · Guardian alerts sent: <b class="num">${active.notifiedGuardiansCount}</b>
        </p>
      </div>
      ${uiBadge(isDeviceOwner ? 'OS Package Suspension Active' : 'Advisory Lockout Window', isDeviceOwner ? 'LOW' : 'MEDIUM')}
    </div>

    ${uiAlert(
      isDeviceOwner
        ? 'Selected apps are suspended via Android DevicePolicyManager on this managed device. Suspending an app does NOT cancel server-side UPI mandates, auto-debits, or netbanking — complete bank-side blocking below if credentials were exposed.'
        : 'Standard Android & browser sessions cannot forcibly freeze third-party apps (PhonePe / GPay / Paytm) or cancel bank-side mandates. This session records an audited emergency lockout and alerts your family while you freeze channels directly at your bank below.',
      {
        title: 'Critical Protection Scope Notice:',
        tone: isDeviceOwner ? 'info' : 'warn',
        actionsHtml: `<button type="button" class="s" onclick="eppScrollToBanks()">Open Bank's Official Blocking Options</button>`,
      }
    )}

    <div class="qr-kv-list" style="margin:10px 0">
      <div class="qr-kv-row">
        <div class="qr-kv-key">Selected Payment Apps</div>
        <div class="qr-kv-val">${active.selectedApps.map((a) => `${esc(a.label)} (<code>${esc(a.packageName)}</code>)`).join(' · ')}</div>
      </div>
      <div class="qr-kv-row">
        <div class="qr-kv-key">Remaining Duration</div>
        <div class="qr-kv-val num">
          <b ${!active.manualUntilUnlock && active.expiresAt ? `data-epp-exp="${active.expiresAt}"` : ''}>
            ${esc(eppFormatCountdown(active.expiresAt, active.manualUntilUnlock))}
          </b>
          ${active.expiresAt ? ` (auto-expires at ${new Date(active.expiresAt).toLocaleString()})` : ' (until manually unlocked)'}
        </div>
      </div>
      <div class="qr-kv-row">
        <div class="qr-kv-key">Emergency &amp; Accessibility Safeguard</div>
        <div class="qr-kv-val">Phone dialer, emergency calls (112 / 1930), OS Settings, and Accessibility services are never restricted.</div>
      </div>
    </div>

    ${
      canModify
        ? `<div class="row" style="margin-top:12px">
            <button type="button" class="r" onclick="eppUnlockLock()" ${S.busy.epp ? 'disabled' : ''}>
              ${uiIcon('lock', 15)}Unlock Payment Protection Early
            </button>
            <button type="button" class="epp-btn-sapphire" onclick="eppScrollToBanks()">
              ${uiIcon('building', 15)}Open Bank's Official Blocking Options
            </button>
          </div>`
        : `<p class="mut" style="margin:8px 0 0">Guardian view is read-only. Only the account owner can modify or unlock this protection session.</p>`
    }
  </section>`;
}

function renderBankDirectoryEditor(selectedBank: EppBankEntry | null): string {
  if (!S.eppBankEditorOpen) return '';
  const b = selectedBank;
  return `<div class="warn" style="margin-top:12px;border-color:rgba(37,99,235,0.45)">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h3 class="t-card" style="margin:0">Update &amp; Verify Official Bank Blocking URLs</h3>
        <p class="mut" style="margin:2px 0 0;font-size:12.5px">Dynamically update verified HTTPS bank support pages or add a new bank entry without rebuilding the app. Private IPs and non-HTTPS URLs are rejected.</p>
      </div>
      <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="eppToggleBankEditor(false)">Close</button>
    </div>
    <input type="hidden" id="epp-ed-id" value="${esc(b?.id || '')}">
    <div class="g">
      <div>
        <label for="epp-ed-name">Bank Name</label>
        <input id="epp-ed-name" value="${esc(b?.bankName || '')}" placeholder="e.g. HDFC Bank">
        <label for="epp-ed-code">Short Code</label>
        <input id="epp-ed-code" value="${esc(b?.shortCode || '')}" placeholder="e.g. HDFC">
        <label for="epp-ed-phone">Official Verified Support Phone</label>
        <input id="epp-ed-phone" value="${esc(b?.supportPhone || '')}" placeholder="e.g. 1800 1600">
        <label for="epp-ed-notes">Verification Notes</label>
        <input id="epp-ed-notes" value="${esc(b?.notes || '')}" placeholder="Official toll-free or portal verification detail">
      </div>
      <div>
        <label for="epp-ed-upi">UPI Blocking HTTPS URL</label>
        <input id="epp-ed-upi" value="${esc(b?.upiBlockUrl || '')}" placeholder="https://...">
        <label for="epp-ed-debit">Debit Card Blocking HTTPS URL</label>
        <input id="epp-ed-debit" value="${esc(b?.debitBlockUrl || '')}" placeholder="https://...">
        <label for="epp-ed-credit">Credit Card Blocking HTTPS URL</label>
        <input id="epp-ed-credit" value="${esc(b?.creditBlockUrl || '')}" placeholder="https://...">
        <label for="epp-ed-net">Net Banking Security HTTPS URL</label>
        <input id="epp-ed-net" value="${esc(b?.netbankingUrl || '')}" placeholder="https://...">
        <label for="epp-ed-fraud">Bank Fraud Reporting HTTPS URL</label>
        <input id="epp-ed-fraud" value="${esc(b?.fraudReportUrl || '')}" placeholder="https://...">
      </div>
    </div>
    <div class="row">
      <button type="button" class="epp-btn-sapphire" onclick="eppSaveBankDirectoryEntry()" ${S.busy.epp ? 'disabled' : ''}>
        ${S.busy.epp ? 'Verifying & Saving…' : 'Verify HTTPS & Save Bank Entry'}
      </button>
      <button type="button" class="s" onclick="document.getElementById('epp-ed-id').value='';document.getElementById('epp-ed-name').value='';document.getElementById('epp-ed-code').value='';document.getElementById('epp-ed-phone').value='';document.getElementById('epp-ed-upi').value='';document.getElementById('epp-ed-debit').value='';document.getElementById('epp-ed-credit').value='';document.getElementById('epp-ed-net').value='';document.getElementById('epp-ed-fraud').value='';document.getElementById('epp-ed-notes').value='';">
        Clear for New Bank
      </button>
    </div>
  </div>`;
}

function renderOfficialBankBlockingSection(
  banks: EppBankEntry[],
  canModify: boolean
): string {
  const q = S.eppBankSearch.trim().toLowerCase();
  const filteredBanks = q
    ? banks.filter(
        (b) =>
          b.bankName.toLowerCase().includes(q) ||
          b.shortCode.toLowerCase().includes(q) ||
          b.supportPhone.toLowerCase().includes(q)
      )
    : banks;

  const selectedBank =
    banks.find((b) => b.id === S.eppSelectedBankId) ||
    filteredBanks[0] ||
    banks[0] ||
    null;

  const previewMeta = S.eppPreviewService
    ? BANK_SERVICES.find((s) => s.type === S.eppPreviewService) || null
    : null;
  const previewUrl =
    selectedBank && previewMeta ? selectedBank[previewMeta.urlField] : null;

  const logs = S.epp?.bankActions || [];

  return `<section id="epp-bank-section" class="epp-panel card-anim">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h2 class="t-section" style="margin:0">${uiIcon('building', 18)} Block Payments at My Bank</h2>
        <p class="mut" style="margin:2px 0 0">Select your bank to open its verified official HTTPS emergency-blocking portal or verified toll-free support number.</p>
      </div>
      <div class="row">
        ${uiBadge('Zero Bank Credentials Collected', 'LOW')}
        ${canModify ? `<button type="button" class="s" style="min-height:34px;padding:4px 10px" onclick="eppToggleBankEditor()">${S.eppBankEditorOpen ? 'Hide URL Editor' : 'Update / Verify URLs'}</button>` : ''}
      </div>
    </div>

    ${uiAlert(
      'Guardian NEVER claims to have blocked your bank account, UPI ID, or cards on its own, and NEVER asks for netbanking passwords, UPI PINs, ATM PINs, CVVs, or OTPs. Always complete blocking directly on your bank’s official portal or verified phone line.',
      { title: 'Honest Bank Blocking Boundary:', tone: 'info' }
    )}

    <div class="g" style="margin-top:12px">
      <div>
        <label for="epp-bank-search">Search Verified Bank Directory</label>
        <input id="epp-bank-search" type="search" value="${esc(S.eppBankSearch)}" oninput="eppSetBankSearch(this.value)" placeholder="Search e.g. SBI, HDFC, ICICI, Axis, 1930…">
      </div>
      <div>
        <label for="epp-bank-select">Select Your Bank</label>
        <select id="epp-bank-select" onchange="eppSelectBank(this.value)">
          ${filteredBanks
            .map(
              (b) =>
                `<option value="${esc(b.id)}" ${selectedBank?.id === b.id ? 'selected' : ''}>${esc(b.bankName)} (${esc(b.shortCode)}) — ${esc(b.supportPhone)}</option>`
            )
            .join('')}
        </select>
      </div>
    </div>

    <div class="row" style="margin-bottom:10px;gap:6px">
      ${filteredBanks
        .slice(0, 8)
        .map(
          (b) => `<button type="button" class="seg-btn ${selectedBank?.id === b.id ? 'on' : ''}" style="min-height:34px;padding:4px 12px;border:1px solid var(--line)" onclick="eppSelectBank('${esc(b.id)}')">${esc(b.shortCode)}</button>`
        )
        .join('')}
    </div>

    ${
      selectedBank
        ? `<div class="qr-risk-panel" style="border-color:rgba(37,99,235,0.35)">
            <div class="row" style="justify-content:space-between;margin-bottom:6px">
              <div>
                <b style="font-size:16px">${esc(selectedBank.bankName)}</b>
                <span class="mut"> · Official Helpline: <b class="num">${esc(selectedBank.supportPhone)}</b></span>
              </div>
              <div class="row">
                ${uiBadge(
                  selectedBank.verificationStatus === 'verified' ? 'Verified Official Directory' : selectedBank.verificationStatus,
                  selectedBank.verificationStatus === 'verified' ? 'LOW' : 'MEDIUM'
                )}
                ${
                  canModify && selectedBank.supportPhone
                    ? `<button type="button" class="r" style="min-height:34px;padding:4px 12px" onclick="eppLaunchBankService('${esc(selectedBank.id)}','fraud_report','support_phone')" ${S.busy.epp ? 'disabled' : ''}>${uiIcon('phone', 14)}Call ${esc(selectedBank.supportPhone)}</button>`
                    : selectedBank.supportPhone
                      ? `<a class="btn r" style="min-height:34px;padding:4px 12px" href="tel:${esc(selectedBank.supportPhone.replace(/[^0-9+]/g, ''))}">${uiIcon('phone', 14)}Call ${esc(selectedBank.supportPhone)}</a>`
                      : ''
                }
              </div>
            </div>
            <p class="mut" style="margin:0 0 10px;font-size:13px">${esc(selectedBank.notes)} · Last verified: <span class="num">${new Date(selectedBank.lastVerifiedAt).toLocaleDateString()}</span></p>

            <div class="epp-service-grid">
              ${BANK_SERVICES.map((svc) => {
                const url = selectedBank[svc.urlField];
                const isSelected = S.eppPreviewService === svc.type;
                return `<button type="button" class="epp-service-btn ${isSelected ? 'selected' : ''}" onclick="eppPreviewBankService('${svc.type}')">
                  <b>${esc(svc.label)}</b>
                  <span class="mut" style="font-size:12px">${esc(svc.shortDesc)}</span>
                  <span style="font-size:11.5px;color:var(--accent-ink)">${url ? 'Official HTTPS + Helpline Ready' : 'Verified Helpline Only'}</span>
                </button>`;
              }).join('')}
            </div>

            ${
              previewMeta
                ? `<div class="warn" style="margin-top:12px;border-color:#2563EB;background:rgba(37,99,235,0.08)">
                    <div class="row" style="justify-content:space-between;margin-bottom:6px">
                      <b>${esc(previewMeta.label)} — ${esc(selectedBank.bankName)}</b>
                      <button type="button" class="s" style="min-height:30px;padding:2px 8px" onclick="eppPreviewBankService(null)">Close preview</button>
                    </div>
                    <p style="margin:0 0 8px;font-size:13.5px">${esc(previewMeta.explanation)}</p>
                    <p class="mut" style="margin:0 0 10px;font-size:12.5px">
                      Verified destination: ${previewUrl ? `<code>${esc(previewUrl)}</code>` : `Official phone line <code>${esc(selectedBank.supportPhone)}</code>`}
                    </p>
                    <div class="row">
                      ${
                        canModify
                          ? `${
                              previewUrl
                                ? `<button type="button" class="epp-btn-sapphire" onclick="eppLaunchBankService('${esc(selectedBank.id)}','${previewMeta.type}','official_url')" ${S.busy.epp ? 'disabled' : ''}>Open Verified Official Bank Page</button>`
                                : ''
                            }
                            <button type="button" class="s" onclick="eppLaunchBankService('${esc(selectedBank.id)}','${previewMeta.type}','support_phone')" ${S.busy.epp ? 'disabled' : ''}>
                              ${uiIcon('phone', 14)}Call Verified Helpline (${esc(selectedBank.supportPhone)})
                            </button>`
                          : `<span class="mut">Linked guardian view: ask the account owner to launch and confirm bank blocking directly.</span>`
                      }
                    </div>
                  </div>`
                : ''
            }
          </div>`
        : '<p class="mut">No matching bank found in the verified directory.</p>'
    }

    ${canModify ? renderBankDirectoryEditor(selectedBank) : ''}

    <div style="margin-top:14px">
      <div class="row" style="justify-content:space-between;margin-bottom:6px">
        <b style="font-size:14px">Recent Official Bank Blocking Actions</b>
        ${uiSourceBadge('actual')}
      </div>
      ${
        logs.length
          ? logs
              .slice(0, 6)
              .map(
                (lg) => `<div class="qr-history-row">
                  <div>
                    <b>${esc(lg.bankName)} — ${esc(lg.serviceType.replace(/_/g, ' ').toUpperCase())}</b>
                    <div class="mut" style="font-size:12.5px">
                      Launched via ${lg.launchType === 'support_phone' ? 'Official Helpline' : 'Official HTTPS Portal'} · <span class="num">${new Date(lg.createdAt).toLocaleString()}</span>
                    </div>
                  </div>
                  <div class="row">
                    ${uiBadge(
                      lg.bankConfirmedByUser ? 'User Confirmed Blocked at Bank' : 'Opened Official Page (Not Yet Confirmed)',
                      lg.bankConfirmedByUser ? 'LOW' : 'MEDIUM'
                    )}
                    ${
                      canModify
                        ? `<button type="button" class="s" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="eppConfirmBankCompleted('${esc(lg.id)}',${!lg.bankConfirmedByUser})" ${S.busy.epp ? 'disabled' : ''}>
                            ${lg.bankConfirmedByUser ? 'Unmark Confirmation' : 'I Confirmed Bank Blocked It'}
                          </button>`
                        : ''
                    }
                  </div>
                </div>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No official bank blocking links launched yet. Select a service above when you need to freeze UPI, cards, or NetBanking.</p>'
      }
    </div>
  </section>`;
}

function renderEmergencyPaymentAppLockSection(canModify: boolean): string {
  const cap = detectDevicePaymentLockCapability();
  const supportedApps = S.epp?.supportedApps || [];
  const selectedSet = new Set(S.eppSelectedApps);
  const customPackages = S.eppSelectedApps.filter(
    (p) => !supportedApps.some((a) => a.packageName === p)
  );
  const hasActive = Boolean(S.epp?.activeSession);

  return `<section class="epp-panel card-anim">
    <div class="row" style="justify-content:space-between;margin-bottom:8px">
      <div>
        <h2 class="t-section" style="margin:0">${uiIcon('lock', 18)} Emergency Payment App Lock</h2>
        <p class="mut" style="margin:2px 0 0">Select payment apps to include in your timed emergency lockout and send immediate family alerts.</p>
      </div>
      ${uiBadge(cap.headline, cap.osLockSupported ? 'LOW' : 'MEDIUM')}
    </div>

    ${uiAlert(
      `${cap.disclosure} ${cap.permissionsNote}`,
      {
        title: cap.osLockSupported ? 'Device Owner Enforcement & Bank Scope:' : 'Android / Browser OS Limitation Disclosure:',
        tone: cap.osLockSupported ? 'info' : 'warn',
        actionsHtml: `<button type="button" class="s" onclick="eppScrollToBanks()">Open Bank's Official Blocking Options</button>`,
      }
    )}

    ${
      !canModify
        ? uiAlert('Guardian account view is read-only. You will receive emergency alerts and countdown status automatically when the account owner activates Payment Lock.', { tone: 'info' })
        : `<div style="margin-top:12px">
            <div class="row" style="justify-content:space-between;margin-bottom:6px">
              <label style="margin:0">1. Choose Payment Apps (${S.eppSelectedApps.length} selected)</label>
              <div class="row" style="gap:6px">
                <button type="button" class="s" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="eppSelectAllApps(true)">Select all</button>
                <button type="button" class="s" style="min-height:32px;padding:3px 10px;font-size:12px" onclick="eppSelectAllApps(false)">Clear</button>
              </div>
            </div>

            <div class="epp-app-grid">
              ${supportedApps
                .map((app) => {
                  const isOn = selectedSet.has(app.packageName);
                  return `<button type="button" class="epp-app-chip ${isOn ? 'on' : ''}" onclick="eppToggleApp('${esc(app.packageName)}')" aria-pressed="${isOn}">
                    <div>
                      <b style="display:block;font-size:13.5px">${esc(app.label)}</b>
                      <span class="mut" style="font-size:11.5px">${esc(app.category)} · ${esc(app.packageName)}</span>
                    </div>
                    <span>${isOn ? uiBadge('Selected', 'LOW') : uiBadge('Off', 'NEUTRAL')}</span>
                  </button>`;
                })
                .join('')}
              ${customPackages
                .map(
                  (pkg) => `<button type="button" class="epp-app-chip on" onclick="eppToggleApp('${esc(pkg)}')" aria-pressed="true">
                    <div>
                      <b style="display:block;font-size:13.5px">${esc(pkg)}</b>
                      <span class="mut" style="font-size:11.5px">Custom App Package</span>
                    </div>
                    <span>${uiBadge('Selected', 'LOW')}</span>
                  </button>`
                )
                .join('')}
            </div>

            <div class="row" style="margin-top:8px">
              <input id="epp-custom-pkg" placeholder="Optional custom Android package ID (e.g. com.bank.upi)" style="flex:1;margin:0">
              <button type="button" class="s" onclick="eppAddCustomApp()">${uiIcon('plus', 14)}Add Custom App</button>
            </div>
            <p class="mut" style="margin:6px 0 12px;font-size:12.5px">Essential safety safeguard: phone dialer, emergency calls (112 / 1930), settings, and accessibility tools can never be added or restricted.</p>

            <label>2. Choose Lockout Duration</label>
            <div class="seg-group" role="group" aria-label="Emergency lock duration" style="margin-bottom:14px">
              ${DURATION_OPTIONS.map(
                (d) => `<button type="button" class="seg-btn ${S.eppDuration === d.id ? 'on' : ''}" onclick="eppSetDuration('${d.id}')">${esc(d.label)}</button>`
              ).join('')}
            </div>

            <div class="sw" style="padding:10px 12px;border:1px solid rgba(37,99,235,0.3);border-radius:10px;background:var(--elev)">
              <input id="epp-auth-ack" type="checkbox" ${S.eppAuthAck ? 'checked' : ''} onchange="eppToggleAuthAck(this.checked)" aria-label="Confirm emergency payment protection authorization">
              <span style="font-size:13.5px">
                I understand the platform limitations above, authorize activating Emergency Payment Protection for the selected duration, and consent to alerting my authorized linked guardians.
              </span>
            </div>

            <div class="row" style="margin-top:12px">
              <button type="button" class="epp-btn-sapphire" onclick="eppActivateLock()" ${S.busy.epp || !S.eppAuthAck || S.eppSelectedApps.length === 0 ? 'disabled' : ''}>
                ${uiIcon('shield', 16)}${S.busy.epp ? 'Activating…' : hasActive ? 'Update / Restart Emergency Payment Lock' : 'Activate Emergency Payment Protection'}
              </button>
              <button type="button" class="s" onclick="eppScrollToBanks()">
                Open Bank's Official Blocking Options
              </button>
            </div>
          </div>`
    }
  </section>`;
}

function renderFamilyAndAuditSection(): string {
  const epp = S.epp;
  const policy = epp?.familyNotificationPolicy;
  const sessions = epp?.sessions || [];
  const auditTrail = epp?.auditTrail || [];

  return `<div class="g-2">
    ${uiCard(
      'Family Emergency Alert Status',
      `<div class="qr-kv-list" style="margin-bottom:10px">
        <div class="qr-kv-row">
          <div class="qr-kv-key">Linked Active Guardians</div>
          <div class="qr-kv-val num">${policy?.activeGuardiansCount ?? 0} ${policy?.guardianNames?.length ? `(${esc(policy.guardianNames.join(', '))})` : ''}</div>
        </div>
        <div class="qr-kv-row">
          <div class="qr-kv-key">Guardian Alert Consent</div>
          <div class="qr-kv-val">${policy?.guardianAlertsEnabled ? uiBadge('Enabled — Alerts Delivered', 'LOW') : uiBadge('Paused or Disabled in Privacy', 'MEDIUM')}</div>
        </div>
        <div class="qr-kv-row">
          <div class="qr-kv-key">Data Shared in Family Alerts</div>
          <div class="qr-kv-val">Only who activated protection, timestamp, selected apps/channels, and remaining duration — never bank balances, OTPs, PINs, or credentials.</div>
        </div>
      </div>
      ${
        sessions.length
          ? `<b>Recent Protection Sessions</b>` +
            sessions
              .slice(0, 4)
              .map(
                (s) => `<div class="warn" style="margin:6px 0">
                  <div class="row" style="justify-content:space-between">
                    <b>${esc(s.activatedByName)} · ${esc(s.durationOption)}</b>
                    ${uiBadge(s.status.toUpperCase(), s.status === 'active' ? 'HIGH' : s.status === 'unlocked' ? 'LOW' : 'NEUTRAL')}
                  </div>
                  <p class="mut" style="margin:4px 0 0;font-size:12.5px">
                    Apps: ${s.selectedApps.map((a) => esc(a.label)).join(', ')} · Notified ${s.notifiedGuardiansCount} guardian(s) · <span class="num">${new Date(s.activatedAt).toLocaleString()}</span>
                  </p>
                </div>`
              )
              .join('')
          : '<p class="mut" style="margin:0">No Emergency Payment Lock sessions activated yet.</p>'
      }`,
      { badgeHtml: uiSourceBadge('actual') }
    )}

    ${uiCard(
      'Tamper-Evident Security Audit Trail',
      auditTrail.length
        ? auditTrail
            .slice(0, 8)
            .map(
              (a) => `<div class="qr-history-row">
                <div>
                  <b>${esc(a.action.replace(/_/g, ' '))}</b> · <span class="mut">${esc(a.actorName)}</span>
                  <div class="mut" style="font-size:12.5px">${esc(a.details)}</div>
                </div>
                <div class="row" style="gap:6px">
                  <span class="mut num" style="font-size:11.5px">${new Date(a.createdAt).toLocaleTimeString()}</span>
                  <code>#${esc(a.hash)}</code>
                </div>
              </div>`
            )
            .join('')
        : '<p class="mut" style="margin:0">No Emergency Payment Protection audit entries yet.</p>',
      { badgeHtml: uiBadge('Hash-Chained Log', 'LOW') }
    )}
  </div>`;
}

export function renderEmergencyPaymentProtectionTab(): string {
  const epp = S.epp;
  const active = epp?.activeSession || null;
  const canModify = Boolean(epp ? epp.canModify : S.user?.role === 'parent');
  const banks = epp?.banks || [];

  return `${renderActiveSessionBanner(active, canModify)}
    ${active ? renderActiveSessionDetails(active, canModify) : ''}
    ${renderOfficialBankBlockingSection(banks, canModify)}
    ${renderEmergencyPaymentAppLockSection(canModify)}
    ${renderFamilyAndAuditSection()}`;
}
