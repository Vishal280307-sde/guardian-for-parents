import { db } from "./db.ts";
import {
  createNotification,
  generateId,
  getActiveGuardiansForParent,
  sha256,
  writeAudit,
} from "./security.ts";
import { generateCallWatcherAiReport, type CallWatcherAiSummary } from "./ai.ts";
import { ingestGsiEvent } from "./gsi.ts";
import {
  extractEntitiesFromPayment,
  lookupSharedEntitiesForQuery,
  normalizeEntityValue,
  submitEntityFeedback,
  type SharedIntelligenceItem,
} from "./gcih.ts";

export type MonitoringState = "not_activated" | "active" | "paused" | "revoked";
export type PermissionState =
  | "granted"
  | "denied"
  | "permission_required"
  | "unavailable_in_browser";

export type ProtectionStatusLevel =
  | "Protection active"
  | "Protection partially active"
  | "Permission required"
  | "Background execution restricted"
  | "Offline intelligence"
  | "Protection unavailable";

export type AppLifecycleState =
  | "web_foreground"
  | "foreground"
  | "background"
  | "app_closed"
  | "removed_from_recents"
  | "force_stopped"
  | "device_restarted";

export type CallLifecyclePhase =
  | "ringing"
  | "answered"
  | "ended"
  | "missed"
  | "rejected"
  | "unavailable";

export type CallerClassification =
  | "Known Contact"
  | "Unknown Number"
  | "Private/Hidden Number"
  | "Unavailable Caller Information";

export type CallStatus = "Answered" | "Missed" | "Rejected" | "Unavailable";

export type PaymentStatus =
  | "Successful transaction"
  | "Failed transaction"
  | "Pending transaction"
  | "Payment request"
  | "Promotional message"
  | "Informational banking message"
  | "Unknown or unclassified message";

export type RiskLevel =
  | "Low Risk"
  | "Moderate Risk"
  | "High Risk"
  | "Critical Risk"
  | "Inconclusive";

export interface SeparateRiskAssessment {
  riskLevel: RiskLevel;
  riskCategory: string;
  supportingEvidence: string[];
  detectedPatterns: string[];
  missingInformation: string[];
  recommendedAction: string;
  assessedAt: number;
}

export interface CallWatcherSettings {
  consentGiven: boolean;
  consentAt: number | null;
  monitoringState: MonitoringState;
  notifyUnknownCalls: boolean;
  permissionCallState: PermissionState;
  permissionSmsState: PermissionState;
  permissionNotifState: PermissionState;
  permissionCallLogState: PermissionState;
  callScreeningRoleState: PermissionState;
  batteryRestricted: boolean;
  appLifecycleState: AppLifecycleState;
  bootRestorePending: boolean;
  lastEventAt: number | null;
  updatedAt: number;
  effectiveStatusLabel: string;
  protectionStatus: ProtectionStatusLevel;
  protectionDetail: string;
  androidBridgeConnected: boolean;
}

export interface CallWatcherCallRecord {
  id: string;
  callerClassification: CallerClassification;
  callerMasked: string | null;
  callerHash: string | null;
  callStatus: CallStatus;
  callLifecyclePhase: CallLifecyclePhase;
  incomingAt: number;
  startedAt: number | null;
  endedAt: number | null;
  durationMs: number | null;
  screeningVerdict: string | null;
  screeningLatencyMs: number | null;
  simInfo: string | null;
  source: string;
  createdAt: number;
}

export interface CallScreeningResult {
  verdict: "allow_normal" | "allow_caution" | "allow_with_warning";
  callerClassification: CallerClassification;
  callerMasked: string | null;
  callerHash: string | null;
  reputationClass: "Trusted" | "Unknown" | "Suspicious" | "High Risk" | "Verified Spam";
  riskLevel: RiskLevel;
  confidence: number;
  evidence: string[];
  recommendations: string[];
  matchedEntityId: string | null;
  callScreeningRoleGranted: boolean;
  lookupLatencyMs: number;
  neverAutoBlocked: true;
  noAudioCollected: true;
}

export interface ThreatCacheEntry {
  callerHash: string;
  entityHash: string | null;
  maskedDisplay: string;
  reputationLabel: string;
  riskLevel: RiskLevel;
  confidence: number;
  reportCount: number;
  falsePositiveCount: number;
  updatedAt: number;
}

export interface PaymentMessageRecord {
  id: string;
  senderLabel: string | null;
  messageTs: number;
  amount: number | null;
  currency: string | null;
  txType: string;
  txRef: string | null;
  upiRef: string | null;
  accountMasked: string | null;
  merchantOrRecipient: string | null;
  paymentStatus: PaymentStatus;
  redactedSummary: string;
  source: string;
  createdAt: number;
}

export interface QuestionnaireResponseRecord {
  id: string;
  correlationId: string | null;
  callEventId: string | null;
  callerHash: string | null;
  askedToDo: string | null;
  urgencyPressure: string | null;
  askedSensitiveCreds: string | null;
  emotionalFeeling: string | null;
  dismissed: boolean;
  criticalWarningTriggered: boolean;
  createdAt: number;
}

export interface CallWatcherAiReportBlock {
  available: boolean;
  model: string | null;
  summary: CallWatcherAiSummary;
  errorReason?: string;
}

export interface CallWatcherTimelineItem {
  correlationId: string;
  parentId?: string;
  parentName?: string;
  createdAt: number;
  updatedAt: number;
  status: string;
  timeDiffMs: number | null;
  duringCall: boolean;
  detectedPatterns: string[];
  call: CallWatcherCallRecord | null;
  payment: PaymentMessageRecord | null;
  callRisk: SeparateRiskAssessment;
  paymentRisk: SeparateRiskAssessment;
  aiReport: CallWatcherAiReportBlock;
  questionnaire: QuestionnaireResponseRecord | null;
  questionnaireNeeded: boolean;
  questionnaireReason: string | null;
  criticalWarningActive: boolean;
  parentNotifiedCount: number;
  sharedIntelligence?: SharedIntelligenceItem[];
}

export interface CallWatcherSummary {
  recentCallsCount: number;
  unknownCallsCount: number;
  paymentEventsCount: number;
  correlatedAlertsCount: number;
  criticalAlertsCount: number;
  pendingQuestionnairesCount: number;
}

export interface CallWatcherDashboard {
  settings: CallWatcherSettings;
  summary: CallWatcherSummary;
  timeline: CallWatcherTimelineItem[];
  pendingQuestionnaire: CallWatcherTimelineItem | null;
}

export async function cleanupCallWatcherRetention(userId: string, retentionDays: number): Promise<void> {
  const cutoff = Date.now() - Math.max(1, retentionDays) * 86_400_000;
  await db.prepare("DELETE FROM call_payment_correlations WHERE user_id = ? AND created_at < ?").run(
    userId,
    cutoff
  );
  await db.prepare("DELETE FROM safety_questionnaire_responses WHERE user_id = ? AND created_at < ?").run(
    userId,
    cutoff
  );
  await db.prepare("DELETE FROM payment_message_events WHERE user_id = ? AND created_at < ?").run(
    userId,
    cutoff
  );
  await db.prepare("DELETE FROM call_watcher_calls WHERE user_id = ? AND incoming_at < ?").run(
    userId,
    cutoff
  );
}

function computeProtectionStatus(params: {
  consentGiven: boolean;
  monitoringState: MonitoringState;
  permCall: PermissionState;
  permCallLog: PermissionState;
  callScreeningRole: PermissionState;
  permSms: PermissionState;
  permNotif: PermissionState;
  batteryRestricted: boolean;
  appLifecycleState: AppLifecycleState;
  bootRestorePending: boolean;
}): {
  protectionStatus: ProtectionStatusLevel;
  protectionDetail: string;
  effectiveStatusLabel: string;
  androidBridgeConnected: boolean;
} {
  const {
    consentGiven,
    monitoringState,
    permCall,
    permCallLog,
    callScreeningRole,
    permSms,
    permNotif,
    batteryRestricted,
    appLifecycleState,
    bootRestorePending,
  } = params;

  const androidBridgeConnected =
    callScreeningRole === "granted" ||
    (permCall === "granted" && (permSms === "granted" || permNotif === "granted"));

  let effectiveStatusLabel = "Inactive — Consent Required";
  if (monitoringState === "revoked") {
    effectiveStatusLabel = "Inactive — Consent Revoked";
  } else if (monitoringState === "paused") {
    effectiveStatusLabel = "Paused by User";
  } else if (consentGiven && monitoringState === "active") {
    effectiveStatusLabel = androidBridgeConnected
      ? "Active (Android Companion Connected)"
      : "Partially Active (Web User-Assisted & Timing)";
  }

  // Truthful Section 7 6-state protection reporting
  if (!consentGiven || monitoringState === "not_activated" || monitoringState === "revoked") {
    return {
      protectionStatus: "Protection unavailable",
      protectionDetail:
        monitoringState === "revoked"
          ? "Call Watcher consent was revoked by user."
          : "Activate Call Watcher consent before call metadata or screening runs.",
      effectiveStatusLabel,
      androidBridgeConnected,
    };
  }

  if (monitoringState === "paused") {
    return {
      protectionStatus: "Protection unavailable",
      protectionDetail: "Call Watcher monitoring is paused by user; resume monitoring to restore protection.",
      effectiveStatusLabel,
      androidBridgeConnected,
    };
  }

  if (appLifecycleState === "force_stopped" || batteryRestricted) {
    return {
      protectionStatus: "Background execution restricted",
      protectionDetail:
        appLifecycleState === "force_stopped"
          ? "Android Force Stop suspends background services/receivers until user reopens the app."
          : "Battery optimization is restricted; Android may delay or stop background call workers. Request unrestricted battery mode.",
      effectiveStatusLabel,
      androidBridgeConnected,
    };
  }

  if (bootRestorePending && appLifecycleState === "device_restarted") {
    return {
      protectionStatus: "Protection partially active",
      protectionDetail:
        "Device restarted — local screening cache is active while full WorkManager sync restoration finishes.",
      effectiveStatusLabel,
      androidBridgeConnected,
    };
  }

  const anyPermissionDeniedOrRequired =
    permCall === "denied" ||
    permCall === "permission_required" ||
    callScreeningRole === "denied" ||
    callScreeningRole === "permission_required" ||
    permNotif === "denied" ||
    permNotif === "permission_required";

  if (anyPermissionDeniedOrRequired) {
    return {
      protectionStatus: "Permission required",
      protectionDetail:
        callScreeningRole !== "granted"
          ? "Call Screening Role or Phone State / Notification permission is needed for automatic Android caller alerts."
          : "Grant missing Android phone/notification permissions so alerts can run cleanly.",
      effectiveStatusLabel,
      androidBridgeConnected,
    };
  }

  if (callScreeningRole === "granted" && permCall === "granted" && permCallLog === "granted" && !batteryRestricted) {
    return {
      protectionStatus: "Protection active",
      protectionDetail:
        "Call Screening Role, phone state, call-log duration verification, and unrestricted background execution are active.",
      effectiveStatusLabel,
      androidBridgeConnected: true,
    };
  }

  if (callScreeningRole === "granted" || permCall === "granted") {
    return {
      protectionStatus: "Protection partially active",
      protectionDetail:
        permCallLog !== "granted"
          ? "Real-time call detection active; exact duration fallback is limited without Call Log permission."
          : "Real-time call detection active in partial companion mode.",
      effectiveStatusLabel,
      androidBridgeConnected: true,
    };
  }

  return {
    protectionStatus: "Protection partially active",
    protectionDetail:
      "Web user-assisted mode: live manual timer & call/SMS logging active; automatic background call interception requires the Android app.",
    effectiveStatusLabel,
    androidBridgeConnected: false,
  };
}

export async function ensureCallWatcherSettings(userId: string): Promise<CallWatcherSettings> {
  let row = (await db
    .prepare("SELECT * FROM call_watcher_settings WHERE user_id = ?")
    .get(userId)) as Record<string, unknown> | undefined;

  const now = Date.now();
  if (!row) {
    await db.prepare(
      `INSERT INTO call_watcher_settings (
        user_id, consent_given, consent_at, monitoring_state, notify_unknown_calls,
        permission_call_state, permission_sms_state, permission_notif_state,
        permission_call_log_state, call_screening_role_state, battery_restricted,
        app_lifecycle_state, boot_restore_pending, last_event_at, updated_at
      ) VALUES (?, 0, NULL, 'not_activated', 0, 'unavailable_in_browser', 'unavailable_in_browser', 'unavailable_in_browser', 'unavailable_in_browser', 'unavailable_in_browser', 0, 'web_foreground', 0, NULL, ?)`
    ).run(userId, now);
    row = (await db
      .prepare("SELECT * FROM call_watcher_settings WHERE user_id = ?")
      .get(userId)) as Record<string, unknown>;
  }

  const monitoringState = (String(row.monitoring_state || "not_activated") as MonitoringState);
  const consentGiven = Boolean(row.consent_given);
  const permCall = (String(row.permission_call_state || "unavailable_in_browser") as PermissionState);
  const permSms = (String(row.permission_sms_state || "unavailable_in_browser") as PermissionState);
  const permNotif = (String(row.permission_notif_state || "unavailable_in_browser") as PermissionState);
  const permCallLog = (String(row.permission_call_log_state || "unavailable_in_browser") as PermissionState);
  const callScreeningRole = (String(row.call_screening_role_state || "unavailable_in_browser") as PermissionState);
  const batteryRestricted = Boolean(row.battery_restricted);
  const appLifecycleState = (String(row.app_lifecycle_state || "web_foreground") as AppLifecycleState);
  const bootRestorePending = Boolean(row.boot_restore_pending);

  const computed = computeProtectionStatus({
    consentGiven,
    monitoringState,
    permCall,
    permCallLog,
    callScreeningRole,
    permSms,
    permNotif,
    batteryRestricted,
    appLifecycleState,
    bootRestorePending,
  });

  return {
    consentGiven,
    consentAt: row.consent_at ? Number(row.consent_at) : null,
    monitoringState,
    notifyUnknownCalls: Boolean(row.notify_unknown_calls),
    permissionCallState: permCall,
    permissionSmsState: permSms,
    permissionNotifState: permNotif,
    permissionCallLogState: permCallLog,
    callScreeningRoleState: callScreeningRole,
    batteryRestricted,
    appLifecycleState,
    bootRestorePending,
    lastEventAt: row.last_event_at ? Number(row.last_event_at) : null,
    updatedAt: Number(row.updated_at || now),
    effectiveStatusLabel: computed.effectiveStatusLabel,
    protectionStatus: computed.protectionStatus,
    protectionDetail: computed.protectionDetail,
    androidBridgeConnected: computed.androidBridgeConnected,
  };
}

export async function updateCallWatcherConsent(
  userId: string,
  action: "activate" | "pause" | "resume" | "revoke" | "update_prefs",
  opts: {
    notifyUnknownCalls?: boolean;
    permissionCallState?: PermissionState;
    permissionSmsState?: PermissionState;
    permissionNotifState?: PermissionState;
    permissionCallLogState?: PermissionState;
    callScreeningRoleState?: PermissionState;
    batteryRestricted?: boolean;
    appLifecycleState?: AppLifecycleState;
    bootRestorePending?: boolean;
  } = {}
): Promise<CallWatcherSettings> {
  const current = await ensureCallWatcherSettings(userId);
  const now = Date.now();

  let consentGiven = current.consentGiven ? 1 : 0;
  let consentAt = current.consentAt;
  let monitoringState: MonitoringState = current.monitoringState;
  const notifyUnknownCalls =
    typeof opts.notifyUnknownCalls === "boolean"
      ? opts.notifyUnknownCalls
        ? 1
        : 0
      : current.notifyUnknownCalls
        ? 1
        : 0;

  const validPerm = (v: unknown, fallback: PermissionState): PermissionState =>
    v === "granted" ||
    v === "denied" ||
    v === "permission_required" ||
    v === "unavailable_in_browser"
      ? v
      : fallback;

  const validLifecycle = (v: unknown, fallback: AppLifecycleState): AppLifecycleState =>
    v === "web_foreground" ||
    v === "foreground" ||
    v === "background" ||
    v === "app_closed" ||
    v === "removed_from_recents" ||
    v === "force_stopped" ||
    v === "device_restarted"
      ? v
      : fallback;

  const permCall = validPerm(opts.permissionCallState, current.permissionCallState);
  const permSms = validPerm(opts.permissionSmsState, current.permissionSmsState);
  const permNotif = validPerm(opts.permissionNotifState, current.permissionNotifState);
  const permCallLog = validPerm(opts.permissionCallLogState, current.permissionCallLogState);
  const callScreeningRole = validPerm(opts.callScreeningRoleState, current.callScreeningRoleState);
  const batteryRestricted =
    typeof opts.batteryRestricted === "boolean"
      ? opts.batteryRestricted
        ? 1
        : 0
      : current.batteryRestricted
        ? 1
        : 0;
  const appLifecycleState = validLifecycle(opts.appLifecycleState, current.appLifecycleState);
  const bootRestorePending =
    typeof opts.bootRestorePending === "boolean"
      ? opts.bootRestorePending
        ? 1
        : 0
      : current.bootRestorePending
        ? 1
        : 0;

  if (action === "activate") {
    consentGiven = 1;
    consentAt = consentAt || now;
    monitoringState = "active";
    await writeAudit(userId, "Call Watcher consent granted and monitoring activated (no audio/recording)");
  } else if (action === "pause") {
    monitoringState = "paused";
    await writeAudit(userId, "Call Watcher monitoring paused by user");
  } else if (action === "resume") {
    if (!consentGiven) {
      throw new Error("Activate Call Watcher with one-time consent before resuming.");
    }
    monitoringState = "active";
    await writeAudit(userId, "Call Watcher monitoring resumed");
  } else if (action === "revoke") {
    consentGiven = 0;
    monitoringState = "revoked";
    await writeAudit(userId, "Call Watcher consent revoked by user");
  } else {
    await writeAudit(userId, "Updated Call Watcher notification/permission preferences");
  }

  await db.prepare(
    `UPDATE call_watcher_settings SET
      consent_given = ?,
      consent_at = ?,
      monitoring_state = ?,
      notify_unknown_calls = ?,
      permission_call_state = ?,
      permission_sms_state = ?,
      permission_notif_state = ?,
      permission_call_log_state = ?,
      call_screening_role_state = ?,
      battery_restricted = ?,
      app_lifecycle_state = ?,
      boot_restore_pending = ?,
      updated_at = ?
     WHERE user_id = ?`
  ).run(
    consentGiven,
    consentAt,
    monitoringState,
    notifyUnknownCalls,
    permCall,
    permSms,
    permNotif,
    permCallLog,
    callScreeningRole,
    batteryRestricted,
    appLifecycleState,
    bootRestorePending,
    now,
    userId
  );

  return ensureCallWatcherSettings(userId);
}

export function maskCallerIdentifier(
  userId: string,
  rawCaller: string | null | undefined,
  classification: CallerClassification
): { callerMasked: string | null; callerHash: string | null } {
  const cleaned = String(rawCaller || "").trim();
  if (
    classification === "Private/Hidden Number" ||
    classification === "Unavailable Caller Information" ||
    !cleaned
  ) {
    return {
      callerMasked: null,
      callerHash:
        classification === "Private/Hidden Number"
          ? sha256(`${userId}:private_hidden`)
          : null,
    };
  }
  const digits = cleaned.replace(/\D/g, "");
  if (digits.length >= 4) {
    const tail = digits.slice(-4);
    const masked = digits.length > 6 ? `******${tail}` : `***${tail}`;
    return {
      callerMasked: masked,
      callerHash: sha256(`${userId}:phone:${digits.slice(-10)}`),
    };
  }
  return {
    callerMasked: cleaned.slice(0, 2) + "***",
    callerHash: sha256(`${userId}:label:${cleaned.toLowerCase()}`),
  };
}

export function formatDur(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return "Duration unavailable";
  const sec = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}m ${s}s`;
}

function redactPaymentSms(rawText: string): string {
  return String(rawText || "")
    .replace(
      /\b(otp|one[\s-]?time[\s-]?password|upi[\s-]?pin|mpin|atm[\s-]?pin|pin|cvv|password|passcode)\b([^\d]{0,14})\d{3,8}/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\b\d{6,}\b/g, (digits) => `XX${digits.slice(-4)}`)
    .replace(/[\w.-]+@[\w.-]+/g, (id) => {
      const [lhs, rhs] = id.split("@");
      return `${(lhs || "u").slice(0, 2)}***@${rhs || "upi"}`;
    })
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
}

export interface ParsedPaymentMessage {
  senderLabel: string | null;
  messageTs: number;
  amount: number | null;
  currency: string | null;
  txType: string;
  txRef: string | null;
  upiRef: string | null;
  accountMasked: string | null;
  merchantOrRecipient: string | null;
  paymentStatus: PaymentStatus;
  redactedSummary: string;
  dedupHash: string;
  cues: {
    urgentOrThreat: boolean;
    remoteAccessOrCredAsk: boolean;
    hasUrl: boolean;
    isPromo: boolean;
    isInformational: boolean;
  };
}

export function parsePaymentMessage(
  rawText: string,
  senderLabelInput?: string | null,
  messageTsInput?: number
): ParsedPaymentMessage {
  const raw = String(rawText || "").trim().slice(0, 1500);
  const lower = raw.toLowerCase();
  const senderLabel = senderLabelInput ? String(senderLabelInput).trim().slice(0, 40) : null;
  const messageTs =
    messageTsInput && Number.isFinite(messageTsInput) && messageTsInput > 0
      ? Math.round(messageTsInput)
      : Date.now();

  // Amount parsing: Rs. 5,000.00 / INR 1850 / ₹ 2500
  let amount: number | null = null;
  let currency: string | null = null;
  const amtMatch = raw.match(/(?:₹|rs\.?|inr)\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (amtMatch && amtMatch[1]) {
    const val = Number(amtMatch[1].replace(/,/g, ""));
    if (Number.isFinite(val) && val > 0 && val <= 100_000_000) {
      amount = val;
      currency = "INR";
    }
  } else {
    const usdMatch = raw.match(/(?:\$|usd)\s*([\d,]+(?:\.\d{1,2})?)/i);
    if (usdMatch && usdMatch[1]) {
      const val = Number(usdMatch[1].replace(/,/g, ""));
      if (Number.isFinite(val) && val > 0) {
        amount = val;
        currency = "USD";
      }
    }
  }

  // Masked account (XX1234 / A/c *1234 / ending 4321)
  let accountMasked: string | null = null;
  const acctMatch = raw.match(/(?:a\/c|acct|account|card|ending|xx|x{2,})\s*[*xX-]*(\d{4})\b/i);
  if (acctMatch && acctMatch[1]) {
    accountMasked = `XX${acctMatch[1]}`;
  }

  // Transaction / UPI reference (masked tail or short ref)
  let upiRef: string | null = null;
  const upiRefMatch = raw.match(/(?:utr|upi\s*ref|rrn|ref(?:\s*no)?)\s*[:#-]?\s*([A-Z0-9]{6,18})/i);
  if (upiRefMatch && upiRefMatch[1]) {
    const refVal = upiRefMatch[1];
    upiRef = refVal.length > 6 ? `**${refVal.slice(-6)}` : refVal;
  }

  let txRef: string | null = null;
  const txMatch = raw.match(/(?:txn|txnid|transaction\s*id)\s*[:#-]?\s*([A-Z0-9]{5,18})/i);
  if (txMatch && txMatch[1]) {
    const refVal = txMatch[1];
    txRef = refVal.length > 6 ? `**${refVal.slice(-6)}` : refVal;
  }

  // Merchant / recipient extraction
  let merchantOrRecipient: string | null = null;
  const merchMatch = raw.match(
    /(?:to|paid to|at|towards|from|by|merchant|vpa)\s+([A-Za-z0-9._@-]{2,40}(?:\s+[A-Za-z0-9._@-]{2,25})?)/i
  );
  if (merchMatch && merchMatch[1]) {
    const candidate = merchMatch[1].replace(/\b(on|via|ref|utr|upi|using|dated)\b.*$/i, "").trim();
    if (candidate && !/^\d{5,}$/.test(candidate)) {
      merchantOrRecipient = candidate.slice(0, 48);
    }
  }

  // Cues
  const isPromo =
    /\b(offer|cashback\s+up\s+to|pre-?approved\s+loan|apply\s+now|discount|voucher|win\s+a?\s*prize|reward\s+points|congratulations|exclusive\s+deal)\b/i.test(
      raw
    ) && !/\b(debited|deducted|paid|sent|transferred|credited|collect\s+request|has\s+requested)\b/i.test(raw);

  const isFailed =
    /\b(failed|declined|unsuccessful|timed\s*out|could\s+not\s+be\s+processed|insufficient\s+balance|tx\s*failed|transaction\s*failed|rejected)\b/i.test(
      raw
    );

  const isPaymentRequest =
    /\b(has\s+requested|collect\s+request|payment\s+request|approve\s+(?:the\s+)?request|pay\s+link|payment\s+link|mandate\s+request|requesting\s+rs|requested\s+rs|requested\s+₹|approve\s+to\s+pay)\b/i.test(
      raw
    );

  const isDebitedOrPaid =
    /\b(debited|deducted|paid|sent|transferred|payment\s+of|completed|successful|withdrawn|spent|charged)\b/i.test(
      raw
    );

  const isCredited = /\b(credited|received\s+rs|received\s+₹|deposited|refunded)\b/i.test(raw);

  const isPending =
    /\b(pending|in\s+progress|processing|awaiting\s+confirmation|under\s+process)\b/i.test(raw) &&
    !isDebitedOrPaid &&
    !isFailed;

  const isInformational =
    (/\b(available\s+balance|avail\s*bal|statement|mini\s*statement|kyc\s+reminder|bill\s+generated|due\s+date)\b/i.test(
      raw
    ) &&
      !isDebitedOrPaid &&
      !isPaymentRequest &&
      !isFailed) ||
    (/\botp\b/i.test(raw) && !isDebitedOrPaid && !isPaymentRequest && !isFailed && amount === null);

  let paymentStatus: PaymentStatus = "Unknown or unclassified message";
  if (isPromo) {
    paymentStatus = "Promotional message";
  } else if (isFailed) {
    paymentStatus = "Failed transaction";
  } else if (isPaymentRequest) {
    paymentStatus = "Payment request";
  } else if (isPending) {
    paymentStatus = "Pending transaction";
  } else if (isDebitedOrPaid || isCredited) {
    paymentStatus = "Successful transaction";
  } else if (isInformational) {
    paymentStatus = "Informational banking message";
  }

  let txType = "Unknown";
  if (isPaymentRequest) txType = "Collection Request";
  else if (/\bupi\b|@/i.test(raw)) txType = "UPI";
  else if (/\bcard\b|visa|mastercard|rupay/i.test(raw)) txType = "Card";
  else if (isCredited) txType = "Bank Credit";
  else if (isDebitedOrPaid) txType = "Bank Debit";
  else if (/wallet|paytm|phonepe|gpay/i.test(raw)) txType = "Wallet";

  const urgentOrThreat =
    /\b(urgent|immediately|block(?:ed)?|suspend(?:ed)?|freeze|frozen|legal|police|arrest|penalty|expire|within\s+\d+\s*(?:min|hr|hour)|तुरंत|बंद)\b/i.test(
      raw
    );
  const remoteAccessOrCredAsk =
    /\b(anydesk|teamviewer|quicksupport|rustdesk|screen\s*share|share\s+otp|enter\s+pin|upi\s+pin\s+to\s+receive|do\s+not\s+tell\s+anyone)\b/i.test(
      raw
    );
  const hasUrl = /https?:\/\/|bit\.ly|tinyurl|t\.co/i.test(raw);

  // Deduplication hash across normalized message + 10-minute time window
  const timeBucket = Math.floor(messageTs / 600_000);
  const dedupHash = sha256(
    `${lower.replace(/\s+/g, " ")}|${(senderLabel || "").toLowerCase()}|${timeBucket}`
  );

  return {
    senderLabel,
    messageTs,
    amount,
    currency,
    txType,
    txRef,
    upiRef,
    accountMasked,
    merchantOrRecipient,
    paymentStatus,
    redactedSummary: redactPaymentSms(raw),
    dedupHash,
    cues: {
      urgentOrThreat,
      remoteAccessOrCredAsk,
      hasUrl,
      isPromo,
      isInformational,
    },
  };
}

async function getPriorCallerContext(userId: string, callerHash: string | null, callIncomingAt: number) {
  let unknownCalls30m = 0;
  const rows30m = (await db
    .prepare(
      "SELECT caller_classification FROM call_watcher_calls WHERE user_id = ? AND incoming_at >= ? AND incoming_at <= ?"
    )
    .all(userId, callIncomingAt - 1_800_000, callIncomingAt)) as { caller_classification: string }[];
  unknownCalls30m = rows30m.filter((r) => r.caller_classification !== "Known Contact").length;

  let sameCaller24h = 0;
  if (callerHash) {
    const row = (await db
      .prepare(
        "SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND caller_hash = ? AND incoming_at >= ?"
      )
      .get(userId, callerHash, callIncomingAt - 86_400_000)) as { cnt: number };
    sameCaller24h = Number(row?.cnt || 0);
  }

  let priorQuestionnaire: QuestionnaireResponseRecord | null = null;
  if (callerHash) {
    const qRow = (await db
      .prepare(
        `SELECT * FROM safety_questionnaire_responses
         WHERE user_id = ? AND caller_hash = ? AND dismissed = 0
         ORDER BY created_at DESC LIMIT 1`
      )
      .get(userId, callerHash)) as Record<string, unknown> | undefined;
    if (qRow) {
      priorQuestionnaire = mapQuestionnaireRow(qRow);
    }
  }

  return { unknownCalls30m, sameCaller24h, priorQuestionnaire };
}

async function inputCallerLookup(userId: string, callerMasked: string | null): Promise<SharedIntelligenceItem[]> {
  if (!callerMasked) return [];
  const digits = callerMasked.replace(/\D/g, "");
  if (digits.length < 4) return [];
  const rows = (await db
    .prepare(
      `SELECT * FROM gcih_entities
       WHERE family_owner_id = ? AND entity_type = 'phone_number'
       ORDER BY updated_at DESC LIMIT 20`
    )
    .all(userId)) as Record<string, unknown>[];
  const tail = digits.slice(-4);
  const out: SharedIntelligenceItem[] = [];
  for (const r of rows) {
    if (!String(r.masked_display).endsWith(tail)) continue;
    const mods = JSON.parse(String(r.source_modules_json || "[]")) as string[];
    const devs = JSON.parse(String(r.source_device_ids_json || "[]")) as string[];
    out.push({
      entityId: String(r.id),
      entityType: "phone_number",
      maskedDisplay: String(r.masked_display),
      riskClassification: String(r.risk_classification) as SharedIntelligenceItem["riskClassification"],
      verificationStatus: String(r.verification_status) as SharedIntelligenceItem["verificationStatus"],
      confidence: Number(r.confidence || 0.5),
      sourceModule: mods[0] || "gcih",
      sourceModules: mods,
      sourceDeviceId: devs[0] || "web_session",
      discoveryTimestamp: Number(r.first_detected_at),
      familyMemberAttribution: "Family Shared Entity",
      reasonForSharing: `Phone number flagged across ${mods.join(", ")}`,
      evidenceRefs: JSON.parse(String(r.evidence_refs_json || "[]")) as string[],
      relatedEventIds: JSON.parse(String(r.related_event_ids_json || "[]")) as string[],
      relatedIncidentIds: JSON.parse(String(r.related_incident_ids_json || "[]")) as string[],
    });
  }
  return out;
}

export function assessCallRisk(params: {
  call: CallWatcherCallRecord | null;
  unknownCalls30m: number;
  sameCaller24h: number;
  questionnaire: QuestionnaireResponseRecord | null;
  sharedItems?: SharedIntelligenceItem[];
  hasCorroboratingContext?: boolean;
}): SeparateRiskAssessment {
  const { call, unknownCalls30m, sameCaller24h, questionnaire } = params;
  const now = Date.now();

  if (!call) {
    return {
      riskLevel: "Inconclusive",
      riskCategory: "Call Context Missing",
      supportingEvidence: ["No associated call metadata event was recorded or linked."],
      detectedPatterns: ["no_linked_call"],
      missingInformation: ["Caller classification, call timestamps, and call duration are unavailable."],
      recommendedAction:
        "If this payment message followed an unexpected phone call, log the call details in Call Watch.",
      assessedAt: now,
    };
  }

  const evidence: string[] = [];
  const patterns: string[] = [];
  const missing: string[] = [];
  let score = 0;

  evidence.push(`Caller classification: ${call.callerClassification}.`);
  evidence.push(`Call status: ${call.callStatus}.`);
  if (call.durationMs !== null) {
    evidence.push(`Measured call duration: ${formatDur(call.durationMs)} (timing metadata only, no audio).`);
  } else {
    missing.push("Exact call duration was unavailable from the source.");
  }
  missing.push("Call audio and spoken content are never heard, recorded, or transcribed.");

  if (call.callerClassification === "Known Contact") {
    score += 5;
  } else if (call.callerClassification === "Private/Hidden Number") {
    score += 30;
    patterns.push("private_or_hidden_caller");
    evidence.push("Caller identity was private or hidden.");
  } else if (call.callerClassification === "Unavailable Caller Information") {
    score += 20;
    patterns.push("unavailable_caller_metadata");
    missing.push("Phone number or contact match was unavailable.");
  } else {
    score += 18;
    patterns.push("unknown_caller");
  }

  const hasFlaggedIntel = Boolean(
    params.sharedItems?.some(
      (s) =>
        s.verificationStatus === "High risk" ||
        s.verificationStatus === "Confirmed malicious" ||
        s.verificationStatus === "Suspicious"
    )
  );
  const corroboratingSignals =
    Boolean(params.hasCorroboratingContext) ||
    call.callerClassification === "Private/Hidden Number" ||
    unknownCalls30m >= 2 ||
    sameCaller24h >= 2 ||
    hasFlaggedIntel ||
    Boolean(questionnaire && !questionnaire.dismissed && questionnaire.askedToDo !== "none_or_normal");

  if (call.callerClassification !== "Known Contact" && call.durationMs !== null && call.durationMs >= 180_000) {
    if (corroboratingSignals) {
      score += 32;
      patterns.push("long_unknown_call");
      evidence.push(
        `Extended unknown-caller duration (${formatDur(call.durationMs)}) paired with corroborating risk signals.`
      );
    } else {
      score += 4;
      patterns.push("extended_call_duration_note");
      evidence.push(
        `Call duration (${formatDur(call.durationMs)}) recorded as contextual timing only — a long call alone never triggers a scam alert.`
      );
    }
  }

  if (unknownCalls30m >= 2) {
    score += 20;
    patterns.push("repeated_unknown_calls");
    evidence.push(`${unknownCalls30m} unknown-caller events recorded within 30 minutes.`);
  }
  if (sameCaller24h >= 2) {
    score += 15;
    patterns.push("same_caller_repeat");
    evidence.push(`Repeated contact from the same masked caller identifier (${sameCaller24h} times in 24h).`);
  }

  if (questionnaire && !questionnaire.dismissed) {
    if (
      questionnaire.askedSensitiveCreds === "yes_otp_pin_password" ||
      questionnaire.askedSensitiveCreds === "yes_remote_access" ||
      questionnaire.askedToDo === "share_otp_pin" ||
      questionnaire.askedToDo === "install_remote_app"
    ) {
      score = Math.max(score, 90);
      patterns.push("questionnaire_credential_or_remote_access");
      evidence.push("User reported the caller asked for OTP/PIN/password or screen-sharing app installation.");
    } else if (questionnaire.urgencyPressure === "yes_threatened") {
      score += 35;
      patterns.push("questionnaire_caller_threats");
      evidence.push("User reported threats or intimidation from the caller.");
    } else if (questionnaire.urgencyPressure === "yes_urgent") {
      score += 25;
      patterns.push("questionnaire_urgency");
      evidence.push("User reported urgent pressure to act immediately.");
    } else if (questionnaire.askedToDo === "none_or_normal" && questionnaire.urgencyPressure === "no") {
      score = Math.max(0, score - 15);
      evidence.push("User confirmed the call was normal with no pressure or sensitive requests.");
    }
  }

  if (call && call.callerClassification !== "Known Contact" && params.sharedItems && params.sharedItems.length > 0) {
    for (const sItem of params.sharedItems) {
      if (sItem.verificationStatus === "High risk" || sItem.verificationStatus === "Confirmed malicious" || sItem.verificationStatus === "Suspicious") {
        score += sItem.verificationStatus === "Suspicious" ? 20 : 35;
        patterns.push("cross_section_shared_phone_flag");
        evidence.push(`Cross-section alert (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} — ${sItem.verificationStatus}.`);
      } else if (sItem.verificationStatus === "Verified legitimate") {
        score = Math.max(0, score - 15);
        evidence.push(`Family feedback: ${sItem.maskedDisplay} verified legitimate.`);
      }
    }
  }

  let riskLevel: RiskLevel;
  if (
    call.callerClassification === "Unavailable Caller Information" &&
    call.durationMs === null &&
    !questionnaire
  ) {
    riskLevel = "Inconclusive";
  } else if (score >= 80) {
    riskLevel = "Critical Risk";
  } else if (score >= 50) {
    riskLevel = "High Risk";
  } else if (score >= 25) {
    riskLevel = "Moderate Risk";
  } else {
    riskLevel = "Low Risk";
  }

  const recommendedAction =
    riskLevel === "Critical Risk"
      ? "Disconnect immediately if still on the call. Do not share OTP, UPI PIN, or install screen-sharing apps. Call a trusted family guardian."
      : riskLevel === "High Risk"
        ? "Hang up and independently verify the caller using an official or saved number before taking any action."
        : riskLevel === "Moderate Risk"
          ? "Treat unexpected requests from an unknown caller with caution until independently confirmed."
          : riskLevel === "Inconclusive"
            ? "Caller metadata was incomplete; verify caller identity independently if any request was made."
            : "No high-risk call metadata patterns detected, though saved caller IDs can still be spoofed.";

  return {
    riskLevel,
    riskCategory:
      call.callerClassification === "Known Contact"
        ? "Saved Contact Call Metadata"
        : "Unknown/Unverified Caller Metadata",
    supportingEvidence: evidence,
    detectedPatterns: patterns.length ? patterns : ["no_suspicious_call_pattern"],
    missingInformation: missing,
    recommendedAction,
    assessedAt: now,
  };
}

export function assessPaymentRisk(params: {
  payment: PaymentMessageRecord | null;
  parsedCues?: ParsedPaymentMessage["cues"];
  call: CallWatcherCallRecord | null;
  timeDiffMs: number | null;
  duringCall: boolean;
  recentPayments15m: number;
  questionnaire: QuestionnaireResponseRecord | null;
  sharedItems?: SharedIntelligenceItem[];
}): SeparateRiskAssessment {
  const { payment, parsedCues, call, timeDiffMs, duringCall, recentPayments15m, questionnaire } = params;
  const now = Date.now();

  if (!payment) {
    return {
      riskLevel: "Inconclusive",
      riskCategory: "No Payment Message Linked",
      supportingEvidence: ["No payment SMS or notification event has been paired with this call yet."],
      detectedPatterns: ["awaiting_or_no_payment_message"],
      missingInformation: ["Transaction amount, status, and merchant/recipient details."],
      recommendedAction:
        "If a payment alert, UPI collect request, or bank SMS arrives during or after the call, share it in Call Watch.",
      assessedAt: now,
    };
  }

  const evidence: string[] = [];
  const patterns: string[] = [];
  const missing: string[] = [];
  let score = 0;

  evidence.push(`Payment message status classified as: ${payment.paymentStatus}.`);
  if (payment.amount !== null) {
    evidence.push(`Extracted amount: ${payment.currency || "INR"} ${payment.amount.toLocaleString("en-IN")}.`);
  } else {
    missing.push("Transaction amount was not present or could not be reliably extracted.");
  }
  if (!payment.merchantOrRecipient) {
    missing.push("Recipient or merchant name could not be verified from the message alone.");
  } else {
    evidence.push(`Extracted recipient/merchant label: ${payment.merchantOrRecipient}.`);
  }
  missing.push("Timing correlation is a safety clue only and cannot prove the call caused the payment.");

  // Distinguish non-transaction statuses strictly
  if (payment.paymentStatus === "Promotional message") {
    patterns.push("promotional_message_not_debit");
    evidence.push("Identified as promotional/marketing content rather than a completed debit or collect request.");
    if (parsedCues?.hasUrl) {
      score += 20;
      patterns.push("promotional_link_caution");
      evidence.push("Contains an external URL—avoid clicking unverified promotional links.");
    }
    return {
      riskLevel: score >= 20 ? "Moderate Risk" : "Low Risk",
      riskCategory: "Promotional Message",
      supportingEvidence: evidence,
      detectedPatterns: patterns,
      missingInformation: missing,
      recommendedAction:
        "No financial transaction was detected in this promotional message. Do not click unverified links.",
      assessedAt: now,
    };
  }

  if (payment.paymentStatus === "Informational banking message") {
    patterns.push("informational_banking_notice");
    if (parsedCues?.urgentOrThreat || parsedCues?.hasUrl) {
      score += 35;
      patterns.push("urgent_informational_or_phishing_cue");
      evidence.push("Message uses urgent/account-block wording or external links alongside a notice.");
    }
    return {
      riskLevel: score >= 35 ? "Moderate Risk" : "Low Risk",
      riskCategory: "Informational Notice",
      supportingEvidence: evidence,
      detectedPatterns: patterns,
      missingInformation: missing,
      recommendedAction:
        score >= 35
          ? "Check your official bank app directly instead of acting on urgent SMS wording."
          : "Informational notice only; no completed debit or payment request found.",
      assessedAt: now,
    };
  }

  if (payment.paymentStatus === "Unknown or unclassified message") {
    return {
      riskLevel: "Inconclusive",
      riskCategory: "Unclassified Message",
      supportingEvidence: evidence,
      detectedPatterns: ["unclassified_message"],
      missingInformation: [...missing, "Clear transaction outcome or payment-request phrasing missing."],
      recommendedAction: "Review the message carefully and verify inside your official banking app.",
      assessedAt: now,
    };
  }

  // Genuine payment/request/pending/failed evaluation
  // Note: High amount alone NEVER sets fraud risk!
  const isUnknownCall = call ? call.callerClassification !== "Known Contact" : false;

  if (payment.paymentStatus === "Payment request") {
    score += 30;
    patterns.push("collect_or_payment_request");
    evidence.push("Message represents a payment/collect request asking the user to approve funds.");
  }

  if (duringCall) {
    score += isUnknownCall ? 45 : 25;
    patterns.push("payment_during_active_call");
    evidence.push("Payment message arrived during an active phone call.");
  } else if (timeDiffMs !== null && call) {
    if (timeDiffMs <= 120_000) {
      score += isUnknownCall ? 40 : 20;
      patterns.push("immediate_call_to_payment_gap");
      evidence.push(`Payment message occurred within ${formatDur(timeDiffMs)} of the call.`);
    } else if (timeDiffMs <= 600_000) {
      score += isUnknownCall ? 30 : 12;
      patterns.push("short_call_to_payment_gap");
      evidence.push(`Payment message occurred ${formatDur(timeDiffMs)} from the call.`);
    } else if (timeDiffMs <= 1_800_000) {
      score += isUnknownCall ? 18 : 5;
      patterns.push("post_call_30m_window");
      evidence.push(`Payment message occurred ${formatDur(timeDiffMs)} after the call.`);
    }
  }

  if (isUnknownCall && (payment.paymentStatus === "Successful transaction" || payment.paymentStatus === "Payment request")) {
    patterns.push("unknown_caller_correlated_payment");
  }

  if (recentPayments15m >= 2) {
    score += 20;
    patterns.push("multiple_payment_messages");
    evidence.push(`${recentPayments15m} payment-related messages recorded within 15 minutes.`);
  }

  if (parsedCues?.urgentOrThreat) {
    score += 25;
    patterns.push("urgent_or_threat_language");
    evidence.push("Urgent, account-blocking, or threatening language detected.");
  }
  if (parsedCues?.remoteAccessOrCredAsk) {
    score = Math.max(score, 85);
    patterns.push("credential_or_remote_access_cue");
    evidence.push("Mentions OTP/PIN sharing or remote-access tools.");
  }
  if (payment.paymentStatus === "Failed transaction" && score < 50) {
    patterns.push("failed_transaction_attempt");
    evidence.push("Transaction attempt failed; check if unsolicited attempts are occurring.");
  }

  // Explicitly ensure high amount alone with known contact & zero scam/timing pressure stays Low Risk
  if (payment.amount !== null && payment.amount >= 25_000 && patterns.length === 0) {
    evidence.push(
      "Amount is notably large, which alone does not indicate fraud because no suspicious timing or scam cues were present."
    );
  }

  if (questionnaire && !questionnaire.dismissed) {
    if (
      questionnaire.askedSensitiveCreds === "yes_otp_pin_password" ||
      questionnaire.askedSensitiveCreds === "yes_remote_access" ||
      questionnaire.askedToDo === "share_otp_pin" ||
      questionnaire.askedToDo === "install_remote_app"
    ) {
      score = Math.max(score, 90);
      patterns.push("questionnaire_credential_compromise_risk");
      evidence.push("Questionnaire confirmed sensitive credential or remote-access pressure.");
    } else if (questionnaire.askedToDo === "send_money" || questionnaire.askedToDo === "approve_request") {
      score += 20;
      patterns.push("questionnaire_coached_payment");
      evidence.push("User indicated the caller asked them to send money or approve a request.");
    } else if (questionnaire.askedToDo === "none_or_normal" && questionnaire.urgencyPressure === "no") {
      score = Math.max(0, score - 20);
    }
  }

  if (params.sharedItems && params.sharedItems.length > 0) {
    for (const sItem of params.sharedItems) {
      if (sItem.verificationStatus === "High risk" || sItem.verificationStatus === "Confirmed malicious" || sItem.verificationStatus === "Suspicious") {
        score += sItem.verificationStatus === "Suspicious" ? 20 : 30;
        patterns.push("cross_section_shared_payment_flag");
        evidence.push(`Cross-section intelligence (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} (${sItem.verificationStatus}).`);
      }
    }
  }

  let riskLevel: RiskLevel;
  if (score >= 80) riskLevel = "Critical Risk";
  else if (score >= 50) riskLevel = "High Risk";
  else if (score >= 25) riskLevel = "Moderate Risk";
  else riskLevel = "Low Risk";

  const recommendedAction =
    riskLevel === "Critical Risk"
      ? "Stop further payments immediately. Do NOT share any OTP/PIN. Contact your bank directly, call 1930 or report at cybercrime.gov.in, and alert your guardian."
      : riskLevel === "High Risk"
        ? "Pause before making any additional transfers or approving collect requests. Independently verify the recipient with a trusted family member."
        : riskLevel === "Moderate Risk"
          ? "Double-check the recipient and transaction purpose inside your official banking app before proceeding."
          : "No suspicious call-to-payment scam indicators were detected. Keep safeguarding your OTP and UPI PIN.";

  return {
    riskLevel,
    riskCategory:
      payment.paymentStatus === "Payment request"
        ? "Incoming Payment Request"
        : "Transaction Activity Assessment",
    supportingEvidence: evidence,
    detectedPatterns: patterns.length ? patterns : ["no_suspicious_payment_pattern"],
    missingInformation: missing,
    recommendedAction,
    assessedAt: now,
  };
}

function buildFallbackAiReport(params: {
  call: CallWatcherCallRecord | null;
  payment: PaymentMessageRecord | null;
  timeDiffMs: number | null;
  duringCall: boolean;
  callRisk: SeparateRiskAssessment;
  paymentRisk: SeparateRiskAssessment;
  questionnaire: QuestionnaireResponseRecord | null;
  criticalWarningActive: boolean;
  errorReason?: string;
}): CallWatcherAiReportBlock {
  const { call, payment, timeDiffMs, duringCall, callRisk, paymentRisk, questionnaire, criticalWarningActive, errorReason } =
    params;

  const callDesc = call
    ? `${call.callerClassification} call (${call.callStatus}, ${formatDur(call.durationMs)})`
    : "no linked call recorded";
  const payDesc = payment
    ? `${payment.paymentStatus}${payment.amount !== null ? ` of ₹${payment.amount.toLocaleString("en-IN")}` : ""}`
    : "no payment message linked yet";

  const timingNote =
    call && payment
      ? duringCall
        ? "The payment message arrived while the call was active. Timing close to a call is a safety clue to verify carefully, not proof that the caller caused the payment."
        : timeDiffMs !== null
          ? `The payment message and call occurred ${formatDur(timeDiffMs)} apart. Close timing is only an advisory safety clue and never proves causation.`
          : "Exact call-to-payment timing gap could not be determined."
      : "Only partial call or payment timing metadata is currently available.";

  let qInterp = "Caller context questionnaire has not been answered for this event yet.";
  if (questionnaire && !questionnaire.dismissed) {
    qInterp = criticalWarningActive
      ? "Your answers indicate a request for OTP, PIN, password, or remote-access software—treat this as an active critical scam risk."
      : `Recorded caller context: asked to '${questionnaire.askedToDo || "unspecified"}', pressure '${questionnaire.urgencyPressure || "unspecified"}'.`;
  }

  const actions: string[] = criticalWarningActive
    ? [
        "Do NOT share any OTP, UPI PIN, or banking password.",
        "Uninstall any screen-sharing or remote-access app immediately.",
        "Call your bank on its official number and report at 1930 or cybercrime.gov.in.",
        "Notify your linked family guardian before taking any further action.",
      ]
    : [
        callRisk.recommendedAction,
        paymentRisk.recommendedAction,
      ];

  return {
    available: false,
    model: null,
    summary: {
      plainExplanation: `Call Watch logged a ${callDesc} paired with ${payDesc}. Call Risk is assessed separately as ${callRisk.riskLevel} and Payment Risk as ${paymentRisk.riskLevel}.`,
      timingRelationshipNote: timingNote,
      questionnaireInterpretation: qInterp,
      recommendedActions: actions.slice(0, 4),
      uncertaintyStatement:
        "No call audio was heard or transcribed; recipient legitimacy and off-device context remain unverified.",
    },
    ...(errorReason ? { errorReason } : {}),
  };
}

async function generateCorrelationAiReport(params: {
  call: CallWatcherCallRecord | null;
  payment: PaymentMessageRecord | null;
  timeDiffMs: number | null;
  duringCall: boolean;
  callRisk: SeparateRiskAssessment;
  paymentRisk: SeparateRiskAssessment;
  questionnaire: QuestionnaireResponseRecord | null;
  criticalWarningActive: boolean;
  lang: string;
}): Promise<CallWatcherAiReportBlock> {
  const { call, payment, timeDiffMs, duringCall, callRisk, paymentRisk, questionnaire, criticalWarningActive, lang } =
    params;

  // Call Gemini when significant risk, correlation, or critical warning exists; otherwise avoid unnecessary latency if API absent
  const structuredFacts = {
    call: call
      ? {
          classification: call.callerClassification,
          status: call.callStatus,
          durationMs: call.durationMs,
          durationFormatted: formatDur(call.durationMs),
          source: call.source,
        }
      : null,
    payment: payment
      ? {
          status: payment.paymentStatus,
          amount: payment.amount,
          currency: payment.currency,
          txType: payment.txType,
          merchantOrRecipient: payment.merchantOrRecipient,
          accountMasked: payment.accountMasked,
        }
      : null,
    correlation: {
      duringCall,
      timeDiffMs,
      timeDiffFormatted: formatDur(timeDiffMs),
      timingCaveat: "Timing correlation is a safety clue only and never proves causation.",
    },
    callRisk: {
      riskLevel: callRisk.riskLevel,
      evidence: callRisk.supportingEvidence,
      patterns: callRisk.detectedPatterns,
    },
    paymentRisk: {
      riskLevel: paymentRisk.riskLevel,
      evidence: paymentRisk.supportingEvidence,
      patterns: paymentRisk.detectedPatterns,
    },
    questionnaire: questionnaire
      ? {
          askedToDo: questionnaire.askedToDo,
          urgencyPressure: questionnaire.urgencyPressure,
          askedSensitiveCreds: questionnaire.askedSensitiveCreds,
          emotionalFeeling: questionnaire.emotionalFeeling,
          criticalWarningActive,
        }
      : null,
  };

  try {
    const summary = await generateCallWatcherAiReport({ structuredFacts, lang });
    return {
      available: true,
      model: "gemini-4-hydrogen",
      summary,
    };
  } catch (err) {
    return buildFallbackAiReport({
      ...params,
      errorReason: err instanceof Error ? err.message : "Live AI unavailable",
    });
  }
}

function shouldTriggerQuestionnaire(params: {
  call: CallWatcherCallRecord | null;
  payment: PaymentMessageRecord | null;
  callRisk: SeparateRiskAssessment;
  paymentRisk: SeparateRiskAssessment;
  priorQuestionnaire: QuestionnaireResponseRecord | null;
}): { needed: boolean; reason: string | null } {
  const { call, payment, callRisk, paymentRisk, priorQuestionnaire } = params;
  if (!call || call.callerClassification === "Known Contact") {
    return { needed: false, reason: null };
  }
  if (
    payment &&
    (payment.paymentStatus === "Promotional message" ||
      payment.paymentStatus === "Informational banking message")
  ) {
    return { needed: false, reason: null };
  }
  const warranted =
    Boolean(payment) ||
    callRisk.riskLevel === "Moderate Risk" ||
    callRisk.riskLevel === "High Risk" ||
    callRisk.riskLevel === "Critical Risk" ||
    paymentRisk.riskLevel === "High Risk" ||
    paymentRisk.riskLevel === "Critical Risk";

  if (!warranted) return { needed: false, reason: null };

  if (
    priorQuestionnaire &&
    !priorQuestionnaire.dismissed &&
    callRisk.riskLevel !== "Critical Risk" &&
    paymentRisk.riskLevel !== "Critical Risk"
  ) {
    return { needed: false, reason: "Previously answered for this caller within retention window." };
  }

  return {
    needed: true,
    reason: payment
      ? `Payment activity occurred close to a call from '${call.callerClassification}'. Confirming what the caller asked helps separate genuine help from pressure scams.`
      : `An extended or repeated '${call.callerClassification}' call was logged. Confirming caller behavior helps protect you before any payment request arrives.`,
  };
}

async function dispatchSynchronizedNotifications(params: {
  userId: string;
  userName: string;
  callRisk: SeparateRiskAssessment;
  paymentRisk: SeparateRiskAssessment;
  payment: PaymentMessageRecord | null;
  call: CallWatcherCallRecord | null;
  duringCall: boolean;
  timeDiffMs: number | null;
  criticalWarningActive: boolean;
}): Promise<number> {
  const { userId, userName, callRisk, paymentRisk, payment, call, duringCall, timeDiffMs, criticalWarningActive } =
    params;

  const isElevated =
    criticalWarningActive ||
    callRisk.riskLevel === "High Risk" ||
    callRisk.riskLevel === "Critical Risk" ||
    paymentRisk.riskLevel === "Moderate Risk" ||
    paymentRisk.riskLevel === "High Risk" ||
    paymentRisk.riskLevel === "Critical Risk";

  if (!isElevated) return 0;

  const consent = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(userId)) as { guardian_alerts: number; paused: number } | undefined;

  const amtText =
    payment && payment.amount !== null ? `₹${payment.amount.toLocaleString("en-IN")} ` : "";
  const statusText = payment ? payment.paymentStatus : "Call Watch event";
  const timingText =
    call && payment
      ? duringCall
        ? "during an active call"
        : timeDiffMs !== null
          ? `${formatDur(timeDiffMs)} from call`
          : "near a call"
      : call
        ? `${call.callerClassification} (${formatDur(call.durationMs)})`
        : "recent activity";

  const title = criticalWarningActive
    ? "CRITICAL Call Watcher Warning"
    : `Call Watcher Alert (${paymentRisk.riskLevel !== "Low Risk" ? paymentRisk.riskLevel : callRisk.riskLevel})`;

  const userBody = criticalWarningActive
    ? `Sensitive OTP/PIN or remote-access request reported (${statusText} ${amtText}${timingText}). Stop payments, do not share OTP/PIN, call 1930 if fraud occurred.`
    : `${statusText} ${amtText}detected ${timingText}. Call Risk: ${callRisk.riskLevel}; Payment Risk: ${paymentRisk.riskLevel}. Pause and verify independently.`;

  // Notify monitored account owner
  await createNotification(userId, userId, "call_watcher_alert", title, userBody);
  let sent = 1;

  // Notify linked guardians if global guardian_alerts enabled & not paused
  if (consent && consent.guardian_alerts && !consent.paused) {
    const guardians = await getActiveGuardiansForParent(userId);
    const guardianBody = criticalWarningActive
      ? `${userName} reported a critical credential/remote-access call event (${amtText}${timingText}). Please call them on their saved number immediately.`
      : `${userName}: ${statusText} ${amtText}(${timingText}). Call Risk: ${callRisk.riskLevel}, Payment Risk: ${paymentRisk.riskLevel}.`;

    for (const g of guardians) {
      await createNotification(g.guardian_id, userId, "call_watcher_guardian_alert", title, guardianBody);
      sent++;
    }
  }

  return sent;
}

function mapCallRow(row: Record<string, unknown>): CallWatcherCallRecord {
  return {
    id: String(row.id),
    callerClassification: String(row.caller_classification) as CallerClassification,
    callerMasked: row.caller_masked ? String(row.caller_masked) : null,
    callerHash: row.caller_hash ? String(row.caller_hash) : null,
    callStatus: String(row.call_status) as CallStatus,
    callLifecyclePhase: String(row.call_lifecycle_phase || "ended") as CallLifecyclePhase,
    incomingAt: Number(row.incoming_at),
    startedAt: row.started_at !== null && row.started_at !== undefined ? Number(row.started_at) : null,
    endedAt: row.ended_at !== null && row.ended_at !== undefined ? Number(row.ended_at) : null,
    durationMs: row.duration_ms !== null && row.duration_ms !== undefined ? Number(row.duration_ms) : null,
    screeningVerdict: row.screening_verdict ? String(row.screening_verdict) : null,
    screeningLatencyMs:
      row.screening_latency_ms !== null && row.screening_latency_ms !== undefined
        ? Number(row.screening_latency_ms)
        : null,
    simInfo: row.sim_info ? String(row.sim_info) : null,
    source: String(row.source || "user_assisted"),
    createdAt: Number(row.created_at),
  };
}

function mapPaymentRow(row: Record<string, unknown>): PaymentMessageRecord {
  return {
    id: String(row.id),
    senderLabel: row.sender_label ? String(row.sender_label) : null,
    messageTs: Number(row.message_ts),
    amount: row.amount !== null && row.amount !== undefined ? Number(row.amount) : null,
    currency: row.currency ? String(row.currency) : null,
    txType: String(row.tx_type || "Unknown"),
    txRef: row.tx_ref ? String(row.tx_ref) : null,
    upiRef: row.upi_ref ? String(row.upi_ref) : null,
    accountMasked: row.account_masked ? String(row.account_masked) : null,
    merchantOrRecipient: row.merchant_or_recipient ? String(row.merchant_or_recipient) : null,
    paymentStatus: String(row.payment_status) as PaymentStatus,
    redactedSummary: String(row.redacted_summary || ""),
    source: String(row.source || "user_assisted"),
    createdAt: Number(row.created_at),
  };
}

function mapQuestionnaireRow(row: Record<string, unknown>): QuestionnaireResponseRecord {
  return {
    id: String(row.id),
    correlationId: row.correlation_id ? String(row.correlation_id) : null,
    callEventId: row.call_event_id ? String(row.call_event_id) : null,
    callerHash: row.caller_hash ? String(row.caller_hash) : null,
    askedToDo: row.asked_to_do ? String(row.asked_to_do) : null,
    urgencyPressure: row.urgency_pressure ? String(row.urgency_pressure) : null,
    askedSensitiveCreds: row.asked_sensitive_creds ? String(row.asked_sensitive_creds) : null,
    emotionalFeeling: row.emotional_feeling ? String(row.emotional_feeling) : null,
    dismissed: Boolean(row.dismissed),
    criticalWarningTriggered: Boolean(row.critical_warning_triggered),
    createdAt: Number(row.created_at),
  };
}

async function hydrateCorrelationRow(
  userId: string,
  row: Record<string, unknown>,
  extraParent?: { parentId: string; parentName: string }
): Promise<CallWatcherTimelineItem> {
  const callRow = row.call_event_id
    ? ((await db.prepare("SELECT * FROM call_watcher_calls WHERE id = ?").get(String(row.call_event_id))) as
        | Record<string, unknown>
        | undefined)
    : undefined;
  const payRow = row.payment_event_id
    ? ((await db.prepare("SELECT * FROM payment_message_events WHERE id = ?").get(String(row.payment_event_id))) as
        | Record<string, unknown>
        | undefined)
    : undefined;
  const qRow = (await db
    .prepare(
      "SELECT * FROM safety_questionnaire_responses WHERE correlation_id = ? ORDER BY created_at DESC LIMIT 1"
    )
    .get(String(row.id))) as Record<string, unknown> | undefined;

  const call = callRow ? mapCallRow(callRow) : null;
  const payment = payRow ? mapPaymentRow(payRow) : null;
  const questionnaire = qRow ? mapQuestionnaireRow(qRow) : null;
  const callRisk = JSON.parse(String(row.call_risk_json)) as SeparateRiskAssessment;
  const paymentRisk = JSON.parse(String(row.payment_risk_json)) as SeparateRiskAssessment;
  const aiReport = JSON.parse(String(row.ai_report_json)) as CallWatcherAiReportBlock;

  let priorQ: QuestionnaireResponseRecord | null = null;
  if (!questionnaire && call?.callerHash) {
    const prev = (await db
      .prepare(
        "SELECT * FROM safety_questionnaire_responses WHERE user_id = ? AND caller_hash = ? AND dismissed = 0 ORDER BY created_at DESC LIMIT 1"
      )
      .get(userId, call.callerHash)) as Record<string, unknown> | undefined;
    priorQ = prev ? mapQuestionnaireRow(prev) : null;
  }

  const qCheck = questionnaire
    ? { needed: false, reason: null }
    : shouldTriggerQuestionnaire({
        call,
        payment,
        callRisk,
        paymentRisk,
        priorQuestionnaire: priorQ,
      });

  const criticalWarningActive =
    Boolean(questionnaire?.criticalWarningTriggered) ||
    callRisk.riskLevel === "Critical Risk" ||
    paymentRisk.riskLevel === "Critical Risk";

  const sharedIntelligence = call ? await inputCallerLookup(userId, call.callerMasked) : [];

  return {
    correlationId: String(row.id),
    ...(extraParent ? extraParent : {}),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    status: String(row.status || "open"),
    timeDiffMs: row.time_diff_ms !== null && row.time_diff_ms !== undefined ? Number(row.time_diff_ms) : null,
    duringCall: Boolean(row.during_call),
    detectedPatterns: JSON.parse(String(row.patterns_json || "[]")) as string[],
    call,
    payment,
    callRisk,
    paymentRisk,
    aiReport,
    questionnaire,
    questionnaireNeeded: qCheck.needed && String(row.status) !== "dismissed",
    questionnaireReason: qCheck.reason,
    criticalWarningActive,
    parentNotifiedCount: Number(row.parent_notified_count || 0),
    ...(sharedIntelligence.length ? { sharedIntelligence } : {}),
  };
}

export async function recordCallWatcherCall(
  userId: string,
  userName: string,
  input: {
    externalEventId?: string;
    callerIdentifier?: string | null;
    callerClassification?: CallerClassification;
    callStatus?: CallStatus;
    callLifecyclePhase?: CallLifecyclePhase;
    incomingAt?: number;
    startedAt?: number | null;
    endedAt?: number | null;
    durationMs?: number | null;
    screeningVerdict?: string | null;
    screeningLatencyMs?: number | null;
    simInfo?: string | null;
    source?: string;
  },
  lang = "en"
): Promise<{
  call: CallWatcherCallRecord;
  duplicate: boolean;
  correlation: CallWatcherTimelineItem | null;
}> {
  const settings = await ensureCallWatcherSettings(userId);
  if (!settings.consentGiven || settings.monitoringState !== "active") {
    throw new Error(
      settings.monitoringState === "paused"
        ? "Call Watcher is paused. Resume monitoring first."
        : "Activate Call Watcher consent before logging call events."
    );
  }

  const extId = input.externalEventId ? String(input.externalEventId).trim().slice(0, 80) : null;
  if (extId) {
    const existing = (await db
      .prepare("SELECT * FROM call_watcher_calls WHERE user_id = ? AND external_event_id = ?")
      .get(userId, extId)) as Record<string, unknown> | undefined;
    if (existing) {
      return { call: mapCallRow(existing), duplicate: true, correlation: null };
    }
  }

  const validClassifications: CallerClassification[] = [
    "Known Contact",
    "Unknown Number",
    "Private/Hidden Number",
    "Unavailable Caller Information",
  ];
  const callerClassification: CallerClassification = validClassifications.includes(
    input.callerClassification as CallerClassification
  )
    ? (input.callerClassification as CallerClassification)
    : "Unknown Number";

  const validStatuses: CallStatus[] = ["Answered", "Missed", "Rejected", "Unavailable"];
  const callStatus: CallStatus = validStatuses.includes(input.callStatus as CallStatus)
    ? (input.callStatus as CallStatus)
    : "Answered";

  const validPhases: CallLifecyclePhase[] = [
    "ringing",
    "answered",
    "ended",
    "missed",
    "rejected",
    "unavailable",
  ];
  const callLifecyclePhase: CallLifecyclePhase = validPhases.includes(
    input.callLifecyclePhase as CallLifecyclePhase
  )
    ? (input.callLifecyclePhase as CallLifecyclePhase)
    : callStatus === "Missed"
      ? "missed"
      : callStatus === "Rejected"
        ? "rejected"
        : "ended";

  const now = Date.now();
  const incomingAt =
    input.incomingAt && Number.isFinite(input.incomingAt) ? Math.round(input.incomingAt) : now;
  const startedAt =
    input.startedAt !== undefined && input.startedAt !== null && Number.isFinite(input.startedAt)
      ? Math.round(input.startedAt)
      : null;
  const endedAt =
    input.endedAt !== undefined && input.endedAt !== null && Number.isFinite(input.endedAt)
      ? Math.round(input.endedAt)
      : null;

  let durationMs: number | null = null;
  if (startedAt !== null && endedAt !== null && endedAt >= startedAt) {
    durationMs = endedAt - startedAt;
  } else if (
    input.durationMs !== undefined &&
    input.durationMs !== null &&
    Number.isFinite(input.durationMs) &&
    input.durationMs >= 0
  ) {
    durationMs = Math.round(input.durationMs);
  }

  const { callerMasked, callerHash } = maskCallerIdentifier(
    userId,
    input.callerIdentifier,
    callerClassification
  );
  const simInfo = input.simInfo ? String(input.simInfo).trim().slice(0, 40) : null;
  const source =
    input.source === "android_bridge" || input.source === "simulated"
      ? input.source
      : "user_assisted";
  const screeningVerdict = input.screeningVerdict ? String(input.screeningVerdict).slice(0, 40) : null;
  const screeningLatencyMs =
    input.screeningLatencyMs !== undefined &&
    input.screeningLatencyMs !== null &&
    Number.isFinite(input.screeningLatencyMs)
      ? Math.max(0, Math.round(input.screeningLatencyMs))
      : null;

  const callId = generateId("cwc");
  await db.prepare(
    `INSERT INTO call_watcher_calls (
      id, user_id, external_event_id, caller_classification, caller_masked, caller_hash,
      call_status, incoming_at, started_at, ended_at, duration_ms, sim_info, source, created_at,
      call_lifecycle_phase, screening_verdict, screening_latency_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    callId,
    userId,
    extId,
    callerClassification,
    callerMasked,
    callerHash,
    callStatus,
    incomingAt,
    startedAt,
    endedAt,
    durationMs,
    simInfo,
    source,
    now,
    callLifecyclePhase,
    screeningVerdict,
    screeningLatencyMs
  );

  await db.prepare("UPDATE call_watcher_settings SET last_event_at = ?, updated_at = ? WHERE user_id = ?").run(
    now,
    now,
    userId
  );

  const callRow = (await db.prepare("SELECT * FROM call_watcher_calls WHERE id = ?").get(callId)) as Record<
    string,
    unknown
  >;
  const call = mapCallRow(callRow);

  await writeAudit(
    userId,
    `Call Watcher logged call (${callerClassification}, ${callStatus}, phase=${callLifecyclePhase}, dur=${durationMs === null ? "unavailable" : formatDur(durationMs)})`
  );

  // Unknown-call notification preference
  if (
    settings.notifyUnknownCalls &&
    (callerClassification === "Unknown Number" || callerClassification === "Private/Hidden Number")
  ) {
    await createNotification(
      userId,
      userId,
      "call_watcher_unknown_call",
      "Unknown Call Logged",
      `${callerClassification} (${callStatus}, ${formatDur(durationMs)}) recorded by Call Watcher (metadata only, no audio).`
    );
  }

  // Out-of-order check: did a payment message arrive slightly before this call arrived in backend ([-5 min, +60 min])?
  const refTime = endedAt ?? startedAt ?? incomingAt;
  const unlinkedPay = (await db
    .prepare(
      `SELECT p.* FROM payment_message_events p
       LEFT JOIN call_payment_correlations c ON c.payment_event_id = p.id AND c.call_event_id IS NOT NULL
       WHERE p.user_id = ? AND c.id IS NULL AND p.message_ts >= ? AND p.message_ts <= ?
       ORDER BY ABS(p.message_ts - ?) ASC LIMIT 1`
    )
    .get(userId, refTime - 300_000, refTime + 3_600_000, refTime)) as Record<string, unknown> | undefined;

  let correlation: CallWatcherTimelineItem | null = null;
  if (unlinkedPay) {
    const payment = mapPaymentRow(unlinkedPay);
    correlation = await createOrUpdateCorrelation({
      userId,
      userName,
      call,
      payment,
      lang,
    });
  } else if (callLifecyclePhase !== "ringing" && callLifecyclePhase !== "answered") {
    // Evaluate standalone completed call risk (long calls alone stay Low Risk unless corroborated)
    const ctx = await getPriorCallerContext(userId, call.callerHash, call.incomingAt);
    const sharedPhoneItems = await inputCallerLookup(userId, call.callerMasked);
    const callRisk = assessCallRisk({
      call,
      unknownCalls30m: ctx.unknownCalls30m,
      sameCaller24h: ctx.sameCaller24h,
      questionnaire: ctx.priorQuestionnaire,
      sharedItems: sharedPhoneItems,
    });
    if (
      callerClassification !== "Known Contact" &&
      (callRisk.riskLevel === "Moderate Risk" ||
        callRisk.riskLevel === "High Risk" ||
        callRisk.riskLevel === "Critical Risk")
    ) {
      correlation = await createOrUpdateCorrelation({
        userId,
        userName,
        call,
        payment: null,
        lang,
      });
    }
  }

  try {
    await ingestGsiEvent({
      familyOwnerId: userId,
      familyOwnerName: userName,
      eventType: "call_event",
      eventTimestamp: call.incomingAt,
      sourceModule: call.source === "android_bridge" ? "module_a_android_bridge" : "module_a_call_watcher",
      lang: lang === "hi" ? "hi" : "en",
      callData: {
        callerClassification: call.callerClassification,
        callerIdentifier: input.callerIdentifier || null,
        callerMasked: call.callerMasked,
        callerHash: call.callerHash,
        callStatus: call.callStatus,
        durationMs: call.durationMs,
        known: call.callerClassification === "Known Contact",
      },
    });
  } catch {
    // Non-blocking GSI telemetry hook
  }

  return { call, duplicate: false, correlation };
}

async function createOrUpdateCorrelation(params: {
  userId: string;
  userName: string;
  call: CallWatcherCallRecord | null;
  payment: PaymentMessageRecord | null;
  parsedCues?: ParsedPaymentMessage["cues"];
  lang: string;
}): Promise<CallWatcherTimelineItem> {
  const { userId, userName, call, payment, parsedCues, lang } = params;
  const now = Date.now();

  const ctx = call
    ? await getPriorCallerContext(userId, call.callerHash, call.incomingAt)
    : { unknownCalls30m: 0, sameCaller24h: 0, priorQuestionnaire: null };

  let timeDiffMs: number | null = null;
  let duringCall = false;
  if (call && payment) {
    if (call.startedAt !== null && payment.messageTs >= call.startedAt && (call.endedAt === null || payment.messageTs <= call.endedAt)) {
      duringCall = true;
      timeDiffMs = 0;
    } else {
      const ref = call.endedAt ?? call.startedAt ?? call.incomingAt;
      timeDiffMs = Math.abs(payment.messageTs - ref);
    }
  }

  const recentPayRow = payment
    ? ((await db
        .prepare(
          `SELECT COUNT(*) as cnt FROM payment_message_events
           WHERE user_id = ? AND message_ts >= ? AND message_ts <= ?
             AND payment_status NOT IN ('Promotional message', 'Informational banking message', 'Unknown or unclassified message')`
        )
        .get(userId, payment.messageTs - 900_000, payment.messageTs + 60_000)) as { cnt: number })
    : { cnt: 0 };

  const sharedPhoneItems = call ? await inputCallerLookup(userId, call.callerMasked) : [];
  const sharedPayItems =
    payment?.merchantOrRecipient
      ? await lookupSharedEntitiesForQuery({
          familyOwnerId: userId,
          candidates: extractEntitiesFromPayment({ beneficiary: payment.merchantOrRecipient }),
          currentSection: "call_scam",
        })
      : [];

  const hasPaymentCorroboration = Boolean(
    payment &&
      payment.paymentStatus !== "Promotional message" &&
      payment.paymentStatus !== "Informational banking message" &&
      (duringCall || (timeDiffMs !== null && timeDiffMs <= 600_000) || parsedCues?.urgentOrThreat || parsedCues?.remoteAccessOrCredAsk)
  );

  const callRisk = assessCallRisk({
    call,
    unknownCalls30m: ctx.unknownCalls30m,
    sameCaller24h: ctx.sameCaller24h,
    questionnaire: ctx.priorQuestionnaire,
    sharedItems: sharedPhoneItems,
    hasCorroboratingContext: hasPaymentCorroboration,
  });

  const paymentRisk = assessPaymentRisk({
    payment,
    parsedCues,
    call,
    timeDiffMs,
    duringCall,
    recentPayments15m: Number(recentPayRow?.cnt || 0),
    questionnaire: ctx.priorQuestionnaire,
    sharedItems: sharedPayItems,
  });

  const patterns = Array.from(
    new Set([...callRisk.detectedPatterns, ...paymentRisk.detectedPatterns])
  );

  const criticalWarningActive =
    callRisk.riskLevel === "Critical Risk" || paymentRisk.riskLevel === "Critical Risk";

  const aiReport = await generateCorrelationAiReport({
    call,
    payment,
    timeDiffMs,
    duringCall,
    callRisk,
    paymentRisk,
    questionnaire: ctx.priorQuestionnaire,
    criticalWarningActive,
    lang,
  });

  const parentNotifiedCount = await dispatchSynchronizedNotifications({
    userId,
    userName,
    callRisk,
    paymentRisk,
    payment,
    call,
    duringCall,
    timeDiffMs,
    criticalWarningActive,
  });

  const corrId = generateId("cwc_r");
  await db.prepare(
    `INSERT INTO call_payment_correlations (
      id, user_id, call_event_id, payment_event_id, time_diff_ms, during_call,
      patterns_json, call_risk_level, call_risk_json, payment_risk_level, payment_risk_json,
      ai_report_json, parent_notified_count, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`
  ).run(
    corrId,
    userId,
    call ? call.id : null,
    payment ? payment.id : null,
    timeDiffMs,
    duringCall ? 1 : 0,
    JSON.stringify(patterns),
    callRisk.riskLevel,
    JSON.stringify(callRisk),
    paymentRisk.riskLevel,
    JSON.stringify(paymentRisk),
    JSON.stringify(aiReport),
    parentNotifiedCount,
    now,
    now
  );

  await writeAudit(
    userId,
    `Call Watcher correlation ${corrId}: Call=${callRisk.riskLevel}, Payment=${paymentRisk.riskLevel}`
  );

  const row = (await db
    .prepare("SELECT * FROM call_payment_correlations WHERE id = ?")
    .get(corrId)) as Record<string, unknown>;
  return hydrateCorrelationRow(userId, row);
}

export async function recordPaymentMessageEvent(
  userId: string,
  userName: string,
  input: {
    rawMessageText: string;
    senderLabel?: string | null;
    messageTs?: number;
    source?: string;
    linkedCallId?: string | null;
  },
  lang = "en"
): Promise<{
  duplicate: boolean;
  payment: PaymentMessageRecord;
  correlation: CallWatcherTimelineItem;
}> {
  const settings = await ensureCallWatcherSettings(userId);
  if (!settings.consentGiven || settings.monitoringState !== "active") {
    throw new Error(
      settings.monitoringState === "paused"
        ? "Call Watcher is paused. Resume monitoring first."
        : "Activate Call Watcher consent before logging payment messages."
    );
  }

  const rawText = String(input.rawMessageText || "").trim();
  if (rawText.length < 4) {
    throw new Error("Provide a payment SMS or notification text to analyze.");
  }

  const parsed = parsePaymentMessage(rawText, input.senderLabel, input.messageTs);

  // Deduplication check
  const existingPay = (await db
    .prepare("SELECT * FROM payment_message_events WHERE user_id = ? AND dedup_hash = ?")
    .get(userId, parsed.dedupHash)) as Record<string, unknown> | undefined;

  if (existingPay) {
    const payment = mapPaymentRow(existingPay);
    const existingCorr = (await db
      .prepare(
        "SELECT * FROM call_payment_correlations WHERE user_id = ? AND payment_event_id = ? ORDER BY created_at DESC LIMIT 1"
      )
      .get(userId, payment.id)) as Record<string, unknown> | undefined;

    if (existingCorr) {
      return {
        duplicate: true,
        payment,
        correlation: await hydrateCorrelationRow(userId, existingCorr),
      };
    }
  }

  const now = Date.now();
  const payId = generateId("pmt");
  const source =
    input.source === "android_bridge" || input.source === "simulated"
      ? input.source
      : "user_assisted";

  await db.prepare(
    `INSERT INTO payment_message_events (
      id, user_id, dedup_hash, sender_label, message_ts, amount, currency,
      tx_type, tx_ref, upi_ref, account_masked, merchant_or_recipient,
      payment_status, redacted_summary, source, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    payId,
    userId,
    parsed.dedupHash,
    parsed.senderLabel,
    parsed.messageTs,
    parsed.amount,
    parsed.currency,
    parsed.txType,
    parsed.txRef,
    parsed.upiRef,
    parsed.accountMasked,
    parsed.merchantOrRecipient,
    parsed.paymentStatus,
    parsed.redactedSummary,
    source,
    now
  );

  await db.prepare("UPDATE call_watcher_settings SET last_event_at = ?, updated_at = ? WHERE user_id = ?").run(
    now,
    now,
    userId
  );

  const payRow = (await db
    .prepare("SELECT * FROM payment_message_events WHERE id = ?")
    .get(payId)) as Record<string, unknown>;
  const payment = mapPaymentRow(payRow);

  // Find matching call (explicit linkedCallId or most recent within [-60m, +5m])
  let callRow: Record<string, unknown> | undefined;
  if (input.linkedCallId) {
    callRow = (await db
      .prepare("SELECT * FROM call_watcher_calls WHERE id = ? AND user_id = ?")
      .get(String(input.linkedCallId), userId)) as Record<string, unknown> | undefined;
  }
  if (!callRow) {
    callRow = (await db
      .prepare(
        `SELECT * FROM call_watcher_calls
         WHERE user_id = ? AND incoming_at >= ? AND incoming_at <= ?
         ORDER BY incoming_at DESC LIMIT 1`
      )
      .get(userId, parsed.messageTs - 3_600_000, parsed.messageTs + 300_000)) as
      | Record<string, unknown>
      | undefined;
  }

  const call = callRow ? mapCallRow(callRow) : null;
  const correlation = await createOrUpdateCorrelation({
    userId,
    userName,
    call,
    payment,
    parsedCues: parsed.cues,
    lang,
  });

  try {
    await ingestGsiEvent({
      familyOwnerId: userId,
      familyOwnerName: userName,
      eventType: "sms_event",
      eventTimestamp: parsed.messageTs,
      sourceModule: source === "android_bridge" ? "module_b_android_bridge" : "module_b_sms_watcher",
      lang: lang === "hi" ? "hi" : "en",
      smsData: {
        rawText,
        senderLabel: parsed.senderLabel,
        amount: parsed.amount,
        paymentStatus: parsed.paymentStatus,
      },
    });
  } catch {
    // Non-blocking GSI telemetry hook
  }

  return { duplicate: false, payment, correlation };
}

export async function submitSafetyQuestionnaire(
  userId: string,
  userName: string,
  input: {
    correlationId: string;
    askedToDo?: string;
    urgencyPressure?: string;
    askedSensitiveCreds?: string;
    emotionalFeeling?: string;
    dismissed?: boolean;
  },
  lang = "en"
): Promise<CallWatcherTimelineItem> {
  const corrRow = (await db
    .prepare("SELECT * FROM call_payment_correlations WHERE id = ? AND user_id = ?")
    .get(String(input.correlationId || ""), userId)) as Record<string, unknown> | undefined;

  if (!corrRow) {
    throw new Error("Correlation event not found.");
  }

  const callRow = corrRow.call_event_id
    ? ((await db.prepare("SELECT * FROM call_watcher_calls WHERE id = ?").get(String(corrRow.call_event_id))) as
        | Record<string, unknown>
        | undefined)
    : undefined;
  const payRow = corrRow.payment_event_id
    ? ((await db
        .prepare("SELECT * FROM payment_message_events WHERE id = ?")
        .get(String(corrRow.payment_event_id))) as Record<string, unknown> | undefined)
    : undefined;

  const call = callRow ? mapCallRow(callRow) : null;
  const payment = payRow ? mapPaymentRow(payRow) : null;
  const now = Date.now();
  const dismissed = Boolean(input.dismissed);

  const criticalTriggered =
    !dismissed &&
    (input.askedSensitiveCreds === "yes_otp_pin_password" ||
      input.askedSensitiveCreds === "yes_remote_access" ||
      input.askedToDo === "share_otp_pin" ||
      input.askedToDo === "install_remote_app");

  const qId = generateId("cwq");
  await db.prepare(
    `INSERT INTO safety_questionnaire_responses (
      id, user_id, correlation_id, call_event_id, caller_hash,
      asked_to_do, urgency_pressure, asked_sensitive_creds, emotional_feeling,
      dismissed, critical_warning_triggered, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    qId,
    userId,
    String(corrRow.id),
    call ? call.id : null,
    call ? call.callerHash : null,
    input.askedToDo ? String(input.askedToDo).slice(0, 60) : null,
    input.urgencyPressure ? String(input.urgencyPressure).slice(0, 60) : null,
    input.askedSensitiveCreds ? String(input.askedSensitiveCreds).slice(0, 60) : null,
    input.emotionalFeeling ? String(input.emotionalFeeling).slice(0, 60) : null,
    dismissed ? 1 : 0,
    criticalTriggered ? 1 : 0,
    now
  );

  const qRow = (await db.prepare("SELECT * FROM safety_questionnaire_responses WHERE id = ?").get(qId)) as Record<
    string,
    unknown
  >;
  const questionnaire = mapQuestionnaireRow(qRow);

  if (dismissed) {
    await db.prepare(
      "UPDATE call_payment_correlations SET status = 'dismissed', updated_at = ? WHERE id = ?"
    ).run(now, String(corrRow.id));
    await writeAudit(userId, `Questionnaire postponed/dismissed for ${String(corrRow.id)}`);
    const updated = (await db
      .prepare("SELECT * FROM call_payment_correlations WHERE id = ?")
      .get(String(corrRow.id))) as Record<string, unknown>;
    return hydrateCorrelationRow(userId, updated);
  }

  // Recalculate both assessments and AI explanation using updated questionnaire answers
  const ctx = call
    ? await getPriorCallerContext(userId, call.callerHash, call.incomingAt)
    : { unknownCalls30m: 0, sameCaller24h: 0, priorQuestionnaire: null };
  const timeDiffMs =
    corrRow.time_diff_ms !== null && corrRow.time_diff_ms !== undefined
      ? Number(corrRow.time_diff_ms)
      : null;
  const duringCall = Boolean(corrRow.during_call);

  const callRisk = assessCallRisk({
    call,
    unknownCalls30m: ctx.unknownCalls30m,
    sameCaller24h: ctx.sameCaller24h,
    questionnaire,
  });

  const paymentRisk = assessPaymentRisk({
    payment,
    call,
    timeDiffMs,
    duringCall,
    recentPayments15m: 1,
    questionnaire,
  });

  const patterns = Array.from(
    new Set([...callRisk.detectedPatterns, ...paymentRisk.detectedPatterns])
  );

  const aiReport = await generateCorrelationAiReport({
    call,
    payment,
    timeDiffMs,
    duringCall,
    callRisk,
    paymentRisk,
    questionnaire,
    criticalWarningActive: criticalTriggered || callRisk.riskLevel === "Critical Risk",
    lang,
  });

  const notified = await dispatchSynchronizedNotifications({
    userId,
    userName,
    callRisk,
    paymentRisk,
    payment,
    call,
    duringCall,
    timeDiffMs,
    criticalWarningActive: criticalTriggered,
  });

  await db.prepare(
    `UPDATE call_payment_correlations SET
       patterns_json = ?,
       call_risk_level = ?,
       call_risk_json = ?,
       payment_risk_level = ?,
       payment_risk_json = ?,
       ai_report_json = ?,
       parent_notified_count = parent_notified_count + ?,
       status = ?,
       updated_at = ?
     WHERE id = ?`
  ).run(
    JSON.stringify(patterns),
    callRisk.riskLevel,
    JSON.stringify(callRisk),
    paymentRisk.riskLevel,
    JSON.stringify(paymentRisk),
    JSON.stringify(aiReport),
    notified,
    criticalTriggered ? "critical_alert" : "answered",
    now,
    String(corrRow.id)
  );

  await writeAudit(
    userId,
    `Questionnaire answered (${criticalTriggered ? "CRITICAL OTP/PIN/REMOTE warning" : "updated"})`
  );

  const updated = (await db
    .prepare("SELECT * FROM call_payment_correlations WHERE id = ?")
    .get(String(corrRow.id))) as Record<string, unknown>;
  return hydrateCorrelationRow(userId, updated);
}

export async function getCallWatcherDashboard(userId: string): Promise<CallWatcherDashboard> {
  const settings = await ensureCallWatcherSettings(userId);
  const since = Date.now() - 7 * 86_400_000;

  const recentCallsCount = Number(
    (
      (await db
        .prepare("SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND incoming_at >= ?")
        .get(userId, since)) as { cnt: number }
    )?.cnt || 0
  );
  const unknownCallsCount = Number(
    (
      (await db
        .prepare(
          "SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND incoming_at >= ? AND caller_classification != 'Known Contact'"
        )
        .get(userId, since)) as { cnt: number }
    )?.cnt || 0
  );
  const paymentEventsCount = Number(
    (
      (await db
        .prepare("SELECT COUNT(*) as cnt FROM payment_message_events WHERE user_id = ? AND message_ts >= ?")
        .get(userId, since)) as { cnt: number }
    )?.cnt || 0
  );

  const corrRows = (await db
    .prepare(
      "SELECT * FROM call_payment_correlations WHERE user_id = ? ORDER BY created_at DESC LIMIT 25"
    )
    .all(userId)) as Record<string, unknown>[];

  const timeline = await Promise.all(corrRows.map((r) => hydrateCorrelationRow(userId, r)));
  const correlatedAlertsCount = timeline.filter(
    (item) =>
      item.callRisk.riskLevel !== "Low Risk" || item.paymentRisk.riskLevel !== "Low Risk"
  ).length;
  const criticalAlertsCount = timeline.filter((item) => item.criticalWarningActive).length;
  const pendingItems = timeline.filter((item) => item.questionnaireNeeded && !item.questionnaire);

  return {
    settings,
    summary: {
      recentCallsCount,
      unknownCallsCount,
      paymentEventsCount,
      correlatedAlertsCount,
      criticalAlertsCount,
      pendingQuestionnairesCount: pendingItems.length,
    },
    timeline,
    pendingQuestionnaire: pendingItems[0] || null,
  };
}

export async function getGuardianSharedCallWatcher(
  permittedParents: { id: string; name: string }[]
): Promise<CallWatcherTimelineItem[]> {
  if (!permittedParents.length) return [];
  const nameMap = new Map(permittedParents.map((p) => [p.id, p.name]));
  const ids = permittedParents.map((p) => p.id);
  const rows = (await db
    .prepare(
      `SELECT c.* FROM call_payment_correlations c
       JOIN consents cs ON cs.user_id = c.user_id
       WHERE c.user_id IN (${ids.map(() => "?").join(",")})
         AND cs.guardian_alerts = 1 AND cs.paused = 0
       ORDER BY c.created_at DESC LIMIT 20`
    )
    .all(...ids)) as Record<string, unknown>[];

  return Promise.all(
    rows.map((r) => {
      const pid = String(r.user_id);
      return hydrateCorrelationRow(pid, r, {
        parentId: pid,
        parentName: nameMap.get(pid) || "Linked Parent",
      });
    })
  );
}

/* ---- CallScreeningService Fast Local Lookup, Threat Cache & Lifecycle Extensions ---- */

export async function screenIncomingCaller(
  userId: string,
  input: {
    callerIdentifier?: string | null;
    callerClassification?: CallerClassification;
    callScreeningRoleGranted?: boolean;
  }
): Promise<CallScreeningResult> {
  const startedPerf = Date.now();
  const validClassifications: CallerClassification[] = [
    "Known Contact",
    "Unknown Number",
    "Private/Hidden Number",
    "Unavailable Caller Information",
  ];
  const callerClassification: CallerClassification = validClassifications.includes(
    input.callerClassification as CallerClassification
  )
    ? (input.callerClassification as CallerClassification)
    : input.callerIdentifier
      ? "Unknown Number"
      : "Unavailable Caller Information";

  const { callerMasked, callerHash } = maskCallerIdentifier(
    userId,
    input.callerIdentifier,
    callerClassification
  );
  const normalizedPhone = input.callerIdentifier
    ? normalizeEntityValue("phone_number", input.callerIdentifier)
    : null;

  const evidence: string[] = [];
  let reputationClass: CallScreeningResult["reputationClass"] =
    callerClassification === "Known Contact" ? "Trusted" : "Unknown";
  let riskLevel: RiskLevel =
    callerClassification === "Known Contact"
      ? "Low Risk"
      : callerClassification === "Unavailable Caller Information"
        ? "Inconclusive"
        : "Moderate Risk";
  let verdict: CallScreeningResult["verdict"] =
    callerClassification === "Known Contact" ? "allow_normal" : "allow_caution";
  let confidence = callerClassification === "Known Contact" ? 0.8 : 0.45;
  let matchedEntityId: string | null = null;

  if (callerClassification === "Private/Hidden Number") {
    reputationClass = "Suspicious";
    riskLevel = "Moderate Risk";
    confidence = 0.65;
    evidence.push("Caller withheld their phone number (Private/Hidden).");
  } else if (callerClassification === "Unknown Number") {
    evidence.push("Caller is not in saved contacts (unknown caller alone is NOT treated as high-risk spam).");
  } else if (callerClassification === "Known Contact") {
    evidence.push("Caller matches a saved contact (verify independently if urgent money is requested).");
  }

  // Fast threat lookup (zero external LLM delay)
  if (callerHash) {
    const intelRow = (await db
      .prepare(
        `SELECT reputation_label, confidence, report_count, false_positive_count, evidence_summary
         FROM gsi_threat_intel
         WHERE (user_id IS NULL OR user_id = ?) AND indicator_type = 'phone_hash' AND indicator_hash = ?
         ORDER BY updated_at DESC LIMIT 1`
      )
      .get(userId, callerHash)) as
      | {
          reputation_label: string;
          confidence: number;
          report_count: number;
          false_positive_count: number;
          evidence_summary: string;
        }
      | undefined;

    if (intelRow) {
      if (intelRow.reputation_label === "Trusted" || intelRow.false_positive_count > intelRow.report_count) {
        reputationClass = "Trusted";
        riskLevel = "Low Risk";
        verdict = "allow_normal";
        confidence = Math.max(0.75, Number(intelRow.confidence || 0.8));
        evidence.push("Marked as trusted in family threat intelligence (never blindly exempts OTP/PIN pressure).");
      } else if (
        intelRow.reputation_label === "Verified Spam" ||
        intelRow.reputation_label === "High Risk" ||
        intelRow.report_count >= 2
      ) {
        reputationClass =
          intelRow.reputation_label === "Verified Spam" ? "Verified Spam" : "High Risk";
        riskLevel = "High Risk";
        verdict = "allow_with_warning";
        confidence = Math.max(0.82, Number(intelRow.confidence || 0.85));
        evidence.push(
          `Credible local intelligence: ${intelRow.reputation_label} (${intelRow.report_count} report(s)) — ${intelRow.evidence_summary}`
        );
      } else if (intelRow.reputation_label === "Suspicious") {
        reputationClass = "Suspicious";
        riskLevel = "Moderate Risk";
        verdict = "allow_caution";
        confidence = Math.max(0.6, Number(intelRow.confidence || 0.65));
        evidence.push(`Prior caution flag recorded (${intelRow.evidence_summary}).`);
      }
    }
  }

  if (normalizedPhone) {
    const gcihEntity = (await db
      .prepare(
        `SELECT id, verification_status, risk_classification, confidence, report_count, fp_count
         FROM gcih_entities
         WHERE family_owner_id = ? AND entity_type = 'phone_number' AND normalized_hash = ?
         LIMIT 1`
      )
      .get(userId, normalizedPhone.normalizedHash)) as
      | {
          id: string;
          verification_status: string;
          risk_classification: string;
          confidence: number;
          report_count: number;
          fp_count: number;
        }
      | undefined;

    if (gcihEntity) {
      matchedEntityId = String(gcihEntity.id);
      if (gcihEntity.verification_status === "Verified legitimate") {
        reputationClass = "Trusted";
        riskLevel = "Low Risk";
        verdict = "allow_normal";
        confidence = Math.max(confidence, Number(gcihEntity.confidence || 0.85));
        evidence.push("Family Central Intelligence verified this number as legitimate.");
      } else if (
        gcihEntity.verification_status === "Confirmed malicious" ||
        gcihEntity.verification_status === "High risk" ||
        gcihEntity.risk_classification === "Critical" ||
        gcihEntity.risk_classification === "High"
      ) {
        reputationClass =
          gcihEntity.verification_status === "Confirmed malicious" ? "Verified Spam" : "High Risk";
        riskLevel = gcihEntity.risk_classification === "Critical" ? "Critical Risk" : "High Risk";
        verdict = "allow_with_warning";
        confidence = Math.max(confidence, Number(gcihEntity.confidence || 0.86));
        evidence.push(
          `Shared family intelligence flagged caller (${gcihEntity.verification_status}, ${gcihEntity.report_count} report(s)).`
        );
      } else if (gcihEntity.verification_status === "Suspicious") {
        reputationClass = "Suspicious";
        if (riskLevel === "Low Risk" || riskLevel === "Inconclusive") riskLevel = "Moderate Risk";
        evidence.push("Shared family intelligence marked this caller under caution.");
      }
    }
  }

  // Repeat burst check inside SQLite call_watcher_calls
  if (callerHash && callerClassification !== "Known Contact") {
    const recentCntRow = (await db
      .prepare("SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND caller_hash = ? AND incoming_at >= ?")
      .get(userId, callerHash, Date.now() - 86_400_000)) as { cnt: number };
    const cnt24 = Number(recentCntRow?.cnt || 0);
    if (cnt24 >= 3 && reputationClass !== "Trusted") {
      riskLevel = riskLevel === "Critical Risk" ? "Critical Risk" : "High Risk";
      verdict = "allow_with_warning";
      reputationClass = reputationClass === "Verified Spam" ? "Verified Spam" : "High Risk";
      confidence = Math.max(confidence, 0.8);
      evidence.push(`Repeated contact from same caller (${cnt24} recent calls within 24h).`);
    }
  }

  const recommendations =
    verdict === "allow_with_warning"
      ? [
          "Guardian NEVER silently drops calls — this alert is advisory so you stay in control.",
          "Do NOT share OTP, UPI PIN, passwords, or install screen-sharing apps (AnyDesk/TeamViewer).",
          "Hang up and call a trusted family guardian or official bank helpline if pressured.",
        ]
      : verdict === "allow_caution"
        ? [
            "Unknown caller alone does NOT prove fraud. Listen carefully without rushing.",
            "Pause immediately if anyone demands urgent money, OTP, PIN, or secrecy.",
          ]
        : [
            "No adverse call-screening flags found. Remember caller IDs can still be spoofed.",
          ];

  const lookupLatencyMs = Math.max(0, Date.now() - startedPerf);

  return {
    verdict,
    callerClassification,
    callerMasked,
    callerHash,
    reputationClass,
    riskLevel,
    confidence: Number(confidence.toFixed(2)),
    evidence,
    recommendations,
    matchedEntityId,
    callScreeningRoleGranted: Boolean(input.callScreeningRoleGranted),
    lookupLatencyMs,
    neverAutoBlocked: true,
    noAudioCollected: true,
  };
}

export async function getLocalCallThreatCache(userId: string): Promise<{
  generatedAt: number;
  items: ThreatCacheEntry[];
}> {
  const intelRows = (await db
    .prepare(
      `SELECT indicator_hash, indicator_display, reputation_label, confidence, report_count, false_positive_count, updated_at
       FROM gsi_threat_intel
       WHERE (user_id IS NULL OR user_id = ?) AND indicator_type = 'phone_hash'
       ORDER BY updated_at DESC LIMIT 200`
    )
    .all(userId)) as {
    indicator_hash: string;
    indicator_display: string;
    reputation_label: string;
    confidence: number;
    report_count: number;
    false_positive_count: number;
    updated_at: number;
  }[];

  const entityRows = (await db
    .prepare(
      `SELECT normalized_hash, masked_display, verification_status, risk_classification, confidence, report_count, fp_count, updated_at
       FROM gcih_entities
       WHERE family_owner_id = ? AND entity_type = 'phone_number'
       ORDER BY updated_at DESC LIMIT 200`
    )
    .all(userId)) as {
    normalized_hash: string;
    masked_display: string;
    verification_status: string;
    risk_classification: string;
    confidence: number;
    report_count: number;
    fp_count: number;
    updated_at: number;
  }[];

  const items: ThreatCacheEntry[] = intelRows.map((r) => ({
    callerHash: String(r.indicator_hash),
    entityHash: null,
    maskedDisplay: String(r.indicator_display).replace(/\d{6,}/g, (m) => `******${m.slice(-4)}`),
    reputationLabel: String(r.reputation_label),
    riskLevel:
      r.reputation_label === "Verified Spam" || r.reputation_label === "High Risk"
        ? "High Risk"
        : r.reputation_label === "Suspicious"
          ? "Moderate Risk"
          : "Low Risk",
    confidence: Number(r.confidence || 0.5),
    reportCount: Number(r.report_count || 0),
    falsePositiveCount: Number(r.false_positive_count || 0),
    updatedAt: Number(r.updated_at || Date.now()),
  }));

  for (const e of entityRows) {
    items.push({
      callerHash: String(e.normalized_hash),
      entityHash: String(e.normalized_hash),
      maskedDisplay: String(e.masked_display),
      reputationLabel: String(e.verification_status),
      riskLevel:
        e.risk_classification === "Critical"
          ? "Critical Risk"
          : e.risk_classification === "High"
            ? "High Risk"
            : e.risk_classification === "Moderate"
              ? "Moderate Risk"
              : "Low Risk",
      confidence: Number(e.confidence || 0.5),
      reportCount: Number(e.report_count || 0),
      falsePositiveCount: Number(e.fp_count || 0),
      updatedAt: Number(e.updated_at || Date.now()),
    });
  }

  return {
    generatedAt: Date.now(),
    items,
  };
}

export async function endActiveCallEvent(
  userId: string,
  userName: string,
  callId: string,
  input: {
    endedAt?: number | null;
    startedAt?: number | null;
    callStatus?: CallStatus;
    durationMs?: number | null;
    lang?: string;
  } = {}
): Promise<{ call: CallWatcherCallRecord; correlation: CallWatcherTimelineItem | null }> {
  const row = (await db
    .prepare("SELECT * FROM call_watcher_calls WHERE id = ? AND user_id = ?")
    .get(String(callId), userId)) as Record<string, unknown> | undefined;

  if (!row) {
    throw new Error("Call Watcher record not found.");
  }

  const prev = mapCallRow(row);
  const startedAt =
    input.startedAt !== undefined && input.startedAt !== null && Number.isFinite(input.startedAt)
      ? Math.round(input.startedAt)
      : prev.startedAt;
  const endedAt =
    input.endedAt === null
      ? null
      : input.endedAt !== undefined && Number.isFinite(input.endedAt)
        ? Math.round(input.endedAt)
        : prev.endedAt;

  let durationMs: number | null = null;
  if (startedAt !== null && endedAt !== null && endedAt >= startedAt) {
    durationMs = endedAt - startedAt;
  } else if (
    input.durationMs !== undefined &&
    input.durationMs !== null &&
    Number.isFinite(input.durationMs) &&
    input.durationMs >= 0
  ) {
    durationMs = Math.round(input.durationMs);
  }

  const validStatuses: CallStatus[] = ["Answered", "Missed", "Rejected", "Unavailable"];
  const callStatus: CallStatus = validStatuses.includes(input.callStatus as CallStatus)
    ? (input.callStatus as CallStatus)
    : prev.callStatus;
  const phase: CallLifecyclePhase =
    callStatus === "Missed"
      ? "missed"
      : callStatus === "Rejected"
        ? "rejected"
        : callStatus === "Unavailable"
          ? "unavailable"
          : "ended";

  await db.prepare(
    `UPDATE call_watcher_calls SET
      started_at = ?,
      ended_at = ?,
      duration_ms = ?,
      call_status = ?,
      call_lifecycle_phase = ?
     WHERE id = ? AND user_id = ?`
  ).run(startedAt, endedAt, durationMs, callStatus, phase, prev.id, userId);

  const now = Date.now();
  await db.prepare("UPDATE call_watcher_settings SET last_event_at = ?, updated_at = ? WHERE user_id = ?").run(
    now,
    now,
    userId
  );

  const updatedRow = (await db
    .prepare("SELECT * FROM call_watcher_calls WHERE id = ?")
    .get(prev.id)) as Record<string, unknown>;
  const call = mapCallRow(updatedRow);

  await writeAudit(
    userId,
    `Call Watcher call ended (${call.callerClassification}, dur=${durationMs === null ? "unavailable" : formatDur(durationMs)})`
  );

  const existingCorr = (await db
    .prepare("SELECT * FROM call_payment_correlations WHERE user_id = ? AND call_event_id = ? ORDER BY created_at DESC LIMIT 1")
    .get(userId, call.id)) as Record<string, unknown> | undefined;

  let correlation: CallWatcherTimelineItem | null = existingCorr
    ? await hydrateCorrelationRow(userId, existingCorr)
    : null;

  if (!correlation) {
    const ctx = await getPriorCallerContext(userId, call.callerHash, call.incomingAt);
    const sharedPhoneItems = await inputCallerLookup(userId, call.callerMasked);
    const callRisk = assessCallRisk({
      call,
      unknownCalls30m: ctx.unknownCalls30m,
      sameCaller24h: ctx.sameCaller24h,
      questionnaire: ctx.priorQuestionnaire,
      sharedItems: sharedPhoneItems,
    });
    if (
      call.callerClassification !== "Known Contact" &&
      (callRisk.riskLevel === "Moderate Risk" ||
        callRisk.riskLevel === "High Risk" ||
        callRisk.riskLevel === "Critical Risk")
    ) {
      correlation = await createOrUpdateCorrelation({
        userId,
        userName,
        call,
        payment: null,
        lang: input.lang === "hi" ? "hi" : "en",
      });
    }
  }

  return { call, correlation };
}

export async function updateCallWatcherDeviceStatus(
  userId: string,
  input: {
    appLifecycleState?: AppLifecycleState;
    batteryRestricted?: boolean;
    callScreeningRoleState?: PermissionState;
    permissionCallLogState?: PermissionState;
    permissionCallState?: PermissionState;
    permissionNotifState?: PermissionState;
    bootRestorePending?: boolean;
  }
): Promise<CallWatcherSettings> {
  const settings = await updateCallWatcherConsent(userId, "update_prefs", input);
  await writeAudit(
    userId,
    `Protection status evaluated: ${settings.protectionStatus} (lifecycle=${settings.appLifecycleState}, batteryRestricted=${settings.batteryRestricted})`
  );
  return settings;
}

export async function markCallerTrustedWithSafeguard(
  userId: string,
  input: {
    callerIdentifier?: string | null;
    callerHash?: string | null;
    entityId?: string | null;
    note?: string;
  }
): Promise<{
  ok: true;
  trustedHash: string | null;
  safeguardNotice: string;
}> {
  const now = Date.now();
  const norm = input.callerIdentifier
    ? normalizeEntityValue("phone_number", input.callerIdentifier)
    : null;
  const trustedHash =
    input.callerHash ||
    (norm ? sha256(`${userId}:phone:${norm.normalizedKey.replace(/\D/g, "").slice(-10)}`) : null);
  const maskedDisplay = norm?.maskedDisplay || "Masked Caller";
  const safeguardNotice =
    "Marked as trusted locally. Safeguard active: urgent OTP, UPI PIN, password, or screen-sharing requests still trigger critical scam warnings.";

  if (input.entityId) {
    await submitEntityFeedback({
      actorId: userId,
      actorRole: "parent",
      entityId: input.entityId,
      feedbackType: "legitimate",
      note: input.note || "Marked as trusted via Safe Decision Assistant (OTP/PIN safeguard preserved)",
    });
  } else if (trustedHash) {
    const existing = (await db
      .prepare("SELECT id FROM gsi_threat_intel WHERE user_id = ? AND indicator_type = 'phone_hash' AND indicator_hash = ?")
      .get(userId, trustedHash)) as { id: string } | undefined;
    if (existing) {
      await db.prepare(
        "UPDATE gsi_threat_intel SET reputation_label = 'Trusted', false_positive_count = false_positive_count + 1, confidence = 0.85, evidence_summary = ?, updated_at = ? WHERE id = ?"
      ).run(safeguardNotice, now, existing.id);
    } else {
      await db.prepare(
        `INSERT INTO gsi_threat_intel (
          id, user_id, indicator_type, indicator_hash, indicator_display,
          reputation_label, confidence, report_count, false_positive_count,
          evidence_summary, source, rule_version, created_at, updated_at
        ) VALUES (?, ?, 'phone_hash', ?, ?, 'Trusted', 0.85, 0, 1, ?, 'user_feedback', 'GSI-2026.11', ?, ?)`
      ).run(generateId("gti"), userId, trustedHash, maskedDisplay, safeguardNotice, now, now);
    }
  }

  await writeAudit(userId, `Caller ${maskedDisplay} marked trusted (OTP/PIN safeguard retained)`);
  return { ok: true, trustedHash, safeguardNotice };
}

export async function notifyLinkedGuardiansFromAssistant(
  userId: string,
  userName: string,
  input: { correlationId?: string; message?: string } = {}
): Promise<{ ok: true; notifiedCount: number; statusMessage: string }> {
  const consent = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(userId)) as { guardian_alerts: number; paused: number } | undefined;

  if (consent && (consent.paused || !consent.guardian_alerts)) {
    return {
      ok: true,
      notifiedCount: 0,
      statusMessage: "Guardian alerts are currently paused or disabled in Settings; no notification sent.",
    };
  }

  const guardians = await getActiveGuardiansForParent(userId);
  if (!guardians.length) {
    return {
      ok: true,
      notifiedCount: 0,
      statusMessage: "No active linked guardian found. Invite a guardian under Family Management first.",
    };
  }

  const customNote = input.message ? String(input.message).trim().slice(0, 180) : "";
  const title = "Family Help Request from Safe Decision Assistant";
  const body = customNote
    ? `${userName} asked you to review a suspicious call: ${customNote}`
    : `${userName} tapped Contact My Parent regarding a flagged call in Call Watcher. Please call them on their saved number.`;

  for (const g of guardians) {
    await createNotification(g.guardian_id, userId, "call_watcher_guardian_help", title, body);
  }
  if (input.correlationId) {
    await db.prepare(
      "UPDATE call_payment_correlations SET parent_notified_count = parent_notified_count + ? WHERE id = ? AND user_id = ?"
    ).run(guardians.length, String(input.correlationId), userId);
  }
  await writeAudit(userId, `Contacted ${guardians.length} linked guardian(s) via Safe Decision Assistant`);
  return {
    ok: true,
    notifiedCount: guardians.length,
    statusMessage: `Notified ${guardians.length} active linked guardian(s). Call them directly on their saved number if urgent.`,
  };
}

