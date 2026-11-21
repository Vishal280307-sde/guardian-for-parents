import { db } from "./db.ts";
import {
  explainGsiIncidentWithGemini,
  redactSensitive,
  type GsiAiExplanation,
} from "./ai.ts";
import {
  analyzeUrlIntelligence,
  extractUrlsFromText,
  type LinkAnalysisResult,
} from "./linkIntelligence.ts";
import {
  createNotification,
  ensureDefaultConsent,
  generateId,
  getActiveGuardiansForParent,
  sanitizeAuditText,
  sha256,
  writeAudit,
} from "./security.ts";
import {
  attachIncidentToEntities,
  extractEntitiesFromPayment,
  extractEntitiesFromQrPayload,
  extractEntitiesFromText,
  getSectionForModule,
  linkCoOccurringEntities,
  lookupSharedEntitiesForQuery,
  normalizeEntityValue,
  publishDomainEvent,
  recordIncidentHistory,
  severityToGcihRisk,
  upsertSharedEntity,
  type ExtractedEntityCandidate,
  type GcihDomainEventType,
  type GcihEntityRecord,
  type GcihIncidentWorkflowStatus,
  type SharedIntelligenceItem,
} from "./gcih.ts";

export const GSI_RULE_VERSION = "GSI-2026.11";

export type GsiSeverity = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
export type AlertLevel = "GREEN" | "YELLOW" | "RED" | "CRITICAL_RED";
export type NotifDeliveryStatus = "Sent" | "Pending" | "Failed" | "Not Required" | "Suppressed";
export type GsiConfidence = "low" | "medium" | "high";
export type CallerReputationClass =
  | "Trusted"
  | "Unknown"
  | "Suspicious"
  | "High Risk"
  | "Verified Spam";

export type SmsFraudCategory =
  | "Normal transaction"
  | "Promotional"
  | "Informational"
  | "Suspicious financial request"
  | "Potential phishing"
  | "High-risk fraudulent pattern"
  | "OTP-related security warning";

export type GsiEventType =
  | "call_event"
  | "sms_event"
  | "link_event"
  | "qr_event"
  | "payment_event";

export interface CallerIntelResult {
  callerClassificationInput: string;
  reputationClass: CallerReputationClass;
  callerMasked: string | null;
  callerHash: string | null;
  riskScore: number;
  severity: GsiSeverity;
  confidence: GsiConfidence;
  frequency24h: number;
  unknownBurst30m: number;
  blockRecommended: boolean;
  blockAdvisoryText: string;
  rationale: string[];
  sharedAssociations?: SharedIntelligenceItem[];
  neverAutoRejected: true;
  noAudioCollected: true;
}

export interface SmsIntelResult {
  category: SmsFraudCategory;
  otpLegitimacy: "none" | "legitimate_delivery" | "disclosure_pressure";
  senderLabel: string | null;
  redactedExcerpt: string;
  extractedAmount: number | null;
  paymentDirection: "debit" | "credit" | "collect_request" | "none";
  riskScore: number;
  severity: GsiSeverity;
  confidence: GsiConfidence;
  cues: string[];
  embeddedLinks: LinkAnalysisResult[];
  sharedAssociations?: SharedIntelligenceItem[];
  isGenuineInformationalOrPromo: boolean;
}

export interface PaymentIntelResult {
  direction: "debit" | "credit" | "collect_request" | "qr_payment" | "manual_intent";
  amount: number | null;
  beneficiary: string | null;
  exceedsLimit: boolean;
  isRefundOrCollectLure: boolean;
  isHighAmountAlone: boolean;
  riskScore: number;
  severity: GsiSeverity;
  confidence: GsiConfidence;
  evidence: string[];
  sharedAssociations?: SharedIntelligenceItem[];
}

export interface CorrelationPatternMatch {
  patternId:
    | "call_sms_link_chain"
    | "phishing_credential_chain"
    | "repeat_caller_pressure"
    | "qr_call_payment_context";
  title: string;
  relatedEventIds: string[];
  scoreBoost: number;
  contradictoryContext: boolean;
  reasoning: string;
}

export interface SmartRedAlertDecision {
  alertLevel: AlertLevel;
  redAlertTriggered: boolean;
  headline: string;
  riskScore: number;
  confidence: GsiConfidence;
  evidenceQuality: "weak" | "moderate" | "strong";
  corroboratingIndicatorsCount: number;
  priorFalsePositiveCount: number;
  rationale: string[];
}

export interface GsiIncidentRecord {
  incidentId: string;
  familyOwnerId: string;
  parentName?: string;
  relatedEventIds: string[];
  incidentCategory: string;
  riskScore: number;
  severity: GsiSeverity;
  alertLevel: AlertLevel;
  redAlertTriggered: boolean;
  confidence: GsiConfidence;
  detectionSource: string;
  actorMasked: string | null;
  evidence: string[];
  reasoningSummary: string;
  recommendedAction: string;
  ruleVersion: string;
  aiExplanation: GsiAiExplanation;
  acknowledgementStatus: "unacknowledged" | "acknowledged";
  resolutionStatus: "open" | "resolved" | "false_positive" | "confirmed_threat";
  feedbackStatus: string | null;
  feedbackNote: string | null;
  parentNotifStatus: NotifDeliveryStatus;
  childNotifStatus: NotifDeliveryStatus;
  decisionRationale: string[];
  notificationsDispatched: number;
  involvedEntityIds?: string[];
  sourceModules?: string[];
  sourceDeviceIds?: string[];
  workflowStatus?: GcihIncidentWorkflowStatus;
  timeline?: { at: number; action: string; status: string; summary: string }[];
  createdAt: number;
  updatedAt: number;
}

export interface GsiThreatIntelItem {
  id: string;
  indicatorType: "phone_hash" | "domain" | "url_hash" | "upi_id";
  indicatorDisplay: string;
  reputationLabel: CallerReputationClass;
  confidence: number;
  reportCount: number;
  falsePositiveCount: number;
  evidenceSummary: string;
  source: string;
  ruleVersion: string;
  updatedAt: number;
}

export interface GsiPeriodicReport {
  id: string;
  familyOwnerId: string;
  periodType: "daily" | "weekly" | "monthly";
  periodKey: string;
  generatedAt: number;
  totalEvents: number;
  moduleBreakdown: {
    calls: number;
    sms: number;
    links: number;
    qr: number;
    payments: number;
  };
  incidentCounts: {
    total: number;
    low: number;
    moderate: number;
    high: number;
    critical: number;
    resolved: number;
    falsePositives: number;
    confirmedThreats: number;
  };
  previousPeriodTotalIncidents: number;
  trendDelta: number;
  recurringIndicators: { display: string; type: string; label: string; count: number }[];
  recommendations: string[];
  summaryText: string;
}

export interface GsiCapabilityHealth {
  overallStatus: "healthy" | "degraded" | "paused";
  runtimeMode: "web_assisted" | "android_companion_connected";
  items: {
    capability: string;
    status: "active" | "degraded" | "paused" | "unavailable_in_browser";
    detail: string;
  }[];
  lastCheckedAt: number;
}

export interface GsiIngestPayload {
  familyOwnerId: string;
  familyOwnerName: string;
  deviceId?: string;
  eventType: GsiEventType;
  eventTimestamp?: number;
  sourceModule: string;
  eventVersion?: number;
  lang?: "en" | "hi";
  allowNetworkProbe?: boolean;
  skipAi?: boolean;
  simulateNotificationFailure?: "parent" | "child" | "both" | boolean;
  callData?: {
    callerClassification?: string;
    callerIdentifier?: string | null;
    callerMasked?: string | null;
    callerHash?: string | null;
    callStatus?: string;
    durationMs?: number | null;
    known?: boolean;
  };
  smsData?: {
    rawText: string;
    senderLabel?: string | null;
    amount?: number | null;
    paymentStatus?: string;
  };
  linkData?: {
    url: string;
    contextText?: string;
  };
  qrData?: {
    scanId?: string;
    classification: string;
    securityScore: number;
    securityRiskLevel: string;
    paymentLoadCategory: string;
    upiId?: string | null;
    payeeName?: string | null;
    merchantName?: string | null;
    payloadHash?: string | null;
    amount?: number | null;
    urlString?: string | null;
    findings?: string[];
  };
  paymentData?: {
    direction: "debit" | "credit" | "collect_request" | "qr_payment" | "manual_intent";
    amount: number | null;
    beneficiary?: string | null;
    knownDeclared?: boolean;
    baseScore?: number;
    signals?: string[];
    isDuplicateRequest?: boolean;
  };
}

export interface GsiDashboardState {
  ruleVersion: string;
  capabilities: GsiCapabilityHealth;
  recentIncidents: GsiIncidentRecord[];
  activeRedAlerts: GsiIncidentRecord[];
  threatIntel: GsiThreatIntelItem[];
  latestReports: {
    daily: GsiPeriodicReport | null;
    weekly: GsiPeriodicReport | null;
    monthly: GsiPeriodicReport | null;
  };
  metrics: {
    events24h: number;
    openHighCritical: number;
    openRedAlerts: number;
    falsePositiveCount: number;
    confirmedThreatCount: number;
  };
}

export function scoreToSeverity(score: number): GsiSeverity {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MODERATE";
  return "LOW";
}

function severityRank(sev: GsiSeverity): number {
  return sev === "CRITICAL" ? 4 : sev === "HIGH" ? 3 : sev === "MODERATE" ? 2 : 1;
}

async function upsertThreatIntelIndicator(params: {
  userId: string;
  indicatorType: "phone_hash" | "domain" | "url_hash" | "upi_id";
  indicatorHash: string;
  indicatorDisplay: string;
  suggestedLabel: CallerReputationClass;
  evidenceSummary: string;
  source: string;
  deltaReport?: number;
  deltaFalsePositive?: number;
}): Promise<GsiThreatIntelItem> {
  const now = Date.now();
  const existing = (await db
    .prepare(
      "SELECT * FROM gsi_threat_intel WHERE user_id = ? AND indicator_type = ? AND indicator_hash = ?"
    )
    .get(params.userId, params.indicatorType, params.indicatorHash)) as
    | Record<string, unknown>
    | undefined;

  if (!existing) {
    const reports = Math.max(0, params.deltaReport ?? 0);
    const fps = Math.max(0, params.deltaFalsePositive ?? 0);
    // Single report cannot immediately elevate to Verified Spam
    let label = params.suggestedLabel;
    if (label === "Verified Spam" && reports < 2) {
      label = "High Risk";
    }
    const id = generateId("gti");
    const conf =
      label === "Verified Spam"
        ? 0.9
        : label === "High Risk"
          ? 0.78
          : label === "Suspicious"
            ? 0.62
            : label === "Trusted"
              ? 0.85
              : 0.45;
    await db.prepare(
      `INSERT INTO gsi_threat_intel (
         id, user_id, indicator_type, indicator_hash, indicator_display,
         reputation_label, confidence, report_count, false_positive_count,
         evidence_summary, source, rule_version, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      id,
      params.userId,
      params.indicatorType,
      params.indicatorHash,
      params.indicatorDisplay.slice(0, 80),
      label,
      conf,
      reports,
      fps,
      params.evidenceSummary.slice(0, 220),
      params.source.slice(0, 40),
      GSI_RULE_VERSION,
      now,
      now
    );
    return {
      id,
      indicatorType: params.indicatorType,
      indicatorDisplay: params.indicatorDisplay.slice(0, 80),
      reputationLabel: label,
      confidence: conf,
      reportCount: reports,
      falsePositiveCount: fps,
      evidenceSummary: params.evidenceSummary.slice(0, 220),
      source: params.source,
      ruleVersion: GSI_RULE_VERSION,
      updatedAt: now,
    };
  }

  const nextReports = Math.max(0, Number(existing.report_count || 0) + (params.deltaReport ?? 0));
  const nextFps = Math.max(0, Number(existing.false_positive_count || 0) + (params.deltaFalsePositive ?? 0));
  let nextLabel = String(existing.reputation_label) as CallerReputationClass;

  if (nextFps > nextReports) {
    nextLabel = nextFps >= 2 ? "Trusted" : "Unknown";
  } else if ((params.deltaReport ?? 0) > 0) {
    if (nextReports >= 2 && nextFps === 0) {
      nextLabel = "Verified Spam";
    } else if (nextReports >= 1) {
      nextLabel = params.suggestedLabel === "Verified Spam" ? "High Risk" : params.suggestedLabel;
    }
  } else if (
    severityRankFromLabel(params.suggestedLabel) > severityRankFromLabel(nextLabel) &&
    nextFps === 0
  ) {
    nextLabel = params.suggestedLabel === "Verified Spam" ? "High Risk" : params.suggestedLabel;
  }

  const nextConf = Math.max(
    0.2,
    Math.min(
      0.95,
      (nextLabel === "Verified Spam"
        ? 0.9
        : nextLabel === "High Risk"
          ? 0.78
          : nextLabel === "Suspicious"
            ? 0.62
            : 0.45) -
        nextFps * 0.12 +
        Math.min(0.15, nextReports * 0.05)
    )
  );

  await db.prepare(
    `UPDATE gsi_threat_intel SET
       reputation_label = ?, confidence = ?, report_count = ?, false_positive_count = ?,
       evidence_summary = ?, rule_version = ?, updated_at = ?
     WHERE id = ?`
  ).run(
    nextLabel,
    Math.round(nextConf * 100) / 100,
    nextReports,
    nextFps,
    params.evidenceSummary.slice(0, 220),
    GSI_RULE_VERSION,
    now,
    String(existing.id)
  );

  return {
    id: String(existing.id),
    indicatorType: params.indicatorType,
    indicatorDisplay: String(existing.indicator_display),
    reputationLabel: nextLabel,
    confidence: Math.round(nextConf * 100) / 100,
    reportCount: nextReports,
    falsePositiveCount: nextFps,
    evidenceSummary: params.evidenceSummary.slice(0, 220),
    source: String(existing.source),
    ruleVersion: GSI_RULE_VERSION,
    updatedAt: now,
  };
}

function severityRankFromLabel(label: CallerReputationClass): number {
  if (label === "Verified Spam") return 5;
  if (label === "High Risk") return 4;
  if (label === "Suspicious") return 3;
  if (label === "Unknown") return 2;
  return 1;
}

/* ---- Module A: Smart Caller Intelligence ---- */
export async function evaluateCallerIntelligence(
  userId: string,
  input: NonNullable<GsiIngestPayload["callData"]>,
  now = Date.now()
): Promise<CallerIntelResult> {
  const cls =
    input.callerClassification ||
    (input.known ? "Known Contact" : "Unknown Number");
  const isKnown = cls === "Known Contact" || Boolean(input.known);
  const dur = typeof input.durationMs === "number" && Number.isFinite(input.durationMs) ? input.durationMs : null;

  let callerHash = input.callerHash || null;
  let callerMasked = input.callerMasked || null;
  if (!callerHash && input.callerIdentifier) {
    const digits = String(input.callerIdentifier).replace(/\D/g, "");
    if (digits.length >= 4) {
      callerHash = sha256(`${userId}:phone:${digits.slice(-10)}`);
      callerMasked = callerMasked || (digits.length > 6 ? `******${digits.slice(-4)}` : `***${digits.slice(-4)}`);
    } else {
      callerHash = sha256(`${userId}:label:${input.callerIdentifier.trim().toLowerCase()}`);
      callerMasked = callerMasked || input.callerIdentifier.trim().slice(0, 2) + "***";
    }
  }

  let frequency24h = 1;
  if (callerHash) {
    const cwRow = (await db
      .prepare(
        "SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND caller_hash = ? AND incoming_at >= ?"
      )
      .get(userId, callerHash, now - 86_400_000)) as { cnt: number };
    const gsiCallRows = (await db
      .prepare(
        "SELECT metadata_json FROM gsi_events WHERE family_owner_id = ? AND event_type = 'call_event' AND event_timestamp >= ?"
      )
      .all(userId, now - 86_400_000)) as { metadata_json: string }[];
    let gsiMatches = 0;
    for (const r of gsiCallRows) {
      try {
        const m = JSON.parse(r.metadata_json || "{}") as { callerHash?: string };
        if (m.callerHash === callerHash) gsiMatches++;
      } catch {
        // ignore malformed json
      }
    }
    frequency24h = Math.max(1, Number(cwRow?.cnt || 0), gsiMatches + 1);
  }

  const unkRows = (await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM call_watcher_calls WHERE user_id = ? AND caller_classification != 'Known Contact' AND incoming_at >= ?"
    )
    .get(userId, now - 1_800_000)) as { cnt: number };
  const gsiUnkRows = (await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM gsi_events WHERE family_owner_id = ? AND event_type = 'call_event' AND event_timestamp >= ? AND metadata_json NOT LIKE '%\"reputationClass\":\"Trusted\"%'"
    )
    .get(userId, now - 1_800_000)) as { cnt: number };
  const unknownBurst30m = Math.max(Number(unkRows?.cnt || 0), Number(gsiUnkRows?.cnt || 0));

  let intelRow: { reputation_label: CallerReputationClass; report_count: number; false_positive_count: number; evidence_summary: string } | undefined;
  if (callerHash) {
    intelRow = (await db
      .prepare(
        "SELECT reputation_label, report_count, false_positive_count, evidence_summary FROM gsi_threat_intel WHERE (user_id IS NULL OR user_id = ?) AND indicator_type = 'phone_hash' AND indicator_hash = ? ORDER BY updated_at DESC LIMIT 1"
      )
      .get(userId, callerHash)) as typeof intelRow;
  }

  const rationale: string[] = [];
  let score = 0;
  let reputationClass: CallerReputationClass = isKnown ? "Trusted" : "Unknown";

  if (isKnown) {
    score = 5;
    rationale.push("Caller matched a saved contact (verify independently if urgent money is requested).");
  } else if (cls === "Private/Hidden Number") {
    score += 32;
    reputationClass = "Suspicious";
    rationale.push("Caller withheld their phone number (Private/Hidden).");
  } else {
    score += 18;
    rationale.push("Caller is not in saved contacts (unknown caller alone is NOT treated as spam).");
  }

  const hasAdditionalLongCallEvidence =
    cls === "Private/Hidden Number" ||
    Boolean(intelRow && intelRow.false_positive_count === 0) ||
    frequency24h >= 2 ||
    unknownBurst30m >= 3;

  if (!isKnown && dur !== null && dur >= 180_000) {
    if (hasAdditionalLongCallEvidence) {
      score += 22;
      reputationClass = "Suspicious";
      rationale.push(`Extended unknown call duration (${Math.round(dur / 1000)}s) combined with corroborating caller signals.`);
    } else {
      score += 4;
      rationale.push(`Call duration (${Math.round(dur / 1000)}s) recorded as contextual timing only — long calls alone do not indicate fraud.`);
    }
  }

  if (!isKnown && frequency24h >= 3) {
    score += 36;
    reputationClass = frequency24h >= 4 ? "High Risk" : "Suspicious";
    rationale.push(`Repeated contact from same masked identifier (${frequency24h} calls in 24h).`);
  } else if (!isKnown && frequency24h === 2) {
    score += 12;
    reputationClass = "Suspicious";
    rationale.push("Second recent call from the same unknown masked identifier within 24h.");
  }

  if (!isKnown && unknownBurst30m >= 3) {
    score += 15;
    if (reputationClass === "Unknown") reputationClass = "Suspicious";
    rationale.push(`${unknownBurst30m} unknown calls recorded within 30 minutes.`);
  }

  if (intelRow) {
    if (intelRow.reputation_label === "Verified Spam" && intelRow.false_positive_count === 0) {
      score = Math.max(score + 35, 80);
      reputationClass = "Verified Spam";
      rationale.push(`Corroborated spam reputation (${intelRow.report_count} confirmed reports): ${intelRow.evidence_summary}`);
    } else if (intelRow.reputation_label === "High Risk" && intelRow.false_positive_count === 0) {
      score = Math.max(score + 25, 58);
      reputationClass = "High Risk";
      rationale.push(`Previously flagged High Risk in local threat intelligence: ${intelRow.evidence_summary}`);
    } else if (intelRow.reputation_label === "Suspicious" && intelRow.false_positive_count === 0) {
      score = Math.max(score, 35);
      if (reputationClass === "Unknown") reputationClass = "Suspicious";
      rationale.push(`Prior suspicious report recorded: ${intelRow.evidence_summary}`);
    } else if (intelRow.reputation_label === "Trusted" || intelRow.false_positive_count > 0) {
      score = Math.max(0, score - (isKnown ? 5 : 15));
      if (intelRow.false_positive_count > 0) {
        rationale.push(`Prior false-positive feedback recorded (${intelRow.false_positive_count}); alert confidence tempered.`);
      }
    }
  }

  // Cross-section GCIH lookup: check if caller phone number was previously extracted in SMS Scam or Payment Safety
  const callerCandidates: ExtractedEntityCandidate[] = [];
  if (input.callerIdentifier) {
    const phCand = normalizeEntityValue("phone_number", input.callerIdentifier);
    if (phCand) callerCandidates.push(phCand);
  }
  const sharedAssociations = callerCandidates.length
    ? await lookupSharedEntitiesForQuery({
        familyOwnerId: userId,
        candidates: callerCandidates,
        currentSection: "call_scam",
      })
    : [];

  for (const sItem of sharedAssociations) {
    if (
      (sItem.verificationStatus === "High risk" ||
        sItem.verificationStatus === "Confirmed malicious" ||
        sItem.verificationStatus === "Suspicious") &&
      !isKnown
    ) {
      const boost = sItem.verificationStatus === "Suspicious" ? 22 : 34;
      score = Math.max(score + boost, sItem.verificationStatus === "Suspicious" ? 38 : 55);
      if (reputationClass === "Unknown") {
        reputationClass = sItem.verificationStatus === "Suspicious" ? "Suspicious" : "High Risk";
      } else if (reputationClass === "Suspicious" && sItem.verificationStatus !== "Suspicious") {
        reputationClass = "High Risk";
      }
      rationale.push(
        `Shared family intelligence (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} flagged ${sItem.verificationStatus} — ${sItem.reasonForSharing}.`
      );
    } else if (sItem.verificationStatus === "Verified legitimate") {
      score = Math.max(0, score - 15);
      rationale.push(`Verified legitimate in family intelligence (${sItem.maskedDisplay}).`);
    }
  }

  // Safeguard: never label a single plain unknown call with no other flags as High Risk or Spam
  if (
    !isKnown &&
    cls !== "Private/Hidden Number" &&
    !intelRow &&
    !sharedAssociations.some((s) => s.verificationStatus === "Suspicious" || s.verificationStatus === "High risk" || s.verificationStatus === "Confirmed malicious") &&
    frequency24h <= 1 &&
    (dur === null || dur < 180_000) &&
    unknownBurst30m < 3
  ) {
    score = Math.min(score, 22);
    reputationClass = "Unknown";
  }

  score = Math.max(0, Math.min(100, score));
  const severity = scoreToSeverity(score);
  const blockRecommended =
    reputationClass === "Verified Spam" ||
    reputationClass === "High Risk" ||
    (reputationClass === "Suspicious" && (frequency24h >= 3 || score >= 50));

  const blockAdvisoryText = blockRecommended
    ? "Recommended action: Do not return this call; consider blocking this number in your phone app (Guardian never auto-rejects calls)."
    : "No automatic block recommended. Only metadata & timing are monitored (audio is never recorded).";

  const confidence: GsiConfidence =
    isKnown ||
    (intelRow && intelRow.false_positive_count === 0 && (intelRow.reputation_label === "Verified Spam" || intelRow.reputation_label === "High Risk")) ||
    sharedAssociations.some((s) => s.verificationStatus === "High risk" || s.verificationStatus === "Confirmed malicious") ||
    frequency24h >= 3
      ? "high"
      : frequency24h >= 2 || dur !== null || sharedAssociations.length > 0
        ? "medium"
        : "low";

  return {
    callerClassificationInput: cls,
    reputationClass,
    callerMasked,
    callerHash,
    riskScore: score,
    severity,
    confidence,
    frequency24h,
    unknownBurst30m,
    blockRecommended,
    blockAdvisoryText,
    rationale,
    ...(sharedAssociations.length ? { sharedAssociations } : {}),
    neverAutoRejected: true,
    noAudioCollected: true,
  };
}

/* ---- Module B: Automated SMS Fraud Intelligence (7 Categories + Link Inspection) ---- */
export async function evaluateSmsIntelligence(
  userId: string,
  input: NonNullable<GsiIngestPayload["smsData"]>,
  allowNetworkProbe = false
): Promise<SmsIntelResult> {
  const raw = String(input.rawText || "").trim();
  const senderLabel = input.senderLabel ? String(input.senderLabel).trim().slice(0, 40) : null;
  const cues: string[] = [];
  let score = 0;

  const urls = extractUrlsFromText(raw);
  const embeddedLinks: LinkAnalysisResult[] = [];
  for (const u of urls.slice(0, 3)) {
    embeddedLinks.push(await analyzeUrlIntelligence(u, { userId, contextText: raw, allowNetworkProbe }));
  }

  const maxLinkScore = embeddedLinks.reduce((m, l) => Math.max(m, l.riskScore), 0);

  // Extract amount if not passed
  let amount = typeof input.amount === "number" && Number.isFinite(input.amount) ? input.amount : null;
  if (amount === null) {
    const m = raw.match(/(?:₹|rs\.?|inr)\s*([\d,]+(?:\.\d{1,2})?)/i);
    if (m && m[1]) {
      const val = Number(m[1].replace(/,/g, ""));
      if (Number.isFinite(val) && val > 0) amount = val;
    }
  }

  const isCollectOrPayReq =
    /\b(collect\s+request|payment\s+request|has\s+requested|approve\s+(?:the\s+)?request|pay\s+link|approve\s+to\s+pay|requesting\s+rs)\b/i.test(
      raw
    );
  const isDebit = /\b(debited|deducted|paid|sent|transferred|spent|withdrawn)\b/i.test(raw);
  const isCredit = /\b(credited|received\s+rs|received\s+₹|deposited)\b/i.test(raw);
  const paymentDirection: SmsIntelResult["paymentDirection"] = isCollectOrPayReq
    ? "collect_request"
    : isDebit
      ? "debit"
      : isCredit
        ? "credit"
        : "none";

  const mentionsOtp = /\b[o0]t[p]\b|one[\s-]?time[\s-]?(?:pass|code)|ओटीपी/i.test(raw);
  const asksToShareOtpOrPin =
    /(?:share|tell|send|forward|give|provide|disclose|enter|confirm|submit|verify|update|साझा).{0,25}(?:\b[o0]t[p]\b|\bpin\b|mpin|upi\s*pin|cvv|password|ओटीपी|पिन)|(?:\b[o0]t[p]\b|\bpin\b|cvv|mpin).{0,20}(?:now|immediately|calling|officer|unblock|verify|avoid)/i.test(
      raw
    );
  const isStandardOtpNotice =
    mentionsOtp &&
    !asksToShareOtpOrPin &&
    /\b(is your|your otp|valid for|never share|do not share with anyone|expires in|txn of)\b/i.test(raw) &&
    !/(kyc\s*suspend|account\s*(?:will be|getting)\s*block|arrest|anydesk|teamviewer|fee)/i.test(raw);

  const hasRemoteAccess = /anydesk|teamviewer|quicksupport|rustdesk|screen.?shar|remote\s*access/i.test(raw);
  const hasKycOrBlockThreat =
    /k\.?y\.?c|केवाईसी|re.?kyc|a[c]{1,2}ount.{0,25}(bl[o0]ck|suspend|freez|clos|deactivat)|pan\s*(card\s*)?(update|suspend)/i.test(
      raw
    );
  const hasImpersonation =
    /(sbi|hdfc|icici|axis|pnb|kotak|rbi|npci|paytm|phonepe|gpay|cyber\s*cell|cbi|customs|police|electricity\s*officer|bluedart|india\s*post).{0,30}(officer|manager|calling|desk|helpdesk|support|notice|arrest|seized|disconnect)/i.test(
      raw
    );
  const hasUrgency = /\b(urgent|immediately|right now|within \d+|today only|tonight|turant|abhi)\b|तुरंत|अभी/i.test(
    raw
  );
  const hasRefundOrLoanLure =
    /\b(refund|cashback|lottery|prize|reward\s+points|pre-?approved\s+loan|processing\s+fee|instant\s+loan|guaranteed\s+return)\b/i.test(
      raw
    );
  const isPromo =
    /\b(offer|discount|voucher|exclusive\s+deal|cashback\s+up\s+to|apply\s+now)\b/i.test(raw) &&
    !isDebit &&
    !isCollectOrPayReq &&
    !asksToShareOtpOrPin &&
    !hasKycOrBlockThreat &&
    !hasRemoteAccess;
  const isNormalBankInfo =
    ((isDebit || isCredit) &&
      !hasUrgency &&
      !hasKycOrBlockThreat &&
      !asksToShareOtpOrPin &&
      !hasRemoteAccess &&
      maxLinkScore < 40) ||
    /\b(available\s+balance|avail\s*bal|statement|due\s+on\s+\d|delivered)\b/i.test(raw);

  let category: SmsFraudCategory = "Informational";
  let otpLegitimacy: SmsIntelResult["otpLegitimacy"] = "none";

  if (asksToShareOtpOrPin || hasRemoteAccess) {
    score += asksToShareOtpOrPin ? 60 : 0;
    score += hasRemoteAccess ? 55 : 0;
    if (hasKycOrBlockThreat) score += 25;
    if (hasUrgency) score += 15;
    if (maxLinkScore >= 40) score += 20;
    otpLegitimacy = asksToShareOtpOrPin ? "disclosure_pressure" : "none";
    category =
      hasRemoteAccess || (asksToShareOtpOrPin && (hasKycOrBlockThreat || hasImpersonation))
        ? "High-risk fraudulent pattern"
        : "OTP-related security warning";
    if (asksToShareOtpOrPin) cues.push("Requests or pressures user to disclose OTP, PIN, or CVV");
    if (hasRemoteAccess) cues.push("Requests remote-access / screen-sharing app installation");
  } else if (isStandardOtpNotice) {
    otpLegitimacy = "legitimate_delivery";
    category = "Informational";
    score = Math.max(5, Math.min(18, Math.round(maxLinkScore * 0.25)));
    cues.push("Standard one-time password (OTP) delivery alert with no disclosure demand");
  } else if (isPromo && maxLinkScore < 45) {
    category = "Promotional";
    score = maxLinkScore >= 25 ? 25 : 8;
    cues.push("Promotional / marketing offer (no debit or collect request)");
    if (embeddedLinks.length > 0) cues.push("Contains promotional URL; verify before clicking");
  } else if (maxLinkScore >= 45 || (embeddedLinks.some((l) => l.isLookalike || l.isShortener) && (hasKycOrBlockThreat || hasImpersonation || hasRefundOrLoanLure))) {
    score = Math.max(55, maxLinkScore + (hasKycOrBlockThreat ? 20 : 0) + (hasUrgency ? 15 : 0));
    category = score >= 75 ? "High-risk fraudulent pattern" : "Potential phishing";
    cues.push("Message pairs suspicious/impersonation URL with financial or account-verification lure");
  } else if (hasKycOrBlockThreat || hasImpersonation || isCollectOrPayReq || hasRefundOrLoanLure) {
    if (hasKycOrBlockThreat) {
      score += 32;
      cues.push("Account suspension or fake KYC urgency claim");
    }
    if (hasImpersonation) {
      score += 24;
      cues.push("Impersonates bank, courier, utility, or authority official");
    }
    if (isCollectOrPayReq) {
      score += 30;
      cues.push("Incoming UPI collect / payment approval request");
    }
    if (hasRefundOrLoanLure) {
      score += 26;
      cues.push("Refund, prize, or upfront-fee loan lure");
    }
    if (hasUrgency) {
      score += 15;
      cues.push("Urgent time pressure language");
    }
    if (maxLinkScore >= 25) {
      score += 20;
      cues.push("Contains unverified external URL");
    }
    category = score >= 75 ? "High-risk fraudulent pattern" : "Suspicious financial request";
  } else if (isNormalBankInfo && (isDebit || isCredit)) {
    category = "Normal transaction";
    score = 8;
    cues.push("Standard bank/UPI transaction notice with no fraud or urgency indicators");
  } else if (isNormalBankInfo) {
    category = "Informational";
    score = 6;
    cues.push("Informational banking or delivery message");
  } else {
    category = "Informational";
    score = Math.min(35, 10 + (hasUrgency ? 15 : 0) + Math.round(maxLinkScore * 0.4));
    cues.push("Unclassified general message; verify any financial request independently");
  }

  // Cross-reference extracted phones, URLs, UPI IDs, senders against GCIH shared intelligence
  const smsCandidates = extractEntitiesFromText(raw, senderLabel);
  const sharedAssociations = smsCandidates.length
    ? await lookupSharedEntitiesForQuery({
        familyOwnerId: userId,
        candidates: smsCandidates,
        currentSection: "sms_scam",
      })
    : [];

  for (const sItem of sharedAssociations) {
    if (
      sItem.verificationStatus === "High risk" ||
      sItem.verificationStatus === "Confirmed malicious" ||
      sItem.verificationStatus === "Suspicious"
    ) {
      if (category === "Informational" || category === "Normal transaction" || category === "Promotional") {
        // Keep explicitly benign normal OTP/transaction safe unless high risk indicator actually matches
        if (sItem.verificationStatus !== "Suspicious" && !isStandardOtpNotice) {
          score = Math.max(score + 20, 42);
          cues.push(`Cross-section flag (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} marked ${sItem.verificationStatus}`);
        }
      } else {
        score += sItem.verificationStatus === "Suspicious" ? 12 : 20;
        cues.push(`Cross-section flag (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} marked ${sItem.verificationStatus}`);
      }
    } else if (sItem.verificationStatus === "Verified legitimate" && !asksToShareOtpOrPin && !hasRemoteAccess) {
      score = Math.max(0, score - 15);
      cues.push(`Entity ${sItem.maskedDisplay} previously verified legitimate by family`);
    }
  }

  score = Math.max(0, Math.min(100, score));
  const severity = scoreToSeverity(score);
  return {
    category,
    otpLegitimacy,
    senderLabel,
    redactedExcerpt: redactSensitive(raw).slice(0, 220),
    extractedAmount: amount,
    paymentDirection,
    riskScore: score,
    severity,
    confidence: cues.length >= 2 || embeddedLinks.some((l) => l.findings.length > 0) ? "high" : "medium",
    cues,
    embeddedLinks,
    ...(sharedAssociations.length ? { sharedAssociations } : {}),
    isGenuineInformationalOrPromo:
      category === "Normal transaction" ||
      category === "Promotional" ||
      category === "Informational",
  };
}

/* ---- Module D: Automated Payment Intelligence ---- */
export async function evaluatePaymentIntelligence(
  userId: string,
  input: NonNullable<GsiIngestPayload["paymentData"]>
): Promise<PaymentIntelResult> {
  const consentRow = (await db
    .prepare("SELECT payment_limit FROM consents WHERE user_id = ?")
    .get(userId)) as { payment_limit: number } | undefined;
  const limit = Number(consentRow?.payment_limit || 10000);
  const amt = input.amount;
  const ben = input.beneficiary ? String(input.beneficiary).trim().slice(0, 80) : null;
  const exceedsLimit = amt !== null && amt > limit;

  const evidence: string[] = [];
  let score = 0;

  if (amt !== null) {
    evidence.push(`Amount: ₹${amt.toLocaleString("en-IN")} (configured family safety limit ₹${limit.toLocaleString("en-IN")}).`);
  }
  if (ben) {
    evidence.push(`Recipient/Beneficiary: ${ben}.`);
  }

  const benSuspicious = Boolean(ben && /(refund|prize|lottery|kyc|helpdesk|support|claim|fake)/i.test(ben));
  if (benSuspicious) {
    score += 30;
    evidence.push("Beneficiary / UPI handle contains suspicious support, KYC, or refund keywords.");
  }
  if (input.direction === "collect_request") {
    score += 32;
    evidence.push("Incoming UPI collect/payment request asks the user to authorize funds.");
  }
  if (input.knownDeclared === false) {
    score += 20;
    evidence.push("Unfamiliar or newly added beneficiary.");
  }
  if (input.isDuplicateRequest) {
    score += 18;
    evidence.push("Duplicate or repeated financial request detected.");
  }
  if (exceedsLimit) {
    score += 15;
    evidence.push("Amount exceeds parent-configured safety threshold.");
  }

  // Cross-reference UPI ID / recipient / phone / bank against GCIH shared entities (e.g. from QR Scam or SMS Scam)
  const payCandidates = extractEntitiesFromPayment({
    beneficiary: ben,
    signals: input.signals,
  });
  const sharedAssociations = payCandidates.length
    ? await lookupSharedEntitiesForQuery({
        familyOwnerId: userId,
        candidates: payCandidates,
        currentSection: "payment_safety",
      })
    : [];

  let sharedFraudHit = false;
  for (const sItem of sharedAssociations) {
    if (
      sItem.verificationStatus === "High risk" ||
      sItem.verificationStatus === "Confirmed malicious" ||
      sItem.verificationStatus === "Suspicious"
    ) {
      sharedFraudHit = true;
      const boost = sItem.verificationStatus === "Suspicious" ? 24 : 38;
      score = Math.max(score + boost, sItem.verificationStatus === "Suspicious" ? 45 : 62);
      evidence.push(
        `Shared Intelligence Alert (${sItem.sourceModules.join(", ")}): ${sItem.maskedDisplay} is marked ${sItem.verificationStatus}. ${sItem.reasonForSharing}`
      );
    } else if (sItem.verificationStatus === "Verified legitimate") {
      score = Math.max(0, score - 15);
      evidence.push(`Family feedback: ${sItem.maskedDisplay} was verified legitimate.`);
    }
  }

  for (const s of input.signals || []) {
    if (!evidence.includes(s)) evidence.push(s);
  }
  if (typeof input.baseScore === "number" && Number.isFinite(input.baseScore)) {
    score = Math.max(score, Math.min(100, input.baseScore));
  }

  // Safeguard: High amount alone NEVER triggers HIGH/CRITICAL fraud!
  const hasFraudIndicator =
    benSuspicious ||
    sharedFraudHit ||
    input.direction === "collect_request" ||
    Boolean(input.isDuplicateRequest) ||
    (input.signals || []).some((s) => /call|urgency|secret|kyc|refund|suspicious|impersonat/i.test(s));

  const isHighAmountAlone = exceedsLimit && !hasFraudIndicator && Boolean(input.knownDeclared !== false);
  if (isHighAmountAlone) {
    score = Math.min(score, 28);
    evidence.push("Large payment amount alone does not establish fraud without corroborating pressure or scam cues.");
  }

  score = Math.max(0, Math.min(100, score));
  return {
    direction: input.direction,
    amount: amt,
    beneficiary: ben,
    exceedsLimit,
    isRefundOrCollectLure: benSuspicious || input.direction === "collect_request",
    isHighAmountAlone,
    riskScore: score,
    severity: scoreToSeverity(score),
    confidence: hasFraudIndicator ? "high" : amt !== null ? "medium" : "low",
    evidence,
    ...(sharedAssociations.length ? { sharedAssociations } : {}),
  };
}

/* ---- Module E: Cross-Event Behavioural Correlation Engine ---- */
async function correlateRecentEvents(
  familyOwnerId: string,
  currentEventId: string,
  currentEventType: GsiEventType,
  currentTs: number,
  currentMeta: Record<string, unknown>,
  windowMs = 1_800_000
): Promise<CorrelationPatternMatch[]> {
  const recent = (await db
    .prepare(
      `SELECT event_id, event_type, event_timestamp, metadata_json, risk_indicators_json
       FROM gsi_events
       WHERE family_owner_id = ? AND event_id != ?
         AND event_timestamp >= ? AND event_timestamp <= ?
       ORDER BY event_timestamp DESC LIMIT 30`
    )
    .all(familyOwnerId, currentEventId, currentTs - windowMs, currentTs + 300_000)) as {
    event_id: string;
    event_type: string;
    event_timestamp: number;
    metadata_json: string;
    risk_indicators_json: string;
  }[];

  const parsedRecent = recent.map((r) => ({
    eventId: r.event_id,
    eventType: r.event_type as GsiEventType,
    ts: Number(r.event_timestamp),
    meta: JSON.parse(r.metadata_json || "{}") as Record<string, unknown>,
    risk: JSON.parse(r.risk_indicators_json || "{}") as Record<string, unknown>,
  }));

  const matches: CorrelationPatternMatch[] = [];
  const all = [
    {
      eventId: currentEventId,
      eventType: currentEventType,
      ts: currentTs,
      meta: currentMeta,
      risk: currentMeta,
    },
    ...parsedRecent,
  ];

  const calls = all.filter((e) => e.eventType === "call_event");
  const smsList = all.filter((e) => e.eventType === "sms_event");
  const links = all.filter((e) => e.eventType === "link_event");
  const qrs = all.filter((e) => e.eventType === "qr_event");
  const pays = all.filter((e) => e.eventType === "payment_event");

  const suspiciousCall = calls.find(
    (c) =>
      c.meta.reputationClass !== "Trusted" &&
      c.meta.callerClassificationInput !== "Known Contact" &&
      (Number(c.meta.riskScore || 0) >= 20 || c.meta.reputationClass !== "Unknown" || calls.length >= 2)
  );
  const trustedOnlyCall = calls.length > 0 && calls.every((c) => c.meta.reputationClass === "Trusted");

  const riskySms = smsList.find(
    (s) =>
      !s.meta.isGenuineInformationalOrPromo &&
      (Number(s.meta.riskScore || 0) >= 25 ||
        ["Suspicious financial request", "Potential phishing", "High-risk fraudulent pattern", "OTP-related security warning"].includes(
          String(s.meta.category || "")
        ))
  );
  const benignSmsOnly = smsList.length > 0 && smsList.every((s) => Boolean(s.meta.isGenuineInformationalOrPromo));

  const riskyLink = links.find((l) => Number(l.meta.riskScore || 0) >= 25);

  // Pattern 1: Call -> payment/collect SMS -> unverified/suspicious link
  if (suspiciousCall && riskySms && (riskyLink || (Array.isArray(riskySms.meta.embeddedLinks) && riskySms.meta.embeddedLinks.length > 0))) {
    const p1Ids = Array.from(
      new Set([suspiciousCall.eventId, riskySms.eventId, ...(riskyLink ? [riskyLink.eventId] : [])])
    );
    if (p1Ids.includes(currentEventId)) {
      matches.push({
        patternId: "call_sms_link_chain",
        title: "Pattern 1: Call + financial SMS + unverified/suspicious link within 30m",
        relatedEventIds: p1Ids,
        scoreBoost: 28,
        contradictoryContext: false,
        reasoning:
          "An unverified/unknown call coincided with a financial pressure SMS containing an external link. Timing & link indicators reinforce caution (timing alone never proves causation).",
      });
    }
  }

  // Pattern 2: Fake bank/authority SMS -> lookalike domain -> credential/OTP ask
  if (
    riskySms &&
    (riskySms.meta.otpLegitimacy === "disclosure_pressure" ||
      String(riskySms.meta.category) === "High-risk fraudulent pattern") &&
    (riskyLink || (Array.isArray(riskySms.meta.embeddedLinks) && riskySms.meta.embeddedLinks.length > 0))
  ) {
    const p2Ids = Array.from(new Set([riskySms.eventId, ...(riskyLink ? [riskyLink.eventId] : [])]));
    if (p2Ids.includes(currentEventId)) {
      matches.push({
        patternId: "phishing_credential_chain",
        title: "Pattern 2: Phishing lure + suspicious domain + credential/OTP ask",
        relatedEventIds: p2Ids,
        scoreBoost: 25,
        contradictoryContext: false,
        reasoning:
          "Combined phishing domain and OTP/PIN/remote-access pressure indicate an active credential-harvesting pattern.",
      });
    }
  }

  // Pattern 3: Repeated suspicious/unknown contact + financial/urgency SMS
  const nonTrustedCalls = calls.filter((c) => c.meta.reputationClass !== "Trusted");
  const riskyPays = pays.filter((p) => Number(p.meta.riskScore || 0) >= 25);
  if (nonTrustedCalls.length >= 2 && (riskySms || riskyPays.length > 0)) {
    const p3Ids = Array.from(
      new Set([
        ...nonTrustedCalls.map((c) => c.eventId),
        ...(riskySms ? [riskySms.eventId] : []),
        ...riskyPays.map((p) => p.eventId),
      ])
    );
    if (p3Ids.includes(currentEventId)) {
      matches.push({
        patternId: "repeat_caller_pressure",
        title: "Pattern 3: Repeated unknown/suspicious calls + financial request",
        relatedEventIds: p3Ids,
        scoreBoost: 22,
        contradictoryContext: false,
        reasoning: `${nonTrustedCalls.length} unknown/suspicious call events occurred near a financial request or SMS within the correlation window.`,
      });
    }
  }

  // Pattern 4: Risky QR + active/recent call or payment assessment context
  const riskyQr = qrs.find(
    (q) =>
      Number(q.meta.securityScore || 0) >= 40 ||
      ["HIGH", "CRITICAL"].includes(String(q.meta.securityRiskLevel || ""))
  );
  if (riskyQr && (calls.length > 0 || pays.length > 0)) {
    const contradictory = trustedOnlyCall && benignSmsOnly;
    const p4Ids = Array.from(
      new Set([riskyQr.eventId, ...nonTrustedCalls.map((c) => c.eventId), ...pays.map((p) => p.eventId)])
    );
    if (p4Ids.includes(currentEventId)) {
      matches.push({
        patternId: "qr_call_payment_context",
        title: "Pattern 4: Risky QR scan coinciding with call or payment activity",
        relatedEventIds: Array.from(
          new Set([riskyQr.eventId, ...calls.map((c) => c.eventId), ...pays.map((p) => p.eventId)])
        ),
        scoreBoost: contradictory ? 8 : 22,
        contradictoryContext: contradictory,
        reasoning:
          "A high-risk QR payload was scanned close to a call or payment intent check. Verify recipient independently before paying.",
      });
    }
  }

  // Pattern 5 (GCIH): Shared normalized entity / relationship correlation across independent sections
  const currentEntityIds = Array.isArray(currentMeta.gcihEntityIds)
    ? (currentMeta.gcihEntityIds as string[])
    : [];
  const isCurrentBenignSms = currentEventType === "sms_event" && Boolean(currentMeta.isGenuineInformationalOrPromo);
  const currentRiskScore = Number(currentMeta.riskScore ?? currentMeta.securityScore ?? 0);
  if (currentEntityIds.length > 0 && !isCurrentBenignSms) {
    const sharedRows = (await db
      .prepare(
        `SELECT id, entity_type, masked_display, source_modules_json, related_event_ids_json, risk_classification, verification_status
         FROM gcih_entities
         WHERE family_owner_id = ? AND id IN (${currentEntityIds.map(() => "?").join(",")})`
      )
      .all(familyOwnerId, ...currentEntityIds)) as Record<string, unknown>[];
    for (const row of sharedRows) {
      const entType = String(row.entity_type || "");
      const mods = JSON.parse(String(row.source_modules_json || "[]")) as string[];
      const distinctSections = new Set(mods.map((m) => getSectionForModule(m)));
      const relEvs = JSON.parse(String(row.related_event_ids_json || "[]")) as string[];
      const riskClass = String(row.risk_classification || "Unknown");
      const ver = String(row.verification_status || "Unverified");
      const isSuspiciousShared =
        ["Moderate", "High", "Critical"].includes(riskClass) ||
        ["Suspicious", "High risk", "Confirmed malicious"].includes(ver);
      if (
        distinctSections.size >= 2 &&
        ver !== "Verified legitimate" &&
        relEvs.length >= 2 &&
        (isSuspiciousShared || (entType !== "sms_sender" && currentRiskScore >= 25))
      ) {
        matches.push({
          patternId: "qr_call_payment_context",
          title: `Cross-section entity match (${entType}: ${String(row.masked_display)})`,
          relatedEventIds: Array.from(new Set([currentEventId, ...relEvs.slice(0, 6)])),
          scoreBoost: ver === "High risk" || ver === "Confirmed malicious" || riskClass === "High" || riskClass === "Critical" ? 24 : 14,
          contradictoryContext: false,
          reasoning: `Shared indicator (${String(row.masked_display)}) appeared across ${mods.join(" + ")}, correlating events cleanly without relying on time proximity alone.`,
        });
        break;
      }
    }
  }

  // Contradiction check: trusted call + benign SMS in window -> do NOT fabricate threat from proximity
  if (matches.length === 0 && trustedOnlyCall && benignSmsOnly) {
    matches.push({
      patternId: "call_sms_link_chain",
      title: "Benign proximity context (Trusted contact + Normal transaction/notice)",
      relatedEventIds: Array.from(new Set([...calls.map((c) => c.eventId), ...smsList.map((s) => s.eventId)])),
      scoreBoost: -10,
      contradictoryContext: true,
      reasoning:
        "Events occurred close together, but evidence points to a Trusted contact and normal banking/informational message. Proximity never equals fraud.",
    });
  }

  return matches;
}

function alertLevelRank(lvl: AlertLevel): number {
  if (lvl === "CRITICAL_RED") return 4;
  if (lvl === "RED") return 3;
  if (lvl === "YELLOW") return 2;
  return 1;
}

function buildThreatHeadline(params: {
  eventType: GsiEventType;
  incidentCategory: string;
  alertLevel: AlertLevel;
  callerIntel?: CallerIntelResult;
  smsIntel?: SmsIntelResult;
  linkIntel: LinkAnalysisResult[];
  correlations: CorrelationPatternMatch[];
}): string {
  const activeCorr = params.correlations.find((c) => !c.contradictoryContext);
  if (activeCorr) {
    if (activeCorr.patternId === "phishing_credential_chain") return "Phishing & OTP Credential Threat Detected";
    if (activeCorr.patternId === "call_sms_link_chain") return "Correlated Scam Call & Phishing Message";
    if (activeCorr.patternId === "repeat_caller_pressure") return "Repeated Suspicious Caller & Payment Pressure";
    if (activeCorr.patternId === "qr_call_payment_context") return "Suspicious QR Activity During Call / Payment";
  }
  if (params.smsIntel) {
    if (params.smsIntel.otpLegitimacy === "disclosure_pressure") return "Suspicious OTP Disclosure Request";
    if (params.smsIntel.category === "High-risk fraudulent pattern") return "High-Risk Banking / Fraud Scam Pattern";
    if (params.smsIntel.category === "Potential phishing") return "Phishing Link Detected in SMS";
    if (params.smsIntel.category === "Suspicious financial request") return "Suspicious Payment / KYC Request";
  }
  if (params.linkIntel.some((l) => l.isLookalike)) return "Phishing Lookalike Link Detected";
  if (params.linkIntel.some((l) => l.riskScore >= 50)) return "Malicious or Suspicious Link Detected";
  if (params.callerIntel) {
    if (params.callerIntel.reputationClass === "Verified Spam" || params.callerIntel.reputationClass === "High Risk" || params.callerIntel.frequency24h >= 3) {
      return "Repeated High-Confidence Spam Caller";
    }
    if (params.callerIntel.reputationClass === "Suspicious") return "Suspicious Call Pattern Caution";
    if (params.callerIntel.reputationClass === "Unknown") return "Unknown Caller Caution";
    return "Trusted Caller Activity";
  }
  if (params.alertLevel === "CRITICAL_RED") return "Serious Financial Security Threat";
  if (params.alertLevel === "RED") return "Suspicious Activity Detected";
  if (params.alertLevel === "YELLOW") return "Caution: Unverified Activity";
  return "Normal Activity";
}

async function evaluateSmartRedAlertDecision(params: {
  familyOwnerId: string;
  eventType: GsiEventType;
  finalScore: number;
  confidence: GsiConfidence;
  incidentCategory: string;
  evidence: string[];
  correlations: CorrelationPatternMatch[];
  callerIntel?: CallerIntelResult;
  smsIntel?: SmsIntelResult;
  linkIntel: LinkAnalysisResult[];
  paymentIntel?: PaymentIntelResult;
  qrData?: GsiIngestPayload["qrData"];
}): Promise<SmartRedAlertDecision> {
  const {
    familyOwnerId,
    eventType,
    finalScore,
    confidence,
    incidentCategory,
    evidence,
    correlations,
    callerIntel,
    smsIntel,
    linkIntel,
    paymentIntel,
    qrData,
  } = params;

  const activeCorrs = correlations.filter((c) => !c.contradictoryContext);
  const hasContradiction = correlations.some((c) => c.contradictoryContext);
  const rationale: string[] = [];

  // Check prior false-positive count for relevant indicators
  let priorFalsePositiveCount = 0;
  if (callerIntel?.callerHash) {
    const fpRow = (await db
      .prepare(
        "SELECT false_positive_count FROM gsi_threat_intel WHERE (user_id IS NULL OR user_id = ?) AND indicator_type = 'phone_hash' AND indicator_hash = ? LIMIT 1"
      )
      .get(familyOwnerId, callerIntel.callerHash)) as { false_positive_count: number } | undefined;
    priorFalsePositiveCount += Number(fpRow?.false_positive_count || 0);
  }
  for (const l of linkIntel) {
    if (l.localIntelMatch?.falsePositiveCount) {
      priorFalsePositiveCount += l.localIntelMatch.falsePositiveCount;
    }
  }

  // Count independent corroborating indicators & credible fraud evidence
  let corroboratingIndicatorsCount = 0;
  let strongSignals = 0;

  if (callerIntel && callerIntel.reputationClass !== "Trusted") {
    if (callerIntel.reputationClass === "Verified Spam") {
      strongSignals += 2;
      corroboratingIndicatorsCount += 2;
    } else if (callerIntel.reputationClass === "High Risk") {
      strongSignals += 1;
      corroboratingIndicatorsCount += 1;
    }
    if (callerIntel.frequency24h >= 3) {
      strongSignals += 1;
      corroboratingIndicatorsCount += 1;
    }
    if (callerIntel.callerClassificationInput === "Private/Hidden Number") {
      corroboratingIndicatorsCount += 1;
    }
    if (callerIntel.unknownBurst30m >= 3) {
      corroboratingIndicatorsCount += 1;
    }
    if (callerIntel.rationale.some((r) => r.includes("Extended unknown call duration"))) {
      corroboratingIndicatorsCount += 1;
    }
  }

  if (smsIntel && !smsIntel.isGenuineInformationalOrPromo) {
    if (smsIntel.otpLegitimacy === "disclosure_pressure") {
      strongSignals += 2;
      corroboratingIndicatorsCount += 2;
    }
    if (smsIntel.category === "High-risk fraudulent pattern") {
      strongSignals += 2;
      corroboratingIndicatorsCount += 1;
    } else if (smsIntel.category === "Potential phishing" || smsIntel.category === "OTP-related security warning") {
      strongSignals += 1;
      corroboratingIndicatorsCount += 1;
    } else if (smsIntel.category === "Suspicious financial request" && smsIntel.riskScore >= 45) {
      strongSignals += 1;
      corroboratingIndicatorsCount += 1;
    }
    if (smsIntel.cues.length >= 2) corroboratingIndicatorsCount += 1;
  }

  for (const l of linkIntel) {
    if (l.riskScore >= 45) {
      const highFindings = l.findings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL").length;
      if (l.isLookalike || highFindings >= 1) strongSignals += 1;
      corroboratingIndicatorsCount += Math.max(1, highFindings);
    }
  }

  if (paymentIntel && !paymentIntel.isHighAmountAlone) {
    if (paymentIntel.isRefundOrCollectLure || paymentIntel.riskScore >= 50) {
      strongSignals += 1;
      corroboratingIndicatorsCount += 1;
    }
  }

  if (qrData && Number(qrData.securityScore || 0) >= 50) {
    strongSignals += 1;
    corroboratingIndicatorsCount += Math.max(1, (qrData.findings || []).length >= 2 ? 2 : 1);
  }

  if (activeCorrs.length > 0) {
    strongSignals += activeCorrs.length;
    corroboratingIndicatorsCount += activeCorrs.length;
  }

  const evidenceQuality: SmartRedAlertDecision["evidenceQuality"] =
    strongSignals >= 2 && corroboratingIndicatorsCount >= 2
      ? "strong"
      : strongSignals >= 1 || corroboratingIndicatorsCount >= 2
        ? "moderate"
        : "weak";

  // Explicitly protect known/benign/legitimate cases from false Red Alerts
  const isKnownTrustedCall =
    eventType === "call_event" &&
    callerIntel?.reputationClass === "Trusted" &&
    activeCorrs.length === 0;
  const isBenignSms =
    eventType === "sms_event" &&
    Boolean(smsIntel?.isGenuineInformationalOrPromo) &&
    finalScore < 25 &&
    activeCorrs.length === 0;
  const isPlainUnknownCall =
    eventType === "call_event" &&
    callerIntel?.reputationClass === "Unknown" &&
    callerIntel.frequency24h <= 1 &&
    activeCorrs.length === 0;
  const isHighPaymentOnly =
    eventType === "payment_event" &&
    Boolean(paymentIntel?.isHighAmountAlone) &&
    activeCorrs.length === 0;

  let alertLevel: AlertLevel = "GREEN";

  if (isKnownTrustedCall || isBenignSms) {
    alertLevel = "GREEN";
    rationale.push("Trusted or benign routine activity; recorded quietly without interruption.");
  } else if (isPlainUnknownCall) {
    alertLevel = "YELLOW";
    rationale.push("Unknown caller without corroborating scam evidence; subtle caution only (no red alert).");
  } else if (isHighPaymentOnly) {
    alertLevel = finalScore >= 25 ? "YELLOW" : "GREEN";
    rationale.push("High transaction amount alone never triggers a Red or Critical Red scam alert.");
  } else if (finalScore < 25) {
    alertLevel = "GREEN";
    rationale.push("Risk score below caution threshold; normal activity recorded.");
  } else if (finalScore < 50) {
    alertLevel = "YELLOW";
    rationale.push("Moderate caution signals; monitoring continues without generating a red alert.");
  } else {
    // Score >= 50: apply strict confidence, evidence quality, and FP gating before allowing RED / CRITICAL_RED
    const fpBlocked = priorFalsePositiveCount >= 2 && finalScore < 80;
    const redGatePassed =
      !hasContradiction &&
      confidence !== "low" &&
      strongSignals >= 1 &&
      evidenceQuality !== "weak" &&
      !fpBlocked;

    if (!redGatePassed) {
      alertLevel = "YELLOW";
      rationale.push(
        fpBlocked
          ? "Held at Caution (YELLOW) because prior false-positive feedback reduced indicator confidence."
          : "Held at Caution (YELLOW): insufficient corroborating high-quality evidence or low confidence for a Red Alert."
      );
    } else if (
      finalScore >= 75 &&
      confidence === "high" &&
      corroboratingIndicatorsCount >= 2 &&
      strongSignals >= 2
    ) {
      alertLevel = "CRITICAL_RED";
      rationale.push(
        `CRITICAL RED triggered: score ${finalScore}/100 with high confidence and ${corroboratingIndicatorsCount} corroborating indicators.`
      );
    } else {
      alertLevel = "RED";
      rationale.push(
        finalScore >= 75
          ? "Classified as RED (not CRITICAL RED) because critical multi-indicator corroboration requirements were not fully met."
          : `RED alert triggered: score ${finalScore}/100 with ${evidenceQuality} credible threat evidence.`
      );
    }
  }

  const redAlertTriggered = alertLevel === "RED" || alertLevel === "CRITICAL_RED";
  const headline = buildThreatHeadline({
    eventType,
    incidentCategory,
    alertLevel,
    callerIntel,
    smsIntel,
    linkIntel,
    correlations,
  });

  return {
    alertLevel,
    redAlertTriggered,
    headline,
    riskScore: finalScore,
    confidence,
    evidenceQuality,
    corroboratingIndicatorsCount,
    priorFalsePositiveCount,
    rationale,
  };
}

function buildDeterministicIncidentGuidance(params: {
  severity: GsiSeverity;
  alertLevel: AlertLevel;
  category: string;
  evidence: string[];
  hasCrossCorrelation: boolean;
}): {
  recommendedAction: string;
  aiFallback: GsiAiExplanation;
} {
  const { severity, alertLevel, category, evidence, hasCrossCorrelation } = params;
  const recommendedAction =
    alertLevel === "CRITICAL_RED"
      ? "STOP immediately. Do not share OTP, UPI PIN, or install screen-sharing apps. Call your bank on its official saved number, notify your guardian, and report to 1930 / cybercrime.gov.in if fraud occurred."
      : alertLevel === "RED"
        ? "Pause before any transfer or link tap. Verify independently with your family guardian or by calling the saved official number."
        : alertLevel === "YELLOW"
          ? "Stay cautious and verify through an official app or saved family number before acting."
          : "Recorded quietly in your family safety history. Keep safeguarding OTPs and UPI PINs.";

  const aiFallback: GsiAiExplanation = {
    available: false,
    model: null,
    explanation: `${alertLevel} (${severity}) assessed under ${category}. ${evidence[0] || "Automated rules evaluated available metadata."}${hasCrossCorrelation ? " Cross-event correlation signals are advisory clues and never prove causation." : ""}`,
    guardianSummary: `${alertLevel} (${severity}) GSI incident (${category}): ${evidence[0] || "Review details in Family Activity."}`,
    recommendedActions: [recommendedAction],
    uncertaintyStatement:
      "Deterministic rule assessment only; call audio is never collected and unverified external merchant registries are unavailable.",
  };
  return { recommendedAction, aiFallback };
}

async function dispatchSmartRedAlerts(params: {
  familyOwnerId: string;
  familyOwnerName: string;
  incidentId: string;
  severity: GsiSeverity;
  alertLevel: AlertLevel;
  headline: string;
  actorMasked: string | null;
  evidence: string[];
  recommendedAction: string;
  isEscalation?: boolean;
  simulateFailure?: "parent" | "child" | "both" | boolean;
}): Promise<{
  notificationsDispatched: number;
  parentNotifStatus: NotifDeliveryStatus;
  childNotifStatus: NotifDeliveryStatus;
}> {
  if (params.alertLevel !== "RED" && params.alertLevel !== "CRITICAL_RED") {
    // GREEN and YELLOW must NEVER trigger red alert or urgent notifications
    return {
      notificationsDispatched: 0,
      parentNotifStatus: "Not Required",
      childNotifStatus: "Not Required",
    };
  }

  await ensureDefaultConsent(params.familyOwnerId);
  const consent = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(params.familyOwnerId)) as { guardian_alerts: number; paused: number } | undefined;

  if (consent?.paused) {
    return {
      notificationsDispatched: 0,
      parentNotifStatus: "Suppressed",
      childNotifStatus: "Suppressed",
    };
  }

  let sent = 0;
  let childStatus: NotifDeliveryStatus = "Pending";
  let parentStatus: NotifDeliveryStatus = "Pending";

  const prefix = params.isEscalation ? "ESCALATED SECURITY ALERT" : "GUARDIAN SECURITY ALERT";
  const riskTag = params.alertLevel === "CRITICAL_RED" ? "CRITICAL" : "HIGH";
  const actorNote = params.actorMasked ? ` Source: ${params.actorMasked}.` : "";
  const reasonLine = params.evidence[0] || params.headline;

  // 1. Child / Monitored User Notification: explains what happened, why suspicious, immediate safety recommendation
  const childTitle = `${prefix}: ${params.headline}`.slice(0, 95);
  const childBody = sanitizeAuditText(
    `What happened: ${params.headline}.${actorNote} Why suspicious: ${reasonLine} Immediate action: ${params.recommendedAction}`
  ).slice(0, 235);

  const simChildFail = params.simulateFailure === true || params.simulateFailure === "both" || params.simulateFailure === "child";
  const simParentFail = params.simulateFailure === true || params.simulateFailure === "both" || params.simulateFailure === "parent";

  try {
    if (simChildFail) {
      throw new Error("Simulated monitored-user notification delivery failure");
    }
    await createNotification(params.familyOwnerId, params.familyOwnerId, "gsi_red_alert", childTitle, childBody);
    const verified = await db
      .prepare(
        "SELECT id FROM notifications WHERE recipient_id = ? AND parent_id = ? AND kind = 'gsi_red_alert' AND title = ? ORDER BY created_at DESC LIMIT 1"
      )
      .get(params.familyOwnerId, params.familyOwnerId, childTitle);
    if (verified) {
      childStatus = "Sent";
      sent++;
    } else {
      childStatus = "Failed";
    }
  } catch {
    childStatus = "Failed";
  }

  // 2. Parent / Linked Guardian Notification(s): incident, risk level, supporting evidence, recommended action (privacy-safe)
  if (!consent?.guardian_alerts) {
    parentStatus = "Suppressed";
  } else {
    const guardians = await getActiveGuardiansForParent(params.familyOwnerId);
    if (guardians.length === 0) {
      parentStatus = "Pending";
    } else {
      const parentTitle = `${prefix} [${riskTag}]: ${params.headline}`.slice(0, 95);
      const parentBody = sanitizeAuditText(
        `Incident for ${params.familyOwnerName} (${riskTag}): ${params.headline}.${actorNote} Evidence: ${reasonLine} Recommended action: ${params.recommendedAction}`
      ).slice(0, 235);

      let guardianSucceeded = 0;
      let guardianFailed = 0;
      for (const g of guardians) {
        try {
          if (simParentFail) {
            throw new Error("Simulated guardian notification delivery failure");
          }
          await createNotification(g.guardian_id, params.familyOwnerId, "gsi_red_alert", parentTitle, parentBody);
          const verified = await db
            .prepare(
              "SELECT id FROM notifications WHERE recipient_id = ? AND parent_id = ? AND kind = 'gsi_red_alert' AND title = ? ORDER BY created_at DESC LIMIT 1"
            )
            .get(g.guardian_id, params.familyOwnerId, parentTitle);
          if (verified) {
            guardianSucceeded++;
            sent++;
          } else {
            guardianFailed++;
          }
        } catch {
          guardianFailed++;
        }
      }
      parentStatus = guardianFailed > 0 && guardianSucceeded === 0 ? "Failed" : guardianFailed > 0 ? "Failed" : "Sent";
    }
  }

  return {
    notificationsDispatched: sent,
    parentNotifStatus: parentStatus,
    childNotifStatus: childStatus,
  };
}

export async function ingestGsiEvent(payload: GsiIngestPayload): Promise<{
  eventId: string;
  deduplicated: boolean;
  escalated?: boolean;
  incident: GsiIncidentRecord;
  decision: SmartRedAlertDecision;
  callerIntel?: CallerIntelResult;
  smsIntel?: SmsIntelResult;
  linkIntel?: LinkAnalysisResult[];
  paymentIntel?: PaymentIntelResult;
}> {
  const now = Date.now();
  const ts =
    typeof payload.eventTimestamp === "number" && Number.isFinite(payload.eventTimestamp) && payload.eventTimestamp > 0
      ? Math.round(payload.eventTimestamp)
      : now;

  await ensureDefaultConsent(payload.familyOwnerId);
  const consent = (await db
    .prepare("SELECT text_analysis, guardian_alerts, guardian_approve, call_timing, paused, red_alert_cooldown_sec FROM consents WHERE user_id = ?")
    .get(payload.familyOwnerId)) as Record<string, number>;
  const cooldownMs = Math.max(60, Number(consent?.red_alert_cooldown_sec || 600)) * 1000;

  let callerIntel: CallerIntelResult | undefined;
  let smsIntel: SmsIntelResult | undefined;
  const linkIntel: LinkAnalysisResult[] = [];
  let paymentIntel: PaymentIntelResult | undefined;

  let baseScore = 0;
  let incidentCategory = String(payload.eventType);
  const evidence: string[] = [];
  let confidence: GsiConfidence = "medium";
  let dedupSeed = `${payload.eventType}:${payload.sourceModule}`;
  let indicatorFingerprint = `${payload.eventType}:${payload.sourceModule}`;
  let actorMasked: string | null = null;
  let eventMeta: Record<string, unknown> = {};

  if (payload.eventType === "call_event" && payload.callData) {
    callerIntel = await evaluateCallerIntelligence(payload.familyOwnerId, payload.callData, ts);
    baseScore = callerIntel.riskScore;
    confidence = callerIntel.confidence;
    incidentCategory = `caller_${callerIntel.reputationClass.toLowerCase().replace(/\s+/g, "_")}`;
    evidence.push(...callerIntel.rationale);
    actorMasked = callerIntel.callerMasked || callerIntel.callerClassificationInput;
    dedupSeed = `call:${callerIntel.callerHash || callerIntel.callerClassificationInput}:${Math.floor(ts / 300_000)}`;
    indicatorFingerprint = `call:${callerIntel.callerHash || callerIntel.callerClassificationInput}`;
    eventMeta = { ...callerIntel };

    if (callerIntel.callerHash && callerIntel.reputationClass !== "Unknown" && callerIntel.reputationClass !== "Trusted") {
      await upsertThreatIntelIndicator({
        userId: payload.familyOwnerId,
        indicatorType: "phone_hash",
        indicatorHash: callerIntel.callerHash,
        indicatorDisplay: callerIntel.callerMasked || "Hidden caller",
        suggestedLabel: callerIntel.reputationClass,
        evidenceSummary: callerIntel.rationale[0] || "Suspicious call pattern",
        source: payload.sourceModule,
      });
    }
  } else if (payload.eventType === "sms_event" && payload.smsData) {
    smsIntel = await evaluateSmsIntelligence(
      payload.familyOwnerId,
      payload.smsData,
      Boolean(payload.allowNetworkProbe)
    );
    baseScore = smsIntel.riskScore;
    confidence = smsIntel.confidence;
    incidentCategory = `sms_${smsIntel.category.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`;
    evidence.push(...smsIntel.cues);
    linkIntel.push(...smsIntel.embeddedLinks);
    for (const lnk of smsIntel.embeddedLinks) {
      for (const f of lnk.findings) evidence.push(`Link (${lnk.domain || "url"}): ${f.title}`);
    }
    actorMasked = smsIntel.senderLabel || (smsIntel.embeddedLinks[0]?.domain ? `Sender / ${smsIntel.embeddedLinks[0].domain}` : null);
    dedupSeed = `sms:${sha256(smsIntel.redactedExcerpt.toLowerCase())}:${Math.floor(ts / 600_000)}`;
    indicatorFingerprint = smsIntel.embeddedLinks[0]?.domain
      ? `sms_dom:${smsIntel.embeddedLinks[0].domain}`
      : `sms:${sha256(smsIntel.redactedExcerpt.toLowerCase())}`;
    eventMeta = { ...smsIntel };

    // Record risky domains into local threat intel (without auto-marking Verified Spam from 1 occurrence)
    for (const lnk of smsIntel.embeddedLinks) {
      if (lnk.domain && lnk.riskScore >= 40) {
        await upsertThreatIntelIndicator({
          userId: payload.familyOwnerId,
          indicatorType: "domain",
          indicatorHash: sha256(`domain:${lnk.domain}`),
          indicatorDisplay: lnk.domain,
          suggestedLabel: lnk.riskScore >= 65 ? "High Risk" : "Suspicious",
          evidenceSummary: lnk.findings[0]?.title || "Suspicious domain in SMS",
          source: "module_c_link_intel",
        });
      }
    }
  } else if (payload.eventType === "link_event" && payload.linkData) {
    const lnk = await analyzeUrlIntelligence(payload.linkData.url, {
      userId: payload.familyOwnerId,
      contextText: payload.linkData.contextText,
      allowNetworkProbe: Boolean(payload.allowNetworkProbe),
    });
    linkIntel.push(lnk);
    baseScore = lnk.riskScore;
    confidence = lnk.confidence;
    incidentCategory = lnk.isLookalike ? "phishing_lookalike_link" : "link_inspection";
    evidence.push(...lnk.findings.map((f) => `${f.title} (${f.evidence})`));
    if (evidence.length === 0) evidence.push(lnk.liveProbeNote);
    actorMasked = lnk.domain || lnk.scheme;
    dedupSeed = `link:${lnk.urlHash}:${Math.floor(ts / 600_000)}`;
    indicatorFingerprint = `link:${lnk.urlHash}`;
    eventMeta = { ...lnk };

    if (lnk.domain && lnk.riskScore >= 40) {
      await upsertThreatIntelIndicator({
        userId: payload.familyOwnerId,
        indicatorType: "domain",
        indicatorHash: sha256(`domain:${lnk.domain}`),
        indicatorDisplay: lnk.domain,
        suggestedLabel: lnk.riskScore >= 65 ? "High Risk" : "Suspicious",
        evidenceSummary: lnk.findings[0]?.title || "Flagged URL pattern",
        source: "module_c_link_intel",
      });
    }
  } else if (payload.eventType === "qr_event" && payload.qrData) {
    const qrClassification = String(
      payload.qrData.classification ||
        (payload.qrData.upiId ? "UPI Payment QR" : payload.qrData.urlString ? "External Web URL" : "QR Payload")
    );
    const qrRawScore = Number(payload.qrData.securityScore);
    baseScore = Math.max(0, Math.min(100, Number.isFinite(qrRawScore) ? qrRawScore : 25));
    incidentCategory = `qr_${qrClassification.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`;
    confidence = baseScore >= 40 ? "high" : "medium";
    evidence.push(...(payload.qrData.findings?.length ? payload.qrData.findings : [`QR classified as ${qrClassification}`]));
    const qrUrl = payload.qrData.urlString || (payload.qrData as unknown as { url?: string | null }).url || null;
    if (qrUrl) {
      const lnk = await analyzeUrlIntelligence(qrUrl, {
        userId: payload.familyOwnerId,
        allowNetworkProbe: Boolean(payload.allowNetworkProbe),
      });
      linkIntel.push(lnk);
      baseScore = Math.max(baseScore, lnk.riskScore);
    }
    actorMasked = payload.qrData.upiId || payload.qrData.payeeName || qrUrl || null;
    dedupSeed = `qr:${payload.qrData.scanId || payload.qrData.upiId || qrUrl || ts}`;
    indicatorFingerprint = `qr:${payload.qrData.upiId || qrUrl || qrClassification}`;
    eventMeta = { ...payload.qrData, classification: qrClassification, securityScore: baseScore };
  } else if (payload.eventType === "payment_event" && payload.paymentData) {
    paymentIntel = await evaluatePaymentIntelligence(payload.familyOwnerId, payload.paymentData);
    baseScore = paymentIntel.riskScore;
    confidence = paymentIntel.confidence;
    incidentCategory = `payment_${paymentIntel.direction}`;
    evidence.push(...paymentIntel.evidence);
    actorMasked = paymentIntel.beneficiary;
    dedupSeed = `pay:${paymentIntel.direction}:${paymentIntel.amount ?? "na"}:${paymentIntel.beneficiary || "na"}:${Math.floor(ts / 300_000)}`;
    indicatorFingerprint = `pay:${paymentIntel.direction}:${paymentIntel.beneficiary || "na"}`;
    eventMeta = { ...paymentIntel };
  }

  const dedupHash = sha256(`${payload.familyOwnerId}|${dedupSeed}`);
  const eventId = generateId("gev");
  const deviceId = (payload.deviceId || "web_session").slice(0, 60);

  // Extract normalized GCIH entities BEFORE correlation so cross-section entities unify immediately
  const rawEntityCandidates: ExtractedEntityCandidate[] = [];
  if (payload.eventType === "call_event" && payload.callData?.callerIdentifier) {
    const ph = normalizeEntityValue("phone_number", payload.callData.callerIdentifier);
    if (ph) rawEntityCandidates.push(ph);
  } else if (payload.eventType === "sms_event" && payload.smsData) {
    rawEntityCandidates.push(...extractEntitiesFromText(payload.smsData.rawText, payload.smsData.senderLabel));
  } else if (payload.eventType === "link_event" && payload.linkData) {
    const u = normalizeEntityValue("url", payload.linkData.url);
    if (u) {
      rawEntityCandidates.push(u);
      try {
        const d = normalizeEntityValue("domain", new URL(u.normalizedKey).hostname);
        if (d) rawEntityCandidates.push(d);
      } catch {
        // ignore
      }
    }
  } else if (payload.eventType === "qr_event" && payload.qrData) {
    rawEntityCandidates.push(
      ...extractEntitiesFromQrPayload({
        upiId: payload.qrData.upiId,
        payeeName: payload.qrData.payeeName,
        merchantName: payload.qrData.merchantName,
        urlString: payload.qrData.urlString,
        payloadHash: payload.qrData.payloadHash,
      })
    );
  } else if (payload.eventType === "payment_event" && payload.paymentData) {
    rawEntityCandidates.push(
      ...extractEntitiesFromPayment({
        beneficiary: payload.paymentData.beneficiary,
        signals: payload.paymentData.signals,
      })
    );
  }

  const gcihRiskClass = severityToGcihRisk(baseScore);
  const gcihConfNumeric = confidence === "high" ? 0.85 : confidence === "medium" ? 0.65 : 0.45;
  const upsertedEntities: GcihEntityRecord[] = await Promise.all(
    rawEntityCandidates.map((cand) =>
      upsertSharedEntity({
        familyOwnerId: payload.familyOwnerId,
        candidate: cand,
        sourceModule: payload.sourceModule,
        sourceDeviceId: deviceId,
        eventId,
        riskClassification: gcihRiskClass,
        confidence: gcihConfNumeric,
        evidenceRef: evidence[0] || `${payload.eventType} (${baseScore}/100)`,
        timestamp: ts,
      })
    )
  );
  const gcihEntityIds = upsertedEntities.map((e) => e.id);
  if (upsertedEntities.length >= 2) {
    await linkCoOccurringEntities({
      familyOwnerId: payload.familyOwnerId,
      entities: upsertedEntities,
      eventId,
      sourceModule: payload.sourceModule,
      evidence: evidence[0] || `Observed together in ${payload.sourceModule}`,
      confidence: gcihConfNumeric,
    });
  }
  eventMeta = { ...eventMeta, gcihEntityIds };

  // Preserve initial indicator fingerprint so cooldown deduplication matches the primary incident even if a second module observes the same entity
  const baseIndicatorFingerprint = indicatorFingerprint;

  // Prefer shared high-priority entity fingerprint when multiple modules observe the same indicator (prevents duplicate alerts)
  const primarySharedEntity =
    upsertedEntities.find(
      (e) =>
        e.entityType === "url" ||
        e.entityType === "upi_id" ||
        e.entityType === "phone_number"
    ) || upsertedEntities[0];
  if (primarySharedEntity && primarySharedEntity.sourceModules.length >= 2) {
    indicatorFingerprint = `gcih_ent:${primarySharedEntity.entityType}:${primarySharedEntity.normalizedHash}`;
  }

  await db.prepare(
    `INSERT INTO gsi_events (
       event_id, family_owner_id, device_id, event_type, event_timestamp,
       source_module, event_version, dedup_hash, metadata_json, risk_indicators_json,
       consent_context_json, processing_status, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'processed', ?)`
  ).run(
    eventId,
    payload.familyOwnerId,
    deviceId,
    payload.eventType,
    ts,
    payload.sourceModule.slice(0, 60),
    payload.eventVersion || 1,
    dedupHash,
    JSON.stringify(eventMeta),
    JSON.stringify({ riskScore: baseScore, evidence: evidence.slice(0, 8), gcihEntityIds }),
    JSON.stringify(consent || {}),
    now
  );

  // Module E: Cross-event correlation across recent events (including GCIH entity-matched correlation)
  const correlations = await correlateRecentEvents(
    payload.familyOwnerId,
    eventId,
    payload.eventType,
    ts,
    eventMeta
  );

  let finalScore = baseScore;
  const relatedEventIds = new Set<string>([eventId]);
  let hasContradiction = false;

  for (const c of correlations) {
    for (const id of c.relatedEventIds) relatedEventIds.add(id);
    if (c.contradictoryContext) {
      hasContradiction = true;
      finalScore = Math.max(0, finalScore + c.scoreBoost);
      evidence.push(`${c.title}: ${c.reasoning}`);
    } else {
      finalScore = Math.min(100, finalScore + c.scoreBoost);
      evidence.push(`${c.title}: ${c.reasoning}`);
      incidentCategory = `correlated_${c.patternId}`;
      indicatorFingerprint = `corr:${c.patternId}:${actorMasked || payload.eventType}`;
    }
  }

  const aggregatedModules = new Set<string>([payload.sourceModule]);
  const aggregatedDevices = new Set<string>([deviceId]);
  const aggregatedEntityIds = new Set<string>(gcihEntityIds);
  if (relatedEventIds.size > 1) {
    const relIds = Array.from(relatedEventIds);
    const relRows = (await db
      .prepare(
        `SELECT source_module, device_id, risk_indicators_json
         FROM gsi_events
         WHERE family_owner_id = ? AND event_id IN (${relIds.map(() => "?").join(",")})`
      )
      .all(payload.familyOwnerId, ...relIds)) as {
      source_module: string;
      device_id: string;
      risk_indicators_json: string;
    }[];
    for (const rr of relRows) {
      if (rr.source_module) aggregatedModules.add(String(rr.source_module));
      if (rr.device_id) aggregatedDevices.add(String(rr.device_id));
      try {
        const ri = JSON.parse(String(rr.risk_indicators_json || "{}")) as { gcihEntityIds?: string[] };
        if (Array.isArray(ri.gcihEntityIds)) {
          for (const eid of ri.gcihEntityIds) aggregatedEntityIds.add(String(eid));
        }
      } catch {
        // ignore malformed JSON
      }
    }
  }

  if (hasContradiction) {
    confidence = "low";
  } else if (correlations.some((c) => !c.contradictoryContext) && evidence.length >= 2) {
    confidence = "high";
  }

  // Safeguard: Single weak signal cannot become CRITICAL (unless explicit OTP/remote-access pressure or >=2 findings)
  if (
    finalScore >= 75 &&
    evidence.length < 2 &&
    !(smsIntel && smsIntel.otpLegitimacy === "disclosure_pressure") &&
    !linkIntel.some((l) => l.findings.some((f) => f.severity === "CRITICAL"))
  ) {
    finalScore = 68;
  }

  finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));
  const severity = scoreToSeverity(finalScore);

  // Centralized Smart Red Alert Decision Engine
  const decision = await evaluateSmartRedAlertDecision({
    familyOwnerId: payload.familyOwnerId,
    eventType: payload.eventType,
    finalScore,
    confidence,
    incidentCategory,
    evidence,
    correlations,
    callerIntel,
    smsIntel,
    linkIntel,
    paymentIntel,
    qrData: payload.qrData,
  });

  const guidance = buildDeterministicIncidentGuidance({
    severity,
    alertLevel: decision.alertLevel,
    category: incidentCategory,
    evidence,
    hasCrossCorrelation: correlations.some((c) => !c.contradictoryContext),
  });

  let aiExplanation = guidance.aiFallback;
  if (!payload.skipAi && decision.redAlertTriggered) {
    try {
      aiExplanation = await explainGsiIncidentWithGemini({
        structuredFacts: {
          category: incidentCategory,
          riskScore: finalScore,
          severity,
          confidence,
          evidence: evidence.slice(0, 6),
          hasCrossCorrelation: correlations.some((c) => !c.contradictoryContext),
        },
        lang: payload.lang || "en",
      });
    } catch {
      aiExplanation = guidance.aiFallback;
    }
  }

  const baseFpHash = sha256(`${payload.familyOwnerId}|${baseIndicatorFingerprint}`);
  const fpHash = sha256(`${payload.familyOwnerId}|${indicatorFingerprint}`);
  const incidentDedupKey = sha256(
    `${payload.familyOwnerId}|${incidentCategory}|${indicatorFingerprint}|${Math.floor(ts / cooldownMs)}`
  );

  const existingInc = (await db
    .prepare(
      `SELECT * FROM gsi_incidents
       WHERE family_owner_id = ?
         AND resolution_status = 'open'
         AND (indicator_fingerprint IN (?, ?) OR dedup_key = ?)
         AND updated_at >= ?
       ORDER BY updated_at DESC LIMIT 1`
    )
    .get(payload.familyOwnerId, fpHash, baseFpHash, incidentDedupKey, now - cooldownMs)) as
    | Record<string, unknown>
    | undefined;

  if (existingInc) {
    const mergedIds = Array.from(
      new Set([
        ...(JSON.parse(String(existingInc.related_event_ids_json || "[]")) as string[]),
        ...Array.from(relatedEventIds),
      ])
    ).slice(0, 20);

    const prevAlertLevel = String(existingInc.alert_level || "GREEN") as AlertLevel;
    const escalated = alertLevelRank(decision.alertLevel) > alertLevelRank(prevAlertLevel);
    const nextAlertLevel = escalated ? decision.alertLevel : prevAlertLevel;
    const mergedScore = Math.max(Number(existingInc.risk_score || 0), finalScore);
    const mergedSeverity = scoreToSeverity(mergedScore);
    const mergedEvidence = Array.from(
      new Set([...(JSON.parse(String(existingInc.evidence_json || "[]")) as string[]), ...evidence])
    ).slice(0, 12);

    let notificationsDispatched = 0;
    let nextParentStatus = String(existingInc.parent_notif_status || "Not Required") as NotifDeliveryStatus;
    let nextChildStatus = String(existingInc.child_notif_status || "Not Required") as NotifDeliveryStatus;

    if (escalated && (nextAlertLevel === "RED" || nextAlertLevel === "CRITICAL_RED")) {
      const dispatchRes = await dispatchSmartRedAlerts({
        familyOwnerId: payload.familyOwnerId,
        familyOwnerName: payload.familyOwnerName,
        incidentId: String(existingInc.incident_id),
        severity: mergedSeverity,
        alertLevel: nextAlertLevel,
        headline: decision.headline,
        actorMasked,
        evidence: mergedEvidence,
        recommendedAction: guidance.recommendedAction,
        isEscalation: true,
        simulateFailure: payload.simulateNotificationFailure,
      });
      notificationsDispatched = dispatchRes.notificationsDispatched;
      nextParentStatus = dispatchRes.parentNotifStatus;
      nextChildStatus = dispatchRes.childNotifStatus;
    }

    const mergedEntityIds = Array.from(
      new Set([
        ...(JSON.parse(String(existingInc.involved_entity_ids_json || "[]")) as string[]),
        ...Array.from(aggregatedEntityIds),
      ])
    ).slice(0, 30);
    const mergedModules = Array.from(
      new Set([
        ...(JSON.parse(String(existingInc.source_modules_json || "[]")) as string[]),
        ...Array.from(aggregatedModules),
      ])
    ).slice(0, 15);
    const mergedDevices = Array.from(
      new Set([
        ...(JSON.parse(String(existingInc.source_device_ids_json || "[]")) as string[]),
        ...Array.from(aggregatedDevices),
      ])
    ).slice(0, 15);

    await db.prepare(
      `UPDATE gsi_incidents SET
         related_event_ids_json = ?, incident_category = ?, risk_score = ?, severity = ?, alert_level = ?,
         confidence = ?, actor_masked = COALESCE(?, actor_masked),
         evidence_json = ?, reasoning_summary = ?, recommended_action = ?, ai_explanation_json = ?,
         parent_notif_status = ?, child_notif_status = ?, decision_rationale_json = ?,
         involved_entity_ids_json = ?, source_modules_json = ?, source_device_ids_json = ?,
         acknowledgement_status = CASE WHEN ? = 1 THEN 'unacknowledged' ELSE acknowledgement_status END,
         updated_at = ?
       WHERE incident_id = ?`
    ).run(
      JSON.stringify(mergedIds),
      escalated ? incidentCategory : String(existingInc.incident_category),
      mergedScore,
      mergedSeverity,
      nextAlertLevel,
      confidence,
      actorMasked,
      JSON.stringify(mergedEvidence),
      (evidence[0] || String(existingInc.reasoning_summary)).slice(0, 400),
      guidance.recommendedAction.slice(0, 400),
      JSON.stringify(aiExplanation),
      nextParentStatus,
      nextChildStatus,
      JSON.stringify(decision.rationale),
      JSON.stringify(mergedEntityIds),
      JSON.stringify(mergedModules),
      JSON.stringify(mergedDevices),
      escalated ? 1 : 0,
      now,
      String(existingInc.incident_id)
    );

    const existingIncId = String(existingInc.incident_id);
    await attachIncidentToEntities(gcihEntityIds, existingIncId);
    await recordIncidentHistory({
      incidentId: existingIncId,
      familyOwnerId: payload.familyOwnerId,
      actorId: payload.familyOwnerId,
      previousStatus: String(existingInc.workflow_status || "New"),
      nextStatus: String(existingInc.workflow_status || "New"),
      action: escalated ? "incident_escalated" : "incident_merged",
      summary: `${payload.sourceModule} correlated event (${mergedScore}/100, ${nextAlertLevel})`,
    });
    await emitDomainEventsForIngestion({
      familyOwnerId: payload.familyOwnerId,
      deviceId,
      sourceModule: payload.sourceModule,
      eventType: payload.eventType,
      gsiEventId: eventId,
      incidentId: existingIncId,
      isNewIncident: false,
      baseScore,
      entities: upsertedEntities,
      evidence,
      consent,
      timestamp: ts,
    });

    const refreshed = (await db
      .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
      .get(existingIncId)) as Record<string, unknown>;
    return {
      eventId,
      deduplicated: !escalated,
      escalated,
      incident: mapIncidentRow(refreshed, notificationsDispatched),
      decision,
      callerIntel,
      smsIntel,
      linkIntel: linkIntel.length ? linkIntel : undefined,
      paymentIntel,
    };
  }

  const incidentId = generateId("gsi");
  const reasoningSummary =
    evidence[0] || `GSI ${decision.alertLevel} assessment under ${incidentCategory}`;

  const dispatchRes = await dispatchSmartRedAlerts({
    familyOwnerId: payload.familyOwnerId,
    familyOwnerName: payload.familyOwnerName,
    incidentId,
    severity,
    alertLevel: decision.alertLevel,
    headline: decision.headline,
    actorMasked,
    evidence,
    recommendedAction: guidance.recommendedAction,
    isEscalation: false,
    simulateFailure: payload.simulateNotificationFailure,
  });

  await db.prepare(
    `INSERT INTO gsi_incidents (
       incident_id, family_owner_id, related_event_ids_json, incident_category,
       risk_score, severity, alert_level, confidence, detection_source, actor_masked, evidence_json,
       reasoning_summary, recommended_action, rule_version, ai_explanation_json,
       acknowledgement_status, resolution_status, parent_notif_status, child_notif_status,
       decision_rationale_json, indicator_fingerprint, dedup_key,
       involved_entity_ids_json, source_modules_json, source_device_ids_json, workflow_status, timeline_json,
       created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unacknowledged', 'open', ?, ?, ?, ?, ?, ?, ?, ?, 'New', '[]', ?, ?)`
  ).run(
    incidentId,
    payload.familyOwnerId,
    JSON.stringify(Array.from(relatedEventIds)),
    incidentCategory,
    finalScore,
    severity,
    decision.alertLevel,
    confidence,
    payload.sourceModule,
    actorMasked,
    JSON.stringify(Array.from(new Set(evidence)).slice(0, 12)),
    reasoningSummary.slice(0, 400),
    guidance.recommendedAction.slice(0, 400),
    GSI_RULE_VERSION,
    JSON.stringify(aiExplanation),
    dispatchRes.parentNotifStatus,
    dispatchRes.childNotifStatus,
    JSON.stringify(decision.rationale),
    fpHash,
    incidentDedupKey,
    JSON.stringify(Array.from(aggregatedEntityIds).slice(0, 30)),
    JSON.stringify(Array.from(aggregatedModules).slice(0, 15)),
    JSON.stringify(Array.from(aggregatedDevices).slice(0, 15)),
    now,
    now
  );

  await attachIncidentToEntities(Array.from(aggregatedEntityIds), incidentId);
  await recordIncidentHistory({
    incidentId,
    familyOwnerId: payload.familyOwnerId,
    actorId: payload.familyOwnerId,
    previousStatus: null,
    nextStatus: "New",
    action: "incident_created",
    summary: `${payload.sourceModule}: ${reasoningSummary.slice(0, 120)}`,
  });
  await emitDomainEventsForIngestion({
    familyOwnerId: payload.familyOwnerId,
    deviceId,
    sourceModule: payload.sourceModule,
    eventType: payload.eventType,
    gsiEventId: eventId,
    incidentId,
    isNewIncident: true,
    baseScore,
    entities: upsertedEntities,
    evidence,
    consent,
    timestamp: ts,
  });

  await writeAudit(payload.familyOwnerId, `GSI ${decision.alertLevel}/${severity} (${finalScore}/100) ${incidentCategory}`);

  const row = (await db
    .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
    .get(incidentId)) as Record<string, unknown>;

  return {
    eventId,
    deduplicated: false,
    escalated: false,
    incident: mapIncidentRow(row, dispatchRes.notificationsDispatched),
    decision,
    callerIntel,
    smsIntel,
    linkIntel: linkIntel.length ? linkIntel : undefined,
    paymentIntel,
  };
}

async function emitDomainEventsForIngestion(params: {
  familyOwnerId: string;
  deviceId: string;
  sourceModule: string;
  eventType: GsiEventType;
  gsiEventId: string;
  incidentId: string;
  isNewIncident: boolean;
  baseScore: number;
  entities: GcihEntityRecord[];
  evidence: string[];
  consent: Record<string, number>;
  timestamp: number;
}): Promise<void> {
  const { familyOwnerId, deviceId, sourceModule, eventType, gsiEventId, incidentId, isNewIncident, baseScore, entities, evidence, consent, timestamp } = params;
  const entityIds = entities.map((e) => e.id);
  const pending: Promise<unknown>[] = [];
  const pub = (evType: GcihDomainEventType, seedExtra: string, subsetIds = entityIds) => {
    pending.push(
      publishDomainEvent({
        familyOwnerId,
        sourceDeviceId: deviceId,
        sourceModule,
        eventType: evType,
        entityIds: subsetIds,
        evidenceRefs: evidence.slice(0, 4),
        gsiEventId,
        incidentId,
        consentContext: consent,
        dedupSeed: `${gsiEventId}:${seedExtra}`,
        eventTimestamp: timestamp,
      })
    );
  };

  if (eventType === "call_event") {
    pub("CALL_DETECTED", "call");
    if (baseScore >= 25) pub("SUSPICIOUS_CALL_IDENTIFIED", "susp_call");
  } else if (eventType === "sms_event") {
    pub("SMS_RECEIVED", "sms");
    if (baseScore >= 25) pub("SUSPICIOUS_SMS_IDENTIFIED", "susp_sms");
    const phones = entities.filter((e) => e.entityType === "phone_number").map((e) => e.id);
    if (phones.length) pub("PHONE_NUMBER_EXTRACTED", "sms_phone", phones);
    const urls = entities.filter((e) => e.entityType === "url" || e.entityType === "domain").map((e) => e.id);
    if (urls.length) pub("URL_EXTRACTED", "sms_url", urls);
    const upis = entities.filter((e) => e.entityType === "upi_id").map((e) => e.id);
    if (upis.length && baseScore >= 25) pub("SUSPICIOUS_UPI_IDENTIFIED", "sms_upi", upis);
  } else if (eventType === "link_event") {
    pub("URL_EXTRACTED", "lnk");
    if (baseScore >= 50) pub("MALICIOUS_URL_IDENTIFIED", "mal_lnk");
  } else if (eventType === "qr_event") {
    pub("QR_CODE_SCANNED", "qr");
    pub("QR_DESTINATION_IDENTIFIED", "qr_dest");
    const upis = entities.filter((e) => e.entityType === "upi_id").map((e) => e.id);
    if (upis.length && baseScore >= 25) pub("SUSPICIOUS_UPI_IDENTIFIED", "qr_upi", upis);
    const urls = entities.filter((e) => e.entityType === "url" || e.entityType === "domain").map((e) => e.id);
    if (urls.length) {
      pub("URL_EXTRACTED", "qr_url", urls);
      if (baseScore >= 50) pub("MALICIOUS_URL_IDENTIFIED", "qr_mal_url", urls);
    }
  } else if (eventType === "payment_event") {
    if (baseScore >= 25) pub("PAYMENT_RISK_IDENTIFIED", "pay_risk");
  }

  pub(isNewIncident ? "INCIDENT_CREATED" : "INCIDENT_UPDATED", `inc:${incidentId}`);
  await Promise.all(pending);
}

function mapIncidentRow(
  row: Record<string, unknown>,
  notificationsDispatched = 0,
  parentName?: string
): GsiIncidentRecord {
  const sev = String(row.severity) as GsiSeverity;
  const rawLevel = row.alert_level ? String(row.alert_level) : "";
  const alertLevel: AlertLevel =
    rawLevel === "GREEN" || rawLevel === "YELLOW" || rawLevel === "RED" || rawLevel === "CRITICAL_RED"
      ? rawLevel
      : sev === "CRITICAL"
        ? "CRITICAL_RED"
        : sev === "HIGH"
          ? "RED"
          : sev === "MODERATE"
            ? "YELLOW"
            : "GREEN";
  return {
    incidentId: String(row.incident_id),
    familyOwnerId: String(row.family_owner_id),
    ...(parentName ? { parentName } : {}),
    relatedEventIds: JSON.parse(String(row.related_event_ids_json || "[]")),
    incidentCategory: String(row.incident_category),
    riskScore: Number(row.risk_score),
    severity: sev,
    alertLevel,
    redAlertTriggered: alertLevel === "RED" || alertLevel === "CRITICAL_RED",
    confidence: String(row.confidence) as GsiConfidence,
    detectionSource: String(row.detection_source),
    actorMasked: row.actor_masked ? String(row.actor_masked) : null,
    evidence: JSON.parse(String(row.evidence_json || "[]")),
    reasoningSummary: String(row.reasoning_summary),
    recommendedAction: String(row.recommended_action),
    ruleVersion: String(row.rule_version),
    aiExplanation: JSON.parse(
      String(row.ai_explanation_json || '{"available":false,"model":null,"explanation":"","guardianSummary":"","recommendedActions":[],"uncertaintyStatement":""}')
    ),
    acknowledgementStatus: String(row.acknowledgement_status) as "unacknowledged" | "acknowledged",
    resolutionStatus: String(row.resolution_status) as GsiIncidentRecord["resolutionStatus"],
    feedbackStatus: row.feedback_status ? String(row.feedback_status) : null,
    feedbackNote: row.feedback_note ? String(row.feedback_note) : null,
    parentNotifStatus: (row.parent_notif_status ? String(row.parent_notif_status) : "Not Required") as NotifDeliveryStatus,
    childNotifStatus: (row.child_notif_status ? String(row.child_notif_status) : "Not Required") as NotifDeliveryStatus,
    decisionRationale: JSON.parse(String(row.decision_rationale_json || "[]")),
    notificationsDispatched,
    involvedEntityIds: JSON.parse(String(row.involved_entity_ids_json || "[]")),
    sourceModules: JSON.parse(String(row.source_modules_json || "[]")),
    sourceDeviceIds: JSON.parse(String(row.source_device_ids_json || "[]")),
    workflowStatus: (row.workflow_status ? String(row.workflow_status) : "New") as GcihIncidentWorkflowStatus,
    timeline: JSON.parse(String(row.timeline_json || "[]")),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  };
}

/* ---- Feedback & False-Positive Learning Loop ---- */
export async function recordGsiFeedback(params: {
  actorId: string;
  actorRole: "parent" | "guardian";
  incidentId: string;
  action: "acknowledge" | "resolve" | "confirm_threat" | "false_positive";
  note?: string;
}): Promise<GsiIncidentRecord> {
  const row = (await db
    .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
    .get(params.incidentId)) as Record<string, unknown> | undefined;

  if (!row) {
    throw new Error("Incident not found.");
  }

  const ownerId = String(row.family_owner_id);
  if (params.actorRole === "parent" && ownerId !== params.actorId) {
    throw new Error("Unauthorized access to incident.");
  }
  if (params.actorRole === "guardian") {
    const linked = await db
      .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
      .get(ownerId, params.actorId);
    if (!linked) {
      throw new Error("Unauthorized: you are not an active linked guardian for this account.");
    }
  }

  const now = Date.now();
  const cleanNote = params.note ? sanitizeAuditText(params.note).slice(0, 200) : null;

  let nextAck = String(row.acknowledgement_status);
  let nextRes = String(row.resolution_status);
  let nextFb = row.feedback_status ? String(row.feedback_status) : null;

  if (params.action === "acknowledge") {
    nextAck = "acknowledged";
  } else if (params.action === "resolve") {
    nextAck = "acknowledged";
    nextRes = "resolved";
  } else if (params.action === "false_positive") {
    nextAck = "acknowledged";
    nextRes = "false_positive";
    nextFb = "false_positive";
  } else if (params.action === "confirm_threat") {
    nextAck = "acknowledged";
    nextRes = "confirmed_threat";
    nextFb = "confirmed_threat";
  }

  const prevWorkflow = String(row.workflow_status || "New");
  const nextWorkflow: GcihIncidentWorkflowStatus =
    params.action === "acknowledge"
      ? "Acknowledged"
      : params.action === "resolve"
        ? "Resolved"
        : params.action === "false_positive"
          ? "False positive"
          : "Investigating";

  await db.prepare(
    `UPDATE gsi_incidents SET
       acknowledgement_status = ?, resolution_status = ?, workflow_status = ?,
       feedback_status = ?, feedback_note = COALESCE(?, feedback_note), updated_at = ?
     WHERE incident_id = ?`
  ).run(nextAck, nextRes, nextWorkflow, nextFb, cleanNote, now, params.incidentId);

  await recordIncidentHistory({
    incidentId: params.incidentId,
    familyOwnerId: ownerId,
    actorId: params.actorId,
    previousStatus: prevWorkflow,
    nextStatus: nextWorkflow,
    action: params.action,
    summary: cleanNote || `Incident marked ${params.action}`,
  });

  // Update Threat Intel indicators & GCIH shared entities linked to incident
  if (params.action === "false_positive" || params.action === "confirm_threat") {
    const involvedIds = JSON.parse(String(row.involved_entity_ids_json || "[]")) as string[];
    for (const entId of involvedIds.slice(0, 8)) {
      const entRow = (await db.prepare("SELECT * FROM gcih_entities WHERE id = ?").get(entId)) as
        | Record<string, unknown>
        | undefined;
      if (!entRow) continue;
      if (params.action === "false_positive") {
        // Scope legitimacy strictly to the flagged entities of this incident — NEVER blindly whitelist an entire SMS sender
        if (String(entRow.entity_type) !== "sms_sender") {
          await db.prepare(
            `UPDATE gcih_entities SET
               risk_classification = 'Safe', verification_status = 'Verified legitimate',
               fp_count = fp_count + 1, version = version + 1, updated_at = ?
             WHERE id = ?`
          ).run(now, entId);
        }
      } else {
        await db.prepare(
          `UPDATE gcih_entities SET
             risk_classification = 'High', verification_status = 'Confirmed malicious',
             report_count = report_count + 1, version = version + 1, updated_at = ?
           WHERE id = ?`
        ).run(now, entId);
      }
    }
    await publishDomainEvent({
      familyOwnerId: ownerId,
      sourceDeviceId: params.actorRole === "guardian" ? "guardian_device" : "monitored_device",
      sourceModule: "user_feedback",
      eventType: "USER_FEEDBACK_RECEIVED",
      entityIds: involvedIds,
      evidenceRefs: [cleanNote || `Incident ${params.action}`],
      incidentId: params.incidentId,
      dedupSeed: `incfb:${params.incidentId}:${params.action}:${Math.floor(now / 1000)}`,
      eventTimestamp: now,
    });
    const eventIds = JSON.parse(String(row.related_event_ids_json || "[]")) as string[];
    const deltaReport = params.action === "confirm_threat" ? 1 : 0;
    const deltaFp = params.action === "false_positive" ? 1 : 0;

    for (const eid of eventIds.slice(0, 8)) {
      const ev = (await db
        .prepare("SELECT event_type, metadata_json FROM gsi_events WHERE event_id = ?")
        .get(eid)) as { event_type: string; metadata_json: string } | undefined;
      if (!ev) continue;
      const meta = JSON.parse(ev.metadata_json || "{}") as Record<string, any>;
      if (ev.event_type === "call_event" && meta.callerHash) {
        await upsertThreatIntelIndicator({
          userId: ownerId,
          indicatorType: "phone_hash",
          indicatorHash: String(meta.callerHash),
          indicatorDisplay: String(meta.callerMasked || "Caller"),
          suggestedLabel: deltaFp ? "Trusted" : "High Risk",
          evidenceSummary: deltaFp ? "User marked incident as false positive" : "User confirmed suspicious threat",
          source: "user_feedback",
          deltaReport,
          deltaFalsePositive: deltaFp,
        });
      }
      if ((ev.event_type === "link_event" || ev.event_type === "sms_event") && meta.domain) {
        await upsertThreatIntelIndicator({
          userId: ownerId,
          indicatorType: "domain",
          indicatorHash: sha256(`domain:${String(meta.domain)}`),
          indicatorDisplay: String(meta.domain),
          suggestedLabel: deltaFp ? "Unknown" : "High Risk",
          evidenceSummary: deltaFp ? "Marked false positive by family" : "Confirmed suspicious domain by family",
          source: "user_feedback",
          deltaReport,
          deltaFalsePositive: deltaFp,
        });
      }
      if (ev.event_type === "sms_event" && Array.isArray(meta.embeddedLinks)) {
        for (const l of meta.embeddedLinks as LinkAnalysisResult[]) {
          if (l.domain) {
            await upsertThreatIntelIndicator({
              userId: ownerId,
              indicatorType: "domain",
              indicatorHash: sha256(`domain:${l.domain}`),
              indicatorDisplay: l.domain,
              suggestedLabel: deltaFp ? "Unknown" : "High Risk",
              evidenceSummary: deltaFp ? "Marked false positive by family" : "Confirmed phishing domain in SMS",
              source: "user_feedback",
              deltaReport,
              deltaFalsePositive: deltaFp,
            });
          }
        }
      }
    }
  }

  await writeAudit(ownerId, `GSI feedback '${params.action}' on ${params.incidentId}`);
  const updated = (await db
    .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
    .get(params.incidentId)) as Record<string, unknown>;
  return mapIncidentRow(updated, 0);
}

/* ---- Automated Periodic Security Reports (Daily / Weekly / Monthly) ---- */
export async function buildPeriodicReport(
  familyOwnerId: string,
  periodType: "daily" | "weekly" | "monthly"
): Promise<GsiPeriodicReport> {
  const now = Date.now();
  const spanMs =
    periodType === "daily"
      ? 86_400_000
      : periodType === "weekly"
        ? 7 * 86_400_000
        : 30 * 86_400_000;
  const start = now - spanMs;
  const prevStart = start - spanMs;

  const d = new Date(now);
  const periodKey =
    periodType === "daily"
      ? d.toISOString().slice(0, 10)
      : periodType === "weekly"
        ? `${d.getUTCFullYear()}-W${String(Math.ceil((d.getUTCDate() + 6) / 7)).padStart(2, "0")}`
        : d.toISOString().slice(0, 7);

  const evRows = (await db
    .prepare(
      "SELECT event_type FROM gsi_events WHERE family_owner_id = ? AND event_timestamp >= ?"
    )
    .all(familyOwnerId, start)) as { event_type: string }[];

  const moduleBreakdown = {
    calls: evRows.filter((r) => r.event_type === "call_event").length,
    sms: evRows.filter((r) => r.event_type === "sms_event").length,
    links: evRows.filter((r) => r.event_type === "link_event").length,
    qr: evRows.filter((r) => r.event_type === "qr_event").length,
    payments: evRows.filter((r) => r.event_type === "payment_event").length,
  };

  const incRows = (await db
    .prepare(
      "SELECT severity, resolution_status FROM gsi_incidents WHERE family_owner_id = ? AND created_at >= ?"
    )
    .all(familyOwnerId, start)) as { severity: GsiSeverity; resolution_status: string }[];

  const prevRow = (await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM gsi_incidents WHERE family_owner_id = ? AND created_at >= ? AND created_at < ?"
    )
    .get(familyOwnerId, prevStart, start)) as { cnt: number };

  const incidentCounts = {
    total: incRows.length,
    low: incRows.filter((r) => r.severity === "LOW").length,
    moderate: incRows.filter((r) => r.severity === "MODERATE").length,
    high: incRows.filter((r) => r.severity === "HIGH").length,
    critical: incRows.filter((r) => r.severity === "CRITICAL").length,
    resolved: incRows.filter((r) => r.resolution_status === "resolved").length,
    falsePositives: incRows.filter((r) => r.resolution_status === "false_positive").length,
    confirmedThreats: incRows.filter((r) => r.resolution_status === "confirmed_threat").length,
  };

  const prevTotal = Number(prevRow?.cnt || 0);
  const trendDelta = incidentCounts.total - prevTotal;

  const intelRows = (await db
    .prepare(
      `SELECT indicator_display, indicator_type, reputation_label, report_count
       FROM gsi_threat_intel
       WHERE user_id = ? AND reputation_label IN ('Suspicious', 'High Risk', 'Verified Spam')
       ORDER BY updated_at DESC LIMIT 5`
    )
    .all(familyOwnerId)) as {
    indicator_display: string;
    indicator_type: string;
    reputation_label: string;
    report_count: number;
  }[];

  const recommendations: string[] = [];
  if (incidentCounts.critical + incidentCounts.high > 0) {
    recommendations.push(
      `Review ${incidentCounts.high + incidentCounts.critical} High/Critical event(s) together and confirm safe-word callback habits.`
    );
  }
  if (moduleBreakdown.links > 0) {
    recommendations.push("Remind family members never to tap shortened or banking KYC links inside SMS.");
  }
  if (incidentCounts.falsePositives > 0) {
    recommendations.push("False-positive feedback is actively recalibrating local indicator confidence.");
  }
  if (recommendations.length === 0) {
    recommendations.push("No high-risk spikes in this window. Keep Call Watch and Guardian Alerts active.");
  }

  const summaryText = `${periodType.toUpperCase()} (${periodKey}): ${evRows.length} event(s) analyzed across Calls (${moduleBreakdown.calls}), SMS (${moduleBreakdown.sms}), Links (${moduleBreakdown.links}), QR (${moduleBreakdown.qr}), Payments (${moduleBreakdown.payments}). Incidents: ${incidentCounts.critical} Critical, ${incidentCounts.high} High, ${incidentCounts.moderate} Moderate, ${incidentCounts.low} Low.`;

  const reportPayload = {
    familyOwnerId,
    periodType,
    periodKey,
    totalEvents: evRows.length,
    moduleBreakdown,
    incidentCounts,
    previousPeriodTotalIncidents: prevTotal,
    trendDelta,
    recurringIndicators: intelRows.map((x) => ({
      display: x.indicator_display,
      type: x.indicator_type,
      label: x.reputation_label,
      count: Math.max(1, Number(x.report_count || 0)),
    })),
    recommendations,
    summaryText,
  };

  const fingerprint = sha256(JSON.stringify(reportPayload));
  const existing = (await db
    .prepare(
      "SELECT id, summary_json, created_at FROM gsi_reports WHERE family_owner_id = ? AND period_type = ? AND period_key = ? ORDER BY created_at DESC LIMIT 1"
    )
    .get(familyOwnerId, periodType, periodKey)) as
    | { id: string; summary_json: string; created_at: number }
    | undefined;

  if (existing) {
    const existingFp = (await db
      .prepare("SELECT fingerprint_hash FROM gsi_reports WHERE id = ?")
      .get(existing.id)) as { fingerprint_hash: string } | undefined;
    if (existingFp?.fingerprint_hash === fingerprint) {
      return JSON.parse(existing.summary_json) as GsiPeriodicReport;
    }
  }

  const report: GsiPeriodicReport = {
    id: generateId("grp"),
    generatedAt: now,
    ...reportPayload,
  };
  await db.prepare(
    `INSERT INTO gsi_reports (id, family_owner_id, period_type, period_key, fingerprint_hash, summary_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(report.id, familyOwnerId, periodType, periodKey, fingerprint, JSON.stringify(report), now);

  return report;
}

/* ---- Capability & Monitoring Health ---- */
export async function getCapabilityHealth(userId: string): Promise<GsiCapabilityHealth> {
  const now = Date.now();
  await ensureDefaultConsent(userId);
  const consent = (await db
    .prepare("SELECT text_analysis, guardian_alerts, call_timing, paused FROM consents WHERE user_id = ?")
    .get(userId)) as { text_analysis: number; guardian_alerts: number; call_timing: number; paused: number };
  const cw = (await db
    .prepare("SELECT monitoring_state, permission_call_state, permission_sms_state, permission_notif_state FROM call_watcher_settings WHERE user_id = ?")
    .get(userId)) as
    | {
        monitoring_state: string;
        permission_call_state: string;
        permission_sms_state: string;
        permission_notif_state: string;
      }
    | undefined;
  const guardians = await getActiveGuardiansForParent(userId);
  const aiConfigured = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY");
  const androidConnected =
    cw?.permission_call_state === "granted" &&
    (cw?.permission_sms_state === "granted" || cw?.permission_notif_state === "granted");

  const paused = Boolean(consent?.paused);
  const items: GsiCapabilityHealth["items"] = [
    {
      capability: "Central Risk & Correlation Engine",
      status: paused ? "paused" : "active",
      detail: paused ? "Monitoring paused by owner" : `Active (${GSI_RULE_VERSION})`,
    },
    {
      capability: "Gemini AI Explanation Service",
      status: aiConfigured ? "active" : "degraded",
      detail: aiConfigured ? "Live Gemini explanation ready" : "Using deterministic rule explanations (API key unset)",
    },
    {
      capability: "Guardian Alert Routing",
      status: paused ? "paused" : consent?.guardian_alerts && guardians.length > 0 ? "active" : "degraded",
      detail:
        guardians.length === 0
          ? "No active guardian linked"
          : consent?.guardian_alerts
            ? `${guardians.length} active guardian(s) subscribed`
            : "Guardian alerts disabled in Privacy",
    },
    {
      capability: "Android Call Screening & SMS Bridge",
      status: androidConnected ? "active" : "unavailable_in_browser",
      detail: androidConnected
        ? "Android Companion bridge reporting OS permissions"
        : "Browser mode uses user-assisted inputs & timing watch; OS call/SMS hooks require Android Companion",
    },
  ];

  return {
    overallStatus: paused ? "paused" : guardians.length === 0 || !aiConfigured ? "degraded" : "healthy",
    runtimeMode: androidConnected ? "android_companion_connected" : "web_assisted",
    items,
    lastCheckedAt: now,
  };
}

export async function getGsiDashboardState(userId: string): Promise<GsiDashboardState> {
  const now = Date.now();
  const incRows = (await db
    .prepare("SELECT * FROM gsi_incidents WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 25")
    .all(userId)) as Record<string, unknown>[];

  const intelRows = (await db
    .prepare("SELECT * FROM gsi_threat_intel WHERE user_id = ? ORDER BY updated_at DESC LIMIT 20")
    .all(userId)) as Record<string, unknown>[];

  const evCnt = (await db
    .prepare("SELECT COUNT(*) as cnt FROM gsi_events WHERE family_owner_id = ? AND event_timestamp >= ?")
    .get(userId, now - 86_400_000)) as { cnt: number };

  const [capabilities, daily, weekly, monthly] = await Promise.all([
    getCapabilityHealth(userId),
    buildPeriodicReport(userId, "daily"),
    buildPeriodicReport(userId, "weekly"),
    buildPeriodicReport(userId, "monthly"),
  ]);

  const incidents = incRows.map((r) => mapIncidentRow(r, 0));
  const activeRedAlerts = incidents.filter(
    (i) => i.resolutionStatus === "open" && (i.alertLevel === "RED" || i.alertLevel === "CRITICAL_RED")
  );
  return {
    ruleVersion: GSI_RULE_VERSION,
    capabilities,
    recentIncidents: incidents,
    activeRedAlerts,
    threatIntel: intelRows.map((x) => ({
      id: String(x.id),
      indicatorType: String(x.indicator_type) as GsiThreatIntelItem["indicatorType"],
      indicatorDisplay: String(x.indicator_display),
      reputationLabel: String(x.reputation_label) as CallerReputationClass,
      confidence: Number(x.confidence),
      reportCount: Number(x.report_count),
      falsePositiveCount: Number(x.false_positive_count),
      evidenceSummary: String(x.evidence_summary),
      source: String(x.source),
      ruleVersion: String(x.rule_version),
      updatedAt: Number(x.updated_at),
    })),
    latestReports: { daily, weekly, monthly },
    metrics: {
      events24h: Number(evCnt?.cnt || 0),
      openHighCritical: incidents.filter(
        (i) => i.resolutionStatus === "open" && (i.severity === "HIGH" || i.severity === "CRITICAL")
      ).length,
      openRedAlerts: activeRedAlerts.length,
      falsePositiveCount: incidents.filter((i) => i.resolutionStatus === "false_positive").length,
      confirmedThreatCount: incidents.filter((i) => i.resolutionStatus === "confirmed_threat").length,
    },
  };
}

export async function getGuardianSharedGsiOverview(
  permittedParents: { id: string; name: string }[]
): Promise<{
  incidents: GsiIncidentRecord[];
  activeRedAlerts: GsiIncidentRecord[];
  reports: { parentId: string; parentName: string; weekly: GsiPeriodicReport; capabilities: GsiCapabilityHealth }[];
}> {
  if (!permittedParents.length) return { incidents: [], activeRedAlerts: [], reports: [] };
  const nameMap = new Map(permittedParents.map((p) => [p.id, p.name]));
  const ids = permittedParents.map((p) => p.id);

  const incRows = (await db
    .prepare(
      `SELECT g.* FROM gsi_incidents g
       JOIN consents c ON c.user_id = g.family_owner_id
       WHERE g.family_owner_id IN (${ids.map(() => "?").join(",")})
         AND c.guardian_alerts = 1 AND c.paused = 0
       ORDER BY g.created_at DESC LIMIT 25`
    )
    .all(...ids)) as Record<string, unknown>[];

  const reports = await Promise.all(
    permittedParents.map(async (p) => ({
      parentId: p.id,
      parentName: p.name,
      weekly: await buildPeriodicReport(p.id, "weekly"),
      capabilities: await getCapabilityHealth(p.id),
    }))
  );

  const incidents = incRows.map((r) => mapIncidentRow(r, 0, nameMap.get(String(r.family_owner_id))));
  const activeRedAlerts = incidents.filter(
    (i) => i.resolutionStatus === "open" && (i.alertLevel === "RED" || i.alertLevel === "CRITICAL_RED")
  );

  return {
    incidents,
    activeRedAlerts,
    reports,
  };
}

export async function cleanupGsiRetention(userId: string, retentionDays: number): Promise<void> {
  const cutoff = Date.now() - Math.max(1, retentionDays) * 86_400_000;
  await db.prepare("DELETE FROM gsi_events WHERE family_owner_id = ? AND created_at < ?").run(userId, cutoff);
  await db.prepare("DELETE FROM gsi_incidents WHERE family_owner_id = ? AND created_at < ?").run(userId, cutoff);
  await db.prepare("DELETE FROM gsi_reports WHERE family_owner_id = ? AND created_at < ?").run(userId, cutoff);
}
