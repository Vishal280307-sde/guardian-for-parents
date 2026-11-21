import { db } from "./db.ts";
import {
  createNotification,
  ensureDefaultConsent,
  generateId,
  getActiveGuardiansForParent,
  sanitizeAuditText,
  sha256,
  writeAudit,
} from "./security.ts";

export type GcihEntityType =
  | "phone_number"
  | "upi_id"
  | "url"
  | "domain"
  | "sms_sender"
  | "email"
  | "bank_id"
  | "merchant"
  | "qr_fingerprint";

export type GcihRiskClassification =
  | "Safe"
  | "Low"
  | "Moderate"
  | "High"
  | "Critical"
  | "Inconclusive";

export type GcihVerificationStatus =
  | "Unknown"
  | "Unverified"
  | "Suspicious"
  | "High risk"
  | "Confirmed malicious"
  | "Verified legitimate"
  | "Disputed"
  | "Under review";

export type GcihSectionKey =
  | "call_scam"
  | "sms_scam"
  | "qr_scam"
  | "link_scam"
  | "payment_safety";

export type GcihIncidentWorkflowStatus =
  | "New"
  | "Investigating"
  | "Acknowledged"
  | "Resolved"
  | "False positive"
  | "Reopened";

export type GcihDomainEventType =
  | "CALL_DETECTED"
  | "SUSPICIOUS_CALL_IDENTIFIED"
  | "SMS_RECEIVED"
  | "SUSPICIOUS_SMS_IDENTIFIED"
  | "PHONE_NUMBER_EXTRACTED"
  | "QR_CODE_SCANNED"
  | "QR_DESTINATION_IDENTIFIED"
  | "SUSPICIOUS_UPI_IDENTIFIED"
  | "URL_EXTRACTED"
  | "MALICIOUS_URL_IDENTIFIED"
  | "PAYMENT_RISK_IDENTIFIED"
  | "ENTITY_STATUS_UPDATED"
  | "USER_FEEDBACK_RECEIVED"
  | "INCIDENT_CREATED"
  | "INCIDENT_UPDATED";

export type GcihSyncStatus =
  | "Locally detected"
  | "Pending synchronisation"
  | "Successfully synchronised"
  | "Synchronisation failed"
  | "Permission unavailable";

export interface GcihEntityRecord {
  id: string;
  familyOwnerId: string;
  entityType: GcihEntityType;
  normalizedHash: string;
  normalizedKey: string;
  maskedDisplay: string;
  riskClassification: GcihRiskClassification;
  verificationStatus: GcihVerificationStatus;
  confidence: number;
  reportCount: number;
  fpCount: number;
  sourceModules: string[];
  sourceDeviceIds: string[];
  relatedEventIds: string[];
  relatedIncidentIds: string[];
  evidenceRefs: string[];
  version: number;
  firstDetectedAt: number;
  lastDetectedAt: number;
  updatedAt: number;
}

export interface GcihRelationshipRecord {
  id: string;
  familyOwnerId: string;
  firstEntityId: string;
  secondEntityId: string;
  firstEntityLabel?: string;
  secondEntityLabel?: string;
  relationshipType: string;
  supportingEventIds: string[];
  sourceModules: string[];
  confidence: number;
  evidence: string;
  status: "active" | "disputed" | "corrected";
  correctionNote: string | null;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface GcihDomainEventRecord {
  id: string;
  familyOwnerId: string;
  sourceDeviceId: string;
  sourceModule: string;
  eventType: GcihDomainEventType;
  entityRefs: string[];
  evidenceRefs: string[];
  gsiEventId: string | null;
  incidentId: string | null;
  schemaVersion: number;
  syncStatus: GcihSyncStatus;
  eventTimestamp: number;
  processedAt: number;
}

export interface GcihDevicePermissions {
  callMonitoring: "granted" | "denied" | "unavailable_in_browser" | "permission_revoked";
  smsMonitoring: "granted" | "denied" | "unavailable_in_browser" | "permission_revoked";
  qrCamera: "granted" | "denied" | "prompt" | "unavailable_in_browser";
  notifications: "granted" | "denied" | "default";
  sharedEntityIndicators: boolean;
  sharedRiskClassifications: boolean;
  relatedEventSummaries: boolean;
  incidentNotifications: boolean;
  detailedEvidence: boolean;
}

export interface GcihDeviceRecord {
  id: string;
  userId: string;
  familyOwnerId: string;
  deviceLabel: string;
  platform: string;
  role: "parent" | "guardian";
  status: "active" | "revoked";
  permissions: GcihDevicePermissions;
  lastSyncCursor: number;
  lastSeenAt: number;
  createdAt: number;
  revokedAt: number | null;
}

export interface SharedIntelligenceItem {
  entityId: string;
  entityType: GcihEntityType;
  maskedDisplay: string;
  riskClassification: GcihRiskClassification;
  verificationStatus: GcihVerificationStatus;
  confidence: number;
  sourceModule: string;
  sourceModules: string[];
  sourceDeviceId: string;
  discoveryTimestamp: number;
  familyMemberAttribution: string;
  reasonForSharing: string;
  evidenceRefs: string[];
  relatedEventIds: string[];
  relatedIncidentIds: string[];
}

export interface ExtractedEntityCandidate {
  entityType: GcihEntityType;
  rawValue: string;
  normalizedKey: string;
  normalizedHash: string;
  maskedDisplay: string;
}

export interface GcihFamilySyncPayload {
  familyOwnerId: string;
  familyOwnerName: string;
  serverTimestamp: number;
  syncStatus: GcihSyncStatus;
  entities: GcihEntityRecord[];
  relationships: GcihRelationshipRecord[];
  domainEvents: GcihDomainEventRecord[];
  devices: GcihDeviceRecord[];
  sectionFeeds: Record<GcihSectionKey, SharedIntelligenceItem[]>;
}

const RISK_RANK: Record<GcihRiskClassification, number> = {
  Inconclusive: 0,
  Safe: 1,
  Low: 2,
  Moderate: 3,
  High: 4,
  Critical: 5,
};

const MODULE_SECTION_MAP: Record<string, GcihSectionKey | "family_feedback"> = {
  module_a_call_timer: "call_scam",
  module_a_call_watcher: "call_scam",
  module_a_call_screening: "call_scam",
  module_a_android_bridge: "call_scam",
  test_mod_a: "call_scam",
  test_mod_a_mod: "call_scam",
  test_mod_e: "call_scam",
  test_mod_e_benign: "call_scam",
  sra_test_1: "call_scam",
  sra_test_2: "call_scam",
  sra_test_3: "call_scam",
  sra_test_9: "call_scam",
  call_scam: "call_scam",
  module_b_scam_check: "sms_scam",
  module_b_sms_watcher: "sms_scam",
  module_b_android_bridge: "sms_scam",
  sra_test_4: "sms_scam",
  sra_test_5: "sms_scam",
  sra_test_7: "sms_scam",
  sra_test_8: "sms_scam",
  sms_scam: "sms_scam",
  module_c_link_intel: "link_scam",
  module_c_manual_link_check: "link_scam",
  sra_test_6: "link_scam",
  sra_test_10: "link_scam",
  link_scam: "link_scam",
  module_d_qr_intelligence: "qr_scam",
  module_f_qr_intelligence: "qr_scam",
  qr_scam: "qr_scam",
  module_d_payment_safety: "payment_safety",
  payment_safety: "payment_safety",
  user_feedback: "family_feedback",
};

export function getSectionForModule(mod: string): GcihSectionKey | "family_feedback" | string {
  const m = String(mod || "").trim();
  if (MODULE_SECTION_MAP[m]) return MODULE_SECTION_MAP[m];
  if (m.includes("call") || m.startsWith("module_a")) return "call_scam";
  if (m.includes("sms") || m.startsWith("module_b")) return "sms_scam";
  if (m.includes("qr") || m.startsWith("module_f")) return "qr_scam";
  if (m.includes("link") || m.startsWith("module_c")) return "link_scam";
  if (m.includes("pay") || m.startsWith("module_d")) return "payment_safety";
  return m;
}

export function normalizeEntityValue(
  entityType: GcihEntityType,
  rawValue: string
): ExtractedEntityCandidate | null {
  const trimmed = String(rawValue || "").trim();
  if (!trimmed) return null;

  if (entityType === "phone_number") {
    const digits = trimmed.replace(/\D/g, "");
    if (digits.length < 7) return null;
    const canonicalDigits = digits.length >= 10 ? digits.slice(-10) : digits;
    const normalizedKey = digits.length === 10 ? `+91${canonicalDigits}` : `+${digits}`;
    const maskedDisplay =
      canonicalDigits.length > 4
        ? `******${canonicalDigits.slice(-4)}`
        : `***${canonicalDigits}`;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey,
      normalizedHash: sha256(`phone_number:${canonicalDigits}`),
      maskedDisplay,
    };
  }

  if (entityType === "upi_id") {
    const cleaned = trimmed.toLowerCase().replace(/\s+/g, "");
    if (!/^[a-z0-9._-]{2,64}@[a-z0-9._-]{2,32}$/i.test(cleaned)) return null;
    const [handle, psp] = cleaned.split("@");
    const maskedHandle =
      handle.length > 4 ? `${handle.slice(0, 2)}***${handle.slice(-2)}` : `${handle[0] || "*"}***`;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: cleaned,
      normalizedHash: sha256(`upi_id:${cleaned}`),
      maskedDisplay: `${maskedHandle}@${psp}`,
    };
  }

  if (entityType === "url") {
    let candidate = trimmed;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
      candidate = `https://${candidate}`;
    }
    try {
      const parsed = new URL(candidate);
      const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
      // Strip common tracking params for canonical dedup while preserving core path/query
      const cleanParams = new URLSearchParams();
      parsed.searchParams.forEach((v, k) => {
        if (!/^utm_|^fbclid$|^gclid$|^ref$/i.test(k)) {
          cleanParams.append(k, v);
        }
      });
      const qs = cleanParams.toString();
      const canonical = `${parsed.protocol.toLowerCase()}//${host}${parsed.pathname.replace(/\/+$/, "") || "/"}${qs ? `?${qs}` : ""}`;
      const display = `${host}${parsed.pathname.length > 24 ? `${parsed.pathname.slice(0, 24)}…` : parsed.pathname}`;
      return {
        entityType,
        rawValue: trimmed,
        normalizedKey: canonical.slice(0, 300),
        normalizedHash: sha256(`url:${canonical}`),
        maskedDisplay: display.slice(0, 80),
      };
    } catch {
      return null;
    }
  }

  if (entityType === "domain") {
    const clean = trimmed
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split(":")[0]
      .replace(/\.$/, "");
    if (!clean || clean.length < 3 || !clean.includes(".")) return null;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: clean.slice(0, 120),
      normalizedHash: sha256(`domain:${clean}`),
      maskedDisplay: clean.slice(0, 80),
    };
  }

  if (entityType === "email") {
    const clean = trimmed.toLowerCase();
    const parts = clean.split("@");
    if (parts.length !== 2 || !parts[0] || !parts[1].includes(".")) return null;
    const masked = `${parts[0][0]}***@${parts[1]}`;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: clean.slice(0, 120),
      normalizedHash: sha256(`email:${clean}`),
      maskedDisplay: masked.slice(0, 80),
    };
  }

  if (entityType === "sms_sender") {
    const clean = trimmed.toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 32);
    if (clean.length < 2) return null;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: clean,
      normalizedHash: sha256(`sms_sender:${clean}`),
      maskedDisplay: clean,
    };
  }

  if (entityType === "bank_id") {
    const clean = trimmed.toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (clean.length < 4) return null;
    const masked = clean.length > 4 ? `****${clean.slice(-4)}` : clean;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: sha256(`bank_id:${clean}`),
      normalizedHash: sha256(`bank_id:${clean}`),
      maskedDisplay: masked,
    };
  }

  if (entityType === "merchant") {
    const clean = trimmed.replace(/\s+/g, " ").trim().toLowerCase().slice(0, 100);
    if (clean.length < 2) return null;
    return {
      entityType,
      rawValue: trimmed,
      normalizedKey: clean,
      normalizedHash: sha256(`merchant:${clean}`),
      maskedDisplay: trimmed.replace(/\s+/g, " ").trim().slice(0, 60),
    };
  }

  // qr_fingerprint
  const clean = trimmed.toLowerCase().slice(0, 128);
  return {
    entityType: "qr_fingerprint",
    rawValue: trimmed,
    normalizedKey: clean,
    normalizedHash: sha256(`qr_fingerprint:${clean}`),
    maskedDisplay: `QR-${clean.slice(0, 10)}`,
  };
}

export function extractEntitiesFromText(
  text: string,
  senderLabel?: string | null
): ExtractedEntityCandidate[] {
  const raw = String(text || "");
  const out = new Map<string, ExtractedEntityCandidate>();
  const add = (c: ExtractedEntityCandidate | null) => {
    if (!c) return;
    out.set(`${c.entityType}:${c.normalizedHash}`, c);
  };

  if (senderLabel) {
    const digitsOnly = senderLabel.replace(/\D/g, "");
    if (digitsOnly.length >= 7) {
      add(normalizeEntityValue("phone_number", senderLabel));
    } else {
      add(normalizeEntityValue("sms_sender", senderLabel));
    }
  }

  // URLs + domains
  const urlMatches =
    raw.match(/\bhttps?:\/\/[^\s<>"'`)\]}]+|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|rebrand\.ly|wa\.me)\/[^\s<>"'`)\]}]+/gi) ||
    [];
  for (const u of urlMatches.slice(0, 6)) {
    const cleanU = u.replace(/[.,;!?]+$/, "");
    const urlCand = normalizeEntityValue("url", cleanU);
    if (urlCand) {
      add(urlCand);
      try {
        const parsed = new URL(urlCand.normalizedKey);
        add(normalizeEntityValue("domain", parsed.hostname));
      } catch {
        // ignore
      }
    }
  }

  // Email vs UPI IDs
  const atMatches = raw.match(/\b[a-zA-Z0-9._-]{2,64}@[a-zA-Z0-9._-]{2,64}\b/g) || [];
  for (const m of atMatches.slice(0, 6)) {
    const lower = m.toLowerCase();
    const afterAt = lower.split("@")[1] || "";
    if (afterAt.includes(".")) {
      add(normalizeEntityValue("email", lower));
    } else {
      add(normalizeEntityValue("upi_id", lower));
    }
  }

  // Phone numbers (excluding tiny numbers or plain OTPs of 4-6 digits)
  const phoneMatches = raw.match(/(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)?\d{5,10}\b/g) || [];
  for (const p of phoneMatches.slice(0, 8)) {
    const digits = p.replace(/\D/g, "");
    // Indian mobile/helpline numbers are typically 10-12 digits; ignore years/amounts/4-6 digit OTPs
    if (digits.length >= 10 && digits.length <= 13) {
      add(normalizeEntityValue("phone_number", p));
    }
  }

  // Bank account / IFSC identifiers
  const ifscMatches = raw.match(/\b[A-Z]{4}0[A-Z0-9]{6}\b/g) || [];
  for (const ifsc of ifscMatches.slice(0, 3)) {
    add(normalizeEntityValue("bank_id", ifsc));
  }
  const acctMatches = raw.match(/(?:a\/c|acct|account)\s*(?:no\.?|number)?\s*[:#-]?\s*[x*X\d]{4,16}/gi) || [];
  for (const acc of acctMatches.slice(0, 3)) {
    const lastDigits = acc.replace(/[^0-9]/g, "");
    if (lastDigits.length >= 4) {
      add(normalizeEntityValue("bank_id", lastDigits));
    }
  }

  return Array.from(out.values());
}

export function extractEntitiesFromQrPayload(params: {
  rawPayload?: string;
  upiId?: string | null;
  payeeName?: string | null;
  merchantName?: string | null;
  urlString?: string | null;
  urlHost?: string | null;
  payloadHash?: string | null;
}): ExtractedEntityCandidate[] {
  const out = new Map<string, ExtractedEntityCandidate>();
  const add = (c: ExtractedEntityCandidate | null) => {
    if (!c) return;
    out.set(`${c.entityType}:${c.normalizedHash}`, c);
  };

  if (params.upiId) add(normalizeEntityValue("upi_id", params.upiId));
  if (params.merchantName) add(normalizeEntityValue("merchant", params.merchantName));
  else if (params.payeeName) add(normalizeEntityValue("merchant", params.payeeName));

  if (params.urlString) {
    const urlCand = normalizeEntityValue("url", params.urlString);
    add(urlCand);
    if (urlCand) {
      try {
        add(normalizeEntityValue("domain", new URL(urlCand.normalizedKey).hostname));
      } catch {
        // ignore
      }
    }
  }
  if (params.urlHost) {
    add(normalizeEntityValue("domain", params.urlHost));
  }
  if (params.payloadHash) {
    add(normalizeEntityValue("qr_fingerprint", params.payloadHash));
  } else if (params.rawPayload) {
    add(normalizeEntityValue("qr_fingerprint", sha256(params.rawPayload.trim())));
  }

  return Array.from(out.values());
}

export function extractEntitiesFromPayment(params: {
  beneficiary?: string | null;
  signals?: string[];
}): ExtractedEntityCandidate[] {
  const out = new Map<string, ExtractedEntityCandidate>();
  const add = (c: ExtractedEntityCandidate | null) => {
    if (!c) return;
    out.set(`${c.entityType}:${c.normalizedHash}`, c);
  };

  if (params.beneficiary) {
    const ben = params.beneficiary.trim();
    if (ben.includes("@")) {
      const after = ben.split("@")[1] || "";
      add(normalizeEntityValue(after.includes(".") ? "email" : "upi_id", ben));
    } else if (ben.replace(/\D/g, "").length >= 10) {
      add(normalizeEntityValue("phone_number", ben));
    } else if (ben && ben.toLowerCase() !== "unknown") {
      add(normalizeEntityValue("merchant", ben));
    }
  }
  for (const s of params.signals || []) {
    for (const c of extractEntitiesFromText(s)) {
      add(c);
    }
  }
  return Array.from(out.values());
}

function mapEntityRow(row: Record<string, unknown>): GcihEntityRecord {
  return {
    id: String(row.id),
    familyOwnerId: String(row.family_owner_id),
    entityType: String(row.entity_type) as GcihEntityType,
    normalizedHash: String(row.normalized_hash),
    normalizedKey: String(row.normalized_key),
    maskedDisplay: String(row.masked_display),
    riskClassification: String(row.risk_classification) as GcihRiskClassification,
    verificationStatus: String(row.verification_status) as GcihVerificationStatus,
    confidence: Number(row.confidence || 0.5),
    reportCount: Number(row.report_count || 0),
    fpCount: Number(row.fp_count || 0),
    sourceModules: JSON.parse(String(row.source_modules_json || "[]")),
    sourceDeviceIds: JSON.parse(String(row.source_device_ids_json || "[]")),
    relatedEventIds: JSON.parse(String(row.related_event_ids_json || "[]")),
    relatedIncidentIds: JSON.parse(String(row.related_incident_ids_json || "[]")),
    evidenceRefs: JSON.parse(String(row.evidence_refs_json || "[]")),
    version: Number(row.version || 1),
    firstDetectedAt: Number(row.first_detected_at),
    lastDetectedAt: Number(row.last_detected_at),
    updatedAt: Number(row.updated_at),
  };
}

export function severityToGcihRisk(score: number): GcihRiskClassification {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Moderate";
  if (score >= 10) return "Low";
  return "Safe";
}

function initialVerificationStatus(
  risk: GcihRiskClassification,
  sourceModulesCount: number
): GcihVerificationStatus {
  // Single-source signal NEVER automatically marks Confirmed malicious
  if (risk === "Critical" || risk === "High") {
    return sourceModulesCount >= 2 ? "High risk" : "Suspicious";
  }
  if (risk === "Moderate") return "Suspicious";
  if (risk === "Low" || risk === "Safe") return "Unverified";
  return "Unknown";
}

export async function upsertSharedEntity(params: {
  familyOwnerId: string;
  candidate: ExtractedEntityCandidate;
  sourceModule: string;
  sourceDeviceId?: string;
  eventId?: string;
  incidentId?: string;
  riskClassification: GcihRiskClassification;
  confidence: number;
  evidenceRef?: string;
  timestamp?: number;
}): Promise<GcihEntityRecord> {
  const now = params.timestamp || Date.now();
  const deviceId = (params.sourceDeviceId || "web_session").slice(0, 60);
  const existing = (await db
    .prepare(
      "SELECT * FROM gcih_entities WHERE family_owner_id = ? AND entity_type = ? AND normalized_hash = ?"
    )
    .get(params.familyOwnerId, params.candidate.entityType, params.candidate.normalizedHash)) as
    | Record<string, unknown>
    | undefined;

  const evRef = params.evidenceRef ? sanitizeAuditText(params.evidenceRef).slice(0, 180) : null;

  if (!existing) {
    const id = generateId("ent");
    const modules = [params.sourceModule];
    const devices = [deviceId];
    const eventIds = params.eventId ? [params.eventId] : [];
    const incidentIds = params.incidentId ? [params.incidentId] : [];
    const evidences = evRef ? [evRef] : [];
    const verStatus = initialVerificationStatus(params.riskClassification, modules.length);
    const boundedConf = Math.max(0.15, Math.min(0.9, params.confidence));

    await db
      .prepare(
        `INSERT INTO gcih_entities (
           id, family_owner_id, entity_type, normalized_hash, normalized_key, masked_display,
           risk_classification, verification_status, confidence, report_count, fp_count,
           source_modules_json, source_device_ids_json, related_event_ids_json,
           related_incident_ids_json, evidence_refs_json, version,
           first_detected_at, last_detected_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`
      )
      .run(
        id,
        params.familyOwnerId,
        params.candidate.entityType,
        params.candidate.normalizedHash,
        params.candidate.normalizedKey,
        params.candidate.maskedDisplay,
        params.riskClassification,
        verStatus,
        Math.round(boundedConf * 100) / 100,
        params.riskClassification === "High" || params.riskClassification === "Critical" ? 1 : 0,
        0,
        JSON.stringify(modules),
        JSON.stringify(devices),
        JSON.stringify(eventIds),
        JSON.stringify(incidentIds),
        JSON.stringify(evidences),
        now,
        now,
        now
      );

    const row = (await db.prepare("SELECT * FROM gcih_entities WHERE id = ?").get(id)) as Record<string, unknown>;
    return mapEntityRow(row);
  }

  const prev = mapEntityRow(existing);
  const nextModules = Array.from(new Set([...prev.sourceModules, params.sourceModule])).slice(0, 16);
  const nextDevices = Array.from(new Set([...prev.sourceDeviceIds, deviceId])).slice(0, 16);
  const nextEventIds = params.eventId
    ? Array.from(new Set([params.eventId, ...prev.relatedEventIds])).slice(0, 30)
    : prev.relatedEventIds;
  const nextIncidentIds = params.incidentId
    ? Array.from(new Set([params.incidentId, ...prev.relatedIncidentIds])).slice(0, 20)
    : prev.relatedIncidentIds;
  const nextEvidence = evRef
    ? Array.from(new Set([evRef, ...prev.evidenceRefs])).slice(0, 16)
    : prev.evidenceRefs;

  let nextRisk = prev.riskClassification;
  let nextVer = prev.verificationStatus;
  let nextConf = prev.confidence;

  // Safeguard: low-confidence/automated update MUST NOT overwrite Verified legitimate
  if (prev.verificationStatus === "Verified legitimate") {
    if (params.confidence >= 0.85 && (params.riskClassification === "High" || params.riskClassification === "Critical")) {
      nextVer = "Disputed";
      nextConf = Math.min(0.7, prev.confidence);
    }
  } else {
    if (RISK_RANK[params.riskClassification] > RISK_RANK[prev.riskClassification]) {
      nextRisk = params.riskClassification;
    }
    if (nextVer === "Unknown" || nextVer === "Unverified") {
      if (nextRisk === "High" || nextRisk === "Critical") {
        nextVer = nextModules.length >= 2 ? "High risk" : "Suspicious";
      } else if (nextRisk === "Moderate") {
        nextVer = "Suspicious";
      }
    } else if (nextVer === "Suspicious" && (nextRisk === "High" || nextRisk === "Critical") && nextModules.length >= 2) {
      nextVer = "High risk";
    }
    nextConf = Math.max(prev.confidence, Math.min(0.95, params.confidence + (nextModules.length > 1 ? 0.08 : 0)));
  }

  await db
    .prepare(
      `UPDATE gcih_entities SET
         risk_classification = ?, verification_status = ?, confidence = ?,
         source_modules_json = ?, source_device_ids_json = ?,
         related_event_ids_json = ?, related_incident_ids_json = ?,
         evidence_refs_json = ?, version = version + 1,
         last_detected_at = MAX(last_detected_at, ?), updated_at = ?
       WHERE id = ?`
    )
    .run(
      nextRisk,
      nextVer,
      Math.round(nextConf * 100) / 100,
      JSON.stringify(nextModules),
      JSON.stringify(nextDevices),
      JSON.stringify(nextEventIds),
      JSON.stringify(nextIncidentIds),
      JSON.stringify(nextEvidence),
      now,
      now,
      prev.id
    );

  const refreshed = (await db.prepare("SELECT * FROM gcih_entities WHERE id = ?").get(prev.id)) as Record<
    string,
    unknown
  >;
  return mapEntityRow(refreshed);
}

export async function attachIncidentToEntities(
  entityIds: string[],
  incidentId: string
): Promise<void> {
  const now = Date.now();
  for (const id of entityIds) {
    const row = (await db
      .prepare("SELECT related_incident_ids_json FROM gcih_entities WHERE id = ?")
      .get(id)) as { related_incident_ids_json: string } | undefined;
    if (!row) continue;
    const prev = JSON.parse(row.related_incident_ids_json || "[]") as string[];
    if (!prev.includes(incidentId)) {
      const next = [incidentId, ...prev].slice(0, 20);
      await db
        .prepare("UPDATE gcih_entities SET related_incident_ids_json = ?, version = version + 1, updated_at = ? WHERE id = ?")
        .run(JSON.stringify(next), now, id);
    }
  }
}

export async function publishDomainEvent(params: {
  familyOwnerId: string;
  sourceDeviceId?: string;
  sourceModule: string;
  eventType: GcihDomainEventType;
  entityIds: string[];
  evidenceRefs?: string[];
  gsiEventId?: string | null;
  incidentId?: string | null;
  consentContext?: Record<string, unknown>;
  dedupSeed: string;
  eventTimestamp?: number;
  syncStatus?: GcihSyncStatus;
}): Promise<{ id: string; deduplicated: boolean }> {
  const now = Date.now();
  const ts = params.eventTimestamp || now;
  const dedupHash = sha256(`${params.familyOwnerId}|${params.eventType}|${params.dedupSeed}`);
  const existing = (await db
    .prepare("SELECT id FROM gcih_domain_events WHERE family_owner_id = ? AND dedup_hash = ?")
    .get(params.familyOwnerId, dedupHash)) as { id: string } | undefined;

  if (existing) {
    return { id: existing.id, deduplicated: true };
  }

  const id = generateId("gde");
  await db
    .prepare(
      `INSERT INTO gcih_domain_events (
         id, family_owner_id, source_device_id, source_module, event_type,
         entity_refs_json, evidence_refs_json, gsi_event_id, incident_id,
         consent_context_json, schema_version, dedup_hash, sync_status,
         event_timestamp, processed_at, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      params.familyOwnerId,
      (params.sourceDeviceId || "web_session").slice(0, 60),
      params.sourceModule.slice(0, 60),
      params.eventType,
      JSON.stringify(Array.from(new Set(params.entityIds)).slice(0, 20)),
      JSON.stringify((params.evidenceRefs || []).slice(0, 12).map((s) => sanitizeAuditText(s).slice(0, 160))),
      params.gsiEventId || null,
      params.incidentId || null,
      JSON.stringify(params.consentContext || {}),
      dedupHash,
      params.syncStatus || "Successfully synchronised",
      ts,
      now,
      now
    );

  return { id, deduplicated: false };
}

export async function linkCoOccurringEntities(params: {
  familyOwnerId: string;
  entities: GcihEntityRecord[];
  eventId?: string;
  sourceModule: string;
  evidence: string;
  relationshipType?: string;
  confidence?: number;
}): Promise<GcihRelationshipRecord[]> {
  if (params.entities.length < 2) return [];
  const now = Date.now();
  const out: GcihRelationshipRecord[] = [];
  const capped = params.entities.slice(0, 6);

  for (let i = 0; i < capped.length; i++) {
    for (let j = i + 1; j < capped.length; j++) {
      const a = capped[i];
      const b = capped[j];
      const [first, second] = a.id < b.id ? [a, b] : [b, a];
      const relType =
        params.relationshipType ||
        `${first.entityType}_co_occurred_${second.entityType}`;

      const existing = (await db
        .prepare(
          `SELECT * FROM gcih_relationships
           WHERE family_owner_id = ? AND first_entity_id = ? AND second_entity_id = ? AND relationship_type = ?`
        )
        .get(params.familyOwnerId, first.id, second.id, relType)) as Record<string, unknown> | undefined;

      if (!existing) {
        const id = generateId("rel");
        const evIds = params.eventId ? [params.eventId] : [];
        const mods = [params.sourceModule];
        await db
          .prepare(
            `INSERT INTO gcih_relationships (
               id, family_owner_id, first_entity_id, second_entity_id, relationship_type,
               supporting_event_ids_json, source_modules_json, confidence, evidence,
               status, version, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)`
          )
          .run(
            id,
            params.familyOwnerId,
            first.id,
            second.id,
            relType,
            JSON.stringify(evIds),
            JSON.stringify(mods),
            params.confidence ?? 0.72,
            sanitizeAuditText(params.evidence).slice(0, 200),
            now,
            now
          );
        const inserted = (await db.prepare("SELECT * FROM gcih_relationships WHERE id = ?").get(id)) as Record<
          string,
          unknown
        >;
        out.push(await mapRelationshipRow(inserted));
      } else {
        const prevEvents = JSON.parse(String(existing.supporting_event_ids_json || "[]")) as string[];
        const nextEvents = params.eventId
          ? Array.from(new Set([params.eventId, ...prevEvents])).slice(0, 20)
          : prevEvents;
        const prevMods = JSON.parse(String(existing.source_modules_json || "[]")) as string[];
        const nextMods = Array.from(new Set([...prevMods, params.sourceModule])).slice(0, 12);
        const nextConf = Math.min(0.95, Math.max(Number(existing.confidence || 0.6), params.confidence ?? 0.72));
        await db
          .prepare(
            `UPDATE gcih_relationships SET
               supporting_event_ids_json = ?, source_modules_json = ?, confidence = ?,
               version = version + 1, updated_at = ?
             WHERE id = ?`
          )
          .run(JSON.stringify(nextEvents), JSON.stringify(nextMods), nextConf, now, String(existing.id));
        const updated = (await db
          .prepare("SELECT * FROM gcih_relationships WHERE id = ?")
          .get(String(existing.id))) as Record<string, unknown>;
        out.push(await mapRelationshipRow(updated));
      }
    }
  }
  return out;
}

async function mapRelationshipRow(row: Record<string, unknown>): Promise<GcihRelationshipRecord> {
  const firstId = String(row.first_entity_id);
  const secondId = String(row.second_entity_id);
  const firstEnt = (await db
    .prepare("SELECT entity_type, masked_display FROM gcih_entities WHERE id = ?")
    .get(firstId)) as { entity_type: string; masked_display: string } | undefined;
  const secondEnt = (await db
    .prepare("SELECT entity_type, masked_display FROM gcih_entities WHERE id = ?")
    .get(secondId)) as { entity_type: string; masked_display: string } | undefined;
  return {
    id: String(row.id),
    familyOwnerId: String(row.family_owner_id),
    firstEntityId: firstId,
    secondEntityId: secondId,
    firstEntityLabel: firstEnt ? `${firstEnt.entity_type}: ${firstEnt.masked_display}` : firstId,
    secondEntityLabel: secondEnt ? `${secondEnt.entity_type}: ${secondEnt.masked_display}` : secondId,
    relationshipType: String(row.relationship_type),
    supportingEventIds: JSON.parse(String(row.supporting_event_ids_json || "[]")),
    sourceModules: JSON.parse(String(row.source_modules_json || "[]")),
    confidence: Number(row.confidence || 0.6),
    evidence: String(row.evidence || ""),
    status: String(row.status || "active") as "active" | "disputed" | "corrected",
    correctionNote: row.correction_note ? String(row.correction_note) : null,
    version: Number(row.version || 1),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  };
}

export async function lookupSharedEntitiesForQuery(params: {
  familyOwnerId: string;
  candidates: ExtractedEntityCandidate[];
  currentSection?: GcihSectionKey;
}): Promise<SharedIntelligenceItem[]> {
  if (!params.candidates.length) return [];
  const userRow = (await db
    .prepare("SELECT name FROM users WHERE id = ?")
    .get(params.familyOwnerId)) as { name: string } | undefined;
  const ownerName = userRow?.name || "Family Member";
  const results: SharedIntelligenceItem[] = [];
  const seen = new Set<string>();

  for (const c of params.candidates) {
    const row = (await db
      .prepare(
        `SELECT * FROM gcih_entities
         WHERE family_owner_id = ? AND entity_type = ? AND normalized_hash = ?`
      )
      .get(params.familyOwnerId, c.entityType, c.normalizedHash)) as Record<string, unknown> | undefined;
    if (!row) continue;
    const ent = mapEntityRow(row);
    if (seen.has(ent.id)) continue;
    seen.add(ent.id);

    const originMod = ent.sourceModules[0] || "gcih";
    results.push({
      entityId: ent.id,
      entityType: ent.entityType,
      maskedDisplay: ent.maskedDisplay,
      riskClassification: ent.riskClassification,
      verificationStatus: ent.verificationStatus,
      confidence: ent.confidence,
      sourceModule: originMod,
      sourceModules: ent.sourceModules,
      sourceDeviceId: ent.sourceDeviceIds[0] || "web_session",
      discoveryTimestamp: ent.firstDetectedAt,
      familyMemberAttribution: `${ownerName} (${ent.sourceDeviceIds[0] || "web_session"})`,
      reasonForSharing: buildSharingReason(ent, params.currentSection),
      evidenceRefs: ent.evidenceRefs,
      relatedEventIds: ent.relatedEventIds,
      relatedIncidentIds: ent.relatedIncidentIds,
    });
  }
  return results;
}

function buildSharingReason(ent: GcihEntityRecord, targetSection?: GcihSectionKey): string {
  const fromMods = ent.sourceModules.join(", ");
  if (ent.verificationStatus === "Verified legitimate") {
    return `Verified legitimate by family feedback (${fromMods})`;
  }
  if (targetSection === "call_scam" && ent.entityType === "phone_number") {
    return `Phone number previously extracted & flagged in ${fromMods}`;
  }
  if (targetSection === "payment_safety" && (ent.entityType === "upi_id" || ent.entityType === "merchant" || ent.entityType === "qr_fingerprint")) {
    return `Payment identifier observed in ${fromMods}`;
  }
  if (targetSection === "link_scam" && (ent.entityType === "url" || ent.entityType === "domain")) {
    return `URL/domain extracted from ${fromMods} for cross-module check`;
  }
  if (targetSection === "qr_scam") {
    return `QR payment/link indicator cross-referenced with ${fromMods}`;
  }
  return `Shared across sections (${fromMods}) via Guardian Central Intelligence Hub`;
}

export async function getSharedIntelligenceForSection(
  familyOwnerId: string,
  section: GcihSectionKey
): Promise<SharedIntelligenceItem[]> {
  const typesForSection: Record<GcihSectionKey, GcihEntityType[]> = {
    call_scam: ["phone_number", "sms_sender"],
    sms_scam: ["phone_number", "sms_sender", "url", "domain", "upi_id", "email", "bank_id"],
    qr_scam: ["upi_id", "url", "domain", "merchant", "qr_fingerprint"],
    link_scam: ["url", "domain"],
    payment_safety: ["upi_id", "merchant", "bank_id", "phone_number", "qr_fingerprint"],
  };

  const allowedTypes = typesForSection[section];
  const userRow = (await db
    .prepare("SELECT name FROM users WHERE id = ?")
    .get(familyOwnerId)) as { name: string } | undefined;
  const ownerName = userRow?.name || "Family Member";

  const rows = (await db
    .prepare(
      `SELECT * FROM gcih_entities
       WHERE family_owner_id = ?
         AND entity_type IN (${allowedTypes.map(() => "?").join(",")})
       ORDER BY updated_at DESC LIMIT 30`
    )
    .all(familyOwnerId, ...allowedTypes)) as Record<string, unknown>[];

  const items: SharedIntelligenceItem[] = [];
  for (const r of rows) {
    const ent = mapEntityRow(r);
    const originatedHereOnly =
      ent.sourceModules.length === 1 && MODULE_SECTION_MAP[ent.sourceModules[0]] === section;
    const isElevated =
      ent.riskClassification === "Moderate" ||
      ent.riskClassification === "High" ||
      ent.riskClassification === "Critical" ||
      ent.verificationStatus === "Verified legitimate" ||
      ent.verificationStatus === "Disputed" ||
      !originatedHereOnly;

    if (!isElevated) continue;

    items.push({
      entityId: ent.id,
      entityType: ent.entityType,
      maskedDisplay: ent.maskedDisplay,
      riskClassification: ent.riskClassification,
      verificationStatus: ent.verificationStatus,
      confidence: ent.confidence,
      sourceModule: ent.sourceModules[0] || "gcih",
      sourceModules: ent.sourceModules,
      sourceDeviceId: ent.sourceDeviceIds[0] || "web_session",
      discoveryTimestamp: ent.firstDetectedAt,
      familyMemberAttribution: `${ownerName} (${ent.sourceDeviceIds[0] || "web_session"})`,
      reasonForSharing: buildSharingReason(ent, section),
      evidenceRefs: ent.evidenceRefs,
      relatedEventIds: ent.relatedEventIds,
      relatedIncidentIds: ent.relatedIncidentIds,
    });
  }
  return items.slice(0, 15);
}

/* ---- Family Device Registry & Granular Permissions ---- */
const DEFAULT_DEVICE_PERMISSIONS: GcihDevicePermissions = {
  callMonitoring: "unavailable_in_browser",
  smsMonitoring: "unavailable_in_browser",
  qrCamera: "prompt",
  notifications: "default",
  sharedEntityIndicators: true,
  sharedRiskClassifications: true,
  relatedEventSummaries: true,
  incidentNotifications: true,
  detailedEvidence: false,
};

function mapDeviceRow(row: Record<string, unknown>): GcihDeviceRecord {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    familyOwnerId: String(row.family_owner_id),
    deviceLabel: String(row.device_label),
    platform: String(row.platform || "web"),
    role: String(row.role) as "parent" | "guardian",
    status: String(row.status) as "active" | "revoked",
    permissions: {
      ...DEFAULT_DEVICE_PERMISSIONS,
      ...(JSON.parse(String(row.permissions_json || "{}")) as Partial<GcihDevicePermissions>),
    },
    lastSyncCursor: Number(row.last_sync_cursor || 0),
    lastSeenAt: Number(row.last_seen_at),
    createdAt: Number(row.created_at),
    revokedAt: row.revoked_at ? Number(row.revoked_at) : null,
  };
}

export async function registerFamilyDevice(params: {
  deviceId?: string;
  userId: string;
  familyOwnerId: string;
  deviceLabel: string;
  platform?: string;
  role: "parent" | "guardian";
  permissions?: Partial<GcihDevicePermissions>;
}): Promise<GcihDeviceRecord> {
  const now = Date.now();
  const id = (params.deviceId || generateId("dev")).slice(0, 60);
  const existing = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(id)) as
    | Record<string, unknown>
    | undefined;

  const perms: GcihDevicePermissions = {
    ...DEFAULT_DEVICE_PERMISSIONS,
    ...(params.permissions || {}),
  };

  if (!existing) {
    await db
      .prepare(
        `INSERT INTO gcih_devices (
           id, user_id, family_owner_id, device_label, platform, role, status,
           permissions_json, last_sync_cursor, last_seen_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, 0, ?, ?)`
      )
      .run(
        id,
        params.userId,
        params.familyOwnerId,
        sanitizeAuditText(params.deviceLabel).slice(0, 60) || "Guardian Web Session",
        (params.platform || "web").slice(0, 24),
        params.role,
        JSON.stringify(perms),
        now,
        now
      );
  } else {
    if (String(existing.user_id) !== params.userId) {
      throw new Error("Device identifier belongs to another account.");
    }
    const prevPerms = JSON.parse(String(existing.permissions_json || "{}")) as Partial<GcihDevicePermissions>;
    const mergedPerms = { ...DEFAULT_DEVICE_PERMISSIONS, ...prevPerms, ...(params.permissions || {}) };
    await db
      .prepare(
        `UPDATE gcih_devices SET
           family_owner_id = ?, device_label = ?, platform = ?, status = 'active',
           revoked_at = NULL, permissions_json = ?, last_seen_at = ?
         WHERE id = ?`
      )
      .run(
        params.familyOwnerId,
        sanitizeAuditText(params.deviceLabel).slice(0, 60) || String(existing.device_label),
        (params.platform || String(existing.platform)).slice(0, 24),
        JSON.stringify(mergedPerms),
        now,
        id
      );
  }

  await writeAudit(params.userId, `Registered family intelligence device (${id})`);
  const row = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(id)) as Record<string, unknown>;
  return mapDeviceRow(row);
}

export async function updateDevicePermissions(params: {
  actorId: string;
  actorRole: "parent" | "guardian";
  deviceId: string;
  permissions: Partial<GcihDevicePermissions>;
}): Promise<GcihDeviceRecord> {
  const row = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(params.deviceId)) as
    | Record<string, unknown>
    | undefined;
  if (!row) throw new Error("Device not found.");

  const ownerId = String(row.family_owner_id);
  const devUserId = String(row.user_id);
  if (devUserId !== params.actorId && ownerId !== params.actorId) {
    throw new Error("Unauthorized device permission update.");
  }

  const prev = JSON.parse(String(row.permissions_json || "{}")) as Partial<GcihDevicePermissions>;
  const next: GcihDevicePermissions = {
    ...DEFAULT_DEVICE_PERMISSIONS,
    ...prev,
    ...params.permissions,
  };
  const now = Date.now();
  await db
    .prepare("UPDATE gcih_devices SET permissions_json = ?, last_seen_at = ? WHERE id = ?")
    .run(JSON.stringify(next), now, params.deviceId);

  // If Android call/SMS permissions were revoked on monitored parent device, reflect truthfully in call_watcher_settings too
  if (devUserId === ownerId && params.actorRole === "parent") {
    const hasCall = await db.prepare("SELECT user_id FROM call_watcher_settings WHERE user_id = ?").get(ownerId);
    if (hasCall) {
      if (params.permissions.callMonitoring === "permission_revoked" || params.permissions.callMonitoring === "denied") {
        await db
          .prepare("UPDATE call_watcher_settings SET permission_call_state = 'denied', updated_at = ? WHERE user_id = ?")
          .run(now, ownerId);
      }
      if (params.permissions.smsMonitoring === "permission_revoked" || params.permissions.smsMonitoring === "denied") {
        await db
          .prepare("UPDATE call_watcher_settings SET permission_sms_state = 'denied', updated_at = ? WHERE user_id = ?")
          .run(now, ownerId);
      }
    }
  }

  await writeAudit(params.actorId, `Updated permissions for device ${params.deviceId}`);
  const updated = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(params.deviceId)) as Record<
    string,
    unknown
  >;
  return mapDeviceRow(updated);
}

export async function revokeFamilyDevice(params: {
  actorId: string;
  deviceId: string;
}): Promise<GcihDeviceRecord> {
  const row = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(params.deviceId)) as
    | Record<string, unknown>
    | undefined;
  if (!row) throw new Error("Device not found.");
  if (String(row.user_id) !== params.actorId && String(row.family_owner_id) !== params.actorId) {
    throw new Error("Unauthorized: cannot revoke this device.");
  }
  const now = Date.now();
  await db
    .prepare("UPDATE gcih_devices SET status = 'revoked', revoked_at = ? WHERE id = ?")
    .run(now, params.deviceId);
  await writeAudit(params.actorId, `Revoked family device ${params.deviceId}`);
  const updated = (await db.prepare("SELECT * FROM gcih_devices WHERE id = ?").get(params.deviceId)) as Record<
    string,
    unknown
  >;
  return mapDeviceRow(updated);
}

/* ---- Feedback, False-Positive Handling & Relationship Corrections ---- */
export async function submitEntityFeedback(params: {
  actorId: string;
  actorRole: "parent" | "guardian";
  entityId: string;
  feedbackType: "suspicious" | "legitimate" | "false_positive" | "request_review" | "incorrect_association";
  eventId?: string;
  incidentId?: string;
  note?: string;
}): Promise<{ entity: GcihEntityRecord; domainEventId: string }> {
  const row = (await db.prepare("SELECT * FROM gcih_entities WHERE id = ?").get(params.entityId)) as
    | Record<string, unknown>
    | undefined;
  if (!row) throw new Error("Entity not found.");

  const prev = mapEntityRow(row);
  if (params.actorRole === "parent" && prev.familyOwnerId !== params.actorId) {
    throw new Error("Unauthorized access to entity.");
  }
  if (params.actorRole === "guardian") {
    const linked = await db
      .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
      .get(prev.familyOwnerId, params.actorId);
    if (!linked) throw new Error("Unauthorized: not an active linked guardian for this family.");
  }

  const now = Date.now();
  const cleanNote = params.note ? sanitizeAuditText(params.note).slice(0, 200) : null;
  await db
    .prepare(
      `INSERT INTO gcih_entity_feedback (
         id, family_owner_id, actor_id, actor_role, entity_id, event_id, incident_id, feedback_type, note, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      generateId("efb"),
      prev.familyOwnerId,
      params.actorId,
      params.actorRole,
      prev.id,
      params.eventId || null,
      params.incidentId || null,
      params.feedbackType,
      cleanNote,
      now
    );

  let nextRisk = prev.riskClassification;
  let nextVer = prev.verificationStatus;
  let nextConf = prev.confidence;
  let nextReports = prev.reportCount;
  let nextFps = prev.fpCount;
  const nextEvidence = [...prev.evidenceRefs];

  // Important safeguard: marking a single SMS/entity legitimate or false positive does NOT blindly whitelist all sender messages
  if (params.feedbackType === "legitimate" || params.feedbackType === "false_positive") {
    nextFps += 1;
    nextRisk = "Safe";
    nextVer = "Verified legitimate";
    nextConf = 0.88;
    nextEvidence.unshift(
      `Marked ${params.feedbackType.replace("_", " ")} by ${params.actorRole}${cleanNote ? `: ${cleanNote}` : ""} (original evidence retained; scoped strictly to this entity)`
    );
  } else if (params.feedbackType === "suspicious") {
    nextReports += 1;
    nextRisk = nextReports >= 2 ? "High" : "Moderate";
    nextVer = nextReports >= 2 ? "High risk" : "Suspicious";
    nextConf = Math.min(0.95, Math.max(prev.confidence, 0.78));
    nextEvidence.unshift(
      `Flagged suspicious by ${params.actorRole}${cleanNote ? `: ${cleanNote}` : ""}`
    );
  } else if (params.feedbackType === "request_review" || params.feedbackType === "incorrect_association") {
    nextVer = "Under review";
    nextEvidence.unshift(
      `${params.feedbackType === "incorrect_association" ? "Association disputed" : "Review requested"} by ${params.actorRole}${cleanNote ? `: ${cleanNote}` : ""}`
    );
  }

  await db
    .prepare(
      `UPDATE gcih_entities SET
         risk_classification = ?, verification_status = ?, confidence = ?,
         report_count = ?, fp_count = ?, evidence_refs_json = ?,
         version = version + 1, updated_at = ?
       WHERE id = ?`
    )
    .run(
      nextRisk,
      nextVer,
      nextConf,
      nextReports,
      nextFps,
      JSON.stringify(Array.from(new Set(nextEvidence)).slice(0, 16)),
      now,
      prev.id
    );

  // Sync compatible reputation into gsi_threat_intel without overwriting scope across families
  const intelType =
    prev.entityType === "phone_number"
      ? "phone_hash"
      : prev.entityType === "domain"
        ? "domain"
        : prev.entityType === "url"
          ? "url_hash"
          : prev.entityType === "upi_id"
            ? "upi_id"
            : null;
  if (intelType) {
    const intelHash =
      prev.entityType === "phone_number"
        ? sha256(`${prev.familyOwnerId}:phone:${prev.normalizedKey.replace(/\D/g, "").slice(-10)}`)
        : prev.normalizedHash;
    const intelLabel =
      nextVer === "Verified legitimate"
        ? "Trusted"
        : nextVer === "High risk"
          ? "High Risk"
          : nextVer === "Suspicious"
            ? "Suspicious"
            : "Unknown";
    const existingIntel = (await db
      .prepare("SELECT id FROM gsi_threat_intel WHERE user_id = ? AND indicator_type = ? AND indicator_hash = ?")
      .get(prev.familyOwnerId, intelType, intelHash)) as { id: string } | undefined;
    if (existingIntel) {
      await db
        .prepare(
          "UPDATE gsi_threat_intel SET reputation_label = ?, false_positive_count = ?, report_count = ?, confidence = ?, updated_at = ? WHERE id = ?"
        )
        .run(intelLabel, nextFps, nextReports, nextConf, now, existingIntel.id);
    } else {
      await db
        .prepare(
          `INSERT INTO gsi_threat_intel (
             id, user_id, indicator_type, indicator_hash, indicator_display,
             reputation_label, confidence, report_count, false_positive_count,
             evidence_summary, source, rule_version, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user_feedback', 'GSI-2026.11', ?, ?)`
        )
        .run(
          generateId("gti"),
          prev.familyOwnerId,
          intelType,
          intelHash,
          prev.maskedDisplay,
          intelLabel,
          nextConf,
          nextReports,
          nextFps,
          nextEvidence[0] || "Family feedback",
          now,
          now
        );
    }
  }

  // Reassess related open incidents without destroying original forensic records
  for (const incId of prev.relatedIncidentIds.slice(0, 5)) {
    const inc = (await db.prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?").get(incId)) as
      | Record<string, unknown>
      | undefined;
    if (!inc) continue;
    if (params.feedbackType === "false_positive" || params.feedbackType === "legitimate") {
      const prevStatus = String(inc.workflow_status || "New");
      await db
        .prepare(
          `UPDATE gsi_incidents SET
             resolution_status = 'false_positive',
             workflow_status = 'False positive',
             feedback_status = 'false_positive',
             feedback_note = COALESCE(?, feedback_note),
             updated_at = ?
           WHERE incident_id = ?`
        )
        .run(cleanNote || `Entity ${prev.maskedDisplay} verified legitimate`, now, incId);
      await recordIncidentHistory({
        incidentId: incId,
        familyOwnerId: prev.familyOwnerId,
        actorId: params.actorId,
        previousStatus: prevStatus,
        nextStatus: "False positive",
        action: `entity_${params.feedbackType}`,
        summary: `Reassessed after ${prev.maskedDisplay} marked ${params.feedbackType} (original evidence preserved)`,
      });
    }
  }

  const fbEv = await publishDomainEvent({
    familyOwnerId: prev.familyOwnerId,
    sourceDeviceId: params.actorRole === "guardian" ? "guardian_device" : "monitored_device",
    sourceModule: "user_feedback",
    eventType: "USER_FEEDBACK_RECEIVED",
    entityIds: [prev.id],
    evidenceRefs: [nextEvidence[0] || `Feedback: ${params.feedbackType}`],
    incidentId: params.incidentId || null,
    dedupSeed: `fb:${prev.id}:${params.actorId}:${params.feedbackType}:${Math.floor(now / 2000)}`,
    eventTimestamp: now,
  });

  await publishDomainEvent({
    familyOwnerId: prev.familyOwnerId,
    sourceDeviceId: params.actorRole === "guardian" ? "guardian_device" : "monitored_device",
    sourceModule: "user_feedback",
    eventType: "ENTITY_STATUS_UPDATED",
    entityIds: [prev.id],
    evidenceRefs: [`${prev.maskedDisplay} -> ${nextVer} (${nextRisk})`],
    dedupSeed: `entupd:${prev.id}:${nextVer}:${Math.floor(now / 1000)}`,
    eventTimestamp: now,
  });

  // Notify family members of status update (silent family sync notification for guardians/monitored owner)
  const targetRecipient = params.actorRole === "guardian" ? prev.familyOwnerId : null;
  if (targetRecipient) {
    await createNotification(
      targetRecipient,
      prev.familyOwnerId,
      "gcih_family_sync",
      "Family intelligence updated",
      `Guardian marked ${prev.entityType.replace("_", " ")} (${prev.maskedDisplay}) as ${nextVer}.`
    );
  } else {
    const guardians = await getActiveGuardiansForParent(prev.familyOwnerId);
    for (const g of guardians) {
      await createNotification(
        g.guardian_id,
        prev.familyOwnerId,
        "gcih_family_sync",
        "Family feedback synced",
        `${prev.maskedDisplay} updated to ${nextVer}.`
      );
    }
  }

  await writeAudit(prev.familyOwnerId, `GCIH entity feedback '${params.feedbackType}' on ${prev.id}`);
  const refreshed = (await db.prepare("SELECT * FROM gcih_entities WHERE id = ?").get(prev.id)) as Record<
    string,
    unknown
  >;
  return { entity: mapEntityRow(refreshed), domainEventId: fbEv.id };
}

export async function correctRelationship(params: {
  actorId: string;
  actorRole: "parent" | "guardian";
  relationshipId: string;
  action: "dispute" | "correct" | "restore";
  note?: string;
}): Promise<GcihRelationshipRecord> {
  const row = (await db
    .prepare("SELECT * FROM gcih_relationships WHERE id = ?")
    .get(params.relationshipId)) as Record<string, unknown> | undefined;
  if (!row) throw new Error("Relationship not found.");
  const ownerId = String(row.family_owner_id);
  if (params.actorRole === "parent" && ownerId !== params.actorId) {
    throw new Error("Unauthorized access to relationship.");
  }
  if (params.actorRole === "guardian") {
    const linked = await db
      .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
      .get(ownerId, params.actorId);
    if (!linked) throw new Error("Unauthorized: not an active linked guardian.");
  }
  const nextStatus =
    params.action === "dispute" ? "disputed" : params.action === "correct" ? "corrected" : "active";
  const now = Date.now();
  const cleanNote = params.note ? sanitizeAuditText(params.note).slice(0, 180) : null;
  await db
    .prepare(
      "UPDATE gcih_relationships SET status = ?, correction_note = COALESCE(?, correction_note), version = version + 1, updated_at = ? WHERE id = ?"
    )
    .run(nextStatus, cleanNote, now, params.relationshipId);

  await writeAudit(ownerId, `GCIH relationship ${params.relationshipId} marked ${nextStatus}`);
  const updated = (await db
    .prepare("SELECT * FROM gcih_relationships WHERE id = ?")
    .get(params.relationshipId)) as Record<string, unknown>;
  return mapRelationshipRow(updated);
}

export async function recordIncidentHistory(params: {
  incidentId: string;
  familyOwnerId: string;
  actorId: string;
  previousStatus: string | null;
  nextStatus: string;
  action: string;
  summary: string;
}): Promise<void> {
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO gcih_incident_history (
         id, incident_id, family_owner_id, actor_id, previous_status, next_status, action, summary, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      generateId("inh"),
      params.incidentId,
      params.familyOwnerId,
      params.actorId,
      params.previousStatus,
      params.nextStatus,
      params.action,
      sanitizeAuditText(params.summary).slice(0, 220),
      now
    );

  // Append compact timeline entry to incident
  const incRow = (await db
    .prepare("SELECT timeline_json FROM gsi_incidents WHERE incident_id = ?")
    .get(params.incidentId)) as { timeline_json?: string } | undefined;
  if (incRow) {
    const tl = JSON.parse(String(incRow.timeline_json || "[]")) as Record<string, unknown>[];
    tl.unshift({
      at: now,
      action: params.action,
      status: params.nextStatus,
      summary: sanitizeAuditText(params.summary).slice(0, 160),
    });
    await db
      .prepare("UPDATE gsi_incidents SET timeline_json = ?, updated_at = ? WHERE incident_id = ?")
      .run(JSON.stringify(tl.slice(0, 25)), now, params.incidentId);
  }
}

export async function updateIncidentWorkflow(params: {
  actorId: string;
  actorRole: "parent" | "guardian";
  incidentId: string;
  workflowStatus: GcihIncidentWorkflowStatus;
  note?: string;
}): Promise<Record<string, unknown>> {
  const row = (await db
    .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
    .get(params.incidentId)) as Record<string, unknown> | undefined;
  if (!row) throw new Error("Incident not found.");
  const ownerId = String(row.family_owner_id);
  if (params.actorRole === "parent" && ownerId !== params.actorId) {
    throw new Error("Unauthorized access to incident.");
  }
  if (params.actorRole === "guardian") {
    const linked = await db
      .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
      .get(ownerId, params.actorId);
    if (!linked) throw new Error("Unauthorized: not an active linked guardian.");
  }

  const prevStatus = String(row.workflow_status || "New");
  const now = Date.now();
  const cleanNote = params.note ? sanitizeAuditText(params.note).slice(0, 200) : null;

  let ackStatus = String(row.acknowledgement_status || "unacknowledged");
  let resStatus = String(row.resolution_status || "open");
  if (params.workflowStatus === "Acknowledged" || params.workflowStatus === "Investigating") {
    ackStatus = "acknowledged";
    if (resStatus !== "open") resStatus = "open";
  } else if (params.workflowStatus === "Resolved") {
    ackStatus = "acknowledged";
    resStatus = "resolved";
  } else if (params.workflowStatus === "False positive") {
    ackStatus = "acknowledged";
    resStatus = "false_positive";
  } else if (params.workflowStatus === "Reopened") {
    resStatus = "open";
  }

  await db
    .prepare(
      `UPDATE gsi_incidents SET
         workflow_status = ?, acknowledgement_status = ?, resolution_status = ?,
         feedback_note = COALESCE(?, feedback_note), updated_at = ?
       WHERE incident_id = ?`
    )
    .run(params.workflowStatus, ackStatus, resStatus, cleanNote, now, params.incidentId);

  await recordIncidentHistory({
    incidentId: params.incidentId,
    familyOwnerId: ownerId,
    actorId: params.actorId,
    previousStatus: prevStatus,
    nextStatus: params.workflowStatus,
    action: "workflow_transition",
    summary: cleanNote || `Status changed from ${prevStatus} to ${params.workflowStatus}`,
  });

  await publishDomainEvent({
    familyOwnerId: ownerId,
    sourceDeviceId: params.actorRole === "guardian" ? "guardian_device" : "monitored_device",
    sourceModule: "user_feedback",
    eventType: "INCIDENT_UPDATED",
    entityIds: JSON.parse(String(row.involved_entity_ids_json || "[]")),
    evidenceRefs: [`Incident ${params.incidentId}: ${prevStatus} -> ${params.workflowStatus}`],
    incidentId: params.incidentId,
    dedupSeed: `inc_wf:${params.incidentId}:${params.workflowStatus}:${Math.floor(now / 1000)}`,
    eventTimestamp: now,
  });

  await writeAudit(ownerId, `Incident ${params.incidentId} workflow -> ${params.workflowStatus}`);
  return (await db
    .prepare("SELECT * FROM gsi_incidents WHERE incident_id = ?")
    .get(params.incidentId)) as Record<string, unknown>;
}

/* ---- Family-Wide Synchronisation Delta Builder ---- */
export async function buildFamilySyncPayload(params: {
  familyOwnerId: string;
  since?: number;
  devicePermissions?: Partial<GcihDevicePermissions>;
}): Promise<GcihFamilySyncPayload> {
  const since = Math.max(0, Number(params.since || 0));
  const now = Date.now();
  const userRow = (await db
    .prepare("SELECT name FROM users WHERE id = ?")
    .get(params.familyOwnerId)) as { name: string } | undefined;
  const familyOwnerName = userRow?.name || "Family Member";

  const showEntities = params.devicePermissions?.sharedEntityIndicators !== false;
  const showEvidence = Boolean(params.devicePermissions?.detailedEvidence);
  const showEvents = params.devicePermissions?.relatedEventSummaries !== false;

  const entityRows = showEntities
    ? ((await db
        .prepare(
          `SELECT * FROM gcih_entities
           WHERE family_owner_id = ? AND updated_at > ?
           ORDER BY updated_at DESC LIMIT 60`
        )
        .all(params.familyOwnerId, since)) as Record<string, unknown>[])
    : [];

  const entities = entityRows.map((r) => {
    const e = mapEntityRow(r);
    if (!showEvidence) {
      e.evidenceRefs = e.evidenceRefs.slice(0, 2);
    }
    return e;
  });

  const relRows = showEntities
    ? ((await db
        .prepare(
          `SELECT * FROM gcih_relationships
           WHERE family_owner_id = ? AND updated_at > ?
           ORDER BY updated_at DESC LIMIT 40`
        )
        .all(params.familyOwnerId, since)) as Record<string, unknown>[])
    : [];

  const evRows = showEvents
    ? ((await db
        .prepare(
          `SELECT * FROM gcih_domain_events
           WHERE family_owner_id = ? AND processed_at > ?
           ORDER BY processed_at DESC LIMIT 50`
        )
        .all(params.familyOwnerId, since)) as Record<string, unknown>[])
    : [];

  const devRows = (await db
    .prepare("SELECT * FROM gcih_devices WHERE family_owner_id = ? ORDER BY last_seen_at DESC LIMIT 20")
    .all(params.familyOwnerId)) as Record<string, unknown>[];

  const [relationships, callScamFeed, smsScamFeed, qrScamFeed, linkScamFeed, paymentSafetyFeed] = await Promise.all([
    Promise.all(relRows.map(mapRelationshipRow)),
    getSharedIntelligenceForSection(params.familyOwnerId, "call_scam"),
    getSharedIntelligenceForSection(params.familyOwnerId, "sms_scam"),
    getSharedIntelligenceForSection(params.familyOwnerId, "qr_scam"),
    getSharedIntelligenceForSection(params.familyOwnerId, "link_scam"),
    getSharedIntelligenceForSection(params.familyOwnerId, "payment_safety"),
  ]);

  return {
    familyOwnerId: params.familyOwnerId,
    familyOwnerName,
    serverTimestamp: now,
    syncStatus: "Successfully synchronised",
    entities,
    relationships,
    domainEvents: evRows.map((r) => ({
      id: String(r.id),
      familyOwnerId: String(r.family_owner_id),
      sourceDeviceId: String(r.source_device_id),
      sourceModule: String(r.source_module),
      eventType: String(r.event_type) as GcihDomainEventType,
      entityRefs: JSON.parse(String(r.entity_refs_json || "[]")),
      evidenceRefs: showEvidence
        ? JSON.parse(String(r.evidence_refs_json || "[]"))
        : JSON.parse(String(r.evidence_refs_json || "[]")).slice(0, 1),
      gsiEventId: r.gsi_event_id ? String(r.gsi_event_id) : null,
      incidentId: r.incident_id ? String(r.incident_id) : null,
      schemaVersion: Number(r.schema_version || 1),
      syncStatus: String(r.sync_status || "Successfully synchronised") as GcihSyncStatus,
      eventTimestamp: Number(r.event_timestamp),
      processedAt: Number(r.processed_at),
    })),
    devices: devRows.map(mapDeviceRow),
    sectionFeeds: {
      call_scam: callScamFeed,
      sms_scam: smsScamFeed,
      qr_scam: qrScamFeed,
      link_scam: linkScamFeed,
      payment_safety: paymentSafetyFeed,
    },
  };
}

export async function deleteGcihDataForOwner(familyOwnerId: string): Promise<void> {
  await db.prepare("DELETE FROM gcih_incident_history WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM gcih_entity_feedback WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM gcih_relationships WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM gcih_domain_events WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM gcih_entities WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM gcih_devices WHERE family_owner_id = ?").run(familyOwnerId);
}

export async function ensureConsentedOwner(
  userId: string
): Promise<{ textAnalysis: boolean; guardianAlerts: boolean; paused: boolean }> {
  await ensureDefaultConsent(userId);
  const c = (await db
    .prepare("SELECT text_analysis, guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(userId)) as { text_analysis: number; guardian_alerts: number; paused: number } | undefined;
  return {
    textAnalysis: Boolean(c?.text_analysis),
    guardianAlerts: Boolean(c?.guardian_alerts),
    paused: Boolean(c?.paused),
  };
}
