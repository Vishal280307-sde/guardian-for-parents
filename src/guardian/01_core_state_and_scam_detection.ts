// Core state, translations, scam rules, AI explanation, screenshot OCR, and message analysis

import { rules, ACT, RULES, type RiskResult } from './scamEngine';
import type { ParentsAiToolKey, ParentsAiWorkspaceState } from './parentsAiClient';
import type {
  EppBankServiceType,
  EppDashboardState,
  EppDurationOption,
} from './emergencyPaymentClient';

export { rules, ACT, RULES, type RiskResult };

export interface AiExplanation {
  st: 'wait' | 'ok' | 'off';
  explanation?: string;
  recommended_actions?: string[];
  uncertainty_statement?: string;
}

export interface CallRecord {
  s: number;
  e: number;
  dur: number;
  known: boolean;
}

export interface ActiveCall {
  s: number;
  known: boolean;
  ai: AiExplanation;
  warnedLong: boolean;
}

export interface CallAlert {
  r: RiskResult;
  txt: string;
  ai: AiExplanation;
  gapMs: number;
  callDurMs: number;
  duringCall: boolean;
  at: number;
}

export interface TimingEvent {
  at: number;
  duringCall: boolean;
  gapMs: number;
  callDurMs: number;
  known: boolean;
  score: number;
}

export interface PaymentAssessment extends RiskResult {
  amt: number;
  ben: string;
  id: string | null;
  assessmentId?: string | null;
  gsiRiskScore?: number;
  sharedIntelligence?: SharedIntelligenceItem[];
}

export interface GuardianRequest {
  id: string;
  parentId?: string;
  parentName?: string;
  amt: number;
  ben: string;
  level: RiskResult['level'];
  sig: string[];
  exp: number;
  st: 'pending' | 'approved' | 'rejected' | 'verification_requested' | 'expired' | 'cancelled' | 'consumed';
  used: boolean;
  decidedBy?: string | null;
  decidedAt?: number | null;
  verifiedCallback?: boolean;
  verificationNote?: string | null;
  escalatedToSecondary?: boolean;
}

export interface GuardianLink {
  id: string;
  invite_code: string;
  status: 'pending' | 'active' | 'revoked';
  is_secondary: number;
  guardian_name?: string | null;
  guardian_username?: string | null;
}

export interface NotificationItem {
  id: string;
  kind: string;
  title: string;
  body: string;
  delivery_status: string;
  read_at: number | null;
  created_at: number;
}

export interface ScamReportItem {
  id: string;
  masked_excerpt: string;
  cat: string;
  status: 'unverified' | 'verified';
  created_at: number;
}

export interface UserAccount {
  id: string;
  username: string;
  name: string;
  role: 'parent' | 'guardian';
}

export interface QrNotificationPrefs {
  qrScanNotify: boolean;
  highRiskQrAlert: boolean;
  criticalRiskQrAlert: boolean;
  highAmountAlert: boolean;
  veryHighLoadAlert: boolean;
  repeatedQrAlert: boolean;
  merchantWarningAlert: boolean;
  suspiciousQrAlert: boolean;
}

export interface QrScanSummaryRecord {
  id: string;
  parent_id?: string;
  parent_name?: string;
  qr_format: string;
  qr_classification: string;
  upi_id: string | null;
  payee_name: string | null;
  amount: number | null;
  amount_state: string;
  security_risk_level: string;
  payment_load_category: string;
  payment_load_risk_level: string;
  created_at: number;
}

export interface QrSourcedField {
  label: string;
  value: string | null;
  displayValue: string;
  source: 'Extracted from QR' | 'Verified through an external source' | 'Inferred' | 'Unverified' | 'Unavailable';
}

export interface QrIntelligenceReport {
  scanId: string;
  scannedAt: number;
  extracted: {
    decodingStatus: 'decoded' | 'incomplete' | 'malformed' | 'unsupported';
    qrFormat: string;
    qrType: string;
    classification: string;
    supportedScheme: string;
    paymentUri: string | null;
    rawPayloadPreview: string;
    payloadLength: number;
    encodedParametersCount: number;
    missingOrInvalidFields: string[];
    upiId: string | null;
    payeeName: string | null;
    merchantName: string | null;
    amount: number | null;
    amountState: 'fixed' | 'not_encoded' | 'invalid' | 'unsupported';
    amountDisplay: string;
    amountEditability: string;
    currency: string | null;
    paymentNote: string | null;
    transactionRef: string | null;
    transactionId: string | null;
    mcc: string | null;
    expiryInfo: string | null;
    providerInferred: string | null;
    urlHost: string | null;
    urlString: string | null;
    paymentFields: QrSourcedField[];
    qrFields: QrSourcedField[];
  };
  qrLoadInfo: {
    paymentAmountDisplay: string;
    currency: string;
    paymentType: string;
    recipientName: string;
    recipientUpiId: string;
    paymentNote: string;
    amountEditability: string;
    encodedPaymentDetailsSummary: string;
    paymentStatus: string[];
    qrLoadCategory: string;
    qrLoadCategoryMessage: string;
    aiAmountExplanation: string;
  };
  merchant: {
    upiId: QrSourcedField;
    payeeName: QrSourcedField;
    merchantName: QrSourcedField;
    merchantCategory: QrSourcedField;
    paymentProvider: QrSourcedField;
    verifiedIdentity: QrSourcedField;
    reputationInfo: QrSourcedField;
    fraudReportsInfo: QrSourcedField;
    nameMismatchDetected: boolean;
    mismatchReason: string | null;
    impersonationIndicators: string[];
    externalVerification: { service: string; available: boolean; status: string; message: string };
  };
  security: {
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INCONCLUSIVE';
    riskLabel: string;
    score: number;
    findings: { severity: string; title: string; evidence: string; reasoning: string }[];
    externalFraudIntel: { service: string; available: boolean; status: string; message: string };
    summary: string;
  };
  paymentAmountAnalysis: {
    caseType: string;
    summary: string;
    editability: string;
    anomalyNote: string;
  };
  paymentLoad: {
    requestedAmount: number | null;
    amountDisplay: string;
    loadCategory: string;
    loadRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INCONCLUSIVE';
    loadRiskLabel: string;
    configuredThresholds: {
      paymentLimit: number;
      moderateMax: number;
      highMax: number;
      veryHighMin: number;
    };
    exceedsPaymentLimit: boolean | null;
    excessAmount: number | null;
    authorisedTransactionHistoryAvailable: boolean;
    historicalComparisonMessage: string;
    priorAssessmentsCount: number;
    priorScansWithAmountCount: number;
    similarPatternCount: number;
    cumulativeRecordedExposure: number;
    unusualAmountSpike: boolean;
    explanationAnswers: {
      requestedAmountText: string;
      loadCategoryText: string;
      exceedsThresholdText: string;
      historicalComparisonText: string;
      repeatedRequestsText: string;
      cumulativeExposureText: string;
      whyPayAttentionText: string;
      recommendedActionText: string;
    };
  };
  duplicateStatus: {
    payloadHash: string;
    isDuplicate: boolean;
    previousScanCount: number;
    totalScansIncludingCurrent: number;
    firstScanAt: number | null;
    mostRecentPreviousScanAt: number | null;
    previousRecipientName: string | null;
    previousUpiId: string | null;
    previousAmount: number | null;
    currentAmount: number | null;
    changesDetected: string[];
    sameMerchantDifferentQrCount: number;
    note: string;
  };
  aiReport: {
    available: boolean;
    model: string | null;
    amountExplanation: string;
    safetySummary: string;
    importantWarnings: string[];
    recommendedPrecautions: string[];
    uncertaintyStatement: string;
    errorReason?: string;
  };
  overallAssessment: {
    combinedLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INCONCLUSIVE';
    combinedLabel: string;
    securityRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INCONCLUSIVE';
    securityRiskLabel: string;
    paymentLoadRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INCONCLUSIVE';
    paymentLoadRiskLabel: string;
    summary: string;
  };
  parentNotifications: {
    consentEnabled: boolean;
    monitoringPaused: boolean;
    linkedGuardiansCount: number;
    triggeredEvents: string[];
    notificationsSentCount: number;
    suppressedReasons: string[];
    statusMessage: string;
  };
  gsiAssessment?: {
    incidentId: string;
    severity: string;
    riskScore: number;
  };
  sharedIntelligence?: SharedIntelligenceItem[];
}

export type CwRiskLevel = 'Low Risk' | 'Moderate Risk' | 'High Risk' | 'Critical Risk' | 'Inconclusive';

export interface CwSeparateRiskAssessment {
  riskLevel: CwRiskLevel;
  riskCategory: string;
  supportingEvidence: string[];
  detectedPatterns: string[];
  missingInformation: string[];
  recommendedAction: string;
  assessedAt: number;
}

export type CwProtectionStatus =
  | 'Protection active'
  | 'Protection partially active'
  | 'Permission required'
  | 'Background execution restricted'
  | 'Offline intelligence'
  | 'Protection unavailable';

export interface CallScreeningResult {
  verdict: 'allow_normal' | 'allow_caution' | 'allow_with_warning';
  callerClassification: string;
  callerMasked: string | null;
  callerHash: string | null;
  reputationClass: 'Trusted' | 'Unknown' | 'Suspicious' | 'High Risk' | 'Verified Spam';
  riskLevel: CwRiskLevel;
  confidence: number;
  evidence: string[];
  recommendations: string[];
  matchedEntityId: string | null;
  callScreeningRoleGranted: boolean;
  lookupLatencyMs: number;
  neverAutoBlocked: true;
  noAudioCollected: true;
}

export interface CwSettings {
  consentGiven: boolean;
  consentAt: number | null;
  monitoringState: 'not_activated' | 'active' | 'paused' | 'revoked';
  notifyUnknownCalls: boolean;
  permissionCallState: 'granted' | 'denied' | 'permission_required' | 'unavailable_in_browser';
  permissionSmsState: 'granted' | 'denied' | 'permission_required' | 'unavailable_in_browser';
  permissionNotifState: 'granted' | 'denied' | 'permission_required' | 'unavailable_in_browser';
  permissionCallLogState?: 'granted' | 'denied' | 'permission_required' | 'unavailable_in_browser';
  callScreeningRoleState?: 'granted' | 'denied' | 'permission_required' | 'unavailable_in_browser';
  batteryRestricted?: boolean;
  appLifecycleState?: string;
  bootRestorePending?: boolean;
  lastEventAt: number | null;
  updatedAt: number;
  effectiveStatusLabel: string;
  protectionStatus?: CwProtectionStatus;
  protectionDetail?: string;
  androidBridgeConnected: boolean;
}

export interface CwCallRecord {
  id: string;
  callerClassification: string;
  callerMasked: string | null;
  callerHash: string | null;
  callStatus: string;
  callLifecyclePhase?: string;
  incomingAt: number;
  startedAt: number | null;
  endedAt: number | null;
  durationMs: number | null;
  screeningVerdict?: string | null;
  screeningLatencyMs?: number | null;
  simInfo: string | null;
  source: string;
  createdAt: number;
}

export interface CwPaymentMessage {
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
  paymentStatus: string;
  redactedSummary: string;
  source: string;
  createdAt: number;
}

export interface CwQuestionnaire {
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

export interface CwTimelineItem {
  correlationId: string;
  parentId?: string;
  parentName?: string;
  createdAt: number;
  updatedAt: number;
  status: string;
  timeDiffMs: number | null;
  duringCall: boolean;
  detectedPatterns: string[];
  call: CwCallRecord | null;
  payment: CwPaymentMessage | null;
  callRisk: CwSeparateRiskAssessment;
  paymentRisk: CwSeparateRiskAssessment;
  aiReport: {
    available: boolean;
    model: string | null;
    summary: {
      plainExplanation: string;
      timingRelationshipNote: string;
      questionnaireInterpretation: string;
      recommendedActions: string[];
      uncertaintyStatement: string;
    };
    errorReason?: string;
  };
  questionnaire: CwQuestionnaire | null;
  questionnaireNeeded: boolean;
  questionnaireReason: string | null;
  criticalWarningActive: boolean;
  parentNotifiedCount: number;
  sharedIntelligence?: SharedIntelligenceItem[];
}

export interface CallWatcherDashboardState {
  settings: CwSettings;
  summary: {
    recentCallsCount: number;
    unknownCallsCount: number;
    paymentEventsCount: number;
    correlatedAlertsCount: number;
    criticalAlertsCount: number;
    pendingQuestionnairesCount: number;
  };
  timeline: CwTimelineItem[];
  pendingQuestionnaire: CwTimelineItem | null;
}

export interface CwOfflineQueueEntry {
  id: string;
  kind: 'call' | 'payment';
  payload: Record<string, unknown>;
  createdAt: number;
}

export type GsiSeverity = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type AlertLevel = 'GREEN' | 'YELLOW' | 'RED' | 'CRITICAL_RED';
export type NotifDeliveryStatus = 'Sent' | 'Pending' | 'Failed' | 'Not Required' | 'Suppressed';
export type GsiAlertFilter = 'all' | 'active_red' | 'critical_red' | 'yellow' | 'green' | 'resolved';

export interface LinkAnalysisResult {
  rawInput: string;
  normalizedUrl: string | null;
  domain: string | null;
  scheme: string;
  urlHash: string;
  isShortener: boolean;
  isLookalike: boolean;
  impersonatedBrand: string | null;
  ssrfBlocked: boolean;
  ssrfReason: string | null;
  riskScore: number;
  severity: GsiSeverity;
  confidence: 'low' | 'medium' | 'high';
  findings: { code: string; severity: GsiSeverity; title: string; evidence: string }[];
  redirectChain: string[];
  liveProbePerformed: boolean;
  liveProbeNote: string;
  localIntelMatch: {
    label: string;
    confidence: number;
    reportCount: number;
    falsePositiveCount: number;
  } | null;
  recommendedAction: string;
  verificationBoundary: string;
  neverAutoOpened: true;
  sharedIntelligence?: SharedIntelligenceItem[];
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
  confidence: 'low' | 'medium' | 'high';
  detectionSource: string;
  actorMasked: string | null;
  evidence: string[];
  reasoningSummary: string;
  recommendedAction: string;
  ruleVersion: string;
  aiExplanation: {
    available: boolean;
    model: string | null;
    explanation: string;
    guardianSummary: string;
    recommendedActions: string[];
    uncertaintyStatement: string;
  };
  acknowledgementStatus: 'unacknowledged' | 'acknowledged';
  resolutionStatus: 'open' | 'resolved' | 'false_positive' | 'confirmed_threat';
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
  indicatorType: 'phone_hash' | 'domain' | 'url_hash' | 'upi_id';
  indicatorDisplay: string;
  reputationLabel: 'Trusted' | 'Unknown' | 'Suspicious' | 'High Risk' | 'Verified Spam';
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
  periodType: 'daily' | 'weekly' | 'monthly';
  periodKey: string;
  generatedAt: number;
  totalEvents: number;
  moduleBreakdown: { calls: number; sms: number; links: number; qr: number; payments: number };
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
  overallStatus: 'healthy' | 'degraded' | 'paused';
  runtimeMode: 'web_assisted' | 'android_companion_connected';
  items: {
    capability: string;
    status: 'active' | 'degraded' | 'paused' | 'unavailable_in_browser';
    detail: string;
  }[];
  lastCheckedAt: number;
}

export interface GsiDashboardState {
  ruleVersion: string;
  capabilities: GsiCapabilityHealth;
  recentIncidents: GsiIncidentRecord[];
  activeRedAlerts?: GsiIncidentRecord[];
  threatIntel: GsiThreatIntelItem[];
  latestReports: {
    daily: GsiPeriodicReport | null;
    weekly: GsiPeriodicReport | null;
    monthly: GsiPeriodicReport | null;
  };
  metrics: {
    events24h: number;
    openHighCritical: number;
    openRedAlerts?: number;
    falsePositiveCount: number;
    confirmedThreatCount: number;
  };
}

export interface LinkedGsiOverview {
  incidents: GsiIncidentRecord[];
  activeRedAlerts?: GsiIncidentRecord[];
  reports: {
    parentId: string;
    parentName: string;
    weekly: GsiPeriodicReport;
    capabilities: GsiCapabilityHealth;
  }[];
}

export interface EmergencyHelpStatus {
  state: 'in_progress' | 'success' | 'failed';
  message: string;
  portalOpened: boolean;
  updatedAt: number;
}

export type GcihEntityType =
  | 'phone_number'
  | 'upi_id'
  | 'url'
  | 'domain'
  | 'sms_sender'
  | 'email'
  | 'bank_id'
  | 'merchant'
  | 'qr_fingerprint';

export type GcihRiskClassification = 'Safe' | 'Low' | 'Moderate' | 'High' | 'Critical' | 'Inconclusive';

export type GcihVerificationStatus =
  | 'Unknown'
  | 'Unverified'
  | 'Suspicious'
  | 'High risk'
  | 'Confirmed malicious'
  | 'Verified legitimate'
  | 'Disputed'
  | 'Under review';

export type GcihSectionKey = 'call_scam' | 'sms_scam' | 'qr_scam' | 'link_scam' | 'payment_safety';

export type GcihIncidentWorkflowStatus =
  | 'New'
  | 'Investigating'
  | 'Acknowledged'
  | 'Resolved'
  | 'False positive'
  | 'Reopened';

export type GcihSyncStatus =
  | 'Locally detected'
  | 'Pending synchronisation'
  | 'Successfully synchronised'
  | 'Synchronisation failed'
  | 'Permission unavailable';

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
  status: 'active' | 'disputed' | 'corrected';
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
  eventType: string;
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
  callMonitoring: 'granted' | 'denied' | 'unavailable_in_browser' | 'permission_revoked';
  smsMonitoring: 'granted' | 'denied' | 'unavailable_in_browser' | 'permission_revoked';
  qrCamera: 'granted' | 'denied' | 'prompt' | 'unavailable_in_browser';
  notifications: 'granted' | 'denied' | 'default';
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
  role: 'parent' | 'guardian';
  status: 'active' | 'revoked';
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

export interface GcihOfflineQueueEntry {
  id: string;
  clientEventId: string;
  eventType: 'call_event' | 'sms_event' | 'link_event' | 'qr_event' | 'payment_event';
  eventTimestamp: number;
  sourceModule: string;
  payload: Record<string, unknown>;
  createdAt: number;
}

export interface AppState {
  user: UserAccount | null;
  booted: boolean;
  online: boolean;
  lang: 'en' | 'hi';
  fontScale: 'normal' | 'lg' | 'xl';
  tab: string;
  mode: 'login' | 'reg' | 'recover';
  role: 'parent' | 'guardian';
  draftLoginUser: string;
  slide: number;
  tip: number;
  err: string;
  recoveryDisplay: string;
  c: {
    text: boolean;
    galerts: boolean;
    gapprove: boolean;
    paused: boolean;
    calls: boolean;
  };
  medThreshold: number;
  highThreshold: number;
  retentionDays: number;
  loadModerateMax: number;
  loadHighMax: number;
  loadVeryHighMin: number;
  redAlertCooldownSec: number;
  qrPrefs: QrNotificationPrefs;
  qrScans: QrScanSummaryRecord[];
  qrReport: QrIntelligenceReport | null;
  qrStatus: {
    state: 'idle' | 'camera_active' | 'camera_denied' | 'camera_unavailable' | 'decoding' | 'analyzing' | 'ready' | 'error';
    message?: string;
  };
  hasSafeWord: boolean;
  pats: number;
  calls: CallRecord[];
  cur: ActiveCall | null;
  alert: CallAlert | null;
  timingEvents: TimingEvent[];
  lastPayMsgAt: number;
  link: number;
  limit: number;
  reqs: GuardianRequest[];
  links: GuardianLink[];
  linkedParents: { id: string; name: string; username: string; guardian_approve: number; guardian_alerts: number; is_secondary: number }[];
  notifications: NotificationItem[];
  reports: ScamReportItem[];
  audit: { t: string; ev: string; h: string }[];
  res: { r: RiskResult; ai: AiExplanation; lastText: string } | null;
  ocrNote: string;
  ocrDraft: string;
  pay: PaymentAssessment | null;
  qr: {
    err?: string;
    d?: Record<string, string | null>;
    r?: RiskResult;
  } | null;
  chat: { r: 'u' | 'a'; x: string; live?: boolean }[];
  q: number;
  score: number;
  inc: { a: string; d: string; s: string }[];
  note: string;
  confirmAction: null | 'delete_data' | 'revoke_guardians';
  evalResult: ReturnType<typeof import('./scamEngine').evaluateScamEngine> | null;
  callWatcher: CallWatcherDashboardState | null;
  linkedCallWatcherEvents: CwTimelineItem[];
  cwSelectedId: string | null;
  cwOfflineQueue: CwOfflineQueueEntry[];
  cwScreenResult: CallScreeningResult | null;
  cwScreenNumber: string;
  cwWhyExpandedId: string | null;
  cwActiveCallId: string | null;
  gsi: GsiDashboardState | null;
  linkedGsiOverview: LinkedGsiOverview | null;
  linkAnalysis: LinkAnalysisResult | null;
  gsiReportPeriod: 'daily' | 'weekly' | 'monthly';
  gsiAlertFilter: GsiAlertFilter;
  emergencyStatus: EmergencyHelpStatus | null;
  gcih: GcihFamilySyncPayload | null;
  linkedGcihSync: GcihFamilySyncPayload[];
  gcihOfflineQueue: GcihOfflineQueueEntry[];
  gcihDeviceId: string;
  gcihSyncStatus: GcihSyncStatus;
  gcihFeedbackNote: string;
  sidebarCollapsed: boolean;
  mobileDrawerOpen: boolean;
  notifDrawerOpen: boolean;
  timelineFilter: 'all' | 'call' | 'sms' | 'qr' | 'pay';
  expandedTimelineIds: Record<string, boolean>;
  selectedFamilyOwnerId: string;
  dismissedNotifIds: Record<string, boolean>;
  parentsAi: ParentsAiWorkspaceState | null;
  activeAiTool: ParentsAiToolKey;
  searchQuery: string;
  bankSearchQuery: string;
  bankCategoryFilter: string;
  recentTools: ParentsAiToolKey[];
  epp: EppDashboardState | null;
  eppSelectedBankId: string;
  eppBankSearch: string;
  eppPreviewService: EppBankServiceType | null;
  eppSelectedApps: string[];
  eppDuration: EppDurationOption;
  eppAuthAck: boolean;
  eppBankEditorOpen: boolean;
  busy: {
    analyze: boolean;
    ocr: boolean;
    chat: boolean;
    auth: boolean;
    cw: boolean;
    emergency: boolean;
    gcih: boolean;
    parentsAi: boolean;
    epp: boolean;
  };
}

export const esc = (s: unknown): string =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));

export const T: Record<'en' | 'hi', Record<string, string>> = {
  en: {
    home: 'Dashboard',
    device: 'Location & Device',
    scam: 'Scam Check',
    pay: 'Payment Safety',
    qr: 'QR Check',
    fam: 'Family Management',
    call: 'Call Watch',
    alerts: 'Safety Alerts',
    ai: 'AI Insights',
    reports: 'Activity Reports',
    priv: 'Settings',
    gset: 'Settings',
    learn: 'Learn',
    req: 'Approval Requests',
    act: 'Family Activity',
    tools: 'AI Tools',
    bank: 'Connect Your Bank',
    control: 'Control Center',
    epp: 'Emergency Pay Lock',
    out: 'Logout',
    hi: 'Namaste',
    safe: 'No current alert',
    tag: 'Protecting the people who protected us.',
    q1: 'Am I protected?',
    q2: 'Is anything suspicious?',
    q3: 'What if I get a payment request?',
    a3: 'Pause. Do not share OTP or PIN. Check with your guardian.',
  },
  hi: {
    home: 'डैशबोर्ड',
    device: 'स्थान और डिवाइस',
    scam: 'स्कैम जाँच',
    pay: 'भुगतान सुरक्षा',
    qr: 'QR जाँच',
    fam: 'परिवार प्रबंधन',
    call: 'कॉल निगरानी',
    alerts: 'सुरक्षा अलर्ट',
    ai: 'AI अंतर्दृष्टि',
    reports: 'गतिविधि रिपोर्ट',
    priv: 'सेटिंग्स',
    gset: 'सेटिंग्स',
    learn: 'सीखें',
    req: 'स्वीकृति अनुरोध',
    act: 'परिवार गतिविधि',
    tools: 'AI टूल्स',
    bank: 'बैंक कनेक्ट करें',
    control: 'नियंत्रण केंद्र',
    epp: 'आपात भुगतान लॉक',
    out: 'लॉगआउट',
    hi: 'नमस्ते',
    safe: 'अभी कोई चेतावनी नहीं',
    tag: 'जिन्होंने हमारी रक्षा की, उनकी रक्षा।',
    q1: 'क्या मैं सुरक्षित हूँ?',
    q2: 'क्या कुछ संदिग्ध है?',
    q3: 'भुगतान का अनुरोध आए तो?',
    a3: 'रुकें। OTP या PIN साझा न करें। अपने अभिभावक से पूछें।',
  },
};

export const inr = (n: number | string): string => '₹' + Number(n).toLocaleString('en-IN');

export const S: AppState = {
  user: null,
  booted: false,
  online: typeof navigator !== 'undefined' ? navigator.onLine : true,
  lang: 'en',
  fontScale: 'normal',
  tab: 'home',
  mode: 'login',
  role: 'parent',
  draftLoginUser: '',
  slide: 0,
  tip: 0,
  err: '',
  recoveryDisplay: '',
  c: { text: true, galerts: true, gapprove: true, paused: false, calls: true },
  medThreshold: 25,
  highThreshold: 50,
  retentionDays: 30,
  loadModerateMax: 2000,
  loadHighMax: 10000,
  loadVeryHighMin: 25000,
  redAlertCooldownSec: 600,
  qrPrefs: {
    qrScanNotify: false,
    highRiskQrAlert: true,
    criticalRiskQrAlert: true,
    highAmountAlert: true,
    veryHighLoadAlert: true,
    repeatedQrAlert: true,
    merchantWarningAlert: true,
    suspiciousQrAlert: true,
  },
  qrScans: [],
  qrReport: null,
  qrStatus: { state: 'idle' },
  hasSafeWord: false,
  pats: 0,
  calls: [],
  cur: null,
  alert: null,
  timingEvents: [],
  lastPayMsgAt: 0,
  link: 0,
  limit: 10000,
  reqs: [],
  links: [],
  linkedParents: [],
  notifications: [],
  reports: [],
  audit: [],
  res: null,
  ocrNote: '',
  ocrDraft: '',
  pay: null,
  qr: null,
  chat: [],
  q: 0,
  score: 0,
  inc: [],
  note: '',
  confirmAction: null,
  evalResult: null,
  callWatcher: null,
  linkedCallWatcherEvents: [],
  cwSelectedId: null,
  cwOfflineQueue: [],
  cwScreenResult: null,
  cwScreenNumber: '',
  cwWhyExpandedId: null,
  cwActiveCallId: null,
  gsi: null,
  linkedGsiOverview: null,
  linkAnalysis: null,
  gsiReportPeriod: 'weekly',
  gsiAlertFilter: 'all',
  emergencyStatus: null,
  gcih: null,
  linkedGcihSync: [],
  gcihOfflineQueue: [],
  gcihDeviceId: '',
  gcihSyncStatus: 'Locally detected',
  gcihFeedbackNote: '',
  sidebarCollapsed: (() => {
    try {
      return typeof window !== 'undefined' && window.localStorage.getItem('guardian_sidebar_collapsed') === '1';
    } catch {
      return false;
    }
  })(),
  mobileDrawerOpen: false,
  notifDrawerOpen: false,
  timelineFilter: 'all',
  expandedTimelineIds: {},
  selectedFamilyOwnerId: 'all',
  dismissedNotifIds: {},
  parentsAi: null,
  activeAiTool: 'parenting',
  searchQuery: '',
  bankSearchQuery: '',
  bankCategoryFilter: 'all',
  recentTools: ['parenting', 'child_safety', 'budget'],
  epp: null,
  eppSelectedBankId: '',
  eppBankSearch: '',
  eppPreviewService: null,
  eppSelectedApps: ['com.google.android.apps.nbu.paisa.user', 'com.phonepe.app', 'net.one97.paytm'],
  eppDuration: '1h',
  eppAuthAck: false,
  eppBankEditorOpen: false,
  busy: {
    analyze: false,
    ocr: false,
    chat: false,
    auth: false,
    cw: false,
    emergency: false,
    gcih: false,
    parentsAi: false,
    epp: false,
  },
};

export const t = (k: string): string => T[S.lang][k] || k;

let renderCallback: () => void = () => {};
export const setRenderer = (fn: () => void): void => {
  renderCallback = fn;
};
export const R = (): void => {
  renderCallback();
};

let callCorrelationHandler: ((sourceLabel?: string) => Promise<void>) | null = null;
export const setCallCorrelationHandler = (fn: (sourceLabel?: string) => Promise<void>): void => {
  callCorrelationHandler = fn;
};

export const log = (ev: string): void => {
  const safe = String(ev)
    .replace(/\b\d{4,}\b/g, '[REDACTED]')
    .replace(/[\w.-]+@[\w.-]+/g, '[ID]');
  S.audit.unshift({ t: new Date().toLocaleTimeString(), ev: safe, h: 'local' });
};

const SESSION_STORAGE_KEY = 'guardian_session_token';
let memorySessionToken: string | null = null;

export function getSessionToken(): string | null {
  if (memorySessionToken) return memorySessionToken;
  try {
    const tok = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (tok) memorySessionToken = tok;
    return tok;
  } catch {
    return null;
  }
}

export function setSessionToken(token: string | null): void {
  memorySessionToken = token;
  try {
    if (token) {
      window.sessionStorage.setItem(SESSION_STORAGE_KEY, token);
    } else {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  } catch {
    // ignore storage restriction
  }
}

function getConfiguredApiBaseUrl(): string {
  const env = (import.meta as { env?: Record<string, string> }).env || {};
  const raw = String(env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    const isLocalHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (env.VITE_APP_ENV === 'production' && parsed.protocol !== 'https:' && !isLocalHost) {
      return '';
    }
    return parsed.origin;
  } catch {
    return '';
  }
}

export function resolveApiUrl(url: string): string {
  if (/^https?:\/\//i.test(url)) return url;
  const base = getConfiguredApiBaseUrl();
  if (!base) return url;
  return `${base}${url.startsWith('/') ? url : `/${url}`}`;
}

export async function apiJson<TRes = Record<string, unknown>>(
  url: string,
  options: RequestInit = {}
): Promise<TRes> {
  const token = getSessionToken();
  const resp = await fetch(resolveApiUrl(url), {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  const rawText = await resp.text().catch(() => '');
  let data: Record<string, unknown> = {};
  let parsedJson = false;
  if (rawText) {
    try {
      data = JSON.parse(rawText) as Record<string, unknown>;
      parsedJson = true;
    } catch {
      data = {};
    }
  }
  if (!resp.ok) {
    if (resp.status === 401 && !url.startsWith('/api/auth/')) {
      setSessionToken(null);
      S.user = null;
    }
    const serverMsg = typeof data.error === 'string' && data.error.trim() ? data.error.trim() : '';
    if (serverMsg) {
      const err = new Error(serverMsg) as Error & { status?: number; code?: string };
      err.status = resp.status;
      if (typeof data.code === 'string') err.code = data.code;
      throw err;
    }
    const looksLikeHtmlOrNotFound =
      !parsedJson &&
      (rawText.includes('<!DOCTYPE') ||
        rawText.includes('<html') ||
        rawText.includes('NOT_FOUND') ||
        rawText.includes('The page could not be found'));
    const fallbackMsg =
      resp.status === 404 && looksLikeHtmlOrNotFound
        ? 'Backend API route returned 404 (not routed). Check Vercel /api serverless deployment or VITE_API_BASE_URL.'
        : resp.status === 503
          ? 'Backend database is unavailable or not configured yet (503). Verify TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.'
          : looksLikeHtmlOrNotFound
            ? `Backend gateway error (${resp.status}). Please retry shortly.`
            : `Request failed (${resp.status})`;
    const err = new Error(fallbackMsg) as Error & { status?: number; code?: string };
    err.status = resp.status;
    throw err;
  }
  return data as TRes;
}

export async function syncStateFromServer(throwOnError = false): Promise<void> {
  try {
    const data = await apiJson<Record<string, unknown>>('/api/state');
    const user = data.user as UserAccount;
    S.user = user;
    if (user.role === 'parent') {
      if (!['home', 'device', 'scam', 'pay', 'qr', 'call', 'alerts', 'ai', 'reports', 'fam', 'priv', 'learn', 'tools', 'bank', 'control', 'epp'].includes(S.tab)) {
        S.tab = 'home';
      }
      const c = data.consent as {
        text: boolean;
        galerts: boolean;
        gapprove: boolean;
        calls: boolean;
        paused: boolean;
        limit: number;
        medThreshold: number;
        highThreshold: number;
        retentionDays: number;
        loadModerateMax?: number;
        loadHighMax?: number;
        loadVeryHighMin?: number;
        redAlertCooldownSec?: number;
      };
      if (c) {
        S.c = {
          text: c.text,
          galerts: c.galerts,
          gapprove: c.gapprove,
          calls: c.calls,
          paused: c.paused,
        };
        S.limit = c.limit;
        S.medThreshold = c.medThreshold;
        S.highThreshold = c.highThreshold;
        S.retentionDays = c.retentionDays;
        if (c.loadModerateMax) S.loadModerateMax = c.loadModerateMax;
        if (c.loadHighMax) S.loadHighMax = c.loadHighMax;
        if (c.loadVeryHighMin) S.loadVeryHighMin = c.loadVeryHighMin;
        if (c.redAlertCooldownSec) S.redAlertCooldownSec = c.redAlertCooldownSec;
      }
      if (data.qrPrefs) {
        S.qrPrefs = data.qrPrefs as QrNotificationPrefs;
      }
      S.qrScans = (data.qrScans as QrScanSummaryRecord[]) || [];
      S.callWatcher = (data.callWatcher as CallWatcherDashboardState) || null;
      S.gsi = (data.gsi as GsiDashboardState) || null;
      S.gcih = (data.gcih as GcihFamilySyncPayload) || null;
      S.linkedGcihSync = [];
      if (!S.gcihDeviceId) S.gcihDeviceId = getOrCreateGcihDeviceId();
      S.gcihSyncStatus =
        S.gcihOfflineQueue.length > 0
          ? 'Pending synchronisation'
          : S.gcih?.syncStatus || 'Successfully synchronised';
      S.hasSafeWord = Boolean(data.hasSafeWord);
      S.reqs = (data.reqs as GuardianRequest[]) || [];
      S.audit = (data.audit as { t: string; ev: string; h: string }[]) || [];
      S.calls = (data.calls as CallRecord[]) || [];
      S.inc = (data.incidents as { a: string; d: string; s: string }[]) || [];
      S.links = (data.links as GuardianLink[]) || [];
      S.notifications = (data.notifications as NotificationItem[]) || [];
      S.reports = (data.reports as ScamReportItem[]) || [];
    } else {
      if (!['req', 'act', 'gset', 'tools', 'bank', 'control', 'epp'].includes(S.tab)) {
        S.tab = 'req';
      }
      if (data.qrPrefs) {
        S.qrPrefs = data.qrPrefs as QrNotificationPrefs;
      }
      S.qrScans = (data.linkedQrScans as QrScanSummaryRecord[]) || [];
      S.linkedCallWatcherEvents = (data.linkedCallWatcherEvents as CwTimelineItem[]) || [];
      S.linkedGsiOverview = (data.linkedGsiOverview as LinkedGsiOverview) || null;
      S.linkedGcihSync = (data.linkedGcihSync as GcihFamilySyncPayload[]) || [];
      S.gcih = null;
      if (!S.gcihDeviceId) S.gcihDeviceId = getOrCreateGcihDeviceId();
      S.gcihSyncStatus = S.linkedGcihSync.length > 0 ? 'Successfully synchronised' : 'Locally detected';
      S.linkedParents = (data.linkedParents as AppState['linkedParents']) || [];
      S.reqs = (data.reqs as GuardianRequest[]) || [];
      S.audit = (data.audit as { t: string; ev: string; h: string }[]) || [];
      S.notifications = (data.notifications as NotificationItem[]) || [];
    }
    try {
      const target =
        user.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : '';
      const qs = target ? `?ownerId=${encodeURIComponent(target)}` : '';
      S.parentsAi = await apiJson<ParentsAiWorkspaceState>(`/api/parents-ai/state${qs}`);
    } catch {
      S.parentsAi = null;
    }
    try {
      const target =
        user.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : '';
      const qs = target ? `?ownerId=${encodeURIComponent(target)}` : '';
      S.epp = await apiJson<EppDashboardState>(`/api/epp/dashboard${qs}`);
      if (!S.eppSelectedBankId && S.epp?.banks?.length) {
        S.eppSelectedBankId = S.epp.banks[0].id;
      }
    } catch {
      S.epp = null;
    }
  } catch (err) {
    S.user = null;
    S.parentsAi = null;
    S.epp = null;
    setSessionToken(null);
    const status = (err as { status?: number } | null)?.status;
    if (!throwOnError && status && status !== 401 && !S.err) {
      S.err = err instanceof Error ? err.message : 'Unable to reach Guardian backend.';
    }
    if (throwOnError) {
      throw err;
    }
  } finally {
    S.booted = true;
    R();
  }
}

export const lvlCol = (l: RiskResult['level']): string =>
  l === 'LOW' ? 'var(--teal)' : l === 'MEDIUM' ? 'var(--amb)' : 'var(--red)';

export const card = (r: RiskResult, extra = ''): string =>
  `<div class="card"><div class="row"><span class="pill ${r.level}">${r.level}</span><b>Rule Score ${r.score}/100</b><span class="mut">Category: ${esc(r.cat)} · Rule signal confidence: ${r.conf}</span></div><div class="bar" style="margin:10px 0"><i style="width:${r.score}%;background:${lvlCol(r.level)}"></i></div><b>Rule-based signals</b><ul>${r.sig.map((s) => `<li>${esc(s)}</li>`).join('') || '<li>No rule matched (does not prove safety)</li>'}</ul>${extra}<p class="mut">This score comes from transparent rules. It is a heuristic, not a probability, and can miss scams or flag genuine messages. Unknown: who the sender really is.</p></div>`;

/* ---- Layer B/C: AI via Gemini server endpoint, validated, with honest fallback ---- */
export async function aiExplain(
  x: string,
  r: RiskResult,
  contextType: 'message' | 'call_start' | 'call_payment_timing' = 'message'
): Promise<{ explanation: string; recommended_actions: string[]; uncertainty_statement: string }> {
  const red = x.replace(/\d{6,}/g, '[NUM]').replace(/[\w.-]+@[\w.-]+/g, '[ID]').slice(0, 800);
  const token = getSessionToken();
  const resp = await fetch(resolveApiUrl('/api/ai/explain'), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      text: red,
      signals: r.sig,
      level: r.level,
      lang: S.lang,
      contextType,
    }),
  });
  if (!resp.ok) {
    throw new Error('AI explain failed');
  }
  const o = await resp.json();
  if (!o || typeof o.explanation !== 'string' || !Array.isArray(o.recommended_actions) || typeof o.uncertainty_statement !== 'string') {
    throw new Error('Invalid AI explain payload');
  }
  return {
    explanation: o.explanation.slice(0, 500),
    recommended_actions: o.recommended_actions.slice(0, 4).map((a: unknown) => String(a).slice(0, 160)),
    uncertainty_statement: o.uncertainty_statement.slice(0, 220),
  };
}

export const aiBox = (r?: AiExplanation | null): string =>
  !r
    ? ''
    : r.st === 'wait'
      ? '<div class="warn">AI is writing a plain-language explanation…</div>'
      : r.st === 'off'
        ? '<div class="warn"><span class="badge-fb">FALLBACK RULES</span> <b>Live AI analysis unavailable.</b> Showing transparent rule-based result only. Pause and verify through an independently trusted channel.</div>'
        : `<div class="warn"><span class="badge-live">LIVE GEMINI AI</span> <b>Plain-language explanation</b><p>${esc(r.explanation)}</p><ul>${(r.recommended_actions || []).map((a) => `<li>${esc(a)}</li>`).join('')}</ul><span class="mut">${esc(r.uncertainty_statement)}</span></div>`;

export async function analyze(): Promise<void> {
  if (S.busy.analyze) return;
  const el = document.getElementById('st') as HTMLTextAreaElement | null;
  const x = el ? el.value.trim() : '';
  if (!x) return;
  if (!S.c.text || S.c.paused) {
    S.note = 'Message analysis is off. Turn it on in Privacy, or paste text after giving consent.';
    R();
    return;
  }

  S.busy.analyze = true;
  S.note = '';
  S.linkAnalysis = null;
  const r = rules(x, S.medThreshold, S.highThreshold);
  S.res = { r, ai: { st: 'wait' }, lastText: x };
  S.ocrDraft = x;

  const urlMatch = x.match(/(?:https?:\/\/|bit\.ly\/|tinyurl\.com\/|t\.co\/|cutt\.ly\/|rb\.gy\/|is\.gd\/|wa\.me\/)[^\s<>"'`)\]}]+/i);
  if (urlMatch && S.user) {
    void apiJson<{ linkAnalysis: LinkAnalysisResult }>('/api/gsi/links/analyze', {
      method: 'POST',
      body: JSON.stringify({
        url: urlMatch[0].replace(/[.,;!?]+$/, ''),
        contextText: x.slice(0, 600),
        allowNetworkProbe: false,
        recordEvent: false,
      }),
    })
      .then((res) => {
        S.linkAnalysis = res.linkAnalysis;
        R();
      })
      .catch(() => {});
  }

  const isPaymentAlertMsg =
    r.cat === 'urgent_payment' ||
    r.cat === 'bank_impersonation' ||
    r.cat === 'otp_theft' ||
    r.cat === 'qr_refund' ||
    /(pay|upi|rs\.?|₹|transfer|payment|alert|debited|credited|kyc|request|भुगतान)/i.test(x);

  if (isPaymentAlertMsg) {
    S.lastPayMsgAt = Date.now();
    if (S.c.calls && !S.c.paused && (S.cur || (S.calls[0] && Date.now() - S.calls[0].e <= 36e5)) && callCorrelationHandler) {
      void callCorrelationHandler('a payment/alert message checked in Scam Check');
    }
  }

  R();
  let aiUsed = false;
  try {
    const a = await aiExplain(x, r, 'message');
    if (S.res) {
      S.res.ai = { st: 'ok', ...a };
      aiUsed = true;
    }
  } catch {
    if (S.res) {
      S.res.ai = { st: 'off' };
    }
  } finally {
    S.busy.analyze = false;
  }

  if (S.user?.role === 'parent') {
    const devId = S.gcihDeviceId || getOrCreateGcihDeviceId();
    if (!S.online) {
      enqueueGcihOfflineEvent({
        eventType: 'sms_event',
        sourceModule: 'module_b_scam_check',
        payload: {
          smsData: { rawText: x.slice(0, 1500), senderLabel: null },
          lang: S.lang,
        },
      });
      S.note = 'Offline: Message check queued locally for Central Intelligence Hub sync when online.';
    } else {
      void apiJson('/api/scam/record', {
        method: 'POST',
        body: JSON.stringify({
          score: r.score,
          level: r.level,
          cat: r.cat,
          sig: r.sig,
          aiUsed,
          text: x.slice(0, 1500),
          deviceId: devId,
          lang: S.lang,
        }),
      })
        .then(() => syncStateFromServer())
        .catch(() => {
          enqueueGcihOfflineEvent({
            eventType: 'sms_event',
            sourceModule: 'module_b_scam_check',
            payload: {
              smsData: { rawText: x.slice(0, 1500), senderLabel: null },
              lang: S.lang,
            },
          });
        });
    }
  }
  R();
}

export async function inspectManualLink(overrideUrl?: string): Promise<void> {
  const input = document.getElementById('gsi-link-url') as HTMLInputElement | null;
  const raw = (overrideUrl !== undefined ? overrideUrl : input ? input.value : '').trim();
  if (!raw) {
    S.note = 'Paste a URL or shortened link to inspect safely.';
    R();
    return;
  }
  if (!S.online && S.user?.role === 'parent') {
    enqueueGcihOfflineEvent({
      eventType: 'link_event',
      sourceModule: 'module_c_manual_link_check',
      payload: {
        linkData: { url: raw },
        lang: S.lang,
      },
    });
    S.note = 'Offline: Link check queued for Central Intelligence Hub analysis when connectivity returns.';
    R();
    return;
  }
  S.busy.analyze = true;
  S.note = '';
  R();
  try {
    const res = await apiJson<{ linkAnalysis: LinkAnalysisResult }>('/api/gsi/links/analyze', {
      method: 'POST',
      body: JSON.stringify({
        url: raw,
        allowNetworkProbe: S.online,
        recordEvent: S.user?.role === 'parent',
        deviceId: S.gcihDeviceId || getOrCreateGcihDeviceId(),
        lang: S.lang,
      }),
    });
    S.linkAnalysis = res.linkAnalysis;
    S.note = 'Link inspected safely on server (never auto-opened).';
    if (S.user?.role === 'parent') {
      await syncStateFromServer();
    }
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Link inspection failed.';
  } finally {
    S.busy.analyze = false;
    R();
  }
}

export function ocrFile(e: Event): void {
  const input = e.target as HTMLInputElement;
  const f = input.files && input.files[0];
  if (!f || S.busy.ocr) return;
  if (!/^image\/(png|jpe?g|webp)$/.test(f.type) || f.size > 5e6) {
    S.note = 'Only PNG, JPG, or WEBP screenshots under 5 MB are allowed.';
    R();
    return;
  }

  S.busy.ocr = true;
  S.ocrNote = 'Reading text from screenshot…';
  R();

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const dataUrl = String(reader.result || '');
      const base64Data = dataUrl.split(',')[1] || '';
      const out = await apiJson<{ extractedText: string; note: string }>('/api/ai/ocr', {
        method: 'POST',
        body: JSON.stringify({ base64Data, mimeType: f.type }),
      });
      S.ocrDraft = out.extractedText;
      S.ocrNote = out.note + ' (Visual appearance alone cannot prove an image is genuine or fake.)';
    } catch (err) {
      S.ocrNote = err instanceof Error ? err.message : 'Screenshot text extraction failed. Please paste text manually.';
    } finally {
      S.busy.ocr = false;
      R();
      const st = document.getElementById('st') as HTMLTextAreaElement | null;
      if (st && S.ocrDraft) {
        st.value = S.ocrDraft;
      }
    }
  };
  reader.onerror = () => {
    S.busy.ocr = false;
    S.ocrNote = 'Could not read screenshot file.';
    R();
  };
  reader.readAsDataURL(f);
}

export async function reportScam(): Promise<void> {
  if (!S.res || !S.res.lastText) return;
  try {
    await apiJson('/api/scam/report', {
      method: 'POST',
      body: JSON.stringify({ text: S.res.lastText, cat: S.res.r.cat }),
    });
    S.note = 'Suspicious message reported (personal numbers and IDs masked, marked unverified until reviewed).';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save report.';
    R();
  }
}

/* ---- Guardian Central Intelligence Hub (GCIH) Client Helpers ---- */
const GCIH_DEVICE_KEY = 'guardian_gcih_device_id';
const GCIH_QUEUE_KEY = 'guardian_gcih_offline_queue';

export function getOrCreateGcihDeviceId(): string {
  if (S.gcihDeviceId) return S.gcihDeviceId;
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const existing = window.localStorage.getItem(GCIH_DEVICE_KEY);
      if (existing) {
        S.gcihDeviceId = existing;
        return existing;
      }
      const created = `web_${Math.random().toString(36).slice(2, 10)}`;
      window.localStorage.setItem(GCIH_DEVICE_KEY, created);
      S.gcihDeviceId = created;
      return created;
    }
  } catch {
    // ignore storage restrictions
  }
  S.gcihDeviceId = 'web_session';
  return S.gcihDeviceId;
}

export function loadGcihOfflineQueue(): void {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const raw = window.localStorage.getItem(GCIH_QUEUE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          S.gcihOfflineQueue = parsed;
        }
      }
    }
  } catch {
    // ignore storage restrictions
  }
}

export function saveGcihOfflineQueue(): void {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(GCIH_QUEUE_KEY, JSON.stringify(S.gcihOfflineQueue));
    }
  } catch {
    // ignore storage restrictions
  }
}

export function enqueueGcihOfflineEvent(params: {
  eventType: GcihOfflineQueueEntry['eventType'];
  sourceModule: string;
  payload: Record<string, unknown>;
}): void {
  const now = Date.now();
  const entry: GcihOfflineQueueEntry = {
    id: `gcihq_${now}_${Math.random().toString(36).slice(2, 6)}`,
    clientEventId: `off_${now}_${Math.random().toString(36).slice(2, 8)}`,
    eventType: params.eventType,
    eventTimestamp: now,
    sourceModule: params.sourceModule,
    payload: params.payload,
    createdAt: now,
  };
  S.gcihOfflineQueue.push(entry);
  S.gcihSyncStatus = 'Pending synchronisation';
  saveGcihOfflineQueue();
}

export async function gcihFlushOfflineQueue(): Promise<void> {
  if (!S.online || S.user?.role !== 'parent' || S.gcihOfflineQueue.length === 0 || S.busy.gcih) return;
  S.busy.gcih = true;
  R();
  try {
    const devId = S.gcihDeviceId || getOrCreateGcihDeviceId();
    const res = await apiJson<{
      acks: { clientEventId: string; status: string }[];
      gcih?: GcihFamilySyncPayload;
      gsi?: GsiDashboardState;
    }>('/api/gcih/sync/push', {
      method: 'POST',
      body: JSON.stringify({
        deviceId: devId,
        events: S.gcihOfflineQueue.map((e) => ({
          clientEventId: e.clientEventId,
          eventType: e.eventType,
          eventTimestamp: e.eventTimestamp,
          sourceModule: e.sourceModule,
          ...e.payload,
        })),
      }),
    });
    const ackedIds = new Set(
      (res.acks || [])
        .filter((a) => a.status === 'Successfully synchronised')
        .map((a) => a.clientEventId)
    );
    const before = S.gcihOfflineQueue.length;
    S.gcihOfflineQueue = S.gcihOfflineQueue.filter((e) => !ackedIds.has(e.clientEventId));
    saveGcihOfflineQueue();
    if (res.gcih) S.gcih = res.gcih;
    if (res.gsi) S.gsi = res.gsi;
    S.gcihSyncStatus =
      S.gcihOfflineQueue.length > 0 ? 'Synchronisation failed' : 'Successfully synchronised';
    const syncedCount = before - S.gcihOfflineQueue.length;
    if (syncedCount > 0) {
      S.note = `Central Intelligence Hub synced ${syncedCount} queued offline event(s) cleanly without duplicates.`;
    }
    await syncStateFromServer();
  } catch (err) {
    S.gcihSyncStatus = 'Synchronisation failed';
    S.note = err instanceof Error ? err.message : 'Offline sync failed; items kept in local queue.';
  } finally {
    S.busy.gcih = false;
    R();
  }
}

export async function gcihRegisterCurrentDevice(customLabel?: string): Promise<void> {
  if (!S.user || S.busy.gcih) return;
  S.busy.gcih = true;
  R();
  try {
    const devId = getOrCreateGcihDeviceId();
    const notifPerm =
      typeof Notification !== 'undefined' && Notification.permission
        ? Notification.permission
        : 'default';
    await apiJson('/api/gcih/devices/register', {
      method: 'POST',
      body: JSON.stringify({
        deviceId: devId,
        deviceLabel:
          customLabel ||
          (S.user.role === 'parent' ? `${S.user.name} Web Session` : `${S.user.name} Guardian Browser`),
        platform: 'web',
        permissions: {
          callMonitoring: 'unavailable_in_browser',
          smsMonitoring: 'unavailable_in_browser',
          notifications: notifPerm,
        },
      }),
    });
    S.note = 'This browser session is registered with the Guardian Central Intelligence Hub.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Device registration failed.';
  } finally {
    S.busy.gcih = false;
    R();
  }
}

export async function gcihUpdateDevicePermissions(
  deviceId: string,
  permissions: Partial<GcihDevicePermissions>
): Promise<void> {
  try {
    await apiJson(`/api/gcih/devices/${encodeURIComponent(deviceId)}/permissions`, {
      method: 'PUT',
      body: JSON.stringify({ permissions }),
    });
    S.note = 'Device sharing & permission state updated.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update device permissions.';
    R();
  }
}

export async function gcihRevokeDevice(deviceId: string): Promise<void> {
  try {
    await apiJson(`/api/gcih/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST',
    });
    S.note = 'Device access revoked immediately across family sync.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not revoke device.';
    R();
  }
}

export async function gcihSyncNow(): Promise<void> {
  if (!S.online) {
    S.note = 'Offline: Cannot sync with Central Intelligence Hub right now.';
    R();
    return;
  }
  if (S.user?.role === 'parent' && S.gcihOfflineQueue.length > 0) {
    await gcihFlushOfflineQueue();
  }
  try {
    const devId = S.gcihDeviceId || getOrCreateGcihDeviceId();
    await apiJson(`/api/gcih/sync?deviceId=${encodeURIComponent(devId)}`);
    await syncStateFromServer();
    if (!S.note) S.note = 'Family Central Intelligence Hub synchronised.';
  } catch (err) {
    S.gcihSyncStatus = 'Synchronisation failed';
    S.note = err instanceof Error ? err.message : 'Sync failed.';
    R();
  }
}

export async function gcihSubmitEntityFeedback(
  entityId: string,
  feedbackType: 'suspicious' | 'legitimate' | 'false_positive' | 'request_review' | 'incorrect_association',
  note?: string
): Promise<void> {
  try {
    const cleanNote = note !== undefined ? note : S.gcihFeedbackNote.trim() || undefined;
    await apiJson(`/api/gcih/entities/${encodeURIComponent(entityId)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ feedbackType, note: cleanNote }),
    });
    S.gcihFeedbackNote = '';
    S.note =
      feedbackType === 'legitimate' || feedbackType === 'false_positive'
        ? 'Entity marked legitimate/false positive (original evidence preserved; scoped to this specific entity and synced across family).'
        : feedbackType === 'suspicious'
          ? 'Entity flagged as suspicious across linked family modules.'
          : 'Review/association dispute recorded and synced across family.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not submit entity feedback.';
    R();
  }
}

export async function gcihCorrectRelationship(
  relationshipId: string,
  action: 'dispute' | 'correct' | 'restore',
  note?: string
): Promise<void> {
  try {
    await apiJson(`/api/gcih/relationships/${encodeURIComponent(relationshipId)}/correct`, {
      method: 'POST',
      body: JSON.stringify({ action, note }),
    });
    S.note = `Entity relationship updated (${action}).`;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update relationship.';
    R();
  }
}

export async function gcihUpdateIncidentWorkflow(
  incidentId: string,
  workflowStatus: GcihIncidentWorkflowStatus,
  note?: string
): Promise<void> {
  try {
    await apiJson(`/api/gcih/incidents/${encodeURIComponent(incidentId)}/workflow`, {
      method: 'POST',
      body: JSON.stringify({ workflowStatus, note }),
    });
    S.note = `Incident status updated to ${workflowStatus}.`;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update incident workflow.';
    R();
  }
}
