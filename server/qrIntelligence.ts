import crypto from "node:crypto";
import { db } from "./db.ts";
import { generateQrIntelligenceWithGemini } from "./ai.ts";
import {
  createNotification,
  ensureDefaultConsent,
  ensureDefaultQrNotificationPrefs,
  generateId,
  getActiveGuardiansForParent,
  sha256,
  writeAudit,
} from "./security.ts";
import { ingestGsiEvent } from "./gsi.ts";
import {
  extractEntitiesFromQrPayload,
  lookupSharedEntitiesForQuery,
  type SharedIntelligenceItem,
} from "./gcih.ts";

export type DataProvenance =
  | "Extracted from QR"
  | "Verified through an external source"
  | "Inferred"
  | "Unverified"
  | "Unavailable";

export type RiskCategoryLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "INCONCLUSIVE";

export type PaymentLoadCategory =
  | "Low Payment Load"
  | "Moderate Payment Load"
  | "High Payment Load"
  | "Very High Payment Load"
  | "Not Classified";

export type AmountState = "fixed" | "not_encoded" | "invalid" | "unsupported";

export interface SourcedField {
  label: string;
  value: string | null;
  displayValue: string;
  source: DataProvenance;
}

export interface ExtractedQrInfo {
  decodingStatus: "decoded" | "incomplete" | "malformed" | "unsupported";
  qrFormat: string;
  qrType: string;
  classification: "Static UPI QR" | "Dynamic UPI QR" | "External Web URL" | "EMVCo / BharatQR" | "Malformed" | "Unsupported";
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
  rawAmountParam: string | null;
  amountState: AmountState;
  amountDisplay: string;
  amountEditability:
    | "Fixed amount encoded in QR"
    | "No amount encoded; user may enter an amount"
    | "Amount editability not determinable";
  currency: string | null;
  paymentNote: string | null;
  transactionRef: string | null;
  transactionId: string | null;
  mcc: string | null;
  expiryInfo: string | null;
  providerInferred: string | null;
  urlHost: string | null;
  urlString: string | null;
  unexpectedParams: string[];
  paymentFields: SourcedField[];
  qrFields: SourcedField[];
}

export interface ExternalServiceBoundary {
  service: string;
  available: boolean;
  status: "unavailable" | "available";
  message: string;
}

export interface MerchantIntelligence {
  upiId: SourcedField;
  payeeName: SourcedField;
  merchantName: SourcedField;
  merchantCategory: SourcedField;
  paymentProvider: SourcedField;
  verifiedIdentity: SourcedField;
  reputationInfo: SourcedField;
  fraudReportsInfo: SourcedField;
  nameMismatchDetected: boolean;
  mismatchReason: string | null;
  impersonationIndicators: string[];
  externalVerification: ExternalServiceBoundary;
}

export interface SecurityFinding {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  evidence: string;
  reasoning: string;
}

export interface QrSecurityAnalysis {
  riskLevel: RiskCategoryLevel;
  riskLabel: string;
  score: number;
  findings: SecurityFinding[];
  externalFraudIntel: ExternalServiceBoundary;
  summary: string;
}

export interface LoadThresholds {
  paymentLimit: number;
  moderateMax: number;
  highMax: number;
  veryHighMin: number;
}

export interface PaymentLoadAnalysis {
  requestedAmount: number | null;
  amountDisplay: string;
  loadCategory: PaymentLoadCategory;
  loadRiskLevel: RiskCategoryLevel;
  loadRiskLabel: string;
  configuredThresholds: LoadThresholds;
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
}

export interface DuplicateQrStatus {
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
}

export interface ParentNotificationDelivery {
  consentEnabled: boolean;
  monitoringPaused: boolean;
  linkedGuardiansCount: number;
  triggeredEvents: string[];
  notificationsSentCount: number;
  suppressedReasons: string[];
  statusMessage: string;
}

export interface FullQrIntelligenceReport {
  scanId: string;
  scannedAt: number;
  extracted: ExtractedQrInfo;
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
    qrLoadCategory: PaymentLoadCategory;
    qrLoadCategoryMessage: string;
    aiAmountExplanation: string;
  };
  merchant: MerchantIntelligence;
  security: QrSecurityAnalysis;
  paymentAmountAnalysis: {
    caseType: AmountState;
    summary: string;
    editability: string;
    anomalyNote: string;
  };
  paymentLoad: PaymentLoadAnalysis;
  duplicateStatus: DuplicateQrStatus;
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
    combinedLevel: RiskCategoryLevel;
    combinedLabel: string;
    securityRiskLevel: RiskCategoryLevel;
    securityRiskLabel: string;
    paymentLoadRiskLevel: RiskCategoryLevel;
    paymentLoadRiskLabel: string;
    summary: string;
  };
  parentNotifications: ParentNotificationDelivery;
  gsiAssessment?: {
    incidentId: string;
    severity: string;
    riskScore: number;
  };
  sharedIntelligence?: SharedIntelligenceItem[];
}

const KNOWN_PSP_HANDLES: Record<string, string> = {
  okaxis: "Google Pay (Axis Bank PSP)",
  okicici: "Google Pay (ICICI Bank PSP)",
  oksbi: "Google Pay (SBI PSP)",
  okhdfcbank: "Google Pay (HDFC Bank PSP)",
  ybl: "PhonePe (Yes Bank PSP)",
  ibl: "PhonePe (ICICI Bank PSP)",
  axl: "PhonePe (Axis Bank PSP)",
  paytm: "Paytm Payments Bank / UPI",
  ptaxis: "Paytm (Axis Bank PSP)",
  pthdfc: "Paytm (HDFC Bank PSP)",
  ptsbi: "Paytm (SBI PSP)",
  ptyes: "Paytm (Yes Bank PSP)",
  upi: "BHIM / NPCI Generic Handle",
  apl: "Amazon Pay (Axis Bank PSP)",
  yapl: "Amazon Pay (Yes Bank PSP)",
  rapl: "Amazon Pay (RBL Bank PSP)",
  icici: "ICICI Bank iMobile",
  hdfcbank: "HDFC Bank UPI",
  sbi: "State Bank of India YONO / BHIM SBI",
  axisbank: "Axis Bank UPI",
  kotak: "Kotak Mahindra Bank UPI",
  indus: "IndusInd Bank UPI",
  idfcbank: "IDFC FIRST Bank UPI",
  fbl: "Federal Bank UPI",
  barodampay: "Bank of Baroda UPI",
  airtel: "Airtel Payments Bank",
  jio: "JioPay UPI",
};

const KNOWN_MCC_CATEGORIES: Record<string, string> = {
  "0000": "Person-to-Person / Unspecified Merchant Category",
  "4814": "Telecommunication Services",
  "4900": "Utilities (Electric, Gas, Water, Sanitary)",
  "5311": "Department Stores",
  "5411": "Grocery Stores & Supermarkets",
  "5499": "Misc. Food Stores / Convenience",
  "5541": "Fuel / Service Stations",
  "5812": "Eating Places & Restaurants",
  "5814": "Fast Food Restaurants",
  "5912": "Drug Stores & Pharmacies",
  "5999": "Miscellaneous Retail Stores",
  "6012": "Financial Institutions",
  "7399": "Business Services",
  "8011": "Doctors & Physicians",
  "8062": "Hospitals",
  "8299": "Schools & Educational Services",
  "9399": "Government Services",
};

const KNOWN_UPI_KEYS = new Set([
  "pa",
  "pn",
  "mc",
  "tid",
  "tr",
  "tn",
  "am",
  "cu",
  "url",
  "mode",
  "orgid",
  "sign",
  "mam",
  "ver",
  "qrMedium",
  "qrmedium",
  "invoiceNo",
  "invoiceno",
  "invoiceDate",
  "invoicedate",
  "gstIn",
  "gstin",
  "purpose",
  "mid",
  "msid",
  "mtid",
]);

function field(label: string, value: string | null, source: DataProvenance): SourcedField {
  return {
    label,
    value,
    displayValue: value && value.trim() ? value.trim() : "Not available in QR.",
    source: value && value.trim() ? source : "Unavailable",
  };
}

function riskLabel(level: RiskCategoryLevel): string {
  if (level === "LOW") return "LOW RISK";
  if (level === "MEDIUM") return "MODERATE RISK";
  if (level === "HIGH") return "HIGH RISK";
  if (level === "CRITICAL") return "CRITICAL RISK";
  return "INCONCLUSIVE";
}

function formatInr(n: number): string {
  return "₹" + n.toLocaleString("en-IN", { maximumFractionDigits: 2 });
}

function maskPreview(raw: string): string {
  return raw.replace(/[\x00-\x1F\x7F]/g, "").slice(0, 260);
}

function parseEmvCoTlv(payload: string): Record<string, string> {
  const tags: Record<string, string> = {};
  let i = 0;
  while (i + 4 <= payload.length) {
    const tag = payload.slice(i, i + 2);
    const lenStr = payload.slice(i + 2, i + 4);
    if (!/^\d{2}$/.test(tag) || !/^\d{2}$/.test(lenStr)) break;
    const len = Number(lenStr);
    const valStart = i + 4;
    const valEnd = valStart + len;
    if (valEnd > payload.length) break;
    tags[tag] = payload.slice(valStart, valEnd);
    i = valEnd;
  }
  return tags;
}

export function extractQrInformation(rawPayloadInput: string): ExtractedQrInfo {
  const cleanRaw = String(rawPayloadInput || "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  const payloadLength = cleanRaw.length;
  const preview = maskPreview(cleanRaw);

  if (!cleanRaw) {
    return buildUnsupportedInfo("malformed", "Empty / Invalid", "Invalid QR", "Malformed", "None", cleanRaw, preview, payloadLength, [
      "QR payload is empty.",
    ]);
  }

  // Case A: Standard or malformed UPI URI
  if (/^upi:\/\//i.test(cleanRaw)) {
    const qIdx = cleanRaw.indexOf("?");
    const routePart = (qIdx >= 0 ? cleanRaw.slice(6, qIdx) : cleanRaw.slice(6)).toLowerCase();
    const queryStr = qIdx >= 0 ? cleanRaw.slice(qIdx + 1) : "";

    if (routePart !== "pay") {
      return buildUnsupportedInfo(
        "unsupported",
        `UPI (${routePart || "unknown"} scheme)`,
        `Unsupported UPI action: upi://${routePart}`,
        "Unsupported",
        `upi://${routePart}`,
        cleanRaw,
        preview,
        payloadLength,
        [`Unsupported UPI operation (${routePart}); only upi://pay is supported for payment inspection.`]
      );
    }

    const params = new URLSearchParams(queryStr);
    const pa = (params.get("pa") || "").trim() || null;
    const pn = (params.get("pn") || "").trim() || null;
    const amRaw = params.get("am");
    const cu = (params.get("cu") || "").trim().toUpperCase() || null;
    const tn = (params.get("tn") || "").trim() || null;
    const tr = (params.get("tr") || "").trim() || null;
    const tid = (params.get("tid") || "").trim() || null;
    const mc = (params.get("mc") || "").trim() || null;
    const mode = (params.get("mode") || "").trim() || null;
    const sign = (params.get("sign") || "").trim() || null;
    const urlParam = (params.get("url") || "").trim() || null;
    const mam = (params.get("mam") || "").trim() || null;
    const expParam =
      (params.get("exp") || params.get("expiry") || params.get("validity") || "").trim() || null;

    const missingOrInvalid: string[] = [];
    const unexpectedParams: string[] = [];
    for (const k of params.keys()) {
      if (!KNOWN_UPI_KEYS.has(k) && !KNOWN_UPI_KEYS.has(k.toLowerCase())) {
        unexpectedParams.push(k);
      }
    }

    const vpaValid = Boolean(pa && /^[a-zA-Z0-9._-]{2,64}@[a-zA-Z0-9.-]{2,32}$/.test(pa));
    if (!pa) {
      missingOrInvalid.push("Payee UPI ID (pa) is missing.");
    } else if (!vpaValid) {
      missingOrInvalid.push("Payee UPI ID (pa) format is invalid.");
    }
    if (!pn) {
      missingOrInvalid.push("Payee name (pn) is missing from QR.");
    }

    let amount: number | null = null;
    let amountState: AmountState = "not_encoded";
    let amountDisplay = "Amount not specified – user must enter the amount in their UPI application.";
    let amountEditability: ExtractedQrInfo["amountEditability"] =
      "No amount encoded; user may enter an amount";

    if (amRaw !== null && amRaw.trim() !== "") {
      const trimmedAm = amRaw.trim();
      const parsed = Number(trimmedAm);
      if (!/^\d+(\.\d{1,2})?$/.test(trimmedAm) || !Number.isFinite(parsed) || parsed <= 0 || parsed > 10_000_000) {
        amountState = "invalid";
        amount = null;
        amountDisplay = "Unable to determine the payment amount.";
        amountEditability = "Amount editability not determinable";
        missingOrInvalid.push("Encoded payment amount (am) is invalid or out of safe numeric format.");
      } else {
        amountState = "fixed";
        amount = parsed;
        amountDisplay = formatInr(parsed);
        if (mam && Number.isFinite(Number(mam)) && Number(mam) > 0 && Number(mam) !== parsed) {
          amountEditability = "Amount editability not determinable";
        } else {
          amountEditability = "Fixed amount encoded in QR";
        }
      }
    }

    const hasDynamicSignals = Boolean(tr || tid || sign || urlParam || mode === "15" || mode === "22");
    const classification: ExtractedQrInfo["classification"] = !vpaValid
      ? "Malformed"
      : hasDynamicSignals
        ? "Dynamic UPI QR"
        : "Static UPI QR";

    const decodingStatus: ExtractedQrInfo["decodingStatus"] = !vpaValid
      ? "malformed"
      : !pn || amountState === "invalid"
        ? "incomplete"
        : "decoded";

    const handleSuffix = pa && pa.includes("@") ? pa.split("@")[1].toLowerCase() : "";
    const providerInferred = handleSuffix && KNOWN_PSP_HANDLES[handleSuffix] ? KNOWN_PSP_HANDLES[handleSuffix] : null;
    const merchantName = mc || tr || mode ? pn : null;

    const paymentFields: SourcedField[] = [
      field("UPI ID / VPA", pa, "Extracted from QR"),
      field("Payee Name", pn, "Extracted from QR"),
      field("Merchant Name", merchantName, merchantName ? "Inferred" : "Unavailable"),
      field(
        "Payment Amount",
        amountState === "fixed" && amount !== null ? formatInr(amount) : amountState === "not_encoded" ? "Not encoded (user enters in UPI app)" : "Invalid amount",
        amountState === "fixed" ? "Extracted from QR" : "Unavailable"
      ),
      field("Currency", cu || (vpaValid ? "INR (UPI default)" : null), cu ? "Extracted from QR" : vpaValid ? "Inferred" : "Unavailable"),
      field("Payment Note", tn, "Extracted from QR"),
      field("Transaction Reference (tr)", tr, "Extracted from QR"),
      field("Transaction ID (tid)", tid, "Extracted from QR"),
      field("Merchant Category Code (MCC)", mc, "Extracted from QR"),
      field("Expiry Information", expParam, "Extracted from QR"),
      field("Payment URI", preview, "Extracted from QR"),
      field("Payment Provider (PSP)", providerInferred, providerInferred ? "Inferred" : "Unavailable"),
      field("Decoded Payload Preview", preview, "Extracted from QR"),
    ];

    const paramList = Array.from(params.keys()).join(", ") || "None";
    const qrFields: SourcedField[] = [
      field("QR Format", "Standard Indian UPI URI", "Extracted from QR"),
      field("QR Type", "UPI Payment Request", "Extracted from QR"),
      field("Static or Dynamic Classification", classification, "Inferred"),
      field("Encoded Payment Parameters", paramList, "Extracted from QR"),
      field(
        "Missing or Invalid Fields",
        missingOrInvalid.length ? missingOrInvalid.join(" | ") : "None detected",
        "Extracted from QR"
      ),
      field("Supported Payment Scheme", "upi://pay", "Extracted from QR"),
      field("QR Decoding Status", decodingStatus, "Extracted from QR"),
    ];

    return {
      decodingStatus,
      qrFormat: "Standard Indian UPI URI",
      qrType: "UPI Payment QR",
      classification,
      supportedScheme: "upi://pay",
      paymentUri: preview,
      rawPayloadPreview: preview,
      payloadLength,
      encodedParametersCount: Array.from(params.keys()).length,
      missingOrInvalidFields: missingOrInvalid,
      upiId: pa,
      payeeName: pn,
      merchantName,
      amount,
      rawAmountParam: amRaw,
      amountState,
      amountDisplay,
      amountEditability,
      currency: cu || (vpaValid ? "INR" : null),
      paymentNote: tn,
      transactionRef: tr,
      transactionId: tid,
      mcc: mc,
      expiryInfo: expParam,
      providerInferred,
      urlHost: urlParam,
      urlString: urlParam,
      unexpectedParams,
      paymentFields,
      qrFields,
    };
  }

  // Case B: EMVCo / BharatQR TLV payload (starts with 000201)
  if (/^000201/.test(cleanRaw)) {
    const tags = parseEmvCoTlv(cleanRaw);
    const pn = tags["59"] || null;
    const mc = tags["52"] || null;
    const amRaw = tags["54"] || null;
    const cuNum = tags["53"] || null;
    const currency = cuNum === "356" ? "INR" : cuNum ? `ISO-4217 (${cuNum})` : null;
    const isDynamic = tags["01"] === "12";
    let amount: number | null = null;
    let amountState: AmountState = "not_encoded";
    let amountDisplay = "Amount not specified – user must enter the amount in their UPI application.";
    let amountEditability: ExtractedQrInfo["amountEditability"] = "No amount encoded; user may enter an amount";
    if (amRaw) {
      const parsed = Number(amRaw);
      if (Number.isFinite(parsed) && parsed > 0 && parsed <= 10_000_000) {
        amount = parsed;
        amountState = "fixed";
        amountDisplay = formatInr(parsed);
        amountEditability = "Fixed amount encoded in QR";
      } else {
        amountState = "invalid";
        amountDisplay = "Unable to determine the payment amount.";
        amountEditability = "Amount editability not determinable";
      }
    }
    const classification = "EMVCo / BharatQR";
    const paymentFields: SourcedField[] = [
      field("UPI ID / VPA", null, "Unavailable"),
      field("Payee Name", pn, "Extracted from QR"),
      field("Merchant Name", pn, "Extracted from QR"),
      field("Payment Amount", amount !== null ? formatInr(amount) : null, amount !== null ? "Extracted from QR" : "Unavailable"),
      field("Currency", currency, currency ? "Inferred" : "Unavailable"),
      field("Payment Note", null, "Unavailable"),
      field("Transaction Reference (tr)", null, "Unavailable"),
      field("Transaction ID (tid)", null, "Unavailable"),
      field("Merchant Category Code (MCC)", mc, "Extracted from QR"),
      field("Expiry Information", null, "Unavailable"),
      field("Payment URI", null, "Unavailable"),
      field("Payment Provider (PSP)", "EMVCo / BharatQR Merchant Network", "Inferred"),
      field("Decoded Payload Preview", preview, "Extracted from QR"),
    ];
    const qrFields: SourcedField[] = [
      field("QR Format", "EMVCo Merchant-Presented QR (BharatQR)", "Extracted from QR"),
      field("QR Type", isDynamic ? "Dynamic Merchant QR" : "Static Merchant QR", "Inferred"),
      field("Static or Dynamic Classification", isDynamic ? "Dynamic UPI QR" : "Static UPI QR", "Inferred"),
      field("Encoded Payment Parameters", Object.keys(tags).join(", "), "Extracted from QR"),
      field("Missing or Invalid Fields", pn ? "None detected" : "Merchant name missing", "Extracted from QR"),
      field("Supported Payment Scheme", "EMVCo TLV", "Extracted from QR"),
      field("QR Decoding Status", "decoded", "Extracted from QR"),
    ];
    return {
      decodingStatus: "decoded",
      qrFormat: "EMVCo / BharatQR",
      qrType: "Merchant Payment QR",
      classification,
      supportedScheme: "EMVCo TLV",
      paymentUri: null,
      rawPayloadPreview: preview,
      payloadLength,
      encodedParametersCount: Object.keys(tags).length,
      missingOrInvalidFields: pn ? [] : ["Merchant name (tag 59) missing"],
      upiId: null,
      payeeName: pn,
      merchantName: pn,
      amount,
      rawAmountParam: amRaw,
      amountState,
      amountDisplay,
      amountEditability,
      currency,
      paymentNote: null,
      transactionRef: null,
      transactionId: null,
      mcc: mc,
      expiryInfo: null,
      providerInferred: "EMVCo / BharatQR Network",
      urlHost: null,
      urlString: null,
      unexpectedParams: [],
      paymentFields,
      qrFields,
    };
  }

  // Case C: External HTTP/HTTPS URL
  if (/^https?:\/\//i.test(cleanRaw)) {
    try {
      const parsedUrl = new URL(cleanRaw);
      const host = parsedUrl.hostname.toLowerCase();
      return {
        decodingStatus: "unsupported",
        qrFormat: "External Web URL",
        qrType: "Web Link (Not a UPI Payment URI)",
        classification: "External Web URL",
        supportedScheme: parsedUrl.protocol.replace(":", ""),
        paymentUri: null,
        rawPayloadPreview: preview,
        payloadLength,
        encodedParametersCount: Array.from(parsedUrl.searchParams.keys()).length,
        missingOrInvalidFields: ["Not a UPI payment URI; payment amount and recipient VPA are unavailable."],
        upiId: null,
        payeeName: null,
        merchantName: null,
        amount: null,
        rawAmountParam: null,
        amountState: "unsupported",
        amountDisplay: "Payment amount information is unavailable for this QR format.",
        amountEditability: "Amount editability not determinable",
        currency: null,
        paymentNote: null,
        transactionRef: null,
        transactionId: null,
        mcc: null,
        expiryInfo: null,
        providerInferred: null,
        urlHost: host,
        urlString: parsedUrl.toString().slice(0, 320),
        unexpectedParams: [],
        paymentFields: [
          field("UPI ID / VPA", null, "Unavailable"),
          field("Payee Name", null, "Unavailable"),
          field("Merchant Name", null, "Unavailable"),
          field("Payment Amount", null, "Unavailable"),
          field("Currency", null, "Unavailable"),
          field("Payment Note", null, "Unavailable"),
          field("External Web Domain", host, "Extracted from QR"),
          field("Decoded Payload Preview", preview, "Extracted from QR"),
        ],
        qrFields: [
          field("QR Format", "Web URL", "Extracted from QR"),
          field("QR Type", "External Website Link", "Extracted from QR"),
          field("Static or Dynamic Classification", "External Web URL", "Extracted from QR"),
          field("Encoded Payment Parameters", "None (HTTP/HTTPS URL)", "Extracted from QR"),
          field("Missing or Invalid Fields", "Not a supported UPI payment scheme", "Extracted from QR"),
          field("Supported Payment Scheme", `${parsedUrl.protocol.replace(":", "")} (non-payment)`, "Extracted from QR"),
          field("QR Decoding Status", "unsupported", "Extracted from QR"),
        ],
      };
    } catch {
      return buildUnsupportedInfo("malformed", "Malformed Web URL", "Invalid URL QR", "Malformed", "http/https", cleanRaw, preview, payloadLength, [
        "QR contains a malformed web URL.",
      ]);
    }
  }

  return buildUnsupportedInfo("unsupported", "Plain Text / Unsupported Format", "Non-Payment QR", "Unsupported", "None", cleanRaw, preview, payloadLength, [
    "QR does not contain a recognised UPI payment URI or web URL.",
  ]);
}

function buildUnsupportedInfo(
  decodingStatus: ExtractedQrInfo["decodingStatus"],
  qrFormat: string,
  qrType: string,
  classification: ExtractedQrInfo["classification"],
  supportedScheme: string,
  _cleanRaw: string,
  preview: string,
  payloadLength: number,
  missingOrInvalidFields: string[]
): ExtractedQrInfo {
  return {
    decodingStatus,
    qrFormat,
    qrType,
    classification,
    supportedScheme,
    paymentUri: null,
    rawPayloadPreview: preview,
    payloadLength,
    encodedParametersCount: 0,
    missingOrInvalidFields,
    upiId: null,
    payeeName: null,
    merchantName: null,
    amount: null,
    rawAmountParam: null,
    amountState: "unsupported",
    amountDisplay: "Payment amount information is unavailable for this QR format.",
    amountEditability: "Amount editability not determinable",
    currency: null,
    paymentNote: null,
    transactionRef: null,
    transactionId: null,
    mcc: null,
    expiryInfo: null,
    providerInferred: null,
    urlHost: null,
    urlString: null,
    unexpectedParams: [],
    paymentFields: [
      field("UPI ID / VPA", null, "Unavailable"),
      field("Payee Name", null, "Unavailable"),
      field("Merchant Name", null, "Unavailable"),
      field("Payment Amount", null, "Unavailable"),
      field("Decoded Payload Preview", preview, "Extracted from QR"),
    ],
    qrFields: [
      field("QR Format", qrFormat, "Extracted from QR"),
      field("QR Type", qrType, "Extracted from QR"),
      field("Static or Dynamic Classification", classification, "Inferred"),
      field("Missing or Invalid Fields", missingOrInvalidFields.join(" | "), "Extracted from QR"),
      field("Supported Payment Scheme", supportedScheme, "Extracted from QR"),
      field("QR Decoding Status", decodingStatus, "Extracted from QR"),
    ],
  };
}

export async function analyzeMerchantAndRecipient(extracted: ExtractedQrInfo): Promise<MerchantIntelligence> {
  const upiLocal = extracted.upiId ? extracted.upiId.split("@")[0].toLowerCase() : "";
  const pn = extracted.payeeName || "";
  const mn = extracted.merchantName || "";
  const pnClean = pn.toLowerCase().replace(/[^a-z0-9]/g, "");
  const upiLocalClean = upiLocal.replace(/[^a-z0-9]/g, "");

  let nameMismatchDetected = false;
  let mismatchReason: string | null = null;
  const impersonationIndicators: string[] = [];

  if (extracted.upiId && pn) {
    // Check obvious brand/authority claim vs generic handle or mismatch
    const authorityClaim = /(sbi|hdfc|icici|axis|rbi|npci|paytm|phonepe|gpay|police|cyber|income.?tax|customs|support|helpdesk|customer.?care|kyc)/i.test(
      pn
    );
    const localHasWord = pnClean.length >= 4 && upiLocalClean.length >= 4;
    if (authorityClaim && !/(bank|gov|nic|sbi|hdfc|icici|axis|paytm|phonepe)/i.test(upiLocal)) {
      nameMismatchDetected = true;
      mismatchReason = `Payee name ("${pn}") claims an official/bank/support identity, while the UPI ID local handle ("${upiLocal}") does not match an official institutional identifier.`;
      impersonationIndicators.push("Official/support payee name paired with unrelated UPI handle");
    } else if (
      localHasWord &&
      !/^\d+$/.test(upiLocalClean) &&
      !upiLocalClean.includes(pnClean.slice(0, 4)) &&
      !pnClean.includes(upiLocalClean.slice(0, 4)) &&
      /(refund|prize|lottery|claim|help|desk|support|verify|kyc)/i.test(upiLocal)
    ) {
      nameMismatchDetected = true;
      mismatchReason = `Payee name ("${pn}") appears inconsistent with suspicious handle keywords in "${extracted.upiId}".`;
    }
  }

  // Internal unverified community scam report check (never treated as verified fraud database)
  let communityMatchMsg: string | null = null;
  if (extracted.upiId) {
    const reports = (await db
      .prepare("SELECT masked_excerpt, cat FROM scam_reports ORDER BY created_at DESC LIMIT 50")
      .all()) as { masked_excerpt: string; cat: string }[];
    const handleToken = upiLocal.length >= 4 ? upiLocal : "";
    if (handleToken && reports.some((r) => r.masked_excerpt.toLowerCase().includes(handleToken))) {
      communityMatchMsg = "Unverified internal community report mentions a similar identifier fragment (requires independent verification).";
    }
  }

  const mccDesc = extracted.mcc
    ? KNOWN_MCC_CATEGORIES[extracted.mcc]
      ? `MCC ${extracted.mcc}: ${KNOWN_MCC_CATEGORIES[extracted.mcc]}`
      : `MCC ${extracted.mcc} (category label unmapped)`
    : null;

  return {
    upiId: field("Recipient UPI ID", extracted.upiId, "Extracted from QR"),
    payeeName: field("Payee Name", extracted.payeeName, "Extracted from QR"),
    merchantName: field("Merchant Name", extracted.merchantName, extracted.merchantName ? "Inferred" : "Unavailable"),
    merchantCategory: field("Merchant Category", mccDesc, mccDesc ? "Inferred" : "Unavailable"),
    paymentProvider: field(
      "Payment Provider",
      extracted.providerInferred,
      extracted.providerInferred ? "Inferred" : "Unavailable"
    ),
    verifiedIdentity: {
      label: "Independently Verified Identity",
      value: null,
      displayValue: "Independent merchant verification is currently unavailable.",
      source: "Unavailable",
    },
    reputationInfo: {
      label: "Reputation Information",
      value: null,
      displayValue: "External merchant reputation lookup is currently unavailable.",
      source: "Unavailable",
    },
    fraudReportsInfo: {
      label: "Known Fraud Reports",
      value: communityMatchMsg,
      displayValue: communityMatchMsg || "External fraud-report registry is currently unavailable; no confirmed reports verified.",
      source: communityMatchMsg ? "Unverified" : "Unavailable",
    },
    nameMismatchDetected,
    mismatchReason,
    impersonationIndicators,
    externalVerification: {
      service: "Independent Merchant & VPA Verification Registry",
      available: false,
      status: "unavailable",
      message: "Independent merchant verification is currently unavailable.",
    },
  };
}

export function analyzeQrSecurity(
  extracted: ExtractedQrInfo,
  merchant: MerchantIntelligence
): QrSecurityAnalysis {
  const findings: SecurityFinding[] = [];
  let score = 0;

  // Notice: Payment amount size NEVER increases QR security risk score here (kept strictly separate!)
  if (extracted.decodingStatus === "malformed") {
    score += 65;
    findings.push({
      severity: "HIGH",
      title: "Malformed payment URI or invalid identifier",
      evidence: extracted.missingOrInvalidFields.join(" ") || "Malformed QR payload",
      reasoning: "Malformed payment URIs or broken UPI identifiers can indicate tampered or unsafe QR payloads.",
    });
  } else if (extracted.decodingStatus === "unsupported" && extracted.classification === "External Web URL") {
    score += 40;
    const host = extracted.urlHost || "";
    findings.push({
      severity: "MEDIUM",
      title: "QR opens an external website instead of a UPI payment",
      evidence: `Domain: ${host}`,
      reasoning: "Scanning a QR expecting a payment that actually points to a web link is a common phishing vector.",
    });

    if (/^(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|wa\.me)$/.test(host)) {
      score += 25;
      findings.push({
        severity: "HIGH",
        title: "URL shortener hides final destination",
        evidence: `Shortened host: ${host}`,
        reasoning: "Shortened links conceal where the user will be redirected.",
      });
    }
    if (/^http:\/\//i.test(extracted.urlString || "")) {
      score += 15;
      findings.push({
        severity: "MEDIUM",
        title: "Unencrypted HTTP link",
        evidence: "Scheme uses http:// instead of https://",
        reasoning: "Legitimate banking and merchant portals use encrypted HTTPS connections.",
      });
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("xn--")) {
      score += 30;
      findings.push({
        severity: "HIGH",
        title: "Raw IP address or Punycode lookalike domain",
        evidence: `Host: ${host}`,
        reasoning: "Fraudulent sites often use raw IP addresses or internationalized lookalike characters.",
      });
    }
    if (/sbi|hdfc|icici|axis|paytm|phonepe|gpay|kyc|refund|rbi|npci/.test(host) && !/\.(gov\.in|nic\.in|sbi\.co\.in|hdfcbank\.com|icicibank\.com)$/.test(host)) {
      score += 25;
      findings.push({
        severity: "HIGH",
        title: "Possible bank or payment-brand impersonation domain",
        evidence: `Domain contains financial brand keyword: ${host}`,
        reasoning: "Verify official bank domains independently rather than trusting a QR link.",
      });
    }
    if (extracted.urlString && /[?&](redirect|next|url|target|continue)=/i.test(extracted.urlString)) {
      score += 15;
      findings.push({
        severity: "MEDIUM",
        title: "Unexpected redirection parameter inside URL",
        evidence: "Query string contains redirection parameter",
        reasoning: "Open-redirect parameters can bounce users to malicious pages after clicking.",
      });
    }
  } else if (extracted.decodingStatus === "unsupported") {
    findings.push({
      severity: "LOW",
      title: "Unsupported or non-payment QR format",
      evidence: `Format: ${extracted.qrFormat}`,
      reasoning: "Insufficient structured payment data to evaluate UPI fraud indicators.",
    });
  }

  // UPI-specific security checks
  const combinedText = `${extracted.upiId || ""} ${extracted.payeeName || ""} ${extracted.paymentNote || ""}`;
  if (/refund|receive|prize|lottery|cashback|claim|reward|bonus/i.test(combinedText)) {
    score += 45;
    findings.push({
      severity: "HIGH",
      title: "QR mentions refund, prize, lottery, or cashback",
      evidence: `Matched text in payee/note/UPI ID (${extracted.paymentNote || extracted.payeeName || extracted.upiId})`,
      reasoning: "Scanning a UPI QR only sends money out of your account. You never scan a QR or enter a UPI PIN to receive a refund or prize.",
    });
  }

  if (/kyc|blocked|suspend|urgent|penalty|fine|customs|arrest|court|processing fee|verification fee/i.test(combinedText)) {
    score += 35;
    findings.push({
      severity: "HIGH",
      title: "Urgency, KYC, or fee pressure keywords in QR fields",
      evidence: `Payment note / label: "${extracted.paymentNote || extracted.payeeName || ""}"`,
      reasoning: "Scammers embed fear-inducing or fee pretext descriptions to rush victims into paying.",
    });
  }

  if (extracted.upiId && !extracted.payeeName) {
    score += 15;
    findings.push({
      severity: "MEDIUM",
      title: "Missing payee / merchant name (pn) in UPI QR",
      evidence: `UPI ID ${extracted.upiId} has no payee name parameter`,
      reasoning: "Without a payee name encoded in the QR, the recipient identity is even less transparent before opening a payment app.",
    });
  }

  if (merchant.nameMismatchDetected && merchant.mismatchReason) {
    score += 35;
    findings.push({
      severity: "HIGH",
      title: "Merchant / recipient name mismatch or impersonation cue",
      evidence: merchant.mismatchReason,
      reasoning: "Institutional names paired with mismatched consumer UPI handles are a strong impersonation warning.",
    });
  }

  if (extracted.unexpectedParams.length > 0) {
    score += 15;
    findings.push({
      severity: "MEDIUM",
      title: "Unexpected URI parameters present",
      evidence: `Extra keys: ${extracted.unexpectedParams.join(", ")}`,
      reasoning: "Non-standard query parameters can indicate tampered or non-compliant payment links.",
    });
  }

  if (extracted.urlHost && extracted.supportedScheme === "upi://pay") {
    score += 15;
    findings.push({
      severity: "MEDIUM",
      title: "UPI QR includes an external reference URL",
      evidence: `URL parameter: ${extracted.urlHost}`,
      reasoning: "Verify whether an external URL attached to a UPI QR belongs to an official merchant.",
    });
  }

  if (extracted.amountState === "invalid") {
    score += 20;
    findings.push({
      severity: "MEDIUM",
      title: "Invalid or malformed amount parameter",
      evidence: `Raw am parameter: ${extracted.rawAmountParam || "invalid"}`,
      reasoning: "Tampered or malformed numeric amounts indicate a broken or manipulated QR payload.",
    });
  }

  if (merchant.fraudReportsInfo.source === "Unverified" && merchant.fraudReportsInfo.value) {
    score += 20;
    findings.push({
      severity: "MEDIUM",
      title: "Unverified local report mentions similar identifier",
      evidence: merchant.fraudReportsInfo.value,
      reasoning: "A prior user-submitted report contained a matching identifier fragment; external verification remains unavailable.",
    });
  }

  score = Math.min(100, score);

  let level: RiskCategoryLevel;
  if (extracted.decodingStatus === "unsupported" && extracted.classification === "Unsupported") {
    level = "INCONCLUSIVE";
  } else if (score >= 75) {
    level = "CRITICAL";
  } else if (score >= 45) {
    level = "HIGH";
  } else if (score >= 20) {
    level = "MEDIUM";
  } else {
    level = "LOW";
  }

  if (findings.length === 0 && level === "LOW") {
    findings.push({
      severity: "LOW",
      title: "No structural or keyword fraud indicators detected",
      evidence: "UPI URI structure and parameters parsed cleanly",
      reasoning: "Even when no rule warning triggers, external merchant verification is unavailable and QR validity never guarantees recipient trustworthiness.",
    });
  }

  const summary =
    level === "INCONCLUSIVE"
      ? "Insufficient structured payment information to evaluate UPI QR security indicators."
      : level === "CRITICAL"
        ? "Strong evidence of suspicious or manipulated QR indicators detected."
        : level === "HIGH"
          ? "Significant suspicious QR indicators detected. Do not pay without independent verification."
          : level === "MEDIUM"
            ? "Some QR details require independent verification before proceeding."
            : "No significant QR structure or keyword warnings identified, though recipient identity remains unverified.";

  return {
    riskLevel: level,
    riskLabel: riskLabel(level),
    score,
    findings,
    externalFraudIntel: {
      service: "External Fraud-Intelligence Feed",
      available: false,
      status: "unavailable",
      message: "External fraud-intelligence service is currently unavailable.",
    },
    summary,
  };
}

export async function analyzePaymentLoad(
  extracted: ExtractedQrInfo,
  userId: string,
  thresholds: LoadThresholds
): Promise<PaymentLoadAnalysis> {
  const priorAssessments = (await db
    .prepare("SELECT amount, beneficiary, created_at FROM payment_assessments WHERE user_id = ? ORDER BY created_at DESC LIMIT 30")
    .all(userId)) as { amount: number; beneficiary: string; created_at: number }[];

  const priorScansWithAmount = (await db
    .prepare("SELECT amount, upi_id, created_at FROM qr_scan_records WHERE user_id = ? AND amount IS NOT NULL ORDER BY created_at DESC LIMIT 30")
    .all(userId)) as { amount: number; upi_id: string | null; created_at: number }[];

  const historicalMsg =
    "Historical completed bank/UPI transaction comparison cannot be performed because no authorised bank transaction-history integration is connected.";

  if (extracted.amountState !== "fixed" || extracted.amount === null) {
    const isNotEncoded = extracted.amountState === "not_encoded";
    return {
      requestedAmount: null,
      amountDisplay: extracted.amountDisplay,
      loadCategory: "Not Classified",
      loadRiskLevel: "INCONCLUSIVE",
      loadRiskLabel: riskLabel("INCONCLUSIVE"),
      configuredThresholds: thresholds,
      exceedsPaymentLimit: null,
      excessAmount: null,
      authorisedTransactionHistoryAvailable: false,
      historicalComparisonMessage: historicalMsg,
      priorAssessmentsCount: priorAssessments.length,
      priorScansWithAmountCount: priorScansWithAmount.length,
      similarPatternCount: 0,
      cumulativeRecordedExposure: 0,
      unusualAmountSpike: false,
      explanationAnswers: {
        requestedAmountText: isNotEncoded
          ? "No fixed amount is encoded; you would have to type the amount yourself in your UPI app."
          : "No valid payment amount could be read from this QR.",
        loadCategoryText: isNotEncoded
          ? "Payment load cannot be classified because no amount is encoded."
          : "Payment load cannot be classified for this QR format.",
        exceedsThresholdText: "Cannot compare against the parent-configured limit without an encoded amount.",
        historicalComparisonText: historicalMsg,
        repeatedRequestsText: `Recorded scan/assessment logs show ${priorAssessments.length} prior payment checks and ${priorScansWithAmount.length} prior fixed-amount QR scans (scans do not prove completed payments).`,
        cumulativeExposureText: "Cumulative exposure cannot be calculated when the QR leaves the amount blank.",
        whyPayAttentionText: isNotEncoded
          ? "Open-amount QRs let a caller instruct you to type a larger sum during a live call. Double-check the exact amount before entering your PIN anywhere."
          : "Verify what this QR actually links to before taking any action.",
        recommendedActionText: "Confirm the exact expected amount and recipient independently with your family guardian before entering any amount in a payment app.",
      },
    };
  }

  const amt = extracted.amount;
  let category: PaymentLoadCategory;
  let loadRiskLevel: RiskCategoryLevel;
  if (amt <= thresholds.moderateMax) {
    category = "Low Payment Load";
    loadRiskLevel = "LOW";
  } else if (amt <= thresholds.highMax) {
    category = "Moderate Payment Load";
    loadRiskLevel = "MEDIUM";
  } else if (amt <= thresholds.veryHighMin) {
    category = "High Payment Load";
    loadRiskLevel = "HIGH";
  } else {
    category = "Very High Payment Load";
    loadRiskLevel = "CRITICAL";
  }

  const exceedsLimit = amt > thresholds.paymentLimit;
  const excessAmount = exceedsLimit ? Math.round((amt - thresholds.paymentLimit) * 100) / 100 : 0;

  const last7dCutoff = Date.now() - 7 * 86_400_000;
  const recentScans = priorScansWithAmount.filter((s) => s.created_at >= last7dCutoff);
  const similarPatternCount = recentScans.filter(
    (s) => Math.abs(s.amount - amt) <= Math.max(100, amt * 0.1) || (extracted.upiId && s.upi_id === extracted.upiId)
  ).length;
  const cumulativeRecordedExposure =
    amt + recentScans.reduce((acc, s) => acc + (Number.isFinite(s.amount) ? s.amount : 0), 0);

  const avgPriorScan =
    recentScans.length > 0 ? recentScans.reduce((a, s) => a + s.amount, 0) / recentScans.length : null;
  const unusualAmountSpike = avgPriorScan !== null && avgPriorScan > 0 && amt >= avgPriorScan * 2.5 && amt > thresholds.moderateMax;

  return {
    requestedAmount: amt,
    amountDisplay: formatInr(amt),
    loadCategory: category,
    loadRiskLevel,
    loadRiskLabel: riskLabel(loadRiskLevel),
    configuredThresholds: thresholds,
    exceedsPaymentLimit: exceedsLimit,
    excessAmount,
    authorisedTransactionHistoryAvailable: false,
    historicalComparisonMessage: historicalMsg,
    priorAssessmentsCount: priorAssessments.length,
    priorScansWithAmountCount: priorScansWithAmount.length,
    similarPatternCount,
    cumulativeRecordedExposure: Math.round(cumulativeRecordedExposure * 100) / 100,
    unusualAmountSpike,
    explanationAnswers: {
      requestedAmountText: `The QR requests ${formatInr(amt)} (fixed encoded amount).`,
      loadCategoryText: `Based on parent-configured thresholds, this is classified as ${category}.`,
      exceedsThresholdText: exceedsLimit
        ? `Yes — ${formatInr(amt)} exceeds the configured safety limit of ${formatInr(thresholds.paymentLimit)} by ${formatInr(excessAmount)}.`
        : `No — ${formatInr(amt)} is within the configured safety limit of ${formatInr(thresholds.paymentLimit)}.`,
      historicalComparisonText: historicalMsg,
      repeatedRequestsText:
        similarPatternCount > 0
          ? `${similarPatternCount} prior fixed-amount QR scan(s) with a similar amount or recipient were logged in the last 7 days (Note: repeated scans do not prove completed payments).`
          : `No similar fixed-amount QR scans were logged in the last 7 days (${priorAssessments.length} total recorded payment assessments).`,
      cumulativeExposureText: `If this request plus ${recentScans.length} recent fixed-amount QR scan(s) from the past 7 days were all paid, total potential exposure would be ${formatInr(cumulativeRecordedExposure)} (assuming none were duplicates already skipped).`,
      whyPayAttentionText: exceedsLimit
        ? "Large one-time or repeated high-load transfers carry greater financial impact and deserve an unhurried family confirmation."
        : "Even moderate amounts warrant checking the recipient name and payment purpose before confirming.",
      recommendedActionText: exceedsLimit
        ? "Pause and request guardian review or call a trusted family member on a saved number before making any transfer."
        : "Confirm the bill or merchant expectation independently before proceeding in your UPI app.",
    },
  };
}

export async function inspectDuplicateQr(
  rawPayload: string,
  extracted: ExtractedQrInfo,
  userId: string
): Promise<DuplicateQrStatus> {
  const normalized = rawPayload.trim();
  const payloadHash = sha256(normalized);

  const exactMatches = (await db
    .prepare(
      `SELECT payee_name, upi_id, amount, created_at
       FROM qr_scan_records
       WHERE user_id = ? AND payload_hash = ?
       ORDER BY created_at ASC`
    )
    .all(userId, payloadHash)) as {
    payee_name: string | null;
    upi_id: string | null;
    amount: number | null;
    created_at: number;
  }[];

  let sameMerchantDifferentQrCount = 0;
  const changesDetected: string[] = [];

  if (extracted.upiId) {
    const diffRows = (await db
      .prepare(
        `SELECT payee_name, amount, created_at
         FROM qr_scan_records
         WHERE user_id = ? AND upi_id = ? AND payload_hash != ?
         ORDER BY created_at DESC LIMIT 10`
      )
      .all(userId, extracted.upiId, payloadHash)) as {
      payee_name: string | null;
      amount: number | null;
      created_at: number;
    }[];
    sameMerchantDifferentQrCount = diffRows.length;
    if (diffRows.length > 0) {
      const prev = diffRows[0];
      if (prev.amount !== extracted.amount) {
        changesDetected.push(
          `Different QR payload from same UPI ID: previous scan requested ${prev.amount !== null ? formatInr(prev.amount) : "no fixed amount"}, current requests ${extracted.amount !== null ? formatInr(extracted.amount) : "no fixed amount"}.`
        );
      }
      if ((prev.payee_name || "") !== (extracted.payeeName || "")) {
        changesDetected.push(
          `Payee name changed across payloads for this UPI ID (${prev.payee_name || "none"} -> ${extracted.payeeName || "none"}).`
        );
      }
    }
  }

  const isDuplicate = exactMatches.length > 0;
  const first = exactMatches[0];
  const last = exactMatches[exactMatches.length - 1];

  return {
    payloadHash,
    isDuplicate,
    previousScanCount: exactMatches.length,
    totalScansIncludingCurrent: exactMatches.length + 1,
    firstScanAt: first ? first.created_at : null,
    mostRecentPreviousScanAt: last ? last.created_at : null,
    previousRecipientName: last ? last.payee_name : null,
    previousUpiId: last ? last.upi_id : null,
    previousAmount: last ? last.amount : null,
    currentAmount: extracted.amount,
    changesDetected,
    sameMerchantDifferentQrCount,
    note: isDuplicate
      ? `Exact same QR payload was scanned ${exactMatches.length} time(s) previously. Repeated scans do not prove repeated payments were made.`
      : sameMerchantDifferentQrCount > 0
        ? `This exact QR payload is new, though ${sameMerchantDifferentQrCount} different QR code(s) for ${extracted.upiId} were scanned earlier (not treated as a duplicate QR).`
        : "First time this QR payload has been scanned under your current retention window.",
  };
}

function buildFallbackAiReport(
  extracted: ExtractedQrInfo,
  merchant: MerchantIntelligence,
  security: QrSecurityAnalysis,
  load: PaymentLoadAnalysis,
  dup: DuplicateQrStatus,
  errorReason: string
): FullQrIntelligenceReport["aiReport"] {
  const warnings: string[] = [];
  for (const f of security.findings.slice(0, 2)) {
    if (f.severity !== "LOW") warnings.push(`${f.title}: ${f.reasoning}`);
  }
  if (load.exceedsPaymentLimit) {
    warnings.push(
      `Requested amount (${load.amountDisplay}) exceeds your configured limit of ${formatInr(load.configuredThresholds.paymentLimit)}.`
    );
  }
  if (dup.isDuplicate) {
    warnings.push("This exact QR payload has been scanned before. Confirm no earlier payment was already sent.");
  }
  if (warnings.length === 0) {
    warnings.push("External merchant verification is unavailable; a clean QR syntax check never guarantees safety.");
  }

  return {
    available: false,
    model: null,
    amountExplanation:
      extracted.amountState === "fixed"
        ? `This QR requests a fixed payment of ${extracted.amountDisplay}.`
        : extracted.amountDisplay,
    safetySummary: `${security.summary} Payment load status: ${load.loadCategory}.`,
    importantWarnings: warnings.slice(0, 4),
    recommendedPrecautions: [
      "Verify the recipient name and reason for payment through a trusted saved phone number.",
      "Remember: scanning a QR or entering a UPI PIN always sends money—never receives a refund or prize.",
      "If pressured to pay urgently, pause and consult your family guardian.",
    ],
    uncertaintyStatement:
      "Live Gemini AI explanation is unavailable right now, and independent merchant verification and bank history remain unavailable.",
    errorReason,
  };
}

async function triggerQrNotifications(params: {
  parentId: string;
  parentName: string;
  extracted: ExtractedQrInfo;
  security: QrSecurityAnalysis;
  load: PaymentLoadAnalysis;
  dup: DuplicateQrStatus;
  merchant: MerchantIntelligence;
  aiSummary: string;
}): Promise<ParentNotificationDelivery> {
  const consent = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(params.parentId)) as { guardian_alerts: number; paused: number } | undefined;

  const consentEnabled = Boolean(consent?.guardian_alerts);
  const monitoringPaused = Boolean(consent?.paused);
  const guardians = await getActiveGuardiansForParent(params.parentId);

  const triggers: string[] = ["qr_scan_notify"];
  if (params.security.riskLevel === "HIGH") triggers.push("high_risk_qr_alert");
  if (params.security.riskLevel === "CRITICAL") triggers.push("critical_risk_qr_alert");
  if (params.load.exceedsPaymentLimit) triggers.push("high_amount_alert");
  if (params.load.loadCategory === "Very High Payment Load") triggers.push("very_high_load_alert");
  if (params.dup.isDuplicate) triggers.push("repeated_qr_alert");
  if (
    !params.extracted.payeeName ||
    params.merchant.nameMismatchDetected ||
    params.merchant.impersonationIndicators.length > 0
  ) {
    triggers.push("merchant_warning_alert");
  }
  if (["MEDIUM", "HIGH", "CRITICAL"].includes(params.security.riskLevel)) {
    triggers.push("suspicious_qr_alert");
  }

  if (monitoringPaused) {
    return {
      consentEnabled,
      monitoringPaused: true,
      linkedGuardiansCount: guardians.length,
      triggeredEvents: triggers,
      notificationsSentCount: 0,
      suppressedReasons: ["All monitoring is paused in parent Settings."],
      statusMessage: "Notifications suppressed: monitoring is currently paused by parent consent.",
    };
  }

  if (!consentEnabled) {
    return {
      consentEnabled: false,
      monitoringPaused: false,
      linkedGuardiansCount: guardians.length,
      triggeredEvents: triggers,
      notificationsSentCount: 0,
      suppressedReasons: ["Guardian alerts consent toggle is turned off."],
      statusMessage: "Notifications disabled: guardian alerts are turned off in Privacy & Consent settings.",
    };
  }

  if (guardians.length === 0) {
    return {
      consentEnabled: true,
      monitoringPaused: false,
      linkedGuardiansCount: 0,
      triggeredEvents: triggers,
      notificationsSentCount: 0,
      suppressedReasons: ["No active linked guardian accounts."],
      statusMessage: "No linked guardians found to notify. Invite a guardian in Family Management.",
    };
  }

  let sentCount = 0;
  const suppressedReasons: string[] = [];
  const recipientLabel = params.extracted.payeeName || params.extracted.merchantName || "Unnamed recipient";
  const upiLabel = params.extracted.upiId || "N/A";
  const amtLabel = params.load.requestedAmount !== null ? params.load.amountDisplay : "Not specified";

  for (const g of guardians) {
    const prefs = await ensureDefaultQrNotificationPrefs(g.guardian_id);
    const matchedForGuardian: string[] = [];
    if (prefs.qrScanNotify) matchedForGuardian.push("QR scanned");
    if (prefs.highRiskQrAlert && params.security.riskLevel === "HIGH") matchedForGuardian.push("High-risk QR");
    if (prefs.criticalRiskQrAlert && params.security.riskLevel === "CRITICAL") matchedForGuardian.push("Critical-risk QR");
    if (prefs.highAmountAlert && params.load.exceedsPaymentLimit) matchedForGuardian.push("High amount exceeds limit");
    if (prefs.veryHighLoadAlert && params.load.loadCategory === "Very High Payment Load") matchedForGuardian.push("Very high payment load");
    if (prefs.repeatedQrAlert && params.dup.isDuplicate) matchedForGuardian.push("Repeated QR scan");
    if (
      prefs.merchantWarningAlert &&
      (!params.extracted.payeeName || params.merchant.nameMismatchDetected || params.merchant.impersonationIndicators.length > 0)
    ) {
      matchedForGuardian.push("Merchant warning");
    }
    if (prefs.suspiciousQrAlert && ["MEDIUM", "HIGH", "CRITICAL"].includes(params.security.riskLevel)) {
      matchedForGuardian.push("Suspicious QR");
    }

    if (matchedForGuardian.length === 0) {
      suppressedReasons.push(`Skipped ${g.name} (matching alert categories are disabled in their preferences).`);
      continue;
    }

    const title = `QR Intelligence Alert (${params.security.riskLabel}) — ${params.parentName}`;
    const body = `${matchedForGuardian.join(", ")} | Recipient: ${recipientLabel} (${upiLabel}) | Amount: ${amtLabel} | Load: ${params.load.loadCategory}. ${params.aiSummary.slice(0, 90)}`;
    await createNotification(g.guardian_id, params.parentId, "qr_intelligence_alert", title, body);
    sentCount++;
  }

  return {
    consentEnabled: true,
    monitoringPaused: false,
    linkedGuardiansCount: guardians.length,
    triggeredEvents: triggers,
    notificationsSentCount: sentCount,
    suppressedReasons,
    statusMessage:
      sentCount > 0
        ? `Alert delivered to ${sentCount} linked guardian account(s) (${new Date().toLocaleTimeString()}).`
        : "No notification sent because enabled guardian alert preferences did not match this scan.",
  };
}

export async function runFullQrIntelligencePipeline(params: {
  userId: string;
  userName: string;
  rawPayload: string;
  lang: string;
}): Promise<FullQrIntelligenceReport> {
  await ensureDefaultConsent(params.userId);
  const consentRow = (await db.prepare("SELECT * FROM consents WHERE user_id = ?").get(params.userId)) as Record<
    string,
    number
  >;

  const thresholds: LoadThresholds = {
    paymentLimit: Number(consentRow.payment_limit || 10000),
    moderateMax: Number(consentRow.load_moderate_max || 2000),
    highMax: Number(consentRow.load_high_max || 10000),
    veryHighMin: Number(consentRow.load_very_high_min || 25000),
  };

  // Stage A: Pure extraction
  const extracted = extractQrInformation(params.rawPayload);
  // Stage B: Merchant & Recipient Intelligence
  const merchant = await analyzeMerchantAndRecipient(extracted);
  // Stage C: Independent Security & Fraud Detection
  const security = analyzeQrSecurity(extracted, merchant);
  // Stage D: Independent Payment Load Analysis
  const paymentLoad = await analyzePaymentLoad(extracted, params.userId, thresholds);
  // Stage E: Duplicate QR Inspection (before inserting current record)
  const duplicateStatus = await inspectDuplicateQr(params.rawPayload, extracted, params.userId);
  // Stage E2: Query GCIH cross-section shared entities (e.g. suspicious UPI/URL/merchant previously spotted in SMS/Payment/Call)
  const qrCandidates = extractEntitiesFromQrPayload({
    rawPayload: params.rawPayload,
    upiId: extracted.upiId,
    payeeName: extracted.payeeName,
    merchantName: extracted.merchantName,
    urlString: extracted.urlString,
    urlHost: extracted.urlHost,
    payloadHash: duplicateStatus.payloadHash,
  });
  const sharedIntelligence = await lookupSharedEntitiesForQuery({
    familyOwnerId: params.userId,
    candidates: qrCandidates,
    currentSection: "qr_scam",
  });
  for (const sItem of sharedIntelligence) {
    if (
      sItem.verificationStatus === "High risk" ||
      sItem.verificationStatus === "Confirmed malicious" ||
      sItem.verificationStatus === "Suspicious"
    ) {
      const boost = sItem.verificationStatus === "Suspicious" ? 20 : 35;
      security.score = Math.min(100, Math.max(security.score + boost, boost === 35 ? 65 : 40));
      security.findings.push({
        severity: sItem.verificationStatus === "Suspicious" ? "MEDIUM" : "HIGH",
        title: `Shared family intelligence warning (${sItem.entityType})`,
        evidence: `${sItem.maskedDisplay} · ${sItem.verificationStatus} (from ${sItem.sourceModules.join(", ")})`,
        reasoning: sItem.reasonForSharing,
      });
    } else if (sItem.verificationStatus === "Verified legitimate") {
      security.findings.push({
        severity: "LOW",
        title: `Verified legitimate in family history (${sItem.entityType})`,
        evidence: `${sItem.maskedDisplay} marked Verified legitimate`,
        reasoning: sItem.reasonForSharing,
      });
    }
  }
  if (security.score >= 75) {
    security.riskLevel = "CRITICAL";
    security.riskLabel = "Critical Risk";
  } else if (security.score >= 50) {
    security.riskLevel = "HIGH";
    security.riskLabel = "High Risk";
  } else if (security.score >= 25 && security.riskLevel === "LOW") {
    security.riskLevel = "MEDIUM";
    security.riskLabel = "Medium Risk";
  }

  // Stage F: Structured AI Safety Explanation (interprets ONLY validated backend facts)
  let aiReport: FullQrIntelligenceReport["aiReport"];
  try {
    const structuredFacts = {
      qrFormat: extracted.qrFormat,
      classification: extracted.classification,
      decodingStatus: extracted.decodingStatus,
      upiIdPresent: Boolean(extracted.upiId),
      payeeName: extracted.payeeName || "Not available in QR",
      providerInferred: extracted.providerInferred || "Unavailable",
      amountState: extracted.amountState,
      amountDisplay: extracted.amountDisplay,
      amountEditability: extracted.amountEditability,
      paymentLoadCategory: paymentLoad.loadCategory,
      exceedsConfiguredLimit: paymentLoad.exceedsPaymentLimit,
      securityRiskLevel: security.riskLabel,
      securityFindings: security.findings.map((f) => `${f.severity}: ${f.title} (${f.reasoning})`),
      merchantNameMismatch: merchant.nameMismatchDetected,
      externalVerificationAvailable: false,
      authorisedTransactionHistoryAvailable: false,
      isDuplicateQr: duplicateStatus.isDuplicate,
      previousScansCount: duplicateStatus.previousScanCount,
    };

    const aiOut = await generateQrIntelligenceWithGemini({
      structuredFacts,
      lang: params.lang,
    });
    aiReport = {
      available: true,
      model: "gemini-4-hydrogen",
      ...aiOut,
    };
  } catch (err) {
    const reason = err instanceof Error ? err.message : "Live AI service unavailable";
    aiReport = buildFallbackAiReport(extracted, merchant, security, paymentLoad, duplicateStatus, reason);
  }

  // Overall assessment keeping Security Risk and Load Risk distinct
  const rank: Record<RiskCategoryLevel, number> = {
    LOW: 1,
    INCONCLUSIVE: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5,
  };
  const combinedLevel =
    rank[security.riskLevel] >= rank[paymentLoad.loadRiskLevel]
      ? security.riskLevel
      : paymentLoad.loadRiskLevel;

  const overallSummary = `QR Security Risk is ${security.riskLabel} (${security.findings.length} finding(s)), while Payment Load Risk is ${paymentLoad.loadRiskLabel} (${paymentLoad.loadCategory}). Neither metric overrides the other.`;

  const parentNotifications = await triggerQrNotifications({
    parentId: params.userId,
    parentName: params.userName,
    extracted,
    security,
    load: paymentLoad,
    dup: duplicateStatus,
    merchant,
    aiSummary: aiReport.safetySummary,
  });

  const scanId = generateId("qri");
  const now = Date.now();

  const qrLoadCategoryMessage =
    extracted.amountState === "fixed"
      ? `Classified as ${paymentLoad.loadCategory} under parent-configured thresholds.`
      : extracted.amountState === "not_encoded"
        ? "Payment load cannot be classified because no amount is encoded."
        : "Payment load cannot be classified because no valid amount is encoded.";

  const encodedDetailsSummary =
    extracted.decodingStatus === "unsupported" && extracted.classification !== "EMVCo / BharatQR"
      ? "Not a UPI payment payload."
      : `UPI ID: ${extracted.upiId || "Not available in QR."} · Payee: ${extracted.payeeName || "Not available in QR."} · Note: ${extracted.paymentNote || "Not available in QR."}`;

  const report: FullQrIntelligenceReport = {
    scanId,
    scannedAt: now,
    extracted,
    qrLoadInfo: {
      paymentAmountDisplay: extracted.amountDisplay,
      currency: extracted.currency || "Not available in QR.",
      paymentType: extracted.classification,
      recipientName: extracted.payeeName || extracted.merchantName || "Not available in QR.",
      recipientUpiId: extracted.upiId || "Not available in QR.",
      paymentNote: extracted.paymentNote || "Not available in QR.",
      amountEditability: extracted.amountEditability,
      encodedPaymentDetailsSummary: encodedDetailsSummary,
      paymentStatus: ["QR Scanned", "Payment Not Initiated", "Payment Status Unknown"],
      qrLoadCategory: paymentLoad.loadCategory,
      qrLoadCategoryMessage,
      aiAmountExplanation: aiReport.amountExplanation,
    },
    merchant,
    security,
    paymentAmountAnalysis: {
      caseType: extracted.amountState,
      summary:
        extracted.amountState === "fixed"
          ? `A fixed payment amount of ${extracted.amountDisplay} is encoded directly inside the QR parameters.`
          : extracted.amountState === "not_encoded"
            ? "Amount not specified – user must enter the amount in their UPI application."
            : extracted.amountState === "invalid"
              ? "Unable to determine the payment amount."
              : "Payment amount information is unavailable for this QR format.",
      editability: extracted.amountEditability,
      anomalyNote: paymentLoad.unusualAmountSpike
        ? `Unusual spike compared to recent fixed-amount QR scans (${paymentLoad.priorScansWithAmountCount} prior scans).`
        : paymentLoad.exceedsPaymentLimit
          ? `Amount exceeds configured parent limit of ${formatInr(thresholds.paymentLimit)}.`
          : "No amount anomaly detected against configured thresholds.",
    },
    paymentLoad,
    duplicateStatus,
    aiReport,
    overallAssessment: {
      combinedLevel,
      combinedLabel: riskLabel(combinedLevel),
      securityRiskLevel: security.riskLevel,
      securityRiskLabel: security.riskLabel,
      paymentLoadRiskLevel: paymentLoad.loadRiskLevel,
      paymentLoadRiskLabel: paymentLoad.loadRiskLabel,
      summary: overallSummary,
    },
    parentNotifications,
    ...(sharedIntelligence.length ? { sharedIntelligence } : {}),
  };

  // Persist sanitized scan record (payload stored only via SHA-256 hash + validated fields)
  await db
    .prepare(
      `INSERT INTO qr_scan_records (
         id, user_id, payload_hash, qr_format, qr_classification,
         upi_id, payee_name, merchant_name, mcc, tx_ref, tx_id, payment_note,
         amount, amount_state, currency, provider_name,
         security_risk_level, security_risk_score, payment_load_category, payment_load_risk_level,
         report_json, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      scanId,
      params.userId,
      duplicateStatus.payloadHash,
      extracted.qrFormat,
      extracted.classification,
      extracted.upiId,
      extracted.payeeName,
      extracted.merchantName,
      extracted.mcc,
      extracted.transactionRef,
      extracted.transactionId,
      extracted.paymentNote ? extracted.paymentNote.slice(0, 120) : null,
      extracted.amount,
      extracted.amountState,
      extracted.currency,
      extracted.providerInferred,
      security.riskLevel,
      security.score,
      paymentLoad.loadCategory,
      paymentLoad.loadRiskLevel,
      JSON.stringify(report),
      now
    );

  // Also record compact summary into existing qr_checks table for compatibility
  await db
    .prepare(
      "INSERT INTO qr_checks (id, user_id, kind, payee, amount, score, level, signals_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      generateId("qr"),
      params.userId,
      extracted.classification,
      extracted.upiId || extracted.urlHost || null,
      extracted.amount,
      security.score,
      security.riskLevel === "INCONCLUSIVE" ? "MEDIUM" : security.riskLevel,
      JSON.stringify(security.findings.map((f) => f.title).slice(0, 8)),
      now
    );

  await writeAudit(
    params.userId,
    `QR Intelligence analyzed (${security.riskLabel} security / ${paymentLoad.loadCategory})`
  );

  try {
    const gsiRes = await ingestGsiEvent({
      familyOwnerId: params.userId,
      familyOwnerName: params.userName,
      eventType: "qr_event",
      eventTimestamp: now,
      sourceModule: "module_f_qr_intelligence",
      lang: params.lang === "hi" ? "hi" : "en",
      qrData: {
        scanId,
        classification: extracted.classification,
        securityScore: security.score,
        securityRiskLevel: security.riskLevel,
        paymentLoadCategory: paymentLoad.loadCategory,
        upiId: extracted.upiId,
        payeeName: extracted.payeeName,
        merchantName: extracted.merchantName,
        payloadHash: duplicateStatus.payloadHash,
        amount: extracted.amount,
        urlString: extracted.urlString,
        findings: security.findings.map((f) => f.title),
      },
    });
    report.gsiAssessment = {
      incidentId: gsiRes.incident.incidentId,
      severity: gsiRes.incident.severity,
      riskScore: gsiRes.incident.riskScore,
    };
    const refreshedShared = await lookupSharedEntitiesForQuery({
      familyOwnerId: params.userId,
      candidates: qrCandidates,
      currentSection: "qr_scam",
    });
    if (refreshedShared.length) {
      report.sharedIntelligence = refreshedShared;
    }
  } catch {
    // Non-blocking GSI telemetry hook
  }

  return report;
}
