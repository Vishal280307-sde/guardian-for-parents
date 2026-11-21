import { db } from "./db.ts";
import {
  createNotification,
  generateId,
  getActiveGuardiansForParent,
  getActiveLinkedParentIds,
  sanitizeAuditText,
  sha256,
  writeAudit,
} from "./security.ts";
import { assertNoBankingCredentials } from "./parentsAi.ts";

export type EppDurationOption = "30m" | "1h" | "3h" | "6h" | "manual";
export type EppBankServiceType =
  | "upi_block"
  | "debit_block"
  | "credit_block"
  | "netbanking_security"
  | "fraud_report";

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
  verificationStatus: "verified" | "unverified" | "phone_only";
  lastVerifiedAt: number;
  notes: string;
  updatedAt: number;
}

export interface EppAppInfo {
  packageName: string;
  label: string;
  category: "UPI" | "Bank" | "Wallet";
}

export const SUPPORTED_PAYMENT_APPS: EppAppInfo[] = [
  { packageName: "com.google.android.apps.nbu.paisa.user", label: "Google Pay", category: "UPI" },
  { packageName: "com.phonepe.app", label: "PhonePe", category: "UPI" },
  { packageName: "net.one97.paytm", label: "Paytm", category: "UPI" },
  { packageName: "in.org.npci.upiapp", label: "BHIM UPI", category: "UPI" },
  { packageName: "in.amazon.mShop.android.shopping", label: "Amazon Pay / Shopping", category: "Wallet" },
  { packageName: "com.dreamplug.androidapp", label: "CRED", category: "UPI" },
  { packageName: "com.sbi.lotusintouch", label: "YONO SBI", category: "Bank" },
  { packageName: "com.snapwork.hdfc", label: "HDFC Bank MobileBanking", category: "Bank" },
  { packageName: "com.csam.icici.bank.imobile", label: "iMobile Pay (ICICI)", category: "Bank" },
  { packageName: "com.axis.mobile", label: "Axis Mobile", category: "Bank" },
];

export const EMERGENCY_EXCLUDED_PACKAGES = new Set([
  "com.android.dialer",
  "com.google.android.dialer",
  "com.android.phone",
  "com.android.emergency",
  "com.android.settings",
  "com.android.systemui",
]);

const DURATION_MINUTES_MAP: Record<EppDurationOption, number | null> = {
  "30m": 30,
  "1h": 60,
  "3h": 180,
  "6h": 360,
  manual: null,
};

interface SeedBankRow {
  id: string;
  bankName: string;
  shortCode: string;
  supportPhone: string;
  upiBlockUrl: string | null;
  debitBlockUrl: string | null;
  creditBlockUrl: string | null;
  netbankingUrl: string | null;
  fraudReportUrl: string | null;
  verificationStatus: "verified" | "unverified" | "phone_only";
  notes: string;
}

const DEFAULT_BANK_DIRECTORY: SeedBankRow[] = [
  {
    id: "bank_sbi",
    bankName: "State Bank of India (SBI)",
    shortCode: "SBI",
    supportPhone: "1800 1234",
    upiBlockUrl: "https://sbi.co.in/web/personal-banking/digital/upi/upi-faq",
    debitBlockUrl: "https://retail.onlinesbi.sbi/retail/blockatmcard.htm",
    creditBlockUrl: "https://www.sbicard.com/en/personal/benefits/card-security/lost-or-stolen-card.page",
    netbankingUrl: "https://retail.onlinesbi.sbi/",
    fraudReportUrl: "https://cybercrime.gov.in/",
    verificationStatus: "verified",
    notes: "24x7 toll-free: 1800 1234 / 1800 2100. For urgent UPI disablement if portal login is unavailable, call SBI Customer Care directly.",
  },
  {
    id: "bank_hdfc",
    bankName: "HDFC Bank",
    shortCode: "HDFC",
    supportPhone: "1800 1600",
    upiBlockUrl: "https://www.hdfcbank.com/personal/pay/money-transfer/unified-payments-interface",
    debitBlockUrl: "https://www.hdfcbank.com/personal/ways-to-bank/bank-with-us/hotlist-your-debit-card",
    creditBlockUrl: "https://www.hdfcbank.com/personal/pay/cards/credit-cards/block-credit-card",
    netbankingUrl: "https://netbanking.hdfcbank.com/",
    fraudReportUrl: "https://www.hdfcbank.com/personal/useful-links/security/report-fraud",
    verificationStatus: "verified",
    notes: "National helpline 1800 1600 / 1800 2600. Dedicated unauthorized-transaction & card hotlisting portal.",
  },
  {
    id: "bank_icici",
    bankName: "ICICI Bank",
    shortCode: "ICICI",
    supportPhone: "1800 1080",
    upiBlockUrl: "https://www.icicibank.com/personal-banking/online-services/upi-payment",
    debitBlockUrl: "https://www.icicibank.com/personal-banking/cards/debit-card/block-unblock-debit-card",
    creditBlockUrl: "https://www.icicibank.com/personal-banking/cards/credit-card/block-credit-card",
    netbankingUrl: "https://www.icicibank.com/personal-banking/insta-banking/internet-banking",
    fraudReportUrl: "https://www.icicibank.com/personal-banking/online-safe-banking/report-fraud",
    verificationStatus: "verified",
    notes: "24x7 helpline: 1800 1080. You can also freeze Internet Banking or cards via official iMobile / customer care.",
  },
  {
    id: "bank_axis",
    bankName: "Axis Bank",
    shortCode: "AXIS",
    supportPhone: "1800 103 5577",
    upiBlockUrl: "https://www.axisbank.com/bank-smart/open-access/upi",
    debitBlockUrl: "https://www.axisbank.com/support/block-your-card",
    creditBlockUrl: "https://www.axisbank.com/support/block-your-card",
    netbankingUrl: "https://www.axisbank.com/bank-smart/internet-banking/getting-started",
    fraudReportUrl: "https://www.axisbank.com/support/report-a-fraud",
    verificationStatus: "verified",
    notes: "24x7 Block Card & Fraud helpline: 1800 103 5577 / +91 22 6798 7700.",
  },
  {
    id: "bank_pnb",
    bankName: "Punjab National Bank (PNB)",
    shortCode: "PNB",
    supportPhone: "1800 1800",
    upiBlockUrl: "https://www.pnbindia.in/BHIM-PNB.html",
    debitBlockUrl: "https://www.pnbindia.in/hotlisting-of-debit-card.html",
    creditBlockUrl: "https://www.pnbcard.in/",
    netbankingUrl: "https://netpnb.com/",
    fraudReportUrl: "https://www.pnbindia.in/cyber-security.html",
    verificationStatus: "verified",
    notes: "24x7 toll-free: 1800 1800 / 1800 2021. Call support immediately to block UPI & ATM cards if net banking access is locked.",
  },
  {
    id: "bank_kotak",
    bankName: "Kotak Mahindra Bank",
    shortCode: "KOTAK",
    supportPhone: "1860 266 2666",
    upiBlockUrl: "https://www.kotak.com/en/digital-banking/ways-to-bank/upi.html",
    debitBlockUrl: "https://www.kotak.com/en/customer-service/report-lost-card.html",
    creditBlockUrl: "https://www.kotak.com/en/customer-service/report-lost-card.html",
    netbankingUrl: "https://netbanking.kotak.com/",
    fraudReportUrl: "https://www.kotak.com/en/customer-service/report-unauthorized-transaction.html",
    verificationStatus: "verified",
    notes: "24x7 emergency lost-card & unauthorized transaction desk: 1860 266 2666.",
  },
  {
    id: "bank_bob",
    bankName: "Bank of Baroda",
    shortCode: "BOB",
    supportPhone: "1800 5700",
    upiBlockUrl: "https://www.bankofbaroda.in/personal-banking/digital-products/instant-pay/bhim-baroda-pay",
    debitBlockUrl: "https://www.bankofbaroda.in/personal-banking/digital-products/cards/debit-cards/block-unblock-debit-card",
    creditBlockUrl: "https://www.bobcard.co.in/",
    netbankingUrl: "https://www.bobibanking.com/",
    fraudReportUrl: "https://www.bankofbaroda.in/safe-banking",
    verificationStatus: "verified",
    notes: "24x7 toll-free support: 1800 5700.",
  },
  {
    id: "bank_canara",
    bankName: "Canara Bank",
    shortCode: "CANARA",
    supportPhone: "1800 1030",
    upiBlockUrl: "https://canarabank.com/upi",
    debitBlockUrl: "https://canarabank.com/debit-cards",
    creditBlockUrl: "https://canarabank.com/credit-cards",
    netbankingUrl: "https://online.canarabank.in/",
    fraudReportUrl: "https://canarabank.com/cyber-security-awareness",
    verificationStatus: "verified",
    notes: "24x7 toll-free: 1800 1030. Direct telephone card/UPI hotlisting available on toll-free helpline.",
  },
  {
    id: "bank_union",
    bankName: "Union Bank of India",
    shortCode: "UBI",
    supportPhone: "1800 22 2244",
    upiBlockUrl: "https://www.unionbankofindia.co.in/english/bhim-upi.aspx",
    debitBlockUrl: "https://www.unionbankofindia.co.in/english/debit-card-hotlisting.aspx",
    creditBlockUrl: "https://www.unionbankofindia.co.in/english/credit-card.aspx",
    netbankingUrl: "https://www.unionbankonline.co.in/",
    fraudReportUrl: "https://www.unionbankofindia.co.in/english/cyber-security.aspx",
    verificationStatus: "verified",
    notes: "24x7 toll-free: 1800 22 2244 / 1800 208 2244.",
  },
  {
    id: "bank_indusind",
    bankName: "IndusInd Bank",
    shortCode: "INDUSIND",
    supportPhone: "1860 267 7777",
    upiBlockUrl: "https://www.indusind.com/in/en/personal/online-banking/upi.html",
    debitBlockUrl: "https://www.indusind.com/in/en/personal/cards/debit-card.html",
    creditBlockUrl: "https://www.indusind.com/in/en/personal/cards/credit-card.html",
    netbankingUrl: "https://www.indusind.com/in/en/personal/online-banking/netbanking.html",
    fraudReportUrl: "https://www.indusind.com/in/en/personal/report-fraud.html",
    verificationStatus: "verified",
    notes: "Customer support & emergency card blocking: 1860 267 7777 / 022 4220 7777.",
  },
  {
    id: "bank_npci_national",
    bankName: "NPCI BHIM / National Cyber Fraud (1930)",
    shortCode: "NPCI1930",
    supportPhone: "1930",
    upiBlockUrl: "https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism",
    debitBlockUrl: null,
    creditBlockUrl: null,
    netbankingUrl: "https://www.cybercrime.gov.in/",
    fraudReportUrl: "https://cybercrime.gov.in/",
    verificationStatus: "verified",
    notes: "National Cyber Crime Helpline 1930 (24x7) freezes scam fund movement across Indian banks & UPI switches when reported immediately.",
  },
];

export function validateOfficialHttpsUrl(rawUrl: unknown, allowNull = true): string | null {
  if (rawUrl === null || rawUrl === undefined || String(rawUrl).trim() === "") {
    if (allowNull) return null;
    throw new Error("Official URL is required.");
  }
  const str = String(rawUrl).trim();
  let parsed: URL;
  try {
    parsed = new URL(str);
  } catch {
    throw new Error(`Invalid URL format: ${str.slice(0, 60)}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Official bank URLs must use secure HTTPS protocol.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Bank URLs must not contain embedded credentials.");
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".local") ||
    /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.0\.0\.0|\[?::1\]?$)/.test(host)
  ) {
    throw new Error("Private or loopback network hosts are blocked for security.");
  }
  if (!host.includes(".") || host.length > 180) {
    throw new Error("Bank URL must point to a valid public domain.");
  }
  return parsed.toString();
}

export async function seedDefaultBankDirectoryIfEmpty(): Promise<void> {
  const now = Date.now();
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO epp_bank_directory
     (id, bank_name, short_code, support_phone, upi_block_url, debit_block_url, credit_block_url, netbanking_url, fraud_report_url, verification_status, last_verified_at, notes, updated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const row of DEFAULT_BANK_DIRECTORY) {
    await stmt.run(
      row.id,
      row.bankName,
      row.shortCode,
      row.supportPhone,
      row.upiBlockUrl,
      row.debitBlockUrl,
      row.creditBlockUrl,
      row.netbankingUrl,
      row.fraudReportUrl,
      row.verificationStatus,
      now,
      row.notes,
      now,
      now
    );
  }
}

function mapBankRow(r: Record<string, unknown>): EppBankEntry {
  return {
    id: String(r.id),
    bankName: String(r.bank_name),
    shortCode: String(r.short_code),
    supportPhone: String(r.support_phone),
    upiBlockUrl: r.upi_block_url ? String(r.upi_block_url) : null,
    debitBlockUrl: r.debit_block_url ? String(r.debit_block_url) : null,
    creditBlockUrl: r.credit_block_url ? String(r.credit_block_url) : null,
    netbankingUrl: r.netbanking_url ? String(r.netbanking_url) : null,
    fraudReportUrl: r.fraud_report_url ? String(r.fraud_report_url) : null,
    verificationStatus: String(r.verification_status) as EppBankEntry["verificationStatus"],
    lastVerifiedAt: Number(r.last_verified_at),
    notes: String(r.notes || ""),
    updatedAt: Number(r.updated_at),
  };
}

export async function listBankDirectory(): Promise<EppBankEntry[]> {
  await seedDefaultBankDirectoryIfEmpty();
  const rows = (await db
    .prepare("SELECT * FROM epp_bank_directory ORDER BY bank_name ASC")
    .all()) as Record<string, unknown>[];
  return rows.map(mapBankRow);
}

export async function upsertAndVerifyBankEntry(params: {
  actor: { id: string; name: string; role: "parent" | "guardian" };
  id?: string;
  bankName: string;
  shortCode: string;
  supportPhone: string;
  upiBlockUrl?: string | null;
  debitBlockUrl?: string | null;
  creditBlockUrl?: string | null;
  netbankingUrl?: string | null;
  fraudReportUrl?: string | null;
  verificationStatus?: "verified" | "unverified" | "phone_only";
  notes?: string;
}): Promise<EppBankEntry> {
  await seedDefaultBankDirectoryIfEmpty();
  const bankName = sanitizeAuditText(String(params.bankName || "").trim()).slice(0, 80);
  const shortCode = String(params.shortCode || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, "")
    .slice(0, 16);
  const supportPhone = String(params.supportPhone || "")
    .trim()
    .replace(/[^0-9+\-\s()]/g, "")
    .slice(0, 32);

  if (!bankName || bankName.length < 2) {
    throw new Error("Bank name is required.");
  }
  if (!shortCode || shortCode.length < 2) {
    throw new Error("Bank short code (2-16 chars) is required.");
  }
  if (!supportPhone || supportPhone.length < 3) {
    throw new Error("Verified support phone number is required.");
  }

  const upiBlockUrl = validateOfficialHttpsUrl(params.upiBlockUrl, true);
  const debitBlockUrl = validateOfficialHttpsUrl(params.debitBlockUrl, true);
  const creditBlockUrl = validateOfficialHttpsUrl(params.creditBlockUrl, true);
  const netbankingUrl = validateOfficialHttpsUrl(params.netbankingUrl, true);
  const fraudReportUrl = validateOfficialHttpsUrl(params.fraudReportUrl, true);

  const hasAnyUrl = Boolean(upiBlockUrl || debitBlockUrl || creditBlockUrl || netbankingUrl || fraudReportUrl);
  const verStatus: EppBankEntry["verificationStatus"] =
    params.verificationStatus && ["verified", "unverified", "phone_only"].includes(params.verificationStatus)
      ? params.verificationStatus
      : hasAnyUrl
        ? "verified"
        : "phone_only";

  const now = Date.now();
  const id = params.id ? String(params.id).trim() : `bank_${shortCode.toLowerCase()}`;
  const existing = (await db
    .prepare("SELECT id FROM epp_bank_directory WHERE id = ? OR short_code = ?")
    .get(id, shortCode)) as { id: string } | undefined;
  const targetId = existing?.id || id;
  const notes = sanitizeAuditText(String(params.notes || "").trim()).slice(0, 240);

  if (existing) {
    await db
      .prepare(
        `UPDATE epp_bank_directory SET
           bank_name = ?,
           short_code = ?,
           support_phone = ?,
           upi_block_url = ?,
           debit_block_url = ?,
           credit_block_url = ?,
           netbanking_url = ?,
           fraud_report_url = ?,
           verification_status = ?,
           last_verified_at = ?,
           notes = ?,
           updated_at = ?
         WHERE id = ?`
      )
      .run(
        bankName,
        shortCode,
        supportPhone,
        upiBlockUrl,
        debitBlockUrl,
        creditBlockUrl,
        netbankingUrl,
        fraudReportUrl,
        verStatus,
        now,
        notes,
        now,
        targetId
      );
  } else {
    await db
      .prepare(
        `INSERT INTO epp_bank_directory
         (id, bank_name, short_code, support_phone, upi_block_url, debit_block_url, credit_block_url, netbanking_url, fraud_report_url, verification_status, last_verified_at, notes, updated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        targetId,
        bankName,
        shortCode,
        supportPhone,
        upiBlockUrl,
        debitBlockUrl,
        creditBlockUrl,
        netbankingUrl,
        fraudReportUrl,
        verStatus,
        now,
        notes,
        now,
        now
      );
  }

  await writeEppAudit(
    params.actor.id,
    params.actor.id,
    params.actor.name,
    "bank_directory_updated",
    `Updated & verified official entry for ${bankName} (${verStatus})`
  );
  await writeAudit(params.actor.id, `Updated verified bank blocking URLs for ${shortCode}`);

  const saved = (await db.prepare("SELECT * FROM epp_bank_directory WHERE id = ?").get(targetId)) as Record<
    string,
    unknown
  >;
  return mapBankRow(saved);
}

async function writeEppAudit(
  familyOwnerId: string,
  actorId: string,
  actorName: string,
  action: string,
  details: string
): Promise<void> {
  const cleanDetails = sanitizeAuditText(details).slice(0, 240);
  const prev = (await db
    .prepare("SELECT hash FROM epp_audit_trail WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 1")
    .get(familyOwnerId)) as { hash: string } | undefined;
  const prevHash = prev?.hash || "0";
  const now = Date.now();
  const hash = sha256(`${prevHash}|${familyOwnerId}|${actorId}|${action}|${cleanDetails}|${now}`).slice(0, 16);
  await db
    .prepare(
      `INSERT INTO epp_audit_trail
       (id, family_owner_id, actor_id, actor_name, action, details, prev_hash, hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(generateId("eppa"), familyOwnerId, actorId, actorName, action, cleanDetails, prevHash, hash, now);
}

async function resolveReadableScope(actor: { id: string; role: "parent" | "guardian" }, requestedOwnerId?: string): Promise<string> {
  if (actor.role === "parent") {
    if (requestedOwnerId && requestedOwnerId !== actor.id) {
      throw new Error("Unauthorized: cannot access another family member's emergency payment protection.");
    }
    return actor.id;
  }
  const linked = await getActiveLinkedParentIds(actor.id);
  const target = requestedOwnerId && requestedOwnerId !== "all" ? requestedOwnerId : linked[0];
  if (!target || !linked.includes(target)) {
    throw new Error("Unauthorized: no active guardian link for this family member.");
  }
  return target;
}

async function dispatchEppFamilyNotifications(params: {
  familyOwnerId: string;
  kind: "epp_activated" | "epp_unlocked" | "epp_expired";
  title: string;
  body: string;
  dedupWithinMs?: number;
}): Promise<number> {
  const consent = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(params.familyOwnerId)) as { guardian_alerts: number; paused: number } | undefined;
  if (consent && (!consent.guardian_alerts || consent.paused)) {
    return 0;
  }
  const guardians = await getActiveGuardiansForParent(params.familyOwnerId);
  if (!guardians.length) return 0;

  const now = Date.now();
  const windowMs = params.dedupWithinMs ?? 15_000;
  let sent = 0;

  for (const g of guardians) {
    const recentDup = await db
      .prepare(
        `SELECT id FROM notifications
         WHERE recipient_id = ? AND parent_id = ? AND kind = ? AND title = ? AND created_at > ?
         LIMIT 1`
      )
      .get(g.guardian_id, params.familyOwnerId, params.kind, sanitizeAuditText(params.title).slice(0, 100), now - windowMs);
    if (!recentDup) {
      await createNotification(g.guardian_id, params.familyOwnerId, params.kind, params.title, params.body);
      sent++;
    }
  }
  return sent;
}

export async function reconcileExpiredEppSessions(familyOwnerId: string): Promise<number> {
  const now = Date.now();
  const expiredRows = (await db
    .prepare(
      `SELECT * FROM epp_lock_sessions
       WHERE family_owner_id = ? AND status = 'active' AND manual_until_unlock = 0 AND expires_at IS NOT NULL AND expires_at <= ?`
    )
    .all(familyOwnerId, now)) as Record<string, unknown>[];

  if (!expiredRows.length) return 0;

  for (const row of expiredRows) {
    const sid = String(row.id);
    const updated = await db
      .prepare("UPDATE epp_lock_sessions SET status = 'expired' WHERE id = ? AND status = 'active'")
      .run(sid);
    if (Number(updated.changes || 0) > 0) {
      const apps = parseSelectedApps(row.selected_apps_json);
      const appNames = apps.map((a) => a.label).join(", ") || "selected apps";
      await writeEppAudit(
        familyOwnerId,
        "system_timer",
        "Guardian Timer",
        "lock_expired",
        `Emergency Payment App Lock expired automatically after configured duration (${appNames}).`
      );
      await writeAudit(familyOwnerId, "Emergency Payment App Lock expired automatically");
      if (!Number(row.expiry_notified || 0)) {
        await dispatchEppFamilyNotifications({
          familyOwnerId,
          kind: "epp_expired",
          title: "Emergency Payment Lock expired",
          body: `${String(row.activated_by_name)}'s temporary app lock (${appNames}) automatically expired. Bank-level blocks (if set) stay active until you change them at your bank.`,
          dedupWithinMs: 60_000,
        });
        await db.prepare("UPDATE epp_lock_sessions SET expiry_notified = 1 WHERE id = ?").run(sid);
      }
    }
  }
  return expiredRows.length;
}

function parseSelectedApps(raw: unknown): EppAppInfo[] {
  try {
    const arr = JSON.parse(String(raw || "[]"));
    if (Array.isArray(arr)) {
      return arr
        .filter((x) => x && typeof x === "object" && typeof (x as any).packageName === "string")
        .map((x: any) => ({
          packageName: String(x.packageName).slice(0, 120),
          label: String(x.label || x.packageName).slice(0, 60),
          category: (["UPI", "Bank", "Wallet"].includes(x.category) ? x.category : "UPI") as EppAppInfo["category"],
        }));
    }
  } catch {
    // ignore
  }
  return [];
}

function formatDurationHuman(opt: EppDurationOption, expiresAt: number | null, manual: boolean): string {
  if (manual || !expiresAt) return "Until manually unlocked";
  const minsLeft = Math.max(0, Math.ceil((expiresAt - Date.now()) / 60_000));
  if (minsLeft >= 60) {
    const hrs = Math.floor(minsLeft / 60);
    const rem = minsLeft % 60;
    return rem > 0 ? `${hrs}h ${rem}m remaining` : `${hrs}h remaining`;
  }
  return `${minsLeft}m remaining (${opt})`;
}

export async function activateEmergencyPaymentLock(params: {
  actor: { id: string; name: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
  selectedPackages: string[];
  durationOption: string;
  explicitConsent: boolean;
  osEnforcementMode?: string;
  devicePlatform?: string;
  deviceCapabilityNote?: string;
}) {
  assertNoBankingCredentials(params);

  // Strict authorization: only authenticated account holder may activate/modify their own payment lock
  if (params.actor.role !== "parent" || (params.requestedOwnerId && params.requestedOwnerId !== params.actor.id)) {
    const err = new Error(
      "Unauthorized: only the authenticated account owner can activate or modify their Emergency Payment Protection."
    ) as Error & { statusCode?: number };
    err.statusCode = 403;
    throw err;
  }

  if (params.explicitConsent !== true) {
    throw new Error("Explicit user authorization confirmation is required before activating Emergency Payment Lock.");
  }

  const durationOption = String(params.durationOption || "") as EppDurationOption;
  if (!(durationOption in DURATION_MINUTES_MAP)) {
    throw new Error("Invalid lock duration option. Choose 30m, 1h, 3h, 6h, or manual.");
  }

  const rawPackages = Array.isArray(params.selectedPackages) ? params.selectedPackages : [];
  const normalizedApps: EppAppInfo[] = [];
  const seen = new Set<string>();
  for (const pkgRaw of rawPackages.slice(0, 15)) {
    const pkg = String(pkgRaw || "").trim().slice(0, 120);
    if (!pkg || seen.has(pkg)) continue;
    if (
      EMERGENCY_EXCLUDED_PACKAGES.has(pkg) ||
      /(?:^|[._])(dialer|phone|telecom|incallui|emergency|accessibility|systemui)(?:$|[._])/i.test(pkg)
    ) {
      throw new Error("Essential phone, emergency dialer (112/1930), and accessibility packages cannot be restricted.");
    }
    seen.add(pkg);
    const known = SUPPORTED_PAYMENT_APPS.find((a) => a.packageName === pkg);
    normalizedApps.push(
      known || {
        packageName: pkg,
        label: pkg.split(".").slice(-1)[0] || pkg,
        category: "UPI",
      }
    );
  }

  if (!normalizedApps.length) {
    throw new Error("Select at least one payment app before activating Emergency Payment Lock.");
  }

  await reconcileExpiredEppSessions(params.actor.id);
  const now = Date.now();
  const durationMinutes = DURATION_MINUTES_MAP[durationOption];
  const manual = durationOption === "manual";
  const expiresAt = durationMinutes ? now + durationMinutes * 60_000 : null;

  const osMode =
    params.osEnforcementMode === "native_device_owner"
      ? "native_device_owner"
      : "guardian_advisory_session";
  const devicePlatform = sanitizeAuditText(String(params.devicePlatform || "web_browser")).slice(0, 60);
  const capabilityNote = sanitizeAuditText(
    String(
      params.deviceCapabilityNote ||
        (osMode === "native_device_owner"
          ? "Android Device Owner package suspension requested. Does not replace bank-side blocking."
          : "Web browser / standard device cannot suspend external payment apps at OS level. Use official bank blocking below for account/UPI freezes.")
    )
  ).slice(0, 220);

  // Deduplicate if user hits Activate twice inside 15 seconds with same selection & duration
  const dedupKey = sha256(
    `${params.actor.id}|${normalizedApps.map((a) => a.packageName).sort().join(",")}|${durationOption}`
  ).slice(0, 16);

  const existingActive = (await db
    .prepare("SELECT * FROM epp_lock_sessions WHERE family_owner_id = ? AND status = 'active' ORDER BY activated_at DESC LIMIT 1")
    .get(params.actor.id)) as Record<string, unknown> | undefined;

  if (existingActive) {
    if (String(existingActive.dedup_key || "") === dedupKey && now - Number(existingActive.activated_at) < 15_000) {
      return {
        sessionId: String(existingActive.id),
        deduplicated: true,
        notificationsSent: 0,
      };
    }
    await db
      .prepare(
        "UPDATE epp_lock_sessions SET status = 'unlocked', unlocked_at = ?, unlocked_by_id = ?, unlocked_by_name = ? WHERE id = ?"
      )
      .run(now, params.actor.id, params.actor.name, String(existingActive.id));
  }

  const sessionId = generateId("eppl");
  const appLabels = normalizedApps.map((a) => a.label).join(", ");
  const durationLabel = formatDurationHuman(durationOption, expiresAt, manual);

  const notificationsSent = await dispatchEppFamilyNotifications({
    familyOwnerId: params.actor.id,
    kind: "epp_activated",
    title: `Emergency Payment Protection activated by ${params.actor.name}`,
    body: `Activated at ${new Date(now).toLocaleTimeString()} · Apps: ${appLabels} · Duration: ${durationLabel}. (${osMode === "native_device_owner" ? "Device-Owner lock" : "Advisory lock — official bank block recommended"}).`,
    dedupWithinMs: 20_000,
  });

  await db
    .prepare(
      `INSERT INTO epp_lock_sessions
       (id, family_owner_id, activated_by_id, activated_by_name, activated_by_role, status, selected_apps_json, duration_option, duration_minutes, manual_until_unlock, os_enforcement_mode, device_platform, device_capability_note, explicit_consent_ack, dedup_key, notified_guardians_count, expiry_notified, activated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0, ?, ?)`
    )
    .run(
      sessionId,
      params.actor.id,
      params.actor.id,
      params.actor.name,
      params.actor.role,
      JSON.stringify(normalizedApps),
      durationOption,
      durationMinutes,
      manual ? 1 : 0,
      osMode,
      devicePlatform,
      capabilityNote,
      dedupKey,
      notificationsSent,
      now,
      expiresAt
    );

  await writeEppAudit(
    params.actor.id,
    params.actor.id,
    params.actor.name,
    "lock_activated",
    `Activated Emergency Payment Lock (${durationOption}) for ${appLabels} via ${osMode}. Notified ${notificationsSent} guardian(s).`
  );
  await writeAudit(params.actor.id, `Emergency Payment Lock activated (${durationOption})`);

  return { sessionId, deduplicated: false, notificationsSent };
}

export async function unlockEmergencyPaymentLock(params: {
  actor: { id: string; name: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
}) {
  if (params.actor.role !== "parent" || (params.requestedOwnerId && params.requestedOwnerId !== params.actor.id)) {
    const err = new Error(
      "Unauthorized: only the authenticated account owner can unlock their Emergency Payment Protection."
    ) as Error & { statusCode?: number };
    err.statusCode = 403;
    throw err;
  }

  await reconcileExpiredEppSessions(params.actor.id);
  const active = (await db
    .prepare("SELECT * FROM epp_lock_sessions WHERE family_owner_id = ? AND status = 'active' ORDER BY activated_at DESC LIMIT 1")
    .get(params.actor.id)) as Record<string, unknown> | undefined;

  if (!active) {
    throw new Error("No active Emergency Payment Lock session found.");
  }

  const now = Date.now();
  const sid = String(active.id);
  await db
    .prepare(
      "UPDATE epp_lock_sessions SET status = 'unlocked', unlocked_at = ?, unlocked_by_id = ?, unlocked_by_name = ? WHERE id = ?"
    )
    .run(now, params.actor.id, params.actor.name, sid);

  const apps = parseSelectedApps(active.selected_apps_json).map((a) => a.label).join(", ");
  await writeEppAudit(
    params.actor.id,
    params.actor.id,
    params.actor.name,
    "lock_unlocked_early",
    `Manually unlocked Emergency Payment Lock early for ${apps}.`
  );
  await writeAudit(params.actor.id, "Emergency Payment Lock manually unlocked early");

  const notificationsSent = await dispatchEppFamilyNotifications({
    familyOwnerId: params.actor.id,
    kind: "epp_unlocked",
    title: `Emergency Payment Lock unlocked by ${params.actor.name}`,
    body: `Manually unlocked at ${new Date(now).toLocaleTimeString()} for ${apps}. Official bank blocks (if placed directly with the bank) remain under bank control.`,
    dedupWithinMs: 15_000,
  });

  return { ok: true, sessionId: sid, notificationsSent };
}

export async function recordBankBlockingAction(params: {
  actor: { id: string; name: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
  bankId: string;
  serviceType: string;
  launchType?: string;
}) {
  assertNoBankingCredentials(params);
  if (params.actor.role !== "parent" || (params.requestedOwnerId && params.requestedOwnerId !== params.actor.id)) {
    const err = new Error("Unauthorized: only the account holder can log bank blocking actions.") as Error & {
      statusCode?: number;
    };
    err.statusCode = 403;
    throw err;
  }

  await seedDefaultBankDirectoryIfEmpty();
  const bankRow = (await db.prepare("SELECT * FROM epp_bank_directory WHERE id = ?").get(params.bankId)) as
    | Record<string, unknown>
    | undefined;
  if (!bankRow) {
    throw new Error("Selected bank entry not found.");
  }
  const bank = mapBankRow(bankRow);

  const serviceType = String(params.serviceType || "") as EppBankServiceType;
  if (!["upi_block", "debit_block", "credit_block", "netbanking_security", "fraud_report"].includes(serviceType)) {
    throw new Error("Invalid bank security service type.");
  }

  const serviceUrlMap: Record<EppBankServiceType, string | null> = {
    upi_block: bank.upiBlockUrl,
    debit_block: bank.debitBlockUrl,
    credit_block: bank.creditBlockUrl,
    netbanking_security: bank.netbankingUrl,
    fraud_report: bank.fraudReportUrl,
  };

  const resolvedUrl = serviceUrlMap[serviceType];
  const launchType =
    params.launchType === "support_phone" || !resolvedUrl ? "support_phone" : "official_url";
  const targetRef = launchType === "official_url" && resolvedUrl ? resolvedUrl : `tel:${bank.supportPhone}`;

  const id = generateId("eppb");
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO epp_bank_action_logs
       (id, family_owner_id, actor_id, bank_id, bank_name, service_type, launch_type, target_ref, bank_confirmed_by_user, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
    )
    .run(id, params.actor.id, params.actor.id, bank.id, bank.bankName, serviceType, launchType, targetRef, now);

  await writeEppAudit(
    params.actor.id,
    params.actor.id,
    params.actor.name,
    "bank_blocking_opened",
    `Opened ${launchType === "official_url" ? "official bank page" : "official support phone"} (${serviceType}) for ${bank.bankName}. Bank has NOT confirmed block yet.`
  );
  await writeAudit(params.actor.id, `Opened official ${bank.shortCode} ${serviceType} channel`);

  return {
    id,
    bankName: bank.bankName,
    supportPhone: bank.supportPhone,
    serviceType,
    launchType,
    targetRef,
    bankBlockedStatus: "opened_official_channel_unconfirmed",
  };
}

export async function markBankServiceUserConfirmed(params: {
  actor: { id: string; name: string; role: "parent" | "guardian" };
  logId: string;
  confirmed: boolean;
}) {
  const row = (await db.prepare("SELECT * FROM epp_bank_action_logs WHERE id = ?").get(params.logId)) as
    | Record<string, unknown>
    | undefined;
  if (!row) throw new Error("Bank action record not found.");
  if (params.actor.role !== "parent" || String(row.family_owner_id) !== params.actor.id) {
    const err = new Error("Unauthorized: cannot modify another user's bank blocking confirmation.") as Error & {
      statusCode?: number;
    };
    err.statusCode = 403;
    throw err;
  }

  const now = Date.now();
  await db
    .prepare("UPDATE epp_bank_action_logs SET bank_confirmed_by_user = ?, confirmed_at = ? WHERE id = ?")
    .run(params.confirmed ? 1 : 0, params.confirmed ? now : null, params.logId);

  await writeEppAudit(
    params.actor.id,
    params.actor.id,
    params.actor.name,
    params.confirmed ? "bank_block_user_confirmed" : "bank_block_unconfirmed",
    `${params.confirmed ? "User reported completing bank-side block directly with" : "Cleared bank-side block confirmation for"} ${String(row.bank_name)} (${String(row.service_type)}).`
  );

  if (params.confirmed) {
    await dispatchEppFamilyNotifications({
      familyOwnerId: params.actor.id,
      kind: "epp_activated",
      title: `Bank security action confirmed by ${params.actor.name}`,
      body: `${params.actor.name} reported completing ${String(row.service_type).replace(/_/g, " ")} directly with ${String(row.bank_name)}.`,
      dedupWithinMs: 20_000,
    });
  }

  return { ok: true };
}

export async function getEmergencyPaymentDashboard(
  actor: { id: string; role: "parent" | "guardian" },
  requestedOwnerId?: string
) {
  await seedDefaultBankDirectoryIfEmpty();
  const familyOwnerId = await resolveReadableScope(actor, requestedOwnerId);
  await reconcileExpiredEppSessions(familyOwnerId);

  const banks = await listBankDirectory();
  const now = Date.now();
  const rawSessions = (await db
    .prepare("SELECT * FROM epp_lock_sessions WHERE family_owner_id = ? ORDER BY activated_at DESC LIMIT 12")
    .all(familyOwnerId)) as Record<string, unknown>[];

  const sessions = rawSessions.map((r) => {
    const expiresAt = r.expires_at ? Number(r.expires_at) : null;
    const status = String(r.status) as "active" | "unlocked" | "expired";
    const manualUntilUnlock = Boolean(r.manual_until_unlock);
    const remainingMs =
      status === "active" && !manualUntilUnlock && expiresAt ? Math.max(0, expiresAt - now) : null;
    return {
      id: String(r.id),
      activatedByName: String(r.activated_by_name),
      activatedByRole: String(r.activated_by_role),
      status,
      selectedApps: parseSelectedApps(r.selected_apps_json),
      durationOption: String(r.duration_option),
      durationMinutes: r.duration_minutes ? Number(r.duration_minutes) : null,
      manualUntilUnlock,
      osEnforcementMode: String(r.os_enforcement_mode),
      devicePlatform: String(r.device_platform),
      deviceCapabilityNote: String(r.device_capability_note),
      notifiedGuardiansCount: Number(r.notified_guardians_count || 0),
      activatedAt: Number(r.activated_at),
      expiresAt,
      remainingMs,
      unlockedAt: r.unlocked_at ? Number(r.unlocked_at) : null,
      unlockedByName: r.unlocked_by_name ? String(r.unlocked_by_name) : null,
    };
  });

  const activeSession = sessions.find((s) => s.status === "active") || null;

  const rawActions = (await db
    .prepare("SELECT * FROM epp_bank_action_logs WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 15")
    .all(familyOwnerId)) as Record<string, unknown>[];

  const bankActions = rawActions.map((a) => ({
    id: String(a.id),
    bankId: String(a.bank_id),
    bankName: String(a.bank_name),
    serviceType: String(a.service_type),
    launchType: String(a.launch_type),
    bankConfirmedByUser: Boolean(a.bank_confirmed_by_user),
    createdAt: Number(a.created_at),
    confirmedAt: a.confirmed_at ? Number(a.confirmed_at) : null,
  }));

  const rawAudit = (await db
    .prepare("SELECT * FROM epp_audit_trail WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 20")
    .all(familyOwnerId)) as Record<string, unknown>[];

  const auditTrail = rawAudit.map((au) => ({
    id: String(au.id),
    actorName: String(au.actor_name),
    action: String(au.action),
    details: String(au.details),
    hash: String(au.hash),
    createdAt: Number(au.created_at),
  }));

  const guardians = await getActiveGuardiansForParent(familyOwnerId);
  const consentRow = (await db
    .prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?")
    .get(familyOwnerId)) as { guardian_alerts: number; paused: number } | undefined;

  return {
    familyOwnerId,
    canModify: actor.role === "parent" && actor.id === familyOwnerId,
    supportedApps: SUPPORTED_PAYMENT_APPS,
    banks,
    activeSession,
    sessions,
    bankActions,
    auditTrail,
    familyNotificationPolicy: {
      activeGuardiansCount: guardians.length,
      guardianAlertsEnabled: consentRow ? Boolean(consentRow.guardian_alerts && !consentRow.paused) : true,
      guardianNames: guardians.map((g) => g.name),
    },
  };
}

export async function deleteEppDataForOwner(familyOwnerId: string): Promise<void> {
  await db.prepare("DELETE FROM epp_lock_sessions WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM epp_bank_action_logs WHERE family_owner_id = ?").run(familyOwnerId);
  await db.prepare("DELETE FROM epp_audit_trail WHERE family_owner_id = ?").run(familyOwnerId);
}
