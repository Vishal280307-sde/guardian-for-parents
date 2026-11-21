import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { db } from "./db.ts";

export interface AuthUser {
  id: string;
  username: string;
  name: string;
  role: "parent" | "guardian";
}

export interface AuthedRequest extends Request {
  authUser?: AuthUser;
  sessionTokenHash?: string;
}

const SESSION_COOKIE = "guardian_sid";
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export function hashSecret(secret: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(secret, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

export function verifySecret(secret: string, stored: string): boolean {
  const parts = String(stored || "").split(":");
  if (parts.length !== 2) return false;
  const [salt, hexHash] = parts;
  if (!salt || !hexHash) return false;
  try {
    const derived = crypto.scryptSync(secret, salt, 64);
    const expected = Buffer.from(hexHash, "hex");
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

export function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function generateId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

export function extractSessionToken(req: Request): string | null {
  const authHeader = String(req.headers.authorization || "");
  if (/^Bearer\s+/i.test(authHeader)) {
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (token) return token;
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies[SESSION_COOKIE] || null;
}

export async function createSession(req: Request, res: Response, user: AuthUser): Promise<string> {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256(rawToken);
  const now = Date.now();
  await db
    .prepare("INSERT INTO sessions (token_hash, user_id, role, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(tokenHash, user.id, user.role, now + SESSION_TTL_MS, now);

  const isHttps =
    req.secure ||
    String(req.headers["x-forwarded-proto"] || "")
      .toLowerCase()
      .includes("https") ||
    process.env.NODE_ENV === "production" ||
    Boolean(process.env.VERCEL);

  res.cookie(SESSION_COOKIE, rawToken, {
    httpOnly: true,
    sameSite: isHttps ? "none" : "lax",
    secure: isHttps,
    maxAge: SESSION_TTL_MS,
    path: "/",
  });

  return rawToken;
}

export async function clearSession(req: AuthedRequest, res: Response): Promise<void> {
  const rawToken = extractSessionToken(req);
  if (rawToken) {
    await db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha256(rawToken));
  }
  const isHttps =
    req.secure ||
    String(req.headers["x-forwarded-proto"] || "")
      .toLowerCase()
      .includes("https") ||
    process.env.NODE_ENV === "production" ||
    Boolean(process.env.VERCEL);
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    path: "/",
    sameSite: isHttps ? "none" : "lax",
    secure: isHttps,
  });
}

export async function attachAuth(req: AuthedRequest, _res: Response, next: NextFunction): Promise<void> {
  try {
    const rawToken = extractSessionToken(req);
    if (!rawToken) {
      next();
      return;
    }
    const tokenHash = sha256(rawToken);
    const now = Date.now();
    const row = (await db
      .prepare(
        `SELECT s.token_hash, s.expires_at, u.id, u.username, u.name, u.role
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?`
      )
      .get(tokenHash)) as
      | {
          token_hash: string;
          expires_at: number;
          id: string;
          username: string;
          name: string;
          role: "parent" | "guardian";
        }
      | undefined;

    if (!row || row.expires_at < now) {
      if (row) {
        await db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
      }
      next();
      return;
    }

    req.authUser = {
      id: row.id,
      username: row.username,
      name: row.name,
      role: row.role,
    };
    req.sessionTokenHash = tokenHash;
    next();
  } catch (err) {
    next(err);
  }
}

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (!req.authUser) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }
  next();
}

export function requireRole(role: "parent" | "guardian") {
  return (req: AuthedRequest, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (req.authUser.role !== role) {
      res.status(403).json({ error: `Only ${role} accounts can access this action.` });
      return;
    }
    next();
  };
}

/* ---- In-memory sliding-window rate limiter ---- */
const rateBuckets = new Map<string, number[]>();

export function checkRateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const cutoff = now - windowMs;
  const list = (rateBuckets.get(key) || []).filter((ts) => ts > cutoff);
  if (list.length >= maxRequests) {
    rateBuckets.set(key, list);
    return false;
  }
  list.push(now);
  rateBuckets.set(key, list);
  return true;
}

/* ---- Audit log sanitizer & hash chain ---- */
export function sanitizeAuditText(raw: string): string {
  return String(raw || "")
    .replace(/\b\d{4,}\b/g, "[REDACTED]")
    .replace(/[\w.-]+@[\w.-]+/g, "[ID]")
    .replace(/(otp|pin|password|safe.?word)\s*[:=]\s*\S+/gi, "$1=[REDACTED]")
    .slice(0, 180);
}

export async function writeAudit(userId: string, event: string): Promise<{ t: string; ev: string; h: string }> {
  const cleanEv = sanitizeAuditText(event);
  const prev = (await db
    .prepare("SELECT hash FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
    .get(userId)) as { hash: string } | undefined;
  const now = Date.now();
  const prevHash = prev?.hash || "0";
  const hash = sha256(`${prevHash}|${userId}|${cleanEv}|${now}`).slice(0, 12);
  await db
    .prepare("INSERT INTO audit_logs (id, user_id, event, hash, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(generateId("aud"), userId, cleanEv, hash, now);
  return { t: new Date(now).toLocaleTimeString(), ev: cleanEv, h: hash };
}

export async function ensureDefaultConsent(userId: string): Promise<void> {
  const existing = await db.prepare("SELECT user_id FROM consents WHERE user_id = ?").get(userId);
  if (!existing) {
    await db
      .prepare(
        `INSERT INTO consents (user_id, text_analysis, guardian_alerts, guardian_approve, call_timing, paused, payment_limit, med_threshold, high_threshold, retention_days, updated_at)
         VALUES (?, 1, 1, 1, 1, 0, 10000, 25, 50, 30, ?)`
      )
      .run(userId, Date.now());
  }
}

export async function ensureDefaultQrNotificationPrefs(userId: string): Promise<{
  qrScanNotify: boolean;
  highRiskQrAlert: boolean;
  criticalRiskQrAlert: boolean;
  highAmountAlert: boolean;
  veryHighLoadAlert: boolean;
  repeatedQrAlert: boolean;
  merchantWarningAlert: boolean;
  suspiciousQrAlert: boolean;
}> {
  let row = (await db.prepare("SELECT * FROM qr_notification_prefs WHERE user_id = ?").get(userId)) as
    | Record<string, number>
    | undefined;
  if (!row) {
    await db
      .prepare(
        `INSERT INTO qr_notification_prefs (
           user_id, qr_scan_notify, high_risk_qr_alert, critical_risk_qr_alert,
           high_amount_alert, very_high_load_alert, repeated_qr_alert,
           merchant_warning_alert, suspicious_qr_alert, updated_at
         ) VALUES (?, 0, 1, 1, 1, 1, 1, 1, 1, ?)`
      )
      .run(userId, Date.now());
    row = (await db.prepare("SELECT * FROM qr_notification_prefs WHERE user_id = ?").get(userId)) as Record<
      string,
      number
    >;
  }
  return {
    qrScanNotify: Boolean(row.qr_scan_notify),
    highRiskQrAlert: Boolean(row.high_risk_qr_alert),
    criticalRiskQrAlert: Boolean(row.critical_risk_qr_alert),
    highAmountAlert: Boolean(row.high_amount_alert),
    veryHighLoadAlert: Boolean(row.very_high_load_alert),
    repeatedQrAlert: Boolean(row.repeated_qr_alert),
    merchantWarningAlert: Boolean(row.merchant_warning_alert),
    suspiciousQrAlert: Boolean(row.suspicious_qr_alert),
  };
}

export async function getActiveLinkedParentIds(guardianId: string): Promise<string[]> {
  const rows = (await db
    .prepare("SELECT parent_id FROM guardian_links WHERE guardian_id = ? AND status = 'active'")
    .all(guardianId)) as { parent_id: string }[];
  return rows.map((r) => r.parent_id);
}

export async function getActiveGuardiansForParent(
  parentId: string
): Promise<{ id: string; guardian_id: string; name: string; username: string; is_secondary: number }[]> {
  return (await db
    .prepare(
      `SELECT gl.id, gl.guardian_id, u.name, u.username, gl.is_secondary
       FROM guardian_links gl
       JOIN users u ON u.id = gl.guardian_id
       WHERE gl.parent_id = ? AND gl.status = 'active'
       ORDER BY gl.is_secondary ASC, gl.verified_at ASC`
    )
    .all(parentId)) as { id: string; guardian_id: string; name: string; username: string; is_secondary: number }[];
}

export async function createNotification(
  recipientId: string,
  parentId: string,
  kind: string,
  title: string,
  body: string
): Promise<void> {
  const cleanTitle = sanitizeAuditText(title).slice(0, 100);
  const cleanBody = sanitizeAuditText(body).slice(0, 240);
  await db
    .prepare(
      `INSERT INTO notifications (id, recipient_id, parent_id, kind, title, body, channel, delivery_status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'in_app', 'delivered', ?)`
    )
    .run(generateId("ntf"), recipientId, parentId, kind, cleanTitle, cleanBody, Date.now());
}

export async function purgeExpiredSessions(): Promise<number> {
  const res = await db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
  return Number(res.changes || 0);
}

export async function invalidateAllSessions(): Promise<number> {
  const res = await db.prepare("DELETE FROM sessions").run();
  return Number(res.changes || 0);
}

export async function seedInitialDemoUsersIfEmpty(options?: {
  nodeEnv?: string;
  enableDemoAccounts?: string;
}): Promise<boolean> {
  await purgeExpiredSessions();
  const nodeEnv = options?.nodeEnv ?? process.env.NODE_ENV ?? "development";
  const flag = options?.enableDemoAccounts ?? process.env.ENABLE_DEMO_ACCOUNTS;

  // Never seed predictable demo accounts in production environments
  if (nodeEnv === "production" || flag === "false") {
    return false;
  }

  const now = Date.now();
  const sunitaId = "usr_sunita_demo";
  const rahulId = "usr_rahul_demo";
  const meeraId = "usr_meera_demo";

  const demoPass = process.env.DEMO_SEED_PASSWORD || "demo1234";
  const demoRecovery = process.env.DEMO_SEED_RECOVERY || "GUARDIAN-DEMO";
  const pwHash = hashSecret(demoPass);
  const recHash = hashSecret(demoRecovery);

  await db
    .prepare(
      "INSERT OR IGNORE INTO users (id, username, name, role, password_hash, recovery_code_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .run(sunitaId, "sunita", "Sunita Sharma", "parent", pwHash, recHash, now);

  await db
    .prepare(
      "INSERT OR IGNORE INTO users (id, username, name, role, password_hash, recovery_code_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .run(rahulId, "rahul", "Rahul Sharma", "guardian", pwHash, recHash, now);

  await db
    .prepare(
      "INSERT OR IGNORE INTO users (id, username, name, role, password_hash, recovery_code_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .run(meeraId, "meera", "Meera Sharma", "guardian", pwHash, recHash, now);

  await ensureDefaultConsent(sunitaId);
  await db
    .prepare(
      `INSERT OR IGNORE INTO guardian_links (id, parent_id, guardian_id, invite_code, status, is_secondary, created_at, verified_at)
       VALUES (?, ?, ?, ?, 'active', 0, ?, ?)`
    )
    .run("lnk_demo_1", sunitaId, rahulId, "DEMO-LINK-1", now, now);

  await db
    .prepare(
      `INSERT OR IGNORE INTO guardian_links (id, parent_id, guardian_id, invite_code, status, is_secondary, created_at, verified_at)
       VALUES (?, ?, ?, ?, 'active', 1, ?, ?)`
    )
    .run("lnk_demo_2", sunitaId, meeraId, "DEMO-LINK-2", now, now);

  return true;
}
