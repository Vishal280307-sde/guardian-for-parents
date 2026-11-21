import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db, DbNotConfiguredError, getDbMode, initDb } from "./server/db.ts";
import {
  attachAuth,
  checkRateLimit,
  clearSession,
  createNotification,
  createSession,
  ensureDefaultConsent,
  ensureDefaultQrNotificationPrefs,
  generateId,
  getActiveGuardiansForParent,
  getActiveLinkedParentIds,
  hashSecret,
  requireAuth,
  requireRole,
  sanitizeAuditText,
  seedInitialDemoUsersIfEmpty,
  verifySecret,
  writeAudit,
  type AuthedRequest,
} from "./server/security.ts";
import {
  chatWithGemini,
  explainRiskWithGemini,
  extractScreenshotTextWithGemini,
  redactSensitive,
} from "./server/ai.ts";
import { runFullQrIntelligencePipeline } from "./server/qrIntelligence.ts";
import {
  cleanupCallWatcherRetention,
  endActiveCallEvent,
  getCallWatcherDashboard,
  getGuardianSharedCallWatcher,
  getLocalCallThreatCache,
  markCallerTrustedWithSafeguard,
  notifyLinkedGuardiansFromAssistant,
  recordCallWatcherCall,
  recordPaymentMessageEvent,
  screenIncomingCaller,
  submitSafetyQuestionnaire,
  updateCallWatcherConsent,
  updateCallWatcherDeviceStatus,
} from "./server/callWatcher.ts";
import { analyzeUrlIntelligence, extractUrlsFromText } from "./server/linkIntelligence.ts";
import {
  buildPeriodicReport,
  cleanupGsiRetention,
  getGsiDashboardState,
  getGuardianSharedGsiOverview,
  ingestGsiEvent,
  recordGsiFeedback,
} from "./server/gsi.ts";
import {
  buildFamilySyncPayload,
  correctRelationship,
  deleteGcihDataForOwner,
  extractEntitiesFromPayment,
  getSharedIntelligenceForSection,
  lookupSharedEntitiesForQuery,
  registerFamilyDevice,
  revokeFamilyDevice,
  submitEntityFeedback,
  updateDevicePermissions,
  updateIncidentWorkflow,
  type GcihDevicePermissions,
  type GcihIncidentWorkflowStatus,
  type GcihSectionKey,
} from "./server/gcih.ts";
import {
  askParentsAiTool,
  assertNoBankingCredentials,
  connectSampleAaBank,
  createToolItem,
  deleteFamilyBudget,
  deleteParentsAiDataForOwner,
  deleteToolItem,
  getParentsAiState,
  revokeBankConnection,
  updateFinancialAccessControl,
  updateToolItem,
  upsertFamilyBudget,
} from "./server/parentsAi.ts";
import {
  activateEmergencyPaymentLock,
  deleteEppDataForOwner,
  getEmergencyPaymentDashboard,
  listBankDirectory,
  markBankServiceUserConfirmed,
  recordBankBlockingAction,
  seedDefaultBankDirectoryIfEmpty,
  unlockEmergencyPaymentLock,
  upsertAndVerifyBankEntry,
} from "./server/emergencyPayment.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;

let readyPromise: Promise<void> | null = null;
let readyInitialized = false;

export async function ensureServerReady(): Promise<void> {
  if (readyInitialized) return;
  if (!readyPromise) {
    readyPromise = (async () => {
      await initDb();
      await seedInitialDemoUsersIfEmpty();
      await seedDefaultBankDirectoryIfEmpty();
      readyInitialized = true;
    })().catch((err) => {
      readyPromise = null;
      readyInitialized = false;
      throw err;
    });
  }
  await readyPromise;
}

export function resetServerReadyForTests(): void {
  readyPromise = null;
  readyInitialized = false;
}

function asyncHandler<TReq extends express.Request = express.Request>(
  fn: (req: TReq, res: express.Response, next: express.NextFunction) => Promise<unknown> | unknown
): express.RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req as TReq, res, next)).catch(next);
  };
}

async function formatApprovalRequest(row: Record<string, unknown>) {
  const now = Date.now();
  let st = String(row.status);
  if (st === "pending" && Number(row.expires_at) < now) {
    await db
      .prepare("UPDATE approval_requests SET status = 'expired' WHERE id = ? AND status = 'pending'")
      .run(String(row.id));
    st = "expired";
  }
  return {
    id: String(row.id),
    parentId: String(row.parent_id),
    amt: Number(row.amount),
    ben: String(row.beneficiary),
    level: String(row.level),
    sig: JSON.parse(String(row.signals_json || "[]")) as string[],
    exp: Number(row.expires_at),
    st,
    used: st === "consumed",
    decidedBy: row.decided_by ? String(row.decided_by) : null,
    decidedAt: row.decided_at ? Number(row.decided_at) : null,
    verifiedCallback: Boolean(row.verified_callback),
    verificationNote: row.verification_note ? String(row.verification_note) : null,
    escalatedToSecondary: Boolean(row.escalated_to_secondary),
  };
}

function getAllowedCorsOrigins(): Set<string> {
  const origins = new Set<string>([
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://localhost",
    "capacitor://localhost",
  ]);
  const envOrigins = String(process.env.CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const o of envOrigins) origins.add(o);
  for (const rawHost of [
    process.env.APP_URL,
    process.env.RENDER_EXTERNAL_URL,
    process.env.RENDER_EXTERNAL_HOSTNAME,
    process.env.VERCEL_URL,
    process.env.VERCEL_BRANCH_URL,
    process.env.VERCEL_PROJECT_PRODUCTION_URL,
  ]) {
    if (!rawHost) continue;
    const normalized = /^https?:\/\//i.test(rawHost) ? rawHost : `https://${rawHost}`;
    try {
      origins.add(new URL(normalized).origin);
    } catch {
      // ignore invalid URL
    }
  }
  return origins;
}

export function createApp() {
  const app = express();
  app.set("trust proxy", 1);

  const allowedOrigins = getAllowedCorsOrigins();
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const reqHost = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
    let isSameHostOrigin = false;
    if (origin && reqHost) {
      try {
        isSameHostOrigin = new URL(origin).host === reqHost;
      } catch {
        isSameHostOrigin = false;
      }
    }
    if (origin && (allowedOrigins.has(origin) || isSameHostOrigin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    }
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(express.json({ limit: "8mb" }));

  app.get("/health", async (_req, res) => {
    try {
      await ensureServerReady();
      await db.prepare("SELECT 1 as ok").get();
      res.json({
        ok: true,
        status: "healthy",
        db: "connected",
        dbMode: getDbMode(),
        uptimeSec: Math.round(process.uptime()),
        nodeVersion: process.version,
        timestamp: Date.now(),
      });
    } catch (err) {
      const code = err instanceof DbNotConfiguredError ? err.code : "DB_ERROR";
      const status = err instanceof DbNotConfiguredError ? err.statusCode : 503;
      res.status(status).json({
        ok: false,
        status: "unhealthy",
        db: "error",
        code,
        dbMode: getDbMode(),
        error: err instanceof Error ? err.message : "Database unavailable.",
        timestamp: Date.now(),
      });
    }
  });

  app.use(
    "/api",
    asyncHandler(async (_req, _res, next) => {
      await ensureServerReady();
      next();
    })
  );
  app.use("/api", asyncHandler(attachAuth as (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<void>));

  /* ---- Auth ---- */
  app.post(
    "/api/auth/register",
    asyncHandler(async (req, res) => {
      const ip = req.ip || "local";
      if (!checkRateLimit(`reg:${ip}`, 15, 60_000)) {
        res.status(429).json({ error: "Too many registration attempts. Please wait a minute." });
        return;
      }

      const username = String(req.body?.username || "").trim().toLowerCase();
      const name = String(req.body?.name || "").trim().slice(0, 60);
      const password = String(req.body?.password || "");
      const role = req.body?.role === "guardian" ? "guardian" : req.body?.role === "parent" ? "parent" : null;

      if (!role || !/^[a-z0-9_]{3,20}$/.test(username) || name.length < 2 || password.length < 8) {
        res.status(400).json({
          error: "Use a username (3–20 lowercase letters/digits/_), a name (2+ chars), a valid role, and a password of 8+ characters.",
        });
        return;
      }

      const existing = await db.prepare("SELECT id FROM users WHERE username = ?").get(username);
      if (existing) {
        res.status(409).json({ error: "That username is already taken." });
        return;
      }

      const id = generateId("usr");
      const recoveryCode = `GRD-${crypto.randomBytes(3).toString("hex").toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
      const now = Date.now();
      await db
        .prepare(
          `INSERT INTO users (id, username, name, role, password_hash, recovery_code_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(id, username, name, role, hashSecret(password), hashSecret(recoveryCode), now);

      if (role === "parent") {
        await ensureDefaultConsent(id);
      }
      await writeAudit(id, `Account registered (${role})`);
      res.status(201).json({
        ok: true,
        recoveryCode,
        message: "Account created. Save your recovery code safely—it is shown only once.",
      });
    })
  );

  app.post(
    "/api/auth/login",
    asyncHandler(async (req, res) => {
      const ip = req.ip || "local";
      if (!checkRateLimit(`login:${ip}`, 25, 60_000)) {
        res.status(429).json({ error: "Too many login attempts. Please wait a minute." });
        return;
      }

      const username = String(req.body?.username || "").trim().toLowerCase();
      const password = String(req.body?.password || "");
      const role = req.body?.role === "guardian" ? "guardian" : req.body?.role === "parent" ? "parent" : null;

      if (!username || !password || !role) {
        res.status(400).json({ error: "Username, password, and role are required." });
        return;
      }

      const user = (await db.prepare("SELECT * FROM users WHERE username = ?").get(username)) as
        | {
            id: string;
            username: string;
            name: string;
            role: "parent" | "guardian";
            password_hash: string;
            failed_attempts: number;
            locked_until: number;
          }
        | undefined;

      const now = Date.now();
      if (user && user.locked_until > now) {
        const secs = Math.ceil((user.locked_until - now) / 1000);
        res.status(429).json({ error: `Account temporarily locked. Try again in ${secs}s.` });
        return;
      }

      if (!user || user.role !== role || !verifySecret(password, user.password_hash)) {
        if (user) {
          const nextTries = user.failed_attempts + 1;
          const lockUntil = nextTries >= 5 ? now + Math.min(300_000, 30_000 * (nextTries - 4)) : 0;
          await db
            .prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?")
            .run(nextTries, lockUntil, user.id);
          if (lockUntil > 0) {
            await writeAudit(user.id, "Account temporarily locked after failed login attempts");
          }
        }
        res.status(401).json({ error: "Incorrect username, password, or role." });
        return;
      }

      await db.prepare("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?").run(user.id);
      if (user.role === "parent") await ensureDefaultConsent(user.id);

      const authUser = {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role,
      };
      const sessionToken = await createSession(req, res, authUser);
      await writeAudit(user.id, `Login (${user.role})`);
      res.json({ user: authUser, sessionToken });
    })
  );

  app.post(
    "/api/auth/recover",
    asyncHandler(async (req, res) => {
      const ip = req.ip || "local";
      if (!checkRateLimit(`rec:${ip}`, 10, 60_000)) {
        res.status(429).json({ error: "Too many recovery attempts. Please wait a minute." });
        return;
      }
      const username = String(req.body?.username || "").trim().toLowerCase();
      const recoveryCode = String(req.body?.recoveryCode || "").trim();
      const newPassword = String(req.body?.newPassword || "");

      if (!username || !recoveryCode || newPassword.length < 8) {
        res.status(400).json({ error: "Provide username, recovery code, and a new password (8+ chars)." });
        return;
      }

      const user = (await db.prepare("SELECT * FROM users WHERE username = ?").get(username)) as
        | { id: string; recovery_code_hash: string }
        | undefined;

      if (!user || !verifySecret(recoveryCode, user.recovery_code_hash)) {
        res.status(401).json({ error: "Invalid username or recovery code." });
        return;
      }

      const nextRecovery = `GRD-${crypto.randomBytes(3).toString("hex").toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
      await db
        .prepare("UPDATE users SET password_hash = ?, recovery_code_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?")
        .run(hashSecret(newPassword), hashSecret(nextRecovery), user.id);
      await db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
      await writeAudit(user.id, "Password reset via recovery code");
      res.json({
        ok: true,
        recoveryCode: nextRecovery,
        message: "Password updated. Save your new recovery code.",
      });
    })
  );

  app.post(
    "/api/auth/logout",
    asyncHandler(async (req: AuthedRequest, res) => {
      if (req.authUser) {
        await writeAudit(req.authUser.id, "Logout");
      }
      await clearSession(req, res);
      res.json({ ok: true });
    })
  );

  app.get("/api/auth/me", (req: AuthedRequest, res) => {
    if (!req.authUser) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }
    res.json({ user: req.authUser });
  });

  /* ---- State Hydration ---- */
  app.get(
    "/api/state",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const now = Date.now();

      if (user.role === "parent") {
        await ensureDefaultConsent(user.id);
        const consent = (await db.prepare("SELECT * FROM consents WHERE user_id = ?").get(user.id)) as Record<string, number>;
        const retentionMs = Math.max(1, Number(consent.retention_days || 30)) * 86_400_000;
        const cutoff = now - retentionMs;
        await db.prepare("DELETE FROM scam_analyses WHERE user_id = ? AND created_at < ?").run(user.id, cutoff);
        await db.prepare("DELETE FROM call_events WHERE user_id = ? AND created_at < ?").run(user.id, cutoff);
        await db.prepare("DELETE FROM qr_checks WHERE user_id = ? AND created_at < ?").run(user.id, cutoff);
        await db.prepare("DELETE FROM qr_scan_records WHERE user_id = ? AND created_at < ?").run(user.id, cutoff);
        await cleanupCallWatcherRetention(user.id, Number(consent.retention_days || 30));
        await cleanupGsiRetention(user.id, Number(consent.retention_days || 30));

        const reqRows = (await db
          .prepare("SELECT * FROM approval_requests WHERE parent_id = ? ORDER BY created_at DESC LIMIT 30")
          .all(user.id)) as Record<string, unknown>[];
        const reqs = await Promise.all(reqRows.map(formatApprovalRequest));

        const audit = (
          (await db
            .prepare("SELECT event, hash, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 30")
            .all(user.id)) as { event: string; hash: string; created_at: number }[]
        ).map((a) => ({ t: new Date(a.created_at).toLocaleTimeString(), ev: a.event, h: a.hash }));

        const calls = (
          (await db
            .prepare("SELECT started_at, ended_at, duration_ms, known FROM call_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 20")
            .all(user.id)) as { started_at: number; ended_at: number; duration_ms: number; known: number }[]
        ).map((c) => ({ s: c.started_at, e: c.ended_at, dur: c.duration_ms, known: Boolean(c.known) }));

        const incidents = (
          (await db
            .prepare("SELECT summary, channel, status, created_at FROM incidents WHERE user_id = ? ORDER BY created_at DESC LIMIT 20")
            .all(user.id)) as { summary: string; channel: string; status: string; created_at: number }[]
        ).map((i) => ({ a: `${i.summary} (${i.channel})`, d: new Date(i.created_at).toLocaleDateString(), s: i.status }));

        const safeWordRow = (await db.prepare("SELECT updated_at FROM safe_words WHERE user_id = ?").get(user.id)) as
          | { updated_at: number }
          | undefined;

        const links = await db
          .prepare(
            `SELECT gl.id, gl.invite_code, gl.status, gl.is_secondary, u.name as guardian_name, u.username as guardian_username
             FROM guardian_links gl
             LEFT JOIN users u ON u.id = gl.guardian_id
             WHERE gl.parent_id = ?
             ORDER BY gl.created_at DESC`
          )
          .all(user.id);

        const notifications = await db
          .prepare("SELECT id, kind, title, body, delivery_status, read_at, created_at FROM notifications WHERE recipient_id = ? ORDER BY created_at DESC LIMIT 20")
          .all(user.id);

        const reports = await db
          .prepare("SELECT id, masked_excerpt, cat, status, created_at FROM scam_reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 20")
          .all(user.id);

        const qrScans = (await db
          .prepare("SELECT id, qr_format, qr_classification, upi_id, payee_name, amount, amount_state, security_risk_level, payment_load_category, payment_load_risk_level, created_at FROM qr_scan_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 15")
          .all(user.id)) as Record<string, unknown>[];
        const qrPrefs = await ensureDefaultQrNotificationPrefs(user.id);
        const callWatcher = await getCallWatcherDashboard(user.id);
        const gsi = await getGsiDashboardState(user.id);
        const gcih = await buildFamilySyncPayload({ familyOwnerId: user.id });

        res.json({
          user,
          consent: {
            text: Boolean(consent.text_analysis),
            galerts: Boolean(consent.guardian_alerts),
            gapprove: Boolean(consent.guardian_approve),
            calls: Boolean(consent.call_timing),
            paused: Boolean(consent.paused),
            limit: Number(consent.payment_limit),
            medThreshold: Number(consent.med_threshold),
            highThreshold: Number(consent.high_threshold),
            retentionDays: Number(consent.retention_days),
            loadModerateMax: Number(consent.load_moderate_max ?? 2000),
            loadHighMax: Number(consent.load_high_max ?? 10000),
            loadVeryHighMin: Number(consent.load_very_high_min ?? 25000),
            redAlertCooldownSec: Number(consent.red_alert_cooldown_sec ?? 600),
          },
          qrPrefs,
          qrScans,
          callWatcher,
          gsi,
          gcih,
          hasSafeWord: Boolean(safeWordRow),
          reqs,
          audit,
          calls,
          incidents,
          links,
          notifications,
          reports,
        });
        return;
      }

      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      const linkedParents = linkedParentIds.length
        ? ((await db
            .prepare(
              `SELECT u.id, u.name, u.username, c.guardian_approve, c.guardian_alerts, gl.is_secondary
               FROM guardian_links gl
               JOIN users u ON u.id = gl.parent_id
               LEFT JOIN consents c ON c.user_id = u.id
               WHERE gl.guardian_id = ? AND gl.status = 'active'`
            )
            .all(user.id)) as Record<string, unknown>[])
        : [];

      const rawGuardianReqs = linkedParentIds.length
        ? ((await db
            .prepare(
              `SELECT ar.*, u.name as parent_name
               FROM approval_requests ar
               JOIN users u ON u.id = ar.parent_id
               WHERE ar.parent_id IN (${linkedParentIds.map(() => "?").join(",")})
               ORDER BY ar.created_at DESC LIMIT 30`
            )
            .all(...linkedParentIds)) as Record<string, unknown>[])
        : [];
      const reqs = await Promise.all(
        rawGuardianReqs.map(async (r) => ({
          ...(await formatApprovalRequest(r)),
          parentName: String(r.parent_name),
        }))
      );

      const permittedParentIds = linkedParents
        .filter((p) => Boolean(p.guardian_alerts))
        .map((p) => String(p.id));

      const linkedQrScans = permittedParentIds.length
        ? ((await db
            .prepare(
              `SELECT q.id, q.user_id as parent_id, u.name as parent_name, q.qr_format, q.qr_classification,
                      q.upi_id, q.payee_name, q.amount, q.amount_state, q.security_risk_level,
                      q.payment_load_category, q.payment_load_risk_level, q.created_at
               FROM qr_scan_records q
               JOIN users u ON u.id = q.user_id
               JOIN consents c ON c.user_id = q.user_id
               WHERE q.user_id IN (${permittedParentIds.map(() => "?").join(",")})
                 AND c.guardian_alerts = 1 AND c.paused = 0
               ORDER BY q.created_at DESC LIMIT 15`
            )
            .all(...permittedParentIds)) as Record<string, unknown>[])
        : [];

      const audit = (
        (await db
          .prepare("SELECT event, hash, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 30")
          .all(user.id)) as { event: string; hash: string; created_at: number }[]
      ).map((a) => ({ t: new Date(a.created_at).toLocaleTimeString(), ev: a.event, h: a.hash }));

      const notifications = await db
        .prepare("SELECT id, kind, title, body, delivery_status, read_at, created_at FROM notifications WHERE recipient_id = ? ORDER BY created_at DESC LIMIT 25")
        .all(user.id);

      const qrPrefs = await ensureDefaultQrNotificationPrefs(user.id);
      const alertParents = linkedParents
        .filter((p) => Boolean(p.guardian_alerts))
        .map((p) => ({ id: String(p.id), name: String(p.name) }));
      const linkedCallWatcherEvents = await getGuardianSharedCallWatcher(alertParents);
      const linkedGsiOverview = await getGuardianSharedGsiOverview(alertParents);

      const linkedGcihSync = (
        await Promise.all(
          linkedParents
            .filter((p) => Boolean(p.guardian_alerts))
            .map(async (p) => {
              const pid = String(p.id);
              const cRow = (await db.prepare("SELECT paused FROM consents WHERE user_id = ?").get(pid)) as
                | { paused: number }
                | undefined;
              if (cRow?.paused) return null;
              return buildFamilySyncPayload({ familyOwnerId: pid });
            })
        )
      ).filter(Boolean);

      res.json({
        user,
        linkedParents,
        reqs,
        audit,
        notifications,
        qrPrefs,
        linkedQrScans,
        linkedCallWatcherEvents,
        linkedGsiOverview,
        linkedGcihSync,
      });
    })
  );

  /* ---- Parent–Guardian Linking ---- */
  app.post(
    "/api/links/invite",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const isSecondary = req.body?.isSecondary ? 1 : 0;
      const inviteCode = `INV-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
      const id = generateId("lnk");
      await db
        .prepare(
          `INSERT INTO guardian_links (id, parent_id, guardian_id, invite_code, status, is_secondary, created_at)
           VALUES (?, ?, NULL, ?, 'pending', ?, ?)`
        )
        .run(id, parentId, inviteCode, isSecondary, Date.now());
      await writeAudit(parentId, `Created guardian invite (${isSecondary ? "secondary" : "primary"})`);
      res.status(201).json({ id, inviteCode, isSecondary: Boolean(isSecondary) });
    })
  );

  app.post(
    "/api/links/accept",
    requireRole("guardian"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const guardianId = req.authUser!.id;
      const inviteCode = String(req.body?.inviteCode || "").trim().toUpperCase();
      if (!inviteCode) {
        res.status(400).json({ error: "Invite code is required." });
        return;
      }
      const link = (await db
        .prepare("SELECT * FROM guardian_links WHERE invite_code = ? AND status = 'pending'")
        .get(inviteCode)) as { id: string; parent_id: string } | undefined;

      if (!link) {
        res.status(404).json({ error: "Invalid or already used invite code." });
        return;
      }

      const alreadyActive = await db
        .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
        .get(link.parent_id, guardianId);
      if (alreadyActive) {
        res.status(409).json({ error: "You are already linked to this parent." });
        return;
      }

      const now = Date.now();
      await db
        .prepare("UPDATE guardian_links SET guardian_id = ?, status = 'active', verified_at = ? WHERE id = ?")
        .run(guardianId, now, link.id);

      await writeAudit(guardianId, "Accepted parent guardian invitation");
      await writeAudit(link.parent_id, "Guardian link verified and activated");
      await createNotification(
        link.parent_id,
        link.parent_id,
        "link_verified",
        "Guardian linked",
        `${req.authUser!.name} accepted your guardian invite.`
      );
      res.json({ ok: true });
    })
  );

  app.post(
    "/api/links/:id/revoke",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const linkId = String(req.params.id);
      const link = (await db
        .prepare("SELECT id, guardian_id FROM guardian_links WHERE id = ? AND parent_id = ?")
        .get(linkId, parentId)) as { id: string; guardian_id: string | null } | undefined;
      if (!link) {
        res.status(404).json({ error: "Link not found." });
        return;
      }
      await db.prepare("UPDATE guardian_links SET status = 'revoked', revoked_at = ? WHERE id = ?").run(
        Date.now(),
        linkId
      );
      await writeAudit(parentId, "Revoked guardian link");
      if (link.guardian_id) {
        await db
          .prepare("UPDATE gcih_devices SET status = 'revoked', revoked_at = ? WHERE family_owner_id = ? AND user_id = ?")
          .run(Date.now(), parentId, link.guardian_id);
        await writeAudit(link.guardian_id, "Guardian access revoked by parent");
      }
      res.json({ ok: true });
    })
  );

  /* ---- Privacy & Consents ---- */
  app.put(
    "/api/privacy/consents",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      await ensureDefaultConsent(userId);
      const b = req.body || {};
      const limit = Math.max(1000, Math.min(500000, Math.round(Number(b.limit) || 10000)));
      const medThreshold = Math.max(10, Math.min(45, Math.round(Number(b.medThreshold) || 25)));
      const highThreshold = Math.max(medThreshold + 10, Math.min(85, Math.round(Number(b.highThreshold) || 50)));
      const retentionDays = Math.max(1, Math.min(365, Math.round(Number(b.retentionDays) || 30)));
      const loadModerateMax = Math.max(100, Math.min(200000, Math.round(Number(b.loadModerateMax) || 2000)));
      const loadHighMax = Math.max(loadModerateMax + 500, Math.min(500000, Math.round(Number(b.loadHighMax) || 10000)));
      const loadVeryHighMin = Math.max(loadHighMax + 1000, Math.min(1000000, Math.round(Number(b.loadVeryHighMin) || 25000)));
      const redAlertCooldownSec = Math.max(60, Math.min(3600, Math.round(Number(b.redAlertCooldownSec) || 600)));

      await db
        .prepare(
          `UPDATE consents SET
             text_analysis = ?,
             guardian_alerts = ?,
             guardian_approve = ?,
             call_timing = ?,
             paused = ?,
             payment_limit = ?,
             med_threshold = ?,
             high_threshold = ?,
             retention_days = ?,
             load_moderate_max = ?,
             load_high_max = ?,
             load_very_high_min = ?,
             red_alert_cooldown_sec = ?,
             updated_at = ?
           WHERE user_id = ?`
        )
        .run(
          b.text ? 1 : 0,
          b.galerts ? 1 : 0,
          b.gapprove ? 1 : 0,
          b.calls ? 1 : 0,
          b.paused ? 1 : 0,
          limit,
          medThreshold,
          highThreshold,
          retentionDays,
          loadModerateMax,
          loadHighMax,
          loadVeryHighMin,
          redAlertCooldownSec,
          Date.now(),
          userId
        );
      await writeAudit(userId, "Updated privacy and consent settings");
      res.json({ ok: true });
    })
  );

  app.post(
    "/api/privacy/revoke-guardians",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const now = Date.now();
      await db
        .prepare("UPDATE consents SET guardian_alerts = 0, guardian_approve = 0, updated_at = ? WHERE user_id = ?")
        .run(now, userId);
      await db
        .prepare("UPDATE guardian_links SET status = 'revoked', revoked_at = ? WHERE parent_id = ? AND status = 'active'")
        .run(now, userId);
      await db
        .prepare("UPDATE gcih_devices SET status = 'revoked', revoked_at = ? WHERE family_owner_id = ? AND role = 'guardian'")
        .run(now, userId);
      await writeAudit(userId, "Removed all guardian access");
      res.json({ ok: true });
    })
  );

  app.get(
    "/api/privacy/export",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const [
        consent,
        requests,
        calls,
        qrScans,
        callWatcherSettings,
        callWatcherCalls,
        paymentMessageEvents,
        callPaymentCorrelations,
        gsiIncidents,
        gsiThreatIntel,
        gsiReports,
        gcihEntities,
        gcihRelationships,
        gcihDomainEvents,
        gcihDevices,
        eppSessions,
        eppBankActions,
        eppAuditTrail,
        incidents,
        auditLogs,
      ] = await Promise.all([
        db.prepare("SELECT * FROM consents WHERE user_id = ?").get(userId),
        db.prepare("SELECT id, amount, beneficiary, level, status, created_at FROM approval_requests WHERE parent_id = ?").all(userId),
        db.prepare("SELECT started_at, ended_at, duration_ms, known FROM call_events WHERE user_id = ?").all(userId),
        db.prepare("SELECT id, qr_format, qr_classification, upi_id, payee_name, amount, amount_state, security_risk_level, payment_load_category, created_at FROM qr_scan_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT * FROM call_watcher_settings WHERE user_id = ?").get(userId),
        db.prepare("SELECT id, caller_classification, caller_masked, call_status, incoming_at, duration_ms, source, created_at FROM call_watcher_calls WHERE user_id = ? ORDER BY incoming_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT id, sender_label, message_ts, amount, currency, tx_type, account_masked, merchant_or_recipient, payment_status, redacted_summary, source, created_at FROM payment_message_events WHERE user_id = ? ORDER BY message_ts DESC LIMIT 50").all(userId),
        db.prepare("SELECT id, time_diff_ms, during_call, call_risk_level, payment_risk_level, status, created_at FROM call_payment_correlations WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT incident_id, incident_category, risk_score, severity, confidence, detection_source, reasoning_summary, acknowledgement_status, resolution_status, workflow_status, created_at FROM gsi_incidents WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT id, indicator_type, indicator_display, reputation_label, confidence, report_count, false_positive_count, updated_at FROM gsi_threat_intel WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT id, period_type, period_key, created_at FROM gsi_reports WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 20").all(userId),
        db.prepare("SELECT id, entity_type, masked_display, risk_classification, verification_status, source_modules_json, version, updated_at FROM gcih_entities WHERE family_owner_id = ? ORDER BY updated_at DESC LIMIT 60").all(userId),
        db.prepare("SELECT id, first_entity_id, second_entity_id, relationship_type, status, confidence, updated_at FROM gcih_relationships WHERE family_owner_id = ? ORDER BY updated_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT id, source_module, event_type, sync_status, event_timestamp FROM gcih_domain_events WHERE family_owner_id = ? ORDER BY event_timestamp DESC LIMIT 60").all(userId),
        db.prepare("SELECT id, device_label, platform, role, status, last_seen_at FROM gcih_devices WHERE family_owner_id = ?").all(userId),
        db.prepare("SELECT id, status, duration_option, os_enforcement_mode, activated_at, expires_at, unlocked_at FROM epp_lock_sessions WHERE family_owner_id = ? ORDER BY activated_at DESC LIMIT 30").all(userId),
        db.prepare("SELECT id, bank_name, service_type, launch_type, bank_confirmed_by_user, created_at FROM epp_bank_action_logs WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 30").all(userId),
        db.prepare("SELECT action, details, hash, created_at FROM epp_audit_trail WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 50").all(userId),
        db.prepare("SELECT summary, channel, status, created_at FROM incidents WHERE user_id = ?").all(userId),
        db.prepare("SELECT event, hash, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100").all(userId),
      ]);
      const payload = {
        exportedAt: new Date().toISOString(),
        user: req.authUser,
        consent,
        requests,
        calls,
        qrScans,
        callWatcherSettings,
        callWatcherCalls,
        paymentMessageEvents,
        callPaymentCorrelations,
        gsiIncidents,
        gsiThreatIntel,
        gsiReports,
        gcihEntities,
        gcihRelationships,
        gcihDomainEvents,
        gcihDevices,
        eppSessions,
        eppBankActions,
        eppAuditTrail,
        incidents,
        auditLogs,
      };
      await writeAudit(userId, "Exported personal safety data");
      res.json(payload);
    })
  );

  app.delete(
    "/api/privacy/data",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      await deleteGcihDataForOwner(userId);
      await deleteParentsAiDataForOwner(userId);
      await deleteEppDataForOwner(userId);
      await db.prepare("DELETE FROM approval_requests WHERE parent_id = ?").run(userId);
      await db.prepare("DELETE FROM payment_assessments WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM scam_analyses WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM scam_reports WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM qr_checks WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM qr_scan_records WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM qr_notification_prefs WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM safety_questionnaire_responses WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM call_payment_correlations WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM payment_message_events WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM call_watcher_calls WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM call_watcher_settings WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM call_events WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM gsi_incidents WHERE family_owner_id = ?").run(userId);
      await db.prepare("DELETE FROM gsi_events WHERE family_owner_id = ?").run(userId);
      await db.prepare("DELETE FROM gsi_threat_intel WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM gsi_reports WHERE family_owner_id = ?").run(userId);
      await db.prepare("DELETE FROM incidents WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM safe_words WHERE user_id = ?").run(userId);
      await db.prepare("DELETE FROM notifications WHERE recipient_id = ? OR parent_id = ?").run(userId, userId);
      await db.prepare("DELETE FROM audit_logs WHERE user_id = ?").run(userId);
      await clearSession(req, res);
      res.json({ ok: true });
    })
  );

  /* ---- Safe Word ---- */
  app.post(
    "/api/safeword/set",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const value = String(req.body?.safeWord || "").trim().toLowerCase();
      if (value.length < 6 || !/[a-z]/i.test(value)) {
        res.status(400).json({ error: "Safe word must be at least 6 characters and include letters." });
        return;
      }
      const now = Date.now();
      const h = hashSecret(value);
      await db
        .prepare(
          `INSERT INTO safe_words (user_id, hash, failed_attempts, locked_until, updated_at)
           VALUES (?, ?, 0, 0, ?)
           ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, failed_attempts = 0, locked_until = 0, updated_at = excluded.updated_at`
        )
        .run(userId, h, now);
      await writeAudit(userId, "Safe word saved (salted scrypt hash only)");
      res.json({ ok: true });
    })
  );

  app.post(
    "/api/safeword/verify",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const value = String(req.body?.safeWord || "").trim().toLowerCase();
      const row = (await db.prepare("SELECT * FROM safe_words WHERE user_id = ?").get(userId)) as
        | { hash: string; failed_attempts: number; locked_until: number }
        | undefined;

      if (!row) {
        res.status(400).json({ error: "Set a family safe word first." });
        return;
      }
      const now = Date.now();
      if (row.locked_until > now) {
        const secs = Math.ceil((row.locked_until - now) / 1000);
        res.status(429).json({ error: `Safe-word verification temporarily locked. Wait ${secs}s.` });
        return;
      }

      const ok = verifySecret(value, row.hash);
      if (!ok) {
        const next = row.failed_attempts + 1;
        const lockUntil = next >= 5 ? now + 300_000 : 0;
        await db
          .prepare("UPDATE safe_words SET failed_attempts = ?, locked_until = ? WHERE user_id = ?")
          .run(next, lockUntil, userId);
        await writeAudit(userId, "Safe word check: FAILED");
        res.json({
          match: false,
          locked: lockUntil > 0,
          message: lockUntil > 0
            ? "Too many failed attempts. Safe-word check locked for 5 minutes. Hang up and call your guardian."
            : "No match. Hang up and call the person on their saved number.",
        });
        return;
      }

      await db.prepare("UPDATE safe_words SET failed_attempts = 0, locked_until = 0 WHERE user_id = ?").run(userId);
      await writeAudit(userId, "Safe word check: match");
      res.json({
        match: true,
        message: "Safe word matches. Still call the person back on their independently saved number—a safe word alone is not full proof.",
      });
    })
  );

  /* ---- Scam Records & Reporting ---- */
  app.post(
    "/api/scam/record",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const score = Number(req.body?.score || 0);
      const level = String(req.body?.level || "LOW");
      const cat = String(req.body?.cat || "none_detected").slice(0, 50);
      const signals = Array.isArray(req.body?.sig) ? req.body.sig.slice(0, 12).map(String) : [];
      const aiUsed = req.body?.aiUsed ? 1 : 0;
      const rawText = typeof req.body?.text === "string" ? req.body.text.trim().slice(0, 1500) : "";

      const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId : "web_session";
      const senderLabel = typeof req.body?.senderLabel === "string" ? req.body.senderLabel.slice(0, 40) : null;

      await db
        .prepare(
          "INSERT INTO scam_analyses (id, user_id, score, level, cat, signals_json, ai_used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .run(generateId("scm"), userId, score, level, cat, JSON.stringify(signals), aiUsed, Date.now());
      await writeAudit(userId, `Scam check run (${level})`);

      let gsiSummary: { eventId: string; incidentId: string; alertLevel: string } | null = null;
      const consentRow = (await db.prepare("SELECT text_analysis, paused FROM consents WHERE user_id = ?").get(userId)) as
        | { text_analysis: number; paused: number }
        | undefined;

      if (rawText && (!consentRow || (consentRow.text_analysis && !consentRow.paused))) {
        try {
          const ingested = await ingestGsiEvent({
            familyOwnerId: userId,
            familyOwnerName: req.authUser!.name,
            deviceId,
            eventType: "sms_event",
            sourceModule: "module_b_scam_check",
            lang: req.body?.lang === "hi" ? "hi" : "en",
            skipAi: true,
            smsData: { rawText, senderLabel },
          });
          gsiSummary = {
            eventId: ingested.eventId,
            incidentId: ingested.incident.incidentId,
            alertLevel: ingested.decision.alertLevel,
          };
        } catch {
          // Never block /api/scam/record
        }
      }

      res.json({ ok: true, ...(gsiSummary ? { gsi: gsiSummary } : {}) });
    })
  );

  app.post(
    "/api/scam/report",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const rawText = String(req.body?.text || "").trim();
      const cat = String(req.body?.cat || "other").slice(0, 50);
      if (rawText.length < 8) {
        res.status(400).json({ error: "Provide the suspicious message text to report." });
        return;
      }
      const masked = redactSensitive(rawText).slice(0, 320);
      const id = generateId("rpt");
      const createdAt = Date.now();
      await db
        .prepare("INSERT INTO scam_reports (id, user_id, masked_excerpt, cat, status, created_at) VALUES (?, ?, ?, ?, 'unverified', ?)")
        .run(id, userId, masked, cat, createdAt);
      await writeAudit(userId, `Reported suspicious message (${cat}, masked)`);
      res.status(201).json({
        id,
        masked_excerpt: masked,
        cat,
        status: "unverified",
        created_at: createdAt,
      });
    })
  );

  /* ---- Payment Assessment & Guardian Approval State Machine ---- */
  app.post(
    "/api/payments/assess",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const amt = Number(req.body?.amt);
      const ben = String(req.body?.ben || "").trim().slice(0, 120);
      const knownDeclared = req.body?.knownDeclared ? 1 : 0;
      const score = Math.max(0, Math.min(100, Number(req.body?.score || 0)));
      const level = String(req.body?.level || "LOW");
      const sig = Array.isArray(req.body?.sig) ? req.body.sig.slice(0, 15).map(String) : [];

      if (!Number.isFinite(amt) || amt <= 0) {
        res.status(400).json({ error: "Enter a valid positive amount." });
        return;
      }

      const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId : "web_session";
      const id = generateId("pay");
      await db
        .prepare(
          "INSERT INTO payment_assessments (id, user_id, amount, beneficiary, known_declared, score, level, signals_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .run(id, userId, amt, ben || "Unknown", knownDeclared, score, level, JSON.stringify(sig), Date.now());
      await writeAudit(userId, `Payment intent assessed (${level})`);

      let sharedIntelligence = await lookupSharedEntitiesForQuery({
        familyOwnerId: userId,
        candidates: extractEntitiesFromPayment({ beneficiary: ben, signals: sig }),
        currentSection: "payment_safety",
      });
      let gsiRiskScore = score;
      try {
        const ingested = await ingestGsiEvent({
          familyOwnerId: userId,
          familyOwnerName: req.authUser!.name,
          deviceId,
          eventType: "payment_event",
          sourceModule: "module_d_payment_safety",
          lang: req.body?.lang === "hi" ? "hi" : "en",
          skipAi: true,
          paymentData: {
            direction: "manual_intent",
            amount: amt,
            beneficiary: ben || null,
            knownDeclared: Boolean(knownDeclared),
            baseScore: score,
            signals: sig,
          },
        });
        gsiRiskScore = ingested.incident.riskScore;
        if (ingested.paymentIntel?.sharedAssociations?.length) {
          sharedIntelligence = ingested.paymentIntel.sharedAssociations;
        }
      } catch {
        // Never block payment assessment response
      }

      res.status(201).json({
        id,
        gsiRiskScore,
        ...(sharedIntelligence.length ? { sharedIntelligence } : {}),
      });
    })
  );

  app.post(
    "/api/requests",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const consent = (await db.prepare("SELECT guardian_approve, paused FROM consents WHERE user_id = ?").get(parentId)) as
        | { guardian_approve: number; paused: number }
        | undefined;

      if (!consent || !consent.guardian_approve || consent.paused) {
        res.status(403).json({ error: "Guardian approval is not enabled in Privacy." });
        return;
      }

      const amt = Number(req.body?.amt);
      const ben = String(req.body?.ben || "").trim().slice(0, 120);
      const level = String(req.body?.level || "MEDIUM");
      const sig = Array.isArray(req.body?.sig) ? req.body.sig.slice(0, 15).map(String) : [];
      const assessmentId = req.body?.assessmentId ? String(req.body.assessmentId) : null;

      if (!Number.isFinite(amt) || amt <= 0 || !ben) {
        res.status(400).json({ error: "Valid amount and beneficiary are required." });
        return;
      }

      const guardians = await getActiveGuardiansForParent(parentId);
      if (guardians.length === 0) {
        res.status(400).json({ error: "No active linked guardian. Invite and verify a guardian in Privacy first." });
        return;
      }

      const dup = (await db
        .prepare(
          `SELECT id FROM approval_requests
           WHERE parent_id = ? AND amount = ? AND beneficiary = ? AND status IN ('pending', 'verification_requested') AND expires_at > ?`
        )
        .get(parentId, amt, ben, Date.now())) as { id: string } | undefined;

      if (dup) {
        res.status(409).json({ error: "An active request for this exact payment already exists." });
        return;
      }

      const id = generateId("req");
      const now = Date.now();
      const expiresAt = now + 15 * 60 * 1000;
      await db
        .prepare(
          `INSERT INTO approval_requests (id, parent_id, assessment_id, amount, beneficiary, level, signals_json, status, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
        )
        .run(id, parentId, assessmentId, amt, ben, level, JSON.stringify(sig), expiresAt, now);

      for (const g of guardians.filter((x) => !x.is_secondary)) {
        await createNotification(
          g.guardian_id,
          parentId,
          "approval_request",
          `New ${level} payment review`,
          `${req.authUser!.name} requested review for ₹${amt.toLocaleString("en-IN")} to ${ben}.`
        );
      }

      await writeAudit(parentId, `Guardian request ${id} created (expires in 15 min)`);
      const row = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(id)) as Record<string, unknown>;
      res.status(201).json({ request: await formatApprovalRequest(row) });
    })
  );

  app.post(
    "/api/requests/:id/decide",
    requireRole("guardian"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const guardianId = req.authUser!.id;
      const reqId = String(req.params.id);
      const decision = String(req.body?.decision || "");
      const verifiedCallback = Boolean(req.body?.verifiedCallback);
      const note = String(req.body?.note || "").trim().slice(0, 180);

      if (!["approved", "rejected", "verification_requested"].includes(decision)) {
        res.status(400).json({ error: "Invalid decision." });
        return;
      }

      const row = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as
        | Record<string, unknown>
        | undefined;

      if (!row) {
        res.status(404).json({ error: "Request not found." });
        return;
      }

      const parentId = String(row.parent_id);
      const linked = await db
        .prepare("SELECT id FROM guardian_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'")
        .get(parentId, guardianId);
      if (!linked) {
        res.status(403).json({ error: "You are not an active linked guardian for this parent." });
        return;
      }

      const currentStatus = String(row.status);
      const now = Date.now();
      if (currentStatus !== "pending" || Number(row.expires_at) < now) {
        if (currentStatus === "pending" && Number(row.expires_at) < now) {
          await db.prepare("UPDATE approval_requests SET status = 'expired' WHERE id = ?").run(reqId);
        }
        await writeAudit(guardianId, `REJECTED: invalid/expired decision on ${reqId}`);
        res.status(409).json({ error: "Request expired or already decided." });
        return;
      }

      if (decision === "approved" && String(row.level) !== "LOW" && !verifiedCallback) {
        res.status(400).json({ error: "Tick that you verified by calling the parent on an independently saved number." });
        return;
      }

      await db
        .prepare(
          `UPDATE approval_requests
           SET status = ?, decided_by = ?, decided_at = ?, verified_callback = ?, verification_note = ?
           WHERE id = ?`
        )
        .run(decision, guardianId, now, verifiedCallback ? 1 : 0, note || null, reqId);

      await writeAudit(guardianId, `Guardian ${decision} ${reqId}`);
      await writeAudit(parentId, `Guardian ${req.authUser!.name} marked ${reqId} as ${decision}`);
      await createNotification(
        parentId,
        parentId,
        "guardian_decision",
        `Guardian ${decision.replace("_", " ")}`,
        `${req.authUser!.name} marked your ₹${Number(row.amount).toLocaleString("en-IN")} check as ${decision.replace("_", " ")}.${note ? " Note: " + note : ""}`
      );

      const updated = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as Record<string, unknown>;
      res.json({ request: await formatApprovalRequest(updated) });
    })
  );

  app.post(
    "/api/requests/:id/resubmit",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const reqId = String(req.params.id);
      const note = String(req.body?.note || "").trim().slice(0, 180);
      const row = (await db
        .prepare("SELECT * FROM approval_requests WHERE id = ? AND parent_id = ?")
        .get(reqId, parentId)) as Record<string, unknown> | undefined;

      if (!row) {
        res.status(404).json({ error: "Request not found." });
        return;
      }
      if (String(row.status) !== "verification_requested") {
        res.status(409).json({ error: "Only verification-requested items can be resubmitted." });
        return;
      }
      if (Number(row.expires_at) < Date.now()) {
        await db.prepare("UPDATE approval_requests SET status = 'expired' WHERE id = ?").run(reqId);
        res.status(409).json({ error: "Request has expired." });
        return;
      }
      if (!note || note.length < 4) {
        res.status(400).json({ error: "Enter a brief verification note before resubmitting." });
        return;
      }

      await db
        .prepare("UPDATE approval_requests SET status = 'pending', verification_note = ?, expires_at = ? WHERE id = ?")
        .run(note, Date.now() + 10 * 60 * 1000, reqId);

      for (const g of await getActiveGuardiansForParent(parentId)) {
        await createNotification(
          g.guardian_id,
          parentId,
          "verification_reply",
          "Parent replied to verification request",
          `${req.authUser!.name} added verification details for ${reqId}: ${note}`
        );
      }
      await writeAudit(parentId, `Parent resubmitted ${reqId} after verification`);
      const updated = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as Record<string, unknown>;
      res.json({ request: await formatApprovalRequest(updated) });
    })
  );

  app.post(
    "/api/requests/:id/escalate",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const reqId = String(req.params.id);
      const row = (await db
        .prepare("SELECT * FROM approval_requests WHERE id = ? AND parent_id = ?")
        .get(reqId, parentId)) as Record<string, unknown> | undefined;

      if (!row || String(row.status) !== "pending" || Number(row.expires_at) < Date.now()) {
        res.status(409).json({ error: "Only active pending requests can be escalated." });
        return;
      }

      const secondaries = (await getActiveGuardiansForParent(parentId)).filter((g) => g.is_secondary);
      if (secondaries.length === 0) {
        res.status(400).json({ error: "No secondary guardian linked. Add a secondary guardian invite in Privacy." });
        return;
      }

      await db.prepare("UPDATE approval_requests SET escalated_to_secondary = 1 WHERE id = ?").run(reqId);
      for (const g of secondaries) {
        await createNotification(
          g.guardian_id,
          parentId,
          "escalation",
          "Escalated payment review",
          `${req.authUser!.name} escalated ₹${Number(row.amount).toLocaleString("en-IN")} to secondary guardian.`
        );
      }
      await writeAudit(parentId, `Escalated request ${reqId} to secondary guardian`);
      const updated = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as Record<string, unknown>;
      res.json({ request: await formatApprovalRequest(updated) });
    })
  );

  app.post(
    "/api/requests/:id/consume",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const reqId = String(req.params.id);
      const row = (await db
        .prepare("SELECT * FROM approval_requests WHERE id = ? AND parent_id = ?")
        .get(reqId, parentId)) as Record<string, unknown> | undefined;
      const consent = (await db.prepare("SELECT paused FROM consents WHERE user_id = ?").get(parentId)) as
        | { paused: number }
        | undefined;

      if (!row || String(row.status) !== "approved" || Number(row.expires_at) < Date.now() || consent?.paused) {
        await writeAudit(parentId, `SECURITY: blocked replayed, expired or unapproved authorization ${reqId}`);
        res.status(403).json({ error: "Authorization is invalid (used, expired, paused, or not approved)." });
        return;
      }

      await db.prepare("UPDATE approval_requests SET status = 'consumed' WHERE id = ? AND status = 'approved'").run(reqId);
      await writeAudit(parentId, `Parent proceeded after verification (simulated, single-use) ${reqId}`);
      const updated = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as Record<string, unknown>;
      res.json({ request: await formatApprovalRequest(updated) });
    })
  );

  app.post(
    "/api/requests/:id/cancel",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const parentId = req.authUser!.id;
      const reqId = String(req.params.id);
      const row = (await db
        .prepare("SELECT * FROM approval_requests WHERE id = ? AND parent_id = ?")
        .get(reqId, parentId)) as Record<string, unknown> | undefined;

      if (!row || ["consumed", "cancelled", "rejected"].includes(String(row.status))) {
        res.status(409).json({ error: "Request cannot be cancelled in its current state." });
        return;
      }

      await db.prepare("UPDATE approval_requests SET status = 'cancelled' WHERE id = ?").run(reqId);
      await writeAudit(parentId, `Parent cancelled ${reqId}`);
      const updated = (await db.prepare("SELECT * FROM approval_requests WHERE id = ?").get(reqId)) as Record<string, unknown>;
      res.json({ request: await formatApprovalRequest(updated) });
    })
  );

  /* ---- Call Watch, QR, Incidents, Notifications ---- */
  app.post(
    "/api/calls/record",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const startedAt = Number(req.body?.s);
      const endedAt = Number(req.body?.e);
      const durationMs = Number(req.body?.dur);
      const known = req.body?.known ? 1 : 0;

      if (!Number.isFinite(startedAt) || !Number.isFinite(endedAt) || endedAt < startedAt || durationMs < 0) {
        res.status(400).json({ error: "Invalid call timestamps." });
        return;
      }

      await db
        .prepare("INSERT INTO call_events (id, user_id, started_at, ended_at, duration_ms, known, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(generateId("cal"), userId, startedAt, endedAt, durationMs, known, Date.now());
      await writeAudit(userId, `Call timing recorded (${known ? "saved" : "unknown"}, no audio)`);

      try {
        await ingestGsiEvent({
          familyOwnerId: userId,
          familyOwnerName: req.authUser!.name,
          eventType: "call_event",
          eventTimestamp: startedAt,
          sourceModule: "module_a_call_timer",
          callData: {
            callerClassification: known ? "Known Contact" : "Unknown Number",
            callStatus: "Answered",
            durationMs,
            known: Boolean(known),
          },
        });
      } catch {
        // Non-blocking GSI hook
      }

      res.json({ ok: true });
    })
  );

  app.post(
    "/api/calls/alert",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const level = String(req.body?.level || "MEDIUM");
      const summary = String(req.body?.summary || "").slice(0, 180);
      const consent = (await db.prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?").get(userId)) as
        | { guardian_alerts: number; paused: number }
        | undefined;

      await writeAudit(userId, `Call-payment timing pattern alert (${level})`);
      if (consent?.guardian_alerts && !consent.paused) {
        for (const g of await getActiveGuardiansForParent(userId)) {
          await createNotification(
            g.guardian_id,
            parentIdOrUser(userId),
            "call_timing_alert",
            `Call-payment alert (${level})`,
            summary || "Suspicious timing between a phone call and a payment alert (no audio shared)."
          );
        }
      }
      res.json({ ok: true });
    })
  );

  function parentIdOrUser(id: string): string {
    return id;
  }

  app.post(
    "/api/qr/record",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const kind = String(req.body?.kind || "upi").slice(0, 20);
      const payee = req.body?.payee ? String(req.body.payee).slice(0, 120) : null;
      const amount = req.body?.amount && Number.isFinite(Number(req.body.amount)) ? Number(req.body.amount) : null;
      const score = Number(req.body?.score || 0);
      const level = String(req.body?.level || "LOW");
      const sig = Array.isArray(req.body?.sig) ? req.body.sig.slice(0, 10).map(String) : [];
      await db
        .prepare("INSERT INTO qr_checks (id, user_id, kind, payee, amount, score, level, signals_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(generateId("qr"), userId, kind, payee, amount, score, level, JSON.stringify(sig), Date.now());
      await writeAudit(userId, `QR checked (${level})`);
      res.json({ ok: true });
    })
  );

  /* ---- Guardian AI QR Intelligence ---- */
  app.post(
    "/api/qr/analyze",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      if (!checkRateLimit(`qr:${userId}`, 40, 60_000)) {
        res.status(429).json({ error: "Too many QR scan requests. Please wait a minute." });
        return;
      }
      const rawPayload = String(req.body?.payload || "");
      const lang = req.body?.lang === "hi" ? "hi" : "en";
      if (!rawPayload.trim()) {
        res.status(400).json({ error: "No QR payload provided to analyze." });
        return;
      }
      if (rawPayload.length > 4096) {
        res.status(400).json({ error: "QR payload exceeds maximum allowed size (4096 characters)." });
        return;
      }
      try {
        const report = await runFullQrIntelligencePipeline({
          userId,
          userName: req.authUser!.name,
          rawPayload,
          lang,
        });
        res.status(201).json({ report });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to analyze QR code.";
        res.status(500).json({ error: msg });
      }
    })
  );

  app.get(
    "/api/qr/history",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (user.role === "parent") {
        const rows = (await db
          .prepare(
            `SELECT id, qr_format, qr_classification, upi_id, payee_name, amount, amount_state,
                    security_risk_level, payment_load_category, payment_load_risk_level, report_json, created_at
             FROM qr_scan_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`
          )
          .all(user.id)) as Record<string, unknown>[];
        res.json({ scans: rows });
        return;
      }

      const requestedParentId = String(req.query.parentId || "").trim();
      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      if (requestedParentId && !linkedParentIds.includes(requestedParentId)) {
        res.status(403).json({ error: "Unauthorized: you are not an active linked guardian for this account." });
        return;
      }
      const targetIds = requestedParentId ? [requestedParentId] : linkedParentIds;
      if (targetIds.length === 0) {
        res.json({ scans: [] });
        return;
      }
      const rows = (await db
        .prepare(
          `SELECT q.id, q.user_id as parent_id, u.name as parent_name, q.qr_format, q.qr_classification,
                  q.upi_id, q.payee_name, q.amount, q.amount_state, q.security_risk_level,
                  q.payment_load_category, q.payment_load_risk_level, q.created_at
           FROM qr_scan_records q
           JOIN users u ON u.id = q.user_id
           JOIN consents c ON c.user_id = q.user_id
           WHERE q.user_id IN (${targetIds.map(() => "?").join(",")})
             AND c.guardian_alerts = 1 AND c.paused = 0
           ORDER BY q.created_at DESC LIMIT 20`
        )
        .all(...targetIds)) as Record<string, unknown>[];
      res.json({ scans: rows });
    })
  );

  app.put(
    "/api/qr/preferences",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      await ensureDefaultQrNotificationPrefs(userId);
      const b = req.body || {};
      await db
        .prepare(
          `UPDATE qr_notification_prefs SET
             qr_scan_notify = ?,
             high_risk_qr_alert = ?,
             critical_risk_qr_alert = ?,
             high_amount_alert = ?,
             very_high_load_alert = ?,
             repeated_qr_alert = ?,
             merchant_warning_alert = ?,
             suspicious_qr_alert = ?,
             updated_at = ?
           WHERE user_id = ?`
        )
        .run(
          b.qrScanNotify ? 1 : 0,
          b.highRiskQrAlert ? 1 : 0,
          b.criticalRiskQrAlert ? 1 : 0,
          b.highAmountAlert ? 1 : 0,
          b.veryHighLoadAlert ? 1 : 0,
          b.repeatedQrAlert ? 1 : 0,
          b.merchantWarningAlert ? 1 : 0,
          b.suspiciousQrAlert ? 1 : 0,
          Date.now(),
          userId
        );
      await writeAudit(userId, "Updated QR alert notification preferences");
      res.json({ ok: true, qrPrefs: await ensureDefaultQrNotificationPrefs(userId) });
    })
  );

  /* ---- AI Call Watcher & Payment Correlation Intelligence ---- */
  app.post(
    "/api/call-watcher/consent",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const action = String(req.body?.action || "");
      if (!["activate", "pause", "resume", "revoke", "update_prefs"].includes(action)) {
        res.status(400).json({ error: "Invalid Call Watcher consent action." });
        return;
      }
      try {
        const settings = await updateCallWatcherConsent(
          userId,
          action as "activate" | "pause" | "resume" | "revoke" | "update_prefs",
          {
            notifyUnknownCalls:
              typeof req.body?.notifyUnknownCalls === "boolean"
                ? req.body.notifyUnknownCalls
                : undefined,
            permissionCallState: req.body?.permissionCallState,
            permissionSmsState: req.body?.permissionSmsState,
            permissionNotifState: req.body?.permissionNotifState,
          }
        );
        res.json({ ok: true, settings });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not update consent." });
      }
    })
  );

  app.post(
    "/api/call-watcher/calls",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      if (!checkRateLimit(`cwc:${userId}`, 60, 60_000)) {
        res.status(429).json({ error: "Too many Call Watcher events. Please wait a minute." });
        return;
      }
      try {
        const result = await recordCallWatcherCall(
          userId,
          req.authUser!.name,
          {
            externalEventId: req.body?.externalEventId,
            callerIdentifier: req.body?.callerIdentifier,
            callerClassification: req.body?.callerClassification,
            callStatus: req.body?.callStatus,
            callLifecyclePhase: req.body?.callLifecyclePhase,
            incomingAt: req.body?.incomingAt !== undefined ? Number(req.body.incomingAt) : undefined,
            startedAt: req.body?.startedAt !== undefined && req.body.startedAt !== null ? Number(req.body.startedAt) : null,
            endedAt: req.body?.endedAt !== undefined && req.body.endedAt !== null ? Number(req.body.endedAt) : null,
            durationMs: req.body?.durationMs !== undefined && req.body.durationMs !== null ? Number(req.body.durationMs) : null,
            screeningVerdict: req.body?.screeningVerdict,
            screeningLatencyMs:
              req.body?.screeningLatencyMs !== undefined && req.body.screeningLatencyMs !== null
                ? Number(req.body.screeningLatencyMs)
                : null,
            simInfo: req.body?.simInfo,
            source: req.body?.source,
          },
          req.body?.lang === "hi" ? "hi" : "en"
        );
        res.status(result.duplicate ? 200 : 201).json(result);
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not record call event." });
      }
    })
  );

  app.post(
    "/api/call-watcher/screen",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      if (!checkRateLimit(`cws:${userId}`, 90, 60_000)) {
        res.status(429).json({ error: "Too many call screening checks. Please wait briefly." });
        return;
      }
      const result = await screenIncomingCaller(userId, {
        callerIdentifier: req.body?.callerIdentifier,
        callerClassification: req.body?.callerClassification,
        callScreeningRoleGranted: Boolean(req.body?.callScreeningRoleGranted),
      });
      res.json(result);
    })
  );

  app.get(
    "/api/call-watcher/threat-cache",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const cache = await getLocalCallThreatCache(req.authUser!.id);
      res.json(cache);
    })
  );

  app.patch(
    "/api/call-watcher/calls/:id/end",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      try {
        const result = await endActiveCallEvent(userId, req.authUser!.name, String(req.params.id), {
          endedAt: req.body?.endedAt === null ? null : req.body?.endedAt !== undefined ? Number(req.body.endedAt) : undefined,
          startedAt:
            req.body?.startedAt !== undefined && req.body.startedAt !== null ? Number(req.body.startedAt) : undefined,
          callStatus: req.body?.callStatus,
          durationMs:
            req.body?.durationMs !== undefined && req.body.durationMs !== null ? Number(req.body.durationMs) : undefined,
          lang: req.body?.lang === "hi" ? "hi" : "en",
        });
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not close call record.";
        res.status(msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/call-watcher/device-status",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const settings = await updateCallWatcherDeviceStatus(req.authUser!.id, {
        appLifecycleState: req.body?.appLifecycleState,
        batteryRestricted:
          typeof req.body?.batteryRestricted === "boolean" ? req.body.batteryRestricted : undefined,
        callScreeningRoleState: req.body?.callScreeningRoleState,
        permissionCallLogState: req.body?.permissionCallLogState,
        permissionCallState: req.body?.permissionCallState,
        permissionNotifState: req.body?.permissionNotifState,
        bootRestorePending:
          typeof req.body?.bootRestorePending === "boolean" ? req.body.bootRestorePending : undefined,
      });
      res.json({ ok: true, settings });
    })
  );

  app.post(
    "/api/call-watcher/trusted",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const result = await markCallerTrustedWithSafeguard(req.authUser!.id, {
        callerIdentifier: req.body?.callerIdentifier,
        callerHash: req.body?.callerHash,
        entityId: req.body?.entityId,
        note: req.body?.note,
      });
      res.json(result);
    })
  );

  app.post(
    "/api/call-watcher/notify-guardian",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const result = await notifyLinkedGuardiansFromAssistant(req.authUser!.id, req.authUser!.name, {
        correlationId: req.body?.correlationId,
        message: req.body?.message,
      });
      res.json(result);
    })
  );

  app.post(
    "/api/call-watcher/payment-message",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      if (!checkRateLimit(`cwp:${userId}`, 45, 60_000)) {
        res.status(429).json({ error: "Too many payment message events. Please wait a minute." });
        return;
      }
      try {
        const result = await recordPaymentMessageEvent(
          userId,
          req.authUser!.name,
          {
            rawMessageText: String(req.body?.rawMessageText || ""),
            senderLabel: req.body?.senderLabel,
            messageTs: req.body?.messageTs !== undefined ? Number(req.body.messageTs) : undefined,
            source: req.body?.source,
            linkedCallId: req.body?.linkedCallId,
          },
          req.body?.lang === "hi" ? "hi" : "en"
        );
        res.status(result.duplicate ? 200 : 201).json(result);
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not analyze payment message." });
      }
    })
  );

  app.post(
    "/api/call-watcher/questionnaire",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      try {
        const updated = await submitSafetyQuestionnaire(
          userId,
          req.authUser!.name,
          {
            correlationId: String(req.body?.correlationId || ""),
            askedToDo: req.body?.askedToDo,
            urgencyPressure: req.body?.urgencyPressure,
            askedSensitiveCreds: req.body?.askedSensitiveCreds,
            emotionalFeeling: req.body?.emotionalFeeling,
            dismissed: Boolean(req.body?.dismissed),
          },
          req.body?.lang === "hi" ? "hi" : "en"
        );
        res.json({ ok: true, item: updated });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not submit questionnaire." });
      }
    })
  );

  app.post(
    "/api/call-watcher/bridge/event",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      if (!checkRateLimit(`cwb:${userId}`, 60, 60_000)) {
        res.status(429).json({ error: "Bridge rate limit exceeded." });
        return;
      }
      try {
        const lang = req.body?.lang === "hi" ? "hi" : "en";
        if (req.body?.permissions) {
          await updateCallWatcherConsent(userId, "update_prefs", {
            permissionCallState: req.body.permissions.call,
            permissionSmsState: req.body.permissions.sms,
            permissionNotifState: req.body.permissions.notifications,
            permissionCallLogState: req.body.permissions.callLog,
            callScreeningRoleState: req.body.permissions.callScreeningRole,
            batteryRestricted: req.body.permissions.batteryRestricted,
            appLifecycleState: req.body.permissions.appLifecycleState,
            bootRestorePending: req.body.permissions.bootRestorePending,
          });
        }
        const callsInput = Array.isArray(req.body?.calls) ? req.body.calls.slice(0, 15) : [];
        const msgsInput = Array.isArray(req.body?.paymentMessages) ? req.body.paymentMessages.slice(0, 15) : [];
        const recordedCalls = [];
        for (const c of callsInput) {
          recordedCalls.push(
            await recordCallWatcherCall(
              userId,
              req.authUser!.name,
              { ...c, source: "android_bridge" },
              lang
            )
          );
        }
        const recordedMessages = [];
        for (const m of msgsInput) {
          recordedMessages.push(
            await recordPaymentMessageEvent(
              userId,
              req.authUser!.name,
              { ...m, source: "android_bridge" },
              lang
            )
          );
        }
        res.status(201).json({
          ok: true,
          callsProcessed: recordedCalls.length,
          paymentMessagesProcessed: recordedMessages.length,
          dashboard: await getCallWatcherDashboard(userId),
        });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Bridge sync failed." });
      }
    })
  );

  app.get(
    "/api/call-watcher/timeline",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (user.role === "parent") {
        res.json(await getCallWatcherDashboard(user.id));
        return;
      }
      const requestedParentId = String(req.query.parentId || "").trim();
      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      if (requestedParentId && !linkedParentIds.includes(requestedParentId)) {
        res.status(403).json({ error: "Unauthorized: you are not an active linked guardian for this account." });
        return;
      }
      const targetIds = requestedParentId ? [requestedParentId] : linkedParentIds;
      if (!targetIds.length) {
        res.json({ timeline: [] });
        return;
      }
      const parentRows = (await db
        .prepare(`SELECT id, name FROM users WHERE id IN (${targetIds.map(() => "?").join(",")})`)
        .all(...targetIds)) as { id: string; name: string }[];
      res.json({ timeline: await getGuardianSharedCallWatcher(parentRows) });
    })
  );

  app.post(
    "/api/incidents",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const userId = req.authUser!.id;
      const summary = String(req.body?.summary || "").trim().slice(0, 80);
      const channel = String(req.body?.channel || "UPI").trim().slice(0, 30);
      if (!summary) {
        res.status(400).json({ error: "Enter incident details." });
        return;
      }
      const clean = sanitizeAuditText(summary);
      const now = Date.now();
      await db
        .prepare("INSERT INTO incidents (id, user_id, summary, channel, status, created_at) VALUES (?, ?, ?, ?, 'Reported to bank: pending', ?)")
        .run(generateId("inc"), userId, clean, channel, now);
      await writeAudit(userId, "Incident recorded");
      res.status(201).json({
        a: `${clean} (${channel})`,
        d: new Date(now).toLocaleDateString(),
        s: "Reported to bank: pending",
      });
    })
  );

  app.post(
    "/api/notifications/read",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      await db.prepare("UPDATE notifications SET read_at = ? WHERE recipient_id = ? AND read_at IS NULL").run(
        Date.now(),
        req.authUser!.id
      );
      res.json({ ok: true });
    })
  );

  /* ---- Guardian Security Intelligence (GSI) APIs ---- */
  app.post(
    "/api/gsi/links/analyze",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (!checkRateLimit(`gsi-lnk:${user.id}`, 45, 60_000)) {
        res.status(429).json({ error: "Too many link analysis requests. Please wait a minute." });
        return;
      }
      const url = String(req.body?.url || "").trim();
      const contextText = typeof req.body?.contextText === "string" ? req.body.contextText.slice(0, 600) : undefined;
      const allowNetworkProbe = Boolean(req.body?.allowNetworkProbe);
      const recordEvent = Boolean(req.body?.recordEvent);
      if (!url) {
        res.status(400).json({ error: "Provide a URL to inspect." });
        return;
      }
      try {
        const linkAnalysis = await analyzeUrlIntelligence(url, {
          userId: user.id,
          contextText,
          allowNetworkProbe,
        });
        let incident = null;
        if (recordEvent && user.role === "parent") {
          const ingested = await ingestGsiEvent({
            familyOwnerId: user.id,
            familyOwnerName: user.name,
            eventType: "link_event",
            sourceModule: "module_c_manual_link_check",
            lang: req.body?.lang === "hi" ? "hi" : "en",
            allowNetworkProbe,
            linkData: { url, contextText },
          });
          incident = ingested.incident;
        }
        res.json({ linkAnalysis, incident });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Link inspection failed." });
      }
    })
  );

  app.post(
    "/api/gsi/events/ingest",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (!checkRateLimit(`gsi-ing:${user.id}`, 60, 60_000)) {
        res.status(429).json({ error: "GSI event ingestion rate limit exceeded." });
        return;
      }
      const eventsInput = Array.isArray(req.body?.events) ? req.body.events.slice(0, 15) : [req.body];
      const allowedTypes = new Set(["call_event", "sms_event", "link_event", "qr_event", "payment_event"]);
      try {
        const results = [];
        for (const item of eventsInput) {
          if (!item || !allowedTypes.has(String(item.eventType))) {
            res.status(400).json({ error: "Invalid or unsupported GSI eventType." });
            return;
          }
          results.push(
            await ingestGsiEvent({
              familyOwnerId: user.id,
              familyOwnerName: user.name,
              deviceId: typeof item.deviceId === "string" ? item.deviceId : "web_session",
              eventType: item.eventType,
              eventTimestamp: typeof item.eventTimestamp === "number" ? item.eventTimestamp : undefined,
              sourceModule: String(item.sourceModule || "gsi_unified_ingest"),
              lang: item.lang === "hi" ? "hi" : "en",
              allowNetworkProbe: Boolean(item.allowNetworkProbe),
              skipAi: Boolean(item.skipAi),
              callData: item.callData,
              smsData: item.smsData,
              linkData: item.linkData,
              qrData: item.qrData,
              paymentData: item.paymentData,
            })
          );
        }
        res.status(201).json({
          ok: true,
          results,
          dashboard: await getGsiDashboardState(user.id),
        });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Failed to ingest GSI event." });
      }
    })
  );

  app.post(
    "/api/gsi/incidents/:id/feedback",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const incidentId = String(req.params.id);
      const action = String(req.body?.action || "");
      const note = typeof req.body?.note === "string" ? req.body.note : undefined;
      if (!["acknowledge", "resolve", "confirm_threat", "false_positive"].includes(action)) {
        res.status(400).json({ error: "Invalid feedback action." });
        return;
      }
      try {
        const incident = await recordGsiFeedback({
          actorId: user.id,
          actorRole: user.role,
          incidentId,
          action: action as "acknowledge" | "resolve" | "confirm_threat" | "false_positive",
          note,
        });
        res.json({ ok: true, incident });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not record feedback.";
        const status = msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400;
        res.status(status).json({ error: msg });
      }
    })
  );

  app.get(
    "/api/gsi/reports",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (user.role === "parent") {
        res.json(await getGsiDashboardState(user.id));
        return;
      }
      const requestedParentId = String(req.query.parentId || "").trim();
      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      if (requestedParentId && !linkedParentIds.includes(requestedParentId)) {
        res.status(403).json({ error: "Unauthorized: you are not an active linked guardian for this account." });
        return;
      }
      const targetIds = requestedParentId ? [requestedParentId] : linkedParentIds;
      if (!targetIds.length) {
        res.json({ incidents: [], activeRedAlerts: [], reports: [] });
        return;
      }
      const permittedParents = (await db
        .prepare(
          `SELECT u.id, u.name
           FROM users u
           JOIN consents c ON c.user_id = u.id
           WHERE u.id IN (${targetIds.map(() => "?").join(",")})
             AND c.guardian_alerts = 1 AND c.paused = 0`
        )
        .all(...targetIds)) as { id: string; name: string }[];
      res.json(await getGuardianSharedGsiOverview(permittedParents));
    })
  );

  app.post(
    "/api/gsi/reports/generate",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const periodType =
        req.body?.periodType === "daily" || req.body?.periodType === "weekly" || req.body?.periodType === "monthly"
          ? req.body.periodType
          : "weekly";
      const report = await buildPeriodicReport(req.authUser!.id, periodType);
      res.json({ ok: true, report });
    })
  );

  /* ---- Guardian Central Intelligence Hub (GCIH) APIs ---- */
  app.post(
    "/api/gcih/devices/register",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      let familyOwnerId = user.id;
      if (user.role === "guardian") {
        const requestedParentId = String(req.body?.familyOwnerId || "").trim();
        const linkedIds = await getActiveLinkedParentIds(user.id);
        if (requestedParentId) {
          if (!linkedIds.includes(requestedParentId)) {
            res.status(403).json({ error: "Unauthorized: not an active linked guardian for this family." });
            return;
          }
          familyOwnerId = requestedParentId;
        } else if (linkedIds.length > 0) {
          familyOwnerId = linkedIds[0];
        }
      }
      try {
        const device = await registerFamilyDevice({
          deviceId: typeof req.body?.deviceId === "string" ? req.body.deviceId : undefined,
          userId: user.id,
          familyOwnerId,
          deviceLabel: String(req.body?.deviceLabel || (user.role === "parent" ? "Monitored User Browser" : "Linked Guardian Browser")),
          platform: typeof req.body?.platform === "string" ? req.body.platform : "web",
          role: user.role,
          permissions: req.body?.permissions as Partial<GcihDevicePermissions> | undefined,
        });
        res.status(201).json({ ok: true, device });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Device registration failed." });
      }
    })
  );

  app.post(
    "/api/gcih/devices/:id/revoke",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const device = await revokeFamilyDevice({
          actorId: req.authUser!.id,
          deviceId: String(req.params.id),
        });
        res.json({ ok: true, device });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not revoke device.";
        res.status(msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.put(
    "/api/gcih/devices/:id/permissions",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const device = await updateDevicePermissions({
          actorId: req.authUser!.id,
          actorRole: req.authUser!.role,
          deviceId: String(req.params.id),
          permissions: (req.body?.permissions || req.body || {}) as Partial<GcihDevicePermissions>,
        });
        res.json({ ok: true, device });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not update device permissions.";
        res.status(msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.get(
    "/api/gcih/sync",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const since = req.query.since ? Number(req.query.since) : 0;
      const deviceId = req.query.deviceId ? String(req.query.deviceId) : "";

      let devicePermissions: Partial<GcihDevicePermissions> | undefined;
      if (deviceId) {
        const devRow = (await db.prepare("SELECT user_id, status, permissions_json FROM gcih_devices WHERE id = ?").get(deviceId)) as
          | { user_id: string; status: string; permissions_json: string }
          | undefined;
        if (devRow) {
          if (devRow.user_id !== user.id || devRow.status === "revoked") {
            res.status(403).json({ error: "Device access has been revoked or is unauthorized." });
            return;
          }
          devicePermissions = JSON.parse(devRow.permissions_json || "{}") as Partial<GcihDevicePermissions>;
          await db.prepare("UPDATE gcih_devices SET last_seen_at = ?, last_sync_cursor = ? WHERE id = ?").run(
            Date.now(),
            Date.now(),
            deviceId
          );
        }
      }

      if (user.role === "parent") {
        res.json(await buildFamilySyncPayload({ familyOwnerId: user.id, since, devicePermissions }));
        return;
      }

      const requestedParentId = String(req.query.parentId || "").trim();
      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      if (requestedParentId && !linkedParentIds.includes(requestedParentId)) {
        res.status(403).json({ error: "Unauthorized: you are not an active linked guardian for this family." });
        return;
      }
      const targetIds = requestedParentId ? [requestedParentId] : linkedParentIds;
      const payloads = (
        await Promise.all(
          targetIds.map(async (pid) => {
            const c = (await db.prepare("SELECT guardian_alerts, paused FROM consents WHERE user_id = ?").get(pid)) as
              | { guardian_alerts: number; paused: number }
              | undefined;
            if (c && (!c.guardian_alerts || c.paused)) return null;
            return buildFamilySyncPayload({ familyOwnerId: pid, since, devicePermissions });
          })
        )
      ).filter(Boolean);

      res.json({ families: payloads, serverTimestamp: Date.now() });
    })
  );

  app.post(
    "/api/gcih/sync/push",
    requireRole("parent"),
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      if (!checkRateLimit(`gcih-push:${user.id}`, 40, 60_000)) {
        res.status(429).json({ error: "Sync push rate limit exceeded. Wait briefly." });
        return;
      }
      const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId.slice(0, 60) : "web_offline_queue";
      const devRow = (await db.prepare("SELECT user_id, status FROM gcih_devices WHERE id = ?").get(deviceId)) as
        | { user_id: string; status: string }
        | undefined;
      if (devRow && (devRow.user_id !== user.id || devRow.status === "revoked")) {
        res.status(403).json({ error: "This device was revoked and cannot push sync updates." });
        return;
      }

      const eventsInput = Array.isArray(req.body?.events) ? req.body.events.slice(0, 25) : [];
      const allowedTypes = new Set(["call_event", "sms_event", "link_event", "qr_event", "payment_event"]);
      const acks: { clientEventId: string; status: string; eventId?: string; incidentId?: string }[] = [];

      for (const item of eventsInput) {
        const clientEventId = String(item?.clientEventId || generateId("off"));
        if (!item || !allowedTypes.has(String(item.eventType))) {
          acks.push({ clientEventId, status: "Synchronisation failed" });
          continue;
        }
        const seenBefore = (await db
          .prepare("SELECT event_id FROM gsi_events WHERE family_owner_id = ? AND metadata_json LIKE ? LIMIT 1")
          .get(user.id, `%"clientSyncId":"${clientEventId.replace(/[^a-zA-Z0-9_-]/g, "")}"%`)) as
          | { event_id: string }
          | undefined;
        if (seenBefore) {
          acks.push({ clientEventId, status: "Successfully synchronised", eventId: seenBefore.event_id });
          continue;
        }
        try {
          const resIngest = await ingestGsiEvent({
            familyOwnerId: user.id,
            familyOwnerName: user.name,
            deviceId: typeof item.deviceId === "string" ? item.deviceId : deviceId,
            eventType: item.eventType,
            eventTimestamp: typeof item.eventTimestamp === "number" ? item.eventTimestamp : Date.now(),
            sourceModule: String(item.sourceModule || "offline_sync"),
            lang: item.lang === "hi" ? "hi" : "en",
            skipAi: true,
            callData: item.callData,
            smsData: item.smsData,
            linkData: item.linkData,
            qrData: item.qrData,
            paymentData: item.paymentData,
          });
          const evMetaRow = (await db
            .prepare("SELECT metadata_json FROM gsi_events WHERE event_id = ?")
            .get(resIngest.eventId)) as { metadata_json: string } | undefined;
          if (evMetaRow) {
            const parsedMeta = JSON.parse(evMetaRow.metadata_json || "{}") as Record<string, unknown>;
            parsedMeta.clientSyncId = clientEventId.replace(/[^a-zA-Z0-9_-]/g, "");
            await db.prepare("UPDATE gsi_events SET metadata_json = ? WHERE event_id = ?").run(
              JSON.stringify(parsedMeta),
              resIngest.eventId
            );
          }
          acks.push({
            clientEventId,
            status: "Successfully synchronised",
            eventId: resIngest.eventId,
            incidentId: resIngest.incident.incidentId,
          });
        } catch {
          acks.push({ clientEventId, status: "Synchronisation failed" });
        }
      }

      if (devRow) {
        await db.prepare("UPDATE gcih_devices SET last_seen_at = ?, last_sync_cursor = ? WHERE id = ?").run(
          Date.now(),
          Date.now(),
          deviceId
        );
      }

      res.json({
        ok: true,
        acks,
        gcih: await buildFamilySyncPayload({ familyOwnerId: user.id }),
        gsi: await getGsiDashboardState(user.id),
      });
    })
  );

  app.post(
    "/api/gcih/entities/:id/feedback",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const feedbackType = String(req.body?.feedbackType || "");
      if (!["suspicious", "legitimate", "false_positive", "request_review", "incorrect_association"].includes(feedbackType)) {
        res.status(400).json({ error: "Invalid entity feedback type." });
        return;
      }
      try {
        const result = await submitEntityFeedback({
          actorId: user.id,
          actorRole: user.role,
          entityId: String(req.params.id),
          feedbackType: feedbackType as "suspicious" | "legitimate" | "false_positive" | "request_review" | "incorrect_association",
          eventId: typeof req.body?.eventId === "string" ? req.body.eventId : undefined,
          incidentId: typeof req.body?.incidentId === "string" ? req.body.incidentId : undefined,
          note: typeof req.body?.note === "string" ? req.body.note : undefined,
        });
        res.json({ ok: true, ...result });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not record entity feedback.";
        res.status(msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/gcih/relationships/:id/correct",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const action = String(req.body?.action || "");
      if (!["dispute", "correct", "restore"].includes(action)) {
        res.status(400).json({ error: "Invalid relationship correction action." });
        return;
      }
      try {
        const relationship = await correctRelationship({
          actorId: user.id,
          actorRole: user.role,
          relationshipId: String(req.params.id),
          action: action as "dispute" | "correct" | "restore",
          note: typeof req.body?.note === "string" ? req.body.note : undefined,
        });
        res.json({ ok: true, relationship });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not update relationship.";
        res.status(msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/gcih/incidents/:id/workflow",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const user = req.authUser!;
      const wf = String(req.body?.workflowStatus || "");
      if (!["New", "Investigating", "Acknowledged", "Resolved", "False positive", "Reopened"].includes(wf)) {
        res.status(400).json({ error: "Invalid incident workflow status." });
        return;
      }
      try {
        const updated = await updateIncidentWorkflow({
          actorId: user.id,
          actorRole: user.role,
          incidentId: String(req.params.id),
          workflowStatus: wf as GcihIncidentWorkflowStatus,
          note: typeof req.body?.note === "string" ? req.body.note : undefined,
        });
        res.json({ ok: true, incident: updated });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not update incident workflow.";
        res.status(msg.startsWith("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.get(
    "/api/gcih/section/:section",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      const section = String(req.params.section) as GcihSectionKey;
      if (!["call_scam", "sms_scam", "qr_scam", "link_scam", "payment_safety"].includes(section)) {
        res.status(400).json({ error: "Invalid intelligence section." });
        return;
      }
      const user = req.authUser!;
      if (user.role === "parent") {
        res.json({ items: await getSharedIntelligenceForSection(user.id, section) });
        return;
      }
      const requestedParentId = String(req.query.parentId || "").trim();
      const linkedParentIds = await getActiveLinkedParentIds(user.id);
      if (requestedParentId && !linkedParentIds.includes(requestedParentId)) {
        res.status(403).json({ error: "Unauthorized: not linked to this family member." });
        return;
      }
      const targetId = requestedParentId || linkedParentIds[0];
      if (!targetId) {
        res.json({ items: [] });
        return;
      }
      res.json({ items: await getSharedIntelligenceForSection(targetId, section) });
    })
  );

  /* ---- Parents AI Tools & RBI AA Bank Connectivity ---- */
  app.get(
    "/api/parents-ai/state",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const requestedOwnerId = typeof req.query.ownerId === "string" ? req.query.ownerId : undefined;
        res.json(await getParentsAiState(req.authUser!, requestedOwnerId));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not load Parents AI workspace state.";
        res.status(msg.includes("link") ? 403 : 400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/parents-ai/tools/ask",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const out = await askParentsAiTool({
          actor: req.authUser!,
          toolKey: String(req.body?.toolKey || "parenting"),
          prompt: String(req.body?.prompt || ""),
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          lang: String(req.body?.lang || "en"),
        });
        await writeAudit(req.authUser!.id, `Used Parents AI tool (${out.toolKey})`);
        res.json(out);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Parents AI request failed.";
        res.status(400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/parents-ai/tools/items",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const created = await createToolItem({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          toolKey: String(req.body?.toolKey || ""),
          title: String(req.body?.title || ""),
          category: typeof req.body?.category === "string" ? req.body.category : undefined,
          status: typeof req.body?.status === "string" ? req.body.status : undefined,
          dueAt: req.body?.dueAt ?? null,
          metadata: req.body?.metadata && typeof req.body.metadata === "object" ? req.body.metadata : undefined,
          sharedWithGuardian: req.body?.sharedWithGuardian,
        });
        await writeAudit(req.authUser!.id, `Added ${req.body?.toolKey || "workspace"} item`);
        res.status(201).json({ ok: true, id: created.id });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not save item.";
        res.status(400).json({ error: msg });
      }
    })
  );

  app.patch(
    "/api/parents-ai/tools/items/:id",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const result = await updateToolItem({
          actor: req.authUser!,
          itemId: String(req.params.id),
          status: typeof req.body?.status === "string" ? req.body.status : undefined,
          title: typeof req.body?.title === "string" ? req.body.title : undefined,
          dueAt: req.body?.dueAt,
        });
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not update item.";
        res.status(msg.includes("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.delete(
    "/api/parents-ai/tools/items/:id",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await deleteToolItem(req.authUser!, String(req.params.id));
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not delete item.";
        res.status(msg.includes("Unauthorized") ? 403 : msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/parents-ai/bank/connect-demo",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const result = await connectSampleAaBank({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          institutionName: typeof req.body?.institutionName === "string" ? req.body.institutionName : undefined,
          aaHandle: typeof req.body?.aaHandle === "string" ? req.body.aaHandle : undefined,
          mode: typeof req.body?.mode === "string" ? req.body.mode : "demo_sample",
          scopes: Array.isArray(req.body?.scopes) ? req.body.scopes : undefined,
          consentDays: req.body?.consentDays,
        });
        await writeAudit(req.authUser!.id, "Connected RBI AA Sample Demo Bank Profile (read-only consent)");
        res.status(201).json({ ok: true, ...result });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not connect bank demo.";
        res.status(400).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/parents-ai/bank/revoke/:id",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await revokeBankConnection(req.authUser!, String(req.params.id));
        await writeAudit(req.authUser!.id, "Revoked RBI AA bank consent");
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not revoke connection.";
        res.status(msg.includes("not found") ? 404 : 400).json({ error: msg });
      }
    })
  );

  app.put(
    "/api/parents-ai/bank/access-control",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const updated = await updateFinancialAccessControl({
          actor: req.authUser!,
          childFinancialAccess:
            typeof req.body?.childFinancialAccess === "boolean" ? req.body.childFinancialAccess : undefined,
          guardianFinancialAccess:
            typeof req.body?.guardianFinancialAccess === "boolean" ? req.body.guardianFinancialAccess : undefined,
          requireGuardianAuth:
            typeof req.body?.requireGuardianAuth === "boolean" ? req.body.requireGuardianAuth : undefined,
        });
        await writeAudit(req.authUser!.id, "Updated family financial visibility controls");
        res.json({ ok: true, accessControl: updated });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not update financial access controls.";
        res.status(403).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/parents-ai/budgets",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const result = await upsertFamilyBudget({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          category: String(req.body?.category || ""),
          monthlyLimit: Number(req.body?.monthlyLimit || 0),
          savingsGoalName: typeof req.body?.savingsGoalName === "string" ? req.body.savingsGoalName : undefined,
          savingsTarget: Number(req.body?.savingsTarget || 0),
          savingsCurrent: Number(req.body?.savingsCurrent || 0),
        });
        await writeAudit(req.authUser!.id, `Updated family budget (${String(req.body?.category || "")})`);
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not save budget.";
        res.status(400).json({ error: msg });
      }
    })
  );

  app.delete(
    "/api/parents-ai/budgets/:id",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        res.json(await deleteFamilyBudget(req.authUser!, String(req.params.id)));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not remove budget.";
        res.status(msg.includes("Unauthorized") ? 403 : 404).json({ error: msg });
      }
    })
  );

  /* ---- Guardian Emergency Payment Protection (EPP) APIs ---- */
  app.get(
    "/api/epp/dashboard",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const requestedOwnerId = typeof req.query.ownerId === "string" ? req.query.ownerId : undefined;
        res.json(await getEmergencyPaymentDashboard(req.authUser!, requestedOwnerId));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Could not load Emergency Payment Protection dashboard.";
        res.status(msg.startsWith("Unauthorized") ? 403 : 400).json({ error: msg });
      }
    })
  );

  app.get(
    "/api/epp/banks",
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({ banks: await listBankDirectory() });
    })
  );

  app.post(
    "/api/epp/banks",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const bank = await upsertAndVerifyBankEntry({
          actor: req.authUser!,
          bankName: String(req.body?.bankName || ""),
          shortCode: String(req.body?.shortCode || ""),
          supportPhone: String(req.body?.supportPhone || ""),
          upiBlockUrl: req.body?.upiBlockUrl ?? null,
          debitBlockUrl: req.body?.debitBlockUrl ?? null,
          creditBlockUrl: req.body?.creditBlockUrl ?? null,
          netbankingUrl: req.body?.netbankingUrl ?? null,
          fraudReportUrl: req.body?.fraudReportUrl ?? null,
          verificationStatus: req.body?.verificationStatus,
          notes: req.body?.notes,
        });
        res.status(201).json({ ok: true, bank });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not add bank entry." });
      }
    })
  );

  app.put(
    "/api/epp/banks/:id",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        assertNoBankingCredentials(req.body);
        const bank = await upsertAndVerifyBankEntry({
          actor: req.authUser!,
          id: String(req.params.id),
          bankName: String(req.body?.bankName || ""),
          shortCode: String(req.body?.shortCode || ""),
          supportPhone: String(req.body?.supportPhone || ""),
          upiBlockUrl: req.body?.upiBlockUrl ?? null,
          debitBlockUrl: req.body?.debitBlockUrl ?? null,
          creditBlockUrl: req.body?.creditBlockUrl ?? null,
          netbankingUrl: req.body?.netbankingUrl ?? null,
          fraudReportUrl: req.body?.fraudReportUrl ?? null,
          verificationStatus: req.body?.verificationStatus,
          notes: req.body?.notes,
        });
        res.json({ ok: true, bank });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : "Could not update bank directory entry." });
      }
    })
  );

  app.post(
    "/api/epp/lock/activate",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await activateEmergencyPaymentLock({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          selectedPackages: Array.isArray(req.body?.selectedPackages) ? req.body.selectedPackages : [],
          durationOption: String(req.body?.durationOption || "1h"),
          explicitConsent: Boolean(req.body?.explicitConsent),
          osEnforcementMode: typeof req.body?.osEnforcementMode === "string" ? req.body.osEnforcementMode : undefined,
          devicePlatform: typeof req.body?.devicePlatform === "string" ? req.body.devicePlatform : undefined,
          deviceCapabilityNote:
            typeof req.body?.deviceCapabilityNote === "string" ? req.body.deviceCapabilityNote : undefined,
        });
        res.status(201).json({ ok: true, ...result });
      } catch (err) {
        const statusCode =
          typeof (err as { statusCode?: number })?.statusCode === "number"
            ? (err as { statusCode: number }).statusCode
            : 400;
        res.status(statusCode).json({ error: err instanceof Error ? err.message : "Could not activate payment lock." });
      }
    })
  );

  app.post(
    "/api/epp/lock/unlock",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await unlockEmergencyPaymentLock({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
        });
        res.json(result);
      } catch (err) {
        const statusCode =
          typeof (err as { statusCode?: number })?.statusCode === "number"
            ? (err as { statusCode: number }).statusCode
            : 400;
        res.status(statusCode).json({ error: err instanceof Error ? err.message : "Could not unlock payment lock." });
      }
    })
  );

  app.post(
    "/api/epp/bank-action",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await recordBankBlockingAction({
          actor: req.authUser!,
          requestedOwnerId: typeof req.body?.ownerId === "string" ? req.body.ownerId : undefined,
          bankId: String(req.body?.bankId || ""),
          serviceType: String(req.body?.serviceType || ""),
          launchType: typeof req.body?.launchType === "string" ? req.body.launchType : undefined,
        });
        res.status(201).json({ ok: true, ...result });
      } catch (err) {
        const statusCode =
          typeof (err as { statusCode?: number })?.statusCode === "number"
            ? (err as { statusCode: number }).statusCode
            : 400;
        res.status(statusCode).json({ error: err instanceof Error ? err.message : "Could not log bank action." });
      }
    })
  );

  app.post(
    "/api/epp/bank-action/:id/confirm",
    requireAuth,
    asyncHandler(async (req: AuthedRequest, res) => {
      try {
        const result = await markBankServiceUserConfirmed({
          actor: req.authUser!,
          logId: String(req.params.id),
          confirmed: Boolean(req.body?.confirmed ?? true),
        });
        res.json(result);
      } catch (err) {
        const statusCode =
          typeof (err as { statusCode?: number })?.statusCode === "number"
            ? (err as { statusCode: number }).statusCode
            : 400;
        res.status(statusCode).json({ error: err instanceof Error ? err.message : "Could not update confirmation." });
      }
    })
  );

  /* ---- AI Routes ---- */
  app.post(
    "/api/ai/explain",
    asyncHandler(async (req, res) => {
      try {
        const result = await explainRiskWithGemini({
          text: String(req.body?.text || ""),
          signals: Array.isArray(req.body?.signals) ? req.body.signals : [],
          level: String(req.body?.level || "LOW"),
          lang: String(req.body?.lang || "en"),
          contextType: String(req.body?.contextType || "message"),
        });
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "AI service unavailable";
        const status = msg.includes("not configured") ? 503 : 502;
        res.status(status).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/ai/chat",
    asyncHandler(async (req, res) => {
      const message = String(req.body?.message || "").trim();
      if (!message) {
        res.status(400).json({ error: "Message is required." });
        return;
      }
      try {
        const text = await chatWithGemini({
          history: Array.isArray(req.body?.history) ? req.body.history : [],
          message,
          signals: Array.isArray(req.body?.signals) ? req.body.signals : [],
          lang: String(req.body?.lang || "en"),
        });
        res.json({ text });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "AI service unavailable";
        const status = msg.includes("not configured") ? 503 : 502;
        res.status(status).json({ error: msg });
      }
    })
  );

  app.post(
    "/api/ai/ocr",
    requireAuth,
    asyncHandler(async (req, res) => {
      const base64Data = String(req.body?.base64Data || "");
      const mimeType = String(req.body?.mimeType || "");
      if (!base64Data || !/^image\/(png|jpeg|jpg|webp)$/.test(mimeType)) {
        res.status(400).json({ error: "Valid PNG, JPG, or WEBP image data is required." });
        return;
      }
      try {
        const result = await extractScreenshotTextWithGemini({ base64Data, mimeType });
        res.json(result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Screenshot OCR unavailable";
        const status = msg.includes("not configured") ? 503 : 502;
        res.status(status).json({ error: msg });
      }
    })
  );

  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "API endpoint not found." });
  });

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const isSyntaxErr = err instanceof SyntaxError;
    const isDbUnconfigured = err instanceof DbNotConfiguredError;
    const customStatus =
      typeof (err as { statusCode?: number })?.statusCode === "number"
        ? (err as { statusCode: number }).statusCode
        : undefined;
    const customCode = typeof (err as { code?: string })?.code === "string" ? (err as { code: string }).code : undefined;

    if (process.env.NODE_ENV !== "production" && err instanceof Error) {
      console.error("[server error]", err.message);
    }

    const status = isSyntaxErr ? 400 : isDbUnconfigured ? err.statusCode : customStatus || 500;
    const errorMessage = isSyntaxErr
      ? "Invalid JSON request body."
      : isDbUnconfigured || (customStatus && customStatus < 500 && err instanceof Error)
        ? err instanceof Error
          ? err.message
          : "Request failed."
        : isDbUnconfigured && err instanceof Error
          ? err.message
          : "Internal server error.";

    res.status(status).json({
      error: errorMessage,
      ...(customCode ? { code: customCode } : {}),
    });
  });

  return app;
}

async function startServer() {
  try {
    await ensureServerReady();
  } catch (err) {
    console.error("[guardian] Server initialization failed:", err instanceof Error ? err.message : err);
  }
  const app = createApp();

  if (process.env.NODE_ENV !== "production") {
    const vitePkg = "vite";
    const { createServer: createViteServer } = await import(vitePkg);
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, "dist");
    const indexHtmlPath = path.join(distDir, "index.html");
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      if (fs.existsSync(indexHtmlPath)) {
        res.sendFile(indexHtmlPath);
      } else {
        res.status(404).send("Frontend build not found. Please ensure 'npm run build' was executed.");
      }
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Guardian server listening on http://0.0.0.0:${PORT}`);
  });
}

const isMainModule =
  Boolean(process.argv[1]) &&
  (path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
    process.argv[1].endsWith("server.ts") ||
    process.argv[1].endsWith("server.js"));

if (isMainModule) {
  startServer();
}
