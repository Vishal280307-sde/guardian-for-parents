import fs from "node:fs";
import path from "node:path";

export type DbMode = "turso_libsql" | "local_sqlite" | "ephemeral_sqlite" | "unconfigured";

export class DbNotConfiguredError extends Error {
  statusCode = 503;
  code = "DB_NOT_CONFIGURED";
  constructor(message?: string) {
    super(
      message ||
        "Persistent database is not configured for serverless deployment. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in your environment variables, or deploy the Express backend to a persistent Node server."
    );
    this.name = "DbNotConfiguredError";
  }
}

export interface DbRunResult {
  changes: number;
  lastInsertRowid?: number | bigint;
}

export interface DbStatement {
  get<T = Record<string, unknown>>(...params: unknown[]): Promise<T | undefined>;
  all<T = Record<string, unknown>>(...params: unknown[]): Promise<T[]>;
  run(...params: unknown[]): Promise<DbRunResult>;
}

interface RawDriver {
  mode: DbMode;
  targetLabel: string;
  exec(sql: string): Promise<void>;
  prepare(sql: string): DbStatement;
  close(): Promise<void>;
}

function sanitizeEnvValue(raw: unknown): string {
  return String(raw || "")
    .trim()
    .replace(/^(['"])(.*)\1$/, "$2")
    .trim();
}

function getConfiguredTursoUrl(): string {
  const raw = sanitizeEnvValue(
    process.env.TURSO_DATABASE_URL ||
    process.env.LIBSQL_URL ||
    process.env.TURSO_URL ||
    (process.env.DATABASE_URL && /^(libsql|https?|file):/i.test(process.env.DATABASE_URL) ? process.env.DATABASE_URL : "")
  );
  return raw ? raw.replace(/\/+$/, "") : "";
}

function getConfiguredTursoToken(): string | undefined {
  const t = sanitizeEnvValue(
    process.env.TURSO_AUTH_TOKEN ||
    process.env.LIBSQL_AUTH_TOKEN ||
    process.env.TURSO_TOKEN
  );
  return t || undefined;
}

function isRunningOnVercel(): boolean {
  return process.env.VERCEL === "1" || process.env.VERCEL === "true" || Boolean(process.env.VERCEL_ENV);
}

export function resolveConfiguredDbPath(): string {
  if (process.env.GUARDIAN_DB_PATH) {
    return path.resolve(process.cwd(), process.env.GUARDIAN_DB_PATH);
  }
  if (isRunningOnVercel() && process.env.ALLOW_EPHEMERAL_SQLITE === "true") {
    return "/tmp/guardian-ephemeral.db";
  }
  return path.resolve(process.cwd(), "data", "guardian.db");
}

export let dbPath = resolveConfiguredDbPath();

export function getDbMode(): DbMode {
  if (getConfiguredTursoUrl()) return "turso_libsql";
  if (isRunningOnVercel()) {
    return process.env.ALLOW_EPHEMERAL_SQLITE === "true" ? "ephemeral_sqlite" : "unconfigured";
  }
  return "local_sqlite";
}

export function getDbDiagnostics() {
  const mode = getDbMode();
  return {
    mode,
    persistent: mode === "turso_libsql" || mode === "local_sqlite",
    vercel: isRunningOnVercel(),
    tursoConfigured: Boolean(getConfiguredTursoUrl()),
    ephemeralAllowed: process.env.ALLOW_EPHEMERAL_SQLITE === "true",
    dbPath: mode === "turso_libsql" ? "[remote libSQL / Turso]" : dbPath,
  };
}

function normalizeSqlArgs(params: unknown[]): (string | number | Uint8Array | null)[] {
  const flattened = params.length === 1 && Array.isArray(params[0]) ? (params[0] as unknown[]) : params;
  return flattened.map((arg) => {
    if (arg === undefined || arg === null) return null;
    if (typeof arg === "boolean") return arg ? 1 : 0;
    if (typeof arg === "number" || typeof arg === "string" || arg instanceof Uint8Array) {
      return arg;
    }
    if (typeof arg === "bigint") return Number(arg);
    return String(arg);
  });
}

function mapLibsqlRow<T>(columns: string[], rawRow: Record<string, unknown>): T {
  const out: Record<string, unknown> = {};
  for (let i = 0; i < columns.length; i++) {
    const col = columns[i];
    let val = rawRow[col];
    if (val === undefined && (rawRow as Record<number, unknown>)[i] !== undefined) {
      val = (rawRow as Record<number, unknown>)[i];
    }
    out[col] = val === undefined ? null : val;
  }
  return out as T;
}

async function createDriver(): Promise<RawDriver> {
  const tursoUrl = getConfiguredTursoUrl();
  if (tursoUrl) {
    const { createClient } = await import("@libsql/client");
    const authToken = getConfiguredTursoToken();
    const client = createClient({
      url: tursoUrl,
      authToken,
    });
    return {
      mode: "turso_libsql",
      targetLabel: tursoUrl.startsWith("file:") ? tursoUrl : "turso_remote",
      async exec(sql: string) {
        const trimmed = sql.trim();
        if (!trimmed) return;
        await client.executeMultiple(trimmed);
      },
      prepare(sql: string): DbStatement {
        return {
          async get<T = Record<string, unknown>>(...params: unknown[]): Promise<T | undefined> {
            const res = await client.execute({ sql, args: normalizeSqlArgs(params) });
            if (!res.rows || res.rows.length === 0) return undefined;
            return mapLibsqlRow<T>(res.columns, res.rows[0] as Record<string, unknown>);
          },
          async all<T = Record<string, unknown>>(...params: unknown[]): Promise<T[]> {
            const res = await client.execute({ sql, args: normalizeSqlArgs(params) });
            if (!res.rows || res.rows.length === 0) return [];
            return res.rows.map((r) => mapLibsqlRow<T>(res.columns, r as Record<string, unknown>));
          },
          async run(...params: unknown[]): Promise<DbRunResult> {
            const res = await client.execute({ sql, args: normalizeSqlArgs(params) });
            return {
              changes: Number(res.rowsAffected ?? 0),
              lastInsertRowid: res.lastInsertRowid,
            };
          },
        };
      },
      async close() {
        client.close();
      },
    };
  }

  if (isRunningOnVercel() && process.env.ALLOW_EPHEMERAL_SQLITE !== "true") {
    throw new DbNotConfiguredError();
  }

  dbPath = resolveConfiguredDbPath();
  const dataDir = path.dirname(dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  const sqliteBuiltin = "node:sqlite";
  const { DatabaseSync } = await import(sqliteBuiltin);
  const sqliteDb = new DatabaseSync(dbPath);
  sqliteDb.exec("PRAGMA journal_mode = WAL;");
  sqliteDb.exec("PRAGMA foreign_keys = ON;");

  const mode: DbMode = isRunningOnVercel() ? "ephemeral_sqlite" : "local_sqlite";

  return {
    mode,
    targetLabel: dbPath,
    async exec(sql: string) {
      sqliteDb.exec(sql);
    },
    prepare(sql: string): DbStatement {
      const stmt = sqliteDb.prepare(sql);
      return {
        async get<T = Record<string, unknown>>(...params: unknown[]): Promise<T | undefined> {
          return stmt.get(...(normalizeSqlArgs(params) as any[])) as T | undefined;
        },
        async all<T = Record<string, unknown>>(...params: unknown[]): Promise<T[]> {
          return stmt.all(...(normalizeSqlArgs(params) as any[])) as T[];
        },
        async run(...params: unknown[]): Promise<DbRunResult> {
          const info = stmt.run(...(normalizeSqlArgs(params) as any[])) as {
            changes?: number | bigint;
            lastInsertRowid?: number | bigint;
          };
          return {
            changes: Number(info?.changes ?? 0),
            lastInsertRowid: info?.lastInsertRowid,
          };
        },
      };
    },
    async close() {
      sqliteDb.close();
    },
  };
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('parent', 'guardian')),
  password_hash TEXT NOT NULL,
  recovery_code_hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS guardian_links (
  id TEXT PRIMARY KEY,
  parent_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guardian_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  invite_code TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
  is_secondary INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  verified_at INTEGER,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS consents (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  text_analysis INTEGER NOT NULL DEFAULT 1,
  guardian_alerts INTEGER NOT NULL DEFAULT 1,
  guardian_approve INTEGER NOT NULL DEFAULT 1,
  call_timing INTEGER NOT NULL DEFAULT 1,
  paused INTEGER NOT NULL DEFAULT 0,
  payment_limit INTEGER NOT NULL DEFAULT 10000,
  med_threshold INTEGER NOT NULL DEFAULT 25,
  high_threshold INTEGER NOT NULL DEFAULT 50,
  retention_days INTEGER NOT NULL DEFAULT 30,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS safe_words (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scam_analyses (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  cat TEXT NOT NULL,
  signals_json TEXT NOT NULL,
  ai_used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scam_reports (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  masked_excerpt TEXT NOT NULL,
  cat TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('unverified', 'verified')) DEFAULT 'unverified',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_assessments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount REAL NOT NULL,
  beneficiary TEXT NOT NULL,
  known_declared INTEGER NOT NULL,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  signals_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  parent_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assessment_id TEXT,
  amount REAL NOT NULL,
  beneficiary TEXT NOT NULL,
  level TEXT NOT NULL,
  signals_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'verification_requested', 'expired', 'cancelled', 'consumed')),
  decided_by TEXT REFERENCES users(id),
  decided_at INTEGER,
  verified_callback INTEGER NOT NULL DEFAULT 0,
  verification_note TEXT,
  escalated_to_secondary INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS qr_checks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  payee TEXT,
  amount REAL,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  signals_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS call_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  known INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  summary TEXT NOT NULL,
  channel TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT 'in_app',
  delivery_status TEXT NOT NULL DEFAULT 'delivered',
  read_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS qr_notification_prefs (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  qr_scan_notify INTEGER NOT NULL DEFAULT 0,
  high_risk_qr_alert INTEGER NOT NULL DEFAULT 1,
  critical_risk_qr_alert INTEGER NOT NULL DEFAULT 1,
  high_amount_alert INTEGER NOT NULL DEFAULT 1,
  very_high_load_alert INTEGER NOT NULL DEFAULT 1,
  repeated_qr_alert INTEGER NOT NULL DEFAULT 1,
  merchant_warning_alert INTEGER NOT NULL DEFAULT 1,
  suspicious_qr_alert INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS qr_scan_records (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  payload_hash TEXT NOT NULL,
  qr_format TEXT NOT NULL,
  qr_classification TEXT NOT NULL,
  upi_id TEXT,
  payee_name TEXT,
  merchant_name TEXT,
  mcc TEXT,
  tx_ref TEXT,
  tx_id TEXT,
  payment_note TEXT,
  amount REAL,
  amount_state TEXT NOT NULL,
  currency TEXT,
  provider_name TEXT,
  security_risk_level TEXT NOT NULL,
  security_risk_score INTEGER NOT NULL,
  payment_load_category TEXT NOT NULL,
  payment_load_risk_level TEXT NOT NULL,
  report_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS call_watcher_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  consent_given INTEGER NOT NULL DEFAULT 0,
  consent_at INTEGER,
  monitoring_state TEXT NOT NULL DEFAULT 'not_activated',
  notify_unknown_calls INTEGER NOT NULL DEFAULT 0,
  permission_call_state TEXT NOT NULL DEFAULT 'unavailable_in_browser',
  permission_sms_state TEXT NOT NULL DEFAULT 'unavailable_in_browser',
  permission_notif_state TEXT NOT NULL DEFAULT 'unavailable_in_browser',
  last_event_at INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS call_watcher_calls (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  external_event_id TEXT,
  caller_classification TEXT NOT NULL,
  caller_masked TEXT,
  caller_hash TEXT,
  call_status TEXT NOT NULL,
  incoming_at INTEGER NOT NULL,
  started_at INTEGER,
  ended_at INTEGER,
  duration_ms INTEGER,
  sim_info TEXT,
  source TEXT NOT NULL DEFAULT 'user_assisted',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_message_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  dedup_hash TEXT NOT NULL,
  sender_label TEXT,
  message_ts INTEGER NOT NULL,
  amount REAL,
  currency TEXT,
  tx_type TEXT NOT NULL,
  tx_ref TEXT,
  upi_ref TEXT,
  account_masked TEXT,
  merchant_or_recipient TEXT,
  payment_status TEXT NOT NULL,
  redacted_summary TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'user_assisted',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS call_payment_correlations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  call_event_id TEXT REFERENCES call_watcher_calls(id) ON DELETE SET NULL,
  payment_event_id TEXT REFERENCES payment_message_events(id) ON DELETE SET NULL,
  time_diff_ms INTEGER,
  during_call INTEGER NOT NULL DEFAULT 0,
  patterns_json TEXT NOT NULL,
  call_risk_level TEXT NOT NULL,
  call_risk_json TEXT NOT NULL,
  payment_risk_level TEXT NOT NULL,
  payment_risk_json TEXT NOT NULL,
  ai_report_json TEXT NOT NULL,
  parent_notified_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS safety_questionnaire_responses (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  correlation_id TEXT REFERENCES call_payment_correlations(id) ON DELETE CASCADE,
  call_event_id TEXT REFERENCES call_watcher_calls(id) ON DELETE SET NULL,
  caller_hash TEXT,
  asked_to_do TEXT,
  urgency_pressure TEXT,
  asked_sensitive_creds TEXT,
  emotional_feeling TEXT,
  dismissed INTEGER NOT NULL DEFAULT 0,
  critical_warning_triggered INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gsi_events (
  event_id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL DEFAULT 'web_session',
  event_type TEXT NOT NULL,
  event_timestamp INTEGER NOT NULL,
  source_module TEXT NOT NULL,
  event_version INTEGER NOT NULL DEFAULT 1,
  dedup_hash TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  risk_indicators_json TEXT NOT NULL,
  consent_context_json TEXT NOT NULL,
  processing_status TEXT NOT NULL DEFAULT 'processed',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gsi_incidents (
  incident_id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  related_event_ids_json TEXT NOT NULL,
  incident_category TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
  confidence TEXT NOT NULL CHECK(confidence IN ('low', 'medium', 'high')),
  detection_source TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  reasoning_summary TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  ai_explanation_json TEXT,
  acknowledgement_status TEXT NOT NULL DEFAULT 'unacknowledged' CHECK(acknowledgement_status IN ('unacknowledged', 'acknowledged')),
  resolution_status TEXT NOT NULL DEFAULT 'open' CHECK(resolution_status IN ('open', 'resolved', 'false_positive', 'confirmed_threat')),
  feedback_status TEXT,
  feedback_note TEXT,
  dedup_key TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gsi_threat_intel (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  indicator_type TEXT NOT NULL CHECK(indicator_type IN ('phone_hash', 'domain', 'url_hash', 'upi_id')),
  indicator_hash TEXT NOT NULL,
  indicator_display TEXT NOT NULL,
  reputation_label TEXT NOT NULL CHECK(reputation_label IN ('Trusted', 'Unknown', 'Suspicious', 'High Risk', 'Verified Spam')),
  confidence REAL NOT NULL DEFAULT 0.5,
  report_count INTEGER NOT NULL DEFAULT 0,
  false_positive_count INTEGER NOT NULL DEFAULT 0,
  evidence_summary TEXT NOT NULL,
  source TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gsi_reports (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period_type TEXT NOT NULL CHECK(period_type IN ('daily', 'weekly', 'monthly')),
  period_key TEXT NOT NULL,
  fingerprint_hash TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_links_parent ON guardian_links(parent_id, status);
CREATE INDEX IF NOT EXISTS idx_links_guardian ON guardian_links(guardian_id, status);
CREATE INDEX IF NOT EXISTS idx_requests_parent ON approval_requests(parent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qr_scans_user_hash ON qr_scan_records(user_id, payload_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qr_scans_user_upi ON qr_scan_records(user_id, upi_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qr_scans_user_time ON qr_scan_records(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cw_calls_user_time ON call_watcher_calls(user_id, incoming_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cw_calls_ext ON call_watcher_calls(user_id, external_event_id) WHERE external_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cw_pay_user_dedup ON payment_message_events(user_id, dedup_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cw_corr_user_time ON call_payment_correlations(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cw_quest_caller ON safety_questionnaire_responses(user_id, caller_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gsi_events_owner_time ON gsi_events(family_owner_id, event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gsi_events_dedup ON gsi_events(family_owner_id, dedup_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gsi_incidents_owner_time ON gsi_incidents(family_owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gsi_incidents_dedup ON gsi_incidents(family_owner_id, dedup_key, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gsi_intel_scope ON gsi_threat_intel(COALESCE(user_id, 'global'), indicator_type, indicator_hash);
CREATE INDEX IF NOT EXISTS idx_gsi_reports_owner_period ON gsi_reports(family_owner_id, period_type, period_key, created_at DESC);

CREATE TABLE IF NOT EXISTS gcih_entities (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL CHECK(entity_type IN (
    'phone_number', 'upi_id', 'url', 'domain', 'sms_sender', 'email', 'bank_id', 'merchant', 'qr_fingerprint'
  )),
  normalized_hash TEXT NOT NULL,
  normalized_key TEXT NOT NULL,
  masked_display TEXT NOT NULL,
  risk_classification TEXT NOT NULL DEFAULT 'Inconclusive' CHECK(risk_classification IN (
    'Safe', 'Low', 'Moderate', 'High', 'Critical', 'Inconclusive'
  )),
  verification_status TEXT NOT NULL DEFAULT 'Unverified' CHECK(verification_status IN (
    'Unknown', 'Unverified', 'Suspicious', 'High risk', 'Confirmed malicious', 'Verified legitimate', 'Disputed', 'Under review'
  )),
  confidence REAL NOT NULL DEFAULT 0.5,
  report_count INTEGER NOT NULL DEFAULT 0,
  fp_count INTEGER NOT NULL DEFAULT 0,
  source_modules_json TEXT NOT NULL DEFAULT '[]',
  source_device_ids_json TEXT NOT NULL DEFAULT '[]',
  related_event_ids_json TEXT NOT NULL DEFAULT '[]',
  related_incident_ids_json TEXT NOT NULL DEFAULT '[]',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  version INTEGER NOT NULL DEFAULT 1,
  first_detected_at INTEGER NOT NULL,
  last_detected_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gcih_domain_events (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_device_id TEXT NOT NULL DEFAULT 'web_session',
  source_module TEXT NOT NULL,
  event_type TEXT NOT NULL,
  entity_refs_json TEXT NOT NULL DEFAULT '[]',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  gsi_event_id TEXT,
  incident_id TEXT,
  consent_context_json TEXT NOT NULL DEFAULT '{}',
  schema_version INTEGER NOT NULL DEFAULT 1,
  dedup_hash TEXT NOT NULL,
  sync_status TEXT NOT NULL DEFAULT 'Successfully synchronised',
  event_timestamp INTEGER NOT NULL,
  processed_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gcih_relationships (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  first_entity_id TEXT NOT NULL REFERENCES gcih_entities(id) ON DELETE CASCADE,
  second_entity_id TEXT NOT NULL REFERENCES gcih_entities(id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL,
  supporting_event_ids_json TEXT NOT NULL DEFAULT '[]',
  source_modules_json TEXT NOT NULL DEFAULT '[]',
  confidence REAL NOT NULL DEFAULT 0.6,
  evidence TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disputed', 'corrected')),
  correction_note TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gcih_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_label TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'web',
  role TEXT NOT NULL CHECK(role IN ('parent', 'guardian')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
  permissions_json TEXT NOT NULL DEFAULT '{}',
  last_sync_cursor INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS gcih_entity_feedback (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_role TEXT NOT NULL CHECK(actor_role IN ('parent', 'guardian')),
  entity_id TEXT NOT NULL REFERENCES gcih_entities(id) ON DELETE CASCADE,
  event_id TEXT,
  incident_id TEXT,
  feedback_type TEXT NOT NULL CHECK(feedback_type IN (
    'suspicious', 'legitimate', 'false_positive', 'request_review', 'incorrect_association'
  )),
  note TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gcih_incident_history (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES gsi_incidents(incident_id) ON DELETE CASCADE,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  previous_status TEXT,
  next_status TEXT NOT NULL,
  action TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_gcih_entities_unique ON gcih_entities(family_owner_id, entity_type, normalized_hash);
CREATE INDEX IF NOT EXISTS idx_gcih_entities_owner_upd ON gcih_entities(family_owner_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gcih_events_dedup ON gcih_domain_events(family_owner_id, dedup_hash);
CREATE INDEX IF NOT EXISTS idx_gcih_events_owner_time ON gcih_domain_events(family_owner_id, processed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gcih_rel_unique ON gcih_relationships(family_owner_id, first_entity_id, second_entity_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_gcih_rel_owner_upd ON gcih_relationships(family_owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_gcih_devices_user ON gcih_devices(user_id, status);
CREATE INDEX IF NOT EXISTS idx_gcih_devices_owner ON gcih_devices(family_owner_id, status);
CREATE INDEX IF NOT EXISTS idx_gcih_feedback_entity ON gcih_entity_feedback(entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gcih_inc_hist ON gcih_incident_history(incident_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_tool_items (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_key TEXT NOT NULL CHECK(tool_key IN ('education', 'health', 'calendar', 'document', 'emergency_contact')),
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  status TEXT NOT NULL DEFAULT 'active',
  due_at INTEGER,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  shared_with_guardian INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_tool_conversations (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_key TEXT NOT NULL CHECK(tool_key IN ('parenting', 'child_safety', 'education', 'health', 'budget', 'emergency', 'calendar', 'document')),
  prompt TEXT NOT NULL,
  response TEXT NOT NULL,
  checklist_json TEXT NOT NULL DEFAULT '[]',
  ai_used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bank_connections (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  institution_name TEXT NOT NULL,
  account_masked TEXT NOT NULL,
  aa_handle TEXT NOT NULL,
  aa_framework TEXT NOT NULL,
  consent_status TEXT NOT NULL DEFAULT 'active' CHECK(consent_status IN ('active', 'revoked')),
  is_demo_sample INTEGER NOT NULL DEFAULT 1,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  consent_expires_at INTEGER NOT NULL,
  guardian_authorized INTEGER NOT NULL DEFAULT 1,
  balance_inr REAL NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS bank_transactions (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES bank_connections(id) ON DELETE CASCADE,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tx_date INTEGER NOT NULL,
  merchant TEXT NOT NULL,
  category TEXT NOT NULL,
  tx_type TEXT NOT NULL CHECK(tx_type IN ('debit', 'credit')),
  amount REAL NOT NULL,
  is_demo_sample INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS family_budgets (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  monthly_limit REAL NOT NULL DEFAULT 0,
  savings_goal_name TEXT,
  savings_target REAL NOT NULL DEFAULT 0,
  savings_current REAL NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS financial_access_controls (
  family_owner_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  child_financial_access INTEGER NOT NULL DEFAULT 0,
  guardian_financial_access INTEGER NOT NULL DEFAULT 1,
  require_guardian_auth INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_tool_items_owner ON ai_tool_items(family_owner_id, tool_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_tool_conv_owner ON ai_tool_conversations(family_owner_id, tool_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bank_conn_owner ON bank_connections(family_owner_id, consent_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bank_tx_owner ON bank_transactions(family_owner_id, tx_date DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_family_budget_cat ON family_budgets(family_owner_id, category);

CREATE TABLE IF NOT EXISTS epp_bank_directory (
  id TEXT PRIMARY KEY,
  bank_name TEXT NOT NULL,
  short_code TEXT UNIQUE NOT NULL,
  support_phone TEXT NOT NULL,
  upi_block_url TEXT,
  debit_block_url TEXT,
  credit_block_url TEXT,
  netbanking_url TEXT,
  fraud_report_url TEXT,
  verification_status TEXT NOT NULL DEFAULT 'verified' CHECK(verification_status IN ('verified', 'unverified', 'phone_only')),
  last_verified_at INTEGER NOT NULL,
  notes TEXT,
  updated_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS epp_lock_sessions (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  activated_by_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  activated_by_name TEXT NOT NULL,
  activated_by_role TEXT NOT NULL CHECK(activated_by_role IN ('parent', 'guardian')),
  status TEXT NOT NULL CHECK(status IN ('active', 'unlocked', 'expired')),
  selected_apps_json TEXT NOT NULL DEFAULT '[]',
  duration_option TEXT NOT NULL,
  duration_minutes INTEGER,
  manual_until_unlock INTEGER NOT NULL DEFAULT 0,
  os_enforcement_mode TEXT NOT NULL DEFAULT 'guardian_advisory_session',
  device_platform TEXT NOT NULL DEFAULT 'web_browser',
  device_capability_note TEXT NOT NULL DEFAULT '',
  explicit_consent_ack INTEGER NOT NULL DEFAULT 1,
  dedup_key TEXT,
  notified_guardians_count INTEGER NOT NULL DEFAULT 0,
  expiry_notified INTEGER NOT NULL DEFAULT 0,
  activated_at INTEGER NOT NULL,
  expires_at INTEGER,
  unlocked_at INTEGER,
  unlocked_by_id TEXT,
  unlocked_by_name TEXT
);

CREATE TABLE IF NOT EXISTS epp_bank_action_logs (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bank_id TEXT NOT NULL,
  bank_name TEXT NOT NULL,
  service_type TEXT NOT NULL CHECK(service_type IN ('upi_block', 'debit_block', 'credit_block', 'netbanking_security', 'fraud_report')),
  launch_type TEXT NOT NULL CHECK(launch_type IN ('official_url', 'support_phone')),
  target_ref TEXT NOT NULL,
  bank_confirmed_by_user INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  confirmed_at INTEGER
);

CREATE TABLE IF NOT EXISTS epp_audit_trail (
  id TEXT PRIMARY KEY,
  family_owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  actor_name TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_epp_lock_owner ON epp_lock_sessions(family_owner_id, status, activated_at DESC);
CREATE INDEX IF NOT EXISTS idx_epp_bank_logs_owner ON epp_bank_action_logs(family_owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_epp_audit_owner ON epp_audit_trail(family_owner_id, created_at DESC);
`;

async function safeAddColumn(
  driver: RawDriver,
  table: string,
  colName: string,
  colDef: string,
  existingCols: { name?: string }[]
): Promise<void> {
  const exists = existingCols.some(
    (c) => String(c?.name || "").toLowerCase() === colName.toLowerCase()
  );
  if (exists) return;
  try {
    await driver.exec(`ALTER TABLE ${table} ADD COLUMN ${colName} ${colDef};`);
  } catch (err: unknown) {
    const msg = String((err as { message?: string })?.message || "").toLowerCase();
    if (msg.includes("duplicate column") || msg.includes("already exists")) {
      return;
    }
    throw err;
  }
}

async function safeExecSchema(driver: RawDriver, sql: string): Promise<void> {
  try {
    await driver.exec(sql);
  } catch (_err: unknown) {
    // If executeMultiple fails on certain drivers or existing indexes, execute statement-by-statement
    const statements = sql
      .split(/;\s*[\r\n]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith("--"));
    for (const stmt of statements) {
      try {
        await driver.exec(stmt.endsWith(";") ? stmt : `${stmt};`);
      } catch (stmtErr: unknown) {
        const msg = String((stmtErr as { message?: string })?.message || "").toLowerCase();
        if (msg.includes("already exists") || msg.includes("duplicate")) {
          continue;
        }
        throw stmtErr;
      }
    }
  }
}

async function runMigrations(driver: RawDriver): Promise<void> {
  if (driver.mode === "turso_libsql") {
    try {
      await driver.exec("PRAGMA foreign_keys = ON;");
    } catch {
      // ignore pragma warning if restricted on specific endpoints
    }
  }
  await safeExecSchema(driver, SCHEMA_SQL);

  // Safe migrations for existing consents columns
  const consentCols = await driver.prepare("PRAGMA table_info(consents)").all<{ name: string }>();
  await safeAddColumn(driver, "consents", "load_moderate_max", "INTEGER NOT NULL DEFAULT 2000", consentCols);
  await safeAddColumn(driver, "consents", "load_high_max", "INTEGER NOT NULL DEFAULT 10000", consentCols);
  await safeAddColumn(driver, "consents", "load_very_high_min", "INTEGER NOT NULL DEFAULT 25000", consentCols);
  await safeAddColumn(driver, "consents", "red_alert_cooldown_sec", "INTEGER NOT NULL DEFAULT 600", consentCols);

  // Safe migrations for Smart Red Alert System columns on gsi_incidents
  const gsiIncCols = await driver.prepare("PRAGMA table_info(gsi_incidents)").all<{ name: string }>();
  await safeAddColumn(driver, "gsi_incidents", "alert_level", "TEXT NOT NULL DEFAULT 'GREEN'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "actor_masked", "TEXT", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "parent_notif_status", "TEXT NOT NULL DEFAULT 'Not Required'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "child_notif_status", "TEXT NOT NULL DEFAULT 'Not Required'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "decision_rationale_json", "TEXT", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "indicator_fingerprint", "TEXT", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "involved_entity_ids_json", "TEXT NOT NULL DEFAULT '[]'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "source_modules_json", "TEXT NOT NULL DEFAULT '[]'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "source_device_ids_json", "TEXT NOT NULL DEFAULT '[]'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "workflow_status", "TEXT NOT NULL DEFAULT 'New'", gsiIncCols);
  await safeAddColumn(driver, "gsi_incidents", "timeline_json", "TEXT NOT NULL DEFAULT '[]'", gsiIncCols);

  try {
    await driver.exec(
      "CREATE INDEX IF NOT EXISTS idx_gsi_incidents_fp ON gsi_incidents(family_owner_id, indicator_fingerprint, updated_at DESC);"
    );
  } catch (err: unknown) {
    const msg = String((err as { message?: string })?.message || "").toLowerCase();
    if (!msg.includes("already exists") && !msg.includes("duplicate")) {
      throw err;
    }
  }

  // Safe migrations for Call Watcher background protection & call-screening columns
  const cwSettingsCols = await driver.prepare("PRAGMA table_info(call_watcher_settings)").all<{ name: string }>();
  await safeAddColumn(driver, "call_watcher_settings", "permission_call_log_state", "TEXT NOT NULL DEFAULT 'unavailable_in_browser'", cwSettingsCols);
  await safeAddColumn(driver, "call_watcher_settings", "call_screening_role_state", "TEXT NOT NULL DEFAULT 'unavailable_in_browser'", cwSettingsCols);
  await safeAddColumn(driver, "call_watcher_settings", "battery_restricted", "INTEGER NOT NULL DEFAULT 0", cwSettingsCols);
  await safeAddColumn(driver, "call_watcher_settings", "app_lifecycle_state", "TEXT NOT NULL DEFAULT 'web_foreground'", cwSettingsCols);
  await safeAddColumn(driver, "call_watcher_settings", "boot_restore_pending", "INTEGER NOT NULL DEFAULT 0", cwSettingsCols);

  const cwCallsCols = await driver.prepare("PRAGMA table_info(call_watcher_calls)").all<{ name: string }>();
  await safeAddColumn(driver, "call_watcher_calls", "call_lifecycle_phase", "TEXT NOT NULL DEFAULT 'ended'", cwCallsCols);
  await safeAddColumn(driver, "call_watcher_calls", "screening_verdict", "TEXT", cwCallsCols);
  await safeAddColumn(driver, "call_watcher_calls", "screening_latency_ms", "INTEGER", cwCallsCols);
}

let activeDriver: RawDriver | null = null;
let initPromise: Promise<RawDriver> | null = null;

export async function initDb(): Promise<void> {
  if (activeDriver) return;
  if (!initPromise) {
    initPromise = (async () => {
      const driver = await createDriver();
      await runMigrations(driver);
      activeDriver = driver;
      return driver;
    })().catch((err) => {
      initPromise = null;
      activeDriver = null;
      throw err;
    });
  }
  await initPromise;
}

async function getDriver(): Promise<RawDriver> {
  if (!activeDriver) {
    await initDb();
  }
  if (!activeDriver) {
    throw new DbNotConfiguredError();
  }
  return activeDriver;
}

export async function resetDbConnectionForTests(): Promise<void> {
  initPromise = null;
  if (activeDriver) {
    try {
      await activeDriver.close();
    } catch {
      // ignore close errors in test teardown
    }
    activeDriver = null;
  }
  dbPath = resolveConfiguredDbPath();
}

export const db = {
  prepare(sql: string): DbStatement {
    return {
      async get<T = Record<string, unknown>>(...params: unknown[]): Promise<T | undefined> {
        const driver = await getDriver();
        return driver.prepare(sql).get<T>(...params);
      },
      async all<T = Record<string, unknown>>(...params: unknown[]): Promise<T[]> {
        const driver = await getDriver();
        return driver.prepare(sql).all<T>(...params);
      },
      async run(...params: unknown[]): Promise<DbRunResult> {
        const driver = await getDriver();
        return driver.prepare(sql).run(...params);
      },
    };
  },
  async exec(sql: string): Promise<void> {
    const driver = await getDriver();
    await driver.exec(sql);
  },
};
