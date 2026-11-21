import crypto from "node:crypto";
import { db } from "./db.ts";
import { runParentsAiToolAssistant, redactSensitive } from "./ai.ts";

export type ParentsAiToolKey =
  | "parenting"
  | "child_safety"
  | "education"
  | "health"
  | "budget"
  | "emergency"
  | "calendar"
  | "document";

export type ToolItemKey = "education" | "health" | "calendar" | "document" | "emergency_contact";

const VALID_TOOL_KEYS = new Set<ParentsAiToolKey>([
  "parenting",
  "child_safety",
  "education",
  "health",
  "budget",
  "emergency",
  "calendar",
  "document",
]);

const VALID_ITEM_KEYS = new Set<ToolItemKey>([
  "education",
  "health",
  "calendar",
  "document",
  "emergency_contact",
]);

const FORBIDDEN_CREDENTIAL_KEY_RE =
  /^(password|passcode|pin|upi_?pin|atm_?pin|mpin|cvv|cvc|otp|netbanking_?pass|secret_?pin)$/i;

const FORBIDDEN_CREDENTIAL_VALUE_RE =
  /\b(?:upi\s*pin|atm\s*pin|mpin|cvv|netbanking\s*password)\s*[:=]?\s*\d{3,8}\b/i;

function makeId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

export function assertNoBankingCredentials(payload: unknown): void {
  if (!payload || typeof payload !== "object") return;
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (FORBIDDEN_CREDENTIAL_KEY_RE.test(k) && String(v ?? "").trim().length > 0) {
          throw new Error(
            "Security Policy: Parents AI uses read-only RBI Account Aggregator consent and never collects banking passwords, UPI PINs, ATM PINs, CVVs, or OTPs."
          );
        }
        if (typeof v === "string" && FORBIDDEN_CREDENTIAL_VALUE_RE.test(v)) {
          throw new Error(
            "Security Policy: Sensitive PIN/CVV/password values are never accepted or stored by Parents AI."
          );
        }
        walk(v);
      }
    }
  };
  walk(payload);
}

export async function ensureFinancialAccessControl(familyOwnerId: string) {
  const row = (await db
    .prepare("SELECT * FROM financial_access_controls WHERE family_owner_id = ?")
    .get(familyOwnerId)) as
    | {
        family_owner_id: string;
        child_financial_access: number;
        guardian_financial_access: number;
        require_guardian_auth: number;
        updated_at: number;
      }
    | undefined;
  if (row) return row;

  const now = Date.now();
  await db
    .prepare(
      `INSERT OR IGNORE INTO financial_access_controls
       (family_owner_id, child_financial_access, guardian_financial_access, require_guardian_auth, updated_at)
       VALUES (?, 0, 1, 1, ?)`
    )
    .run(familyOwnerId, now);
  return (await db
    .prepare("SELECT * FROM financial_access_controls WHERE family_owner_id = ?")
    .get(familyOwnerId)) as {
    family_owner_id: string;
    child_financial_access: number;
    guardian_financial_access: number;
    require_guardian_auth: number;
    updated_at: number;
  };
}

export async function resolveParentsAiScope(
  actor: { id: string; role: "parent" | "guardian" },
  requestedOwnerId?: string
): Promise<{ familyOwnerId: string; isOwner: boolean }> {
  if (actor.role === "parent") {
    return { familyOwnerId: actor.id, isOwner: true };
  }
  const linkedRows = (await db
    .prepare(
      `SELECT parent_id FROM guardian_links
       WHERE guardian_id = ? AND status = 'active'
       ORDER BY verified_at DESC`
    )
    .all(actor.id)) as { parent_id: string }[];
  if (linkedRows.length === 0) {
    throw new Error("No active family parent link found for this guardian account.");
  }
  const target =
    requestedOwnerId && linkedRows.some((r) => r.parent_id === requestedOwnerId)
      ? requestedOwnerId
      : linkedRows[0].parent_id;
  return { familyOwnerId: target, isOwner: false };
}

function deterministicToolFallback(toolKey: ParentsAiToolKey, prompt: string, lang: string): {
  answer: string;
  checklist: string[];
  nextSteps: string[];
} {
  const isHi = lang === "hi";
  const lower = prompt.toLowerCase();

  if (toolKey === "child_safety") {
    return {
      answer: isHi
        ? "बच्चों की डिजिटल सुरक्षा के लिए अज्ञात लिंक, गेमिंग टॉप-अप और रिमोट स्क्रीन-शेयरिंग ऐप्स से दूरी रखें।"
        : "Protect children online by keeping private details off public chats, reviewing app purchase approvals, and avoiding unknown links or screen-sharing requests.",
      checklist: [
        "Keep UPI/card payment approvals locked behind Parent or Guardian consent.",
        "Never install AnyDesk/TeamViewer or grant Accessibility rights to unverified apps.",
        "Review privacy settings and friend requests weekly together calmly.",
      ],
      nextSteps: [
        "Open AI Child Safety Checklist to mark completed items",
        "Inspect any suspicious URL inside Scam & Link Check",
      ],
    };
  }
  if (toolKey === "education") {
    return {
      answer:
        "Break study goals into 35-minute focused blocks with short hydration breaks, mixing revision of weak concepts first before practice problems.",
      checklist: [
        "Schedule core Math/Science revision during peak morning or early evening focus.",
        "Reserve 15 minutes at the end of the day to review completed tasks.",
        "Store upcoming exam dates in the AI Education Planner.",
      ],
      nextSteps: ["Add today's study block in AI Education Planner", "Sync exam dates to Family Calendar"],
    };
  }
  if (toolKey === "health") {
    return {
      answer:
        "Organize medications, hydration, and doctor check-ups in one shared schedule so linked guardians can see reminder status without micromanaging. (Non-diagnostic organizational guidance only.)",
      checklist: [
        "Group morning, afternoon, and evening medicines clearly by dosage window.",
        "Keep upcoming lab tests and clinic follow-ups 48 hours ahead on the Family Calendar.",
        "Verify prescription changes only with your licensed physician.",
      ],
      nextSteps: ["Log medication reminder in Health Organizer", "Confirm emergency doctor contact in AI Emergency Assistant"],
    };
  }
  if (toolKey === "budget") {
    return {
      answer:
        lower.includes("save") || lower.includes("goal")
          ? "Prioritize an automated monthly family emergency fund allocation first, then cap discretionary shopping and track recurring utility & grocery totals."
          : "Track household inflows against core essentials (groceries, utilities, healthcare, education) using read-only RBI Account Aggregator summaries — never share PINs or banking passwords.",
      checklist: [
        "Review category monthly caps for Groceries, Healthcare, Utilities, and Education.",
        "Inspect uncategorized or unusually large outflows with a linked Guardian.",
        "Keep read-only AA consent scoped and time-limited.",
      ],
      nextSteps: ["Set monthly category caps in Connect Your Bank / Budget", "Review monthly spending breakdown"],
    };
  }
  if (toolKey === "emergency") {
    return {
      answer:
        "Keep local family contacts, family doctor, bank fraud helpline (1930), and cybercrime.gov.in one tap away, and verify urgent family calls using your private Family Safe Word.",
      checklist: [
        "Verify any urgent money call by hanging up and calling back on a saved contact number.",
        "For suspected financial cyber fraud in India, immediately call 1930 or visit cybercrime.gov.in.",
        "Use Guardian Emergency Help to revoke compromised admin/guardian access instantly.",
      ],
      nextSteps: ["Add primary emergency contacts below", "Verify Family Safe Word in Family Control Center"],
    };
  }
  if (toolKey === "calendar") {
    return {
      answer:
        "Coordinate school events, medical check-ups, bill due dates, and family visits in a single shared timeline visible to authorized family members.",
      checklist: [
        "Tag high-priority appointments so guardians receive timely reminders.",
        "Group recurring monthly utility and tuition dates at the start of the month.",
      ],
      nextSteps: ["Add an upcoming family event", "Check document renewal dates alongside calendar events"],
    };
  }
  if (toolKey === "document") {
    return {
      answer:
        "Track expiry and renewal windows using masked document labels only (e.g., Health Policy ending ****4821) — never upload or store raw Aadhaar/card numbers or PINs.",
      checklist: [
        "Track Passport, Motor Insurance, Health Insurance, and Senior Citizen ID renewal dates.",
        "Set reminders at 30 days and 7 days before expiry.",
        "Store only masked last-4 reference identifiers and renewal dates.",
      ],
      nextSteps: ["Add a document renewal reminder below", "Review items expiring within 30 days"],
    };
  }
  return {
    answer:
      "Balanced daily routines, open two-way check-ins without judgment, and clear family safety agreements build lasting digital confidence for both children and senior parents.",
    checklist: [
      "Hold a calm 10-minute weekly family check-in on calls, messages, and schedules.",
      "Establish a rule that urgent financial requests always pause for verification.",
      "Celebrate small learning milestones across generations.",
    ],
    nextSteps: ["Save a shared family reminder in Calendar", "Review child digital safety checklist"],
  };
}

export async function askParentsAiTool(params: {
  actor: { id: string; role: "parent" | "guardian"; name: string };
  toolKey: string;
  prompt: string;
  requestedOwnerId?: string;
  lang?: string;
}) {
  const toolKey = String(params.toolKey || "parenting") as ParentsAiToolKey;
  if (!VALID_TOOL_KEYS.has(toolKey)) {
    throw new Error("Invalid AI tool key.");
  }
  const cleanPrompt = String(params.prompt || "").trim().slice(0, 800);
  if (!cleanPrompt) {
    throw new Error("Please enter a question or scenario.");
  }

  const { familyOwnerId } = await resolveParentsAiScope(params.actor, params.requestedOwnerId);
  const itemCount = (
    (await db
      .prepare("SELECT COUNT(*) as c FROM ai_tool_items WHERE family_owner_id = ?")
      .get(familyOwnerId)) as { c: number }
  ).c;
  const linksCount = (
    (await db
      .prepare("SELECT COUNT(*) as c FROM guardian_links WHERE parent_id = ? AND status = 'active'")
      .get(familyOwnerId)) as { c: number }
  ).c;
  const familyContext = `Role=${params.actor.role}, SavedPlannerItems=${itemCount}, LinkedGuardians=${linksCount}`;

  let result: { answer: string; checklist: string[]; nextSteps: string[] };
  let aiUsed = false;
  let model: string | null = null;

  try {
    const aiOut = await runParentsAiToolAssistant({
      toolKey,
      prompt: cleanPrompt,
      familyContext,
      lang: params.lang || "en",
    });
    result = {
      answer: aiOut.answer,
      checklist: aiOut.checklist,
      nextSteps: aiOut.nextSteps,
    };
    aiUsed = true;
    model = aiOut.model;
  } catch {
    result = deterministicToolFallback(toolKey, cleanPrompt, params.lang || "en");
  }

  const id = makeId("aitc");
  const now = Date.now();
  const safeStoredPrompt = redactSensitive(cleanPrompt);
  await db
    .prepare(
      `INSERT INTO ai_tool_conversations
       (id, family_owner_id, user_id, tool_key, prompt, response, checklist_json, ai_used, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      familyOwnerId,
      params.actor.id,
      toolKey,
      safeStoredPrompt,
      result.answer,
      JSON.stringify({ checklist: result.checklist, nextSteps: result.nextSteps }),
      aiUsed ? 1 : 0,
      now
    );

  return {
    id,
    toolKey,
    prompt: safeStoredPrompt,
    answer: result.answer,
    checklist: result.checklist,
    nextSteps: result.nextSteps,
    aiUsed,
    model,
    createdAt: now,
  };
}

export async function createToolItem(params: {
  actor: { id: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
  toolKey: string;
  title: string;
  category?: string;
  status?: string;
  dueAt?: number | null;
  metadata?: Record<string, unknown>;
  sharedWithGuardian?: boolean;
}) {
  const toolKey = String(params.toolKey || "") as ToolItemKey;
  if (!VALID_ITEM_KEYS.has(toolKey)) {
    throw new Error("Invalid workspace item type.");
  }
  const title = redactSensitive(String(params.title || "").trim()).slice(0, 140);
  if (!title) {
    throw new Error("Item title is required.");
  }
  const { familyOwnerId } = await resolveParentsAiScope(params.actor, params.requestedOwnerId);
  const now = Date.now();
  const id = makeId("aiti");
  const category = String(params.category || "general").trim().slice(0, 50) || "general";
  const status = String(params.status || "active").trim().slice(0, 32) || "active";
  const dueAt = params.dueAt && Number.isFinite(Number(params.dueAt)) ? Math.round(Number(params.dueAt)) : null;

  const safeMeta: Record<string, unknown> = {};
  if (params.metadata && typeof params.metadata === "object") {
    for (const [k, v] of Object.entries(params.metadata)) {
      if (typeof v === "string") {
        safeMeta[k.slice(0, 40)] = redactSensitive(v).slice(0, 220);
      } else if (typeof v === "number" || typeof v === "boolean") {
        safeMeta[k.slice(0, 40)] = v;
      }
    }
  }

  await db
    .prepare(
      `INSERT INTO ai_tool_items
       (id, family_owner_id, created_by, tool_key, title, category, status, due_at, metadata_json, shared_with_guardian, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      familyOwnerId,
      params.actor.id,
      toolKey,
      title,
      category,
      status,
      dueAt,
      JSON.stringify(safeMeta),
      params.sharedWithGuardian === false ? 0 : 1,
      now,
      now
    );
  return { id, familyOwnerId };
}

export async function updateToolItem(params: {
  actor: { id: string; role: "parent" | "guardian" };
  itemId: string;
  status?: string;
  title?: string;
  dueAt?: number | null;
}) {
  const row = (await db.prepare("SELECT * FROM ai_tool_items WHERE id = ?").get(params.itemId)) as
    | { id: string; family_owner_id: string; status: string; title: string; due_at: number | null }
    | undefined;
  if (!row) throw new Error("Item not found.");
  const { familyOwnerId } = await resolveParentsAiScope(params.actor, row.family_owner_id);
  if (familyOwnerId !== row.family_owner_id) {
    throw new Error("Unauthorized to update this item.");
  }
  const nextStatus = params.status ? String(params.status).slice(0, 32) : row.status;
  const nextTitle = params.title ? redactSensitive(String(params.title).trim()).slice(0, 140) : row.title;
  const nextDue =
    params.dueAt === undefined ? row.due_at : params.dueAt ? Math.round(Number(params.dueAt)) : null;

  await db
    .prepare("UPDATE ai_tool_items SET status = ?, title = ?, due_at = ?, updated_at = ? WHERE id = ?")
    .run(nextStatus, nextTitle, nextDue, Date.now(), row.id);
  return { ok: true };
}

export async function deleteToolItem(actor: { id: string; role: "parent" | "guardian" }, itemId: string) {
  const row = (await db.prepare("SELECT id, family_owner_id FROM ai_tool_items WHERE id = ?").get(itemId)) as
    | { id: string; family_owner_id: string }
    | undefined;
  if (!row) throw new Error("Item not found.");
  const { familyOwnerId } = await resolveParentsAiScope(actor, row.family_owner_id);
  if (familyOwnerId !== row.family_owner_id) {
    throw new Error("Unauthorized to delete this item.");
  }
  await db.prepare("DELETE FROM ai_tool_items WHERE id = ?").run(itemId);
  return { ok: true };
}

export async function connectSampleAaBank(params: {
  actor: { id: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
  institutionName?: string;
  aaHandle?: string;
  mode?: string;
  scopes?: string[];
  consentDays?: number;
}) {
  if (params.mode === "live") {
    const err = new Error(
      "Live RBI Account Aggregator FIP/TSP keys (Sahamati / Finvu / Anumati) are not configured on this server. Select Sample Demo Mode to explore RBI AA consent & financial analytics safely."
    ) as Error & { statusCode?: number };
    err.statusCode = 400;
    throw err;
  }

  const { familyOwnerId } = await resolveParentsAiScope(params.actor, params.requestedOwnerId);
  if (params.actor.role !== "parent") {
    throw new Error("Only the primary parent/account holder can grant RBI Account Aggregator bank consent.");
  }

  const institution = String(params.institutionName || "State Bank of India (Sample FIP)").trim().slice(0, 80);
  const aaHandle = String(params.aaHandle || "family@finvu.demo").trim().slice(0, 80);
  if (!aaHandle.includes("@")) {
    throw new Error("Please enter a valid Account Aggregator handle (e.g. name@finvu.demo).");
  }

  const now = Date.now();
  const days = Math.max(7, Math.min(180, Math.round(Number(params.consentDays) || 90)));
  const connId = makeId("bank");
  const last4 = String(1000 + crypto.randomInt(8999));
  const scopes =
    Array.isArray(params.scopes) && params.scopes.length
      ? params.scopes.slice(0, 4).map((s) => String(s).slice(0, 40))
      : ["PROFILE (Read-Only)", "SUMMARY (Read-Only)", "TRANSACTIONS (Read-Only)"];

  const sampleBalance = 148650;
  await db
    .prepare(
      `INSERT INTO bank_connections
       (id, family_owner_id, institution_name, account_masked, aa_handle, aa_framework, consent_status, is_demo_sample, scopes_json, consent_expires_at, guardian_authorized, balance_inr, created_at)
       VALUES (?, ?, ?, ?, ?, 'RBI Account Aggregator (Sample Demo Mode)', 'active', 1, ?, ?, 1, ?, ?)`
    )
    .run(
      connId,
      familyOwnerId,
      institution,
      `XXXX-${last4}`,
      aaHandle,
      JSON.stringify(scopes),
      now + days * 86_400_000,
      sampleBalance,
      now
    );

  const dayMs = 86_400_000;
  const sampleTxs: { daysAgo: number; merchant: string; category: string; txType: "debit" | "credit"; amount: number }[] = [
    { daysAgo: 1, merchant: "FreshMart Neighbourhood Groceries", category: "Groceries", txType: "debit", amount: 3420 },
    { daysAgo: 2, merchant: "Apollo Pharmacy & Wellness", category: "Healthcare", txType: "debit", amount: 1850 },
    { daysAgo: 4, merchant: "MSEDCL Electricity Utility", category: "Utilities", txType: "debit", amount: 2680 },
    { daysAgo: 5, merchant: "Pension & Dividend Credit", category: "Income", txType: "credit", amount: 52000 },
    { daysAgo: 7, merchant: "St. Xavier Tuition & Books", category: "Education", txType: "debit", amount: 8500 },
    { daysAgo: 9, merchant: "PPF & Family Emergency Transfer", category: "Savings", txType: "debit", amount: 10000 },
    { daysAgo: 12, merchant: "Indane Gas & Broadband", category: "Utilities", txType: "debit", amount: 1790 },
    { daysAgo: 14, merchant: "Organic Harvest Market", category: "Groceries", txType: "debit", amount: 2940 },
    { daysAgo: 17, merchant: "Family Consultancy Annuity", category: "Income", txType: "credit", amount: 24500 },
    { daysAgo: 21, merchant: "Metro Commute & Fuel", category: "Transport", txType: "debit", amount: 2150 },
  ];

  const insertTx = db.prepare(
    `INSERT INTO bank_transactions
     (id, connection_id, family_owner_id, tx_date, merchant, category, tx_type, amount, is_demo_sample, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
  );
  for (const tx of sampleTxs) {
    await insertTx.run(
      makeId("btx"),
      connId,
      familyOwnerId,
      now - tx.daysAgo * dayMs,
      tx.merchant,
      tx.category,
      tx.txType,
      tx.amount,
      now
    );
  }

  // Seed starter household budget caps if none exist
  const budgetCount = (
    (await db
      .prepare("SELECT COUNT(*) as c FROM family_budgets WHERE family_owner_id = ?")
      .get(familyOwnerId)) as { c: number }
  ).c;
  if (budgetCount === 0) {
    const starterBudgets: [string, number, string | null, number, number][] = [
      ["Groceries", 12000, "Family Emergency Reserve", 250000, 148650],
      ["Healthcare", 6000, null, 0, 0],
      ["Utilities", 6500, null, 0, 0],
      ["Education", 12000, null, 0, 0],
      ["Transport", 4500, null, 0, 0],
    ];
    const insBud = db.prepare(
      `INSERT OR IGNORE INTO family_budgets
       (id, family_owner_id, category, monthly_limit, savings_goal_name, savings_target, savings_current, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const [cat, lim, gName, gTarget, gCur] of starterBudgets) {
      await insBud.run(makeId("bud"), familyOwnerId, cat, lim, gName, gTarget, gCur, now);
    }
  }

  return { connectionId: connId, isDemoSample: true };
}

export async function revokeBankConnection(actor: { id: string; role: "parent" | "guardian" }, connId: string) {
  if (actor.role !== "parent") {
    throw new Error("Only the parent/account holder can revoke Account Aggregator consent.");
  }
  const row = (await db
    .prepare("SELECT id, family_owner_id FROM bank_connections WHERE id = ? AND family_owner_id = ?")
    .get(connId, actor.id)) as { id: string; family_owner_id: string } | undefined;
  if (!row) {
    throw new Error("Bank connection not found.");
  }
  const now = Date.now();
  await db
    .prepare("UPDATE bank_connections SET consent_status = 'revoked', revoked_at = ? WHERE id = ?")
    .run(now, connId);
  await db.prepare("DELETE FROM bank_transactions WHERE connection_id = ?").run(connId);
  return { ok: true };
}

export async function upsertFamilyBudget(params: {
  actor: { id: string; role: "parent" | "guardian" };
  requestedOwnerId?: string;
  category: string;
  monthlyLimit: number;
  savingsGoalName?: string;
  savingsTarget?: number;
  savingsCurrent?: number;
}) {
  const { familyOwnerId } = await resolveParentsAiScope(params.actor, params.requestedOwnerId);
  const category = String(params.category || "").trim().slice(0, 48);
  if (!category) throw new Error("Budget category is required.");
  const monthlyLimit = Math.max(0, Math.min(10_000_000, Number(params.monthlyLimit) || 0));
  const savingsTarget = Math.max(0, Math.min(100_000_000, Number(params.savingsTarget) || 0));
  const savingsCurrent = Math.max(0, Math.min(100_000_000, Number(params.savingsCurrent) || 0));
  const goalName = params.savingsGoalName ? String(params.savingsGoalName).trim().slice(0, 80) : null;
  const now = Date.now();

  await db
    .prepare(
      `INSERT INTO family_budgets (id, family_owner_id, category, monthly_limit, savings_goal_name, savings_target, savings_current, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(family_owner_id, category) DO UPDATE SET
         monthly_limit = excluded.monthly_limit,
         savings_goal_name = COALESCE(excluded.savings_goal_name, family_budgets.savings_goal_name),
         savings_target = CASE WHEN excluded.savings_target > 0 THEN excluded.savings_target ELSE family_budgets.savings_target END,
         savings_current = CASE WHEN excluded.savings_current > 0 THEN excluded.savings_current ELSE family_budgets.savings_current END,
         updated_at = excluded.updated_at`
    )
    .run(makeId("bud"), familyOwnerId, category, monthlyLimit, goalName, savingsTarget, savingsCurrent, now);
  return { ok: true };
}

export async function deleteFamilyBudget(actor: { id: string; role: "parent" | "guardian" }, budgetId: string) {
  const row = (await db.prepare("SELECT id, family_owner_id FROM family_budgets WHERE id = ?").get(budgetId)) as
    | { id: string; family_owner_id: string }
    | undefined;
  if (!row) throw new Error("Budget entry not found.");
  const { familyOwnerId } = await resolveParentsAiScope(actor, row.family_owner_id);
  if (familyOwnerId !== row.family_owner_id) throw new Error("Unauthorized.");
  await db.prepare("DELETE FROM family_budgets WHERE id = ?").run(budgetId);
  return { ok: true };
}

export async function updateFinancialAccessControl(params: {
  actor: { id: string; role: "parent" | "guardian" };
  childFinancialAccess?: boolean;
  guardianFinancialAccess?: boolean;
  requireGuardianAuth?: boolean;
}) {
  if (params.actor.role !== "parent") {
    throw new Error("Only the parent account holder can change financial visibility controls.");
  }
  const cur = await ensureFinancialAccessControl(params.actor.id);
  const childAcc = params.childFinancialAccess !== undefined ? (params.childFinancialAccess ? 1 : 0) : cur.child_financial_access;
  const guardAcc =
    params.guardianFinancialAccess !== undefined
      ? params.guardianFinancialAccess
        ? 1
        : 0
      : cur.guardian_financial_access;
  const reqAuth =
    params.requireGuardianAuth !== undefined ? (params.requireGuardianAuth ? 1 : 0) : cur.require_guardian_auth;

  await db
    .prepare(
      `UPDATE financial_access_controls
       SET child_financial_access = ?, guardian_financial_access = ?, require_guardian_auth = ?, updated_at = ?
       WHERE family_owner_id = ?`
    )
    .run(childAcc, guardAcc, reqAuth, Date.now(), params.actor.id);

  return ensureFinancialAccessControl(params.actor.id);
}

export async function getParentsAiState(
  actor: { id: string; role: "parent" | "guardian" },
  requestedOwnerId?: string
) {
  const { familyOwnerId, isOwner } = await resolveParentsAiScope(actor, requestedOwnerId);
  const accessRow = await ensureFinancialAccessControl(familyOwnerId);
  const accessControl = {
    childFinancialAccess: Boolean(accessRow.child_financial_access),
    guardianFinancialAccess: Boolean(accessRow.guardian_financial_access),
    requireGuardianAuth: Boolean(accessRow.require_guardian_auth),
  };

  // Guardians see financial details only when authorized by the parent
  const financialAuthorized = isOwner || accessControl.guardianFinancialAccess;

  const rawItems = (await db
    .prepare(
      `SELECT * FROM ai_tool_items
       WHERE family_owner_id = ?
       ${isOwner ? "" : "AND shared_with_guardian = 1"}
       ORDER BY created_at DESC LIMIT 80`
    )
    .all(familyOwnerId)) as Record<string, unknown>[];

  const now = Date.now();
  const items = rawItems.map((r) => {
    let metadata: Record<string, unknown> = {};
    try {
      metadata = JSON.parse(String(r.metadata_json || "{}"));
    } catch {
      metadata = {};
    }
    const dueAt = r.due_at ? Number(r.due_at) : null;
    const daysRemaining = dueAt ? Math.ceil((dueAt - now) / 86_400_000) : null;
    return {
      id: String(r.id),
      toolKey: String(r.tool_key),
      title: String(r.title),
      category: String(r.category),
      status: String(r.status),
      dueAt,
      daysRemaining,
      metadata,
      sharedWithGuardian: Boolean(r.shared_with_guardian),
      createdAt: Number(r.created_at),
    };
  });

  const rawConvs = (await db
    .prepare(
      `SELECT * FROM ai_tool_conversations
       WHERE family_owner_id = ?
       ORDER BY created_at DESC LIMIT 30`
    )
    .all(familyOwnerId)) as Record<string, unknown>[];

  const conversations = rawConvs.map((c) => {
    let parsed = { checklist: [] as string[], nextSteps: [] as string[] };
    try {
      parsed = JSON.parse(String(c.checklist_json || "{}"));
    } catch {
      parsed = { checklist: [], nextSteps: [] };
    }
    return {
      id: String(c.id),
      toolKey: String(c.tool_key),
      prompt: String(c.prompt),
      response: String(c.response),
      checklist: Array.isArray(parsed.checklist) ? parsed.checklist : [],
      nextSteps: Array.isArray(parsed.nextSteps) ? parsed.nextSteps : [],
      aiUsed: Boolean(c.ai_used),
      createdAt: Number(c.created_at),
    };
  });

  const rawConns = (await db
    .prepare("SELECT * FROM bank_connections WHERE family_owner_id = ? ORDER BY created_at DESC LIMIT 10")
    .all(familyOwnerId)) as Record<string, unknown>[];

  const activeConns = rawConns.filter((c) => c.consent_status === "active");
  const bankConnections = rawConns.map((c) => {
    let scopes: string[] = [];
    try {
      scopes = JSON.parse(String(c.scopes_json || "[]"));
    } catch {
      scopes = [];
    }
    return {
      id: String(c.id),
      institutionName: String(c.institution_name),
      accountMasked: String(c.account_masked),
      aaHandle: String(c.aa_handle),
      aaFramework: String(c.aa_framework),
      consentStatus: String(c.consent_status),
      isDemoSample: Boolean(c.is_demo_sample),
      scopes,
      consentExpiresAt: Number(c.consent_expires_at),
      balanceInr: financialAuthorized ? Number(c.balance_inr || 0) : null,
      createdAt: Number(c.created_at),
      revokedAt: c.revoked_at ? Number(c.revoked_at) : null,
    };
  });

  const rawTxs = financialAuthorized
    ? ((await db
        .prepare("SELECT * FROM bank_transactions WHERE family_owner_id = ? ORDER BY tx_date DESC LIMIT 50")
        .all(familyOwnerId)) as Record<string, unknown>[])
    : [];

  const transactions = rawTxs.map((t) => ({
    id: String(t.id),
    connectionId: String(t.connection_id),
    txDate: Number(t.tx_date),
    merchant: String(t.merchant),
    category: String(t.category),
    txType: String(t.tx_type) as "debit" | "credit",
    amount: Number(t.amount),
    isDemoSample: Boolean(t.is_demo_sample),
  }));

  const rawBudgets = (await db
    .prepare("SELECT * FROM family_budgets WHERE family_owner_id = ? ORDER BY category ASC")
    .all(familyOwnerId)) as Record<string, unknown>[];

  const categorySpend: Record<string, number> = {};
  let totalIncome = 0;
  let totalExpense = 0;
  for (const tx of transactions) {
    if (tx.txType === "credit") {
      totalIncome += tx.amount;
    } else {
      totalExpense += tx.amount;
      categorySpend[tx.category] = (categorySpend[tx.category] || 0) + tx.amount;
    }
  }

  const budgets = rawBudgets.map((b) => {
    const cat = String(b.category);
    return {
      id: String(b.id),
      category: cat,
      monthlyLimit: Number(b.monthly_limit || 0),
      spent: financialAuthorized ? categorySpend[cat] || 0 : null,
      savingsGoalName: b.savings_goal_name ? String(b.savings_goal_name) : null,
      savingsTarget: Number(b.savings_target || 0),
      savingsCurrent: financialAuthorized ? Number(b.savings_current || 0) : null,
    };
  });

  const totalBalance = financialAuthorized
    ? activeConns.reduce((acc, c) => acc + Number(c.balance_inr || 0), 0)
    : null;

  return {
    familyOwnerId,
    liveAaConfigured: false,
    financialAuthorized,
    accessControl,
    items,
    conversations,
    bankConnections,
    transactions,
    budgets,
    summary: {
      totalBalance,
      totalIncome: financialAuthorized ? totalIncome : null,
      totalExpense: financialAuthorized ? totalExpense : null,
      hasDemoConnection: activeConns.some((c) => Boolean(c.is_demo_sample)),
      activeConnectionsCount: activeConns.length,
      categorySpend: financialAuthorized ? categorySpend : {},
      expiringDocsCount: items.filter(
        (i) => i.toolKey === "document" && i.daysRemaining !== null && i.daysRemaining <= 30
      ).length,
    },
  };
}

export async function deleteParentsAiDataForOwner(ownerId: string): Promise<void> {
  await db.prepare("DELETE FROM ai_tool_items WHERE family_owner_id = ?").run(ownerId);
  await db.prepare("DELETE FROM ai_tool_conversations WHERE family_owner_id = ?").run(ownerId);
  await db.prepare("DELETE FROM bank_transactions WHERE family_owner_id = ?").run(ownerId);
  await db.prepare("DELETE FROM bank_connections WHERE family_owner_id = ?").run(ownerId);
  await db.prepare("DELETE FROM family_budgets WHERE family_owner_id = ?").run(ownerId);
  await db.prepare("DELETE FROM financial_access_controls WHERE family_owner_id = ?").run(ownerId);
}
