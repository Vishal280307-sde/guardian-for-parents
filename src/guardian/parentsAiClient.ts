// Client state synchronization and API actions for Parents AI 8 Tools & RBI Account Aggregator Bank Connectivity

import { S, R, apiJson } from './01_core_state_and_scam_detection';

export type ParentsAiToolKey =
  | 'parenting'
  | 'child_safety'
  | 'education'
  | 'health'
  | 'budget'
  | 'emergency'
  | 'calendar'
  | 'document';

export interface ParentsAiToolItem {
  id: string;
  toolKey: 'education' | 'health' | 'calendar' | 'document' | 'emergency_contact';
  title: string;
  category: string;
  status: string;
  dueAt: number | null;
  daysRemaining: number | null;
  metadata: Record<string, unknown>;
  sharedWithGuardian: boolean;
  createdAt: number;
}

export interface ParentsAiConversation {
  id: string;
  toolKey: ParentsAiToolKey;
  prompt: string;
  response: string;
  checklist: string[];
  nextSteps: string[];
  aiUsed: boolean;
  createdAt: number;
}

export interface BankConnectionRecord {
  id: string;
  institutionName: string;
  accountMasked: string;
  aaHandle: string;
  aaFramework: string;
  consentStatus: 'active' | 'revoked';
  isDemoSample: boolean;
  scopes: string[];
  consentExpiresAt: number;
  balanceInr: number | null;
  createdAt: number;
  revokedAt: number | null;
}

export interface BankTransactionRecord {
  id: string;
  connectionId: string;
  txDate: number;
  merchant: string;
  category: string;
  txType: 'debit' | 'credit';
  amount: number;
  isDemoSample: boolean;
}

export interface FamilyBudgetRecord {
  id: string;
  category: string;
  monthlyLimit: number;
  spent: number | null;
  savingsGoalName: string | null;
  savingsTarget: number;
  savingsCurrent: number | null;
}

export interface ParentsAiWorkspaceState {
  familyOwnerId: string;
  liveAaConfigured: boolean;
  financialAuthorized: boolean;
  accessControl: {
    childFinancialAccess: boolean;
    guardianFinancialAccess: boolean;
    requireGuardianAuth: boolean;
  };
  items: ParentsAiToolItem[];
  conversations: ParentsAiConversation[];
  bankConnections: BankConnectionRecord[];
  transactions: BankTransactionRecord[];
  budgets: FamilyBudgetRecord[];
  summary: {
    totalBalance: number | null;
    totalIncome: number | null;
    totalExpense: number | null;
    hasDemoConnection: boolean;
    activeConnectionsCount: number;
    categorySpend: Record<string, number>;
    expiringDocsCount: number;
  };
}

const RECENT_TOOLS_KEY = 'parents_ai_recent_tools';

export function loadRecentTools(): ParentsAiToolKey[] {
  try {
    const raw = window.localStorage.getItem(RECENT_TOOLS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.slice(0, 6);
    }
  } catch {
    // ignore storage limits
  }
  return ['parenting', 'child_safety', 'budget'];
}

export function trackRecentTool(toolKey: ParentsAiToolKey): void {
  const next = [toolKey, ...S.recentTools.filter((k) => k !== toolKey)].slice(0, 6);
  S.recentTools = next;
  try {
    window.localStorage.setItem(RECENT_TOOLS_KEY, JSON.stringify(next));
  } catch {
    // ignore
  }
}

export function openAiTool(toolKey: ParentsAiToolKey): void {
  S.activeAiTool = toolKey;
  S.tab = 'tools';
  S.mobileDrawerOpen = false;
  S.note = '';
  trackRecentTool(toolKey);
  R();
}

export async function loadParentsAiState(ownerId?: string): Promise<void> {
  if (!S.user) return;
  try {
    const target = ownerId || (S.user.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : '');
    const qs = target ? `?ownerId=${encodeURIComponent(target)}` : '';
    const data = await apiJson<ParentsAiWorkspaceState>(`/api/parents-ai/state${qs}`);
    S.parentsAi = data;
  } catch {
    // Preserve previous or null safely when unlinked
  }
}

export async function askAiToolPrompt(toolKey: ParentsAiToolKey, presetPrompt?: string): Promise<void> {
  const input = document.getElementById(`pai-prompt-${toolKey}`) as HTMLTextAreaElement | HTMLInputElement | null;
  const prompt = (presetPrompt !== undefined ? presetPrompt : input ? input.value : '').trim();
  if (!prompt) {
    S.note = 'Enter a question or scenario to get tailored Parents AI guidance.';
    R();
    return;
  }
  S.busy.parentsAi = true;
  S.note = '';
  trackRecentTool(toolKey);
  R();
  try {
    const ownerId = S.user?.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : undefined;
    await apiJson('/api/parents-ai/tools/ask', {
      method: 'POST',
      body: JSON.stringify({ toolKey, prompt, ownerId, lang: S.lang }),
    });
    if (input) input.value = '';
    await loadParentsAiState(ownerId);
    S.note = 'Parents AI response ready.';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Parents AI request failed.';
  } finally {
    S.busy.parentsAi = false;
    R();
  }
}

export async function addToolWorkspaceItem(toolKey: ParentsAiToolItem['toolKey']): Promise<void> {
  const titleEl = document.getElementById(`pai-item-title-${toolKey}`) as HTMLInputElement | null;
  const catEl = document.getElementById(`pai-item-cat-${toolKey}`) as HTMLInputElement | HTMLSelectElement | null;
  const dueEl = document.getElementById(`pai-item-due-${toolKey}`) as HTMLInputElement | null;
  const metaEl = document.getElementById(`pai-item-meta-${toolKey}`) as HTMLInputElement | null;

  const title = (titleEl?.value || '').trim();
  if (!title) {
    S.note = 'Please enter a title or contact name.';
    R();
    return;
  }

  let dueAt: number | null = null;
  if (dueEl?.value) {
    const ms = new Date(dueEl.value).getTime();
    if (Number.isFinite(ms)) dueAt = ms;
  }

  const metadata: Record<string, unknown> = {};
  if (metaEl?.value.trim()) {
    metadata.detail = metaEl.value.trim();
  }

  S.busy.parentsAi = true;
  R();
  try {
    const ownerId = S.user?.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : undefined;
    await apiJson('/api/parents-ai/tools/items', {
      method: 'POST',
      body: JSON.stringify({
        toolKey,
        title,
        category: catEl?.value || 'general',
        dueAt,
        metadata,
        ownerId,
      }),
    });
    if (titleEl) titleEl.value = '';
    if (metaEl) metaEl.value = '';
    await loadParentsAiState(ownerId);
    S.note = 'Saved to family workspace.';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save workspace item.';
  } finally {
    S.busy.parentsAi = false;
    R();
  }
}

export async function toggleToolWorkspaceItem(itemId: string, nextStatus: string): Promise<void> {
  try {
    await apiJson(`/api/parents-ai/tools/items/${encodeURIComponent(itemId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: nextStatus }),
    });
    await loadParentsAiState();
    R();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update item.';
    R();
  }
}

export async function removeToolWorkspaceItem(itemId: string): Promise<void> {
  try {
    await apiJson(`/api/parents-ai/tools/items/${encodeURIComponent(itemId)}`, {
      method: 'DELETE',
    });
    await loadParentsAiState();
    R();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not delete item.';
    R();
  }
}

export async function connectBankAa(mode: 'demo_sample' | 'live'): Promise<void> {
  const instEl = document.getElementById('pai-bank-inst') as HTMLSelectElement | HTMLInputElement | null;
  const handleEl = document.getElementById('pai-bank-handle') as HTMLInputElement | null;
  const daysEl = document.getElementById('pai-bank-days') as HTMLSelectElement | null;

  S.busy.parentsAi = true;
  S.note = '';
  R();
  try {
    await apiJson('/api/parents-ai/bank/connect-demo', {
      method: 'POST',
      body: JSON.stringify({
        mode,
        institutionName: instEl?.value || 'State Bank of India (Sample FIP)',
        aaHandle: handleEl?.value || 'family@finvu.demo',
        consentDays: Number(daysEl?.value || 90),
        scopes: ['PROFILE (Read-Only)', 'SUMMARY (Read-Only)', 'TRANSACTIONS (Read-Only)'],
      }),
    });
    await loadParentsAiState();
    S.note =
      'Connected RBI Account Aggregator Sample Demo profile (read-only consent, zero passwords or PINs collected).';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not connect Account Aggregator.';
  } finally {
    S.busy.parentsAi = false;
    R();
  }
}

export async function revokeBankConsent(connId: string): Promise<void> {
  S.busy.parentsAi = true;
  R();
  try {
    await apiJson(`/api/parents-ai/bank/revoke/${encodeURIComponent(connId)}`, {
      method: 'POST',
    });
    await loadParentsAiState();
    S.note = 'RBI Account Aggregator consent revoked and demo transactions cleared.';
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not revoke bank consent.';
  } finally {
    S.busy.parentsAi = false;
    R();
  }
}

export async function saveFamilyBudget(): Promise<void> {
  const catEl = document.getElementById('pai-bud-cat') as HTMLSelectElement | HTMLInputElement | null;
  const limEl = document.getElementById('pai-bud-limit') as HTMLInputElement | null;
  const goalNameEl = document.getElementById('pai-bud-goal') as HTMLInputElement | null;
  const goalTargetEl = document.getElementById('pai-bud-target') as HTMLInputElement | null;
  const goalCurEl = document.getElementById('pai-bud-cur') as HTMLInputElement | null;

  const category = (catEl?.value || '').trim();
  if (!category) {
    S.note = 'Select or enter a budget category.';
    R();
    return;
  }

  S.busy.parentsAi = true;
  R();
  try {
    const ownerId = S.user?.role === 'guardian' && S.selectedFamilyOwnerId !== 'all' ? S.selectedFamilyOwnerId : undefined;
    await apiJson('/api/parents-ai/budgets', {
      method: 'POST',
      body: JSON.stringify({
        category,
        monthlyLimit: Number(limEl?.value || 0),
        savingsGoalName: goalNameEl?.value.trim() || undefined,
        savingsTarget: Number(goalTargetEl?.value || 0),
        savingsCurrent: Number(goalCurEl?.value || 0),
        ownerId,
      }),
    });
    await loadParentsAiState(ownerId);
    S.note = `Saved budget settings for ${category}.`;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save budget.';
  } finally {
    S.busy.parentsAi = false;
    R();
  }
}

export async function removeBudget(budgetId: string): Promise<void> {
  try {
    await apiJson(`/api/parents-ai/budgets/${encodeURIComponent(budgetId)}`, {
      method: 'DELETE',
    });
    await loadParentsAiState();
    R();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not remove budget.';
    R();
  }
}

export async function updateFinAccess(patch: {
  childFinancialAccess?: boolean;
  guardianFinancialAccess?: boolean;
  requireGuardianAuth?: boolean;
}): Promise<void> {
  try {
    await apiJson('/api/parents-ai/bank/access-control', {
      method: 'PUT',
      body: JSON.stringify(patch),
    });
    await loadParentsAiState();
    S.note = 'Updated family financial privacy & guardian authorization controls.';
    R();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update financial access controls.';
    R();
  }
}
