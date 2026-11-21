// Luxury Parents AI UI Views: 8 Functional AI Tools, Netflix Showcase, RBI AA Bank Connectivity, Control Center & Global Search

import { S, esc, inr } from './01_core_state_and_scam_detection';
import {
  uiIcon,
  uiBadge,
  uiSourceBadge,
  uiCard,
  uiStatCard,
  uiAlert,
  uiStateBox,
  type IconName,
} from './ui';
import type { ParentsAiToolKey, ParentsAiToolItem } from './parentsAiClient';

export interface AiToolMeta {
  key: ParentsAiToolKey;
  title: string;
  tagline: string;
  badge: string;
  icon: IconName;
  placeholder: string;
  presets: string[];
  workspaceKind?: ParentsAiToolItem['toolKey'];
}

export const AI_TOOLS_META: AiToolMeta[] = [
  {
    key: 'parenting',
    title: 'AI Parenting Assistant',
    tagline: 'Calm guidance on teen screen habits, elder digital trust, and everyday family dialogue.',
    badge: 'Live Gemini AI',
    icon: 'spark',
    placeholder: 'Ask about screen boundaries, teen online safety, or supporting aging parents…',
    presets: [
      'How do I set healthy evening screen limits without family conflict?',
      'Help my parents recognize WhatsApp courier and KYC scams gently.',
    ],
  },
  {
    key: 'child_safety',
    title: 'Child & Safety Monitor',
    tagline: 'Unified scam defense, cyberbullying prevention, and consent-first device awareness.',
    badge: 'Security Core',
    icon: 'shield',
    placeholder: 'Ask about suspicious links, gaming chat risks, or stranger calls…',
    presets: [
      'Build a 5-point digital safety checklist for our family phones.',
      'What signs indicate a relative is being pressured on an unknown call?',
    ],
  },
  {
    key: 'education',
    title: 'Homework & Study Helper',
    tagline: 'Step-by-step concept coaching plus a tracked family homework & exam planner.',
    badge: 'Study Planner',
    icon: 'book',
    placeholder: 'Ask to explain a math/science concept or plan weekly study blocks…',
    presets: [
      'Break down quadratic equations into 3 clear steps for Grade 9.',
      'Create a balanced 5-day revision schedule before science exams.',
    ],
    workspaceKind: 'education',
  },
  {
    key: 'health',
    title: 'Health & Wellness Advisor',
    tagline: 'Daily wellness routines and synced family medication & checkup reminders.',
    badge: 'Wellness',
    icon: 'heart',
    placeholder: 'Ask about sleep hygiene, hydration habits, or senior walking routines…',
    presets: [
      'Suggest a gentle morning mobility & hydration routine for seniors.',
      'How can our family organize weekly blood pressure & medicine reminders?',
    ],
    workspaceKind: 'health',
  },
  {
    key: 'budget',
    title: 'Family Budget Planner',
    tagline: '50/30/20 planning, household expense analysis, and linked RBI AA insights.',
    badge: 'Fintech AI',
    icon: 'wallet',
    placeholder: 'Ask how to optimize groceries, school fees, or emergency fund targets…',
    presets: [
      'Design a monthly ₹65,000 Indian household budget with a ₹12,000 savings buffer.',
      'How do we cut recurring subscription & utility waste this month?',
    ],
  },
  {
    key: 'emergency',
    title: 'Emergency Help & Alerts',
    tagline: '1-tap admin revocation + cybercrime.gov.in redirection and trusted ICE contacts.',
    badge: 'Critical Action',
    icon: 'life-buoy',
    placeholder: 'Describe an urgent fraud or safety situation for immediate step-by-step action…',
    presets: [
      'Someone shared an OTP on a fake bank call — what are our exact first 5 steps?',
      'Checklist to lock UPI, notify the bank, and file on cybercrime.gov.in (1930).',
    ],
    workspaceKind: 'emergency_contact',
  },
  {
    key: 'calendar',
    title: 'Smart Family Calendar',
    tagline: 'Track school PTMs, doctor appointments, bill renewals, and shared routines.',
    badge: 'Shared Schedule',
    icon: 'calendar',
    placeholder: 'Ask to organize school pick-ups, clinic visits, or weekend family prep…',
    presets: [
      'Organize a stress-free Sunday family reset and school week checklist.',
      'Plan reminder intervals for quarterly medical checkups and utility bills.',
    ],
    workspaceKind: 'calendar',
  },
  {
    key: 'document',
    title: 'Document & Record Vault',
    tagline: 'Track passports, insurance policies, IDs, and school records with expiry countdowns.',
    badge: 'Expiry Alerts',
    icon: 'file-text',
    placeholder: 'Ask which documents to keep ready for school admission or travel renewals…',
    presets: [
      'List essential family documents and renewal timelines to audit every year.',
      'What copies should we store for senior health insurance claims?',
    ],
    workspaceKind: 'document',
  },
];

function getToolMeta(key: ParentsAiToolKey): AiToolMeta {
  return AI_TOOLS_META.find((m) => m.key === key) || AI_TOOLS_META[0];
}

function formatDateInputValue(ts: number | null): string {
  if (!ts) return '';
  try {
    return new Date(ts).toISOString().slice(0, 10);
  } catch {
    return '';
  }
}

export function renderLandingFeaturedShelf(): string {
  return `<section style="margin:22px 0">
    <div class="netflix-rail-head">
      <div>
        <span class="t-label" style="margin:0;color:var(--gold)">PARENTS AI INTELLIGENCE SUITE</span>
        <h2 class="t-section" style="margin:2px 0 0">Featured Family &amp; Security Experiences</h2>
      </div>
      <div class="row" style="gap:6px">
        <button type="button" class="s" style="min-height:34px;padding:4px 10px" onclick="scrollSwipeStrip('landing-netflix-rail',-1)" aria-label="Scroll featured cards left">${uiIcon('chevron-left', 14)}</button>
        <button type="button" class="s" style="min-height:34px;padding:4px 10px" onclick="scrollSwipeStrip('landing-netflix-rail',1)" aria-label="Scroll featured cards right">${uiIcon('chevron-right', 14)}</button>
      </div>
    </div>
    <div id="landing-netflix-rail" class="netflix-rail">
      ${AI_TOOLS_META.map(
        (m, idx) => `<article class="netflix-tile tilt-card" onclick="S.draftLoginUser='';document.getElementById('lu')?.focus()">
          <div>
            <div class="row" style="justify-content:space-between;margin-bottom:10px">
              <span class="tool-icon-chip">${uiIcon(m.icon, 18)}</span>
              <span class="pill NEUTRAL" style="background:rgba(212,175,55,0.16);color:#F5E0AE;border-color:rgba(212,175,55,0.38)">0${idx + 1} · ${esc(m.badge)}</span>
            </div>
            <h3 class="t-card" style="color:#FAF6EE;margin:0">${esc(m.title)}</h3>
            <p>${esc(m.tagline)}</p>
          </div>
          <div class="row" style="justify-content:space-between;font-size:12px;color:#E7C98F">
            <span>Sign in to launch</span>
            ${uiIcon('arrow-right', 14)}
          </div>
        </article>`
      ).join('')}
      <article class="netflix-tile tilt-card" onclick="document.getElementById('lu')?.focus()">
        <div>
          <div class="row" style="justify-content:space-between;margin-bottom:10px">
            <span class="tool-icon-chip">${uiIcon('building', 18)}</span>
            <span class="pill LOW">RBI AA Ready</span>
          </div>
          <h3 class="t-card" style="color:#FAF6EE;margin:0">Connect Your Bank</h3>
          <p>Consent-first Account Aggregator financial clarity with Sample Demo Mode &amp; guardian privacy controls.</p>
        </div>
        <div class="row" style="justify-content:space-between;font-size:12px;color:#E7C98F">
          <span>Zero PINs or Passwords</span>
          ${uiIcon('arrow-right', 14)}
        </div>
      </article>
    </div>
  </section>`;
}

export function renderDashboardRecentlyUsed(): string {
  const recents = (S.recentTools.length ? S.recentTools : (['parenting', 'child_safety', 'budget'] as ParentsAiToolKey[]))
    .slice(0, 4)
    .map(getToolMeta);

  return `<section style="margin:14px 0">
    <div class="netflix-rail-head" style="margin-top:8px">
      <div>
        <span class="t-label" style="margin:0;color:var(--gold)">PERSONALIZED WORKSPACE</span>
        <h2 class="t-section" style="margin:2px 0 0">Recently Used &amp; Featured AI Tools</h2>
      </div>
      <button type="button" class="gold" style="min-height:36px;padding:6px 14px;font-size:13px" onclick="switchTab('tools')">Explore All 8 Tools ${uiIcon('arrow-right', 14)}</button>
    </div>
    <div class="netflix-rail">
      ${recents
        .map(
          (m) => `<div class="netflix-tile tilt-card" onclick="openAiTool('${m.key}')">
            <div>
              <div class="row" style="justify-content:space-between;margin-bottom:10px">
                <span class="tool-icon-chip">${uiIcon(m.icon, 18)}</span>
                <span class="pill NEUTRAL" style="background:rgba(212,175,55,0.16);color:#F5E0AE;border-color:rgba(212,175,55,0.35)">${esc(m.badge)}</span>
              </div>
              <h3 class="t-card" style="color:#FAF6EE;margin:0">${esc(m.title)}</h3>
              <p>${esc(m.tagline)}</p>
            </div>
            <div class="row" style="justify-content:space-between;font-size:12px;color:#E7C98F">
              <span>Open workspace</span>
              ${uiIcon('arrow-right', 14)}
            </div>
          </div>`
        )
        .join('')}
    </div>
  </section>`;
}

export function renderDashboardFinanceSnapshot(): string {
  const pai = S.parentsAi;
  const sum = pai?.summary;
  const expiring = sum?.expiringDocsCount || 0;
  const activeConns = sum?.activeConnectionsCount || 0;

  return `<div class="g-2">
    <section class="bank-card-visual card-anim tilt-card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <div class="row" style="gap:8px">
          ${uiIcon('building', 18)}
          <b>Family Financial Overview</b>
        </div>
        ${sum?.hasDemoConnection ? '<span class="pill MEDIUM">Sample Demo Mode</span>' : '<span class="pill NEUTRAL">RBI AA Framework</span>'}
      </div>
      ${
        activeConns > 0 && sum && sum.totalBalance !== null
          ? `<div style="font-size:28px;font-weight:800;letter-spacing:-0.02em;margin:4px 0" class="num">${inr(sum.totalBalance)}</div>
             <p class="mut" style="margin:0 0 12px;font-size:13px">Monthly Inflow <b class="num" style="color:#6EE7B7">${inr(sum.totalIncome || 0)}</b> · Monthly Outflow <b class="num" style="color:#FDE68A">${inr(sum.totalExpense || 0)}</b></p>`
          : `<p class="mut" style="margin:0 0 12px">Connect your family bank cleanly via RBI Account Aggregator Sample Demo Mode to view category spending, savings targets, and 3D analytics — with zero passwords or PINs ever stored.</p>`
      }
      <div class="row">
        <button type="button" class="gold" style="min-height:38px;padding:7px 14px" onclick="switchTab('bank')">${activeConns > 0 ? 'Open Financial Center' : 'Connect Your Bank'} ${uiIcon('arrow-right', 14)}</button>
        <button type="button" class="s" style="min-height:38px;padding:7px 14px;background:rgba(255,255,255,0.08);color:#FAF6EE;border-color:rgba(212,175,55,0.32)" onclick="openAiTool('budget')">Budget AI</button>
      </div>
    </section>

    <section class="card card-anim tilt-card">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div>
          <h2 class="t-section" style="margin:0">${uiIcon('spark', 18)} Personalized Parents AI Insights</h2>
          <p class="mut" style="margin:2px 0 0">Unified reminders across education, health, documents, and family control</p>
        </div>
        ${uiSourceBadge('actual')}
      </div>
      <ul style="margin:6px 0 12px">
        <li><b>${(pai?.items || []).filter((i) => i.status === 'pending').length}</b> active tasks/reminders across Homework, Health &amp; Calendar</li>
        <li><b>${expiring}</b> document(s) due or expiring within 30 days</li>
        <li><b>${(pai?.conversations || []).length}</b> saved AI coaching &amp; guidance sessions</li>
      </ul>
      <div class="row">
        <button type="button" class="s" onclick="openAiTool('parenting')">Ask Parenting AI</button>
        <button type="button" class="s" onclick="switchTab('control')">Open Control Center</button>
      </div>
    </section>
  </div>`;
}

export function renderSearchResultsOverlay(): string {
  const q = S.searchQuery.trim().toLowerCase();
  if (!q) return '';

  const matchedTools = AI_TOOLS_META.filter(
    (m) => m.title.toLowerCase().includes(q) || m.tagline.toLowerCase().includes(q) || m.badge.toLowerCase().includes(q)
  );
  const items = S.parentsAi?.items || [];
  const matchedItems = items.filter(
    (it) => it.title.toLowerCase().includes(q) || it.category.toLowerCase().includes(q)
  );
  const txs = S.parentsAi?.transactions || [];
  const matchedTxs = txs.filter(
    (tx) => tx.merchant.toLowerCase().includes(q) || tx.category.toLowerCase().includes(q)
  );
  const alerts =
    S.user?.role === 'guardian' ? S.linkedGsiOverview?.incidents || [] : S.gsi?.recentIncidents || [];
  const matchedAlerts = alerts.filter(
    (inc) =>
      inc.incidentCategory.toLowerCase().includes(q) ||
      inc.reasoningSummary.toLowerCase().includes(q) ||
      inc.alertLevel.toLowerCase().includes(q)
  );

  return `<section class="card card-anim" style="border-color:var(--gold)">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <div>
        <h2 class="t-section" style="margin:0">${uiIcon('search', 17)} Search Results for “${esc(S.searchQuery.trim())}”</h2>
        <p class="mut" style="margin:2px 0 0;font-size:13px">${matchedTools.length} tools · ${matchedItems.length} family items · ${matchedTxs.length} transactions · ${matchedAlerts.length} security alerts</p>
      </div>
      <button type="button" class="s" onclick="setGlobalSearch('')">Clear search</button>
    </div>
    ${
      matchedTools.length
        ? `<div class="row" style="margin-bottom:10px">${matchedTools
            .map(
              (m) =>
                `<button type="button" class="gold" style="min-height:36px;padding:6px 12px;font-size:13px" onclick="setGlobalSearch('');openAiTool('${m.key}')">${uiIcon(m.icon, 14)} ${esc(m.title)}</button>`
            )
            .join('')}</div>`
        : ''
    }
    ${
      matchedItems.length
        ? `<div class="warn"><b>Saved Family Items:</b><ul style="margin:6px 0 0">${matchedItems
            .slice(0, 6)
            .map(
              (it) =>
                `<li><a href="javascript:void(0)" onclick="setGlobalSearch('');openAiTool('${it.toolKey === 'emergency_contact' ? 'emergency' : it.toolKey}')"><b>${esc(it.title)}</b></a> (${esc(it.category)}) · ${esc(it.status)}</li>`
            )
            .join('')}</ul></div>`
        : ''
    }
    ${
      matchedTxs.length
        ? `<div class="warn"><b>Financial Transactions:</b><ul style="margin:6px 0 0">${matchedTxs
            .slice(0, 6)
            .map(
              (tx) =>
                `<li><a href="javascript:void(0)" onclick="setGlobalSearch('');switchTab('bank')"><b>${esc(tx.merchant)}</b></a> · ${esc(tx.category)} · <b class="num">${inr(tx.amount)}</b></li>`
            )
            .join('')}</ul></div>`
        : ''
    }
    ${
      matchedAlerts.length
        ? `<div class="warn"><b>Security Alerts:</b><ul style="margin:6px 0 0">${matchedAlerts
            .slice(0, 5)
            .map(
              (inc) =>
                `<li><a href="javascript:void(0)" onclick="setGlobalSearch('');switchTab('${S.user?.role === 'guardian' ? 'act' : 'alerts'}')"><b>${esc(inc.incidentCategory)}</b></a> · ${esc(inc.alertLevel)} — ${esc(inc.reasoningSummary.slice(0, 72))}</li>`
            )
            .join('')}</ul></div>`
        : ''
    }
    ${
      !matchedTools.length && !matchedItems.length && !matchedTxs.length && !matchedAlerts.length
        ? '<p class="mut" style="margin:0">No matching AI tools, family plans, transactions, or alerts found.</p>'
        : ''
    }
  </section>`;
}

export function renderAiToolsTab(): string {
  const activeKey: ParentsAiToolKey = S.activeAiTool || 'parenting';
  const activeMeta = getToolMeta(activeKey);
  const pai = S.parentsAi;
  const convos = (pai?.conversations || []).filter((c) => c.toolKey === activeKey);
  const items = (pai?.items || []).filter((it) =>
    activeMeta.workspaceKind ? it.toolKey === activeMeta.workspaceKind : false
  );
  const isGuardian = S.user?.role === 'guardian';

  let workspacePanel = '';
  if (activeMeta.workspaceKind) {
    const kind = activeMeta.workspaceKind;
    const catOptions =
      kind === 'education'
        ? ['Mathematics', 'Science', 'Languages', 'Exam Prep', 'Reading']
        : kind === 'health'
          ? ['Medication', 'Doctor Visit', 'Vaccination', 'Daily Wellness']
          : kind === 'calendar'
            ? ['School & PTM', 'Medical', 'Bill & Renewal', 'Family Time']
            : kind === 'document'
              ? ['Passport & ID', 'Insurance Policy', 'Medical Record', 'Academic Certificate']
              : ['Primary Family Contact', 'Local Doctor', 'School Office', 'Bank Fraud Desk'];

    const titleLabel =
      kind === 'education'
        ? 'Homework or exam task'
        : kind === 'health'
          ? 'Medicine or checkup reminder'
          : kind === 'calendar'
            ? 'Family event title'
            : kind === 'document'
              ? 'Document title'
              : 'Emergency contact name';

    const showDate = kind !== 'emergency_contact';
    const dueLabel = kind === 'document' ? 'Expiry / renewal date' : 'Due / schedule date';

    workspacePanel = `<div class="card card-anim">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div>
          <h3 class="t-section" style="margin:0">${esc(activeMeta.title)} — Shared Family Tracker</h3>
          <p class="mut" style="margin:2px 0 0">Stored securely in SQLite and visible across authorized parent &amp; guardian sessions.</p>
        </div>
        ${uiSourceBadge('actual')}
      </div>
      <div class="g" style="gap:10px">
        <div>
          <label for="pai-item-title-${kind}">${titleLabel}</label>
          <input id="pai-item-title-${kind}" placeholder="Enter title…">
        </div>
        <div>
          <label for="pai-item-cat-${kind}">Category</label>
          <select id="pai-item-cat-${kind}">
            ${catOptions.map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join('')}
          </select>
        </div>
        ${
          showDate
            ? `<div>
                 <label for="pai-item-due-${kind}">${dueLabel}</label>
                 <input id="pai-item-due-${kind}" type="date">
               </div>`
            : ''
        }
        <div>
          <label for="pai-item-meta-${kind}">${kind === 'emergency_contact' ? 'Phone / helpline number' : 'Notes / details (optional)'}</label>
          <input id="pai-item-meta-${kind}" placeholder="${kind === 'emergency_contact' ? 'e.g. +91 98XXXXXX10 or 1930' : 'Brief reminder note'}">
        </div>
      </div>
      <div class="row">
        <button type="button" class="gold" onclick="addToolWorkspaceItem('${kind}')" ${S.busy.parentsAi ? 'disabled' : ''}>${uiIcon('plus', 15)} Save to Family Tracker</button>
        ${
          kind === 'emergency_contact' && !isGuardian
            ? `<button type="button" class="r" onclick="emergencyHelpAction()" ${S.busy.emergency ? 'disabled' : ''}>${uiIcon('shield', 15)} Trigger Emergency Help (Revoke Admin + Cybercrime Portal)</button>`
            : ''
        }
      </div>
      <hr class="divider">
      ${
        items.length
          ? items
              .map((it) => {
                const done = it.status === 'completed';
                const detail = typeof it.metadata?.detail === 'string' ? it.metadata.detail : '';
                let expiryBadge = '';
                if (it.daysRemaining !== null) {
                  if (it.daysRemaining < 0) {
                    expiryBadge = uiBadge(`Expired ${Math.abs(it.daysRemaining)}d ago`, 'HIGH');
                  } else if (it.daysRemaining <= 30) {
                    expiryBadge = uiBadge(`Due in ${it.daysRemaining}d`, 'MEDIUM');
                  } else {
                    expiryBadge = uiBadge(`${it.daysRemaining}d left`, 'LOW');
                  }
                }
                return `<div class="qr-history-row">
                  <div>
                    <b style="${done ? 'text-decoration:line-through;opacity:0.65' : ''}">${esc(it.title)}</b>
                    <div class="mut" style="font-size:12.5px">${esc(it.category)}${detail ? ' · ' + esc(detail) : ''}${it.dueAt ? ' · ' + formatDateInputValue(it.dueAt) : ''}</div>
                  </div>
                  <div class="row">
                    ${expiryBadge}
                    ${uiBadge(done ? 'Done' : 'Active', done ? 'LOW' : 'NEUTRAL')}
                    <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="toggleToolWorkspaceItem('${esc(it.id)}','${done ? 'pending' : 'completed'}')">${done ? 'Reopen' : 'Complete'}</button>
                    <button type="button" class="s" style="min-height:32px;padding:4px 10px" onclick="removeToolWorkspaceItem('${esc(it.id)}')" aria-label="Delete item">${uiIcon('trash', 14)}</button>
                  </div>
                </div>`;
              })
              .join('')
          : `<p class="mut" style="margin:0">No saved items yet in ${esc(activeMeta.title)}. Add your first item above.</p>`
      }
    </div>`;
  }

  let specialBridgeCard = '';
  if (activeKey === 'child_safety') {
    specialBridgeCard = `<div class="card card-anim">
      <h3 class="t-card">Live Family Protection Modules</h3>
      <p class="mut" style="margin:4px 0 10px">Jump directly into real-time Guardian safety workflows connected to this tool:</p>
      <div class="row">
        ${
          !isGuardian
            ? `<button type="button" class="s" onclick="switchTab('scam')">Scam &amp; Link Checker</button>
               <button type="button" class="s" onclick="switchTab('call')">AI Call Watcher</button>
               <button type="button" class="s" onclick="switchTab('qr')">QR Intelligence</button>
               <button type="button" class="s" onclick="switchTab('alerts')">Safety Alerts</button>`
            : `<button type="button" class="s" onclick="switchTab('act')">Family Security Activity</button>
               <button type="button" class="s" onclick="switchTab('req')">Approval Requests</button>`
        }
      </div>
    </div>`;
  } else if (activeKey === 'budget') {
    specialBridgeCard = `<div class="card card-anim">
      <div class="row" style="justify-content:space-between">
        <div>
          <h3 class="t-card" style="margin:0">Connected Bank &amp; Household Budgets</h3>
          <p class="mut" style="margin:4px 0 0">Manage RBI Account Aggregator demo insights, 3D category charts, and monthly limits.</p>
        </div>
        <button type="button" class="gold" onclick="switchTab('bank')">Open Connect Your Bank ${uiIcon('arrow-right', 14)}</button>
      </div>
    </div>`;
  } else if (activeKey === 'emergency') {
    specialBridgeCard = `<div class="card card-anim">
      <div class="row" style="justify-content:space-between">
        <div>
          <h3 class="t-card" style="margin:0">Immediate Fraud &amp; Cybercrime Action</h3>
          <p class="mut" style="margin:4px 0 0">India National Cyber Crime Helpline: <b>1930</b> · Emergency: <b>112</b> · Portal: <b>cybercrime.gov.in</b></p>
        </div>
        ${
          !isGuardian
            ? `<button type="button" class="r" onclick="emergencyHelpAction()" ${S.busy.emergency ? 'disabled' : ''}>${uiIcon('shield', 15)} Emergency Help (Revoke + Open Portal)</button>`
            : ''
        }
      </div>
    </div>`;
  }

  return `<section class="cyber-overview-card card-anim">
      <div class="cyber-overview-grid">
        <div>
          <span class="pill LOW" style="margin-bottom:8px">Parents AI Suite · 8 Integrated Tools</span>
          <h1 class="t-page" style="margin:0;color:#FAF6EE">AI Tools Workspace</h1>
          <p class="mut" style="margin:6px 0 0;color:#C9BFA9">Dedicated AI guidance and real shared family trackers for parenting, safety, study, wellness, budgeting, emergency preparedness, calendars, and documents.</p>
        </div>
        <div id="guardian-3d-orb" class="stage-3d-shell" aria-label="Interactive 3D Golden AI Orb"></div>
      </div>
    </section>

    <div class="tool-grid">
      ${AI_TOOLS_META.map(
        (m) => `<div class="tool-card tilt-card ${m.key === activeKey ? 'active' : ''}" onclick="openAiTool('${m.key}')" role="button" tabindex="0">
          <div>
            <div class="row" style="justify-content:space-between;margin-bottom:8px">
              <span class="tool-icon-chip">${uiIcon(m.icon, 18)}</span>
              ${uiBadge(m.badge, m.key === activeKey ? 'LOW' : 'NEUTRAL')}
            </div>
            <h3 class="t-card" style="margin:0">${esc(m.title)}</h3>
            <p class="mut" style="margin:4px 0 0;font-size:13px">${esc(m.tagline)}</p>
          </div>
          <div class="row" style="justify-content:space-between;font-size:12.5px;color:var(--gold)">
            <span>${m.key === activeKey ? 'Active Workspace' : 'Open Tool'}</span>
            ${uiIcon('arrow-right', 14)}
          </div>
        </div>`
      ).join('')}
    </div>

    <div class="card card-anim" style="border-color:rgba(212,175,55,0.42)">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div class="row" style="gap:10px">
          <span class="tool-icon-chip">${uiIcon(activeMeta.icon, 18)}</span>
          <div>
            <h2 class="t-section" style="margin:0">${esc(activeMeta.title)}</h2>
            <p class="mut" style="margin:2px 0 0;font-size:13px">${esc(activeMeta.tagline)}</p>
          </div>
        </div>
        ${uiSourceBadge('actual')}
      </div>
      ${
        activeKey === 'health'
          ? uiAlert('Health & Wellness Advisor shares general educational routines only and does not replace qualified medical advice or emergency care.', { tone: 'warn' })
          : ''
      }
      <label for="pai-prompt-${activeKey}">Ask ${esc(activeMeta.title)}</label>
      <textarea id="pai-prompt-${activeKey}" rows="2" placeholder="${esc(activeMeta.placeholder)}"></textarea>
      <div class="row" style="margin-bottom:10px">
        <button type="button" class="gold" onclick="askAiToolPrompt('${activeKey}')" ${S.busy.parentsAi ? 'disabled' : ''}>${S.busy.parentsAi ? 'Thinking…' : 'Ask Parents AI'} ${uiIcon('spark', 15)}</button>
        ${activeMeta.presets
          .map(
            (pr, i) =>
              `<button type="button" class="s" style="font-size:12.5px" onclick="askAiToolPrompt('${activeKey}', ${JSON.stringify(pr).replace(/"/g, '&quot;')})" ${S.busy.parentsAi ? 'disabled' : ''}>Try prompt ${i + 1}</button>`
          )
          .join('')}
      </div>
      ${
        convos.length
          ? convos
              .slice(0, 4)
              .map(
                (cv) => `<div class="warn" style="margin-top:10px">
                  <div class="row" style="justify-content:space-between;margin-bottom:4px">
                    <b>Prompt: ${esc(cv.prompt)}</b>
                    <span class="${cv.aiUsed ? 'badge-live' : 'badge-fb'}">${cv.aiUsed ? 'LIVE GEMINI AI' : 'GUIDED ASSISTANT'}</span>
                  </div>
                  <p style="margin:4px 0 8px">${esc(cv.response)}</p>
                  ${
                    cv.checklist.length
                      ? `<b>Action Checklist</b><ul>${cv.checklist.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>`
                      : ''
                  }
                  ${
                    cv.nextSteps.length
                      ? `<p class="mut" style="margin:6px 0 0;font-size:12.5px"><b>Next steps:</b> ${esc(cv.nextSteps.join(' · '))}</p>`
                      : ''
                  }
                </div>`
              )
              .join('')
          : '<p class="mut" style="margin:6px 0 0">Ask a question or click one of the starter prompts above to generate an actionable checklist.</p>'
      }
    </div>

    ${workspacePanel}
    ${specialBridgeCard}`;
}

export function renderBankTab(): string {
  const pai = S.parentsAi;
  const activeConns = (pai?.bankConnections || []).filter((c) => c.consentStatus === 'active');
  const sum = pai?.summary;
  const isGuardian = S.user?.role === 'guardian';
  const authorized = pai ? pai.financialAuthorized : !isGuardian;

  const transactions = (pai?.transactions || []).filter((tx) => {
    const q = S.bankSearchQuery.trim().toLowerCase();
    const matchQ = !q || tx.merchant.toLowerCase().includes(q) || tx.category.toLowerCase().includes(q);
    const matchCat = S.bankCategoryFilter === 'all' || tx.category === S.bankCategoryFilter;
    return matchQ && matchCat;
  });

  const allCategories = Array.from(new Set((pai?.transactions || []).map((t2) => t2.category)));
  const categorySpend = sum?.categorySpend || {};

  return `<section class="bank-card-visual card-anim">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div>
          <span class="pill LOW" style="margin-bottom:6px">RBI Account Aggregator (AA) Consent Architecture</span>
          <h1 class="t-page" style="margin:0;color:#FAF6EE">Connect Your Bank &amp; Family Financial Hub</h1>
        </div>
        ${sum?.hasDemoConnection ? '<span class="pill MEDIUM">Sample Demo Mode</span>' : '<span class="pill NEUTRAL">Zero Credentials</span>'}
      </div>
      <p class="mut" style="margin:0">Read-only consent-driven financial insights. <b>Parents AI never requests, accepts, or stores bank passwords, UPI PINs, ATM PINs, CVVs, or OTPs.</b> Live FIP connectivity requires licensed Sahamati / Finvu / Anumati TSP credentials; until configured, Sample Demo Mode lets you preview full RBI AA workflows safely.</p>
    </section>

    ${
      !authorized
        ? uiAlert(
            'Financial visibility for your role is currently restricted by Family Control Center privacy settings. Ask the primary parent account to enable Guardian or Child Financial Access.',
            { title: 'Financial Access Restricted:', tone: 'warn' }
          )
        : ''
    }

    <div class="g-2">
      <section class="card card-anim">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <div>
            <h2 class="t-section" style="margin:0">${uiIcon('lock', 17)} RBI Account Aggregator Consent</h2>
            <p class="mut" style="margin:2px 0 0;font-size:13px">Zero bank login credentials — read-only FIU consent handle only</p>
          </div>
          ${uiBadge(pai?.liveAaConfigured ? 'Live AA Configured' : 'Sample Demo Mode', pai?.liveAaConfigured ? 'LOW' : 'MEDIUM')}
        </div>
        <label for="pai-bank-inst">Choose participating Financial Information Provider (Sample FIP)</label>
        <select id="pai-bank-inst">
          <option value="State Bank of India (Sample FIP)">State Bank of India (Sample FIP)</option>
          <option value="HDFC Bank (Sample FIP)">HDFC Bank (Sample FIP)</option>
          <option value="ICICI Bank (Sample FIP)">ICICI Bank (Sample FIP)</option>
          <option value="Axis Bank (Sample FIP)">Axis Bank (Sample FIP)</option>
        </select>
        <div class="g" style="gap:10px">
          <div>
            <label for="pai-bank-handle">AA Consent Handle</label>
            <input id="pai-bank-handle" value="family@finvu.demo" placeholder="e.g. name@finvu">
          </div>
          <div>
            <label for="pai-bank-days">Read-only consent validity</label>
            <select id="pai-bank-days">
              <option value="30">30 Days</option>
              <option value="90" selected>90 Days</option>
              <option value="180">180 Days</option>
            </select>
          </div>
        </div>
        <div class="warn" style="font-size:12.5px">
          <b>Requested Read-Only Scopes:</b> Profile · Summary Balance · Masked Statements. Revocable in one click at any time.
        </div>
        <div class="row">
          <button type="button" class="gold" onclick="connectBankAa('demo_sample')" ${S.busy.parentsAi ? 'disabled' : ''}>${S.busy.parentsAi ? 'Connecting…' : 'Connect Sample Demo Account'}</button>
          <button type="button" class="s" onclick="connectBankAa('live')" ${S.busy.parentsAi ? 'disabled' : ''}>Verify Live RBI AA TSP</button>
        </div>
      </section>

      <section class="card card-anim">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <div>
            <h2 class="t-section" style="margin:0">${uiIcon('chart', 17)} 3D Monthly Spend Analytics</h2>
            <p class="mut" style="margin:2px 0 0;font-size:13px">Interactive 3D metallic category bars vs monthly budget limits</p>
          </div>
          ${sum?.hasDemoConnection ? uiBadge('Sample Demo Data', 'MEDIUM') : uiSourceBadge('unavailable')}
        </div>
        <div id="guardian-3d-finance" class="stage-3d-shell stage-3d-finance" aria-label="Interactive 3D Financial Chart"></div>
      </section>
    </div>

    ${
      activeConns.length
        ? `<div class="stat-grid">
            ${uiStatCard('Total Balance', authorized && sum?.totalBalance !== null ? inr(sum?.totalBalance || 0) : 'Protected', 'Sample Demo Mode balance', { source: 'simulated', icon: 'wallet' })}
            ${uiStatCard('Monthly Income', authorized && sum?.totalIncome !== null ? inr(sum?.totalIncome || 0) : 'Protected', 'Credited inflows', { source: 'simulated', icon: 'chart' })}
            ${uiStatCard('Monthly Expense', authorized && sum?.totalExpense !== null ? inr(sum?.totalExpense || 0) : 'Protected', 'Tracked outflows', { source: 'simulated', icon: 'card' })}
            ${uiStatCard('Active AA Consents', activeConns.length, 'One-click revocation ready', { source: 'actual', icon: 'lock' })}
          </div>`
        : ''
    }

    ${
      activeConns.length
        ? `<div class="card card-anim">
            <h2 class="t-section">Linked Account Aggregator Consents</h2>
            ${activeConns
              .map(
                (c) => `<div class="qr-history-row">
                  <div>
                    <b>${esc(c.institutionName)}</b> · <code>${esc(c.accountMasked)}</code>
                    <div class="mut" style="font-size:12.5px">Handle: <b>${esc(c.aaHandle)}</b> · ${esc(c.aaFramework)} · Expires ${formatDateInputValue(c.consentExpiresAt)}</div>
                  </div>
                  <div class="row">
                    ${c.isDemoSample ? uiBadge('Sample Demo', 'MEDIUM') : uiBadge('Live AA', 'LOW')}
                    ${authorized && c.balanceInr !== null ? `<b class="num">${inr(c.balanceInr)}</b>` : ''}
                    <button type="button" class="r" style="min-height:34px;padding:4px 12px" onclick="revokeBankConsent('${esc(c.id)}')" ${S.busy.parentsAi ? 'disabled' : ''}>Revoke Consent</button>
                  </div>
                </div>`
              )
              .join('')}
          </div>`
        : ''
    }

    <div class="g-2">
      <section class="card card-anim">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <div>
            <h2 class="t-section" style="margin:0">Family Budgets &amp; Savings Goals</h2>
            <p class="mut" style="margin:2px 0 0;font-size:13px">Set category caps and monitor savings milestones</p>
          </div>
          ${uiSourceBadge('actual')}
        </div>
        <div class="g" style="gap:10px">
          <div>
            <label for="pai-bud-cat">Category</label>
            <select id="pai-bud-cat">
              <option value="Groceries">Groceries</option>
              <option value="Utilities & Bills">Utilities &amp; Bills</option>
              <option value="Education">Education</option>
              <option value="Healthcare">Healthcare</option>
              <option value="Household & Lifestyle">Household &amp; Lifestyle</option>
            </select>
          </div>
          <div>
            <label for="pai-bud-limit">Monthly Limit (₹)</label>
            <input id="pai-bud-limit" type="number" min="0" value="15000">
          </div>
          <div>
            <label for="pai-bud-goal">Savings Goal Name (optional)</label>
            <input id="pai-bud-goal" placeholder="e.g. College Fund or Family Reserve">
          </div>
          <div class="g" style="gap:8px">
            <div>
              <label for="pai-bud-target">Target (₹)</label>
              <input id="pai-bud-target" type="number" min="0" value="50000">
            </div>
            <div>
              <label for="pai-bud-cur">Saved So Far (₹)</label>
              <input id="pai-bud-cur" type="number" min="0" value="18000">
            </div>
          </div>
        </div>
        <button type="button" class="gold" onclick="saveFamilyBudget()" ${S.busy.parentsAi ? 'disabled' : ''}>Save Budget &amp; Goal</button>
        <hr class="divider">
        ${
          (pai?.budgets || []).length
            ? (pai?.budgets || [])
                .map((b) => {
                  const spent = authorized && b.spent !== null ? b.spent : categorySpend[b.category] || 0;
                  const pct = b.monthlyLimit > 0 ? Math.min(100, Math.round((spent / b.monthlyLimit) * 100)) : 0;
                  const goalPct =
                    b.savingsTarget > 0 && authorized && b.savingsCurrent !== null
                      ? Math.min(100, Math.round((b.savingsCurrent / b.savingsTarget) * 100))
                      : 0;
                  return `<div class="warn">
                    <div class="row" style="justify-content:space-between;margin-bottom:4px">
                      <b>${esc(b.category)}</b>
                      <div class="row">
                        <span class="num">${authorized ? inr(spent) : 'Hidden'} / ${inr(b.monthlyLimit)}</span>
                        <button type="button" class="s" style="min-height:28px;padding:2px 8px" onclick="removeBudget('${esc(b.id)}')" aria-label="Remove budget">${uiIcon('trash', 13)}</button>
                      </div>
                    </div>
                    <div class="bar"><i style="width:${pct}%;background:${pct >= 90 ? 'var(--red)' : pct >= 70 ? 'var(--amb)' : 'var(--teal)'}"></i></div>
                    ${
                      b.savingsGoalName
                        ? `<p class="mut" style="margin:6px 0 0;font-size:12.5px">Goal: <b>${esc(b.savingsGoalName)}</b> · ${authorized && b.savingsCurrent !== null ? `${inr(b.savingsCurrent)} / ${inr(b.savingsTarget)} (${goalPct}%)` : `Target ${inr(b.savingsTarget)}`}</p>`
                        : ''
                    }
                  </div>`;
                })
                .join('')
            : '<p class="mut" style="margin:0">No custom budgets saved yet. Connect a Sample Demo account or create a category budget above.</p>'
        }
      </section>

      <section class="card card-anim">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <div>
            <h2 class="t-section" style="margin:0">Transaction History</h2>
            <p class="mut" style="margin:2px 0 0;font-size:13px">Search and filter read-only Account Aggregator entries</p>
          </div>
          ${sum?.hasDemoConnection ? uiBadge('Sample Demo Data', 'MEDIUM') : ''}
        </div>
        <div class="g" style="gap:8px;margin-bottom:10px">
          <div>
            <label for="pai-tx-search">Filter merchant or category</label>
            <input id="pai-tx-search" value="${esc(S.bankSearchQuery)}" oninput="setBankSearch(this.value)" placeholder="Search grocery, electricity, school…">
          </div>
          <div>
            <label for="pai-tx-cat">Category</label>
            <select id="pai-tx-cat" onchange="setBankCatFilter(this.value)">
              <option value="all" ${S.bankCategoryFilter === 'all' ? 'selected' : ''}>All Categories</option>
              ${allCategories.map((cat) => `<option value="${esc(cat)}" ${S.bankCategoryFilter === cat ? 'selected' : ''}>${esc(cat)}</option>`).join('')}
            </select>
          </div>
        </div>
        ${
          !authorized
            ? uiStateBox('empty', 'Transactions protected', 'Ask the primary parent account to authorize guardian financial visibility in Family Control Center.')
            : transactions.length
              ? transactions
                  .map(
                    (tx) => `<div class="qr-history-row">
                      <div>
                        <b>${esc(tx.merchant)}</b>
                        <div class="mut" style="font-size:12.5px">${esc(tx.category)} · ${formatDateInputValue(tx.txDate)}${tx.isDemoSample ? ' · Sample Demo' : ''}</div>
                      </div>
                      <b class="num" style="color:${tx.txType === 'credit' ? 'var(--teal)' : 'var(--ink)'}">${tx.txType === 'credit' ? '+' : '-'}${inr(tx.amount)}</b>
                    </div>`
                  )
                  .join('')
              : '<p class="mut" style="margin:0">No transactions yet. Click <b>Connect Sample Demo Account</b> above to preview read-only RBI AA bank statements.</p>'
        }
      </section>
    </div>`;
}

export function renderControlCenterTab(): string {
  const pai = S.parentsAi;
  const ac = pai?.accessControl || {
    childFinancialAccess: false,
    guardianFinancialAccess: true,
    requireGuardianAuth: true,
  };
  const isGuardian = S.user?.role === 'guardian';
  const emergencyContacts = (pai?.items || []).filter((i) => i.toolKey === 'emergency_contact');

  return `<section class="cyber-overview-card card-anim">
      <div class="row" style="justify-content:space-between">
        <div>
          <span class="pill LOW" style="margin-bottom:8px">Unified Governance &amp; Privacy</span>
          <h1 class="t-page" style="margin:0;color:#FAF6EE">Family Control Center</h1>
          <p class="mut" style="margin:4px 0 0;color:#C9BFA9">Manage profile oversight, family links, financial privacy controls, emergency readiness, and security settings from one place.</p>
        </div>
        ${uiBadge(S.user?.role === 'guardian' ? 'Guardian Role' : 'Primary Parent', 'LOW')}
      </div>
    </section>

    <div class="g-2">
      <section class="card card-anim">
        <h2 class="t-section">${uiIcon('users', 18)} Account &amp; Family Profile</h2>
        <div class="qr-kv-row"><b>Name</b><span>${esc(S.user?.name || '')}</span></div>
        <div class="qr-kv-row"><b>Username</b><code>@${esc(S.user?.username || '')}</code></div>
        <div class="qr-kv-row"><b>Linked Members</b><span>${isGuardian ? S.linkedParents.length + ' parent(s)' : S.links.filter((l) => l.status === 'active').length + ' active guardian(s)'}</span></div>
        <div class="row" style="margin-top:12px">
          ${
            !isGuardian
              ? `<button type="button" class="s" onclick="switchTab('fam')">Manage Family Invites</button>
                 <button type="button" class="s" onclick="switchTab('priv')">Security &amp; Retention Settings</button>`
              : `<button type="button" class="s" onclick="switchTab('req')">Review Approval Requests</button>
                 <button type="button" class="s" onclick="switchTab('gset')">Guardian Preferences</button>`
          }
        </div>
      </section>

      <section class="card card-anim">
        <div class="row" style="justify-content:space-between;margin-bottom:6px">
          <h2 class="t-section" style="margin:0">${uiIcon('lock', 18)} Financial Privacy &amp; Access Controls</h2>
          ${uiSourceBadge('actual')}
        </div>
        ${
          isGuardian
            ? `<p class="mut">Parent-controlled privacy preferences for linked financial visibility:</p>
               <ul>
                 <li>Guardian financial visibility: <b>${ac.guardianFinancialAccess ? 'Authorized' : 'Restricted by parent'}</b></li>
                 <li>Child member financial visibility: <b>${ac.childFinancialAccess ? 'Allowed' : 'Protected'}</b></li>
                 <li>Guardian verification required for financial updates: <b>${ac.requireGuardianAuth ? 'Enabled' : 'Optional'}</b></li>
               </ul>`
            : `<div class="sw">
                 <input type="checkbox" ${ac.guardianFinancialAccess ? 'checked' : ''} onchange="updateFinAccess({guardianFinancialAccess:this.checked})" aria-label="Allow linked guardians to view financial overview">
                 <span>Allow linked guardians to view Read-Only Financial Overview</span>
               </div>
               <div class="sw">
                 <input type="checkbox" ${ac.childFinancialAccess ? 'checked' : ''} onchange="updateFinAccess({childFinancialAccess:this.checked})" aria-label="Allow child profiles to view financial overview">
                 <span>Allow child/secondary members to view household budgets</span>
               </div>
               <div class="sw">
                 <input type="checkbox" ${ac.requireGuardianAuth ? 'checked' : ''} onchange="updateFinAccess({requireGuardianAuth:this.checked})" aria-label="Require guardian approval for sensitive transfers">
                 <span>Require Guardian authorization on high-value payment reviews</span>
               </div>`
        }
        <button type="button" class="gold" style="margin-top:8px" onclick="switchTab('bank')">Open Connect Your Bank</button>
      </section>
    </div>

    <div class="g-2">
      <section class="card card-anim">
        <h2 class="t-section">${uiIcon('life-buoy', 18)} Emergency Readiness</h2>
        <p class="mut" style="margin:0 0 10px">${emergencyContacts.length} trusted emergency contact(s) saved. For cyber fraud in India, dial <b>1930</b> or report at <b>cybercrime.gov.in</b>.</p>
        <div class="row">
          <button type="button" class="s" onclick="openAiTool('emergency')">Manage ICE Contacts</button>
          ${!isGuardian ? `<button type="button" class="r" onclick="emergencyHelpAction()" ${S.busy.emergency ? 'disabled' : ''}>Emergency Help</button>` : ''}
        </div>
      </section>

      <section class="card card-anim">
        <h2 class="t-section">${uiIcon('bell', 18)} Alerts &amp; Device Intelligence</h2>
        <p class="mut" style="margin:0 0 10px">Smart Red Alerts, GSI capability posture, and notification drawers stay active across sessions.</p>
        <div class="row">
          <button type="button" class="s" onclick="toggleNotifDrawer(true)">Open Notification Center</button>
          <button type="button" class="s" onclick="switchTab('tools')">Open All 8 AI Tools</button>
        </div>
      </section>
    </div>`;
}
