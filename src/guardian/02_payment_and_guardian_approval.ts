// Payment assessment, guardian approval workflow, approval validation, safe-word setup/check

import {
  S,
  R,
  inr,
  apiJson,
  syncStateFromServer,
  enqueueGcihOfflineEvent,
  getOrCreateGcihDeviceId,
  type SharedIntelligenceItem,
} from './01_core_state_and_scam_detection';

let payAssessCorrelation: ((sourceLabel?: string) => Promise<void>) | null = null;
export const setPayAssessCorrelation = (fn: (sourceLabel?: string) => Promise<void>): void => {
  payAssessCorrelation = fn;
};

export function demo(k: 'kyc' | 'fam' | 'ok'): void {
  const d = {
    kyc: 'Your bank account will be blocked today. Complete your KYC by paying ₹2,000 immediately. Do not delay.',
    fam: 'Papa, I am your son. I had an accident, need ₹50,000 urgently. Do not tell mom. Pay to this new number.',
    ok: 'Your electricity bill of ₹1,500 is due on 25th. Pay via the official app.',
  };
  S.ocrDraft = d[k];
  const el = document.getElementById('st') as HTMLTextAreaElement | null;
  if (el) el.value = d[k];
}

/* ---- Payment-intent engine ---- */
export async function assess(): Promise<void> {
  const g = (i: string) => document.getElementById(i) as HTMLInputElement | HTMLSelectElement | null;
  const rawAmt = (g('am')?.value || '').trim();
  const amt = Number(rawAmt);
  const ben = (g('bn')?.value || '').trim();
  const known = g('kn')?.value === 'known';
  const f = (i: string) => Boolean((g(i) as HTMLInputElement | null)?.checked);

  if (!rawAmt || !Number.isFinite(amt) || amt <= 0) {
    S.note = 'Enter a valid positive payment amount greater than ₹0.';
    R();
    return;
  }
  if (!/^\d+(\.\d{1,2})?$/.test(rawAmt)) {
    S.note = 'Amount can have at most 2 decimal places (paise).';
    R();
    return;
  }
  if (!ben || ben.length < 2) {
    S.note = 'Enter a beneficiary name or UPI ID.';
    R();
    return;
  }
  if (ben.includes('@') && !/^[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9]{2,}$/.test(ben)) {
    S.note = 'That UPI ID looks malformed (expected format like name@bank). Double-check before paying.';
    R();
    return;
  }

  let s = 0;
  const sig: string[] = [];
  if (amt > S.limit) {
    s += 30;
    sig.push(`Amount ${inr(amt)} is above your limit ${inr(S.limit)}`);
  }
  if (amt > S.limit * 3) {
    s += 15;
    sig.push('Unusually large payment: far above your safety limit');
  }
  if (!known) {
    s += 25;
    sig.push('New or unfamiliar beneficiary');
  } else {
    s -= 10;
    sig.push('Self-declared familiar beneficiary (not independently verified)');
  }
  if (/fake|refund|prize|lottery|helpdesk|kyc|support|claim/i.test(ben)) {
    s += 25;
    sig.push('Suspicious keywords inside beneficiary / UPI handle');
  }
  if (f('nt')) {
    s += 10;
    sig.push('Unusual time of day');
  }
  if (f('cl')) {
    s += 30;
    sig.push('Follows a suspicious call or message');
  }
  if (f('ug')) {
    s += 15;
    sig.push('Urgency pressure');
  }
  if (f('sc')) {
    s += 15;
    sig.push('Asked to keep it secret');
  }
  if (S.link && Date.now() - S.link < 18e5) {
    s += 20;
    sig.push('Follows a flagged call-and-payment-alert timing pattern');
  }
  if (S.cur) {
    s += 25;
    sig.push(`Assessed while a call is active (${fmtD(Date.now() - S.cur.s)})`);
  } else if (S.calls[0] && Date.now() - S.calls[0].e <= 18e5) {
    const gap = Date.now() - S.calls[0].e;
    s += gap <= 6e5 ? 20 : 10;
    sig.push(`Payment check occurred ${fmtD(gap)} after a ${fmtD(S.calls[0].dur)} call ended`);
  }

  const dup = S.reqs.find(
    (q) =>
      q.amt === amt &&
      q.ben.toLowerCase() === ben.toLowerCase() &&
      ['pending', 'verification_requested'].includes(q.st) &&
      q.exp > Date.now()
  );
  if (dup) {
    s += 15;
    sig.push(`Duplicate active request detected (${dup.id})`);
  }

  s = Math.max(0, Math.min(100, s));
  const critThreshold = Math.min(95, S.highThreshold + 25);
  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' =
    s < S.medThreshold ? 'LOW' : s < S.highThreshold ? 'MEDIUM' : s < critThreshold ? 'HIGH' : 'CRITICAL';

  let assessmentId: string | null = null;
  let gsiRiskScore = s;
  let sharedIntelligence: SharedIntelligenceItem[] = [];
  const devId = getOrCreateGcihDeviceId();

  if (!S.online && S.user?.role === 'parent') {
    enqueueGcihOfflineEvent({
      eventType: 'payment_event',
      sourceModule: 'module_d_payment_safety',
      payload: {
        paymentData: {
          direction: 'manual_intent',
          amount: amt,
          beneficiary: ben || null,
          knownDeclared: known,
          baseScore: s,
          signals: sig,
        },
        lang: S.lang,
      },
    });
  } else {
    try {
      const saved = await apiJson<{
        id: string;
        gsiRiskScore?: number;
        sharedIntelligence?: SharedIntelligenceItem[];
      }>('/api/payments/assess', {
        method: 'POST',
        body: JSON.stringify({ amt, ben, knownDeclared: known, score: s, level, sig, deviceId: devId, lang: S.lang }),
      });
      assessmentId = saved.id;
      if (typeof saved.gsiRiskScore === 'number') {
        gsiRiskScore = saved.gsiRiskScore;
      }
      if (Array.isArray(saved.sharedIntelligence) && saved.sharedIntelligence.length > 0) {
        sharedIntelligence = saved.sharedIntelligence;
        const flaggedShared = sharedIntelligence.filter(
          (item) =>
            item.verificationStatus !== 'Verified legitimate' &&
            ['Moderate', 'High', 'Critical'].includes(item.riskClassification)
        );
        if (flaggedShared.length > 0) {
          for (const item of flaggedShared.slice(0, 2)) {
            sig.push(
              `Shared Hub Warning (${item.sourceModule}): ${item.maskedDisplay} flagged as ${item.verificationStatus} (${item.riskClassification})`
            );
          }
          s = Math.max(s, gsiRiskScore);
          level =
            s < S.medThreshold ? 'LOW' : s < S.highThreshold ? 'MEDIUM' : s < critThreshold ? 'HIGH' : 'CRITICAL';
        }
      }
    } catch {
      // Keep client assessment visible even if network drops
    }
  }

  S.pay = {
    score: s,
    level,
    cat: 'payment_intent',
    sig,
    conf: sig.length > 2 ? 'high' : 'medium',
    amt,
    ben,
    id: null,
    assessmentId,
    gsiRiskScore,
    sharedIntelligence,
  };
  S.note = !S.online ? 'Offline: Payment assessment saved locally and queued for Central Intelligence Hub sync.' : '';

  if ((f('cl') || !known || amt > S.limit) && S.c.calls && !S.c.paused && (S.cur || (S.calls[0] && Date.now() - S.calls[0].e <= 36e5)) && payAssessCorrelation) {
    void payAssessCorrelation('a payment assessment');
  }

  if (S.online) {
    await syncStateFromServer();
  } else {
    R();
  }
}

export function payFill(k: 'bad' | 'ok'): void {
  const set = (i: string, v: string | number | boolean) => {
    const el = document.getElementById(i) as HTMLInputElement | HTMLSelectElement | null;
    if (!el) return;
    if (typeof v === 'boolean') {
      (el as HTMLInputElement).checked = v;
    } else {
      el.value = String(v);
    }
  };
  if (k === 'bad') {
    set('am', 30000);
    set('bn', 'unknown.pay@okfake');
    set('kn', 'new');
    set('cl', true);
    set('ug', true);
    set('sc', false);
    set('nt', false);
  } else {
    set('am', 1500);
    set('bn', 'Electricity Board');
    set('kn', 'known');
    set('cl', false);
    set('ug', false);
    set('sc', false);
    set('nt', false);
  }
}

export async function askG(): Promise<void> {
  const p = S.pay;
  if (!p) return;
  try {
    const res = await apiJson<{ request: { id: string } }>('/api/requests', {
      method: 'POST',
      body: JSON.stringify({
        amt: p.amt,
        ben: p.ben,
        level: p.level,
        sig: p.sig,
        assessmentId: p.assessmentId || null,
      }),
    });
    p.id = res.request.id;
    S.note = 'Guardian approval request sent (expires in 15 min).';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not send guardian request.';
    R();
  }
}

export const rq = (id: string) => S.reqs.find((q) => q.id === id);

export async function decide(id: string, d: 'approved' | 'rejected' | 'verification_requested'): Promise<void> {
  const v = document.getElementById('vf' + id) as HTMLInputElement | null;
  const noteEl = document.getElementById('gn' + id) as HTMLInputElement | null;
  try {
    await apiJson(`/api/requests/${encodeURIComponent(id)}/decide`, {
      method: 'POST',
      body: JSON.stringify({
        decision: d,
        verifiedCallback: Boolean(v && v.checked),
        note: noteEl ? noteEl.value.trim() : '',
      }),
    });
    S.note = `Decision recorded: ${d.replace('_', ' ')}.`;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Decision failed.';
    R();
  }
}

export async function resubmitReq(id: string): Promise<void> {
  const el = document.getElementById('rn' + id) as HTMLInputElement | null;
  const note = el ? el.value.trim() : '';
  try {
    await apiJson(`/api/requests/${encodeURIComponent(id)}/resubmit`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    });
    S.note = 'Verification details submitted back to your guardian.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not resubmit request.';
    R();
  }
}

export async function escalateReq(id: string): Promise<void> {
  try {
    await apiJson(`/api/requests/${encodeURIComponent(id)}/escalate`, { method: 'POST' });
    S.note = 'Request escalated to your secondary guardian.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not escalate request.';
    R();
  }
}

export async function proceed(id: string): Promise<void> {
  try {
    await apiJson(`/api/requests/${encodeURIComponent(id)}/consume`, { method: 'POST' });
    S.note = 'Simulated: no real payment was made. Approval is now consumed (single-use).';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Authorization invalid.';
    await syncStateFromServer();
  }
}

export async function cancelPay(id?: string): Promise<void> {
  if (id) {
    try {
      await apiJson(`/api/requests/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
    } catch {
      // ignore if already closed
    }
  }
  S.pay = null;
  S.note = 'Payment assessment cancelled.';
  await syncStateFromServer();
}

export async function forged(): Promise<void> {
  try {
    await apiJson('/api/requests/R-FAKE/consume', { method: 'POST' });
  } catch (err) {
    S.note = err instanceof Error ? `Server rejected: ${err.message}` : 'Rejected: forged authorization invalid.';
  }
  await syncStateFromServer();
}

export async function swSet(): Promise<void> {
  const el = document.getElementById('sw') as HTMLInputElement | null;
  const v = el ? el.value.trim() : '';
  try {
    await apiJson('/api/safeword/set', {
      method: 'POST',
      body: JSON.stringify({ safeWord: v }),
    });
    if (el) el.value = '';
    S.note = 'Safe word saved securely on server (salted hash only).';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save safe word.';
    R();
  }
}

export async function swCheck(): Promise<void> {
  const el = document.getElementById('sw') as HTMLInputElement | null;
  const v = el ? el.value.trim() : '';
  try {
    const res = await apiJson<{ match: boolean; message: string }>('/api/safeword/verify', {
      method: 'POST',
      body: JSON.stringify({ safeWord: v }),
    });
    S.note = res.message;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Safe-word verification failed.';
    R();
  }
}

/* ---- Call Watch: timing only, never audio ---- */
export const fmtD = (ms: number): string => Math.max(0, Math.floor(ms / 6e4)) + 'm ' + Math.max(0, Math.floor((ms % 6e4) / 1e3)) + 's';

export const needCall = (): boolean => {
  if (!S.c.calls || S.c.paused) {
    S.note = 'Turn on call-duration timing in Privacy first (and ensure monitoring is not paused). It records only start and end times, never audio.';
    R();
    return true;
  }
  return false;
};
