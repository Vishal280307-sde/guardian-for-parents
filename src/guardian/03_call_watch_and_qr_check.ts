// Call timing watch, suspicious-call/payment correlation, QR parsing and QR image handling

import jsQR from 'jsqr';
import {
  S,
  R,
  log,
  inr,
  aiExplain,
  apiJson,
  syncStateFromServer,
  setCallCorrelationHandler,
  enqueueGcihOfflineEvent,
  getOrCreateGcihDeviceId,
  type CallRecord,
  type RiskResult,
} from './01_core_state_and_scam_detection';
import { fmtD, needCall, setPayAssessCorrelation } from './02_payment_and_guardian_approval';

(window as unknown as { jsQR?: typeof jsQR }).jsQR = jsQR;

export async function callStart(callerType?: 'unknown' | 'known'): Promise<void> {
  if (needCall()) return;
  if (S.cur) {
    S.note = 'A call timer is already active. End the current call before starting another.';
    R();
    return;
  }
  const ck = document.getElementById('ck') as HTMLSelectElement | null;
  const known = callerType ? callerType === 'known' : ck ? ck.value === 'known' : false;
  const startedAt = Date.now();
  S.cur = {
    s: startedAt,
    known,
    ai: { st: 'wait' },
    warnedLong: false,
  };
  log('Call started: AI timing watch active — measuring length only (no audio, no transcription)');
  S.note =
    'AI Call Watch activated. Measuring call duration only — never listening, recording, or transcribing.';
  R();

  const recentUnknown = S.calls.filter((c) => !c.known && startedAt - c.e <= 18e5).length;
  const metaSig = [
    known ? 'Incoming call from a saved contact' : 'Incoming call from an unknown number',
    'AI measuring call length only (no audio, no transcript)',
  ];
  if (!known && recentUnknown >= 1) {
    metaSig.push(`Repeated unknown calls (${recentUnknown + 1} within 30 minutes)`);
  }
  if (S.pats >= 1) {
    metaSig.push('Prior call-to-payment suspicious pattern detected in this session');
  }
  const initScore = (!known ? 20 : 5) + (recentUnknown >= 1 ? 15 : 0) + (S.pats >= 1 ? 15 : 0);
  const initRisk: RiskResult = {
    score: Math.min(100, initScore),
    level: initScore >= 50 ? 'HIGH' : initScore >= 25 ? 'MEDIUM' : 'LOW',
    cat: 'call_timing_watch',
    sig: metaSig,
    conf: 'medium',
  };
  const metaTxt = `Call just started from ${known ? 'a saved contact' : 'an unknown number'}. Only call start time and duration are measured. No audio or transcription is used.`;

  try {
    const explanation = await aiExplain(metaTxt, initRisk, 'call_start');
    if (S.cur && S.cur.s === startedAt) {
      S.cur.ai = { st: 'ok', ...explanation };
      R();
    }
  } catch {
    if (S.cur && S.cur.s === startedAt) {
      S.cur.ai = { st: 'off' };
      R();
    }
  }
}

async function evaluatePostCallPatterns(lastCall: CallRecord): Promise<void> {
  const now = lastCall.e;
  const recentUnknown = S.calls.filter((c) => !c.known && now - c.e <= 18e5).length;
  const hadPayMsgAroundCall = Boolean(S.lastPayMsgAt && S.lastPayMsgAt >= lastCall.s - 12e4);

  if (hadPayMsgAroundCall) {
    await payAlert('a payment alert detected around this call');
    return;
  }

  const hasCorroboratingContext =
    recentUnknown >= 2 || (S.pats >= 1 && !lastCall.known);
  let s = 0;
  const sig: string[] = [];
  if (!lastCall.known) {
    s += 15;
    sig.push('Call was from an unknown number');
  }
  if (!lastCall.known && lastCall.dur >= 18e4) {
    if (hasCorroboratingContext) {
      s += 25;
      sig.push(`Long unknown call (${fmtD(lastCall.dur)}) combined with repeated/prior pressure signals`);
    } else {
      s += 4;
      sig.push(`Call duration (${fmtD(lastCall.dur)}) recorded as contextual timing only — long calls alone do not trigger alerts`);
    }
  }
  if (recentUnknown >= 2) {
    s += 20;
    sig.push(`Repeated unknown calls pattern (${recentUnknown} unknown calls within 30 minutes)`);
  }
  if (S.pats >= 1 && !lastCall.known) {
    s += 15;
    sig.push('Follows prior suspicious call-to-payment alert pattern');
  }

  if (s >= 35) {
    s = Math.min(100, s);
    const r: RiskResult = {
      score: s,
      level: s < 50 ? 'MEDIUM' : s < 75 ? 'HIGH' : 'CRITICAL',
      cat: 'call_timing_pattern',
      sig,
      conf: sig.length >= 2 ? 'high' : 'medium',
    };
    const txt = `A ${lastCall.known ? 'saved-contact' : 'unknown-number'} call lasted ${fmtD(lastCall.dur)}. Timing and caller metadata matched suspicious patterns. If any payment message or OTP alert arrives now, pause and verify.`;
    S.alert = {
      r,
      txt,
      ai: { st: 'wait' },
      gapMs: 0,
      callDurMs: lastCall.dur,
      duringCall: false,
      at: now,
    };
    log('Post-call timing pattern flagged (' + r.level + ')');
    if (S.user?.role === 'parent') {
      void apiJson('/api/calls/alert', {
        method: 'POST',
        body: JSON.stringify({ level: r.level, summary: sig[0] || txt }),
      }).catch(() => {});
    }
    R();
    try {
      const a = await aiExplain(txt, r, 'call_payment_timing');
      if (S.alert && S.alert.at === now) {
        S.alert.ai = { st: 'ok', ...a };
      }
    } catch {
      if (S.alert && S.alert.at === now) {
        S.alert.ai = { st: 'off' };
      }
    }
    R();
  }
}

export function callEnd(): void {
  const c = S.cur;
  if (!c) {
    S.note = 'No active call is running right now.';
    R();
    return;
  }
  const e = Date.now();
  const dur = Math.max(0, e - c.s);
  const record: CallRecord = { s: c.s, e, dur, known: c.known };
  S.calls.unshift(record);
  S.cur = null;
  log('Call ended, length ' + fmtD(dur) + ' (timing only, no audio/transcription)');
  S.note = `Call ended (length ${fmtD(dur)}). Only the duration was saved — no audio was heard or transcribed. Watching for any payment alert that follows.`;

  if (S.user?.role === 'parent') {
    void apiJson('/api/calls/record', {
      method: 'POST',
      body: JSON.stringify(record),
    })
      .then(() => syncStateFromServer())
      .catch(() => {});
  }

  R();
  void evaluatePostCallPatterns(record);
}

export function demoCall(): void {
  if (needCall()) return;
  if (S.cur) {
    S.note = 'End the active call before adding a demo call.';
    R();
    return;
  }
  const e = Date.now() - 12e4;
  const record: CallRecord = { s: e - 24e4, e, dur: 24e4, known: false };
  S.calls.unshift(record);
  if (S.user?.role === 'parent') {
    void apiJson('/api/calls/record', {
      method: 'POST',
      body: JSON.stringify(record),
    }).catch(() => {});
  }
  S.note = 'Demo call added (4m unknown call ended 2m ago). Now press Payment alert received now.';
  R();
}

export async function payAlert(sourceLabel?: string): Promise<void> {
  if (needCall()) return;
  const now = Date.now();
  const c = S.cur;
  const l = S.calls[0];
  let s = 0;
  const sig: string[] = [];
  let txt = '';
  let gapMs = 0;
  let callDurMs = 0;
  let known = false;
  const srcText = sourceLabel ? ` (${sourceLabel})` : '';

  if (c) {
    callDurMs = Math.max(0, now - c.s);
    gapMs = 0;
    known = c.known;
    s += 45;
    sig.push(
      `Payment alert arrived DURING an active call${c.known ? '' : ' from an unknown number'} (call length so far: ${fmtD(callDurMs)})${srcText}`
    );
    if (!c.known) s += 15;
    if (callDurMs >= 18e4) {
      s += 15;
      sig.push(`Extended active call (${fmtD(callDurMs)}) coinciding with payment request`);
    }
    txt = `A payment alert${srcText} arrived while a call was in progress from ${c.known ? 'a saved contact' : 'an unknown number'}. The call had lasted ${fmtD(callDurMs)}.`;
  } else if (l) {
    gapMs = Math.max(0, now - l.e);
    callDurMs = Math.max(0, l.dur);
    known = l.known;
    if (gapMs <= 12e4) {
      s += 45;
      sig.push(`Immediate pattern: payment alert came ${fmtD(gapMs)} after a ${fmtD(l.dur)} call ended${srcText}`);
    } else if (gapMs <= 6e5) {
      s += 35;
      sig.push(`Short-gap pattern: payment alert came ${fmtD(gapMs)} after a ${fmtD(l.dur)} call ended${srcText}`);
    } else if (gapMs <= 18e5) {
      s += 20;
      sig.push(`Post-call pattern: payment alert came ${fmtD(gapMs)} after a call ended (within 30 minutes)${srcText}`);
    } else if (gapMs <= 36e5) {
      s += 10;
      sig.push(`Payment alert came ${fmtD(gapMs)} after a call ended (within 1 hour)${srcText}`);
    } else {
      sig.push(`Payment alert came ${fmtD(gapMs)} after the last call (longer gap)${srcText}`);
    }

    if (!l.known) {
      s += 15;
      sig.push('The call was from an unknown number');
    }
    if (!l.known && l.dur >= 18e4) {
      s += 20;
      sig.push(`Long call (${fmtD(l.dur)}) from an unknown number followed by payment alert`);
    } else if (l.dur >= 18e4) {
      s += 10;
      sig.push(`Long call (${fmtD(l.dur)}) before payment alert`);
    }
    txt = `The last call was from ${l.known ? 'a saved contact' : 'an unknown number'} and lasted ${fmtD(l.dur)}. A payment alert${srcText} came ${fmtD(gapMs)} after it ended.`;
  } else {
    S.note = 'No call recorded yet. Start or demo a call first.';
    R();
    return;
  }

  const recentTimingCount = S.timingEvents.filter((ev) => now - ev.at <= 9e5).length;
  if (S.pats >= 1 && s >= 35) {
    s += 15;
    sig.push(`Repeated pattern (${S.pats + 1}x): payment alerts arriving during or shortly after calls`);
  }
  if (recentTimingCount >= 1 && s >= 25) {
    s += 10;
    sig.push('Burst pattern: multiple payment alerts tightly timed with calls');
  }

  s = Math.min(100, s);
  const r: RiskResult = {
    score: s,
    level: s < S.medThreshold ? 'LOW' : s < S.highThreshold ? 'MEDIUM' : s < 75 ? 'HIGH' : 'CRITICAL',
    cat: 'call_payment_timing',
    sig,
    conf: sig.length > 2 ? 'high' : 'medium',
  };

  S.timingEvents.unshift({
    at: now,
    duringCall: Boolean(c),
    gapMs,
    callDurMs,
    known,
    score: s,
  });

  if (s >= 50) S.pats++;
  if (s >= 35) S.link = now;

  S.alert = {
    r,
    txt,
    ai: { st: 'wait' },
    gapMs,
    callDurMs,
    duringCall: Boolean(c),
    at: now,
  };
  log('Call-to-payment timing checked (' + r.level + ')');
  if (S.user?.role === 'parent' && s >= 35) {
    void apiJson('/api/calls/alert', {
      method: 'POST',
      body: JSON.stringify({ level: r.level, summary: sig[0] || txt }),
    }).catch(() => {});
  }
  S.note = '';
  R();

  try {
    const a = await aiExplain(txt, r, 'call_payment_timing');
    if (S.alert && S.alert.at === now) {
      S.alert.ai = { st: 'ok', ...a };
    }
  } catch {
    if (S.alert && S.alert.at === now) {
      S.alert.ai = { st: 'off' };
    }
  }
  R();
}

setCallCorrelationHandler(payAlert);
setPayAssessCorrelation(payAlert);

import type { QrIntelligenceReport } from './01_core_state_and_scam_detection';

/* ---- QR Live Camera, File Decode & Guardian AI QR Intelligence ---- */
let qrCameraStream: MediaStream | null = null;
let qrScanTimer: number | null = null;
let qrCameraCanvas: HTMLCanvasElement | null = null;

export function stopQrCamera(silent = false): void {
  if (qrScanTimer !== null) {
    window.clearInterval(qrScanTimer);
    qrScanTimer = null;
  }
  if (qrCameraStream) {
    for (const track of qrCameraStream.getTracks()) {
      try {
        track.stop();
      } catch {
        // ignore track stop error
      }
    }
    qrCameraStream = null;
  }
  const video = document.getElementById('qr-video') as HTMLVideoElement | null;
  if (video) {
    try {
      video.srcObject = null;
    } catch {
      // ignore
    }
  }
  if (!silent) {
    S.qrStatus = S.qrReport ? { state: 'ready' } : { state: 'idle' };
    R();
  }
}

export async function startQrCamera(): Promise<void> {
  if (typeof navigator === 'undefined' || !navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
    S.qrStatus = {
      state: 'camera_unavailable',
      message: 'Live camera access is unavailable in this browser or context. Upload a QR image or paste the QR payload instead.',
    };
    R();
    return;
  }

  stopQrCamera(true);
  try {
    qrCameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
      audio: false,
    });
  } catch (err) {
    const name = err instanceof DOMException ? err.name : '';
    if (name === 'NotAllowedError' || name === 'PermissionDeniedError' || name === 'SecurityError') {
      S.qrStatus = {
        state: 'camera_denied',
        message: 'Camera permission was denied. Allow camera access in your browser settings, or upload a QR image below.',
      };
    } else if (name === 'NotFoundError' || name === 'DevicesNotFoundError' || name === 'OverconstrainedError') {
      S.qrStatus = {
        state: 'camera_unavailable',
        message: 'No usable camera was found on this device. Upload a QR image or paste QR text below.',
      };
    } else {
      S.qrStatus = {
        state: 'error',
        message: err instanceof Error ? err.message : 'Unable to start camera scanner.',
      };
    }
    R();
    return;
  }

  S.qrStatus = {
    state: 'camera_active',
    message: 'Camera active. Hold a UPI or payment QR steady inside the frame.',
  };
  R();

  window.requestAnimationFrame(() => {
    const video = document.getElementById('qr-video') as HTMLVideoElement | null;
    if (!video || !qrCameraStream) return;
    video.srcObject = qrCameraStream;
    void video.play().catch(() => {});

    if (!qrCameraCanvas) {
      qrCameraCanvas = document.createElement('canvas');
    }

    qrScanTimer = window.setInterval(() => {
      if (!qrCameraStream) {
        stopQrCamera(true);
        return;
      }
      const v = document.getElementById('qr-video') as HTMLVideoElement | null;
      if (!v || v.readyState < 2 || !v.videoWidth || !v.videoHeight) return;

      const maxDim = 720;
      const scale = Math.min(1, maxDim / Math.max(v.videoWidth, v.videoHeight));
      const w = Math.max(1, Math.round(v.videoWidth * scale));
      const h = Math.max(1, Math.round(v.videoHeight * scale));
      qrCameraCanvas!.width = w;
      qrCameraCanvas!.height = h;
      const ctx = qrCameraCanvas!.getContext('2d', { willReadFrequently: true });
      if (!ctx) return;
      ctx.drawImage(v, 0, 0, w, h);
      const imageData = ctx.getImageData(0, 0, w, h);
      const decoded = jsQR(imageData.data, w, h);
      if (decoded && decoded.data) {
        stopQrCamera(true);
        const qt = document.getElementById('qt') as HTMLTextAreaElement | null;
        if (qt) qt.value = decoded.data;
        void qrParse(decoded.data);
      }
    }, 220);
  });
}

export async function openQrHistoryReport(scanId: string): Promise<void> {
  try {
    const data = await apiJson<{
      scans: { id: string; report_json?: string | null }[];
    }>('/api/qr/history');
    const found = data.scans.find((x) => x.id === scanId);
    if (found && found.report_json) {
      S.qrReport = JSON.parse(found.report_json) as QrIntelligenceReport;
      S.qrStatus = { state: 'ready' };
      R();
    }
  } catch (err) {
    S.qrStatus = {
      state: 'error',
      message: err instanceof Error ? err.message : 'Could not load saved QR scan report.',
    };
    R();
  }
}

export async function qrParse(p: string): Promise<void> {
  S.qr = null;
  const trimmed = p.trim();
  if (!trimmed) {
    S.qrReport = null;
    S.qr = { err: 'Nothing to decode. Paste QR text, upload an image, or use the camera.' };
    S.qrStatus = { state: 'error', message: 'No QR payload provided.' };
    R();
    return;
  }

  // Run quick local structural check (for unauthenticated/offline fallback display)
  const sig: string[] = [];
  let s = 0;
  let d: Record<string, string | null> = {};

  if (/^upi:\/\/pay/i.test(trimmed)) {
    const q = new URLSearchParams(trimmed.split('?')[1] || '');
    d = { pa: q.get('pa'), pn: q.get('pn'), am: q.get('am'), tn: q.get('tn') };
    if (!d.pa || !/^[\w.-]+@[\w.-]+$/.test(d.pa)) {
      sig.push('UPI payee VPA ID is missing or malformed.');
      s += 55;
    }
    if (d.am) {
      const numAmt = Number(d.am);
      if (!Number.isFinite(numAmt) || numAmt <= 0) {
        s += 30;
        sig.push('Pre-filled UPI amount is invalid or malformed');
      } else {
        sig.push('Amount ' + inr(numAmt) + ' is pre-filled');
      }
    }
    if (/refund|prize|lottery|reward|kyc|cashback|help|support|fake/i.test((d.pn || '') + (d.pa || '') + (d.tn || ''))) {
      s += 40;
      sig.push('Payee or note mentions refund, prize, support, or KYC');
    }
  } else if (/^https?:/i.test(trimmed)) {
    try {
      const u = new URL(trimmed);
      s = 40;
      sig.push('QR leads to an external web link, not a UPI payment');
      d = { url: u.toString(), host: u.hostname.toLowerCase() };
    } catch {
      s = 65;
      sig.push('Malformed web URL in QR payload');
    }
  } else if (/^000201/.test(trimmed)) {
    s = 10;
    sig.push('EMVCo / BharatQR TLV payload detected');
    d = { format: 'EMVCo / BharatQR' };
  } else {
    s = 20;
    sig.push('Unsupported or non-payment QR payload');
  }

  s = Math.min(100, s || 10);
  const localRisk: RiskResult = {
    score: s,
    level: s < S.medThreshold ? 'LOW' : s < S.highThreshold ? 'MEDIUM' : s < 75 ? 'HIGH' : 'CRITICAL',
    cat: 'qr_payment',
    sig,
    conf: 'medium',
  };
  S.qr = { d, r: localRisk };

  if (S.user?.role === 'parent') {
    if (!S.online) {
      enqueueGcihOfflineEvent({
        eventType: 'qr_event',
        sourceModule: 'module_f_qr_intelligence',
        payload: {
          qrData: {
            rawPayload: trimmed,
            format: d.format || 'qr',
            classification: d.url ? 'External Web URL' : d.pa ? 'UPI Payment QR' : 'QR Payload',
            decodingStatus: 'decoded',
            upiId: d.pa || null,
            payeeName: d.pn || null,
            amount: d.am && Number.isFinite(Number(d.am)) ? Number(d.am) : null,
            url: d.url || null,
            securityScore: s,
            securityLevel: localRisk.level,
            loadCategory: 'Not Classified',
            findings: sig,
          },
          lang: S.lang,
        },
      });
      S.qrStatus = {
        state: 'ready',
        message: 'Offline: Local QR structure inspected and queued for Central Intelligence Hub sync when online.',
      };
    } else {
      S.qrStatus = {
        state: 'analyzing',
        message: 'Extracting QR data, analyzing merchant & security risks, evaluating payment load, and generating AI report...',
      };
      R();

      try {
        const res = await apiJson<{ report: QrIntelligenceReport }>('/api/qr/analyze', {
          method: 'POST',
          body: JSON.stringify({
            payload: trimmed,
            deviceId: getOrCreateGcihDeviceId(),
            lang: S.lang,
          }),
        });
        S.qrReport = res.report;
        S.qrStatus = { state: 'ready' };
        await syncStateFromServer().catch(() => {});
      } catch (err) {
        S.qrStatus = {
          state: 'error',
          message: err instanceof Error ? err.message : 'Unable to analyze QR code right now.',
        };
      }
    }
  } else {
    S.qrStatus = { state: 'ready' };
  }
  R();
}

export function qrFile(e: Event): void {
  const input = e.target as HTMLInputElement;
  const f = input.files && input.files[0];
  if (!f) return;
  if (!/^image\/(png|jpe?g|webp)$/.test(f.type) || f.size > 5e6) {
    S.qr = { err: 'Only PNG, JPG or WEBP images under 5 MB are supported.' };
    S.qrStatus = { state: 'error', message: 'Only PNG, JPG or WEBP images under 5 MB are supported.' };
    R();
    return;
  }

  stopQrCamera(true);
  S.qrStatus = { state: 'decoding', message: 'Decoding QR image locally...' };
  R();

  const objectUrl = URL.createObjectURL(f);
  const im = new Image();
  im.onload = () => {
    try {
      const maxDim = 1024;
      const scale = Math.min(1, maxDim / Math.max(im.width || 1, im.height || 1));
      const c = document.createElement('canvas');
      c.width = Math.max(1, Math.round(im.width * scale));
      c.height = Math.max(1, Math.round(im.height * scale));
      const x = c.getContext('2d');
      if (!x) {
        S.qr = { err: 'Image could not be processed.' };
        S.qrStatus = { state: 'error', message: 'Image could not be processed.' };
        R();
        return;
      }
      x.drawImage(im, 0, 0, c.width, c.height);
      const z = jsQR(x.getImageData(0, 0, c.width, c.height).data, c.width, c.height);
      if (z && z.data) {
        const qt = document.getElementById('qt') as HTMLTextAreaElement | null;
        if (qt) qt.value = z.data;
        void qrParse(z.data);
      } else {
        const msg = 'Could not decode a QR code from this image. No result was guessed. Try a clearer photo.';
        S.qr = { err: msg };
        S.qrStatus = { state: 'error', message: msg };
        R();
      }
    } finally {
      URL.revokeObjectURL(objectUrl);
      input.value = '';
    }
  };
  im.onerror = () => {
    URL.revokeObjectURL(objectUrl);
    input.value = '';
    S.qr = { err: 'Image could not be read.' };
    S.qrStatus = { state: 'error', message: 'Image could not be read.' };
    R();
  };
  im.src = objectUrl;
}

/* ---- AI Call Watcher & Payment Correlation Actions ---- */
const CW_QUEUE_KEY = 'guardian_cw_offline_queue';

export function loadCwOfflineQueue(): void {
  try {
    const raw = window.localStorage.getItem(CW_QUEUE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        S.cwOfflineQueue = parsed;
      }
    }
  } catch {
    // ignore storage restriction
  }
}

function saveCwOfflineQueue(): void {
  try {
    window.localStorage.setItem(CW_QUEUE_KEY, JSON.stringify(S.cwOfflineQueue));
  } catch {
    // ignore storage restriction
  }
}

export async function cwConsentAction(
  action: 'activate' | 'pause' | 'resume' | 'revoke'
): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  try {
    await apiJson('/api/call-watcher/consent', {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
    S.note =
      action === 'activate'
        ? 'AI Call Watcher activated (metadata & timing only — never listens, records, or transcribes audio).'
        : action === 'pause'
          ? 'AI Call Watcher paused. No new call or payment correlations will be recorded until resumed.'
          : action === 'resume'
            ? 'AI Call Watcher resumed.'
            : 'Call Watcher consent revoked.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update Call Watcher consent.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwToggleUnknownNotify(checked: boolean): Promise<void> {
  try {
    await apiJson('/api/call-watcher/consent', {
      method: 'POST',
      body: JSON.stringify({ action: 'update_prefs', notifyUnknownCalls: checked }),
    });
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not update preference.';
    R();
  }
}

export function cwSelectEvent(corrId: string | null): void {
  S.cwSelectedId = corrId;
  R();
}

export async function cwFlushOfflineQueue(): Promise<void> {
  if (!S.online || S.user?.role !== 'parent' || S.cwOfflineQueue.length === 0) return;
  const remaining: typeof S.cwOfflineQueue = [];
  let syncedCount = 0;

  for (const item of S.cwOfflineQueue) {
    try {
      if (item.kind === 'call') {
        await apiJson('/api/call-watcher/calls', {
          method: 'POST',
          body: JSON.stringify(item.payload),
        });
      } else {
        await apiJson('/api/call-watcher/payment-message', {
          method: 'POST',
          body: JSON.stringify(item.payload),
        });
      }
      syncedCount++;
    } catch {
      remaining.push(item);
    }
  }

  S.cwOfflineQueue = remaining;
  saveCwOfflineQueue();
  if (syncedCount > 0) {
    S.note = `Synced ${syncedCount} offline Call Watcher event(s) to the server.`;
    await syncStateFromServer();
  } else {
    R();
  }
}

export async function cwLogCall(): Promise<void> {
  if (S.busy.cw) return;
  const clsEl = document.getElementById('cw-call-cls') as HTMLSelectElement | null;
  const stEl = document.getElementById('cw-call-status') as HTMLSelectElement | null;
  const idEl = document.getElementById('cw-caller-id') as HTMLInputElement | null;
  const durEl = document.getElementById('cw-call-dur') as HTMLInputElement | null;

  const callerClassification = clsEl ? clsEl.value : 'Unknown Number';
  const callStatus = stEl ? stEl.value : 'Answered';
  const callerIdentifier = idEl ? idEl.value.trim() : '';
  const durSecRaw = durEl && durEl.value.trim() !== '' ? Number(durEl.value.trim()) : null;
  const durationMs =
    durSecRaw !== null && Number.isFinite(durSecRaw) && durSecRaw >= 0
      ? Math.round(durSecRaw * 1000)
      : null;

  const now = Date.now();
  const payload = {
    externalEventId: `web_${now}_${Math.random().toString(36).slice(2, 8)}`,
    callerIdentifier: callerIdentifier || null,
    callerClassification,
    callStatus,
    incomingAt: durationMs !== null ? now - durationMs : now,
    startedAt: durationMs !== null ? now - durationMs : null,
    endedAt: durationMs !== null ? now : null,
    durationMs,
    source: 'user_assisted',
    deviceId: getOrCreateGcihDeviceId(),
    lang: S.lang,
  };

  if (!S.online) {
    S.cwOfflineQueue.push({ id: `q_${now}`, kind: 'call', payload, createdAt: now });
    saveCwOfflineQueue();
    S.note =
      'Offline: Call event queued locally. It will sync and check guardian notifications once internet connectivity returns.';
    R();
    return;
  }

  S.busy.cw = true;
  R();
  try {
    const res = await apiJson<{
      correlation?: { correlationId: string } | null;
    }>('/api/call-watcher/calls', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (idEl) idEl.value = '';
    if (res.correlation?.correlationId) {
      S.cwSelectedId = res.correlation.correlationId;
    }
    S.note =
      'Call metadata saved (no audio heard or recorded). Share any payment SMS/notification below to evaluate call-payment timing.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not log call metadata.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwLogPaymentMsg(overrideText?: string, overrideSender?: string): Promise<void> {
  if (S.busy.cw) return;
  const msgEl = document.getElementById('cw-pay-msg') as HTMLTextAreaElement | null;
  const sndEl = document.getElementById('cw-pay-sender') as HTMLInputElement | null;

  const rawMessageText = overrideText !== undefined ? overrideText : msgEl ? msgEl.value.trim() : '';
  const senderLabel = overrideSender !== undefined ? overrideSender : sndEl ? sndEl.value.trim() : '';

  if (!rawMessageText || rawMessageText.length < 4) {
    S.note = 'Paste or type a payment SMS or notification summary (at least 4 characters).';
    R();
    return;
  }

  const now = Date.now();
  const payload = {
    rawMessageText,
    senderLabel: senderLabel || null,
    messageTs: now,
    source: 'user_assisted',
    deviceId: getOrCreateGcihDeviceId(),
    lang: S.lang,
  };

  if (!S.online) {
    S.cwOfflineQueue.push({ id: `q_${now}`, kind: 'payment', payload, createdAt: now });
    saveCwOfflineQueue();
    S.note =
      'Offline: Payment message queued locally (OTPs/PINs are never stored raw). It will sync when online.';
    R();
    return;
  }

  S.busy.cw = true;
  R();
  try {
    const res = await apiJson<{
      duplicate: boolean;
      correlation?: { correlationId: string };
    }>('/api/call-watcher/payment-message', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (msgEl && overrideText === undefined) msgEl.value = '';
    if (res.correlation?.correlationId) {
      S.cwSelectedId = res.correlation.correlationId;
    }
    S.note = res.duplicate
      ? 'Duplicate payment message ignored (already analyzed in this time window).'
      : 'Payment message metadata extracted (OTPs/PINs stripped) and correlated with recent call timing.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not analyze payment message.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwDemoScenario(kind: 'scam_corr' | 'promo' | 'high_legit'): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  const now = Date.now();
  try {
    if (kind === 'scam_corr') {
      await apiJson('/api/call-watcher/calls', {
        method: 'POST',
        body: JSON.stringify({
          externalEventId: `demo_scam_${now}`,
          callerIdentifier: '9876543210',
          callerClassification: 'Unknown Number',
          callStatus: 'Answered',
          incomingAt: now - 240_000,
          startedAt: now - 240_000,
          endedAt: now - 30_000,
          durationMs: 210_000,
          source: 'simulated',
          lang: S.lang,
        }),
      });
      const res = await apiJson<{ correlation: { correlationId: string } }>(
        '/api/call-watcher/payment-message',
        {
          method: 'POST',
          body: JSON.stringify({
            rawMessageText:
              'URGENT: Your KYC is suspended. Approve UPI collect request of Rs. 9,500 to kyc.support@okfake immediately or A/c XX4321 will be blocked. UTR 421998112233.',
            senderLabel: 'VK-KYCBLK',
            messageTs: now,
            source: 'simulated',
            lang: S.lang,
          }),
        }
      );
      S.cwSelectedId = res.correlation.correlationId;
      S.note = 'Demo scenario added: 3m 30s unknown call followed by suspicious UPI payment request.';
    } else if (kind === 'promo') {
      const res = await apiJson<{ correlation: { correlationId: string } }>(
        '/api/call-watcher/payment-message',
        {
          method: 'POST',
          body: JSON.stringify({
            rawMessageText:
              'Exclusive Offer! Get Rs. 500 cashback voucher on your next credit card spend. Apply now!',
            senderLabel: 'AD-OFFERS',
            messageTs: now,
            source: 'simulated',
            lang: S.lang,
          }),
        }
      );
      S.cwSelectedId = res.correlation.correlationId;
      S.note = 'Demo promotional message tested (correctly classified as Promotional message, Low Risk).';
    } else {
      await apiJson('/api/call-watcher/calls', {
        method: 'POST',
        body: JSON.stringify({
          externalEventId: `demo_legit_${now}`,
          callerIdentifier: '9811122233',
          callerClassification: 'Known Contact',
          callStatus: 'Answered',
          incomingAt: now - 600_000,
          startedAt: now - 600_000,
          endedAt: now - 540_000,
          durationMs: 60_000,
          source: 'simulated',
          lang: S.lang,
        }),
      });
      const res = await apiJson<{ correlation: { correlationId: string } }>(
        '/api/call-watcher/payment-message',
        {
          method: 'POST',
          body: JSON.stringify({
            rawMessageText:
              'Rs. 32,000 debited from A/c XX8812 via UPI to Max Hospital Pharmacy on 18-Nov. Ref 9912341122.',
            senderLabel: 'HDFCBK',
            messageTs: now,
            source: 'simulated',
            lang: S.lang,
          }),
        }
      );
      S.cwSelectedId = res.correlation.correlationId;
      S.note = 'Demo high-amount known-contact debit tested (proves high amount alone does not indicate fraud).';
    }
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Demo scenario failed.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwSubmitQuestionnaire(correlationId: string): Promise<void> {
  if (S.busy.cw) return;
  const askEl = document.getElementById(`cwq-ask-${correlationId}`) as HTMLSelectElement | null;
  const urgEl = document.getElementById(`cwq-urg-${correlationId}`) as HTMLSelectElement | null;
  const crdEl = document.getElementById(`cwq-crd-${correlationId}`) as HTMLSelectElement | null;
  const emoEl = document.getElementById(`cwq-emo-${correlationId}`) as HTMLSelectElement | null;

  S.busy.cw = true;
  R();
  try {
    await apiJson('/api/call-watcher/questionnaire', {
      method: 'POST',
      body: JSON.stringify({
        correlationId,
        askedToDo: askEl ? askEl.value : 'none_or_normal',
        urgencyPressure: urgEl ? urgEl.value : 'no',
        askedSensitiveCreds: crdEl ? crdEl.value : 'no',
        emotionalFeeling: emoEl ? emoEl.value : 'calm',
        dismissed: false,
        lang: S.lang,
      }),
    });
    S.cwSelectedId = correlationId;
    S.note = 'Safety check answers saved and Call/Payment risks updated.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not save questionnaire answers.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwDismissQuestionnaire(correlationId: string): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  try {
    await apiJson('/api/call-watcher/questionnaire', {
      method: 'POST',
      body: JSON.stringify({ correlationId, dismissed: true, lang: S.lang }),
    });
    S.note = 'Questionnaire postponed. You can still review this event in the timeline below.';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not dismiss questionnaire.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwScreenCallerNumber(): Promise<void> {
  if (S.busy.cw) return;
  const numEl = document.getElementById('cw-screen-num') as HTMLInputElement | null;
  const clsEl = document.getElementById('cw-screen-cls') as HTMLSelectElement | null;
  const callerIdentifier = numEl ? numEl.value.trim() : S.cwScreenNumber.trim();
  const callerClassification = clsEl ? clsEl.value : 'Unknown Number';

  S.cwScreenNumber = callerIdentifier;
  S.busy.cw = true;
  R();
  try {
    const res = await apiJson<NonNullable<typeof S.cwScreenResult>>('/api/call-watcher/screen', {
      method: 'POST',
      body: JSON.stringify({
        callerIdentifier: callerIdentifier || null,
        callerClassification,
        callScreeningRoleGranted: S.callWatcher?.settings.callScreeningRoleState === 'granted',
      }),
    });
    S.cwScreenResult = res;
    S.note = `Pre-screen completed in ${res.lookupLatencyMs}ms (${res.riskLevel}; calls are never auto-blocked).`;
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not screen caller number.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwMarkCallerTrusted(
  correlationId: string,
  entityId?: string,
  callerHash?: string
): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  try {
    const res = await apiJson<{ ok: boolean; safeguardNotice: string }>('/api/call-watcher/trusted', {
      method: 'POST',
      body: JSON.stringify({
        entityId: entityId || null,
        callerHash: callerHash || null,
        note: `Trusted via Safe Decision Assistant on ${correlationId}`,
      }),
    });
    S.note = res.safeguardNotice;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not mark caller as trusted.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwReportSuspiciousCaller(
  correlationId: string,
  entityId?: string
): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  try {
    if (entityId) {
      await apiJson(`/api/gcih/entities/${encodeURIComponent(entityId)}/feedback`, {
        method: 'POST',
        body: JSON.stringify({
          feedbackType: 'suspicious',
          note: `Reported suspicious via Safe Decision Assistant (${correlationId})`,
        }),
      });
    } else {
      await apiJson('/api/incidents', {
        method: 'POST',
        body: JSON.stringify({
          summary: `Suspicious caller reported (${correlationId})`,
          channel: 'Call/SMS',
        }),
      });
    }
    S.note =
      'Suspicious caller indicator recorded in Guardian family threat intelligence (never shares raw phone numbers externally).';
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not report number.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export async function cwContactParent(correlationId: string): Promise<void> {
  if (S.busy.cw) return;
  S.busy.cw = true;
  R();
  try {
    const res = await apiJson<{ ok: boolean; statusMessage: string }>('/api/call-watcher/notify-guardian', {
      method: 'POST',
      body: JSON.stringify({ correlationId }),
    });
    S.note = res.statusMessage;
    await syncStateFromServer();
  } catch (err) {
    S.note = err instanceof Error ? err.message : 'Could not notify linked guardian.';
  } finally {
    S.busy.cw = false;
    R();
  }
}

export function cwToggleWhyFlagged(correlationId: string): void {
  S.cwWhyExpandedId = S.cwWhyExpandedId === correlationId ? null : correlationId;
  R();
}



