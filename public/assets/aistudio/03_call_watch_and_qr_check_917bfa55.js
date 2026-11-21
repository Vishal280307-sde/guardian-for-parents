// Call timing watch, suspicious-call/payment correlation, QR parsing and QR image handling

function callStart(){if(needCall())return;S.cur={s:Date.now(),known:document.getElementById('ck').value=='known'};log('Call started: AI timing watch active (no audio)');R()}
function callEnd(){const c=S.cur,e=Date.now();S.calls.unshift({s:c.s,e,dur:e-c.s,known:c.known});S.cur=null;log('Call ended, length '+fmtD(e-c.s)+' (timing only)');S.note='Call ended. Only the length was saved. No audio was heard or stored.';R()}
function demoCall(){if(needCall())return;const e=Date.now()-12e4;S.calls.unshift({s:e-24e4,e,dur:24e4,known:false});S.note='Demo call added. Now press Payment alert received now.';R()}
async function payAlert(){if(needCall())return;const now=Date.now(),c=S.cur,l=S.calls[0];let s=0,sig=[],txt;
if(c){s+=45;sig.push('Payment alert arrived DURING a call'+(c.known?'':' from an unknown number'));if(!c.known)s+=15;txt='A payment alert arrived while a call was in progress from '+(c.known?'a saved contact':'an unknown number')+'. The call had lasted '+fmtD(now-c.s)+'.'}
else if(l){const g=now-l.e;if(g<=6e5){s+=35;sig.push('Payment alert came '+fmtD(g)+' after a call ended')}else if(g<=18e5){s+=15;sig.push('Payment alert came within 30 minutes of a call')}if(!l.known){s+=15;sig.push('The call was from an unknown number')}if(!l.known&&l.dur>=18e4){s+=20;sig.push('Long call ('+fmtD(l.dur)+') from an unknown number')}txt='The last call was from '+(l.known?'a saved contact':'an unknown number')+' and lasted '+fmtD(l.dur)+'. A payment alert came '+fmtD(g)+' after it ended.'}
else{S.note='No call recorded yet. Start or demo a call first.';return R()}
if(S.pats>=2&&s>=35){s+=15;sig.push('Repeated pattern: payment alerts right after unknown calls')}
s=Math.min(100,s);const r={score:s,level:s<25?'LOW':s<50?'MEDIUM':s<75?'HIGH':'CRITICAL',cat:'call_payment_timing',sig,conf:sig.length>2?'high':'medium'};if(s>=50)S.pats++;if(s>=35)S.link=now;
S.alert={r,txt,ai:{st:'wait'}};log('Call-to-payment timing checked ('+r.level+')');S.note='';R();
try{S.alert.ai={st:'ok',...await aiExplain(txt,r)}}catch(e){S.alert.ai={st:'off'}}R()}
/* ---- QR ---- */
function qrParse(p){S.qr=null;p=p.trim();if(!p){S.qr={err:'Nothing to decode.'};return R()}let sig=[],s=0,d={};
if(/^upi:\/\//i.test(p)){const q=new URLSearchParams(p.split('?')[1]||'');d={pa:q.get('pa'),pn:q.get('pn'),am:q.get('am'),tn:q.get('tn')};
if(!d.pa){S.qr={err:'UPI payload found but no payee ID. Treat as unsafe.'};return R()}
if(d.am){s+=15;sig.push('Amount '+inr(d.am)+' is pre-filled')}if(/refund|prize|lottery|reward|kyc|cashback|help/i.test((d.pn||'')+(d.pa||'')+(d.tn||''))){s+=35;sig.push('Payee or note mentions refund, prize or KYC')}
if(/refund|receive|prize|cashback/i.test(d.tn||'')){s+=30;sig.push('Scanning a QR sends money. You never pay to receive money')}}
else if(/^https?:/i.test(p)){s=45;sig.push('QR leads to a web link, not a payment');d={url:p}}else{S.qr={err:'Could not recognise a payment or link in this QR.'};return R()}
s=Math.min(100,s||10);S.qr={d,r:{score:s,level:s<25?'LOW':s<50?'MEDIUM':s<75?'HIGH':'CRITICAL',cat:'qr_payment',sig,conf:'medium'}};log('QR checked');R()}
function qrFile(e){const f=e.target.files[0];if(!f)return;if(!/^image\/(png|jpe?g|webp)$/.test(f.type)||f.size>5e6){S.qr={err:'Only PNG, JPG or WEBP under 5 MB.'};return R()}
const im=new Image();im.onload=()=>{const c=document.createElement('canvas');c.width=im.width;c.height=im.height;const x=c.getContext('2d');x.drawImage(im,0,0);const z=window.jsQR&&jsQR(x.getImageData(0,0,c.width,c.height).data,c.width,c.height);if(z)qrParse(z.data);else{S.qr={err:'Could not decode this QR image. No result was guessed. Try a clearer photo.'};R()}};im.onerror=()=>{S.qr={err:'Image could not be read.'};R()};im.src=URL.createObjectURL(f)}
/* ---- Assistant ---- */
