// Payment assessment, guardian approval workflow, approval validation, safe-word setup/check

function demo(k){const d={kyc:'Your bank account will be blocked today. Complete your KYC by paying ₹2,000 immediately. Do not delay.',fam:'Papa, I am your son. I had an accident, need ₹50,000 urgently. Do not tell mom. Pay to this new number.',ok:'Your electricity bill of ₹1,500 is due on 25th. Pay via the official app.'};document.getElementById('st').value=d[k]}
/* ---- Payment-intent engine ---- */
function assess(){const g=i=>document.getElementById(i),amt=+g('am').value||0,known=g('kn').value=='known',f=i=>g(i).checked;
let s=0,sig=[];if(amt>S.limit){s+=30;sig.push(`Amount ${inr(amt)} is above your limit ${inr(S.limit)}`)}if(amt>S.limit*3){s+=10;sig.push('Amount is far above your limit')}
if(!known){s+=25;sig.push('New or unfamiliar beneficiary')}else s-=15;if(f('nt')){s+=10;sig.push('Unusual time of day')}if(f('cl')){s+=30;sig.push('Follows a suspicious call or message')}if(f('ug')){s+=15;sig.push('Urgency pressure')}if(f('sc')){s+=15;sig.push('Asked to keep it secret')}if(S.link&&Date.now()-S.link<18e5){s+=20;sig.push('Follows a flagged call-and-payment-alert timing pattern')}
s=Math.max(0,Math.min(100,s));const level=s<25?'LOW':s<50?'MEDIUM':s<75?'HIGH':'CRITICAL';
S.pay={score:s,level,cat:'payment_intent',sig,conf:sig.length>2?'high':'medium',amt,ben:g('bn').value||'Unknown',id:null};log('Payment intent assessed ('+level+')');R()}
function payFill(k){const set=(i,v)=>document.getElementById(i)[typeof v=='boolean'?'checked':'value']=v;
if(k=='bad'){set('am',30000);set('bn','unknown.pay@okfake');set('kn','new');set('cl',true);set('ug',true);set('sc',false);set('nt',false)}else{set('am',1500);set('bn','Electricity Board');set('kn','known');set('cl',false);set('ug',false);set('sc',false);set('nt',false)}}
function askG(){const p=S.pay;if(!S.c.gapprove||S.c.paused){S.note='Guardian approval is not enabled. Enable it in Privacy.';return R()}
const q={id:'R'+Date.now().toString(36),amt:p.amt,ben:p.ben,level:p.level,sig:p.sig,exp:Date.now()+9e5,st:'pending',used:false};S.reqs.unshift(q);p.id=q.id;log('Guardian request '+q.id+' created (expires in 15 min)');R()}
const rq=id=>S.reqs.find(q=>q.id==id);
function decide(id,d){const q=rq(id),v=document.getElementById('vf'+id);if(!q||q.st!='pending'||Date.now()>q.exp){log('REJECTED: expired or invalid decision on '+id);S.note='Request expired or already decided.';return R()}
if(d=='approved'&&q.level!='LOW'&&!(v&&v.checked)){S.note='Tick that you verified by calling the parent on a saved number.';return R()}
q.st=d;log('Guardian '+d+' '+id);R()}
function proceed(id){const q=rq(id);if(!q||q.st!='approved'||q.used||Date.now()>q.exp||S.c.paused){log('SECURITY: blocked replayed, expired or unapproved authorization '+id);S.note='Authorization is invalid (used, expired or not approved). Event recorded.';return R()}q.used=true;log('Parent proceeded after verification (simulated, single-use) '+id);S.note='Simulated: no real payment was made. Approval is now used up.';R()}
function cancelPay(id){const q=rq(id);if(q){q.st='cancelled';q.used=true}S.pay=null;log('Parent cancelled '+(id||'assessment'));R()}
function forged(){log('SECURITY: forged/expired approval attempt rejected (R-FAKE)');S.note='Rejected: authorization is invalid. Security event recorded.';R()}
async function swSet(){const v=document.getElementById('sw').value;if(v.length<3){S.note='Use at least 3 characters.';return R()}const salt=crypto.getRandomValues(new Uint32Array(2)).join('-');S.safe={salt,h:await sha(salt+v.toLowerCase())};log('Safe word saved (hash only)');S.note='Safe word saved.';R()}
async function swCheck(){const v=document.getElementById('sw').value;if(!S.safe){S.note='Set a safe word first.';return R()}const ok=S.safe.h==await sha(S.safe.salt+v.toLowerCase());log('Safe word check: '+(ok?'match':'FAILED'));S.note=ok?'Safe word matches. Still call the person on their saved number.':'No match. Hang up and ask your guardian.';R()}
/* ---- Call Watch: timing only, never audio ---- */
const fmtD=ms=>Math.floor(ms/6e4)+'m '+Math.floor(ms%6e4/1e3)+'s';
const needCall=()=>{if(!S.c.calls||S.c.paused){S.note='Turn on call-duration timing in Privacy first. It records only start and end times, never audio.';R();return true}};
