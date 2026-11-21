// Transparent rule-based scam detection engine + labelled evaluation dataset

export interface RiskResult {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cat: string;
  sig: string[];
  conf: 'low' | 'medium' | 'high';
}

export const RULES: [RegExp, number, string, string][] = [
  [/\b[o0]t[p]\b|0tp|o\.t\.p|one.?time.?(pass|code)|ओटीपी|\bp\.?i\.?n\b|पिन|cvv|mpin|upi\s*pin/i, 40, 'Asks for OTP, PIN, or CVV', 'otp_theft'],
  [/k\.?y\.?c|केवाईसी|re.?kyc|pan\s*(card\s*)?(update|link|suspend)|aadha?ar.{0,20}(update|suspend)|a[c]{1,2}ount.{0,25}(bl[o0]ck|suspend|freez|clos|deactivat)|khata.{0,15}(band|block)|खाता.{0,15}(बंद|ब्लॉक)/i, 30, 'KYC or account-blocking threat', 'bank_impersonation'],
  [/(sbi|hdfc|icici|axis|pnb|kotak|rbi|npci|paytm|phonepe|gpay|bank).{0,30}(officer|manager|official|calling|desk|support|helpdesk)/i, 15, 'Claims to be a bank or payment official', 'bank_impersonation'],
  [/urgent|immediately|right now|within \d+|today only|tonight|तुरंत|अभी|जल्दी|turant|abhi|jaldi|aaj hi/i, 15, 'Urgency pressure (English/Hindi/Hinglish)', 'urgent_payment'],
  [/(pay|transfer|send|bhejo|jama)\s.{0,24}(₹|rs\.?|inr)\s?\d|(₹|rs\.?|inr)\s?\d.{0,24}(pay|transfer|bhejo)|भुगतान|processing\s*fee/i, 15, 'Payment or fee demand', 'urgent_payment'],
  [/anydesk|teamviewer|quicksupport|rustdesk|screen.?shar|remote\s*access|download.{0,20}app/i, 35, 'Remote-access or screen-sharing request', 'remote_access'],
  [/arrest|cbi|ncb|trai|customs|cyber\s*cell|police\s*(station|notice)|warrant|digital\s*arrest|giraftar|गिरफ्तार|parcel.{0,25}(drugs|illegal|seized)/i, 35, 'Digital arrest, police, or authority threat', 'digital_arrest'],
  [/(courier|parcel|bluedart|delhivery|fedex|india\s*post).{0,35}(held|customs|address|update|pay|fee|seized)/i, 30, 'Fake courier or parcel delivery scam', 'courier_scam'],
  [/(electricity|bijli|power|meter).{0,30}(disconnect|cut|tonight|update|bill.{0,15}officer)/i, 30, 'Fake electricity disconnection threat', 'utility_scam'],
  [/(work\s*from\s*home|part.?time\s*job|telegram\s*task|like.{0,15}(video|post)|daily\s*(income|earn)).{0,35}(₹|rs\.?|earn|join|deposit)/i, 25, 'Fake job or task-earning offer', 'job_scam'],
  [/(instant\s*loan|pre.?approved\s*loan|loan\s*approved).{0,30}(fee|charge|pay|deposit|kyc)/i, 25, 'Fake loan approval upfront-fee indicator', 'loan_scam'],
  [/(scan|qr).{0,25}(receive|refund|prize|lottery|cashback|claim)|enter\s*pin\s*to\s*receive/i, 35, 'QR/PIN to receive money (you never pay to receive)', 'qr_refund'],
  [/don.?t\s*tell|keep\s*(it\s*)?secret|kisi\s*ko\s*(mat\s*)?bata|batana\s*mat|किसी को न बता|गोपनीय/i, 25, 'Secrecy manipulation', 'secrecy'],
  [/https?:\/\/\S+|bit\.ly|tinyurl|t\.co\/|cutt\.ly|rb\.gy|is\.gd|shorturl|wa\.me\//i, 15, 'Link or shortened URL in message', 'phishing'],
  [/(i am|this is|मैं|main).{0,20}(your\s*)?(son|daughter|beta|beti|बेटा)|accident|hospital|bail|दुर्घटना|police\s*pakad/i, 30, 'Family emergency impersonation claim', 'family_emergency'],
  [/guaranteed\s*return|double\s*your|crypto|vip\s*trading|मुनाफा|munafa/i, 25, 'Unrealistic investment return promise', 'investment_fraud'],
];

export function rules(x: string, medThreshold = 25, highThreshold = 50): RiskResult {
  const hits = RULES.filter((r) => r[0].test(x));
  const sc = Math.min(100, hits.reduce((a, r) => a + r[1], 0));
  const top = [...hits].sort((a, b) => b[1] - a[1])[0];
  const critThreshold = Math.min(95, highThreshold + 25);
  return {
    score: sc,
    level: sc < medThreshold ? 'LOW' : sc < highThreshold ? 'MEDIUM' : sc < critThreshold ? 'HIGH' : 'CRITICAL',
    cat: top ? top[3] : 'none_detected',
    sig: hits.map((r) => r[2]),
    conf: hits.length >= 3 ? 'high' : hits.length ? 'medium' : 'low',
  };
}

export const ACT: Record<RiskResult['level'], string[]> = {
  LOW: ['No rule matched, which does not guarantee safety. Stay careful and never share OTP or PIN.'],
  MEDIUM: ['Pause and verify through an independently trusted channel.', 'Do not click links in the message.'],
  HIGH: ['Do not pay or share any code.', 'Call your bank on the number saved in your phone or printed on your card.', 'Ask your guardian.'],
  CRITICAL: ['Stop. Do not pay or share any code.', 'Hang up and call your bank on its official saved number.', 'Ask your guardian now.'],
};

export interface EvalSample {
  id: string;
  label: 'scam' | 'genuine';
  category: string;
  text: string;
}

export const EVAL_DATASET: EvalSample[] = [
  { id: 's1', label: 'scam', category: 'fake_kyc', text: 'Your SBI account will be blocked today. Complete KYC by paying ₹2,000 immediately.' },
  { id: 's2', label: 'scam', category: 'obfuscated_otp', text: 'HDFC bank official calling: share your 0tp now or a/c blocked within 10 mins.' },
  { id: 's3', label: 'scam', category: 'digital_arrest', text: 'Mumbai Cyber Cell CBI notice: you are under digital arrest for customs parcel drugs. Pay ₹45,000 now.' },
  { id: 's4', label: 'scam', category: 'remote_access', text: 'Bank officer support: download AnyDesk and share screen to unblock debit card immediately.' },
  { id: 's5', label: 'scam', category: 'courier_scam', text: 'India Post parcel held at customs. Update address and pay ₹49 fee at bit.ly/post-fee' },
  { id: 's6', label: 'scam', category: 'electricity_scam', text: 'Your bijli power meter will be disconnected tonight at 9pm. Call electricity officer immediately.' },
  { id: 's7', label: 'scam', category: 'job_scam', text: 'Work from home part time job: like YouTube video and earn ₹3,000 daily income, deposit ₹1,000.' },
  { id: 's8', label: 'scam', category: 'loan_scam', text: 'Pre-approved instant loan ₹2,00,000 approved! Pay ₹1,999 processing fee right now.' },
  { id: 's9', label: 'scam', category: 'qr_refund', text: 'Scan this QR code and enter PIN to receive your ₹5,000 cashback refund.' },
  { id: 's10', label: 'scam', category: 'hinglish_family', text: 'Papa main beta bol raha hu, hospital mein accident ho gaya, turant ₹30,000 bhejo, kisi ko mat batana.' },
  { id: 's11', label: 'scam', category: 'hindi_otp', text: 'आपका खाता बंद होने वाला है, तुरंत ओटीपी और पिन साझा करें।' },
  { id: 's12', label: 'scam', category: 'investment', text: 'Join VIP trading crypto group for guaranteed return and double your money in 7 days.' },
  { id: 'g1', label: 'genuine', category: 'bill_reminder', text: 'Your electricity bill of ₹1,500 is due on 25th. Pay via the official provider app.' },
  { id: 'g2', label: 'genuine', category: 'bank_debit_info', text: 'INR 450.00 debited from A/c XX1234 at Metro Pharmacy. If not you, call official bank helpline.' },
  { id: 'g3', label: 'genuine', category: 'family_chat', text: 'Maa, reached Pune safely! Will call you after dinner around 9 PM.' },
  { id: 'g4', label: 'genuine', category: 'delivery_info', text: 'Your medicine order #4821 has been delivered to your security desk at 4:15 PM.' },
];

export function evaluateScamEngine(medThreshold = 25) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const details = EVAL_DATASET.map((sample) => {
    const res = rules(sample.text, medThreshold);
    const predictedScam = res.score >= medThreshold;
    const actualScam = sample.label === 'scam';
    if (predictedScam && actualScam) tp++;
    else if (predictedScam && !actualScam) fp++;
    else if (!predictedScam && !actualScam) tn++;
    else fn++;
    return {
      id: sample.id,
      label: sample.label,
      category: sample.category,
      predicted: predictedScam ? 'scam' : 'genuine',
      score: res.score,
      correct: predictedScam === actualScam,
    };
  });
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { total: EVAL_DATASET.length, tp, fp, tn, fn, precision, recall, f1, details };
}
