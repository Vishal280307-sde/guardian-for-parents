import dns from "node:dns/promises";
import net from "node:net";
import { db } from "./db.ts";
import { sha256 } from "./security.ts";
import {
  lookupSharedEntitiesForQuery,
  normalizeEntityValue,
  type ExtractedEntityCandidate,
  type SharedIntelligenceItem,
} from "./gcih.ts";

export interface LinkFinding {
  code: string;
  severity: "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
  title: string;
  evidence: string;
}

export interface LinkAnalysisResult {
  rawInput: string;
  normalizedUrl: string | null;
  domain: string | null;
  scheme: string;
  urlHash: string;
  isShortener: boolean;
  isLookalike: boolean;
  impersonatedBrand: string | null;
  ssrfBlocked: boolean;
  ssrfReason: string | null;
  riskScore: number;
  severity: "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
  confidence: "low" | "medium" | "high";
  findings: LinkFinding[];
  redirectChain: string[];
  liveProbePerformed: boolean;
  liveProbeNote: string;
  localIntelMatch: {
    label: string;
    confidence: number;
    reportCount: number;
    falsePositiveCount: number;
  } | null;
  sharedIntelligence?: SharedIntelligenceItem[];
  recommendedAction: string;
  verificationBoundary: string;
  neverAutoOpened: true;
}

const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "cutt.ly",
  "rb.gy",
  "is.gd",
  "shorturl.at",
  "rebrand.ly",
  "ow.ly",
  "goo.gl",
  "tiny.cc",
  "wa.me",
  "s.id",
  "v.gd",
]);

const RISKY_TLDS = new Set([
  "xyz",
  "top",
  "click",
  "loan",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "zip",
  "mov",
  "work",
  "support",
  "buzz",
  "rest",
]);

const OFFICIAL_BRAND_DOMAINS: { brand: string; keywords: string[]; officialSuffixes: string[] }[] = [
  { brand: "State Bank of India (SBI)", keywords: ["sbi", "onlinesbi", "yonosbi"], officialSuffixes: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "statebankofindia.com"] },
  { brand: "HDFC Bank", keywords: ["hdfc", "hdfcbank"], officialSuffixes: ["hdfcbank.com", "hdfc.com"] },
  { brand: "ICICI Bank", keywords: ["icici", "icicibank"], officialSuffixes: ["icicibank.com", "icici.com"] },
  { brand: "Axis Bank", keywords: ["axisbank", "axis"], officialSuffixes: ["axisbank.com"] },
  { brand: "Kotak Mahindra Bank", keywords: ["kotak"], officialSuffixes: ["kotak.com", "kotakbank.com"] },
  { brand: "Punjab National Bank", keywords: ["pnbindia", "netpnb", "pnb"], officialSuffixes: ["pnbindia.in", "netpnb.com"] },
  { brand: "RBI / NPCI / UPI", keywords: ["rbi", "npci", "bhimupi"], officialSuffixes: ["rbi.org.in", "npci.org.in", "bhimupi.org.in"] },
  { brand: "Paytm", keywords: ["paytm"], officialSuffixes: ["paytm.com", "paytmbank.com"] },
  { brand: "PhonePe", keywords: ["phonepe"], officialSuffixes: ["phonepe.com"] },
  { brand: "Google Pay", keywords: ["gpay", "tez"], officialSuffixes: ["pay.google.com", "google.com"] },
  { brand: "Government / Aadhaar / Income Tax", keywords: ["uidai", "aadhaar", "incometax", "epfo", "parivahan", "indiapost"], officialSuffixes: ["gov.in", "nic.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "indiapost.gov.in"] },
];

export function extractUrlsFromText(text: string): string[] {
  const input = String(text || "");
  const matches = new Set<string>();

  const fullRegex = /\bhttps?:\/\/[^\s<>"'`)\]}]+/gi;
  for (const m of input.match(fullRegex) || []) {
    matches.add(m.replace(/[.,;!?]+$/, ""));
  }

  const shortenerRegex =
    /\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|rebrand\.ly|wa\.me)\/[^\s<>"'`)\]}]+/gi;
  for (const m of input.match(shortenerRegex) || []) {
    const clean = m.replace(/[.,;!?]+$/, "");
    if (!matches.has(`https://${clean}`) && !matches.has(`http://${clean}`)) {
      matches.add(`https://${clean}`);
    }
  }

  return Array.from(matches).slice(0, 8);
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const cleaned = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!cleaned) return true;

  if (cleaned === "localhost" || cleaned === "::1" || cleaned === "0.0.0.0") return true;

  if (net.isIPv4(cleaned)) {
    const parts = cleaned.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local & cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a >= 224) return true; // Multicast / reserved
    return false;
  }

  if (net.isIPv6(cleaned)) {
    if (cleaned === "::" || cleaned === "::1") return true;
    if (cleaned.startsWith("::ffff:")) {
      return isPrivateOrReservedIp(cleaned.slice(7));
    }
    const firstHextet = cleaned.split(":")[0] || "";
    const val = parseInt(firstHextet, 16);
    if (!Number.isNaN(val)) {
      if ((val & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique Local
      if ((val & 0xffc0) === 0xfe80) return true; // fe80::/10 Link Local
      if ((val & 0xff00) === 0xff00) return true; // Multicast
    }
    return false;
  }

  return false;
}

export async function validateSafeInspectionUrl(
  rawUrl: string,
  resolveDns = false
): Promise<{ safe: boolean; parsed: URL | null; reason: string | null }> {
  const trimmed = String(rawUrl || "").trim();
  if (!trimmed) return { safe: false, parsed: null, reason: "Empty URL" };

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate) && !/^[a-zA-Z]+:/.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { safe: false, parsed: null, reason: "Malformed URL syntax" };
  }

  const proto = parsed.protocol.toLowerCase();
  if (proto !== "http:" && proto !== "https:") {
    return { safe: false, parsed, reason: `Blocked non-web URL scheme (${proto})` };
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (
    !host ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "metadata.google.internal" ||
    host === "metadata"
  ) {
    return { safe: false, parsed, reason: `Blocked internal/local hostname (${host || "empty"})` };
  }

  if (net.isIP(host) && isPrivateOrReservedIp(host)) {
    return { safe: false, parsed, reason: `Blocked private, loopback, or metadata IP address (${host})` };
  }

  if (resolveDns && !net.isIP(host)) {
    try {
      const records = await dns.lookup(host, { all: true });
      for (const rec of records) {
        if (isPrivateOrReservedIp(rec.address)) {
          return {
            safe: false,
            parsed,
            reason: `Hostname ${host} resolved to a private/loopback IP (${rec.address})`,
          };
        }
      }
    } catch {
      // DNS resolution may be unavailable in offline preview; lexical checks still proceed safely
    }
  }

  return { safe: true, parsed, reason: null };
}

function hostMatchesOfficial(host: string, suffixes: string[]): boolean {
  return suffixes.some((s) => host === s || host.endsWith(`.${s}`));
}

export async function analyzeUrlIntelligence(
  rawUrl: string,
  opts: {
    userId?: string;
    contextText?: string;
    allowNetworkProbe?: boolean;
  } = {}
): Promise<LinkAnalysisResult> {
  const input = String(rawUrl || "").trim().slice(0, 1024);
  const findings: LinkFinding[] = [];
  let score = 0;

  const safety = await validateSafeInspectionUrl(input, Boolean(opts.allowNetworkProbe));
  if (!safety.parsed) {
    return {
      rawInput: input,
      normalizedUrl: null,
      domain: null,
      scheme: "invalid",
      urlHash: sha256(input.toLowerCase()),
      isShortener: false,
      isLookalike: false,
      impersonatedBrand: null,
      ssrfBlocked: true,
      ssrfReason: safety.reason || "Invalid URL",
      riskScore: 45,
      severity: "MODERATE",
      confidence: "medium",
      findings: [
        {
          code: "malformed_url",
          severity: "MODERATE",
          title: "Malformed or non-inspectable link",
          evidence: safety.reason || "Could not parse URL safely",
        },
      ],
      redirectChain: [],
      liveProbePerformed: false,
      liveProbeNote: "Link was not fetched because URL syntax was invalid or unsafe.",
      localIntelMatch: null,
      recommendedAction: "Do not open malformed or unfamiliar links.",
      verificationBoundary: "Offline/lexical check only; malformed URL could not be inspected externally.",
      neverAutoOpened: true,
    };
  }

  const parsed = safety.parsed;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const normalizedUrl = parsed.toString();
  const urlHash = sha256(normalizedUrl.toLowerCase());

  if (!safety.safe) {
    return {
      rawInput: input,
      normalizedUrl,
      domain: host || null,
      scheme,
      urlHash,
      isShortener: false,
      isLookalike: false,
      impersonatedBrand: null,
      ssrfBlocked: true,
      ssrfReason: safety.reason,
      riskScore: 70,
      severity: "HIGH",
      confidence: "high",
      findings: [
        {
          code: "blocked_internal_or_unsafe_scheme",
          severity: "HIGH",
          title: "Blocked unsafe scheme or internal/private address",
          evidence: safety.reason || "Unsafe link target",
        },
      ],
      redirectChain: [],
      liveProbePerformed: false,
      liveProbeNote: "Blocked server-side inspection to prevent unsafe internal network access (SSRF protection).",
      localIntelMatch: null,
      recommendedAction: "Do not open this link. Legitimate services never ask you to open local network or non-web links.",
      verificationBoundary: "Server-side fetch blocked by strict SSRF safety policy.",
      neverAutoOpened: true,
    };
  }

  const isShortener = SHORTENER_HOSTS.has(host);
  if (isShortener) {
    score += 30;
    findings.push({
      code: "url_shortener",
      severity: "HIGH",
      title: "Shortened URL hides actual destination",
      evidence: `Shortener host: ${host}`,
    });
  }

  if (scheme === "http") {
    score += 18;
    findings.push({
      code: "unencrypted_http",
      severity: "MODERATE",
      title: "Unencrypted HTTP connection",
      evidence: "Uses http:// instead of encrypted https://",
    });
  }

  if (net.isIP(host)) {
    score += 35;
    findings.push({
      code: "raw_ip_url",
      severity: "HIGH",
      title: "Link uses a raw IP address instead of a domain name",
      evidence: `Host IP: ${host}`,
    });
  }

  if (host.includes("xn--")) {
    score += 35;
    findings.push({
      code: "punycode_homoglyph",
      severity: "HIGH",
      title: "Internationalized Punycode domain (possible lookalike characters)",
      evidence: `Host contains xn-- label: ${host}`,
    });
  }

  if (parsed.username || parsed.password || input.includes("@")) {
    const beforePath = input.split("/").slice(0, 3).join("/");
    if (beforePath.includes("@")) {
      score += 35;
      findings.push({
        code: "authority_at_obfuscation",
        severity: "HIGH",
        title: "URL contains '@' authority obfuscation",
        evidence: "Attackers place trusted domain text before '@' to disguise the real destination.",
      });
    }
  }

  const labels = host.split(".").filter(Boolean);
  const tld = labels[labels.length - 1] || "";
  if (labels.length >= 4) {
    score += 15;
    findings.push({
      code: "excessive_subdomains",
      severity: "MODERATE",
      title: "Deeply nested subdomain structure",
      evidence: `${labels.length} domain labels (${host})`,
    });
  }

  if (RISKY_TLDS.has(tld) && /(bank|kyc|pay|upi|refund|verify|sbi|hdfc|icici|axis|reward|claim|apk)/i.test(normalizedUrl + " " + (opts.contextText || ""))) {
    score += 25;
    findings.push({
      code: "risky_tld_financial_context",
      severity: "HIGH",
      title: `High-abuse top-level domain (.${tld}) with financial keywords`,
      evidence: `Domain: ${host}`,
    });
  }

  // Brand impersonation / typosquatting detection
  let isLookalike = false;
  let impersonatedBrand: string | null = null;
  const hostNormalized = host.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/5/g, "s");
  for (const b of OFFICIAL_BRAND_DOMAINS) {
    if (hostMatchesOfficial(host, b.officialSuffixes)) {
      break;
    }
    const matchedKw = b.keywords.find(
      (kw) => host.includes(kw) || hostNormalized.includes(kw) || parsed.pathname.toLowerCase().includes(`/${kw}`)
    );
    if (matchedKw) {
      isLookalike = true;
      impersonatedBrand = b.brand;
      score += 38;
      findings.push({
        code: "brand_impersonation_domain",
        severity: "HIGH",
        title: `Possible ${b.brand} lookalike or impersonation domain`,
        evidence: `Host "${host}" references "${matchedKw}" but does not match verified official ${b.brand} domains.`,
      });
      break;
    }
  }

  // Phishing / credential harvesting / APK path & query signals
  const fullLower = normalizedUrl.toLowerCase();
  if (/\.apk(\?|$)/i.test(parsed.pathname) || /[?&](download|app)=.*\.apk/i.test(fullLower)) {
    score += 45;
    findings.push({
      code: "apk_download_link",
      severity: "CRITICAL",
      title: "Direct Android APK app download link",
      evidence: parsed.pathname.slice(0, 120),
    });
  }

  if (/(kyc|re-?kyc|unblock|verify-?account|otp|upi-?pin|mpin|refund|cashback|lottery|claim-?prize|pan-?update|aadhaar)/i.test(fullLower)) {
    score += 22;
    findings.push({
      code: "phishing_lure_keywords",
      severity: "MODERATE",
      title: "URL path/query uses KYC, refund, OTP, or account-verify lures",
      evidence: parsed.pathname.slice(0, 120) || host,
    });
  }

  if (/[?&](redirect|next|url|target|continue|dest|return_to)=/i.test(parsed.search)) {
    score += 18;
    findings.push({
      code: "open_redirect_param",
      severity: "MODERATE",
      title: "Link includes a redirect query parameter",
      evidence: parsed.search.slice(0, 120),
    });
  }

  // Check local managed threat intelligence DB (by domain and urlHash)
  let localIntelMatch: LinkAnalysisResult["localIntelMatch"] = null;
  const domainHash = sha256(`domain:${host}`);
  const intelRows = (await db
    .prepare(
      `SELECT reputation_label, confidence, report_count, false_positive_count, evidence_summary
       FROM gsi_threat_intel
       WHERE (user_id IS NULL OR user_id = ?)
         AND indicator_hash IN (?, ?)
       ORDER BY updated_at DESC LIMIT 2`
    )
    .all(opts.userId || "__none__", domainHash, urlHash)) as {
    reputation_label: string;
    confidence: number;
    report_count: number;
    false_positive_count: number;
    evidence_summary: string;
  }[];

  const topIntel = intelRows[0];
  if (topIntel) {
    localIntelMatch = {
      label: topIntel.reputation_label,
      confidence: Number(topIntel.confidence),
      reportCount: Number(topIntel.report_count),
      falsePositiveCount: Number(topIntel.false_positive_count),
    };
    if (topIntel.reputation_label === "Verified Spam" || topIntel.reputation_label === "High Risk") {
      score += 35;
      findings.push({
        code: "local_threat_intel_hit",
        severity: "HIGH",
        title: `Matched local threat intelligence (${topIntel.reputation_label})`,
        evidence: topIntel.evidence_summary,
      });
    } else if (topIntel.reputation_label === "Suspicious") {
      score += 18;
      findings.push({
        code: "local_threat_intel_suspicious",
        severity: "MODERATE",
        title: "Domain/URL flagged as Suspicious in local threat history",
        evidence: topIntel.evidence_summary,
      });
    }
  }

  // Also query GCIH cross-section shared entities (e.g. URL/domain discovered in SMS or QR)
  let sharedIntelligence: SharedIntelligenceItem[] = [];
  if (opts.userId && !opts.userId.startsWith("__")) {
    const cands = [
      normalizeEntityValue("url", normalizedUrl),
      normalizeEntityValue("domain", host),
    ].filter((c): c is ExtractedEntityCandidate => Boolean(c));
    sharedIntelligence = await lookupSharedEntitiesForQuery({
      familyOwnerId: opts.userId,
      candidates: cands,
      currentSection: "link_scam",
    });
    for (const sItem of sharedIntelligence) {
      if (
        (sItem.verificationStatus === "High risk" ||
          sItem.verificationStatus === "Confirmed malicious" ||
          sItem.verificationStatus === "Suspicious") &&
        sItem.sourceModule !== "module_c_manual_link_check"
      ) {
        score = Math.max(score, sItem.verificationStatus === "Suspicious" ? 45 : 65);
        findings.push({
          code: "gcih_shared_entity_hit",
          severity: sItem.verificationStatus === "Suspicious" ? "MODERATE" : "HIGH",
          title: `Cross-section intelligence hit from ${sItem.sourceModule}`,
          evidence: `${sItem.maskedDisplay} (${sItem.verificationStatus}) — ${sItem.reasonForSharing}`,
        });
      } else if (sItem.verificationStatus === "Verified legitimate") {
        score = Math.max(0, score - 20);
      }
    }
  }

  // Optional SSRF-safe bounded server-side redirect inspection (HEAD only, never executes page scripts)
  const redirectChain: string[] = [normalizedUrl];
  let liveProbePerformed = false;
  let liveProbeNote =
    "Evaluated via offline lexical, lookalike-domain, and local threat intelligence rules (external website content never executed).";

  if (opts.allowNetworkProbe) {
    try {
      let current = normalizedUrl;
      for (let hop = 0; hop < 2; hop++) {
        const hopSafety = await validateSafeInspectionUrl(current, true);
        if (!hopSafety.safe) {
          score += 30;
          findings.push({
            code: "redirect_to_unsafe_target",
            severity: "HIGH",
            title: "Redirect pointed to an unsafe or internal address",
            evidence: hopSafety.reason || "Blocked redirect",
          });
          break;
        }
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 2200);
        try {
          const resp = await fetch(current, {
            method: "HEAD",
            redirect: "manual",
            signal: ctrl.signal,
            headers: { "User-Agent": "GuardianSafetyInspector/1.0" },
          });
          liveProbePerformed = true;
          if (resp.status >= 300 && resp.status < 400) {
            const loc = resp.headers.get("location");
            if (!loc) break;
            const resolvedNext = new URL(loc, current).toString();
            redirectChain.push(resolvedNext);
            const nextHost = new URL(resolvedNext).hostname.toLowerCase();
            if (nextHost !== host) {
              score += 15;
              findings.push({
                code: "cross_domain_redirect",
                severity: "MODERATE",
                title: "Link redirects to a different domain",
                evidence: `${host} -> ${nextHost}`,
              });
            }
            current = resolvedNext;
          } else {
            break;
          }
        } finally {
          clearTimeout(timer);
        }
      }
      if (liveProbePerformed) {
        liveProbeNote = `Inspected HTTP headers safely (${redirectChain.length - 1} redirect hop(s) observed); page scripts were never executed.`;
      }
    } catch {
      liveProbeNote =
        "Live network header probe timed out or is unavailable offline; risk score reflects structural & local intelligence checks.";
    }
  }

  score = Math.min(100, score);
  const severity: LinkAnalysisResult["severity"] =
    score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MODERATE" : "LOW";
  const confidence: LinkAnalysisResult["confidence"] =
    findings.length >= 2 || localIntelMatch ? "high" : findings.length === 1 ? "medium" : "low";

  const recommendedAction =
    severity === "CRITICAL" || severity === "HIGH"
      ? "Do NOT tap this link or enter bank/OTP/PIN details. Open your official bank app or dial a trusted saved number directly."
      : severity === "MODERATE"
        ? "Verify the sender independently before opening this link. Never enter OTPs or passwords via SMS links."
        : "No obvious phishing syntax detected, but absence from a blocklist never guarantees a link is safe. Verify the domain carefully before tapping.";

  return {
    rawInput: input,
    normalizedUrl,
    domain: host,
    scheme,
    urlHash,
    isShortener,
    isLookalike,
    impersonatedBrand,
    ssrfBlocked: false,
    ssrfReason: null,
    riskScore: score,
    severity,
    confidence,
    findings,
    redirectChain,
    liveProbePerformed,
    liveProbeNote,
    localIntelMatch,
    ...(sharedIntelligence.length ? { sharedIntelligence } : {}),
    recommendedAction,
    verificationBoundary:
      "Absence from local threat lists never guarantees safety; external domain reputation feeds are not connected unless explicitly configured.",
    neverAutoOpened: true,
  };
}
