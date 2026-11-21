# Guardian for Parents

Family digital-safety and financial-scam protection platform combining transparent heuristic rules, SQLite intelligence, optional Google Gemini AI explanations, and consent-first parent/guardian oversight.

> **Workspace Scope Note:** This repository contains the complete **React 19 + TypeScript + Vite 8** web application and **Express.js + Node.js (`node:sqlite`)** backend. Native Android Capacitor wrapper files (`capacitor.config.ts`, `android/`) referenced for external Android deployment live in the external mobile repository and are not bundled inside this web workspace.

---

## 1. Architecture Overview

| Layer | Technology | Entry Point & Modules |
| :--- | :--- | :--- |
| **Frontend SPA** | React 19, TypeScript, Vite 8, Tailwind CSS | `src/App.tsx`, `src/main.tsx`, `src/guardian/01..05`, `src/guardian/scamEngine.ts` |
| **Backend API** | Express.js 4, Node.js (`>=22.14.0`) native TypeScript strip-types | `server.ts`, `server/db.ts`, `server/security.ts`, `server/ai.ts` |
| **Database** | Embedded SQLite via `node:sqlite` (`WAL` mode + foreign keys) | `data/guardian.db` (configurable via `GUARDIAN_DB_PATH`) |
| **Intelligence Modules** | QR Intelligence, Call Watcher & Screening, Link Inspection, GSI, GCIH | `server/qrIntelligence.ts`, `server/callWatcher.ts`, `server/linkIntelligence.ts`, `server/gsi.ts`, `server/gcih.ts` |
| **Automated Tests** | Node native assertions over HTTP + SQLite | `tests/runTests.ts` |

---

## 2. Core Features Implemented in This Codebase

- **Dual-Role Family Accounts:** Separate **Parent** (monitored account holder) and **Guardian** (invited family reviewer) workflows with salted scrypt password hashing, one-time recovery codes, rate-limited lockouts, session token expiry/purging, and revocable invite links.
- **Scam Message & Screenshot OCR Analysis:** Evaluates SMS/WhatsApp/call-transcript text with transparent heuristics (`scamEngine.ts`) and optional Gemini OCR/explanations after stripping sensitive digits/UPI IDs.
- **Payment Safety & Single-Use Guardian Approvals:** Assesses transaction risk against configurable thresholds and creates time-limited, single-use guardian approval tokens with secondary-guardian escalation.
- **QR Intelligence (`server/qrIntelligence.ts`):** Live camera scanning (`jsQR`), uploaded QR decoding, UPI/BharatQR/web payload parsing, merchant mismatch checks, payment load evaluation, and duplicate-hash tracking without auto-initiating payments or opening links.
- **AI Call Watcher, Call Screening & Safe Decision Assistant (`server/callWatcher.ts`):**
  - Strictly metadata & timing only — **never** listens to, records, or transcribes call audio.
  - Fast local SQLite `POST /api/call-watcher/screen` pre-screening (`allow_normal`, `allow_caution`, `allow_with_warning`, never auto-blocks).
  - Privacy-safe hashed local threat feed (`GET /api/call-watcher/threat-cache`).
  - Call lifecycle end-duration calculation (`PATCH /api/call-watcher/calls/:id/end`) with `null` honesty when timings are unavailable.
  - Long-call safeguard: isolated long calls (e.g., 18+ minutes) alone remain `LOW` severity and never trigger scam alerts without corroborating risk evidence.
  - 6-state Protection Status reporting (`Protection active`, `Protection partially active`, `Permission required`, `Background execution restricted`, `Offline intelligence`, `Protection unavailable`) plus Safe Decision Assistant actions (`Mark as trusted` with OTP/PIN safeguard, `Report this number`, `Contact my parent`).
- **Guardian Security Intelligence (GSI) & Smart Red Alerts (`server/gsi.ts`):** 4-tier severity (`GREEN`, `YELLOW`, `RED`, `CRITICAL_RED`) with cooldown deduplication and false-positive feedback.
- **Guardian Central Intelligence Hub (GCIH) (`server/gcih.ts`):** Cross-module entity normalization, family relationship graphs, device permission enforcement, offline sync replay idempotency, and workflow state tracking.
- **Emergency Help:** Revokes all linked guardians cleanly (`POST /api/links/revoke-all`) and opens the official Indian Cyber Crime Portal (`https://cybercrime.gov.in/`).

---

## 3. Privacy & Security Guarantees

1. **No Call Audio or Surveillance Overreach:** Zero audio capture, zero call recording, zero speech transcription, and zero hidden spying tools (`RECORD_AUDIO`, Accessibility bypass, `NotificationListener`, or silent `READ_SMS` ingestion are never implemented).
2. **Play-Store-Honest Browser Boundaries:** Browsers cannot automatically intercept background OS phone calls or SMS messages. Browser sessions operate transparently in user-assisted timing mode; automatic OS `CallScreeningService` / call-state / battery-optimization flows require the separate native Android Capacitor companion app.
3. **Production Demo-Seeding Guard:** Default demo accounts (`seedInitialDemoUsersIfEmpty()`) are **strictly disabled** when `NODE_ENV=production` or `ENABLE_DEMO_ACCOUNTS=false`.
4. **Data Redaction:** Sensitive numeric sequences, OTPs, PINs, passwords, and full phone numbers are masked or hashed (`sha256`) before audit logging, threat caching, or Gemini prompts.

---

## 4. Environment Configuration

Copy `.env.example` to `.env` before running locally or deploying:

```env
PORT=3000
NODE_ENV="development"
GEMINI_API_KEY="your-gemini-api-key"
APP_URL="http://localhost:3000"
GUARDIAN_DB_PATH="./data/guardian.db"
ENABLE_DEMO_ACCOUNTS="false"
CORS_ORIGINS="http://localhost:3000,https://localhost,capacitor://localhost"
VITE_API_BASE_URL=""
VITE_APP_ENV="development"
```

- Set `VITE_API_BASE_URL` to an `https://` backend origin when building a standalone web or Capacitor APK frontend.
- Keep `.env` and `data/*.db*` excluded from Git (already configured in `.gitignore`).

---

## 5. Setup & Execution Commands

### Prerequisites
- **Node.js `>=22.14.0`** (uses built-in `node:sqlite` and native TypeScript type-stripping for `node server.ts`).

### Install Dependencies
```bash
npm install
```

### Run Development Server
```bash
npm run dev
```
Serves API + Vite frontend middleware on `http://localhost:3000`.

### Run Automated Test Suite
```bash
npm test
```
Executes `tsx tests/runTests.ts` covering Auth, Workflow, QR Intelligence, Call Watcher, Smart Red Alerts, Emergency Help, GCIH, Background Call Protection, Screening, and `/health`.

### Typecheck & Production Build
```bash
npm run lint
npm run build
```

### Start Production Server
```bash
NODE_ENV=production PORT=3000 npm start
```
Check server & SQLite readiness via `GET /health`.

---

## 6. SQLite Backup & Restore

Ensure the server is stopped (or run SQLite `.backup`) so WAL changes are cleanly flushed:

```bash
# Create consistent hot backup (requires sqlite3 CLI)
sqlite3 data/guardian.db ".backup 'data/guardian-backup.db'"

# Or file copy when server is stopped
cp data/guardian.db data/guardian-backup.db

# Restore when server is stopped (remove stale WAL/SHM first)
rm -f data/guardian.db-wal data/guardian.db-shm
cp data/guardian-backup.db data/guardian.db
```

---

## 7. Android Capacitor Deployment & Release Signing (External Native Project)

Because this workspace contains only the web + Express/SQLite codebase (`android/` and `capacitor.config.ts` live in the external Capacitor Android project):

1. Build the production frontend web assets targeting your deployed HTTPS backend:
   ```bash
   VITE_API_BASE_URL="https://api.your-guardian-domain.example" VITE_APP_ENV="production" npm run build
   ```
2. Copy `dist/` into the external Android Capacitor repository and run `npx cap sync android`.
3. Configure `android/keystore.properties` (never committed) with release keystore credentials (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`).
4. Build debug APK / release AAB in Android Studio or Gradle (`./gradlew assembleDebug` / `./gradlew bundleRelease`), then validate on a physical Android device with:
   - `CallScreeningService` role prompt + fast local lookup (`POST /api/call-watcher/screen`)
   - `READ_PHONE_STATE` lifecycle + optional `READ_CALL_LOG` duration verification (`PATCH /api/call-watcher/calls/:id/end`)
   - Battery optimization exception banner & force-stop honest status (`POST /api/call-watcher/device-status`)
   - Offline queue sync verification and APK release install verification.

---

## 8. Known Limitations

- Web browsers cannot execute Android `CallScreeningService`, `PhoneStateListener`, or background battery-exemption checks natively.
- External Gemini AI features (`ocr`, `explain`, `chat`) automatically fall back to transparent local rule guidance if `GEMINI_API_KEY` is unset or unreachable.
- Native Gradle compilation, APK generation, and physical-device telephony validation cannot be executed inside a headless Node web container without an Android SDK toolchain or hardware device.
