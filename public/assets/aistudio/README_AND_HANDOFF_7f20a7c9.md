# Guardian for Parents – AI Studio batch preparation

## What was inspected
The usable project prototype is embedded in `_t.html` (the uploaded page titled "Guardian for Parents"). Its inline app script is approximately 33 KB / 118 source lines, with a 3.8 KB inline stylesheet.

The other uploads are primarily Claude artifact-viewer/browser resources, analytics/anti-bot pages, fonts, and UI assets. They are not additional Guardian feature specifications. In particular, the large CSS and frame JavaScript files belong to the Claude viewing page, not the Guardian application.

## Batch order
1. `01_core_state_and_scam_detection.js`
2. `02_payment_and_guardian_approval.js`
3. `03_call_watch_and_qr_check.js`
4. `04_ai_assistant_and_learning.js`
5. `05_interface_and_rendering.js`

`00_app_styles.css` contains the app stylesheet. `00_shell_reference.html` is a minimal assembly reference, not a verified production-ready page.

## Important limitations found
- The original page references `jsQR.js.download`, but that dependency was not included in the uploads. The shell references `jsQR.js`; obtain and verify the correct library before QR image decoding can work.
- The code calls `claude.use('sample')` for advanced AI explanation. That is a Claude-specific integration and will not automatically work in Google AI Studio/Gemini. It needs an explicit Gemini API integration.
- The supplied material is a small working-prototype source export, not the claimed 1.3-million-token project context or a complete product requirements specification.
- This split is a code-organisation aid. It does not establish that all product requirements, backend services, database, deployment configuration, or external APIs are present.
- Do not upload the Claude frame-shell JavaScript/CSS/analytics assets as Guardian project context; they are unrelated to the app's business logic.

## Suggested AI Studio instruction
Treat the five numbered JS files as source-code batches from one prototype. Analyse each batch in order, preserve existing behaviour, and maintain a cumulative implementation map. Do not assume the project is complete. Identify missing dependencies and replace Claude-specific AI calls with a Gemini-compatible implementation only after defining the expected behaviour and API configuration.
