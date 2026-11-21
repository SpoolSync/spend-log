# Spend Log

A spending and bills tracker for iPhone, part of the Pixora apps. It installs from Safari onto the home screen and works offline.

Live: https://spoolsync.github.io/spend-log/

## Install on an iPhone

1. Open the link above in **Safari**.
2. Tap **Share**, then **Add to Home Screen**.
3. Open Spend Log from the home-screen icon (not from Safari) and either sign in with your Pixora account or choose to use it on this phone only.
4. The first receipt scan downloads the on-phone reader once (about 40 MB, so use Wi-Fi). After that, scanning works offline.

## What it does

- **Home**: today's check-in, things that need attention (bills due, return deadlines, budgets near their limit), budgets with a month-pace marker, a few plain insights, a six-month trend and the month's receipt.
- **Log** (the round + button): scan a receipt, type a purchase in, or pick a recent purchase to log again.
- **Purchases**: every purchase by month, searchable by item, item ID, store or receipt number. Export a month as a spreadsheet (CSV).
- **Returns**: return-by dates (filled in from Canadian store policies, editable), whole or per-item returns and refunds.
- **More**: monthly bills, budgets, bank-import rows that need details, bank CSV import, account, passcode and backup.
- Duplicate receipts are detected. Deleting a purchase can be undone for a few seconds.

## Privacy

- Everything is encrypted on the phone with the person's Pixora passcode before it syncs to the Pixora Firebase project. Nobody else can read it, including whoever runs the project.
- Receipt photos never leave the phone. A full backup file (encrypted with its own password) is the way to move photos to a new phone.
- Only anonymous feature-usage counts are collected, never what anyone logs.
- "Erase all data" removes Spend Log's data from the phone and the cloud. It does not delete the Pixora login; to delete that, email pixora3dstudios@gmail.com.

## For maintainers

- Plain HTML, CSS and JavaScript with no build step. `app.js` is the app, `index.html` holds the markup and styles, and `sw.js` handles offline caching.
- **Bump `CACHE` in `sw.js` (and the version string passed to `PixoraUsage.init` in `app.js`) on every release**, or installed phones keep the old version.
- Cloud data lives at `apps/spendlog/users/<uid>` in Firestore. The security rules are kept in the SpoolSync/pixora repo; always publish that full rule set, never one app's section alone.
- Receipt reading runs on the phone (PaddleOCR models with ONNX Runtime): `ppocr.js`, `pp-*.onnx`, `ort-wasm-*`.
