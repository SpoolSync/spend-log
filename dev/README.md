# Developer tools

Not part of the app (the service worker never caches this folder). They run against a local copy of Tally that talks to the Firebase emulators, never the live Pixora project.

- The end-to-end suites (passcode, sync between phones, scanning, backup) use personal receipts and screenshots, so they are kept outside this public repository.
- `audit_all.py` opens every screen, sheet and dialog at 320, 375 and 430 points wide, in light and dark mode, and reports accessibility problems (axe-core: serious and critical), anything wider than the screen, cut-off text, small tap targets and console errors. It also checks that the app opens offline.
- `score.py` grades the receipt scanner on store, total, date, time, item count and card digits, with seconds per scan.
- `receipts/` holds twelve Canadian receipt layouts and `render.py`, which draws them and "photographs" them (tilt, perspective, uneven light, blur, sideways shots). `truth.json` has the expected answers. Real receipt photos are kept out of this public repository.

Before a release: `python3 dev/audit_all.py` (expect 0 findings) and `python3 dev/score.py` after rendering the receipts with `receipts/render.py` (last run: 158/162 fields).
