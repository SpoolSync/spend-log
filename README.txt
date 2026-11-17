Spend Log - group version (installable iPhone web app)

One person hosts it once. Everyone else just opens the link.

HOST IT (free, GitHub Pages)
1. github.com > New repository > name it spend-log > Public > Create.
2. In the repo: Add file > Upload files > select ALL files in this folder > Commit.
   Every file must sit at the top level of the repo, not inside a folder.
   (About 40 MB in total. Nearly all of it is the on-phone receipt reader.)
3. Settings > Pages > Deploy from a branch > Branch: main, folder / (root) > Save.
4. After about a minute the address is https://YOUR-USERNAME.github.io/spend-log/

EACH PERSON INSTALLS IT
5. Open that address in Safari > Share > Add to Home Screen.
6. Open Spend Log from the home-screen icon and set a passcode THERE, not in Safari.
7. The first receipt scan downloads the reader once (about 40 MB, so use Wi-Fi).
   After that, scanning works offline.

WHAT TO TELL YOUR FRIENDS
- Everything they log is encrypted on their own phone. Nobody else, including
  whoever hosts the app, can see it. Receipt photos are read on the phone and
  never uploaded.
- A forgotten passcode cannot be recovered. Use Lock & backup > Save a backup file.
- Every scan opens for checking before it saves. The note under the photo says
  whether the item prices add up to the receipt total.

TO UPDATE THE APP LATER
Upload the changed files to the same repo. Phones pick up the new version the
next time they open the app while online. Nobody's data is touched.

Receipt reading uses open-source software that runs on the phone:
PaddleOCR PP-OCRv4 models (Apache-2.0), ONNX Runtime Web (MIT),
@gutenye/ocr (MIT), OpenCV.js (Apache-2.0).
