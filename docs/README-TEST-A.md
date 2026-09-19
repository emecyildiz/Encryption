# KASA 1.1.0-test.2 — Update Test A

Install using `KASA-Setup-1.1.0-test.2.exe` on Windows 10/11 x64.
Use disposable sample files first. This is a prerelease, not a production release.
The installer is not Authenticode-signed; Windows may display a publisher warning.
The internal update signature does not replace Windows code signing.

1. Open Updates and confirm installed version `1.1.0-test.2`.
2. Select Test and stable releases; use Check now. With Test B not yet published,
   no newer version is expected. Report that Test A is installed to the publisher.
3. After Test B is published, Check now should offer it. Download and verify.
4. Save any pending Results and finish active operations. Explicitly approve
   closing KASA, then click Install update. The verified installer runs
   interactively after KASA closes; it is not a silent installation.
5. Finish setup and choose Launch KASA. Confirm the newer version in Updates.

Test A deliberately retains the earlier optional file-association behavior.
The `.kasa` default-handler improvement is reserved for Test B.
Decryption source deletion is ON by default; encryption source deletion is OFF.
Read the red source-deletion warning and opt out when retaining encrypted copies.

ZIP/portable copies can check releases, but installer handoff requires a registered
installation at the running application's location. Do not move an installed
folder manually. Never run publisher/test utilities; they are not distributed.

## Failure / recovery

- Missing/expired/invalid signed metadata: no installer is run; retain your
  current installation and contact the publisher. Metadata lasts 30 days.
- Cancelled/failed setup: reopen KASA. Updates shows the last installer exit code
  (0 means completed). If files are damaged, rerun the official setup. There is
  no automatic binary rollback in this prerelease; encrypted documents are not
  installer inputs and are not removed by the updater.
- Crash/power loss may leave a private `%TEMP%\KASA-update-<32 hex>` directory
  containing `installer.exe`. Do not execute leftover files manually. After
  closing KASA and all installers, remove only that updater download directory
  if you want to reclaim space. Automatic crash-orphan deletion is not enabled;
  unrelated files are never recursively removed by the updater.
- Keep a separate backup of valuable encrypted files. No secrets or documents
  are uploaded by update checks; GitHub receives normal request/IP information.
