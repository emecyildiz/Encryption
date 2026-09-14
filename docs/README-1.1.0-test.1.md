# KASA 1.1.0 Test 1 — Windows x64

This is a user-acceptance test build, not a final release. The installer and
application are unsigned. Use expendable sample files, not the only copy of
important data. Keep source deletion disabled while testing.

## Install or run

- Installer: run KASA-Setup-1.1.0-test.1.exe. The existing per-user KASA install
  will be updated in place. This has not been acceptance-tested on this machine.
- Portable: extract the entire ZIP to a new folder and run KASA.exe. Keep all
  DLL files beside it. No installer or administrator access is required.
- Close any running KASA instance before updating. Do not extract over an old
  portable folder; use a new folder so rollback stays straightforward.
- The optional installer file-association task registers KASA under Open with.
  Windows may still ask you to select KASA as the app for .kasa files; existing
  default-app choices are not forcibly replaced.
- Portable preview: KASA.exe --preview "C:\path\sample.txt.kasa"

## What changed

- Redesigned file/operation/results workspace.
- Hardened authenticated decryption, output saving and batch retry/cancellation.
- Read-only, authenticated in-memory preview for supported AES text/PNG/JPEG.
- Improved error/success dialogs and Enter acknowledgement.

## Suggested acceptance checks

1. Encrypt and decrypt a disposable file; compare its contents.
2. Try a wrong password, then retry the correct one.
3. Open a supported .kasa file in preview; close it and confirm no plaintext
   file was automatically saved. Explicit Decrypt and save does create one.
4. Try multiple files, cancellation, and choosing a different save folder.
5. Check window size/scaling, installation, optional association and uninstall.

## Limits

Preview is read-only and does not repair corrupt files. Unsupported formats
are not executed. Preview can leave OS/pagefile/GPU traces; this is not an
anti-forensics guarantee. XOR is educational, not recommended protection.
File format v1 and existing AES compatibility are unchanged.

Minimum-window/high-DPI coverage, font/EXIF edge cases, and installer
upgrade/uninstall acceptance remain open. This package was built and checked
for packaging completeness; installation and user testing are left to you.
KASA has not received an independent security audit.
