# KASA 1.2.0

Windows 10/11 x64. Acceptance build distributed as a GitHub pre-release.
The recommended stable release remains 1.1.0 until acceptance is complete.

## Changes since 1.1.0

- Encryption and decryption ask for confirmation when source deletion is OFF.
  The warning explains retained originals, extra disk usage and same-folder
  confusion. Choosing to go back does not start processing or enable deletion.
- User-approved updates reuse the existing installation location and choices,
  without repeating the normal license/shortcut wizard. Progress and errors
  remain visible. After success KASA reopens; cancellation, failure or a required
  Windows restart do not automatically reopen it. Windows is never restarted
  automatically.
- Offline What's New notes appear until acknowledged for the installed version.
  Reopen them from Updates. The separate read-only preview window is unchanged.
- Fresh installs default to `%LOCALAPPDATA%\Emecworks\KASA`. Existing installs
  remain in their current folder during an update. There is no automatic move.
- Publisher branding is Emecworks; application copyright is Emeç Yıldız.
  Third-party license notices are preserved.

## Important behavior and upgrade notes

Decryption source deletion remains ON by default after successful saving;
encryption source deletion remains OFF. Review the deletion controls before
processing. Preview does not delete the encrypted file. Keep independent backups
of important encrypted files and remember the password.

The first update launched by an older updater (including the published 1.1.0
helper) may still use the full installation wizard. The simplified path applies
when the installed updater supports it. Portable copies do not auto-install.

Changing the installation folder does not change the encryption format or key.
Engine-level compatibility with files generated from 1.1.0 source was checked;
old-file/new-GUI acceptance remains part of the final user test. Do not decrypt
all documents just to reinstall. Back up the encrypted files first.

This EXE is not Authenticode-signed. Windows/SmartScreen may show an unknown
publisher warning. Ed25519 signatures verify KASA updates internally; they do not
establish Windows publisher reputation. No independent security audit is claimed.
The reported brief first-preview startup delay has not been diagnosed or fixed.

## Acceptance checklist

- Test with disposable copies before valuable data.
- Check source-retention confirmation in both modes, including Go back.
- Check What's New after first launch, acknowledgement, restart and manual reopen.
- Check old `.kasa` preview/decryption and Windows association after reinstall.
- Check installed-folder behavior and real update/installer presentation.

Automated evidence: 25 CTest groups, 29 cross-release engine checks, isolated
installer path/task checks and 7 updater process cases. Process fixtures replace
the installer and notification UI; they do not replace final GUI acceptance.
