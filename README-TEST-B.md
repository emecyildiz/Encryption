# KASA 1.1.0-test.3 — Test B

This package is prepared locally; preparation does not mean it has been published.
Windows 10/11 x64. Prerelease; use disposable files and independent backups.

## A to B test (after the publisher announces Test B)

1. Keep Test A (1.1.0-test.2) installed. Do not manually install B first.
2. In Test A, select Updates > Test and stable releases, then Check now.
3. Confirm the offered version is 1.1.0-test.3. Download and verify it.
4. Save pending Results and finish any active file operation. Approve closing
   KASA and starting the verified installer, then select Install update.
5. Complete the interactive installer. Review the association option; previous
   selections are retained on upgrade. Choose Launch KASA at the end.
6. Confirm 1.1.0-test.3 in Updates. Its release-channel popup should have a light,
   readable background. A further update is not expected yet.
7. Double-click a disposable supported `.kasa` file. The small password/preview
   window should open. Preview must not remove the encrypted source.

## Association behavior

- Fresh install: association is selected and marked Recommended in the installer.
- Upgrade: an earlier explicit opt-out remains off; selecting it is your choice.
- Another app's default or Windows UserChoice is never forcibly replaced.
  Windows may still ask you to select KASA/Always.
- Uninstall removes KASA's extension-default value only if it still points to
  KASA; it does not delete encrypted documents or another app's default.
- Recommended is our installer wording, not control over Windows chooser labels.

## Important limits

Decryption source deletion is ON by default after successful saving. Turn it OFF
to retain encrypted originals. Encryption source deletion remains OFF by default.
Preview does not delete its source. The brief first-open delay is not addressed
by this package.

The installer is not Authenticode-signed. Internal Ed25519 update signatures do
not remove Windows publisher/reputation warnings. ZIP copies can check versions,
but automatic installer handoff requires a registered installed KASA location.

If setup is cancelled or fails, reopen KASA or rerun the official installer.
Automatic binary rollback is not provided. The last installer exit code is shown
in Updates (0 = completed). Crash-orphan downloads may remain in private
`%TEMP%\KASA-update-<32 hex>` folders; do not run them manually. Close KASA and all
installers before manually removing only a confirmed updater download directory.

GUI/clean-machine association and A-to-B acceptance must still be performed.
