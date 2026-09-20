# KASA 1.1.0

Windows 10/11 x64. This stable release replaces 1.0.0 as the recommended download.

## Changes since 1.0.0

- Redesigned desktop interface and readable release-channel menus.
- Password-protected read-only preview for supported .kasa content.
- Recommended optional .kasa association; existing Windows defaults are preserved.
- User-approved updates with signed metadata and verified installer downloads.
- Explicit source-deletion warnings and improved processing/preview safeguards.

## Important behavior

Decryption source deletion is ON by default after a successful save. Disable it
to retain encrypted originals. Encryption source deletion is OFF by default.
Read-only preview does not delete the encrypted file.

Updates currently launch the normal interactive installation wizard; license and
shortcut screens can appear again. A streamlined update flow and an in-app
What's New screen are planned, not included. A brief first-preview startup delay
has not been diagnosed or fixed. Portable copies do not invoke automatic install.

The EXE is not Authenticode-signed. Windows may warn about an unknown publisher;
internal Ed25519 update signatures do not remove SmartScreen warnings. This is
not an independent security audit. Keep backups and test with disposable files.

Test A-to-B update installation was confirmed by the user. Automated tests do
not establish that every Windows association/uninstall combination was tested.
