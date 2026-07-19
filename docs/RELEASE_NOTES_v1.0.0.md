## KASA v1.0.0

The first public release of KASA, a local-first Windows desktop application for
authenticated file protection.

### Highlights

- AES-256-GCM authenticated file encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- Wrong-password and tamper detection
- Automatic `.kasa` cipher and format-version detection
- Multi-file and recursive-folder workflows
- Password-strength guidance
- Selected file count and total-size summary
- Virtualized file lists for large batches
- Safe cancellation after the current file
- Authenticated XOR learning mode
- Fully local processing with no file uploads

### Downloads

**Recommended:** Download `KASA-Setup-1.0.0.exe` for the standard Windows
installation experience, Start menu integration, an optional desktop shortcut,
and clean uninstallation.

**Portable:** Download `KASA-1.0.0-windows-x64.zip`, extract the complete
archive, and run `KASA.exe`. The DLL files beside the executable are required.

### Verification

```text
KASA-Setup-1.0.0.exe
SHA-256: F522A3723553DFFD975E6B56C38CC51CB95B8EC32F63CE400E9755A5CD826409

KASA-1.0.0-windows-x64.zip
SHA-256: F7AA221D7813C950B74FCBE0DAA933606DA6939547BC573F29BE77E01E2899A5
```

### Security notice

KASA has not received an independent security audit. Keep backups of
irreplaceable files and review `docs/SECURITY.md` before using the application
with important data.

The current Windows binaries are not code-signed. Windows may display an
unknown publisher warning.

### Platform

- Windows 10 x64
- Windows 11 x64

### License

MIT License. Third-party copyright notices are included with each distribution.
