# KASA 1.2.1

Stable maintenance release following user acceptance of 1.2.0.

- Fix edge-to-edge text in What's new and Keep source files dialogs with shared modal padding and consistent headings.
- Keep release-note scrolling and its acknowledgement button in separate content areas.
- Wrap source-retention text to the available content width.
- Retain the 1.2 features: confirmation when keeping sources, fresh installations under Emecworks/KASA, user-approved signed updates and offline release notes.

Encryption, source deletion choices and the .kasa file format are unchanged. Existing encrypted files do not need conversion. Existing installation locations and choices are retained during updates.

The installer is not Authenticode-signed and Windows may show an unknown-publisher warning. KASA's Ed25519 update verification is separate from Windows code signing.
