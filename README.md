# KASA

## KASA 1.1.0 — current stable release

[Download KASA 1.1.0](https://github.com/emecyildiz/Encryption/releases/tag/v1.1.0).
Choose the Setup EXE for installation. Existing update-aware versions can use
Updates > Check now. Version 1.0.0 users must download the new installer. Updates use signed
metadata, bounded downloads and locked installer handoff; installation is never
automatic without approval. Portable copies can check releases but do not invoke
the installer automatically. See [release notes](RELEASE-NOTES-1.1.0.md).

This is a Windows release without Authenticode signing or an independent
security audit. Internal update signatures do not remove SmartScreen warnings.
Use disposable samples. Decryption source deletion is ON by default after
successful saving; encryption source deletion remains OFF. Review the red
warnings and turn deletion off when you want to retain encrypted originals.
KASA selects the Recommended `.kasa` association on fresh installs, preserves
previous choices on upgrade, and fixes release-channel popup contrast. Existing
Windows default-app choices are not overridden. The user confirmed A-to-B update
installation. The reported brief first-open delay is not fixed in this build.
Updates still show the regular installation wizard; a streamlined updater and
an in-app What's New screen are planned, not included in 1.1.0.

KASA is a local-first Windows desktop application for protecting files without
uploading them to a cloud service. It provides a focused drag-and-drop workflow,
authenticated encryption, automatic `.kasa` format detection, and explicit
control over where encrypted and decrypted outputs are saved.

## Why KASA?

Many file-protection tools expose either a complicated technical interface or a
black-box cloud workflow. KASA keeps the operation on the user's device and
presents the source files, security settings, progress, and verified outputs in
one workspace.

## Features

- AES-256-GCM authenticated encryption for normal use.
- PBKDF2-HMAC-SHA256 password-based key derivation with a random salt.
- A random 96-bit nonce for every AES-GCM encryption operation.
- Authentication-tag validation before a decrypted file is accepted.
- Automatic cipher and format-version detection from the `.kasa` footer.
- Temporary-file and atomic-rename workflows to avoid replacing a source with a
  partial output.
- Wrong-password and file-tampering detection.
- Multi-file and recursive-folder processing without uploading file contents.
- Source-adjacent output by default, with relative folder structure preserved
  when a different destination is chosen.
- Selected-file count and total-size feedback before an operation starts.
- A password-strength indicator for protection workflows.
- A virtualized source list that remains responsive with large file sets.
- Safe batch cancellation after the currently active file finishes.
- Footer inspection that displays the cipher and format version of valid `.kasa`
  files and rejects unsupported files before decryption.
- A clearly labelled authenticated XOR learning mode for educational comparison.

## Security model

KASA's default mode derives a 256-bit key from the password using
PBKDF2-HMAC-SHA256 and encrypts file data with AES-256-GCM. The salt, nonce, and
format footer are authenticated, and the output is accepted during decryption
only when the GCM authentication tag is valid.

XOR mode is included only as a learning tool. It uses independently derived
encryption and authentication keys plus HMAC-SHA256, but it is not presented as
a replacement for modern authenticated encryption.

KASA has not received an independent security audit. Do not rely on a
development build as the only copy of irreplaceable data.

## Build from source

### Requirements

- Windows 10 or Windows 11
- A C++20 compiler
- CMake 3.25 or newer
- [vcpkg](https://github.com/microsoft/vcpkg)

The repository contains a `vcpkg.json` manifest for OpenSSL, Dear ImGui, GLFW,
GLEW, and nlohmann-json. Publisher/test utilities are not user-distribution files.

```powershell
cmake -S . -B build `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

Depending on the selected CMake generator, the executable is produced as either
`build/KASA.exe` or `build/Release/KASA.exe`.

## Run the automated tests

The engine test suite covers AES and XOR binary round trips, an empty AES file,
automatic cipher and format-version detection, invalid-footer rejection,
wrong-password rejection, tamper detection, and the guarantee that rejected
decryptions do not leave an output file.

```powershell
ctest --test-dir build --output-on-failure
```

## Basic workflow

1. Add files, add a folder, or drag files into the Sources card.
2. KASA selects protection for normal files and unlock mode for `.kasa` files.
3. Enter a password and keep AES-256-GCM selected for normal protection.
4. Start the operation from the button at the bottom of the Sources card.
5. By default, KASA writes each successful output beside its source. Clear
   `Keep outputs beside their source files` to choose a different destination;
   folder selections retain their relative directory structure.

## Windows downloads

GitHub Releases provides two distribution formats:

- `KASA-Setup-1.0.0.exe` is recommended for most users. It installs KASA for
  the current Windows account, creates a Start menu shortcut, optionally creates
  a desktop shortcut, and includes an uninstaller.
- `KASA-1.0.0-windows-x64.zip` is the portable build. Extract the complete
  archive before running `KASA.exe`; the DLL files beside it are required.

The current binaries are not code-signed, so Windows may display an unknown
publisher warning.

## Build the Windows installer

After generating the standalone Release folder, compile the Inno Setup script:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\KASA.iss
```

The current test installer is written to `dist/KASA-Setup-1.1.0-test.1.exe`. See
`installer/README.md` for version-update instructions.

## Built with Codex

KASA was developed for OpenAI Build Week with Codex and GPT-5.6. Codex was used
as a collaborative engineering partner for architecture review, authenticated
file-format design, failure-mode analysis, UI implementation, debugging,
testing strategy, and release preparation. Security-sensitive design decisions
were discussed explicitly and verified with round-trip, wrong-password, and
tamper-detection tests.

## Competition track

OpenAI Build Week - **Apps for your life**.

## License

KASA is available under the [MIT License](LICENSE). Third-party components keep
their respective licenses; the standalone Release package includes their
copyright notices in its `licenses` directory.
