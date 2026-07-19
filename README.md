# KASA

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
and GLEW.

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
5. Review the result and choose where the output should be saved.

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
