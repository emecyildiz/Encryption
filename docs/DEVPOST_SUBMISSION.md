# KASA - Devpost Submission Draft

## Tagline

Protect personal files locally with authenticated encryption and a workflow
people can understand.

## Track

Apps for your life

## Inspiration

People often have to choose between complicated encryption utilities and cloud
services that require their files to leave the device. KASA started from a
simple question: can strong local file protection feel as clear as moving a file
between two panels?

The project also grew from learning modern C++ by building a real application.
That made transparent engineering important: the interface should explain what
will happen, the file format should identify itself, and failure cases such as a
wrong password must be treated as core product behavior rather than edge cases.

## What it does

KASA is a Windows desktop application that protects files locally with
AES-256-GCM. Users add files or folders by browsing or drag and drop, enter a
password, and save authenticated `.kasa` outputs wherever they choose.

When a `.kasa` file is added, KASA automatically reads its footer, identifies
the format version and cipher, and switches to the unlock workflow. Wrong
passwords, modified ciphertext, unsupported formats, and invalid authentication
tags are rejected without publishing partial decrypted output.

The interface also shows the selected file count and total size, password
strength guidance, per-file status, save state, and security metadata. Files are
not uploaded by KASA.

## How we built it

- C++20
- OpenSSL 3 for AES-256-GCM, PBKDF2-HMAC-SHA256, secure randomness, and HMAC
- Dear ImGui for the custom two-panel desktop experience
- GLFW, OpenGL, and GLEW for windowing and rendering
- CMake, CTest, and vcpkg for reproducible builds and regression tests
- Codex with GPT-5.6 as a collaborative engineering partner

The encrypted file format uses an explicit six-byte footer containing the KASA
magic, format version, and cipher identifier. AES outputs contain a random salt,
random nonce, ciphertext, GCM tag, and footer. Sensitive output is written to a
temporary file and exposed at the destination only after the operation succeeds.

## How Codex and GPT-5.6 accelerated the project

Codex was used throughout the main implementation session, not only for final
polish. It reviewed the original file-processing design, helped reason through
streaming and memory tradeoffs, identified unsafe in-place behavior, designed
authenticated temporary-output workflows, implemented and debugged the desktop
UI, investigated native Windows window behavior, and built the automated
security regression suite.

The most valuable collaboration happened around decisions rather than code
volume: distinguishing encryption from authentication, choosing what belongs in
authenticated metadata, ensuring wrong-password failures leave no accepted
plaintext, and keeping the app's local-only promise instead of adding an
unnecessary online AI dependency.

## Challenges

- Designing a versioned format that can select the correct decryption path.
- Making wrong-password and tamper detection safe for streamed files.
- Keeping source files untouched until a complete output has been finalized.
- Building a custom modern Windows interface while preserving native window
  dragging, responsive multi-file lists, and background processing.
- Packaging a C++ application with all required runtime dependencies for judges.

## Accomplishments

- Authenticated AES-256-GCM protection and automatic format detection.
- An educational XOR mode with separate derived keys and HMAC-SHA256.
- Regression tests for binary and empty-file round trips, wrong passwords,
  modified ciphertext, invalid footers, and automatic cipher detection.
- A compact standalone Windows Release package with third-party license notices.
- A tested per-user Windows installer with shortcuts and clean uninstallation.
- A coherent local-first interface rather than a command-line proof of concept.

## What we learned

Encryption alone is not enough: integrity, output lifecycle, metadata design,
and error behavior determine whether a file-protection workflow is trustworthy.
We also learned that product quality includes packaging, documentation, and
reproducible failure tests, not just a successful demo path.

## What's next

- Preserve directory structures and optionally package folders as one vault.
- Add cancellation within a large individual file operation.
- Introduce a memory-hard password KDF in a future versioned format.
- Add signed releases and an installer.
- Commission an independent security review before recommending production use.

## Submission checklist

- [ ] Replace this draft with the final public repository URL.
- [ ] Add the public YouTube demo URL.
- [ ] Add the Codex `/feedback` session ID.
- [x] Confirm the repository license (MIT).
- [ ] Upload tested Release assets.
- [ ] Verify that the video is public and shorter than three minutes.
- [ ] Run the final package on a clean Windows environment.
