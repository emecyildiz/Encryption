# KASA Demo Script

Target length: 2 minutes 35 seconds. Keep the final upload below 3 minutes.

## 0:00-0:15 - The problem

**Visual:** Open KASA on the empty workspace.

**Narration:**

"Personal file encryption is often either intimidating or tied to a cloud
workflow. KASA is a local-first Windows app that makes authenticated file
protection understandable without sending the file off the device."

## 0:15-0:40 - Add files and explain the workspace

**Visual:** Drag two synthetic demo files into Sources. Show the file count and
total size.

**Narration:**

"I can browse, add a folder, or drag files directly into the source card. KASA
keeps references to the original files, shows the total workload, and prepares
new outputs instead of encrypting the source in place."

## 0:40-1:05 - Protect with AES-256-GCM

**Visual:** Type a prepared demo password, show the strength meter, leave
AES-256-GCM selected, click Protect Files, and save the outputs.

**Narration:**

"The default is AES-256-GCM. A random salt and nonce are created for every file,
the password-derived key never needs to be stored, and authentication metadata
is checked before an output is accepted. The operation happens locally."

## 1:05-1:28 - Inspect the KASA format

**Visual:** Clear the list and drag one new `.kasa` file back into Sources. Pause
on the AES-256-GCM and format-version label.

**Narration:**

"The file identifies itself through a compact versioned footer. KASA detects
AES-256-GCM and format version one automatically. Renaming an arbitrary file to
dot-kasa is not enough; unsupported footers are rejected before the unlock
workflow starts."

## 1:28-1:52 - Demonstrate safe failure

**Visual:** Choose a destination folder, enter a wrong password, and click Unlock
Files. Show the failed result and confirm that no decrypted output was accepted.

**Narration:**

"A wrong password is a normal failure case, not an afterthought. GCM
authentication fails, the temporary plaintext is removed, and no destination
file is published. Modified ciphertext is handled the same way."

## 1:52-2:08 - Successful recovery

**Visual:** Enter the correct password, unlock again, and open the restored file.

**Narration:**

"With the correct password, authentication succeeds and KASA atomically exposes
the restored file at the selected destination."

## 2:08-2:32 - Codex and GPT-5.6

**Visual:** Show a quick montage of the source tree, automated test output, and
the Codex session.

**Narration:**

"I built KASA with Codex and GPT-5.6 as an engineering partner. Codex helped me
reason about authenticated formats, temporary-file safety, streaming tradeoffs,
native Windows UI behavior, and a regression suite covering round trips, wrong
passwords, tampering, and invalid footers. It accelerated both the implementation
and the decisions behind it."

## 2:32-2:35 - Close

**Visual:** Return to the KASA hero screen and project name.

**Narration:**

"KASA: your files, your device, your control."

## Recording checklist

- Use only synthetic demo files with no personal information.
- Pre-create an empty destination folder.
- Keep the demo password in a private note for consistent typing.
- Record at 1080p and keep the application large enough for labels to be read.
- Hide desktop notifications and unrelated windows.
- Do not speed up the wrong-password result so much that judges miss it.
- Show Codex/GPT-5.6 use explicitly and mention both names in narration.
- Confirm the final public YouTube upload is shorter than three minutes.
