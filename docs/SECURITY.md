# KASA Security Model

## Scope

KASA is a local-first desktop file-protection application. File contents are
processed on the user's Windows device and are not sent to a server by KASA.
The default protection mode is AES-256-GCM authenticated encryption.

KASA is a competition project and has not received an independent security
audit. Users should keep backups of irreplaceable data and should not treat a
development build as their only recovery path.

## AES-256-GCM format

The current KASA format version is `1`.

```text
[16-byte salt]
[12-byte nonce]
[ciphertext]
[16-byte GCM authentication tag]
[4-byte "KASA" magic][1-byte format version][1-byte cipher identifier]
```

- The 256-bit encryption key is derived from the password with
  PBKDF2-HMAC-SHA256 and 100,000 iterations.
- Every encryption operation generates a random 16-byte salt and a random
  12-byte GCM nonce with OpenSSL's cryptographic random generator.
- The salt, nonce, and footer are supplied to GCM as additional authenticated
  data.
- Decryption is accepted only if the GCM authentication tag is valid.
- AES decryption first authenticates the entire input in bounded, wiped scratch
  memory without creating an output file. A second pass writes the plaintext to
  a temporary file and verifies the tag again before publishing the destination.
- Both passes use the same Windows input handle, allowing only read sharing.
  Ordinary concurrent writers and delete/rename operations are excluded; an
  existing conflicting writer makes the operation fail closed.
- This is not protection against raw disk access, kernel compromise, or all
  memory-mapped mutation scenarios. Successful authenticated decryption still
  creates plaintext; interruption during its second pass can leave a temporary
  plaintext file. No whole-machine no-plaintext-on-disk guarantee is made.

## XOR learning format

XOR mode exists for educational comparison and is visibly labelled as a
learning mode. It is not recommended for normal file security.

```text
[XOR ciphertext]
[16-byte salt]
[32-byte HMAC-SHA256 tag]
[4-byte "KASA" magic][1-byte format version][1-byte cipher identifier]
```

PBKDF2-HMAC-SHA256 derives separate 256-bit encryption and authentication keys.
The ciphertext, salt, and footer are authenticated with HMAC-SHA256. The HMAC
is checked before decrypted output is accepted.

## Failure behavior

- AES and XOR decryption create an exclusive temporary output and mark its
  handle for deletion before writing plaintext. Handled failures and process
  exit close the handle and normally remove the incomplete output. Plaintext
  writes use unbuffered stdio to avoid an additional CRT-owned plaintext buffer.
  Only authenticated, finalized and flushed output is published by renaming its
  existing handle without replacing a destination. Clearing the deletion mark
  and renaming are not atomic: a crash in that interval can retain COMPLETE
  plaintext at the temporary name. OS crashes/power loss, filesystem/driver
  failures, disk remnants, snapshots and synced copies are not covered.
  This is logical cleanup, not guaranteed secure erasure.

  Windows semantics: [Microsoft's delete-disposition explanation](https://devblogs.microsoft.com/oldnewthing/20260706-00/?p=112506)
  and [handle cleanup on termination](https://learn.microsoft.com/en-us/windows/win32/fileio/closing-and-deleting-files).

- Delayed Save/Save All copies staged output into an exclusively created random
  temporary file beside the destination, flushes it and compares a full readback
  byte-for-byte with the staging input. The owned handle is renamed without
  replacing an existing destination, then flushed again. Only success permits
  the UI to attempt optional original-source deletion. The staging copy remains
  until normal session cleanup. On a post-publication failure both copies remain
  and the operation reports failure; retry requires a different destination name.
- These flush/readback checks are not a physical power-loss guarantee: reads
  may be served from cache, storage devices can misreport persistence, and a
  process crash can leave an intermediate file. This path covers delayed saves,
  not a new durability guarantee for every direct beside-source crypto output.

- Optional source deletion records the source file identity, size, last-write
  time and SHA-256 while the crypto operation holds a read-sharing input handle.
  Before overwriting, the source is opened exclusively and compared with that
  record. Changed, replaced, multiply linked, reparse-point or busy sources are
  not overwritten. Verification, overwrite and delete disposition use the same
  handle. The UI retains this record through delayed Save and Save All actions.
- A failed deletion keeps the saved output and reports a warning. An I/O error
  during an overwrite can still leave a partially overwritten source: this is
  not a transactional erase. Raw disk/kernel access and pre-existing writable
  memory mappings are outside the concurrency guarantees.

- A wrong password does not produce an accepted destination file.
- Modified authenticated data or ciphertext is rejected.
- An unsupported footer version or cipher identifier is rejected before the
  file is added to an unlock workflow.
- Existing destination files are not overwritten silently.
- Encryption writes to a temporary file and renames it only after the output is
  finalized successfully.

## Known limitations

- KASA does not provide password recovery. Losing the password means losing
  access to the encrypted contents.
- The original filename remains visible because protection appends `.kasa` to
  the filename. Filename privacy is not currently a goal of format version 1.
- File size is not hidden.
- The password-strength indicator is guidance, not a formal entropy estimate.
- The optional source-deletion feature performs one best-effort overwrite pass
  before deletion and refuses to overwrite files with multiple hard links. This
  can reduce simple recovery on conventional HDDs, but it is not guaranteed
  secure erasure. It cannot remove copies retained by SSD wear levelling,
  copy-on-write file systems, backups, synchronized folders, or recovery tools.
- Files are protected individually. When a folder is selected, KASA recreates
  its relative directory tree at the chosen destination, but it does not package
  that tree into a single encrypted archive and does not preserve empty folders.
- KASA currently targets Windows 10 and Windows 11.

## Reporting a security issue

Do not publish passwords, plaintext test files, or sensitive encrypted samples
in a public issue. Provide a minimal synthetic reproduction and identify the
KASA format version involved.
