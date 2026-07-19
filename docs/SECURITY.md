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
- Plaintext is first written to a temporary file. A failed authentication check
  removes that temporary output instead of publishing it as the destination.

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
- The optional source-deletion feature cannot guarantee forensic erasure on
  SSDs, copy-on-write file systems, backups, or synchronized folders.
- Files are protected individually. KASA does not currently preserve a complete
  directory tree as one encrypted archive.
- KASA currently targets Windows 10 and Windows 11.

## Reporting a security issue

Do not publish passwords, plaintext test files, or sensitive encrypted samples
in a public issue. Provide a minimal synthetic reproduction and identify the
KASA format version involved.
