# Update verification contract (development)

Test A (1.1.0-test.2) integrates release checking, signed preparation and
user-approved installer handoff. Historical package entries below record the
incremental implementation; the current release state is recorded at the end.

## Trust boundary

The initial installed application must embed a trusted Ed25519 public key. Its
private counterpart belongs only to the publisher and must never be committed,
bundled, uploaded as a release asset, or obtained by the client from GitHub.
GitHub/TLS authenticate transport; SHA-256 detects payload changes; the detached
Ed25519 signature authenticates the descriptor against the pinned publisher key.
This does not replace Windows Authenticode and does not remove SmartScreen warnings.

`verify_manifest` uses the OpenSSL PureEd25519 one-shot verification API, with no
external digest: https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ED25519/

## Wire format

The descriptor is at most 8192 bytes of UTF-8 JSON. Its detached signature is
exactly 64 raw binary bytes over the exact descriptor bytes. Do not pretty-print,
change line endings or reserialize the descriptor after signing. No BOM is emitted
by the future publisher tool. Unknown or duplicate fields are rejected.

Exactly these ten root properties are required:

| Property | Contract |
| --- | --- |
| schema | Integer 1 |
| product | `KASA` |
| platform | `windows-x64` |
| version | Canonical `MAJOR.MINOR.PATCH[-test.NUMBER]`, without `v` |
| prerelease | Boolean consistent with the version suffix |
| asset | Exactly `KASA-Setup-<version>.exe`; no URL or path |
| size | Integer 1..268435456 bytes |
| sha256 | 64 lowercase hexadecimal characters |
| issued_at | Nonnegative Unix seconds |
| expires_at | Unix seconds, strictly after issued_at, at most 30 days later |

The signature is checked before JSON parsing. The descriptor must match the
release selected by the client and pass the same channel/no-downgrade policy as
availability discovery. Future-issued descriptors allow only 300 seconds of
clock tolerance. Expiry uses the local wall clock; it cannot prevent an attacker
who also controls that clock from replaying otherwise valid metadata.

The 30-day lifetime requires an explicit publisher renewal procedure. Do not ship
Test A without deciding how expired metadata and old clients will be supported.

## Payload and handoff

`verify_payload` streams bytes through SHA-256 in 64 KiB blocks and rejects short,
appended, altered and failed reads. It does not open, download, delete, or execute
files. A successful result is not permission to execute an arbitrary path later.
The future downloader/handoff must bind verification to an exclusively held file,
reject reparse-point/path replacement, check install destination and running work,
and obtain explicit user approval. Closing the handle and later running the same
path without protection leaves a time-of-check/time-of-use race.

No silent fallback to unsigned/hash-only installation is allowed. Portable and
installed distributions need separate handling. A malformed descriptor or key
failure leaves the current application and user data untouched.

## Outstanding release gate

### Package 39: constrained transport (implemented, not yet wired into the UI)

`update_download` constructs only canonical release URLs in the fixed
`emecyildiz/Encryption` repository. It accepts the version-matching installer,
`KASA-update.json`, or `KASA-update.sig`. HTTPS certificate validation stays on.
Automatic redirects, cookies and HTTP authentication are disabled; up to three
redirects are followed manually, exclusively to the HTTPS
`release-assets.githubusercontent.com/github-production-release-asset/` endpoint.
Other hosts, credentials, fragments, non-443 ports and HTTP are rejected.

Reads use 64 KiB chunks, a caller-supplied byte limit (at most 256 MiB), 5-second
WinHTTP phase timeouts and a cooperative 120-second deadline. This is not a hard
120-second wall-clock guarantee: an in-progress synchronous call completes or
times out before cancellation/deadline is inspected again. HTTP/system errors
are numeric; signed CDN query URLs are not logged.

`download_verified_payload` requires a `VerifiedManifest` and enforces signed
size and SHA-256 while streaming. The staging sink can receive untrusted bytes
before the final hash is known. ALL failure paths must discard staging; only a
successful final result permits the next verification/handoff step. This layer
does not create files or launch processes. Production locked staging, cleanup,
fresh manifest revalidation and installer handoff remain open.

Tests: 32 deterministic checks; 19/19 full CTest suite. A live transport-only smoke
test received HTTP 200 and 5,235,824 bytes from the existing Test 1 installer;
all bytes were discarded. This does not constitute live signed-manifest or
installer acceptance. No production signing key has been created.

Microsoft WinHTTP option reference:
https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags

### Package 40: private staging and preparation pipeline

`prepare_update` reads bounded descriptor/signature assets, authenticates them
against a supplied pinned public key, then calls `stage_update`. No payload is
requested after invalid signature/expiry/channel validation. Tests use a fake
transport and real ephemeral Ed25519 signatures; no production key is pinned yet.

Staging requires an existing absolute local root. Its directory chain is opened
without delete sharing and reparse points are rejected. A random 128-bit directory
name is created with a protected DACL granting the current user and SYSTEM access.
The package is created with CREATE_NEW and exclusive write access: existing files
are not overwritten. Data is streamed, flushed, then reopened under a retained
read-only sharing lock. Any substitution in the write-close/read-open gap must
pass a fresh size/SHA-256 check under the read lock. Reparse files and multiple
hard links are rejected. Parent directory handles remain alive with the package.

`StagedUpdate::may_handoff` requires explicit approval, no active operation, no
pending output, a currently valid signed descriptor and a fresh locked-file hash.
It does not start a process. The eventual helper must preserve these locks while
the main app exits and the installer starts; a successful boolean is not a durable
authorization to run a path after destroying this object.

RAII makes a best-effort cleanup of only the owned installer and empty owned
directory. `discard()` reports incomplete cleanup; failure paths mention cleanup
errors. Unknown files are never recursively deleted. A crash/power loss can leave
private staging behind; startup orphan recovery is not implemented. This is not a
security boundary against an administrator or arbitrary code already executing
as the same user (including process-handle duplication/injection).

Validation: 47 staging/pipeline checks and 20/20 CTest groups pass in the normal
Windows user environment. The restricted agent sandbox returns access denied
when pinning ancestors, so the same suite was rerun with normal-user permissions,
without weakening the checks. Tests cover writer/deleter/renamer exclusion,
read-only access, expiry/approval/busy/pending gates, partial/cancelled/bad downloads,
isolated concurrent staging and preservation of unrelated files. No installer
was executed and no GUI acceptance was claimed.

Microsoft file-sharing reference:
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

### Package 41: background preparation controller

`UpdatePreparation` owns the worker and staged package. The UI can consume a
thread-safe status snapshot (phase, payload bytes/total, bounded static status
text and numeric HTTP/system error). Metadata bytes are excluded from progress.
Preparation requests copy the selected version/channel/root and public trust key;
no private key belongs in this object. An empty trust root is rejected.

Only an Idle job can start. Ready packages cannot be silently replaced. Reset
refuses active work; cancellation is cooperative, and destruction requests cancel
then joins before resources disappear. Cancelling an already-ready package
discards it. Worker-completion/cancellation publication is synchronized.

`take_ready` transfers unique ownership once, only after the approval/busy/pending/
expiry/locked-hash gates. The final hash is synchronous and must be invoked by the
future installer controller off the GUI thread. `Transferred` does not mean
installed: no process is launched here. Start/reset/take_ready are single-owner
operations; only snapshot and cancel support concurrent calls. The caller must
retain the transferred StagedUpdate and its locks until a safe helper handoff.

37 lifecycle checks and all 21 CTest groups pass in the normal Windows user
environment. The concrete ImGui bindings, production trust root, publisher tool
and installer helper remain unimplemented. No user-facing EXE has been released.

### Package 42: preparation UI bindings

The Updates tab now starts the background preparation job, displays payload
progress and numeric errors, supports cooperative cancellation/reset, and allows
discarding a verified package. Selection is locked while preparing or holding a
package. No installer is launched and downloading does not close KASA.

`KASA_UPDATE_PUBLIC_KEY_HEX` is a build-time PUBLIC key setting: exactly 64
lowercase hexadecimal characters, not all zero. Its default is empty. The UI
explicitly disables preparation without this trust root; metadata checks remain
available. No production key was generated and verification is never bypassed.

Build and 22/22 CTest groups passed, including 23 UI policy checks. This is source
integration, not visual GUI acceptance or a new user-facing executable release.

### Remaining integration

- Publisher key creation, protected storage outside the repository/OneDrive,
  recovery backup, pinned public-key integration and rotation/revocation policy.
- Publisher signing tool, immutable versioned assets, metadata renewal policy.
- Visually validate preparation controls, keep staged locks across the
  helper process handoff, and implement installer result/restart handling.
- Define safe orphan-staging recovery and surface explicit cleanup warnings.
- Consent UI, busy/unsaved-output guard, restart and failed-install recovery.
- Test A is published first; Test B only after the user confirms A is installed.

Tests generate ephemeral in-memory keys. They are not production credentials.

## Test A integration — 19 September 2026

The compiled public trust root is
`ba6cb46d90a411d4641a952058d7e97cd5cfebb6a3a2de2d8975745053daf745`.
The private key is stored separately from the repository and OneDrive using
Windows current-user DPAPI and a current-user/SYSTEM protected file ACL.
No private key is distributed or uploaded. Publisher tooling is not included
in user ZIP/installer packages. Authenticode remains a separate, unsatisfied
Windows publisher-reputation concern.

`kasa_publisher init` creates a key only in an empty slot; `public` prints only
the public key. `sign VERSION INSTALLER OUTPUT_DIRECTORY` holds the installer
read-locked, emits bounded exact-byte Ed25519 metadata, and never overwrites
existing metadata. Both metadata files must be verified before publishing.
`export ENCRYPTED_PEM` prompts for a backup passphrase locally (not argv).
`import ENCRYPTED_PEM` restores to an empty key slot on a new Windows account.
Use a long random passphrase. Merely copying the DPAPI file to USB is NOT a
portable recovery backup; export the encrypted PEM while this account works.
The owner elected to keep the key on this PC and make a USB backup later.

Metadata lifetime is 30 days. To renew, re-sign the SAME immutable installer
in a new output directory, verify it, then replace only its descriptor/signature
assets as a pair. A transient mismatch fails closed; clients can retry. Never
replace installer bytes under an existing version. Expired metadata leaves the
installed app intact and prevents installation. Key loss requires manual trusted
reinstallation; key compromise requires stopping releases and an out-of-band
replacement installer. No automatic remote key rotation is accepted in Test A.

After explicit approval and no active/pending file work, a background worker
rehashes the package under its lock. A version-named static helper inherits only
allowlisted duplicated file/directory locks, a parent synchronization handle,
and a readiness event. It acknowledges readiness, waits for the parent to exit
(90 seconds maximum), checks descriptor expiry, and directly starts the locked
installer without a shell or elevation. It keeps the locks until installer exit.
The installer is interactive. Its finish page can launch the new application.
The helper records the numeric exit code, then deletes only its owned installer
and empty staging directory; unrelated contents are not recursively removed.

Automatic handoff requires the running path to match the current-user registered
KASA install location. Portable/development copies cannot invoke it. A cancelled
or failed setup does not trigger automatic retry/downgrade. Reopen KASA or rerun
the official installer; automatic binary rollback is not implemented. Crashes
may leave staging downloads; conservative manual cleanup is documented in the
Test A guide instead of automatic deletion of uncertain files.

Validation: full automated suite plus a benign real-process handoff probe, with
ephemeral test signing keys. Probe confirms child execution after parent exit
and staging cleanup. GUI/clean-machine installer acceptance is assigned to the
owner after Computer Use denied the preview application. This is why Test A
remains a prerelease. Test B is explicitly NOT published with Test A.

Publisher PEM API reference: https://docs.openssl.org/3.4/man3/PEM_read_bio_PrivateKey/
