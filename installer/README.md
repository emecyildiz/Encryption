# Building the KASA installer

The installer is built with Inno Setup 6 or newer after the standalone Release
folder has been generated.

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\KASA.iss
```

The current compiler configuration writes `KASA-Setup-1.1.0-test.3.exe` to the
repository's `dist` folder and expects `dist/KASA-1.1.0-test.3-windows-x64`
to contain the application, runtime DLLs, license notices and test guide.
The optional association registers an Open with handler for authenticated
read-only preview; it does not override an existing Windows default-app choice.
Before publishing a new version, update `MyAppVersion`, `PackageDirectory`, and
`VersionInfoVersion` in `KASA.iss`, rebuild the standalone Release folder, and
test install, launch, and uninstall flows on Windows.

The installer is currently unsigned. Windows may therefore display an unknown
publisher warning until the project uses a trusted code-signing certificate.

Test B includes the version-named static helper `KASA-Updater-1.1.0-test.3.exe`.
Package runtime DLLs and nlohmann-json's MIT notice, but NEVER publisher utilities,
test probes, private keys or backups. Sign the completed Setup EXE using the
publisher utility and verify metadata/payload against the compiled public key.
The `.kasa` association enhancement is included in this local Test B candidate.

## Test B association source preparation (not yet released)

The current installer source now selects association by default on a fresh install
and labels it Recommended. `UsePreviousTasks=yes` preserves the previous choice
on upgrades, including an explicit opt-out. Recommended is installer wording,
not a promise about the label Windows displays in its app chooser.

Only an extension with no merged HKCR default value and no current-user UserChoice
key receives a KASA default. Existing defaults remain untouched; OpenWith remains
available. Uninstall removes the extension default only if it still equals KASA's
ProgID, never the extension tree, another default, or UserChoice.

Before Test B publication, validate in an isolated Windows environment:
- Fresh install with an unassigned `.kasa` extension.
- Existing other-app default/UserChoice remains unchanged.
- Test A upgrade with both previous selected and unselected association choices.
- Uninstall after assigning another app preserves its selection and documents.
- Quoted/Unicode file paths still open the small password/preview window.

The local Test B candidate is version `1.1.0-test.3`. Its Release build, all 23
CTest groups and 8 installer contract checks passed. This is not Windows GUI or
upgrade acceptance. Local candidate artifacts are preserved separately under
`dist/test-b-preparation`; Test A release assets must not be replaced.
Signed update metadata is prepared and verified against the pinned Ed25519 key,
installer size and SHA-256. Publication is still pending. The manifest expires
30 days after signing; revalidate its time window before publication, and generate
fresh metadata in a new directory if necessary. This is not Authenticode signing.
See `README-TEST-B.md` in the repository root for the user test procedure.

Reference: https://jrsoftware.org/ishelp/topic_setup_useprevioustasks.htm
