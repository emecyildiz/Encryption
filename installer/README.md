# Building the KASA installer

The installer is built with Inno Setup 6 or newer after the standalone Release
folder has been generated.

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\KASA.iss
```

The current compiler configuration writes `KASA-Setup-1.1.0-test.2.exe` to the
repository's `dist` folder and expects `dist/KASA-1.1.0-test.2-windows-x64`
to contain the application, runtime DLLs, license notices and test guide.
The optional association registers an Open with handler for authenticated
read-only preview; it does not override an existing Windows default-app choice.
Before publishing a new version, update `MyAppVersion`, `PackageDirectory`, and
`VersionInfoVersion` in `KASA.iss`, rebuild the standalone Release folder, and
test install, launch, and uninstall flows on Windows.

The installer is currently unsigned. Windows may therefore display an unknown
publisher warning until the project uses a trusted code-signing certificate.

Test A includes the version-named static helper `KASA-Updater-1.1.0-test.2.exe`.
Package runtime DLLs and nlohmann-json's MIT notice, but NEVER publisher utilities,
test probes, private keys or backups. Sign the completed Setup EXE using the
publisher utility and verify metadata/payload against the compiled public key.
The `.kasa` association enhancement is reserved for Test B after Test A acceptance.
