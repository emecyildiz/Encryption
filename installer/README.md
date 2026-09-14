# Building the KASA installer

The installer is built with Inno Setup 6 or newer after the standalone Release
folder has been generated.

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\KASA.iss
```

The current compiler configuration writes `KASA-Setup-1.1.0-test.1.exe` to the
repository's `dist` folder and expects `dist/KASA-1.1.0-test.1-windows-x64`
to contain the application, runtime DLLs, license notices and test guide.
The optional association registers an Open with handler for authenticated
read-only preview; it does not override an existing Windows default-app choice.
Before publishing a new version, update `MyAppVersion`, `PackageDirectory`, and
`VersionInfoVersion` in `KASA.iss`, rebuild the standalone Release folder, and
test install, launch, and uninstall flows on Windows.

The installer is currently unsigned. Windows may therefore display an unknown
publisher warning until the project uses a trusted code-signing certificate.
