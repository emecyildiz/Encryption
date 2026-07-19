# Building the KASA installer

The installer is built with Inno Setup 6 or newer after the standalone Release
folder has been generated.

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\KASA.iss
```

The compiler writes `KASA-Setup-1.0.0.exe` to the repository's `dist` folder.
Before publishing a new version, update `MyAppVersion`, `PackageDirectory`, and
`VersionInfoVersion` in `KASA.iss`, rebuild the standalone Release folder, and
test install, launch, and uninstall flows on Windows.

The installer is currently unsigned. Windows may therefore display an unknown
publisher warning until the project uses a trusted code-signing certificate.
