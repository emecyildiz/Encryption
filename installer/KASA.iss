#define MyAppName "KASA"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "KASA contributors"
#define MyAppURL "https://github.com/emecyildiz/Encryption"
#define MyAppExeName "KASA.exe"
#define PackageDirectory "..\dist\KASA-1.0.0-windows-x64"

[Setup]
AppId={{8AAE51C3-BD6C-495A-A0E6-15B0BF50C4A4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=KASA-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\resources\KASA.ico
CloseApplications=yes
CloseApplicationsFilter={#MyAppExeName}
RestartApplications=no
SetupLogging=yes
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=KASA local file protection installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCopyright=Copyright (c) 2026 KASA contributors

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#PackageDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
