#define MyAppName "KASA"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "KASA contributors"
#define MyAppURL "https://github.com/emecyildiz/Encryption"
#define MyAppExeName "KASA.exe"
#ifndef PackageDirectory
#define PackageDirectory "..\dist\KASA-1.1.0-windows-x64"
#endif

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
VersionInfoVersion=1.1.0.0
ChangesAssociations=yes
UsePreviousTasks=yes
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=KASA local file protection installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion=1.1.0.0
VersionInfoCopyright=Copyright (c) 2026 KASA contributors

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "fileassociation"; Description: "Open .kasa files with KASA password / read-only preview (Recommended)"; GroupDescription: "File association:"

[Registry]
; Only assign an extension with no existing default. Never write Windows UserChoice.
Root: HKCU; Subkey: "Software\Classes\.kasa"; ValueType: string; ValueData: "KASA.EncryptedFile"; Tasks: fileassociation; Check: CanRegisterKasaDefault
Root: HKCU; Subkey: "Software\Classes\.kasa\OpenWithProgids"; ValueType: string; ValueName: "KASA.EncryptedFile"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassociation
Root: HKCU; Subkey: "Software\Classes\KASA.EncryptedFile"; ValueType: string; ValueData: "KASA encrypted file"; Flags: uninsdeletekey; Tasks: fileassociation
Root: HKCU; Subkey: "Software\Classes\KASA.EncryptedFile\DefaultIcon"; ValueType: string; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassociation
Root: HKCU; Subkey: "Software\Classes\KASA.EncryptedFile\shell\open\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" --preview ""%1"""; Tasks: fileassociation

[Files]
Source: "{#PackageDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
#include "association_policy.iss"
function CanRegisterKasaDefault: Boolean;
begin
  { Preserve even an empty/non-string existing value rather than replacing it. }
  Result := KasaMayAssignDefault(
    RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.kasa\UserChoice'),
    RegValueExists(HKCR, '.kasa', ''));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('fileassociation') then
    WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
      'Double-click a .kasa file to enter its password and preview supported content. ' +
      'If Windows asks which app to use, select KASA and choose Always. ' +
      'Existing default-app choices are preserved. Preview does not delete the encrypted file.';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Current: String;
  ValueWasRead: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    ValueWasRead := RegQueryStringValue(HKCU, 'Software\Classes\.kasa', '', Current);
    if KasaMayRemoveDefault(ValueWasRead, Current) then
      RegDeleteValue(HKCU, 'Software\Classes\.kasa', '');
    { Keep the extension key, other handlers, UserChoice and encrypted documents. }
  end;
end;
