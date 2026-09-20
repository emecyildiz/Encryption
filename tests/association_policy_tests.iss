; Compiles/runs pure policy checks only. InitializeSetup always stops setup.
[Setup]
AppName=KASA association policy tests
AppVersion=1
CreateAppDir=no
Uninstallable=no
CreateUninstallRegKey=no
PrivilegesRequired=lowest
OutputBaseFilename=KASA-association-policy-tests
SetupLogging=no

[Code]
#include "..\installer\association_policy.iss"
var
  Checks: Integer;

procedure Expect(Condition: Boolean; Name: String);
begin
  Checks := Checks + 1;
  if not Condition then RaiseException('FAIL: ' + Name);
end;

function InitializeSetup: Boolean;
var
  Destination: String;
begin
  Result := False;
  Checks := 0;
  Destination := ExpandConstant('{param:RESULT|}');
  if (Destination = '') or FileExists(Destination) then
    RaiseException('A new result file path is required');
  Expect(KasaMayAssignDefault(False, False), 'unassigned extension');
  Expect(not KasaMayAssignDefault(True, False), 'UserChoice only');
  Expect(not KasaMayAssignDefault(False, True), 'existing merged default');
  Expect(not KasaMayAssignDefault(True, True), 'both existing choices');
  Expect(KasaMayRemoveDefault(True, 'KASA.EncryptedFile'), 'own default');
  Expect(not KasaMayRemoveDefault(False, 'KASA.EncryptedFile'), 'failed read');
  Expect(not KasaMayRemoveDefault(True, 'OtherApplication.Document'), 'changed default');
  Expect(not KasaMayRemoveDefault(True, ''), 'empty default');
  Expect(not KasaMayRemoveDefault(False, ''), 'missing default');
  if not SaveStringToFile(Destination, 'PASS: ' + IntToStr(Checks) + ' policy checks', False) then
    RaiseException('Cannot write test result');
end;
