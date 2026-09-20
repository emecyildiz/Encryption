{ Shared pure decisions: test harness uses the same functions as production. }
function KasaMayAssignDefault(HasUserChoice, HasDefaultValue: Boolean): Boolean;
begin
  Result := (not HasUserChoice) and (not HasDefaultValue);
end;

function KasaMayRemoveDefault(ValueWasRead: Boolean; Current: String): Boolean;
begin
  Result := ValueWasRead and (Current = 'KASA.EncryptedFile');
end;
