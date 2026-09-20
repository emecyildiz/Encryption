param([string]$Installer=(Join-Path $PSScriptRoot '..\installer\KASA.iss'))
$ErrorActionPreference='Stop'
$text=Get-Content -LiteralPath $Installer -Raw
$checks=0
function Assert([bool]$Condition,[string]$Message){
    $script:checks++
    if(-not $Condition){throw $Message}
}
$task=($text -split '\r?\n' | Where-Object {$_ -match '^Name: "fileassociation";'})
Assert (@($task).Count -eq 1) 'Exactly one association task required'
Assert ($task -match 'Recommended') 'Recommended explanation missing'
Assert ($task -notmatch 'unchecked|checkedonce') 'Fresh-install default must be selected'
Assert ($text -match '(?m)^UsePreviousTasks=yes\s*$') 'Upgrade choice preservation missing'
Assert ($text.Contains('--preview ""%1""')) 'Quoted preview path argument missing'
$writes=@($text -split '\r?\n' | Where-Object {$_ -match '^Root:'})
Assert (@($writes | Where-Object {$_ -match 'UserChoice'}).Count -eq 0) 'UserChoice must never be written'
Assert ($text.Contains('Check: CanRegisterKasaDefault')) 'Default registration must be gated'
Assert ($text.Contains('KasaMayAssignDefault(') -and $text.Contains('KasaMayRemoveDefault(')) 'Tested policy must be used'
Write-Output ("PASS: $checks installer contract checks (not Windows integration tests)")
