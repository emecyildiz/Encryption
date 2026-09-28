param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$helper=Get-Content (Join-Path $Root 'update_helper.cpp') -Raw
$installer=Get-Content (Join-Path $Root 'installer/KASA.iss') -Raw
$checks=@{
 'New install brand directory'=$installer.Contains('DefaultDirName={localappdata}\Emecworks\{#MyAppName}')
 'Visible progress'=$helper.Contains('/KASAUPDATE=1 /SILENT /SP- /NORESTART')
 'No forced app close'=$helper.Contains('/NOCLOSEAPPLICATIONS')
 'Restart exit distinguished'=$helper.Contains('/RESTARTEXITCODE=3010')
 'No suppression flags'=($helper -notmatch '/SUPPRESSMSGBOXES|/VERYSILENT|/FORCECLOSEAPPLICATIONS')
 'No task override'=($helper -notmatch '/TASKS=|/MERGETASKS=')
 'Previous tasks'=$installer.Contains('UsePreviousTasks=yes')
 'Previous directory'=$installer.Contains('UsePreviousAppDir=yes')
 'Existing install gate'=$installer.Contains("'InstallLocation', PreviousInstallDir")
 'Path gate'=$installer.Contains('function PrepareToInstall') -and $installer.Contains('ExpandFileName(PreviousInstallDir)')
 'Normal launch retained'=$installer.Contains('Flags: nowait postinstall skipifsilent')
}
foreach($name in $checks.Keys){if(-not $checks[$name]){throw "Contract failed: $name"}}
Write-Output "PASS: $($checks.Count) source contract checks; not runtime/GUI acceptance"
