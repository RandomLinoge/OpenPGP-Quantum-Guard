$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/OpenPGP-Quantum-Guard.Cli.ps1'
$docs = Join-Path (Split-Path -Parent $PSScriptRoot) 'docs/CLI.md'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($cli, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { throw ($errors | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" } | Out-String) }
if (-not (Test-Path -LiteralPath $docs)) { throw 'CLI docs missing.' }
$text = Get-Content -LiteralPath $cli -Raw
if ($text -match '(?i)\$home\b') { throw 'Reserved PowerShell HOME variable collision detected.' }
if ($text -match '(?i)--passphrase\b|--pinentry-mode\s+loopback') { throw 'Passphrase-handling guardrail violated.' }
if ($text -notmatch 'require-pqc-encryption') { throw 'RequirePqc binding missing.' }
if ($text -notmatch 'OUTPUT_UNSAFE') { throw 'Output overwrite guardrail missing.' }
if ($text -notmatch 'PQC_POLICY_REJECTED') { throw 'Policy-specific error missing.' }
if ($text -notmatch 'Add-SubkeyDescriptions') { throw 'Hybrid subkey classification missing.' }
if ($text -notmatch 'with-subkey-fingerprint') { throw 'Subkey fingerprint parsing missing.' }
if ($text -notmatch 'ValueFromRemainingArguments' -or $text -notmatch '\$commandIsHelp') { throw 'Literal double-dash help routing missing.' }
if ($text -notmatch 'function Get-HelpText') { throw 'Command-specific help missing.' }
if ($text -notmatch 'exit 0') { throw 'Help success exit missing.' }

# Parse the regression harness too; protect named parameter splatting on Windows PowerShell 5.1.
$integration = Join-Path $PSScriptRoot 'Cli.IntegrationTests.ps1'
$integrationTokens = $null
$integrationErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($integration, [ref]$integrationTokens, [ref]$integrationErrors) | Out-Null
if ($integrationErrors.Count -gt 0) { throw 'Integration harness has PowerShell syntax errors.' }
$integrationText = Get-Content -LiteralPath $integration -Raw
if ($integrationText -match '\&\s*\$cli\s+@argList') { throw 'Unsafe positional CLI splatting regression found.' }
if ($integrationText -notmatch '\&\s*\$cli\s+@named') { throw 'Named CLI parameter splatting not found.' }
Write-Output 'CLI static checks passed.'
