$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $root "src/OpenPGP-Quantum-Guard.ps1"
$configPath = Join-Path $root "config/openpgp_quantum_guard.config.example.json"

# Parse without executing the interactive application.
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { throw ($errors | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" } | Out-String) }
Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json | Out-Null

# Publication guardrails. Generic example placeholders remain permitted.
$forbidden = @(
    '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    '[A-Za-z]:\\Users\\',
    '[A-Za-z]:\\Misc\\',
    'protonmail\.',
    'PQC-is-fun'
)
$hits = Select-String -Path $scriptPath,$configPath -Pattern $forbidden
if ($hits) { throw "Publication guardrail failed at: $($hits.Path):$($hits.LineNumber)" }

Write-Host "Static checks passed."
