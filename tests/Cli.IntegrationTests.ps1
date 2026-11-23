#requires -Version 5.1
<#[.SYNOPSIS
Runs CLI v1.2 against an explicitly supplied disposable GnuPG home.
No keys are created, imported, exported, or deleted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$GpgHome,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$HybridFingerprint,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ClassicalFingerprint
)
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/OpenPGP-Quantum-Guard.Cli.ps1'
if (-not (Test-Path -LiteralPath $GpgHome -PathType Container)) { throw 'GpgHome does not exist' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('oqg-cli-v12-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
function Invoke-CliTest([object[]]$argList) {
    # Windows PowerShell 5.1 does not reliably bind option-name strings
    # splatted from a positional array to script named parameters.
    # Convert the controlled test arguments into named parameter splatting.
    if ($argList.Count -lt 1) { throw 'Missing CLI command' }
    $named = @{ Command = [string]$argList[0] }
    $switchNames = @('Json', 'RequirePqc')
    $valueNames = @('GpgHome', 'Fingerprint', 'InputPath', 'OutputPath', 'ConfigPath', 'GpgPath')
    for ($i = 1; $i -lt $argList.Count; $i++) {
        $option = [string]$argList[$i]
        if (-not $option.StartsWith('-')) { throw "Unexpected CLI test argument: $option" }
        $name = $option.TrimStart('-')
        if ($switchNames -contains $name) {
            $named[$name] = $true
        } elseif ($valueNames -contains $name) {
            if ($i + 1 -ge $argList.Count) { throw "Missing value for: $option" }
            $i++
            $named[$name] = [string]$argList[$i]
        } else {
            throw "Unknown CLI test option: $option"
        }
    }
    $lines = @(& $cli @named)
    $code = $LASTEXITCODE
    if ($lines.Count -ne 1) { throw "Expected one JSON output line, received $($lines.Count)" }
    $data = $lines[0] | ConvertFrom-Json
    if ($data.schema -ne 'openpgp-quantum-guard-cli-v1') { throw 'Unexpected schema' }
    return [pscustomobject]@{ ExitCode=$code; Json=$data }
}
try {
    $inspect = Invoke-CliTest -argList @('Inspect','-GpgHome',$GpgHome,'-Json')
    if ($inspect.ExitCode -ne 0) { throw 'Inspect failed' }
    $hybrid = @($inspect.Json.data.keys | Where-Object { $_.fingerprint -eq $HybridFingerprint })
    $classical = @($inspect.Json.data.keys | Where-Object { $_.fingerprint -eq $ClassicalFingerprint })
    if ($hybrid.Count -ne 1 -or $classical.Count -ne 1) { throw 'Specified keys not both found' }
    if (@($hybrid[0].subkeys | Where-Object { $_.algorithmName -eq 'ky768_cv25519' -and $_.pqcHybrid -eq $true }).Count -eq 0) {
        throw 'Hybrid subkey not positively classified from GnuPG listing'
    }
    $plain = Join-Path $work 'original.txt'
    $cipher = Join-Path $work 'hybrid.gpg'
    $recovered = Join-Path $work 'recovered.txt'
    $rsaCipher = Join-Path $work 'classical-allowed.gpg'
    $blocked = Join-Path $work 'classical-blocked.gpg'
    [IO.File]::WriteAllText($plain,'OpenPGP Quantum Guard CLI v1.2 test', [Text.Encoding]::UTF8)
    $encrypt = Invoke-CliTest -argList @('Encrypt','-GpgHome',$GpgHome,'-Fingerprint',$HybridFingerprint,'-InputPath',$plain,'-OutputPath',$cipher,'-RequirePqc','-Json')
    if ($encrypt.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $cipher)) { throw 'Hybrid encryption failed' }
    $decrypt = Invoke-CliTest -argList @('Decrypt','-GpgHome',$GpgHome,'-InputPath',$cipher,'-OutputPath',$recovered,'-Json')
    if ($decrypt.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $recovered)) { throw 'Hybrid decryption failed (pinentry/agent may be required)' }
    if ((Get-FileHash $plain -Algorithm SHA256).Hash -ne (Get-FileHash $recovered -Algorithm SHA256).Hash) { throw 'SHA256 mismatch' }
    $allow = Invoke-CliTest -argList @('Encrypt','-GpgHome',$GpgHome,'-Fingerprint',$ClassicalFingerprint,'-InputPath',$plain,'-OutputPath',$rsaCipher,'-Json')
    if ($allow.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $rsaCipher)) { throw 'Classical control is not usable; cannot attribute policy rejection' }
    $deny = Invoke-CliTest -argList @('Encrypt','-GpgHome',$GpgHome,'-Fingerprint',$ClassicalFingerprint,'-InputPath',$plain,'-OutputPath',$blocked,'-RequirePqc','-Json')
    if ($deny.ExitCode -ne 4 -or $deny.Json.code -ne 'PQC_POLICY_REJECTED' -or (Test-Path -LiteralPath $blocked)) { throw 'PQC rejection/exit code failed' }
    $unsafe = Invoke-CliTest -argList @('Encrypt','-GpgHome',$GpgHome,'-Fingerprint',$HybridFingerprint,'-InputPath',$plain,'-OutputPath',$cipher,'-RequirePqc','-Json')
    if ($unsafe.ExitCode -ne 2 -or $unsafe.Json.code -ne 'OUTPUT_UNSAFE') { throw 'Existing output overwrite guard failed' }
    $invalid = Invoke-CliTest -argList @('Encrypt','-GpgHome',$GpgHome,'-Fingerprint','bad','-InputPath',$plain,'-OutputPath',(Join-Path $work 'invalid.gpg'),'-Json')
    if ($invalid.ExitCode -ne 2) { throw 'Invalid fingerprint should exit 2' }
    Write-Output 'PASS: JSON, PQC classification, round-trip SHA256, RSA control, policy exit 4, overwrite protection, invalid fingerprint'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
