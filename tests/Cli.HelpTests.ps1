#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/OpenPGP-Quantum-Guard.Cli.ps1'
function Assert-Help([object[]]$cliArguments, [string]$expected) {
    $output = @(& $cli @cliArguments)
    if ($LASTEXITCODE -ne 0) { throw "Help command exited $LASTEXITCODE" }
    $content = $output -join "`n"
    if ($content -notmatch [regex]::Escape($expected)) { throw "Missing help text: $expected" }
}
# Positional command help and named PowerShell -Help / --help alias are exercised
# separately, without creating files or requiring GnuPG.
Assert-Help @('Help') 'COMMANDS'
# Direct invocation is important because PowerShell 5.1 parses named flags
# differently from positional-array splatting.
$general = @(& $cli -Help)
if ($LASTEXITCODE -ne 0 -or (($general -join "`n") -notmatch 'COMMANDS')) { throw 'General -Help failed' }
$longHelp = @(& $cli --help)
if ($LASTEXITCODE -ne 0 -or (($longHelp -join "`n") -notmatch 'COMMANDS')) { throw 'General --help failed' }
$commandHelp = @(& $cli Encrypt --help)
if ($LASTEXITCODE -ne 0 -or (($commandHelp -join "`n") -notmatch 'ENCRYPT')) { throw 'Encrypt --help failed' }
$json = @(& $cli -Help -Json) -join "`n"
$parsed = $json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $parsed.success -or $parsed.data.subject -ne 'general') { throw 'JSON help failed' }
$longJson = @(& $cli --help -Json) -join "`n"
$longParsed = $longJson | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $longParsed.success -or $longParsed.data.subject -ne 'general') { throw 'Literal --help JSON failed' }
$bad = @(& $cli Bogus -Json) -join "`n"
$badCode = $LASTEXITCODE
$badResult = $bad | ConvertFrom-Json
if ($badCode -ne 2 -or $badResult.code -ne 'INVALID_COMMAND') { throw 'Unknown command should fail with exit code 2' }
Write-Output 'PASS: general help, --help, command help, JSON help'
