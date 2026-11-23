#requires -Version 5.1
<#
.SYNOPSIS
  Non-interactive companion for OpenPGP Quantum Guard (GnuPG backend).
.DESCRIPTION
  Preserves the existing TUI unchanged. Does not implement cryptography.
  JSON output is a single object. Exit codes: 0 success, 2 invalid input,
  3 missing dependency/configuration, 4 policy failure, 5 GnuPG failure.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Command,
    [switch]$Json,
    [Alias('h')]
    [switch]$Help,
    [string]$Fingerprint,
    [string]$InputPath,
    [string]$OutputPath,
    [switch]$RequirePqc,
    [string]$ConfigPath,
    [string]$GpgPath,
    [string]$GpgHome,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ExitStatus = 0
if ($null -eq $RemainingArguments) { $RemainingArguments = @() }

function New-Result([string]$operation, [bool]$success, [string]$code, [object]$data, [string]$message) {
    return [ordered]@{
        schema = 'openpgp-quantum-guard-cli-v1'
        command = $operation.ToLowerInvariant()
        success = $success
        code = $code
        message = $message
        data = $data
    }
}

function Write-Result([object]$result) {
    if ($Json) {
        $result | ConvertTo-Json -Depth 12 -Compress | Write-Output
    } else {
        Write-Output ('[{0}] {1}' -f $result.code, $result.message)
        if ($null -ne $result.data) { $result.data | ConvertTo-Json -Depth 12 | Write-Output }
    }
}

function Fail([int]$exitCode, [string]$code, [string]$message) {
    $script:ExitStatus = $exitCode
    Write-Result (New-Result $Command $false $code $null $message)
}

# Windows PowerShell 5.1 can bind GNU-style --help as a positional argument,
# rather than a PowerShell switch. Accept it explicitly without interfering
# with the strongly-typed flags used by existing cryptographic commands.
# Render help before reading configuration, finding GnuPG, or touching the keyring.
function Get-HelpText([string]$subject) {
    $name = 'OpenPGP-Quantum-Guard.Cli.ps1'
    switch ($subject) {
        'Doctor' { return @"
OPENPGP QUANTUM GUARD CLI  |  DOCTOR
USAGE
  .\src\$name Doctor [-GpgHome <directory>] [-GpgPath <executable>] [-ConfigPath <file>] [-Json]

Checks that GnuPG is available and reports its version. A reported PQC-capable
version is NOT cryptographic proof of hybrid support.

EXAMPLE
  .\src\$name Doctor -GpgHome '.\.lab\gnupg' -Json
"@
        }
        'Inspect' { return @"
OPENPGP QUANTUM GUARD CLI  |  INSPECT
USAGE
  .\src\$name Inspect [-Fingerprint <40-or-64-hex>] [-GpgHome <directory>] [-Json]

Lists public identities and their subkeys. Includes hybrid PQC classifications
when the installed GnuPG explicitly reports a recognized hybrid subkey.

EXAMPLE
  .\src\$name Inspect -GpgHome '.\.lab\gnupg' -Json
"@
        }
        'Algorithms' { return @"
OPENPGP QUANTUM GUARD CLI  |  ALGORITHMS
USAGE
  .\src\$name Algorithms [-GpgHome <directory>] [-Json]

Displays GnuPG-advertised algorithms and documented research profiles.
Advertised support does not imply a completed encryption/decryption test.

EXAMPLE
  .\src\$name Algorithms -Json
"@
        }
        'Encrypt' { return @"
OPENPGP QUANTUM GUARD CLI  |  ENCRYPT
USAGE
  .\src\$name Encrypt -Fingerprint <40-or-64-hex> -InputPath <file> -OutputPath <new-file> [-RequirePqc] [-GpgHome <directory>] [-Json]

Encrypts to an explicit primary key fingerprint using GnuPG. -RequirePqc
requires GnuPG's hybrid post-quantum encryption policy. Never overwrites an
existing output file. GnuPG performs all cryptographic operations.

EXAMPLE
  .\src\$name Encrypt -GpgHome '.\.lab\gnupg' -Fingerprint 'FULL_FINGERPRINT' -InputPath '.\sample.txt' -OutputPath '.\sample.gpg' -RequirePqc -Json
"@
        }
        'Decrypt' { return @"
OPENPGP QUANTUM GUARD CLI  |  DECRYPT
USAGE
  .\src\$name Decrypt -InputPath <encrypted-file> -OutputPath <new-file> [-GpgHome <directory>] [-Json]

Decrypts an OpenPGP file using GnuPG. Never overwrites an existing output
file. Batch mode may require an already-unlocked gpg-agent.

EXAMPLE
  .\src\$name Decrypt -GpgHome '.\.lab\gnupg' -InputPath '.\sample.gpg' -OutputPath '.\sample.recovered.txt' -Json
"@
        }
        default { return @"
OPENPGP QUANTUM GUARD  |  COMMAND LINE
PQC-aware OpenPGP file protection. GnuPG backend. Windows PowerShell 5.1+.

USAGE
  .\src\$name <command> [options]
  .\src\$name --help
  .\src\$name <command> --help

COMMANDS
  Doctor       Check GnuPG installation and configuration
  Inspect      List public keys, fingerprints and hybrid PQC subkeys
  Algorithms   Show GnuPG capabilities and research profiles
  Encrypt      Encrypt to an explicitly selected recipient
  Decrypt      Decrypt an OpenPGP file
  Help         Show this usage screen

COMMON OPTIONS
  -GpgHome <directory>   Use an isolated GnuPG home
  -GpgPath <executable>  Set GnuPG executable path
  -ConfigPath <file>     Read a specified JSON configuration
  -Json                  Emit a single machine-readable JSON object
  -Help / --help         Show general or command-specific help

ENCRYPT OPTIONS
  -Fingerprint <hex>     Full 40-hex or 64-hex recipient fingerprint
  -InputPath <file>      Existing input file
  -OutputPath <file>     Unused output path, no overwrites
  -RequirePqc            Enforce GnuPG's mandatory PQC encryption policy

EXAMPLES
  .\src\$name Doctor -Json
  .\src\$name Inspect -GpgHome '.\.lab\gnupg' -Json
  .\src\$name Encrypt --help

EXIT CODES
  0 Success / help   2 Invalid input   3 Missing GnuPG or configuration
  4 Key/policy rejection             5 GnuPG or operation failure

RESEARCH PREVIEW. Hybrid support requires independent cryptographic validation.
"@
        }
    }
}

# Help requests are deliberately side-effect-free, including on systems without GnuPG.
# The command token may literally be --help. For command-specific help,
# PowerShell 5.1 may place --help in RemainingArguments instead of binding -Help.
$validCommands = @('Doctor','Inspect','Algorithms','Encrypt','Decrypt','Help')
$commandIsHelp = $Command -in @('--help','-help','-h')
$trailingHelp = ($RemainingArguments.Count -eq 1 -and $RemainingArguments[0] -in @('--help','-help','-h'))
if ($Help -or $commandIsHelp -or $trailingHelp -or [string]::IsNullOrWhiteSpace($Command) -or $Command -eq 'Help') {
    $subject = if (($Help -or $trailingHelp) -and $Command -in $validCommands -and $Command -ne 'Help') { $Command } else { '' }
    $usage = Get-HelpText $subject
    if ($Json) {
        Write-Result (New-Result 'Help' $true 'OK' ([ordered]@{ subject=$(if ($subject) { $subject.ToLowerInvariant() } else { 'general' }); usage=$usage }) 'Help displayed.')
    } else {
        Write-Output $usage
    }
    exit 0
}

# Do not let unknown commands silently succeed after bypassing ValidateSet.
# Validate only after help routing so literal --help can reach the dispatcher.
if ($Command -notin $validCommands -or $RemainingArguments.Count -gt 0) {
    $script:ExitStatus = 2
    Write-Result (New-Result $Command $false 'INVALID_COMMAND' $null 'Unknown command or unexpected argument. Run --help for usage.')
    exit $script:ExitStatus
}

function Test-Fingerprint([string]$value) {
    return ($value -cmatch '^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$')
}

function Read-Configuration {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $path = Join-Path $PSScriptRoot 'openpgp_quantum_guard.config.json'
    } else { $path = $ConfigPath }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    return ($content | ConvertFrom-Json)
}

function Find-Gpg([object]$cfg) {
    $specified = $GpgPath
    if ([string]::IsNullOrWhiteSpace($specified) -and $null -ne $cfg) { $specified = [string]$cfg.GpgPath }
    if ([string]::IsNullOrWhiteSpace($specified)) { $specified = 'gpg' }
    $cmd = Get-Command -Name $specified -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { throw 'GnuPG executable not found. Set -GpgPath or install GnuPG.' }
    return $cmd.Source
}

function Invoke-Gpg([string]$exe, [string[]]$arguments, [string]$gpgHomeDirectory) {
    $all = @('--batch','--no-tty')
    if (-not [string]::IsNullOrWhiteSpace($gpgHomeDirectory)) { $all += @('--homedir',$gpgHomeDirectory) }
    $all += $arguments
    # Capture native stderr as output, never allow it to pollute JSON stdout.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& $exe @all 2>&1 | ForEach-Object { $_.ToString() })
        $status = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    return @{ exit = [int]$status; lines = @($lines) }
}

# GnuPG 2.5 can render a composite Kyber subkey as numeric algorithm 8 in
# --with-colons output. Never interpret that number alone as RSA or PQC.
# Inspect the human-readable --list-keys view and match subkeys in order,
# but only if both views list the same number of subkeys for the exact key.
function Add-SubkeyDescriptions([string]$exe, [string]$gpgHomeDirectory, [object[]]$keys) {
    foreach ($key in $keys) {
        if (-not (Test-Fingerprint $key.fingerprint)) { continue }
        $rendered = Invoke-Gpg $exe @('--list-keys','--with-subkey-fingerprint','--',$key.fingerprint) $gpgHomeDirectory
        if ($rendered.exit -ne 0) { continue }
        $names = @($rendered.lines | ForEach-Object {
            if ($_ -match '^\s*sub\s+([a-zA-Z0-9_+-]+)\s') { $Matches[1].ToLowerInvariant() }
        })
        if ($names.Count -ne $key.subkeys.Count) { continue }
        for ($i = 0; $i -lt $names.Count; $i++) {
            $name = $names[$i]
            # Only recognize canonical algorithm tokens returned by GnuPG itself.
            if ($name -match '^ky(?:768|1024)_(?:cv25519|cv448|bp256|bp384)$') {
                $key.subkeys[$i].algorithmName = $name
                $key.subkeys[$i].pqcHybrid = $true
                $key.subkeys[$i].classificationSource = 'gpg-human-readable'
            } elseif ($name -match '^(rsa|rsa[0-9]+|cv25519|cv448|ed25519|ed448|nistp[0-9]+|brainpoolp[0-9]+|elg|dsa)$') {
                $key.subkeys[$i].algorithmName = $name
                $key.subkeys[$i].pqcHybrid = $false
                $key.subkeys[$i].classificationSource = 'gpg-human-readable'
            }
        }
    }
}

function Get-Keys([string]$exe, [string]$gpgHomeDirectory) {
    $r = Invoke-Gpg $exe @('--with-colons','--with-subkey-fingerprint','--list-keys') $gpgHomeDirectory
    if ($r.exit -ne 0) { throw 'GnuPG could not enumerate public keys.' }
    $keys = New-Object System.Collections.Generic.List[object]
    $current = $null
    $lastRecord = ''
    foreach ($line in $r.lines) {
        $parts = $line -split ':', -1
        if ($parts.Count -lt 10) { continue }
        switch ($parts[0]) {
            'pub' {
                $current = [ordered]@{ fingerprint=''; validity=$parts[1]; algorithm=$parts[3]; capabilities=$(if ($parts.Count -gt 11) { $parts[11] } else { '' }); created=$parts[5]; expires=$parts[6]; uid=@(); subkeys=@() }
                $keys.Add($current)
                $lastRecord = 'pub'
            }
            'fpr' {
                if ($null -ne $current) {
                    if ($lastRecord -eq 'pub' -and [string]::IsNullOrWhiteSpace($current.fingerprint)) { $current.fingerprint = $parts[9] }
                    elseif ($lastRecord -eq 'sub' -and $current.subkeys.Count -gt 0) { $current.subkeys[$current.subkeys.Count - 1].fingerprint = $parts[9] }
                }
            }
            'uid' {
                if ($null -ne $current) { $current.uid += $parts[9] }
                $lastRecord = 'uid'
            }
            'sub' {
                if ($null -ne $current) {
                    $caps = if ($parts.Count -gt 11) { $parts[11] } else { '' }
                    $current.subkeys += [ordered]@{ algorithm=$parts[3]; algorithmName=$null; pqcHybrid=$null; classificationSource='unclassified'; fingerprint=''; capabilities=$caps; created=$parts[5]; expires=$parts[6] }
                }
                $lastRecord = 'sub'
            }
        }
    }
    Add-SubkeyDescriptions $exe $gpgHomeDirectory @($keys.ToArray())
    return @($keys.ToArray())
}

try {
    $cfg = Read-Configuration
    $gpgHomeDirectory = $GpgHome
    if ([string]::IsNullOrWhiteSpace($gpgHomeDirectory) -and $null -ne $cfg) { $gpgHomeDirectory = [string]$cfg.GpgHome }
    if (-not [string]::IsNullOrWhiteSpace($gpgHomeDirectory) -and -not (Test-Path -LiteralPath $gpgHomeDirectory -PathType Container)) {
        Fail 3 'GPG_HOME_NOT_FOUND' 'Configured GnuPG home directory does not exist.'
    } else {
        $exe = Find-Gpg $cfg
        switch ($Command) {
            'Doctor' {
                $v = Invoke-Gpg $exe @('--version') $gpgHomeDirectory
                if ($v.exit -ne 0) { Fail 5 'GPG_FAILED' 'GnuPG version query failed.'; break }
                $version = if ($v.lines.Count -gt 0) { [string]$v.lines[0] } else { '' }
                $supported = $version -match 'gpg \(GnuPG\) (\d+)\.(\d+)'
                $pqcBuildCandidate = $false
                if ($supported) {
                    $major = [int]$Matches[1]; $minor = [int]$Matches[2]
                    $pqcBuildCandidate = ($major -gt 2 -or ($major -eq 2 -and $minor -ge 5))
                }
                $data = [ordered]@{ gpgVersion=$version; gpgFound=$true; pqcVersionCandidate=$pqcBuildCandidate; pqcCapabilityVerified=$false; configuredHome= (-not [string]::IsNullOrWhiteSpace($gpgHomeDirectory)); configFound=($null -ne $cfg) }
                Write-Result (New-Result $Command $true 'OK' $data 'GnuPG detected. PQC capability must be verified with a real test key.')
            }
            'Algorithms' {
                $v = Invoke-Gpg $exe @('--version') $gpgHomeDirectory
                if ($v.exit -ne 0) { Fail 5 'GPG_FAILED' 'GnuPG capability query failed.'; break }
                $data = [ordered]@{ reportedByGpg=@($v.lines); researchProfiles=@('ky1024_cv448','ky768_cv25519','ky768_bp256','cv25519'); profileAvailabilityVerified=$false }
                Write-Result (New-Result $Command $true 'OK' $data 'GnuPG capability advertisement and documented research profiles.')
            }
            'Inspect' {
                $keys = @(Get-Keys $exe $gpgHomeDirectory)
                if (-not [string]::IsNullOrWhiteSpace($Fingerprint)) {
                    if (-not (Test-Fingerprint $Fingerprint)) { Fail 2 'INVALID_FINGERPRINT' 'Provide a full 40-hex or 64-hex fingerprint.'; break }
                    $keys = @($keys | Where-Object { $_.fingerprint -eq $Fingerprint })
                    if ($keys.Count -eq 0) { Fail 4 'KEY_NOT_FOUND' 'No public key matched the specified fingerprint.'; break }
                }
                $hybridCount = @($keys | ForEach-Object { $_.subkeys } | Where-Object { $_.pqcHybrid -eq $true }).Count
                $unknownCount = @($keys | ForEach-Object { $_.subkeys } | Where-Object { $null -eq $_.pqcHybrid }).Count
                $classification = if ($unknownCount -gt 0) { 'partial' } elseif ($hybridCount -gt 0) { 'hybrid-reported-by-gpg' } else { 'no-hybrid-reported' }
                Write-Result (New-Result $Command $true 'OK' ([ordered]@{ keys=$keys; count=$keys.Count; pqcClassification=$classification; hybridSubkeyCount=$hybridCount }) 'Public key inventory retrieved; hybrid labels are reported by GnuPG, not proof of a cryptographic round-trip.')
            }
            'Encrypt' {
                if (-not (Test-Fingerprint $Fingerprint)) { Fail 2 'INVALID_FINGERPRINT' 'Encrypt requires an explicit full 40-hex or 64-hex recipient fingerprint.'; break }
                if ([string]::IsNullOrWhiteSpace($InputPath) -or -not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { Fail 2 'INPUT_NOT_FOUND' 'A regular input file is required.'; break }
                if ([string]::IsNullOrWhiteSpace($OutputPath) -or (Test-Path -LiteralPath $OutputPath)) { Fail 2 'OUTPUT_UNSAFE' 'An unused explicit output path is required. Overwrite is prohibited.'; break }
                $keys = @(Get-Keys $exe $gpgHomeDirectory | Where-Object { $_.fingerprint -eq $Fingerprint })
                if ($keys.Count -ne 1) { Fail 4 'KEY_NOT_FOUND' 'Exact recipient fingerprint was not found.'; break }
                # Fail-closed preflight: a fully classified recipient with no PQC
                # encryption subkey cannot satisfy mandatory PQC enforcement.
                # Unknown classification is NOT a reason to claim policy rejection:
                # defer to GnuPG and return its generic error on failure.
                if ($RequirePqc) {
                    $encryptionSubkeys = @($keys[0].subkeys | Where-Object { $_.capabilities -match '(?i)e' })
                    $unknownSubkeys = @($encryptionSubkeys | Where-Object { $null -eq $_.pqcHybrid })
                    $hybridSubkeys = @($encryptionSubkeys | Where-Object { $_.pqcHybrid -eq $true })
                    $primaryRsaEncryptionOnly = ($encryptionSubkeys.Count -eq 0 -and $keys[0].algorithm -eq '1' -and $keys[0].capabilities -match '(?i)e')
                    if ($primaryRsaEncryptionOnly -or ($encryptionSubkeys.Count -gt 0 -and $unknownSubkeys.Count -eq 0 -and $hybridSubkeys.Count -eq 0)) {
                        Fail 4 'PQC_POLICY_REJECTED' 'Recipient has no eligible hybrid PQC encryption subkey according to the GnuPG key listing.'; break
                    }
                }
                $args = @('--no-auto-key-retrieve','--recipient', $Fingerprint, '--output', $OutputPath, '--encrypt')
                if ($RequirePqc) { $args += '--require-pqc-encryption' }
                $args += $InputPath
                $r = Invoke-Gpg $exe $args $gpgHomeDirectory
                if ($r.exit -ne 0) {
                    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { Remove-Item -LiteralPath $OutputPath -Force }
                    Fail 5 'GPG_FAILED' 'GnuPG encryption failed. Check recipient trust, subkeys and PQC policy.'; break
                }
                Write-Result (New-Result $Command $true 'OK' ([ordered]@{ recipient=$Fingerprint.ToUpperInvariant(); requirePqc=[bool]$RequirePqc; outputCreated=$true }) 'Encryption completed. GnuPG performed the cryptographic operation.')
            }
            'Decrypt' {
                if ([string]::IsNullOrWhiteSpace($InputPath) -or -not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { Fail 2 'INPUT_NOT_FOUND' 'A regular encrypted input file is required.'; break }
                if ([string]::IsNullOrWhiteSpace($OutputPath) -or (Test-Path -LiteralPath $OutputPath)) { Fail 2 'OUTPUT_UNSAFE' 'An unused explicit output path is required. Overwrite is prohibited.'; break }
                $r = Invoke-Gpg $exe @('--output',$OutputPath,'--decrypt',$InputPath) $gpgHomeDirectory
                if ($r.exit -ne 0) {
                    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { Remove-Item -LiteralPath $OutputPath -Force }
                    Fail 5 'GPG_FAILED' 'GnuPG decryption failed. An already-unlocked gpg-agent may be required in batch mode.'; break
                }
                Write-Result (New-Result $Command $true 'OK' ([ordered]@{ outputCreated=$true }) 'Decryption completed.')
            }
        }
    }
} catch {
    if ($_.Exception.Message -like '*executable not found*') {
        Fail 3 'GPG_NOT_FOUND' $_.Exception.Message
    } else {
        Fail 5 'OPERATION_FAILED' ('Operation failed: ' + $_.Exception.Message)
    }
}
exit $script:ExitStatus
