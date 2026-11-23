<#
OpenPGP Quantum Guard

Purpose
  Provides an interactive Windows PowerShell interface for GnuPG file and
  text protection, key inspection, key generation, and controlled exports.

Post-quantum scope
  Detects and prefers GnuPG composite Kyber/ML-KEM encryption subkeys when
  the local GnuPG build supports them. The tool delegates all cryptographic
  operations and private-key unlocking to GnuPG.

Configuration
  Operator-specific paths, identity selection, and policy switches belong in
  openpgp_quantum_guard.config.json beside the script. Never hard-code a real
  fingerprint, UID, passphrase, or workstation path in this file.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
} catch { }

# =============================================================================
# RUNTIME STATE AND SAFE DEFAULTS
# Loaded configuration replaces these values during startup. Repository-relative
# folders allow a clean checkout to run without exposing workstation paths.
# =============================================================================
$script:IdentityFingerprint = ""
$script:ExpectedUidHint = ""
$script:DefaultStartFolder = Join-Path $PSScriptRoot "data"
$script:OutputFolder = ""
$script:GpgExecutable = ""
$script:GpgHome = ""
$script:ConfigPath = ""
$script:DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448"
$script:DefaultKeyExpiry = "2y"
$script:AutoTrustGeneratedKeys = $true
$script:KeySelectableRequiresUltimateTrust = $false
$script:PreferKyberHybridSubkeys = $true
$script:RequirePqcEncryption = $true
$script:OutputMode = "Shareable" # Private or Shareable. Default is public-safe Shareable mode.
$script:AdminPassword = $null
$script:UidGatePassphrase = $null
$script:DrainQueuedMenuKeys = $true # Prevent delayed key-repeat drift in arrow menus
$script:QuitGuardInstalled = $false
$script:QuitGuardHandler = $null
$script:PreviousTreatControlCAsInput = $null

# Tool branding.
$script:ToolName = "OpenPGP Quantum Guard"
$script:ToolSubtitle = "PQC-aware OpenPGP file protection"
# Legacy custom-header support remains disabled for compatibility. Current
# builds use the single maintained embedded boot mark and compact menu panel.
$script:ShowCustomAnsiHeader = $false
$script:CustomAnsiHeader = ""

# No More Secrets style reveal effect. Purely cosmetic.
$script:EnableNoMoreSecretsEffect = $true
$script:EnableDynamicNmsMenu = $true
$script:NmsMenuPulseFrames = 1
$script:NmsMenuPulseDelayMs = 0
$script:NmsOperationFrames = 4
$script:NmsOperationDelayMs = 8
$script:NmsEffectAlreadyShown = $false
$script:NmsWaveTick = 0
$script:NmsWaveDelayMs = 24
$script:NmsWaveMinimumReveal = 0.82
$script:NmsWavePeakReveal = 0.97
$script:NmsAnimateHints = $false # Keep long hint text readable and prevent slow full-sentence redraws.
$script:NmsMaxAnimatedTextLength = 34 # Animate compact labels; leave long descriptions stable.
$script:NmsGlyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*+=?/\|[]{}<>:;'
$script:NmsGlyphChars = $script:NmsGlyphs.ToCharArray()

# UI palette: deep blue to white-silver.
$script:UiInkBlue        = "Rgb:0,4,16"
$script:UiDeepBlue       = "Rgb:0,14,52"
$script:UiHighlightBlue  = "Rgb:0,22,88"
$script:UiBorderBlue     = "Rgb:18,44,96"
$script:UiMidBlue        = "Rgb:56,94,158"
$script:UiLightBlue      = "Rgb:128,166,207"
$script:UiSilverBlue     = "Rgb:188,212,235"
$script:UiWhiteSilver    = "Rgb:238,244,250"
$script:UiDimSilver      = "Rgb:132,158,188"

# Compatibility names used by older sections of the script.
$script:UiRose           = $script:UiSilverBlue
$script:UiCopper         = $script:UiMidBlue
$script:UiBone           = $script:UiWhiteSilver
$script:UiDimBone        = $script:UiDimSilver
$script:UiGreen          = $script:UiWhiteSilver
$script:UiMutedGreen     = $script:UiSilverBlue

# Gradient colors adapted from the supplied RGB interpolation style.
$script:GradientSilverStart = @(192, 192, 192)
$script:GradientSilverEnd   = @(173, 216, 230)
$script:GradientBlueStart   = @(0, 80, 180)
$script:GradientBlueEnd     = @(226, 234, 246)
$script:GradientIceStart    = @(0, 150, 255)
$script:GradientIceEnd      = @(188, 212, 235)
$script:GradientLabelStart  = @(90, 170, 255)
$script:GradientLabelEnd    = @(226, 234, 246)
# ==============


# RGB-safe Write-Host shim.
# PowerShell's native Write-Host only accepts ConsoleColor names. This tool uses
# ANSI RGB strings such as Rgb:128,166,207, so this wrapper routes RGB output
# through ANSI escape codes and routes normal ConsoleColor output to the original cmdlet.
function Write-Host {
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromRemainingArguments=$true)]
        [AllowNull()][object[]]$Object,
        [string]$Separator = " ",
        [AllowEmptyString()][string]$ForegroundColor = "",
        [AllowEmptyString()][string]$BackgroundColor = "",
        [switch]$NoNewline
    )

    begin {
        $items = @()
    }
    process {
        if ($null -ne $Object) { $items += @($Object) }
    }
    end {
        $text = ""
        if ($items.Count -gt 0) {
            $text = (@($items) | ForEach-Object { if ($null -eq $_) { "" } else { [string]$_ } }) -join $Separator
        }

        $usesAnsi = ($ForegroundColor -match '^Rgb:' -or $BackgroundColor -match '^Rgb:')
        if ($usesAnsi) {
            $fg = if ([string]::IsNullOrWhiteSpace($ForegroundColor)) { "Gray" } else { $ForegroundColor }
            $bg = if ([string]::IsNullOrWhiteSpace($BackgroundColor)) { "" } else { $BackgroundColor }
            $fgAnsi = Get-AnsiStyleCode -Color $fg -Background:$false
            $bgAnsi = Get-AnsiStyleCode -Color $bg -Background:$true
            $reset = "$([char]27)[0m"
            [Console]::Write(("{0}{1}{2}{3}" -f $fgAnsi, $bgAnsi, $text, $reset))
            if (-not $NoNewline) { [Console]::WriteLine() }
            return
        }

        $params = @{}
        if (-not [string]::IsNullOrWhiteSpace($ForegroundColor)) { $params.ForegroundColor = $ForegroundColor }
        if (-not [string]::IsNullOrWhiteSpace($BackgroundColor)) { $params.BackgroundColor = $BackgroundColor }
        if ($NoNewline) { $params.NoNewline = $true }
        Microsoft.PowerShell.Utility\Write-Host $text @params
    }
}

function Normalize-Fingerprint {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    return (($Text -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}

function Short-Fpr {
    param([string]$Fingerprint)
    $f = Normalize-Fingerprint $Fingerprint
    if ($f.Length -le 16) { return $f }
    return $f.Substring($f.Length - 16)
}

function Convert-GpgDate {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return "" }
    try {
        if ($Raw -match '^\d+$') {
            return [DateTimeOffset]::FromUnixTimeSeconds([int64]$Raw).LocalDateTime.ToString("yyyy-MM-dd")
        }
    } catch { }
    return $Raw
}

function Test-ShareableOutput {
    return ($script:OutputMode -eq "Shareable")
}

function Format-DisplayPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    if (Test-ShareableOutput) {
        try {
            $leaf = Split-Path -Leaf $Path
            if (-not [string]::IsNullOrWhiteSpace($leaf)) { return "[local path hidden]\$leaf" }
        } catch { }
        return "[local path hidden]"
    }
    return $Path
}

function Redact-PrivateText {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    $s = [string]$Text
    if (Test-ShareableOutput) {
        $s = $s -replace '[A-Za-z]:\\[^\s"'']+', '[local-path-redacted]'
        $s = $s -replace '(?i)(homedir|home directory|gnupg home|gpg home)[:=]\s*\S+', '$1: [hidden]'
    }
    return $s
}

function Write-GpgFailure {
    param(
        [Parameter(Mandatory=$true)]$Result,
        [Parameter(Mandatory=$true)][string]$ActionName
    )

    $joinedOutput = @($Result.Output) -join "`n"

    Write-Host ""
    Write-Host "$ActionName failed." -ForegroundColor $script:UiLightBlue

    if ($ActionName -eq "Decryption" -and $joinedOutput -match "no valid OpenPGP data found") {
        Write-Host ""
        Write-Host "This file does not look like OpenPGP encrypted data." -ForegroundColor White
        Write-Host "Choose a file that was produced by OpenPGP/GnuPG, usually ending with:" -ForegroundColor Gray
        Write-Host "  .gpg   .pgp   .asc" -ForegroundColor White
        Write-Host ""
        Write-Host "The selected file may be plaintext, a script, or another non-PGP format." -ForegroundColor Gray
        return
    }

    if (Test-ShareableOutput) {
        Write-Host "Output mode is Shareable, so local command lines and machine paths are hidden." -ForegroundColor $script:UiDimSilver
        Write-Host "GnuPG output, redacted when needed:" -ForegroundColor $script:UiDimSilver
        $Result.Output | ForEach-Object { Write-Host ("  {0}" -f (Redact-PrivateText $_)) -ForegroundColor Gray }
    } else {
        Write-Host "Command:" -ForegroundColor $script:UiDimSilver
        Write-Host "  $($Result.Command)" -ForegroundColor $script:UiDimSilver
        Write-Host "Output:" -ForegroundColor $script:UiDimSilver
        $Result.Output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
}


function Test-CustomAnsiHeaderEnabled {
    if (-not $script:ShowCustomAnsiHeader) { return $false }
    if ([string]::IsNullOrWhiteSpace($script:CustomAnsiHeader)) { return $false }
    return $true
}

function Write-CustomAnsiHeader {
    if (-not (Test-CustomAnsiHeaderEnabled)) { return }

    $raw = [string]$script:CustomAnsiHeader
    # If the pasted header already contains ANSI escape codes, preserve it exactly.
    if ($raw.Contains("$([char]27)")) {
        try {
            [Console]::Write($raw)
            if (-not $raw.EndsWith("`n")) { [Console]::WriteLine() }
            return
        } catch { }
    }

    foreach ($line in @($raw -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            Write-Host ""
        } else {
            Write-GradientLine -Text ("  {0}" -f $line) -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd
        }
    }
}

function Get-CustomAnsiHeaderRenderLines {
    $out = @()
    if (-not (Test-CustomAnsiHeaderEnabled)) { return @() }

    $raw = [string]$script:CustomAnsiHeader
    # Render raw ANSI headers outside the menu renderer, because the menu renderer
    # must know line widths and will treat escape sequences as printable chars.
    if ($raw.Contains("$([char]27)")) { return @() }

    foreach ($line in @($raw -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            $out += (New-ConsoleLine -Text "" -Color $script:UiDimSilver)
        } else {
            $out += (New-ConsoleRichLine -Segments (New-GradientSegments -Text ("  {0}" -f $line) -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold))
        }
    }
    $out += (New-ConsoleLine -Text "" -Color $script:UiDimSilver)
    return @($out)
}

function Write-Banner {
    param([string]$Title = $script:ToolName)
    Clear-Host
    $modeColor = if (Test-ShareableOutput) { $script:UiSilverBlue } else { $script:UiLightBlue }
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $w = 72
    $inner = $w - 4

    Write-Host ""
    Write-ConsoleSegment -Text "  ╔" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╗" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-ConsoleSegment -Text "  ║ " -ForegroundColor $script:UiBorderBlue
    foreach ($seg in (New-GradientSegments -Text $Title -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd)) {
        Write-ConsoleSegment -Text $seg.Text -ForegroundColor $seg.Color
    }
    $pad = [Math]::Max(0, $inner - $Title.Length)
    Write-ConsoleSegment -Text (" " * $pad) -ForegroundColor $script:UiDimSilver
    Write-ConsoleSegment -Text " ║" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-ConsoleSegment -Text "  ║ " -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("PQC-enabled OpenPGP operations".PadRight($inner)) -ForegroundColor $script:UiSilverBlue
    Write-ConsoleSegment -Text " ║" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-ConsoleSegment -Text "  ╠" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╣" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    foreach ($row in @(
        @{Text=("Active FPR : {0}" -f (Short-Fpr $script:IdentityFingerprint)); Color=$script:UiWhiteSilver},
        @{Text=("Output     : {0}" -f $modeText); Color=$modeColor},
        @{Text="Crypto     : Kyber / ML-KEM hybrid ready"; Color=$script:UiLightBlue}
    )) {
        Write-ConsoleSegment -Text "  ║ " -ForegroundColor $script:UiBorderBlue
        Write-ConsoleSegment -Text ([string]$row.Text).PadRight($inner) -ForegroundColor ([string]$row.Color)
        Write-ConsoleSegment -Text " ║" -ForegroundColor $script:UiBorderBlue
        Write-Host ""
    }

    Write-ConsoleSegment -Text "  ╚" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╝" -ForegroundColor $script:UiBorderBlue
    Write-Host ""
}

function Write-QuitGuardNotice {
    Write-Host ""
    Write-Host "Use the Quit option from the menu to close this tool cleanly." -ForegroundColor $script:UiDimSilver
    Start-Sleep -Milliseconds 650
}

function Start-OqgInteractiveGpg {
    param([string[]]$Arguments)
    $quoted = foreach ($argument in $Arguments) {
        '"' + (($argument -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }
    Start-Process -FilePath $script:GpgPath -ArgumentList ($quoted -join ' ') -Wait
}

function Install-QuitGuard {
    if ($script:QuitGuardInstalled) { return }

    # Do not use [Console]::CancelKeyPress here.
    # Some PowerShell/.NET hosts expose the static event differently, which can throw:
    # "The property 'CancelKeyPress' cannot be found on this object."
    # TreatControlCAsInput is more portable for this console-style script. It turns Ctrl+C
    # into a keypress that our menus can catch and ignore, instead of a process cancel.
    try {
        $script:PreviousTreatControlCAsInput = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
    } catch {
        # Non-interactive or restricted hosts may not allow changing this setting.
        # The script should still run. Arrow menus still ignore Ctrl+Q / Ctrl+Z.
        $script:PreviousTreatControlCAsInput = $null
    }

    $script:QuitGuardInstalled = $true
}

function Restore-QuitGuard {
    if (-not $script:QuitGuardInstalled) { return }

    try {
        if ($null -ne $script:PreviousTreatControlCAsInput) {
            [Console]::TreatControlCAsInput = [bool]$script:PreviousTreatControlCAsInput
        }
    } catch { }
}

function Test-BlockedControlQuitKey {
    param([Parameter(Mandatory=$true)][ConsoleKeyInfo]$KeyInfo)

    if ([int]$KeyInfo.KeyChar -in @(3,17,26)) { return $true }
    $isCtrl = (($KeyInfo.Modifiers -band [ConsoleModifiers]::Control) -eq [ConsoleModifiers]::Control)
    if (-not $isCtrl) { return $false }

    return ($KeyInfo.Key -in @([ConsoleKey]::C, [ConsoleKey]::Q, [ConsoleKey]::Z))
}

$script:GpgPath = $null # v63: resolved after config is loaded
$script:IdentityFingerprint = ""


function Wait-User {
    Write-Host ""
    [void](Read-OqgPrompt "Press ENTER to continue")
}

function Format-Size {
    param([Int64]$Bytes)
    if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Read-OqgPrompt {
    param([string]$Prompt)
    [Console]::Write($Prompt + ': ')
    if ([Console]::IsInputRedirected) {
        $line = [Console]::ReadLine()
        if ($null -eq $line) { throw 'Standard input closed while reading a prompt.' }
        return $line
    }
    [Console]::TreatControlCAsInput = $true
    $line = New-Object System.Text.StringBuilder
    while ($true) {
        $key = [Console]::ReadKey($true)
        if (Test-BlockedControlQuitKey -KeyInfo $key) { continue }
        if ($key.Key -eq 'Enter' -or [int]$key.KeyChar -in @(10,13)) {
            [Console]::WriteLine()
            return $line.ToString()
        }
        if ($key.Key -eq 'Backspace' -and $line.Length -gt 0) {
            [void]$line.Remove($line.Length-1,1)
            [Console]::Write("`b `b")
        } elseif (-not [char]::IsControl($key.KeyChar)) {
            [void]$line.Append($key.KeyChar)
            [Console]::Write($key.KeyChar)
        }
    }
}

function Read-YesNo {
    param(
        [Parameter(Mandatory=$true)][string]$Question,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $answer = (Read-OqgPrompt "$Question $suffix").Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
        if ($answer -in @("y", "yes")) { return $true }
        if ($answer -in @("n", "no")) { return $false }
        Write-Host "Please answer y or n." -ForegroundColor $script:UiDimSilver
    }
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory=$true)][System.Security.SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}


function Clear-PendingConsoleKeys {
    if (-not $script:DrainQueuedMenuKeys) { return }
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { }
}

function New-ConsoleMenuItem {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string]$Value,
        [string]$Hint = "",
        [string]$Color = "White",
        [string]$Shortcut = ""
    )

    return [pscustomobject]@{
        Label    = $Label
        Value    = $Value
        Hint     = $Hint
        Color    = $Color
        Shortcut = $Shortcut
    }
}

function New-ConsoleLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = "Gray"
    )

    return [pscustomobject]@{
        Text  = $Text
        Color = $Color
    }
}


function New-ConsoleSegment {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = "Gray",
        [string]$BackgroundColor = "",
        [switch]$Bold
    )

    return [pscustomobject]@{
        Text            = $Text
        Color           = $Color
        BackgroundColor = $BackgroundColor
        Bold            = [bool]$Bold
    }
}

function New-ConsoleRichLine {
    param($Segments = @())

    return [pscustomobject]@{
        Text            = ""
        Color           = "Gray"
        BackgroundColor = ""
        Segments        = @($Segments)
    }
}

function Get-AnsiColorCode {
    param(
        [string]$Color,
        [bool]$Background = $false
    )

    $base = if ($Background) { 40 } else { 30 }
    switch -Regex ($Color) {
        '^Black$'       { return "$([char]27)[$($base + 0)m" }
        '^DarkRed$'     { return "$([char]27)[$($base + 1)m" }
        '^DarkGreen$'   { return "$([char]27)[$($base + 2)m" }
        '^DarkYellow$'  { return "$([char]27)[$($base + 3)m" }
        '^DarkBlue$'    { return "$([char]27)[$($base + 4)m" }
        '^DarkMagenta$' { return "$([char]27)[$($base + 5)m" }
        '^DarkCyan$'    { return "$([char]27)[$($base + 6)m" }
        '^Gray$'        { return "$([char]27)[$($base + 7)m" }
        '^DarkGray$'    { return "$([char]27)[90m" }
        '^Red$'         { return "$([char]27)[91m" }
        '^Green$'       { return "$([char]27)[92m" }
        '^Yellow$'      { return "$([char]27)[93m" }
        '^Blue$'        { return "$([char]27)[94m" }
        '^Magenta$'     { return "$([char]27)[95m" }
        '^Cyan$'        { return "$([char]27)[96m" }
        '^White$'       { return "$([char]27)[97m" }
        default         { return "" }
    }
}

function Get-AnsiRgbCode {
    param(
        [string]$Spec,
        [bool]$Background = $false
    )

    if ($Spec -notmatch '^Rgb:(\d{1,3}),(\d{1,3}),(\d{1,3})$') { return "" }
    $r = [Math]::Min(255, [Math]::Max(0, [int]$matches[1]))
    $g = [Math]::Min(255, [Math]::Max(0, [int]$matches[2]))
    $b = [Math]::Min(255, [Math]::Max(0, [int]$matches[3]))
    $kind = if ($Background) { 48 } else { 38 }
    return "$([char]27)[$kind;2;$r;$g;${b}m"
}

function Get-AnsiStyleCode {
    param(
        [string]$Color,
        [bool]$Background = $false
    )

    if ([string]::IsNullOrWhiteSpace($Color)) { return "" }
    if ($Color -match '^Rgb:') { return Get-AnsiRgbCode -Spec $Color -Background:$Background }
    return Get-AnsiColorCode -Color $Color -Background:$Background
}

function Write-ConsoleSegment {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$ForegroundColor = "Gray",
        [string]$BackgroundColor = "",
        [switch]$Bold
    )

    $boldAnsi = if ($Bold) { "$([char]27)[1m" } else { "" }
    if ($ForegroundColor -match '^Rgb:' -or $BackgroundColor -match '^Rgb:' -or $Bold) {
        $fg = Get-AnsiStyleCode -Color $ForegroundColor -Background:$false
        $bg = Get-AnsiStyleCode -Color $BackgroundColor -Background:$true
        $reset = "$([char]27)[0m"
        [Console]::Write(("{0}{1}{2}{3}{4}" -f $boldAnsi, $fg, $bg, $Text, $reset))
    } elseif ([string]::IsNullOrWhiteSpace($BackgroundColor)) {
        Write-Host $Text -ForegroundColor $ForegroundColor -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -NoNewline
    }
}

function Move-MenuIndex {
    param(
        [Parameter(Mandatory=$true)][int]$Current,
        [Parameter(Mandatory=$true)][int]$Count,
        [Parameter(Mandatory=$true)][int]$Delta
    )

    if ($Count -le 0) { return 0 }
    $next = $Current + $Delta
    while ($next -lt 0) { $next += $Count }
    while ($next -ge $Count) { $next -= $Count }
    return $next
}

function Write-MenuLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$ForegroundColor = "Gray",
        [string]$BackgroundColor = ""
    )

    $width = 79
    try {
        $width = [Math]::Max(20, [Console]::WindowWidth - 1)
    } catch { }

    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    if ($safe.Length -gt $width) {
        if ($width -gt 1) {
            $safe = $safe.Substring(0, $width - 1) + "…"
        } else {
            $safe = ""
        }
    }
    $padded = $safe.PadRight($width)

    Write-ConsoleSegment -Text $padded -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    Write-Host ""
}

function Write-MenuRichLine {
    param(
        $Segments = @(),
        [string]$BackgroundColor = ""
    )

    if ($null -eq $Segments) { $Segments = @() }

    $width = 79
    try {
        $width = [Math]::Max(20, [Console]::WindowWidth - 1)
    } catch { }

    $used = 0
    foreach ($seg in @($Segments)) {
        if ($null -eq $seg) { continue }
        $t = if ($seg.PSObject.Properties.Name -contains "Text") { [string]$seg.Text } else { [string]$seg }
        $fg = if ($seg.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$seg.Color)) { [string]$seg.Color } else { "Gray" }
        $bg = if ($seg.PSObject.Properties.Name -contains "BackgroundColor") { [string]$seg.BackgroundColor } else { "" }
        $bold = if ($seg.PSObject.Properties.Name -contains "Bold") { [bool]$seg.Bold } else { $false }
        if ($used + $t.Length -gt $width) {
            $remaining = [Math]::Max(0, $width - $used)
            if ($remaining -le 0) { break }
            $t = $t.Substring(0, $remaining)
        }
        Write-ConsoleSegment -Text $t -ForegroundColor $fg -BackgroundColor $bg -Bold:($bold)
        $used += $t.Length
    }

    if ($used -lt $width) {
        Write-ConsoleSegment -Text (" " * ($width - $used)) -ForegroundColor $script:UiDimSilver -BackgroundColor $BackgroundColor
    }
    Write-Host ""
}

function New-MenuRenderLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = "Gray",
        [string]$BackgroundColor = "",
        $Segments = $null
    )

    return [pscustomobject]@{
        Text            = $Text
        Color           = $Color
        BackgroundColor = $BackgroundColor
        Segments        = $(if ($null -eq $Segments) { @() } else { @($Segments) })
    }
}

function Get-MenuItemColor {
    param($Item)
    if ($null -ne $Item -and $Item.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$Item.Color)) {
        return [string]$Item.Color
    }
    return "White"
}

function Invoke-OqgLegacyConsoleMenu {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)]$Items,
        $HeaderLines = @(),
        [string]$Footer = "Use LEFT/RIGHT or UP/DOWN. ENTER opens. ESC backs out.",
        [ValidateSet("Vertical", "Horizontal")][string]$Layout = "Vertical",
        [int]$SelectedIndex = 0
    )

    $itemsArray = @($Items)
    if ($itemsArray.Count -eq 0) { return "Back" }
    if ($SelectedIndex -lt 0 -or $SelectedIndex -ge $itemsArray.Count) { $SelectedIndex = 0 }

    $firstDraw = $true
    $lastLineCount = 0
    $oldCursorVisible = $null
    try {
        $oldCursorVisible = [Console]::CursorVisible
        [Console]::CursorVisible = $false
    } catch { }

    try {
        while ($true) {
            $render = New-Object System.Collections.Generic.List[object]
            [void]$render.Add((New-MenuRenderLine -Text "" -Color $script:UiDimSilver))
            [void]$render.Add((New-MenuRenderLine -Text "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color $script:UiBorderBlue))
            [void]$render.Add((New-MenuRenderLine -Segments (New-GradientSegments -Text ("  {0}" -f $Title) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd)))
            [void]$render.Add((New-MenuRenderLine -Text "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color $script:UiBorderBlue))

            foreach ($line in @($HeaderLines)) {
                if ($null -eq $line) { continue }
                if ($line.PSObject.Properties.Name -contains "Segments" -and @($line.Segments).Count -gt 0) {
                    [void]$render.Add((New-MenuRenderLine -Segments $line.Segments))
                } elseif ($line.PSObject.Properties.Name -contains "Text") {
                    $c = if ($line.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$line.Color)) { [string]$line.Color } else { "Gray" }
                    [void]$render.Add((New-MenuRenderLine -Text ([string]$line.Text) -Color $c))
                } else {
                    [void]$render.Add((New-MenuRenderLine -Text ([string]$line) -Color $script:UiDimSilver))
                }
            }

            [void]$render.Add((New-MenuRenderLine -Text "" -Color $script:UiDimSilver))

            if ($Layout -eq "Horizontal") {
                $rowSegments = @()
                for ($i = 0; $i -lt $itemsArray.Count; $i++) {
                    $item = $itemsArray[$i]
                    $label = [string]$item.Label
                    $displayLabel = if ($i -eq $SelectedIndex) { $label } else { New-NmsWaveText -Text $label -Index $i -SelectedIndex $SelectedIndex }
                    $color = Get-MenuItemColor -Item $item
                    if ($i -eq $SelectedIndex) {
                        $rowSegments += @(New-MenuLabelSegments -Label $displayLabel -Prefix "  ▶ " -Selected:$true)
                        $rowSegments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver -BackgroundColor $script:UiHighlightBlue)
                    } else {
                        $rowSegments += @(New-MenuLabelSegments -Label $displayLabel -Prefix "    " -Selected:$false)
                        $rowSegments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver)
                    }
                }
                [void]$render.Add((New-MenuRenderLine -Segments $rowSegments))
                $hint = [string]$itemsArray[$SelectedIndex].Hint
                if (-not [string]::IsNullOrWhiteSpace($hint)) {
                    [void]$render.Add((New-MenuRenderLine -Text "" -Color $script:UiDimSilver))
                    [void]$render.Add((New-MenuRenderLine -Text ("  {0}" -f $hint) -Color $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue))
                }
            } else {
                for ($i = 0; $i -lt $itemsArray.Count; $i++) {
                    $item = $itemsArray[$i]
                    $label = [string]$item.Label
                    $displayLabel = if ($i -eq $SelectedIndex) { $label } else { New-NmsWaveText -Text $label -Index $i -SelectedIndex $SelectedIndex }
                    $hint = [string]$item.Hint
                    $displayHint = if ($i -eq $SelectedIndex -or -not $script:NmsAnimateHints) { $hint } else { New-NmsWaveText -Text $hint -Index $i -SelectedIndex $SelectedIndex -Bias -0.08 }
                    $color = Get-MenuItemColor -Item $item
                    if ($i -eq $SelectedIndex) {
                        [void]$render.Add((New-MenuRenderLine -Segments (New-MenuLabelSegments -Label $displayLabel -Prefix "  ▶ " -Selected:$true) -BackgroundColor $script:UiHighlightBlue))
                        if (-not [string]::IsNullOrWhiteSpace($hint)) {
                            [void]$render.Add((New-MenuRenderLine -Text ("      {0}" -f $hint) -Color $script:UiSilverBlue -BackgroundColor $script:UiDeepBlue))
                        }
                    } else {
                        [void]$render.Add((New-MenuRenderLine -Segments (New-MenuLabelSegments -Label $displayLabel -Prefix "    " -Selected:$false)))
                        if (-not [string]::IsNullOrWhiteSpace($hint)) {
                            [void]$render.Add((New-MenuRenderLine -Text ("      {0}" -f $displayHint) -Color $script:UiDimSilver))
                        }
                    }
                }
            }

            [void]$render.Add((New-MenuRenderLine -Text "" -Color $script:UiDimSilver))
            [void]$render.Add((New-MenuRenderLine -Text $Footer -Color $script:UiDimBone))

            if ($firstDraw) {
                Clear-Host
                $firstDraw = $false
            } else {
                try {
                    [Console]::SetCursorPosition(0, 0)
                } catch {
                    Clear-Host
                }
            }

            foreach ($line in $render) {
                if ($line.PSObject.Properties.Name -contains "Segments" -and @($line.Segments).Count -gt 0) {
                    Write-MenuRichLine -Segments $line.Segments -BackgroundColor ([string]$line.BackgroundColor)
                } else {
                    Write-MenuLine -Text ([string]$line.Text) -ForegroundColor ([string]$line.Color) -BackgroundColor ([string]$line.BackgroundColor)
                }
            }

            if ($lastLineCount -gt $render.Count) {
                for ($i = $render.Count; $i -lt $lastLineCount; $i++) {
                    Write-MenuLine -Text "" -ForegroundColor $script:UiDimSilver
                }
            }
            $lastLineCount = $render.Count

            try {
                $keyState = Read-KeyOrNmsWaveTimeout
                if (-not $keyState.HasKey) { Advance-NmsWave; continue }
                $key = $keyState.Key
            } catch {
                $fallback = (Read-OqgPrompt "Choose").Trim()
                if ($fallback -match "^[\x03\x11\x1A]$") {
                    Write-QuitGuardNotice
                    continue
                }
                foreach ($item in $itemsArray) {
                    if ($fallback -eq [string]$item.Shortcut -or $fallback -eq [string]$item.Label) {
                        return [string]$item.Value
                    }
                }
                if ([string]::IsNullOrWhiteSpace($fallback)) { return "Back" }
                continue
            }

            if (Test-BlockedControlQuitKey -KeyInfo $key) {
                Write-QuitGuardNotice
                $firstDraw = $true
                continue
            }

            switch ($key.Key) {
                "N" { Switch-OqgMenuNms; $firstDraw = $true }
                "LeftArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Advance-NmsWave; Clear-PendingConsoleKeys }
                "UpArrow"    { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Advance-NmsWave; Clear-PendingConsoleKeys }
                "RightArrow" { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Advance-NmsWave; Clear-PendingConsoleKeys }
                "DownArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Advance-NmsWave; Clear-PendingConsoleKeys }
                "Enter"      { return [string]$itemsArray[$SelectedIndex].Value }
                "Escape"     { return "Back" }
                default {
                    $ch = [string]$key.KeyChar
                    if (-not [string]::IsNullOrWhiteSpace($ch)) {
                        foreach ($item in $itemsArray) {
                            if ($ch -eq [string]$item.Shortcut) { return [string]$item.Value }
                        }
                    }
                }
            }
        }
    } finally {
        try {
            if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible }
        } catch { }
    }
}


function Get-NonClobberPath {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $Path }

    $dir = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $ext = [System.IO.Path]::GetExtension($leaf)

    for ($i = 1; $i -lt 10000; $i++) {
        $candidate = Join-Path $dir ("{0}_{1}{2}" -f $name, $i, $ext)
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    }

    throw "Could not create a non-conflicting output path for: $Path"
}


function Select-KeyFileArrowInteractive {
    param(
        [string]$StartFolder,
        [string]$Purpose = "Import OpenPGP key"
    )

    if ([string]::IsNullOrWhiteSpace($StartFolder) -or -not (Test-Path -LiteralPath $StartFolder -PathType Container)) {
        $StartFolder = (Get-Location).Path
    }

    $current = (Resolve-Path -LiteralPath $StartFolder).Path
    $selected = 0
    $oldCursorVisible = $null
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }

    try {
        while ($true) {
            $dirs = @(Get-ChildItem -LiteralPath $current -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)
            $files = @(Get-ChildItem -LiteralPath $current -File -Force -ErrorAction SilentlyContinue |
                Sort-Object @{ Expression = { if ($_.Extension -match '(?i)^\.(asc|gpg|pgp|key|pub|sec|txt)$') { 0 } else { 1 } } }, Name)

            $items = @()
            $parent = Split-Path -Parent $current
            if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) {
                $items += [pscustomobject]@{ Type = "UP"; Name = ".."; FullName = $parent; Size = $null }
            }
            foreach ($d in $dirs) { $items += [pscustomobject]@{ Type = "DIR"; Name = $d.Name; FullName = $d.FullName; Size = $null } }
            foreach ($f in $files) { $items += [pscustomobject]@{ Type = "FILE"; Name = $f.Name; FullName = $f.FullName; Size = $f.Length } }

            if ($items.Count -eq 0) { $selected = 0 } elseif ($selected -ge $items.Count) { $selected = $items.Count - 1 }
            if ($selected -lt 0) { $selected = 0 }

            $windowHeight = 30
            try { $windowHeight = [Math]::Max(18, [Console]::WindowHeight - 10) } catch { }
            $maxVisible = [Math]::Min(24, $windowHeight)
            $start = 0
            if ($items.Count -gt $maxVisible) {
                $start = [Math]::Max(0, $selected - [Math]::Floor($maxVisible / 2))
                if (($start + $maxVisible) -gt $items.Count) { $start = [Math]::Max(0, $items.Count - $maxVisible) }
            }
            $end = if ($items.Count -eq 0) { -1 } else { [Math]::Min($items.Count - 1, $start + $maxVisible - 1) }

            Write-Banner -Title $Purpose
            Write-Host "Use UP/DOWN to move, ENTER to open/select, BACKSPACE to go up, ESC to cancel." -ForegroundColor $script:UiDimSilver
            Write-Host "Current folder:" -ForegroundColor $script:UiDimSilver
            Write-Host ("  {0}" -f (Format-DisplayPath $current)) -ForegroundColor $script:UiWhiteSilver
            Write-Host ""

            if ($items.Count -eq 0) {
                Write-Host "  Folder is empty." -ForegroundColor $script:UiDimSilver
            } else {
                if ($start -gt 0) { Write-Host "  ..." -ForegroundColor $script:UiDimSilver }
                for ($i = $start; $i -le $end; $i++) {
                    $entry = $items[$i]
                    $prefix = if ($i -eq $selected) { "  ▶ " } else { "    " }
                    $typeText = switch ($entry.Type) {
                        "UP"   { "[UP  ]" }
                        "DIR"  { "[DIR ]" }
                        default { "[KEY ]" }
                    }
                    $name = if ($entry.Type -eq "DIR") { "{0}\" -f $entry.Name } else { [string]$entry.Name }
                    if ($entry.Type -eq "FILE") { $name = "{0}  ({1})" -f $name, (Format-Size $entry.Size) }
                    $line = "{0}{1} {2}" -f $prefix, $typeText, $name
                    if ($i -eq $selected) {
                        Write-MenuLine -Text $line -ForegroundColor $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue
                    } else {
                        $color = if ($entry.Type -eq "FILE") { $script:UiSilverBlue } else { $script:UiDimSilver }
                        Write-Host $line -ForegroundColor $color
                    }
                }
                if ($end -lt ($items.Count - 1)) { Write-Host "  ..." -ForegroundColor $script:UiDimSilver }
            }

            $key = [Console]::ReadKey($true)
            if (Test-BlockedControlQuitKey -KeyInfo $key) { Write-QuitGuardNotice; continue }
            switch ($key.Key) {
                "UpArrow"   { if ($items.Count -gt 0) { $selected = Move-MenuIndex -Current $selected -Count $items.Count -Delta -1 } }
                "DownArrow" { if ($items.Count -gt 0) { $selected = Move-MenuIndex -Current $selected -Count $items.Count -Delta 1 } }
                "Backspace" {
                    if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) {
                        $current = (Resolve-Path -LiteralPath $parent).Path
                        $selected = 0
                    }
                }
                "Enter" {
                    if ($items.Count -eq 0) { continue }
                    $entry = $items[$selected]
                    if ($entry.Type -eq "FILE") { return [string]$entry.FullName }
                    if (Test-Path -LiteralPath $entry.FullName -PathType Container) {
                        $current = (Resolve-Path -LiteralPath $entry.FullName).Path
                        $selected = 0
                    }
                }
                "Escape" { return $null }
                default {
                    $ch = [string]$key.KeyChar
                    if ($ch -match '^(?i)q$') { return $null }
                    if ($ch -match '^(?i)u$') {
                        if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) {
                            $current = (Resolve-Path -LiteralPath $parent).Path
                            $selected = 0
                        }
                    }
                }
            }
            Clear-PendingConsoleKeys
        }
    } finally {
        try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { }
    }
}

function Import-KeyFromFolderWorkflow {
    if (-not (Request-UidGateAccess -Reason "OpenPGP key import")) { return }
    $keyFile = Select-KeyFileArrowInteractive -StartFolder $script:DefaultStartFolder -Purpose "Import OpenPGP key from folder"
    if ([string]::IsNullOrWhiteSpace($keyFile)) { return }

    Write-Banner -Title "Import OpenPGP key"
    Write-Host "Selected key file:" -ForegroundColor $script:UiDimSilver
    Write-Host ("  {0}" -f (Format-DisplayPath $keyFile)) -ForegroundColor $script:UiWhiteSilver
    Write-Host ""
    Write-Host "This will run local GnuPG import. Public certificates are safe to import; secret-key files are sensitive." -ForegroundColor $script:UiDimSilver
    if (-not (Read-YesNo "Import this key material now?" $false)) { return }

    Write-Host ""
    Write-Host "Running GnuPG import..." -ForegroundColor $script:UiDimSilver
    $result = Invoke-GpgCaptured -Arguments @("--import", $keyFile)
    if ($result.ExitCode -eq 0) {
        Invoke-NmsOperationReveal -Lines @("KEY IMPORT COMPLETE", ("INPUT :: {0}" -f (Format-DisplayPath $keyFile)))
        Write-Host "GnuPG import summary:" -ForegroundColor $script:UiSilverBlue
        @($result.Output) | ForEach-Object { Write-Host ("  {0}" -f (Redact-PrivateText $_)) -ForegroundColor Gray }
        Write-Host ""
        if (Read-YesNo "Switch active fingerprint after import?" $false) {
            Switch-ActiveFingerprintWorkflow
        }
    } else {
        Write-GpgFailure -Result $result -ActionName "Key import"
    }
    Wait-User
}

function Get-TextSubkeyAlgorithmMap {
    $map = @{}
    $r = Invoke-GpgCaptured -Arguments @("--list-keys", "--keyid-format", "LONG", $script:IdentityFingerprint)
    foreach ($line in @($r.Output)) {
        # Example: sub   ky768_cv25519/38488040C0D1298A 2026-06-06 [E]
        if ($line -match '^\s*sub\s+([^/\s]+)/([0-9A-Fa-f]{16})\s+') {
            $kid = $matches[2].ToUpperInvariant()
            $map[$kid] = [string]$matches[1]
        }
    }
    return $map
}

function Test-PqcLikeSubkey {
    param([Parameter(Mandatory=$true)]$Subkey)
    $hay = "{0} {1} {2} {3} {4}" -f $Subkey.DisplayAlgo, $Subkey.Curve, $Subkey.Algo, $Subkey.KeyId, $Subkey.Capabilities
    return ($hay -match '(?i)(ky|kyber|kem|mlkem|ml-kem|pqc)')
}


function Get-StrengthColor {
    param([int]$Score)

    if ($Score -le 0) { return $script:UiDimSilver }
    if ($Score -le 2) { return $script:UiMidBlue }
    if ($Score -le 4) { return "Rgb:82,124,184" }
    if ($Score -le 6) { return $script:UiLightBlue }
    if ($Score -le 8) { return $script:UiSilverBlue }
    return $script:UiWhiteSilver
}

function Get-StrengthBucketColor {
    param([int]$Position)

    if ($Position -le 1) { return $script:UiBorderBlue }
    if ($Position -le 2) { return $script:UiMidBlue }
    if ($Position -le 3) { return "Rgb:82,124,184" }
    if ($Position -le 4) { return $script:UiLightBlue }
    if ($Position -le 5) { return $script:UiSilverBlue }
    return $script:UiWhiteSilver
}


function Get-StrengthPlainBar {
    param([int]$Score)
    if ($Score -le 0) { return "[unknown]" }

    $filled = [Math]::Ceiling(([double]$Score / 10.0) * 6.0)
    $filled = [Math]::Min(6, [Math]::Max(1, [int]$filled))
    $bar = ""
    for ($cell = 1; $cell -le 6; $cell++) {
        $bar += $(if ($cell -le $filled) { "█" } else { "░" })
    }
    return ("[{0}/10] [{1}]" -f $Score, $bar)
}

function Get-StrengthRatingSegments {
    param([int]$Score)

    if ($Score -le 0) {
        return @((New-ConsoleSegment -Text "[unknown]" -Color $script:UiDimSilver))
    }

    $segments = @()
    $segments += (New-ConsoleSegment -Text "[" -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text ([string]$Score) -Color (Get-StrengthColor -Score $Score))
    $segments += (New-ConsoleSegment -Text "/" -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text "10" -Color $script:UiWhiteSilver)
    $segments += (New-ConsoleSegment -Text "] [" -Color $script:UiDimSilver)
    $segments += @(Get-StrengthBarSegments -Score $Score)
    $segments += (New-ConsoleSegment -Text "]" -Color $script:UiDimSilver)
    return @($segments)
}

function Get-StrengthRatingText {
    param([int]$Score)
    if ($Score -le 0) { return "[unknown]" }
    return (Get-StrengthPlainBar -Score $Score)
}
function Get-EncryptionKindBaseLabel {
    param($Subkey)

    if ($null -ne $Subkey -and (Test-PqcLikeSubkey $Subkey)) { return "KYBER/HYBRID/PQC" }
    return "CLASSIC"
}

function Get-EncryptionKindLabel {
    param($Subkey)

    $score = [int](Get-EncryptionStrengthScore -Subkey $Subkey)
    return "{0} {1}" -f (Get-EncryptionKindBaseLabel -Subkey $Subkey), (Get-StrengthRatingText -Score $score)
}

function New-StrengthLineSegments {
    param(
        [string]$Prefix = "",
        [string]$Name,
        [int]$Score,
        [string]$Suffix = ""
    )

    $segments = @()
    if (-not [string]::IsNullOrEmpty($Prefix)) { $segments += (New-ConsoleSegment -Text $Prefix -Color $script:UiDimSilver) }
    $segments += (New-ConsoleSegment -Text $Name -Color $script:UiWhiteSilver)
    $segments += (New-ConsoleSegment -Text " " -Color $script:UiDimSilver)
    $segments += @(Get-StrengthRatingSegments -Score $Score)
    if (-not [string]::IsNullOrEmpty($Suffix)) { $segments += (New-ConsoleSegment -Text $Suffix -Color $script:UiDimSilver) }
    return @($segments)
}

function Write-StrengthLine {
    param(
        [string]$Prefix = "",
        [string]$Name,
        [int]$Score,
        [string]$Suffix = ""
    )

    Write-MenuRichLine -Segments (New-StrengthLineSegments -Prefix $Prefix -Name $Name -Score $Score -Suffix $Suffix)
}

function Get-GpgIdentityInfo {
    $args = @(
        "--batch",
        "--with-colons",
        "--with-fingerprint",
        "--with-fingerprint",
        "--list-keys",
        $script:IdentityFingerprint
    )

    $r = Invoke-GpgCaptured -Arguments $args
    if ($r.ExitCode -ne 0) {
        throw "Could not read public key for $script:IdentityFingerprint.`n$($r.Output -join "`n")"
    }

    $primaryFpr = ""
    $uids = @()
    $subRows = @()
    $currentKind = ""
    $currentSubIndex = -1
    $textAlgoByKeyId = Get-TextSubkeyAlgorithmMap

    foreach ($line in @($r.Output)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }
        $fields = @($line -split ":", -1)
        if ($fields.Count -lt 1) { continue }
        $type = [string]$fields[0]

        switch ($type) {
            "pub" {
                $currentKind = "pub"
                $currentSubIndex = -1
            }
            "uid" {
                if ($fields.Count -gt 9 -and -not [string]::IsNullOrWhiteSpace([string]$fields[9])) {
                    $uids += [string]$fields[9]
                }
                $currentKind = "uid"
                $currentSubIndex = -1
            }
            "sub" {
                $keyId = if ($fields.Count -gt 4) { [string]$fields[4] } else { "" }
                $keyIdNorm = $keyId.ToUpperInvariant()
                $displayAlgo = ""
                if ($textAlgoByKeyId.ContainsKey($keyIdNorm)) {
                    $displayAlgo = [string]$textAlgoByKeyId[$keyIdNorm]
                }

                $row = [ordered]@{
                    KeyId        = $keyId
                    Length       = if ($fields.Count -gt 2) { [string]$fields[2] } else { "" }
                    Algo         = if ($fields.Count -gt 3) { [string]$fields[3] } else { "" }
                    Created      = if ($fields.Count -gt 5) { Convert-GpgDate ([string]$fields[5]) } else { "" }
                    Expires      = if ($fields.Count -gt 6) { Convert-GpgDate ([string]$fields[6]) } else { "" }
                    Capabilities = if ($fields.Count -gt 11) { [string]$fields[11] } else { "" }
                    Curve        = if ($fields.Count -gt 16) { [string]$fields[16] } else { "" }
                    DisplayAlgo  = $displayAlgo
                    Fingerprint  = ""
                }

                $subRows += $row
                $currentKind = "sub"
                $currentSubIndex = $subRows.Count - 1
            }
            "fpr" {
                $fpr = if ($fields.Count -gt 9) { Normalize-Fingerprint ([string]$fields[9]) } else { "" }
                if ([string]::IsNullOrWhiteSpace($fpr)) { continue }

                if ($currentKind -eq "pub") {
                    $primaryFpr = $fpr
                } elseif ($currentKind -eq "sub" -and $currentSubIndex -ge 0 -and $currentSubIndex -lt $subRows.Count) {
                    $subRows[$currentSubIndex]["Fingerprint"] = $fpr
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($primaryFpr)) {
        $primaryFpr = $script:IdentityFingerprint
    }

    $subkeys = @()
    foreach ($row in @($subRows)) {
        $subkeys += [pscustomobject]$row
    }

    return [pscustomobject]@{
        PrimaryFingerprint = $primaryFpr
        Uids               = @($uids)
        Subkeys            = @($subkeys)
    }
}

function Show-EncryptionSubkeys {
    param([Parameter(Mandatory=$true)]$Info)

    $enc = @($Info.Subkeys | Where-Object {
        ([string]$_.Capabilities) -match '[eE]' -and -not [string]::IsNullOrWhiteSpace([string]$_.Fingerprint)
    })

    if ($enc.Count -eq 0) {
        Write-Host "No encryption subkeys were found under this identity." -ForegroundColor $script:UiLightBlue
        return @()
    }

    Write-Host "Encryption-capable subkeys under the active identity:" -ForegroundColor $script:UiSilverBlue
    Write-Host ""
    for ($i = 0; $i -lt $enc.Count; $i++) {
        $n = $i + 1
        $s = $enc[$i]
        $kind = Get-EncryptionKindBaseLabel -Subkey $s
        $score = [int](Get-EncryptionStrengthScore -Subkey $s)
        $exp = if ([string]::IsNullOrWhiteSpace([string]$s.Expires)) { "no expiry" } else { [string]$s.Expires }
        $displayAlgo = if ([string]::IsNullOrWhiteSpace([string]$s.DisplayAlgo)) { "text alg unavailable" } else { [string]$s.DisplayAlgo }
        $curve = if ([string]::IsNullOrWhiteSpace([string]$s.Curve)) { "curve field unavailable" } else { [string]$s.Curve }
        Write-StrengthLine -Prefix ("{0,3}. " -f $n) -Name $kind -Score $score -Suffix ("  {0}" -f (Short-Fpr ([string]$s.Fingerprint)))
        Write-Host ("     KeyId: {0}" -f $s.KeyId) -ForegroundColor Gray
        Write-Host ("     Fingerprint: {0}" -f $s.Fingerprint) -ForegroundColor Gray
        Write-Host ("     Algo/curve: {0}/{1}/{2}, capabilities: {3}, expires: {4}" -f $s.Algo, $displayAlgo, $curve, $s.Capabilities, $exp) -ForegroundColor Gray
    }
    Write-Host ""
    return @($enc)
}


function Show-RawGpgListing {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)]$Result,
        [bool]$Redact = $true
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor $script:UiSilverBlue
    Write-Host ("Exit code: {0}" -f $Result.ExitCode) -ForegroundColor $script:UiDimSilver
    Write-Host ""
    foreach ($line in @($Result.Output)) {
        if ($Redact) {
            Write-Host (Redact-PrivateText $line)
        } else {
            Write-Host $line
        }
    }
}

function Show-KeyConsoleMenu {
    param(
        [Parameter(Mandatory=$true)]$PublicResult,
        $SecretResult
    )

    while ($true) {
        $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
        $modeColor = if (Test-ShareableOutput) { $script:UiGreen } else { $script:UiRose }
        $secretHint = if (Test-ShareableOutput) { "Hidden in Shareable mode." } else { "Local secret-key inventory from GnuPG." }
        $fullHint = if (Test-ShareableOutput) { "Public status only, secret inventory stays hidden." } else { "Public certificate plus secret-key inventory." }

        $header = @(
            (New-ConsoleLine -Text ("  FPR : {0}" -f (Short-Fpr $script:IdentityFingerprint)) -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text ("  Mode: {0}" -f $modeText) -Color $modeColor),
            (New-ConsoleLine -Text "  Console: inspect listings, compare status, export material" -Color $script:UiDimSilver)
        )

        $items = @(
            (New-ConsoleMenuItem -Label "Public identity" -Value "Public" -Hint "Public certificate, UIDs, public subkeys, fingerprints." -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Secret inventory" -Value "Secret" -Hint $secretHint -Color $(if (Test-ShareableOutput) { "DarkGray" } else { "White" }) -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Full status" -Value "Both" -Hint $fullHint -Color $(if (Test-ShareableOutput) { "DarkGray" } else { "White" }) -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Export" -Value "Export" -Hint "Export public cert, secret subkeys, or full backup." -Color $script:UiWhiteSilver -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to key status." -Color $script:UiDimSilver -Shortcut "b")
        )

        $choice = Invoke-ConsoleMenu -Title "OpenPGP Key Console" -HeaderLines $header -Items $items -Layout "Vertical"
        switch ($choice) {
            "Public" {
                Clear-Host
                Show-RawGpgListing -Title "Public identity" -Result $PublicResult -Redact:$true
                Wait-User
            }
            "Secret" {
                Clear-Host
                if (Test-ShareableOutput) {
                    Write-Host "Secret inventory is hidden in Shareable mode." -ForegroundColor $script:UiDimSilver
                    Wait-User
                } else {
                    Show-RawGpgListing -Title "Secret inventory" -Result $SecretResult -Redact:$false
                    Wait-User
                }
            }
            "Both" {
                Clear-Host
                Show-RawGpgListing -Title "Public identity" -Result $PublicResult -Redact:$true
                if (Test-ShareableOutput) {
                    Write-Host ""
                    Write-Host "Secret inventory hidden in Shareable mode." -ForegroundColor $script:UiDimSilver
                } else {
                    Show-RawGpgListing -Title "Secret inventory" -Result $SecretResult -Redact:$false
                }
                Wait-User
            }
            "Export" { Show-KeyExportMenu }
            "Back" { return }
            default { return }
        }
    }
}

function Get-DefaultExportPath {
    param([Parameter(Mandatory=$true)][string]$Kind)

    $folder = $script:DefaultStartFolder
    if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder -PathType Container)) {
        $folder = (Get-Location).Path
    }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $short = Short-Fpr $script:IdentityFingerprint
    $safeKind = ($Kind -replace '[^A-Za-z0-9_-]', '_').ToLowerInvariant()
    $name = "openpgp_quantum_guard_${safeKind}_${short}_${stamp}.asc"
    return (Get-NonClobberPath -Path (Join-Path $folder $name))
}

function Read-ExportPath {
    param([Parameter(Mandatory=$true)][string]$DefaultPath)

    Write-Host "" 
    Write-Host "Default export path:" -ForegroundColor Gray
    Write-Host "  $(Format-DisplayPath $DefaultPath)" -ForegroundColor White

    if (Read-YesNo "Use this export path?" $true) {
        return $DefaultPath
    }

    $custom = (Read-OqgPrompt "Export path").Trim('"')
    if ([string]::IsNullOrWhiteSpace($custom)) {
        return $DefaultPath
    }
    return $custom
}

function Confirm-DangerousExport {
    param(
        [Parameter(Mandatory=$true)][string]$MaterialName,
        [Parameter(Mandatory=$true)][string]$Phrase
    )

    $cleanMaterialName = ([string]$MaterialName -replace '^(?i)Export\s+', '')

    Write-Host "" 
    Write-Host "Sensitive export warning" -ForegroundColor $script:UiLightBlue
    Write-Host "  Sensitive material: $cleanMaterialName" -ForegroundColor White
    Write-Host "  Anyone who gets this file may be able to use your OpenPGP identity if they can unlock it." -ForegroundColor White
    Write-Host "  Store it offline, encrypted, and never post it in screenshots, chats, tickets, or cloud notes." -ForegroundColor White
    Write-Host "" 
    Write-Host "To continue, type exactly:" -ForegroundColor Gray
    Write-Host "  $Phrase" -ForegroundColor White
    $typed = Read-OqgPrompt "Confirmation"
    return ($typed -ceq $Phrase)
}

function Invoke-KeyExport {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$GpgExportVerb,
        [Parameter(Mandatory=$true)][string]$DefaultKind,
        [bool]$Dangerous = $false,
        [string]$DangerPhrase = ""
    )

    Write-Banner -Title $Title

    if ($Dangerous) {
        if (-not (Confirm-DangerousExport -MaterialName $Title -Phrase $DangerPhrase)) {
            Write-Host "Export cancelled. Confirmation phrase did not match." -ForegroundColor $script:UiDimSilver
            Wait-User
            return
        }
    }

    $defaultPath = Get-DefaultExportPath -Kind $DefaultKind
    $outPath = Read-ExportPath -DefaultPath $defaultPath

    $parent = Split-Path -Parent $outPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        if (Read-YesNo "Export folder does not exist. Create it?" $true) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        } else {
            Write-Host "Export cancelled." -ForegroundColor $script:UiDimSilver
            Wait-User
            return
        }
    }

    if ((Test-Path -LiteralPath $outPath) -and -not (Read-YesNo "File already exists. Overwrite it?" $false)) {
        $outPath = Get-NonClobberPath -Path $outPath
        Write-Host "Using non-conflicting path:" -ForegroundColor Gray
        Write-Host "  $(Format-DisplayPath $outPath)" -ForegroundColor White
    }

    $args = @("--armor", "--output", $outPath) + $GpgExportVerb + @($script:IdentityFingerprint)

    Write-Host "" 
    Write-Host "Running GnuPG export..." -ForegroundColor $script:UiDimSilver
    $result = Invoke-GpgCaptured -Arguments $args

    if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $outPath)) {
        Write-Host "" 
        Write-Host "Export completed:" -ForegroundColor $script:UiWhiteSilver
        Write-Host "  $(Format-DisplayPath $outPath)" -ForegroundColor White

        if ($Dangerous) {
            Write-Host "" 
            Write-Host "Treat this file as secret material. Move it to encrypted offline storage." -ForegroundColor $script:UiLightBlue
        } else {
            Write-Host "This public certificate export is shareable." -ForegroundColor $script:UiWhiteSilver
        }
    } else {
        Write-GpgFailure -Result $result -ActionName "Key export"
    }

    Wait-User
}

function Show-KeyExportMenu {
    while ($true) {
        $header = @(
            (New-ConsoleLine -Text ("  FPR : {0}" -f $script:IdentityFingerprint) -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text "  Public export is shareable. Secret exports are sensitive." -Color $script:UiDimSilver)
        )
        $items = @(
            (New-ConsoleMenuItem -Label "Public cert" -Value "Public" -Hint "Shareable public OpenPGP certificate." -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Secret subkeys" -Value "SecretSubkeys" -Hint "Sensitive working-machine export. Primary secret key exported as a stub." -Color $script:UiWhiteSilver -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Full secret backup" -Value "FullSecret" -Hint "Highly sensitive offline recovery backup." -Color $script:UiLightBlue -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to previous console." -Color $script:UiDimSilver -Shortcut "b")
        )

        $choice = Invoke-ConsoleMenu -Title "Export OpenPGP material" -HeaderLines $header -Items $items -Layout "Vertical"
        switch ($choice) {
            "Public" {
                Invoke-KeyExport `
                    -Title "Export public certificate" `
                    -GpgExportVerb @("--export") `
                    -DefaultKind "public_certificate" `
                    -Dangerous:$false
            }
            "SecretSubkeys" {
                Invoke-KeyExport `
                    -Title "Export secret subkeys" `
                    -GpgExportVerb @("--export-secret-subkeys") `
                    -DefaultKind "secret_subkeys" `
                    -Dangerous:$true `
                    -DangerPhrase "EXPORT SECRET SUBKEYS"
            }
            "FullSecret" {
                Invoke-KeyExport `
                    -Title "Export full secret key backup" `
                    -GpgExportVerb @("--export-secret-keys") `
                    -DefaultKind "full_secret_key_backup" `
                    -Dangerous:$true `
                    -DangerPhrase "EXPORT FULL SECRET KEY"
            }
            "Back" { return }
            default { return }
        }
    }
}

function Show-KeyStatus {
    while ($true) {
        $modeColor = if (Test-ShareableOutput) { $script:UiGreen } else { $script:UiRose }
        $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }

        $pub = Invoke-GpgCaptured -Arguments @("--list-keys", "--keyid-format", "LONG", "--fingerprint", "--fingerprint", $script:IdentityFingerprint)
        $sec = $null
        if (-not (Test-ShareableOutput)) {
            $sec = Invoke-GpgCaptured -Arguments @("--list-secret-keys", "--keyid-format", "LONG", "--fingerprint", "--fingerprint", $script:IdentityFingerprint)
        }

        $pubStatus = if ($pub.ExitCode -eq 0) { "OK" } else { "ERROR" }
        $pubColor = if ($pub.ExitCode -eq 0) { "Green" } else { "Red" }

        $secretText = "hidden by output mode"
        $secretColor = "DarkGray"
        if (-not (Test-ShareableOutput)) {
            $secText = if ($sec) { $sec.Output -join "`n" } else { "" }
            if ($sec.ExitCode -ne 0) {
                $secretText = "ERROR reading local inventory"
                $secretColor = "Red"
            } elseif ($secText -match '(?m)^\s*(sec|ssb)#') {
                $secretText = "WARNING, GnuPG printed sec# or ssb#"
                $secretColor = "Red"
            } else {
                $secretText = "OK"
                $secretColor = "Green"
            }
        }

        $header = @(
            (New-ConsoleLine -Text ("  FPR : {0}" -f $script:IdentityFingerprint) -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text ("  UID : {0}" -f $script:ExpectedUidHint) -Color $script:UiDimSilver),
            (New-ConsoleRichLine -Segments (New-StrengthLineSegments -Prefix ("  Mode: {0}    PQC: " -f $modeText) -Name "Kyber / ML-KEM hybrid" -Score 10)),
            (New-ConsoleLine -Text "" -Color $script:UiDimSilver),
            (New-ConsoleLine -Text ("  Public cert : {0}" -f $pubStatus) -Color $pubColor),
            (New-ConsoleLine -Text ("  Secret keys : {0}" -f $secretText) -Color $secretColor),
            (New-ConsoleLine -Text "" -Color $script:UiDimSilver),
            (New-ConsoleLine -Text "  Encryption subkeys:" -Color $script:UiRose)
        )

        try {
            $info = Get-GpgIdentityInfo
            $enc = @($info.Subkeys | Where-Object {
                ([string]$_.Capabilities) -match '[eE]' -and -not [string]::IsNullOrWhiteSpace([string]$_.Fingerprint)
            })

            if ($enc.Count -eq 0) {
                $header += (New-ConsoleLine -Text "    none found" -Color $script:UiLightBlue)
            } else {
                for ($i = 0; $i -lt $enc.Count; $i++) {
                    $s = $enc[$i]
                    $kind = Get-EncryptionKindBaseLabel -Subkey $s
                    $score = [int](Get-EncryptionStrengthScore -Subkey $s)
                    $algo = if ([string]::IsNullOrWhiteSpace([string]$s.DisplayAlgo)) { [string]$s.Algo } else { [string]$s.DisplayAlgo }
                    $exp = if ([string]::IsNullOrWhiteSpace([string]$s.Expires)) { "no expiry" } else { [string]$s.Expires }
                    $n = $i + 1
                    $suffix = ("  {0,-18} {1}  exp:{2}" -f $algo, (Short-Fpr ([string]$s.Fingerprint)), $exp)
                    $header += (New-ConsoleRichLine -Segments (New-StrengthLineSegments -Prefix ("    {0}. " -f $n) -Name $kind -Score $score -Suffix $suffix))
                }
            }
        } catch {
            $header += (New-ConsoleLine -Text "    parser error. Open the console below for GnuPG output." -Color $script:UiLightBlue)
            $header += (New-ConsoleLine -Text ("    {0}" -f (Redact-PrivateText $_.Exception.Message)) -Color $script:UiDimSilver)
        }

        $header += (New-ConsoleLine -Text "" -Color $script:UiDimSilver)
        $header += (New-ConsoleLine -Text "  Subkey numbers are display rows. Use the action selector below." -Color $script:UiDimSilver)

        $items = @(
            (New-ConsoleMenuItem -Label "Console" -Value "Console" -Hint "Open public/secret key details and full status views." -Color $script:UiRose -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Export" -Value "Export" -Hint "Export public cert, secret subkeys, or full backup." -Color $script:UiWhiteSilver -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to main menu." -Color $script:UiDimSilver -Shortcut "b")
        )

        $choice = Invoke-ConsoleMenu -Title "OpenPGP key status" -HeaderLines $header -Items $items -Layout "Horizontal"
        switch ($choice) {
            "Console" { Show-KeyConsoleMenu -PublicResult $pub -SecretResult $sec }
            "Export" { Show-KeyExportMenu }
            "Back" { return }
            default { return }
        }
    }
}


function Decrypt-FileWorkflow {
    Write-Banner -Title "Decrypt OpenPGP file"

    if (Test-ShareableOutput) {
        Write-Host "GnuPG will read the encrypted packet and use the matching local key, while shareable output hides local machine details." -ForegroundColor Gray
    } else {
        Write-Host "Decryption does not force a UID or recipient." -ForegroundColor Gray
        Write-Host "GnuPG reads the encrypted packet and uses the matching local private key." -ForegroundColor Gray
    }
    Write-Host ""

    $inputFile = Select-FileInteractive -StartFolder $script:DefaultStartFolder -Purpose "Choose file to decrypt"
    if (-not $inputFile) { return }

    $defaultOut = Get-NonClobberPath -Path (Get-DefaultDecryptOutputPath -InputFile $inputFile)
    Write-Host ""
    Write-Host "Default output:" -ForegroundColor Gray
    Write-Host "  $(Format-DisplayPath $defaultOut)" -ForegroundColor White

    $outPath = $defaultOut
    if (-not (Read-YesNo "Use this output path?" $true)) {
        $custom = (Read-OqgPrompt "Output path").Trim('"')
        if (-not [string]::IsNullOrWhiteSpace($custom)) {
            $outPath = $custom
        }
    }

    $gpgArgs = @("--yes", "--output", $outPath, "--decrypt", $inputFile)

    Write-Host ""
    Write-Host "Running GnuPG..." -ForegroundColor $script:UiDimSilver
    $result = Invoke-GpgCaptured -Arguments $gpgArgs

    if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $outPath)) {
        Write-Host ""
        Invoke-NmsOperationReveal -Lines @(
            "DECRYPTION COMPLETE",
            ("OUTPUT :: {0}" -f (Format-DisplayPath $outPath))
        )
        Write-Host "Decrypted successfully:" -ForegroundColor $script:UiWhiteSilver
        Write-Host "  $(Format-DisplayPath $outPath)" -ForegroundColor White
        Write-Host ""
        Write-Host "GnuPG messages, including signature verification if present:" -ForegroundColor $script:UiSilverBlue
        $result.Output | ForEach-Object { Write-Host ("  {0}" -f (Redact-PrivateText $_)) -ForegroundColor Gray }
    } else {
        if (Test-Path -LiteralPath $outPath) {
            try {
                $created = Get-Item -LiteralPath $outPath -ErrorAction Stop
                if ($created.Length -eq 0) {
                    Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        Write-GpgFailure -Result $result -ActionName "Decryption"
    }

    Wait-User
}

function Get-PublicPrimaryKeyRows {
    $r = Invoke-GpgCaptured -Arguments @("--batch", "--with-colons", "--with-fingerprint", "--list-keys")
    $rows = @()
    $current = $null
    foreach ($line in @($r.Output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = @($line -split ":", -1)
        if ($f.Count -lt 1) { continue }
        switch ($f[0]) {
            "pub" {
                if ($null -ne $current) { $rows += [pscustomobject]$current }
                $current = [ordered]@{ Fingerprint=""; KeyId=$(if($f.Count -gt 4){[string]$f[4]}else{""}); Created=$(if($f.Count -gt 5){Convert-GpgDate ([string]$f[5])}else{""}); Expires=$(if($f.Count -gt 6){Convert-GpgDate ([string]$f[6])}else{""}); Uids=@() }
            }
            "fpr" {
                if ($null -ne $current -and $f.Count -gt 9 -and [string]::IsNullOrWhiteSpace([string]$current.Fingerprint)) { $current.Fingerprint = Normalize-Fingerprint ([string]$f[9]) }
            }
            "uid" {
                if ($null -ne $current -and $f.Count -gt 9) { $current.Uids += [string]$f[9] }
            }
        }
    }
    if ($null -ne $current) { $rows += [pscustomobject]$current }
    return @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Fingerprint) })
}


function Switch-ActiveFingerprintWorkflow {
    if (-not (Request-UidGateAccess -Reason "active fingerprint switching")) { return }
    $fp = Select-PublicPrimaryFingerprint -Title "Switch active fingerprint"
    if ([string]::IsNullOrWhiteSpace($fp)) { return }
    if ($fp -eq $script:IdentityFingerprint) { Write-Host "This fingerprint is already active." -ForegroundColor $script:UiDimSilver; Wait-User; return }
    Write-Host ""
    Write-Host "You are about to switch the active encryption identity." -ForegroundColor $script:UiWhiteSilver
    Write-Host ("Current: {0}" -f $script:IdentityFingerprint) -ForegroundColor $script:UiDimSilver
    Write-Host ("New    : {0}" -f $fp) -ForegroundColor $script:UiWhiteSilver
    if (-not (Read-YesNo "Are you sure you want to switch fingerprints?" $false)) { return }
    $script:IdentityFingerprint = Normalize-Fingerprint $fp
    Write-Host "Active fingerprint switched." -ForegroundColor $script:UiWhiteSilver
    Wait-User
}

function Add-UidToActiveKeyWorkflow {
    if (-not (Request-UidGateAccess -Reason "UID change")) { return }
    Write-Banner -Title "Add UID to active key"
    Write-Host "Active fingerprint:" -ForegroundColor $script:UiDimSilver
    Write-Host "  $script:IdentityFingerprint" -ForegroundColor $script:UiWhiteSilver
    Write-Host ""
    $name = (Read-OqgPrompt "Name").Trim(); $email = (Read-OqgPrompt "Email").Trim(); $comment = (Read-OqgPrompt "Comment, optional").Trim()
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($email)) { Write-Host "Name and email are required." -ForegroundColor $script:UiLightBlue; Wait-User; return }
    $uid = if ([string]::IsNullOrWhiteSpace($comment)) { "{0} <{1}>" -f $name, $email } else { "{0} ({1}) <{2}>" -f $name, $comment, $email }
    Write-Host ""; Write-Host "New UID:" -ForegroundColor $script:UiDimSilver; Write-Host "  $uid" -ForegroundColor $script:UiWhiteSilver
    Write-Host "GnuPG may ask for the key passphrase through pinentry." -ForegroundColor $script:UiDimSilver
    if (-not (Read-YesNo "Add this UID to the active key?" $false)) { return }
    $r = Invoke-GpgCaptured -Arguments @("--quick-add-uid", $script:IdentityFingerprint, $uid)
    if ($r.ExitCode -eq 0) { $script:ExpectedUidHint = $uid; Write-Host "UID added." -ForegroundColor $script:UiWhiteSilver } else { Write-GpgFailure -Result $r -ActionName "Add UID" }
    Wait-User
}

function Edit-ActiveKeyWorkflow {
    if (-not (Request-UidGateAccess -Reason "interactive key editing")) { return }
    Write-Banner -Title "Edit active key"
    Write-Host "This opens GnuPG interactive key editing for the active fingerprint." -ForegroundColor $script:UiDimSilver
    Write-Host "Use GnuPG commands carefully. Type 'help' inside GnuPG for commands and 'quit' to exit." -ForegroundColor $script:UiDimSilver
    Write-Host ""; Write-Host "Active fingerprint:" -ForegroundColor $script:UiDimSilver; Write-Host "  $script:IdentityFingerprint" -ForegroundColor $script:UiWhiteSilver
    if (-not (Read-YesNo "Open gpg --edit-key for this identity?" $false)) { return }
    Start-OqgInteractiveGpg -Arguments @('--edit-key', $script:IdentityFingerprint)
    Wait-User
}


function Show-IdentityAdminMenu {
    if (-not (Request-UidGateAccess -Reason "identity administration")) { return }
    while ($true) {
        $header = @(
            (New-ConsoleLine -Text "  Identity operations require confirmation and UID gate access." -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text ("  Active FPR: {0}" -f (Short-Fpr $script:IdentityFingerprint)) -Color $script:UiSilverBlue)
        )
        $items = @(
            (New-ConsoleMenuItem -Label "Generate PQC key" -Value "Generate" -Hint "Create a new Ed25519 primary key with Kyber / hybrid encryption subkeys." -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Import key" -Value "Import" -Hint "Import public certs or secret-key material from an arrow-key file browser." -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Switch fingerprint" -Value "Switch" -Hint "Choose another public OpenPGP identity for encryption/signing operations." -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Add UID" -Value "AddUid" -Hint "Add a new UID to the active key through GnuPG." -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Edit key" -Value "Edit" -Hint "Open gpg --edit-key for advanced key maintenance." -Shortcut "5"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to Admin settings." -Shortcut "b")
        )
        $choice = Invoke-ConsoleMenu -Title "Identity admin" -HeaderLines $header -Items $items -Layout "Vertical"
        switch ($choice) { "Generate" { Generate-PqcKeyWorkflow } "Import" { Import-KeyFromFolderWorkflow } "Switch" { Switch-ActiveFingerprintWorkflow } "AddUid" { Add-UidToActiveKeyWorkflow } "Edit" { Edit-ActiveKeyWorkflow } default { return } }
    }
}

function Change-ActiveFingerprint {
    Switch-ActiveFingerprintWorkflow
}

function Show-OutputModeSettings {
    while ($true) {
        $header = @(
            (New-ConsoleLine -Text ("  Current mode: {0}" -f $script:OutputMode) -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text "  Default is Shareable. Private prints local diagnostics and must be enabled here." -Color $script:UiDimSilver)
        )
        $items = @(
            (New-ConsoleMenuItem -Label "Private" -Value "Private" -Hint "Full operator diagnostics for your local machine." -Color $script:UiWhiteSilver -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Shareable" -Value "Shareable" -Hint "Public-safe output for screenshots, chats, posts, and notes." -Color $script:UiWhiteSilver -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to Admin settings." -Color $script:UiDimSilver -Shortcut "b")
        )

        $choice = Invoke-ConsoleMenu -Title "Output safety mode" -HeaderLines $header -Items $items -Layout "Horizontal"
        switch ($choice) {
            "Private" {
                $script:OutputMode = "Private"
                Write-Host ""
                Write-Host "Output mode changed to Private operator output." -ForegroundColor $script:UiWhiteSilver
                Wait-User
            }
            "Shareable" {
                $script:OutputMode = "Shareable"
                Write-Host ""
                Write-Host "Output mode changed to Shareable public output." -ForegroundColor $script:UiWhiteSilver
                Wait-User
            }
            "Back" { return }
            default { return }
        }
    }
}

function Convert-SecureInputToPlainText {
    param([Parameter(Mandatory=$true)][securestring]$SecureText)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureText)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

function Request-AdminAccess {
    Write-Banner -Title "Admin settings"
    Write-Host "These settings can change identity selection, exports, and output safety." -ForegroundColor Gray
    Write-Host ""
    Write-Host "This confirmation is a safety interlock, not authentication." -ForegroundColor $script:UiDimSilver
    $confirmation = Read-OqgPrompt 'Type AUTHORIZED to continue'
    if ($confirmation -ceq "AUTHORIZED") { return $true }

    Write-Host ""
    Write-Host "Admin settings cancelled." -ForegroundColor $script:UiLightBlue
    Wait-User
    return $false
}

function Show-AdminSettings {
    if (-not (Request-AdminAccess)) { return }

    while ($true) {
        $modeColor = if (Test-ShareableOutput) { $script:UiGreen } else { $script:UiRose }
        $header = @(
            (New-ConsoleLine -Text "  Admin gate: unlocked for this visit." -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text ("  Output mode: {0}" -f $script:OutputMode) -Color $modeColor),
            (New-ConsoleLine -Text ("  Active FPR : {0}" -f (Short-Fpr $script:IdentityFingerprint)) -Color $script:UiWhiteSilver),
            (New-ConsoleLine -Text "  Note: the password is a local UI gate, not cryptographic protection." -Color $script:UiDimSilver)
        )
        $items = @(
            (New-ConsoleMenuItem -Label "Output mode" -Value "OutputMode" -Hint "Switch Private / Shareable verbosity." -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Identity admin" -Value "IdentityAdmin" -Hint "Generate PQC keys, add UID, edit key, or switch fingerprint." -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Fingerprint" -Value "Fingerprint" -Hint "Quick switch active primary fingerprint for this run." -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Menu reveal" -Value "MenuReveal" -Hint "Toggle NMS wave reveal across menus and submenus." -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to main menu." -Color $script:UiDimSilver -Shortcut "b")
        )

        $choice = Invoke-ConsoleMenu -Title "Admin settings" -HeaderLines $header -Items $items -Layout "Vertical"
        switch ($choice) {
            "OutputMode" { Show-OutputModeSettings }
            "IdentityAdmin" { Show-IdentityAdminMenu }
            "Fingerprint" { Change-ActiveFingerprint }
            "MenuReveal" {
                Switch-OqgMenuNms
            }
            "Back" { return }
            default { return }
        }
    }
}


function Split-BoxTextLine {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [int]$Width = 68
    )

    $words = @($Text -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($words.Count -eq 0) { return @("") }

    $lines = @()
    $current = ""
    foreach ($word in $words) {
        if ([string]::IsNullOrWhiteSpace($current)) {
            $current = $word
        } elseif (($current.Length + 1 + $word.Length) -le $Width) {
            $current = "$current $word"
        } else {
            $lines += $current
            $current = $word
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($current)) { $lines += $current }
    return @($lines)
}

function Write-TextBox {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Lines,
        [int]$Width = 74,
        [string]$BorderColor = $script:UiBorderBlue,
        [string]$TitleColor = $script:UiBone,
        [string]$TextColor = $script:UiDimSilver
    )

    $inner = [Math]::Max(20, $Width - 4)
    Write-ConsoleSegment -Text "  ╔" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╗" -ForegroundColor $BorderColor
    Write-Host ""

    $safeTitle = " $Title "
    if ($safeTitle.Length -gt $inner) { $safeTitle = $safeTitle.Substring(0, $inner) }
    Write-ConsoleSegment -Text "  ║" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ($safeTitle.PadRight($inner + 2)) -ForegroundColor $TitleColor
    Write-ConsoleSegment -Text "║" -ForegroundColor $BorderColor
    Write-Host ""

    Write-ConsoleSegment -Text "  ╠" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╣" -ForegroundColor $BorderColor
    Write-Host ""

    foreach ($line in $Lines) {
        foreach ($wrapped in (Split-BoxTextLine -Text $line -Width $inner)) {
            Write-ConsoleSegment -Text "  ║ " -ForegroundColor $BorderColor
            Write-ConsoleSegment -Text ($wrapped.PadRight($inner)) -ForegroundColor $TextColor
            Write-ConsoleSegment -Text " ║" -ForegroundColor $BorderColor
            Write-Host ""
        }
    }

    Write-ConsoleSegment -Text "  ╚" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╝" -ForegroundColor $BorderColor
    Write-Host ""
}


function New-StatusPanelLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = $script:UiWhiteSilver,
        [int]$InnerWidth = 66
    )

    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    if ($safe.Length -gt $InnerWidth) { $safe = $safe.Substring(0, $InnerWidth - 1) + "…" }
    return (New-ConsoleLine -Text ("  │  " + $safe.PadRight($InnerWidth) + "│") -Color $Color)
}

function New-StatusPanelGradientSegments {
    param(
        [AllowEmptyString()][string]$Label = "",
        [AllowEmptyString()][string]$Value = "",
        [int]$InnerWidth = 66,
        [switch]$BoldValue
    )

    $segments = @()
    $segments += (New-ConsoleSegment -Text "  │  " -Color $script:UiBorderBlue)
    $plain = ""
    if ([string]::IsNullOrWhiteSpace($Label)) {
        $safeValue = [string]$Value
        if ($safeValue.Length -gt $InnerWidth) { $safeValue = $safeValue.Substring(0, $InnerWidth - 1) + "…" }
        $segments += @(New-GradientSegments -Text $safeValue -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold:($BoldValue))
        $plain = $safeValue
    } else {
        $safeLabel = $Label.PadRight(6)
        $segments += @(New-GradientSegments -Text $safeLabel -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd -Bold)
        $segments += (New-ConsoleSegment -Text ": " -Color $script:UiLightBlue)
        $safeValue = [string]$Value
        $maxValue = $InnerWidth - 8
        if ($safeValue.Length -gt $maxValue) { $safeValue = $safeValue.Substring(0, $maxValue - 1) + "…" }
        $segments += (New-ConsoleSegment -Text $safeValue -Color $script:UiWhiteSilver -Bold:($BoldValue))
        $plain = $safeLabel + ": " + $safeValue
    }
    if ($plain.Length -lt $InnerWidth) {
        $segments += (New-ConsoleSegment -Text (" " * ($InnerWidth - $plain.Length)) -Color $script:UiDimSilver)
    }
    $segments += (New-ConsoleSegment -Text "│" -Color $script:UiBorderBlue)
    return @($segments)
}


function New-StatusPanelCryptoSegments {
    param([int]$Score = 10, [int]$InnerWidth = 66)

    $labelWidth = 6
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  │  " -Color $script:UiBorderBlue)
    $label = "Crypto".PadRight($labelWidth)
    $segments += @(New-GradientSegments -Text $label -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd -Bold)
    $segments += (New-ConsoleSegment -Text ": " -Color $script:UiLightBlue)
    $name = "Kyber / ML-KEM hybrid "
    $segments += (New-ConsoleSegment -Text $name -Color $script:UiWhiteSilver -Bold)
    $segments += @(Get-StrengthRatingSegments -Score $Score)

    $plain = $label + ": " + $name + (Get-StrengthPlainBar -Score $Score)
    if ($plain.Length -lt $InnerWidth) {
        $segments += (New-ConsoleSegment -Text (" " * ($InnerWidth - $plain.Length)) -Color $script:UiDimSilver)
    }
    $segments += (New-ConsoleSegment -Text "│" -Color $script:UiBorderBlue)
    return @($segments)
}

function New-GradientSegments {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int[]]$StartRgb = @(192, 192, 192),
        [int[]]$EndRgb = @(173, 216, 230),
        [string]$BackgroundColor = "",
        [switch]$Bold
    )

    $segments = @()
    if ($null -eq $Text) { $Text = "" }

    # v53: null-safe and empty-line safe gradient rendering.
    # Windows PowerShell treats an empty command result as $null when it is
    # passed to another mandatory parameter. Return one harmless empty
    # segment instead of an empty array so Write-MenuRichLine never receives
    # a null Segments argument during boot-screen blank lines.
    if ($Text.Length -le 0) {
        $segments += (New-ConsoleSegment -Text "" -Color ("Rgb:{0},{1},{2}" -f $StartRgb[0], $StartRgb[1], $StartRgb[2]) -BackgroundColor $BackgroundColor -Bold:($Bold))
        return @($segments)
    }

    $length = $Text.Length
    $denom = [Math]::Max(1, $length - 1)

    for ($i = 0; $i -lt $length; $i++) {
        $ratio = [double]$i / [double]$denom
        $r = [int]($StartRgb[0] + (($EndRgb[0] - $StartRgb[0]) * $ratio))
        $g = [int]($StartRgb[1] + (($EndRgb[1] - $StartRgb[1]) * $ratio))
        $b = [int]($StartRgb[2] + (($EndRgb[2] - $StartRgb[2]) * $ratio))
        $segments += (New-ConsoleSegment -Text $Text.Substring($i, 1) -Color ("Rgb:{0},{1},{2}" -f $r, $g, $b) -BackgroundColor $BackgroundColor -Bold:($Bold))
    }
    return @($segments)
}

function New-MenuLabelSegments {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [string]$Prefix = "    ",
        [bool]$Selected = $false
    )

    $bg = if ($Selected) { $script:UiHighlightBlue } else { "" }
    $prefixColor = if ($Selected) { $script:UiWhiteSilver } else { $script:UiDimSilver }
    $segments = @()
    $segments += (New-ConsoleSegment -Text $Prefix -Color $prefixColor -BackgroundColor $bg -Bold:($Selected))
    $segments += @(New-GradientSegments -Text $Label -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd -BackgroundColor $bg -Bold:($Selected))
    return @($segments)
}

function New-MarkupSegments {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$NormalColor = $script:UiSilverBlue,
        [string]$BoldColor = $script:UiWhiteSilver,
        [string]$BackgroundColor = ""
    )

    $segments = @()
    $remaining = if ($null -eq $Text) { "" } else { [string]$Text }
    while ($remaining.Length -gt 0) {
        $m = [regex]::Match($remaining, '\*\*(.+?)\*\*')
        if (-not $m.Success) {
            $segments += (New-ConsoleSegment -Text $remaining -Color $NormalColor -BackgroundColor $BackgroundColor)
            break
        }
        if ($m.Index -gt 0) {
            $segments += (New-ConsoleSegment -Text $remaining.Substring(0, $m.Index) -Color $NormalColor -BackgroundColor $BackgroundColor)
        }
        $segments += (New-ConsoleSegment -Text $m.Groups[1].Value -Color $BoldColor -BackgroundColor $BackgroundColor -Bold)
        $remaining = $remaining.Substring($m.Index + $m.Length)
    }
    return @($segments)
}

function Get-MarkupPlainLength {
    param([AllowEmptyString()][string]$Text = "")
    if ($null -eq $Text) { return 0 }
    return (($Text -replace '\*\*(.+?)\*\*', '$1').Length)
}

function Write-GradientLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int[]]$StartRgb = $script:GradientBlueStart,
        [int[]]$EndRgb = $script:GradientBlueEnd
    )

    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    $segments = @(New-GradientSegments -Text $safe -StartRgb $StartRgb -EndRgb $EndRgb)
    if ($null -eq $segments -or $segments.Count -le 0) {
        Write-MenuLine -Text "" -ForegroundColor $script:UiDimSilver
        return
    }
    Write-MenuRichLine -Segments $segments
}


function New-NmsScrambledText {
    param(
        [AllowEmptyString()][string]$Text = "",
        [double]$RevealRatio = 0.0
    )

    if ($null -eq $Text) { return "" }

    # v41: per-character NMS wave.
    # Earlier builds scrambled the whole sentence too aggressively and used random
    # choices on every redraw. This version gives each character its own small
    # deterministic reveal/encrypt phase. It is smoother, faster, and avoids the
    # half-second menu blip while still looking like an encrypted wave.
    $chars = $script:NmsGlyphChars
    if ($null -eq $chars -or $chars.Count -eq 0) { $chars = $script:NmsGlyphs.ToCharArray() }
    $sb = New-Object System.Text.StringBuilder
    $tick = 0
    try { $tick = [int]$script:NmsWaveTick } catch { $tick = 0 }
    $ratio = [Math]::Min(0.99, [Math]::Max(0.05, [double]$RevealRatio))

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]
        if ([char]::IsWhiteSpace($ch)) {
            [void]$sb.Append($ch)
            continue
        }

        $chText = [string]$ch
        $isWordChar = ([char]::IsLetterOrDigit($ch) -or $chText -eq "_" -or $chText -eq "-" -or $chText -eq "/")
        if (-not $isWordChar) {
            [void]$sb.Append($ch)
            continue
        }

        # One moving encryption band crosses the text. Outside the band the text
        # is mostly readable. Inside the band, characters individually flicker.
        $wave = ([Math]::Sin((($i * 0.72) + ($tick * 0.95))) + 1.0) / 2.0
        $gate = ((($i * 37) + ($tick * 17)) % 100) / 100.0
        $effectiveReveal = $ratio - ($wave * 0.16)
        if ($effectiveReveal -lt 0.08) { $effectiveReveal = 0.08 }
        if ($effectiveReveal -gt 0.99) { $effectiveReveal = 0.99 }

        if ($gate -lt $effectiveReveal) {
            [void]$sb.Append($ch)
        } else {
            $glyphIndex = (($i * 11) + ($tick * 7) + [int][char]$ch) % $chars.Length
            [void]$sb.Append($chars[$glyphIndex])
        }
    }
    return $sb.ToString()
}


function Get-NmsWaveRevealRatio {
    param(
        [int]$Index = 0,
        [int]$SelectedIndex = 0,
        [double]$Minimum = $script:NmsWaveMinimumReveal,
        [double]$Peak = $script:NmsWavePeakReveal
    )

    $distance = [Math]::Abs($Index - $SelectedIndex)
    $distanceDrop = [Math]::Min(0.42, $distance * 0.13)
    $phase = (($script:NmsWaveTick + ($Index * 2)) % 12) / 12.0
    $sine = ([Math]::Sin($phase * 2.0 * [Math]::PI) + 1.0) / 2.0
    $ratio = $Minimum + (($Peak - $Minimum) * $sine) - $distanceDrop
    if ($ratio -lt 0.08) { $ratio = 0.08 }
    if ($ratio -gt 0.88) { $ratio = 0.88 }
    return [double]$ratio
}

function New-NmsWaveText {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Index = 0,
        [int]$SelectedIndex = 0,
        [double]$Bias = 0.0
    )

    if (-not $script:EnableNoMoreSecretsEffect) { return $Text }
    if (-not $script:EnableDynamicNmsMenu) { return $Text }
    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    # v42 speed guard: animate compact labels per-character, not long prose.
    # This keeps the encrypted-flow look without forcing every full sentence to
    # be rebuilt on every idle frame.
    try {
        if ($Text.Length -gt [int]$script:NmsMaxAnimatedTextLength) { return $Text }
    } catch { }

    $ratio = (Get-NmsWaveRevealRatio -Index $Index -SelectedIndex $SelectedIndex) + $Bias
    if ($ratio -gt 0.94) { $ratio = 0.94 }
    if ($ratio -lt 0.05) { $ratio = 0.05 }
    return (New-NmsScrambledText -Text $Text -RevealRatio $ratio)
}


function Advance-NmsWave {
    try { $script:NmsWaveTick = [int]($script:NmsWaveTick + 1) } catch { }
}

function Read-KeyOrNmsWaveTimeout {
    param([int]$DelayMs = $script:NmsWaveDelayMs)

    # v41: live per-character NMS wave without queued-key drift.
    # The loop redraws on a short timer only when no key is waiting.
    # If a key is available, it returns immediately, so menu movement stays fast.
    try {
        if ([Console]::KeyAvailable) {
            return [pscustomobject]@{ HasKey = $true; Key = [Console]::ReadKey($true) }
        }
    } catch {
        return [pscustomobject]@{ HasKey = $true; Key = [Console]::ReadKey($true) }
    }

    $sleepMs = [Math]::Max(8, [Math]::Min(48, [int]$DelayMs))
    $elapsed = 0
    $slice = 2
    while ($elapsed -lt $sleepMs) {
        Start-Sleep -Milliseconds $slice
        $elapsed += $slice
        try {
            if ([Console]::KeyAvailable) {
                return [pscustomobject]@{ HasKey = $true; Key = [Console]::ReadKey($true) }
            }
        } catch { }
    }

    return [pscustomobject]@{ HasKey = $false; Key = $null }
}

function Invoke-NoMoreSecretsEffect {
    param(
        [Parameter(Mandatory=$true)][string[]]$Lines,
        [int]$Frames = 4,
        [int]$DelayMs = 8,
        [switch]$ClearBefore,
        [switch]$ClearAfter
    )

    if (-not $script:EnableNoMoreSecretsEffect) { return }
    if ($ClearBefore) { Clear-Host }

    $width = 100
    try { $width = [Math]::Max(30, [Console]::WindowWidth - 2) } catch { }
    $safeLines = @($Lines | ForEach-Object { [string]$_ })
    $startTop = 0
    $canRewrite = $true
    try { $startTop = [Console]::CursorTop } catch { $canRewrite = $false }

    # Use a very short, cursor-stable reveal. If cursor positioning is not
    # reliable, fall back to final plaintext only, never print frame spam.
    if ($canRewrite -and $Frames -gt 0) {
        for ($frame = 0; $frame -le $Frames; $frame++) {
            $ratio = [double]$frame / [double][Math]::Max(1, $Frames)
            try { [Console]::SetCursorPosition(0, $startTop) } catch { break }
            foreach ($line in $safeLines) {
                $scrambled = if ($frame -eq $Frames) { $line } else { New-NmsScrambledText -Text $line -RevealRatio $ratio }
                $padded = $scrambled
                if ($padded.Length -gt $width) { $padded = $padded.Substring(0, $width) }
                if ($padded.Length -lt $width) { $padded = $padded + (' ' * ($width - $padded.Length)) }
                Write-MenuRichLine -Segments (New-GradientSegments -Text $padded -StartRgb $script:GradientIceStart -EndRgb $script:GradientBlueEnd -Bold)
            }
            if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
        }
    } else {
        foreach ($line in $safeLines) {
            Write-MenuRichLine -Segments (New-GradientSegments -Text $line -StartRgb $script:GradientIceStart -EndRgb $script:GradientBlueEnd -Bold)
        }
    }

    if ($ClearAfter) {
        Start-Sleep -Milliseconds 80
        Clear-Host
    } else {
        Write-Host ""
    }
}


function Invoke-NmsMenuMovementPulse {
    param([AllowEmptyString()][string]$Label = "")

    if (-not $script:EnableNoMoreSecretsEffect) { return }
    if (-not $script:EnableDynamicNmsMenu) { return }
    if ([string]::IsNullOrWhiteSpace($Label)) { return }

    Invoke-NoMoreSecretsEffect -Frames $script:NmsMenuPulseFrames -DelayMs $script:NmsMenuPulseDelayMs -Lines @(
        ("SELECTING :: {0}" -f $Label)
    )
}

function Invoke-NmsOperationReveal {
    param([Parameter(Mandatory=$true)][string[]]$Lines)

    if (-not $script:EnableNoMoreSecretsEffect) { return }

    # v43: operation results must not echo "NO MORE SECRETS" on every line.
    # Render one clean NMS header, then readable result lines underneath.
    $clean = @()
    foreach ($line in @($Lines)) {
        $text = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($text -match '^(?i)NO MORE SECRETS$') { continue }
        $clean += $text
    }
    if ($clean.Count -eq 0) { return }

    Write-Host ""
    Write-MenuRichLine -Segments (New-GradientSegments -Text ("NO MORE SECRETS :: {0}" -f $clean[0]) -StartRgb $script:GradientIceStart -EndRgb $script:GradientBlueEnd -Bold)
    if ($clean.Count -gt 1) {
        for ($i = 1; $i -lt $clean.Count; $i++) {
            Write-MenuRichLine -Segments (New-GradientSegments -Text ("  {0}" -f $clean[$i]) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd)
        }
    }
    Write-Host ""
}

function Invoke-StartupNmsEffectOnce {
    if ($script:NmsEffectAlreadyShown) { return }
    $script:NmsEffectAlreadyShown = $true
    Invoke-NoMoreSecretsEffect -ClearBefore -ClearAfter -Frames 20 -DelayMs 22 -Lines @(
        "OPENPGP QUANTUM GUARD",
        "NO MORE SECRETS",
        "PQC-AWARE OPENPGP PROTECTION"
    )
}

function Write-FrameTop {
    param([int]$Width = 76, [string]$BorderColor = $script:UiBorderBlue)
    Write-ConsoleSegment -Text "  ╔" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╗" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-FrameBottom {
    param([int]$Width = 76, [string]$BorderColor = $script:UiBorderBlue)
    Write-ConsoleSegment -Text "  ╚" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╝" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-FrameRule {
    param([int]$Width = 76, [string]$BorderColor = $script:UiBorderBlue)
    Write-ConsoleSegment -Text "  ╠" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("═" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╣" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-FrameTitleRule {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [int]$Width = 76,
        [string]$BorderColor = $script:UiBorderBlue
    )
    $inner = $Width - 2
    $safe = "═ $Title "
    if ($safe.Length -gt $inner) { $safe = $safe.Substring(0, $inner) }
    Write-ConsoleSegment -Text "  ╠" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ($safe.PadRight($inner, [char]"═")) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╣" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-FrameText {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 76,
        [string]$TextColor = $script:UiSilverBlue,
        [string]$BorderColor = $script:UiBorderBlue
    )
    $inner = $Width - 4
    foreach ($wrapped in (Split-BoxTextLine -Text $Text -Width $inner)) {
        Write-ConsoleSegment -Text "  ║ " -ForegroundColor $BorderColor
        Write-ConsoleSegment -Text ($wrapped.PadRight($inner)) -ForegroundColor $TextColor
        Write-ConsoleSegment -Text " ║" -ForegroundColor $BorderColor
        Write-Host ""
    }
}

function Write-FrameBlank {
    param([int]$Width = 76, [string]$BorderColor = $script:UiBorderBlue)
    $inner = $Width - 4
    Write-ConsoleSegment -Text "  ║ " -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text (" " * $inner) -ForegroundColor $script:UiDimSilver
    Write-ConsoleSegment -Text " ║" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-FrameGradientText {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 76,
        [int[]]$StartRgb = $script:GradientBlueStart,
        [int[]]$EndRgb = $script:GradientBlueEnd,
        [string]$BorderColor = $script:UiBorderBlue
    )
    $inner = $Width - 4
    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    if ($safe.Length -gt $inner) { $safe = $safe.Substring(0, $inner) }
    Write-ConsoleSegment -Text "  ║ " -ForegroundColor $BorderColor
    foreach ($seg in (New-GradientSegments -Text $safe -StartRgb $StartRgb -EndRgb $EndRgb)) {
        Write-ConsoleSegment -Text $seg.Text -ForegroundColor $seg.Color
    }
    if ($safe.Length -lt $inner) {
        Write-ConsoleSegment -Text (" " * ($inner - $safe.Length)) -ForegroundColor $script:UiDimSilver
    }
    Write-ConsoleSegment -Text " ║" -ForegroundColor $BorderColor
    Write-Host ""
}

function Write-AboutRowCompact {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string[]]$Lines,
        [int]$Width = 90,
        [int]$LabelWidth = 12,
        [string]$BorderColor = $script:UiBorderBlue,
        [string]$TextColor = $script:UiSilverBlue
    )

    $inner = $Width - 4
    $textWidth = $inner - $LabelWidth - 3
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = [string]$Lines[$i]
        $plainLength = Get-MarkupPlainLength -Text $line
        Write-ConsoleSegment -Text "  ║ " -ForegroundColor $BorderColor
        if ($i -eq 0) {
            $safeLabel = $Label
            if ($safeLabel.Length -gt $LabelWidth) { $safeLabel = $safeLabel.Substring(0, $LabelWidth) }
            foreach ($seg in (New-GradientSegments -Text $safeLabel -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd -Bold)) {
                Write-ConsoleSegment -Text $seg.Text -ForegroundColor $seg.Color -Bold
            }
            if ($safeLabel.Length -lt $LabelWidth) {
                Write-ConsoleSegment -Text (" " * ($LabelWidth - $safeLabel.Length)) -ForegroundColor $script:UiDimSilver
            }
        } else {
            Write-ConsoleSegment -Text (" " * $LabelWidth) -ForegroundColor $script:UiDimSilver
        }
        Write-ConsoleSegment -Text " │ " -ForegroundColor $script:UiLightBlue
        foreach ($seg in (New-MarkupSegments -Text $line -NormalColor $TextColor -BoldColor $script:UiWhiteSilver)) {
            Write-ConsoleSegment -Text $seg.Text -ForegroundColor $seg.Color -Bold:([bool]$seg.Bold)
        }
        if ($plainLength -lt $textWidth) {
            Write-ConsoleSegment -Text (" " * ($textWidth - $plainLength)) -ForegroundColor $script:UiDimSilver
        }
        Write-ConsoleSegment -Text " ║" -ForegroundColor $BorderColor
        Write-Host ""
    }
}

function Write-AboutRuleCompact {
    param([int]$Width = 90, [string]$BorderColor = $script:UiBorderBlue)
    Write-ConsoleSegment -Text "  ╟" -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text ("─" * ($Width - 2)) -ForegroundColor $BorderColor
    Write-ConsoleSegment -Text "╢" -ForegroundColor $BorderColor
    Write-Host ""
}

function Show-AboutDashboard {
    $w = 86
    Write-ConsoleSegment -Text "  ╔" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╗" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-ConsoleSegment -Text "  ║ " -ForegroundColor $script:UiBorderBlue
    $title = "OpenPGP Quantum Guard"
    foreach ($seg in (New-GradientSegments -Text $title -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold)) {
        Write-ConsoleSegment -Text $seg.Text -ForegroundColor $seg.Color -Bold
    }
    $tag = "  PQC-enabled OpenPGP operations"
    Write-ConsoleSegment -Text $tag -ForegroundColor $script:UiSilverBlue -Bold
    $pad = ($w - 4) - $title.Length - $tag.Length
    if ($pad -gt 0) { Write-ConsoleSegment -Text (" " * $pad) -ForegroundColor $script:UiDimSilver }
    Write-ConsoleSegment -Text " ║" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-ConsoleSegment -Text "  ╠" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╣" -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    Write-AboutRowCompact -Width $w -Label "Mission" -TextColor $script:UiSilverBlue -Lines @(
        "**Protect files** with OpenPGP while keeping **Private** diagnostics",
        "separate from **Shareable** output for screenshots, reports,",
        "and public proof-of-identity workflows."
    )
    Write-AboutRuleCompact -Width $w
    Write-AboutRowCompact -Width $w -Label "PQC flow" -TextColor $script:UiSilverBlue -Lines @(
        "**Encrypt** prefers **Kyber / ML-KEM hybrid** subkeys when available.",
        "**Decrypt** is packet-driven: GnuPG reads the encrypted data",
        "and selects the matching local private key automatically."
    )
    Write-AboutRuleCompact -Width $w
    Write-AboutRowCompact -Width $w -Label "Controls" -TextColor $script:UiSilverBlue -Lines @(
        "Browse folders, choose files, encrypt, decrypt, inspect keys,",
        "view public and secret-key status, export public certs,",
        "secret subkeys, and full backups with confirmation prompts."
    )
    Write-AboutRuleCompact -Width $w
    Write-AboutRowCompact -Width $w -Label "Operator" -TextColor $script:UiSilverBlue -Lines @(
        "Bak3n3k0.",
        "Security researcher, builder, hacker. Practical cryptography lab.",
        "Maintained as an open cryptography research project.",
        "GitHub: https://github.com/RandomLinoge"
    )
    Write-AboutRuleCompact -Width $w
    Write-AboutRowCompact -Width $w -Label "Security" -TextColor $script:UiDimSilver -Lines @(
        "Protect endpoints, private keys, passphrases,",
        "backups, recipient compatibility,",
        "and correct GnuPG behavior."
    )

    Write-ConsoleSegment -Text "  ╚" -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text ("═" * ($w - 2)) -ForegroundColor $script:UiBorderBlue
    Write-ConsoleSegment -Text "╝" -ForegroundColor $script:UiBorderBlue
    Write-Host ""
}

function Show-Goodbye {
    Write-Host ""
    Write-MenuLine -Text "Session closed. Keys guarded. Logs honest. See you in the rabbit hole." -ForegroundColor $script:UiRose
    Write-Host ""
}


function Write-MenuRenderLineFixed {
    param(
        [Parameter(Mandatory=$true)]$Line,
        [int]$Width = 40
    )

    $Width = [Math]::Max(12, $Width)
    if ($Line.PSObject.Properties.Name -contains "Segments" -and @($Line.Segments).Count -gt 0) {
        $used = 0
        foreach ($seg in @($Line.Segments)) {
            if ($null -eq $seg) { continue }
            $t = if ($seg.PSObject.Properties.Name -contains "Text") { [string]$seg.Text } else { [string]$seg }
            $fg = if ($seg.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$seg.Color)) { [string]$seg.Color } else { $script:UiDimSilver }
            $bg = if ($seg.PSObject.Properties.Name -contains "BackgroundColor") { [string]$seg.BackgroundColor } else { "" }
            $bold = if ($seg.PSObject.Properties.Name -contains "Bold") { [bool]$seg.Bold } else { $false }
            if ($used + $t.Length -gt $Width) {
                $remain = [Math]::Max(0, $Width - $used)
                if ($remain -le 0) { break }
                $t = $t.Substring(0, $remain)
            }
            Write-ConsoleSegment -Text $t -ForegroundColor $fg -BackgroundColor $bg -Bold:($bold)
            $used += $t.Length
        }
        if ($used -lt $Width) {
            $bg = if ($Line.PSObject.Properties.Name -contains "BackgroundColor") { [string]$Line.BackgroundColor } else { "" }
            Write-ConsoleSegment -Text (" " * ($Width - $used)) -ForegroundColor $script:UiDimSilver -BackgroundColor $bg
        }
    } else {
        $txt = if ($Line.PSObject.Properties.Name -contains "Text") { [string]$Line.Text } else { [string]$Line }
        $fg = if ($Line.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$Line.Color)) { [string]$Line.Color } else { $script:UiDimSilver }
        $bg = if ($Line.PSObject.Properties.Name -contains "BackgroundColor") { [string]$Line.BackgroundColor } else { "" }
        if ($txt.Length -gt $Width) { $txt = $txt.Substring(0, [Math]::Max(0, $Width - 1)) + "…" }
        Write-ConsoleSegment -Text ($txt.PadRight($Width)) -ForegroundColor $fg -BackgroundColor $bg
    }
}

function Write-MenuRenderLineAt {
    param(
        [Parameter(Mandatory=$true)]$Line,
        [int]$X = 0,
        [int]$Y = 0,
        [int]$Width = 40
    )
    try { [Console]::SetCursorPosition($X, $Y) } catch { }
    Write-MenuRenderLineFixed -Line $Line -Width $Width
}


function New-MenuHintRenderLines {
    param(
        [AllowEmptyString()][string]$Hint = "",
        [int]$HintWidth = 34,
        [bool]$Selected = $false,
        [int]$MaxLines = 2
    )

    $result = @()
    if ([string]::IsNullOrWhiteSpace($Hint)) { return $result }

    $wrapWidth = [Math]::Max(14, $HintWidth)
    $wrapped = @(Split-BoxTextLine -Text $Hint -Width $wrapWidth)
    if ($wrapped.Count -gt $MaxLines) {
        $wrapped = @($wrapped[0..($MaxLines - 1)])
        $last = [string]$wrapped[$wrapped.Count - 1]
        if ($last.Length -gt ($wrapWidth - 1)) { $last = $last.Substring(0, [Math]::Max(1, $wrapWidth - 1)) }
        $wrapped[$wrapped.Count - 1] = $last.TrimEnd() + "…"
    }

    foreach ($w in $wrapped) {
        if ($Selected) {
            $result += (New-MenuRenderLine -Text ("      {0}" -f $w) -Color $script:UiSilverBlue -BackgroundColor $script:UiDeepBlue)
        } else {
            $result += (New-MenuRenderLine -Text ("      {0}" -f $w) -Color $script:UiDimSilver)
        }
    }
    return $result
}

function New-VersionPanelLines {
    $lines = @()
    $lines += (New-ConsoleLine -Text "" -Color $script:UiDimSilver)
    $lines += (New-ConsoleLine -Text "  ┌────────────────────────────────────────────────────────┐" -Color $script:UiBorderBlue)
    $lines += (New-ConsoleRichLine -Segments (New-StatusPanelGradientSegments -Label "Build" -Value ("{0} :: what changed" -f $script:ToolVersion) -InnerWidth 54 -BoldValue))
    $lines += (New-ConsoleLine -Text "  ├────────────────────────────────────────────────────────┤" -Color $script:UiBorderBlue)
    $lines += (New-ConsoleLine -Text "  │  NMS wave: encrypted flow, plaintext on focus.        │" -Color $script:UiSilverBlue)
    $lines += (New-ConsoleLine -Text "  │  Identity: generate PQC keys, add UID, switch FPR.    │" -Color $script:UiDimSilver)
    $lines += (New-ConsoleLine -Text "  │  Layout: clean about panel, uncropped status box.     │" -Color $script:UiDimSilver)
    $lines += (New-ConsoleLine -Text "  └────────────────────────────────────────────────────────┘" -Color $script:UiBorderBlue)
    return @($lines)
}

function Convert-MarkupToWrappedSegmentLines {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 34,
        [string]$NormalColor = $script:UiSilverBlue,
        [string]$BoldColor = $script:UiWhiteSilver
    )

    $Width = [Math]::Max(12, $Width)
    $raw = if ($null -eq $Text) { "" } else { [string]$Text }
    $tokens = @()
    $parts = [regex]::Split($raw, '(\*\*.*?\*\*)')
    foreach ($part in $parts) {
        if ($part -eq "") { continue }
        $bold = $false
        $piece = $part
        if ($piece.StartsWith('**') -and $piece.EndsWith('**') -and $piece.Length -ge 4) {
            $bold = $true
            $piece = $piece.Substring(2, $piece.Length - 4)
        }
        foreach ($tok in [regex]::Split($piece, '(\s+)')) {
            if ($tok -eq "") { continue }
            $tokens += [pscustomobject]@{ Text = [string]$tok; Bold = [bool]$bold }
        }
    }

    $lines = @()
    $current = @()
    $len = 0

    foreach ($tok in $tokens) {
        $t = [string]$tok.Text
        $isSpace = [string]::IsNullOrWhiteSpace($t)
        if ($len -eq 0 -and $isSpace) { continue }

        if (($len + $t.Length) -gt $Width -and $len -gt 0) {
            while ($current.Count -gt 0 -and [string]::IsNullOrWhiteSpace([string]$current[$current.Count - 1].Text)) {
                if ($current.Count -eq 1) { $current = @() } else { $current = @($current[0..($current.Count - 2)]) }
            }
            $lines += [pscustomobject]@{ Segments = @($current) }
            $current = @()
            $len = 0
            if ($isSpace) { continue }
        }

        if ($t.Length -gt $Width) {
            $pos = 0
            while ($pos -lt $t.Length) {
                if ($len -ge $Width) {
                    $lines += [pscustomobject]@{ Segments = @($current) }
                    $current = @()
                    $len = 0
                }
                $take = [Math]::Min($Width - $len, $t.Length - $pos)
                $partText = $t.Substring($pos, $take)
                $color = if ($tok.Bold) { $BoldColor } else { $NormalColor }
                $current += (New-ConsoleSegment -Text $partText -Color $color -Bold:([bool]$tok.Bold))
                $len += $take
                $pos += $take
            }
        } else {
            $color = if ($tok.Bold) { $BoldColor } else { $NormalColor }
            $current += (New-ConsoleSegment -Text $t -Color $color -Bold:([bool]$tok.Bold))
            $len += $t.Length
        }
    }

    if ($current.Count -gt 0) {
        while ($current.Count -gt 0 -and [string]::IsNullOrWhiteSpace([string]$current[$current.Count - 1].Text)) {
            if ($current.Count -eq 1) { $current = @() } else { $current = @($current[0..($current.Count - 2)]) }
        }
        $lines += [pscustomobject]@{ Segments = @($current) }
    }

    if ($lines.Count -eq 0) {
        $lines += [pscustomobject]@{ Segments = @((New-ConsoleSegment -Text "" -Color $NormalColor)) }
    }
    return @($lines)
}


function Invoke-AboutRightPanel {
    param([Parameter(Mandatory=$true)]$LeftLines)

    Clear-Host
    $windowWidth = 120
    try { $windowWidth = [Console]::WindowWidth } catch { }

    if ($windowWidth -lt 112) {
        foreach ($line in @($LeftLines)) { Write-MenuRenderLineFixed -Line $line -Width ([Math]::Min($windowWidth - 1, 90)); Write-Host "" }
        Show-AboutDashboard
        Wait-User
        return
    }

    $leftWidth = 60
    $rightX = $leftWidth + 3
    $rightWidth = [Math]::Max(50, $windowWidth - $rightX - 2)
    $right = @(New-AboutRightLines -Width $rightWidth)
    $left = @($LeftLines)
    $rows = [Math]::Max($left.Count, $right.Count) + 2
    for ($row = 0; $row -lt $rows; $row++) {
        $empty = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
        $lineLeft = if ($row -lt $left.Count) { $left[$row] } else { $empty }
        $lineRight = if ($row -lt $right.Count) { $right[$row] } else { $empty }
        Write-MenuRenderLineAt -Line $lineLeft -X 0 -Y $row -Width $leftWidth
        Write-MenuRenderLineAt -Line $lineRight -X $rightX -Y $row -Width $rightWidth
    }
    Wait-User
}


function Read-MultilineTextBlock {
    param([string]$Title = "Paste text")
    Write-Host ""
    Write-Host $Title -ForegroundColor $script:UiWhiteSilver
    Write-Host "Finish with .END on its own line. Ctrl+C discards this entry and returns to the menu." -ForegroundColor $script:UiDimSilver
    $lines = New-Object System.Collections.Generic.List[string]
    if ([Console]::IsInputRedirected) {
        while ($null -ne ($line = [Console]::ReadLine())) {
            if ($line -eq ".END") { return ($lines -join [Environment]::NewLine) }
            [void]$lines.Add($line)
        }
        return $null
    }

    $priorMode = [Console]::TreatControlCAsInput
    try {
        [Console]::TreatControlCAsInput = $true
        $buffer = New-Object System.Text.StringBuilder
        $afterCR = $false
        [Console]::Write("> ")
        while ($true) {
            $key = [Console]::ReadKey($true)
            $ch = $key.KeyChar
            if ([int]$ch -eq 3 -or ($key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control))) {
                [Console]::WriteLine()
                return $null
            }
            if ($afterCR -and [int]$ch -eq 10) { $afterCR = $false; continue }
            if (Test-BlockedControlQuitKey -KeyInfo $key) { continue }
            $afterCR = ([int]$ch -eq 13)
            if ($key.Key -eq 'Enter' -or $afterCR -or [int]$ch -eq 10) {
                [Console]::WriteLine()
                $line = $buffer.ToString()
                if ($line -eq ".END") { return ($lines -join [Environment]::NewLine) }
                [void]$lines.Add($line)
                [void]$buffer.Clear()
                [Console]::Write("> ")
            } elseif ($key.Key -eq 'Backspace' -and $buffer.Length -gt 0) {
                [void]$buffer.Remove($buffer.Length-1,1)
                [Console]::Write("`b `b")
            } elseif (-not [char]::IsControl($ch) -or [int]$ch -eq 9) {
                [void]$buffer.Append($ch)
                [Console]::Write($ch)
            }
        }
    } finally {
        [Console]::TreatControlCAsInput = $priorMode
    }
}


function Split-PlainTextForPanel {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 82
    )

    $result = New-Object System.Collections.Generic.List[string]
    $rawLines = $Text -split "`r?`n", -1
    foreach ($raw in $rawLines) {
        $line = [string]$raw
        if ($line.Length -eq 0) {
            [void]$result.Add("")
            continue
        }
        while ($line.Length -gt $Width) {
            $cut = $line.LastIndexOf(' ', [Math]::Min($Width, $line.Length - 1))
            if ($cut -lt 12) { $cut = $Width }
            [void]$result.Add($line.Substring(0, $cut).TrimEnd())
            $line = $line.Substring($cut).TrimStart()
        }
        [void]$result.Add($line)
    }
    return @($result)
}

function Show-DecryptedTextPanel {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$PlainText,
        $GpgMessages = @()
    )

    Clear-Host
    $boxWidth = 92
    try { $boxWidth = [Math]::Min(110, [Math]::Max(70, [Console]::WindowWidth - 8)) } catch { }
    $inner = $boxWidth - 2
    $contentWidth = $inner - 2

    function Write-DecryptBoxBorder([string]$Kind) {
        $left = if ($Kind -eq 'top') { '╔' } elseif ($Kind -eq 'sep') { '╠' } else { '╚' }
        $right = if ($Kind -eq 'top') { '╗' } elseif ($Kind -eq 'sep') { '╣' } else { '╝' }
        Write-ConsoleSegment -Text ("  {0}{1}{2}" -f $left, ('═' * ($boxWidth - 2)), $right) -ForegroundColor $script:UiBorderBlue
        Write-Host ""
    }

    function Write-DecryptBoxLine([string]$Line, [switch]$Bold) {
        if ($null -eq $Line) { $Line = '' }
        if ($Line.Length -gt $contentWidth) { $Line = $Line.Substring(0, $contentWidth) }
        $pad = [Math]::Max(0, $contentWidth - $Line.Length)
        Write-ConsoleSegment -Text "  ║ " -ForegroundColor $script:UiBorderBlue
        Write-ConsoleSegment -Text $Line -ForegroundColor $script:UiWhiteSilver -Bold:$Bold
        Write-ConsoleSegment -Text ((" " * $pad) + " ║") -ForegroundColor $script:UiBorderBlue
        Write-Host ""
    }

    Write-DecryptBoxBorder 'top'
    Write-DecryptBoxLine 'DECRYPTED TEXT' -Bold
    Write-DecryptBoxBorder 'sep'

    foreach ($line in (Split-PlainTextForPanel -Text $PlainText -Width $contentWidth)) {
        Write-DecryptBoxLine $line
    }

    Write-DecryptBoxBorder 'bottom'
    Write-Host ""
    if (-not (Test-ShareableOutput) -and $null -ne $GpgMessages -and @($GpgMessages).Count -gt 0) {
        Write-Host "GnuPG messages:" -ForegroundColor $script:UiSilverBlue
        @($GpgMessages) | ForEach-Object { Write-Host ("  {0}" -f (Redact-PrivateText $_)) -ForegroundColor Gray }
        Write-Host ""
    }
}


# === v44 upgrade: encrypted file browser, startup identity selection, eligible key inventory, differentiated strength ===

function Test-EncryptedFileNameV44 {
    param([AllowEmptyString()][string]$Name = "")
    return ([string]$Name -match '(?i)\.(asc|gpg|pgp)$')
}

function Write-V44GradientTextLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int[]]$StartRgb = $script:GradientIceStart,
        [int[]]$EndRgb = $script:GradientIceEnd,
        [switch]$Bold
    )
    Write-MenuRichLine -Segments (New-GradientSegments -Text $Text -StartRgb $StartRgb -EndRgb $EndRgb -Bold:($Bold))
}

function Write-V44WrappedText {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [string]$Color = $script:UiDimSilver,
        [int]$Width = 92,
        [string]$Indent = "      "
    )
    foreach ($line in @(Split-BoxTextLine -Text $Text -Width $Width)) {
        Write-Host ($Indent + $line) -ForegroundColor $Color
    }
}

function Select-FileInteractive {
    param(
        [string]$StartFolder,
        [string]$Purpose = "Choose a file"
    )

    if ([string]::IsNullOrWhiteSpace($StartFolder) -or -not (Test-Path -LiteralPath $StartFolder -PathType Container)) {
        $StartFolder = (Get-Location).Path
    }

    $current = (Resolve-Path -LiteralPath $StartFolder).Path

    while ($true) {
        Write-Banner -Title $Purpose
        Write-GradientLine -Text "Current folder:" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd
        Write-Host "  $(Format-DisplayPath $current)" -ForegroundColor $script:UiWhiteSilver
        Write-Host ""

        $dirs = @(Get-ChildItem -LiteralPath $current -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)
        $files = @(Get-ChildItem -LiteralPath $current -File -Force -ErrorAction SilentlyContinue |
            Sort-Object @{ Expression = { if (Test-EncryptedFileNameV44 $_.Name) { 0 } else { 1 } } }, Name)
        $items = @()

        foreach ($d in $dirs) { $items += [pscustomobject]@{ Type = "DIR"; Name = $d.Name; FullName = $d.FullName; Size = $null } }
        foreach ($f in $files) { $items += [pscustomobject]@{ Type = "FILE"; Name = $f.Name; FullName = $f.FullName; Size = $f.Length; Encrypted = (Test-EncryptedFileNameV44 $f.Name) } }

        if ($items.Count -eq 0) {
            Write-Host "  Folder is empty." -ForegroundColor $script:UiDimSilver
        } else {
            for ($i = 0; $i -lt $items.Count; $i++) {
                $num = $i + 1
                $entry = $items[$i]
                if ($entry.Type -eq "DIR") {
                    Write-Host ("{0,3}. [DIR ] {1}\" -f $num, $entry.Name) -ForegroundColor $script:UiSilverBlue
                } else {
                    $size = Format-Size $entry.Size
                    $tag = if ($entry.Encrypted) { "[ENC ]" } else { "[FILE]" }
                    $line = ("{0,3}. {1} {2}  ({3})" -f $num, $tag, $entry.Name, $size)
                    if ($entry.Encrypted) {
                        Write-V44GradientTextLine -Text $line -StartRgb $script:GradientIceStart -EndRgb $script:GradientBlueEnd -Bold
                    } else {
                        Write-Host $line -ForegroundColor $script:UiWhiteSilver
                    }
                }
            }
        }

        Write-Host ""
        Write-GradientLine -Text "Options:" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientLabelEnd
        Write-Host "  number = open folder / choose file" -ForegroundColor $script:UiDimSilver
        Write-Host "  U      = go up one folder" -ForegroundColor $script:UiDimSilver
        Write-Host "  J      = paste full folder path and jump there" -ForegroundColor $script:UiDimSilver
        Write-Host "  P      = paste exact file path" -ForegroundColor $script:UiDimSilver
        Write-Host "  S      = search file names under a folder" -ForegroundColor $script:UiDimSilver
        Write-Host "  R      = refresh" -ForegroundColor $script:UiDimSilver
        Write-Host "  Q      = cancel" -ForegroundColor $script:UiDimSilver
        Write-Host ""

        $choice = (Read-OqgPrompt "Selection").Trim()
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^(r|refresh)$') { continue }
        if ($choice -match '^(q|quit|cancel)$') { return $null }
        if ($choice -match '^(u|up|\.\.)$') {
            $parent = Split-Path -Parent $current
            if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) { $current = (Resolve-Path -LiteralPath $parent).Path }
            continue
        }
        if ($choice -match '^(j|jump|c|cd)$') {
            $newPath = (Read-OqgPrompt "Paste full folder path").Trim('"')
            if (Test-Path -LiteralPath $newPath -PathType Container) {
                $current = (Resolve-Path -LiteralPath $newPath).Path
            } else {
                Write-Host "Folder not found: $newPath" -ForegroundColor $script:UiLightBlue
                Wait-User
            }
            continue
        }
        if ($choice -match '^(p|path)$') {
            $filePath = (Read-OqgPrompt "Exact file path").Trim('"')
            if (Test-Path -LiteralPath $filePath -PathType Leaf) { return (Resolve-Path -LiteralPath $filePath).Path }
            Write-Host "File not found: $filePath" -ForegroundColor $script:UiLightBlue
            Wait-User
            continue
        }
        if ($choice -match '^(s|search)$') {
            $searchRoot = (Read-OqgPrompt "Search under folder path [ENTER = current]").Trim('"')
            if ([string]::IsNullOrWhiteSpace($searchRoot)) { $searchRoot = $current }
            if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) {
                Write-Host "Folder not found: $searchRoot" -ForegroundColor $script:UiLightBlue
                Wait-User
                continue
            }
            $current = (Resolve-Path -LiteralPath $searchRoot).Path
            $pattern = (Read-OqgPrompt "Search file name contains").Trim()
            if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
            Write-Host "Searching. Large folders may take a few seconds..." -ForegroundColor $script:UiDimSilver
            $results = @(Get-ChildItem -LiteralPath $current -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*$pattern*" } |
                Sort-Object @{ Expression = { if (Test-EncryptedFileNameV44 $_.Name) { 0 } else { 1 } } }, Name |
                Select-Object -First 200)
            $selected = Select-FromSearchResults -Results $results
            if ($selected) { return $selected }
            continue
        }

        $numChoice = 0
        if ([int]::TryParse($choice, [ref]$numChoice)) {
            if ($numChoice -ge 1 -and $numChoice -le $items.Count) {
                $selected = $items[$numChoice - 1]
                if ($selected.Type -eq "DIR") { $current = (Resolve-Path -LiteralPath $selected.FullName).Path } else { return $selected.FullName }
                continue
            }
        }

        Write-Host "Invalid choice." -ForegroundColor $script:UiDimSilver
        Wait-User
    }
}

function Get-GpgTrustLabelV44 {
    param([AllowEmptyString()][string]$Validity = "")
    switch ($Validity) {
        "u" { return "ultimate" }
        "f" { return "full" }
        "m" { return "marginal" }
        "n" { return "none" }
        "q" { return "unknown" }
        "e" { return "expired" }
        "r" { return "revoked" }
        default { if ([string]::IsNullOrWhiteSpace($Validity)) { return "unknown" } else { return $Validity } }
    }
}

function Get-EmailFromUidV44 {
    param([AllowEmptyString()][string]$Uid = "")
    if ($Uid -match '<([^>]+)>') { return ([string]$matches[1]).ToLowerInvariant().Replace('\\x5c','').Trim() }
    return ""
}

function Get-SecretFingerprintSetV44 {
    $set = @{}
    $r = Invoke-GpgCaptured -Arguments @("--batch", "--with-colons", "--with-fingerprint", "--list-secret-keys")
    $currentKind = ""
    foreach ($line in @($r.Output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = @($line -split ":", -1)
        if ($f.Count -lt 1) { continue }
        if ($f[0] -in @("sec", "ssb")) { $currentKind = [string]$f[0]; continue }
        if ($f[0] -eq "fpr" -and $currentKind -eq "sec" -and $f.Count -gt 9) {
            $fp = Normalize-Fingerprint ([string]$f[9])
            if (-not [string]::IsNullOrWhiteSpace($fp)) { $set[$fp] = $true }
            $currentKind = ""
        }
    }
    return $set
}


function Write-V46GradientWrappedText {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [string]$Indent = "      ",
        [int]$Width = 108,
        [int[]]$StartRgb = $script:GradientLabelStart,
        [int[]]$EndRgb = $script:GradientBlueEnd,
        [switch]$Bold
    )

    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    $consoleWidth = 120
    try { $consoleWidth = [Console]::WindowWidth } catch { }
    $maxWidth = [Math]::Max(24, [Math]::Min($Width, $consoleWidth - $Indent.Length - 3))
    foreach ($line in @(Split-BoxTextLine -Text $safe -Width $maxWidth)) {
        $segments = @()
        if (-not [string]::IsNullOrEmpty($Indent)) {
            $segments += (New-ConsoleSegment -Text $Indent -Color $script:UiDimSilver)
        }
        $segments += @(New-GradientSegments -Text $line -StartRgb $StartRgb -EndRgb $EndRgb -Bold:($Bold))
        Write-MenuRichLine -Segments $segments
    }
}


function Show-KeyDetailsV44 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    Write-Host ""
    Write-GradientLine -Text ("Details for {0}" -f (Short-Fpr $Key.Fingerprint)) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-Host ("  Fingerprint : {0}" -f $Key.Fingerprint) -ForegroundColor $script:UiWhiteSilver
    Write-Host ("  UID         : {0}" -f $Key.PrimaryUid) -ForegroundColor $script:UiSilverBlue
    Write-Host ("  Created     : {0}" -f $Key.Created) -ForegroundColor $script:UiDimSilver
    Write-Host ("  Expires     : {0}" -f $(if ([string]::IsNullOrWhiteSpace([string]$Key.Expires)) { "no expiry" } else { [string]$Key.Expires })) -ForegroundColor $script:UiDimSilver
    Write-Host ("  Trust       : {0}" -f $Key.Trust) -ForegroundColor $script:UiDimSilver
    Write-Host ("  Secret key  : {0}" -f $(if ($Key.HasSecret) { "present" } else { "missing" })) -ForegroundColor $script:UiDimSilver
    Write-Host ("  Selectable  : {0}" -f $(if ($Key.Selectable) { "yes" } else { "no, requires local secret key and ultimate trust" })) -ForegroundColor $script:UiDimSilver
    Write-Host ("  Algorithms  : {0}" -f (@($Key.Algorithms) -join ", ")) -ForegroundColor $script:UiSilverBlue
    Write-StrengthLine -Prefix "  Strength    : " -Name $Key.StrengthLabel -Score ([int]$Key.Strength) -Suffix ""
    Write-V44WrappedText -Text $Key.StrengthExplanation -Color $script:UiDimSilver -Width 92 -Indent "                "
    $dup = Get-DuplicateKeySummaryV44 -Key $Key -Inventory $Inventory
    if (-not [string]::IsNullOrWhiteSpace($dup)) { Write-V44WrappedText -Text $dup -Color $script:UiDimSilver -Width 100 -Indent "      " }
    Write-Host ""
}


function Get-ConsoleSafeHeightV47 {
    $h = 28
    try { $h = [Console]::WindowHeight } catch { }
    return [Math]::Max(18, [int]$h)
}

function Get-DuplicateKeyCountV47 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    $email = [string]$Key.Email
    if ([string]::IsNullOrWhiteSpace($email)) { return 0 }
    return @($Inventory | Where-Object { ([string]$_.Email) -eq $email -and (Normalize-Fingerprint $_.Fingerprint) -ne (Normalize-Fingerprint $Key.Fingerprint) }).Count
}

function Get-CompactAlgorithmProfileV47 {
    param([Parameter(Mandatory=$true)]$Key)
    $algs = @($Key.Algorithms | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($algs.Count -eq 0) { return "alg unknown" }
    $s = (($algs -join "+").ToLowerInvariant())
    $parts = @()
    if ($s -match 'ky768[_-]?cv25519') { $parts += "ky768_cv25519" }
    if ($s -match 'ky768[_-]?bp256') { $parts += "ky768_bp256" }
    if ($s -match 'brainpoolp384r1') { $parts += "brainpoolP384r1" }
    if ($s -match 'cv25519|curve25519|x25519') {
        if ($parts -notcontains "cv25519" -and $s -notmatch 'ky768[_-]?cv25519') { $parts += "cv25519" }
    }
    if ($s -match 'ed25519') { $parts += "ed25519" }
    if ($parts.Count -eq 0) { $parts = @($algs | Select-Object -First 4) }
    return ($parts -join "+")
}

function New-StrengthBadgeSegmentsV47 {
    param([int]$Score)
    $segments = @()
    if ($Score -le 0) {
        $segments += (New-ConsoleSegment -Text "[unknown]" -Color $script:UiDimSilver)
        return @($segments)
    }
    $c = Get-StrengthColor -Score $Score
    $segments += (New-ConsoleSegment -Text "[" -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text ([string]$Score) -Color $c -Bold)
    $segments += (New-ConsoleSegment -Text "/10" -Color $c -Bold)
    $segments += (New-ConsoleSegment -Text "] [" -Color $script:UiDimSilver)
    $segments += @(Get-StrengthBarSegments -Score $Score)
    $segments += (New-ConsoleSegment -Text "]" -Color $script:UiDimSilver)
    return @($segments)
}


function Get-EncryptionStrengthScore {
    param($Subkey)
    if ($null -eq $Subkey) { return 0 }
    $hay = ("{0} {1} {2} {3}" -f $Subkey.DisplayAlgo, $Subkey.Curve, $Subkey.Algo, $Subkey.KeyId)
    return [int](Get-AlgorithmScoreV44 -AlgorithmText $hay)
}


function Select-FromSearchResults {
    param([Parameter(Mandatory=$true)]$Results)

    $items = @($Results)
    if ($items.Count -eq 0) {
        Write-Host "No matching files found." -ForegroundColor $script:UiDimSilver
        return $null
    }

    Write-Host ""
    Write-GradientLine -Text "Search results" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    for ($i = 0; $i -lt $items.Count; $i++) {
        $n = $i + 1
        $size = Format-Size $items[$i].Length
        $line = ("{0,3}. {1}  ({2})" -f $n, (Format-DisplayPath $items[$i].FullName), $size)
        if (Test-EncryptedFileNameV44 $items[$i].Name) {
            Write-V44GradientTextLine -Text $line -StartRgb $script:GradientIceStart -EndRgb $script:GradientBlueEnd -Bold
        } else {
            Write-Host $line -ForegroundColor $script:UiWhiteSilver
        }
    }

    while ($true) {
        $choice = (Read-OqgPrompt "Choose file number, or Q to cancel").Trim()
        if ($choice -match '^(q|quit|cancel)$') { return $null }
        $num = 0
        if ([int]::TryParse($choice, [ref]$num)) {
            if ($num -ge 1 -and $num -le $items.Count) { return $items[$num - 1].FullName }
        }
        Write-Host "Invalid choice." -ForegroundColor $script:UiDimSilver
    }
}

function Select-EncryptionSubkey {
    param([Parameter(Mandatory=$true)]$Info)

    $enc = @(Show-EncryptionSubkeys -Info $Info)
    if ($enc.Count -eq 0) { return $null }

    $ranked = @($enc | Sort-Object @{Expression={ [int](Get-EncryptionStrengthScore -Subkey $_) }; Descending=$true})
    $best = $ranked[0]
    $bestScore = [int](Get-EncryptionStrengthScore -Subkey $best)
    $bestAlg = if ([string]::IsNullOrWhiteSpace([string]$best.DisplayAlgo)) { [string]$best.Curve } else { [string]$best.DisplayAlgo }

    if ($script:PreferKyberHybridSubkeys -and $bestScore -ge 9) {
        Write-Host "Recommended encryption subkey:" -ForegroundColor $script:UiSilverBlue
        Write-StrengthLine -Prefix "  " -Name $bestAlg -Score $bestScore -Suffix ("  {0}" -f (Short-Fpr ([string]$best.Fingerprint)))
        if (Read-YesNo "Use the strongest detected encryption subkey?" $true) { return $best }
    }

    while ($true) {
        $choice = (Read-OqgPrompt "Choose encryption subkey number, or Q to cancel").Trim()
        if ($choice -match '^(q|quit|cancel)$') { return $null }
        $num = 0
        if ([int]::TryParse($choice, [ref]$num)) {
            if ($num -ge 1 -and $num -le $enc.Count) { return $enc[$num - 1] }
        }
        Write-Host "Invalid choice." -ForegroundColor $script:UiDimSilver
    }
}


# === v48 patch: condensed key chooser, key comparison, visible key generation, admin-only local gate ===
$script:GradientBlueEnd = @(238, 244, 250)
$script:GradientLabelEnd = @(238, 244, 250)
$script:GradientSilverEnd = @(238, 244, 250)

function Request-UidGateAccess {
    param([string]$Reason = "identity operation")
    # v48: the local tool passphrase is only required when entering Admin settings.
    # GnuPG may still ask for the real private-key passphrase through pinentry when needed.
    return $true
}

function Get-StrengthCompactTextV48 {
    param([int]$Score)
    if ($Score -le 0) { return "[unknown]" }
    $filled = [Math]::Ceiling(([double]$Score / 10.0) * 6.0)
    $filled = [Math]::Min(6, [Math]::Max(1, [int]$filled))
    $bar = ""
    for ($cell = 1; $cell -le 6; $cell++) { $bar += $(if ($cell -le $filled) { "█" } else { "░" }) }
    return ("[{0}/10] [{1}]" -f $Score, $bar)
}

function Get-DuplicateKeySummaryV44 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    $email = [string]$Key.Email
    if ([string]::IsNullOrWhiteSpace($email)) { return "" }
    $others = @($Inventory | Where-Object { ([string]$_.Email) -eq $email -and (Normalize-Fingerprint $_.Fingerprint) -ne (Normalize-Fingerprint $Key.Fingerprint) })
    if ($others.Count -eq 0) { return "" }
    $parts = @()
    foreach ($o in @($others | Sort-Object @{Expression="Strength";Descending=$true}, Created)) {
        $alg = if (@($o.Algorithms).Count -gt 0) { (Get-CompactAlgorithmProfileV47 -Key $o) } else { "alg unknown" }
        $parts += ("{0}, created {1}, {2}, {3}" -f (Short-Fpr $o.Fingerprint), $o.Created, (Get-StrengthCompactTextV48 -Score ([int]$o.Strength)), $alg)
    }
    return ("Same email appears on another key: {0}" -f ($parts -join "; "))
}

function Write-DuplicateStrengthComparisonV48 {
    param(
        [Parameter(Mandatory=$true)]$Key,
        [Parameter(Mandatory=$true)]$Inventory,
        [int]$LocalNumber = 1
    )
    $email = [string]$Key.Email
    if ([string]::IsNullOrWhiteSpace($email)) { return }
    $others = @($Inventory | Where-Object { ([string]$_.Email) -eq $email -and (Normalize-Fingerprint $_.Fingerprint) -ne (Normalize-Fingerprint $Key.Fingerprint) })
    if ($others.Count -eq 0) { return }

    $best = @($others | Sort-Object @{Expression="Strength";Descending=$true}, Created | Select-Object -First 1)[0]
    $weak = @($others | Sort-Object @{Expression="Strength";Descending=$false}, Created | Select-Object -First 1)[0]

    $segments = @()
    $segments += (New-ConsoleSegment -Text "    other range: " -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text "best " -Color $script:UiSilverBlue)
    $segments += @(New-StrengthBadgeSegmentsV47 -Score ([int]$best.Strength))
    $segments += (New-ConsoleSegment -Text (" {0}" -f (Short-Fpr $best.Fingerprint)) -Color $script:UiWhiteSilver -Bold)

    if ((Normalize-Fingerprint $best.Fingerprint) -ne (Normalize-Fingerprint $weak.Fingerprint)) {
        $segments += (New-ConsoleSegment -Text "  |  weakest " -Color $script:UiDimSilver)
        $segments += @(New-StrengthBadgeSegmentsV47 -Score ([int]$weak.Strength))
        $segments += (New-ConsoleSegment -Text (" {0}" -f (Short-Fpr $weak.Fingerprint)) -Color $script:UiWhiteSilver -Bold)
    }
    Write-MenuRichLine -Segments $segments
}


function Read-KeyChooserCommandV47 {
    param([int]$VisibleCount)
    try {
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "Enter"      { return @{ Action="Cancel" } }
            "RightArrow" { return @{ Action="Next" } }
            "PageDown"   { return @{ Action="Next" } }
            "DownArrow"  { return @{ Action="Next" } }
            "LeftArrow"  { return @{ Action="Prev" } }
            "PageUp"     { return @{ Action="Prev" } }
            "UpArrow"    { return @{ Action="Prev" } }
            default {
                $ch = [string]$key.KeyChar
                if ($ch -match '^[nN]$') { return @{ Action="Next" } }
                if ($ch -match '^[pPbB]$') { return @{ Action="Prev" } }
                if ($ch -match '^[gG]$') { return @{ Action="Generate" } }
                if ($ch -match '^[qQ]$') { return @{ Action="Cancel" } }
                if ($ch -match '^[dD]$') {
                    $d = Read-OqgPrompt "Details number"
                    $n = 0
                    if ([int]::TryParse($d, [ref]$n) -and $n -ge 1 -and $n -le $VisibleCount) { return @{ Action="Details"; Number=$n } }
                    return @{ Action="Invalid" }
                }
                if ($ch -match '^[1-9]$') {
                    $n = [int]$ch
                    if ($n -ge 1 -and $n -le $VisibleCount) { return @{ Action="Choose"; Number=$n } }
                    return @{ Action="Invalid" }
                }
            }
        }
    } catch { }
    $raw = (Read-OqgPrompt "> ").Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Action="Cancel" } }
    if ($raw -match '^(?i)(g|gen|generate|new)$') { return @{ Action="Generate" } }
    if ($raw -match '^(?i)(n|next|right)$') { return @{ Action="Next" } }
    if ($raw -match '^(?i)(p|prev|back|left)$') { return @{ Action="Prev" } }
    if ($raw -match '^(?i)(q|quit|cancel)$') { return @{ Action="Cancel" } }
    if ($raw -match '^(?i)d(\d+)$') { return @{ Action="Details"; Number=[int]$matches[1] } }
    $num = 0
    if ([int]::TryParse($raw, [ref]$num)) { return @{ Action="Choose"; Number=$num } }
    return @{ Action="Invalid" }
}


# -----------------------------------------------------------------------------
# v49 stable screen override
# Keeps the v35/v48 dashboard style, but removes the unstable animated menu redraw
# that caused repeated footers, repeated Actions labels, and scrambled labels.
# Operation-result NMS can still be toggled, but main menu labels stay readable.
# -----------------------------------------------------------------------------
$script:EnableDynamicNmsMenu = $false
$script:NmsAnimateHints = $false


# -----------------------------------------------------------------------------
# v50 clarity, NMS restore, stable redraw, stronger About gradient
# -----------------------------------------------------------------------------
$script:EnableDynamicNmsMenu = $script:EnableNoMoreSecretsEffect
$script:NmsAnimateHints = $false
$script:NmsWaveMinimumReveal = 0.86
$script:NmsWavePeakReveal = 0.96
$script:NmsMaxAnimatedTextLength = 28

function Confirm-KeyMayNeedPassphraseV44 {
    param([Parameter(Mandatory=$true)]$Key)
    # Switching active identities is not an admin action and does not unlock the
    # private key. GnuPG will ask for the real private-key passphrase only when a
    # decrypt/sign operation needs it.
    return $true
}


function Get-StrengthRuleShortV50 {
    param([Parameter(Mandatory=$true)]$Key)
    $alg = (Get-CompactAlgorithmProfileV47 -Key $Key)
    $s = [int]$Key.Strength
    if ($s -ge 10) { return ("why: 10/10 because ky768_cv25519 is detected. Strongest detected profile decides the score.") }
    if ($s -eq 9) { return ("why: 9/10 because ky768_bp256 is detected. Strong PQC hybrid, ranked below ky768_cv25519.") }
    if ($s -eq 7) { return ("why: 7/10 because brainpoolP384r1 is classic ECC without a stronger Kyber hybrid.") }
    if ($s -eq 6) { return ("why: 6/10 because cv25519 is classic encryption, not PQC hybrid.") }
    if ($s -eq 5) { return ("why: 5/10 because ed25519 is mainly signing/certification, not encryption by itself.") }
    return ("why: score based on strongest recognized profile detected: {0}." -f $alg)
}

function New-StrengthBadgeSegmentsV50 {
    param([int]$Score)
    $segments = @()
    if ($Score -le 0) {
        $segments += (New-ConsoleSegment -Text "[unknown]" -Color $script:UiDimSilver)
        return @($segments)
    }
    $c = Get-StrengthColor -Score $Score
    $segments += (New-ConsoleSegment -Text "[" -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text ([string]$Score) -Color $c -Bold)
    $segments += (New-ConsoleSegment -Text "/10" -Color $c -Bold)
    $segments += (New-ConsoleSegment -Text "] [" -Color $script:UiDimSilver)
    $segments += @(Get-StrengthBarSegments -Score $Score)
    $segments += (New-ConsoleSegment -Text "]" -Color $script:UiDimSilver)
    return @($segments)
}

function Get-DuplicateKeyObjectsV50 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    $email = [string]$Key.Email
    if ([string]::IsNullOrWhiteSpace($email)) { return @() }
    return @($Inventory | Where-Object { ([string]$_.Email) -eq $email -and (Normalize-Fingerprint $_.Fingerprint) -ne (Normalize-Fingerprint $Key.Fingerprint) })
}

function Write-DuplicateStrengthComparisonV50 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory, [int]$LocalNumber = 0)
    $others = @(Get-DuplicateKeyObjectsV50 -Key $Key -Inventory $Inventory)
    if ($others.Count -eq 0) { return }

    $best = @($others | Sort-Object @{Expression="Strength";Descending=$true}, Created | Select-Object -First 1)
    $weak = @($others | Sort-Object @{Expression="Strength";Descending=$false}, Created | Select-Object -First 1)
    $thisAlg = Get-CompactAlgorithmProfileV47 -Key $Key

    Write-V46GradientWrappedText -Text ("same email: {0} other key(s). Press D{1} for full differences." -f $others.Count, $LocalNumber) -Indent "    " -Width 108 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("this key: {0} {1}. You choose which identity to use; the tool does not auto-switch to the strongest one." -f (Get-StrengthPlainBar -Score ([int]$Key.Strength)), $thisAlg) -Indent "    " -Width 108 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd

    if ($best.Count -gt 0) {
        $b = $best[0]
        Write-V46GradientWrappedText -Text ("best other: {0} {1} {2}" -f (Get-StrengthPlainBar -Score ([int]$b.Strength)), (Short-Fpr $b.Fingerprint), (Get-CompactAlgorithmProfileV47 -Key $b)) -Indent "    " -Width 108 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }
    if ($weak.Count -gt 0 -and (Normalize-Fingerprint $weak[0].Fingerprint) -ne (Normalize-Fingerprint $best[0].Fingerprint)) {
        $w = $weak[0]
        Write-V46GradientWrappedText -Text ("weakest other: {0} {1} {2}" -f (Get-StrengthPlainBar -Score ([int]$w.Strength)), (Short-Fpr $w.Fingerprint), (Get-CompactAlgorithmProfileV47 -Key $w)) -Indent "    " -Width 108 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }

    $kyberOthers = @($others | Where-Object { (Get-CompactAlgorithmProfileV47 -Key $_) -match 'ky768' } | Sort-Object @{Expression="Strength";Descending=$true}, Created)
    if ($kyberOthers.Count -gt 0) {
        $k = $kyberOthers[0]
        Write-V46GradientWrappedText -Text ("Kyber comparison: this {0} {1}; other {2} {3} {4}" -f (Get-StrengthPlainBar -Score ([int]$Key.Strength)), $thisAlg, (Get-StrengthPlainBar -Score ([int]$k.Strength)), (Short-Fpr $k.Fingerprint), (Get-CompactAlgorithmProfileV47 -Key $k)) -Indent "    " -Width 108 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    }
}


function New-AboutPairRenderLines {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string[]]$TextLines,
        [int]$TextWidth = 34
    )

    $out = @()
    $safeLabel = $Label.PadRight(12)
    $first = $true
    foreach ($t in @($TextLines)) {
        $plain = ([string]$t) -replace '\*\*(.+?)\*\*', '$1'
        foreach ($line in @(Split-BoxTextLine -Text $plain -Width $TextWidth)) {
            $segs = @()
            if ($first) {
                $segs += @(New-GradientSegments -Text $safeLabel -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
            } else {
                $segs += (New-ConsoleSegment -Text (" " * $safeLabel.Length) -Color $script:UiDimSilver)
            }
            $segs += (New-ConsoleSegment -Text " │ " -Color $script:UiLightBlue)
            $segs += @(New-GradientSegments -Text $line -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd)
            $out += (New-MenuRenderLine -Segments $segs)
            $first = $false
        }
    }
    return @($out)
}

function New-AboutRightLines {
    param([int]$Width = 54)

    $w = [Math]::Max(50, $Width)
    $inner = $w - 4
    $textWidth = [Math]::Max(30, $inner - 15)
    $rule = "─" * [Math]::Min($w, 80)
    $lines = @()
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text "About OpenPGP Quantum Guard" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "Mission" -TextWidth $textWidth -TextLines @(
        "Protect files and text with OpenPGP while keeping the operator in control of identity, output mode, and key choice.",
        "Private output keeps local diagnostic detail visible. Shareable output keeps screenshots cleaner and safer."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "PQC flow" -TextWidth $textWidth -TextLines @(
        "Encryption prefers the strongest usable Kyber / ML-KEM hybrid encryption profile on the selected identity.",
        "Scoring is explicit: 10 ky768_cv25519, 9 ky768_bp256, 7 brainpoolP384r1, 6 cv25519, 5 ed25519 identity only."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "NMS" -TextWidth $textWidth -TextLines @(
        "The No More Secrets wave is part of the interface. Menu labels keep a readable reveal while operation results can still use the cinematic reveal effect.",
        "Press N on the main screen to toggle the NMS layer without changing cryptographic behavior."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "Controls" -TextWidth $textWidth -TextLines @(
        "Use arrows to move, ENTER to open, shortcuts for direct actions, and select Quit to close the tool.",
        "The file browser can jump to a pasted folder, accept an exact file path, search, and highlight encrypted .asc/.gpg/.pgp files."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "Keys" -TextWidth $textWidth -TextLines @(
        "The chooser lists only ultimate-trust identities with a local secret key. Switching keys does not ask for the local admin passphrase.",
        "Duplicate email details compare fingerprints, creation dates, algorithms, score bars, and the exact rule behind each score."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)

    $lines += @(New-AboutPairRenderLines -Label "Security" -TextWidth $textWidth -TextLines @(
        "The script does not store private-key passphrases. GnuPG and pinentry handle private-key unlock prompts only when a crypto operation needs them.",
        "Admin settings require an explicit AUTHORIZED confirmation because they change operational behavior and defaults."
    ))
    $lines += (New-MenuRenderLine -Text $rule -Color $script:UiBorderBlue)
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text "Press ENTER to return." -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold))
    return @($lines)
}


# -----------------------------------------------------------------------------
# v53: boot gradient empty-line fix plus v51 mixed key generation, stable menu, N-only NMS, clearer scores
# -----------------------------------------------------------------------------
$script:EnableDynamicNmsMenu = $false
$script:NmsRevealOnlyWithN = $true

$script:ConfigRoot = Join-Path $env:APPDATA "OpenPGPQuantumGuard"
$script:ConfigPath = Join-Path $script:ConfigRoot "config.json"


function Get-AlgorithmScoreV51 {
    param([AllowEmptyString()][string]$AlgorithmText = "")
    $a = ([string]$AlgorithmText).ToLowerInvariant()
    if ($a -match 'ky768[_-]?cv25519|kyber.*25519|ml.?kem.*25519') { return 10 }
    if ($a -match 'ky768[_-]?bp256|kyber.*bp256|ml.?kem.*bp256') { return 9 }
    if ($a -match 'brainpoolp384r1|bp384') { return 7 }
    if ($a -match 'cv25519|curve25519|x25519') { return 6 }
    if ($a -match 'ed25519') { return 5 }
    if ($a -match 'rsa4096|4096') { return 6 }
    if ($a -match 'rsa|elg') { return 4 }
    return 0
}

function Get-AlgorithmKindV51 {
    param([AllowEmptyString()][string]$AlgorithmText = "")
    $a = ([string]$AlgorithmText).ToLowerInvariant()
    if ($a -match 'ky768|kyber|ml.?kem|pqc') { return "KYBER/HYBRID/PQC" }
    if ($a -match 'cv25519|curve25519|x25519') { return "EMAIL/CLASSIC" }
    if ($a -match 'brainpool') { return "CLASSIC ECC" }
    if ($a -match 'ed25519') { return "SIGNING ID" }
    return "CLASSIC"
}

function Get-AlgorithmRecommendationV51 {
    param([AllowEmptyString()][string]$AlgorithmText = "")
    $a = ([string]$AlgorithmText).ToLowerInvariant()
    if ($a -match 'ky768[_-]?cv25519') { return "recommended for local file protection. strongest PQC profile in this tool. not the safe email-interop choice today." }
    if ($a -match 'ky768[_-]?bp256') { return "strong PQC profile, ranked below ky768_cv25519. use when you specifically want the brainpool hybrid variant." }
    if ($a -match 'cv25519|curve25519|x25519') { return "recommended for current OpenPGP email compatibility with common clients and services." }
    if ($a -match 'brainpool') { return "solid classic ECC profile, but below PQC hybrid profiles in this tool." }
    if ($a -match 'ed25519') { return "excellent signing identity. encryption still depends on encryption subkeys." }
    return "inspect before use. the tool could not map this profile to a clear recommendation."
}

function Get-TextSubkeyAlgorithmMapForFingerprintV51 {
    param([Parameter(Mandatory=$true)][string]$Fingerprint)
    $map = @{}
    $r = Invoke-GpgCaptured -Arguments @("--list-keys", "--keyid-format", "LONG", (Normalize-Fingerprint $Fingerprint))
    foreach ($line in @($r.Output)) {
        if ($line -match '^\s*sub\s+([^/\s]+)/([0-9A-Fa-f]{16})\s+') {
            $kid = $matches[2].ToUpperInvariant()
            $map[$kid] = [string]$matches[1]
        }
    }
    return $map
}

function Get-KeyEncryptionSubkeysV51 {
    param([Parameter(Mandatory=$true)][string]$Fingerprint)

    $fp = Normalize-Fingerprint $Fingerprint
    $textMap = Get-TextSubkeyAlgorithmMapForFingerprintV51 -Fingerprint $fp
    $r = Invoke-GpgCaptured -Arguments @("--batch", "--with-colons", "--with-fingerprint", "--list-keys", $fp)
    $rows = @()
    $pending = $null

    foreach ($line in @($r.Output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = @($line -split ":", -1)
        if ($f.Count -lt 1) { continue }
        if ($f[0] -eq "sub") {
            $kid = if ($f.Count -gt 4) { ([string]$f[4]).ToUpperInvariant() } else { "" }
            $caps = if ($f.Count -gt 11) { [string]$f[11] } else { "" }
            $display = ""
            if (-not [string]::IsNullOrWhiteSpace($kid) -and $textMap.ContainsKey($kid)) { $display = [string]$textMap[$kid] }
            elseif ($f.Count -gt 16 -and -not [string]::IsNullOrWhiteSpace([string]$f[16])) { $display = [string]$f[16] }
            elseif ($f.Count -gt 3) { $display = "algo#{0}" -f $f[3] }
            $pending = [ordered]@{
                KeyId        = $kid
                Fingerprint  = ""
                Algorithm    = $display
                Created      = if ($f.Count -gt 5) { Convert-GpgDate ([string]$f[5]) } else { "" }
                Expires      = if ($f.Count -gt 6) { Convert-GpgDate ([string]$f[6]) } else { "" }
                Capabilities = $caps
                Score        = [int](Get-AlgorithmScoreV51 -AlgorithmText $display)
                Kind         = Get-AlgorithmKindV51 -AlgorithmText $display
                Recommendation = Get-AlgorithmRecommendationV51 -AlgorithmText $display
            }
        } elseif ($f[0] -eq "fpr" -and $null -ne $pending) {
            if ($f.Count -gt 9) { $pending.Fingerprint = Normalize-Fingerprint ([string]$f[9]) }
            if (([string]$pending.Capabilities) -match 'e' -or ([string]$pending.Algorithm) -match '(?i)(cv25519|ky768|brainpool|rsa|elg)') {
                $rows += [pscustomobject]$pending
            }
            $pending = $null
        }
    }

    return @($rows | Sort-Object @{Expression="Score";Descending=$true}, Algorithm, Expires)
}

function Write-StrengthBadgeV51 {
    param([int]$Score)
    Write-MenuRichLine -Segments @(New-StrengthBadgeSegmentsV50 -Score $Score)
}

function New-StrengthBadgeInlineSegmentsV51 {
    param([int]$Score)
    return @(New-StrengthBadgeSegmentsV50 -Score $Score)
}


# -----------------------------------------------------------------------------
# v54: slower boot screen and gradient strength/progress bars
# -----------------------------------------------------------------------------
function Convert-RgbArrayToColorV54 {
    param([int[]]$Rgb)
    if ($null -eq $Rgb -or $Rgb.Count -lt 3) { return "Rgb:188,212,235" }
    return ("Rgb:{0},{1},{2}" -f [int]$Rgb[0], [int]$Rgb[1], [int]$Rgb[2])
}

function Get-InterpolatedRgbV54 {
    param(
        [int[]]$StartRgb,
        [int[]]$EndRgb,
        [double]$Ratio
    )
    if ($null -eq $StartRgb -or $StartRgb.Count -lt 3) { $StartRgb = @(0, 80, 180) }
    if ($null -eq $EndRgb -or $EndRgb.Count -lt 3) { $EndRgb = @(226, 234, 246) }
    $r = [Math]::Max(0.0, [Math]::Min(1.0, [double]$Ratio))
    return @(
        [int]($StartRgb[0] + (($EndRgb[0] - $StartRgb[0]) * $r)),
        [int]($StartRgb[1] + (($EndRgb[1] - $StartRgb[1]) * $r)),
        [int]($StartRgb[2] + (($EndRgb[2] - $StartRgb[2]) * $r))
    )
}

function Get-StrengthBarGradientRangeV54 {
    param([int]$Score)

    if ($Score -ge 10) { return @{ Start=@(0, 82, 185); End=@(238, 244, 250) } }
    if ($Score -ge 9)  { return @{ Start=@(0, 74, 168); End=@(220, 232, 245) } }
    if ($Score -ge 7)  { return @{ Start=@(30, 88, 165); End=@(188, 212, 235) } }
    if ($Score -ge 6)  { return @{ Start=@(26, 62, 125); End=@(142, 188, 226) } }
    if ($Score -ge 5)  { return @{ Start=@(35, 55, 95); End=@(112, 156, 204) } }
    return @{ Start=@(30, 42, 65); End=@(82, 116, 170) }
}


function Get-StrengthBarSegments {
    param([int]$Score)
    return @(Get-GradientBarSegmentsV54 -Score $Score -Cells 6 -Bold)
}

function New-ProgressBarSegmentsV54 {
    param(
        [int]$Percent,
        [int]$Cells = 42
    )
    $segments = @()
    $safePercent = [Math]::Max(0, [Math]::Min(100, [int]$Percent))
    $safeCells = [Math]::Max(10, [int]$Cells)
    $filled = [Math]::Floor(([double]$safePercent / 100.0) * [double]$safeCells)
    $filled = [Math]::Max(0, [Math]::Min($safeCells, [int]$filled))

    $segments += (New-ConsoleSegment -Text "[" -Color $script:UiDimSilver)
    for ($i = 1; $i -le $safeCells; $i++) {
        if ($i -le $filled) {
            $ratio = if ($safeCells -le 1) { 1.0 } else { [double]($i - 1) / [double]($safeCells - 1) }
            $rgb = Get-InterpolatedRgbV54 -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Ratio $ratio
            $segments += (New-ConsoleSegment -Text "█" -Color (Convert-RgbArrayToColorV54 -Rgb $rgb) -Bold)
        } else {
            $segments += (New-ConsoleSegment -Text "░" -Color "Rgb:28,38,58")
        }
    }
    $segments += (New-ConsoleSegment -Text ("] {0,3}%" -f $safePercent) -Color $script:UiWhiteSilver -Bold)
    return @($segments)
}

function Write-BootProgressLineV54 {
    param(
        [string]$Label,
        [int]$Percent
    )
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver)
    $segments += @(New-GradientSegments -Text (($Label).PadRight(24)) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text " " -Color $script:UiDimSilver)
    $segments += @(New-ProgressBarSegmentsV54 -Percent $Percent -Cells 38)
    Write-MenuRichLine -Segments $segments
}

function Clear-PendingEnterV54 {
    try {
        while ([Console]::KeyAvailable) {
            $null = [Console]::ReadKey($true)
        }
    } catch { }
}

function Wait-BootMinimumV54 {
    param([int]$Milliseconds = 4600)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $Milliseconds) {
        Start-Sleep -Milliseconds 50
        try {
            if ([Console]::KeyAvailable) {
                # Ignore early input. The boot screen should not be skipped before it finishes loading.
                $null = [Console]::ReadKey($true)
            }
        } catch { }
    }
}

function Wait-BootAfterLoadedV54 {
    param([int]$Milliseconds = 1200)

    $deadline = [DateTime]::UtcNow.AddMilliseconds($Milliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter) { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 60
    }
}


# -----------------------------------------------------------------------------
# v55: fix N key handler, keep NMS off the right menu, compact aligned About page
# -----------------------------------------------------------------------------
function New-AboutV55SectionLines {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string[]]$TextLines,
        [int]$Width = 54
    )

    $out = @()
    $safeWidth = [Math]::Max(28, $Width)
    $textWidth = [Math]::Max(18, $safeWidth - 5)
    $out += (New-MenuRenderLine -Segments @(New-GradientSegments -Text ("  {0}" -f $Label) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    foreach ($line in @($TextLines)) {
        foreach ($wrapped in @(Split-BoxTextLine -Text ([string]$line) -Width $textWidth)) {
            $out += (New-MenuRenderLine -Text ("    {0}" -f $wrapped) -Color $script:UiSilverBlue)
        }
    }
    $out += (New-MenuRenderLine -Text ("  {0}" -f ("─" * [Math]::Max(12, [Math]::Min($safeWidth - 2, 52)))) -Color $script:UiBorderBlue)
    return @($out)
}

function Get-AboutV55LeftLines {
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
    $leftInner = 52
    $h = "─" * ($leftInner + 2)
    $lines = @(
        (New-MenuRenderLine -Text "" -Color $script:UiDimSilver),
        (New-MenuRenderLine -Text ("  ┌{0}┐" -f $h) -Color $script:UiBorderBlue),
        (New-MenuRenderLine -Segments @(New-StatusPanelGradientSegments -Label "" -Value $script:ToolName -InnerWidth $leftInner -BoldValue:$true)),
        (New-MenuRenderLine -Text "  │  PQC-enabled OpenPGP operations                      │" -Color $script:UiSilverBlue),
        (New-MenuRenderLine -Text ("  ├{0}┤" -f $h) -Color $script:UiBorderBlue),
        (New-MenuRenderLine -Segments @(New-StatusPanelGradientSegments -Label "FPR" -Value (Short-Fpr $script:IdentityFingerprint) -InnerWidth $leftInner)),
        (New-MenuRenderLine -Segments @(New-StatusPanelGradientSegments -Label "Mode" -Value ("{0}        GnuPG: {1}" -f $modeText, $gpgState) -InnerWidth $leftInner)),
        (New-MenuRenderLine -Segments @(New-StatusPanelCryptoSegments -Score 10 -InnerWidth $leftInner)),
        (New-MenuRenderLine -Segments @(New-StatusPanelGradientSegments -Label "Flow" -Value "Encrypt PQC. Decrypt auto-detect." -InnerWidth $leftInner)),
        (New-MenuRenderLine -Text ("  └{0}┘" -f $h) -Color $script:UiBorderBlue)
    )

    $lines += @(New-AboutV55SectionLines -Width 58 -Label "Mission" -TextLines @(
        "Protect files and text with OpenPGP.",
        "Keep identity, output mode, and key choice visible."
    ))
    $lines += @(New-AboutV55SectionLines -Width 58 -Label "Operator" -TextLines @(
        "Bak3n3k0.",
        "Security researcher, builder, hacker. Practical cryptography lab.",
        "Maintained as an open cryptography research project.",
        "GitHub: https://github.com/RandomLinoge"
    ))
    $lines += @(New-AboutV55SectionLines -Width 58 -Label "Security" -TextLines @(
        "Private-key passphrases are not stored by this script.",
        "GnuPG and pinentry unlock keys only when needed."
    ))
    return @($lines)
}

function Get-AboutV55RightLines {
    param([int]$Width = 62)

    $lines = @()
    $lines += (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text "About OpenPGP Quantum Guard" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    $lines += (New-MenuRenderLine -Text ("─" * [Math]::Max(20, [Math]::Min($Width - 2, 64))) -Color $script:UiBorderBlue)
    $lines += @(New-AboutV55SectionLines -Width $Width -Label "PQC flow" -TextLines @(
        "Encryption prefers Kyber / ML-KEM hybrid subkeys when both sides support them.",
        "For email compatibility today, ed25519 + cv25519 remains the practical profile."
    ))
    $lines += @(New-AboutV55SectionLines -Width $Width -Label "Scoring" -TextLines @(
        "10 ky768_cv25519, 9 ky768_bp256, 7 brainpoolP384r1, 6 cv25519, 5 ed25519 identity only.",
        "The score explains the strongest detected encryption profile, not personal trust."
    ))
    $lines += @(New-AboutV55SectionLines -Width $Width -Label "Controls" -TextLines @(
        "Arrows move, ENTER opens, N runs a left-side NMS pulse, Q exits.",
        "The browser can jump to a pasted folder, accept a file path, and highlight .asc/.gpg/.pgp."
    ))
    $lines += @(New-AboutV55SectionLines -Width $Width -Label "Keys" -TextLines @(
        "The chooser shows ultimate-trust identities with a local secret key.",
        "Duplicate email details compare fingerprints, dates, algorithms, score bars, and reasons."
    ))
    $lines += @(New-AboutV55SectionLines -Width $Width -Label "NMS" -TextLines @(
        "NMS is kept as a deliberate hotkey effect, not tied to arrow movement.",
        "The right action menu stays readable and stable."
    ))
    $lines += (New-MenuRenderLine -Text "Press ENTER to return." -Color $script:UiDimSilver)
    return @($lines)
}


function Show-NmsLeftPulseV55 {
    Clear-Host
    $width = 72
    $box = "═" * ($width - 4)
    Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Text ("  ╔{0}╗" -f $box) -Color $script:UiBorderBlue) -Width $width
    Write-Host ""
    Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Segments @(New-GradientSegments -Text "  ║ NO MORE SECRETS :: LEFT PANEL PULSE" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)) -Width $width
    Write-Host ""
    Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Text ("  ╚{0}╝" -f $box) -Color $script:UiBorderBlue) -Width $width
    Write-Host ""
    Write-V46GradientWrappedText -Text "NMS reveal executed from the N key only. The right-side action menu remains readable." -Indent "  " -Width 70 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Start-Sleep -Milliseconds 900
}


# -----------------------------------------------------------------------------
# v56: boot logo, blocking boot progress, stable menu descriptions, compact about
# -----------------------------------------------------------------------------
function Clip-TextNoWrapV56 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 120
    )
    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    $limit = [Math]::Max(1, [int]$Width)
    if ($safe.Length -le $limit) { return $safe }
    return $safe.Substring(0, $limit)
}

function Fit-TextWholeWordNoEllipsisV56 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 44
    )
    $safe = if ($null -eq $Text) { "" } else { ([string]$Text).Trim() }
    $limit = [Math]::Max(8, [int]$Width)
    if ($safe.Length -le $limit) { return $safe }
    $cut = $safe.Substring(0, $limit)
    $lastSpace = $cut.LastIndexOf(" ")
    if ($lastSpace -gt 10) { return $cut.Substring(0, $lastSpace).TrimEnd() }
    return $cut.TrimEnd()
}

function Write-GradientFixedLineV56 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [object[]]$StartRgb = $script:GradientBlueStart,
        [object[]]$EndRgb = $script:GradientBlueEnd,
        [switch]$Bold
    )
    $width = 120
    try { $width = [Math]::Max(20, [Console]::WindowWidth - 1) } catch { }
    $safe = Clip-TextNoWrapV56 -Text $Text -Width $width
    if ([string]::IsNullOrWhiteSpace($safe)) { Write-Host ""; return }
    Write-MenuRichLine -Segments @(New-GradientSegments -Text $safe -StartRgb $StartRgb -EndRgb $EndRgb -Bold:([bool]$Bold))
}

function Clear-PendingConsoleInputV56 {
    try {
        while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }
    } catch { }
}

function Get-BootStageLabelV56 {
    param([int]$Percent)
    if ($Percent -lt 12) { return "initializing console skin" }
    if ($Percent -lt 28) { return "probing GnuPG runtime" }
    if ($Percent -lt 45) { return "reading OpenPGP inventory" }
    if ($Percent -lt 62) { return "filtering ultimate secret keys" }
    if ($Percent -lt 78) { return "mapping strength profiles" }
    if ($Percent -lt 94) { return "arming filesystem browser" }
    return "ready"
}

function Write-BootProgressAtV56 {
    param(
        [int]$Row,
        [int]$Percent,
        [string]$Label
    )
    try { [Console]::SetCursorPosition(0, $Row) } catch { }
    $labelText = ("  {0}" -f (Fit-TextWholeWordNoEllipsisV56 -Text $Label -Width 28)).PadRight(30)
    $segments = @()
    $segments += @(New-GradientSegments -Text $labelText -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text " " -Color $script:UiDimSilver)
    $segments += @(New-ProgressBarSegmentsV54 -Percent $Percent -Cells 46)
    Write-MenuRichLine -Segments $segments
}

function Wait-ForEnterOnlyV56 {
    while ($true) {
        try {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq [ConsoleKey]::Enter) { return }
        } catch {
            Read-OqgPrompt "Press ENTER to continue"
            return
        }
    }
}


function New-AboutLineV56 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = $script:UiSilverBlue,
        [switch]$Gradient,
        [switch]$Bold
    )
    if ($Gradient) {
        return (New-MenuRenderLine -Segments @(New-GradientSegments -Text $Text -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold:([bool]$Bold)))
    }
    return (New-MenuRenderLine -Text $Text -Color $Color)
}

function Get-AboutV56LeftLines {
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
    $fpr = Short-Fpr $script:IdentityFingerprint
    $lines = @()
    $lines += New-AboutLineV56 "  ┌──────────────────────────────────────────────────────┐" $script:UiBorderBlue
    $lines += New-AboutLineV56 "  │  OpenPGP Quantum Guard                               │" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "  │  PQC-enabled OpenPGP operations                      │" $script:UiSilverBlue
    $lines += New-AboutLineV56 "  ├──────────────────────────────────────────────────────┤" $script:UiBorderBlue
    $lines += New-AboutLineV56 (("  │  FPR   : {0}" -f $fpr).PadRight(59) + "│") $script:UiSilverBlue
    $lines += New-AboutLineV56 (("  │  Mode  : {0}   GnuPG: {1}" -f $modeText, $gpgState).PadRight(59) + "│") $script:UiSilverBlue
    $lines += New-AboutLineV56 "  │  Crypto: Kyber / ML-KEM hybrid, score based          │" $script:UiSilverBlue
    $lines += New-AboutLineV56 "  │  Flow  : Encrypt PQC. Decrypt auto-detect.           │" $script:UiSilverBlue
    $lines += New-AboutLineV56 "  └──────────────────────────────────────────────────────┘" $script:UiBorderBlue
    $lines += New-AboutLineV56 "  Mission" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Protect files and text with OpenPGP." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Keep identity and output mode visible." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Operator" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Maintained as an open cryptography research project." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Practical crypto lab for real workflows." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Security" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Private-key passphrases are not stored." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    GnuPG pinentry unlocks only when needed." $script:UiSilverBlue
    return @($lines)
}

function Get-AboutV56RightLines {
    $lines = @()
    $lines += New-AboutLineV56 "  About OpenPGP Quantum Guard" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "  ────────────────────────────────────────────────────" $script:UiBorderBlue
    $lines += New-AboutLineV56 "  PQC flow" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Kyber / ML-KEM is preferred for local files." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Email today: ed25519 + cv25519." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Scoring" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    10 ky768_cv25519, 9 ky768_bp256." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    7 brainpoolP384r1, 6 cv25519, 5 ed25519." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Controls" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Arrows move. ENTER opens. Q exits." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Browser jumps to folder or exact file path." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Keys" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Chooser shows ultimate keys with local secret." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Details compare dates, algos, scores, reasons." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  NMS" $script:UiWhiteSilver -Gradient -Bold
    $lines += New-AboutLineV56 "    Press N for a left-side reveal pulse." $script:UiSilverBlue
    $lines += New-AboutLineV56 "    Arrow movement never triggers NMS." $script:UiSilverBlue
    $lines += New-AboutLineV56 "  Press ENTER to return." $script:UiDimSilver
    return @($lines)
}


function Show-NmsLeftPulseV56 {
    Clear-Host
    $target = @(
        "NO MORE SECRETS :: LEFT PANEL PULSE",
        "ACTIVE IDENTITY :: $(Short-Fpr $script:IdentityFingerprint)",
        "MENU MOVEMENT :: CLEAN",
        "RIGHT ACTIONS :: READABLE"
    )
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%&*+=?/"
    for ($frame = 0; $frame -lt 14; $frame++) {
        try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
        Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Text "  ╔══════════════════════════════════════════════════════════════════╗" -Color $script:UiBorderBlue) -Width 72
        Write-Host ""
        foreach ($line in $target) {
            $txt = $line
            if ($frame -lt 10) {
                $arr = $txt.ToCharArray()
                for ($i = 0; $i -lt $arr.Length; $i++) {
                    if ($arr[$i] -ne ' ' -and (Get-Random -Minimum 0 -Maximum 100) -lt (70 - ($frame * 6))) {
                        $arr[$i] = $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
                    }
                }
                $txt = -join $arr
            }
            $padded = ("  ║  {0}" -f (Clip-TextNoWrapV56 -Text $txt -Width 58)).PadRight(69) + "║"
            Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Segments @(New-GradientSegments -Text $padded -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)) -Width 72
            Write-Host ""
        }
        Write-MenuRenderLineFixed -Line (New-MenuRenderLine -Text "  ╚══════════════════════════════════════════════════════════════════╝" -Color $script:UiBorderBlue) -Width 72
        Start-Sleep -Milliseconds 75
    }
    Start-Sleep -Milliseconds 500
}


# -----------------------------------------------------------------------------
# v57: smoother boot, live left-side NMS, optimized main menu, richer one-page About
# -----------------------------------------------------------------------------
if (-not (Get-Variable -Scope Script -Name LiveNmsMenuEnabled -ErrorAction SilentlyContinue)) { $script:LiveNmsMenuEnabled = $false }

function New-V57GradientLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [switch]$Bold,
        [int[]]$StartRgb = $script:GradientLabelStart,
        [int[]]$EndRgb = $script:GradientBlueEnd
    )
    return (New-MenuRenderLine -Segments @(New-GradientSegments -Text $Text -StartRgb $StartRgb -EndRgb $EndRgb -Bold:([bool]$Bold)))
}

function New-V57TextLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = $script:UiSilverBlue
    )
    return (New-MenuRenderLine -Text $Text -Color $Color)
}

function Get-V57WindowWidth {
    try { return [Math]::Max(80, [Console]::WindowWidth) } catch { return 120 }
}

function Get-V57WindowHeight {
    try { return [Math]::Max(24, [Console]::WindowHeight) } catch { return 32 }
}

function Fit-V57 {
    param([AllowEmptyString()][string]$Text = "", [int]$Width = 40)
    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    if ($Width -le 0) { return "" }
    if ($safe.Length -le $Width) { return $safe.PadRight($Width) }
    return $safe.Substring(0, $Width)
}

function Write-SegmentsNoNewlineV57 {
    param($Segments = @(), [int]$Width = 80)
    if ($null -eq $Segments) { $Segments = @() }
    $used = 0
    foreach ($seg in @($Segments)) {
        if ($null -eq $seg) { continue }
        $t = if ($seg.PSObject.Properties.Name -contains "Text") { [string]$seg.Text } else { [string]$seg }
        $fg = if ($seg.PSObject.Properties.Name -contains "Color" -and -not [string]::IsNullOrWhiteSpace([string]$seg.Color)) { [string]$seg.Color } else { "Gray" }
        $bg = if ($seg.PSObject.Properties.Name -contains "BackgroundColor") { [string]$seg.BackgroundColor } else { "" }
        $bold = if ($seg.PSObject.Properties.Name -contains "Bold") { [bool]$seg.Bold } else { $false }
        if (($used + $t.Length) -gt $Width) {
            $remaining = [Math]::Max(0, $Width - $used)
            if ($remaining -le 0) { break }
            $t = $t.Substring(0, $remaining)
        }
        Write-ConsoleSegment -Text $t -ForegroundColor $fg -BackgroundColor $bg -Bold:($bold)
        $used += $t.Length
    }
    if ($used -lt $Width) {
        Write-ConsoleSegment -Text (" " * ($Width - $used)) -ForegroundColor $script:UiDimSilver
    }
}

function New-V57BoxTop {
    param([int]$Width = 58)
    return ("  ┌" + ("─" * ($Width - 4)) + "┐")
}
function New-V57BoxMid {
    param([int]$Width = 58)
    return ("  ├" + ("─" * ($Width - 4)) + "┤")
}
function New-V57BoxBottom {
    param([int]$Width = 58)
    return ("  └" + ("─" * ($Width - 4)) + "┘")
}
function New-V57BoxLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 58,
        [string]$Color = $script:UiSilverBlue,
        [switch]$Gradient,
        [switch]$Bold
    )
    $inner = [Math]::Max(10, $Width - 7)
    $line = "  │ " + (Fit-V57 -Text $Text -Width $inner) + " │"
    if ($Gradient) { return (New-V57GradientLine -Text $line -Bold:([bool]$Bold)) }
    return (New-V57TextLine -Text $line -Color $Color)
}
function New-V57SectionLabel {
    param([string]$Text)
    return (New-V57GradientLine -Text ("  ▸ " + $Text) -Bold)
}

function Get-V57NmsScramble {
    param([string]$Target = "NO MORE SECRETS", [int]$Frame = 0)
    if (-not [bool]$script:LiveNmsMenuEnabled) { return "NMS layer: standby" }
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%&*+=?/"
    $reveal = [Math]::Min($Target.Length, [Math]::Max(0, $Frame % ($Target.Length + 8)))
    $out = ""
    for ($i = 0; $i -lt $Target.Length; $i++) {
        if ($Target[$i] -eq ' ') { $out += ' '; continue }
        if ($i -lt $reveal) { $out += $Target[$i] }
        else { $out += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] }
    }
    return ("NMS layer: " + $out)
}


function Write-BootProgressAtV57 {
    param([int]$Row, [int]$Percent, [string]$Label)
    $width = [Math]::Min((Get-V57WindowWidth) - 1, 132)
    if ($width -lt 80) { $width = [Math]::Max(60, $width) }
    try { [Console]::SetCursorPosition(0, $Row) } catch { }
    $segments = @()
    $segments += @(New-GradientSegments -Text ("  {0}" -f (Fit-V57 -Text $Label -Width 30)) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text " " -Color $script:UiDimSilver)
    $cells = [Math]::Max(18, [Math]::Min(54, $width - 45))
    $segments += @(New-ProgressBarSegmentsV54 -Percent $Percent -Cells $cells)
    # OQG v36: the generic writer pads to Width with opaque spaces.
    # Progress is special: only paint the text and meter, not the rain behind it.
    $visible = 0
    foreach ($seg in @($segments)) { if ($null -ne $seg) { $visible += ([string]$seg.Text).Length } }
    $paintWidth = [Math]::Min($width,[Math]::Max(1,$visible))
    Write-SegmentsNoNewlineV57 -Segments $segments -Width $paintWidth
}


# v57 compact key chooser override, keeps identity check and chooser on one screen.


# -----------------------------------------------------------------------------
# v58: restore stable left dashboard, new boot logo, cleaner chooser blocks,
#      richer one-page About grid, persistent live NMS, clearer strength bars.
# -----------------------------------------------------------------------------
if (-not (Get-Variable -Scope Script -Name LiveNmsMenuEnabled -ErrorAction SilentlyContinue)) { $script:LiveNmsMenuEnabled = $false }
if (-not (Get-Variable -Scope Script -Name V58NmsFrame -ErrorAction SilentlyContinue)) { $script:V58NmsFrame = 0 }

function Get-GradientBarSegmentsV54 {
    param(
        [int]$Score,
        [int]$Cells = 6,
        [switch]$Bold
    )

    $segments = @()
    $safeCells = [Math]::Max(1, [int]$Cells)
    $safeScore = [Math]::Max(0, [Math]::Min(10, [int]$Score))
    $filled = 0
    if ($safeScore -gt 0) {
        # v58: floor makes 9/10 visually different from 10/10.
        $filled = [Math]::Floor(([double]$safeScore / 10.0) * [double]$safeCells)
        $filled = [Math]::Min($safeCells, [Math]::Max(1, [int]$filled))
    }

    $range = Get-StrengthBarGradientRangeV54 -Score $safeScore
    for ($cell = 1; $cell -le $safeCells; $cell++) {
        if ($cell -le $filled) {
            $ratio = if ($safeCells -le 1) { 1.0 } else { [double]($cell - 1) / [double]($safeCells - 1) }
            $rgb = Get-InterpolatedRgbV54 -StartRgb $range.Start -EndRgb $range.End -Ratio $ratio
            $segments += (New-ConsoleSegment -Text "█" -Color (Convert-RgbArrayToColorV54 -Rgb $rgb) -Bold:($Bold))
        } else {
            $segments += (New-ConsoleSegment -Text "░" -Color "Rgb:28,38,58")
        }
    }
    return @($segments)
}


function New-V58SectionBox {
    param(
        [int]$Width,
        [string]$Title,
        [string[]]$Lines
    )
    $inner = [Math]::Max(18, $Width - 6)
    $out = @()
    $titleSafe = Fit-V57 -Text ("╭─ {0} " -f $Title) -Width ($Width - 1)
    $top = $titleSafe + ("─" * [Math]::Max(0, $Width - $titleSafe.Length - 1)) + "╮"
    $out += New-V57GradientLine ("  " + $top) -Bold
    foreach ($line in @($Lines)) {
        $wrapped = @(Split-BoxTextLine -Text $line -Width $inner)
        if ($wrapped.Count -eq 0) { $wrapped = @('') }
        foreach ($wline in $wrapped) { $out += New-V57TextLine ("  │ " + (Fit-V57 -Text $wline -Width $inner) + " │") $script:UiSilverBlue }
    }
    $out += New-V57TextLine ("  ╰" + ("─" * ($Width - 3)) + "╯") $script:UiBorderBlue
    return @($out)
}


function Write-KeyChooserHeaderV47 {
    param([string]$Title, [int]$Page, [int]$Pages, [int]$HiddenCount)
    Clear-Host
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $active = Short-Fpr $script:IdentityFingerprint
    Write-GradientLine -Text ("  {0}" -f $Title) -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Identity check: active {0} | output {1} | selectable ultimate + local secret only | page {2}/{3}" -f $active, $modeText, ($Page + 1), $Pages) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    if ($HiddenCount -gt 0) {
        Write-V46GradientWrappedText -Text ("Hidden from chooser: {0} public, non-secret, or non-ultimate key(s)." -f $HiddenCount) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }
    Write-V46GradientWrappedText -Text "Score legend: 10 ky768_cv25519 > 9 ky768_bp256 > 7 brainpoolP384r1 > 6 cv25519 > 5 ed25519 identity." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-Host ""
}


# -----------------------------------------------------------------------------
# v60: exact boot logo, faster step loading, deterministic live NMS,
#      restored stable left dashboard, richer one-page About, cleaner key blocks.
# -----------------------------------------------------------------------------
if (-not (Get-Variable -Scope Script -Name LiveNmsMenuEnabled -ErrorAction SilentlyContinue)) { $script:LiveNmsMenuEnabled = $false }
if (-not (Get-Variable -Scope Script -Name V58NmsFrame -ErrorAction SilentlyContinue)) { $script:V58NmsFrame = 0 }

function Get-V58NmsText {
    param([string]$Target = "NO MORE SECRETS")
    $script:V58NmsFrame = [int]$script:V58NmsFrame + 1
    if (-not [bool]$script:LiveNmsMenuEnabled) { return "NMS : standby" }
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%&*+=?/"
    $frame = [int]$script:V58NmsFrame
    $reveal = [Math]::Min($Target.Length, [Math]::Max(0, $frame % ($Target.Length + 8)))
    $out = ""
    for ($i = 0; $i -lt $Target.Length; $i++) {
        if ($Target[$i] -eq ' ') { $out += ' '; continue }
        if ($i -lt $reveal) { $out += $Target[$i] }
        else { $out += $chars[(($i * 7) + $frame) % $chars.Length] }
    }
    return ("NMS : {0}" -f $out)
}


function Get-AboutV57LeftLines {
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
    $fpr = Short-Fpr $script:IdentityFingerprint
    $w = 58
    $lines = @()
    $lines += New-V57TextLine (New-V57BoxTop $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text "OpenPGP Quantum Guard" -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text "PQC-enabled OpenPGP operations" -Width $w -Color $script:UiSilverBlue
    $lines += New-V57TextLine (New-V57BoxMid $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text ("FPR  : {0}" -f $fpr) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text ("Mode : {0}  GnuPG: {1}" -f $modeText, $gpgState) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text "Flow : Encrypt PQC. Decrypt auto-detect." -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Get-V58NmsText -Target "NO MORE SECRETS") -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += @(New-V58SectionBox -Width $w -Title "Mission" -Lines @(
        "Protect files and text while the active identity stays visible.",
        "Private and Shareable modes keep operator output intentional.",
        "Designed for local file protection, lab testing, and safe screenshots."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "Operator" -Lines @(
        "Maintained as an open cryptography research project.",
        "Practical crypto lab for real workflows, not blind magic.",
        "The truth is in the logs; the proof is in the keys."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "Security" -Lines @(
        "Private-key passphrases are never stored by this script.",
        "GnuPG and pinentry unlock keys only when an operation needs them.",
        "Admin settings are gated because they change defaults and behavior."
    ))
    return @($lines)
}

function Get-AboutV57RightLines {
    $w = 66
    $lines = @()
    $lines += New-V57GradientLine "  About OpenPGP Quantum Guard" -Bold
    $lines += New-V57TextLine "  ─────────────────────────────────────────────────────────────" $script:UiBorderBlue
    $lines += @(New-V58SectionBox -Width $w -Title "PQC flow" -Lines @(
        "Local and file protection can prefer Kyber / ML-KEM hybrid subkeys.",
        "Email compatibility today still favors ed25519 plus cv25519.",
        "The tool shows the profile so the operator chooses deliberately."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "Scoring" -Lines @(
        "10 ky768_cv25519, 9 ky768_bp256, 7 brainpoolP384r1.",
        "6 cv25519, 5 ed25519 identity only.",
        "The score describes crypto profile strength, not owner trust."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "Controls" -Lines @(
        "Arrows move, ENTER opens, Q exits, N toggles live NMS.",
        "The browser jumps to folders, accepts exact paths, and highlights encrypted files.",
        "Action labels remain readable even when the NMS layer is active."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "Keys" -Lines @(
        "The chooser shows ultimate-trust identities with local secret material.",
        "Details compare fingerprints, dates, algorithms, duplicate emails, score bars, and reasons.",
        "Switching active keys does not ask for the local admin passphrase."
    ))
    $lines += @(New-V58SectionBox -Width $w -Title "NMS layer" -Lines @(
        "The reveal layer is interface theater only and never changes cryptographic behavior.",
        "It is live on dashboard redraws, but arrow movement does not trigger a scramble.",
        "Readable action labels stay stable."
    ))
    $lines += New-V57GradientLine "  Press ENTER to return." -Bold
    return @($lines)
}

function Write-KeyChooserCompactRowV47 {
    param([int]$LocalNumber, [Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    $created = if ([string]::IsNullOrWhiteSpace([string]$Key.Created)) { "unknown" } else { [string]$Key.Created }
    $uid = [string]$Key.PrimaryUid
    $subkeys = @(Get-KeyEncryptionSubkeysV51 -Fingerprint ([string]$Key.Fingerprint))
    $bestScore = if ($subkeys.Count -gt 0) { [int]$subkeys[0].Score } else { [int]$Key.Strength }
    $boxWidth = 116
    $inner = $boxWidth - 8
    Write-GradientLine -Text ("  ╔═ KEY {0} ═══════════════════════════════════════════════════════════════════════════════════════" -f $LocalNumber) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  ║ " -Color $script:UiBorderBlue)
    $segments += @(New-GradientSegments -Text (Short-Fpr $Key.Fingerprint) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver)
    $segments += @(New-StrengthBadgeInlineSegmentsV51 -Score $bestScore)
    $segments += (New-ConsoleSegment -Text ("  created {0}" -f $created) -Color $script:UiSilverBlue)
    Write-MenuRichLine -Segments $segments
    Write-V46GradientWrappedText -Text $uid -Indent "  ║   " -Width $inner -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    if ($subkeys.Count -gt 0) {
        Write-V46GradientWrappedText -Text "Encryption profiles" -Indent "  ╟─ " -Width $inner -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        $maxSub = [Math]::Min(3, $subkeys.Count)
        for ($i = 0; $i -lt $maxSub; $i++) {
            $skey = $subkeys[$i]
            $exp = if ([string]::IsNullOrWhiteSpace([string]$skey.Expires)) { "no-exp" } else { [string]$skey.Expires }
            $lineSegs = @()
            $lineSegs += (New-ConsoleSegment -Text ("  ║   {0}. " -f ($i + 1)) -Color $script:UiDimSilver)
            $lineSegs += (New-ConsoleSegment -Text ([string]$skey.Kind).PadRight(17) -Color (Get-StrengthColor -Score ([int]$skey.Score)) -Bold)
            $lineSegs += (New-ConsoleSegment -Text " " -Color $script:UiDimSilver)
            $lineSegs += @(New-StrengthBadgeInlineSegmentsV51 -Score ([int]$skey.Score))
            $lineSegs += (New-ConsoleSegment -Text ("  {0}" -f ([string]$skey.Algorithm).PadRight(16)) -Color $script:UiSilverBlue)
            $lineSegs += @(New-GradientSegments -Text (Short-Fpr $skey.Fingerprint) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold)
            $lineSegs += (New-ConsoleSegment -Text ("  exp:{0}" -f $exp) -Color $script:UiDimSilver)
            Write-MenuRichLine -Segments $lineSegs
            Write-V46GradientWrappedText -Text ("note: {0}" -f $skey.Recommendation) -Indent "  ║      " -Width ($inner - 4) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
            if ($i -lt ($maxSub - 1)) { Write-Host "  ║      ─────────────────────────────────────────────────────────────────────────" -ForegroundColor $script:UiBorderBlue }
        }
    } else {
        Write-V46GradientWrappedText -Text ("profile: {0}" -f (Get-CompactAlgorithmProfileV47 -Key $Key)) -Indent "  ║   " -Width $inner -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
        Write-V46GradientWrappedText -Text (Get-StrengthRuleShortV50 -Key $Key) -Indent "  ║   " -Width $inner -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }
    $dupCount = Get-DuplicateKeyCountV47 -Key $Key -Inventory $Inventory
    if ($dupCount -gt 0) {
        Write-V46GradientWrappedText -Text ("same email: {0} other key(s), D{1} for full differences." -f $dupCount, $LocalNumber) -Indent "  ║   " -Width $inner -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }
    Write-Host ("  ╚" + ("═" * 111) + "╝") -ForegroundColor $script:UiBorderBlue
}


# -----------------------------------------------------------------------------
# v61: richer gradient About page, highlighted key statements, one-page grid
# -----------------------------------------------------------------------------
function Remove-V61Markup {
    param([AllowEmptyString()][string]$Text = "")
    if ($null -eq $Text) { return "" }
    $s = [string]$Text
    $s = $s -replace '\[\[(.*?)\]\]', '$1'
    $s = $s -replace '\*\*(.*?)\*\*', '$1'
    return $s
}

function Get-V61PlainLength {
    param([AllowEmptyString()][string]$Text = "")
    return (Remove-V61Markup -Text $Text).Length
}

function New-V61RichSegments {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$NormalColor = $script:UiSilverBlue,
        [string]$StrongColor = $script:UiWhiteSilver
    )

    $segments = @()
    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    while ($safe.Length -gt 0) {
        $m = [regex]::Match($safe, '(\[\[.*?\]\]|\*\*.*?\*\*)')
        if (-not $m.Success) {
            if ($safe.Length -gt 0) { $segments += (New-ConsoleSegment -Text $safe -Color $NormalColor) }
            break
        }
        if ($m.Index -gt 0) {
            $segments += (New-ConsoleSegment -Text $safe.Substring(0, $m.Index) -Color $NormalColor)
        }
        $token = $m.Value
        if ($token.StartsWith('[[') -and $token.EndsWith(']]')) {
            $inner = $token.Substring(2, $token.Length - 4)
            $segments += @(New-GradientSegments -Text $inner -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
        } elseif ($token.StartsWith('**') -and $token.EndsWith('**')) {
            $inner = $token.Substring(2, $token.Length - 4)
            $segments += (New-ConsoleSegment -Text $inner -Color $StrongColor -Bold)
        }
        $safe = $safe.Substring($m.Index + $m.Length)
    }
    return @($segments)
}

function New-V61BoxLine {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 58,
        [string]$NormalColor = $script:UiSilverBlue
    )

    $inner = [Math]::Max(18, $Width - 6)
    $plain = Remove-V61Markup -Text $Text
    $safeText = [string]$Text
    if ($plain.Length -gt $inner) {
        # Keep the page inside the terminal. Important lines are manually short,
        # but this protects pasted edits from spilling into the next column.
        $plain = $plain.Substring(0, $inner)
        $safeText = $plain
    }
    $plainLen = Get-V61PlainLength -Text $safeText
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  │ " -Color $script:UiBorderBlue)
    $segments += @(New-V61RichSegments -Text $safeText -NormalColor $NormalColor)
    if ($plainLen -lt $inner) { $segments += (New-ConsoleSegment -Text (" " * ($inner - $plainLen)) -Color $script:UiDimSilver) }
    $segments += (New-ConsoleSegment -Text " │" -Color $script:UiBorderBlue)
    return (New-MenuRenderLine -Segments $segments)
}

function New-V61Box {
    param(
        [int]$Width = 58,
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Lines
    )

    $safeWidth = [Math]::Max(28, [int]$Width)
    $inner = $safeWidth - 6
    $titleText = "╭─ {0} " -f $Title
    if ($titleText.Length -gt ($safeWidth - 1)) { $titleText = $titleText.Substring(0, $safeWidth - 1) }
    $top = "  " + $titleText + ("─" * [Math]::Max(0, $safeWidth - $titleText.Length - 1)) + "╮"
    $bottom = "  ╰" + ("─" * ($safeWidth - 3)) + "╯"

    $out = @()
    $out += (New-MenuRenderLine -Segments @(New-GradientSegments -Text $top -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) {
            $out += (New-V61BoxLine -Text "" -Width $safeWidth)
            continue
        }
        # Keep manual highlights intact. Wrap only normal long lines.
        $plain = Remove-V61Markup -Text ([string]$line)
        if ($plain.Length -le $inner) {
            $out += (New-V61BoxLine -Text ([string]$line) -Width $safeWidth)
        } else {
            foreach ($wrapped in @(Split-BoxTextLine -Text $plain -Width $inner)) {
                $out += (New-V61BoxLine -Text $wrapped -Width $safeWidth)
            }
        }
    }
    $out += (New-MenuRenderLine -Text $bottom -Color $script:UiBorderBlue)
    return @($out)
}

function Get-AboutV61LeftLines {
    $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
    $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
    $fpr = Short-Fpr $script:IdentityFingerprint
    $w = 58
    $lines = @()
    $lines += New-V57TextLine (New-V57BoxTop $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text "OpenPGP Quantum Guard" -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text "PQC-enabled OpenPGP operations" -Width $w -Color $script:UiSilverBlue
    $lines += New-V57TextLine (New-V57BoxMid $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text ("FPR  : {0}" -f $fpr) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text ("Mode : {0}  GnuPG: {1}" -f $modeText, $gpgState) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text "Flow : Encrypt PQC. Decrypt auto-detect." -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Get-V58NmsText -Target "NO MORE SECRETS") -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += @(New-V61Box -Width $w -Title "Mission" -Lines @(
        "[[Protect files and text]] without hiding the operator.",
        "[[Private]] shows diagnostics. [[Shareable]] cleans output.",
        "Active identity, score, and flow stay visible."
    ))
    $lines += @(New-V61Box -Width $w -Title "Operator" -Lines @(
        "Built as an open cryptography research project.",
        "Practical crypto lab, not blind magic.",
        "Motto: **the truth is in the logs**."
    ))
    $lines += @(New-V61Box -Width $w -Title "Security model" -Lines @(
        "[[No private-key passphrase is stored]].",
        "GnuPG pinentry unlocks only when needed.",
        "Admin gate changes defaults, not key choice."
    ))
    return @($lines)
}

function Get-AboutV61RightLines {
    $w = 66
    $lines = @()
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text "  About OpenPGP Quantum Guard" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    $lines += (New-MenuRenderLine -Text "  ─────────────────────────────────────────────────────────────" -Color $script:UiBorderBlue)
    $lines += @(New-V61Box -Width $w -Title "PQC flow" -Lines @(
        "[[Kyber / ML-KEM]] is preferred for local files.",
        "Email today: [[ed25519 + cv25519]].",
        "Kyber email support depends on client support."
    ))
    $lines += @(New-V61Box -Width $w -Title "Scoring" -Lines @(
        "[[10]] ky768_cv25519, [[9]] ky768_bp256.",
        "[[7]] brainpoolP384r1, [[6]] cv25519.",
        "[[5]] ed25519 identity only.",
        "Score is crypto profile, not personal trust."
    ))
    $lines += @(New-V61Box -Width $w -Title "Controls" -Lines @(
        "Arrows move. [[ENTER opens]]. Q exits.",
        "[[N]] toggles live dashboard NMS.",
        "Action labels stay readable and stable."
    ))
    $lines += @(New-V61Box -Width $w -Title "Keys and evidence" -Lines @(
        "Chooser shows [[ultimate + local secret]] keys.",
        "Details compare fingerprints, dates, algos.",
        "Browser highlights [[.asc .gpg .pgp]].",
        "Secret exports keep confirmation gates."
    ))
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text "  Press ENTER to return." -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    return @($lines)
}

# -----------------------------------------------------------------------------
# v62: live NMS across all main-menu sentences, fixed-width and real-time
# -----------------------------------------------------------------------------
$script:LiveNmsMenuEnabled = $true
$script:V62NmsFrame = 0
$script:V62NmsFrameDelayMs = 95
$script:V62NmsGlyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*+=?/\\|[]{}<>:;'

function Convert-ToNmsSentenceV62 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Seed = 0,
        [double]$Reveal = 0.72,
        [switch]$Selected
    )

    if (-not [bool]$script:LiveNmsMenuEnabled) { return $Text }
    if ($null -eq $Text) { return "" }

    $source = [string]$Text
    if ($source.Length -le 0) { return $source }

    $glyphs = $script:V62NmsGlyphs.ToCharArray()
    if ($null -eq $glyphs -or $glyphs.Count -eq 0) { $glyphs = $script:NmsGlyphChars }
    if ($null -eq $glyphs -or $glyphs.Count -eq 0) { return $source }

    $frame = 0
    try { $frame = [int]$script:V62NmsFrame } catch { $frame = 0 }

    $baseReveal = [double]$Reveal
    if ($Selected) { $baseReveal += 0.10 }
    if ($baseReveal -lt 0.46) { $baseReveal = 0.46 }
    if ($baseReveal -gt 0.93) { $baseReveal = 0.93 }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $source.Length; $i++) {
        $ch = $source[$i]
        $chText = [string]$ch
        if ([char]::IsWhiteSpace($ch) -or $chText -match '^[\.,:;!\?\(\)\[\]{}<>/\\|\-_=+''"]$') {
            [void]$sb.Append($ch)
            continue
        }

        $code = [int][char]$ch
        $wave = ([Math]::Sin(($frame * 0.42) + ($i * 0.65) + ($Seed * 0.31)) + 1.0) / 2.0
        $effectiveReveal = $baseReveal - (0.22 * $wave)
        if ($effectiveReveal -lt 0.36) { $effectiveReveal = 0.36 }
        if ($effectiveReveal -gt 0.94) { $effectiveReveal = 0.94 }

        $gate = ((($i * 37) + ($frame * 13) + ($Seed * 19) + $code) % 100) / 100.0
        if ($gate -lt $effectiveReveal) {
            [void]$sb.Append($ch)
        } else {
            $glyphIndex = (($i * 11) + ($frame * 7) + ($Seed * 5) + $code) % $glyphs.Length
            [void]$sb.Append($glyphs[$glyphIndex])
        }
    }
    return $sb.ToString()
}

function New-NmsSentenceLineV62 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Color = $script:UiSilverBlue,
        [int]$Seed = 0,
        [double]$Reveal = 0.72,
        [string]$BackgroundColor = "",
        [switch]$Selected
    )

    $display = Convert-ToNmsSentenceV62 -Text $Text -Seed $Seed -Reveal $Reveal -Selected:([bool]$Selected)
    return (New-MenuRenderLine -Text $display -Color $Color -BackgroundColor $BackgroundColor)
}

function New-NmsSentenceGradientLineV62 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Seed = 0,
        [double]$Reveal = 0.72,
        [switch]$Bold,
        [switch]$Selected
    )

    $display = Convert-ToNmsSentenceV62 -Text $Text -Seed $Seed -Reveal $Reveal -Selected:([bool]$Selected)
    return (New-MenuRenderLine -Segments @(New-GradientSegments -Text $display -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold:([bool]$Bold)))
}

function New-NmsMenuLabelSegmentsV62 {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [string]$Prefix = "    ",
        [bool]$Selected = $false,
        [int]$Seed = 0
    )

    $displayLabel = Convert-ToNmsSentenceV62 -Text $Label -Seed $Seed -Reveal 0.74 -Selected:($Selected)
    return @(New-MenuLabelSegments -Label $displayLabel -Prefix $Prefix -Selected:$Selected)
}


function Main-Menu {
    while ($true) {
        $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
        $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
        $header = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
        $items = @(
            (New-ConsoleMenuItem -Label "Encrypt file" -Value "Encrypt" -Hint "Protect a file to the active OpenPGP identity." -Color $script:UiWhiteSilver -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Decrypt file" -Value "Decrypt" -Hint "Locate an encrypted file, then decrypt it with the matching private key." -Color $script:UiSilverBlue -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Encrypt text" -Value "EncryptText" -Hint "Paste plaintext and create ASCII-armored OpenPGP text." -Color $script:UiWhiteSilver -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Decrypt text" -Value "DecryptText" -Hint "Paste armored OpenPGP text and reveal plaintext." -Color $script:UiSilverBlue -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Inspect key status" -Value "Inspect" -Hint "View certificate, subkeys, details and export options." -Color $script:UiLightBlue -Shortcut "5"),
            (New-ConsoleMenuItem -Label "Choose active key" -Value "CycleKey" -Hint "Choose an ultimate OpenPGP identity with a local secret key." -Color $script:UiWhiteSilver -Shortcut "6"),
            (New-ConsoleMenuItem -Label "Generate new key" -Value "GenerateKey" -Hint "Create email-compatible, PQC, or manually mixed identities." -Color $script:UiSilverBlue -Shortcut "7"),
            (New-ConsoleMenuItem -Label "Export keys" -Value "Export" -Hint "Export public certificates or protected secret material." -Color $script:UiWhiteSilver -Shortcut "8"),
            (New-ConsoleMenuItem -Label "About" -Value "About" -Hint "Open the operator notes, scoring rules, controls and security model." -Color $script:UiSilverBlue -Shortcut "9"),
            (New-ConsoleMenuItem -Label "Admin settings" -Value "Admin" -Hint "Safety-confirmed settings, output mode, identity administration and defaults." -Color $script:UiMidBlue -Shortcut "0"),
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Press Enter to close the tool cleanly." -Color $script:UiWhiteSilver)
        )
        $choice = Invoke-MainMenuRightPanel -HeaderLines $header -Items $items
        switch ($choice) {
            "Encrypt" { Encrypt-FileWorkflow }
            "Decrypt" { Decrypt-FileWorkflow }
            "EncryptText" { Encrypt-TextWorkflow }
            "DecryptText" { Decrypt-TextWorkflow }
            "Inspect" { Show-KeyStatus }
            "CycleKey" { Cycle-ActiveIdentityV44 }
            "GenerateKey" { Generate-PqcKeyWorkflow }
            "Export" { Show-KeyExportMenu }
            "About" { Show-AboutSection }
            "Admin" { Show-AdminSettings }
            "Quit" { Show-Goodbye; return }
            "Back" { Write-QuitGuardNotice; continue }
            default { Write-QuitGuardNotice; continue }
        }
    }
}


# === v63 CONFIG, KEY INVENTORY, OUTPUT FOLDER, AND KEYGEN REPAIR LAYER ===
$script:ToolVersion = "v64"

function Get-ScriptDirectoryV63 {
    try {
        if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { return $PSScriptRoot }
    } catch { }
    try {
        $path = $MyInvocation.MyCommand.Path
        if (-not [string]::IsNullOrWhiteSpace($path)) { return (Split-Path -Parent $path) }
    } catch { }
    return (Get-Location).Path
}

function Get-ConfigPathV63 {
    try {
        if (-not [string]::IsNullOrWhiteSpace($env:OQG_CONFIG)) { return $env:OQG_CONFIG }
    } catch { }
    return (Join-Path (Get-ScriptDirectoryV63) "openpgp_quantum_guard.config.json")
}

function Get-ScriptVariableValueV63 {
    param([Parameter(Mandatory=$true)][string]$Name, $Default = $null)
    $v = Get-Variable -Scope Script -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $v) { return $Default }
    return $v.Value
}

function Get-ConfigPropertyV63 {
    param($Config, [Parameter(Mandatory=$true)][string]$Name, $Default = $null)
    if ($null -eq $Config) { return $Default }
    if ($Config.PSObject.Properties.Name -contains $Name) {
        $value = $Config.$Name
        if ($null -ne $value) { return $value }
    }
    return $Default
}

function New-DefaultConfigObjectV63 {
    $baseFolder = Join-Path (Get-ScriptDirectoryV63) "pgp"
    if ([string]::IsNullOrWhiteSpace($baseFolder)) { $baseFolder = Join-Path (Get-Location).Path "pgp" }
    $outFolder = Join-Path $baseFolder "output"
    return [ordered]@{
        Version = "v64"
        PgpFolder = $baseFolder
        OutputFolder = $outFolder
        GpgPath = ""
        GpgHome = ""
        DefaultIdentityFingerprint = ""
        ExpectedUidHint = ""
        OutputMode = "Shareable"
        PreferKyberHybridSubkeys = $true
        RequirePqcEncryption = $true
        DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448"
        DefaultKeyExpiry = "2y"
        AutoTrustGeneratedKeys = $true
        KeySelectableRequiresUltimateTrust = $false
        EnableLiveNmsMenu = $true
        EnableNoMoreSecretsEffect = $true
        SecurityNote = "Do not store real OpenPGP private-key passphrases in this file. GnuPG pinentry should ask for them."
    }
}

function Write-ConfigFileV63 {
    param($Config)
    $path = Get-ConfigPathV63
    $dir = Split-Path -Parent $path
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
        [void](New-Item -Path $dir -ItemType Directory -Force)
    }
    ($Config | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $path -Encoding UTF8
    $script:ConfigPath = $path
}

function Ensure-DirectoryV63 {
    param([AllowEmptyString()][string]$Path, [string]$Label = "folder")
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        try { [void](New-Item -Path $Path -ItemType Directory -Force) }
        catch { Write-Host ("Could not create {0}: {1}" -f $Label, $Path) -ForegroundColor $script:UiLightBlue }
    }
}

function Apply-ConfigObjectV63 {
    param($Config)
    $script:DefaultStartFolder = [string](Get-ConfigPropertyV63 -Config $Config -Name "PgpFolder" -Default $script:DefaultStartFolder)
    $script:OutputFolder = [string](Get-ConfigPropertyV63 -Config $Config -Name "OutputFolder" -Default $script:OutputFolder)
    $script:GpgExecutable = [string](Get-ConfigPropertyV63 -Config $Config -Name "GpgPath" -Default $script:GpgExecutable)
    $script:GpgHome = [string](Get-ConfigPropertyV63 -Config $Config -Name "GpgHome" -Default $script:GpgHome)
    $script:OutputMode = [string](Get-ConfigPropertyV63 -Config $Config -Name "OutputMode" -Default $script:OutputMode)
    $script:PreferKyberHybridSubkeys = [bool](Get-ConfigPropertyV63 -Config $Config -Name "PreferKyberHybridSubkeys" -Default $script:PreferKyberHybridSubkeys)
    $script:RequirePqcEncryption = [bool](Get-ConfigPropertyV63 -Config $Config -Name "RequirePqcEncryption" -Default $true)
    $script:DefaultKeyProfile = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultKeyProfile" -Default "LOCAL_PQC_KYBER1024_X448")
    $script:DefaultKeyExpiry = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultKeyExpiry" -Default "2y")
    $script:AutoTrustGeneratedKeys = [bool](Get-ConfigPropertyV63 -Config $Config -Name "AutoTrustGeneratedKeys" -Default $true)
    $script:KeySelectableRequiresUltimateTrust = [bool](Get-ConfigPropertyV63 -Config $Config -Name "KeySelectableRequiresUltimateTrust" -Default $false)
    $script:EnableNoMoreSecretsEffect = [bool](Get-ConfigPropertyV63 -Config $Config -Name "EnableNoMoreSecretsEffect" -Default $script:EnableNoMoreSecretsEffect)
    $script:LiveNmsMenuEnabled = [bool](Get-ConfigPropertyV63 -Config $Config -Name "EnableLiveNmsMenu" -Default $true)

    $cfgFpr = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultIdentityFingerprint" -Default "")
    if ($cfgFpr -match '^<[^>]+>$') { $cfgFpr = "" }
    $script:IdentityFingerprint = Normalize-Fingerprint $cfgFpr
    $cfgUid = [string](Get-ConfigPropertyV63 -Config $Config -Name "ExpectedUidHint" -Default "")
    if ($cfgUid -match '^Example Researcher\s*<researcher@example\.invalid>$') { $cfgUid = "" }
    $script:ExpectedUidHint = $cfgUid

    if (-not [string]::IsNullOrWhiteSpace($script:GpgHome)) {
        Ensure-DirectoryV63 -Path $script:GpgHome -Label "GnuPG home"
        $env:GNUPGHOME = $script:GpgHome
    }
    Ensure-DirectoryV63 -Path $script:DefaultStartFolder -Label "PGP folder"
    if ([string]::IsNullOrWhiteSpace($script:OutputFolder)) { $script:OutputFolder = Join-Path $script:DefaultStartFolder "output" }
    Ensure-DirectoryV63 -Path $script:OutputFolder -Label "output folder"
}

function Load-ConfigV51 {
    $script:ConfigPath = Get-ConfigPathV63
    $default = New-DefaultConfigObjectV63
    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        Write-ConfigFileV63 -Config $default
        Apply-ConfigObjectV63 -Config ([pscustomobject]$default)
    } else {
        try {
            $raw = Get-Content -LiteralPath $script:ConfigPath -Raw -ErrorAction Stop
            $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($p in $default.Keys) {
                if ($cfg.PSObject.Properties.Name -notcontains $p) {
                    Add-Member -InputObject $cfg -MemberType NoteProperty -Name $p -Value $default[$p] -Force
                }
            }
            # v64 migration: if an existing v63 config still has the old default profile,
            # move it to the requested Kyber 1024 X448 profile. Custom profiles are preserved.
            try {
                $cfgVersion = if ($cfg.PSObject.Properties.Name -contains "Version") { [string]$cfg.Version } else { "" }
                $cfgProfile = if ($cfg.PSObject.Properties.Name -contains "DefaultKeyProfile") { [string]$cfg.DefaultKeyProfile } else { "" }
                if ($cfgVersion -eq "v63" -and $cfgProfile -eq "LOCAL_PQC_KYBER768_X25519") {
                    $cfg.DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448"
                    $cfg.Version = "v64"
                }
            } catch { }
            Apply-ConfigObjectV63 -Config $cfg
            Write-ConfigFileV63 -Config $cfg
        } catch {
            Write-Host "Config file could not be parsed. Using safe defaults for this session." -ForegroundColor $script:UiLightBlue
            Write-Host ("Config path: {0}" -f $script:ConfigPath) -ForegroundColor $script:UiDimSilver
            Write-Host $_.Exception.Message -ForegroundColor $script:UiDimSilver
            Apply-ConfigObjectV63 -Config ([pscustomobject]$default)
        }
    }
    $script:GpgPath = Resolve-GpgPath
}

function Save-Config {
    $cfg = [ordered]@{
        Version = "v64"
        PgpFolder = [string]$script:DefaultStartFolder
        OutputFolder = [string]$script:OutputFolder
        GpgPath = [string]$script:GpgExecutable
        GpgHome = [string]$script:GpgHome
        DefaultIdentityFingerprint = [string](Normalize-Fingerprint $script:IdentityFingerprint)
        ExpectedUidHint = [string]$script:ExpectedUidHint
        OutputMode = [string]$script:OutputMode
        PreferKyberHybridSubkeys = [bool]$script:PreferKyberHybridSubkeys
        RequirePqcEncryption = [bool]$script:RequirePqcEncryption
        DefaultKeyProfile = [string]$script:DefaultKeyProfile
        DefaultKeyExpiry = [string]$script:DefaultKeyExpiry
        AutoTrustGeneratedKeys = [bool]$script:AutoTrustGeneratedKeys
        KeySelectableRequiresUltimateTrust = [bool]$script:KeySelectableRequiresUltimateTrust
        EnableLiveNmsMenu = [bool]$script:LiveNmsMenuEnabled
        EnableNoMoreSecretsEffect = [bool]$script:EnableNoMoreSecretsEffect
        SecurityNote = "Do not store real OpenPGP private-key passphrases in this file. GnuPG pinentry should ask for them."
    }
    Write-ConfigFileV63 -Config $cfg
}

function Resolve-GpgPath {
    if (-not [string]::IsNullOrWhiteSpace([string](Get-ScriptVariableValueV63 -Name "GpgExecutable" -Default ""))) {
        $configured = [string]$script:GpgExecutable
        if (Test-Path -LiteralPath $configured -PathType Leaf) { return (Resolve-Path -LiteralPath $configured).Path }
        $cmdConfigured = Get-Command $configured -ErrorAction SilentlyContinue
        if ($cmdConfigured) { return $cmdConfigured.Source }
    }
    $cmd = Get-Command "gpg" -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw ("GnuPG was not found. Install Gpg4win, add gpg.exe to PATH, or set GpgPath in {0}" -f (Get-ConfigPathV63))
    }
    return $cmd.Source
}

function Get-GpgBaseArgumentsV63 {
    $args = @()
    if (-not [string]::IsNullOrWhiteSpace([string](Get-ScriptVariableValueV63 -Name "GpgHome" -Default ""))) {
        $args += @("--homedir", [string]$script:GpgHome)
    }
    return @($args)
}

function Invoke-GpgCaptured {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    if ([string]::IsNullOrWhiteSpace([string](Get-ScriptVariableValueV63 -Name "GpgPath" -Default ""))) { $script:GpgPath = Resolve-GpgPath }
    $effectiveArguments = @()
    $effectiveArguments += @(Get-GpgBaseArgumentsV63)
    $effectiveArguments += @($Arguments)
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = @()
    $code = 1
    try {
        $out = @(& $script:GpgPath @effectiveArguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
    } catch {
        $out += $_.Exception.Message
        if ($null -ne $LASTEXITCODE) { $code = $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $oldEap
    }
    return [pscustomobject]@{
        ExitCode = [int]$code
        Output   = @($out)
        Command  = "gpg " + (($effectiveArguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join " ")
    }
}

function Get-OutputFolderV63 {
    if ([string]::IsNullOrWhiteSpace([string](Get-ScriptVariableValueV63 -Name "OutputFolder" -Default ""))) {
        $script:OutputFolder = Join-Path $script:DefaultStartFolder "output"
    }
    Ensure-DirectoryV63 -Path $script:OutputFolder -Label "output folder"
    return [string]$script:OutputFolder
}

function Get-DefaultEncryptOutputPathV63 {
    param([Parameter(Mandatory=$true)][string]$InputFile, [bool]$Armor = $false)
    $leaf = Split-Path -Leaf $InputFile
    $ext = if ($Armor) { ".asc" } else { ".gpg" }
    return (Get-NonClobberPath -Path (Join-Path (Get-OutputFolderV63) ($leaf + $ext)))
}

function Get-DefaultDecryptOutputPath {
    param([Parameter(Mandatory=$true)][string]$InputFile)
    $leaf = Split-Path -Leaf $InputFile
    $lower = $leaf.ToLowerInvariant()
    $baseName = $leaf
    foreach ($ext in @(".gpg", ".pgp", ".asc")) {
        if ($lower.EndsWith($ext)) {
            $baseName = $leaf.Substring(0, $leaf.Length - $ext.Length)
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = "decrypted_output" }
    return (Join-Path (Get-OutputFolderV63) $baseName)
}

function Get-AlgorithmScoreV44 {
    param([AllowEmptyString()][string]$AlgorithmText = "")
    $a = ([string]$AlgorithmText).ToLowerInvariant()
    if ($a -match 'ky1024[_-]?(cv448|x448)|kyber\s*1024.*(cv448|x448)') { return 10 }
    if ($a -match 'ky1024[_-]?bp384|kyber\s*1024.*bp384') { return 10 }
    if ($a -match 'ky768[_-]?cv25519|kyber\s*768.*(cv25519|x25519)|ml.?kem.*25519') { return 10 }
    if ($a -match 'ky768[_-]?bp256|kyber\s*768.*bp256|ml.?kem.*bp256') { return 9 }
    if ($a -match 'brainpoolp384r1|bp384') { return 7 }
    if ($a -match 'cv25519|curve25519|x25519') { return 6 }
    if ($a -match 'ed25519') { return 5 }
    if ($a -match 'rsa4096|4096') { return 6 }
    if ($a -match 'rsa|elg') { return 4 }
    return 0
}

function Get-KeyStrengthProfileV44 {
    param([string[]]$Algorithms = @())
    $cleanAlgorithms = @($Algorithms | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $joined = ($cleanAlgorithms -join ", ")
    $scores = @()
    foreach ($a in @($cleanAlgorithms)) { $scores += [int](Get-AlgorithmScoreV44 -AlgorithmText $a) }
    $score = 0
    if ($scores.Count -gt 0) { $score = [int](($scores | Measure-Object -Maximum).Maximum) }
    $lower = $joined.ToLowerInvariant()
    $label = "0/10 unknown crypto profile"
    $rule = "No recognized encryption or identity profile was detected by this tool. Inspect the raw GnuPG key before using it for protection."
    if ($lower -match 'ky1024[_-]?(cv448|x448)') { $label = "10/10 ky1024_x448 PQC hybrid"; $rule = "Score rule: Kyber1024 with X448 was detected. This is treated as a top PQC hybrid profile." }
    elseif ($lower -match 'ky1024[_-]?bp384') { $label = "10/10 ky1024_bp384 PQC hybrid"; $rule = "Score rule: Kyber1024 with brainpoolP384 was detected. This is treated as a top PQC hybrid profile." }
    elseif ($lower -match 'ky768[_-]?cv25519') { $label = "10/10 ky768_cv25519 PQC hybrid"; $rule = "Score rule: ky768_cv25519 was detected. This is the preferred Kyber768 X25519 profile in this tool." }
    elseif ($lower -match 'ky768[_-]?bp256') { $label = "9/10 ky768_bp256 PQC hybrid"; $rule = "Score rule: ky768_bp256 was detected. This is strong Kyber768 hybrid encryption, ranked below ky768_cv25519 here." }
    elseif ($lower -match 'brainpoolp384r1') { $label = "7/10 brainpool classic ECC"; $rule = "Score rule: brainpoolP384r1 was detected without a stronger Kyber hybrid encryption profile." }
    elseif ($lower -match 'cv25519|curve25519|x25519') { $label = "6/10 cv25519 classic encryption"; $rule = "Score rule: cv25519 / Curve25519 encryption was detected. It is good classic OpenPGP encryption, but not PQC hybrid." }
    elseif ($lower -match 'ed25519') { $label = "5/10 ed25519 identity only"; $rule = "Score rule: ed25519 was detected. Encryption strength depends on encryption subkeys." }
    elseif ($score -gt 0) { $label = ("{0}/10 recognized fallback profile" -f $score) }
    $rank = "Ranking used here: 10 ky1024_x448 or ky1024_bp384 or ky768_cv25519, 9 ky768_bp256, 7 brainpoolP384r1, 6 cv25519, 5 ed25519 identity only."
    return [pscustomobject]@{ Score=$score; Label=$label; Explanation=("{0} {1}" -f $rule, $rank); Algorithms=$joined }
}

function Get-TextAlgorithmListForFingerprintV44 {
    param([Parameter(Mandatory=$true)][string]$Fingerprint)
    $algs = @()
    $r = Invoke-GpgCaptured -Arguments @("--list-keys", "--keyid-format", "LONG", $Fingerprint)
    foreach ($line in @($r.Output)) {
        if ($line -match '^\s*(pub|sub)\s+([^/\s]+)') { $algs += [string]$matches[2] }
    }
    $r2 = Invoke-GpgCaptured -Arguments @("--batch", "--with-colons", "--with-fingerprint", "--list-keys", $Fingerprint)
    foreach ($line in @($r2.Output)) {
        if ($line -match '(?i)(ky\d+[_-]?(cv25519|bp256|cv448|bp384)|cv25519|ed25519|brainpoolP384r1)') { $algs += [string]$matches[1] }
    }
    return @($algs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-KeyInventoryV44 {
    $secretSet = Get-SecretFingerprintSetV44
    $r = Invoke-GpgCaptured -Arguments @("--batch", "--with-colons", "--with-fingerprint", "--list-keys")
    $rows = @()
    $current = $null
    $currentKind = ""
    foreach ($line in @($r.Output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = @($line -split ":", -1)
        if ($f.Count -lt 1) { continue }
        switch ($f[0]) {
            "pub" {
                if ($null -ne $current) { $rows += [pscustomobject]$current }
                $validity = if ($f.Count -gt 1) { [string]$f[1] } else { "" }
                $current = [ordered]@{
                    Fingerprint = ""; KeyId = $(if($f.Count -gt 4){[string]$f[4]}else{ "" }); Created = $(if($f.Count -gt 5){Convert-GpgDate ([string]$f[5])}else{ "" }); Expires = $(if($f.Count -gt 6){Convert-GpgDate ([string]$f[6])}else{ "" }); Trust = Get-GpgTrustLabelV44 -Validity $validity; Uids = @(); PrimaryUid = ""; Email = ""; Algorithms = @(); HasSecret = $false; Selectable = $false; SelectReason = ""; Strength = 0; StrengthLabel = ""; StrengthExplanation = ""
                }
                $currentKind = "pub"
            }
            "uid" {
                if ($null -ne $current -and $f.Count -gt 9) {
                    $uid = [string]$f[9]
                    $current.Uids += $uid
                    if ([string]::IsNullOrWhiteSpace([string]$current.PrimaryUid)) { $current.PrimaryUid = $uid; $current.Email = Get-EmailFromUidV44 -Uid $uid }
                }
                $currentKind = "uid"
            }
            "fpr" {
                if ($currentKind -eq "pub" -and $null -ne $current -and $f.Count -gt 9) { $current.Fingerprint = Normalize-Fingerprint ([string]$f[9]) }
            }
        }
    }
    if ($null -ne $current) { $rows += [pscustomobject]$current }
    $out = @()
    foreach ($k in @($rows)) {
        if ([string]::IsNullOrWhiteSpace([string]$k.Fingerprint)) { continue }
        $fp = Normalize-Fingerprint ([string]$k.Fingerprint)
        $k.Fingerprint = $fp
        $k.HasSecret = [bool]$secretSet.ContainsKey($fp)
        $k.Algorithms = @(Get-TextAlgorithmListForFingerprintV44 -Fingerprint $fp)
        $profile = Get-KeyStrengthProfileV44 -Algorithms $k.Algorithms
        $k.Strength = [int]$profile.Score
        $k.StrengthLabel = [string]$profile.Label
        $k.StrengthExplanation = [string]$profile.Explanation
        if ([bool]$script:KeySelectableRequiresUltimateTrust) {
            $k.Selectable = ([bool]$k.HasSecret -and ([string]$k.Trust -eq "ultimate"))
            $k.SelectReason = if ($k.Selectable) { "local secret key and ultimate trust" } else { "requires local secret key and ultimate trust" }
        } else {
            $k.Selectable = [bool]$k.HasSecret
            $k.SelectReason = if ($k.Selectable) { "local secret key present" } else { "no local secret key" }
        }
        $out += $k
    }
    return @($out)
}

function Get-SelectableKeysV44 {
    return @((Get-KeyInventoryV44) | Where-Object { $_.Selectable } | Sort-Object @{Expression="Strength";Descending=$true}, Created)
}

function Show-KeyDetailsV46 {
    param([Parameter(Mandatory=$true)]$Key, [Parameter(Mandatory=$true)]$Inventory)
    Write-Host ""
    Write-GradientLine -Text ("Details for {0}" -f (Short-Fpr $Key.Fingerprint)) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Fingerprint : {0}" -f $Key.Fingerprint) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("UID         : {0}" -f $Key.PrimaryUid) -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("Created     : {0}" -f $Key.Created) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Expires     : {0}" -f $(if ([string]::IsNullOrWhiteSpace([string]$Key.Expires)) { "no expiry" } else { [string]$Key.Expires })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Trust       : {0}" -f $Key.Trust) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Secret key  : {0}" -f $(if ($Key.HasSecret) { "present" } else { "missing" })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Selectable  : {0}" -f $(if ($Key.Selectable) { "yes, " + [string]$Key.SelectReason } else { "no, " + [string]$Key.SelectReason })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Algorithms  : {0}" -f (@($Key.Algorithms) -join ", ")) -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-StrengthLine -Prefix "  Strength    : " -Name $Key.StrengthLabel -Score ([int]$Key.Strength) -Suffix ""
    Write-V46GradientWrappedText -Text $Key.StrengthExplanation -Indent "                " -Width 96 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    $dup = Get-DuplicateKeySummaryV44 -Key $Key -Inventory $Inventory
    if (-not [string]::IsNullOrWhiteSpace($dup)) { Write-V46GradientWrappedText -Text $dup -Indent "      " -Width 106 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd }
    Write-Host ""
}

function Get-KeyGenProfileFromConfigV63 {
    $p = ([string](Get-ScriptVariableValueV63 -Name "DefaultKeyProfile" -Default "LOCAL_PQC_KYBER1024_X448")).ToUpperInvariant()
    switch ($p) {
        "EMAIL_COMPATIBLE" { return "2" }
        "LOCAL_PQC_KYBER768_BP256" { return "3" }
        "LOCAL_PQC_KYBER1024_X448" { return "4" }
        "MIXED_LAB" { return "5" }
        default { return "1" }
    }
}

function Get-SubkeyAlgorithmRegexV63 {
    param([Parameter(Mandatory=$true)][string]$Algorithm)
    switch -Regex ($Algorithm.ToLowerInvariant()) {
        '^cv25519$' { return '^(cv25519|curve25519|x25519)$' }
        '^ky768_cv25519$' { return 'ky768[_-]?(cv25519|x25519)|kyber\s*768.*(cv25519|x25519)' }
        '^ky768_bp256$' { return 'ky768[_-]?bp256|kyber\s*768.*bp256' }
        '^ky1024_cv448$' { return 'ky1024[_-]?(cv448|x448)|kyber\s*1024.*(cv448|x448)' }
        '^ky1024_bp384$' { return 'ky1024[_-]?bp384|kyber\s*1024.*bp384' }
        default { return [regex]::Escape($Algorithm) }
    }
}

function Test-KeyHasSubkeyAlgorithmV63 {
    param([Parameter(Mandatory=$true)][string]$Fingerprint, [Parameter(Mandatory=$true)][string]$Algorithm)
    $algs = @(Get-TextAlgorithmListForFingerprintV44 -Fingerprint $Fingerprint)
    $rx = Get-SubkeyAlgorithmRegexV63 -Algorithm $Algorithm
    foreach ($a in @($algs)) {
        $value = ([string]$a).ToLowerInvariant()
        if ($Algorithm -eq "cv25519") {
            if ($value -notmatch 'ky' -and $value -match $rx) { return $true }
        } else {
            if ($value -match $rx) { return $true }
        }
    }
    return $false
}

function Set-GpgOwnerTrustUltimateV63 {
    param([Parameter(Mandatory=$true)][string]$Fingerprint)
    $fp = Normalize-Fingerprint $Fingerprint
    if ([string]::IsNullOrWhiteSpace($fp)) { return $false }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("oqg_ownertrust_{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    try {
        [System.IO.File]::WriteAllText($tmp, ("{0}:6:`n" -f $fp), [System.Text.UTF8Encoding]::new($false))
        $r = Invoke-GpgCaptured -Arguments @("--import-ownertrust", $tmp)
        return ($r.ExitCode -eq 0)
    } catch { return $false }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Invoke-GpgFullGenerateKeyWizardV63 {
    Write-Banner -Title "GnuPG built-in key wizard"
    Write-V46GradientWrappedText -Text "This opens the real GnuPG key wizard. For Kyber on your GnuPG build, choose key type 16, ECC and Kyber." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "Kyber menu mapping: 1 Kyber 768 bp256, 2 Kyber 1024 bp384, 3 Kyber 768 X25519, 4 Kyber 1024 X448." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "After the wizard finishes, this tool will refresh the key inventory and local secret keys will be selectable even if ownertrust is still unknown." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""
    if (-not (Read-YesNo "Launch gpg --full-generate-key now?" $true)) { return }
    try {
        $args = @()
        $args += @(Get-GpgBaseArgumentsV63)
        $args += "--full-generate-key"
        Start-OqgInteractiveGpg -Arguments $args
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor $script:UiLightBlue
    }
    Wait-User
}

function Generate-PqcKeyWorkflow {
    Write-Banner -Title "Generate OpenPGP key"
    Write-V46GradientWrappedText -Text "Choose a profile. This build verifies that the requested encryption subkey actually exists after generation. If Kyber was requested but not created, it will warn and will not silently label the key as PQC." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "Compatibility note: Microsoft Outlook and Proton Mail are still safest with classic Ed25519 plus cv25519 keys. Use Kyber profiles for local file protection, labs, or recipients who explicitly support OpenPGP PQC." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""
    Write-Host "Profiles:" -ForegroundColor $script:UiWhiteSilver
    Write-Host "  1. LOCAL PQC [recommended for this tool]" -ForegroundColor $script:UiSilverBlue
    Write-Host "     primary: ed25519 | encryption: ky768_cv25519, GPG Kyber menu option 3" -ForegroundColor $script:UiDimSilver
    Write-Host "  2. EMAIL COMPATIBLE [recommended for Outlook/Proton today]" -ForegroundColor $script:UiSilverBlue
    Write-Host "     primary: ed25519 | encryption: cv25519 classic" -ForegroundColor $script:UiDimSilver
    Write-Host "  3. LOCAL PQC GPG DEFAULT" -ForegroundColor $script:UiSilverBlue
    Write-Host "     primary: ed25519 | encryption: ky768_bp256, GPG Kyber menu option 1" -ForegroundColor $script:UiDimSilver
    Write-Host "  4. ADVANCED PQC" -ForegroundColor $script:UiSilverBlue
    Write-Host "     primary: ed25519 | encryption: ky1024_cv448, GPG Kyber menu option 4" -ForegroundColor $script:UiDimSilver
    Write-Host "  5. MIXED LAB" -ForegroundColor $script:UiSilverBlue
    Write-Host "     primary: ed25519 | encryption: cv25519 + ky768_cv25519 + ky768_bp256" -ForegroundColor $script:UiDimSilver
    Write-Host "  6. MANUAL MIX" -ForegroundColor $script:UiSilverBlue
    Write-Host "     choose encryption subkeys manually" -ForegroundColor $script:UiDimSilver
    Write-Host "  7. GnuPG built-in wizard" -ForegroundColor $script:UiSilverBlue
    Write-Host "     use option 16, ECC and Kyber, exactly as shown by your gpg.exe" -ForegroundColor $script:UiDimSilver
    Write-Host ""
    $defaultProfile = Get-KeyGenProfileFromConfigV63
    $profile = (Read-OqgPrompt ("Choose profile [{0}]" -f $defaultProfile)).Trim()
    if ([string]::IsNullOrWhiteSpace($profile)) { $profile = $defaultProfile }
    if ($profile -eq "7") { Invoke-GpgFullGenerateKeyWizardV63; return }

    $primaryAlgo = "ed25519"
    $subAlgos = @("ky768_cv25519")
    switch ($profile) {
        "2" { $subAlgos = @("cv25519"); $script:DefaultKeyProfile = "EMAIL_COMPATIBLE" }
        "3" { $subAlgos = @("ky768_bp256"); $script:DefaultKeyProfile = "LOCAL_PQC_KYBER768_BP256" }
        "4" { $subAlgos = @("ky1024_cv448"); $script:DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448" }
        "5" { $subAlgos = @("cv25519", "ky768_cv25519", "ky768_bp256"); $script:DefaultKeyProfile = "MIXED_LAB" }
        "6" {
            Write-Host ""
            Write-Host "Encryption subkeys, comma separated:" -ForegroundColor $script:UiWhiteSilver
            Write-Host "  1. cv25519            classic email-compatible encryption" -ForegroundColor $script:UiSilverBlue
            Write-Host "  2. ky768_bp256        Kyber 768 bp256, GPG Kyber menu option 1" -ForegroundColor $script:UiSilverBlue
            Write-Host "  3. ky1024_bp384       Kyber 1024 bp384, GPG Kyber menu option 2" -ForegroundColor $script:UiSilverBlue
            Write-Host "  4. ky768_cv25519      Kyber 768 X25519, GPG Kyber menu option 3" -ForegroundColor $script:UiSilverBlue
            Write-Host "  5. ky1024_cv448       Kyber 1024 X448, GPG Kyber menu option 4" -ForegroundColor $script:UiSilverBlue
            $mix = (Read-OqgPrompt "Choose subkeys [4]").Trim()
            if ([string]::IsNullOrWhiteSpace($mix)) { $mix = "4" }
            $subAlgos = @()
            foreach ($part in ($mix -split ',')) {
                switch ($part.Trim()) {
                    "1" { $subAlgos += "cv25519" }
                    "2" { $subAlgos += "ky768_bp256" }
                    "3" { $subAlgos += "ky1024_bp384" }
                    "4" { $subAlgos += "ky768_cv25519" }
                    "5" { $subAlgos += "ky1024_cv448" }
                }
            }
            $subAlgos = @($subAlgos | Select-Object -Unique)
            if ($subAlgos.Count -eq 0) { $subAlgos = @("ky768_cv25519") }
            $script:DefaultKeyProfile = "MANUAL_MIX"
        }
        default { $subAlgos = @("ky1024_cv448"); $script:DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448" }
    }

    Write-Host ""
    $name = (Read-OqgPrompt "Name").Trim()
    $email = (Read-OqgPrompt "Email").Trim()
    $comment = (Read-OqgPrompt "Comment, optional").Trim()
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($email)) { Write-Host "Name and email are required." -ForegroundColor $script:UiLightBlue; Wait-User; return }
    $uid = if ([string]::IsNullOrWhiteSpace($comment)) { "{0} <{1}>" -f $name, $email } else { "{0} ({1}) <{2}>" -f $name, $comment, $email }
    $expiryDefault = [string](Get-ScriptVariableValueV63 -Name "DefaultKeyExpiry" -Default "2y")
    $expiry = (Read-OqgPrompt ("Expiration [{0}]" -f $expiryDefault)).Trim()
    if ([string]::IsNullOrWhiteSpace($expiry)) { $expiry = $expiryDefault }
    $script:DefaultKeyExpiry = $expiry

    Write-Host ""
    Write-V46GradientWrappedText -Text ("New UID      : {0}" -f $uid) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("Primary      : {0}" -f $primaryAlgo) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Encryption   : {0}" -f ($subAlgos -join ", ")) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Expiration   : {0}" -f $expiry) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    if (-not (Read-YesNo "Generate this new key now?" $false)) { return }

    $before = @(Get-PublicPrimaryKeyRows | ForEach-Object { Normalize-Fingerprint $_.Fingerprint })
    $r = Invoke-GpgCaptured -Arguments @("--quick-generate-key", $uid, $primaryAlgo, "cert,sign", $expiry)
    if ($r.ExitCode -ne 0) { Write-GpgFailure -Result $r -ActionName "Generate primary key"; Wait-User; return }
    Start-Sleep -Milliseconds 600
    $afterRows = @(Get-PublicPrimaryKeyRows)
    $newRows = @($afterRows | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -notin $before })
    $newFpr = ""
    if ($newRows.Count -gt 0) { $newFpr = Normalize-Fingerprint ([string]$newRows[-1].Fingerprint) }
    if ([string]::IsNullOrWhiteSpace($newFpr)) { $newFpr = Select-PublicPrimaryFingerprint -Title "Select the newly generated key" }
    if ([string]::IsNullOrWhiteSpace($newFpr)) { Write-Host "Could not determine new fingerprint." -ForegroundColor $script:UiLightBlue; Wait-User; return }

    $failed = @()
    foreach ($algo in $subAlgos) {
        Write-Host ("Adding encryption subkey: {0}" -f $algo) -ForegroundColor $script:UiSilverBlue
        $add = Invoke-GpgCaptured -Arguments @("--quick-add-key", $newFpr, $algo, "encrypt", $expiry)
        Start-Sleep -Milliseconds 600
        if ($add.ExitCode -ne 0 -or -not (Test-KeyHasSubkeyAlgorithmV63 -Fingerprint $newFpr -Algorithm $algo)) {
            $failed += $algo
            Write-GpgFailure -Result $add -ActionName ("Add subkey {0}" -f $algo)
        } else {
            Write-Host ("Verified subkey: {0}" -f $algo) -ForegroundColor $script:UiWhiteSilver
        }
    }

    if ([bool]$script:AutoTrustGeneratedKeys) {
        if (Set-GpgOwnerTrustUltimateV63 -Fingerprint $newFpr) { Write-Host "Ownertrust set to ultimate for the generated local key." -ForegroundColor $script:UiDimSilver }
    }

    $actualAlgorithms = @(Get-TextAlgorithmListForFingerprintV44 -Fingerprint $newFpr)
    Write-Host ""
    Write-Host "New key generated:" -ForegroundColor $script:UiWhiteSilver
    Write-Host "  $newFpr" -ForegroundColor $script:UiWhiteSilver
    Write-V46GradientWrappedText -Text ("Detected algorithms: {0}" -f ($actualAlgorithms -join ", ")) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-V46GradientWrappedText -Text ("Warning: requested subkey(s) were not detected: {0}" -f ($failed -join ", ")) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        Write-V46GradientWrappedText -Text "The primary key exists, but this script will not pretend it is Kyber/PQC unless the Kyber subkey is visible in GnuPG. You can retry adding subkeys, or use the built-in GnuPG wizard with option 16, ECC and Kyber." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        if (Read-YesNo "Open the built-in GnuPG wizard now?" $false) { Invoke-GpgFullGenerateKeyWizardV63 }
    }

    if (Read-YesNo "Use this key as the active default for this program?" ($failed.Count -eq 0)) {
        $script:IdentityFingerprint = Normalize-Fingerprint $newFpr
        $script:ExpectedUidHint = $uid
        Save-Config
        Write-Host "Active fingerprint saved to the config file." -ForegroundColor $script:UiWhiteSilver
    }
    Wait-User
}

function Select-PublicPrimaryFingerprint {
    param([string]$Title = "Choose default OpenPGP identity")
    $inventory = @(Get-KeyInventoryV44)
    $keys = @($inventory | Where-Object { $_.Selectable } | Sort-Object @{Expression="Strength";Descending=$true}, Created)
    if ($keys.Count -eq 0) {
        Clear-Host
        Write-KeyChooserHeaderV47 -Title $Title -Page 0 -Pages 1 -HiddenCount ([Math]::Max(0, $inventory.Count))
        Write-V46GradientWrappedText -Text "No selectable OpenPGP identity was found. In v63, selectable means a local private key is present. Ultimate trust is helpful, but no longer required unless the config explicitly enables that strict rule." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        Write-V46GradientWrappedText -Text "Press G to create a new key, or create/import a key outside the script and return here. The next refresh will recognize local secret keys." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        $cmd = Read-KeyChooserCommandV47 -VisibleCount 0
        if ([string]$cmd.Action -eq "Generate") { Generate-PqcKeyWorkflow; return (Select-PublicPrimaryFingerprint -Title $Title) }
        return $null
    }
    $page = 0
    while ($true) {
        $height = Get-ConsoleSafeHeightV47
        $pageSize = [Math]::Max(1, [Math]::Floor(($height - 8) / 5))
        $pageSize = [Math]::Min(4, $pageSize)
        $pages = [Math]::Max(1, [int][Math]::Ceiling([double]$keys.Count / [double]$pageSize))
        if ($page -ge $pages) { $page = $pages - 1 }
        if ($page -lt 0) { $page = 0 }
        $hidden = [Math]::Max(0, $inventory.Count - $keys.Count)
        Write-KeyChooserHeaderV47 -Title $Title -Page $page -Pages $pages -HiddenCount $hidden
        $startIndex = $page * $pageSize
        $visible = @($keys | Select-Object -Skip $startIndex -First $pageSize)
        for ($i = 0; $i -lt $visible.Count; $i++) { Write-KeyChooserCompactRowV47 -LocalNumber ($i + 1) -Key $visible[$i] -Inventory $inventory; Write-Host "" }
        $rangeText = if ($visible.Count -le 1) { "Choose 1" } else { "Choose 1-{0}" -f $visible.Count }
        $detailsText = if ($visible.Count -le 1) { "D1 details" } else { "D1-D{0} details" -f $visible.Count }
        $footer = ("{0}, {1}, G generate key, ENTER/Q cancel" -f $rangeText, $detailsText)
        if ($pages -gt 1) { $footer += ", arrows or N/P pages" }
        Write-V46GradientWrappedText -Text $footer -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
        $cmd = Read-KeyChooserCommandV47 -VisibleCount $visible.Count
        switch ([string]$cmd.Action) {
            "Cancel" { return $null }
            "Next"   { if ($page -lt ($pages - 1)) { $page++ }; continue }
            "Prev"   { if ($page -gt 0) { $page-- }; continue }
            "Generate" { Generate-PqcKeyWorkflow; $inventory = @(Get-KeyInventoryV44); $keys = @($inventory | Where-Object { $_.Selectable } | Sort-Object @{Expression="Strength";Descending=$true}, Created); $page = 0; if ($keys.Count -eq 0) { return $null }; continue }
            "Details" { $n = [int]$cmd.Number; if ($n -ge 1 -and $n -le $visible.Count) { Clear-Host; Show-KeyDetailsV46 -Key $visible[$n - 1] -Inventory $inventory; Wait-User }; continue }
            "Choose" { $n = [int]$cmd.Number; if ($n -ge 1 -and $n -le $visible.Count) { return (Normalize-Fingerprint ([string]$visible[$n - 1].Fingerprint)) }; continue }
            default { Write-V46GradientWrappedText -Text "Invalid selection." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd; Start-Sleep -Milliseconds 350; continue }
        }
    }
}

function Cycle-ActiveIdentityV44 {
    $chosen = Select-PublicPrimaryFingerprint -Title "Choose active OpenPGP identity"
    if ([string]::IsNullOrWhiteSpace($chosen)) { return }
    $keys = @(Get-SelectableKeysV44)
    $match = @($keys | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq (Normalize-Fingerprint $chosen) })
    if ($match.Count -eq 0) { return }
    $k = $match[0]
    $script:IdentityFingerprint = Normalize-Fingerprint ([string]$k.Fingerprint)
    $script:ExpectedUidHint = [string]$k.PrimaryUid
    Save-Config
    Write-Banner -Title "Active OpenPGP identity updated"
    Write-V46GradientWrappedText -Text ("Active: {0}  {1}" -f (Short-Fpr $script:IdentityFingerprint), $script:ExpectedUidHint) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-StrengthLine -Prefix "Strength: " -Name $k.StrengthLabel -Score ([int]$k.Strength) -Suffix ""
    Wait-User
}

function Initialize-ActiveIdentityV44 {
    Show-StartupBootScreenV51
    Load-ConfigV51
    Write-Banner -Title "OpenPGP identity check"
    Write-V46GradientWrappedText -Text ("Config: {0}" -f (Format-DisplayPath $script:ConfigPath)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("PGP folder: {0}" -f (Format-DisplayPath $script:DefaultStartFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Output folder: {0}" -f (Format-DisplayPath $script:OutputFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    $inventory = @(Get-KeyInventoryV44)
    if ($inventory.Count -eq 0) {
        Write-V46GradientWrappedText -Text "No OpenPGP keys were found in this GnuPG home." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        if (Read-YesNo "Generate a new OpenPGP key now?" $true) { Generate-PqcKeyWorkflow; $inventory = @(Get-KeyInventoryV44) }
    }
    $selectable = @($inventory | Where-Object { $_.Selectable })
    if ($selectable.Count -eq 0) {
        Write-V46GradientWrappedText -Text "No selectable key was found. In v63, a selectable key means a local private key is present. The old ultimate-trust-only rule is now configurable and disabled by default." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        if (Read-YesNo "Generate a new key and use it as default?" $true) { Generate-PqcKeyWorkflow; $selectable = @(Get-SelectableKeysV44) }
    }
    if ($selectable.Count -eq 0) { return }
    $current = @($selectable | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq (Normalize-Fingerprint $script:IdentityFingerprint) })
    if ($current.Count -gt 0) { return }
    $chosen = Select-PublicPrimaryFingerprint -Title "Choose default OpenPGP identity"
    if (-not [string]::IsNullOrWhiteSpace($chosen)) {
        $script:IdentityFingerprint = Normalize-Fingerprint $chosen
        $chosenKey = @($selectable | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq $script:IdentityFingerprint })
        if ($chosenKey.Count -gt 0) { $script:ExpectedUidHint = [string]$chosenKey[0].PrimaryUid }
        Save-Config
    }
}

function Encrypt-FileWorkflow {
    Write-Banner -Title "Encrypt OpenPGP file"
    $info = Get-GpgIdentityInfo
    if ((Normalize-Fingerprint $info.PrimaryFingerprint) -ne $script:IdentityFingerprint) {
        Write-Host "Warning: GnuPG resolved a different primary fingerprint than the configured one:" -ForegroundColor $script:UiDimSilver
        Write-Host "Configured: $script:IdentityFingerprint" -ForegroundColor $script:UiDimSilver
        Write-Host "Resolved:   $($info.PrimaryFingerprint)" -ForegroundColor $script:UiDimSilver
        if (-not (Read-YesNo "Continue anyway?" $false)) { return }
    }
    if ($info.Uids.Count -gt 0) { Write-Host "UIDs on this certificate:" -ForegroundColor $script:UiSilverBlue; $info.Uids | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }; Write-Host "" }
    $subkey = Select-EncryptionSubkey -Info $info
    if (-not $subkey) { return }
    $recipient = "{0}!" -f ([string]$subkey.Fingerprint)
    Write-Host ""
    Write-Host "Encryption will use the exact recipient subkey:" -ForegroundColor $script:UiSilverBlue
    Write-Host "  $recipient" -ForegroundColor White
    Write-Host "The trailing ! is intentional. It prevents GnuPG from auto-selecting another subkey." -ForegroundColor $script:UiDimSilver
    Write-Host ""
    $inputFile = Select-FileInteractive -StartFolder $script:DefaultStartFolder -Purpose "Choose file to encrypt"
    if (-not $inputFile) { return }
    $armor = Read-YesNo "Create ASCII armored output .asc instead of binary .gpg?" $false
    $sign = Read-YesNo "Also sign the encrypted file with this active key?" $true
    $defaultOut = Get-DefaultEncryptOutputPathV63 -InputFile $inputFile -Armor:$armor
    Write-Host ""
    Write-Host "Default output:" -ForegroundColor Gray
    Write-Host "  $(Format-DisplayPath $defaultOut)" -ForegroundColor White
    $outPath = $defaultOut
    if (-not (Read-YesNo "Use this output path?" $true)) { $custom = (Read-OqgPrompt "Output path").Trim('"'); if (-not [string]::IsNullOrWhiteSpace($custom)) { $outPath = $custom } }
    $gpgArgs = @("--yes", "--trust-model", "always")
    # GnuPG 2.5+ can enforce that every recipient uses a composite
    # Kyber/ML-KEM encryption key. Disable this policy in the config only when
    # deliberately testing a classic compatibility profile.
    if ([bool]$script:RequirePqcEncryption) { $gpgArgs += "--require-pqc-encryption" }
    if ($armor) { $gpgArgs += "--armor" }
    $gpgArgs += @("--encrypt", "--recipient", $recipient)
    if ($sign) { $gpgArgs += @("--sign", "--local-user", $script:IdentityFingerprint) }
    $gpgArgs += @("--output", $outPath, $inputFile)
    Write-Host ""
    Write-Host "Running GnuPG..." -ForegroundColor $script:UiDimSilver
    $result = Invoke-GpgCaptured -Arguments $gpgArgs
    if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $outPath)) {
        Write-Host ""
        Invoke-NmsOperationReveal -Lines @("ENCRYPTION COMPLETE", ("OUTPUT :: {0}" -f (Format-DisplayPath $outPath)))
        Write-Host "Encrypted successfully:" -ForegroundColor $script:UiWhiteSilver
        Write-Host "  $(Format-DisplayPath $outPath)" -ForegroundColor White
    } else { Write-GpgFailure -Result $result -ActionName "Encryption" }
    Wait-User
}

function Encrypt-TextWorkflow {
    Write-Banner -Title "Encrypt OpenPGP text"
    $info = Get-GpgIdentityInfo
    $subkey = Select-EncryptionSubkey -Info $info
    if (-not $subkey) { return }
    $recipient = "{0}!" -f ([string]$subkey.Fingerprint)
    $plain = Read-MultilineTextBlock -Title "Text to encrypt"
    if ($null -eq $plain) { return }
    if ([string]::IsNullOrWhiteSpace($plain)) { Write-Host "No text entered. Encryption cancelled." -ForegroundColor $script:UiDimSilver; Wait-User; return }
    $sign = Read-YesNo "Also sign the encrypted text with this active key?" $true
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $defaultOut = Get-NonClobberPath -Path (Join-Path (Get-OutputFolderV63) ("openpgp_quantum_guard_text_{0}.asc" -f $stamp))
    Write-Host ""
    Write-Host "Default output:" -ForegroundColor $script:UiDimSilver
    Write-Host "  $(Format-DisplayPath $defaultOut)" -ForegroundColor White
    $outPath = $defaultOut
    if (-not (Read-YesNo "Use this output path?" $true)) { $custom = (Read-OqgPrompt "Output path").Trim('"'); if (-not [string]::IsNullOrWhiteSpace($custom)) { $outPath = $custom } }
    $tmpIn = Join-Path ([System.IO.Path]::GetTempPath()) ("oqg_plain_{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    try {
        [System.IO.File]::WriteAllText($tmpIn, $plain, [System.Text.UTF8Encoding]::new($false))
        $gpgArgs = @("--yes", "--trust-model", "always")
        if ([bool]$script:RequirePqcEncryption) { $gpgArgs += "--require-pqc-encryption" }
        $gpgArgs += @("--armor", "--encrypt", "--recipient", $recipient)
        if ($sign) { $gpgArgs += @("--sign", "--local-user", $script:IdentityFingerprint) }
        $gpgArgs += @("--output", $outPath, $tmpIn)
        Write-Host ""
        Write-Host "Running GnuPG..." -ForegroundColor $script:UiDimSilver
        $result = Invoke-GpgCaptured -Arguments $gpgArgs
        if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $outPath)) {
            Invoke-NmsOperationReveal -Lines @("TEXT ENCRYPTION COMPLETE", ("OUTPUT :: {0}" -f (Format-DisplayPath $outPath)))
            Write-Host "Encrypted text saved:" -ForegroundColor $script:UiWhiteSilver
            Write-Host "  $(Format-DisplayPath $outPath)" -ForegroundColor White
            Write-Host ""
            Write-Host "Encrypted text block:" -ForegroundColor $script:UiSilverBlue
            Get-Content -LiteralPath $outPath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        } else { Write-GpgFailure -Result $result -ActionName "Text encryption" }
    } finally { Remove-Item -LiteralPath $tmpIn -Force -ErrorAction SilentlyContinue }
    Wait-User
}

function Decrypt-TextWorkflow {
    Write-Banner -Title "Decrypt OpenPGP text"
    Write-Host "Paste an ASCII-armored OpenPGP message or encrypted block." -ForegroundColor $script:UiDimSilver
    $cipher = Read-MultilineTextBlock -Title "Text to decrypt"
    if ($null -eq $cipher) { return }
    if ([string]::IsNullOrWhiteSpace($cipher)) { Write-Host "No text entered. Decryption cancelled." -ForegroundColor $script:UiDimSilver; Wait-User; return }
    $tmpIn = Join-Path ([System.IO.Path]::GetTempPath()) ("oqg_cipher_{0}.asc" -f ([guid]::NewGuid().ToString("N")))
    $tmpOut = Join-Path ([System.IO.Path]::GetTempPath()) ("oqg_decrypted_{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    try {
        [System.IO.File]::WriteAllText($tmpIn, $cipher, [System.Text.UTF8Encoding]::new($false))
        $result = Invoke-GpgCaptured -Arguments @("--yes", "--output", $tmpOut, "--decrypt", $tmpIn)
        if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $tmpOut)) {
            $plain = [System.IO.File]::ReadAllText($tmpOut, [System.Text.UTF8Encoding]::new($false))
            Invoke-NmsOperationReveal -Lines @("TEXT DECRYPTION COMPLETE")
            Show-DecryptedTextPanel -PlainText $plain -GpgMessages $result.Output
            if (Read-YesNo "Save decrypted text to a file?" $false) {
                $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $defaultOut = Get-NonClobberPath -Path (Join-Path (Get-OutputFolderV63) ("openpgp_quantum_guard_decrypted_text_{0}.txt" -f $stamp))
                $savePath = (Read-OqgPrompt "Output path [$defaultOut]").Trim('"')
                if ([string]::IsNullOrWhiteSpace($savePath)) { $savePath = $defaultOut }
                [System.IO.File]::WriteAllText($savePath, $plain, [System.Text.UTF8Encoding]::new($false))
                Write-Host "Saved:" -ForegroundColor $script:UiWhiteSilver
                Write-Host "  $(Format-DisplayPath $savePath)" -ForegroundColor White
            }
        } else { Write-GpgFailure -Result $result -ActionName "Text decryption" }
    } finally { Remove-Item -LiteralPath $tmpIn -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue }
    Wait-User
}


# === END v63 REPAIR LAYER ===


# -----------------------------------------------------------------------------
# v67: external logo files, parser-safe config, cleaner boot menu
# -----------------------------------------------------------------------------
$script:ToolVersion = "v67"
$script:LeftMenuLogoLines = @()
$script:BootMenuLogoLines = @()
$script:BootMenuTitle = "OpenPGP Quantum Guard"
$script:BootMenuSubtitle = "PQC-enabled OpenPGP operations"
$script:BootWaitForEnter = $true
$script:BootLogoPath = ""
$script:LeftMenuLogoPath = ""

function Get-LogoFolderV67 {
    $folder = Join-Path (Get-ScriptDirectoryV63) "logos"
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = Join-Path (Get-Location).Path "logos" }
    return $folder
}

function Get-DefaultBootLogoPathV67 {
    return (Join-Path (Get-LogoFolderV67) "openpgp_quantum_guard_boot_logo.txt")
}

function Get-DefaultLeftLogoPathV67 {
    return (Join-Path (Get-LogoFolderV67) "openpgp_quantum_guard_left_logo.txt")
}

function Get-DefaultBootLogoTextV67 {
    # One maintained boot logo lives in Get-DefaultBootLogoTextV71.
    return (Get-DefaultBootLogoTextV71)
}

function Get-DefaultLeftLogoTextV67 {
@'
╭──────────────────────────────╮
│  OPENPGP QUANTUM GUARD       │
├──────────────────────────────┤
│  ML-KEM composite encryption │
│  GnuPG capability verified   │
╰──────────────────────────────╯
'@
}

function Convert-LogoTextToLinesV67 {
    param([AllowEmptyString()][string]$Text = "")
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @(([string]$Text) -split "`r?`n" | Where-Object { $null -ne $_ })
}

function Resolve-LogoPathV67 {
    param(
        [AllowEmptyString()][string]$Path,
        [Parameter(Mandatory=$true)][string]$DefaultPath
    )

    $candidate = [string]$Path
    if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $DefaultPath }
    try {
        if (-not [System.IO.Path]::IsPathRooted($candidate)) {
            $candidate = Join-Path (Get-ScriptDirectoryV63) $candidate
        }
    } catch { }
    return $candidate
}

function Ensure-LogoFileV67 {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$DefaultText,
        $LegacyLines = @()
    )

    $folder = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -LiteralPath $folder -PathType Container)) {
        [void](New-Item -Path $folder -ItemType Directory -Force)
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $legacy = @()
        foreach ($line in @($LegacyLines)) {
            if ($null -ne $line) { $legacy += [string]$line }
        }
        $text = if ($legacy.Count -gt 0) { ($legacy -join "`r`n") } else { [string]$DefaultText }
        $text | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Read-LogoFileLinesV67 {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$FallbackText
    )

    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
            $lines = @(Convert-LogoTextToLinesV67 -Text $raw)
            if ($lines.Count -gt 0) { return @($lines) }
        }
    } catch { }
    return @(Convert-LogoTextToLinesV67 -Text $FallbackText)
}

function Get-ConfigLegacyLogoLinesV67 {
    param($Config, [string]$Name)
    if ($null -eq $Config) { return @() }
    try {
        if ($Config.PSObject.Properties.Name -contains $Name) {
            $value = $Config.$Name
            if ($null -eq $value) { return @() }
            if ($value -is [string]) { return @(Convert-LogoTextToLinesV67 -Text ([string]$value)) }
            $out = @()
            foreach ($item in @($value)) {
                if ($null -ne $item) { $out += [string]$item }
            }
            return @($out)
        }
    } catch { }
    return @()
}

function New-DefaultConfigObjectV63 {
    $baseFolder = Join-Path (Get-ScriptDirectoryV63) "pgp"
    if ([string]::IsNullOrWhiteSpace($baseFolder)) { $baseFolder = Join-Path (Get-Location).Path "pgp" }
    $outFolder = Join-Path $baseFolder "output"

    return [ordered]@{
        Version = "v67"
        PgpFolder = $baseFolder
        OutputFolder = $outFolder
        GpgPath = ""
        GpgHome = ""
        DefaultIdentityFingerprint = ""
        ExpectedUidHint = ""
        OutputMode = "Shareable"
        PreferKyberHybridSubkeys = $true
        RequirePqcEncryption = $true
        DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448"
        DefaultKeyExpiry = "2y"
        AutoTrustGeneratedKeys = $true
        KeySelectableRequiresUltimateTrust = $false
        EnableLiveNmsMenu = $true
        EnableNoMoreSecretsEffect = $true
        BootMenuTitle = "OpenPGP Quantum Guard"
        BootMenuSubtitle = "PQC-enabled OpenPGP operations"
        BootWaitForEnter = $true
        BootLogoPath = (Get-DefaultBootLogoPathV67)
        LeftMenuLogoPath = (Get-DefaultLeftLogoPathV67)
        SecurityNote = "Do not store real OpenPGP private-key passphrases in this file. GnuPG pinentry should ask for them. Logos now live in external .txt files, not JSON arrays."
    }
}

function Apply-ConfigObjectV63 {
    param($Config)

    $script:DefaultStartFolder = [string](Get-ConfigPropertyV63 -Config $Config -Name "PgpFolder" -Default $script:DefaultStartFolder)
    $script:OutputFolder = [string](Get-ConfigPropertyV63 -Config $Config -Name "OutputFolder" -Default $script:OutputFolder)
    $script:GpgExecutable = [string](Get-ConfigPropertyV63 -Config $Config -Name "GpgPath" -Default $script:GpgExecutable)
    $script:GpgHome = [string](Get-ConfigPropertyV63 -Config $Config -Name "GpgHome" -Default $script:GpgHome)
    $script:OutputMode = [string](Get-ConfigPropertyV63 -Config $Config -Name "OutputMode" -Default $script:OutputMode)
    $script:PreferKyberHybridSubkeys = [bool](Get-ConfigPropertyV63 -Config $Config -Name "PreferKyberHybridSubkeys" -Default $script:PreferKyberHybridSubkeys)
    $script:RequirePqcEncryption = [bool](Get-ConfigPropertyV63 -Config $Config -Name "RequirePqcEncryption" -Default $true)
    $script:DefaultKeyProfile = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultKeyProfile" -Default "LOCAL_PQC_KYBER1024_X448")
    $script:DefaultKeyExpiry = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultKeyExpiry" -Default "2y")
    $script:AutoTrustGeneratedKeys = [bool](Get-ConfigPropertyV63 -Config $Config -Name "AutoTrustGeneratedKeys" -Default $true)
    $script:KeySelectableRequiresUltimateTrust = [bool](Get-ConfigPropertyV63 -Config $Config -Name "KeySelectableRequiresUltimateTrust" -Default $false)
    $script:EnableNoMoreSecretsEffect = [bool](Get-ConfigPropertyV63 -Config $Config -Name "EnableNoMoreSecretsEffect" -Default $script:EnableNoMoreSecretsEffect)
    $script:LiveNmsMenuEnabled = [bool](Get-ConfigPropertyV63 -Config $Config -Name "EnableLiveNmsMenu" -Default $true)
    $script:BootMenuTitle = [string](Get-ConfigPropertyV63 -Config $Config -Name "BootMenuTitle" -Default "OpenPGP Quantum Guard")
    $script:BootMenuSubtitle = [string](Get-ConfigPropertyV63 -Config $Config -Name "BootMenuSubtitle" -Default "PQC-enabled OpenPGP operations")
    $script:BootWaitForEnter = [bool](Get-ConfigPropertyV63 -Config $Config -Name "BootWaitForEnter" -Default $true)

    $script:BootLogoPath = Resolve-LogoPathV67 -Path ([string](Get-ConfigPropertyV63 -Config $Config -Name "BootLogoPath" -Default (Get-DefaultBootLogoPathV67))) -DefaultPath (Get-DefaultBootLogoPathV67)
    $script:LeftMenuLogoPath = Resolve-LogoPathV67 -Path ([string](Get-ConfigPropertyV63 -Config $Config -Name "LeftMenuLogoPath" -Default (Get-DefaultLeftLogoPathV67))) -DefaultPath (Get-DefaultLeftLogoPathV67)

    $legacyBoot = @(Get-ConfigLegacyLogoLinesV67 -Config $Config -Name "BootMenuLogoLines")
    $legacyLeft = @(Get-ConfigLegacyLogoLinesV67 -Config $Config -Name "LeftMenuLogoLines")
    Ensure-LogoFileV67 -Path $script:BootLogoPath -DefaultText (Get-DefaultBootLogoTextV67) -LegacyLines $legacyBoot
    Ensure-LogoFileV67 -Path $script:LeftMenuLogoPath -DefaultText (Get-DefaultLeftLogoTextV67) -LegacyLines $legacyLeft
    $script:BootMenuLogoLines = @(Read-LogoFileLinesV67 -Path $script:BootLogoPath -FallbackText (Get-DefaultBootLogoTextV67))
    $script:LeftMenuLogoLines = @(Read-LogoFileLinesV67 -Path $script:LeftMenuLogoPath -FallbackText (Get-DefaultLeftLogoTextV67))

    $cfgFpr = [string](Get-ConfigPropertyV63 -Config $Config -Name "DefaultIdentityFingerprint" -Default "")
    if ($cfgFpr -match '^<[^>]+>$') { $cfgFpr = "" }
    $script:IdentityFingerprint = Normalize-Fingerprint $cfgFpr
    $cfgUid = [string](Get-ConfigPropertyV63 -Config $Config -Name "ExpectedUidHint" -Default "")
    if ($cfgUid -match '^Example Researcher\s*<researcher@example\.invalid>$') { $cfgUid = "" }
    $script:ExpectedUidHint = $cfgUid

    if (-not [string]::IsNullOrWhiteSpace($script:GpgHome)) {
        Ensure-DirectoryV63 -Path $script:GpgHome -Label "GnuPG home"
        $env:GNUPGHOME = $script:GpgHome
    }
    Ensure-DirectoryV63 -Path $script:DefaultStartFolder -Label "PGP folder"
    if ([string]::IsNullOrWhiteSpace($script:OutputFolder)) { $script:OutputFolder = Join-Path $script:DefaultStartFolder "output" }
    Ensure-DirectoryV63 -Path $script:OutputFolder -Label "output folder"
}

function Save-Config {
    $cfg = [ordered]@{
        Version = "v67"
        PgpFolder = [string]$script:DefaultStartFolder
        OutputFolder = [string]$script:OutputFolder
        GpgPath = [string]$script:GpgExecutable
        GpgHome = [string]$script:GpgHome
        DefaultIdentityFingerprint = [string](Normalize-Fingerprint $script:IdentityFingerprint)
        ExpectedUidHint = [string]$script:ExpectedUidHint
        OutputMode = [string]$script:OutputMode
        PreferKyberHybridSubkeys = [bool]$script:PreferKyberHybridSubkeys
        RequirePqcEncryption = [bool]$script:RequirePqcEncryption
        DefaultKeyProfile = [string]$script:DefaultKeyProfile
        DefaultKeyExpiry = [string]$script:DefaultKeyExpiry
        AutoTrustGeneratedKeys = [bool]$script:AutoTrustGeneratedKeys
        KeySelectableRequiresUltimateTrust = [bool]$script:KeySelectableRequiresUltimateTrust
        EnableLiveNmsMenu = [bool]$script:LiveNmsMenuEnabled
        EnableNoMoreSecretsEffect = [bool]$script:EnableNoMoreSecretsEffect
        BootMenuTitle = [string]$script:BootMenuTitle
        BootMenuSubtitle = [string]$script:BootMenuSubtitle
        BootWaitForEnter = [bool]$script:BootWaitForEnter
        BootLogoPath = [string]$script:BootLogoPath
        LeftMenuLogoPath = [string]$script:LeftMenuLogoPath
        SecurityNote = "Do not store real OpenPGP private-key passphrases in this file. GnuPG pinentry should ask for them. Logos are external .txt files."
    }
    Write-ConfigFileV63 -Config $cfg
}

function Load-ConfigV51 {
    $script:ConfigPath = Get-ConfigPathV63
    $default = New-DefaultConfigObjectV63
    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        Write-ConfigFileV63 -Config $default
        Apply-ConfigObjectV63 -Config ([pscustomobject]$default)
        Save-Config
    } else {
        try {
            $raw = Get-Content -LiteralPath $script:ConfigPath -Raw -ErrorAction Stop
            $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($p in $default.Keys) {
                if ($cfg.PSObject.Properties.Name -notcontains $p) {
                    Add-Member -InputObject $cfg -MemberType NoteProperty -Name $p -Value $default[$p] -Force
                }
            }
            try {
                $cfgProfile = if ($cfg.PSObject.Properties.Name -contains "DefaultKeyProfile") { [string]$cfg.DefaultKeyProfile } else { "" }
                if ($cfgProfile -eq "LOCAL_PQC_KYBER768_X25519") { $cfg.DefaultKeyProfile = "LOCAL_PQC_KYBER1024_X448" }
                if ($cfg.PSObject.Properties.Name -contains "Version") { $cfg.Version = "v67" }
            } catch { }
            Apply-ConfigObjectV63 -Config $cfg
            Save-Config
        } catch {
            Write-Host "Config file could not be parsed. Using safe defaults for this session." -ForegroundColor $script:UiLightBlue
            Write-Host ("Config path: {0}" -f $script:ConfigPath) -ForegroundColor $script:UiDimSilver
            Write-Host $_.Exception.Message -ForegroundColor $script:UiDimSilver
            Apply-ConfigObjectV63 -Config ([pscustomobject]$default)
            Save-Config
        }
    }
    $script:GpgPath = Resolve-GpgPath
}

function Clip-AsciiLineV67 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Width = 80
    )
    $safe = if ($null -eq $Text) { "" } else { [string]$Text }
    $w = [Math]::Max(1, [int]$Width)
    if ($safe.Length -gt $w) { return $safe.Substring(0, $w) }
    return $safe
}


function Write-BootMenuBoxLineV67 {
    param(
        [AllowEmptyString()][string]$Label = "",
        [AllowEmptyString()][string]$Value = "",
        [int]$Width = 96,
        [int]$LabelWidth = 17,
        [switch]$Highlight
    )
    $inner = [Math]::Max(20, $Width - 6)
    $maxValue = [Math]::Max(8, $inner - $LabelWidth - 3)
    $labelText = (Fit-V57 -Text $Label -Width $LabelWidth)
    $valueText = (Fit-V57 -Text $Value -Width $maxValue)
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  │ " -Color $script:UiBorderBlue)
    $segments += @(New-GradientSegments -Text $labelText -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text " │ " -Color $script:UiLightBlue)
    if ($Highlight) { $segments += @(New-GradientSegments -Text $valueText -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold) }
    else { $segments += (New-ConsoleSegment -Text $valueText -Color $script:UiSilverBlue) }
    $plainUsed = $LabelWidth + 3 + $maxValue
    if ($plainUsed -lt $inner) { $segments += (New-ConsoleSegment -Text (" " * ($inner - $plainUsed)) -Color $script:UiDimSilver) }
    $segments += (New-ConsoleSegment -Text " │" -Color $script:UiBorderBlue)
    Write-MenuRichLine -Segments $segments
}


function Initialize-ActiveIdentityV44 {
    Load-ConfigV51
    Show-StartupBootScreenV51
    Write-Banner -Title "OpenPGP identity check"
    Write-V46GradientWrappedText -Text ("Config: {0}" -f (Format-DisplayPath $script:ConfigPath)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("PGP folder: {0}" -f (Format-DisplayPath $script:DefaultStartFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Output folder: {0}" -f (Format-DisplayPath $script:OutputFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Boot logo : {0}" -f (Split-Path -Leaf $script:BootLogoPath)) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("Menu logo : {0}" -f (Split-Path -Leaf $script:LeftMenuLogoPath)) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    $inventory = @(Get-KeyInventoryV44)
    if ($inventory.Count -eq 0) {
        Write-V46GradientWrappedText -Text "No OpenPGP keys were found in this GnuPG home." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        if (Read-YesNo "Generate a new OpenPGP key now?" $true) { Generate-PqcKeyWorkflow; $inventory = @(Get-KeyInventoryV44) }
    }
    $selectable = @($inventory | Where-Object { $_.Selectable })
    if ($selectable.Count -eq 0) {
        Write-V46GradientWrappedText -Text "No selectable key was found. A selectable key means a local private key is present. Ultimate trust is optional unless the config enables that strict rule." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        if (Read-YesNo "Generate a new key and use it as default?" $true) { Generate-PqcKeyWorkflow; $selectable = @(Get-SelectableKeysV44) }
    }
    if ($selectable.Count -eq 0) { return }
    $current = @($selectable | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq (Normalize-Fingerprint $script:IdentityFingerprint) })
    if ($current.Count -gt 0) { return }
    $chosen = Select-PublicPrimaryFingerprint -Title "Choose default OpenPGP identity"
    if (-not [string]::IsNullOrWhiteSpace($chosen)) {
        $script:IdentityFingerprint = Normalize-Fingerprint $chosen
        $chosenKey = @($selectable | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq $script:IdentityFingerprint })
        if ($chosenKey.Count -gt 0) { $script:ExpectedUidHint = [string]$chosenKey[0].PrimaryUid }
        Save-Config
    }
}


# -----------------------------------------------------------------------------
# v68: compact left logo, readable live NMS, responsive main menu proportions
# -----------------------------------------------------------------------------
$script:ToolVersion = "v68"
$script:V62NmsFrameDelayMs = 120
$script:LiveNmsMenuEnabled = $true
$script:LeftLogoUseCompactWhenOversized = $true

function Get-CompactLeftLogoTextV68 {
@'
╭────────────────────────────╮
│ OpenPGP Quantum Guard      │
│ Kyber 1024 X448 default    │
│ OpenPGP Quantum Guard      │
╰────────────────────────────╯
'@
}

function Get-VisibleWindowHeightV68 {
    try { return [Math]::Max(20, [Console]::WindowHeight) } catch { return 30 }
}

function Get-VisibleWindowWidthV68 {
    try { return [Math]::Max(80, [Console]::WindowWidth) } catch { return 120 }
}

function Convert-ToNmsSentenceV62 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Seed = 0,
        [double]$Reveal = 0.88,
        [switch]$Selected
    )

    if (-not [bool]$script:LiveNmsMenuEnabled) { return $Text }
    if ($null -eq $Text) { return "" }
    $source = [string]$Text
    if ($source.Length -le 0) { return $source }

    $glyphs = $script:V62NmsGlyphs.ToCharArray()
    if ($null -eq $glyphs -or $glyphs.Count -eq 0) { $glyphs = $script:NmsGlyphChars }
    if ($null -eq $glyphs -or $glyphs.Count -eq 0) { return $source }

    $frame = 0
    try { $frame = [int]$script:V62NmsFrame } catch { $frame = 0 }

    # v68: the NMS layer is live everywhere, but the menu must remain readable.
    # Keep most characters intact and move only a thin encrypted band across text.
    $baseReveal = [Math]::Max(0.88, [double]$Reveal)
    if ($Selected) { $baseReveal = [Math]::Max($baseReveal, 0.95) }
    if ($baseReveal -gt 0.98) { $baseReveal = 0.98 }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $source.Length; $i++) {
        $ch = $source[$i]
        $chText = [string]$ch
        if ([char]::IsWhiteSpace($ch) -or $chText -match '^[\.,:;!\?\(\)\[\]{}<>/\\|\-_=+''"]$') {
            [void]$sb.Append($ch)
            continue
        }

        $code = [int][char]$ch
        $band = [Math]::Abs(((($frame + $Seed + ($i * 2)) % 22) - 11))
        $bandBoost = if ($band -le 1) { -0.11 } elseif ($band -le 3) { -0.04 } else { 0.04 }
        $effectiveReveal = $baseReveal + $bandBoost
        if ($effectiveReveal -lt 0.82) { $effectiveReveal = 0.82 }
        if ($effectiveReveal -gt 0.98) { $effectiveReveal = 0.98 }

        $gate = ((($i * 37) + ($frame * 13) + ($Seed * 19) + $code) % 100) / 100.0
        if ($gate -lt $effectiveReveal) {
            [void]$sb.Append($ch)
        } else {
            $glyphIndex = (($i * 11) + ($frame * 7) + ($Seed * 5) + $code) % $glyphs.Length
            [void]$sb.Append($glyphs[$glyphIndex])
        }
    }
    return $sb.ToString()
}


# -----------------------------------------------------------------------------
# v69: restore the original ANSI / ASCII left-menu logo hook.
# External logo files stay supported, but they are no longer allowed to replace
# the built-in $script:CustomAnsiHeader unless the custom header is disabled.
# -----------------------------------------------------------------------------
$script:ToolVersion = "v69"

function Get-LeftMenuAnsiLogoLinesV69 {
    param([int]$Width = 60)

    $safeWidth = [Math]::Max(24, [int]$Width)
    if (-not (Test-CustomAnsiHeaderEnabled)) { return @() }

    $raw = @(([string]$script:CustomAnsiHeader) -split "`r?`n" | Where-Object {
        $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    if ($raw.Count -eq 0) { return @() }

    $windowHeight = Get-VisibleWindowHeightV68
    $maxRows = if ($windowHeight -ge 40) { 10 } elseif ($windowHeight -ge 34) { 8 } elseif ($windowHeight -ge 29) { 6 } else { 4 }

    $lines = @()
    foreach ($line in @($raw | Select-Object -First $maxRows)) {
        $safe = Clip-AsciiLineV67 -Text ([string]$line) -Width ([Math]::Max(10, $safeWidth - 2))
        $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text ("  " + $safe) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold))
    }
    $lines += New-V57TextLine "" $script:UiDimSilver
    return @($lines)
}

function New-LeftMenuLogoRenderLinesV65 {
    param([int]$Width = 60)

    # v69: User did not ask to remove the built-in ANSI/ASCII logo.
    # Prefer the original CustomAnsiHeader when enabled, and use external logo
    # files only as a fallback or when ShowCustomAnsiHeader is disabled.
    $ansi = @(Get-LeftMenuAnsiLogoLinesV69 -Width $Width)
    if ($ansi.Count -gt 0) { return @($ansi) }

    $safeWidth = [Math]::Max(24, [int]$Width)
    $raw = @($script:LeftMenuLogoLines | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($raw.Count -eq 0) { $raw = @(Convert-LogoTextToLinesV67 -Text (Get-CompactLeftLogoTextV68)) }

    $raw = @($raw | Where-Object { ([string]$_).Trim() -notmatch '^(?i)left\s+screen\s+logo$' })

    $maxRawLength = 0
    foreach ($line in @($raw)) { if (([string]$line).Length -gt $maxRawLength) { $maxRawLength = ([string]$line).Length } }

    $windowHeight = Get-VisibleWindowHeightV68
    $maxLogoRows = if ($windowHeight -ge 38) { 6 } elseif ($windowHeight -ge 30) { 5 } else { 4 }

    $tooWide = ($maxRawLength -gt ($safeWidth - 2))
    $tooTall = ($raw.Count -gt ($maxLogoRows + 2))
    if ([bool]$script:LeftLogoUseCompactWhenOversized -and ($tooWide -or $tooTall)) {
        $raw = @(Convert-LogoTextToLinesV67 -Text (Get-CompactLeftLogoTextV68))
    }

    $lines = @()
    foreach ($line in @($raw | Select-Object -First $maxLogoRows)) {
        $safe = Clip-AsciiLineV67 -Text ([string]$line) -Width ([Math]::Max(10, $safeWidth - 2))
        $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text ("  " + $safe) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold))
    }
    $lines += New-V57TextLine "" $script:UiDimSilver
    return @($lines)
}


# -----------------------------------------------------------------------------
# v70: Setup Doctor, config editor, GnuPG capability check, key recognition repair
# -----------------------------------------------------------------------------
$script:ToolVersion = "v70"

function Get-DoctorStateColorV70 {
    param([string]$State = "OK")
    switch ($State.ToUpperInvariant()) {
        "OK" { return $script:UiWhiteSilver }
        "WARN" { return $script:UiLightBlue }
        "FAIL" { return $script:UiLightBlue }
        default { return $script:UiDimSilver }
    }
}

function Write-DoctorLineV70 {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value,
        [string]$State = "OK",
        [AllowEmptyString()][string]$Note = ""
    )

    $stateText = ("[{0}]" -f $State.ToUpperInvariant()).PadRight(8)
    $segments = @()
    $segments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver)
    $segments += (New-ConsoleSegment -Text $stateText -Color (Get-DoctorStateColorV70 -State $State) -Bold)
    $segments += (New-ConsoleSegment -Text ($Label.PadRight(18)) -Color $script:UiSilverBlue -Bold)
    $segments += (New-ConsoleSegment -Text ": " -Color $script:UiDimSilver)
    $segments += @(New-GradientSegments -Text $Value -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold:($State.ToUpperInvariant() -eq "OK"))
    Write-MenuRichLine -Segments $segments
    if (-not [string]::IsNullOrWhiteSpace($Note)) {
        Write-V46GradientWrappedText -Text $Note -Indent "      " -Width 108 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    }
}

function Get-GpgVersionSummaryV70 {
    $r = Invoke-GpgCaptured -Arguments @("--version")
    if ($r.ExitCode -ne 0) {
        return [pscustomobject]@{ Ok=$false; FirstLine="GnuPG version check failed"; FullText=(@($r.Output) -join "`n"); PqcHint=$false }
    }
    $lines = @($r.Output | ForEach-Object { [string]$_ })
    $first = if ($lines.Count -gt 0) { [string]$lines[0] } else { "GnuPG version detected" }
    $full = $lines -join "`n"
    $pqc = ($full -match '(?i)(kyber|ky768|ky1024|mlkem|ml-kem|pqc)')
    return [pscustomobject]@{ Ok=$true; FirstLine=$first; FullText=$full; PqcHint=$pqc }
}

function Open-ConfigFileV70 {
    try {
        $script:ConfigPath = Get-ConfigPathV63
        if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) { Save-Config }
        Start-Process -FilePath "notepad.exe" -ArgumentList @($script:ConfigPath) | Out-Null
        Write-Host "Config opened in Notepad." -ForegroundColor $script:UiWhiteSilver
    } catch {
        Write-Host "Could not open Notepad automatically." -ForegroundColor $script:UiLightBlue
        Write-Host ("Config path: {0}" -f $script:ConfigPath) -ForegroundColor $script:UiWhiteSilver
        Write-Host $_.Exception.Message -ForegroundColor $script:UiDimSilver
    }
}

function Invoke-TrustDbRefreshV70 {
    Write-Host "Refreshing GnuPG trust database and key inventory..." -ForegroundColor $script:UiSilverBlue
    $args = @(Get-GpgBaseArgumentsV63) + @("--check-trustdb")
    $r = Invoke-GpgCaptured -Arguments $args
    if ($r.ExitCode -eq 0) {
        Write-Host "GnuPG trust database refresh completed." -ForegroundColor $script:UiWhiteSilver
    } else {
        Write-GpgFailure -Result $r -ActionName "Trust database refresh"
    }
}

function Show-KeyInventorySummaryV70 {
    $inventory = @(Get-KeyInventoryV44)
    $selectable = @($inventory | Where-Object { $_.Selectable })
    $secret = @($inventory | Where-Object { $_.HasSecret })
    $activeFp = Normalize-Fingerprint $script:IdentityFingerprint
    $active = @($inventory | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq $activeFp })

    Write-GradientLine -Text "  KEY INVENTORY" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-DoctorLineV70 -Label "Public keys" -Value ([string]$inventory.Count) -State $(if ($inventory.Count -gt 0) { "OK" } else { "WARN" }) -Note $(if ($inventory.Count -eq 0) { "No OpenPGP public keys were found in this GnuPG home." } else { "" })
    Write-DoctorLineV70 -Label "Secret keys" -Value ([string]$secret.Count) -State $(if ($secret.Count -gt 0) { "OK" } else { "WARN" }) -Note $(if ($secret.Count -eq 0) { "No local private keys were found. Generated or imported public keys alone cannot decrypt or sign." } else { "" })
    Write-DoctorLineV70 -Label "Selectable keys" -Value ([string]$selectable.Count) -State $(if ($selectable.Count -gt 0) { "OK" } else { "WARN" }) -Note "Selectable currently means local private key present, unless strict ultimate-trust mode is enabled in config."

    if ($active.Count -gt 0) {
        $k = $active[0]
        $state = if ($k.HasSecret) { "OK" } else { "WARN" }
        Write-DoctorLineV70 -Label "Active key" -Value (("{0}  {1}" -f (Short-Fpr $k.Fingerprint), $k.PrimaryUid)) -State $state -Note $(if (-not $k.HasSecret) { "The active key exists, but no local private key was detected for it." } else { "" })
        $sub = @(Get-KeyEncryptionSubkeysV51 -Fingerprint ([string]$k.Fingerprint))
        if ($sub.Count -gt 0) {
            $best = $sub[0]
            Write-DoctorLineV70 -Label "Best subkey" -Value (("{0}  {1}/10  {2}" -f $best.Algorithm, $best.Score, (Short-Fpr $best.Fingerprint))) -State $(if ([int]$best.Score -ge 9) { "OK" } else { "WARN" }) -Note $(if ([int]$best.Score -lt 9) { "Active identity does not expose a strong Kyber encryption profile according to this tool." } else { "" })
        } else {
            Write-DoctorLineV70 -Label "Encryption" -Value "no encryption subkey detected" -State "WARN" -Note "The key may be sign-only, or GnuPG did not expose encryption subkeys in the expected listing."
        }
    } else {
        Write-DoctorLineV70 -Label "Active key" -Value "not found in current inventory" -State "WARN" -Note "Choose an active key from the main menu, or clear DefaultIdentityFingerprint in the config and restart."
    }

    if ($inventory.Count -gt 0) {
        Write-Host ""
        Write-GradientLine -Text "  Visible keys" -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        $max = [Math]::Min(8, $inventory.Count)
        for ($i = 0; $i -lt $max; $i++) {
            $k = $inventory[$i]
            $flags = @()
            if ($k.HasSecret) { $flags += "secret" } else { $flags += "public-only" }
            if ($k.Selectable) { $flags += "selectable" }
            $line = "{0}. {1}  {2}/10  {3}  {4}" -f ($i + 1), (Short-Fpr $k.Fingerprint), ([int]$k.Strength), ($flags -join ","), ([string]$k.PrimaryUid)
            Write-V46GradientWrappedText -Text $line -Indent "    " -Width 108 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        }
    }
}

function Show-SetupDoctorV70 {
    while ($true) {
        Write-Banner -Title "Setup Doctor"
        Write-V46GradientWrappedText -Text "This page checks the config, folders, GnuPG path, GnuPG home, key recognition, active key state, and PQC capability hints. It is meant for moving the tool between machines." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        Write-Host ""

        $script:ConfigPath = Get-ConfigPathV63
        $configExists = Test-Path -LiteralPath $script:ConfigPath -PathType Leaf
        $pgpExists = Test-Path -LiteralPath $script:DefaultStartFolder -PathType Container
        $outExists = Test-Path -LiteralPath $script:OutputFolder -PathType Container
        $gpgHomeText = if ([string]::IsNullOrWhiteSpace([string]$script:GpgHome)) { "default GnuPG home" } else { [string]$script:GpgHome }
        $gpgVersion = Get-GpgVersionSummaryV70

        Write-GradientLine -Text "  CONFIG AND PATHS" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
        Write-DoctorLineV70 -Label "Config" -Value (Format-DisplayPath $script:ConfigPath) -State $(if ($configExists) { "OK" } else { "WARN" })
        Write-DoctorLineV70 -Label "PGP folder" -Value (Format-DisplayPath $script:DefaultStartFolder) -State $(if ($pgpExists) { "OK" } else { "WARN" })
        Write-DoctorLineV70 -Label "Output folder" -Value (Format-DisplayPath $script:OutputFolder) -State $(if ($outExists) { "OK" } else { "WARN" })
        Write-DoctorLineV70 -Label "GnuPG home" -Value $gpgHomeText -State "OK"
        Write-DoctorLineV70 -Label "GnuPG path" -Value (Format-DisplayPath $script:GpgPath) -State $(if ($gpgVersion.Ok) { "OK" } else { "FAIL" })
        Write-DoctorLineV70 -Label "GnuPG version" -Value $gpgVersion.FirstLine -State $(if ($gpgVersion.Ok) { "OK" } else { "FAIL" })
        Write-DoctorLineV70 -Label "PQC hint" -Value $(if ($gpgVersion.PqcHint) { "Kyber/PQC text appears in gpg --version" } else { "no Kyber text found in gpg --version" }) -State $(if ($gpgVersion.PqcHint) { "OK" } else { "WARN" }) -Note "If your interactive gpg menu shows option 16, ECC and Kyber, your build can still be PQC-capable even when --version is quiet."
        Write-DoctorLineV70 -Label "Default profile" -Value ([string]$script:DefaultKeyProfile) -State "OK" -Note "LOCAL_PQC_KYBER1024_X448 maps to GnuPG key type 16, Kyber option 4."
        Write-Host ""

        if (-not $pgpExists -or -not $outExists) {
            if (Read-YesNo "Create missing PGP/output folders now?" $true) {
                Ensure-DirectoryV63 -Path $script:DefaultStartFolder -Label "PGP folder"
                Ensure-DirectoryV63 -Path $script:OutputFolder -Label "output folder"
                Save-Config
                Write-Host "Folders checked and config saved." -ForegroundColor $script:UiWhiteSilver
            }
            Write-Host ""
        }

        if ([bool]$script:KeySelectableRequiresUltimateTrust) {
            Write-DoctorLineV70 -Label "Selection mode" -Value "strict ultimate trust is ON" -State "WARN" -Note "This can hide newly generated workplace keys until ownertrust is set."
            if (Read-YesNo "Disable strict ultimate-trust requirement so local private keys are selectable?" $true) {
                $script:KeySelectableRequiresUltimateTrust = $false
                Save-Config
                Write-Host "Config updated: KeySelectableRequiresUltimateTrust = false" -ForegroundColor $script:UiWhiteSilver
            }
            Write-Host ""
        } else {
            Write-DoctorLineV70 -Label "Selection mode" -Value "local private key is enough" -State "OK"
            Write-Host ""
        }

        Show-KeyInventorySummaryV70
        Write-Host ""
        Write-GradientLine -Text "  ACTIONS" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
        $items = @(
            (New-ConsoleMenuItem -Label "Open config" -Value "Config" -Hint "Open openpgp_quantum_guard.config.json in Notepad." -Color $script:UiWhiteSilver -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Refresh trustdb" -Value "Trust" -Hint "Run gpg --check-trustdb and rescan key inventory." -Color $script:UiSilverBlue -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Choose active key" -Value "Choose" -Hint "Pick a local private key recognized by this GnuPG home." -Color $script:UiWhiteSilver -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Generate key" -Value "Generate" -Hint "Run the key generation assistant again." -Color $script:UiSilverBlue -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Back" -Value "Back" -Hint "Return to main menu." -Color $script:UiDimSilver -Shortcut "b")
        )
        # OQG-RECOVERY-DOCTOR-PAUSE-V1
        Write-Host ''
        [void](Read-OqgPrompt '  Setup Doctor report complete. Press ENTER to open actions')
        Clear-Host
        $choice = Invoke-ConsoleMenu -Title "Setup Doctor Actions" -Items $items -Layout "Vertical" -Footer "Use arrows. ENTER opens. ESC returns."
        switch ($choice) {
            "Config" { Open-ConfigFileV70; Wait-User; continue }
            "Trust" { Invoke-TrustDbRefreshV70; Wait-User; continue }
            "Choose" { Cycle-ActiveIdentityV44; continue }
            "Generate" { Generate-PqcKeyWorkflow; continue }
            default { return }
        }
    }
}

function Get-CompactMainLeftLines {
    param([string]$ModeText, [string]$GpgState)
    try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 } catch { $script:V62NmsFrame = 1 }

    $windowWidth = Get-VisibleWindowWidthV68
    $windowHeight = Get-VisibleWindowHeightV68
    $w = if ($windowWidth -ge 150) { 62 } elseif ($windowWidth -ge 120) { 56 } else { 52 }
    $fpr = Short-Fpr $script:IdentityFingerprint
    $modeLine = ("Mode  : {0}   GnuPG: {1}" -f $ModeText, $GpgState)

    $lines = @()
    $lines += @(New-LeftMenuLogoRenderLinesV65 -Width $w)
    $lines += New-V57TextLine (New-V57BoxTop $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "OpenPGP Quantum Guard" -Seed 101 -Reveal 0.94 -Selected) -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "PQC-enabled OpenPGP operations" -Seed 102 -Reveal 0.93 -Selected) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57TextLine (New-V57BoxMid $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text ("FPR   : {0}" -f $fpr) -Seed 103 -Reveal 0.91) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text $modeLine -Seed 104 -Reveal 0.91) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Crypto: Kyber 1024 X448 default" -Seed 105 -Reveal 0.90) -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Flow  : Encrypt PQC. Decrypt auto-detect." -Seed 106 -Reveal 0.90) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Doctor: config, GnuPG, keys, folders" -Seed 107 -Reveal 0.89) -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-NmsSentenceGradientLineV62 -Text ("  Build {0}: setup doctor" -f $script:ToolVersion) -Seed 108 -Reveal 0.90 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  One maintained embedded logo; optional external art is configurable." -Color $script:UiDimSilver -Seed 109 -Reveal 0.88
    $lines += New-NmsSentenceLineV62 -Text "  Use Setup Doctor when moving the tool to another PC." -Color $script:UiDimSilver -Seed 110 -Reveal 0.88

    if ($windowHeight -ge 34) {
        $lines += New-V57TextLine "" $script:UiDimSilver
        $lines += New-NmsSentenceLineV62 -Text "  The truth is in the logs. The proof is in the keys." -Color $script:UiDimSilver -Seed 111 -Reveal 0.88
    }
    return @($lines)
}


function Main-Menu {
    while ($true) {
        $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
        $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
        $header = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
        $items = @(
            (New-ConsoleMenuItem -Label "Encrypt file" -Value "Encrypt" -Hint "Protect a file to the active OpenPGP identity." -Color $script:UiWhiteSilver -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Decrypt file" -Value "Decrypt" -Hint "Locate an encrypted file, then decrypt it with the matching private key." -Color $script:UiSilverBlue -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Encrypt text" -Value "EncryptText" -Hint "Paste plaintext and create ASCII-armored OpenPGP text." -Color $script:UiWhiteSilver -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Decrypt text" -Value "DecryptText" -Hint "Paste armored OpenPGP text and reveal plaintext." -Color $script:UiSilverBlue -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Inspect key status" -Value "Inspect" -Hint "View certificate, subkeys, details and export options." -Color $script:UiLightBlue -Shortcut "5"),
            (New-ConsoleMenuItem -Label "Choose active key" -Value "CycleKey" -Hint "Choose a local private key recognized by this GnuPG home." -Color $script:UiWhiteSilver -Shortcut "6"),
            (New-ConsoleMenuItem -Label "Generate new key" -Value "GenerateKey" -Hint "Create email-compatible, PQC, or manually mixed identities." -Color $script:UiSilverBlue -Shortcut "7"),
            (New-ConsoleMenuItem -Label "Export keys" -Value "Export" -Hint "Export public certificates or protected secret material." -Color $script:UiWhiteSilver -Shortcut "8"),
            (New-ConsoleMenuItem -Label "Setup doctor" -Value "Doctor" -Hint "Check config, folders, GnuPG, key inventory, and PQC hints." -Color $script:UiWhiteSilver -Shortcut "d"),
            (New-ConsoleMenuItem -Label "About" -Value "About" -Hint "Open operator notes, logo source order, scoring and security model." -Color $script:UiSilverBlue -Shortcut "9"),
            (New-ConsoleMenuItem -Label "Admin settings" -Value "Admin" -Hint "Safety-confirmed settings, output mode, identity administration and defaults." -Color $script:UiMidBlue -Shortcut "0"),
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Press Enter to close the tool cleanly." -Color $script:UiWhiteSilver)
        )
        $choice = Invoke-MainMenuRightPanel -HeaderLines $header -Items $items
        switch ($choice) {
            "Encrypt" { Encrypt-FileWorkflow }
            "Decrypt" { Decrypt-FileWorkflow }
            "EncryptText" { Encrypt-TextWorkflow }
            "DecryptText" { Decrypt-TextWorkflow }
            "Inspect" { Show-KeyStatus }
            "CycleKey" { Cycle-ActiveIdentityV44 }
            "GenerateKey" { Generate-PqcKeyWorkflow }
            "Export" { Show-KeyExportMenu }
            "Doctor" { Show-SetupDoctorV70 }
            "About" { Show-AboutSection }
            "Admin" { Show-AdminSettings }
            "Quit" { Show-Goodbye; return }
            "Back" { Write-QuitGuardNotice; continue }
            default { Write-QuitGuardNotice; continue }
        }
    }
}

# -----------------------------------------------------------------------------
# CURRENT INTERFACE AND ENTRY POINT
# Compact key selection, live display effects, About page, and the single
# maintained embedded boot logo. Definitions below are the active overrides.
# -----------------------------------------------------------------------------
$script:ToolVersion = "1.1.0-rc6"
$script:LiveNmsMenuEnabled = $true
$script:V62NmsFrameDelayMs = 52
$script:LeftLogoUseCompactWhenOversized = $false

function Get-DefaultBootLogoTextV71 {
@'
_______/\\\\\__________________________________________________/\\\\\\\\\\\\\_______/\\\\\\\\\\\\__/\\\\\\\\\\\\\___        
 _____/\\\///\\\_______________________________________________\/\\\/////////\\\___/\\\//////////__\/\\\/////////\\\_       
  ___/\\\/__\///\\\____/\\\\\\\\\_______________________________\/\\\_______\/\\\__/\\\_____________\/\\\_______\/\\\_      
   __/\\\______\//\\\__/\\\/////\\\_____/\\\\\\\\___/\\/\\\\\\___\/\\\\\\\\\\\\\/__\/\\\____/\\\\\\\_\/\\\\\\\\\\\\\/__     
    _\/\\\_______\/\\\_\/\\\\\\\\\\____/\\\/////\\\_\/\\\////\\\__\/\\\/////////____\/\\\___\/////\\\_\/\\\/////////____    
     _\//\\\______/\\\__\/\\\//////____/\\\\\\\\\\\__\/\\\__\//\\\_\/\\\_____________\/\\\_______\/\\\_\/\\\_____________   
      __\///\\\__/\\\____\/\\\_________\//\\///////___\/\\\___\/\\\_\/\\\_____________\/\\\_______\/\\\_\/\\\_____________  
       ____\///\\\\\/_____\/\\\__________\//\\\\\\\\\\_\/\\\___\/\\\_\/\\\_____________\//\\\\\\\\\\\\/__\/\\\_____________ 
________/\\\__\/////_______\///____________\//////////__\///____\///__\///_______________\////////////____\///______________
 _____/\\\\/\\\\_______________________________________________________________________________________________             
  ___/\\\//\////\\\_________________________________________________/\\\________________________________________            
   __/\\\______\//\\\__/\\\____/\\\__/\\\\\\\\\_____/\\/\\\\\\____/\\\\\\\\\\\__/\\\____/\\\____/\\\\\__/\\\\\___           
    _\//\\\______/\\\__\/\\\___\/\\\_\////////\\\___\/\\\////\\\__\////\\\////__\/\\\___\/\\\__/\\\///\\\\\///\\\_          
     __\///\\\\/\\\\/___\/\\\___\/\\\___/\\\\\\\\\\__\/\\\__\//\\\____\/\\\______\/\\\___\/\\\_\/\\\_\//\\\__\/\\\_         
      ____\////\\\//_____\/\\\___\/\\\__/\\\/////\\\__\/\\\___\/\\\____\/\\\_/\\__\/\\\___\/\\\_\/\\\__\/\\\__\/\\\_        
       _______\///\\\\\\__\//\\\\\\\\\__\//\\\\\\\\/\\_\/\\\___\/\\\____\//\\\\\___\//\\\\\\\\\__\/\\\__\/\\\__\/\\\_       
_____/\\\\\\\\\\\\//////____\/////////____\////////\//__\///____\///__/\\\\/////_____\/////////___\///___\///___\///__      
 ___/\\\//////////____________________________________________________\/\\\__                                               
  __/\\\_______________________________________________________________\/\\\__                                              
   _\/\\\____/\\\\\\\__/\\\____/\\\__/\\\\\\\\\_____/\\/\\\\\\\_________\/\\\__                                             
    _\/\\\___\/////\\\_\/\\\___\/\\\_\////////\\\___\/\\\/////\\\___/\\\\\\\\\__                                            
     _\/\\\_______\/\\\_\/\\\___\/\\\___/\\\\\\\\\\__\/\\\___\///___/\\\////\\\__                                           
      _\/\\\_______\/\\\_\/\\\___\/\\\__/\\\/////\\\__\/\\\_________\/\\\__\/\\\__                                          
       _\//\\\\\\\\\\\\/__\//\\\\\\\\\__\//\\\\\\\\/\\_\/\\\_________\//\\\\\\\/\\_                                         
        __\////////////_____\/////////____\////////\//__\///___________\///////\//__                                                                                                          
'@
}

function Get-BootLogoLinesV65 {
    # v71: use the requested embedded boot logo by default so an older external
    # boot logo file cannot silently keep showing stale art.
    return @(Convert-LogoTextToLinesV67 -Text (Get-DefaultBootLogoTextV71))
}

function Convert-ToNmsSentenceV62 {
    param(
        [AllowEmptyString()][string]$Text = "",
        [int]$Seed = 0,
        [double]$Reveal = 0.86,
        [switch]$Selected
    )

    if (-not [bool]$script:LiveNmsMenuEnabled) { return $Text }
    if ($null -eq $Text) { return "" }
    $source = [string]$Text
    if ($source.Length -le 0) { return $source }

    $glyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%&*+=?/'.ToCharArray()
    $frame = 0
    try { $frame = [int]$script:V62NmsFrame } catch { $frame = 0 }

    # v71: smoother NMS, a rolling encrypted band over otherwise readable text.
    # It keeps the same string length, so the menu does not jump.
    $baseReveal = [Math]::Max(0.80, [double]$Reveal)
    if ($Selected) { $baseReveal = [Math]::Max($baseReveal, 0.90) }
    if ($baseReveal -gt 0.97) { $baseReveal = 0.97 }

    $period = [Math]::Max(12, $source.Length + 8)
    $center = (($frame + $Seed) % $period) - 4
    $sb = New-Object System.Text.StringBuilder

    for ($i = 0; $i -lt $source.Length; $i++) {
        $ch = $source[$i]
        $chText = [string]$ch
        $eligible = ([char]::IsLetterOrDigit($ch) -or $chText -eq "_" -or $chText -eq "-" -or $chText -eq "/")
        if (-not $eligible) {
            [void]$sb.Append($ch)
            continue
        }

        $distance = [Math]::Abs($i - $center)
        $bandPenalty = 0.0
        if ($distance -le 1) { $bandPenalty = 0.28 }
        elseif ($distance -le 3) { $bandPenalty = 0.16 }
        elseif ($distance -le 5) { $bandPenalty = 0.06 }

        $sine = ([Math]::Sin((($i * 0.55) + ($frame * 0.32) + ($Seed * 0.05))) + 1.0) / 2.0
        $effectiveReveal = $baseReveal - ($bandPenalty * (0.65 + (0.35 * $sine)))
        if ($effectiveReveal -lt 0.54) { $effectiveReveal = 0.54 }
        if ($effectiveReveal -gt 0.98) { $effectiveReveal = 0.98 }

        $code = [int][char]$ch
        $gate = ((($i * 31) + ($frame * 11) + ($Seed * 13) + $code) % 100) / 100.0
        if ($gate -lt $effectiveReveal) {
            [void]$sb.Append($ch)
        } else {
            $glyphIndex = (($i * 9) + ($frame * 5) + ($Seed * 3) + $code) % $glyphs.Length
            [void]$sb.Append($glyphs[$glyphIndex])
        }
    }
    return $sb.ToString()
}

function New-MainMenuRightLines {
    param(
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0,
        [bool]$Pulse = $false,
        [int]$PanelWidth = 56,
        [bool]$ShowAllHints = $true
    )

    $arr = @($Items)
    $lines = @()
    $ruleLen = [Math]::Max(28, [Math]::Min([int]$PanelWidth, 54))
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text (Convert-ToNmsSentenceV62 -Text "Actions" -Seed 20 -Reveal 0.90 -Selected) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    $lines += (New-MenuRenderLine -Text ("─" * $ruleLen) -Color $script:UiBorderBlue)

    for ($i = 0; $i -lt $arr.Count; $i++) {
        $item = $arr[$i]
        $label = [string]$item.Label
        $hint = [string]$item.Hint
        $hintWidth = [Math]::Max(26, $PanelWidth - 8)
        $hintLines = @(Split-BoxTextLine -Text $hint -Width $hintWidth | Select-Object -First 1)
        $selected = ($i -eq $SelectedIndex)
        $seedBase = 100 + ($i * 17)

        if ($selected) {
            $labelText = "  ▶ {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.91 -Selected)
            $lines += (New-MenuRenderLine -Text $labelText -Color $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue)
            foreach ($h in $hintLines) {
                $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 3) -Reveal 0.88 -Selected
                $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiWhiteSilver -BackgroundColor $script:UiDeepBlue)
            }
        } else {
            $labelText = "    {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.82)
            $lines += (New-MenuRenderLine -Text $labelText -Color ([string]$item.Color))
            if ($ShowAllHints) {
                foreach ($h in $hintLines) {
                    $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 5) -Reveal 0.80
                    $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiDimSilver)
                }
            }
        }
    }
    $lines += (New-MenuRenderLine -Text ("─" * $ruleLen) -Color $script:UiBorderBlue)
    return @($lines)
}


function Write-V71CompactKeyRow {
    param([int]$LocalNumber, [Parameter(Mandatory=$true)]$Key)
    $uid = [string]$Key.PrimaryUid
    if ($uid.Length -gt 68) { $uid = $uid.Substring(0, 67) + "…" }
    $alg = Get-CompactAlgorithmProfileV47 -Key $Key
    if ($alg.Length -gt 28) { $alg = $alg.Substring(0, 27) + "…" }
    $created = if ([string]::IsNullOrWhiteSpace([string]$Key.Created)) { "unknown" } else { [string]$Key.Created }
    $segments = @()
    $segments += (New-ConsoleSegment -Text ("  {0}. " -f $LocalNumber) -Color $script:UiWhiteSilver -Bold)
    $segments += @(New-GradientSegments -Text (Short-Fpr $Key.Fingerprint) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text "  " -Color $script:UiDimSilver)
    $segments += @(New-StrengthBadgeInlineSegmentsV51 -Score ([int]$Key.Strength))
    $segments += (New-ConsoleSegment -Text ("  {0}  {1}" -f $created, $alg) -Color $script:UiSilverBlue)
    Write-MenuRichLine -Segments $segments
    Write-V46GradientWrappedText -Text $uid -Indent "      " -Width 96 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
}

function Select-PublicPrimaryFingerprint {
    param([string]$Title = "Choose Different Key")
    if ([string]::IsNullOrWhiteSpace($Title) -or $Title -match 'OpenPGP identity') { $Title = "Choose Different Key" }
    $inventory = @(Get-KeyInventoryV44)
    $keys = @($inventory | Where-Object { $_.Selectable } | Sort-Object @{Expression="Strength";Descending=$true}, Created)
    if ($keys.Count -eq 0) {
        Clear-Host
        Write-GradientLine -Text ("  {0}" -f $Title) -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd
        Write-V46GradientWrappedText -Text "No selectable key was found. Selectable means a local private key exists, unless strict trust mode is enabled in config." -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
        Write-V46GradientWrappedText -Text "Press G to generate a new key, or Q to cancel." -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
        $cmd = Read-KeyChooserCommandV47 -VisibleCount 0
        if ([string]$cmd.Action -eq "Generate") { Generate-PqcKeyWorkflow; return (Select-PublicPrimaryFingerprint -Title $Title) }
        return $null
    }
    $page = 0
    while ($true) {
        $height = Get-ConsoleSafeHeightV47
        $pageSize = [Math]::Max(3, [Math]::Floor(($height - 9) / 2))
        $pageSize = [Math]::Min(8, $pageSize)
        $pages = [Math]::Max(1, [int][Math]::Ceiling([double]$keys.Count / [double]$pageSize))
        if ($page -ge $pages) { $page = $pages - 1 }
        if ($page -lt 0) { $page = 0 }
        $hidden = [Math]::Max(0, $inventory.Count - $keys.Count)
        Clear-Host
        Write-GradientLine -Text ("  {0}" -f $Title) -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd
        Write-V46GradientWrappedText -Text ("Active: {0} | page {1}/{2} | hidden: {3}" -f (Short-Fpr $script:IdentityFingerprint), ($page + 1), $pages, $hidden) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
        Write-V46GradientWrappedText -Text "Compact view. Use D plus number for full details. Use G to generate a new key." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
        Write-Host ""
        $startIndex = $page * $pageSize
        $visible = @($keys | Select-Object -Skip $startIndex -First $pageSize)
        for ($i = 0; $i -lt $visible.Count; $i++) {
            Write-V71CompactKeyRow -LocalNumber ($i + 1) -Key $visible[$i]
        }
        Write-Host ""
        $rangeText = if ($visible.Count -le 1) { "Choose 1" } else { "Choose 1-{0}" -f $visible.Count }
        $detailsText = if ($visible.Count -le 1) { "D1 details" } else { "D1-D{0} details" -f $visible.Count }
        $footer = ("{0}, {1}, G generate, ENTER/Q cancel" -f $rangeText, $detailsText)
        if ($pages -gt 1) { $footer += ", arrows or N/P pages" }
        Write-V46GradientWrappedText -Text $footer -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
        $cmd = Read-KeyChooserCommandV47 -VisibleCount $visible.Count
        switch ([string]$cmd.Action) {
            "Cancel" { return $null }
            "Next"   { if ($page -lt ($pages - 1)) { $page++ }; continue }
            "Prev"   { if ($page -gt 0) { $page-- }; continue }
            "Generate" {
                Generate-PqcKeyWorkflow
                $inventory = @(Get-KeyInventoryV44)
                $keys = @($inventory | Where-Object { $_.Selectable } | Sort-Object @{Expression="Strength";Descending=$true}, Created)
                $page = 0
                if ($keys.Count -eq 0) { return $null }
                continue
            }
            "Details" {
                $n = [int]$cmd.Number
                if ($n -ge 1 -and $n -le $visible.Count) { Clear-Host; Show-KeyDetailsV46 -Key $visible[$n - 1] -Inventory $inventory; Wait-User }
                continue
            }
            "Choose" {
                $n = [int]$cmd.Number
                if ($n -ge 1 -and $n -le $visible.Count) { return (Normalize-Fingerprint ([string]$visible[$n - 1].Fingerprint)) }
                continue
            }
            default { Start-Sleep -Milliseconds 150; continue }
        }
    }
}

function Cycle-ActiveIdentityV44 {
    $chosen = Select-PublicPrimaryFingerprint -Title "Choose Different Key"
    if ([string]::IsNullOrWhiteSpace($chosen)) { return }
    $keys = @(Get-SelectableKeysV44)
    $match = @($keys | Where-Object { (Normalize-Fingerprint $_.Fingerprint) -eq (Normalize-Fingerprint $chosen) })
    if ($match.Count -eq 0) { return }
    $k = $match[0]
    $script:IdentityFingerprint = Normalize-Fingerprint ([string]$k.Fingerprint)
    $script:ExpectedUidHint = [string]$k.PrimaryUid
    Save-Config
    Write-Banner -Title "Active key changed"
    Write-V46GradientWrappedText -Text ("Active: {0}  {1}" -f (Short-Fpr $script:IdentityFingerprint), $script:ExpectedUidHint) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-StrengthLine -Prefix "Strength: " -Name $k.StrengthLabel -Score ([int]$k.Strength) -Suffix ""
    Wait-User
}

function Write-V71AboutBox {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Lines,
        [int]$Width = 112
    )
    $inner = [Math]::Max(40, $Width - 8)
    Write-GradientLine -Text ("  ╭─ {0} {1}" -f $Title, ("─" * [Math]::Max(8, $Width - $Title.Length - 9))) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    foreach ($line in @($Lines)) {
        Write-V46GradientWrappedText -Text $line -Indent "  │  " -Width $inner -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    }
    Write-Host ("  ╰" + ("─" * ($Width - 3)) + "╯") -ForegroundColor $script:UiBorderBlue
    Write-Host ""
}

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-V71AboutBox -Title "Project" -Lines @(
        "OpenPGP Quantum Guard is a Windows PowerShell operator console around GnuPG.",
        "It brings file encryption, text encryption, key inspection, export workflows, Setup Doctor, config paths, and visual safety modes into one practical tool."
    )
    Write-V71AboutBox -Title "PQC" -Lines @(
        "PQC means post-quantum cryptography: algorithms designed for the transition toward attackers with quantum-scale capabilities.",
        "This project highlights Kyber / ML-KEM hybrid OpenPGP profiles, including Kyber 1024 X448 as the current default profile.",
        "The tool still treats compatibility honestly: many email flows still need classic ed25519 plus cv25519 today."
    )
    Write-V71AboutBox -Title "Design goal" -Lines @(
        "This project is a practical cryptography lab, operator interface, and workflow helper.",
        "Its goal is to make strong OpenPGP operations readable, repeatable, and safer for humans without hiding what GnuPG is doing."
    )
    Write-V71AboutBox -Title "Security model" -Lines @(
        "The script does not store private-key passphrases. GnuPG pinentry unlocks private keys only when a crypto operation needs them.",
        "Config files define folders, output paths, GnuPG home, logo files, active fingerprint, and defaults. They must never store real passphrases.",
        "Setup Doctor exists for workplace handoff: check paths, key recognition, GnuPG capability, trust mode, and active key state before blaming the key."
    )
    Write-V71AboutBox -Title "Interface" -Lines @(
        "Live NMS is visual theater across the main menu. It does not change encryption, signing, key choice, or GnuPG behavior.",
        "One maintained boot logo is embedded. Optional external artwork is loaded only from paths explicitly set in the configuration file."
    )
    Wait-User
}

function Main-Menu {
    Initialize-OqgRainV22BeforeMenu
    while ($true) {
        $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
        $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
        $header = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
        $items = @(
            (New-ConsoleMenuItem -Label "Encrypt file" -Value "Encrypt" -Hint "Protect a file to the active OpenPGP identity." -Color $script:UiWhiteSilver -Shortcut "1"),
            (New-ConsoleMenuItem -Label "Decrypt file" -Value "Decrypt" -Hint "Locate an encrypted file, then decrypt it with the matching private key." -Color $script:UiSilverBlue -Shortcut "2"),
            (New-ConsoleMenuItem -Label "Encrypt text" -Value "EncryptText" -Hint "Paste plaintext and create ASCII-armored OpenPGP text." -Color $script:UiWhiteSilver -Shortcut "3"),
            (New-ConsoleMenuItem -Label "Decrypt text" -Value "DecryptText" -Hint "Paste armored OpenPGP text and reveal plaintext." -Color $script:UiSilverBlue -Shortcut "4"),
            (New-ConsoleMenuItem -Label "Inspect key status" -Value "Inspect" -Hint "View certificate, subkeys, details and export options." -Color $script:UiLightBlue -Shortcut "5"),
            (New-ConsoleMenuItem -Label "Choose Different Key" -Value "CycleKey" -Hint "Switch to another local private key recognized by this GnuPG home." -Color $script:UiWhiteSilver -Shortcut "6"),
            (New-ConsoleMenuItem -Label "Generate new key" -Value "GenerateKey" -Hint "Create email-compatible, PQC, or manually mixed identities." -Color $script:UiSilverBlue -Shortcut "7"),
            (New-ConsoleMenuItem -Label "Export keys" -Value "Export" -Hint "Export public certificates or protected secret material." -Color $script:UiWhiteSilver -Shortcut "8"),
            (New-ConsoleMenuItem -Label "Setup doctor" -Value "Doctor" -Hint "Check config, folders, GnuPG, key inventory, and PQC hints." -Color $script:UiWhiteSilver -Shortcut "d"),
            (New-ConsoleMenuItem -Label "About" -Value "About" -Hint "Project scope, PQC notes, interface behavior, and security model." -Color $script:UiSilverBlue -Shortcut "9"),
            (New-ConsoleMenuItem -Label "Admin settings" -Value "Admin" -Hint "Safety-confirmed settings, output mode, identity administration and defaults." -Color $script:UiMidBlue -Shortcut "0"),
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Press Enter to close the tool cleanly." -Color $script:UiWhiteSilver)
        )
        $choice = Invoke-MainMenuRightPanel -HeaderLines $header -Items $items
        switch ($choice) {
            "Encrypt" { Encrypt-FileWorkflow }
            "Decrypt" { Decrypt-FileWorkflow }
            "EncryptText" { Encrypt-TextWorkflow }
            "DecryptText" { Decrypt-TextWorkflow }
            "Inspect" { Show-KeyStatus }
            "CycleKey" { Cycle-ActiveIdentityV44 }
            "GenerateKey" { Generate-PqcKeyWorkflow }
            "Export" { Show-KeyExportMenu }
            "Doctor" { Show-SetupDoctorV70 }
            "About" { Show-AboutSection }
            "Admin" { Show-AdminSettings }
            "Quit" { Show-Goodbye; return }
            "Back" { Write-QuitGuardNotice; continue }
            default { Write-QuitGuardNotice; continue }
        }
    }
}


# OQG-RECOVERY-HOLD-V1
function Wait-OqgIdentityReview {
    param([ValidateRange(1,60)][int]$Seconds=10)
    Write-Host ''
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch {}
    do {
        $secondsLeft=[Math]::Ceiling(($deadline-[DateTime]::UtcNow).TotalSeconds)
        if ($secondsLeft -le 0) { break }
        Write-Host ("`r  Identity ready. Press ANY KEY to continue. Auto in {0,2}s  " -f $secondsLeft) -NoNewline -ForegroundColor Cyan
        try {
            if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); break }
        } catch {}
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    Write-Host ''
}

# OQG-RICH-WIDE-V6
# Fullscreen menu renderer, animated shell, and shared prompts.
$script:OqgMenuTitle = ''

function Write-OqgWideLine {
    param(
        [string]$Text = '',
        [int]$X,
        [int]$Y,
        [int]$Width,
        [string]$Color = 'Gray',
        [string]$BackgroundColor = ''
    )
    if ($Width -lt 1) { return }
    $line = New-MenuRenderLine -Text $Text -Color $Color -BackgroundColor $BackgroundColor
    Write-MenuRenderLineAt -Line $line -X $X -Y $Y -Width $Width
}

function Write-OqgRichGradient {
    param([string]$Text = '', [int]$X, [int]$Y, [int]$Width,
          [string]$Background = '', [switch]$Bold)
    $segments = @(New-GradientSegments -Text $Text -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -BackgroundColor $Background -Bold:$Bold)
    Write-MenuRenderLineAt -Line (New-ConsoleRichLine -Segments $segments) -X $X -Y $Y -Width $Width
}


# v5: visual indicators are illustrative UI only, not measured cryptographic strength.
function Write-OqgGradientMeter {
    param([int]$X,[int]$Y,[int]$Width,[string]$Label,[int]$Filled,[int]$Cells=14)
    $segments = @()
    $segments += (New-ConsoleSegment -Text ('  ' + $Label.PadRight(11) + ': [') -Color $script:UiSilverBlue)
    for ($i=0; $i -lt $Cells; $i++) {
        if ($i -lt $Filled) {
            $ratio = if ($Cells -le 1) { 0.0 } else { $i / [double]($Cells - 1) }
            # Indigo -> electric blue -> ice-white, aligned with existing QG palette.
            if ($ratio -lt 0.5) {
                $t = $ratio * 2.0
                $r=[int](34 + 34*$t); $g=[int](83 + 133*$t); $b=[int](186 + 69*$t)
            } else {
                $t = ($ratio - 0.5) * 2.0
                $r=[int](68 + 160*$t); $g=[int](216 + 22*$t); $b=[int](255 - 6*$t)
            }
            $segments += (New-ConsoleSegment -Text '█' -Color ('Rgb:{0},{1},{2}' -f $r,$g,$b) -Bold)
        } else {
            $segments += (New-ConsoleSegment -Text '░' -Color 'Rgb:35,48,68')
        }
    }
    $segments += (New-ConsoleSegment -Text ']' -Color $script:UiSilverBlue)
    Write-MenuRenderLineAt -Line (New-ConsoleRichLine -Segments $segments) -X $X -Y $Y -Width $Width
}

function Write-OqgAnimatedChrome {
    param([int]$LeftWidth,[int]$ActionX,[int]$ActionWidth,[int]$DashX,[int]$DashWidth,
          [int]$FooterY,[string]$Selection,[int]$BodyTop,[int]$NmsY,[int]$NmsRows)
    # Advance the ORIGINAL v71 NMS engine. v4 never advanced the frame here.
    try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 }
    catch { $script:V62NmsFrame = 1 }
    Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text 'OPENPGP QUANTUM GUARD' -Reveal 0.93 -Seed 7)) -X 0 -Y 1 -Width $LeftWidth -Bold
    $screenTitle = if ([string]::IsNullOrWhiteSpace([string]$script:OqgMenuTitle)) { 'ACTION CENTER / INTERACTIVE CONSOLE' } else { ([string]$script:OqgMenuTitle).ToUpperInvariant() }
    Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text $screenTitle -Reveal 0.92 -Seed 13)) -X $ActionX -Y 1 -Width $ActionWidth -Bold
    Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text 'DASHBOARD / TELEMETRY / NMS' -Reveal 0.91 -Seed 19)) -X $DashX -Y 1 -Width $DashWidth -Bold
    Write-OqgRichNmsTicker -X $ActionX -Y $FooterY -Width ($DashX + $DashWidth - $ActionX) -Selection $Selection
    if ($NmsRows -gt 0) {
        Write-OqgPanel -X $DashX -Y $NmsY -Width $DashWidth -Lines (Get-OqgNmsPanelLines -Selection $Selection) -MaxRows $NmsRows -BodyColor $script:UiLightBlue
    }
}

function Get-OqgSafeNmsText {
    param([string]$Text,[double]$Reveal=0.90,[int]$Seed=17)
    if (-not [bool]$script:LiveNmsMenuEnabled) { return $Text }
    try {
        return (Convert-ToNmsSentenceV62 -Text $Text -Seed $Seed -Reveal $Reveal)
    } catch {
        return $Text
    }
}

function Get-OqgBarText {
    param([int]$Value = 7,[int]$Max = 10,[int]$Width = 14)
    if ($Max -lt 1) { $Max = 1 }
    $fill = [int][Math]::Round(($Value / [double]$Max) * $Width)
    if ($fill -lt 0) { $fill = 0 }
    if ($fill -gt $Width) { $fill = $Width }
    return ('[' + ('█' * $fill) + ('░' * ($Width - $fill)) + ']')
}

function Get-OqgMenuCategory {
    param([string]$Label)
    switch -Regex ($Label) {
        'Encrypt file|Decrypt file' { return 'FILE' }
        'Encrypt text|Decrypt text' { return 'TEXT' }
        'Inspect|Choose Different Key|Generate new key|Export keys' { return 'KEY' }
        'Setup doctor|Admin settings' { return 'ADMIN' }
        'About' { return 'INFO' }
        'Quit' { return 'EXIT' }
        default { return 'TASK' }
    }
}

function Get-OqgActionDetailLines {
    param($Item,[int]$Width)
    $label = [string]$Item.Label
    $hint = [string]$Item.Hint
    $shortcut = [string]$Item.Shortcut
    $category = Get-OqgMenuCategory -Label $label
    $fpr = Short-Fpr $script:IdentityFingerprint
    $mode = if (Test-ShareableOutput) { 'Shareable' } else { 'Private' }
    $lines = @(
        '  SELECTED ACTION',
        '',
        ('  Name      : ' + $label),
        ('  Category  : ' + $category),
        ('  Shortcut  : ' + $(if ([string]::IsNullOrWhiteSpace($shortcut)) { 'none' } else { $shortcut.ToUpperInvariant() })),
        ('  Output    : ' + $mode),
        ('  Identity  : ' + $(if ([string]::IsNullOrWhiteSpace($fpr)) { 'not selected' } else { $fpr })),
        '',
        '  PURPOSE',
        ('  ' + $hint),
        '',
        '  NEXT STEP',
        '  Press ENTER to open the selected workflow.'
    )
    return $lines
}

function Get-OqgTelemetryLines {
    param([int]$WindowWidth,[int]$WindowHeight)
    # No repeated GnuPG calls during animation. Use Setup Doctor for real key counts.
    $publicCount = 'See Doctor'; $secretCount = 'See Doctor'
    $lines = @(
        '  TELEMETRY',
        '',
        ('  Session    : LIVE'),
        ('  PQC mode   : ' + $(if ([bool]$script:RequirePqcEncryption) { 'REQUIRED' } else { 'OPTIONAL' })),
        ('  Profile    : ' + [string]$script:DefaultKeyProfile),
        ('  Backend    : GnuPG'),
        ('  Public keys: ' + $publicCount),
        ('  Secret keys: ' + $secretCount),
        ('  Window     : {0}x{1}' -f $WindowWidth,$WindowHeight),
        ('  Build      : ' + [string]$script:ToolVersion),
        '',
        '  Visual indicators (illustrative)',
        '  No security score is inferred.'
    )
    return $lines
}

function Switch-OqgMenuNms {
    $enabled = -not [bool]$script:LiveNmsMenuEnabled
    $script:LiveNmsMenuEnabled = $enabled
    $script:EnableNoMoreSecretsEffect = $enabled
    $script:EnableDynamicNmsMenu = $enabled
    # A full repaint replaces the text. Resample its foreground before resuming rain.
    $script:OqgRainV22.Previous = @{}
    $script:OqgRainV22.ForegroundKey = ''
    $script:OqgRainV22.MaskKey = ''
    Save-Config
}

function Get-OqgNmsPanelLines {
    param([string]$Selection)
    $channel = @(
        '  NMS CHANNEL',
        '',
        ('  ' + (Get-OqgSafeNmsText -Text ('ACTIVE  ::  ' + $Selection) -Reveal 0.82 -Seed 11)),
        ('  ' + (Get-OqgSafeNmsText -Text 'PKT FLOW ::  OPENPGP / ML-KEM / KEYRING' -Reveal 0.77 -Seed 23)),
        ('  ' + (Get-OqgSafeNmsText -Text 'STATUS   ::  CHANNEL LIVE / OPERATOR READY' -Reveal 0.84 -Seed 31)),
        ('  ' + (Get-OqgSafeNmsText -Text 'NOTE     ::  MENUS READABLE / SHELL ANIMATED' -Reveal 0.78 -Seed 41)),
        ('  ' + (Get-OqgSafeNmsText -Text 'VERIFY   ::  RUN SETUP DOCTOR BEFORE LIVE USE' -Reveal 0.86 -Seed 53))
    )
    return $channel
}

function Write-OqgPanel {
    param([int]$X,[int]$Y,[int]$Width,[string[]]$Lines,[int]$MaxRows,[string]$BodyColor='Gray')
    if ($MaxRows -lt 1) { return }
    for ($i = 0; $i -lt $Lines.Count -and $i -lt $MaxRows; $i++) {
        $line = [string]$Lines[$i]
        $row = $Y + $i
        if ($line -match '^  (IDENTITY|CRYPTOGRAPHIC PROFILE|CONSOLE|SELECTED ACTION|PURPOSE|NEXT STEP|TELEMETRY|NMS CHANNEL)$') {
            Write-OqgRichGradient -Text $line -X $X -Y $row -Width $Width -Bold
        } else {
            Write-OqgWideLine -Text $line -X $X -Y $row -Width $Width -Color $BodyColor
        }
    }
}

function Write-OqgRichNmsTicker {
    param([int]$X,[int]$Y,[int]$Width,[string]$Selection)
    $msg = if ([bool]$script:LiveNmsMenuEnabled) {
        Get-OqgSafeNmsText -Text ('NMS :: ACTIVE CHANNEL | ' + $Selection + ' | OPENPGP QUANTUM GUARD') -Reveal 0.88 -Seed 61
    } else {
        'NMS :: OFF  |  PRESS N TO ENABLE'
    }
    Write-OqgWideLine -Text ('  ' + $msg) -X $X -Y $Y -Width $Width -Color $script:UiLightBlue
}

function Wait-User {
    param([string]$Prompt = 'Press ENTER to continue')
    $oldCursorVisible = $null
    $firstPaint = $true
    $lastSize = ''
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }
    try {
        while ($true) {
            $windowWidth = 80; $windowHeight = 25
            try { $windowWidth = [Console]::WindowWidth; $windowHeight = [Console]::WindowHeight } catch { }
            $usableWidth = [Math]::Max(20, $windowWidth - 1)
            $y = [Math]::Max(0, $windowHeight - 3)
            $rule = '─' * [Math]::Max(1,$usableWidth - 2)
            Write-OqgWideLine -Text ('├' + $rule + '┤') -X 0 -Y $y -Width $usableWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('  ' + $Prompt) -X 0 -Y ($y + 1) -Width $usableWidth -Color $script:UiWhiteSilver
            Write-OqgRichNmsTicker -X 0 -Y ($y + 2) -Width $usableWidth -Selection 'RETURN'
            try { [Console]::SetCursorPosition(0, [Math]::Min($windowHeight - 1, $y + 2)) } catch { }
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter' -or $key.Key -eq 'Escape' -or $key.Key -eq 'Spacebar') { return }
        }
    } finally {
        try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { }
    }
}

function Invoke-MainMenuRightPanel {
    param(
        [Parameter(Mandatory=$true)]$HeaderLines,
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0
    )
    $itemsArray = @($Items)
    if ($itemsArray.Count -eq 0) { return 'Back' }
    if ($SelectedIndex -lt 0 -or $SelectedIndex -ge $itemsArray.Count) { $SelectedIndex = 0 }
    # OQG-FIRSTPAINT-HOTFIX-V6
    # These are local to the main menu, not Wait-User.
    $firstPaint = $true
    $lastSize = ''
    $oqgPreviousIndex = -1
    $oqgPreviousPage = -1
    $oldCursorVisible = $null
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }
    try {
        while ($true) {
            $windowWidth = 80
            $windowHeight = 25
            try {
                $windowWidth = [Console]::WindowWidth
                $windowHeight = [Console]::WindowHeight
            } catch { }

            if ($windowWidth -lt 120 -or $windowHeight -lt 28) {
                return (Invoke-OqgLegacyConsoleMenu -Title 'Main menu' -HeaderLines $HeaderLines -Items $itemsArray -Layout 'Vertical' -SelectedIndex $SelectedIndex)
            }

            $usableWidth = $windowWidth - 1
            # OQG-DUAL-ANSI-V9: preserve full left logo proportions without stealing navigation width.
            $leftArtWidth = Get-OqgAnsiWidth -FileName 'openpgp_quantum_guard_left_logo.ansi.txt'
            $requestedLeft = if ($leftArtWidth -gt 0 -and $windowWidth -ge 165) { [Math]::Min(84, $leftArtWidth + 4) } else { 48 }
            $leftWidth = [int][Math]::Max(38, [Math]::Min($requestedLeft, [Math]::Floor($usableWidth * 0.38)))
            $dashWidth = [int][Math]::Max(38, [Math]::Min(48, [Math]::Floor($usableWidth * 0.28)))
            $gap = 2
            $actionX = $leftWidth + $gap
            $dashX = $usableWidth - $dashWidth
            $actionWidth = $dashX - $actionX - 1
            if ($actionWidth -lt 40) {
                $dashWidth = 36
                $dashX = $usableWidth - $dashWidth
                $actionWidth = $dashX - $actionX - 1
            }

            $headerY = 0
            $bodyTop = 3
            $footerTop = $windowHeight - 4
            $bodyHeight = $footerTop - $bodyTop - 1
            $ruleLeft = '─' * [Math]::Max(1, $leftWidth - 2)
            $ruleAction = '─' * [Math]::Max(1, $actionWidth - 2)
            $ruleDash = '─' * [Math]::Max(1, $dashWidth - 2)

            $step = 3
            $pageSize = [Math]::Max(1, [int][Math]::Floor(($bodyHeight - 4) / $step))
            $page = [int][Math]::Floor($SelectedIndex / $pageSize)
            $pages = [int][Math]::Ceiling($itemsArray.Count / [double]$pageSize)
            $pageStart = $page * $pageSize
            $pageEnd = [Math]::Min($itemsArray.Count, $pageStart + $pageSize)

            # Do not Clear-Host on every arrow/ESC. Paint only on first entry or resize.
            $sizeKey = '{0}x{1}' -f $windowWidth,$windowHeight
            $oqgNavOnly = (-not $firstPaint -and $lastSize -eq $sizeKey -and $oqgPreviousIndex -ge 0 -and $oqgPreviousPage -eq $page)
            if ($firstPaint -or $lastSize -ne $sizeKey) {
                Clear-Host
                $firstPaint = $false
                $lastSize = $sizeKey
            }
            if (-not $oqgNavOnly) {
            # Top chrome
            Write-OqgWideLine -Text ('┌' + $ruleLeft + '┐') -X 0 -Y 0 -Width $leftWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('┌' + $ruleAction + '┐') -X $actionX -Y 0 -Width $actionWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('┌' + $ruleDash + '┐') -X $dashX -Y 0 -Width $dashWidth -Color $script:UiBorderBlue
            Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text 'OPENPGP QUANTUM GUARD' -Reveal 0.96 -Seed 7)) -X 0 -Y 1 -Width $leftWidth -Bold
            Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text $(if ([string]::IsNullOrWhiteSpace([string]$script:OqgMenuTitle)) { 'ACTION CENTER / INTERACTIVE CONSOLE' } else { [string]$script:OqgMenuTitle }) -Reveal 0.96 -Seed 13)) -X $actionX -Y 1 -Width $actionWidth -Bold
            Write-OqgRichGradient -Text ('  ' + (Get-OqgSafeNmsText -Text 'DASHBOARD / TELEMETRY / NMS' -Reveal 0.96 -Seed 19)) -X $dashX -Y 1 -Width $dashWidth -Bold
            Write-OqgWideLine -Text ('├' + $ruleLeft + '┤') -X 0 -Y 2 -Width $leftWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('├' + $ruleAction + '┤') -X $actionX -Y 2 -Width $actionWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('├' + $ruleDash + '┤') -X $dashX -Y 2 -Width $dashWidth -Color $script:UiBorderBlue

            # Left logo: native SGR art, with safe compact fallback.
            $leftArt = @(Get-OqgAnsiRows -FileName 'openpgp_quantum_guard_left_logo.ansi.txt')
            $canShowLeftArt = ($leftArt.Count -ge 3 -and $leftArtWidth -le ($leftWidth - 4) -and $bodyHeight -ge ($leftArt.Count + 12))
            $logoCount = 0
            if ($canShowLeftArt) {
                $logoCount = $leftArt.Count
                for ($k = 0; $k -lt $logoCount; $k++) {
                    Write-OqgAnsiAt -Text ([string]$leftArt[$k]) -X 2 -Y ($bodyTop + $k) -MaxWidth ($leftWidth - 4)
                }
            } else {
                $logo = @(New-LeftMenuLogoRenderLinesV65 -Width ($leftWidth - 2))
                $maxLogo = if ($windowHeight -ge 40) { 10 } else { 6 }
                $logoCount = [Math]::Min($logo.Count, $maxLogo)
                for ($k = 0; $k -lt $logoCount; $k++) {
                    Write-MenuRenderLineAt -Line $logo[$k] -X 1 -Y ($bodyTop + $k) -Width ($leftWidth - 2)
                }
            }
            $fpr = Short-Fpr $script:IdentityFingerprint
            $modeLabel = if (Test-ShareableOutput) { 'Shareable' } else { 'Private' }
            $pqcLabel = if ([bool]$script:RequirePqcEncryption) { 'REQUIRED' } else { 'OPTIONAL' }
            $leftRows = @(
                '  IDENTITY / SESSION','',
                ('  Active key  : ' + $(if ([string]::IsNullOrWhiteSpace($fpr)) { 'NOT SELECTED' } else { $fpr })),
                ('  Output mode : ' + $modeLabel),
                ('  PQC policy  : ' + $pqcLabel),
                '',
                '  CRYPTOGRAPHIC PROFILE','',
                ('  Profile : ' + [string]$script:DefaultKeyProfile),
                '  Backend : GnuPG',
                '  Visual UI meters (illustrative)',
                '',,
                '',
                '  CONSOLE','',
                ('  TUI build : ' + [string]$script:ToolVersion),
                '  Controls  : Arrows / Enter',
                '  Shortcuts : Listed at center',
                '',
                $(if ($script:LiveNmsMenuEnabled) { '  Global NMS shell is live' } else { '  Global NMS shell is off' }),
                '  while selected actions remain',
                '  fully readable.'
            )
            Write-OqgPanel -X 0 -Y ($bodyTop + $logoCount + 1) -Width $leftWidth -Lines $leftRows -MaxRows ($bodyHeight - $logoCount - 1) -BodyColor $script:UiSilverBlue
            # Meters are UI decoration, not measured cryptographic readiness.
            $meterY = [Math]::Min($footerTop - 7, $bodyTop + $logoCount + $leftRows.Count + 2)
            if ($meterY -gt ($bodyTop + $logoCount + 5)) {
                Write-OqgGradientMeter -X 0 -Y $meterY -Width $leftWidth -Label 'Readiness*' -Filled 11
                Write-OqgGradientMeter -X 0 -Y ($meterY + 1) -Width $leftWidth -Label 'Signal*' -Filled 9
                Write-OqgWideLine -Text '  * Visual activity only' -X 0 -Y ($meterY + 2) -Width $leftWidth -Color $script:UiDimSilver
            }

            # Center actions
            $summaryTitle = $(if ($pages -gt 1) { '  {0} actions  /  page {1} of {2}' -f $itemsArray.Count, ($page + 1), $pages } else { '  {0} actions' -f $itemsArray.Count })
            Write-OqgRichGradient -Text (Get-OqgSafeNmsText -Text $summaryTitle -Reveal 0.95 -Seed 29) -X $actionX -Y $bodyTop -Width $actionWidth -Bold
            Write-OqgWideLine -Text ('  ·───·───· ' + ('─' * [Math]::Max(1, $actionWidth - 15))) -X $actionX -Y ($bodyTop + 1) -Width $actionWidth -Color $script:UiBorderBlue
            for ($i = $pageStart; $i -lt $pageEnd; $i++) {
                $item = $itemsArray[$i]
                $local = $i - $pageStart
                $y = $bodyTop + 2 + ($local * $step)
                if (($y + 1) -ge $footerTop) { break }
                $selected = ($i -eq $SelectedIndex)
                $prefix = if ($selected) { '  ▶ ' } else { '    ' }
                $hotkey = [string]$item.Shortcut
                $label = [string]$item.Label
                $hint = [string]$item.Hint
                $category = Get-OqgMenuCategory -Label $label
                $line = ('{0}· {1,-7} · {2}' -f $prefix, ('[' + $category + ']'), $label)
                if (-not [string]::IsNullOrWhiteSpace($hotkey)) { $line += ('  [{0}]' -f $hotkey.ToUpperInvariant()) }
                $foreground = if ($selected) { $script:UiWhiteSilver } else { $script:UiSilverBlue }
                $background = if ($selected) { $script:UiHighlightBlue } else { '' }
                if ($selected) {
                    Write-OqgWideLine -Text '' -X $actionX -Y $y -Width $actionWidth -Color $script:UiWhiteSilver -BackgroundColor $background
                    Write-OqgBloomSelectionV19 -Text $line -X $actionX -Y $y -Width $actionWidth -Background $background
                } else {
                    Write-OqgWideLine -Text $line -X $actionX -Y $y -Width $actionWidth -Color $foreground
                }
                Write-OqgWideLine -Text ('       ' + $hint) -X $actionX -Y ($y + 1) -Width $actionWidth -Color $(if ($selected) { $script:UiLightBlue } else { $script:UiDimSilver }) -BackgroundColor $background
            }

            # Right dashboard
            $selectedItem = $itemsArray[$SelectedIndex]
            $detailLines = Get-OqgActionDetailLines -Item $selectedItem -Width $dashWidth
            $telemetryLines = Get-OqgTelemetryLines -WindowWidth $windowWidth -WindowHeight $windowHeight
            $nmsLines = Get-OqgNmsPanelLines -Selection ([string]$selectedItem.Label)
            $dashSection1 = [Math]::Min([Math]::Max(11,[int]($bodyHeight * 0.34)), $bodyHeight - 10)
            $dashSection2 = [Math]::Min([Math]::Max(10,[int]($bodyHeight * 0.30)), $bodyHeight - $dashSection1 - 6)
            $dashSection3 = [Math]::Max(5, $bodyHeight - $dashSection1 - $dashSection2)
            Write-OqgPanel -X $dashX -Y $bodyTop -Width $dashWidth -Lines $detailLines -MaxRows $dashSection1 -BodyColor $script:UiWhiteSilver
            Write-OqgWideLine -Text ('  ' + ('─' * [Math]::Max(1, $dashWidth - 5))) -X $dashX -Y ($bodyTop + $dashSection1) -Width $dashWidth -Color $script:UiBorderBlue
            Write-OqgPanel -X $dashX -Y ($bodyTop + $dashSection1 + 1) -Width $dashWidth -Lines $telemetryLines -MaxRows $dashSection2 -BodyColor $script:UiSilverBlue
            $telemetryMeterY = $bodyTop + $dashSection1 + $dashSection2 - 3
            if ($telemetryMeterY -gt ($bodyTop + $dashSection1 + 5)) {
                Write-OqgGradientMeter -X $dashX -Y $telemetryMeterY -Width $dashWidth -Label 'Readiness*' -Filled 11
                Write-OqgGradientMeter -X $dashX -Y ($telemetryMeterY + 1) -Width $dashWidth -Label 'Signal*' -Filled 9
            }
            Write-OqgWideLine -Text ('  ' + ('─' * [Math]::Max(1, $dashWidth - 5))) -X $dashX -Y ($bodyTop + $dashSection1 + $dashSection2 + 1) -Width $dashWidth -Color $script:UiBorderBlue
            Write-OqgPanel -X $dashX -Y ($bodyTop + $dashSection1 + $dashSection2 + 2) -Width $dashWidth -Lines $nmsLines -MaxRows ($dashSection3 - 1) -BodyColor $script:UiLightBlue

            # Footer chrome
            Write-OqgWideLine -Text ('├' + $ruleLeft + '┤') -X 0 -Y $footerTop -Width $leftWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('├' + $ruleAction + '┤') -X $actionX -Y $footerTop -Width $actionWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('├' + $ruleDash + '┤') -X $dashX -Y $footerTop -Width $dashWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text '  ESC Stay  |  N Live NMS' -X 0 -Y ($footerTop + 1) -Width $leftWidth -Color $script:UiDimSilver
            Write-OqgWideLine -Text '  ↑ ↓ Navigate   PgUp/PgDn Page   ENTER Open   N Toggle NMS   B Toggle Rain' -X $actionX -Y ($footerTop + 1) -Width $actionWidth -Color $script:UiSilverBlue
            Write-OqgWideLine -Text ('  Active :: ' + (Get-OqgMenuCategory -Label ([string]$selectedItem.Label))) -X $dashX -Y ($footerTop + 1) -Width $dashWidth -Color $script:UiSilverBlue
            Write-OqgRichGradient -Text ('  CURRENT  ' + [string]$selectedItem.Label) -X 0 -Y ($footerTop + 2) -Width $leftWidth -Bold
            Write-OqgRichNmsTicker -X $actionX -Y ($footerTop + 2) -Width ($dashX + $dashWidth - $actionX) -Selection ([string]$selectedItem.Label)
            Write-OqgWideLine -Text ('└' + $ruleLeft + '┘') -X 0 -Y ($windowHeight - 1) -Width $leftWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('└' + $ruleAction + '┘') -X $actionX -Y ($windowHeight - 1) -Width $actionWidth -Color $script:UiBorderBlue
            Write-OqgWideLine -Text ('└' + $ruleDash + '┘') -X $dashX -Y ($windowHeight - 1) -Width $dashWidth -Color $script:UiBorderBlue
            try { [Console]::SetCursorPosition(0, $windowHeight - 1) } catch { }

            $script:OqgRainMenuRepaintV24 = $false
            } else {
                # V28: Navigation is a two-row update, not a full redraw.
                # Keep the rain state and all nonchanging dashboard/UI cells intact.
                foreach ($index in @($oqgPreviousIndex, $SelectedIndex)) {
                    if ($index -lt $pageStart -or $index -ge $pageEnd) { continue }
                    $obj = $itemsArray[$index]
                    $y = $bodyTop + 2 + (($index - $pageStart) * $step)
                    if (($y + 1) -ge $footerTop) { continue }
                    $isSelected = ($index -eq $SelectedIndex)
                    $prefix = if ($isSelected) { '  ▶ ' } else { '    ' }
                    $label = [string]$obj.Label
                    $hint = [string]$obj.Hint
                    $category = Get-OqgMenuCategory -Label $label
                    $line = ('{0}· {1,-7} · {2}' -f $prefix, ('[' + $category + ']'), $label)
                    $hotkey = [string]$obj.Shortcut
                    if (-not [string]::IsNullOrWhiteSpace($hotkey)) { $line += ('  [{0}]' -f $hotkey.ToUpperInvariant()) }
                    if ($isSelected) {
                        Write-OqgWideLine -Text '' -X $actionX -Y $y -Width $actionWidth -Color $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue
                        Write-OqgBloomSelectionV19 -Text $line -X $actionX -Y $y -Width $actionWidth -Background $script:UiHighlightBlue
                    } else {
                        Write-OqgWideLine -Text $line -X $actionX -Y $y -Width $actionWidth -Color $script:UiSilverBlue
                    }
                    Write-OqgWideLine -Text ('       ' + $hint) -X $actionX -Y ($y + 1) -Width $actionWidth -Color $(if ($isSelected) { $script:UiLightBlue } else { $script:UiDimSilver }) -BackgroundColor $(if ($isSelected) { $script:UiHighlightBlue } else { '' })
                }
                $selectedItem = $itemsArray[$SelectedIndex]
                $detailLines = Get-OqgActionDetailLines -Item $selectedItem -Width $dashWidth
                $nmsLines = Get-OqgNmsPanelLines -Selection ([string]$selectedItem.Label)
                Write-OqgPanel -X $dashX -Y $bodyTop -Width $dashWidth -Lines $detailLines -MaxRows $dashSection1 -BodyColor $script:UiWhiteSilver
                Write-OqgPanel -X $dashX -Y ($bodyTop + $dashSection1 + $dashSection2 + 2) -Width $dashWidth -Lines $nmsLines -MaxRows ($dashSection3 - 1) -BodyColor $script:UiLightBlue
                Write-OqgWideLine -Text ('  Active :: ' + (Get-OqgMenuCategory -Label ([string]$selectedItem.Label))) -X $dashX -Y ($footerTop + 1) -Width $dashWidth -Color $script:UiSilverBlue
                Write-OqgRichGradient -Text ('  CURRENT  ' + [string]$selectedItem.Label) -X 0 -Y ($footerTop + 2) -Width $leftWidth -Bold
                # Only the small areas overwritten by navigation need a rain refresh.
                # Mark their previous background cells as stale, preserving all
                # other rain glyphs and their unchanged falling-stream state.
                try {
                    $rainPrevious = $script:OqgRainV22.Previous
                    if ($null -ne $rainPrevious) {
                        foreach ($rainKey in @($rainPrevious.Keys)) {
                            $cell = $rainPrevious[$rainKey]
                            $rx = [int]$cell[0]; $ry = [int]$cell[1]
                            $prevY = $bodyTop + 2 + (($oqgPreviousIndex - $pageStart) * $step)
                            $newY = $bodyTop + 2 + (($SelectedIndex - $pageStart) * $step)
                            if ((($ry -ge $prevY -and $ry -le ($prevY+1)) -or
                                 ($ry -ge $newY -and $ry -le ($newY+1))) -and
                                $rx -ge $actionX -and $rx -lt ($actionX+$actionWidth)) {
                                [void]$rainPrevious.Remove($rainKey)
                            } elseif ($rx -ge $dashX -and $rx -lt ($dashX+$dashWidth) -and
                                      (($ry -ge $bodyTop -and $ry -lt ($bodyTop+$dashSection1)) -or
                                       ($ry -ge ($bodyTop+$dashSection1+$dashSection2+2) -and $ry -lt ($bodyTop+$dashSection1+$dashSection2+2+$dashSection3)))) {
                                [void]$rainPrevious.Remove($rainKey)
                            }
                        }
                    }
                } catch { }
            }
            $script:OqgRainMenuRepaintV24 = $false
            $key = $null
            try {
                while ($null -eq $key) {
                    # OQG-RAIN-AMBIENT-V12: global continuous state, RGB gradient and protected UI areas.
# The same falling streams cross panel boundaries, but UI text is never overwritten.
$actionLastY = $bodyTop + 2 + (($pageEnd - $pageStart - 1) * $step) + 1
$selectedMenuY = $bodyTop + 2 + (($SelectedIndex - $pageStart) * $step)
$leftSafeBottom = [Math]::Max(($bodyTop + $logoCount + $leftRows.Count + 2),($meterY + 4))
$longestAction = 30
foreach ($rainItem in $itemsArray) {
    $candidateLength = [Math]::Max(([string]$rainItem.Hint).Length + 11,([string]$rainItem.Label).Length + 24)
    if ($candidateLength -gt $longestAction) { $longestAction = $candidateLength }
}
Invoke-OqgAmbientRainV22 -LeftWidth $leftWidth -LeftContentBottom $leftSafeBottom -LogoBottom ($bodyTop + $logoCount + 1) -ActionX $actionX -ActionWidth $actionWidth -ActionEnd $actionLastY -ActionTextWidth $longestAction -SelectedRow $selectedMenuY -DashX $dashX -DashWidth $dashWidth -DashDetailEnd ($bodyTop + $dashSection1) -DashTelemetryStart ($bodyTop + $dashSection1 + 1) -DashTelemetryEnd ($bodyTop + $dashSection1 + $dashSection2 + 1) -DashNmsStart ($bodyTop + $dashSection1 + $dashSection2 + 2) -DashNmsEnd ($bodyTop + $dashSection1 + $dashSection2 + 2 + $nmsLines.Count) -BodyTop $bodyTop -FooterTop $footerTop -PageStart $pageStart -PageEnd $pageEnd -RowStep $step -LeftMeterY $meterY -DashMeterY $telemetryMeterY
                    # v35: one coherent NMS pass AFTER ambient rain, every ~120 ms.
                    # Ink-only glyph runs keep rain visible between the letters.
                    if ([bool]$script:LiveNmsMenuEnabled -and (($script:V34MenuTick % 3) -eq 0)) {
                        Write-OqgAnimatedChrome -LeftWidth $leftWidth -ActionX $actionX -ActionWidth $actionWidth -DashX $dashX -DashWidth $dashWidth -FooterY ($footerTop + 2) -Selection ([string]$selectedItem.Label) -BodyTop $bodyTop -NmsY ($bodyTop + $dashSection1 + $dashSection2 + 2) -NmsRows ($dashSection3 - 1)
                        Write-OqgV35MenuForeground -LeftWidth $leftWidth -LeftTop ($bodyTop + $logoCount + 1) -LeftRows $leftRows -ActionX $actionX -ActionWidth $actionWidth -BodyTop $bodyTop -PageStart $pageStart -PageEnd $pageEnd -SelectedIndex $SelectedIndex -Step $step -Items $itemsArray -DashX $dashX -DashWidth $dashWidth -DashDetailY $bodyTop -DetailLines $detailLines -DashTelemetryY ($bodyTop + $dashSection1 + 1) -TelemetryLines $telemetryLines -DashNmsY ($bodyTop + $dashSection1 + $dashSection2 + 2) -NmsLines $nmsLines -FooterTop $footerTop
                    }
                    # NMS shares the existing single menu animation path.
                    # It never runs on the identity countdown or a second
                    # competing chrome renderer.
                    $script:V34MenuTick = [int]$script:V34MenuTick + 1
                    $deadline = [DateTime]::UtcNow.AddMilliseconds($(if ([bool]$script:OqgCodeRainEnabled) { 40 } elseif ([bool]$script:LiveNmsMenuEnabled) { 95 } else { 500 }))
                    while ([DateTime]::UtcNow -lt $deadline) {
                        if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true); break }
                        Start-Sleep -Milliseconds 12
                    }
                }
            } catch {
                return (Invoke-OqgLegacyConsoleMenu -Title 'Main menu' -HeaderLines $HeaderLines -Items $itemsArray -Layout 'Vertical' -SelectedIndex $SelectedIndex)
            }
            if (Test-BlockedControlQuitKey -KeyInfo $key) { continue }
            $oqgPreviousIndex = $SelectedIndex
            $oqgPreviousPage = $page
            switch ($key.Key) {
                'UpArrow'    { $SelectedIndex = ($SelectedIndex - 1 + $itemsArray.Count) % $itemsArray.Count }
                'LeftArrow'  { $SelectedIndex = ($SelectedIndex - 1 + $itemsArray.Count) % $itemsArray.Count }
                'DownArrow'  { $SelectedIndex = ($SelectedIndex + 1) % $itemsArray.Count }
                'RightArrow' { $SelectedIndex = ($SelectedIndex + 1) % $itemsArray.Count }
                'PageUp'     { $SelectedIndex = [Math]::Max(0, $SelectedIndex - $pageSize) }
                'PageDown'   { $SelectedIndex = [Math]::Min($itemsArray.Count - 1, $SelectedIndex + $pageSize) }
                'Home'       { $SelectedIndex = 0 }
                'End'        { $SelectedIndex = $itemsArray.Count - 1 }
                'Enter'      { return [string]$itemsArray[$SelectedIndex].Value }
                'Escape'     { if (-not [string]::IsNullOrWhiteSpace([string]$script:OqgMenuTitle)) { return 'Back' }; continue }
                default {
                    $ch = [string]$key.KeyChar
                    if ($ch -eq 'q' -and -not [string]::IsNullOrWhiteSpace([string]$script:OqgMenuTitle)) { return 'Back' }
                    if ($ch -eq 'b' -or $ch -eq 'B') {
    $script:OqgCodeRainEnabled = -not [bool]$script:OqgCodeRainEnabled
    if (-not $script:OqgCodeRainEnabled) { Clear-OqgAmbientRainV22 }
    continue
}
                    if ($ch -eq 'n') {
                        Switch-OqgMenuNms
                        $firstPaint = $true
                        continue
                    }
                    if (-not [string]::IsNullOrWhiteSpace($ch)) {
                        foreach ($item in $itemsArray) {
                            if ($ch.ToLowerInvariant() -eq ([string]$item.Shortcut).ToLowerInvariant()) {
                                return [string]$item.Value
                            }
                        }
                    }
                }
            }
        }
    } finally {
        try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { }
    }
}


# v5: fullscreen shell for ordinary TUI menus, preserving their return-value contract.
function Invoke-ConsoleMenu {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)]$Items,
        $HeaderLines = @(),
        [string]$Footer = 'Use arrows. ENTER opens. ESC returns.',
        [ValidateSet('Vertical','Horizontal')][string]$Layout = 'Vertical',
        [int]$SelectedIndex = 0
    )
    $width=80; $height=25
    try { $width=[Console]::WindowWidth; $height=[Console]::WindowHeight } catch { }
    if ($width -lt 120 -or $height -lt 28) {
        return (Invoke-OqgLegacyConsoleMenu -Title $Title -Items $Items -HeaderLines $HeaderLines -Footer $Footer -Layout $Layout -SelectedIndex $SelectedIndex)
    }
    $old = $script:OqgMenuTitle
    try {
        $script:OqgMenuTitle = $Title
        return (Invoke-MainMenuRightPanel -HeaderLines $HeaderLines -Items $Items -SelectedIndex $SelectedIndex)
    } finally { $script:OqgMenuTitle = $old }
}


# Dedicated exit page: never write farewell in the previously drawn menu.
function Show-Goodbye {
    $w = 80; $h = 25
    try { $w=[Console]::WindowWidth; $h=[Console]::WindowHeight } catch { }
    $w = [Math]::Max(60,$w); $h = [Math]::Max(18,$h)
    Clear-Host
    $boxWidth = [Math]::Min(82,[Math]::Max(52,$w-12))
    $boxX = [int][Math]::Max(0,[Math]::Floor(($w-$boxWidth)/2))
    $top = [int][Math]::Max(2,[Math]::Floor($h/2)-6)
    $rule = '─' * [Math]::Max(1,$boxWidth-2)
    Write-OqgWideLine -Text ('╭' + $rule + '╮') -X $boxX -Y $top -Width $boxWidth -Color $script:UiBorderBlue
    Write-OqgRichGradient -Text '   OPENPGP QUANTUM GUARD  /  SESSION CLOSED' -X $boxX -Y ($top+2) -Width $boxWidth -Bold
    Write-OqgWideLine -Text ('  ' + ('·──·──·' * 5)) -X $boxX -Y ($top+4) -Width $boxWidth -Color $script:UiBorderBlue
    Write-OqgWideLine -Text '   Cryptographic operations have returned control to the operator.' -X $boxX -Y ($top+6) -Width $boxWidth -Color $script:UiSilverBlue
    Write-OqgWideLine -Text '   Keys remain managed by GnuPG. No secret material is displayed.' -X $boxX -Y ($top+7) -Width $boxWidth -Color $script:UiSilverBlue
    Write-OqgRichGradient -Text '   Press ENTER to close this session.' -X $boxX -Y ($top+9) -Width $boxWidth -Bold
    Write-OqgWideLine -Text ('╰' + $rule + '╯') -X $boxX -Y ($top+11) -Width $boxWidth -Color $script:UiBorderBlue
    Invoke-OqgTransitionRainV23 -Mode Exit -WaitForEnter
    Clear-Host
}

function Get-OqgSafeMainLogo {
    $file=Join-Path $PSScriptRoot 'openpgp_quantum_guard_main_logo.ansi.txt'
    if(-not (Test-Path -LiteralPath $file -PathType Leaf)){return @()}
    try{
        $content=[IO.File]::ReadAllText($file,(New-Object System.Text.UTF8Encoding($false,$true)))
        $rows=@($content -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
        if($rows.Count -lt 3 -or $rows.Count -gt 35){return @()}
        $esc=[string][char]27
        foreach($row in $rows){
            $visible=[regex]::Replace([string]$row,[regex]::Escape($esc)+'\[[0-9;]*m','')
            if($visible -match '[\x00-\x1f\x7f]' -or $visible.Length -gt 300){return @()}
        }
        return $rows
    }catch{return @()}
}
# OQG-DUAL-ANSI-V9: controlled SGR asset reader, never executes asset text.
function Get-OqgAnsiRows {
    param([Parameter(Mandatory=$true)][string]$FileName)
    $path=Join-Path $PSScriptRoot $FileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    try {
        $raw=[IO.File]::ReadAllText($path,(New-Object System.Text.UTF8Encoding($false,$true)))
        $rows=@($raw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($rows.Count -lt 3 -or $rows.Count -gt 35) { return @() }
        foreach ($row in $rows) {
            $plain=[regex]::Replace([string]$row,[regex]::Escape([string][char]27)+'\[[0-9;]*m','')
            if ($plain -match '[\x00-\x1f\x7f]' -or $plain.Length -gt 300) { return @() }
        }
        return $rows
    } catch { return @() }
}
function Get-OqgAnsiWidth {
    param([Parameter(Mandatory=$true)][string]$FileName)
    $width=0
    foreach ($row in @(Get-OqgAnsiRows -FileName $FileName)) {
        $w=([regex]::Replace([string]$row,[regex]::Escape([string][char]27)+'\[[0-9;]*m','')).Length
        if ($w -gt $width) { $width=$w }
    }
    return $width
}
function Write-OqgAnsiAt {
    param([string]$Text,[int]$X,[int]$Y,[int]$MaxWidth)
    $visible=([regex]::Replace($Text,[regex]::Escape([string][char]27)+'\[[0-9;]*m','')).Length
    if ($visible -gt $MaxWidth) { return }
    try {
        [Console]::SetCursorPosition($X,$Y)
        [Console]::Write($Text+[string][char]27+'[0m')
    } catch { }
}
# OQG-CODE-RAIN-V10
# Terminal adaptation of PassGenObfuscator2(2).html matrixRain/codeRain canvases.
# Decorative only. Does not read or record keyboard input, paths, plaintext, or cryptographic material.
$script:OqgCodeRainEnabled = $true
$script:OqgCodeRainTick = 0
$script:OqgCodeRainHeads = @()
$script:OqgCodeRainLastGeometry = ''

function Write-OqgCodeRain {
    param([int]$X,[int]$Y,[int]$Width,[int]$Height)
    if (-not [bool]$script:OqgCodeRainEnabled) { return }
    if ($Width -lt 30 -or $Height -lt 5) { return }
    # Clamp every draw to current console dimensions, leaving the final column unused.
    try {
        $consoleWidth = [Console]::WindowWidth
        $consoleHeight = [Console]::WindowHeight
        if ($X -lt 0 -or $Y -lt 0 -or ($X + $Width) -ge $consoleWidth -or ($Y + $Height) -ge $consoleHeight) { return }
    } catch { return }

    $script:OqgCodeRainTick = [int]$script:OqgCodeRainTick + 1
    # Animations can run at 10 Hz; this layer redraws at about 5 Hz.
    if (($script:OqgCodeRainTick % 2) -ne 0) { return }
    $columns = [Math]::Max(4,[int][Math]::Floor(($Width - 4) / 3))
    $geometry = '{0}/{1}/{2}/{3}' -f $X,$Y,$Width,$Height
    if ($script:OqgCodeRainLastGeometry -ne $geometry -or @($script:OqgCodeRainHeads).Count -ne $columns) {
        $script:OqgCodeRainHeads = @()
        for ($c=0; $c -lt $columns; $c++) { $script:OqgCodeRainHeads += (Get-Random -Minimum (-$Height) -Maximum $Height) }
        $script:OqgCodeRainLastGeometry = $geometry
    }

    $alphabet = '0123456789ABCDEF<>/[]{}#@$%*+=?' # code-cipher motif, no file data
    $screen = [object[]]::new($Height)
    for ($r=0; $r -lt $Height; $r++) {
        $screen[$r] = (' ' * $Width).ToCharArray()
    }
    $brightCells = @{}
    for ($c=0; $c -lt $columns; $c++) {
        $head = [int]$script:OqgCodeRainHeads[$c]
        $offset = 1 + ($c * 3)
        for ($t=0; $t -lt 6; $t++) {
            $r = $head - $t
            if ($r -ge 0 -and $r -lt $Height -and $offset -lt $Width) {
                if ((Get-Random -Minimum 0 -Maximum 100) -le (90 - ($t * 8))) {
                    $screen[$r][$offset] = $alphabet[(Get-Random -Minimum 0 -Maximum $alphabet.Length)]
                    if ($t -eq 0) { $brightCells[('{0}:{1}' -f $r,$offset)] = $true }
                }
            }
        }
        $head++
        if ($head -gt ($Height + (Get-Random -Minimum 0 -Maximum $Height))) { $head = (Get-Random -Minimum (-$Height) -Maximum 0) }
        $script:OqgCodeRainHeads[$c] = $head
    }
    # Draw each line once. Two overlaid color planes emulate the HTML's green/cyan canvas layers.
    for ($r=0; $r -lt $Height; $r++) {
        $color = if (($r % 3) -eq 0) { 'Rgb:25,95,109' } else { 'Rgb:19,75,96' }
        Write-OqgWideLine -Text ('  ' + (-join $screen[$r])) -X $X -Y ($Y + $r) -Width $Width -Color $color
    }
    # Draw a small number of moving bright heads. Avoid large numbers of cursor calls.
    $painted = 0
    for ($c=0; $c -lt $columns -and $painted -lt 24; $c++) {
        $head = [int]$script:OqgCodeRainHeads[$c] - 1
        if ($head -ge 0 -and $head -lt $Height) {
            $colX = $X + 2 + ($c * 3) + 1
            $ch = [string]$screen[$head][1 + $c * 3]
            if ($ch -ne ' ') {
                Write-OqgWideLine -Text $ch -X $colX -Y ($Y+$head) -Width 1 -Color $(if (($c % 2) -eq 0) { 'Rgb:48,185,171' } else { 'Rgb:65,195,236' })
                $painted++
            }
        }
    }
}

# OQG-CODE-RAIN-V11
# Terminal-native rain with separate state per panel and no clipping markers.
# A text terminal cannot display real transparent layers. This draws behind
# *blank* regions across all three menu columns without replacing UI text.
$script:OqgRainZonesV11 = @{}

function Write-OqgRainZoneV11 {
    param([string]$Key,[int]$X,[int]$Y,[int]$Width,[int]$Bottom)
    if ($Width -lt 5 -or $Bottom -lt $Y) { return }
    $w=0;$h=0
    try { $w=[Console]::WindowWidth; $h=[Console]::WindowHeight } catch { return }
    $X=[Math]::Max(0,$X)
    $Y=[Math]::Max(0,$Y)
    $maxX=[Math]::Min($X + $Width - 1,$w - 2)
    $bottomSafe=[Math]::Min($Bottom,$h - 2)
    if ($maxX -lt $X -or $bottomSafe -lt $Y) { return }
    $widthSafe=$maxX-$X+1
    $heightSafe=$bottomSafe-$Y+1
    $columns=[Math]::Max(1,[int][Math]::Floor($widthSafe/3))
    $geometry='{0}/{1}/{2}/{3}' -f $X,$Y,$widthSafe,$heightSafe
    if (-not $script:OqgRainZonesV11.ContainsKey($Key) -or $script:OqgRainZonesV11[$Key].Geometry -ne $geometry) {
        $heads=@()
        for($i=0;$i -lt $columns;$i++) { $heads += Get-Random -Minimum (-$heightSafe) -Maximum $heightSafe }
        $script:OqgRainZonesV11[$Key]=@{ Geometry=$geometry; Heads=$heads; Bounds=@($X,$Y,$widthSafe,$heightSafe) }
    }
    $zone=$script:OqgRainZonesV11[$Key]
    $symbols='0123456789ABCDEF#@%+=/[]{}'
    $oldFg=$null
    try {
        $oldFg=[Console]::ForegroundColor
        # Clear the prior frame inside only this known blank region.
        for($row=$Y;$row -le $bottomSafe;$row++) {
            [Console]::SetCursorPosition($X,$row)
            [Console]::Write((' ' * $widthSafe))
        }
        for($i=0;$i -lt $columns;$i++) {
            $head=[int]$zone.Heads[$i]
            $posX=$X+($i*3)
            for($tail=0;$tail -lt 9;$tail++) {
                $row=$Y+$head-$tail
                if($row -lt $Y -or $row -gt $bottomSafe) { continue }
                if ((Get-Random -Minimum 0 -Maximum 100) -lt (15 + $tail*3)) { continue }
                $symbol=$symbols[(Get-Random -Minimum 0 -Maximum $symbols.Length)]
                [Console]::ForegroundColor = if($tail -eq 0) { [ConsoleColor]::Cyan } elseif($tail -lt 3) { [ConsoleColor]::DarkCyan } else { [ConsoleColor]::DarkBlue }
                [Console]::SetCursorPosition($posX,$row)
                [Console]::Write([string]$symbol)
            }
            $head++
            if($head -gt ($heightSafe+9)) { $head = Get-Random -Minimum (-$heightSafe) -Maximum 1 }
            $zone.Heads[$i]=$head
        }
    } catch { }
    finally { try { if($null -ne $oldFg) { [Console]::ForegroundColor=$oldFg } } catch { } }
}

function Clear-OqgRainZoneV11 {
    param([string]$Key)
    if (-not $script:OqgRainZonesV11.ContainsKey($Key)) { return }
    $b=$script:OqgRainZonesV11[$Key].Bounds
    try {
        for($r=[int]$b[1];$r -lt ([int]$b[1]+[int]$b[3]);$r++) {
            [Console]::SetCursorPosition([int]$b[0],$r)
            [Console]::Write((' ' * [int]$b[2]))
        }
    } catch { }
}

# OQG-RAIN-AMBIENT-V12
# Ambient terminal compositor. Decorative glyphs only; no data or input is read.
# PowerShell 5.1 compatible. Direct console writes avoid UI text clipping/ellipses.
$script:OqgRainV12Rng = New-Object System.Random
$script:OqgRainV12 = @{ Signature = ''; Heads = @(); Velocity = @(); Trails = @(); Phase = @(); RowRuns = @(); Tick = 0 }

function New-OqgRainV12State {
    param([int]$Width,[int]$Height)
    # One global set of rain columns. Stream movement stays continuous across the three panels.
    $heads = New-Object 'System.Collections.ArrayList'
    $velocities = New-Object 'System.Collections.ArrayList'
    $trails = New-Object 'System.Collections.ArrayList'
    $phases = New-Object 'System.Collections.ArrayList'
    for ($x = 0; $x -lt $Width; $x += 2) {
        [void]$heads.Add($script:OqgRainV12Rng.Next(-$Height,($Height+1)))
        [void]$velocities.Add($script:OqgRainV12Rng.Next(80,150) / 100.0)
        [void]$trails.Add($script:OqgRainV12Rng.Next(8,23))
        [void]$phases.Add($script:OqgRainV12Rng.Next(0,65535))
    }
    $script:OqgRainV12 = @{
        Signature = ('{0}x{1}' -f $Width,$Height)
        Heads = $heads
        Velocity = $velocities
        Trails = $trails
        Phase = $phases
        RowRuns = @()
        Tick = 0
    }
}

function Get-OqgRainV12Ranges {
    param(
        [int]$Row,[int]$Top,[int]$Bottom,
        [int]$LeftWidth,[int]$LeftContentBottom,[int]$LogoBottom,
        [int]$ActionX,[int]$ActionWidth,[int]$ActionEnd,[int]$ActionTextWidth,[int]$SelectedRow,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailEnd,[int]$DashTelemetryStart,[int]$DashTelemetryEnd,
        [int]$DashNmsStart,[int]$DashNmsEnd
    )
    # Each range is inclusive [start,end], and is known not to contain user-interface text.
    # Static rows and selected-item highlight receive complete protection.
    $ranges = @()
    if ($Row -lt $Top -or $Row -ge $Bottom) { return $ranges }
    if ($Row -gt ($LeftContentBottom + 3)) {
        $ranges += ,@([int]1,[int]($LeftWidth - 3))
    } elseif ($Row -gt $LogoBottom -and $Row -lt ($LeftContentBottom - 4)) {
        # Narrow atmosphere along the outer edge of the left status rail.
        $ranges += ,@([int][Math]::Max(1,$LeftWidth - 8),[int]($LeftWidth - 3))
    }
    if ($Row -gt ($ActionEnd + 2)) {
        $ranges += ,@([int]($ActionX + 1),[int]($ActionX + $ActionWidth - 3))
    } elseif ($Row -ne $SelectedRow -and $Row -ne ($SelectedRow + 1)) {
        $safeStart = [int][Math]::Min(($ActionX + $ActionWidth - 4),($ActionX + $ActionTextWidth + 4))
        if ($safeStart -lt ($ActionX + $ActionWidth - 5)) {
            $ranges += ,@($safeStart,[int]($ActionX + $ActionWidth - 3))
        }
    }
    if ($Row -gt ($DashNmsEnd + 2)) {
        $ranges += ,@([int]($DashX + 1),[int]($DashX + $DashWidth - 3))
    } elseif ($Row -gt ($DashDetailEnd + 1) -and $Row -lt ($DashTelemetryStart - 1)) {
        $ranges += ,@([int]($DashX + 1),[int]($DashX + $DashWidth - 3))
    } elseif ($Row -gt ($DashTelemetryEnd + 1) -and $Row -lt ($DashNmsStart - 1)) {
        $ranges += ,@([int]($DashX + 1),[int]($DashX + $DashWidth - 3))
    } else {
        # Right-panel gutters only, never overwrite content or separators.
        $ranges += ,@([int]($DashX + $DashWidth - 5),[int]($DashX + $DashWidth - 3))
    }
    return $ranges
}

function Write-OqgRainV12Run {
    param([int]$X,[int]$Y,[int]$Width,[int]$CanvasWidth,[int]$CanvasHeight)
    if ($Width -le 0 -or $X -lt 0 -or $Y -lt 0 -or $Y -ge ($CanvasHeight - 1)) { return }
    $Width = [Math]::Min($Width, $CanvasWidth - $X - 2)
    if ($Width -le 0) { return }
    $state = $script:OqgRainV12
    $alphabet = '0123456789ABCDEF@{}[]/=+*%'
    $esc = [string][char]27
    $sb = New-Object System.Text.StringBuilder
    $lastColor = ''
    for ($offset=0; $offset -lt $Width; $offset++) {
        $px=$X+$offset
        $ci=[int][Math]::Floor($px / 2)
        $symbol=' '
        $color=''
        if (($px % 2) -eq 0 -and $ci -lt $state.Heads.Count) {
            $head = [int][Math]::Floor([double]$state.Heads[$ci])
            $distance = $head - $Y
            $trailLength = [int]$state.Trails[$ci]
            if ($distance -ge 0 -and $distance -lt $trailLength) {
                $chance = if ($distance -le 1) { 93 } elseif ($distance -lt 5) { 78 } else { 58 }
                if ($script:OqgRainV12Rng.Next(0,100) -lt $chance) {
                    $symbol = [string]$alphabet[$script:OqgRainV12Rng.Next(0,$alphabet.Length)]
                    $frac = 1.0 - ($distance / [double]$trailLength)
                    if ($distance -eq 0) { $r=132; $g=231; $b=255 }
                    elseif ($distance -le 2) { $r=35; $g=169; $b=214 }
                    else {
                        # Continuous midnight blue -> teal -> icy cyan tail gradient.
                        $r=[int](6 + 22*$frac)
                        $g=[int](26 + 116*$frac)
                        $b=[int](48 + 155*$frac)
                    }
                    $color=('{0};{1};{2}' -f $r,$g,$b)
                }
            } elseif ((($px + ($Y*3) + [int]$state.Tick) % 7) -eq 0 -and $script:OqgRainV12Rng.Next(0,1000) -lt 11) {
                $symbol = [string]$alphabet[$script:OqgRainV12Rng.Next(0,$alphabet.Length)]
                $color='8;31;48'
            }
        }
        if ($color -ne $lastColor) {
            if ($color -eq '') { [void]$sb.Append($esc+'[0m') }
            else { [void]$sb.Append($esc+'[38;2;'+$color+'m') }
            $lastColor=$color
        }
        [void]$sb.Append($symbol)
    }
    [void]$sb.Append($esc+'[0m')
    try {
        [Console]::SetCursorPosition($X,$Y)
        [Console]::Write($sb.ToString())
    } catch { }
}

function Invoke-OqgAmbientRainV12 {
    param(
        [int]$LeftWidth,[int]$LeftContentBottom,[int]$LogoBottom,
        [int]$ActionX,[int]$ActionWidth,[int]$ActionEnd,[int]$ActionTextWidth,[int]$SelectedRow,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailEnd,[int]$DashTelemetryStart,[int]$DashTelemetryEnd,
        [int]$DashNmsStart,[int]$DashNmsEnd,[int]$BodyTop,[int]$FooterTop
    )
    if (-not [bool]$script:OqgCodeRainEnabled) { return }
    $w=0;$h=0
    try { $w=[int][Console]::WindowWidth; $h=[int][Console]::WindowHeight } catch { return }
    if ($w -lt 100 -or $h -lt 27) { return }
    $sig='{0}x{1}' -f $w,$h
    if ($script:OqgRainV12.Signature -ne $sig) { New-OqgRainV12State -Width $w -Height $h }
    $st=$script:OqgRainV12
    $st.Tick=[int]$st.Tick+1
    # Movement is independent from panel positions; use the same stream across every zone.
    for($i=0;$i -lt $st.Heads.Count;$i++) {
        $st.Heads[$i]=[double]$st.Heads[$i] + [double]$st.Velocity[$i]
        if ([double]$st.Heads[$i] -gt ($h+[int]$st.Trails[$i])) {
            $st.Heads[$i]=$script:OqgRainV12Rng.Next(-$h,1)
            $st.Velocity[$i]=$script:OqgRainV12Rng.Next(70,145)/100.0
            $st.Trails[$i]=$script:OqgRainV12Rng.Next(9,23)
        }
    }
    $runs = New-Object 'System.Collections.ArrayList'
    $lo = [Math]::Max(3,$BodyTop)
    $hi = [Math]::Min(($h-3),($FooterTop-1))
    for($row=$lo;$row -le $hi;$row++) {
        $ranges = @(Get-OqgRainV12Ranges -Row $row -Top $BodyTop -Bottom $FooterTop -LeftWidth $LeftWidth -LeftContentBottom $LeftContentBottom -LogoBottom $LogoBottom -ActionX $ActionX -ActionWidth $ActionWidth -ActionEnd $ActionEnd -ActionTextWidth $ActionTextWidth -SelectedRow $SelectedRow -DashX $DashX -DashWidth $DashWidth -DashDetailEnd $DashDetailEnd -DashTelemetryStart $DashTelemetryStart -DashTelemetryEnd $DashTelemetryEnd -DashNmsStart $DashNmsStart -DashNmsEnd $DashNmsEnd)
        foreach($range in $ranges) {
            $x0=[int]$range[0];$x1=[int]$range[1]
            $x0=[Math]::Max(1,$x0);$x1=[Math]::Min(($w-3),$x1)
            if($x1 -lt $x0) {continue}
            Write-OqgRainV12Run -X $x0 -Y $row -Width ($x1-$x0+1) -CanvasWidth $w -CanvasHeight $h
            [void]$runs.Add(@($x0,$row,$x1-$x0+1))
        }
    }
    $st.RowRuns=$runs
}

function Clear-OqgAmbientRainV12 {
    if ($null -eq $script:OqgRainV12 -or $null -eq $script:OqgRainV12.RowRuns) { return }
    foreach($run in @($script:OqgRainV12.RowRuns)) {
        try {
            [Console]::SetCursorPosition([int]$run[0],[int]$run[1])
            [Console]::Write((' ' * [int]$run[2]))
        } catch { }
    }
    $script:OqgRainV12.RowRuns=@()
}

# OQG-RAIN-FAST-START-V22
# Single world-space rain field. No rectangular rain zones.
# NMS is paused while rain is active. Decorative only.
$script:OqgRainV22 = @{
    # Frame is committed as ONE ANSI write, not thousands of cursor writes.
    Pending = $null
    Geometry = ''
    Drops = @()
    Previous = @{}
    Rng = (New-Object System.Random)
    Clock = [System.Diagnostics.Stopwatch]::StartNew()
    LastSeconds = 0.0
    MaskKey = ''
    Mask = $null
    LastSelectedRow = -9999
    Foreground = $null
    ForegroundKey = ''
    SnapshotMethod = 'pending'
}

# Read foreground text from the console after the UI has painted it.
# These are the actual occupied cells, not guessed panel widths. Optional:
# if the host does not expose a Win32 screen buffer, use the legacy mask.
function Get-OqgRainV22ForegroundMask {
    param([int]$Width,[int]$Height,[int]$BodyTop,[int]$FooterTop)
    if ($env:OS -ne 'Windows_NT') { return $null }
    try {
        if (-not ('OqgRainNativeV22' -as [type])) {
            Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class OqgRainNativeV22 {
    [StructLayout(LayoutKind.Sequential)]
    public struct Coord { public short X; public short Y; public Coord(short x, short y) { X=x; Y=y; } }
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, EntryPoint="ReadConsoleOutputCharacterW", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadChars(IntPtr console, StringBuilder buffer, int length, Coord coord, out int read);
}
'@ -ErrorAction Stop
        }
        $handle=[OqgRainNativeV22]::GetStdHandle(-11)
        if ($handle -eq [IntPtr]::Zero -or $handle -eq [IntPtr](-1)) { return $null }
        $mask=New-Object 'System.Boolean[]' ($Width*$Height)
        $winTop=0; $winLeft=0
        try { $winTop=[Console]::WindowTop; $winLeft=[Console]::WindowLeft } catch { }
        for ($y=$BodyTop; $y -lt $FooterTop; $y++) {
            $buffer=New-Object System.Text.StringBuilder ($Width+2)
            $count=0
            $pos=New-Object -TypeName OqgRainNativeV22+Coord -ArgumentList @([int16]$winLeft,[int16]($y+$winTop))
            if (-not [OqgRainNativeV22]::ReadChars($handle,$buffer,$Width,$pos,[ref]$count) -or $count -lt $Width) {
                return $null
            }
            $raw=$buffer.ToString()
            if ($raw.Length -lt $Width) { return $null }
            for ($x=2; $x -lt ($Width-2); $x++) {
                $char=$raw[$x]
                $mask[($y*$Width)+$x]=($char -eq ' ' -or $char -eq [char]0)
            }
        }
        return ,$mask
    } catch { return $null }
}

function Reset-OqgRainV22 {
    param([int]$Width,[int]$Height,[int]$BodyTop,[int]$FooterTop)
    $s = $script:OqgRainV22
    $rng = $s.Rng
    $drops = New-Object 'System.Collections.ArrayList'
    $span = [Math]::Max(1, $FooterTop-$BodyTop)
    for ($layer=0; $layer -lt 2; $layer++) {
        $step = if ($layer -eq 0) { 4 } else { 5 }
        $offset = if ($layer -eq 0) { 2 } else { 3 }
        for ($x=$offset; $x -lt ($Width-2); $x+=$step) {
            # Independent stream phases. No lane bands and no pre-clipped boxes.
            for ($lane=0; $lane -lt 2; $lane++) {
                $len = if ($layer -eq 0) { $rng.Next(13,24) } else { $rng.Next(9,20) }
                [void]$drops.Add(@{
                    X = [int]$x
                    Head = [double]($BodyTop + ($span*($lane + $rng.NextDouble())/2.0))
                    Rate = [double](13.0 + $rng.NextDouble()*7.0 + $layer)
                    Length = [int]$len
                    Seed = [int]$rng.Next(1,10000000)
                    Glyphs = $null
                    Layer = [int]$layer
                })
            }
        }
    }
    # Resolve the stream glyphs before painting the menu. The hot path can
    # index immutable per-stream characters instead of invoking a PS function
    # thousands of times during the first frame.
    foreach ($d in $drops) {
        $d.Glyphs = Get-OqgRainV22GlyphStrip -Seed ([int]$d.Seed) -Length ([int]$d.Length)
    }
    $s.Geometry = ('{0}x{1}:{2}:{3}' -f $Width,$Height,$BodyTop,$FooterTop)
    $s.Drops = $drops
    $s.Previous = @{}
    $s.Clock.Restart()
    $s.LastSeconds = 0.0
    $s.MaskKey = ''
    $s.Mask = $null
    $s.LastSelectedRow = -9999
    $s.Foreground = $null
    $s.ForegroundKey = ''
    $s.SnapshotMethod = 'pending'
}

function Test-OqgRainV22Allowed {
    param(
        [int]$X,[int]$Y,[int]$Width,[int]$BodyTop,[int]$FooterTop,
        [int]$LeftWidth,[int]$LeftContentBottom,[int]$LogoBottom,
        [int]$ActionX,[int]$ActionWidth,[int]$ActionEnd,[int]$ActionTextWidth,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailEnd,[int]$DashTelemetryStart,
        [int]$DashTelemetryEnd,[int]$DashNmsStart,[int]$DashNmsEnd,
        [int]$PageStart,[int]$PageEnd,[int]$RowStep,
        [int]$SelectedRow,[int]$LeftMeterY=-1,[int]$DashMeterY=-1
    )
    if ($Y -lt $BodyTop -or $Y -ge $FooterTop -or $X -le 1 -or $X -ge ($Width-2)) { return $false }
    # Strict occlusion: no rain in either row of the active blue selection.
    # The selected highlight is opaque from the first cell through the panel edge.
    if ($Y -ge $SelectedRow -and $Y -le ($SelectedRow + 1) -and
        $X -ge $ActionX -and $X -lt ($ActionX + $ActionWidth)) { return $false }
    # Meter protection covers only the painted bar, label and legend.
    # The free space to the right remains available for uninterrupted rain.
    if ($LeftMeterY -ge 0 -and $Y -ge $LeftMeterY -and $Y -le ($LeftMeterY + 2) -and
        $X -ge 0 -and $X -lt $(if ($Y -eq ($LeftMeterY + 2)) { 25 } else { 31 })) { return $false }
    if ($DashMeterY -ge 0 -and $Y -ge $DashMeterY -and $Y -le ($DashMeterY + 1) -and
        $X -ge $DashX -and $X -lt ($DashX + 31)) { return $false }
    # Protect vertical chrome / panel dividers, not entire pane rectangles.
    if ([Math]::Abs($X-$LeftWidth) -lt 2 -or [Math]::Abs($X-$ActionX) -lt 2 -or
        [Math]::Abs($X-$DashX) -lt 2) { return $false }
    if ($X -lt $LeftWidth) {
        if ($Y -le $LogoBottom) { return $false }
        # The left metadata spans roughly 20 rows. On its blank interlines,
        # rain can travel through the full width.
        $relative = $Y - ($LogoBottom+1)
        # Protect only the visible content length, not a 45-character black slab.
        # Lengths include the leading panel indent and a short safety margin.
        $occupiedWidths = @{
            0=23; 2=35; 3=29; 4=25; 6=30; 8=43; 9=23; 10=37;
            13=16; 15=25; 16=31; 17=36; 19=39; 20=37; 21=24
        }
        if ($occupiedWidths.ContainsKey($relative) -and
            $X -lt [Math]::Min($LeftWidth-3, [int]$occupiedWidths[$relative])) { return $false }
        if ($Y -le ($LeftContentBottom+2) -and $X -lt 8) { return $false }
        return $true
    }
    if ($X -gt $ActionX -and $X -lt ($ActionX+$ActionWidth-1)) {
        if ($Y -le ($BodyTop+1)) { return $false } # section count, horizontal rule
        if ($Y -le $ActionEnd) {
            $delta = $Y-($BodyTop+2)
            $r = $delta % [Math]::Max(1,$RowStep)
            # Only the actual label and its description rows need protection;
            # the gap rows still receive rain across their whole width.
            if (($r -eq 0 -or $r -eq 1) -and
                $X -lt ($ActionX+[Math]::Min($ActionWidth-3,$ActionTextWidth+12))) { return $false }
        }
        return $true
    }
    if ($X -gt $DashX -and $X -lt ($DashX+$DashWidth-1)) {
        if ($Y -eq $DashDetailEnd -or $Y -eq $DashTelemetryEnd -or
            $Y -eq ($DashNmsStart-1)) { return $false } # section dividers
        $xText = [Math]::Min($DashWidth-3,43)
        if ($X -gt ($DashX+$xText)) { return $true }
        if ($Y -ge $BodyTop -and $Y -lt $DashDetailEnd) {
            $r=$Y-$BodyTop
            if ($r -in @(0,2,3,4,5,6,8,9,11,12)) { return $false }
        }
        if ($Y -ge $DashTelemetryStart -and $Y -lt $DashTelemetryEnd) {
            $r=$Y-$DashTelemetryStart
            if ($r -in @(0,2,3,4,5,6,7,8,9,10,12,13,14,15,16)) { return $false }
        }
        if ($Y -ge $DashNmsStart -and $Y -le $DashNmsEnd) {
            $r=$Y-$DashNmsStart
            if ($r -in @(0,2,3,4,5,6)) { return $false }
        }
        return $true
    }
    return $false
}

function Update-OqgRainV22Mask {
    param(
        [int]$Width,[int]$Height,[int]$BodyTop,[int]$FooterTop,
        [int]$LeftWidth,[int]$LeftContentBottom,[int]$LogoBottom,
        [int]$ActionX,[int]$ActionWidth,[int]$ActionEnd,[int]$ActionTextWidth,[int]$SelectedRow,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailEnd,[int]$DashTelemetryStart,[int]$DashTelemetryEnd,
        [int]$DashNmsStart,[int]$DashNmsEnd,
        [int]$PageStart,[int]$PageEnd,[int]$RowStep,
        [int]$LeftMeterY,[int]$DashMeterY
    )
    $state=$script:OqgRainV22
    $scene=('{0}x{1}:{2}:{3}' -f $Width,$Height,$BodyTop,$FooterTop)
    if ($state.ForegroundKey -ne $scene) {
        $state.Foreground = Get-OqgRainV22ForegroundMask -Width $Width -Height $Height -BodyTop $BodyTop -FooterTop $FooterTop
        $state.ForegroundKey = $scene
        $state.SnapshotMethod = if ($null -eq $state.Foreground) { 'fallback mask' } else { 'screen buffer' }
    }
    $identity=('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}|{17}|{18}|{19}|{20}' -f
        $Width,$Height,$BodyTop,$FooterTop,$LeftWidth,$LeftContentBottom,$LogoBottom,$ActionX,$ActionWidth,
        $ActionEnd,$ActionTextWidth,$DashX,$DashWidth,$DashDetailEnd,$DashTelemetryStart,
        $DashTelemetryEnd,$DashNmsStart,$DashNmsEnd,$LeftMeterY,$DashMeterY,$RowStep)
    if ($identity -eq $state.MaskKey -and $null -ne $state.Mask) { return }
    $mask=New-Object 'System.Boolean[]' ($Width*$Height)
    $columnIndex=@{}
    foreach ($drop in $state.Drops) { $columnIndex[[int]$drop.X]=$true }
    $columns=@($columnIndex.Keys)
    for ($y=$BodyTop; $y -lt $FooterTop; $y++) {
        foreach ($column in $columns) {
            $x=[int]$column
            if ($null -ne $state.Foreground) {
                # Capture real UI text, including the exact length of meter labels,
                # menu descriptions, status lines, separators and ASCII artwork.
                $ok=[bool]$state.Foreground[($y*$Width)+$x]
                # Selection background is opaque even where its cells are spaces.
                if ($y -ge $SelectedRow -and $y -le ($SelectedRow+1) -and
                    $x -ge $ActionX -and $x -lt ($ActionX+$ActionWidth)) { $ok=$false }
                # Keep full bars opaque, but do not block the blank columns after them.
                if ($LeftMeterY -ge 0 -and $y -ge $LeftMeterY -and $y -le ($LeftMeterY+1) -and $x -lt 31) { $ok=$false }
                if ($DashMeterY -ge 0 -and $y -ge $DashMeterY -and $y -le ($DashMeterY+1) -and
                    $x -ge $DashX -and $x -lt ($DashX+31)) { $ok=$false }
                # Reserve the panel columns themselves.
                if ([Math]::Abs($x-$LeftWidth) -lt 2 -or [Math]::Abs($x-$ActionX) -lt 2 -or
                    [Math]::Abs($x-$DashX) -lt 2) { $ok=$false }
            } else {
                $ok=Test-OqgRainV22Allowed -X $x -Y $y -Width $Width -BodyTop $BodyTop -FooterTop $FooterTop `
                    -LeftWidth $LeftWidth -LeftContentBottom $LeftContentBottom -LogoBottom $LogoBottom `
                    -ActionX $ActionX -ActionWidth $ActionWidth -ActionEnd $ActionEnd -ActionTextWidth $ActionTextWidth `
                    -DashX $DashX -DashWidth $DashWidth -DashDetailEnd $DashDetailEnd `
                    -DashTelemetryStart $DashTelemetryStart -DashTelemetryEnd $DashTelemetryEnd `
                    -DashNmsStart $DashNmsStart -DashNmsEnd $DashNmsEnd -PageStart $PageStart -PageEnd $PageEnd `
                    -RowStep $RowStep -SelectedRow -9999 -LeftMeterY $LeftMeterY -DashMeterY $DashMeterY
            }
            $mask[($y*$Width)+$x]=$ok
        }
    }
    $state.Mask=$mask
    $state.MaskKey=$identity
    # Preserve the existing delta buffer during idle animation. Selection
    # changes are handled by the selected-row exclusion in the paint loop.
    $state.Previous=@{}
}

function Write-OqgRainV22Cell {
    param([int]$X,[int]$Y,[string]$Glyph,[string]$Color)
    # Compatible with Windows PowerShell 5.1 and Windows Terminal VT sequences.
    # Only rain-owned glyphs are erased. No row/panel/rectangle clearing.
    try {
        $esc=[string][char]27
        $sequence = $esc + '[' + ($Y+1) + ';' + ($X+1) + 'H'
        if ([string]::IsNullOrEmpty($Color)) {
            $sequence += $esc + '[39m '
        } else {
            $sequence += $esc + '[38;2;' + $Color + 'm' + $Glyph
        }
        if ($null -ne $script:OqgRainV22.Pending) {
            [void]$script:OqgRainV22.Pending.Append($sequence)
        } else {
            [Console]::Write($sequence + $esc + '[0m')
        }
    } catch { }
}

function Flush-OqgRainV22 {
    if ($null -eq $script:OqgRainV22.Pending) { return }
    try {
        $text = $script:OqgRainV22.Pending.ToString()
        if ($text.Length -gt 0) {
            [Console]::Write($text + [string][char]27 + '[0m')
        }
    } finally {
        $script:OqgRainV22.Pending = $null
    }
}

function Get-OqgRainV22Glyph {
    param([int]$Seed,[int]$TrailIndex)
    $chars = '0123456789ABCDEF[]{}+*/=%@'
    $n = (([long]$Seed*17L)+([long]$TrailIndex*103L)+([long]$TrailIndex*$TrailIndex*7L)) % [long]$chars.Length
    return [string]$chars[[int]$n]
}

function Get-OqgRainV22GlyphStrip {
    param([int]$Seed,[int]$Length)
    $characters='0123456789ABCDEF[]{}+*/=%@'
    $builder=New-Object System.Text.StringBuilder ([Math]::Max(1,$Length))
    for ($i=0; $i -lt $Length; $i++) {
        $index=(([long]$Seed*17L)+([long]$i*103L)+([long]$i*$i*7L)) % [long]$characters.Length
        [void]$builder.Append($characters[[int]$index])
    }
    return $builder.ToString()
}

# Called at the start of Main-Menu, before the fullscreen UI is painted.
# No terminal writes, no screen reads, and no changes to cryptography.
function Initialize-OqgRainV22BeforeMenu {
    if (-not [bool]$script:OqgCodeRainEnabled) { return }
    try {
        $w=[int][Console]::WindowWidth
        $h=[int][Console]::WindowHeight
        if ($w -lt 100 -or $h -lt 28) { return }
        $expected=('{0}x{1}:{2}:{3}' -f $w,$h,3,($h-4))
        if ($script:OqgRainV22.Geometry -ne $expected) {
            Reset-OqgRainV22 -Width $w -Height $h -BodyTop 3 -FooterTop ($h-4)
        }
    } catch { }
}

function Invoke-OqgAmbientRainV22 {
    param(
        [int]$LeftWidth,[int]$LeftContentBottom,[int]$LogoBottom,
        [int]$ActionX,[int]$ActionWidth,[int]$ActionEnd,[int]$ActionTextWidth,[int]$SelectedRow,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailEnd,[int]$DashTelemetryStart,[int]$DashTelemetryEnd,
        [int]$DashNmsStart,[int]$DashNmsEnd,[int]$BodyTop,[int]$FooterTop,
        [int]$PageStart=0,[int]$PageEnd=12,[int]$RowStep=3,
        [int]$LeftMeterY=-1,[int]$DashMeterY=-1
    )
    if (-not [bool]$script:OqgCodeRainEnabled) { return }
    try {
        $width=[int][Console]::WindowWidth
        $height=[int][Console]::WindowHeight
        if ($width -lt 100 -or $height -lt 28) { return }
        $s=$script:OqgRainV22
        $geometry=('{0}x{1}:{2}:{3}' -f $width,$height,$BodyTop,$FooterTop)
        if ($s.Geometry -ne $geometry) {
            Reset-OqgRainV22 -Width $width -Height $height -BodyTop $BodyTop -FooterTop $FooterTop
        }
        Update-OqgRainV22Mask -Width $width -Height $height -BodyTop $BodyTop -FooterTop $FooterTop `
            -LeftWidth $LeftWidth -LeftContentBottom $LeftContentBottom -LogoBottom $LogoBottom `
            -ActionX $ActionX -ActionWidth $ActionWidth -ActionEnd $ActionEnd -ActionTextWidth $ActionTextWidth -SelectedRow $SelectedRow `
            -DashX $DashX -DashWidth $DashWidth -DashDetailEnd $DashDetailEnd `
            -DashTelemetryStart $DashTelemetryStart -DashTelemetryEnd $DashTelemetryEnd `
            -DashNmsStart $DashNmsStart -DashNmsEnd $DashNmsEnd `
            -PageStart $PageStart -PageEnd $PageEnd -RowStep $RowStep -LeftMeterY $LeftMeterY -DashMeterY $DashMeterY
        $mask=$s.Mask
        if ([int]$s.LastSelectedRow -ne $SelectedRow) {
            # Preserve prior rain cells in untouched background areas so they
            # can be erased by the normal delta renderer, not left as ghosts.
            $s.LastSelectedRow=$SelectedRow
        }
        $now=[double]$s.Clock.Elapsed.TotalSeconds
        $dt=[Math]::Min(0.20,[Math]::Max(0.0,$now-[double]$s.LastSeconds))
        $s.LastSeconds=$now
        $forcePaintV24=$false # V27: preserve rain delta animation across menu navigation
        $next=@{}
        foreach ($d in $s.Drops) {
            $d.Head=[double]$d.Head+([double]$d.Rate*$dt)
            if ($d.Head -ge ($FooterTop+$d.Length)) {
                # Recycle just above the screen, without spending a whole
                # screen's travel time offscreen.
                $d.Head=[double]($BodyTop-1-$s.Rng.Next(0,5))
                $d.Length=[int]$(if ($d.Layer -eq 0) { $s.Rng.Next(13,24) } else { $s.Rng.Next(9,20) })
                $d.Rate=[double](13.0+$s.Rng.NextDouble()*7.0+$d.Layer)
                $d.Seed=[int]$s.Rng.Next(1,10000000)
                $d.Glyphs=Get-OqgRainV22GlyphStrip -Seed ([int]$d.Seed) -Length ([int]$d.Length)
            }
            $head=[int][Math]::Floor([double]$d.Head)
            $x=[int]$d.X
            $len=[int]$d.Length
            for ($t=0; $t -lt $len; $t++) {
                $y=$head-$t
                if ($y -lt $BodyTop -or $y -ge $FooterTop) { continue }
                if (-not $mask[($y*$width)+$x]) { continue }
                if ($y -ge $SelectedRow -and $y -le ($SelectedRow+1) -and
                    $x -ge $ActionX -and $x -lt ($ActionX+$ActionWidth)) { continue }
                $intensity=1.0-($t/[double][Math]::Max(1,$len-1))
                $layer=[int]$d.Layer
                if ($layer -eq 0) {
                    $r=[int](2+22*$intensity);$g=[int](17+105*$intensity);$b=[int](37+118*$intensity)
                    if ($t -eq 0) { $r=44;$g=160;$b=204 }
                } else {
                    $r=[int](2+28*$intensity);$g=[int](22+143*$intensity);$b=[int](47+172*$intensity)
                    if ($t -eq 0) { $r=145;$g=237;$b=255 }
                    elseif ($t -eq 1) { $r=56;$g=200;$b=244 }
                }
                $color=('{0};{1};{2}' -f $r,$g,$b)
                $glyph=([string]$d.Glyphs).Substring($t,1)
                $key=('{0},{1}' -f $x,$y)
                $brightness=$g+$b
                if (-not $next.ContainsKey($key) -or [int]$next[$key][4] -lt $brightness) {
                    $next[$key]=@($x,$y,$glyph,$color,$brightness)
                }
            }
        }
        # Begin an atomic VT batch. Initial frame is fully seeded and painted
        # without waiting for dozens of successive Console.SetCursorPosition calls.
        $s.Pending = New-Object System.Text.StringBuilder 65536
        foreach ($key in @($s.Previous.Keys)) {
            if (-not $next.ContainsKey($key)) {
                $old=$s.Previous[$key]
                $oldX=[int]$old[0]; $oldY=[int]$old[1]
                if ($oldX -ge 0 -and $oldX -lt $width -and $oldY -ge 0 -and $oldY -lt $height -and $mask[($oldY*$width)+$oldX] -and -not (
                    $oldY -ge $SelectedRow -and $oldY -le ($SelectedRow+1) -and
                    $oldX -ge $ActionX -and $oldX -lt ($ActionX+$ActionWidth))) {
                    Write-OqgRainV22Cell -X $oldX -Y $oldY -Glyph ' ' -Color ''
                }
            }
        }
        foreach ($key in @($next.Keys)) {
            $cell=$next[$key]
            $old=$null
            if ($s.Previous.ContainsKey($key)) { $old=$s.Previous[$key] }
            if ($forcePaintV24 -or $null -eq $old -or [string]$old[2] -cne [string]$cell[2] -or [string]$old[3] -cne [string]$cell[3]) {
                Write-OqgRainV22Cell -X ([int]$cell[0]) -Y ([int]$cell[1]) -Glyph ([string]$cell[2]) -Color ([string]$cell[3])
            }
        }
        Flush-OqgRainV22
        $script:OqgRainMenuRepaintV24=$false
        $s.Previous=$next
    } catch {
        $script:OqgRainV22.Pending = $null
        $script:OqgCodeRainEnabled=$false
    }
}

function Clear-OqgAmbientRainV22 {
    try {
        $script:OqgRainV22.Pending = New-Object System.Text.StringBuilder 65536
        foreach ($cell in @($script:OqgRainV22.Previous.Values)) {
            Write-OqgRainV22Cell -X ([int]$cell[0]) -Y ([int]$cell[1]) -Glyph ' ' -Color ''
        }
        Flush-OqgRainV22
        $script:OqgRainV22.Previous=@{}
    } catch { $script:OqgRainV22.Pending = $null }
}

# Accessible terminal approximation of text bloom: high-contrast luminous
# foreground gradient on the existing opaque blue selection background.
# This cannot perform pixel glow in a character-cell renderer.
function Write-OqgBloomSelectionV19 {
    param([string]$Text,[int]$X,[int]$Y,[int]$Width,[string]$Background)
    $segments = @(New-GradientSegments -Text $Text -StartRgb @(106,209,255) -EndRgb @(245,252,255) -BackgroundColor $Background -Bold)
    Write-MenuRenderLineAt -Line (New-ConsoleRichLine -Segments $segments) -X $X -Y $Y -Width $Width
}

# OQG-TRANSITION-RAIN-V23
# Independent half-density code rain for the startup and exit pages.
# No modification of v22 menu rain state; only background console cells painted.
function Invoke-OqgTransitionRainV23 {
    [CmdletBinding()]
    param(
        [ValidateSet('Boot','Exit')][string]$Mode,
        [int]$DurationMilliseconds = 1400,
        [switch]$WaitForEnter
    )
    if (-not [bool]$script:OqgCodeRainEnabled) {
        if ($WaitForEnter) {
            while ($true) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Escape) { break }
            }
        } elseif ($DurationMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $DurationMilliseconds
        }
        return
    }

    $width=0; $height=0
    try { $width=[int][Console]::WindowWidth; $height=[int][Console]::WindowHeight } catch { }
    if ($width -lt 65 -or $height -lt 20) {
        if ($WaitForEnter) {
            while ($true) {
                $key=[Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Escape) { break }
            }
        } elseif ($DurationMilliseconds -gt 0) { Start-Sleep -Milliseconds $DurationMilliseconds }
        return
    }

    $top=1; $bottom=$height-2
    # Snapshot the already drawn startup or farewell page, before adding rain.
    # Preserve all visible text, horizontal rules, progress meters and artwork.
    $foreground=$null
    try {
        $foreground=Get-OqgRainV22ForegroundMask -Width $width -Height $height -BodyTop $top -FooterTop $bottom
    } catch { $foreground=$null }

    $allowed=New-Object 'System.Boolean[]' ($width*$height)
    for ($y=$top; $y -lt $bottom; $y++) {
        for ($x=2; $x -lt ($width-2); $x++) {
            if ($null -ne $foreground) {
                $allowed[($y*$width)+$x] = [bool]$foreground[($y*$width)+$x]
            } elseif ($Mode -eq 'Boot') {
                # No console snapshot: preserve logo and boot content above it.
                $allowed[($y*$width)+$x] = ($y -ge [int]($height*0.67))
            } else {
                # No console snapshot: protect the central farewell card.
                $centerLeft=[int][Math]::Max(0,[Math]::Floor(($width-84)/2))
                $centerRight=[int][Math]::Min($width-1,$centerLeft+84)
                $centerTop=[int][Math]::Max(2,[Math]::Floor($height/2)-7)
                $allowed[($y*$width)+$x] = -not ($x -ge $centerLeft -and $x -le $centerRight -and
                    $y -ge $centerTop -and $y -le ($centerTop+15))
            }
        }
    }

    $rng=New-Object System.Random
    $drops=New-Object System.Collections.ArrayList
    $span=[Math]::Max(2,$bottom-$top)
    # Main menu v22 uses two lanes for each of two overlapping layers.
    # These transition screens use ONE lane per layer, approximately 50% density.
    for ($layer=0; $layer -lt 2; $layer++) {
        $step=if ($layer -eq 0) { 4 } else { 5 }
        $offset=if ($layer -eq 0) { 2 } else { 3 }
        for ($x=$offset; $x -lt ($width-2); $x+=$step) {
            $len=if ($layer -eq 0) { $rng.Next(13,24) } else { $rng.Next(9,20) }
            $seed=$rng.Next(1,10000000)
            [void]$drops.Add(@{
                X=[int]$x
                Head=[double]($top+$rng.NextDouble()*$span)
                Rate=[double](13.0+$rng.NextDouble()*7.0+$layer)
                Length=[int]$len
                Seed=[int]$seed
                Glyphs=(Get-OqgRainV22GlyphStrip -Seed $seed -Length $len)
                Layer=[int]$layer
            })
        }
    }
    $previous=@{}
    $clock=[System.Diagnostics.Stopwatch]::StartNew()
    $last=0.0
    $esc=[string][char]27
    $keepRunning=$true
    try {
        while ($keepRunning) {
            $elapsed=[double]$clock.Elapsed.TotalSeconds
            $dt=[Math]::Min(0.12,[Math]::Max(0.0,$elapsed-$last))
            $last=$elapsed
            $next=@{}
            foreach ($drop in $drops) {
                $drop.Head=[double]$drop.Head+([double]$drop.Rate*$dt)
                if ($drop.Head -ge ($bottom+$drop.Length)) {
                    $drop.Head=[double]($top-1-$rng.Next(0,4))
                    $drop.Length=[int]$(if ($drop.Layer -eq 0) { $rng.Next(13,24) } else { $rng.Next(9,20) })
                    $drop.Rate=[double](13.0+$rng.NextDouble()*7.0+$drop.Layer)
                    $drop.Seed=[int]$rng.Next(1,10000000)
                    $drop.Glyphs=Get-OqgRainV22GlyphStrip -Seed $drop.Seed -Length $drop.Length
                }
                $head=[int][Math]::Floor([double]$drop.Head)
                $x=[int]$drop.X
                $len=[int]$drop.Length
                for ($trail=0; $trail -lt $len; $trail++) {
                    $y=$head-$trail
                    if ($y -lt $top -or $y -ge $bottom) { continue }
                    if (-not $allowed[($y*$width)+$x]) { continue }
                    $intensity=1.0-($trail/[double][Math]::Max(1,$len-1))
                    if ($drop.Layer -eq 0) {
                        $r=[int](2+22*$intensity); $g=[int](17+105*$intensity); $b=[int](37+118*$intensity)
                        if ($trail -eq 0) { $r=44;$g=160;$b=204 }
                    } else {
                        $r=[int](2+28*$intensity); $g=[int](22+143*$intensity); $b=[int](47+172*$intensity)
                        if ($trail -eq 0) { $r=145;$g=237;$b=255 }
                        elseif ($trail -eq 1) { $r=56;$g=200;$b=244 }
                    }
                    $brightness=$g+$b
                    $key=('{0},{1}' -f $x,$y)
                    if (-not $next.ContainsKey($key) -or [int]$next[$key][4] -lt $brightness) {
                        $next[$key]=@($x,$y,([string]$drop.Glyphs).Substring($trail,1),('{0};{1};{2}' -f $r,$g,$b),$brightness)
                    }
                }
            }
            $batch=New-Object System.Text.StringBuilder 65536
            foreach ($key in @($previous.Keys)) {
                if (-not $next.ContainsKey($key)) {
                    $cell=$previous[$key]
                    [void]$batch.Append($esc+'['+([int]$cell[1]+1)+';'+([int]$cell[0]+1)+'H'+$esc+'[39m ')
                }
            }
            foreach ($key in @($next.Keys)) {
                $cell=$next[$key]
                $old=$null
                if ($previous.ContainsKey($key)) { $old=$previous[$key] }
                if ($null -eq $old -or [string]$old[2] -cne [string]$cell[2] -or [string]$old[3] -cne [string]$cell[3]) {
                    [void]$batch.Append($esc+'['+([int]$cell[1]+1)+';'+([int]$cell[0]+1)+'H'+$esc+'[38;2;'+[string]$cell[3]+'m'+[string]$cell[2])
                }
            }
            if ($batch.Length -gt 0) { [Console]::Write($batch.ToString()+$esc+'[0m') }
            $previous=$next

            # The boot page may be timed; the farewell always allows ENTER/ESC.
            # Checking the keyboard every frame keeps the animation responsive.
            try {
                if ([Console]::KeyAvailable) {
                    $keyInfo=[Console]::ReadKey($true)
                    if ($keyInfo.Key -eq [ConsoleKey]::Enter -or $keyInfo.Key -eq [ConsoleKey]::Escape) { break }
                }
            } catch { if ($WaitForEnter) { break } }
            if (-not $WaitForEnter -and $clock.ElapsedMilliseconds -ge $DurationMilliseconds) { break }
            Start-Sleep -Milliseconds 34
        }
    } catch {
        # Decorative failures must not prevent entering the app or quitting.
        if ($WaitForEnter) {
            try { [Console]::ReadKey($true) | Out-Null } catch { }
        }
    } finally {
        # No clearing here: the next screen clears on its own.
        # Reset VT color, restore cursor to safe location, don't expose secrets.
        try { [Console]::Write($esc+'[0m'+$esc+'['+($height-1)+';1H') } catch { }
        $clock.Stop()
    }
}

# OQG-BOOT-CIPHER-RAIN-V24
# Synthetic armor typography ONLY. Never reads messages or private key material.
$script:OqgV24CipherPool = $null
$script:OqgV24CipherPosition = 0
$script:OqgV24Transition = $null
$script:OqgRainMenuRepaintV24 = $false

function Get-OqgCipherPoolV24 {
    if (-not [string]::IsNullOrEmpty([string]$script:OqgV24CipherPool)) {
        return [string]$script:OqgV24CipherPool
    }
    # 1104 pseudorandom bytes, chosen only for a visual ASCII-armored sample.
    # This is not an encrypted PGP message. No user message or key is accessed.
    $bytes = New-Object 'byte[]' 1104
    $provider = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $provider.GetBytes($bytes) } finally { $provider.Dispose() }
    $base64 = [Convert]::ToBase64String($bytes)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add('-----BEGIN PGP MESSAGE-----')
    [void]$lines.Add('Version: OQG Visual Simulation')
    [void]$lines.Add('')
    for ($i=0; $i -lt $base64.Length; $i+=64) {
        [void]$lines.Add($base64.Substring($i,[Math]::Min(64,$base64.Length-$i)))
    }
    [void]$lines.Add('-----END PGP MESSAGE-----')
    # A terminal rain stream consumes characters, not line breaks.
    $script:OqgV24CipherPool = ($lines -join '')
    return [string]$script:OqgV24CipherPool
}

# Override only the decorative glyph provider used by the v22 menu renderer.
# Stream seed becomes an offset into a looping, synthetic PGP armor block.
function Get-OqgRainV22GlyphStrip {
    param([int]$Seed,[int]$Length)
    $pool=Get-OqgCipherPoolV24
    $size=$pool.Length
    $builder=New-Object System.Text.StringBuilder ([Math]::Max(1,$Length))
    # Consume one deterministic continuous armored text stream across drops.
    $start=[int]($script:OqgV24CipherPosition % $size)
    for ($i=0; $i -lt $Length; $i++) {
        [void]$builder.Append($pool[($start+$i)%$size])
    }
    $script:OqgV24CipherPosition=[int](($start+$Length)%$size)
    return $builder.ToString()
}

function Start-OqgTransitionRainV24 {
    param([ValidateSet('Boot','Exit')][string]$Mode='Boot',[int]$LogoRows=0,[int]$LogoWidth=0,[bool[]]$Foreground=$null)
    $script:OqgV24Transition=$null
    if (-not [bool]$script:OqgCodeRainEnabled) { return }
    $w=0;$h=0
    try { $w=[int][Console]::WindowWidth; $h=[int][Console]::WindowHeight } catch { return }
    if ($w -lt 75 -or $h -lt 27) { return }
    $rng=New-Object System.Random
    $drops=New-Object System.Collections.ArrayList
    $pool=Get-OqgCipherPoolV24
    $top=1;$bottom=$h-2
    $span=[Math]::Max(1,$bottom-$top)
    # Roughly half the main menu's four lanes (two layers, one lane each).
    for ($layer=0; $layer -lt 2; $layer++) {
        $step=if ($layer -eq 0) { 4 } else { 5 }
        $offset=if ($layer -eq 0) { 2 } else { 3 }
        for ($x=$offset; $x -lt ($w-2); $x+=$step) {
            $len=if ($layer -eq 0) { $rng.Next(13,24) } else { $rng.Next(9,20) }
            $seed=$rng.Next(1,10000000)
            [void]$drops.Add(@{
                X=[int]$x; Head=[double]($top+$rng.NextDouble()*$span)
                Rate=[double](13+$rng.NextDouble()*7+$layer)
                Length=[int]$len; Seed=[int]$seed
                Glyphs=(Get-OqgRainV22GlyphStrip -Seed $seed -Length $len)
                Layer=[int]$layer
            })
        }
    }
    # OQG v36: carry the falling phases across the boot -> identity boundary.
    # No console output and no retained user data; only decorative stream positions.
    $carry=$script:OqgV36TransitionCarry
    if ($null -ne $carry -and $carry.Width -eq $w -and $carry.Height -eq $h -and $null -ne $carry.Drops) {
        $drops=New-Object System.Collections.ArrayList
        foreach ($oldDrop in @($carry.Drops)) {
            $copy=@{}
            foreach ($property in @($oldDrop.Keys)) { $copy[$property]=$oldDrop[$property] }
            $copy.Head=[double]$copy.Head + ([double]$copy.Rate * [Math]::Min(0.35,[Math]::Max(0.0,([DateTime]::UtcNow-$carry.When).TotalSeconds)))
            [void]$drops.Add($copy)
        }
    }
    $script:OqgV36TransitionCarry=$null
    $state=@{
        Mode=$Mode; Width=$w; Height=$h; Top=$top; Bottom=$bottom
        LogoRows=$LogoRows; LogoWidth=$LogoWidth; Foreground=$Foreground
        Drops=$drops; Rng=$rng; Previous=@{}
        Clock=[System.Diagnostics.Stopwatch]::StartNew(); LastSeconds=0.0
        LastPaintMilliseconds=-1000L
    }
    $script:OqgV24Transition=$state
    # First frame is already populated. No spawn/build-up transition.
    Update-OqgTransitionRainV24 -Force
}

function Test-OqgTransitionCellV24 {
    param([int]$X,[int]$Y,$State)
    if ($X -le 1 -or $X -ge ($State.Width-2) -or $Y -le 0 -or $Y -ge ($State.Height-2)) { return $false }
    if ($State.Mode -eq 'Boot') {
        # Keep the logo and metadata pristine, including during typing.
        if ($Y -lt $State.LogoRows -and $X -lt ($State.LogoWidth+2)) { return $false }
        if ($Y -ge $State.LogoRows -and $Y -lt ($State.LogoRows+18) -and $X -lt [Math]::Min($State.Width-2,120)) { return $false }
    } else {
        # Actual text mask is read once, before any rain glyphs are written.
        if ($null -ne $State.Foreground) {
            return [bool]$State.Foreground[($Y*$State.Width)+$X]
        }
        $left=[int][Math]::Max(0,[Math]::Floor(($State.Width-84)/2))
        $top=[int][Math]::Max(2,[Math]::Floor($State.Height/2)-7)
        if ($X -ge $left -and $X -le ($left+84) -and $Y -ge $top -and $Y -le ($top+15)) { return $false }
    }
    return $true
}

function Update-OqgTransitionRainV24 {
    param([switch]$Force)
    $s=$script:OqgV24Transition
    if ($null -eq $s) { return }
    $elapsed=$s.Clock.ElapsedMilliseconds
    if (-not $Force -and ($elapsed-$s.LastPaintMilliseconds) -lt 24) { return }
    $s.LastPaintMilliseconds=$elapsed
    $now=[double]$s.Clock.Elapsed.TotalSeconds
    $dt=[Math]::Min(0.12,[Math]::Max(0.0,$now-[double]$s.LastSeconds))
    $s.LastSeconds=$now
    $next=@{}
    foreach ($d in $s.Drops) {
        $d.Head=[double]$d.Head+([double]$d.Rate*$dt)
        if ($d.Head -ge ($s.Bottom+$d.Length)) {
            $d.Head=[double]($s.Top-1-$s.Rng.Next(0,4))
            $d.Length=[int]$(if ($d.Layer -eq 0) { $s.Rng.Next(13,24) } else { $s.Rng.Next(9,20) })
            $d.Rate=[double](13+$s.Rng.NextDouble()*7+$d.Layer)
            $d.Seed=[int]$s.Rng.Next(1,10000000)
            $d.Glyphs=Get-OqgRainV22GlyphStrip -Seed $d.Seed -Length $d.Length
        }
        $head=[int][Math]::Floor([double]$d.Head)
        for ($t=0; $t -lt $d.Length; $t++) {
            $x=[int]$d.X; $y=$head-$t
            if ($y -lt $s.Top -or $y -ge $s.Bottom) { continue }
            if ($s.Mode -eq 'Boot' -and $null -ne $s.Foreground) {
                if (-not $s.Foreground[$y*$s.Width+$x]) { continue }
            } elseif (-not (Test-OqgTransitionCellV24 -X $x -Y $y -State $s)) { continue }
            $fade=1.0-($t/[double][Math]::Max(1,$d.Length-1))
            if ($d.Layer -eq 0) {
                $r=[int](2+22*$fade);$g=[int](17+105*$fade);$b=[int](37+118*$fade)
                if ($t -eq 0) { $r=44;$g=160;$b=204 }
            } else {
                $r=[int](2+28*$fade);$g=[int](22+143*$fade);$b=[int](47+172*$fade)
                if ($t -eq 0) { $r=145;$g=237;$b=255 }
                elseif ($t -eq 1) { $r=56;$g=200;$b=244 }
            }
            $index=('{0},{1}' -f $x,$y)
            $brightness=$g+$b
            if (-not $next.ContainsKey($index) -or [int]$next[$index][4] -lt $brightness) {
                $next[$index]=@($x,$y,([string]$d.Glyphs).Substring($t,1),('{0};{1};{2}' -f $r,$g,$b),$brightness)
            }
        }
    }
    $esc=[string][char]27
    $batch=New-Object System.Text.StringBuilder 65536
    foreach ($index in @($s.Previous.Keys)) {
        if (-not $next.ContainsKey($index)) {
            $old=$s.Previous[$index]
            if (-not (Test-OqgTransitionCellV24 -X $old[0] -Y $old[1] -State $s)) { continue }
            [void]$batch.Append($esc+'['+([int]$old[1]+1)+';'+([int]$old[0]+1)+'H'+$esc+'[39m ')
        }
    }
    foreach ($index in @($next.Keys)) {
        $cell=$next[$index];$old=$null
        if ($s.Previous.ContainsKey($index)) { $old=$s.Previous[$index] }
        if ($Force -or $null -eq $old -or [string]$old[2] -cne [string]$cell[2] -or [string]$old[3] -cne [string]$cell[3]) {
            [void]$batch.Append($esc+'['+([int]$cell[1]+1)+';'+([int]$cell[0]+1)+'H'+$esc+'[38;2;'+[string]$cell[3]+'m'+[string]$cell[2])
        }
    }
    if ($batch.Length -gt 0) {
        # Save cursor position and restore colors/position in the same VT batch.
        [Console]::Write($esc+'7'+$batch.ToString()+$esc+'[0m'+$esc+'8')
    }
    $s.Previous=$next
}


function Wait-OqgTransitionRainV24 {
    param([ValidateSet('Boot','Exit')][string]$Mode='Boot',[int]$DurationMilliseconds=1400,[switch]$WaitForEnter)
    if ($null -eq $script:OqgV24Transition) {
        if ($WaitForEnter) {
            while ($true) { $key=[Console]::ReadKey($true); if ($key.Key -eq 'Enter' -or $key.Key -eq 'Escape') { break } }
        } elseif ($DurationMilliseconds -gt 0) { Start-Sleep -Milliseconds $DurationMilliseconds }
        return
    }
    $clock=[System.Diagnostics.Stopwatch]::StartNew()
    try {
        while ($true) {
            Update-OqgTransitionRainV24
            try {
                if ([Console]::KeyAvailable) {
                    $key=[Console]::ReadKey($true)
                    if ($key.Key -eq 'Enter' -or $key.Key -eq 'Escape') { break }
                }
            } catch { if ($WaitForEnter) { break } }
            if (-not $WaitForEnter -and $clock.ElapsedMilliseconds -ge $DurationMilliseconds) { break }
            Start-Sleep -Milliseconds 30
        }
    } finally {
        try { [Console]::Write([string][char]27+'[0m') } catch { }
        if ($null -ne $script:OqgV24Transition) {
            $script:OqgV36TransitionCarry=@{
                Width=$script:OqgV24Transition.Width
                Height=$script:OqgV24Transition.Height
                Drops=$script:OqgV24Transition.Drops
                When=[DateTime]::UtcNow
            }
        }
        $script:OqgV24Transition=$null
    }
}

# Retain the v23 public API for the existing dedicated goodbye screen.
function Invoke-OqgTransitionRainV23 {
    [CmdletBinding()]
    param([ValidateSet('Boot','Exit')][string]$Mode,[int]$DurationMilliseconds=1400,[switch]$WaitForEnter)
    # Capture existing farewell text BEFORE painting any rain glyphs.
    $exitForeground=$null
    if ($Mode -eq 'Exit') {
        try {
            $width=[int][Console]::WindowWidth;$height=[int][Console]::WindowHeight
            $exitForeground=Get-OqgRainV22ForegroundMask -Width $width -Height $height -BodyTop 1 -FooterTop ($height-2)
        } catch { }
    }
    Start-OqgTransitionRainV24 -Mode $Mode -Foreground $exitForeground
    Wait-OqgTransitionRainV24 -Mode $Mode -DurationMilliseconds $DurationMilliseconds -WaitForEnter:$WaitForEnter
}

# Pre-create the synthetic armor text before the boot screen paints.
try { [void](Get-OqgCipherPoolV24) } catch { }

# OQG-STARTUP-RAIN-V25
# Adapt the existing v24 transition engine to both startup stages.
# Deliberately changes no cryptographic workflows and no saved menu preferences.


# This is the final effective implementation, replacing only the short hold
# originally installed by Identity-Hold. The already printed identity panel is
# never cleared or rewritten.
function Wait-OqgIdentityScreen {
    param([ValidateRange(1,60)][int]$Seconds=10)
    $promptY=-1
    $priorCursor=$null
    try { $priorCursor=[Console]::CursorVisible; [Console]::CursorVisible=$false } catch { }
    try {
        # The Enter used to dismiss the boot must not dismiss this screen.
        try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { }
        # V28: preseed transition before printing the countdown; no late buildup.
        try { $promptY=[int][Console]::CursorTop + 1 } catch { $promptY=-1 }
        # Begin after ALL identity foreground lines and the countdown prompt exist.
        # A single console snapshot protects the actual glyph cells, not a rectangle.
        try { Start-OqgIdentityRainV25 -CountdownRow $promptY } catch { }
        Write-Host ''
        try { $promptY=[int][Console]::CursorTop } catch { $promptY=-1 }
        Write-OqgV35IdentityPrompt -Y $promptY -Remaining $Seconds
        $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
        $lastRemaining=-1
        while ($true) {
            $remaining=[int][Math]::Ceiling(($deadline-[DateTime]::UtcNow).TotalSeconds)
            if ($remaining -le 0) { break }
            if ($remaining -ne $lastRemaining) {
                $lastRemaining=$remaining
                # One writer, one foreground color, no 30 ms repaint flicker.
                Write-OqgV35IdentityPrompt -Y $promptY -Remaining $remaining
            }
            try { Update-OqgTransitionRainV24 } catch { }
            try {
                if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); break }
            } catch { }
            Start-Sleep -Milliseconds 30
        }
    } finally {
        # The following main-menu render clears the transition frame. Do not
        # clear the terminal here, which would cause a black flash.
        $script:OqgV24Transition=$null
        try { if ($null -ne $priorCursor) { [Console]::CursorVisible=[bool]$priorCursor } } catch { }
        Write-Host ''
    }
}

# OQG-STARTUP-RAIN-V26
# Retains animated boot rain across multiple boot waits; narrows protection.
# Does not modify key handling, GnuPG, or main menu rain.


function Wait-OqgTransitionRainV24 {
    [CmdletBinding()]
    param(
        [ValidateSet('Boot','Exit')][string]$Mode='Boot',
        [int]$DurationMilliseconds=1400,
        [switch]$WaitForEnter
    )
    $state=$script:OqgV24Transition
    if ($null -eq $state) {
        if ($WaitForEnter) {
            while ($true) {
                $key=[Console]::ReadKey($true)
                if ($key.Key -eq 'Enter' -or $key.Key -eq 'Escape') { break }
            }
        } elseif ($DurationMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $DurationMilliseconds
        }
        return
    }
    $clock=[System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Force restoration of drops that boot metadata may have overwritten.
        Update-OqgTransitionRainV24 -Force
        while ($true) {
            Update-OqgTransitionRainV24
            try {
                if ([Console]::KeyAvailable) {
                    $key=[Console]::ReadKey($true)
                    if ($key.Key -eq 'Enter' -or $key.Key -eq 'Escape') { break }
                }
            } catch {
                if ($WaitForEnter) { break }
            }
            if (-not $WaitForEnter -and $clock.ElapsedMilliseconds -ge $DurationMilliseconds) { break }
            Start-Sleep -Milliseconds 25
        }
    } finally {
        try { [Console]::Write(([string][char]27)+'[0m') } catch { }
        # V24 unconditionally discarded the transition here. Boot can call
        # this wait more than once; keep its drops alive until the next screen
        # is drawn. The identity screen starts a fresh transition itself.
        if ($Mode -ne 'Boot') { $script:OqgV24Transition=$null }
    }
}


function Get-OqgStartupRainStatusV26 {
    $state=$script:OqgV24Transition
    if ($null -eq $state) { return 'Startup rain state: absent' }
    $mode=[string]$state.Mode
    $count=0
    try { $count=@($state.Drops).Count } catch { }
    return ('Startup rain state: {0}; streams: {1}; size: {2}x{3}' -f $mode,$count,$state.Width,$state.Height)
}

# OQG-STARTUP-RAIN-V27
# Phase-local decorative rain and controlled typewriter rendering.
# This file does not read key material, stored messages, or passphrases.


# The existing countdown uses an already drawn foreground panel and calls
# Start-OqgIdentityRainV25 immediately before its countdown loop.


# OQG-INTEGRATED-STARTUP-V28
# Renders the original SGR logo during live boot rain. No cryptographic I/O.


# OQG-RENDER-INTEGRATED-V31
# Foreground-aware boot + identity rain. Synthetic glyphs only.
# This script is injected before the application entrypoint. It changes UI only.

function Start-OqgV31BootRain {
    param([int]$LogoRows=21,[int]$LogoWidth=130)
    $w=0;$h=0
    try { $w=[int][Console]::WindowWidth; $h=[int][Console]::WindowHeight } catch { return }
    if ($w -lt 75 -or $h -lt 27) { return }
    $mask=New-Object 'System.Boolean[]' ($w*$h)
    for($y=1;$y -lt ($h-2);$y++) {
        for($x=2;$x -lt ($w-2);$x++) { $mask[$y*$w+$x]=$true }
    }
    $script:OqgV31BootGlyphs=New-Object 'System.Collections.Generic.HashSet[string]'
    $prior=[bool]$script:OqgCodeRainEnabled
    try {
        $script:OqgCodeRainEnabled=$true
        # Exit mode accepts an exact foreground mask and never reserves a logo rectangle.
        Start-OqgTransitionRainV24 -Mode Exit -Foreground $mask
        $script:OqgV31BootActive=$true
    } finally { $script:OqgCodeRainEnabled=$prior }
}


function Write-OqgV31LogoLine {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text='',[int]$Burst,$Pacing)
    if ($null -eq $Text) { $Text='' }
    $esc=[string][char]27
    $tokens=[regex]::Matches($Text,([regex]::Escape($esc)+'\[[0-9;]*m|[\s\S]'))
    $originX=0;$originY=0
    try { $originX=[int][Console]::CursorLeft;$originY=[int][Console]::CursorTop } catch { }
    $screenY=$originY-[Console]::WindowTop
    $x=$originX;$style=$esc+'[0m';$rowInk=0;$inRun=$false
    $buffer=New-Object System.Text.StringBuilder 4096

    foreach($token in $tokens) {
        $char=[string]$token.Value
        if ($char.StartsWith($esc+'[')) {
            $style=$char
            if ($inRun) { [void]$buffer.Append($char) }
            continue
        }
        if ($char -ne ' ' -and $char -ne "`r" -and $char -ne "`n") {
            if (-not $inRun) {
                [void]$buffer.Append($esc+'['+($screenY+1)+';'+($x+1)+'H'+$style)
                $inRun=$true
            }
            [void]$buffer.Append($char)
            $rowInk++
            $Pacing.Drawn++
            $state=$script:OqgV24Transition
            if ($null -ne $state -and $x -lt $state.Width -and $screenY -ge 0 -and $screenY -lt $state.Height) {
                $state.Foreground[$screenY*$state.Width+$x]=$false
                [void]$state.Previous.Remove(('{0},{1}' -f $x,$screenY))
            }
        } else { $inRun=$false }
        $x++
        if ($buffer.Length -gt 0 -and ($rowInk -ge $Burst -or ($rowInk -gt 0 -and $x -eq ($originX+$Pacing.LastInkColumn)))) {
            $due = 2500.0 * [Math]::Max(0,$Pacing.Drawn-$Pacing.First) / [Math]::Max(1,$Pacing.Total-$Pacing.First)
            while (($left=$due-$Pacing.Clock.Elapsed.TotalMilliseconds) -gt 0) {
                if ($left -gt 30) { Update-OqgTransitionRainV24 }
                $left=$due-$Pacing.Clock.Elapsed.TotalMilliseconds
                if ($left -gt 0) { [Threading.Thread]::Sleep([int][Math]::Min(16,[Math]::Ceiling($left))) }
            }
            [Console]::Write($buffer.ToString())
            [void]$buffer.Clear()
            $inRun=$false
            $rowInk=0
        }
    }
    if ($buffer.Length -gt 0) { [Console]::Write($buffer.ToString()) }
    [Console]::Write($esc+'[0m')
    try { [Console]::SetCursorPosition($originX,[Math]::Min([Console]::WindowHeight-2,$originY+1)) }
    catch { [Console]::Write([Environment]::NewLine) }
    Update-OqgTransitionRainV24
}

function Start-OqgIdentityRainV25 {
    [CmdletBinding()]
    param([int]$CountdownRow=16)
    $w=0;$h=0
    try { $w=[int][Console]::WindowWidth;$h=[int][Console]::WindowHeight } catch { return }
    if ($w -lt 75 -or $h -lt 27) { return }
    # Identity foreground is already painted. Read its actual occupied cells
    # instead of excluding the first 100 columns across the upper screen.
    $mask=$null
    try { $mask=Get-OqgRainV22ForegroundMask -Width $w -Height $h -BodyTop 1 -FooterTop ($h-2) } catch { }
    if ($null -eq $mask) {
        $mask=New-Object 'System.Boolean[]' ($w*$h)
        for($y=1;$y -lt ($h-2);$y++) {
            for($x=2;$x -lt ($w-2);$x++) { $mask[$y*$w+$x]=$true }
        }
        # Conservative fallback: protect only the known line rows, not blocks.
        foreach ($y in @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,$CountdownRow)) {
            if ($y -ge 1 -and $y -lt ($h-2)) {
                $limit=if ($y -eq $CountdownRow) { 72 } else { 52 }
                for($x=2;$x -lt [Math]::Min($limit,$w-2);$x++) { $mask[$y*$w+$x]=$false }
            }
        }
    }
    # V34: the countdown is always foreground, including spaces between words.
    # Console foreground snapshots protect printed glyphs, not whitespace;
    # do not allow decorative rain to occupy any part of this live line.
    if ($CountdownRow -ge 0 -and $CountdownRow -lt $h) {
        $lastX=[Math]::Min($w-2,104)
        for ($x=0;$x -le $lastX;$x++) { $mask[($CountdownRow*$w)+$x]=$false }
    }
    $old=[bool]$script:OqgCodeRainEnabled
    try {
        $script:OqgCodeRainEnabled=$true
        Start-OqgTransitionRainV24 -Mode Exit -Foreground $mask
    } finally { $script:OqgCodeRainEnabled=$old }
}

function Show-StartupBootScreenV51 {
    Clear-Host
    try { [void](Get-OqgRainV22ForegroundMask -Width 1 -Height 1 -BodyTop 0 -FooterTop 0) } catch { }
    Clear-PendingConsoleInputV56
    $screenWidth=Get-V57WindowWidth
    $maxWidth=[Math]::Max(70,[Math]::Min(138,$screenWidth-1))
    $hero=@(Get-OqgSafeMainLogo)
    $heroWidth=0
    foreach($line in $hero) {
        $plain=[regex]::Replace([string]$line,([regex]::Escape([string][char]27)+'\[[0-9;]*m'),'')
        $heroWidth=[Math]::Max($heroWidth,$plain.Length)
    }
    $showHero=$false
    try { $showHero=($hero.Count -ge 3 -and [Console]::WindowWidth -gt ($heroWidth+2) -and [Console]::WindowHeight -ge ($hero.Count+19)) } catch { }
    $logo=if ($showHero) { @($hero) } else { @(Get-BootLogoLinesV65) }
    $logoWidth=if ($showHero) { $heroWidth } else { $maxWidth }
    # Start with streams already falling, before drawing the first logo glyph.
    Start-OqgV31BootRain -LogoRows $logo.Count -LogoWidth $logoWidth
    $rows=@(foreach ($raw in $logo) {
        $line=if ($showHero) { [string]$raw } else { Clip-AsciiLineV67 -Text ([string]$raw) -Width $maxWidth }
        $plain=[regex]::Replace($line,([string][char]27+'\[[0-9;]*m'),'')
        $ink=[regex]::Replace($plain,'[ \r\n]','').Length
        [pscustomobject]@{Text=$line; Ink=$ink; LastInkColumn=$plain.TrimEnd([char[]]" `r`n").Length}
    })
    $total=0
    $first=0
    foreach ($row in $rows) {
        $total+=$row.Ink
        if ($first -eq 0) { $first=[Math]::Min(10,$row.Ink) }
    }
    $burst=[Math]::Min(10,[Math]::Max(1,$total-1))
    $logoPacing=@{Clock=[Diagnostics.Stopwatch]::StartNew(); Drawn=0; Total=$total; First=[Math]::Min($burst,$first); LastInkColumn=0}
    foreach ($row in $rows) {
        $logoPacing.LastInkColumn=$row.LastInkColumn
        Write-OqgV31LogoLine -Text $row.Text -Burst $burst -Pacing $logoPacing
    }
    Write-Host ''
    $boxWidth=[Math]::Max(78,[Math]::Min(114,$screenWidth-4))
    $rule='─'*($boxWidth-4)
    Write-Host ('  ┌{0}┐' -f $rule) -ForegroundColor $script:UiBorderBlue
    Write-BootMenuBoxLineV67 -Label 'BOOT MENU' -Value ([string]$script:BootMenuTitle) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label 'Operator' -Value ([string]$script:BootMenuSubtitle) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label 'Build' -Value ([string]$script:ToolVersion) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label 'Config' -Value (Format-DisplayPath (Get-ConfigPathV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label 'PGP folder' -Value (Format-DisplayPath $script:DefaultStartFolder) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label 'Output folder' -Value (Format-DisplayPath (Get-OutputFolderV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label 'Key profile' -Value ([string]$script:DefaultKeyProfile) -Width $boxWidth -Highlight
    $bottomBorder='  └{0}┘' -f $rule
    Set-OqgV41BootForeground -Row ([Console]::CursorTop-[Console]::WindowTop) -Text $bottomBorder
    Write-Host $bottomBorder -ForegroundColor $script:UiBorderBlue
    Write-Host ''
    Update-OqgTransitionRainV24
    $progressRow=0
    try { $progressRow=[Console]::CursorTop } catch { }
    foreach($p in @(0,12,25,37,51,66,78,90,100)) {
        Clear-PendingConsoleInputV56
        Write-BootProgressAtV57 -Row $progressRow -Percent $p -Label (Get-BootStageLabelV56 -Percent $p)


        Update-OqgTransitionRainV24
        $hold = [Diagnostics.Stopwatch]::StartNew()
        while ($hold.ElapsedMilliseconds -lt 520) {
            Start-Sleep -Milliseconds 35
            Update-OqgTransitionRainV24
        }
    }
    Write-BootProgressAtV57 -Row $progressRow -Percent 100 -Label 'ready'


    try { [Console]::SetCursorPosition(0,$progressRow+2) } catch { Write-Host '' }
    Write-GradientFixedLineV56 -Text '  Boot complete. Press ENTER to continue to identity selection.' -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold

    Update-OqgTransitionRainV24
    if ([bool]$script:BootWaitForEnter) {
        Wait-OqgTransitionRainV24 -Mode Boot -WaitForEnter
    } else {
        Wait-OqgTransitionRainV24 -Mode Boot -DurationMilliseconds 900
    }
    $state=$script:OqgV24Transition
    if ($null -ne $state) {
        $script:OqgV36TransitionCarry=@{Width=$state.Width;Height=$state.Height;Drops=$state.Drops;When=[DateTime]::UtcNow}
    }
    $script:OqgV31BootActive=$false
}

# OQG-STARTUP-V32
# UI only: draw identity rain as soon as the identity banner exists.
# Uses the same synthetic transition-rain engine as v31; never reads key material.
$script:OqgV32IdentityRainEarly = $false

function Sync-OqgV32IdentityForeground {
    [CmdletBinding()]
    param([int]$ThroughRow = 24)
    $s = $script:OqgV24Transition
    if ($null -eq $s -or $null -eq $s.Foreground) { return }
    if (-not ('OqgRainNativeV22' -as [type])) { return }
    try {
        $w = [int]$s.Width
        $h = [int]$s.Height
        $handle = [OqgRainNativeV22]::GetStdHandle(-11)
        $left = [int][Console]::WindowLeft
        $top = [int][Console]::WindowTop
        $lastRow = [Math]::Min($h-3, [Math]::Max(1,$ThroughRow))
        for ($y=1; $y -le $lastRow; $y++) {
            $line = New-Object System.Text.StringBuilder ($w+2)
            $read = 0
            $pos = New-Object -TypeName OqgRainNativeV22+Coord -ArgumentList @([int16]$left,[int16]($top+$y))
            if (-not [OqgRainNativeV22]::ReadChars($handle,$line,$w,$pos,[ref]$read) -or $read -lt $w) { continue }
            $chars = $line.ToString()
            for ($x=2; $x -lt ($w-2); $x++) {
                $index = $y*$w+$x
                $key = '{0},{1}' -f $x,$y
                $ch = [string]$chars[$x]
                $rain = $false
                if ($s.Previous.ContainsKey($key)) {
                    $rain = ($ch -ceq [string]$s.Previous[$key][2])
                }
                if ($ch -eq ' ' -or $ch -eq [string][char]0 -or $rain) {
                    $s.Foreground[$index] = $true
                } else {
                    $s.Foreground[$index] = $false
                    if ($s.Previous.ContainsKey($key)) { $s.Previous.Remove($key) }
                }
            }
        }
    } catch {
        # Never let optional artwork animation interrupt identity initialization.
    }
}

function Start-OqgV32IdentityRainEarly {
    [CmdletBinding()]
    param()
    $w=0; $h=0
    try { $w=[int][Console]::WindowWidth; $h=[int][Console]::WindowHeight } catch { return }
    if ($w -lt 75 -or $h -lt 27) { return }
    if ([bool]$script:OqgV32IdentityRainEarly -and $null -ne $script:OqgV24Transition) { return }
    $mask = New-Object 'System.Boolean[]' ($w*$h)
    for ($y=1; $y -lt ($h-2); $y++) {
        for ($x=2; $x -lt ($w-2); $x++) { $mask[$y*$w+$x]=$true }
    }
    # Protect visible banner characters before the first frame, not its whole rectangle.
    $sampled = $false
    if ('OqgRainNativeV22' -as [type]) {
        try {
            $handle=[OqgRainNativeV22]::GetStdHandle(-11)
            $left=[int][Console]::WindowLeft
            $top=[int][Console]::WindowTop
            for ($y=1; $y -le [Math]::Min(12,$h-3); $y++) {
                $line=New-Object System.Text.StringBuilder ($w+2)
                $read=0
                $pos=New-Object -TypeName OqgRainNativeV22+Coord -ArgumentList @([int16]$left,[int16]($top+$y))
                if (-not [OqgRainNativeV22]::ReadChars($handle,$line,$w,$pos,[ref]$read) -or $read -lt $w) { throw 'Foreground sampling unavailable.' }
                $characters=$line.ToString()
                for ($x=2; $x -lt ($w-2); $x++) {
                    if ($characters[$x] -ne ' ' -and $characters[$x] -ne [char]0) { $mask[$y*$w+$x]=$false }
                }
            }
            $sampled=$true
        } catch { $sampled=$false }
    }
    if (-not $sampled) {
        # Safe fallback only when buffer capture is unavailable.
        for ($y=1; $y -le [Math]::Min(9,$h-3); $y++) {
            for ($x=2; $x -lt [Math]::Min(76,$w-2); $x++) { $mask[$y*$w+$x]=$false }
        }
    }
    $old=[bool]$script:OqgCodeRainEnabled
    try {
        $script:OqgCodeRainEnabled=$true
        Start-OqgTransitionRainV24 -Mode Exit -Foreground $mask
        $script:OqgV32IdentityRainEarly=($null -ne $script:OqgV24Transition)
    } finally { $script:OqgCodeRainEnabled=$old }
}

# OQG-RAIN-NMS-INDEPENDENCE-V33
$script:V33ChromeTick = 0
# OQG-MENU-NMS-IDENTITY-ISOLATION-V34
$script:V34MenuTick = 0

# OQG-NMS-FOREGROUND-V35
# Console-only decoration. Does not touch crypto, files, keys, or state outside UI.
# Ink-only VT writes preserve the ambient rain between visible characters.
function Add-OqgV35InkLine {
    param(
        [System.Text.StringBuilder]$Buffer,
        [int]$X,[int]$Y,[int]$MaxWidth,
        [string]$Text,
        [string]$Rgb='155;205;250'
    )
    if ($MaxWidth -le 0 -or $Y -lt 0 -or [string]::IsNullOrEmpty($Text)) { return }
    $max=[Math]::Min($MaxWidth,$Text.Length)
    $esc=[string][char]27
    # Only emit nonspace text. No padding, no opaque rows, no black rectangles.
    $i=0
    while ($i -lt $max) {
        while ($i -lt $max -and [char]::IsWhiteSpace($Text[$i])) { $i++ }
        if ($i -ge $max) { break }
        $start=$i
        while ($i -lt $max -and -not [char]::IsWhiteSpace($Text[$i])) { $i++ }
        $run=$Text.Substring($start,$i-$start)
        [void]$Buffer.Append($esc+'['+($Y+1)+';'+($X+$start+1)+'H'+$esc+'[38;2;'+$Rgb+'m'+$run)
    }
}

function Write-OqgV35MenuForeground {
    param(
        [int]$LeftWidth,[int]$LeftTop,[string[]]$LeftRows,
        [int]$ActionX,[int]$ActionWidth,[int]$BodyTop,
        [int]$PageStart,[int]$PageEnd,[int]$SelectedIndex,[int]$Step,
        [object[]]$Items,
        [int]$DashX,[int]$DashWidth,[int]$DashDetailY,[string[]]$DetailLines,
        [int]$DashTelemetryY,[string[]]$TelemetryLines,
        [int]$DashNmsY,[string[]]$NmsLines,[int]$FooterTop
    )
    if (-not [bool]$script:LiveNmsMenuEnabled) { return }
    $esc=[string][char]27
    $buff=New-Object System.Text.StringBuilder 32768
    $oldX=0;$oldY=0
    try { $oldX=[int][Console]::CursorLeft; $oldY=[int][Console]::CursorTop } catch {}
    # LEFT: sections and descriptions animate; keys, policy and profile values are stable.
    for ($i=0;$i -lt $LeftRows.Count;$i++) {
        $yy=$LeftTop+$i
        if ($yy -ge $FooterTop) { break }
        $raw=[string]$LeftRows[$i]
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $decorative=($raw -match '^\s*(IDENTITY / SESSION|CRYPTOGRAPHIC PROFILE|CONSOLE|Controls\s*:|Shortcuts\s*:|Global NMS|while selected|fully readable)')
        $shown=if ($decorative) { Get-OqgSafeNmsText -Text $raw -Reveal 0.956 -Seed (900+$i*11) } else { $raw }
        Add-OqgV35InkLine -Buffer $buff -X 0 -Y $yy -MaxWidth ($LeftWidth-2) -Text $shown -Rgb $(if ($decorative) { '109;188;244' } else { '174;198;222' })
    }
    # CENTER: active selection is owned by its gradient painter; only other actions shift.
    for ($j=$PageStart;$j -lt $PageEnd;$j++) {
        if ($j -eq $SelectedIndex) { continue }
        $yy=$BodyTop+2+(($j-$PageStart)*$Step)
        if (($yy+1) -ge $FooterTop) { break }
        $item=$Items[$j]
        $cat=Get-OqgMenuCategory -Label ([string]$item.Label)
        $raw=('    · {0,-7} · {1}  [{2}]' -f ('['+$cat+']'),[string]$item.Label,[string]$item.Shortcut)
        $row=Get-OqgSafeNmsText -Text $raw -Reveal 0.946 -Seed (100+$j*17)
        $hint=Get-OqgSafeNmsText -Text ('       '+[string]$item.Hint) -Reveal 0.975 -Seed (271+$j*23)
        Add-OqgV35InkLine -Buffer $buff -X $ActionX -Y $yy -MaxWidth ($ActionWidth-2) -Text $row -Rgb '139;196;241'
        Add-OqgV35InkLine -Buffer $buff -X $ActionX -Y ($yy+1) -MaxWidth ($ActionWidth-2) -Text $hint -Rgb '113;151;191'
    }
    # RIGHT: metadata and security-relevant values are stable; ambient NMS is on channel text.
    $zones=@(
        @{Y=$DashDetailY;Lines=$DetailLines;Mutate=$false},
        @{Y=$DashTelemetryY;Lines=$TelemetryLines;Mutate=$false},
        @{Y=$DashNmsY;Lines=$NmsLines;Mutate=$true}
    )
    foreach ($zone in $zones) {
        $arr=@($zone.Lines)
        for ($i=0;$i -lt $arr.Count;$i++) {
            $yy=[int]$zone.Y+$i
            if ($yy -ge $FooterTop) { break }
            if ($yy -lt $BodyTop) { continue }
            $raw=[string]$arr[$i]
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            # Channel lines already use the original NMS generator; repaint its new frame only.
            $shown=if ([bool]$zone.Mutate -and $i -gt 1) { Get-OqgSafeNmsText -Text $raw -Reveal 0.92 -Seed (600+$i*23) } else { $raw }
            Add-OqgV35InkLine -Buffer $buff -X $DashX -Y $yy -MaxWidth ($DashWidth-2) -Text $shown -Rgb $(if ([bool]$zone.Mutate) { '115;198;248' } else { '180;198;218' })
        }
    }
    if ($buff.Length -gt 0) {
        # Always restore cursor and styling. Single console write; no Clear-Host.
        [void]$buff.Append($esc+'[0m'+$esc+'['+($oldY+1)+';'+($oldX+1)+'H')
        [Console]::Write($buff.ToString())
    }
}

function Write-OqgV35IdentityPrompt {
    param([int]$Y,[int]$Remaining)
    if ($Y -lt 0) { return }
    $oldFg=$null;$oldX=0;$oldY=0
    try {
        $oldX=[Console]::CursorLeft;$oldY=[Console]::CursorTop
        $oldFg=[Console]::ForegroundColor
        [Console]::ForegroundColor=[ConsoleColor]::Cyan
        [Console]::SetCursorPosition(0,$Y)
        [Console]::Write(('  Identity ready. Press ANY KEY to continue. Auto in {0,2}s   ' -f $Remaining))
    } finally {
        try { if ($null -ne $oldFg) { [Console]::ForegroundColor=$oldFg } } catch {}
        try { [Console]::SetCursorPosition($oldX,$oldY) } catch {}
    }
}

# OQG-RAIN-SURFACE-V36
# UI-only: invalidate cached rain cells beneath an updated boot progress line.
# No keys, profiles, GnuPG commands, configuration or user files are accessed.
$script:OqgV36TransitionCarry=$null

# OQG-PROGRESS-NMS-V37
# Presentation-only overrides. Keep rain behind visible progress glyphs.
$script:OqgV37ProgressEndX = 0
function Protect-OqgV37ProgressRow {
    param([int]$Y)
    $s = $script:OqgV24Transition
    if ($null -eq $s -or $null -eq $s.Foreground) { return }
    if ($Y -lt 1 -or $Y -ge ($s.Height - 2)) { return }
    $end = [Math]::Min($s.Width - 2,[Math]::Max(0,[int]$script:OqgV37ProgressEndX))
    for ($x=0; $x -lt $end; $x++) {
        $s.Foreground[($Y * $s.Width) + $x] = $false
        $key = ('{0},{1}' -f $x,$Y)
        if ($null -ne $s.Previous -and $s.Previous.ContainsKey($key)) {
            [void]$s.Previous.Remove($key)
        }
    }
}

function Write-BootProgressAtV57 {
    param([int]$Row,[int]$Percent,[string]$Label)
    $width = [Math]::Min((Get-V57WindowWidth) - 1,132)
    if ($width -lt 80) { $width = [Math]::Max(60,$width) }
    $segments = @()
    $segments += @(New-GradientSegments -Text ('  {0}' -f (Fit-V57 -Text $Label -Width 30)) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += (New-ConsoleSegment -Text ' ' -Color $script:UiDimSilver)
    $cells = [Math]::Max(18,[Math]::Min(54,$width - 45))
    $segments += @(New-ProgressBarSegmentsV54 -Percent $Percent -Cells $cells)
    $used = 0
    foreach ($seg in @($segments)) {
        if ($null -ne $seg) { $used += ([string]$seg.Text).Length }
    }
    $used = [Math]::Max(1,[Math]::Min($width,$used))
    $script:OqgV37ProgressEndX = [Math]::Min($width,$used + 2)
    $oldX=0;$oldY=0
    try { $oldX=[Console]::CursorLeft; $oldY=[Console]::CursorTop } catch { }
    try {
        [Console]::SetCursorPosition(0,$Row)
        Write-SegmentsNoNewlineV57 -Segments $segments -Width $used
        # Two quiet cells separate the meter from decorative falling ciphertext.
        [Console]::Write('  ')
    } finally {
        try { [Console]::SetCursorPosition($oldX,$oldY) } catch { }
    }
    Protect-OqgV37ProgressRow -Y $Row
}

# Greater, continuously evolving NMS on decorative surfaces only.
# Nondecorative data and the selected action are protected by the v35 caller.
function Get-OqgSafeNmsText {
    param([string]$Text,[double]$Reveal=0.90,[int]$Seed=17)
    if (-not [bool]$script:LiveNmsMenuEnabled) { return $Text }
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    try {
        $chaosReveal = [Math]::Max(0.60,[Math]::Min(0.77,($Reveal - 0.17)))
        return (Convert-ToNmsSentenceV62 -Text $Text -Seed $Seed -Reveal $chaosReveal)
    } catch { return $Text }
}


# OQG-BOOT-COPY-GUARD-V38.1
# Safely wraps the existing renderers without replacing their function AST extents.
# This is decoration protection only. No GnuPG/key/CLI behavior changes.
$script:OqgV381ProgressRow = -1
$script:OqgV381ProgressEndX = 0
$script:OqgV381SentenceActive = $false
$script:OqgV381SentenceWidth = '  Boot complete. Press ENTER to continue to identity selection.'.Length

$script:OqgV381OriginalCellTest = (Get-Command Test-OqgTransitionCellV24 -CommandType Function).ScriptBlock
$script:OqgV381OriginalProgress = (Get-Command Write-BootProgressAtV57 -CommandType Function).ScriptBlock
$script:OqgV381OriginalGradientLine = (Get-Command Write-GradientFixedLineV56 -CommandType Function).ScriptBlock

function Protect-OqgV381Region {
    param([int]$Row,[int]$StartX,[int]$EndX)
    $s = $script:OqgV24Transition
    if ($null -eq $s -or [string]$s.Mode -ne 'Boot') { return }
    if ($Row -le 0 -or $Row -ge ([int]$s.Height-2)) { return }
    $start = [Math]::Max(0,$StartX)
    $end = [Math]::Min(([int]$s.Width-2),$EndX)
    if ($end -le $start) { return }
    for ($x=$start;$x -lt $end;$x++) {
        if ($null -ne $s.Foreground -and ($Row*[int]$s.Width+$x) -lt $s.Foreground.Length) {
            $s.Foreground[($Row*[int]$s.Width)+$x] = $false
        }
        $k = '{0},{1}' -f $x,$Row
        if ($null -ne $s.Previous -and $s.Previous.ContainsKey($k)) {
            [void]$s.Previous.Remove($k)
        }
    }
}

function Test-OqgTransitionCellV24 {
    param([int]$X,[int]$Y,$State)
    if ($null -ne $State -and [string]$State.Mode -eq 'Boot' -and [int]$script:OqgV381ProgressRow -ge 0) {
        if ($Y -eq [int]$script:OqgV381ProgressRow -and $X -ge 0 -and $X -lt [int]$script:OqgV381ProgressEndX) {
            return $false
        }
        if ([bool]$script:OqgV381SentenceActive -and
            $Y -eq ([int]$script:OqgV381ProgressRow+2) -and
            $X -ge 0 -and $X -lt [int]$script:OqgV381SentenceWidth) {
            return $false
        }
    }
    return [bool](& $script:OqgV381OriginalCellTest -X $X -Y $Y -State $State)
}

function Write-BootProgressAtV57 {
    param([int]$Row,[int]$Percent,[string]$Label)
    # A new boot resets the sentence guard. The original progress renderer is retained.
    if ([int]$script:OqgV381ProgressRow -ne $Row) {
        $script:OqgV381SentenceActive = $false
    }
    $script:OqgV381ProgressRow = $Row
    & $script:OqgV381OriginalProgress -Row $Row -Percent $Percent -Label $Label
    $end = [int]$script:OqgV37ProgressEndX
    if ($end -le 0) { throw 'v37 progress width was not initialized; refusing to guess boot text bounds.' }
    $script:OqgV381ProgressEndX = $end
    Protect-OqgV381Region -Row $Row -StartX 0 -EndX $end
}

function Write-GradientFixedLineV56 {
    param(
        [AllowEmptyString()][string]$Text = '',
        [object[]]$StartRgb = $script:GradientBlueStart,
        [object[]]$EndRgb = $script:GradientBlueEnd,
        [switch]$Bold
    )
    if ($Text -ceq '  Boot complete. Press ENTER to continue to identity selection.' -and
        [int]$script:OqgV381ProgressRow -ge 0 -and
        $null -ne $script:OqgV24Transition -and
        [string]$script:OqgV24Transition.Mode -eq 'Boot') {
        $script:OqgV381SentenceActive = $true
        $script:OqgV381SentenceWidth = $Text.Length
        Protect-OqgV381Region -Row ([int]$script:OqgV381ProgressRow+2) -StartX 0 -EndX $Text.Length
    }
    & $script:OqgV381OriginalGradientLine -Text $Text -StartRgb $StartRgb -EndRgb $EndRgb -Bold:$Bold
}


# OQG-STABLE-BOOT-FOREGROUND-V39
# Inserted after v38.1 wrappers, before the app entry point.
# This patch only alters the boot foreground drawing order.
$script:OqgV39PreviousProgressWriter = (Get-Command Write-BootProgressAtV57 -CommandType Function).ScriptBlock
$script:OqgV39PreviousGradientWriter = (Get-Command Write-GradientFixedLineV56 -CommandType Function).ScriptBlock

function Clear-OqgV39BootTextSpan {
    param([int]$Row,[int]$EndX)
    $s = $script:OqgV24Transition
    if ($null -eq $s -or [string]$s.Mode -ne 'Boot') { return }
    if ($Row -lt 1 -or $Row -ge ([int]$s.Height-2)) { return }
    $end = [Math]::Min([int]$s.Width-2,[Math]::Max(0,$EndX))
    if ($end -le 0) { return }

    # 1. Disallow rain in the ENTIRE text span BEFORE its next paint.
    # 2. Evict existing rain history there BEFORE restoring the foreground.
    # 3. Clear prior glyphs ONCE during the foreground paint (not every rain frame).
    for ($x=0;$x -lt $end;$x++) {
        if ($null -ne $s.Foreground -and $s.Foreground.Length -eq ([int]$s.Width*[int]$s.Height)) {
            $s.Foreground[($Row*[int]$s.Width)+$x]=$false
        }
        $key=('{0},{1}' -f $x,$Row)
        if ($null -ne $s.Previous -and $s.Previous.ContainsKey($key)) {
            [void]$s.Previous.Remove($key)
        }
    }
    $esc = [string][char]27
    $oldX=0;$oldY=0
    try {
        $oldX=[int][Console]::CursorLeft
        $oldY=[int][Console]::CursorTop
        # VT position + clean background + restore cursor as one write.
        [Console]::Write($esc+'['+($Row+1)+';1H'+$esc+'[0m'+(' '*$end)+$esc+'['+($oldY+1)+';'+($oldX+1)+'H')
    } catch { }
}

function Write-BootProgressAtV57 {
    param([int]$Row,[int]$Percent,[string]$Label)
    # Width comes from the actual v37 formula, not the full terminal width.
    $width=[Math]::Min((Get-V57WindowWidth)-1,132)
    if ($width -lt 80) { $width=[Math]::Max(60,$width) }
    $cells=[Math]::Max(18,[Math]::Min(54,$width-45))
    # 2 spaces + 30-column label, 1 gap, bar, percentage, and safety margin.
    $end=[Math]::Min($width,33 + $cells + 10)
    $script:OqgV381ProgressRow = $Row
    $script:OqgV381ProgressEndX = $end
    $script:OqgV37ProgressEndX = $end
    $script:OqgV381SentenceActive = $false
    Clear-OqgV39BootTextSpan -Row $Row -EndX $end
    & $script:OqgV39PreviousProgressWriter -Row $Row -Percent $Percent -Label $Label
    # Keep exact final width, as calculated by the existing v37 writer.
    if ([int]$script:OqgV37ProgressEndX -gt 0) {
        $script:OqgV381ProgressEndX=[int]$script:OqgV37ProgressEndX
        Protect-OqgV381Region -Row $Row -StartX 0 -EndX ([int]$script:OqgV381ProgressEndX)
    }
}

function Write-GradientFixedLineV56 {
    param(
        [AllowEmptyString()][string]$Text='',
        [object[]]$StartRgb=$script:GradientBlueStart,
        [object[]]$EndRgb=$script:GradientBlueEnd,
        [switch]$Bold
    )
    $isBootSentence=($Text -ceq '  Boot complete. Press ENTER to continue to identity selection.' -and
        $null -ne $script:OqgV24Transition -and
        [string]$script:OqgV24Transition.Mode -eq 'Boot' -and
        [int]$script:OqgV381ProgressRow -ge 0)
    if ($isBootSentence) {
        $row=[int]$script:OqgV381ProgressRow+2
        $script:OqgV381SentenceActive=$true
        $script:OqgV381SentenceWidth=$Text.Length
        Clear-OqgV39BootTextSpan -Row $row -EndX $Text.Length
    }
    & $script:OqgV39PreviousGradientWriter -Text $Text -StartRgb $StartRgb -EndRgb $EndRgb -Bold:$Bold
    if ($isBootSentence) {
        Protect-OqgV381Region -Row $row -StartX 0 -EndX $Text.Length
    }
}


# OQG-BOOT-PROGRESS-MODE-BRIDGE-V40
# UI-only fix: the v31 boot screen uses Exit-mode rain, but v38/v39 protect
# the progress sentence only when Mode == Boot. Make the REAL boot screen
# report Boot mode, while using the foreground mask (not the old rectangles).
# Do not modify crypto, keyring, config, NMS, menu or the farewell screen.
$script:OqgV40OriginalBootStart = (Get-Command Start-OqgV31BootRain -CommandType Function).ScriptBlock
$script:OqgV40OriginalCellTest = (Get-Command Test-OqgTransitionCellV24 -CommandType Function).ScriptBlock

function Start-OqgV31BootRain {
    param([int]$LogoRows = 21, [int]$LogoWidth = 130)
    # Start the already-working v31 rain exactly as before. Its first frame
    # may use Exit mode; the foreground has not yet been drawn at that point.
    & $script:OqgV40OriginalBootStart -LogoRows $LogoRows -LogoWidth $LogoWidth
    $state = $script:OqgV24Transition
    if ($null -ne $state -and $null -ne $state.Foreground -and
        $state.Foreground.Length -eq ([int]$state.Width * [int]$state.Height)) {
        # Now v38.1/v39 guards recognize the progress row and sentence.
        $state.Mode = 'Boot'
    }
}

function Test-OqgTransitionCellV24 {
    param([int]$X, [int]$Y, $State)
    if ($null -ne $State -and [string]$State.Mode -eq 'Boot' -and
        $null -ne $State.Foreground) {
        # Use the exact foreground occupancy grid from the v31 compositor.
        # Do NOT fall back to the old LogoRows x LogoWidth rectangle.
        $width = [int]$State.Width
        $height = [int]$State.Height
        if ($X -le 1 -or $X -ge ($width - 2) -or
            $Y -le 0 -or $Y -ge ($height - 2)) { return $false }
        if ($State.Foreground.Length -ne ($width * $height)) { return $false }

        return [bool]$State.Foreground[($Y * $width) + $X]
    }
    # Identity + goodbye continue through the existing v39 renderer.
    return [bool](& $script:OqgV40OriginalCellTest -X $X -Y $Y -State $State)
}


# OQG-BOOT-FOREGROUND-COMPOSITOR-V41
# Draw-order reconciliation. These wrappers register the actual boot UI cells
# in the existing transition's foreground mask and its persistent glyph set.
# No crypto, menu, NMS or configuration functions are replaced.

$script:OqgV41PreviousBootBox = (Get-Command Write-BootMenuBoxLineV67 -CommandType Function -ErrorAction Stop).ScriptBlock
$script:OqgV41PreviousGradient = (Get-Command Write-GradientFixedLineV56 -CommandType Function -ErrorAction Stop).ScriptBlock
$script:OqgV41ProgressRow = -1
$script:OqgV41BootSentence = '  Boot complete. Press ENTER to continue to identity selection.'

function Set-OqgV41BootForeground {
    param(
        [int]$Row,
        [int]$X = 0,
        [AllowEmptyString()][string]$Text = '',
        [switch]$ProtectSpaces,
        [switch]$ClearStale
    )
    $s = $script:OqgV24Transition
    if ($null -eq $s -or $null -eq $s.Foreground) { return }
    $w = [int]$s.Width
    $h = [int]$s.Height
    if ($w -lt 2 -or $h -lt 2 -or $s.Foreground.Length -ne ($w * $h)) { return }
    if ($Row -lt 1 -or $Row -ge ($h - 2)) { return }
    if ($null -eq $script:OqgV31BootGlyphs) {
        $script:OqgV31BootGlyphs = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    for ($i=0; $i -lt $Text.Length; $i++) {
        $px=$X+$i
        if ($px -lt 0 -or $px -ge ($w-1)) { continue }
        if (-not $ProtectSpaces -and [char]::IsWhiteSpace($Text[$i])) { continue }
        $s.Foreground[($Row*$w)+$px] = $false
        $key='{0},{1}' -f $px,$Row
        [void]$script:OqgV31BootGlyphs.Add($key)
        if ($null -ne $s.Previous -and $s.Previous.ContainsKey($key)) {
            [void]$s.Previous.Remove($key)
        }
    }
    if ($ClearStale -and $Text.Length -gt 0) {
        # Only the exact text span is cleared. No wide row padding or black slab.
        $from=[Math]::Max(0,$X)
        $until=[Math]::Min(($w-2),$X+$Text.Length)
        if ($until -gt $from) {
            try {
                $savedX=[int][Console]::CursorLeft
                $savedY=[int][Console]::CursorTop
                $esc=[string][char]27
                [Console]::Write($esc+'['+($Row+1)+';'+($from+1)+'H'+$esc+'[0m'+(' '*($until-$from))+$esc+'['+($savedY+1)+';'+($savedX+1)+'H')
            } catch { }
        }
    }
}

function Write-BootMenuBoxLineV67 {
    param(
        [AllowEmptyString()][string]$Label = '',
        [AllowEmptyString()][string]$Value = '',
        [int]$Width = 96,
        [int]$LabelWidth = 17,
        [switch]$Highlight
    )
    $y=-1
    try { $y=[Console]::CursorTop-[Console]::WindowTop } catch { }
    & $script:OqgV41PreviousBootBox -Label $Label -Value $Value -Width $Width -LabelWidth $LabelWidth -Highlight:$Highlight
    if ($y -lt 1) { return }
    $inner = [Math]::Max(20,$Width-6)
    $maxValue = [Math]::Max(8,$inner-$LabelWidth-3)
    $labelString = Fit-V57 -Text $Label -Width $LabelWidth
    $valueString = Fit-V57 -Text $Value -Width $maxValue
    $plainUsed = $LabelWidth+3+$maxValue
    $padding = if ($plainUsed -lt $inner) { ' '*($inner-$plainUsed) } else { '' }
    $rowText = '  │ '+$labelString+' │ '+$valueString+$padding+' │'
    Set-OqgV41BootForeground -Row $y -X 2 -Text '│'
    Set-OqgV41BootForeground -Row $y -X 4 -Text ($labelString.TrimEnd()) -ProtectSpaces
    Set-OqgV41BootForeground -Row $y -X (5+$LabelWidth) -Text '│'
    Set-OqgV41BootForeground -Row $y -X (7+$LabelWidth) -Text ($valueString.TrimEnd()) -ProtectSpaces
    # Protect the final right-hand border, but NOT the empty space before it.
    Set-OqgV41BootForeground -Row $y -X ($rowText.Length-1) -Text '│'
    # Top boundary was drawn by Write-Host immediately before the first row.
    if ($Label -ceq 'BOOT MENU') {
        Set-OqgV41BootForeground -Row ($y-1) -Text ('  ┌'+('─'*[Math]::Max(0,($Width-4)))+'┐')
    }
}

function Write-BootProgressAtV57 {
    param([int]$Row,[int]$Percent,[string]$Label)
    $width = [Math]::Max(1,[Console]::WindowWidth - 1)
    $labelWidth = [Math]::Min(30,[Math]::Max(1,$width - 23))
    $cells = [Math]::Min(54,[Math]::Max(10,$width - $labelWidth - 13))
    $field = Fit-V57 -Text $Label -Width $labelWidth
    $segments = @(New-GradientSegments -Text ("  " + $field + " ") -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold)
    $segments += @(New-ProgressBarSegmentsV54 -Percent $Percent -Cells $cells)

    $esc = [string][char]27
    $screenRow = $Row - [Console]::WindowTop
    if ($screenRow -lt 0 -or $screenRow -ge [Console]::WindowHeight) { return }
    $frame = New-Object System.Text.StringBuilder
    [void]$frame.Append($esc + '7' + $esc + '[' + ($screenRow+1) + ';1H')
    $used = 0
    foreach ($seg in $segments) {
        $count = [Math]::Min(([string]$seg.Text).Length,$width - $used)
        if ($count -le 0) { break }
        [void]$frame.Append($esc + '[0m')
        if ($seg.Bold) { [void]$frame.Append($esc + '[1m') }
        [void]$frame.Append((Get-AnsiStyleCode -Color $seg.Color))
        [void]$frame.Append(([string]$seg.Text).Substring(0,$count))
        $used += $count
    }
    [void]$frame.Append($esc + '[0m' + $esc + '8')
    $script:OqgV41ProgressRow = $Row
    $script:OqgV381ProgressRow = $screenRow
    $script:OqgV381ProgressEndX = $used
    $script:OqgV37ProgressEndX = $used
    $state=$script:OqgV24Transition
    if ($null -ne $state -and $screenRow -ge 0 -and $screenRow -lt $state.Height) {
        # Reopen the padding as soon as the next stage has a shorter label.
        $barStart=3+$labelWidth
        for ($x=0; $x -lt [Math]::Min($used,$state.Width); $x++) {
            $isLabel=($x -ge 2 -and $x -lt (2+[Math]::Min($Label.Length,$labelWidth)))
            $state.Foreground[$screenRow*$state.Width+$x]=(-not $isLabel -and $x -lt $barStart)
            [void]$state.Previous.Remove(('{0},{1}' -f $x,$screenRow))
        }
    }
    [Console]::Write($frame.ToString())
}

function Write-GradientFixedLineV56 {
    param(
        [AllowEmptyString()][string]$Text='',
        [object[]]$StartRgb=$script:GradientBlueStart,
        [object[]]$EndRgb=$script:GradientBlueEnd,
        [switch]$Bold
    )
    $isBootCopy=($Text -ceq $script:OqgV41BootSentence -and
        [int]$script:OqgV41ProgressRow -ge 0 -and
        $null -ne $script:OqgV24Transition)
    if ($isBootCopy) {
        # The caller moves to progressRow + 2 before printing the completion line.
        $row=[int]$script:OqgV41ProgressRow+2
        Set-OqgV41BootForeground -Row $row -Text $Text -ProtectSpaces -ClearStale
    }
    & $script:OqgV41PreviousGradient -Text $Text -StartRgb $StartRgb -EndRgb $EndRgb -Bold:$Bold
    if ($isBootCopy) { Set-OqgV41BootForeground -Row $row -Text $Text -ProtectSpaces }
}

try {
    Install-QuitGuard
    Initialize-ActiveIdentityV44
    Wait-OqgIdentityScreen -Seconds 10
    Main-Menu
} catch {
    Write-Host ""
    Write-Host "Fatal error:" -ForegroundColor $script:UiLightBlue
    Write-Host $_.Exception.Message -ForegroundColor $script:UiLightBlue
    Write-Host ""
    Write-Host "Stack:" -ForegroundColor $script:UiDimSilver
    Write-Host $_.ScriptStackTrace -ForegroundColor $script:UiDimSilver
    Wait-User
} finally {
    Restore-QuitGuard
}
