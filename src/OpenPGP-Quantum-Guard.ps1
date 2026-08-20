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

    $isCtrl = (($KeyInfo.Modifiers -band [ConsoleModifiers]::Control) -eq [ConsoleModifiers]::Control)
    if (-not $isCtrl) { return $false }

    return ($KeyInfo.Key -in @([ConsoleKey]::C, [ConsoleKey]::Q, [ConsoleKey]::Z))
}

$script:GpgPath = $null # v63: resolved after config is loaded
$script:IdentityFingerprint = ""


function Wait-User {
    Write-Host ""
    [void](Read-Host "Press ENTER to continue")
}

function Format-Size {
    param([Int64]$Bytes)
    if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Read-YesNo {
    param(
        [Parameter(Mandatory=$true)][string]$Question,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $answer = (Read-Host "$Question $suffix").Trim().ToLowerInvariant()
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

function Invoke-ConsoleMenu {
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
                $fallback = (Read-Host "Choose").Trim()
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

    $custom = (Read-Host "Export path").Trim('"')
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
    $typed = Read-Host "Confirmation"
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
        $custom = (Read-Host "Output path").Trim('"')
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
    $name = (Read-Host "Name").Trim(); $email = (Read-Host "Email").Trim(); $comment = (Read-Host "Comment, optional").Trim()
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
    & $script:GpgPath --edit-key $script:IdentityFingerprint
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
    $confirmation = Read-Host 'Type ADMIN to continue'
    if ($confirmation -ceq "ADMIN") { return $true }

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
                $script:EnableNoMoreSecretsEffect = -not $script:EnableNoMoreSecretsEffect
                $script:EnableDynamicNmsMenu = $script:EnableNoMoreSecretsEffect
                $state = if ($script:EnableNoMoreSecretsEffect) { "ON" } else { "OFF" }
                Write-Host ("NMS reveal is now: {0}" -f $state) -ForegroundColor $script:UiWhiteSilver
                Wait-User
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
    Write-Host "Paste or type text below. Finish with a single line containing .END" -ForegroundColor $script:UiDimSilver
    Write-Host ""
    $lines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $line = Read-Host ">"
        if ($line -eq ".END") { break }
        [void]$lines.Add($line)
    }
    return ($lines -join [Environment]::NewLine)
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

        $choice = (Read-Host "Selection").Trim()
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^(r|refresh)$') { continue }
        if ($choice -match '^(q|quit|cancel)$') { return $null }
        if ($choice -match '^(u|up|\.\.)$') {
            $parent = Split-Path -Parent $current
            if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) { $current = (Resolve-Path -LiteralPath $parent).Path }
            continue
        }
        if ($choice -match '^(j|jump|c|cd)$') {
            $newPath = (Read-Host "Paste full folder path").Trim('"')
            if (Test-Path -LiteralPath $newPath -PathType Container) {
                $current = (Resolve-Path -LiteralPath $newPath).Path
            } else {
                Write-Host "Folder not found: $newPath" -ForegroundColor $script:UiLightBlue
                Wait-User
            }
            continue
        }
        if ($choice -match '^(p|path)$') {
            $filePath = (Read-Host "Exact file path").Trim('"')
            if (Test-Path -LiteralPath $filePath -PathType Leaf) { return (Resolve-Path -LiteralPath $filePath).Path }
            Write-Host "File not found: $filePath" -ForegroundColor $script:UiLightBlue
            Wait-User
            continue
        }
        if ($choice -match '^(s|search)$') {
            $searchRoot = (Read-Host "Search under folder path [ENTER = current]").Trim('"')
            if ([string]::IsNullOrWhiteSpace($searchRoot)) { $searchRoot = $current }
            if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) {
                Write-Host "Folder not found: $searchRoot" -ForegroundColor $script:UiLightBlue
                Wait-User
                continue
            }
            $current = (Resolve-Path -LiteralPath $searchRoot).Path
            $pattern = (Read-Host "Search file name contains").Trim()
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
        $choice = (Read-Host "Choose file number, or Q to cancel").Trim()
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
        $choice = (Read-Host "Choose encryption subkey number, or Q to cancel").Trim()
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
                    $d = Read-Host "Details number"
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
    $raw = (Read-Host "> ").Trim()
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
        "Use arrows to move, ENTER to open, shortcuts for direct actions, and Q to quit cleanly.",
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
        "Admin settings require an explicit ADMIN confirmation because they change operational behavior and defaults."
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
            Read-Host "Press ENTER to continue"
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
    Write-SegmentsNoNewlineV57 -Segments $segments -Width $width
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

function Show-StartupBootScreenV51 {
    Clear-Host
    Clear-PendingConsoleInputV56
    $logoText = @'
    __                                    __ ,                                           
  ,-||-,                     -__ /\    ,-| ~   -__ /\                                  
 ('|||  )                      ||  \  ('||/__,   ||  \                                 
(( |||--)) -_-_   _-_  \/\  /||__|| (( |||  |  /||__||                                 
(( |||--)) || \ || \ || ||  \||__|| (( |||==|  \||__||                                 
 ( / |  )  || || ||/   || ||   ||  |,  ( / |  ,   ||  |,                                 
  -____-   ||-'  \,/  \ \ _-||-_/    -____/  _-||-_/                                  
           |/                  ||                 ||                                     
           '                                                                             
    __                                                     __ ,                          
  ,-||-,                       ,                         ,-| ~                      |\   
 ('|||  )          _          ||                        ('||/__,         _           \\  
(( |||--)) \\ \\  < \, \/\\ =||= \\ \\ \/\\/\\       (( |||  | \\ \\  < \, ,._-_  / \\ 
(( |||--)) || ||  /-|| || ||  ||  || || || || ||       (( |||==| || ||  /-||  ||   || || 
 ( / |  )  || || (( || || ||  ||  || || || || ||        ( / |  , || || (( ||  ||   || || 
  -____-\\ \/\\  \/\\ \\ \\  \\, \/\\ \\ \\ \\         -____/  \/\\  \/\\  \\,   \/  
                                                                                         
                                                                                        
'@
    $maxWidth = [Math]::Max(70, (Get-V57WindowWidth) - 1)
    foreach ($line in @($logoText -split "`r?`n")) {
        $safe = if ($line.Length -gt $maxWidth) { $line.Substring(0, $maxWidth) } else { $line }
        Write-GradientFixedLineV56 -Text $safe -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold
        Start-Sleep -Milliseconds 8
    }
    Write-Host ""
    Write-GradientFixedLineV56 -Text "  OpenPGP Quantum Guard boot sequence" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-GradientFixedLineV56 -Text "  Loading runtime, GnuPG probe, trust inventory, strength profile, file browser." -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""
    $progressRow = 0
    try { $progressRow = [Console]::CursorTop } catch { $progressRow = 0 }
    $steps = @(0, 8, 17, 29, 41, 53, 64, 76, 88, 96, 100)
    foreach ($p in $steps) {
        Clear-PendingConsoleInputV56
        Write-BootProgressAtV57 -Row $progressRow -Percent $p -Label (Get-BootStageLabelV56 -Percent $p)
        Start-Sleep -Milliseconds 115
    }
    Write-BootProgressAtV57 -Row $progressRow -Percent 100 -Label "ready"
    try { [Console]::SetCursorPosition(0, $progressRow + 2) } catch { Write-Host "" }
    Write-GradientFixedLineV56 -Text "  Boot complete. Press ENTER to continue to identity selection." -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Wait-ForEnterOnlyV56
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

function Get-CompactMainLeftLines {
    param([string]$ModeText, [string]$GpgState)

    $fpr = Short-Fpr $script:IdentityFingerprint
    $modeLine = ("Mode  : {0}   GnuPG: {1}" -f $ModeText, $GpgState)
    $nmsLine = Convert-ToNmsSentenceV62 -Text "NMS : NO MORE SECRETS" -Seed 90 -Reveal 0.58
    if (-not [bool]$script:LiveNmsMenuEnabled) { $nmsLine = "NMS : standby" }

    $lines = @()
    $w = 60
    $lines += New-V57TextLine (New-V57BoxTop $w) $script:UiBorderBlue
    $lines += New-NmsSentenceGradientLineV62 -Text "OpenPGP Quantum Guard" -Seed 1 -Reveal 0.78 -Bold -Selected
    $lines += New-NmsSentenceLineV62 -Text "  │ PQC-enabled OpenPGP operations                      │" -Color $script:UiSilverBlue -Seed 2 -Reveal 0.78 -Selected
    $lines += New-V57TextLine (New-V57BoxMid $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text ("FPR   : {0}" -f $fpr) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text $modeLine -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Crypto: Kyber / ML-KEM hybrid aware" -Seed 3 -Reveal 0.72) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Flow  : Encrypt PQC. Decrypt auto-detect." -Seed 4 -Reveal 0.72) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text $nmsLine -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-NmsSentenceGradientLineV62 -Text ("  Build {0}: live sentence NMS" -f $script:ToolVersion) -Seed 5 -Reveal 0.70 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  Screen: fixed panels, all menu text animated" -Color $script:UiDimSilver -Seed 6 -Reveal 0.66
    $lines += New-NmsSentenceLineV62 -Text "  Keys  : chooser, generation, strength profiles" -Color $script:UiDimSilver -Seed 7 -Reveal 0.66
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-V57TextLine "  ───────────────────────────────────────────────────────" $script:UiBorderBlue
    $lines += New-NmsSentenceGradientLineV62 -Text "  Operator signal" -Seed 8 -Reveal 0.68 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  Every main-menu sentence is now inside the NMS wave." -Color $script:UiSilverBlue -Seed 9 -Reveal 0.64
    $lines += New-NmsSentenceLineV62 -Text "  N toggles the live layer. It never changes crypto." -Color $script:UiDimSilver -Seed 10 -Reveal 0.64
    $lines += New-NmsSentenceLineV62 -Text "  The truth is in the logs. The proof is in the keys." -Color $script:UiDimSilver -Seed 11 -Reveal 0.64
    return @($lines)
}

function New-MainMenuRightLines {
    param(
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0,
        [bool]$Pulse = $false,
        [int]$PanelWidth = 56
    )

    $arr = @($Items)
    $lines = @()
    $ruleLen = [Math]::Max(28, [Math]::Min([int]$PanelWidth, 54))
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text (Convert-ToNmsSentenceV62 -Text "Actions" -Seed 20 -Reveal 0.72 -Selected) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
    $lines += (New-MenuRenderLine -Text ("─" * $ruleLen) -Color $script:UiBorderBlue)

    for ($i = 0; $i -lt $arr.Count; $i++) {
        $item = $arr[$i]
        $label = [string]$item.Label
        $hint = [string]$item.Hint
        $hintWidth = [Math]::Max(28, $PanelWidth - 8)
        $hintLines = @(Split-BoxTextLine -Text $hint -Width $hintWidth | Select-Object -First 2)
        $selected = ($i -eq $SelectedIndex)
        $seedBase = 100 + ($i * 17)

        if ($selected) {
            $labelText = "  ▶ {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.78 -Selected)
            $lines += (New-MenuRenderLine -Text $labelText -Color $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue)
            foreach ($h in $hintLines) {
                $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 3) -Reveal 0.76 -Selected
                $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiWhiteSilver -BackgroundColor $script:UiDeepBlue)
            }
        } else {
            $labelText = "    {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.66)
            $lines += (New-MenuRenderLine -Text $labelText -Color ([string]$item.Color))
            foreach ($h in $hintLines) {
                $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 5) -Reveal 0.62
                $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiDimSilver)
            }
        }
        if ($i -lt ($arr.Count - 1)) { $lines += (New-MenuRenderLine -Text "" -Color $script:UiDimSilver) }
    }
    $lines += (New-MenuRenderLine -Text ("─" * $ruleLen) -Color $script:UiBorderBlue)
    return @($lines)
}

function Invoke-MainMenuRightPanel {
    param(
        [Parameter(Mandatory=$true)]$HeaderLines,
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0
    )
    $itemsArray = @($Items)
    if ($itemsArray.Count -eq 0) { return "Back" }
    $oldCursorVisible = $null
    $firstDraw = $true
    $lastTotalRows = 0
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }
    try {
        while ($true) {
            try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 } catch { $script:V62NmsFrame = 1 }
            $windowWidth = Get-V57WindowWidth
            $leftWidth = if ($windowWidth -ge 132) { 66 } else { 62 }
            $rightX = $leftWidth + 2
            $rightWidth = [Math]::Max(52, $windowWidth - $rightX - 2)
            $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
            $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
            $left = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
            $right = @(New-MainMenuRightLines -Items $itemsArray -SelectedIndex $SelectedIndex -PanelWidth $rightWidth)
            $footerRow = [Math]::Max($left.Count, $right.Count) + 1
            $totalRows = $footerRow + 2
            if ($firstDraw) { Clear-Host; $firstDraw = $false } else { try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host } }
            $emptyLeft = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            $emptyRight = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            for ($row = 0; $row -lt $totalRows; $row++) {
                $lineLeft = if ($row -lt $left.Count) { $left[$row] } else { $emptyLeft }
                $lineRight = if ($row -lt $right.Count) { $right[$row] } else { $emptyRight }
                Write-MenuRenderLineAt -Line $lineLeft -X 0 -Y $row -Width $leftWidth
                Write-MenuRenderLineAt -Line $lineRight -X $rightX -Y $row -Width $rightWidth
            }
            if ($lastTotalRows -gt $totalRows) {
                $blank = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
                for ($row = $totalRows; $row -lt $lastTotalRows; $row++) { Write-MenuRenderLineAt -Line $blank -X 0 -Y $row -Width ([Math]::Max(20, $windowWidth - 1)) }
            }
            $lastTotalRows = $totalRows
            $footerBase = "Use arrows. ENTER opens. N toggles NMS. Q exits."
            $footerText = Convert-ToNmsSentenceV62 -Text $footerBase -Seed 777 -Reveal 0.70
            $footer = (New-MenuRenderLine -Text $footerText -Color $script:UiDimBone)
            Write-MenuRenderLineAt -Line $footer -X 0 -Y $footerRow -Width ([Math]::Min($windowWidth - 1, 126))
            try { [Console]::SetCursorPosition(0, $footerRow + 1) } catch { }

            $key = $null
            try {
                $delayMs = if ([bool]$script:LiveNmsMenuEnabled) { [int]$script:V62NmsFrameDelayMs } else { 250000 }
                if ([bool]$script:LiveNmsMenuEnabled) {
                    $until = (Get-Date).AddMilliseconds($delayMs)
                    while ((Get-Date) -lt $until) {
                        if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true); break }
                        Start-Sleep -Milliseconds 10
                    }
                    if ($null -eq $key) { continue }
                } else {
                    $key = [Console]::ReadKey($true)
                }
            } catch { return (Invoke-ConsoleMenu -Title "Main menu" -HeaderLines $HeaderLines -Items $itemsArray -Layout "Vertical" -SelectedIndex $SelectedIndex) }
            if (Test-BlockedControlQuitKey -KeyInfo $key) { Write-QuitGuardNotice; $firstDraw = $true; continue }
            switch ($key.Key) {
                "LeftArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "UpArrow"    { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "RightArrow" { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "DownArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "Enter"      { return [string]$itemsArray[$SelectedIndex].Value }
                "Escape"     { continue }
                default {
                    $ch = [string]$key.KeyChar
                    if ($ch -eq "q" -or $ch -eq "Q") { return "Quit" }
                    if ($ch -eq "n" -or $ch -eq "N") { $script:LiveNmsMenuEnabled = -not [bool]$script:LiveNmsMenuEnabled; continue }
                    if (-not [string]::IsNullOrWhiteSpace($ch)) {
                        foreach ($item in $itemsArray) {
                            if ($ch -eq [string]$item.Shortcut) { return [string]$item.Value }
                            if ($ch.ToLowerInvariant() -eq ([string]$item.Shortcut).ToLowerInvariant()) { return [string]$item.Value }
                        }
                    }
                }
            }
        }
    } finally { try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { } }
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
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Close the tool cleanly." -Color $script:UiWhiteSilver -Shortcut "q")
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
        & $script:GpgPath @args
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
    $profile = (Read-Host ("Choose profile [{0}]" -f $defaultProfile)).Trim()
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
            $mix = (Read-Host "Choose subkeys [4]").Trim()
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
    $name = (Read-Host "Name").Trim()
    $email = (Read-Host "Email").Trim()
    $comment = (Read-Host "Comment, optional").Trim()
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($email)) { Write-Host "Name and email are required." -ForegroundColor $script:UiLightBlue; Wait-User; return }
    $uid = if ([string]::IsNullOrWhiteSpace($comment)) { "{0} <{1}>" -f $name, $email } else { "{0} ({1}) <{2}>" -f $name, $comment, $email }
    $expiryDefault = [string](Get-ScriptVariableValueV63 -Name "DefaultKeyExpiry" -Default "2y")
    $expiry = (Read-Host ("Expiration [{0}]" -f $expiryDefault)).Trim()
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
    if (-not (Read-YesNo "Use this output path?" $true)) { $custom = (Read-Host "Output path").Trim('"'); if (-not [string]::IsNullOrWhiteSpace($custom)) { $outPath = $custom } }
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
    if ([string]::IsNullOrWhiteSpace($plain)) { Write-Host "No text entered. Encryption cancelled." -ForegroundColor $script:UiDimSilver; Wait-User; return }
    $sign = Read-YesNo "Also sign the encrypted text with this active key?" $true
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $defaultOut = Get-NonClobberPath -Path (Join-Path (Get-OutputFolderV63) ("openpgp_quantum_guard_text_{0}.asc" -f $stamp))
    Write-Host ""
    Write-Host "Default output:" -ForegroundColor $script:UiDimSilver
    Write-Host "  $(Format-DisplayPath $defaultOut)" -ForegroundColor White
    $outPath = $defaultOut
    if (-not (Read-YesNo "Use this output path?" $true)) { $custom = (Read-Host "Output path").Trim('"'); if (-not [string]::IsNullOrWhiteSpace($custom)) { $outPath = $custom } }
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
                $savePath = (Read-Host "Output path [$defaultOut]").Trim('"')
                if ([string]::IsNullOrWhiteSpace($savePath)) { $savePath = $defaultOut }
                [System.IO.File]::WriteAllText($savePath, $plain, [System.Text.UTF8Encoding]::new($false))
                Write-Host "Saved:" -ForegroundColor $script:UiWhiteSilver
                Write-Host "  $(Format-DisplayPath $savePath)" -ForegroundColor White
            }
        } else { Write-GpgFailure -Result $result -ActionName "Text decryption" }
    } finally { Remove-Item -LiteralPath $tmpIn -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue }
    Wait-User
}

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-GradientLine -Text "  CONFIGURED OPERATOR CONSOLE" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Config file   : {0}" -f (Format-DisplayPath (Get-ConfigPathV63))) -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("PGP folder    : {0}" -f (Format-DisplayPath $script:DefaultStartFolder)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Output folder : {0}" -f (Format-DisplayPath (Get-OutputFolderV63))) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("GnuPG home    : {0}" -f $(if ([string]::IsNullOrWhiteSpace([string]$script:GpgHome)) { "default user keyring" } else { Format-DisplayPath $script:GpgHome })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  IMPORTANT FIXES IN v63" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Key recognition fix: the tool no longer ignores a generated key just because ownertrust is unknown. A local private key is enough for selection unless KeySelectableRequiresUltimateTrust is set to true in the JSON config." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "Keygen verification fix: when Kyber is selected, the script verifies the requested Kyber subkey after generation. If GnuPG produced only a classic key, the tool warns and shows the actual detected algorithms." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "Portable config fix: copied scripts no longer carry a hardcoded workplace or home path as the real default. First run creates openpgp_quantum_guard.config.json beside the script." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""

    Write-GradientLine -Text "  GnuPG KYBER MENU MAPPING" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "GnuPG key type 16 means ECC and Kyber. The script maps Kyber menu option 1 to ky768_bp256, option 2 to ky1024_bp384, option 3 to ky768_cv25519, and option 4 to ky1024_cv448." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Default profile is LOCAL_PQC_KYBER1024_X448, which creates an Ed25519 identity and requests ky1024_cv448 as the encryption subkey." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  OUTPUT ROUTING" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Encrypt, decrypt, encrypted text, and saved decrypted text now use OutputFolder from the config file. This keeps user data away from the script folder and makes the tool easier to deploy to another machine." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  SECURITY MODEL" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "The config file is for folders, GnuPG location, active fingerprint, output mode, and UI defaults. It must not contain real OpenPGP private-key passphrases. GnuPG pinentry remains responsible for private-key passphrases." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Shareable mode still hides local paths in screenshots. Private mode shows more diagnostics for troubleshooting." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  CONTROLS" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Use arrows to move, ENTER to open, N to toggle the live No More Secrets layer on the main screen, and Q to quit cleanly." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
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

function New-LeftMenuLogoRenderLinesV65 {
    param([int]$Width = 60)

    $lines = @()
    $raw = @($script:LeftMenuLogoLines)
    if ($raw.Count -eq 0) { $raw = @(Convert-LogoTextToLinesV67 -Text (Get-DefaultLeftLogoTextV67)) }

    $safeWidth = [Math]::Max(24, [int]$Width)
    $maxLogoRows = 12
    try { $maxLogoRows = [Math]::Max(8, [Math]::Min(16, [int]([Console]::WindowHeight / 2))) } catch { }
    $lines += New-V57GradientLine "  Left screen logo" -Bold
    foreach ($line in @($raw | Select-Object -First $maxLogoRows)) {
        $safe = Clip-AsciiLineV67 -Text ([string]$line) -Width ([Math]::Max(10, $safeWidth - 2))
        $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text ("  " + $safe) -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold))
    }
    if ($raw.Count -gt $maxLogoRows) {
        $lines += New-V57TextLine ("  + {0} more logo lines in external file" -f ($raw.Count - $maxLogoRows)) $script:UiDimSilver
    }
    $lines += New-V57TextLine "" $script:UiDimSilver
    return @($lines)
}

function Get-CompactMainLeftLines {
    param([string]$ModeText, [string]$GpgState)
    try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 } catch { $script:V62NmsFrame = 1 }
    $fpr = Short-Fpr $script:IdentityFingerprint
    $modeLine = ("Mode  : {0}   GnuPG: {1}" -f $ModeText, $GpgState)
    $w = 60
    $lines = @()
    $lines += @(New-LeftMenuLogoRenderLinesV65 -Width $w)
    $lines += New-V57TextLine (New-V57BoxTop $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "OpenPGP Quantum Guard" -Seed 101 -Reveal 0.78 -Selected) -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "PQC-enabled OpenPGP operations" -Seed 102 -Reveal 0.72) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57TextLine (New-V57BoxMid $w) $script:UiBorderBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text ("FPR   : {0}" -f $fpr) -Seed 103 -Reveal 0.72) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text $modeLine -Seed 104 -Reveal 0.72) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Crypto: Kyber 1024 X448 default" -Seed 105 -Reveal 0.70) -Width $w -Gradient -Bold
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "Flow  : Encrypt PQC. Decrypt auto-detect." -Seed 106 -Reveal 0.70) -Width $w -Color $script:UiSilverBlue
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "NMS   : live sentence layer" -Seed 107 -Reveal 0.64) -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-NmsSentenceGradientLineV62 -Text ("  Build {0}: external logos + boot menu" -f $script:ToolVersion) -Seed 108 -Reveal 0.70 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  Config stores logo file paths, not ASCII arrays." -Color $script:UiDimSilver -Seed 109 -Reveal 0.64
    $lines += New-NmsSentenceLineV62 -Text "  Edit the .txt logo files without touching JSON syntax." -Color $script:UiDimSilver -Seed 110 -Reveal 0.64
    return @($lines)
}

function Get-BootLogoLinesV65 {
    $raw = @($script:BootMenuLogoLines)
    if ($raw.Count -eq 0) { $raw = @(Convert-LogoTextToLinesV67 -Text (Get-DefaultBootLogoTextV67)) }
    return @($raw)
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

function Show-StartupBootScreenV51 {
    Clear-Host
    Clear-PendingConsoleInputV56
    $screenWidth = Get-V57WindowWidth
    $maxWidth = [Math]::Max(70, [Math]::Min(132, $screenWidth - 1))
    foreach ($line in @(Get-BootLogoLinesV65)) {
        $safe = Clip-AsciiLineV67 -Text ([string]$line) -Width $maxWidth
        Write-GradientFixedLineV56 -Text $safe -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold
        Start-Sleep -Milliseconds 6
    }
    Write-Host ""
    $boxWidth = [Math]::Max(78, [Math]::Min(114, $screenWidth - 4))
    $rule = "─" * ($boxWidth - 4)
    Write-Host ("  ┌{0}┐" -f $rule) -ForegroundColor $script:UiBorderBlue
    Write-BootMenuBoxLineV67 -Label "BOOT MENU" -Value ([string]$script:BootMenuTitle) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label "Operator" -Value ([string]$script:BootMenuSubtitle) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Build" -Value "v67 external-logo runtime" -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label "Config" -Value (Format-DisplayPath (Get-ConfigPathV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "PGP folder" -Value (Format-DisplayPath $script:DefaultStartFolder) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Output folder" -Value (Format-DisplayPath (Get-OutputFolderV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Key profile" -Value ([string]$script:DefaultKeyProfile) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label "Boot logo" -Value (Format-DisplayPath $script:BootLogoPath) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Left logo" -Value (Format-DisplayPath $script:LeftMenuLogoPath) -Width $boxWidth
    $gpgHomeText = if ([string]::IsNullOrWhiteSpace([string]$script:GpgHome)) { "default user keyring" } else { Format-DisplayPath $script:GpgHome }
    Write-BootMenuBoxLineV67 -Label "GnuPG home" -Value $gpgHomeText -Width $boxWidth
    Write-Host ("  └{0}┘" -f $rule) -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    $progressRow = 0
    try { $progressRow = [Console]::CursorTop } catch { $progressRow = 0 }
    for ($p = 0; $p -le 100; $p += 2) {
        Clear-PendingConsoleInputV56
        Write-BootProgressAtV57 -Row $progressRow -Percent $p -Label (Get-BootStageLabelV56 -Percent $p)
        Start-Sleep -Milliseconds 24
    }
    Write-BootProgressAtV57 -Row $progressRow -Percent 100 -Label "ready"
    try { [Console]::SetCursorPosition(0, $progressRow + 2) } catch { Write-Host "" }
    Write-GradientFixedLineV56 -Text "  ENTER continues. Edit the external logo .txt files, not the JSON, to change the art." -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    if ([bool]$script:BootWaitForEnter) { Wait-ForEnterOnlyV56 }
}

function Initialize-ActiveIdentityV44 {
    Load-ConfigV51
    Show-StartupBootScreenV51
    Write-Banner -Title "OpenPGP identity check"
    Write-V46GradientWrappedText -Text ("Config: {0}" -f (Format-DisplayPath $script:ConfigPath)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("PGP folder: {0}" -f (Format-DisplayPath $script:DefaultStartFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Output folder: {0}" -f (Format-DisplayPath $script:OutputFolder)) -Indent "  " -Width 110 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Logo files: {0} / {1}" -f (Format-DisplayPath $script:BootLogoPath), (Format-DisplayPath $script:LeftMenuLogoPath)) -Indent "  " -Width 110 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
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

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-GradientLine -Text "  V67 EXTERNAL LOGO SYSTEM" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Important: the config now stores only logo file paths. The ASCII art lives in external .txt files, so broken quotes, pipes, or missing commas in JSON cannot break the script parser." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("Boot logo file : {0}" -f (Format-DisplayPath $script:BootLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Left logo file : {0}" -f (Format-DisplayPath $script:LeftMenuLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  CONFIGURED OPERATOR CONSOLE" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Config file   : {0}" -f (Format-DisplayPath (Get-ConfigPathV63))) -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text ("PGP folder    : {0}" -f (Format-DisplayPath $script:DefaultStartFolder)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Output folder : {0}" -f (Format-DisplayPath (Get-OutputFolderV63))) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  KEYGEN DEFAULT" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Default profile is {0}. This maps to GnuPG key type 16, Kyber option 4, Kyber 1024 X448." -f $script:DefaultKeyProfile) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""

    Write-GradientLine -Text "  SECURITY MODEL" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "The config file controls paths, display logo files, active fingerprint, output mode, and keygen defaults. It must never contain real private-key passphrases." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "GnuPG pinentry remains responsible for unlocking private keys only when a cryptographic operation needs them." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-Host ""

    Write-GradientLine -Text "  EDITING NOTES" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "To change the boot or left-menu art, edit the logo .txt files directly. Keep the art narrow for best layout. The renderer hard-clips over-wide lines instead of inserting ellipsis inside ASCII art." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Wait-User
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

function New-LeftMenuLogoRenderLinesV65 {
    param([int]$Width = 60)

    $safeWidth = [Math]::Max(24, [int]$Width)
    $raw = @($script:LeftMenuLogoLines | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($raw.Count -eq 0) { $raw = @(Convert-LogoTextToLinesV67 -Text (Get-CompactLeftLogoTextV68)) }

    # Remove accidental labels from the logo file. The left panel already gives context.
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
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "NMS   : live readable sentence layer" -Seed 107 -Reveal 0.89) -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-NmsSentenceGradientLineV62 -Text ("  Build {0}: compact logo + readable NMS" -f $script:ToolVersion) -Seed 108 -Reveal 0.90 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  NMS is active on main-menu sentences." -Color $script:UiDimSilver -Seed 109 -Reveal 0.88
    $lines += New-NmsSentenceLineV62 -Text "  Oversized left logos collapse to a safe compact mark." -Color $script:UiDimSilver -Seed 110 -Reveal 0.88

    if ($windowHeight -ge 34) {
        $lines += New-V57TextLine "" $script:UiDimSilver
        $lines += New-NmsSentenceLineV62 -Text "  The truth is in the logs. The proof is in the keys." -Color $script:UiDimSilver -Seed 111 -Reveal 0.88
    }
    return @($lines)
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
    $lines += (New-MenuRenderLine -Segments @(New-GradientSegments -Text (Convert-ToNmsSentenceV62 -Text "Actions" -Seed 20 -Reveal 0.94 -Selected) -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold))
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
            $labelText = "  ▶ {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.95 -Selected)
            $lines += (New-MenuRenderLine -Text $labelText -Color $script:UiWhiteSilver -BackgroundColor $script:UiHighlightBlue)
            foreach ($h in $hintLines) {
                $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 3) -Reveal 0.94 -Selected
                $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiWhiteSilver -BackgroundColor $script:UiDeepBlue)
            }
        } else {
            $labelText = "    {0}" -f (Convert-ToNmsSentenceV62 -Text $label -Seed $seedBase -Reveal 0.90)
            $lines += (New-MenuRenderLine -Text $labelText -Color ([string]$item.Color))
            if ($ShowAllHints) {
                foreach ($h in $hintLines) {
                    $h2 = Convert-ToNmsSentenceV62 -Text $h -Seed ($seedBase + 5) -Reveal 0.88
                    $lines += (New-MenuRenderLine -Text ("    {0}" -f $h2) -Color $script:UiDimSilver)
                }
            }
        }
    }
    $lines += (New-MenuRenderLine -Text ("─" * $ruleLen) -Color $script:UiBorderBlue)
    return @($lines)
}

function Invoke-MainMenuRightPanel {
    param(
        [Parameter(Mandatory=$true)]$HeaderLines,
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0
    )
    $itemsArray = @($Items)
    if ($itemsArray.Count -eq 0) { return "Back" }
    $oldCursorVisible = $null
    $firstDraw = $true
    $lastTotalRows = 0
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }
    try {
        while ($true) {
            try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 } catch { $script:V62NmsFrame = 1 }
            $windowWidth = Get-VisibleWindowWidthV68
            $windowHeight = Get-VisibleWindowHeightV68

            if ($windowWidth -lt 105) {
                return (Invoke-ConsoleMenu -Title "Main menu" -HeaderLines $HeaderLines -Items $itemsArray -Layout "Vertical" -SelectedIndex $SelectedIndex)
            }

            $leftWidth = if ($windowWidth -ge 150) { 64 } elseif ($windowWidth -ge 125) { 58 } else { 54 }
            $rightX = $leftWidth + 2
            $rightWidth = [Math]::Max(44, $windowWidth - $rightX - 2)
            $showAllHints = ($windowHeight -ge 34)

            $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
            $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
            $left = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
            $right = @(New-MainMenuRightLines -Items $itemsArray -SelectedIndex $SelectedIndex -PanelWidth $rightWidth -ShowAllHints:$showAllHints)
            $footerRow = [Math]::Max($left.Count, $right.Count) + 1
            $totalRows = $footerRow + 2

            if ($footerRow -gt ($windowHeight - 3)) {
                $showAllHints = $false
                $right = @(New-MainMenuRightLines -Items $itemsArray -SelectedIndex $SelectedIndex -PanelWidth $rightWidth -ShowAllHints:$false)
                $footerRow = [Math]::Max($left.Count, $right.Count) + 1
                $totalRows = $footerRow + 2
            }

            if ($firstDraw) { Clear-Host; $firstDraw = $false } else { try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host } }
            $emptyLeft = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            $emptyRight = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            for ($row = 0; $row -lt $totalRows; $row++) {
                $lineLeft = if ($row -lt $left.Count) { $left[$row] } else { $emptyLeft }
                $lineRight = if ($row -lt $right.Count) { $right[$row] } else { $emptyRight }
                Write-MenuRenderLineAt -Line $lineLeft -X 0 -Y $row -Width $leftWidth
                Write-MenuRenderLineAt -Line $lineRight -X $rightX -Y $row -Width $rightWidth
            }
            if ($lastTotalRows -gt $totalRows) {
                $blank = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
                for ($row = $totalRows; $row -lt $lastTotalRows; $row++) { Write-MenuRenderLineAt -Line $blank -X 0 -Y $row -Width ([Math]::Max(20, $windowWidth - 1)) }
            }
            $lastTotalRows = $totalRows
            $footerBase = if ($showAllHints) { "Use arrows. ENTER opens. N toggles readable NMS. Q exits." } else { "Use arrows. ENTER opens. N toggles NMS. Q exits. Hints compacted for screen height." }
            $footerText = Convert-ToNmsSentenceV62 -Text $footerBase -Seed 777 -Reveal 0.92
            $footer = (New-MenuRenderLine -Text $footerText -Color $script:UiDimBone)
            Write-MenuRenderLineAt -Line $footer -X 0 -Y $footerRow -Width ([Math]::Min($windowWidth - 1, 126))
            try { [Console]::SetCursorPosition(0, $footerRow + 1) } catch { }

            $key = $null
            try {
                if ([bool]$script:LiveNmsMenuEnabled) {
                    $until = (Get-Date).AddMilliseconds([int]$script:V62NmsFrameDelayMs)
                    while ((Get-Date) -lt $until) {
                        if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true); break }
                        Start-Sleep -Milliseconds 12
                    }
                    if ($null -eq $key) { continue }
                } else { $key = [Console]::ReadKey($true) }
            } catch { return (Invoke-ConsoleMenu -Title "Main menu" -HeaderLines $HeaderLines -Items $itemsArray -Layout "Vertical" -SelectedIndex $SelectedIndex) }
            if (Test-BlockedControlQuitKey -KeyInfo $key) { Write-QuitGuardNotice; $firstDraw = $true; continue }
            switch ($key.Key) {
                "LeftArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "UpArrow"    { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "RightArrow" { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "DownArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "Enter"      { return [string]$itemsArray[$SelectedIndex].Value }
                "Escape"     { continue }
                default {
                    $ch = [string]$key.KeyChar
                    if ($ch -eq "q" -or $ch -eq "Q") { return "Quit" }
                    if ($ch -eq "n" -or $ch -eq "N") { $script:LiveNmsMenuEnabled = -not [bool]$script:LiveNmsMenuEnabled; Save-Config; continue }
                    if (-not [string]::IsNullOrWhiteSpace($ch)) {
                        foreach ($item in $itemsArray) {
                            if ($ch -eq [string]$item.Shortcut) { return [string]$item.Value }
                            if ($ch.ToLowerInvariant() -eq ([string]$item.Shortcut).ToLowerInvariant()) { return [string]$item.Value }
                        }
                    }
                }
            }
        }
    } finally { try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { } }
}

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-GradientLine -Text "  V68 RESPONSIVE LOGO AND READABLE NMS" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Important: the left-menu renderer now protects the layout. If the external logo is too wide or too tall, the main menu uses a compact safe logo instead of clipping broken ASCII art." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "NMS is still live across the main menu sentences, but v68 keeps most characters readable and moves a thin encrypted band across the text." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  EXTERNAL LOGO FILES" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Boot logo file : {0}" -f (Format-DisplayPath $script:BootLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Left logo file : {0}" -f (Format-DisplayPath $script:LeftMenuLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Tip: use a compact left logo, around 28-42 characters wide and 3-6 lines high. Large figlet logos are better for the boot logo, not the left panel." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  KEYGEN DEFAULT" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Default profile is {0}. This maps to GnuPG key type 16, Kyber option 4, Kyber 1024 X448." -f $script:DefaultKeyProfile) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  SECURITY MODEL" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "The config controls paths, display logo files, active fingerprint, output mode, and keygen defaults. It must never contain real private-key passphrases." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "GnuPG pinentry remains responsible for unlocking private keys only when a cryptographic operation needs them." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Wait-User
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
    $lines += New-V57BoxLine -Text (Convert-ToNmsSentenceV62 -Text "NMS   : live readable sentence layer" -Seed 107 -Reveal 0.89) -Width $w -Gradient -Bold
    $lines += New-V57TextLine (New-V57BoxBottom $w) $script:UiBorderBlue
    $lines += New-V57TextLine "" $script:UiDimSilver
    $lines += New-NmsSentenceGradientLineV62 -Text ("  Build {0}: portable configuration" -f $script:ToolVersion) -Seed 108 -Reveal 0.90 -Bold
    $lines += New-NmsSentenceLineV62 -Text "  The original ANSI header is the left-menu default again." -Color $script:UiDimSilver -Seed 109 -Reveal 0.88
    $lines += New-NmsSentenceLineV62 -Text "  External logo files remain available as fallback art." -Color $script:UiDimSilver -Seed 110 -Reveal 0.88

    if ($windowHeight -ge 34) {
        $lines += New-V57TextLine "" $script:UiDimSilver
        $lines += New-NmsSentenceLineV62 -Text "  The truth is in the logs. The proof is in the keys." -Color $script:UiDimSilver -Seed 111 -Reveal 0.88
    }
    return @($lines)
}

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-GradientLine -Text "  V69 ANSI LOGO RESTORE" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Important: the original CustomAnsiHeader logo is restored as the left-menu default. External logo files are still supported, but they no longer replace the ANSI header unless ShowCustomAnsiHeader is disabled." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "NMS remains live across the main-menu sentences, with a readable moving band instead of full-line scrambling." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  LOGO SOURCES" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Built-in ANSI header : {0}" -f $(if (Test-CustomAnsiHeaderEnabled) { "enabled" } else { "disabled" })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Boot logo file       : {0}" -f (Format-DisplayPath $script:BootLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Left logo fallback   : {0}" -f (Format-DisplayPath $script:LeftMenuLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Rule: keep the ANSI header for the main left panel. Use the external left logo only when you intentionally disable the built-in header or want fallback art." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  KEYGEN DEFAULT" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Default profile is {0}. This maps to GnuPG key type 16, Kyber option 4, Kyber 1024 X448." -f $script:DefaultKeyProfile) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  SECURITY MODEL" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "The config controls paths, display logo files, active fingerprint, output mode, and keygen defaults. It must never contain real private-key passphrases." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "GnuPG pinentry remains responsible for unlocking private keys only when a cryptographic operation needs them." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Wait-User
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

function Show-AboutSection {
    Write-Banner -Title "About OpenPGP Quantum Guard"
    Write-GradientLine -Text "  V70 SETUP DOCTOR" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "New in v70: Setup Doctor checks the config file, PGP folder, output folder, GnuPG path, GnuPG home, active key, selectable keys, trust mode, and PQC capability hints." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "This is designed for workplace handoff: run the doctor first, confirm the config paths, confirm GnuPG sees the private key, then generate or choose an active key." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  LOGO SOURCES" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Built-in ANSI header : {0}" -f $(if (Test-CustomAnsiHeaderEnabled) { "enabled" } else { "disabled" })) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Boot logo file       : {0}" -f (Format-DisplayPath $script:BootLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Left logo fallback   : {0}" -f (Format-DisplayPath $script:LeftMenuLogoPath)) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "Rule: the original CustomAnsiHeader stays the main left-panel logo. External left logo is fallback art only unless the built-in header is disabled." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  KEYGEN DEFAULT" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text ("Default profile is {0}. This maps to GnuPG key type 16, Kyber option 4, Kyber 1024 X448." -f $script:DefaultKeyProfile) -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd -Bold
    Write-V46GradientWrappedText -Text "If quick-add-key does not create a Kyber subkey on a machine, use Generate key, option 7, GnuPG built-in wizard, then select ECC and Kyber and Kyber option 4." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Write-Host ""
    Write-GradientLine -Text "  SECURITY MODEL" -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "The config controls paths, display logo files, active fingerprint, output mode, and keygen defaults. It must never contain real private-key passphrases." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Write-V46GradientWrappedText -Text "GnuPG pinentry remains responsible for unlocking private keys only when a cryptographic operation needs them." -Indent "  " -Width 112 -StartRgb $script:GradientSilverStart -EndRgb $script:GradientBlueEnd
    Wait-User
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
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Close the tool cleanly." -Color $script:UiWhiteSilver -Shortcut "q")
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
$script:ToolVersion = "1.0.0-rc1"
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

function Invoke-MainMenuRightPanel {
    param(
        [Parameter(Mandatory=$true)]$HeaderLines,
        [Parameter(Mandatory=$true)]$Items,
        [int]$SelectedIndex = 0
    )
    $itemsArray = @($Items)
    if ($itemsArray.Count -eq 0) { return "Back" }
    $oldCursorVisible = $null
    $firstDraw = $true
    $lastTotalRows = 0
    try { $oldCursorVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { }
    try {
        while ($true) {
            try { $script:V62NmsFrame = [int]$script:V62NmsFrame + 1 } catch { $script:V62NmsFrame = 1 }
            $windowWidth = Get-VisibleWindowWidthV68
            $windowHeight = Get-VisibleWindowHeightV68

            if ($windowWidth -lt 105) {
                return (Invoke-ConsoleMenu -Title "Main menu" -HeaderLines $HeaderLines -Items $itemsArray -Layout "Vertical" -SelectedIndex $SelectedIndex)
            }

            $leftWidth = if ($windowWidth -ge 150) { 64 } elseif ($windowWidth -ge 125) { 58 } else { 54 }
            $rightX = $leftWidth + 2
            $rightWidth = [Math]::Max(44, $windowWidth - $rightX - 2)
            $showAllHints = ($windowHeight -ge 36)

            $modeText = if (Test-ShareableOutput) { "Shareable" } else { "Private" }
            $gpgState = if (Test-ShareableOutput) { "hidden" } else { "ready" }
            $left = @(Get-CompactMainLeftLines -ModeText $modeText -GpgState $gpgState)
            $right = @(New-MainMenuRightLines -Items $itemsArray -SelectedIndex $SelectedIndex -PanelWidth $rightWidth -ShowAllHints:$showAllHints)
            $footerRow = [Math]::Max($left.Count, $right.Count) + 1
            $totalRows = $footerRow + 2

            if ($footerRow -gt ($windowHeight - 3)) {
                $showAllHints = $false
                $right = @(New-MainMenuRightLines -Items $itemsArray -SelectedIndex $SelectedIndex -PanelWidth $rightWidth -ShowAllHints:$false)
                $footerRow = [Math]::Max($left.Count, $right.Count) + 1
                $totalRows = $footerRow + 2
            }

            if ($firstDraw) { Clear-Host; $firstDraw = $false } else { try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host } }
            $emptyLeft = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            $emptyRight = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
            for ($row = 0; $row -lt $totalRows; $row++) {
                $lineLeft = if ($row -lt $left.Count) { $left[$row] } else { $emptyLeft }
                $lineRight = if ($row -lt $right.Count) { $right[$row] } else { $emptyRight }
                Write-MenuRenderLineAt -Line $lineLeft -X 0 -Y $row -Width $leftWidth
                Write-MenuRenderLineAt -Line $lineRight -X $rightX -Y $row -Width $rightWidth
            }
            if ($lastTotalRows -gt $totalRows) {
                $blank = (New-MenuRenderLine -Text "" -Color $script:UiDimSilver)
                for ($row = $totalRows; $row -lt $lastTotalRows; $row++) { Write-MenuRenderLineAt -Line $blank -X 0 -Y $row -Width ([Math]::Max(20, $windowWidth - 1)) }
            }
            $lastTotalRows = $totalRows
            $footerBase = if ($showAllHints) { "Use arrows. ENTER opens. N toggles smooth live NMS. Q exits." } else { "Use arrows. ENTER opens. N toggles NMS. Q exits. Hints compacted." }
            $footerText = Convert-ToNmsSentenceV62 -Text $footerBase -Seed 777 -Reveal 0.83
            $footer = (New-MenuRenderLine -Text $footerText -Color $script:UiDimBone)
            Write-MenuRenderLineAt -Line $footer -X 0 -Y $footerRow -Width ([Math]::Min($windowWidth - 1, 126))
            try { [Console]::SetCursorPosition(0, $footerRow + 1) } catch { }

            $key = $null
            try {
                if ([bool]$script:LiveNmsMenuEnabled) {
                    $until = (Get-Date).AddMilliseconds([int]$script:V62NmsFrameDelayMs)
                    while ((Get-Date) -lt $until) {
                        if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true); break }
                        Start-Sleep -Milliseconds 5
                    }
                    if ($null -eq $key) { continue }
                } else { $key = [Console]::ReadKey($true) }
            } catch { return (Invoke-ConsoleMenu -Title "Main menu" -HeaderLines $HeaderLines -Items $itemsArray -Layout "Vertical" -SelectedIndex $SelectedIndex) }
            if (Test-BlockedControlQuitKey -KeyInfo $key) { Write-QuitGuardNotice; $firstDraw = $true; continue }
            switch ($key.Key) {
                "LeftArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "UpArrow"    { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta -1; Clear-PendingConsoleKeys }
                "RightArrow" { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "DownArrow"  { $SelectedIndex = Move-MenuIndex -Current $SelectedIndex -Count $itemsArray.Count -Delta 1; Clear-PendingConsoleKeys }
                "Enter"      { return [string]$itemsArray[$SelectedIndex].Value }
                "Escape"     { continue }
                default {
                    $ch = [string]$key.KeyChar
                    if ($ch -eq "q" -or $ch -eq "Q") { return "Quit" }
                    if ($ch -eq "n" -or $ch -eq "N") { $script:LiveNmsMenuEnabled = -not [bool]$script:LiveNmsMenuEnabled; Save-Config; continue }
                    if (-not [string]::IsNullOrWhiteSpace($ch)) {
                        foreach ($item in $itemsArray) {
                            if ($ch -eq [string]$item.Shortcut) { return [string]$item.Value }
                            if ($ch.ToLowerInvariant() -eq ([string]$item.Shortcut).ToLowerInvariant()) { return [string]$item.Value }
                        }
                    }
                }
            }
        }
    } finally { try { if ($null -ne $oldCursorVisible) { [Console]::CursorVisible = [bool]$oldCursorVisible } } catch { } }
}

function Show-StartupBootScreenV51 {
    Clear-Host
    Clear-PendingConsoleInputV56
    $screenWidth = Get-V57WindowWidth
    $maxWidth = [Math]::Max(70, [Math]::Min(138, $screenWidth - 1))
    foreach ($line in @(Get-BootLogoLinesV65)) {
        $safe = Clip-AsciiLineV67 -Text ([string]$line) -Width $maxWidth
        Write-GradientFixedLineV56 -Text $safe -StartRgb $script:GradientBlueStart -EndRgb $script:GradientBlueEnd -Bold
        Start-Sleep -Milliseconds 4
    }
    Write-Host ""
    $boxWidth = [Math]::Max(78, [Math]::Min(114, $screenWidth - 4))
    $rule = "─" * ($boxWidth - 4)
    Write-Host ("  ┌{0}┐" -f $rule) -ForegroundColor $script:UiBorderBlue
    Write-BootMenuBoxLineV67 -Label "BOOT MENU" -Value ([string]$script:BootMenuTitle) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label "Operator" -Value ([string]$script:BootMenuSubtitle) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Build" -Value ([string]$script:ToolVersion) -Width $boxWidth -Highlight
    Write-BootMenuBoxLineV67 -Label "Config" -Value (Format-DisplayPath (Get-ConfigPathV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "PGP folder" -Value (Format-DisplayPath $script:DefaultStartFolder) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Output folder" -Value (Format-DisplayPath (Get-OutputFolderV63)) -Width $boxWidth
    Write-BootMenuBoxLineV67 -Label "Key profile" -Value ([string]$script:DefaultKeyProfile) -Width $boxWidth -Highlight
    Write-Host ("  └{0}┘" -f $rule) -ForegroundColor $script:UiBorderBlue
    Write-Host ""

    $progressRow = 0
    try { $progressRow = [Console]::CursorTop } catch { $progressRow = 0 }
    foreach ($p in @(0, 12, 25, 37, 51, 66, 78, 90, 100)) {
        Clear-PendingConsoleInputV56
        Write-BootProgressAtV57 -Row $progressRow -Percent $p -Label (Get-BootStageLabelV56 -Percent $p)
        Start-Sleep -Milliseconds 70
    }
    Write-BootProgressAtV57 -Row $progressRow -Percent 100 -Label "ready"
    try { [Console]::SetCursorPosition(0, $progressRow + 2) } catch { Write-Host "" }
    Write-GradientFixedLineV56 -Text "  Boot complete. Press ENTER to continue to identity selection." -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    if ([bool]$script:BootWaitForEnter) { Wait-ForEnterOnlyV56 } else { Start-Sleep -Milliseconds 450 }
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
    Write-V46GradientWrappedText -Text "Press ENTER to return." -Indent "  " -Width 112 -StartRgb $script:GradientLabelStart -EndRgb $script:GradientBlueEnd -Bold
    Wait-User
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
            (New-ConsoleMenuItem -Label "Choose Different Key" -Value "CycleKey" -Hint "Switch to another local private key recognized by this GnuPG home." -Color $script:UiWhiteSilver -Shortcut "6"),
            (New-ConsoleMenuItem -Label "Generate new key" -Value "GenerateKey" -Hint "Create email-compatible, PQC, or manually mixed identities." -Color $script:UiSilverBlue -Shortcut "7"),
            (New-ConsoleMenuItem -Label "Export keys" -Value "Export" -Hint "Export public certificates or protected secret material." -Color $script:UiWhiteSilver -Shortcut "8"),
            (New-ConsoleMenuItem -Label "Setup doctor" -Value "Doctor" -Hint "Check config, folders, GnuPG, key inventory, and PQC hints." -Color $script:UiWhiteSilver -Shortcut "d"),
            (New-ConsoleMenuItem -Label "About" -Value "About" -Hint "Project scope, PQC notes, interface behavior, and security model." -Color $script:UiSilverBlue -Shortcut "9"),
            (New-ConsoleMenuItem -Label "Admin settings" -Value "Admin" -Hint "Safety-confirmed settings, output mode, identity administration and defaults." -Color $script:UiMidBlue -Shortcut "0"),
            (New-ConsoleMenuItem -Label "Quit" -Value "Quit" -Hint "Close the tool cleanly." -Color $script:UiWhiteSilver -Shortcut "q")
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


try {
    Install-QuitGuard
    Initialize-ActiveIdentityV44
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
