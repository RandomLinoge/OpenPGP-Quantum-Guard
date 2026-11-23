# OpenPGP Quantum Guard v41: Boot foreground compositor

This is a focused fix for the boot text corruption shown in the November 23 screenshot and pasted terminal dump. **It does not assert a successful Windows Terminal visual test.**

The previous fixes concentrated on boot vs. exit mode and wrapped text writers multiple times. Those safeguards were not registered consistently in the underlying rain foreground occupancy map. This version uses the source of each boot element itself as the authority for foreground character positions.

## Changes

- `Write-BootMenuBoxLineV67`: registers the actual rendered label/value span and both vertical dividers. Allows rain in unused space beyond the displayed value. Protects the border glyphs.
- `Write-BootProgressAtV57`: reserves precisely the progress text + gradient bar + percentage and a small margin, **before** painting. Removes stale rain history in that span.
- `Write-GradientFixedLineV56`: reserves the entire exact completion sentence, including spaces, before painting it.
- Adds all registered cells to the persistent v31 foreground-glyph set, so later `Sync-OqgV31BootForeground` passes do not misclassify them as background.
- No modifications to cryptographic functions, configuration, NMS, or main-menu rain.

The information rows protect internal word spaces but permit rain after each actual value. The final sentence and progress meter protect their entire visible span. This intentionally reserves some blank cells *between* those two foreground elements; the old 132-column black background is not introduced.

## Install

Extract the two PowerShell files at the repository root, alongside `src`:

```powershell
& '.\Install-Oqg-Boot-Foreground-v41.ps1' -PreviewOnly
& '.\Install-Oqg-Boot-Foreground-v41.ps1'
& '.\src\OpenPGP-Quantum-Guard.ps1'
```

The installer runs a PowerShell parser check and a mask/history **unit test**, creates a `.pre-v41-*.bak` backup, and writes PowerShell 5.1-compatible UTF-8 with BOM. Preview writes nothing.

If the preview fails because the current source differs from the v37+ reference functions, do **not** bypass validation. Supply the actual current `src/OpenPGP-Quantum-Guard.ps1` (remove sensitive material first) so we can reconcile it.

**Known limitations:** This package has not been run under native Windows PowerShell 5.1/Windows Terminal. Static and simulated checks are not equivalent to checking a live terminal recording. It is also not a general-purpose layering solution; it protects the boot elements named above while preserving the existing rain engine.
