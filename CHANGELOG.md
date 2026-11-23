# Changelog

## Unreleased

### 1.1.0-rc6 release candidate

- Added a companion PowerShell CLI entry point and CLI help, static, and integration test scripts to the proposed release.
- Updated the TUI boot logo to target a 2.5-second reveal. The stage label and progress bar repaint together, and rain flows through unused screen space.
- Unified the **N** hotkey and **Admin settings → Menu reveal**. Switching NMS off repaints readable menu text.
- Updated interactive prompts to handle Ctrl+C, Ctrl+Q, and Ctrl+Z. Ctrl+C at multiline text entry discards the current entry. The main menu provides the explicit Quit action.
- Removed superseded rendering helpers and hardcoded operator details from the console source.

## 1.0.0-rc1

- Removed workstation-specific paths and historical fingerprint residue.
- Centralized operator configuration in one JSON file.
- Repaired active-key selection damaged by earlier blanket redaction.
- Removed obsolete embedded logo generations.
- Added GnuPG PQC enforcement through `--require-pqc-encryption`.
- Added repository documentation, security guidance, and static checks.
