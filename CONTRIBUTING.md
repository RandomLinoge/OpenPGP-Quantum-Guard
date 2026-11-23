# Contributing

Use disposable keys and synthetic identities in tests. Never commit a GnuPG home, private key, revocation certificate, real fingerprint, personal path, or generated confidential output.

Changes should pass `tests/StaticChecks.ps1`, preserve Windows PowerShell compatibility, document cryptographic claims, and include a negative test for security-sensitive behavior.

## Console and CLI changes

For TUI input changes, describe the starting screen, keys pressed, and expected screen afterward. Exercise the compact menu as well as the full-width menu when changing shared controls. For CLI changes, include a runnable example using synthetic inputs and test both successful invocation and failure handling.

Stage release files by path. Review the staged diff and actual images or recordings before submission. Keep local configuration, keyrings, generated exports, and installer backups outside the commit.
