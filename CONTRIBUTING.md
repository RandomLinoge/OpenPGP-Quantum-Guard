# Contributing

Use disposable keys and synthetic identities in tests. Never commit a GnuPG home, private key, revocation certificate, real fingerprint, personal path, or generated confidential output.

Changes should pass `tests/StaticChecks.ps1`, preserve Windows PowerShell compatibility, document cryptographic claims, and include a negative test for security-sensitive behavior.
