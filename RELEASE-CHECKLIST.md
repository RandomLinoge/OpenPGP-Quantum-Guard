# Release checklist

- [ ] Copy only reviewed source and example configuration files.
- [ ] Run `tests/StaticChecks.ps1` in PowerShell 7.
- [ ] Run Gitleaks and TruffleHog against the final repository and Git history.
- [ ] Confirm no real fingerprint, UID, email, username, home path, or GnuPG home remains.
- [ ] Confirm the example placeholder produces interactive key selection.
- [ ] Test encryption and decryption with a disposable ML-KEM/Kyber key.
- [ ] Confirm `RequirePqcEncryption=true` rejects a classic-only recipient.
- [ ] Review the diff, create a clean repository, and commit only sanitized files.
- [ ] Enable GitHub secret scanning, Dependabot, and branch protection.
