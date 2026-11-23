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

## Console and CLI release candidate

- [ ] From a clean checkout of the proposed release commit, confirm both PowerShell entry points, the referenced ANSI logos, and the CLI test files are present.
- [ ] Run the CLI help, static, and integration checks with their documented prerequisites. Use a disposable GnuPG home. Record runtime versions, results, and skipped checks.
- [ ] In Windows Terminal, check the 2.5-second logo reveal, changing progress labels, rain around foreground text, and transition to identity selection.
- [ ] Press **N** twice and use **Admin settings → Menu reveal**. Verify that disabling NMS restores readable text and enabling it resumes animation without an extra Enter prompt.
- [ ] At the recommended-subkey confirmation, press **Ctrl+C**, **Ctrl+Q**, and **Ctrl+Z** individually. Verify the prompt retains the typed answer and stays open. At a multiline prompt, verify Ctrl+C discards the entry, and that a fresh entry ending in `.END` submits normally.
- [ ] Confirm selecting **Quit** from the main menu exits cleanly.
- [ ] Inspect the release diff against the intended base, including author and committer metadata, CLI fixtures, logos, and documentation. Exclude local keyrings, configuration, recordings, exports, and backup scripts.
