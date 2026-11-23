# OpenPGP Quantum Guard, non-interactive CLI preview

The existing `src/OpenPGP-Quantum-Guard.ps1` TUI remains unchanged. Run this companion entry point from the repository root. Requires Windows PowerShell 5.1 or PowerShell 7 and a GnuPG installation. The standalone CLI reuses **GnuPG as the crypto engine**, but is not yet a refactoring into shared TUI/CLI application functions.

```powershell
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Doctor -Json
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Algorithms -Json
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Inspect -Json
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Inspect -Fingerprint 'FULL_40_OR_64_HEX_FINGERPRINT' -Json
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Encrypt -Fingerprint 'FULL_40_OR_64_HEX_FINGERPRINT' -InputPath '.\sample.txt' -OutputPath '.\sample.gpg' -RequirePqc -Json
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Decrypt -InputPath '.\sample.gpg' -OutputPath '.\recovered.txt' -Json
```

`-GpgPath`, `-GpgHome`, and `-ConfigPath` override the local configuration. The default configuration path is `src/openpgp_quantum_guard.config.json`. Omission of configuration is supported when `gpg` is available in `PATH`. The CLI never changes the TUI's configuration.

## Contract

A successful command exits `0`. Invalid input exits `2`; missing GnuPG or missing configured home exits `3`; key/policy validation exits `4`; GnuPG or other operational failures exit `5`. `-Json` writes exactly one result object to stdout with `schema`, `command`, `success`, `code`, `message` and `data` fields. No ANSI or animated output is emitted. Do not treat `Doctor.pqcVersionCandidate` as cryptographic proof of a PQC-capable build; the CLI intentionally leaves `pqcCapabilityVerified=false`.

Encryption requires an explicit full recipient fingerprint and will not silently choose a default identity. Existing output paths are refused, and incomplete GnuPG outputs are removed on failure. No secret-key passphrases are read from CLI flags. GnuPG runs with `--batch --no-tty`, so encrypted data requiring private key unlocking may fail unless the agent is already unlocked. `-RequirePqc` is passed directly to GnuPG and must be supported by the installed build. GnuPG's own trust checks are retained.

**Research preview limitations:** No independent security audit. This CLI uses its own GnuPG invocation layer instead of the existing TUI's internal functions. The current `Encrypt`/`Decrypt` commands do not cryptographically verify packet algorithms after operation. For evidence-grade PQC claims, independently inspect encrypted packets and run negative tests with a classical-only recipient. CLI output intentionally omits absolute filesystem locations, but `Inspect` includes UID strings, which may be personally identifying.

## Validation

Run the static checks from a Windows PowerShell environment:

```powershell
& .\tests\Cli.StaticChecks.ps1
```

Integration tests require a disposable GnuPG home with preloaded test keys. Do not run integration tests against a personal default GnuPG home.

## Windows PowerShell 5.1 compatibility

All GnuPG home-directory locals use `$gpgHomeDirectory` to avoid overriding PowerShell's protected `$HOME` automatic variable. The static check rejects a regression.

## v1.2: hybrid classification and policy errors

`Inspect -Json` now enriches subkeys with `fingerprint`, `algorithmName`, `pqcHybrid`, and `classificationSource`. The original numeric `algorithm` remains for compatibility. `pqcClassification` reports `hybrid-reported-by-gpg`, `no-hybrid-reported`, or `partial`. These names are derived from GnuPG's human-readable listing and **do not by themselves constitute a cryptographic proof**. A missing/unrecognized label is represented as `null` (unknown), never guessed from numeric algorithm 8. The classifier currently recognizes GnuPG 2.5's `ky768_cv25519`, `ky768_bp256`, `ky1024_cv448`, and `ky1024_bp384` subkey labels.

`Encrypt -RequirePqc` now returns JSON code `PQC_POLICY_REJECTED` and process exit `4` for a clearly classical-only RSA encryption primary key or a recipient whose encryption subkeys were **all positively classified as non-hybrid**. All other uncertain cases are passed to GnuPG with `--require-pqc-encryption`, whose failure continues to return generic code `GPG_FAILED` and exit `5`. This conservative classification avoids claiming that expiration, trust, or missing keys constitute a demonstrated policy rejection. The GnuPG policy flag remains mandatory even when the preflight allows an attempt.

Run the v1.2 tests against a disposable keyring with one `ky768_cv25519` recipient and one valid RSA-only encryption recipient. Tests produce data only in a fresh temporary directory and remove their own artifacts:

```powershell
& .\tests\Cli.StaticChecks.ps1
& .\tests\Cli.IntegrationTests.ps1 -GpgHome 'D:\code\OpenPGP-Quantum-Guard\.lab\gnupg' `
  -HybridFingerprint 'FULL_HYBRID_PRIMARY_FINGERPRINT' `
  -ClassicalFingerprint 'FULL_RSA_PRIMARY_FINGERPRINT'
```

The integration suite is opt-in; it may require an unlocked GnuPG agent for decryption. The RSA control key must not be expired. Never commit or package `.lab` or any secret key material. This patch contains only source, tests, and documentation; the original interactive entry point is untouched.

## v1.2.1: PowerShell 5.1 test harness fix

The integration harness now translates its controlled command argument list into a named-parameter hashtable before calling the CLI (`& $cli @named`). This fixes the PowerShell 5.1 `A positional parameter cannot be found that accepts argument '-GpgHome'` failure. The cryptographic CLI and TUI files are unchanged from v1.2.

## v1.3: built-in usage and command help

Help is available without GnuPG installed or an initialized keyring. The help
branch runs before any cryptographic or filesystem operations. Both `-Help`
(the native PowerShell switch) and `--help` (the compatibility alias) are
accepted, and a missing command prints general usage instead of prompting.

```powershell
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 --help
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Encrypt --help
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Decrypt -Help
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 Help
& .\src\OpenPGP-Quantum-Guard.Cli.ps1 --help -Json
```

Help exits `0`. The default help screen includes commands, shared flags,
security guidance, examples and documented process exit codes. In JSON mode,
help emits one schema-compatible object.

### Validate help on Windows PowerShell 5.1

```powershell
& .\tests\Cli.HelpTests.ps1
```

### Windows PowerShell 5.1 help

```powershell
.\src\OpenPGP-Quantum-Guard.Cli.ps1 --help
.\src\OpenPGP-Quantum-Guard.Cli.ps1 Encrypt --help
.\src\OpenPGP-Quantum-Guard.Cli.ps1 -Help -Json
```

The literal `--help` token is recognized before command validation, including
when PowerShell binds it as positional text rather than a switch.
