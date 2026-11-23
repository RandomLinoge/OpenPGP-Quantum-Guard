# Threat model

## Protected assets

- OpenPGP private keys and passphrases.
- Plaintext input and decrypted output.
- Recipient selection and active-key configuration.
- Integrity of the selected GnuPG executable.

## Trust boundaries

- The local GnuPG binary and its libraries are trusted cryptographic dependencies.
- GnuPG pinentry is trusted to collect key passphrases.
- The JSON configuration is untrusted operator input and must contain no secret material.
- Shareable output is designed for demonstrations, but must still be reviewed before publication.

## Principal threats

- Executable substitution through `PATH` or a modified configured path.
- Encryption to the wrong key or classic-only subkey.
- Downgrade through disabling PQC enforcement.
- Plaintext recovery from temporary files, terminal transcripts, or generated output.
- Accidental secret-key export.
- Misleading interoperability claims for experimental OpenPGP PQC packets.

## Controls

- Exact full-fingerprint and exact-subkey selection.
- Optional `--require-pqc-encryption` enforcement.
- GnuPG version and capability diagnostics.
- Explicit confirmation for secret exports.
- Repository-relative defaults and ignored local configuration.
- Negative tests for private material and machine-specific paths.

## Console and automation

| Surface | Failure mode | Mitigation or verification |
|---|---|---|
| Interactive prompts | A control key submits a default answer or terminates the operator session. | Exercise the subkey confirmation and multiline prompts separately. Verify that cancellation discards partial input before GnuPG runs. |
| CLI and CI runners | Command arguments, transcripts, logs, or uploaded artifacts disclose plaintext, identity details, or local paths. | Use a disposable GnuPG home for tests. Review both output streams and retained artifacts. Keep secrets out of command arguments. |
| Release contents | A local keyring, backup script, recording, or test export is staged with the release. | Inspect the exact staged paths and outgoing commits, including binary assets and test fixtures. |

The NMS animation, rain, and on-screen meters are presentation features. Evaluate recipient selection and PQC enforcement from the key selection and GnuPG operation results.
