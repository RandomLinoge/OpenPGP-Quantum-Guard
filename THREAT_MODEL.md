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
