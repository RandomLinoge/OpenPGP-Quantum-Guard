# Configuration and placeholders

This directory is the only place you need to inspect before a local test.

1. Copy `openpgp_quantum_guard.config.example.json` into `../src/`.
2. Rename the copy to `openpgp_quantum_guard.config.json`.
3. Replace `<OPENPGP_FINGERPRINT>` or set it to an empty string for interactive key selection.
4. Replace the example UID hint or set it to an empty string.
5. Set `GpgPath` or `GpgHome` only when the normal GnuPG defaults are unsuitable.

Relative paths are resolved for a portable checkout. Do not add passphrases,
private keys, exported secret-key blocks, tokens, or personal workstation paths.
