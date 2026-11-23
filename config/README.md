# Configuration and placeholders

This directory is the only place you need to inspect before a local test.

1. Copy `openpgp_quantum_guard.config.example.json` into `../src/`.
2. Rename the copy to `openpgp_quantum_guard.config.json`.
3. Replace `<OPENPGP_FINGERPRINT>` or set it to an empty string for interactive key selection.
4. Replace the example UID hint or set it to an empty string.
5. Set `GpgPath` or `GpgHome` only when the normal GnuPG defaults are unsuitable.

Relative paths are resolved for a portable checkout. Do not add passphrases,
private keys, exported secret-key blocks, tokens, or personal workstation paths.

## Release candidate settings

`Version` is the configuration marker written by the TUI (`v67`). The application reports its build separately as `1.1.0-rc6`.

The example enables both `EnableLiveNmsMenu` and `EnableNoMoreSecretsEffect` to match a fresh TUI configuration. Press **N** in a menu to change the setting. Set `BootWaitForEnter` to `false` to advance from the completed boot screen automatically.

The two ANSI artwork files shipped in `src/` are application assets. Keep `BootLogoPath` and `LeftMenuLogoPath` for the configurable text artwork. Apply changes to a fresh example copy when testing defaults. Keep your existing local configuration if it already contains your key selection or folder settings.
