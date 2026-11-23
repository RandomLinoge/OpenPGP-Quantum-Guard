# Compatibility

| Profile | Role | Expected compatibility |
|---|---|---|
| `ky1024_cv448` | Strongest local composite PQC profile | GnuPG builds supporting the corresponding Kyber/ML-KEM composite algorithm |
| `ky768_cv25519` | Balanced composite PQC profile | Compatible GnuPG PQC builds |
| `ky768_bp256` | GnuPG composite alternative | Compatible GnuPG PQC builds |
| `cv25519` | Classic encryption | Broad contemporary OpenPGP compatibility |

PQC algorithm support in a local executable does not prove compatibility with email providers, keyservers, browser extensions, or other OpenPGP implementations. Test export, import, encryption, decryption, and packet preservation with every intended peer.

## Interface verification

| Interface | What to record for a compatibility result |
|---|---|
| Interactive TUI | Windows version, PowerShell edition and version, terminal host, window size, and observed keyboard behavior. Exercise compact and full-width layouts. |
| Companion CLI | PowerShell and GnuPG versions, command tested, exit code, and observed output. Use an isolated GnuPG home for integration tests. |

Record parser checks, live terminal tests, and cryptographic round trips separately. The boot logo targets 2.5 seconds across all rows. Actual display timing depends on terminal rendering performance.
