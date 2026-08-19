# Compatibility

| Profile | Role | Expected compatibility |
|---|---|---|
| `ky1024_cv448` | Strongest local composite PQC profile | GnuPG builds supporting the corresponding Kyber/ML-KEM composite algorithm |
| `ky768_cv25519` | Balanced composite PQC profile | Compatible GnuPG PQC builds |
| `ky768_bp256` | GnuPG composite alternative | Compatible GnuPG PQC builds |
| `cv25519` | Classic encryption | Broad contemporary OpenPGP compatibility |

PQC algorithm support in a local executable does not prove compatibility with email providers, keyservers, browser extensions, or other OpenPGP implementations. Test export, import, encryption, decryption, and packet preservation with every intended peer.
