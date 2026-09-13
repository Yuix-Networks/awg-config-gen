# Changelog

## 1.0.0

First release.

- `new` generates a server plus N client configs with a valid, randomised
  obfuscation parameter set shared across all of them.
- `check` audits any existing WireGuard or AmneziaWG config, whoever wrote
  it, and exits non-zero on errors so it fits in CI.
- `params` and `keys` for when you only need one piece.
- Every constraint from the upstream documentation is enforced, including
  the ones AmneziaWG accepts silently: `S1 + 56 != S2`, distinct `H1`-`H4`,
  no `H` equal to a WireGuard message type, junk below the MTU.
- X25519 from `cryptography`; parameters drawn with `secrets`.
