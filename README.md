# awg-config-gen

Generate and audit [AmneziaWG](https://github.com/amnezia-vpn) configs, with
the obfuscation rules actually enforced.

```console
$ awg-config-gen new vpn.example.com -n 3
awg-configs/server.conf
awg-configs/client1.conf
awg-configs/client2.conf
awg-configs/client3.conf

$ awg-config-gen check ~/existing.conf
ERROR   S1 + 56 must not equal S2 (S1=30, S2=86) — that makes the handshake
        init and response the same size on the wire, which is the fingerprint
        the padding exists to hide
WARNING H1=4 matches a standard WireGuard message type — that message stays
        identifiable as WireGuard, so the header obfuscation is configured
        but not doing anything
```

## Why

AmneziaWG hides WireGuard's packet signature behind junk packets, message
padding and randomised headers. It works, and the parameters are documented.
The problem is what happens when you get one wrong:

**Nothing happens.** The tunnel comes up. Traffic flows. `awg show` looks
healthy. You just don't have the obfuscation you think you have.

- `S1 + 56 == S2` makes the handshake initiation and response the same size
  on the wire — which is the exact fingerprint the padding was added to
  remove.
- An `H` value of 1, 2, 3 or 4 leaves that message type looking like plain
  WireGuard. Configured, inert.
- `Jmax` at or above the system MTU gets the junk packet fragmented, and a
  fragmented junk packet is *more* conspicuous than no junk packet.
- Any shared parameter differing between the two ends means the handshake
  never completes, with no log line that says why.

None of these produce an error from AmneziaWG. This tool refuses to emit
them, and finds them in configs it didn't write.

## Install

```
pip install awg-config-gen
```

One dependency: [`cryptography`](https://pypi.org/project/cryptography/), for
X25519. This tool's whole job is producing private keys, so the curve
arithmetic comes from the audited library rather than from us.

## Use

### Generate a server and its clients

```console
$ awg-config-gen new vpn.example.com -n 5 --preshared
```

Writes `server.conf` and `client1..5.conf`, mode `0600`. Every shared
parameter is identical across all of them; `Jc`/`Jmin`/`Jmax` appear on the
clients only, which is what upstream recommends since junk is client-local.

```
-n, --clients   how many clients (default 1)
-o, --out       output directory (default ./awg-configs)
--port          server listen port (default 51820)
--subnet        tunnel subnet (default 10.8.0.0/24)
--dns           client DNS servers (default 1.1.1.1 1.0.0.1)
--mtu           set MTU in the configs, and size junk against it
--preshared     add a PresharedKey per peer
--force         overwrite existing files
```

It will not overwrite an existing config without `--force`. These files
contain private keys, and replacing one silently locks out whoever is using
it.

### Audit a config you already have

```console
$ awg-config-gen check /etc/amnezia/amneziawg/awg0.conf
$ awg-config-gen check *.conf --mtu 1500
```

Exits non-zero if there are errors, so it drops into CI or a pre-deploy
check. This works on any WireGuard or AmneziaWG config, whoever wrote it —
by hand, from a forum post, or from a panel that doesn't know the rules.

### Just the parameters

```console
$ awg-config-gen params
Jc = 8
Jmin = 23
Jmax = 991
S1 = 137
S2 = 71
H1 = 1314739462
...
```

For when you have a config already and only want a valid parameter set to
paste into it.

### Just the keys

```console
$ awg-config-gen keys
PrivateKey = gHlufQLvEgdHwsK9ikaA1oYqkE6GIIWVwUaKR7j5k20=
PublicKey  = cV/vjb0ANP3qJxfu8ROrGJvcyQI5baDvTZsAEIRL0BU=

$ awg-config-gen keys -n 100   # private public, one pair per line
```

### As a library

```python
from awg_config_gen import generate_obfuscation, validate_obfuscation, check_text

obf = generate_obfuscation(mtu=1420)
validate_obfuscation(obf)          # [] when it is sound

for finding in check_text(open("awg0.conf").read()):
    print(finding)
```

## What gets checked

Hard errors — AmneziaWG rejects these, or they stop the tunnel working:

- `Jc` outside 1–128; `Jmin >= Jmax`; `Jmax > 1280`
- `S1 > 1132`, `S2 > 1188`, **`S1 + 56 == S2`**
- `H1`–`H4` not all distinct, or outside a uint32
- `Jc`/`Jmin`/`Jmax` given partially
- Malformed or mismatched keys, all-zero public keys, missing `AllowedIPs`,
  a peer with no `PublicKey`, a config with no `[Peer]` at all

Warnings — legal, and probably not what you meant:

- An `H` value matching a WireGuard message type (1–4)
- `S1`/`S2` below 12, which is less padding than header protection needs
- `Jmax` at or above the MTU
- An endpoint peer with no `PersistentKeepalive`
- A plain WireGuard config with no obfuscation at all

Every rule comes from upstream:
[amneziawg-linux-kernel-module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module#configuration)
and [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go#parameters).
The output format was checked against `awg-quick`, which matches option names
case-insensitively and passes unrecognised `[Interface]` keys through to
`awg setconf`.

## Notes

- Parameters are drawn with `secrets`, not `random`. A censor who can predict
  your padding sizes can fingerprint you as well as if you had none.
- The generator runs its own validator over what it produced before writing
  it. If those two ever disagree it is a bug, and failing is better than
  shipping it into a config.
- `I1`–`I5` custom signature packets are parsed and preserved on a round
  trip, but not generated — a good signature packet imitates a specific real
  protocol, and a generic one is its own fingerprint.

## Compatibility

Python 3.8+. Generates configs for AmneziaWG 1.5+ and plain WireGuard.

## License

MIT.

---

Built by [Yuix Networks](https://yuix.org), who run
[Unblock Master VPN](https://www.unblockmaster.com/) on AmneziaWG.
