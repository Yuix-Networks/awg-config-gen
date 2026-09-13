"""Audit an existing config.

The generator is only useful for configs you are about to create. Most
broken AmneziaWG setups already exist — written by hand, copied from a
forum post, or produced by a panel that does not know the rules. This
checks those.
"""

from dataclasses import dataclass

from . import keys
from .config import ConfigError, parse
from .obfuscation import validate


@dataclass
class Finding:
    level: str      # "error" | "warning"
    message: str

    def __str__(self):
        return "%-7s %s" % (self.level.upper(), self.message)


def check_text(text, mtu=None):
    """Check a config's text. Returns a list of Findings, worst first."""
    errors, warnings = [], []

    try:
        config = parse(text)
    except ConfigError as exc:
        return [Finding("error", str(exc))]

    interface = config.interface
    if interface is None:
        errors.append("no [Interface] section")
    else:
        private = interface.get("PrivateKey")
        if not private:
            errors.append("[Interface] has no PrivateKey")
        elif not keys.is_valid_key(private):
            errors.append("[Interface] PrivateKey is not a valid 32-byte base64 key")

        if not interface.get("Address"):
            errors.append("[Interface] has no Address")

    peers = config.peers
    if not peers:
        errors.append("no [Peer] section — this config cannot connect to anything")

    for index, peer in enumerate(peers, start=1):
        label = "[Peer] %d" % index
        public = peer.get("PublicKey")
        if not public:
            errors.append("%s has no PublicKey" % label)
        else:
            try:
                keys.validate_public_key(public)
            except keys.KeyError_ as exc:
                errors.append("%s PublicKey: %s" % (label, exc))

        psk = peer.get("PresharedKey")
        if psk and not keys.is_valid_key(psk):
            errors.append("%s PresharedKey is not a valid 32-byte base64 key" % label)

        if not peer.get("AllowedIPs"):
            errors.append("%s has no AllowedIPs, so no traffic will be routed to it" % label)

        # A client peer needs an endpoint; a server's peers do not. Treat a
        # missing endpoint as a note rather than an error when the interface
        # has a ListenPort, which is what makes it a server.
        if not peer.get("Endpoint") and interface and not interface.get("ListenPort"):
            warnings.append(
                "%s has no Endpoint and the interface has no ListenPort — "
                "neither side can initiate" % label
            )

        if peer.get("Endpoint") and not peer.get("PersistentKeepalive"):
            warnings.append(
                "%s has no PersistentKeepalive; behind NAT the tunnel goes "
                "quiet and the far side cannot reach back in (25 is typical)"
                % label
            )

    # --- the AmneziaWG part ---
    try:
        obf = config.obfuscation()
    except ConfigError as exc:
        errors.append(str(exc))
        obf = None

    if obf is None and not errors:
        warnings.append(
            "no AmneziaWG parameters — this is a plain WireGuard config, which "
            "is fine but is detectable by DPI"
        )
    elif obf is not None:
        declared_mtu = interface.get("MTU") if interface else None
        effective_mtu = mtu
        if effective_mtu is None and declared_mtu:
            try:
                effective_mtu = int(declared_mtu)
            except ValueError:
                warnings.append("MTU is not a number: %r" % declared_mtu)

        for problem in validate(obf, mtu=effective_mtu, strict=True):
            # The hard constraints are errors; the "legal but pointless"
            # ones are warnings, because the tunnel does come up.
            soft = (
                "match a standard WireGuard message type" in problem
                or "header protection needs" in problem
                or "system MTU" in problem
            )
            (warnings if soft else errors).append(problem)

    return (
        [Finding("error", m) for m in errors]
        + [Finding("warning", m) for m in warnings]
    )


def check_file(path, mtu=None):
    with open(path, "r", encoding="utf-8") as handle:
        return check_text(handle.read(), mtu=mtu)
