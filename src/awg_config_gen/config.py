"""Reading and writing .conf files.

The format is INI-shaped but not INI: it allows repeated [Peer] sections,
which configparser cannot represent. So it is parsed by hand, which also
means comments and unknown keys survive a round trip instead of being
silently dropped.
"""

import re
from dataclasses import dataclass, field

from .obfuscation import Obfuscation

#: Keys that hold obfuscation parameters, lowercased.
OBFUSCATION_KEYS = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
                    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5")

SECTION_RE = re.compile(r"^\[(?P<name>[A-Za-z]+)\]\s*$")
ENTRY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.*?)\s*$")


class ConfigError(ValueError):
    """The file is not a config we can read."""


@dataclass
class Section:
    name: str
    entries: list = field(default_factory=list)   # (key, value) in file order

    def get(self, key, default=None):
        lowered = key.lower()
        for k, v in self.entries:
            if k.lower() == lowered:
                return v
        return default

    def set(self, key, value):
        self.entries.append((key, str(value)))

    def keys(self):
        return [k for k, _ in self.entries]

    def render(self):
        lines = ["[%s]" % self.name]
        lines += ["%s = %s" % (k, v) for k, v in self.entries]
        return "\n".join(lines)


@dataclass
class Config:
    sections: list = field(default_factory=list)

    @property
    def interface(self):
        for section in self.sections:
            if section.name.lower() == "interface":
                return section
        return None

    @property
    def peers(self):
        return [s for s in self.sections if s.name.lower() == "peer"]

    def render(self):
        return "\n\n".join(s.render() for s in self.sections) + "\n"

    def obfuscation(self):
        """The Obfuscation in the [Interface] section, or None.

        Returns None when the file carries no obfuscation keys at all —
        that is a plain WireGuard config, not a broken AmneziaWG one, and
        the caller needs to tell those apart.
        """
        interface = self.interface
        if interface is None:
            return None

        present = {k.lower(): v for k, v in interface.entries if k.lower() in OBFUSCATION_KEYS}
        if not present:
            return None

        # Junk is client-local; a server config legitimately omits it.
        # Everything else has to be there — a partial set does not fall back
        # to WireGuard, it fails to connect.
        required = ("s1", "s2", "h1", "h2", "h3", "h4")
        optional = ("jc", "jmin", "jmax")
        missing = [k for k in required if k not in present]
        if missing:
            raise ConfigError(
                "config has some AmneziaWG parameters but is missing %s — a "
                "partial set does not fall back to WireGuard, it fails to "
                "connect" % ", ".join(k.upper() for k in missing)
            )
        junk_present = [k for k in optional if k in present]
        if junk_present and len(junk_present) != 3:
            raise ConfigError(
                "Jc, Jmin and Jmax must be given together or not at all; found "
                "only %s" % ", ".join(k.upper() for k in junk_present)
            )

        values = {}
        for key in required + tuple(junk_present):
            raw = present[key]
            # H values may be written as a range "x-y"; the low end is what
            # matters for the uniqueness and collision checks.
            text = raw.split("-")[0].strip() if key.startswith("h") else raw.strip()
            try:
                values[key] = int(text)
            except ValueError:
                raise ConfigError(
                    "%s must be a number, got %r" % (key.upper(), raw)
                ) from None
        return Obfuscation(**values)


def parse(text):
    """Parse a WireGuard/AmneziaWG config."""
    config = Config()
    current = None

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        match = SECTION_RE.match(line)
        if match:
            current = Section(match.group("name"))
            config.sections.append(current)
            continue

        match = ENTRY_RE.match(line)
        if match:
            if current is None:
                raise ConfigError(
                    "line %d: %r appears before any [Interface] or [Peer] section"
                    % (number, line)
                )
            value = match.group("value").split("#")[0].strip()
            current.set(match.group("key"), value)
            continue

        raise ConfigError("line %d: cannot parse %r" % (number, line))

    if not config.sections:
        raise ConfigError("file contains no [Interface] or [Peer] section")
    return config


def build_client(*, private_key, address, server_public_key, endpoint,
                 obfuscation, dns=None, allowed_ips=None, keepalive=25,
                 preshared_key=None, mtu=None):
    """A client config."""
    interface = Section("Interface")
    interface.set("PrivateKey", private_key)
    interface.set("Address", address)
    if dns:
        interface.set("DNS", ", ".join(dns))
    if mtu:
        interface.set("MTU", mtu)
    for key, value in obfuscation.to_config():
        interface.set(key, value)

    peer = Section("Peer")
    peer.set("PublicKey", server_public_key)
    if preshared_key:
        peer.set("PresharedKey", preshared_key)
    peer.set("AllowedIPs", ", ".join(allowed_ips or ["0.0.0.0/0", "::/0"]))
    peer.set("Endpoint", endpoint)
    # Without this a client behind NAT goes silent and the server cannot
    # reach it until the client speaks again.
    peer.set("PersistentKeepalive", keepalive)

    return Config([interface, peer])


def build_server(*, private_key, address, listen_port, obfuscation, clients,
                 mtu=None):
    """A server config. ``clients`` is a list of (public_key, address, psk)."""
    interface = Section("Interface")
    interface.set("PrivateKey", private_key)
    interface.set("Address", address)
    interface.set("ListenPort", listen_port)
    if mtu:
        interface.set("MTU", mtu)
    # Jc/Jmin/Jmax are client-local; the upstream guidance is to set junk on
    # the client side only, so the server carries the shared fields only.
    for key, value in obfuscation.to_config():
        if key not in ("Jc", "Jmin", "Jmax"):
            interface.set(key, value)

    sections = [interface]
    for public, address_, psk in clients:
        peer = Section("Peer")
        peer.set("PublicKey", public)
        if psk:
            peer.set("PresharedKey", psk)
        peer.set("AllowedIPs", address_)
        sections.append(peer)

    return Config(sections)
