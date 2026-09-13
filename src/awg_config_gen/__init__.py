"""Generate and audit AmneziaWG configs, with the obfuscation rules enforced.

    >>> from awg_config_gen import generate_obfuscation, validate_obfuscation
    >>> obf = generate_obfuscation()
    >>> validate_obfuscation(obf)
    []

The rules AmneziaWG documents are easy to break by hand, and breaking them
rarely looks like an error — a tunnel with `S1 + 56 == S2` connects and
passes traffic, it just carries the size fingerprint the padding was added
to hide. Everything here is checked rather than assumed.
"""

from .check import Finding, check_file, check_text
from .config import Config, ConfigError, Section, build_client, build_server, parse
from .keys import (
    KeyError_,
    generate_keypair,
    generate_preshared_key,
    generate_private_key,
    is_valid_key,
    keys_match,
    public_key,
)
from .network import NetworkError, allocate, host_cidr, server_address
from .obfuscation import Obfuscation, ObfuscationError
from .obfuscation import generate as generate_obfuscation
from .obfuscation import validate as validate_obfuscation

__version__ = "1.0.0"

__all__ = [
    "Config",
    "ConfigError",
    "Finding",
    "KeyError_",
    "NetworkError",
    "Obfuscation",
    "ObfuscationError",
    "Section",
    "allocate",
    "build_client",
    "build_server",
    "check_file",
    "check_text",
    "generate_keypair",
    "generate_obfuscation",
    "generate_preshared_key",
    "generate_private_key",
    "host_cidr",
    "is_valid_key",
    "keys_match",
    "parse",
    "public_key",
    "server_address",
    "validate_obfuscation",
    "__version__",
]
