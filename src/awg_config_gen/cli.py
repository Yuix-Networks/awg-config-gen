"""awg-config-gen command line."""

import argparse
import os
import sys
from pathlib import Path

from . import __version__, keys
from .check import check_file
from .config import build_client, build_server
from .network import DEFAULT_DNS, DEFAULT_SUBNET, NetworkError, allocate, host_cidr, server_address
from .obfuscation import generate as generate_obfuscation

DEFAULT_PORT = 51820


def _write(path, text, force):
    path = Path(path)
    if path.exists() and not force:
        raise SystemExit(
            "refusing to overwrite %s — pass --force if that is what you want.\n"
            "These files contain private keys; replacing one silently would "
            "lock out whoever is using it." % path
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    # Private keys should not be world-readable.
    os.chmod(path, 0o600)
    return path


def cmd_new(args):
    if args.clients < 1:
        raise SystemExit("--clients must be at least 1")

    try:
        addresses = allocate(args.subnet, args.clients)
        server_ip = server_address(args.subnet)
    except NetworkError as exc:
        raise SystemExit(str(exc)) from exc

    obf = generate_obfuscation(mtu=args.mtu or 1280)
    server_private, server_public = keys.generate_keypair()

    endpoint = "%s:%d" % (args.endpoint, args.port)
    out = Path(args.out)
    written = []

    peers = []
    for index, address in enumerate(addresses, start=1):
        client_private, client_public = keys.generate_keypair()
        psk = keys.generate_preshared_key() if args.preshared else None

        config = build_client(
            private_key=client_private,
            address=host_cidr(address),
            server_public_key=server_public,
            endpoint=endpoint,
            obfuscation=obf,
            dns=args.dns,
            keepalive=args.keepalive,
            preshared_key=psk,
            mtu=args.mtu,
        )
        name = "%s%d.conf" % (args.prefix, index)
        written.append(_write(out / name, config.render(), args.force))
        peers.append((client_public, host_cidr(address), psk))

    server_config = build_server(
        private_key=server_private,
        address=host_cidr(server_ip),
        listen_port=args.port,
        obfuscation=obf,
        clients=peers,
        mtu=args.mtu,
    )
    written.insert(0, _write(out / "server.conf", server_config.render(), args.force))

    for path in written:
        print(path)
    print(
        "\n%d client config(s) and a server config, mode 0600."
        "\nEvery parameter except Jc/Jmin/Jmax matches across all of them, "
        "which AmneziaWG requires." % args.clients,
        file=sys.stderr,
    )
    return 0


def cmd_keys(args):
    for _ in range(args.count):
        private, public = keys.generate_keypair()
        if args.count == 1:
            print("PrivateKey = %s" % private)
            print("PublicKey  = %s" % public)
            if args.preshared:
                print("PresharedKey = %s" % keys.generate_preshared_key())
        else:
            print("%s %s" % (private, public))
    return 0


def cmd_params(args):
    obf = generate_obfuscation(mtu=args.mtu or 1280)
    for key, value in obf.to_config():
        print("%s = %s" % (key, value))
    return 0


def cmd_check(args):
    exit_code = 0
    for path in args.path:
        findings = check_file(path, mtu=args.mtu)
        errors = [f for f in findings if f.level == "error"]
        if len(args.path) > 1:
            print("== %s" % path)
        if not findings:
            print("OK      no problems found")
        for finding in findings:
            print(finding)
        if errors:
            exit_code = 1
        if len(args.path) > 1:
            print()
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="awg-config-gen",
        description="Generate and audit AmneziaWG configs.",
    )
    parser.add_argument("--version", action="version", version="awg-config-gen " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    new = sub.add_parser("new", help="generate a server and its clients")
    new.add_argument("endpoint", help="server hostname or IP clients connect to")
    new.add_argument("-n", "--clients", type=int, default=1)
    new.add_argument("-o", "--out", default="awg-configs", help="output directory")
    new.add_argument("--port", type=int, default=DEFAULT_PORT)
    new.add_argument("--subnet", default=DEFAULT_SUBNET)
    new.add_argument("--dns", nargs="*", default=list(DEFAULT_DNS))
    new.add_argument("--mtu", type=int, default=None)
    new.add_argument("--keepalive", type=int, default=25)
    new.add_argument("--prefix", default="client", help="client filename prefix")
    new.add_argument("--preshared", action="store_true",
                     help="also generate a pre-shared key per peer")
    new.add_argument("--force", action="store_true", help="overwrite existing files")
    new.set_defaults(func=cmd_new)

    keys_cmd = sub.add_parser("keys", help="generate keypairs")
    keys_cmd.add_argument("-n", "--count", type=int, default=1)
    keys_cmd.add_argument("--preshared", action="store_true")
    keys_cmd.set_defaults(func=cmd_keys)

    params = sub.add_parser("params", help="generate a valid obfuscation parameter set")
    params.add_argument("--mtu", type=int, default=None)
    params.set_defaults(func=cmd_params)

    check = sub.add_parser("check", help="audit an existing config")
    check.add_argument("path", nargs="+")
    check.add_argument("--mtu", type=int, default=None,
                       help="system MTU to check junk sizes against")
    check.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except OSError as exc:
        print("awg-config-gen: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
