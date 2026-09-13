"""Tests for awg-config-gen.

The point of the tool is that it never emits a parameter set AmneziaWG
would reject or that would silently defeat the obfuscation, so most of
these are about exactly that.
"""

import base64

import pytest

import awg_config_gen as awg
from awg_config_gen import check, config, keys, network, obfuscation


# --- obfuscation constraints ----------------------------------------------


def test_a_generated_set_validates():
    assert obfuscation.validate(obfuscation.generate()) == []


def test_generation_is_valid_a_thousand_times_over():
    """The constraints interact — S2 is redrawn against S1, H values against
    each other — so one sample proves very little."""
    for _ in range(1000):
        assert obfuscation.validate(obfuscation.generate()) == []


def test_headers_are_always_distinct():
    for _ in range(500):
        obf = obfuscation.generate()
        assert len({obf.h1, obf.h2, obf.h3, obf.h4}) == 4


def test_headers_never_collide_with_wireguard_message_types():
    """H equal to 1-4 leaves that message looking like plain WireGuard, so
    the obfuscation is configured but inert."""
    for _ in range(500):
        obf = obfuscation.generate()
        for value in (obf.h1, obf.h2, obf.h3, obf.h4):
            assert value not in obfuscation.WIREGUARD_MESSAGE_TYPES


def test_s1_plus_56_never_equals_s2():
    """The one constraint whose violation is invisible: the tunnel works,
    it just has the size fingerprint the padding exists to hide."""
    for _ in range(2000):
        obf = obfuscation.generate()
        assert obf.s1 + obfuscation.S_FORBIDDEN_DELTA != obf.s2


def test_junk_stays_below_the_mtu():
    for mtu in (1280, 1420, 1500):
        for _ in range(200):
            obf = obfuscation.generate(mtu=mtu)
            assert obf.jmax < mtu


def test_jmin_is_always_below_jmax():
    for _ in range(500):
        obf = obfuscation.generate()
        assert obf.jmin < obf.jmax


def test_generation_varies():
    """A constant parameter set would be a fingerprint of this tool."""
    sets = {obfuscation.generate() for _ in range(50)}
    assert len(sets) == 50


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"jc": 0}, "Jc must be between"),
        ({"jc": 129}, "Jc must be between"),
        ({"jmin": 100, "jmax": 50}, "Jmin must be less than Jmax"),
        ({"jmax": 2000}, "Jmax must be at most"),
        ({"s1": 2000}, "S1 must be at most"),
        ({"s2": 2000}, "S2 must be at most"),
        ({"s1": 20, "s2": 76}, "must not equal S2"),
        ({"h1": 4}, "standard WireGuard message type"),
        ({"h2": 3}, "standard WireGuard message type"),
        ({"h1": 100, "h2": 100}, "must all differ"),
        ({"s1": 5}, "header protection needs"),
    ],
)
def test_each_rule_is_reported(kwargs, expected):
    base = dict(jc=5, jmin=10, jmax=50, s1=30, s2=90,
                h1=1000, h2=2000, h3=3000, h4=4000)  # noqa: E501
    base.update(kwargs)
    problems = obfuscation.validate(obfuscation.Obfuscation(**base))
    assert any(expected in p for p in problems), problems


def test_strict_off_allows_the_legal_but_pointless():
    """H=4 is inside the uint32 field and AmneziaWG accepts it; it is only
    unwise, because that message then still looks like WireGuard."""
    obf = obfuscation.Obfuscation(30, 90, 4, 2000, 3000, 4000, jc=5, jmin=10, jmax=50)
    assert obfuscation.validate(obf, strict=False) == []
    assert obfuscation.validate(obf, strict=True)


def test_a_server_set_without_junk_is_valid():
    """Junk is client-local; upstream says to set it on the client only."""
    obf = obfuscation.generate().without_junk()
    assert not obf.has_junk
    assert obfuscation.validate(obf) == []


def test_junk_parameters_must_come_as_a_set():
    obf = obfuscation.Obfuscation(30, 90, 10, 20, 30, 40, jc=5)
    assert any("together or not at all" in p for p in obfuscation.validate(obf))


def test_shared_fields_exclude_the_client_local_ones():
    """Jc/Jmin/Jmax may differ between peers; everything else may not."""
    shared = obfuscation.generate().shared_fields
    assert set(shared) == {"s1", "s2", "h1", "h2", "h3", "h4"}


# --- keys ------------------------------------------------------------------


def test_keypair_round_trips():
    private, public = keys.generate_keypair()
    assert keys.public_key(private) == public
    assert keys.keys_match(private, public)


def test_keys_are_wireguard_shaped():
    private, public = keys.generate_keypair()
    for key in (private, public):
        assert len(key) == 44
        assert len(base64.b64decode(key)) == 32


def test_keys_are_unique():
    assert len({keys.generate_private_key() for _ in range(100)}) == 100


def test_mismatched_keys_are_detected():
    private, _ = keys.generate_keypair()
    _, other_public = keys.generate_keypair()
    assert not keys.keys_match(private, other_public)


@pytest.mark.parametrize("bad", ["", "short", "!" * 44, "A" * 43, "A" * 45, None, 42])
def test_invalid_keys_are_rejected(bad):
    assert not keys.is_valid_key(bad)


def test_an_all_zero_public_key_is_rejected():
    """A low-order point makes the shared secret zero whatever the peer
    does; cryptography accepts the bytes, so we have to catch it."""
    zeros = base64.b64encode(bytes(32)).decode()
    with pytest.raises(keys.KeyError_, match="low-order"):
        keys.validate_public_key(zeros)


def test_preshared_key_is_the_right_shape():
    psk = keys.generate_preshared_key()
    assert len(base64.b64decode(psk)) == 32


# --- addressing ------------------------------------------------------------


def test_allocation_skips_the_server_address():
    addresses = network.allocate("10.8.0.0/24", 2)
    assert str(addresses[0]) == "10.8.0.2"
    assert str(network.server_address("10.8.0.0/24")) == "10.8.0.1"


def test_allocation_refuses_to_overflow_the_subnet():
    with pytest.raises(network.NetworkError, match="not enough"):
        network.allocate("10.8.0.0/30", 5)


def test_host_cidr_picks_the_right_prefix_length():
    assert network.host_cidr("10.8.0.2") == "10.8.0.2/32"
    assert network.host_cidr("fd00::2") == "fd00::2/128"


def test_a_bad_subnet_says_so():
    with pytest.raises(network.NetworkError, match="not a valid subnet"):
        network.allocate("not-a-subnet", 1)


# --- config round trip -----------------------------------------------------


def _sample_client():
    private, _ = keys.generate_keypair()
    _, server_public = keys.generate_keypair()
    return config.build_client(
        private_key=private,
        address="10.8.0.2/32",
        server_public_key=server_public,
        endpoint="vpn.example.com:51820",
        obfuscation=obfuscation.generate(),
        dns=["1.1.1.1"],
    )


def test_a_built_client_parses_back():
    text = _sample_client().render()
    parsed = config.parse(text)
    assert parsed.interface is not None
    assert len(parsed.peers) == 1


def test_obfuscation_survives_the_round_trip():
    built = _sample_client()
    original = built.obfuscation()
    assert config.parse(built.render()).obfuscation() == original


def test_multiple_peers_are_preserved():
    """configparser cannot represent repeated sections, which is why this
    format is parsed by hand."""
    clients = [(keys.generate_keypair()[1], "10.8.0.%d/32" % n, None) for n in range(2, 6)]
    private, _ = keys.generate_keypair()
    server = config.build_server(
        private_key=private, address="10.8.0.1/32", listen_port=51820,
        obfuscation=obfuscation.generate(), clients=clients,
    )
    assert len(config.parse(server.render()).peers) == 4


def test_the_server_omits_the_client_local_junk_parameters():
    private, _ = keys.generate_keypair()
    server = config.build_server(
        private_key=private, address="10.8.0.1/32", listen_port=51820,
        obfuscation=obfuscation.generate(), clients=[],
    )
    interface_keys = [k.lower() for k in config.parse(server.render()).interface.keys()]
    for key in ("jc", "jmin", "jmax"):
        assert key not in interface_keys
    assert "h1" in interface_keys


def test_comments_and_inline_comments_are_ignored():
    text = """
# a leading comment
[Interface]
PrivateKey = %s  # inline
Address = 10.8.0.2/32
""" % keys.generate_private_key()
    parsed = config.parse(text)
    assert parsed.interface.get("Address") == "10.8.0.2/32"
    assert "#" not in parsed.interface.get("PrivateKey")


def test_an_entry_before_any_section_is_an_error():
    with pytest.raises(config.ConfigError, match="before any"):
        config.parse("PrivateKey = abc\n[Interface]\n")


def test_a_partial_parameter_set_is_an_error():
    """A half-configured AmneziaWG does not fall back to WireGuard; it just
    fails to connect."""
    text = "[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\nJc = 5\n" % keys.generate_private_key()
    with pytest.raises(config.ConfigError, match="missing"):
        config.parse(text).obfuscation()


def test_a_plain_wireguard_config_has_no_obfuscation_not_a_broken_one():
    text = "[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n" % keys.generate_private_key()
    assert config.parse(text).obfuscation() is None


def test_header_ranges_are_understood():
    """H values may be written as "x-y"."""
    priv = keys.generate_private_key()
    text = ("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n"
            "Jc = 5\nJmin = 10\nJmax = 50\nS1 = 30\nS2 = 90\n"
            "H1 = 1000-2000\nH2 = 3000\nH3 = 4000\nH4 = 5000\n") % priv
    assert config.parse(text).obfuscation().h1 == 1000


# --- the checker -----------------------------------------------------------


def _levels(findings):
    return [f.level for f in findings]


def test_a_generated_config_passes_its_own_check():
    assert check.check_text(_sample_client().render()) == []


def test_the_checker_catches_the_invisible_constraint():
    """The reason the checker exists: this config works, and is wrong."""
    priv = keys.generate_private_key()
    _, pub = keys.generate_keypair()
    text = ("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n"
            "Jc = 5\nJmin = 10\nJmax = 50\nS1 = 30\nS2 = 86\n"
            "H1 = 1000\nH2 = 2000\nH3 = 3000\nH4 = 4000\n"
            "[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\n"
            "Endpoint = a.example.com:51820\nPersistentKeepalive = 25\n") % (priv, pub)
    findings = check.check_text(text)
    assert "error" in _levels(findings)
    assert any("must not equal S2" in f.message for f in findings)


def test_the_checker_warns_about_plain_wireguard():
    priv = keys.generate_private_key()
    _, pub = keys.generate_keypair()
    text = ("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n"
            "[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\n"
            "Endpoint = a.example.com:51820\nPersistentKeepalive = 25\n") % (priv, pub)
    findings = check.check_text(text)
    assert _levels(findings) == ["warning"]
    assert "detectable by DPI" in findings[0].message


def test_the_checker_flags_a_missing_keepalive():
    priv = keys.generate_private_key()
    _, pub = keys.generate_keypair()
    text = ("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n"
            "[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\n"
            "Endpoint = a.example.com:51820\n") % (priv, pub)
    assert any("PersistentKeepalive" in f.message for f in check.check_text(text))


def test_the_checker_flags_a_bad_key():
    text = ("[Interface]\nPrivateKey = nonsense\nAddress = 10.8.0.2/32\n"
            "[Peer]\nPublicKey = also-nonsense\nAllowedIPs = 0.0.0.0/0\n")
    findings = check.check_text(text)
    assert sum(1 for f in findings if f.level == "error") >= 2


def test_the_checker_flags_a_config_with_no_peer():
    text = "[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n" % keys.generate_private_key()
    assert any("no [Peer]" in f.message for f in check.check_text(text))


def test_the_checker_reports_unparseable_input_without_raising():
    findings = check.check_text("this is not a config at all")
    assert _levels(findings) == ["error"]


def test_errors_sort_before_warnings():
    priv = keys.generate_private_key()
    text = ("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n"
            "Jc = 5\nJmin = 10\nJmax = 50\nS1 = 30\nS2 = 86\n"
            "H1 = 4\nH2 = 2000\nH3 = 3000\nH4 = 4000\n") % priv
    levels = _levels(check.check_text(text))
    assert levels == sorted(levels, key=lambda l: 0 if l == "error" else 1)


# --- cli -------------------------------------------------------------------


def test_cli_new_writes_a_full_set(tmp_path, capsys):
    from awg_config_gen.cli import main

    assert main(["new", "vpn.example.com", "-n", "3", "-o", str(tmp_path)]) == 0
    written = sorted(p.name for p in tmp_path.glob("*.conf"))
    assert written == ["client1.conf", "client2.conf", "client3.conf", "server.conf"]


def test_cli_output_passes_the_checker(tmp_path):
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-n", "2", "-o", str(tmp_path)])
    for path in tmp_path.glob("*.conf"):
        findings = [f for f in check.check_file(str(path)) if f.level == "error"]
        assert findings == [], "%s: %s" % (path.name, findings)


def test_cli_gives_every_peer_the_same_shared_parameters(tmp_path):
    """AmneziaWG requires it; getting this wrong produces a tunnel that
    never completes a handshake."""
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-n", "4", "-o", str(tmp_path)])
    shared = {
        config.parse(p.read_text()).obfuscation().shared_fields
        and tuple(sorted(config.parse(p.read_text()).obfuscation().shared_fields.items()))
        for p in tmp_path.glob("*.conf")
    }
    assert len(shared) == 1


def test_cli_refuses_to_clobber_private_keys(tmp_path):
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-o", str(tmp_path)])
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        main(["new", "vpn.example.com", "-o", str(tmp_path)])


def test_cli_force_overwrites(tmp_path):
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-o", str(tmp_path)])
    assert main(["new", "vpn.example.com", "-o", str(tmp_path), "--force"]) == 0


def test_written_configs_are_not_world_readable(tmp_path):
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-o", str(tmp_path)])
    for path in tmp_path.glob("*.conf"):
        assert oct(path.stat().st_mode)[-3:] == "600", path.name


def test_cli_check_exits_nonzero_on_an_error(tmp_path, capsys):
    from awg_config_gen.cli import main

    bad = tmp_path / "bad.conf"
    bad.write_text("[Interface]\nPrivateKey = nope\n")
    assert main(["check", str(bad)]) == 1


def test_cli_check_exits_zero_on_a_clean_config(tmp_path):
    from awg_config_gen.cli import main

    main(["new", "vpn.example.com", "-o", str(tmp_path)])
    assert main(["check", str(tmp_path / "client1.conf")]) == 0


def test_cli_params_prints_a_valid_set(capsys):
    from awg_config_gen.cli import main

    main(["params"])
    out = capsys.readouterr().out
    values = dict(line.split(" = ") for line in out.strip().splitlines())
    obf = obfuscation.Obfuscation(
        s1=int(values["S1"]), s2=int(values["S2"]),
        h1=int(values["H1"]), h2=int(values["H2"]),
        h3=int(values["H3"]), h4=int(values["H4"]),
        jc=int(values["Jc"]), jmin=int(values["Jmin"]), jmax=int(values["Jmax"]),
    )
    assert obfuscation.validate(obf) == []


def test_cli_keys_prints_a_matching_pair(capsys):
    from awg_config_gen.cli import main

    main(["keys"])
    out = capsys.readouterr().out
    private = out.split("PrivateKey = ")[1].split("\n")[0].strip()
    public = out.split("PublicKey  = ")[1].split("\n")[0].strip()
    assert keys.keys_match(private, public)


def test_cli_rejects_zero_clients(tmp_path):
    from awg_config_gen.cli import main

    with pytest.raises(SystemExit, match="at least 1"):
        main(["new", "vpn.example.com", "-n", "0", "-o", str(tmp_path)])


def test_cli_reports_a_subnet_that_is_too_small(tmp_path):
    from awg_config_gen.cli import main

    with pytest.raises(SystemExit, match="not enough"):
        main(["new", "vpn.example.com", "-n", "10", "--subnet", "10.8.0.0/29",
              "-o", str(tmp_path)])


def test_public_api_is_importable():
    for name in awg.__all__:
        assert hasattr(awg, name), name
