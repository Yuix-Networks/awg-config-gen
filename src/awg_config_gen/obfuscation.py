"""AmneziaWG obfuscation parameters, and the rules they have to satisfy.

Every constraint here is from the upstream documentation, cited at the
constant that encodes it:

  https://github.com/amnezia-vpn/amneziawg-linux-kernel-module#configuration
  https://github.com/amnezia-vpn/amneziawg-go#parameters

The reason this module exists at all is that the rules are easy to break by
hand and breaking them usually does not look like an error. A tunnel with
S1 + 56 == S2 comes up and passes traffic; it just has the exact size
fingerprint the padding was added to hide. Silent failure is the normal
failure mode here, which is why every rule is checked rather than assumed.
"""

import secrets
from dataclasses import asdict, dataclass

# The protocol works on a 1280-byte floor; the kernel module derives the
# padding ceilings from it.
BASE_MTU = 1280

JC_MIN, JC_MAX = 1, 128
JC_RECOMMENDED = (4, 12)

#: Junk packet sizes. Jmax at or above the system MTU gets fragmented, and a
#: fragmented junk packet is more conspicuous than no junk packet at all.
JUNK_SIZE_MAX = 1280

#: S1 <= 1280 - 148, S2 <= 1280 - 92.
S1_MAX = BASE_MTU - 148
S2_MAX = BASE_MTU - 92
S_RECOMMENDED = (15, 150)

#: Header protection needs at least this much padding to work with.
S_MIN_FOR_HEADER_PROTECTION = 12

#: The difference that must not appear between S1 and S2: the handshake
#: response is 56 bytes longer than the init, so S1 + 56 == S2 makes the two
#: messages the same size on the wire.
S_FORBIDDEN_DELTA = 56

#: The field is a uint32, so this is the hard bound. 5..2147483647 is the
#: *recommended* range, not a limit — a value outside it is reported only
#: under strict checking.
H_HARD_MIN, H_HARD_MAX = 0, 4294967295
H_MIN, H_MAX = 5, 2147483647

#: Standard WireGuard message types. An H value equal to one of these leaves
#: that message type looking exactly like WireGuard — the obfuscation is
#: configured but not doing anything, which is the worst of both worlds.
WIREGUARD_MESSAGE_TYPES = (1, 2, 3, 4)


class ObfuscationError(ValueError):
    """A parameter set that AmneziaWG would accept but should not be used,
    or would reject outright."""


@dataclass(frozen=True)
class Obfuscation:
    """One AmneziaWG obfuscation parameter set.

    Jc/Jmin/Jmax are client-local — they may differ between the two ends.
    Everything else must match exactly or the tunnel will not come up.
    """

    s1: int
    s2: int
    h1: int
    h2: int
    h3: int
    h4: int
    # Junk is client-local and upstream recommends setting it on the client
    # side only, so a server config legitimately has none. None means
    # "absent", which is different from 0.
    jc: int = None
    jmin: int = None
    jmax: int = None

    @property
    def has_junk(self):
        return None not in (self.jc, self.jmin, self.jmax)

    @property
    def shared_fields(self):
        """The parameters both ends must agree on."""
        return {k: v for k, v in asdict(self).items() if k not in ("jc", "jmin", "jmax")}

    def without_junk(self):
        """The same set with the client-local parameters dropped."""
        return Obfuscation(self.s1, self.s2, self.h1, self.h2, self.h3, self.h4)

    def to_config(self):
        """As they appear in a .conf, in the conventional order."""
        entries = []
        if self.has_junk:
            entries += [("Jc", self.jc), ("Jmin", self.jmin), ("Jmax", self.jmax)]
        entries += [
            ("S1", self.s1), ("S2", self.s2),
            ("H1", self.h1), ("H2", self.h2), ("H3", self.h3), ("H4", self.h4),
        ]
        return entries


def validate(obf, mtu=None, strict=True):
    """Check a parameter set. Returns a list of problem strings.

    ``strict`` also reports the things that are legal but unwise — using a
    WireGuard message type as an H value, or padding too small for header
    protection. Those are not rejected by AmneziaWG, which is exactly why
    they are worth surfacing.
    """
    problems = []

    # Junk is optional: it is client-local, and upstream recommends setting
    # it on the client side only, so a server config without it is correct.
    if obf.has_junk:
        if not JC_MIN <= obf.jc <= JC_MAX:
            problems.append("Jc must be between %d and %d, got %d" % (JC_MIN, JC_MAX, obf.jc))
        if obf.jmin >= obf.jmax:
            problems.append(
                "Jmin must be less than Jmax, got Jmin=%d Jmax=%d" % (obf.jmin, obf.jmax))
        if obf.jmin < 0:
            problems.append("Jmin must not be negative, got %d" % obf.jmin)
        if obf.jmax > JUNK_SIZE_MAX:
            problems.append("Jmax must be at most %d, got %d" % (JUNK_SIZE_MAX, obf.jmax))
    elif any(v is not None for v in (obf.jc, obf.jmin, obf.jmax)):
        problems.append("Jc, Jmin and Jmax must be given together or not at all")

    if obf.s1 > S1_MAX:
        problems.append("S1 must be at most %d, got %d" % (S1_MAX, obf.s1))
    if obf.s2 > S2_MAX:
        problems.append("S2 must be at most %d, got %d" % (S2_MAX, obf.s2))
    if obf.s1 < 0 or obf.s2 < 0:
        problems.append("S1 and S2 must not be negative")

    if obf.s1 + S_FORBIDDEN_DELTA == obf.s2:
        problems.append(
            "S1 + %d must not equal S2 (S1=%d, S2=%d) — that makes the handshake "
            "init and response the same size on the wire, which is the "
            "fingerprint the padding exists to hide"
            % (S_FORBIDDEN_DELTA, obf.s1, obf.s2)
        )

    headers = [obf.h1, obf.h2, obf.h3, obf.h4]
    for index, value in enumerate(headers, start=1):
        if not H_HARD_MIN <= value <= H_HARD_MAX:
            problems.append(
                "H%d must fit in a uint32 (%d-%d), got %d"
                % (index, H_HARD_MIN, H_HARD_MAX, value))
    if len(set(headers)) != 4:
        problems.append("H1-H4 must all differ from each other, got %s" % (headers,))

    if strict:
        clashing = [
            "H%d=%d" % (i, v)
            for i, v in enumerate(headers, start=1)
            if v in WIREGUARD_MESSAGE_TYPES
        ]
        if clashing:
            problems.append(
                "%s match a standard WireGuard message type — that message stays "
                "identifiable as WireGuard, so the header obfuscation is "
                "configured but not doing anything" % ", ".join(clashing)
            )
        outside = [
            "H%d=%d" % (i, v)
            for i, v in enumerate(headers, start=1)
            if v not in WIREGUARD_MESSAGE_TYPES and not H_MIN <= v <= H_MAX
        ]
        if outside:
            problems.append(
                "%s fall outside the recommended range %d-%d"
                % (", ".join(outside), H_MIN, H_MAX))
        for name, value in (("S1", obf.s1), ("S2", obf.s2)):
            if 0 < value < S_MIN_FOR_HEADER_PROTECTION:
                problems.append(
                    "%s=%d is below %d; header protection needs at least that "
                    "much padding to work with"
                    % (name, value, S_MIN_FOR_HEADER_PROTECTION)
                )

    if mtu is not None and obf.jmax >= mtu:
        problems.append(
            "Jmax=%d is at or above the system MTU (%d) — junk packets will be "
            "fragmented, and a fragmented junk packet draws more attention than "
            "no junk packet" % (obf.jmax, mtu)
        )

    return problems


def generate(mtu=BASE_MTU, rng=None):
    """A fresh, valid parameter set.

    Values are drawn with ``secrets`` rather than ``random``: a censor that
    can predict a peer's padding sizes can fingerprint it just as well as if
    there were no padding, so these want a real CSPRNG.
    """
    rand = rng or secrets.randbelow

    def between(low, high):
        return low + rand(high - low + 1)

    jc = between(*JC_RECOMMENDED)

    # Keep junk comfortably under the MTU so nothing fragments.
    jmax_ceiling = min(JUNK_SIZE_MAX, max(64, mtu - 80))
    jmin = between(8, max(9, jmax_ceiling // 8))
    jmax = between(jmin + 1, jmax_ceiling)

    s1 = between(*S_RECOMMENDED)
    # Draw S2 until it does not land on the forbidden delta. The range is
    # wide enough that this retries at most a couple of times.
    while True:
        s2 = between(*S_RECOMMENDED)
        if s1 + S_FORBIDDEN_DELTA != s2:
            break

    # Distinct, and never a standard WireGuard message type.
    headers = []
    while len(headers) < 4:
        value = between(H_MIN, H_MAX)
        if value not in headers and value not in WIREGUARD_MESSAGE_TYPES:
            headers.append(value)

    obf = Obfuscation(s1, s2, *headers, jc=jc, jmin=jmin, jmax=jmax)

    # Belt and braces: the generator and the validator are written from the
    # same spec, so if they ever disagree that is a bug worth failing on
    # rather than shipping into a config.
    problems = validate(obf, mtu=mtu)
    if problems:
        raise ObfuscationError(
            "generated an invalid parameter set, this is a bug: %s" % "; ".join(problems)
        )
    return obf
