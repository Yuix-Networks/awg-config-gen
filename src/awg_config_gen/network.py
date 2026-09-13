"""Address allocation for the tunnel subnet."""

import ipaddress


class NetworkError(ValueError):
    """The subnet cannot accommodate what was asked of it."""


DEFAULT_SUBNET = "10.8.0.0/24"
DEFAULT_DNS = ("1.1.1.1", "1.0.0.1")

#: Send everything through the tunnel. Both halves of the IPv4 space rather
#: than 0.0.0.0/0 so the route does not collide with a default route the
#: system already has.
ROUTE_ALL_V4 = "0.0.0.0/0"
ROUTE_ALL = (ROUTE_ALL_V4, "::/0")


def allocate(subnet, count, skip_server=True):
    """Hand out ``count`` host addresses from ``subnet``.

    The first usable address is the server's by convention, so client
    allocation starts at the second unless told otherwise.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise NetworkError("%r is not a valid subnet: %s" % (subnet, exc)) from exc

    hosts = network.hosts()
    if skip_server:
        try:
            next(hosts)
        except StopIteration:
            raise NetworkError("%s has no usable addresses" % subnet) from None

    addresses = []
    for _ in range(count):
        try:
            addresses.append(next(hosts))
        except StopIteration:
            usable = network.num_addresses - 2 if network.version == 4 else "many"
            raise NetworkError(
                "%s holds %s usable addresses, not enough for %d client(s) plus "
                "the server — use a larger subnet" % (subnet, usable, count)
            ) from None
    return addresses


def server_address(subnet):
    """The first usable address, which the server takes."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise NetworkError("%r is not a valid subnet: %s" % (subnet, exc)) from exc
    try:
        return next(network.hosts())
    except StopIteration:
        raise NetworkError("%s has no usable addresses" % subnet) from None


def host_cidr(address):
    """A single address as a /32 or /128, which is how peers are written."""
    address = ipaddress.ip_address(address)
    return "%s/%d" % (address, 32 if address.version == 4 else 128)
