"""Outbound destination validation at the execution boundary.

Two layers:

* `classify_host(host)` is pure and deterministic (no DNS). The policy engine uses it on every URL it sees,
  so `http://2130706433/`, `http://0x7f.1/`, `http://[::ffff:127.0.0.1]/` and `http://127.1/` are recognised as
  loopback even though they are not dotted quads.
* `safe_fetch(url)` is how Provenant itself performs an HTTP request (the `http_get` tool of the Provenant
  tool server). It resolves the name once, rejects the request if ANY resolved address is restricted, then
  connects to that exact address (TLS still verifies the hostname). Redirects are followed manually and every
  hop is validated again. Because the connection goes to the address that was checked, a DNS answer that
  changes between check and connect (rebinding) cannot redirect it to a private address.

Limits: this protects requests Provenant performs. A shell command, or any other client that makes its own
connection, is outside this function; for those the policy can only judge the URL text.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 5
MAX_BYTES = 2_000_000
_BLOCKED_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "metadata.google.internal",
                  "metadata", "instance-data", "kubernetes.default.svc"}


class DestinationRefused(ValueError):
    pass


def parse_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse every textual form an OS resolver would accept for a literal address, not only dotted quads."""
    h = host.strip("[]").split("%")[0]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums = []
    for p in parts:                       # inet_aton rules: decimal, 0x hex or leading-zero octal per part
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    widths = {1: [32], 2: [8, 24], 3: [8, 8, 16], 4: [8, 8, 8, 8]}[len(nums)]
    value = 0
    for n, w in zip(nums, widths):
        if n < 0 or n >= (1 << w):
            return None
        value = (value << w) | n
    return ipaddress.IPv4Address(value)


def restricted_reason(ip: ipaddress._BaseAddress) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return restricted_reason(ip.ipv4_mapped)
        if ip.sixtofour:
            return restricted_reason(ip.sixtofour)
        if ip in ipaddress.ip_network("64:ff9b::/96"):          # NAT64 can wrap a private v4 address
            return restricted_reason(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    for attr, why in (("is_loopback", "loopback"), ("is_private", "private network"), ("is_link_local", "link-local"),
                      ("is_multicast", "multicast"), ("is_reserved", "reserved"), ("is_unspecified", "unspecified"),
                      ("is_site_local", "site-local")):
        if getattr(ip, attr, False):
            return f"{why} address {ip}"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return f"carrier-grade NAT address {ip}"
    if not ip.is_global:
        return f"non-global address {ip}"
    return None


@dataclass
class HostClass:
    kind: str                  # name | ip
    restricted: str | None     # reason, or None
    ip: str | None = None


def classify_host(host: str) -> HostClass:
    h = (host or "").lower().rstrip(".")
    if not h:
        return HostClass("name", "empty host")
    if h in _BLOCKED_NAMES or h.endswith(".localhost") or h.endswith(".internal") or h.endswith(".local"):
        return HostClass("name", f"{h} is a local or metadata name")
    ip = parse_ip(h)
    if ip is not None:
        return HostClass("ip", restricted_reason(ip) or "raw IP address (no name to check against the allow-list)",
                         str(ip))
    return HostClass("name", None)


def validate_url(url: str) -> tuple[str, str, int]:
    """Static checks: scheme, credentials-in-URL, host form. Returns (scheme, host, port)."""
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as exc:
        raise DestinationRefused(f"unparsable URL: {exc}") from exc
    if u.scheme.lower() not in ALLOWED_SCHEMES:
        raise DestinationRefused(f"scheme '{u.scheme}' is not allowed")
    if u.username or u.password:
        raise DestinationRefused("credentials in the URL are not allowed")
    host = (u.hostname or "").lower().rstrip(".")
    hc = classify_host(host)
    if hc.restricted:
        raise DestinationRefused(hc.restricted)
    return u.scheme.lower(), host, port or (443 if u.scheme.lower() == "https" else 80)


def resolve_checked(host: str, port: int, resolver=socket.getaddrinfo, is_restricted=None) -> str:
    """Resolve once; refuse if any answer is restricted (a mixed answer is a rebinding signal). Returns one IP."""
    try:
        infos = resolver(host, port, 0, socket.SOCK_STREAM)
    except OSError as exc:
        raise DestinationRefused(f"cannot resolve {host}: {exc}") from exc
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        why = (is_restricted or restricted_reason)(ip)
        if why:
            raise DestinationRefused(f"{host} resolves to a {why}")
        addrs.append(str(ip))
    if not addrs:
        raise DestinationRefused(f"{host} has no addresses")
    return addrs[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def safe_fetch(url: str, host_allowed=lambda h: True, timeout: float = 10.0, resolver=socket.getaddrinfo,
               max_bytes: int = MAX_BYTES, context: ssl.SSLContext | None = None, is_restricted=None) -> dict:
    """GET a URL with destination checks on every hop. Returns {url, status, headers, body, hops}."""
    hops = []
    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port = validate_url(url)
        if not host_allowed(host):
            raise DestinationRefused(f"{host} is not on the allowed host list")
        ip = resolve_checked(host, port, resolver, is_restricted)
        hops.append({"url": url, "ip": ip})
        conn = (_PinnedHTTPS(host, ip, port, timeout, context or ssl.create_default_context()) if scheme == "https"
                else _PinnedHTTP(host, ip, port, timeout))
        try:
            u = urlsplit(url)
            conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""),
                         headers={"User-Agent": "provenant-safe-fetch/1", "Accept-Encoding": "identity"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urljoin(url, r.getheader("Location"))
                r.read(0)
                continue
            body = r.read(max_bytes + 1)
            return {"url": url, "status": r.status, "headers": dict(r.getheaders()),
                    "body": body[:max_bytes].decode("utf-8", "replace"), "truncated": len(body) > max_bytes,
                    "hops": hops}
        finally:
            conn.close()
    raise DestinationRefused(f"more than {MAX_REDIRECTS} redirects")
