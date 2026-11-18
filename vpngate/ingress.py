"""Give a private VPN namespace an IPv4 uplink through one SOCKS5 proxy."""

from dataclasses import dataclass, field
import ipaddress
import json
import os
import re
import socket
from urllib.parse import unquote, urlsplit


UPLINK_INTERFACE = "vpd-ingress"
UPLINK_ADDRESS = "198.18.127.1/30"
UPLINK_GATEWAY = "198.18.127.2"
UPLINK_METRIC = "32000"
RELAY_PORT = 39823


@dataclass(frozen=True)
class Upstream:
    host: str
    port: int
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)

    @classmethod
    def parse(cls, raw):
        from .core import GatewayError

        value = raw.strip()
        if not value:
            return None
        message = "Enter a SOCKS5 upstream such as socks5://127.0.0.1:8083."
        if any(char.isspace() or not char.isprintable() for char in value):
            raise GatewayError(message)
        try:
            parsed = urlsplit(value if "://" in value else f"socks5://{value}")
            host, port = parsed.hostname, parsed.port
        except ValueError:
            raise GatewayError(message) from None
        if (parsed.scheme not in {"socks5", "socks5h"} or not host or not port
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise GatewayError(message)

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise GatewayError(message) from None
            if not re.fullmatch(r"[a-zA-Z0-9._-]+", host):
                raise GatewayError(message)
        else:
            if "%" in host:
                raise GatewayError("Use an upstream endpoint without an IPv6 zone identifier.")
            host = str(ip)

        username = _credential(parsed.username)
        password = _credential(parsed.password)
        if bool(username) != bool(password):
            raise GatewayError("Provide both SOCKS5 credentials, or omit both.")
        # Explicit but empty userinfo is invalid rather than an invisible change to no-auth.
        if parsed.username is not None and not username:
            raise GatewayError("Provide both SOCKS5 credentials, or omit both.")
        return cls(host, port, username, password)

    @property
    def address(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"socks5://{host}:{self.port}"

    @property
    def tcp_destination(self):
        if ":" in self.host:
            return f"TCP6:[{self.host}]:{self.port},connect-timeout=4"
        return f"TCP4:{self.host}:{self.port},connect-timeout=4"


def _credential(value):
    from .core import GatewayError

    if value is None:
        return ""
    message = "Use valid percent-encoded SOCKS5 credentials of at most 255 UTF-8 bytes each."
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise GatewayError(message)
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeError:
        raise GatewayError(message) from None
    if len(decoded.encode("utf-8")) > 255 or any(not char.isprintable() for char in decoded):
        raise GatewayError(message)
    return decoded


def ingress_configuration(upstream):
    outbound = {
        "type": "socks", "tag": "upstream", "server": "127.0.0.1",
        "server_port": RELAY_PORT, "version": "5", "network": "tcp",
    }
    if upstream.username:
        outbound.update(username=upstream.username, password=upstream.password)
    return {
        "log": {"disabled": True},
        "inbounds": [{
            "type": "tun", "interface_name": UPLINK_INTERFACE,
            "address": [UPLINK_ADDRESS], "auto_route": False, "dns_mode": "disabled",
        }],
        "outbounds": [outbound],
        "dns": {
            "servers": [{
                "type": "https", "tag": "resolver", "server": "1.1.1.1", "server_port": 443,
                "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}, "detour": "upstream",
            }],
            "final": "resolver", "strategy": "ipv4_only",
        },
        "route": {
            "rules": [
                {"port": 53, "action": "hijack-dns"},
                {"network": "udp", "action": "reject"},
            ],
            "final": "upstream",
        },
    }


def _authenticate(path, upstream):
    from .core import GatewayError, receive_exact

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as relay:
            relay.settimeout(0.5)
            relay.connect(str(path))
            method = 2 if upstream.username else 0
            relay.sendall(bytes((5, 1, method)))
            selected = receive_exact(relay, 2)
            if selected != bytes((5, method)):
                raise GatewayError("The SOCKS5 upstream did not accept the selected authentication method.")
            if method:
                username, password = upstream.username.encode("utf-8"), upstream.password.encode("utf-8")
                relay.sendall(bytes((1, len(username))) + username + bytes((len(password),)) + password)
                if receive_exact(relay, 2) != b"\x01\x00":
                    raise GatewayError("The SOCKS5 upstream rejected the supplied credentials.")
    except (OSError, EOFError):
        return False
    return True


def _socat_path(path):
    # The address is parsed by socat even though there is no shell involved.
    return str(path).replace("\\", "\\\\").replace(",", "\\,")


def start_chained(gateway, upstream, stop):
    """Activate a TUN with no egress path other than the selected proxy."""
    from .core import GatewayError

    processes = []
    gateway.uplink_processes = processes
    ip, socat = gateway.tools["ip"], gateway.tools["socat"]
    relay_path = gateway.directory / "ingress.sock"
    relay_address = _socat_path(relay_path)
    gateway._network(ip, "link", "set", "dev", "lo", "up")
    processes.append(gateway._spawn("Upstream relay", [
        socat, f"UNIX-LISTEN:{relay_address},fork,mode=0600", upstream.tcp_destination,
    ]))
    processes.append(gateway._spawn("Private relay", gateway._enter(
        socat, f"TCP4-LISTEN:{RELAY_PORT},bind=127.0.0.1,reuseaddr,fork", f"UNIX-CONNECT:{relay_address}",
    ), fds=gateway.namespace_fds))

    def check_processes():
        if any(process.poll() is not None for process in processes):
            raise GatewayError("The private SOCKS5 uplink stopped. See Activity for relay startup details.")

    def authenticate():
        check_processes()
        return _authenticate(relay_path, upstream)

    gateway._wait(authenticate, stop, 8, "Could not reach the selected SOCKS5 upstream.")
    if stop.is_set():
        raise InterruptedError("Stopped.")
    fd = os.memfd_create("vpndock-ingress", os.MFD_CLOEXEC)
    with os.fdopen(fd, "wb") as config:
        config.write(json.dumps(ingress_configuration(upstream)).encode("utf-8"))
        config.flush()
        processes.append(gateway._spawn("Private SOCKS5 uplink", gateway._enter(
            gateway.tools["sing-box"], "run", "-c", f"/proc/self/fd/{fd}",
        ), fds=(*gateway.namespace_fds, fd)))

    def interface_ready():
        check_processes()
        links = gateway._ip("-4", "addr", "show", "dev", UPLINK_INTERFACE)
        return any("UP" in link.get("flags", ()) and
                   any(address.get("local") == UPLINK_ADDRESS.split("/", 1)[0]
                       for address in link.get("addr_info", ()))
                   for link in links)

    gateway._wait(interface_ready, stop, 8, "The private SOCKS5 TUN did not become ready.")
    gateway._network(ip, "-4", "route", "add", "default", "via", UPLINK_GATEWAY,
                     "dev", UPLINK_INTERFACE, "metric", UPLINK_METRIC)
    return processes
