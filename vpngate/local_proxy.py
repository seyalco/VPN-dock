"""Detect application-owned IPv4 loopback proxies from inside a private desktop."""

from ast import literal_eval
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys


@dataclass(frozen=True)
class LocalProxy:
    scheme: str
    host: str
    port: int
    inode: int
    advertised: bool = False


def app_pid(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            value = stream.read(20).strip()
            return int(value) if value.isdigit() and int(value) > 1 else None
    except OSError:
        return None


def owned_by_app(pid, root):
    while pid > 1:
        if pid == root:
            return True
        try:
            status = (Path("/proc") / str(pid) / "status").read_text()
            parent = re.search(r"^PPid:\s*(\d+)$", status, re.M)
            pid = int(parent[1]) if parent else 0
        except OSError:
            return False
    return False


def listeners(marker, ss):
    root = app_pid(marker)
    if root is None:
        return []
    result = subprocess.run([ss, "-H", "-4", "-lntpe"], capture_output=True,
                            text=True, timeout=1, check=True)
    found = set()
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        host, _, port = fields[3].rpartition(":")
        inode = re.search(r"\bino:(\d+)", fields[5])
        owners = {int(pid) for pid in re.findall(r"\bpid=(\d+),fd=", fields[5])}
        try:
            valid = ipaddress.IPv4Address(host).is_loopback and 1 <= int(port) <= 65535
        except ValueError:
            continue
        if valid and inode and owners and all(owned_by_app(pid, root) for pid in owners):
            found.add((host, int(port), int(inode[1])))
    return sorted(found)


def _receive(connection, length):
    value = bytearray()
    while len(value) < length:
        block = connection.recv(length - len(value))
        if not block:
            return None
        value.extend(block)
    return bytes(value)


def _socks(address):
    try:
        with socket.create_connection(address, timeout=0.25) as connection:
            connection.sendall(b"\x05\x01\x00")
            return _receive(connection, 2) == b"\x05\x00"
    except OSError:
        return False


def _http(address):
    # Prove CONNECT reaches a private endpoint. A web server can answer HTTP
    # with status 200 yet cannot send the nonce from this listener.
    try:
        with socket.socket() as witness, socket.create_connection(address, timeout=0.25) as connection:
            witness.bind(("127.0.0.1", 0))
            witness.listen(1)
            witness.settimeout(0.25)
            authority = f"127.0.0.1:{witness.getsockname()[1]}"
            connection.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            # Wait for either side first, since servers may send 200 after dialing.
            with connection.makefile("rb", buffering=0) as response:
                if not re.match(rb"^HTTP/1\.[01] 2\d\d(?: |\r)", response.readline(512)):
                    return False
                for _ in range(16):
                    if response.readline(512) == b"\r\n":
                        break
                else:
                    return False
                nonce = secrets.token_bytes(16)
                accepted, _ = witness.accept()
                with accepted:
                    accepted.settimeout(0.25)
                    accepted.sendall(nonce)
                return _receive(connection, len(nonce)) == nonce
    except OSError:
        return False


def _advertised(marker):
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/run/vpndock/home",
        "XDG_RUNTIME_DIR": "/run/vpndock",
        "XDG_CONFIG_HOME": "/run/vpndock/home/config",
        "DCONF_PROFILE": str(Path(marker).parents[1] / "desktop/dconf-profile"),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/vpndock/bus",
        "GSETTINGS_BACKEND": "dconf",
    }

    def setting(section, key):
        result = subprocess.run(["gsettings", "get", "org.gnome.system.proxy" + section, key],
                                capture_output=True, text=True, timeout=0.35, env=environment, check=True)
        return literal_eval(result.stdout)

    try:
        if setting("", "mode") != "manual":
            return set()
        result = set()
        for scheme in ("socks", "http", "https"):
            host = setting(f".{scheme}", "host")
            port = setting(f".{scheme}", "port")
            if isinstance(host, str) and isinstance(port, int):
                host = "127.0.0.1" if host.lower().rstrip(".") == "localhost" else host
                result.add(("http" if scheme == "https" else scheme, host, port))
        return result
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        return set()


def detect(candidates, marker):
    found = []
    if len(candidates) > 12:
        return found
    preferred = _advertised(marker) if len(candidates) > 1 else set()
    for host, port, inode in candidates:
        if _socks((host, port)):
            found.append(LocalProxy("socks", host, port, inode, ("socks", host, port) in preferred))
        elif _http((host, port)):
            found.append(LocalProxy("http", host, port, inode, ("http", host, port) in preferred))
    return found


if __name__ == "__main__":
    from dataclasses import asdict

    marker, ss, operation, *reserved = sys.argv[1:]
    excluded = {int(port) for port in reserved}
    try:
        sockets = [item for item in listeners(marker, ss) if item[1] not in excluded]
        print(json.dumps([asdict(item) for item in detect(sockets, marker)] if operation == "detect" else sockets))
    except (OSError, ValueError, subprocess.SubprocessError):
        print("[]")
