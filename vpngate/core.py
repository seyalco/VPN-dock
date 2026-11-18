"""Supervise a private VPN namespace and its host-loopback proxy."""

from contextlib import ExitStack
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time

from .ingress import RELAY_PORT, UPLINK_INTERFACE as CHAIN_UPLINK, Upstream, start_chained
from .local_proxy import LocalProxy

ROOT = Path(__file__).resolve().parent
UPLINK = "vpngate0"
MIXED_PORT = 39821
RESOLVER = "1.1.1.1"
PROXY_ID = 1


class GatewayError(RuntimeError):
    pass


class SingBoxMissingError(GatewayError):
    pass


@dataclass(frozen=True)
class Config:
    command: str
    interface: str
    port: int
    directory: str = ""
    upstream: str = ""

    def working_directory(self):
        path = Path(self.directory or Path.home()).expanduser().resolve()
        if not path.is_dir():
            raise GatewayError("Choose an existing working folder.")
        return path

    def argv(self):
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", self.interface)
                or self.interface in {UPLINK, CHAIN_UPLINK, "lo", ".", ".."} or self.interface.startswith("-")):
            raise GatewayError("Enter the private VPN interface name, for example tun0 or wg0.")
        if not isinstance(self.port, int) or not 1024 <= self.port <= 65535:
            raise GatewayError("Choose a local TCP port from 1024 to 65535.")
        try:
            args = shlex.split(self.command)
        except ValueError as error:
            raise GatewayError("Check the quoting in the VPN command.") from error
        folder = self.working_directory()
        name = os.path.expanduser(args[0]) if args else ""
        executable = shutil.which(str(folder / name) if "/" in name else name) if name else None
        from .validation import validate_native

        validate_native(args, executable=executable, directory=folder)
        if not executable:
            raise GatewayError("Choose an executable native VPN client.")
        if Path(executable).name in {"sudo", "pkexec", "systemctl", "xdg-open"}:
            raise GatewayError("Choose the VPN executable itself.")
        return [os.path.abspath(executable), *args[1:]]


def remove_owned_socket(path, device, inode):
    try:
        current = path.lstat()
        if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (device, inode):
            path.unlink()
    except FileNotFoundError:
        pass


def find_sing_box():
    instructions = (
        "Install sing-box 1.14 or newer using your distribution’s package manager, or download the Linux "
        "build for your architecture from https://github.com/SagerNet/sing-box/releases. Place the extracted "
        "binary at ~/.local/bin/sing-box and run chmod +x ~/.local/bin/sing-box."
    )
    override = os.environ.get("VPNDOCK_SING_BOX")
    if override:
        executable = shutil.which(os.path.expanduser(override))
        if executable:
            return os.path.abspath(executable)
        raise SingBoxMissingError(f"VPNDOCK_SING_BOX does not point to an executable sing-box.\n\n{instructions}")

    home = Path.home()
    data_home = Path(os.environ.get("XDG_DATA_HOME", ""))
    if not data_home.is_absolute():
        data_home = home / ".local/share"
    launcher_dir = Path(os.environ.get("VPNDOCK_LAUNCHER_DIR", ""))
    bases = (launcher_dir, ROOT.parent) if launcher_dir.is_absolute() else (ROOT.parent,)
    candidates = [base / name for base in bases for name in ("bin/sing-box", "sing-box")]
    candidates.extend((data_home / "vpndock/bin/sing-box", home / ".local/bin/sing-box", "sing-box"))
    for candidate in candidates:
        executable = shutil.which(str(candidate))
        if executable:
            return os.path.abspath(executable)
    raise SingBoxMissingError(instructions)


def dependencies():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise GatewayError("Run VPN Dock on Linux as your desktop user.")
    engine = find_sing_box()
    found = {name: shutil.which(name) for name in (
        "bwrap", "pasta", "nsenter", "unshare", "getsubids", "setpriv", "ip", "ss", "socat", "nft",
    )}
    missing = [name for name, executable in found.items() if not executable]
    if missing:
        raise GatewayError("Missing runtime tools: " + ", ".join(missing))
    try:
        device = Path("/dev/net/tun")
        if not stat.S_ISCHR(device.stat().st_mode) or not os.access(device, os.R_OK | os.W_OK):
            raise OSError
    except OSError as error:
        raise GatewayError("The /dev/net/tun device is not available.") from error
    from .desktop import DesktopError, desktop_dependencies

    try:
        found.update(desktop_dependencies().tools)
    except DesktopError as error:
        raise GatewayError(str(error)) from error
    found["sing-box"] = engine
    return found


def subordinate_id(getsubids, *, group=False):
    username = pwd.getpwuid(os.getuid()).pw_name
    arguments = [getsubids, *(["-g"] if group else []), username]
    owner = os.getgid() if group else os.getuid()
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=3, check=True)
        for line in result.stdout.splitlines():
            _, _, start, size = line.rsplit(maxsplit=3)
            start, size = int(start), int(size)
            candidate = start + (start == owner)
            if 0 < candidate < start + size:
                return candidate
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    kind = "GID" if group else "UID"
    raise GatewayError(f"No delegated {kind} range is configured for {username}. VPN Dock needs one ID for its proxy.")


def proxy_configuration(interface):
    config = {
        "log": {"level": "warn", "disabled": False},
        "inbounds": [{
            "type": "mixed", "listen": "127.0.0.1", "listen_port": MIXED_PORT, "set_system_proxy": False,
        }],
        "route": {
            "rules": [{"network": "udp", "action": "reject"}, {"ip_version": 6, "action": "reject"}],
            "final": "vpn",
        },
    }
    if isinstance(interface, LocalProxy):
        outbound = {"type": interface.scheme, "tag": "vpn", "server": interface.host,
                    "server_port": interface.port, "connect_timeout": "8s"}
        if interface.scheme == "socks":
            outbound.update(version="5", network="tcp")
        config["outbounds"] = [outbound]
    else:
        config["outbounds"] = [{
            "type": "direct", "tag": "vpn", "bind_interface": interface,
            "domain_resolver": "doh", "connect_timeout": "8s",
        }]
        config["dns"] = {
            "servers": [{
                "type": "https", "tag": "doh", "server": RESOLVER,
                "tls": {"server_name": "cloudflare-dns.com"}, "detour": "vpn",
            }],
            "final": "doh", "strategy": "ipv4_only",
        }
    return config


def receive_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        block = conn.recv(length - len(data))
        if not block:
            raise OSError("Incomplete proxy handshake.")
        data.extend(block)
    return bytes(data)


class BridgeHandler(socketserver.BaseRequestHandler):
    def _tcp_only(self, upstream):
        # HTTP is passed through. SOCKS5 must report UDP as unsupported rather
        # than provide a loopback UDP address that cannot cross the TCP bridge.
        if self.request.recv(1, socket.MSG_PEEK) != b"\x05":
            return True
        greeting = receive_exact(self.request, 2)
        upstream.sendall(greeting + receive_exact(self.request, greeting[1]))
        selected = receive_exact(upstream, 2)
        self.request.sendall(selected)
        if selected != b"\x05\x00":
            return False
        request = receive_exact(self.request, 4)
        if request[:3] != b"\x05\x01\x00":
            self.request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return False
        upstream.sendall(request)
        return True

    def handle(self):
        gate = self.server.gateway
        if not gate.ready.is_set() or not self.server.slots.acquire(blocking=False):
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(4)
                upstream.connect(str(gate.upstream))
                self.request.settimeout(4)
                if not self._tcp_only(upstream):
                    return
                sockets = {self.request: upstream, upstream: self.request}
                active = set(sockets)
                while active and gate.ready.is_set():
                    readable, _, _ = select.select(list(active), [], [], 0.25)
                    for source in readable:
                        data = source.recv(65536)
                        if data:
                            sockets[source].sendall(data)
                        else:
                            active.remove(source)
                            sockets[source].shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            self.server.slots.release()


class Bridge(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, gateway, port):
        self.gateway = gateway
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(("127.0.0.1", port), BridgeHandler, bind_and_activate=False)
        try:
            self.server_bind()
        except OSError:
            self.server_close()
            raise


def stop_group(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


class Gateway:
    def __init__(self, config, *, output=None):
        self.config = config
        self.output = output or (lambda _source, _line: None)
        self.ready = threading.Event()
        self.files = ExitStack()
        self.processes = []
        self.readers = {}
        self.serving = False
        self.vpn_interface = None
        self.proxy = None
        self.relay = None
        self.relay_inode = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._stop_proxy()
        if self.serving:
            self.bridge.shutdown()
        for process in reversed(self.processes.copy()):
            self._stop_process(process)
        self.files.close()

    def _spawn(self, source, args, *, fds=(), stdin=subprocess.DEVNULL):
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy"}
               and key not in {"RES_OPTIONS", "LOCALDOMAIN", "HOSTALIASES",
                               "VPNDOCK_EXPORT_SOCKET", "VPNDOCK_EXPORT_PORT"}}
        child = subprocess.Popen(
            [sys.executable, str(ROOT / "guard.py"), str(os.getpid()), *args],
            cwd=Path.home(), env=env, stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True, pass_fds=fds,
        )
        self.processes.append(child)

        def drain():
            with child.stdout:
                while raw := child.stdout.readline(4096):
                    line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw.decode(errors="replace")).strip()
                    if line:
                        self.output(source, line)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        self.readers[child] = reader
        return child

    def _stop_process(self, process):
        stop_group(process)
        self.processes.remove(process)
        self.readers.pop(process).join(0.3)

    def _wait(self, check, stop, timeout, message):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not stop.is_set():
            result = check()
            if result:
                return result
            stop.wait(0.15)
        if stop.is_set():
            raise InterruptedError("Stopped.")
        raise GatewayError(message)

    def _namespace(self, fd, data):
        if self.client.poll() is not None:
            raise GatewayError("Could not create the private VPN desktop. See Activity for details.")
        if select.select([fd], [], [], 0)[0]:
            chunk = os.read(fd, 4096)
            if not chunk:
                raise GatewayError("The private desktop did not report its process ID.")
            data.extend(chunk)
            try:
                return int(json.loads(data)["child-pid"])
            except json.JSONDecodeError:
                pass
        return None

    def start(self, stop):
        if stop.is_set():
            raise InterruptedError("Stopped.")
        if "VPNDOCK_EXPORT_SOCKET" in os.environ or "VPNDOCK_EXPORT_PORT" in os.environ:
            raise GatewayError("Open VPN Dock directly and enter Proxy A in the SOCKS5 field.")
        args = self.config.argv()
        upstream = Upstream.parse(self.config.upstream)
        self.tools = dependencies()
        if (upstream and upstream.host.lower().rstrip(".") in {"127.0.0.1", "localhost"}
                and upstream.port == self.config.port):
            raise GatewayError("Use different endpoints for the upstream SOCKS5 proxy and VPN Dock's output.")
        self.directory = Path(self.files.enter_context(tempfile.TemporaryDirectory(prefix="vpndock-", dir="/tmp")))
        self.desktop_work = self.directory / "application"
        self.desktop_work.mkdir(mode=0o700)
        try:
            self.bridge = Bridge(self, self.config.port)
        except OSError as error:
            raise GatewayError(f"Cannot reserve 127.0.0.1:{self.config.port}: {error.strerror}.") from error
        self.files.callback(self.bridge.server_close)
        self.upstream = self.directory / "proxy.sock"
        self._start_client(args, stop)
        self._install_kill_switch()
        if upstream:
            self.uplink_processes = start_chained(self, upstream, stop)
        else:
            self.uplink_processes = [self._spawn("Uplink", [
                self.tools["pasta"], "-f", "--config-net", "--no-map-gw", "--no-netns-quit", "-4",
                "-t", "none", "-u", "none", "-T", "none", "-U", "none", "-I", UPLINK,
                str(self.client_pid),
            ])]
        base = CHAIN_UPLINK if upstream else UPLINK
        self._wait(lambda: self._uplink_ready(base), stop, 12, "The private uplink did not install an IPv4 route.")
        (self.desktop_work / "uplink-ready").touch()
        self._wait_for_vpn(stop)

    def _wait_for_vpn(self, stop):
        if self.config.interface == "auto":
            self.output("VPN Dock", "Waiting for a tunnel route or a local proxy owned by the VPN client.")
        else:
            self.output("VPN Dock", f"Waiting for {self.config.interface} to have a usable IPv4 route. Connect in the VPN client if needed.")
        next_scan = 0
        pending_policy = None
        while not stop.is_set():
            automatic = self.config.interface == "auto"
            identity = self._vpn_identity(allow_policy=not automatic)
            if identity is None and automatic and time.monotonic() >= next_scan:
                local = self._local_proxies(detect=True)
                identity = self._choose_local_proxy(local)
                if identity is None and not local:
                    policy = self._vpn_identity()
                    if policy == pending_policy:
                        identity = policy
                    pending_policy = policy
                next_scan = time.monotonic() + 1
            if identity is not None:
                if self._start_proxy(identity, stop):
                    return
                self._allow_egress(None)
                self._stop_proxy()
            stop.wait(0.25)
        raise InterruptedError("Stopped.")

    def _start_client(self, args, stop):
        from .desktop import DesktopError, HOME, desktop_keyring, desktop_mounts

        uid = subordinate_id(self.tools["getsubids"])
        gid = subordinate_id(self.tools["getsubids"], group=True)
        holder = self._spawn("User namespace", [self.tools["unshare"], "--map-root-user",
                             f"--map-users={PROXY_ID}:{uid}:1", f"--map-groups={PROXY_ID}:{gid}:1",
                             "--", "/usr/bin/sleep", "infinity"])

        def mappings_ready():
            if holder.poll() is not None:
                raise GatewayError("Could not configure the rootless user namespace. Check subordinate UID/GID support.")
            return all((PROXY_ID, value, 1) in [tuple(map(int, line.split())) for line in
                       Path(f"/proc/{holder.pid}/{kind}_map").read_text().splitlines()]
                       for kind, value in (("uid", uid), ("gid", gid)))

        self._wait(mappings_ready, stop, 5, "Could not initialize the isolated proxy identity.")
        user = self.files.enter_context(open(f"/proc/{holder.pid}/ns/user", "rb")).fileno()
        read_fd, write_fd = os.pipe()
        stdin = subprocess.DEVNULL
        try:
            folder = self.config.working_directory() if self.config.directory else HOME
            try:
                keyring = self.files.enter_context(desktop_keyring(args[0]))
                mounts = desktop_mounts(self.desktop_work, RESOLVER,
                                        CHAIN_UPLINK if self.config.upstream else UPLINK,
                                        working_directory=self.config.directory or None, executable=args[0],
                                        keyring=keyring)
                if keyring is not None:
                    stdin = keyring.unlock_pipe()
            except DesktopError as error:
                raise GatewayError(str(error)) from error
            command = [
                self.tools["bwrap"], "--userns", str(user), "--uid", "0", "--gid", "0",
                "--unshare-net", "--unshare-pid", "--die-with-parent",
                "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_RAW",
                # A private UID 0 can then set up child user namespaces for
                # desktop helpers such as sandboxed image decoders.
                "--cap-add", "CAP_SETFCAP", "--info-fd", str(write_fd),
                *mounts, "--chdir", str(folder), "--", sys.executable, str(ROOT / "desktop.py"),
                str(self.desktop_work / "uplink-ready"), *args,
            ]
            self.client = self._spawn("VPN", command, fds=(user, write_fd,), stdin=stdin)
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)
            if stdin != subprocess.DEVNULL:
                stdin.close()
        try:
            data = bytearray()
            self.client_pid = self._wait(lambda: self._namespace(read_fd, data), stop, 8,
                                         "Could not create a rootless VPN namespace.")
        finally:
            os.close(read_fd)
        net = self.files.enter_context(open(f"/proc/{self.client_pid}/ns/net", "rb")).fileno()
        if os.fstat(net).st_ino == os.stat("/proc/self/ns/net").st_ino:
            raise GatewayError("Refused to start the VPN in the host network.")
        if os.fstat(user).st_ino != os.stat(f"/proc/{self.client_pid}/ns/user").st_ino:
            raise GatewayError("The private VPN desktop did not use the reserved user namespace.")
        self.namespace_fds = (user, net)
        self.desktop_fds = tuple(
            self.files.enter_context(open(f"/proc/{self.client_pid}/ns/{name}", "rb")).fileno()
            for name in ("mnt", "pid")
        )

    def _enter(self, *args):
        user, net = self.namespace_fds
        return [self.tools["nsenter"], f"--user=/proc/self/fd/{user}", f"--net=/proc/self/fd/{net}",
                "--preserve-credentials", "--", *args]

    def _local_proxies(self, *, detect=False):
        user, net = self.namespace_fds
        mount, pid = self.desktop_fds
        command = [self.tools["nsenter"], f"--user=/proc/self/fd/{user}", f"--net=/proc/self/fd/{net}",
                   f"--mount=/proc/self/fd/{mount}", f"--pid=/proc/self/fd/{pid}",
                   "--preserve-credentials", "--", sys.executable, str(ROOT / "local_proxy.py"),
                   str(self.desktop_work / "app-state/app.pid"), self.tools["ss"],
                   "detect" if detect else "list", str(MIXED_PORT), str(RELAY_PORT)]
        try:
            reply = subprocess.run(command, pass_fds=(*self.namespace_fds, *self.desktop_fds),
                                   capture_output=True, text=True, timeout=4 if detect else 2, check=True)
            result = json.loads(reply.stdout)
            return [LocalProxy(**item) for item in result] if detect else [tuple(item) for item in result]
        except (OSError, ValueError, subprocess.SubprocessError):
            return []

    @staticmethod
    def _choose_local_proxy(candidates):
        preferred = [candidate for candidate in candidates if candidate.advertised] or candidates
        choices = [candidate for candidate in preferred if candidate.scheme == "socks"] or preferred
        return choices[0] if len(choices) == 1 else None

    def _network(self, *args, input_text=None):
        try:
            result = subprocess.run(self._enter(*args), pass_fds=self.namespace_fds, input=input_text,
                                    capture_output=True, text=True, timeout=4)
        except (OSError, subprocess.SubprocessError) as error:
            raise GatewayError("A private network command could not run.") from error
        if result.returncode:
            detail = result.stderr.strip().splitlines()
            raise GatewayError(f"Could not configure the private network: {''.join(detail[:1])[:240]}")
        return result.stdout

    def _ip(self, *args):
        try:
            result = subprocess.run(self._enter(self.tools["ip"], "-j", *args), pass_fds=self.namespace_fds,
                                    capture_output=True, text=True, timeout=2)
            return json.loads(result.stdout) if result.returncode == 0 else []
        except (subprocess.TimeoutExpired, ValueError):
            return []

    def _uplink_ready(self, interface):
        self._require_alive()
        expected = self._ip("-4", "route", "get", RESOLVER)
        return bool(expected and expected[0].get("dev") == interface)

    @staticmethod
    def _vpn_link(link):
        if link["ifname"] in {UPLINK, CHAIN_UPLINK, "lo"}:
            return False
        info = link.get("linkinfo", {})
        kind = info.get("info_kind")
        return kind == "wireguard" or (kind == "tun" and info.get("info_data", {}).get("type") in {"tun", "tap"})

    def _vpn_identity(self, *, allow_policy=True):
        self._require_alive()
        name = self.config.interface
        active = self._ip("-4", "route", "get", RESOLVER, "uid", str(PROXY_ID))
        active_name = active[0].get("dev") if active else None
        command = ("-d", "link", "show") if name == "auto" else ("-d", "link", "show", "dev", name)
        links = [link for link in self._ip(*command)
                 if self._vpn_link(link) and "UP" in link.get("flags", ())]
        for link in links:
            if link["ifname"] == active_name:
                return active_name, link["ifindex"]
        if not allow_policy:
            return None

        # Policy routing can leave the base path as the unbound answer while
        # exposing an actual default route for sockets bound to the VPN link.
        candidates = []
        for link in links:
            device = link["ifname"]
            routes = self._ip("-4", "route", "show", "table", "all", "dev", device)
            if not any(route.get("dst") == "default" and route.get("type", "unicast") == "unicast"
                       for route in routes):
                continue
            bound = self._ip("-4", "route", "get", RESOLVER, "oif", device, "uid", str(PROXY_ID))
            if bound and bound[0].get("dev") == device:
                candidates.append((device, link["ifindex"]))
        return candidates[0] if len(candidates) == 1 else None

    def _require_alive(self):
        if self.client.poll() is not None:
            raise GatewayError("The VPN client exited. See its output for details.")
        if any(process.poll() is not None for process in self.uplink_processes):
            raise GatewayError("The private uplink stopped.")

    def _install_kill_switch(self):
        # The process that creates egress sockets runs under the delegated UID.
        # An empty set drops its outbound traffic before any proxy can start.
        self._network(self.tools["nft"], "-f", "-", input_text=f"""
table inet vpndock_egress {{
    set vpn {{ type iface_index; }}
    set client_proxy {{ type ipv4_addr . inet_service; }}
    chain output {{
        type filter hook output priority -5; policy accept;
        meta skuid {PROXY_ID} oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {MIXED_PORT} accept
        meta skuid {PROXY_ID} oifname "lo" ip daddr . tcp dport @client_proxy accept
        meta skuid {PROXY_ID} oifname {{ "{UPLINK}", "{CHAIN_UPLINK}" }} counter drop
        meta skuid {PROXY_ID} meta oif @vpn ip protocol tcp accept
        meta skuid {PROXY_ID} counter drop
    }}
}}
""")

    def _allow_egress(self, identity):
        rules = "flush set inet vpndock_egress vpn\nflush set inet vpndock_egress client_proxy\n"
        if isinstance(identity, LocalProxy):
            host = ipaddress.IPv4Address(identity.host)
            if not host.is_loopback or not 1 <= identity.port <= 65535:
                raise GatewayError("The client proxy endpoint is outside IPv4 loopback.")
            rules += f"add element inet vpndock_egress client_proxy {{ {host} . {identity.port} }}\n"
        elif identity is not None:
            rules += f"add element inet vpndock_egress vpn {{ {int(identity[1])} }}\n"
        self._network(self.tools["nft"], "-f", "-", input_text=rules)

    def _egress_active(self, identity):
        if isinstance(identity, LocalProxy):
            self._require_alive()
            return (identity.host, identity.port, identity.inode) in self._local_proxies()
        return self._vpn_identity() == identity

    def _proxy_user(self, *args):
        return self._enter(*self._drop_proxy_privileges(), *args)

    def _drop_proxy_privileges(self):
        return [self.tools["setpriv"], "--no-new-privs", "--bounding-set=-all",
                "--inh-caps=-all", "--ambient-caps=-all", "--clear-groups",
                f"--reuid={PROXY_ID}", f"--regid={PROXY_ID}", "--"]

    def _start_proxy(self, identity, stop):
        self._allow_egress(identity)
        local = isinstance(identity, LocalProxy)
        # The restricted UID cannot traverse the owner's temp directories.
        # Pass the executable and configuration as already-open descriptors.
        config = os.memfd_create("vpndock-egress", os.MFD_CLOEXEC)
        with os.fdopen(config, "w+b") as profile, open(self.tools["sing-box"], "rb") as engine:
            profile.write(json.dumps(proxy_configuration(identity if local else identity[0])).encode())
            profile.flush()
            os.fchmod(config, 0o444)
            profile.seek(0)
            descriptors = (engine.fileno(), profile.fileno())
            self.proxy = self._spawn("Proxy", self._enter(
                sys.executable, str(ROOT / "proxy_worker.py"), *(str(fd) for fd in descriptors),
                *self._drop_proxy_privileges(), f"/proc/self/fd/{descriptors[0]}",
                "run", "-c", f"/proc/self/fd/{descriptors[1]}",
            ), fds=(*self.namespace_fds, *descriptors))
        self.relay = self._spawn("Relay", self._enter(self.tools["socat"],
            f"UNIX-LISTEN:{self.upstream},fork,mode=0600", f"TCP4:127.0.0.1:{MIXED_PORT}"),
            fds=self.namespace_fds)

        def check():
            if self.proxy.poll() is not None or self.relay.poll() is not None:
                raise GatewayError("The local proxy or relay could not start.")
            try:
                if self.relay_inode is None:
                    info = self.upstream.lstat()
                    if stat.S_ISSOCK(info.st_mode):
                        self.relay_inode = (info.st_dev, info.st_ino)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.settimeout(0.4)
                    conn.connect(str(self.upstream))
                    conn.sendall(b"\x05\x01\x00")
                    return conn.recv(2) == b"\x05\x00"
            except OSError:
                return False

        self._wait(check, stop, 10, "The local proxy did not become ready.")
        if not self._egress_active(identity):
            return False
        self.vpn_interface = identity
        if not self.serving:
            self.bridge.server_activate()
            thread = threading.Thread(target=self.bridge.serve_forever, kwargs={"poll_interval": 0.15}, daemon=True)
            thread.start()
            self.serving = True
        address = f"127.0.0.1:{self.config.port}"
        self.ready.set()
        source = (f"client {identity.scheme.upper()} proxy at {identity.host}:{identity.port}"
                  if local else f"VPN interface {identity[0]}")
        self.output("VPN Dock", f"Local proxies ready on {address} via {source} · TCP/IPv4.")
        return True

    def _stop_proxy(self):
        self.ready.clear()
        for process in (self.relay, self.proxy):
            if process is not None:
                self._stop_process(process)
        self.proxy = self.relay = self.vpn_interface = None
        if self.relay_inode is not None:
            remove_owned_socket(self.upstream, *self.relay_inode)
            self.relay_inode = None

    def follow(self, stop):
        while not stop.wait(0.25):
            if self.proxy.poll() is not None or self.relay.poll() is not None:
                raise GatewayError("The proxy or relay stopped.")
            identity = self.vpn_interface
            if (not self._egress_active(identity)
                    or (isinstance(identity, LocalProxy) and self._vpn_identity(allow_policy=False) is not None)):
                self._allow_egress(None)
                self._stop_proxy()
                self.output("VPN Dock", "The selected VPN path changed. Waiting for an active tunnel or client proxy.")
                self._wait_for_vpn(stop)
