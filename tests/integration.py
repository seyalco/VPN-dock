"""Exercise a real private VPN TUN and its kernel egress guard."""

from contextlib import contextmanager
import errno
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

FIXTURE_ADDRESS = "198.18.0.2"
BOOTSTRAP_ADDRESS = "198.19.0.2"
FIXTURE_PORT = 18871
CLIENT_PROXY_PORT = 18872
FIXTURE_IFACE = "tunproof0"
BODY = b"VPN Dock private fixture\n"


class FixtureHTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_):
        pass


@contextmanager
def fixture_server(port):
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), FixtureHTTP) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            worker.join(2)


@contextmanager
def engine_instance(engine, config):
    with tempfile.TemporaryDirectory(prefix="vpndock-engine-test-") as runtime:
        path = Path(runtime) / "fixture.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([engine, "run", "-c", str(path)])
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.04)
    return False


def echo_configuration(inbound, port, address):
    return {
        "log": {"level": "warn"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "fixture"}],
        "route": {"rules": [
            {"ip_cidr": [f"{address}/32"], "port": FIXTURE_PORT,
             "action": "route", "outbound": "fixture",
             "override_address": "127.0.0.1", "override_port": port},
            {"action": "reject"},
        ]},
    }


@contextmanager
def fixture_tun(engine, *, policy=False):
    inbound = {
        "type": "tun", "interface_name": FIXTURE_IFACE,
        "address": ["198.18.0.1/30"], "auto_route": False, "dns_mode": "disabled",
    }
    with engine_instance(engine, echo_configuration(inbound, FIXTURE_PORT, FIXTURE_ADDRESS)) as process:
        def up():
            if process.poll() is not None:
                raise RuntimeError("The private fixture TUN engine exited.")
            result = subprocess.run(["ip", "-j", "link", "show", "dev", FIXTURE_IFACE],
                                    capture_output=True, text=True, timeout=2)
            return result.returncode == 0 and "UP" in json.loads(result.stdout)[0]["flags"]

        assert wait_until(up), "The private fixture TUN did not appear."
        if policy:
            subprocess.run(["ip", "-4", "route", "replace", "default", "dev", FIXTURE_IFACE, "table", "62000"],
                           check=True)
            rule = ["oif", FIXTURE_IFACE, "lookup", "62000", "priority", "10020"]
            subprocess.run(["ip", "-4", "rule", "add", *rule], check=True)
            try:
                yield
            finally:
                subprocess.run(["ip", "-4", "rule", "del", *rule], check=True)
        else:
            subprocess.run(["ip", "-4", "route", "replace", "1.1.1.1/32", "dev", FIXTURE_IFACE], check=True)
            yield


@contextmanager
def fixture_proxy(engine, scheme, upstream):
    inbound = {"type": scheme, "listen": "127.0.0.1", "listen_port": CLIENT_PROXY_PORT}
    config = echo_configuration(inbound, FIXTURE_PORT, FIXTURE_ADDRESS)
    config["route"]["rules"][0].pop("ip_cidr")
    config["route"]["rules"][0]["domain"] = ["vpndock-fixture.invalid"]
    if upstream:
        config["route"]["rules"][0]["override_address"] = BOOTSTRAP_ADDRESS
    config["route"]["rules"].insert(1, {"ip_cidr": ["127.0.0.1/32"], "outbound": "fixture"})
    with engine_instance(engine, config) as process:
        assert wait_until(lambda: process.poll() is None and not refused(CLIENT_PROXY_PORT))
        yield


def run_fixture(engine, starting, dropping, reconnecting, scheme="tun", via="direct"):
    # The HTTP server is not assigned the TUN peer address. A request to that
    # peer reaches it only after the stub engine receives the packet on its TUN.
    with fixture_server(FIXTURE_PORT):
        assert wait_until(Path(starting).exists, timeout=45)
        def egress():
            return (fixture_tun(engine, policy=via == "chain") if scheme == "tun"
                    else fixture_proxy(engine, scheme, via == "chain"))

        with egress():
            assert wait_until(Path(dropping).exists, timeout=45)
        assert wait_until(Path(reconnecting).exists, timeout=30)
        with egress():
            while True:
                time.sleep(1)


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def refused(port):
    with socket.socket() as client:
        client.settimeout(1)
        return client.connect_ex(("127.0.0.1", port)) == errno.ECONNREFUSED


def curl_command(curl, address, *, proxy=None, extra=(), timeout="5"):
    route = ["--noproxy", "*", "--proxy", ""] if proxy is None else ["--noproxy", "", "--proxy", proxy]
    return [curl, "-fsS", "--max-time", timeout, *route, *extra, f"http://{address}:{FIXTURE_PORT}/"]


@contextmanager
def bootstrap_proxy(engine):
    # This host-loopback proxy has exactly one reserved test destination. It
    # never resolves or connects to a public address, even if the test fails.
    with fixture_server(0) as port:
        socks_port = free_port()
        inbound = {"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}
        with engine_instance(engine, echo_configuration(inbound, port, BOOTSTRAP_ADDRESS)) as process:
            assert wait_until(lambda: process.poll() is None and not refused(socks_port))
            yield f"socks5://127.0.0.1:{socks_port}"


def kernel_drops(gate):
    result = gate._network(gate.tools["nft"], "-j", "list", "chain", "inet", "vpndock_egress", "output")
    rules = (element.get("rule", {}).get("expr", []) for element in json.loads(result)["nftables"])
    return sum(expression["counter"]["packets"] for rule in rules
               if any("drop" in expression for expression in rule)
               for expression in rule if "counter" in expression)


def check_kernel_guard(gate, curl, address):
    direct = curl_command(curl, address, timeout="2")
    root = subprocess.run(gate._enter(*direct), pass_fds=gate.namespace_fds,
                          capture_output=True, timeout=4, check=True)
    assert root.stdout == BODY, "The controlled non-VPN route must be reachable for the test."
    before = kernel_drops(gate)
    restricted = subprocess.run(gate._proxy_user(*direct), pass_fds=gate.namespace_fds,
                                capture_output=True, timeout=4)
    assert restricted.returncode != 0, "The delegated proxy UID reached a non-VPN destination."
    assert kernel_drops(gate) > before, "nft did not log the delegated UID's denied egress."


def check_tundock(curl, engine, port, source):
    sys.path.insert(0, source)
    from tundock.core import Options, Proxy, Tunnel

    os.environ.setdefault("TUNDOCK_SING_BOX", engine)
    for scheme in ("socks5", "http"):
        proxy = Proxy.parse(f"{scheme}://127.0.0.1:{port}")
        with Tunnel(proxy, Options(), udp=False, ipv6=False) as tunnel:
            tunnel.start()
            result = tunnel.run(curl_command(curl, FIXTURE_ADDRESS))
            assert result.returncode == 0 and result.stdout.encode() == BODY, result.stderr
    print("Verified Tundock end-to-end over both exported proxy URLs.")


def exercise(work, engine, curl, upstream="", *, tundock_source=None, local_scheme=None):
    from vpngate.core import Config, Gateway, receive_exact

    # Only this explicit folder is shared into the VPN program's desktop.
    # Copy the stand-in engine here; no access to the user's install is needed.
    fixture = work / "fixture.py"
    fixture_engine = work / "fixture-engine"
    shutil.copy2(__file__, fixture)
    shutil.copy2(engine, fixture_engine)
    allow, drop, reconnect = (work / marker for marker in ("allow", "drop", "reconnect"))
    port = free_port()
    command = shlex.join([sys.executable, "-B", str(fixture), "--fixture",
                          str(fixture_engine), str(allow), str(drop), str(reconnect), local_scheme or "tun",
                          "chain" if upstream else "direct"])
    config = Config(command, "auto" if local_scheme else FIXTURE_IFACE, port, str(work), upstream)
    stop = Event()
    waiting = Event()
    follow = Event()
    ended = Event()
    activity = []
    failures = []

    def output(source, line):
        activity.append(f"{source}: {line}")
        if line.startswith("Waiting for"):
            waiting.set()

    gate = Gateway(config, output=output)

    def launch():
        try:
            with gate:
                gate.start(stop)
                if follow.wait(40) and not stop.is_set():
                    gate.follow(stop)
        except InterruptedError as error:
            if not stop.is_set():
                failures.append(error)
        except Exception as error:
            failures.append(error)
        finally:
            ended.set()

    worker = Thread(target=launch, daemon=True)
    worker.start()
    try:
        assert waiting.wait(20), (failures, activity[-20:])
        assert refused(port), "The host proxy listened before VPN readiness."
        if upstream:
            command = curl_command(curl, BOOTSTRAP_ADDRESS)
            assert subprocess.check_output(gate._enter(*command), pass_fds=gate.namespace_fds,
                                           timeout=7) == BODY
        allow.touch()
        assert gate.ready.wait(20), (failures, activity[-20:])
        first_vpn = gate.vpn_interface
        if local_scheme:
            assert first_vpn.scheme == local_scheme and first_vpn.port == CLIENT_PROXY_PORT, activity[-20:]
        export_address = f"127.0.0.1:{port}"
        target = "vpndock-fixture.invalid" if local_scheme else FIXTURE_ADDRESS
        for scheme, extra in (("socks5h", ()), ("http", ("--proxytunnel",))):
            command = curl_command(curl, target, proxy=f"{scheme}://{export_address}", extra=extra)
            assert subprocess.check_output(command, timeout=7) == BODY
        with socket.create_connection(("127.0.0.1", port), 3) as conn:
            conn.sendall(bytes.fromhex("050100"))
            assert receive_exact(conn, 2) == b"\x05\x00"
            conn.sendall(bytes.fromhex("05030001000000000000"))
            assert receive_exact(conn, 10)[:2] == b"\x05\x07"

        if tundock_source:
            check_tundock(curl, engine, port, tundock_source)

        drop.touch()
        assert wait_until(lambda: not gate._egress_active(first_vpn))
        # The test deliberately holds the user's route watcher, so only nft
        # can enforce the outage while the delegated process is still running.
        assert gate.ready.is_set() and gate.proxy.poll() is None and gate.client.poll() is None
        check_kernel_guard(gate, curl, BOOTSTRAP_ADDRESS if upstream else "127.0.0.1")
        assert gate.ready.is_set() and not ended.is_set()
        follow.set()
        assert wait_until(lambda: not gate.ready.is_set()), (failures, activity[-20:])
        request = curl_command(curl, target, proxy=f"socks5h://{export_address}")
        unavailable = subprocess.run(request, capture_output=True, timeout=7)
        assert unavailable.returncode != 0 and unavailable.stdout != BODY
        assert gate.client.poll() is None and not ended.is_set()

        reconnect.touch()
        assert gate.ready.wait(20), (failures, activity[-20:])
        assert gate.vpn_interface != first_vpn and gate.client.poll() is None
        assert subprocess.check_output(request, timeout=7) == BODY
    finally:
        stop.set()
        follow.set()
        worker.join(18)

    assert not worker.is_alive() and not failures and refused(port), (failures, activity[-20:])
    mode = "SOCKS5 bootstrap" if upstream else "direct bootstrap"
    egress = f"client-owned local {local_scheme.upper()}" if local_scheme else "real TUN egress"
    print(f"Verified {mode}, {egress}, HTTP CONNECT, SOCKS5 TCP-only, "
          "kernel egress denial before the watcher, and reconnect.")


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from vpngate.core import find_sing_box

    curl = shutil.which("curl")
    assert curl, "The integration test requires curl."
    engine = find_sing_box()
    route_command = ["ip", "-j", "-4", "route", "show", "table", "main"]
    before = subprocess.check_output(route_command)
    with tempfile.TemporaryDirectory(prefix="vpndock-test-") as directory:
        work = Path(directory)
        direct = work / "direct"
        direct.mkdir()
        exercise(direct, engine, curl, tundock_source=os.environ.get("VPNDOCK_TEST_TUNDOCK_SOURCE"))
        local_http = work / "local-http"
        local_http.mkdir()
        exercise(local_http, engine, curl, local_scheme="http")
        with bootstrap_proxy(engine) as upstream:
            chained = work / "chained"
            chained.mkdir()
            exercise(chained, engine, curl, upstream)
            local_socks = work / "local-socks"
            local_socks.mkdir()
            exercise(local_socks, engine, curl, upstream, local_scheme="socks")
    assert subprocess.check_output(route_command) == before
    print("The host IPv4 routes remained unchanged.")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture"]:
        run_fixture(*sys.argv[2:])
    else:
        main()
