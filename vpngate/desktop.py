"""Private desktop services for a native VPN client that needs NetworkManager."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
from html import escape
from ipaddress import IPv4Address
import os
from pathlib import Path
import re
import resource
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
RUNTIME = "/run/vpndock"
SYSTEM_BUS = "/run/dbus/system_bus_socket"
SESSION_BUS = f"{RUNTIME}/bus"
HOME = f"{RUNTIME}/home"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DCONF_PATH = SYSTEM_PATH + ":/usr/libexec:/usr/lib/dconf:/usr/lib/x86_64-linux-gnu:/usr/lib/aarch64-linux-gnu"
DESKTOP_TOOLS = ("dbus-daemon", "dbus-send", "NetworkManager", "nmcli")


class DesktopError(RuntimeError):
    pass


@dataclass(frozen=True)
class DesktopDependencies:
    wayland: Path | None
    tools: dict[str, str]


def _private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise DesktopError("The VPN Dock keyring directories must be owned by your account with mode 0700.")
    return path


def _owner_file(path, flags):
    fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise DesktopError("The VPN Dock keyring files must be private regular files with mode 0600.")
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True)
class DesktopKeyring:
    root: Path
    data: Path
    unlock_file: Path

    def unlock_pipe(self):
        with os.fdopen(_owner_file(self.unlock_file, os.O_RDONLY), "rb") as source:
            password = source.read(65)
        if not re.fullmatch(rb"[0-9a-f]{64}", password):
            raise DesktopError("The private keyring unlock record is invalid.")
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(write_fd, "wb") as writer:
                writer.write(password)
        except BaseException:
            os.close(read_fd)
            raise
        return os.fdopen(read_fd, "rb", buffering=0)


@contextmanager
def desktop_keyring(executable):
    """Reserve a keyring for this executable without sharing the host secret store."""
    if not shutil.which("gnome-keyring-daemon", path=SYSTEM_PATH):
        yield None
        return
    configured = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    if not configured.is_absolute():
        configured = Path.home() / ".config"
    configured = configured.resolve()
    configured.mkdir(parents=True, exist_ok=True)
    root = _private_directory(_private_directory(configured / "vpndock") / "keyrings")
    identity = hashlib.sha256(os.fsencode(Path(executable).resolve())).hexdigest()
    client = _private_directory(root / identity)
    with os.fdopen(_owner_file(client / "lock", os.O_CREAT | os.O_RDWR), "r+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DesktopError("This application's private keyring is in use by another VPN Dock session.") from error
        data = _private_directory(client / "store")
        unlock = client / "unlock"
        try:
            fd = _owner_file(unlock, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as file:
                file.write(secrets.token_hex(32).encode("ascii"))
                file.flush()
                os.fsync(file.fileno())
        yield DesktopKeyring(root, data, unlock)


def _system_tools():
    tools = {name: shutil.which(name, path=SYSTEM_PATH) for name in DESKTOP_TOOLS}
    missing = [name for name, command in tools.items() if command is None]
    if missing:
        raise DesktopError("Private desktop services need " + ", ".join(missing) + ".")
    return tools


def desktop_dependencies(*, require_display=False):
    """Resolve one Wayland socket for GUI clients without forwarding its runtime."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    name = os.environ.get("WAYLAND_DISPLAY")
    socket = None
    if runtime and name and re.fullmatch(r"wayland-[0-9]+", name) and Path(runtime).is_absolute():
        try:
            root = Path(runtime).resolve(strict=True)
            candidate = root / name
            if (root.stat().st_uid == os.getuid() and not candidate.is_symlink()
                    and candidate.is_socket() and candidate.stat().st_uid == os.getuid()):
                socket = candidate
        except (OSError, RuntimeError):
            pass
    if require_display and socket is None:
        raise DesktopError("Private GUI mode needs a verified Wayland display socket.")
    return DesktopDependencies(socket, _system_tools())


def _write(path, contents):
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def _bus_config(kind, path, dconf_activation=None):
    # The session bus can start its own dconf writer, never host services.
    activation = f"  <servicedir>{escape(str(dconf_activation))}</servicedir>\n" if dconf_activation else ""
    return f"""<busconfig>
  <type>{kind}</type>
  <listen>unix:path={path}</listen>
  <auth>EXTERNAL</auth>
{activation}  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"""


def _nm_config(uplink):
    unmanaged = sorted({"vpngate0", "vpd-ingress", uplink})
    interfaces = ";".join(f"interface-name:{name}" for name in unmanaged)
    return f"""[main]
plugins=keyfile
auth-polkit=root-only
dns=default
rc-manager=unmanaged
no-auto-default=*
hostname-mode=none

[keyfile]
unmanaged-devices={interfaces}

[connectivity]
enabled=false
"""


def _selected_mounts(hidden, home, protected, working_directory, executable):
    """Restore narrowly selected files without bringing back host runtime paths."""
    user_trees = (home, Path("/tmp"))

    def allowed(path):
        return (any(path != tree and path.is_relative_to(tree) for tree in user_trees)
                and not any(path.is_relative_to(tree) for tree in (Path("/run"), Path("/var"), Path("/root"))))

    args = []
    selected = None
    if working_directory:
        cwd = Path(working_directory).resolve()
        if any(cwd.is_relative_to(path) for path in hidden):
            if cwd == home and cwd not in {Path("/"), Path("/run"), Path("/var"), Path("/root")}:
                args.extend(("--dir", str(cwd)))
            elif cwd not in protected:
                if not allowed(cwd) or any(path.is_relative_to(cwd) for path in protected):
                    raise DesktopError("Choose a program folder inside your home or a private temporary directory.")
                if cwd.is_relative_to(Path("/tmp")):
                    info = cwd.stat()
                    if info.st_uid != os.getuid() or info.st_mode & 0o022:
                        raise DesktopError("Choose a temporary program folder owned by your user and not writable by others.")
                selected = cwd
                args.extend(("--ro-bind", str(cwd), str(cwd)))
    if executable:
        command = Path(executable).absolute()
        if any(command.is_relative_to(path) for path in hidden) and not (
                selected and command.is_relative_to(selected)) and not any(
                    command.is_relative_to(path) for path in protected):
            source = command.resolve()
            if not allowed(command) or any(source.is_relative_to(tree)
                                           for tree in (Path("/run"), Path("/var"), Path("/root"))):
                raise DesktopError("Choose an executable outside the host runtime and system state directories.")
            if not source.is_file() or not os.access(source, os.X_OK):
                raise DesktopError("The selected desktop client is not an executable file.")
            args.extend(("--ro-bind", str(source), str(command)))
    return args


def desktop_mounts(work, resolver, uplink, *, working_directory=None, require_display=False,
                   executable=None, keyring=None):
    """Build the mounts and environment for a fresh private desktop stack."""
    dep = desktop_dependencies(require_display=require_display)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", uplink):
        raise DesktopError("Invalid private desktop uplink name.")
    resolver = IPv4Address(resolver)
    work = Path(work).resolve()
    home = Path.home().resolve()
    hidden = [Path(path) for path in ("/run", "/tmp", "/var", "/home", "/root")]
    if not any(home.is_relative_to(path) for path in hidden) and home != Path("/"):
        hidden.append(home)
    protected = (work, ROOT) + ((dep.wayland,) if dep.wayland else ())
    if keyring:
        if any(path.is_relative_to(keyring.root) for path in protected):
            raise DesktopError("The private keyring directory must be separate from the app and its display.")
        protected += (keyring.root,)
    restore = _selected_mounts(hidden, home, protected, working_directory, executable)
    data = work / "desktop"
    data.mkdir(mode=0o700)
    app_state = work / "app-state"
    app_state.mkdir(mode=0o700)
    config = data / "NetworkManager"
    config.mkdir(mode=0o700)
    for name in ("conf.d", "system-connections"):
        (config / name).mkdir(mode=0o700)
    _write(config / "NetworkManager.conf", _nm_config(uplink))
    dconf = shutil.which("dconf-service", path=DCONF_PATH)
    activation = data / "session-services" if dconf else None
    if activation:
        activation.mkdir(mode=0o700)
        _write(data / "dconf-profile", "user-db:user\n")
        _write(activation / "ca.desrt.dconf.service",
               f"[D-BUS Service]\nName=ca.desrt.dconf\nExec={shlex.quote(dconf)}\n")
    _write(data / "system.conf", _bus_config("system", SYSTEM_BUS))
    _write(data / "session.conf", _bus_config("session", SESSION_BUS, activation))
    _write(data / "machine-id", secrets.token_hex(16) + "\n")
    _write(data / "resolv.conf", f"nameserver {resolver}\noptions timeout:3 attempts:2\n")
    _write(data / "hosts", "127.0.0.1 localhost vpndock\n::1 localhost\n")
    _write(data / "passwd", f"root:x:0:0:VPN Dock desktop:{HOME}:/bin/sh\nnobody:x:65534:65534:Nobody:/:/sbin/nologin\n")
    _write(data / "group", "root:x:0:\nnobody:x:65534:\n")
    _write(data / "nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n")

    args = [
        "--clearenv", "--unshare-ipc", "--unshare-uts", "--hostname", "vpndock",
        "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
        "--dev-bind", "/dev/net/tun", "/dev/net/tun",
    ]
    if keyring:
        # Fedora's keyring daemon retains this capability when it drops the
        # other capabilities of the private user namespace at startup.
        args.extend(("--cap-add", "CAP_IPC_LOCK"))
    for path in hidden:
        if path.is_dir():
            args.extend(("--tmpfs", str(path)))

    for directory in ("/run/dbus", "/run/NetworkManager", "/var/lib/NetworkManager", "/var/lib/dbus"):
        args.extend(("--dir", directory))
    args.extend(("--symlink", "/run", "/var/run", "--symlink", "/etc/machine-id", "/var/lib/dbus/machine-id"))
    for directory in (RUNTIME, HOME, f"{HOME}/config", f"{HOME}/data", f"{HOME}/cache", f"{HOME}/state"):
        args.extend(("--perms", "0700", "--dir", directory))

    # The marker and the bootstrap script are the only host work paths
    # restored after the host runtime, home and temporary directories are hidden.
    args.extend(("--ro-bind", str(work), str(work), "--ro-bind", str(ROOT), str(ROOT),
                 "--bind", str(app_state), str(app_state)))
    args.extend(restore)
    if keyring:
        args.extend(("--tmpfs", str(keyring.root), "--bind", str(keyring.data), f"{HOME}/data/keyrings"))

    if dep.wayland:
        args.extend(("--ro-bind", str(dep.wayland), f"{RUNTIME}/wayland"))
    if not Path("/etc/NetworkManager").is_dir():
        raise DesktopError("NetworkManager config directory is unavailable.")
    args.extend(("--bind", str(config), "/etc/NetworkManager"))
    for name in ("machine-id", "resolv.conf", "hosts", "passwd", "group", "nsswitch.conf"):
        target = Path("/etc", name).resolve()
        args.extend(("--ro-bind", str(data / name), str(target)))
    for path in ("/usr/lib/NetworkManager/conf.d", "/lib/NetworkManager/conf.d"):
        if Path(path).is_dir():
            resolved = str(Path(path).resolve())
            if resolved not in args:
                args.extend(("--tmpfs", resolved))

    environment = {
        "HOME": HOME,
        "USER": "root",
        "LOGNAME": "root",
        "PATH": SYSTEM_PATH,
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "XDG_RUNTIME_DIR": RUNTIME,
        "XDG_CONFIG_HOME": f"{HOME}/config",
        "XDG_DATA_HOME": f"{HOME}/data",
        "XDG_CACHE_HOME": f"{HOME}/cache",
        "XDG_STATE_HOME": f"{HOME}/state",
        "GTK_USE_PORTAL": "0",
        "NO_AT_BRIDGE": "1",
        "DBUS_SYSTEM_BUS_ADDRESS": f"unix:path={SYSTEM_BUS}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={SESSION_BUS}",
    }
    if activation:
        environment.update(GSETTINGS_BACKEND="dconf", DCONF_PROFILE=str(data / "dconf-profile"))
    else:
        environment["GSETTINGS_BACKEND"] = "memory"
    if keyring:
        environment["VPNDOCK_KEYRING_UNLOCK"] = "1"
    if dep.wayland:
        environment.update(XDG_SESSION_TYPE="wayland", WAYLAND_DISPLAY="wayland",
                           GDK_BACKEND="wayland", GSK_RENDERER="cairo", QT_QPA_PLATFORM="wayland")
    for key, value in environment.items():
        args.extend(("--setenv", key, value))
    return args


def _wait(check, processes, stop, label, timeout):
    until = time.monotonic() + timeout
    while not stop() and time.monotonic() < until:
        if any(process.poll() is not None for process in processes):
            raise DesktopError(f"{label} exited during startup.")
        if check():
            return
        time.sleep(0.075)
    if stop():
        raise InterruptedError("Stopped.")
    raise DesktopError(f"{label} did not become ready.")


def _dbus_reply(dbus_send, bus, destination, path, method, *args):
    try:
        result = subprocess.run(
            [dbus_send, f"--{bus}", "--print-reply", "--reply-timeout=500",
             f"--dest={destination}", path, method, *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=1, check=False,
        )
    except subprocess.TimeoutExpired:
        return b""
    return result.stdout if result.returncode == 0 else b""


def _has_name(dbus_send, bus, name):
    return b"boolean true" in _dbus_reply(
        dbus_send, bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus.NameHasOwner", f"string:{name}",
    )


def _keyring_unlocked(dbus_send):
    unlocked = _dbus_reply(
        dbus_send, "session", "org.freedesktop.secrets", "/org/freedesktop/secrets/aliases/default",
        "org.freedesktop.DBus.Properties.Get", "string:org.freedesktop.Secret.Collection", "string:Locked",
    )
    return b"boolean false" in unlocked


def _publish_pid(directory, pid):
    temporary = directory / f".app-{secrets.token_hex(8)}"
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as stream:
            stream.write(f"{pid}\n")
        temporary.replace(directory / "app.pid")
    finally:
        temporary.unlink(missing_ok=True)


def run_desktop(marker, command):
    """Start and supervise services and the VPN in the same private namespaces."""
    if os.geteuid() != 0:
        raise DesktopError("Private desktop requires a root mapping inside its user namespace.")
    # Root in the initial user namespace must never run this launcher.
    try:
        maps = [tuple(map(int, line.split())) for line in Path("/proc/self/uid_map").read_text().splitlines()]
    except (OSError, ValueError) as error:
        raise DesktopError("Could not verify the private desktop user namespace.") from error
    if not maps or maps == [(0, 0, 4294967295)] or not command:
        raise DesktopError("Refused to start desktop services outside a private user namespace.")

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tools = _system_tools()
    work = Path(marker).parent
    data = work / "desktop"
    unlock = os.environ.pop("VPNDOCK_KEYRING_UNLOCK", "") == "1"
    stopped = False
    services = []
    optional_services = []
    app = None

    def notify_stop(*_):
        nonlocal stopped
        stopped = True

    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, notify_stop)

    def start(*args, stdin=subprocess.DEVNULL):
        process = subprocess.Popen(args, stdin=stdin)
        services.append(process)
        return process

    try:
        _wait(lambda: Path(marker).is_file(), (), lambda: stopped, "Private uplink", 25)
        for kind, socket in (("system", SYSTEM_BUS), ("session", SESSION_BUS)):
            process = start(tools["dbus-daemon"], "--nofork", f"--config-file={data / (kind + '.conf')}")
            _wait(lambda: Path(socket).is_socket(), (process,), lambda: stopped, f"Private {kind} D-Bus", 5)

        manager = start(tools["NetworkManager"], "--no-daemon", "--log-level=WARN")
        _wait(lambda: _has_name(tools["dbus-send"], "system", "org.freedesktop.NetworkManager"),
              (manager,), lambda: stopped, "Private NetworkManager", 14)

        if keyring := shutil.which("gnome-keyring-daemon", path=SYSTEM_PATH):
            if unlock:
                try:
                    daemon = start(keyring, "--foreground", "--components=secrets", "--unlock", stdin=sys.stdin)
                finally:
                    sys.stdin.close()
            else:
                daemon = start(keyring, "--foreground", "--components=secrets")
            try:
                _wait(lambda: _has_name(tools["dbus-send"], "session", "org.freedesktop.secrets"),
                      (daemon,), lambda: stopped, "Private Secret Service", 5)
                if unlock:
                    if not _keyring_unlocked(tools["dbus-send"]):
                        raise DesktopError("Could not unlock the application's private keyring.")
                    print("The application's private keyring is unlocked.", flush=True)
            except DesktopError as error:
                if unlock:
                    raise
                print(error, flush=True)
                if daemon.poll() is None:
                    daemon.terminate()
                services.remove(daemon)
                optional_services.append(daemon)
        else:
            if unlock:
                raise DesktopError("gnome-keyring is required to unlock this application's private keyring.")
            print("Private Secret Service unavailable. Some VPN clients need gnome-keyring.", flush=True)

        print("Private NetworkManager and desktop buses are ready.", flush=True)
        app = subprocess.Popen(command, stdin=subprocess.DEVNULL)
        _publish_pid(work / "app-state", app.pid)
        while not stopped and app.poll() is None:
            if any(process.poll() is not None for process in services):
                raise DesktopError("A private desktop service stopped.")
            time.sleep(0.1)
        return app.returncode or 0
    except InterruptedError:
        return 0
    finally:
        processes = ([app] if app is not None else []) + list(reversed(services)) + optional_services
        for process in processes:
            if process.poll() is None:
                process.terminate()
        deadline = time.monotonic() + 1.5
        for process in processes:
            try:
                process.wait(timeout=max(0.05, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    try:
        sys.exit(run_desktop(sys.argv[1], sys.argv[2:]))
    except (DesktopError, OSError, IndexError, ValueError) as error:
        sys.exit(str(error))
