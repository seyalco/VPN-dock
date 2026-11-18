#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )); then
    printf 'Usage: %s /path/to/VPN-Dock [/path/to/vpndock.png]\n' "$0" >&2
    exit 2
fi

project=$(cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/python3 - "$1" "${2:-"$project/vpngate/vpndock.png"}" <<'PY'
from hashlib import sha256
from pathlib import Path
import os
import struct
import sys
import tempfile

APP_ID = "io.github.vpndock.VpnDock"
MANAGED = "X-VPNDock-Managed=true"
DIGEST = "X-VPNDock-IconSHA256="


def checked_inputs(executable, icon):
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Choose an executable VPN Dock file.")
    with executable.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("Choose the standalone VPN Dock Linux ELF.")

    icon = Path(icon).resolve(strict=True)
    if not icon.is_file():
        raise ValueError("Choose the VPN Dock PNG icon.")
    payload = icon.read_bytes()
    if (len(payload) < 24 or payload[:8] != b"\x89PNG\r\n\x1a\n"
            or payload[12:16] != b"IHDR" or struct.unpack(">II", payload[16:24]) != (256, 256)):
        raise ValueError("The icon must be a 256×256 PNG.")
    return executable, payload


def desktop_quote(path):
    value = str(path)
    if "=" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("The executable path may not contain = or control characters.")
    value = value.replace("%", "%%")
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\' + char)
    return '"' + value.replace('\\', '\\\\') + '"'


def existing_file(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Refusing the existing path {path}")
    return path.read_bytes() if path.is_file() else None


def desktop_fields(payload):
    if payload is None:
        return set()
    fields = set()
    in_main_group = False
    for line in payload.decode("utf-8").splitlines():
        line = line.strip()
        if line.startswith("["):
            in_main_group = line == "[Desktop Entry]"
        elif in_main_group:
            fields.add(line)
    return fields


def check_directory_tree(base, relative):
    current = base
    for component in relative.parts:
        current /= component
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise ValueError(f"Refusing the existing path {current}")


def write_atomic(path, new_content, previous):
    if previous == new_content:
        return
    fd, name = tempfile.mkstemp(prefix=".vpndock-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(new_content)
        temporary.chmod(0o644)
        if previous is None:
            os.link(temporary, path)
        else:
            if existing_file(path) != previous:
                raise ValueError(f"The file changed during registration: {path}")
            temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def register(executable_path, icon_path):
    if os.geteuid() == 0:
        raise ValueError("Register the menu entry as your desktop user.")
    executable, icon_bytes = checked_inputs(executable_path, icon_path)
    data_home = Path(os.getenv("XDG_DATA_HOME") or "")
    if not data_home.is_absolute():
        data_home = Path.home() / ".local/share"
    data_home = data_home.resolve()
    applications = Path("applications")
    icons = Path("icons/hicolor/256x256/apps")
    for relative in (applications, icons):
        check_directory_tree(data_home, relative)

    desktop = data_home / applications / f"{APP_ID}.desktop"
    icon = data_home / icons / f"{APP_ID}.png"
    previous_desktop = existing_file(desktop)
    previous_icon = existing_file(icon)
    fields = desktop_fields(previous_desktop)
    if previous_desktop is not None and MANAGED not in fields:
        raise ValueError(f"The existing desktop entry is unmanaged: {desktop}")
    if previous_icon is not None and (
        MANAGED not in fields or DIGEST + sha256(previous_icon).hexdigest() not in fields
    ):
        raise ValueError(f"The existing icon is unmanaged or changed: {icon}")

    command = desktop_quote(executable)
    # Some desktop launchers try to find Exec before decoding %% escapes.
    if "%" in str(executable):
        command = "/usr/bin/env -- " + command
    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=VPN Dock\n"
        "Comment=Expose an isolated VPN as a local proxy\n"
        f"Exec={command}\n"
        f"Icon={APP_ID}\n"
        f"StartupWMClass={APP_ID}\n"
        "Terminal=false\n"
        "Categories=Network;\n"
        "Keywords=VPN;Proxy;WireGuard;OpenVPN;\n"
        f"{MANAGED}\n"
        f"{DIGEST}{sha256(icon_bytes).hexdigest()}\n"
    ).encode()

    desktop.parent.mkdir(parents=True, exist_ok=True)
    icon.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(icon, icon_bytes, previous_icon)
    try:
        write_atomic(desktop, entry, previous_desktop)
    except (OSError, ValueError):
        if existing_file(icon) == icon_bytes and previous_icon != icon_bytes:
            if previous_icon is None:
                icon.unlink()
            else:
                write_atomic(icon, previous_icon, icon_bytes)
        raise
    print(f"VPN Dock menu entry: {desktop}")


try:
    register(*sys.argv[1:])
except (OSError, ValueError, RuntimeError) as error:
    raise SystemExit(f"VPN Dock: {error}") from None
PY
