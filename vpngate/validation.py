"""Recognize packaged launchers before entering the private VPN namespace."""

from configparser import ConfigParser, Error as ConfigError
import os
from pathlib import Path
import re
import shlex
import shutil


NATIVE_PACKAGE_WARNING = (
    "Sandboxed package formats (Flatpak / Snap) are not supported because their internal containers conflict "
    "with network namespace isolation. Please select a Native system package (installed via your distro's "
    "package manager in /usr/bin or /opt) or a direct Executable binary."
)


class SandboxedPackageError(ValueError):
    def __init__(self):
        super().__init__(NATIVE_PACKAGE_WARNING)


_PACKAGE_LAUNCHERS = {
    "flatpak", "flatpak-run", "flatpak-spawn", "snap", "snapctl", "snap-confine", "snap-exec",
}
_PACKAGE_FIELDS = ("X-Flatpak", "X-SnapInstanceName", "X-SnapAppName")
_PACKAGE_VARIABLES = {
    "FLATPAK_ID", "FLATPAK_SANDBOX_DIR", "SNAP", "SNAP_NAME", "SNAP_INSTANCE_NAME", "SNAP_REVISION",
}
_PACKAGE_ROOTS = tuple(map(Path, (
    "/app", "/snap", "/var/snap", "/var/lib/snapd", "/usr/lib/snapd",
    "/var/lib/flatpak", "/run/host/var/lib/flatpak", "/run/host/snap",
)))
_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.DOTALL)
_SHELL_LAUNCHERS = {"sh", "bash", "dash", "zsh", "ksh", "fish"}


def _in_package_tree(path):
    parts = path.parts
    pairs = set(zip(parts, parts[1:]))
    return (any(path.is_relative_to(root) for root in _PACKAGE_ROOTS)
            or bool(pairs & {("flatpak", "exports"), ("flatpak", "app"), (".var", "app")}))


def _desktop_package(path):
    if path.suffix != ".desktop":
        return False
    try:
        if not path.is_file() or path.stat().st_size > 128 * 1024:
            return False
        entry = ConfigParser(interpolation=None, strict=False)
        entry.optionxform = str
        with path.open(encoding="utf-8") as stream:
            entry.read_file(stream)
        return any(entry.get("Desktop Entry", field, fallback="").strip() for field in _PACKAGE_FIELDS)
    except (OSError, UnicodeError, ConfigError):
        return False


def _check_path(value, directory, search_path=None):
    path = Path(value).expanduser()
    lexical = directory / path
    if path.name in _PACKAGE_LAUNCHERS or _in_package_tree(lexical):
        raise SandboxedPackageError()
    if "/" not in value:
        paths = os.get_exec_path() if search_path is None else search_path.split(os.pathsep)
        located = shutil.which(value, path=os.pathsep.join(str(directory / part) for part in paths))
        if not located:
            return path.name
        lexical = Path(located)
    resolved = Path(os.path.realpath(lexical))
    if any(path.name in _PACKAGE_LAUNCHERS or _in_package_tree(path) or _desktop_package(path)
           for path in (lexical, resolved)):
        raise SandboxedPackageError()
    return resolved.name


def _shell_commands(script):
    # Inspect literal commands without invoking the shell or expanding substitutions.
    lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return
    command = []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            if command:
                yield command
                command = []
        else:
            command.append(token)
    if command:
        yield command


def _inspect(args, directory, search_path=None, depth=0):
    if not args or depth >= 8:
        return
    command = list(args)
    if _ASSIGNMENT.fullmatch(command[0]):
        launcher = "env"
    else:
        launcher = _check_path(command.pop(0), directory, search_path)
    if launcher in {"env", "command", "exec"}:
        while command:
            word = command[0]
            if match := _ASSIGNMENT.fullmatch(word):
                key, value = match.groups()
                if key in _PACKAGE_VARIABLES and value:
                    raise SandboxedPackageError()
                if key == "PATH":
                    search_path = value
            elif word in {"-i", "--ignore-environment"}:
                search_path = os.defpath
            elif word in {"-u", "--unset", "-C", "--chdir", "-a", "--argv0"}:
                if len(command) < 2:
                    return
                if word in {"-C", "--chdir"}:
                    directory /= Path(command[1]).expanduser()
                command.pop(0)
            elif word.startswith("--chdir="):
                directory /= Path(word.partition("=")[2]).expanduser()
            elif word in {"-S", "--split-string"} or word.startswith("--split-string="):
                if word.startswith("--split-string="):
                    value = word.partition("=")[2]
                    rest = command[1:]
                elif len(command) > 1:
                    value = command[1]
                    rest = command[2:]
                else:
                    return
                try:
                    expanded = shlex.split(value)
                except ValueError:
                    return
                _inspect(["env", *expanded, *rest], directory, search_path, depth + 1)
                return
            elif word != "--" and not word.startswith("--unset="):
                break
            command.pop(0)
        _inspect(command, directory, search_path, depth + 1)
    elif launcher in _SHELL_LAUNCHERS:
        for index, word in enumerate(command[:-1]):
            if word == "--command" or re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                for child in _shell_commands(command[index + 1]):
                    _inspect(child, directory, search_path, depth + 1)
                break
            if not word.startswith("-"):
                break


def validate_native(args, *, executable=None, desktop=None, directory=None):
    """Reject known Flatpak and Snap launchers without loading GTK or launching code."""
    directory = Path(directory or Path.home()).expanduser().absolute()
    if desktop is not None:
        if any((desktop.get_string(field) or "").strip() for field in _PACKAGE_FIELDS):
            raise SandboxedPackageError()
        if filename := desktop.get_filename():
            _check_path(filename, directory)
    if executable:
        _check_path(str(executable), directory)
    _inspect(args, directory)
