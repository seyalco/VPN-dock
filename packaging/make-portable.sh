#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s [--engine FILE --engine-license FILE --engine-source HTTPS_URL] OUTPUT\n' "$0" >&2
    exit 2
}

engine=
license=
source_url=
while [[ ${1:-} == --* ]]; do
    (( $# >= 2 )) || usage
    case $1 in
        --engine) engine=$(realpath -e -- "$2") ;;
        --engine-license) license=$(realpath -e -- "$2") ;;
        --engine-source) source_url=$2 ;;
        *) usage ;;
    esac
    shift 2
done
(( $# == 1 )) || usage
if [[ -n "$engine" || -n "$license" || -n "$source_url" ]]; then
    [[ -f "$engine" && -x "$engine" && -s "$license" && "$source_url" == https://* ]] || usage
fi

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
destination=$(cd -- "$(dirname -- "$1")" && pwd)
name=$(basename -- "$1")
output=$destination/$name
scratch=$(mktemp -d)
candidate=
checksum=
trap '
    [[ -z "$candidate" ]] || rm -f -- "$candidate"
    [[ -z "$checksum" ]] || rm -f -- "$checksum"
    rm -r -- "$scratch"
' EXIT
cp -- "$root/packaging/portable/launcher.go" "$scratch/main.go"

architecture=$(go env GOARCH)
python3 - "$root" "$scratch/payload.tar.gz" "$architecture" "$engine" "$license" "$source_url" <<'PY'
import gzip
import hashlib
from io import BytesIO
from pathlib import Path
import re
import struct
import sys
import tarfile

root = Path(sys.argv[1])
output = Path(sys.argv[2])
architecture, engine, license_path, source_url = sys.argv[3:]


def add_file(archive, path, name, mode):
    entry = tarfile.TarInfo(name)
    entry.size = path.stat().st_size
    entry.mode = mode
    with path.open("rb") as stream:
        archive.addfile(entry, stream)


def add_text(archive, text, name):
    payload = text.encode()
    entry = tarfile.TarInfo(name)
    entry.size = len(payload)
    entry.mode = 0o644
    archive.addfile(entry, BytesIO(payload))


def verify_engine(path):
    machines = {"386": 3, "amd64": 62, "arm": 40, "arm64": 183, "loong64": 258,
                "mips": 8, "mipsle": 8, "mips64": 8, "mips64le": 8,
                "ppc64": 21, "ppc64le": 21, "riscv64": 243, "s390x": 22}
    with path.open("rb") as stream:
        header = stream.read(20)
    endian = {1: "<", 2: ">"}.get(header[5]) if len(header) == 20 else None
    want_32_bit = architecture in {"386", "arm", "mips", "mipsle"}
    want_big_endian = architecture in {"mips", "mips64", "ppc64", "s390x"}
    if not (
        endian and header[:4] == b"\x7fELF"
        and header[4] == (1 if want_32_bit else 2)
        and endian == (">" if want_big_endian else "<")
        and struct.unpack_from(endian + "H", header, 18)[0] == machines.get(architecture)
    ):
        raise SystemExit(f"Bundled engine must be a Linux ELF for {architecture}.")
    if not re.fullmatch(r"https://[^\s]+", source_url):
        raise SystemExit("The engine source must be an HTTPS URL without whitespace.")


with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as packed:
    with tarfile.open(mode="w", fileobj=packed, format=tarfile.USTAR_FORMAT) as archive:
        app = root / "vpngate"
        for path in [*sorted(app.glob("*.py")), app / "style.css", app / "vpndock.png"]:
            add_file(archive, path, f"vpngate/{path.name}", 0o644)
        if engine:
            path = Path(engine)
            verify_engine(path)
            with path.open("rb") as stream:
                sha256 = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    sha256.update(chunk)
            add_file(archive, path, "engine/sing-box", 0o755)
            add_file(archive, Path(license_path), "engine/LICENSE", 0o644)
            add_text(archive, f"Bundled sing-box source: {source_url}\n"
                              f"Bundled executable SHA-256: {sha256.hexdigest()}\n", "engine/SOURCE")
PY

archive_digest=$(sha256sum "$scratch/payload.tar.gz" | cut -d ' ' -f 1)
bundled=no
[[ -z "$engine" ]] || bundled=yes
candidate=$(mktemp "$destination/.vpngate-build.XXXXXXXX")
(
    cd -- "$scratch"
    GOOS=linux GOARCH="$architecture" CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local \
        GOCACHE="${GOCACHE:-$scratch/go-cache}" go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.payloadHash=$archive_digest -X main.bundledEngine=$bundled" \
        -o "$candidate" ./main.go
)
chmod 755 "$candidate"
mv -T -- "$candidate" "$output"
checksum=$(mktemp "$destination/.vpngate-checksum.XXXXXXXX")
(
    cd -- "$destination"
    sha256sum -- "$name" > "$checksum"
)
chmod 644 "$checksum"
mv -T -- "$checksum" "$output.sha256"
printf '%s\n' "$output"
