#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
output=$(realpath -- "${1:-/tmp}")
[[ -d "$output" ]]
version=$(cd -- "$root" && /usr/bin/python3 -B -c 'from vpngate import __version__; print(__version__)')
name=vpndock-$version
staging=$(mktemp -d)
trap 'rm -r -- "$staging"' EXIT
install -d "$staging/$name"/{vpngate,tests,packaging/portable}
cp -- "$root"/{LICENSE,README.md,THIRD-PARTY-NOTICES,run-vpndock} "$staging/$name/"
cp -- "$root"/vpngate/*.py "$root"/vpngate/{style.css,vpndock.png} "$staging/$name/vpngate/"
cp -- "$root"/tests/*.py "$staging/$name/tests/"
cp -- "$root"/packaging/{make-release.sh,make-portable.sh,register-desktop.sh} "$staging/$name/packaging/"
cp -- "$root/packaging/portable/launcher.go" "$staging/$name/packaging/portable/"
tar -C "$staging" -czf "$output/$name.tar.gz" "$name"
(cd -- "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "$output/$name.tar.gz"
