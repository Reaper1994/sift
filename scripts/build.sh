#!/usr/bin/env bash
# Cross-compiles Sift for Windows, macOS and Linux into dist/.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-dev}"
rm -rf dist && mkdir -p dist

targets=(
  "windows amd64" "windows arm64"
  "darwin arm64"  "darwin amd64"
  "linux amd64"   "linux arm64"
)

for t in "${targets[@]}"; do
  read -r os arch <<<"$t"
  name="sift-${VERSION}-${os}-${arch}"
  dir="dist/$name"
  mkdir -p "$dir"
  bin="sift"; [[ $os == windows ]] && bin="sift.exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" -o "$dir/$bin" ./cmd/sift
  cp sift.env.example README.md "$dir/"
  if [[ $os == windows ]]; then
    cp scripts/install.ps1 "$dir/"
    (cd dist && zip -qr "$name.zip" "$name")
  else
    cp scripts/install.sh "$dir/"
    (cd dist && tar -czf "$name.tar.gz" "$name")
  fi
  rm -rf "$dir"
  echo "built $name"
done

(cd dist && sha256sum *.zip *.tar.gz > SHA256SUMS)
