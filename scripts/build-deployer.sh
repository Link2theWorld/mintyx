#!/bin/sh
# Builds release copies of mintyx-deploy into dist/: the web frontend first, then the panel
# for both Linux CPUs (embedded into the deployer as its payload), then the deployer itself.
# Needs Go and Node 26. Set SKIP_WEB=1 to reuse an existing web/dist build.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

payload_dir=internal/deploy/payload/bin
out_dir=dist
version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)

if [ "${SKIP_WEB:-0}" != 1 ]; then
  echo "==> web frontend"
  (cd web && npm ci && npm run build)
fi
[ -f web/dist/index.html ] || { echo "web/dist/index.html is missing: the panel would be built without its interface" >&2; exit 1; }

# The payload goes away again on exit, so a later plain `go build` cannot embed a stale panel.
cleanup() { rm -f "$payload_dir/mintyx-linux-amd64" "$payload_dir/mintyx-linux-arm64"; }
trap cleanup EXIT

for arch in amd64 arm64; do
  echo "==> panel linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$payload_dir/mintyx-linux-$arch" ./cmd/mintyx
done

mkdir -p "$out_dir"
for target in darwin/arm64 darwin/amd64 windows/amd64 linux/amd64; do
  os=${target%/*}
  arch=${target#*/}
  name="mintyx-deploy-$os-$arch"
  [ "$os" = windows ] && name="$name.exe"
  echo "==> deployer $target"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out_dir/$name" ./cmd/mintyx-deploy
done

echo "==> done ($version)"
ls -l "$out_dir"
