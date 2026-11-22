#!/bin/sh
# Turns the deployer builds that build-deployer.sh left in dist/ into the files a release offers,
# one per desktop system, in dist/release/:
#
#   mintyx-deploy-windows.exe    double-click to run
#   mintyx-deploy-macos.zip      one program for both Apple silicon and Intel Macs
#   mintyx-deploy-linux.tar.gz   x86_64
#   SHA256SUMS.txt
#
# macOS and Linux get an archive because a bare download loses its executable bit; zip and tar keep it.
# The universal macOS program needs lipo, so this runs on a Mac (CI uses a macOS runner).
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root/dist"

for f in mintyx-deploy-windows-amd64.exe mintyx-deploy-darwin-arm64 mintyx-deploy-darwin-amd64 mintyx-deploy-linux-amd64; do
  [ -f "$f" ] || { echo "dist/$f is missing: run scripts/build-deployer.sh first" >&2; exit 1; }
done
command -v lipo >/dev/null || { echo "lipo is missing: the universal macOS program can only be made on a Mac" >&2; exit 1; }

rm -rf release
mkdir -p release/work

cp mintyx-deploy-windows-amd64.exe release/mintyx-deploy-windows.exe

lipo -create -output release/work/mintyx-deploy mintyx-deploy-darwin-arm64 mintyx-deploy-darwin-amd64
chmod 755 release/work/mintyx-deploy
(cd release/work && zip -q -X ../mintyx-deploy-macos.zip mintyx-deploy)
rm release/work/mintyx-deploy

cp mintyx-deploy-linux-amd64 release/work/mintyx-deploy
chmod 755 release/work/mintyx-deploy
tar -C release/work -czf release/mintyx-deploy-linux.tar.gz mintyx-deploy
rm -rf release/work

cd release
if command -v sha256sum >/dev/null; then
  sha256sum mintyx-deploy-* > SHA256SUMS.txt
else
  shasum -a 256 mintyx-deploy-* > SHA256SUMS.txt
fi

echo "==> release files"
ls -l
cat SHA256SUMS.txt
