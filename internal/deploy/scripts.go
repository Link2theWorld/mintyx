package deploy

// Everything the deployer changes on the server is in this file, as POSIX sh run by root.
// Scripts report through `key=value` lines on stdout; stderr is only for humans.

const (
	PanelBinaryPath = "/usr/local/bin/mintyx"
	DataDir         = "/var/lib/mintyx"
	XrayDir         = "/usr/local/lib/mintyx"
	PanelAddr       = "127.0.0.1:8088"
	UnitPath        = "/etc/systemd/system/mintyx.service"
	SSHDDropIn      = "/etc/ssh/sshd_config.d/00-mintyx-keylogin.conf"

	// XrayVersion is the one Xray-core release the deployer installs; the digests below are
	// those of its two Linux assets, so bumping the version means updating all three.
	XrayVersion     = "26.11.9"
	xrayReleaseBase = "https://github.com/XTLS/Xray-core/releases/download"
)

// xrayAssets maps a Go architecture to the release asset name and its SHA-256.
var xrayAssets = map[string]struct{ name, sha256 string }{
	"amd64": {"Xray-linux-64.zip", "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"},
	"arm64": {"Xray-linux-arm64-v8a.zip", "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be"},
}

const unitFile = `[Unit]
Description=Mintyx panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + PanelBinaryPath + ` -data ` + DataDir + ` -listen ` + PanelAddr + ` -xray ` + XrayDir + `/xray
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target`

const inspectBody = `
echo "os=$(uname -s)"
echo "arch=$(uname -m)"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  echo "systemd=1"
else
  echo "systemd=0"
fi
`

// shInstallPkg defines install_pkg for the handful of tools a minimal image may lack.
const shInstallPkg = `
install_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1"
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$1"
  elif command -v yum >/dev/null 2>&1; then yum install -y -q "$1"
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache "$1"
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm "$1"
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install "$1"
  else return 1
  fi
}
`

// The zip must match both the release's own .dgst file and the digest pinned in this program.
const xrayInstallBody = shSHA256 + shInstallPkg + `
has_version() {
  [ -x "$DIR/xray" ] && "$DIR/xray" version 2>/dev/null | head -n 1 | grep -q "^Xray $VERSION "
}
if has_version; then
  echo "xray=present"
  exit 0
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
  else wget -q -O "$2" "$1"
  fi
}
unpack() {
  if command -v unzip >/dev/null 2>&1; then unzip -q -o "$1" -d "$2"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"
  elif command -v bsdtar >/dev/null 2>&1; then bsdtar -xf "$1" -C "$2"
  elif command -v busybox >/dev/null 2>&1; then busybox unzip -q -o "$1" -d "$2"
  else return 127
  fi
}

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  install_pkg curl >&2 || { echo "problem=no-downloader"; exit 10; }
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch "$BASE/v$VERSION/$ASSET" "$work/xray.zip" || { echo "problem=download"; exit 11; }
fetch "$BASE/v$VERSION/$ASSET.dgst" "$work/xray.zip.dgst" || { echo "problem=download"; exit 11; }

published=$(awk -F'= *' '$1 == "SHA2-256" || $1 == "SHA256" { print $2; exit }' "$work/xray.zip.dgst" | tr -d ' \r')
actual=$(sha256_of "$work/xray.zip")
if [ -z "$published" ] || [ "$actual" != "$published" ] || [ "$actual" != "$PINNED" ]; then
  echo "problem=digest"
  echo "Xray download digest: got $actual, release says ${published:-nothing}, expected $PINNED" >&2
  exit 12
fi

mkdir "$work/out"
if ! unpack "$work/xray.zip" "$work/out"; then
  rm -rf "$work/out"; mkdir "$work/out"
  install_pkg unzip >&2 && unpack "$work/xray.zip" "$work/out" || { echo "problem=unpack"; exit 13; }
fi
[ -f "$work/out/xray" ] || { echo "problem=unpack"; exit 13; }

mkdir -p "$DIR"
for f in geoip.dat geosite.dat xray; do
  [ -f "$work/out/$f" ] || continue
  cp "$work/out/$f" "$DIR/$f.new"
  if [ "$f" = xray ]; then chmod 755 "$DIR/$f.new"; else chmod 644 "$DIR/$f.new"; fi
  mv -f "$DIR/$f.new" "$DIR/$f"
done
has_version || { echo "problem=not-runnable"; exit 14; }
echo "xray=installed"
`

const serviceBody = `
mkdir -p "$DATA"
chmod 700 "$DATA"
changed=0
if [ ! -f "$UNIT_PATH" ] || [ "$(cat "$UNIT_PATH")" != "$UNIT" ]; then
  printf '%s\n' "$UNIT" > "$UNIT_PATH.new"
  chmod 644 "$UNIT_PATH.new"
  mv -f "$UNIT_PATH.new" "$UNIT_PATH"
  systemctl daemon-reload
  changed=1
fi
systemctl enable mintyx.service >/dev/null 2>&1 || systemctl enable mintyx.service
if [ "$changed" = 1 ] || [ "$RESTART" = 1 ]; then
  systemctl restart mintyx.service
  echo "service=restarted"
else
  systemctl start mintyx.service
  echo "service=started"
fi
`

const serviceLogBody = `
journalctl -u mintyx.service -n 15 --no-pager 2>/dev/null || true
`

// Only an active firewall is touched, and only for the line's port; the panel port stays closed.
const firewallBody = `
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --quiet --add-port="$PORT/tcp"
  firewall-cmd --quiet --permanent --add-port="$PORT/tcp"
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
`

const authorizedKeysAddBody = `
umask 077
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
f="$HOME/.ssh/authorized_keys"
touch "$f"
chmod 600 "$f"
if ! grep -qxF -- "$KEY" "$f"; then
  # A last line without a newline would swallow the key and break the one already on it.
  [ -z "$(tail -c 1 "$f")" ] || echo >> "$f"
  printf '%s\n' "$KEY" >> "$f"
fi
echo "key=added"
`

const authorizedKeysRemoveBody = `
f="$HOME/.ssh/authorized_keys"
if [ -f "$f" ]; then
  grep -vxF -- "$KEY" "$f" > "$f.mintyx" || true
  cat "$f.mintyx" > "$f"
  rm -f "$f.mintyx"
fi
echo "key=removed"
`

const shSSHD = `
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
reload_sshd() {
  systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service 2>/dev/null || {
    [ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)"
  }
}
`

// The drop-in is removed again unless sshd accepts it AND reports passwords off; sshd reads
// the first value it meets, hence a file name that sorts before cloud-init's 50-*.conf.
const keyLoginApplyBody = shSSHD + `
mkdir -p "$(dirname "$DROPIN")"
valid=0
for kbd in KbdInteractiveAuthentication ChallengeResponseAuthentication; do
  printf '# Written by mintyx-deploy: log in with a key, not a password.\nPasswordAuthentication no\n%s no\n' "$kbd" > "$DROPIN"
  chmod 644 "$DROPIN"
  if "$sshd_bin" -t 2>/dev/null; then valid=1; break; fi
done
if [ "$valid" != 1 ]; then
  "$sshd_bin" -t >&2 || true
  rm -f "$DROPIN"
  echo "result=invalid"
  exit 0
fi
effective=$("$sshd_bin" -T 2>/dev/null | awk '$1 == "passwordauthentication" { print $2; exit }')
if [ "$effective" != no ]; then
  rm -f "$DROPIN"
  echo "result=still-on"
  echo "files=$(grep -rilE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | tr '\n' ' ')"
  exit 0
fi
if ! reload_sshd; then
  rm -f "$DROPIN"
  echo "result=reload-failed"
  exit 0
fi
echo "result=applied"
`

const keyLoginRollbackBody = shSSHD + `
rm -f "$DROPIN"
reload_sshd
echo "result=rolled-back"
`
