#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Install LogicPearl and its bundled Z3 solver from GitHub Releases.

This installer currently supports:
  - macOS x86_64
  - macOS arm64
  - Linux x86_64

Usage:
  ./install.sh [--version <version>] [--install-root <dir>] [--bin-dir <dir>] [--repo <owner/repo>] [--archive-url <url-or-path>] [--checksum-url <url-or-path>] [--dry-run]

Options:
  --version <version>      Release version to install. Defaults to latest.
  --install-root <dir>     Versioned install root. Defaults to $HOME/.logicpearl.
  --bin-dir <dir>          Directory for logicpearl and z3 symlinks. Defaults to $HOME/.local/bin.
  --repo <owner/repo>      GitHub repository to install from. Defaults to LogicPearlHQ/logicpearl.
  --archive-url <path>     Override the release archive URL or use a local archive path.
  --checksum-url <path>    Override the checksum URL or use a local checksum path.
  --dry-run                Print the resolved download URL and install paths without changing anything.
  -h, --help               Show this help text.
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

download() {
  url="$1"
  destination="$2"
  if [ -f "$url" ]; then
    cp "$url" "$destination"
    return
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$destination"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$destination" "$url"
    return
  fi
  echo "missing required downloader: curl or wget" >&2
  exit 1
}

compute_sha256() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
    return
  fi
  echo "missing required checksum tool: sha256sum, shasum, or openssl" >&2
  exit 1
}

verify_checksum() {
  artifact="$1"
  checksum_file="$2"
  expected="$(awk 'NF { print $1; exit }' "$checksum_file")"
  if [ -z "$expected" ]; then
    echo "checksum file did not contain a SHA-256 digest: $checksum_file" >&2
    exit 1
  fi
  actual="$(compute_sha256 "$artifact")"
  if [ "$actual" != "$expected" ]; then
    echo "checksum verification failed for $artifact" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin)
      case "$arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        x86_64|amd64) echo "x86_64-apple-darwin" ;;
        *) echo "unsupported macOS architecture: $arch" >&2; exit 1 ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        *) echo "unsupported Linux architecture: $arch" >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "unsupported operating system: $os" >&2
      exit 1
      ;;
  esac
}

normalize_version_tag() {
  version="$1"
  case "$version" in
    latest) echo "latest" ;;
    v*) echo "$version" ;;
    *) echo "v$version" ;;
  esac
}

release_url() {
  repo="$1"
  version="$2"
  archive_name="$3"
  if [ "$version" = "latest" ]; then
    echo "https://github.com/$repo/releases/latest/download/$archive_name"
  else
    echo "https://github.com/$repo/releases/download/$version/$archive_name"
  fi
}

path_contains_dir() {
  candidate="$1"
  old_ifs="${IFS}"
  IFS=":"
  for entry in ${PATH:-}; do
    if [ "$entry" = "$candidate" ]; then
      IFS="$old_ifs"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

version="latest"
install_root="${LOGICPEARL_INSTALL_ROOT:-$HOME/.logicpearl}"
bin_dir="${LOGICPEARL_BIN_DIR:-$HOME/.local/bin}"
repo="${LOGICPEARL_INSTALL_REPO:-LogicPearlHQ/logicpearl}"
archive_url="${LOGICPEARL_ARCHIVE_URL:-}"
checksum_url="${LOGICPEARL_CHECKSUM_URL:-}"
dry_run="0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      version="$2"
      shift 2
      ;;
    --install-root)
      install_root="$2"
      shift 2
      ;;
    --bin-dir)
      bin_dir="$2"
      shift 2
      ;;
    --repo)
      repo="$2"
      shift 2
      ;;
    --archive-url)
      archive_url="$2"
      shift 2
      ;;
    --checksum-url)
      checksum_url="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd uname
need_cmd tar
need_cmd mktemp
need_cmd find
need_cmd ln
need_cmd cp
need_cmd awk

target_triple="$(detect_target)"
archive_name="logicpearl-${target_triple}.tar.gz"
version_tag="$(normalize_version_tag "$version")"
if [ -n "$archive_url" ]; then
  url="$archive_url"
else
  url="$(release_url "$repo" "$version_tag" "$archive_name")"
fi
if [ -n "$checksum_url" ]; then
  checksum_source="$checksum_url"
else
  checksum_source="${url}.sha256"
fi

if [ "$dry_run" = "1" ]; then
  printf 'target=%s\nurl=%s\nchecksum_url=%s\ninstall_root=%s\nbin_dir=%s\n' \
    "$target_triple" "$url" "$checksum_source" "$install_root" "$bin_dir"
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM HUP

archive_path="$tmpdir/$archive_name"
checksum_path="$tmpdir/$archive_name.sha256"
download "$url" "$archive_path"
download "$checksum_source" "$checksum_path"
verify_checksum "$archive_path" "$checksum_path"
tar -xzf "$archive_path" -C "$tmpdir"

bundle_dir="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d -name 'logicpearl-v*' | head -n 1)"
if [ -z "$bundle_dir" ]; then
  echo "downloaded archive did not contain a LogicPearl bundle directory" >&2
  exit 1
fi

mkdir -p "$install_root/releases" "$bin_dir"
destination_dir="$install_root/releases/$(basename "$bundle_dir")"
rm -rf "$destination_dir"
cp -R "$bundle_dir" "$destination_dir"
ln -sfn "$destination_dir" "$install_root/current"
ln -sfn "$install_root/current/bin/logicpearl" "$bin_dir/logicpearl"
ln -sfn "$install_root/current/bin/z3" "$bin_dir/z3"

printf 'Installed LogicPearl into %s\n' "$destination_dir"
printf 'Symlinked logicpearl and z3 into %s\n' "$bin_dir"
printf 'Verified archive checksum from %s\n' "$checksum_source"

if path_contains_dir "$bin_dir"; then
  printf 'Run: logicpearl quickstart\n'
else
  printf 'Add %s to PATH, then run: logicpearl quickstart\n' "$bin_dir"
fi
