#!/usr/bin/env sh
set -eu

VERSION=""
SKIP_TESTS=0

usage() {
  echo "Usage: $0 [--version <version>] [--skip-tests]" >&2
  exit 1
}

get_ha_auth_version() {
  cargo_toml_path=$1
  version_line=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*$/\1/p' "$cargo_toml_path" | head -n 1)
  if [ -z "$version_line" ]; then
    echo "Could not find package version in $cargo_toml_path" >&2
    exit 1
  fi
  printf '%s\n' "$version_line"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || usage
      VERSION=$2
      shift 2
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

TARGET="x86_64-unknown-linux-musl"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CARGO_TOML_PATH="$REPO_ROOT/Cargo.toml"

if [ -z "$VERSION" ]; then
  VERSION=$(get_ha_auth_version "$CARGO_TOML_PATH")
fi

ARTIFACT_DIR="$REPO_ROOT/dist/v$VERSION"
SOURCE_BIN="$REPO_ROOT/target/$TARGET/release/ha-auth"
ARTIFACT_NAME="ha-auth-v$VERSION-$TARGET.tar.gz"
ARTIFACT_PATH="$ARTIFACT_DIR/$ARTIFACT_NAME"

mkdir -p "$ARTIFACT_DIR"

if [ "$SKIP_TESTS" -ne 1 ]; then
  (cd "$REPO_ROOT" && cargo test -q)
fi

if command -v rustup >/dev/null 2>&1; then
  rustup target add "$TARGET"
fi

(cd "$REPO_ROOT" && cargo build --release --target "$TARGET")

if [ ! -f "$SOURCE_BIN" ]; then
  echo "Built binary not found at $SOURCE_BIN" >&2
  exit 1
fi

tar -czf "$ARTIFACT_PATH" -C "$(dirname "$SOURCE_BIN")" "$(basename "$SOURCE_BIN")"

echo "Built Linux musl x64 release:"
echo "  $ARTIFACT_PATH"
