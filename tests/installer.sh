#!/bin/sh
# Synthetic downloads only; never writes /opt or changes a live router.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TEMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
SANDBOX=$(mktemp -d "$TEMP_PARENT/xkeen-watcher-installer.XXXXXX")
case "$SANDBOX" in
    "$TEMP_PARENT"/xkeen-watcher-installer.*) ;;
    *) echo "Unexpected test directory" >&2; exit 1 ;;
esac
trap 'rm -rf -- "$SANDBOX"' EXIT HUP INT TERM
mkdir "$SANDBOX/bin" "$SANDBOX/dest"
export REAL_MKTEMP=$(command -v mktemp)

cat > "$SANDBOX/bin/mktemp" <<'MOCK'
#!/bin/sh
# BusyBox requires the six X characters at the end of the template.
case "$1" in
    *XXXXXX) exec "$REAL_MKTEMP" "$@" ;;
    *) echo "mktemp: template must end in XXXXXX" >&2; exit 1 ;;
esac
MOCK

cat > "$SANDBOX/bin/uname" <<'MOCK'
#!/bin/sh
printf '%s\n' "$TEST_ARCH"
MOCK
cat > "$SANDBOX/bin/dd" <<'MOCK'
#!/bin/sh
if [ "$TEST_ENDIAN" = big ]; then printf '\002'; else printf '\001'; fi
MOCK
cat > "$SANDBOX/bin/curl" <<'MOCK'
#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -sSfLo) output=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >> "$TEST_LOG"
case "$url" in
    https://api.github.com/repos/alexbuckner/xkeen-subscription-watcher/releases/latest)
        printf '{"tag_name":"v0.7.0"}\n' ;;
    https://github.com/alexbuckner/xkeen-subscription-watcher/releases/download/v0.7.0/xkeen-subscription-watcher-linux-*)
        cat > "$output" <<'BINARY'
#!/bin/sh
printf 'new-binary\n'
BINARY
        [ "$TEST_FAIL" = no ] || exit 22 ;;
    *) echo "Unexpected download URL" >&2; exit 1 ;;
esac
MOCK
chmod 755 "$SANDBOX/bin/"*
export PATH="$SANDBOX/bin:$PATH"
export XKEEN_WATCHER_INSTALL_DIR="$SANDBOX/dest"
export TEST_LOG="$SANDBOX/downloads.log"
export TEST_FAIL=no TEST_ENDIAN=little

for pair in aarch64:arm64 armv7l:armv7 mips:mipsel; do
    export TEST_ARCH=${pair%:*}
    suffix=${pair#*:}
    sh "$ROOT/install.sh" > "$SANDBOX/result.log"
    grep -q "/xkeen-subscription-watcher-linux-$suffix$" "$TEST_LOG"
    [ "$(sh "$SANDBOX/dest/xkeen-subscription-watcher")" = new-binary ]
    [ -x "$SANDBOX/dest/xkeen-subscription-watcher" ]
done
export TEST_ARCH=mips TEST_ENDIAN=big
sh "$ROOT/install.sh" > "$SANDBOX/result.log"
grep -q '/xkeen-subscription-watcher-linux-mips$' "$TEST_LOG"

printf 'old-binary\n' > "$SANDBOX/dest/xkeen-subscription-watcher"
export TEST_ARCH=aarch64 TEST_FAIL=yes
if sh "$ROOT/install.sh" > "$SANDBOX/result.log" 2>&1; then
    echo "Failed download was accepted" >&2; exit 1
fi
[ "$(cat "$SANDBOX/dest/xkeen-subscription-watcher")" = old-binary ]
[ "$(find "$SANDBOX/dest" -type f | wc -l | tr -d ' ')" = 1 ]

export TEST_ARCH=unsupported TEST_FAIL=no
if sh "$ROOT/install.sh" > "$SANDBOX/result.log" 2>&1; then
    echo "Unsupported architecture was accepted" >&2; exit 1
fi
[ "$(cat "$SANDBOX/dest/xkeen-subscription-watcher")" = old-binary ]
echo "PASS: four architectures, fork release URLs, executable mode, failed-download preservation and cleanup."
