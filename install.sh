#!/bin/sh
set -e

REPO="alexbuckner/xkeen-subscription-watcher"
INSTALL_PATH="${XKEEN_WATCHER_INSTALL_DIR:-/opt/sbin}/xkeen-subscription-watcher"

detect_arch() {
    arch=$(uname -m)
    case "$arch" in
        aarch64)
            echo "arm64"
            ;;
        armv7l|armv7)
            echo "armv7"
            ;;
        mips)
            # Определяем порядок байт по ELF-заголовку /bin/sh
            # Байт 5 ELF: 001 (octal) = little-endian, 002 = big-endian
            # od -b работает в BusyBox
            if dd if=/bin/sh bs=1 skip=5 count=1 2>/dev/null | od -b | head -1 | grep -q ' 001'; then
                echo "mipsel"
            else
                echo "mips"
            fi
            ;;
        *)
            echo "Неподдерживаемая архитектура: $arch" >&2
            exit 1
            ;;
    esac
}

ARCH=$(detect_arch)

echo "Определена архитектура: $ARCH"

LATEST_URL="https://api.github.com/repos/$REPO/releases/latest"
TAG=$(curl -sSf "$LATEST_URL" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

if [ -z "$TAG" ]; then
    echo "Не удалось определить последнюю версию." >&2
    exit 1
fi

echo "Последняя версия: $TAG"

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/xkeen-subscription-watcher-linux-$ARCH"

echo "Скачиваем $DOWNLOAD_URL ..."
INSTALL_TMP=$(mktemp "${INSTALL_PATH}.XXXXXX")
trap 'rm -f "$INSTALL_TMP"' EXIT HUP INT TERM
curl -sSfLo "$INSTALL_TMP" "$DOWNLOAD_URL"
chmod 755 "$INSTALL_TMP"
mv -f "$INSTALL_TMP" "$INSTALL_PATH"

echo "Установлено: $INSTALL_PATH ($TAG, $ARCH)"
