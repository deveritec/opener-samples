#!/usr/bin/env bash
# Copyright (c) 2026 Deveritec GmbH - SPDX-License-Identifier: Apache-2.0
#
# Creates a symbolic link in the Wireshark extcap folder that points to
# dectnrp_sniffer_extcap.py in this repository. The folder is created if needed.
#
# Usage: install_extcap_link.sh [-f] [EXTCAP_DIR]
#   EXTCAP_DIR  target folder (default: ~/.local/lib/wireshark/extcap)
#   -f          replace an existing file or link that points elsewhere
#   -h          show this help
set -euo pipefail

DEFAULT_DIR="$HOME/.local/lib/wireshark/extcap"
FORCE=0
EXTCAP_DIR=""

usage() {
    sed -n '3,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -f) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "error: unknown option $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -n "$EXTCAP_DIR" ]; then
                echo "error: only one EXTCAP_DIR allowed" >&2; exit 2
            fi
            EXTCAP_DIR="$1"
            ;;
    esac
    shift
done

EXTCAP_DIR="${EXTCAP_DIR:-$DEFAULT_DIR}"
EXTCAP_DIR="${EXTCAP_DIR/#\~/$HOME}"   # expand a leading ~ given as argument

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/dectnrp_sniffer_extcap.py"
LINK="$EXTCAP_DIR/dectnrp_sniffer_extcap.py"

if [ ! -f "$TARGET" ]; then
    echo "error: $TARGET not found" >&2
    exit 1
fi
TARGET_ABS="$(readlink -f "$TARGET")"

if [ ! -x "$TARGET_ABS" ]; then
    chmod +x "$TARGET_ABS"
    echo "made executable: $TARGET_ABS"
fi

mkdir -p "$EXTCAP_DIR"

if [ -L "$LINK" ]; then
    CURRENT="$(readlink -f "$LINK" || true)"
    if [ "$CURRENT" = "$TARGET_ABS" ]; then
        echo "already linked: $LINK -> $TARGET_ABS"
    elif [ "$FORCE" -eq 1 ]; then
        ln -sfn "$TARGET_ABS" "$LINK"
        echo "replaced link: $LINK -> $TARGET_ABS"
    else
        echo "error: $LINK points to ${CURRENT:-a missing target}; use -f to replace" >&2
        exit 1
    fi
elif [ -e "$LINK" ]; then
    if [ "$FORCE" -eq 1 ]; then
        rm -f "$LINK"
        ln -s "$TARGET_ABS" "$LINK"
        echo "replaced file with link: $LINK -> $TARGET_ABS"
    else
        echo "error: $LINK exists and is not a link; use -f to replace it" >&2
        exit 1
    fi
else
    ln -s "$TARGET_ABS" "$LINK"
    echo "created link: $LINK -> $TARGET_ABS"
fi

if python3 "$LINK" --extcap-interfaces >/dev/null 2>&1; then
    echo "check ok: extcap answers via the link"
else
    echo "warning: the link was created, but the extcap did not answer (is python3 installed?)" >&2
fi
