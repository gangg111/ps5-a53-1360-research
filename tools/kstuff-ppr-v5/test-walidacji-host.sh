#!/usr/bin/env bash
# Uruchamia test funkcjonalny walidacji PPR i zapisu jaskin A53 (v5).
#
# Kompiluje prawdziwy ppr_patch.c z przygotowanego drzewa v5 razem z testem,
# ktory podstawia transport SDBGP w pamieci (okno 0x0..0xBFFFF, blad powyzej,
# tryb "zapis wraca 0, ale nie trafia do pamieci" jak na 13.60 oraz tryb
# "zjadaj tylko zapisy dluzsze niz 32 B", ktory odtwarza hipoteze (c)).
#
# Uzycie:
#   bash tools/kstuff-ppr-v5/test-walidacji-host.sh [katalog-v5]
#
# Domyslnie katalog-v5 = /mnt/d/tmp/kstuff-v5 (drzewo z przygotuj-zrodla-v5.py).
set -euo pipefail

TU="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$TU/../.." && pwd)"
DRZEWO="${1:-/mnt/d/tmp/kstuff-v5}"
PPR="$DRZEWO/ps5-kstuff-ldr/src/ppr"
OBRAZ="$REPO/artifacts/a53-obraz-odtworzony.bin"
BIN="$(mktemp -d)/test-walidacji-host"

if [ ! -f "$PPR/ppr_profiles.inc" ]; then
    echo "brak $PPR/ppr_profiles.inc; najpierw przygotuj drzewo v5" >&2
    exit 2
fi

echo "kompilacja: $BIN"
gcc -O2 -Wall -Wextra -I"$PPR" \
    "$TU/test-walidacji-host.c" "$PPR/ppr_patch.c" -o "$BIN"
echo
"$BIN" "$OBRAZ"
