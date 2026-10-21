#!/usr/bin/env bash
# Buduje kstuff 13.60 z przeniesiona jaskinia plaintext (build v5) z drzewa
# przygotowanego przez tools/kstuff-ppr-v5/przygotuj-zrodla-v5.py.
#
# Wynik: <katalog>/ps5-kstuff-ldr/kstuff.elf
# Artefakt docelowy: artifacts/kstuff-1360-ppr-v5.elf
#
# Wymaga PS5_PAYLOAD_SDK (domyslnie /opt/ps5-payload-sdk) oraz gcc, yasm,
# python3. Flagi te same, co w v2, v3 i v4: KSTUFF_OBS=1 oraz -DNPDRM_PORTING.
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "uzycie: $0 <katalog-przygotowany-przez-przygotuj-zrodla-v5.py>" >&2
    exit 2
fi

KATALOG="$(cd "$1" && pwd)"
export PS5_PAYLOAD_SDK="${PS5_PAYLOAD_SDK:-/opt/ps5-payload-sdk}"

make -C "$KATALOG/ps5-kstuff-ldr" KSTUFF_OBS=1 EXTRA_CFLAGS=-DNPDRM_PORTING

echo
echo "wynik: $KATALOG/ps5-kstuff-ldr/kstuff.elf"
sha256sum "$KATALOG/ps5-kstuff-ldr/kstuff.elf" || true
stat -c '%s bajtow' "$KATALOG/ps5-kstuff-ldr/kstuff.elf" || true
