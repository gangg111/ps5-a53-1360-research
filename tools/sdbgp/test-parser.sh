#!/usr/bin/env bash
# Buduje i uruchamia test parsera pakietow SDBGP z tools/sdbgp/sdbgp.c.
#
# Test nie kopiuje logiki parsera: wycina jej zrodlo z sdbgp.c (od znacznika
# "--- rozbior pakietu SDBGP ---" do "--- deduplikacja po tresci pakietu ---")
# i dokleja do rusztowania test-parser.c, wiec sprawdzana jest realna tresc
# payloadu. Nic nie laduje na konsole, wszystko dzieje sie lokalnie.
#
# Uruchomienie: wsl -d Debian -- bash tools/sdbgp/test-parser.sh

set -euo pipefail

KAT="$(cd "$(dirname "$0")" && pwd)"
PRACA="/tmp/sdbgp-test-parser"

rm -rf "$PRACA"
mkdir -p "$PRACA"

awk '/^\/\* --- rozbior pakietu SDBGP ---/{w=1}
     /^\/\* --- deduplikacja po tresci pakietu/{w=0}
     w' "$KAT/sdbgp.c" > "$PRACA/sdbgp-parser.inc"

echo "wyciagniety blok parsera: $(wc -l < "$PRACA/sdbgp-parser.inc") linii"
head -2 "$PRACA/sdbgp-parser.inc"

cc -Wall -Wextra -Werror -O2 -I"$PRACA" -o "$PRACA/test-parser" "$KAT/test-parser.c"
"$PRACA/test-parser"
