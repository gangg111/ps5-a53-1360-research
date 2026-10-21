#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Skan dowodow na obecnosc polecenia zapisu A53 (0x01040031) w firmware 13.60.

Sprawdza dwa niezalezne zrodla, oba offline:
  1. zrzut jadra 13.60 (artifacts/kernel-1360-13.60.bin, 64 MB),
  2. dziewiec regionow pamieci A53 zrzuconych przez jadro
     (D:\\Tools\\a53_regions\\*.bin).

Dla kazdego zrodla liczy wystapienia typow polecen i wynikow SDBGP. Typ zapisu
(0x01040031) i jego wynik (0x02040031) to jedyne stale, ktore musialyby
wystapic, gdyby firmware A53 obslugiwal zapis pamieci.

Uzycie:
  python3 tools/kstuff-ppr-v5/skan-zapisu-a53.py
"""
import glob
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))))
JADRO = os.path.join(REPO, "artifacts", "kernel-1360-13.60.bin")
REGIONY = [d for d in (r"<work>\a53_regions", "/mnt/d/Tools/a53_regions")
           if os.path.isdir(d)]
REGIONY = REGIONY[0] if REGIONY else ""

STALE = [
    (0x01040031, "polecenie zapisu pamieci A53"),
    (0x02040031, "wynik zapisu pamieci A53"),
    (0x01040021, "polecenie odczytu pamieci A53"),
    (0x02040021, "wynik odczytu pamieci A53"),
    (0x01010010, "konfiguracja GET_CONF"),
    (0x01050020, "lista regionow zrzutu"),
    (0x01050030, "odczyt grupy rejestrow"),
    (0x01200021, "zlecenie zrzutu"),
    (0x02010001, "wpis listy regionow"),
]


def policz(dane, wartosc):
    return dane.count(struct.pack("<I", wartosc))


def main():
    print("== zrzut jadra 13.60 ==")
    if not os.path.isfile(JADRO):
        print("  brak %s" % JADRO)
        jadro = None
    else:
        jadro = open(JADRO, "rb").read()
        print("  %s, %d B" % (JADRO, len(jadro)))
        for wartosc, opis in STALE:
            print("  0x%08X  %-32s %d trafien"
                  % (wartosc, opis, policz(jadro, wartosc)))

    print()
    print("== regiony pamieci A53 ==")
    pliki = sorted(glob.glob(os.path.join(REGIONY, "*.bin"))) if REGIONY else []
    if not pliki:
        print("  brak katalogu regionow (%s)" % REGIONY)
        return 1
    print("  katalog: %s, %d plikow" % (REGIONY, len(pliki)))
    sumy = dict((w, 0) for w, _o in STALE)
    for plik in pliki:
        dane = open(plik, "rb").read()
        for wartosc, _opis in STALE:
            sumy[wartosc] += policz(dane, wartosc)
        print("  %-22s %7d B  zapis %d/%d"
              % (os.path.basename(plik), len(dane),
                 policz(dane, 0x01040031), policz(dane, 0x02040031)))
    print()
    print("  suma po wszystkich regionach:")
    for wartosc, opis in STALE:
        print("  0x%08X  %-32s %d trafien"
              % (wartosc, opis, sumy[wartosc]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
