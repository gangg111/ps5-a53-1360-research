#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analiza ogona segmentu io A53 pod katem przeniesienia jaskini plaintext.

Dwa niezalezne zrodla, oba offline:
  1. obraz odniesienia artifacts/a53-obraz-odtworzony.bin (rekonstrukcja),
  2. zrzut ZYWEJ pamieci A53 D:\\Tools\\a53_regions\\region_00028000.bin
     (caly segment io, PA 0x28000..0x62000, 0x3A000 B).

Skrypt liczy entropie i udzial zer w blokach 4 kB, wyznacza granice miedzy
kodem/danymi a wypelnieniem, sprawdza kolizje kandydatow na jaskinie z
kotwicami, miejscami latki i miedzy soba, oraz mowi, czy pod kandydatem sa
jakiekolwiek odwolania (bajty niezerowe) w obu zrodlach.

Uzycie:
  python tools/kstuff-ppr-v5/analiza-ogona-io-v5.py
"""
import collections
import math
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))))
OBRAZ = os.path.join(REPO, "artifacts", "a53-obraz-odtworzony.bin")
# Zrzut zywego segmentu io A53. Pod Windows sciezka D:\..., w WSL /mnt/d/...
REGIONY = (r"<work>\a53_regions\region_00028000.bin",
           "/mnt/d/Tools/a53_regions/region_00028000.bin")
REGION = next((p for p in REGIONY if os.path.isfile(p)), REGIONY[0])

BAZA = 0x28000          # io_sram_base
KONIEC = 0x62000        # io_sram_base + io_mapped_size
KOTWICE = [("naglowek io", 0x28000), ("helper", 0x5B964),
           ("dispatch_native", 0x57AA8), ("plaintext_direct", 0x5C7E8),
           ("common_return", 0x5BC20)]
MIEJSCA = [("call[0]", 0x4A120), ("call[1]", 0x4B860),
           ("aes_site[0]", 0x57C14), ("aes_site[1]", 0x57D4C),
           ("sha_auth_site", 0x5BC00)]
JASKINIA_RUNTIME = (0x61F00, 76)
JASKINIA_PLAINTEXT_STARA = (0x61F50, 160)
KANDYDACI = [0x5E000, 0x5F000, 0x60000, 0x61000]


def entropia(dane):
    if not dane:
        return 0.0
    licznik = collections.Counter(dane)
    n = float(len(dane))
    return -sum((c / n) * math.log(c / n, 2) for c in licznik.values())


def opis_bloku(dane, start):
    blok = dane[start:start + 0x1000]
    if len(blok) != 0x1000:
        return None
    e = entropia(blok)
    zera = sum(1 for b in blok if b == 0) / float(len(blok))
    return e, zera


def granica_wypelnienia(dane, prog_zera=0.995):
    """Ostatni blok 4 kB, ktory nie jest ani samymi zerami, ani jednostajny."""
    ostatni = None
    for start in range(BAZA, KONIEC, 0x1000):
        o = opis_bloku(dane, start)
        if o is None:
            continue
        e, zera = o
        jednostajny = e > 7.9
        if not jednostajny and zera < prog_zera:
            ostatni = start
    return ostatni


def kolizje(zakresy):
    z = sorted(zakresy)
    return [(a[2], b[2]) for a, b in zip(z, z[1:]) if a[1] > b[0]]


def main():
    obraz = open(OBRAZ, "rb").read()
    print("obraz odniesienia: %s, %d B" % (OBRAZ, len(obraz)))
    if os.path.isfile(REGION):
        region = open(REGION, "rb").read()
        print("zrzut zywej pamieci: %s, %d B (PA 0x%05X..0x%05X)"
              % (REGION, len(region), BAZA, BAZA + len(region)))
    else:
        region = None
        print("zrzut zywej pamieci: BRAK (%s)" % REGION)

    print()
    print("segment io: PA 0x%05X..0x%05X (0x%X B)" % (BAZA, KONIEC, KONIEC - BAZA))
    print()
    print("  blok     obraz: entropia  zera   | zrzut: entropia  zera   opis")
    for start in range(0x5C000, KONIEC, 0x1000):
        o = opis_bloku(obraz, start)
        r = opis_bloku(region, start - BAZA) if region else None
        e, zera = o
        if r:
            er, zr = r
            sreg = "%7.3f  %5.1f%%" % (er, zr * 100.0)
        else:
            sreg = "      -        -"
        opis = ""
        if e > 7.9:
            opis = "jednostajny (wypelnienie/losowe)"
        elif zera > 0.99:
            opis = "same zera"
        print("  0x%05X  %7.3f  %5.1f%%   | %s   %s"
              % (start, e, zera * 100.0, sreg, opis))

    print()
    print("ostatni niezerowy bajt obrazu:        0x%X"
          % max(i for i, b in enumerate(obraz) if b))
    print("ostatni blok niejednostajny w obrazie: 0x%X" % granica_wypelnienia(obraz))
    if region:
        print("ostatni blok niejednostajny w zrzucie: 0x%X"
              % (granica_wypelnienia(region) + BAZA))

    print()
    print("== kandydaci na jaskinie plaintext (160 B) ==")
    zajete = [(pa, pa + 4, n) for n, pa in KOTWICE]
    zajete += [(pa, pa + 4, n) for n, pa in MIEJSCA]
    zajete.append((JASKINIA_RUNTIME[0], JASKINIA_RUNTIME[0] + JASKINIA_RUNTIME[1],
                   "runtime_cave"))
    for pa in KANDYDACI:
        zakres = (pa, pa + JASKINIA_PLAINTEXT_STARA[1], "plaintext_cave@0x%05X" % pa)
        k = kolizje(zajete + [zakres])
        niezero_o = sum(1 for b in obraz[pa:pa + 160] if b)
        niezero_r = (sum(1 for b in region[pa - BAZA:pa - BAZA + 160] if b)
                     if region else -1)
        print("  0x%05X..0x%05X  kolizje: %-4s  niezerowych bajtow: obraz %3d/160,"
              " zrzut %3d/160"
              % (pa, pa + 160,
                 "brak" if not k else ",".join("%s/%s" % x for x in k),
                 niezero_o, niezero_r))

    print()
    print("== stan obecny ==")
    for nazwa, (pa, rozmiar) in (("runtime_cave", JASKINIA_RUNTIME),
                                 ("plaintext_cave", JASKINIA_PLAINTEXT_STARA)):
        koniec = pa + rozmiar
        print("  %-14s PA 0x%05X..0x%05X  %3d B, do konca segmentu %3d B"
              % (nazwa, pa, koniec, rozmiar, KONIEC - koniec))
    print("  obie jaskinie leza w jednej stronie 4 kB: 0x%05X..0x%05X"
          % (0x61000, 0x62000))
    print("  obraz konczy dane na PA 0x%05X (rel 0x%05X); zrzut pod 0x61F00"
          " jest losowy, czyli to nieuzywany SRAM" % (0x61F00, 0x39F00))
    return 0


if __name__ == "__main__":
    sys.exit(main())
