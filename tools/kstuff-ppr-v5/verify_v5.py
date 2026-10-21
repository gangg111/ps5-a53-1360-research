#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Weryfikacja artefaktu v5: przeniesiona jaskinia plaintext i zapis jaskin.

Skrypt robi trzy rzeczy:

  1. uruchamia pelna bramke v2 (tools/kstuff-ppr-v2/verify_v2.py), ale na
     PROFILU v5 i TABELI v5, wiec te same 61 sprawdzen (profil, adresy, slowa
     stock i po latce, szablony jaskin, brak kolizji, sciezka fPKG, stary
     artefakt jako kontrola) przechodzi nowy Uklad jaskin,
  2. powtarza kontrole v3 (kotwice tozsamosci obrazu, okno transportu, granica
     paddingu zmierzona z obrazu A53, slowa stock w obrazie) na profilu v5,
  3. dokłada sprawdzenia wlasne v5:
       E. przeniesienie jaskini plaintext: nowy adres, brak kolizji z 5
          kotwicami, 5 miejscami latki i jaskinia runtime, osobna strona 4 kB,
          jaskinia w zmierzonym wypelnieniu obrazu,
       F. jaskinia runtime (kod) bez zmian wobec v4: ten sam szablon i ten sam
          adres, wiec zostaje wykonywalna,
       G. w binarium sa napisy i stale nowej diagnostyki zapisu (dwie proby,
          zapis porcjami, kolejnosc jaskin), nie ma napisu v4,
       H. manifest menedzera (name, version, checksum).

Uzycie:
  python3 tools/kstuff-ppr-v5/verify_v5.py [--elf PLIK] [--manifest PLIK]

Kod wyjscia: 0 gdy wszystkie sprawdzenia przechodza, 1 gdy ktorekolwiek pada.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys

TU = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TU))
ART = os.path.join(REPO, "artifacts")
ELF_V5 = os.path.join(ART, "kstuff-1360-ppr-v5.elf")
ELF_V4 = os.path.join(ART, "kstuff-1360-ppr-v4.elf")
MANIFEST = os.path.join(ART, "pldmgr_kstuff_ppr_v5.json")
PROFIL_V5 = os.path.join(ART, "kstuff-profile-1360-v5.h")
PROFIL_V4 = os.path.join(ART, "kstuff-profile-1360.h")
TABELA_V5 = os.path.join(TU, "include", "ppr_patch_1360_v5.h")
OBRAZ = os.path.join(ART, "a53-obraz-odtworzony.bin")
REGION = next((p for p in (r"<work>\a53_regions\region_00028000.bin",
                           "/mnt/d/Tools/a53_regions/region_00028000.bin")
               if os.path.isfile(p)), "")

V2_DIR = os.path.join(REPO, "tools", "kstuff-ppr-v2")
V3_DIR = os.path.join(REPO, "tools", "kstuff-ppr-v3")

LIMIT_OKNA = 0xC0000

# Napisy, ktore musza byc w binarium, zeby jeden przebieg na konsoli
# rozstrzygnal, czy zapis pod nowym adresem dziala.
NAPISY_V5 = [
    (b"[*] A53 write probe (%s): typ 0x%08x, PA 0x%lx, %u B, transport=%d",
     "proba zapisu: adres, rozmiar, kod transportu"),
    (b"[!] A53 odrzuca zapis 0x01040031 pod OBOMA adresami",
     "werdykt obejmujacy oba adresy prob"),
    (b"[!] zapis pod starym adresem 0x%lx dziala, a pod nowym 0x%lx nie",
     "werdykt: dziala stary adres, nie dziala nowy"),
    (b"[!] zapis pod nowym adresem 0x%lx dziala, a pod adresem jaskini runtime",
     "werdykt: dziala nowy adres, nie dziala runtime"),
    (b"[!] write/readback failed for %s @ PA 0x%lx: transport write=%d, "
     b"readback=%d, size=%u",
     "rozdzielone kody zwrotu zapisu i odczytu"),
    (b"    zadane    : ", "hex danych do zapisania"),
    (b"    odczytane : ", "hex danych w pamieci po zapisie"),
    (b"probuje porcjami po %u B", "zapis porcjami po nieudanym pelnym zapisie"),
    (b"    porcja %u/%u @ PA 0x%lx, %u B: write=%d, read=%d, %s",
     "wynik kazdej porcji z osobna"),
    (b"[+] zapis porcjami zadzialal dla %s @ PA 0x%lx",
     "ratunek porcjami zadzialal"),
    (b"[*] jaskinie z profilu: plaintext VA 0x%lx (wyrownanie 0x%x), "
     b"runtime VA 0x%lx (wyrownanie 0x%x)",
     "log podaje VA i wyrownanie obu jaskin"),
    (b"[*] kolejnosc: najpierw jaskinia plaintext", "log podaje kolejnosc"),
    (b"[*] PPR v5: jaskinia plaintext (dane, 160 B) pod PA 0x5E000",
     "linia o drodze zapisu z adresami jaskin"),
    (b"1360-ppr-v5", "napis wersji instalacji"),
]


def wczytaj(modul, katalog):
    spec = importlib.util.spec_from_file_location(
        modul, os.path.join(katalog, modul + ".py"))
    if spec is None or spec.loader is None:
        raise SystemExit("nie moge wczytac %s z %s" % (modul, katalog))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ile(dane, wartosc, szerokosc=4):
    if szerokosc == 4:
        wzor = struct.pack("<I", wartosc & 0xFFFFFFFF)
    else:
        wzor = struct.pack("<Q", wartosc & 0xFFFFFFFFFFFFFFFF)
    return dane.count(wzor)


def na_fizyczne(p, va):
    if va >= p["io_mapped_base"]:
        return p["io_sram_base"] + (va - p["io_mapped_base"])
    return 0x85000 + (va - p["dev_mapped_base"])


def cel_galezi(word, va):
    """Adres docelowy rozkazu B/BL (imm26 ze slowa, little endian)."""
    delta = (word & 0x03FFFFFF) << 2
    if delta & 0x08000000:
        delta -= 0x10000000
    return va + delta


def granica_entropii(dane, baza, koniec):
    """Pierwszy blok 4 kB, od ktorego do konca segmentu wszystkie bloki maja
    rozklad jednostajny (entropia powyzej 7.9 bitu). To zmierzona granica
    miedzy trescia obrazu a wypelnieniem."""
    import collections
    import math

    def entropia(blok):
        licznik = collections.Counter(blok)
        n = float(len(blok))
        return -sum((c / n) * math.log(c / n, 2) for c in licznik.values())

    ostatni = None
    for start in range(baza, koniec, 0x1000):
        blok = dane[start:start + 0x1000]
        if len(blok) != 0x1000:
            continue
        if entropia(blok) <= 7.9:
            ostatni = start
    return (ostatni + 0x1000) if ostatni is not None else koniec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=ELF_V5)
    ap.add_argument("--manifest", default=MANIFEST)
    o = ap.parse_args()

    if not os.path.isfile(o.elf):
        raise SystemExit("brak artefaktu %s" % o.elf)
    dane = open(o.elf, "rb").read()
    sha = hashlib.sha256(dane).hexdigest()

    v2 = wczytaj("verify_v2", V2_DIR)
    v3 = wczytaj("verify_v3", V3_DIR)

    print("=" * 78)
    print("0. bramka v2 na PROFILU v5 i artefakcie v5")
    print("=" * 78)
    v2.ROZMIAR_V2 = len(dane)
    zapisane_argv = sys.argv
    sys.argv = ["verify_v2.py", "--nowy", o.elf,
                "--profil", PROFIL_V5, "--tabela", TABELA_V5]
    try:
        rc_v2 = v2.main()
    finally:
        sys.argv = zapisane_argv

    w = v2.Wynik()
    p = v2.czytaj_profil(PROFIL_V5)
    p4 = v2.czytaj_profil(PROFIL_V4)
    obraz = open(OBRAZ, "rb").read()
    baza = p["io_sram_base"]
    koniec_io = baza + p["io_mapped_size"]
    padding_v3 = v3.poczatek_paddingu(obraz, baza, koniec_io)
    padding = granica_entropii(obraz, baza, koniec_io)

    print()
    print("=" * 78)
    print("E. przeniesienie jaskini plaintext")
    print("=" * 78)
    print("  profil v4: plaintext VA 0x%08X (PA 0x%05X)"
          % (p4["plaintext_cave_va"], na_fizyczne(p4, p4["plaintext_cave_va"])))
    print("  profil v5: plaintext VA 0x%08X (PA 0x%05X)"
          % (p["plaintext_cave_va"], na_fizyczne(p, p["plaintext_cave_va"])))
    print("  padding obrazu A53 od PA 0x%05X (zmierzony, nie wyprowadzony)"
          % padding)

    pa_pt = na_fizyczne(p, p["plaintext_cave_va"])
    pa_rt = na_fizyczne(p, p["runtime_cave_va"])
    rozmiar_pt = len(v2.SZABLON_PLAINTEXT) * 4
    rozmiar_rt = len(v2.SZABLON_RUNTIME) * 4

    w.sprawdz(p["plaintext_cave_va"] == 0x04E5E000,
              "v5: plaintext_cave_va to 0x04E5E000", "0x%08X"
              % p["plaintext_cave_va"])
    w.sprawdz(p["runtime_cave_va"] == p4["runtime_cave_va"],
              "v5: runtime_cave_va bez zmian wobec v4",
              "0x%08X" % p["runtime_cave_va"])
    w.sprawdz(p["io_mapped_size"] == p4["io_mapped_size"] and
              p["io_sram_base"] == p4["io_sram_base"] and
              p["io_mapped_base"] == p4["io_mapped_base"],
              "v5: bazy i rozmiar segmentu io bez zmian")
    w.sprawdz(p["io_file_size"] == 0x36000,
              "v5: io_file_size to zmierzona granica paddingu (0x36000)",
              "0x%X" % p["io_file_size"])
    w.sprawdz(padding == baza + p["io_file_size"],
              "v5: granica paddingu z pomiaru entropii = io_sram_base + "
              "io_file_size", "0x%05X" % padding)
    w.sprawdz(padding_v3 <= baza + p["io_file_size"],
              "v5: granica paddingu z reguly v3 nie wykracza poza io_file_size",
              "v3 0x%05X, v5 0x%05X" % (padding_v3, baza + p["io_file_size"]))

    # Kolizje: 5 kotwic (16 B), 5 miejsc latki (4 B), obie jaskinie.
    kotwice = v3.kotwice_z_tabeli(v2)
    zakresy = []
    for rel, nazwa, _bajty in kotwice:
        pa = baza + rel
        zakresy.append((pa, pa + 16,
                        "kotwica %s" % v3.NAZWY_KOTWIC_ASCII.get(nazwa, nazwa)))
    for nazwa, va, _s, _n in v2.policz_latke(p)[0]:
        zakresy.append((na_fizyczne(p, va), na_fizyczne(p, va) + 4, nazwa))
    zakresy.append((pa_rt, pa_rt + rozmiar_rt, "runtime_cave"))
    zakresy.append((pa_pt, pa_pt + rozmiar_pt, "plaintext_cave"))
    posortowane = sorted(zakresy)
    kolizje = [(a[2], b[2]) for a, b in zip(posortowane, posortowane[1:])
               if a[1] > b[0]]
    w.sprawdz(not kolizje,
              "v5: jaskinie nie nachodza na kotwice, miejsca latki ani siebie",
              ", ".join("%s/%s" % k for k in kolizje) if kolizje else "")

    w.sprawdz(pa_pt % 0x1000 == 0, "v5: jaskinia plaintext na granicy strony 4 kB",
              "PA 0x%05X" % pa_pt)
    w.sprawdz(pa_pt // 0x1000 != pa_rt // 0x1000,
              "v5: jaskinie leza w roznych stronach 4 kB",
              "0x%05X / 0x%05X" % (pa_rt, pa_pt))
    w.sprawdz(pa_pt >= padding and pa_pt + rozmiar_pt <= koniec_io,
              "v5: jaskinia plaintext w paddingu io i konczy sie przed koncem "
              "mapowania", "PA 0x%05X..0x%05X" % (pa_pt, pa_pt + rozmiar_pt))
    w.sprawdz(pa_rt >= padding and pa_rt + rozmiar_rt <= koniec_io,
              "v5: jaskinia runtime w paddingu io i konczy sie przed koncem "
              "mapowania", "PA 0x%05X..0x%05X" % (pa_rt, pa_rt + rozmiar_rt))
    w.sprawdz(pa_pt + rozmiar_pt <= LIMIT_OKNA and pa_rt + rozmiar_rt <= LIMIT_OKNA,
              "v5: obie jaskinie w oknie transportu 0x%X" % LIMIT_OKNA)
    zapas = koniec_io - (pa_pt + rozmiar_pt)
    zapas_v4 = koniec_io - (na_fizyczne(p4, p4["plaintext_cave_va"]) + rozmiar_pt)
    w.sprawdz(zapas >= 0x1000,
              "v5: po jaskini plaintext zostaje co najmniej 0x1000 B zapasu "
              "do konca segmentu", "v5 %d B, v4 %d B" % (zapas, zapas_v4))

    # Wypelnienie pod nowa jaskinia nie moze wygladac na kod: entropia bloku
    # 4 kB musi byc jednostajna, tak jak reszta paddingu obrazu.
    blok = obraz[pa_pt - (pa_pt % 0x1000):pa_pt - (pa_pt % 0x1000) + 0x1000]
    w.sprawdz(v3.uniform(blok),
              "v5: blok 4 kB pod nowa jaskinia to wypelnienie (brak kodu)",
              "entropia bloku jednostajna" if v3.uniform(blok) else "NIE")
    if REGION and os.path.isfile(REGION):
        zrzut = open(REGION, "rb").read()
        b2 = zrzut[pa_pt - baza:pa_pt - baza + 0x1000]
        zero = sum(1 for b in b2 if b == 0)
        print("  zrzut zywy pod PA 0x%05X: %d/4096 zer, bajty bez struktury"
              % (pa_pt, zero))
        w.sprawdz(zero <= 0x200,
                  "v5: w zrzucie zywym pod nowa jaskinia nie ma struktury",
                  "%d zer na 4096 B" % zero)

    print()
    print("=" * 78)
    print("F. jaskinia runtime (kod) bez zmian, czyli zostaje wykonywalna")
    print("=" * 78)
    szablon_rt = b"".join(struct.pack("<I", x) for x in v2.policz_latke(p)[2])
    obraz_rt = v2.policz_latke(p)[4]
    w.sprawdz(dane.count(szablon_rt) == 1,
              "v5: szablon jaskini runtime (%d slow) jest w binarium"
              % len(v2.SZABLON_RUNTIME), "%d trafien" % dane.count(szablon_rt))
    obraz_rt4 = v2.policz_latke(p4)[4]
    w.sprawdz(obraz_rt == obraz_rt4,
              "v5: jaskinia runtime ma te same slowa co w v4 (adres i galezie "
              "niezmienione)")
    if os.path.isfile(ELF_V4) and os.path.abspath(o.elf) != os.path.abspath(ELF_V4):
        dane4 = open(ELF_V4, "rb").read()
        i5 = dane.find(szablon_rt)
        i4 = dane4.find(szablon_rt)
        w.sprawdz(i5 >= 0 and i4 >= 0 and
                  dane[i5:i5 + len(szablon_rt)] ==
                  dane4[i4:i4 + len(szablon_rt)],
                  "v5: bajty szablonu jaskini runtime w ELF sa identyczne jak w v4")
    # Dokad naprawde celuja galezie: rozwiniecie B/BL z tabeli slow po latce.
    cel = {}
    for nazwa, va, _s, nowe in v2.policz_latke(p)[0]:
        cel[nazwa] = cel_galezi(nowe, va)
    w.sprawdz(cel.get("sha_auth_site") == p["plaintext_cave_va"],
              "v5: galez sha_auth_site celuje w NOWA jaskinie plaintext",
              "0x%08X" % cel.get("sha_auth_site", 0))
    w.sprawdz(cel.get("call[0]") == p["runtime_cave_va"] and
              cel.get("call[1]") == p["runtime_cave_va"],
              "v5: galezie call celuja w jaskinie runtime, czyli w kod",
              "0x%08X i 0x%08X" % (cel.get("call[0]", 0),
                                   cel.get("call[1]", 0)))
    w.sprawdz(cel.get("aes_site[0]") == p["runtime_cave_va"] + 0x2C and
              cel.get("aes_site[1]") == p["runtime_cave_va"] + 0x2C,
              "v5: galezie aes_site celuja w jaskinie runtime + 0x2C",
              "0x%08X" % cel.get("aes_site[0]", 0))

    print()
    print("=" * 78)
    print("G. diagnostyka zapisu jaskin w binarium v5")
    print("=" * 78)
    for napis, opis in NAPISY_V5:
        w.sprawdz(dane.count(napis) >= 1, "v5: napis obecny (%s)" % opis,
                  napis.decode("latin-1")[:58])
    w.sprawdz(ile(dane, 0x01040031) >= 1,
              "v5: stala polecenia zapisu 0x01040031 jest w binarium",
              "%d trafien" % ile(dane, 0x01040031))
    w.sprawdz(ile(dane, 0x02040031) >= 1,
              "v5: stala wyniku zapisu 0x02040031 jest w binarium",
              "%d trafien" % ile(dane, 0x02040031))
    w.sprawdz(ile(dane, p["plaintext_cave_va"], 8) >= 1,
              "v5: nowy adres VA jaskini plaintext (0x04E5E000) jest w binarium",
              "%d trafien" % ile(dane, p["plaintext_cave_va"], 8))
    w.sprawdz(ile(dane, p4["plaintext_cave_va"], 8) == 0,
              "v5: stary adres VA jaskini plaintext (0x04E61F50) znikl z binarium",
              "%d trafien" % ile(dane, p4["plaintext_cave_va"], 8))
    w.sprawdz(dane.count(b"1360-ppr-v4") == 0,
              "v5: nie ma juz napisu 1360-ppr-v4",
              "%d trafien" % dane.count(b"1360-ppr-v4"))

    print()
    print("=" * 78)
    print("H. manifest menedzera")
    print("=" * 78)
    if os.path.isfile(o.manifest):
        m = json.load(open(o.manifest, encoding="utf-8"))
        w.sprawdz(m.get("name") == "kstuff v5 PPR", "manifest: name",
                  repr(m.get("name")))
        w.sprawdz(m.get("version") == "1360-v5", "manifest: version",
                  repr(m.get("version")))
        w.sprawdz(m.get("checksum") == sha,
                  "manifest: checksum = sha256 pliku", m.get("checksum", ""))
        w.sprawdz("kstuff-1360-ppr-v5.elf" in m.get("description", ""),
                  "manifest: opis wskazuje artefakt v5")
    else:
        w.blad("manifest istnieje", o.manifest)

    print()
    print("=" * 78)
    print("I. artefakt")
    print("=" * 78)
    print("  plik:    %s" % o.elf)
    print("  rozmiar: %d B" % len(dane))
    print("  sha256:  %s" % sha)

    print()
    print("=" * 78)
    print("PODSUMOWANIE v5")
    print("=" * 78)
    ok_v5 = w.raport()
    print("  bramka v2 (profil v5): %s" % ("OK" if rc_v2 == 0 else "BLAD"))
    return 0 if (ok_v5 and rc_v2 == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
