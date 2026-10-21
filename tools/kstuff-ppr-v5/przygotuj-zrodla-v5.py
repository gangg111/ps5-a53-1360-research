#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Przygotowuje drzewo zrodel kstuff z przeniesiona jaskinia plaintext (v5).

Kolejnosc jest celowa i taka sama jak w v4: najpierw skrypt v4 (ktory sam
uruchamia v3, a ta v2) nanosi wszystkie zmiany v2, v3 i v4, a dopiero na gotowe
drzewo ten skrypt naklada zmiany v5. Dzieki temu v5 nie gubi niczego, co
dzialalo: walidacja obrazu 5/5 kotwicami, rozwiazywanie adresow, profil miejsc
latki i diagnostyka zapisu z v4 zostaja.

Zmiany v5:

  1. ppr_profiles.inc - wygenerowany na nowo z profilu
     artifacts/kstuff-profile-1360-v5.h i tabeli v5
     tools/kstuff-ppr-v5/include/ppr_patch_1360_v5.h. Roznia sie od v4 dwoma
     polami: plaintext_cave_va 0x04E61F50 -> 0x04E5E000 (PA 0x61F50 -> 0x5E000)
     oraz io_file_size 0x39F00 -> 0x36000 (zmierzona granica miedzy trescia
     obrazu a wypelnieniem). Reszta profilu bez zmian.
  2. ppr_patch.c - ppr_write_checked: po nieudanym zapisie pelnego rozmiaru
     zapis idzie porcjami po 32 B, kazda z odczytem kontrolnym i wlasna linia
     w klog (hipoteza (c) ze zlecenia, limit dlugosci polecenia).
  3. ppr_patch.c - ppr_probe_a53_write_at: dwie proby zapisu zamiast jednej,
     pod nowym adresem jaskini plaintext (160 B) i pod starym adresem jaskini
     runtime (32 B). Jednym przebiegiem odpowiada to, czy adres ma znaczenie.
  4. ppr_patch.c - ppr_install_caves_with_retry: loguje VA i PA obu jaskin,
     ich wyrownanie i kolejnosc zapisu, a werdykt zalezny od obu prob.
  5. ppr_install_bridge.c - linia o drodze zapisu mowi tez, gdzie leza obie
     jaskinie po przeniesieniu,
  6. main.c - napis instalacji mowi 1360-ppr-v5.

Uzycie:
  python3 tools/kstuff-ppr-v5/przygotuj-zrodla-v5.py --wyjscie /mnt/c/tmp/kstuff-v5 --czysto
  bash tools/kstuff-ppr-v5/build-v5.sh /mnt/c/tmp/kstuff-v5
"""
import argparse
import os
import stat
import subprocess
import sys

TU = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TU))
V4_PREP = os.path.join(REPO, "tools", "kstuff-ppr-v4",
                       "przygotuj-zrodla-v4.py")
GEN_PROFILI = os.path.join(REPO, "tools", "kstuff-ppr-v3",
                           "gen_profiles_1360_v3.py")
PROFIL_V5 = os.path.join(REPO, "artifacts", "kstuff-profile-1360-v5.h")
TABELA_V5 = os.path.join(TU, "include", "ppr_patch_1360_v5.h")
WSTAWKI = os.path.join(TU, "wstawki")

PLIKI_V5 = ["src/ppr/ppr_patch.c", "src/ppr/ppr_profiles.inc",
            "src/ppr/ppr_install_bridge.c", "src/main.c"]

# Linia dodana przez v4 w mostku; v5 dopisuje za nia druga.
LINIA_V4 = ('    ppr_puts("[*] PPR write path: SDBGP typ 0x01040031 '
            'przez skrzynke coredump (jadro 13.60 nigdy go nie buduje, '
            '0 wystapien w obrazie 64 MB)");\n')
LINIA_V5 = ('    ppr_puts("[*] PPR v5: jaskinia plaintext (dane, 160 B) pod '
            'PA 0x5E000, jaskinia runtime (kod, 76 B) pod PA 0x61F00, '
            'kazda w osobnej stronie 4 kB");\n')


def usun_katalog(sciezka):
    """Usuwa katalog roboczy, takze gdy git zostawil pliki tylko do odczytu."""
    if not os.path.exists(sciezka):
        return
    for korzen, _katalogi, pliki in os.walk(sciezka):
        for nazwa in pliki:
            try:
                os.chmod(os.path.join(korzen, nazwa), stat.S_IWRITE)
            except OSError:
                pass
    import shutil
    shutil.rmtree(sciezka)


def podmien(sciezka, stare, nowe, opis=""):
    tekst = open(sciezka, encoding="utf-8").read()
    if tekst.count(stare) != 1:
        raise SystemExit("%s: kotwica wystepuje %d razy, oczekiwano 1%s"
                         % (sciezka, tekst.count(stare),
                            " (%s)" % opis if opis else ""))
    open(sciezka, "w", encoding="utf-8", newline="\n").write(
        tekst.replace(stare, nowe, 1))
    print("  zmieniono %s%s" % (os.path.basename(sciezka),
                                ": " + opis if opis else ""))


def podmien_funkcje(sciezka, sygnatura, nowy_tekst, opis=""):
    """Zastepuje cala funkcje: od linii z sygnatura do pierwszej linii "}".

    Domkniecia blokow wewnatrz funkcji sa wciete, wiec samotne "}" na poczatku
    linii trafia wylacznie w koniec funkcji.
    """
    tekst = open(sciezka, encoding="utf-8").read()
    if tekst.count(sygnatura) != 1:
        raise SystemExit("%s: sygnatura %r wystepuje %d razy"
                         % (sciezka, sygnatura, tekst.count(sygnatura)))
    poczatek = tekst.index(sygnatura)
    koniec = tekst.find("\n}\n", poczatek)
    if koniec < 0:
        raise SystemExit("%s: nie znalazlem konca funkcji %r"
                         % (sciezka, sygnatura))
    koniec += len("\n}\n")
    tekst = tekst[:poczatek] + nowy_tekst + tekst[koniec:]
    open(sciezka, "w", encoding="utf-8", newline="\n").write(tekst)
    print("  podmieniono funkcje %s%s" % (sygnatura.strip(),
                                          ": " + opis if opis else ""))


def czytaj_wstawke(nazwa):
    return open(os.path.join(WSTAWKI, nazwa), encoding="utf-8").read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wyjscie", required=True,
                    help="katalog roboczy na kopie zrodel (poza repozytorium)")
    ap.add_argument("--czysto", action="store_true",
                    help="usun katalog wyjscia, jesli istnieje")
    o = ap.parse_args()
    out = os.path.abspath(o.wyjscie)

    print("[1/4] drzewo v4 (wszystkie zmiany v2, v3 i v4)")
    if os.path.exists(out):
        if not o.czysto:
            raise SystemExit("%s istnieje; uzyj --czysto albo wskaz inny "
                             "katalog" % out)
        usun_katalog(out)
    subprocess.run([sys.executable, V4_PREP, "--wyjscie", out, "--czysto"],
                   check=True)

    ldr = os.path.join(out, "ps5-kstuff-ldr")
    ppr = os.path.join(ldr, "src", "ppr")

    print("[2/4] profil v5: jaskinia plaintext pod PA 0x5E000")
    for sciezka in (PROFIL_V5, TABELA_V5):
        if not os.path.isfile(sciezka):
            raise SystemExit("brak %s" % sciezka)
    subprocess.run([sys.executable, GEN_PROFILI,
                    "--profil", PROFIL_V5,
                    "--tabela", TABELA_V5,
                    "--wyjscie", os.path.join(ppr, "ppr_profiles.inc")],
                   check=True)

    print("[3/4] diagnostyka i kolejnosc zapisu jaskin")
    podmien_funkcje(
        os.path.join(ppr, "ppr_patch.c"),
        "static int ppr_write_checked(const struct ppr_context *ctx, "
        "uint64_t pa,",
        czytaj_wstawke("ppr_write_diag_v5.c"),
        "zapis porcjami po 32 B")
    podmien_funkcje(
        os.path.join(ppr, "ppr_patch.c"),
        "static int ppr_probe_a53_write(const struct ppr_context *ctx,",
        czytaj_wstawke("ppr_probe_v5.c"),
        "dwie proby zapisu: nowy i stary adres")
    podmien_funkcje(
        os.path.join(ppr, "ppr_patch.c"),
        "static int ppr_install_caves_with_retry(",
        czytaj_wstawke("ppr_caves_retry_v5.c"),
        "kolejnosc i werdykt z obu prob")

    print("[4/4] napisy wersji")
    podmien(os.path.join(ppr, "ppr_install_bridge.c"), LINIA_V4,
            LINIA_V4 + LINIA_V5, "adresy obu jaskin po przeniesieniu")
    podmien(os.path.join(ldr, "src", "main.c"), "1360-ppr-v4",
            "1360-ppr-v5", "napis instalacji")

    print("gotowe")
    print("  pliki rozne od v4: %s" % ", ".join(PLIKI_V5))
    print("  buduj: bash tools/kstuff-ppr-v5/build-v5.sh %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
