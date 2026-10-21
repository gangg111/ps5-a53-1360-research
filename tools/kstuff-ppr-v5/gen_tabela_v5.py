#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generuje tabele a53patch dla v5: te same dane, inna jaskinia plaintext.

v5 przenosi jaskinie plaintext z PA 0x61F00-owego ogona na PA 0x5E000, wiec
slowa galezi wewnatrz tej jaskini (indeksy 7, 28, 33) zmieniaja sie, bo licza
sie od jej adresu. Zamiast przepisywac je recznie, ten skrypt podmienia dwa
pola w slowniku P z tools/a53patch/gen_patch.py i wola jego generator, dzieki
czemu tabela v5 powstaje ta sama, sprawdzona droga (weryfikacja slow stock w
obrazie, zasieg galezi, kolizje z kotwicami, bramka prologu celu hooka).

Zmiana wobec v5: tylko plaintext_cave_va i io_file_size, dokladnie jak w
artifacts/kstuff-profile-1360-v5.h.

Uzycie:
  python tools/kstuff-ppr-v5/gen_tabela_v5.py
"""
import importlib.util
import os
import sys

TU = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TU))
GEN = os.path.join(REPO, "tools", "a53patch", "gen_patch.py")
WYJSCIE = os.path.join(TU, "include", "ppr_patch_1360_v5.h")

PLAINTEXT_CAVE_VA = 0x04E5E000
IO_FILE_SIZE = 0x36000


def wczytaj_generator():
    spec = importlib.util.spec_from_file_location("gen_patch", GEN)
    if spec is None or spec.loader is None:
        raise SystemExit("nie moge wczytac %s" % GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    g = wczytaj_generator()
    stare = (g.P["plaintext_cave_va"], g.P["io_file_size"])
    g.P["plaintext_cave_va"] = PLAINTEXT_CAVE_VA
    g.P["io_file_size"] = IO_FILE_SIZE
    print("v5: plaintext_cave_va 0x%08X -> 0x%08X" % (stare[0], PLAINTEXT_CAVE_VA))
    print("v5: io_file_size      0x%08X -> 0x%08X" % (stare[1], IO_FILE_SIZE))
    print()
    os.makedirs(os.path.dirname(WYJSCIE), exist_ok=True)
    zapisane = sys.argv
    sys.argv = ["gen_patch.py", "--wyjscie", WYJSCIE]
    try:
        rc = g.main()
    finally:
        sys.argv = zapisane
    if rc != 0:
        return rc
    print()
    print("tabela v5: %s" % WYJSCIE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
