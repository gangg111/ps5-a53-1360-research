# -*- coding: utf-8 -*-
"""Weryfikacja statyczna artefaktu writeprobe.elf (bez konsoli).

Sprawdza:
 1. naglowek ELF (klasa, maszyna, typ, entry, segment PT_LOAD),
 2. czy w binarium leza wszystkie stale transportu, opcody i typy pamieci,
 3. czy w binarium leza wszystkie adresy macierzy i kotwice obrazu A53,
 4. czy macierz w zrodle ma dokladnie te adresy, typy i dostepy, w tej kolejnosci,
 5. czy kotwice w zrodle zgadzaja sie z obrazem odniesienia (artifacts/a53-obraz-odtworzony.bin),
 6. czy w zrodle sa bramki bezpieczenstwa: firmware 13.60, kotwice, odmowa zapisu bez
    odczytu, przywracanie oryginalu, log z fsync, budzet 600 s i plik stop.

Wynik: wypis na stdout; kod wyjscia 1 przy bledzie.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OKNO_SRAM = 0xC0000

# Adresy macierzy w kolejnosci wymaganej przez zlecenie (od najbezpieczniejszych).
KOLEJNOSC_ADRESOW = [0x5E000, 0x60000, 0x61F00, 0x61F50, 0x28000, 0x80000]
TYPY_PAMIECI = [0x020000, 0x020100, 0x010000, 0x000000]
TYPY_DOSTEPU = [4, 6]


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def naglowek_elfa(b):
    if b[:4] != b"\x7fELF":
        return None
    return {
        "klasa": b[4],
        "dane": b[5],
        "typ": struct.unpack_from("<H", b, 16)[0],
        "maszyna": struct.unpack_from("<H", b, 18)[0],
        "entry": struct.unpack_from("<Q", b, 24)[0],
        "phoff": struct.unpack_from("<Q", b, 32)[0],
        "phnum": struct.unpack_from("<H", b, 56)[0],
    }


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=os.path.join(REPO, "artifacts", "writeprobe.elf"))
    ap.add_argument("--zrodlo", default=os.path.join(REPO, "tools", "writeprobe", "writeprobe.c"))
    ap.add_argument("--rdzen", default=os.path.join(REPO, "tools", "writeprobe",
                                                   "writeprobe_core.c"))
    ap.add_argument("--naglowek", default=os.path.join(REPO, "tools", "writeprobe",
                                                      "writeprobe_core.h"))
    ap.add_argument("--obraz", default=os.path.join(REPO, "artifacts",
                                                    "a53-obraz-odtworzony.bin"))
    ap.add_argument("--manifests", nargs="*", default=[
        os.path.join(REPO, "artifacts", "pldmgr_writeprobe.json"),
        os.path.join(REPO, "artifacts", "writeprobe.elf.json"),
    ])
    o = ap.parse_args()

    bledy = []

    def ok(war, opis, szczegol=""):
        print(("  OK   " if war else "  BLAD ") + opis + (("  " + szczegol) if szczegol else ""))
        if not war:
            bledy.append(opis)

    print("== artefakt ==")
    e = open(o.elf, "rb").read()
    print("  plik: %s, %d B" % (os.path.basename(o.elf), len(e)))
    print("  sha256: %s" % sha256(o.elf))
    h = naglowek_elfa(e)
    ok(h is not None, "naglowek ELF obecny")
    if h:
        ok(h["klasa"] == 2, "ELF64", "klasa=%d" % h["klasa"])
        ok(h["dane"] == 1, "little endian", "dane=%d" % h["dane"])
        ok(h["typ"] in (2, 3), "ELF typu exec/dyn (SDK daje ET_DYN)", "typ=%d" % h["typ"])
        ok(h["maszyna"] == 62, "x86-64", "maszyna=%d" % h["maszyna"])
        ok(h["entry"] != 0, "entry != 0", "0x%x" % h["entry"])
        ok(h["phnum"] > 0, "sa segmenty", "phnum=%d" % h["phnum"])
        _load = [i for i in range(h["phnum"])
                 if struct.unpack_from("<I", e, h["phoff"] + i * 56)[0] == 1]
        ok(bool(_load), "jest co najmniej jeden segment PT_LOAD")

    print()
    print("== stale transportu w binarium ==")
    stale = [
        (0x01040031, "opcode zapisu pamieci A53 (SDBGP_WRITE_MEMORY)"),
        (0x01040021, "opcode odczytu pamieci A53 (SDBGP_READ_MEMORY)"),
        (0x02040031, "typ wyniku zapisu (SDBGP_RES_WRITE_MEMORY)"),
        (0x02040021, "typ wyniku odczytu"),
        (0x73354450, "magic DECI5S"),
        (0x80FF0180, "zrodlo DECI5S jadra"),
        (0x80FF0201, "cel DECI5S MP4"),
        (0x20000201, "protokol SDBGP"),
        (0x20303002, "polecenie zrzutu MP4 (kanal 1)"),
        (0x20303003, "polecenie zrzutu MP4 (kanal 2)"),
        (0x8008410f, "IOCTL_FINISH"),
        (0x40184115, "IOCTL_ALTER_STATE"),
    ]
    for v, nazwa in stale:
        ok(u32(v) in e, "stala 0x%08X: %s" % (v, nazwa))
    # UWAGA o IOCTL_START: kompilator sklada go jako IOCTL_FINISH + 0x3FFFC (lea),
    # wiec samego slowa 0x800C410B nie ma w binarium. Wartosc jest sprawdzana
    # w zrodle, w sekcji "bramki bezpieczenstwa".

    print()
    print("== typy pamieci macierzy w binarium ==")
    for v in TYPY_PAMIECI:
        if v == 0:
            print("  OK   typ 0x000000 to zero, nie da sie go szukac w binarium (sprawdzany w zrodle)")
            continue
        ok(u32(v) in e, "typ pamieci 0x%06X jest w ELF" % v)

    print()
    print("== adresy macierzy i kotwice w binarium ==")
    for a in KOLEJNOSC_ADRESOW:
        ok(u64(a) in e or u32(a) in e, "adres 0x%06X jest w ELF" % a)
    for a in (0x57AA8, 0x5B964, 0x5BC20, 0x5C7E8):
        ok(u64(a) in e or u32(a) in e, "kotwica 0x%06X jest w ELF" % a)

    print()
    print("== macierz w zrodle (kolejnosc i wartosci) ==")
    zrodlo = open(o.zrodlo, encoding="utf-8").read()
    rdzen = open(o.rdzen, encoding="utf-8").read()
    adresy = [(int(a, 16), opis) for a, opis in re.findall(
        r"\{ 0x([0-9A-F]+)ULL, \"([^\"]+)\" \}", rdzen)]
    typy = [int(a, 16) for a in re.findall(r"^    0x([0-9A-F]{6})U,$", rdzen, re.M)]
    dostepy = [int(a) for a in re.findall(r"^    ([0-9]+)U,$", rdzen, re.M)]
    print("  adresy: %s" % ", ".join("0x%X" % a for a, _ in adresy))
    print("  typy pamieci: %s" % ", ".join("0x%06X" % t for t in typy))
    print("  typy dostepu: %s" % ", ".join(str(d) for d in dostepy))
    ok([a for a, _ in adresy] == KOLEJNOSC_ADRESOW,
       "kolejnosc adresow zgodna ze zleceniem (od najbezpieczniejszych)")
    ok(typy == TYPY_PAMIECI, "typy pamieci zgodne ze zleceniem")
    ok(dostepy == TYPY_DOSTEPU, "typy dostepu zgodne ze zleceniem (4 i 6)")
    ok(len(adresy) == 6 and len(typy) == 4 and len(dostepy) == 2,
       "macierz ma 6 x 4 x 2 = 48 prob")
    for a, opis in adresy:
        ok(a + 16 <= OKNO_SRAM, "adres 0x%06X z zapasem 16 B w oknie transportu" % a,
           opis)
    ok(adresy[-1][0] == 0x80000, "0x80000 jest ostatnim adresem macierzy")
    ok(adresy[-2][0] == 0x28000, "zywy kod 0x28000 jest przed ostatnim adresem")

    print()
    print("== kotwice w zrodle kontra obraz odniesienia ==")
    obraz = open(o.obraz, "rb").read()
    kotwice = []
    for a, nazwa, bajty in re.findall(
            r"\{ 0x([0-9A-F]+)ULL, \"([^\"]+)\", \{\s*([0-9a-fx,\s]+?)\} \}", zrodlo, re.S):
        b = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", bajty))
        kotwice.append((int(a, 16), nazwa, b))
    print("  kotwic w zrodle: %d" % len(kotwice))
    ok(len(kotwice) == 5, "piec kotwic tozsamosci obrazu A53")
    for a, nazwa, b in kotwice:
        ok(len(b) == 16, "kotwica %s ma 16 bajtow" % nazwa)
        ok(a + 16 <= OKNO_SRAM, "kotwica %s lezy w oknie transportu" % nazwa)
        if a + 16 <= len(obraz):
            ok(obraz[a:a + 16] == b, "kotwica %s zgodna z obrazem odniesienia" % nazwa,
               "offset 0x%06X" % a)
        else:
            ok(False, "kotwica %s poza obrazem odniesienia" % nazwa)
    ok(any(a == 0x28000 for a, _, _ in kotwice),
       "naglowek obrazu 0x28000 jest wsrod kotwic (bramka odczytu)")

    print()
    print("== bramki bezpieczenstwa w zrodle ==")
    naglowek = open(o.naglowek, encoding="utf-8").read()
    ok(re.search(r"#define BUDZET_S\s+600U", zrodlo) is not None, "budzet 600 s")
    ok(re.search(r"#define IOCTL_START\s+0x800c410bU", zrodlo) is not None,
       "IOCTL_START 0x800c410b (skladany przez kompilator, wiec sprawdzany tutaj)")
    ok(re.search(r"#define FW_1360\s+0x1360U", zrodlo) is not None, "bramka firmware 13.60")
    ok(re.search(r"#define OKNO_SRAM\s+0xC0000ULL", zrodlo) is not None,
       "granica okna transportu 0xC0000")
    ok("ODMOWA" in zrodlo, "sa jawne odmowy (brak zapisow, gdy bramka nie przejdzie)")
    ok("zgodne_przed < 3" in zrodlo,
       "bramka odczytu wymaga naglowka obrazu i co najmniej 3 kotwic")
    ok("ODCZYT PRZED NIEUDANY" in zrodlo,
       "brak wiarygodnego odczytu przed proba wstrzymuje zapis")
    ok("read_at(\"po\"" in zrodlo, "odczyt kontrolny po zapisie")
    ok("przywroc(" in zrodlo and "przywracam" in zrodlo,
       "przywracanie oryginalu po zmianie pamieci")
    ok("memcmp(po_przywroceniu, przed, size)" in zrodlo,
       "przywrocenie jest potwierdzane odczytem")
    ok("PRZERWANIE" in zrodlo, "sa warunki przerwania macierzy")
    ok("write_at(p->adres, wzorzec, WP_WZORZEC" in zrodlo,
       "proba zapisuje wzorzec 16 B (WP_WZORZEC)")
    ok(re.search(r"#define WP_WZORZEC\s+16U", naglowek) is not None, "wzorzec ma 16 bajtow")
    ok("fsync(fileno(g_log))" in zrodlo, "log z fsync po kazdej linii")
    ok("/data/writeprobe.txt" in zrodlo, "log do /data/writeprobe.txt")
    ok("/data/writeprobe.stop" in zrodlo and "stop_plik()" in zrodlo,
       "plik stop /data/writeprobe.stop jest sprawdzany")
    ok("usleep(CZAS_OSADZENIA_MS * 1000U)" in zrodlo,
       "odczekanie miedzy zapisem a odczytem kontrolnym")

    print()
    print("== zgodnosc artefaktu z manifestami ==")
    for m in o.manifests:
        if not os.path.exists(m):
            ok(False, "manifest istnieje: %s" % os.path.basename(m))
            continue
        d = json.load(open(m, encoding="utf-8"))
        ok(d.get("filename") == os.path.basename(o.elf),
           "manifest %s wskazuje na ten plik" % os.path.basename(m),
           str(d.get("filename")))
        ok(d.get("checksum") == sha256(o.elf),
           "sha256 w %s zgodny z artefaktem" % os.path.basename(m),
           str(d.get("checksum")))

    print()
    if bledy:
        print("WERYFIKACJA NIEUDANA: %d bledow" % len(bledy))
        return 1
    print("WERYFIKACJA OK: 0 bledow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
