#!/usr/bin/env python3
"""
OFFLINE: gdzie w zrzucie jadra 13.60 leza funkcje budujace pakiety SDBGP.

Zrzut: artifacts/kernel-1360-13.60.bin, baza obrazu kodu 0xffffffffc0c60000.
Konwencja: VA = 0xffffffffc0c60000 + offset_w_pliku (offset obrazu).

Punkt wyjscia (ustalony wczesniej, tools/mp4cmd/README.md):
  0x01040021 SDBGP_READ_MEMORY  -> mov qword [rcx+0x60], 0x01040021    @ obraz+0xc292be
                                   mov qword [rcx+rsi+0x48], 0x01040021 @ obraz+0xc296c8
  0x01010010 SDBGP_GET_CONF     -> mov qword [rcx+0x48], 0x01010010    @ obraz+0xc292a7
  0x01040031 SDBGP_WRITE_MEMORY -> w tym obrazie NIE WYSTEPUJE (skan calego pliku)

Co robi skrypt:
  1. potwierdza, ze pod kazdym z tych offsetow stoi dokladnie ten zapis,
  2. znajduje poczatek funkcji, w ktorej ten zapis lezy: kandydat to offset
     z prologiem (`push rbp; mov rbp,rsp` albo `endbr64`) poprzedzony paddingiem
     NOP / `ret` / `int3` / `ud2`, a rozstrzyga PRZEMIATANIE LINIOWE od kandydata:
     cel musi wypasc dokladnie na granicy rozkazu i tym rozkazem musi byc zapis
     oczekiwanej stalej,
  3. wypisuje 24-bajtowy prolog funkcji (bramka dla payloadu) i miejsca wywolan
     (`call rel32`) tej funkcji,
  4. wypisuje WSZYSTKIE miejsca z ta sama stala w calym obrazie wraz z ich
     funkcjami, zeby bylo widac, ze w jednej funkcji jest ich wiele.

Uruchomienie: python tools/sdbgp/offline-find-builders.py
"""

import struct
import sys
from pathlib import Path

try:
    import capstone
except ImportError:  # pragma: no cover
    print("brak capstone: pip install capstone")
    sys.exit(1)

BAZA = 0xFFFFFFFFC0C60000
KAT = Path(__file__).resolve().parents[2]
ZRZUT = KAT / "artifacts" / "kernel-1360-13.60.bin"

PROLOG_RBP = b"\x55\x48\x89\xe5"
PROLOG_ENDBR = b"\xf3\x0f\x1e\xfa"
PADDING = (0x90, 0xC3, 0xCC, 0xCB)

PROLOG_DLUGOSC = 24
ZASIEG = 0x4000          # jak daleko wstecz szukamy poczatku funkcji
OKNO_DEASM = 0x400       # ile bajtow od poczatku funkcji rozkladamy

# (offset zapisu stalej, stala, operandy do potwierdzenia, opis)
CELE = [
    (0xC292BE, 0x01040021, "[rcx + 0x60]", "SDBGP_READ_MEMORY, pakiet podstawa bufora"),
    (0xC296C8, 0x01040021, "[rcx + rsi + 0x48]", "SDBGP_READ_MEMORY, pakiet doklejany"),
    (0xC292A7, 0x01010010, "[rcx + 0x48]", "SDBGP_GET_CONF, pakiet podstawa bufora"),
]


def wczytaj() -> bytes:
    if not ZRZUT.exists():
        print(f"brak zrzutu {ZRZUT}")
        sys.exit(1)
    return ZRZUT.read_bytes()


def deasm(kod: bytes, poczatek: int, dlugosc: int):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return list(md.disasm(kod[poczatek:poczatek + dlugosc], BAZA + poczatek))


def jest_prolog(kod: bytes, off: int) -> bool:
    return kod[off:off + 4] in (PROLOG_RBP, PROLOG_ENDBR)


def po_koncu_bloku(kod: bytes, off: int) -> bool:
    """Czy przed offsetem jest padding NOP / ret / int3 / ud2 (typowa granica)."""
    if kod[off - 1] in PADDING:
        return True
    return kod[off - 2:off] == b"\x0f\x0b"


def kandydaci_na_start(kod: bytes, cel: int):
    out = []
    for off in range(max(0, cel - ZASIEG), cel):
        if jest_prolog(kod, off) and po_koncu_bloku(kod, off):
            out.append(off)
    return out


def funkcja_dla(kod: bytes, cel: int, stala: int, operandy: str):
    """(start, prolog, rozkazy) funkcji, w ktorej lezy zapis stalej, albo None."""
    for start in sorted(kandydaci_na_start(kod, cel), reverse=True):
        rozkazy = deasm(kod, start, cel - start + 16)
        for r in rozkazy:
            off = r.address - BAZA
            if off < cel:
                continue
            if off > cel:
                break                      # cel nie wypadl na granicy rozkazu
            imm = f"0x{stala:x}"
            if r.mnemonic == "mov" and imm in r.op_str and operandy in r.op_str:
                return start, kod[start:start + PROLOG_DLUGOSC], rozkazy
    return None


def miejsca_wywolan(kod: bytes, start: int):
    out = []
    for i in range(len(kod) - 5):
        if kod[i] != 0xE8:
            continue
        disp = struct.unpack_from("<i", kod, i + 1)[0]
        cel = i + 5 + disp
        if cel == start:
            out.append(i)
    return out


def wszystkie_sites(kod: bytes, stala: int):
    """[(kandydaci_na_start, offset_imm)] dla kazdego wystapienia stalej.

    Bajty przed imm mozna czasem zdekodowac na dwa sposoby, dlatego zwracamy
    wszystkich kandydatow; rozstrzyga ich przynaleznosc do funkcji (patrz main).
    """
    wzor = struct.pack("<I", stala)
    out, i = [], kod.find(wzor)
    while i != -1:
        kandydaci = []
        for dlugosc in (8, 9, 10, 11):
            start = i - (dlugosc - 4)      # imm to ostatnie 4 bajty rozkazu
            if start < 0:
                continue
            rozkazy = deasm(kod, start, dlugosc + 4)
            if not rozkazy:
                continue
            r = rozkazy[0]
            if (len(rozkazy) == 1 and r.mnemonic == "mov"
                    and len(r.bytes) == dlugosc
                    and start + dlugosc == i + 4
                    and f"0x{stala:x}" in r.op_str):
                kandydaci.append(start)
        out.append((kandydaci, i))
        i = kod.find(wzor, i + 1)
    return out


def starty_funkcji(kod: bytes, od: int, do: int):
    """Offsety, od ktorych moze zaczynac sie funkcja (prolog po paddingu/ret/ud2)."""
    return [o for o in range(od, do) if jest_prolog(kod, o) and po_koncu_bloku(kod, o)]


def funkcja_z_tabeli(kod: bytes, cel: int, starty):
    """Najblizszy poprzedzajacy start funkcji, dla ktorego cel wypada na granicy
    rozkazu przy przemiataniu liniowym od tego startu."""
    for start in sorted([s for s in starty if s <= cel], reverse=True):
        if cel - start > 0x10000:
            break
        for r in deasm(kod, start, cel - start + 8):
            off = r.address - BAZA
            if off == cel:
                return start
            if off > cel:
                break
    return None


def main() -> int:
    kod = wczytaj()
    print(f"zrzut : {ZRZUT}")
    print(f"rozmiar: {len(kod)} B ({len(kod):#x}), baza obrazu kodu: {BAZA:#018x}")
    print()

    funkcje = {}
    for cel, stala, operandy, opis in CELE:
        print(f"=== {opis}: stala {stala:#010x} pod obraz+{cel:#x} ===")
        print(f"    bajty: {' '.join(f'{b:02x}' for b in kod[cel:cel + 8])}")
        trafienie = funkcja_dla(kod, cel, stala, operandy)
        if not trafienie:
            print("    [!] nie znalazlem funkcji z tym zapisem na granicy rozkazu")
            print()
            continue
        start, prolog, rozkazy = trafienie
        idx = next(i for i, r in enumerate(rozkazy) if r.address - BAZA == cel)
        print(f"    funkcja: {BAZA + start:#018x}  (obraz+{start:#x}),"
              f" zapis {cel - start} B od poczatku funkcji")
        for r in rozkazy[max(0, idx - 2):idx + 3]:
            znak = ">>" if r.address - BAZA == cel else "  "
            print(f"    {znak} +{r.address - BAZA:#08x}  {r.bytes.hex(' '):<24}"
                  f" {r.mnemonic} {r.op_str}")
        print(f"    24-bajtowy prolog funkcji: {' '.join(f'{b:02x}' for b in prolog)}")
        wolania = miejsca_wywolan(kod, start)
        if wolania:
            print(f"    miejsca wywolania (call rel32): "
                  f"{' '.join(hex(w) for w in wolania)}")
        else:
            print("    miejsca wywolania (call rel32): brak, funkcja wolana posrednio"
                  " (skokiem albo z tabeli)")
        funkcje[cel] = start
        print()

    print("=== wszystkie miejsca stalych SDBGP w obrazie ===")
    starty = starty_funkcji(kod, 0xC28000, 0xC34000)
    print(f"  (poczatki funkcji wykryte w regionie 0xc28000-0xc34000:"
          f" {len(starty)}), pierwszy z nich: {', '.join(hex(s) for s in starty[:6])} ...")
    for stala, nazwa in ((0x01040021, "SDBGP_READ_MEMORY"),
                         (0x01040031, "SDBGP_WRITE_MEMORY"),
                         (0x01010010, "SDBGP_GET_CONF")):
        sites = wszystkie_sites(kod, stala)
        znane = sum(1 for k, _ in sites if k)
        print(f"  {nazwa} ({stala:#010x}): {znane} wystapien jako imm rozkazu mov")
        for kandydaci, imm in sites:
            if not kandydaci:
                print(f"    imm pod +{imm:#08x}: nie jest polem imm rozkazu mov"
                      " (inne uzycie tych bajtow)")
                continue
            start, gdzie = None, None
            for k in kandydaci:
                if 0xC28000 <= k < 0xC34000:
                    f = funkcja_z_tabeli(kod, k, starty)
                    if f is not None:
                        start, gdzie = k, f
                        break
            if start is None:
                start = kandydaci[0]
                t = funkcja_dla(kod, start, stala, "")
                gdzie = t[0] if t else None
            opis = f"funkcja obraz+{gdzie:#x}" if gdzie is not None else "funkcja nieustalona"
            print(f"    obraz+{start:#08x} (imm pod +{imm:#x})  {opis}"
                  + (f"  [kandydaci: {', '.join(hex(k) for k in kandydaci)}]"
                     if len(kandydaci) > 1 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
