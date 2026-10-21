# writeprobe: matryca prob zapisu do pamieci A53

Payload dla systemu Sony, ktory sprawdza systematycznie, czy procesor A53
przyjmie zapis pamieci przez skrzynke coredump urzadzenia MP4 (protokol SDBGP).
Poprzednie podejscie sprawdzalo **jeden adres i jeden typ pamieci**, wiec nie
pozwalalo odroznic "A53 nie zna opcodu zapisu" od "A53 nie przyjmuje tego typu,
dostepu albo tego adresu". Ten payload robi 48 prob: 6 adresow x 4 typy pamieci
x 2 typy dostepu.

Kazda proba: odczyt 32 B, zapis 16 B wzorca unikalnego dla proby, odczekanie
120 ms, odczyt kontrolny 32 B, werdykt, a przy jakiejkolwiek zmianie pamieci
natychmiastowe przywrocenie oryginalu i odczyt potwierdzajacy.

## Budowa

```
env PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make
```

Test macierzy na komputerze (bez konsoli):

```
make test
```

Weryfikacja statyczna artefaktu (naglowek ELF, stale transportu, adresy macierzy,
kolejnosc adresow, kotwice obrazu A53 kontra `artifacts/a53-obraz-odtworzony.bin`,
bramki bezpieczenstwa w zrodle):

```
python tools/writeprobe/verify.py
```

## Pliki

| plik | rola |
|---|---|
| `writeprobe.c` | payload: transport SDBGP, bramki, przebieg macierzy, przywracanie, log |
| `writeprobe_core.c`, `writeprobe_core.h` | macierz (adresy, typy, dostepy), wzorzec proby, osad proby |
| `test_core.c` | test macierzy na komputerze (`make test`) |
| `verify.py` | weryfikacja statyczna artefaktu i zrodel |
| `Makefile` | budowa payloadu i test hosta |

## Skad transport

Sekwencja skrzynki (pola stanu, flag, bufora, IOMMU i rozmiaru, rejestry
`BAR2+0xf6000` do `+0xfa000`, stale DECI5S i typy SDBGP) jest przejeta bez zmian
z `tools/mboxwrite` i `tools/pprwatch`, czyli z narzedzi, ktorych odczyty sa
potwierdzone pomiarami na tej konsoli (`artifacts/pprwatch-2026-10-15c.txt`).
Nowe sa wylacznie: osie macierzy (adres, `mem_type`, `access`), odczyt odpowiedzi
z opisem typu polecenia, werdykt, przywracanie oryginalu i bramki.

## Warunki uruchomienia

1. Firmware 13.60 (payload sprawdza wersje i odmawia zapisu na innym).
2. Odczyt i zapis pamieci jadra, czyli kstuff (tak jak `tools/mboxwrite`).
3. **Bez latki PPR.** Payload nie potrzebuje zalatanego obrazu A53; sam stawia
   dwie jaskinie tylko jako adresy probne i niczego tam nie zostawia.

Log: `/data/writeprobe.txt`, kazda linia z `fflush` i `fsync`.
Stop: plik `/data/writeprobe.stop`. Budzet: 600 s.

Jak czytac log i co jest dowodem: `notes/WRITEPROBE-MACIERZ.md`.
