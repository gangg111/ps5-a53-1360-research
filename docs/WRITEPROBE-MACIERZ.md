# writeprobe: matryca prob zapisu do pamieci A53

Notatka do payloadu `artifacts/writeprobe.elf`, ktory sprawdza systematycznie,
czy procesor A53 przyjmie zapis pamieci przez skrzynke coredump urzadzenia MP4.
Data: 19.10.2026. Firmware: 13.60 (PS5 Pro).

## 0. Wynik w czterech zdaniach

1. Poprzedni pomiar sprawdzal **jeden adres i jeden typ pamieci**, wiec nie
   rozstrzygal, czy A53 odrzuca opcode zapisu `0x01040031`, typ pamieci, typ
   dostepu, czy sam adres.
2. `writeprobe` wykonuje 48 prob: 6 adresow x 4 typy pamieci x 2 typy dostepu,
   w kolejnosci od najbezpieczniejszych, kazda z odczytem przed, zapisem 16 B,
   odczekaniem, odczytem po i natychmiastowym przywroceniem oryginalu.
3. Payload nie potrzebuje latki PPR: A53 ma byc nietknieta poza probami, a kazda
   proba jest wycofywana i potwierdzana odczytem.
4. Werdykt jest jeden i twardy: zapis jest mozliwy tylko wtedy, gdy **bajty po
   zapisie sa rowne wzorcowi**, a odczyt kontrolny jest wiarygodny. Sama
   odpowiedz transportu nic nie znaczy.

## 1. Po co matryca, czyli czego nie wiedzielismy

Stan wiedzy przed pomiarem (`notes/KSTUFF-PPR-V4.md`, rozdzial 2 i 3):

* pakiet zapisu z opcodem `0x01040031` jest wysylany, transport potwierdza
  ukonczenie zrzutu, pamiec pod adresem proby sie **nie zmienia**, a w odpowiedzi
  A53 nie ma wyniku zapisu (`0x02040031`),
* skan obrazu jadra 13.60 (64 MB) i dziewieciu regionow pamieci A53 dal **zero**
  wystapien tego opcodu, wiec firmware A53 prawdopodobnie go nie zna,
* ale to nie bylo rozstrzygniete: proba dotyczyla **jednego** adresu
  (`0x61F00`) i **jednego** typu pamieci (`0x020000`), a pole dostepu zmieniano
  tylko w jednym przebiegu (`tools/mboxwrite`, `artifacts/mbox_write-2026-10-15*`).

Nie bylo wiec wiadomo, czy A53 nie zna opcodu, czy odrzuca ten typ pamieci, ten
typ dostepu albo ten adres. Dopiero przebieg po **calej siatce** tych trzech osi
pozwala powiedziec "nie przyjmuje nigdzie i nigdy" albo wskazac kombinacje, ktora
dziala.

## 2. Macierz prob

Osie (dokladne wartosci w `tools/writeprobe/writeprobe_core.c`):

| os | wartosci |
|---|---|
| adres (PA) | `0x5E000`, `0x60000`, `0x61F00`, `0x61F50`, `0x28000`, `0x80000` |
| typ pamieci (`mem_type`) | `0x020000`, `0x020100`, `0x010000`, `0x000000` |
| typ dostepu (`access`) | 4, 6 |

Uzasadnienie adresow i kolejnosci (kolejnosc jest czescia zabezpieczenia, payload
nie moze jej zmienic bez zmiany zrodla):

| adres | co tam jest | dlaczego w tej kolejnosci |
|---|---|---|
| `0x5E000` | puste wypelnienie za kodem obrazu (plik konczy sie kolo `0x5DD00`) | najbezpieczniejszy: zadnej instrukcji, zadnej stalej |
| `0x60000` | to samo wypelnienie, blizej konca segmentu io (`0x62000`) | drugi najbezpieczniejszy |
| `0x61F00` | jaskinia runtime latki PPR | potrzebna do latki, ale to nadal wypelnienie |
| `0x61F50` | jaskinia plaintext latki PPR | jak wyzej |
| `0x28000` | naglowek i tablica deskryptorow **zywego** obrazu A53 | najniebezpieczniejszy z adresow obrazu |
| `0x80000` | poczatek trzeciego banku SRAM (okno konczy sie na `0xBFFFF`) | nie wiadomo, co A53 tam trzyma, wiec ostatni |

Typy pamieci:

* `0x020000` jest tym, ktorym idzie zapis w latce PPR (`MEM_TYPE_PA_TO_EL3`
  w `artifacts/kstuff-a53-src/ppr/a53_transport.c`), wiec to punkt odniesienia,
* `0x020100` jest sprawdzony pomiarem **przy odczycie**: tym slowem czyta
  `tools/pprwatch`, `tools/a53layout` i `tools/mboxwrite`, i pod `0x28000`
  zwraca prawdziwy naglowek obrazu (`artifacts/pprwatch-2026-10-15c.txt`),
* `0x010000` i `0x000000` to sasiednie wartosci z tej samej rodziny, zeby
  sprawdzic, czy A53 rozroznia typ po pelnym slowie, czy po jego czesci.

Typy dostepu: 4 (32-bit) i 6 (wartosc uzywana przy zapisie jaskini 160-bajtowej,
a takze wybierana przez `access_size()` w transporcie referencyjnym dla adresow
wyrownanych). Wartosc 1 byla juz zmierzona wczesniej na `0x61F00`
(`artifacts/mbox_write-2026-10-15.txt`, trzy proby: 1, 4, 6), dlatego macierz
doklada 4 i 6, a nie powtarza 1.

Numeracja prob w logu (numer jest tez zapisany w bajcie 2 wzorca):

| nr | adres | mem_type | access |
|---|---|---|---|
| 01 | 0x5E000 | 0x020000 | 4 |
| 02 | 0x5E000 | 0x020000 | 6 |
| 03 | 0x5E000 | 0x020100 | 4 |
| 04 | 0x5E000 | 0x020100 | 6 |
| 05 | 0x5E000 | 0x010000 | 4 |
| 06 | 0x5E000 | 0x010000 | 6 |
| 07 | 0x5E000 | 0x000000 | 4 |
| 08 | 0x5E000 | 0x000000 | 6 |
| 09 | 0x60000 | 0x020000 | 4 |
| 10 | 0x60000 | 0x020000 | 6 |
| 11 | 0x60000 | 0x020100 | 4 |
| 12 | 0x60000 | 0x020100 | 6 |
| 13 | 0x60000 | 0x010000 | 4 |
| 14 | 0x60000 | 0x010000 | 6 |
| 15 | 0x60000 | 0x000000 | 4 |
| 16 | 0x60000 | 0x000000 | 6 |
| 17 | 0x61F00 | 0x020000 | 4 |
| 18 | 0x61F00 | 0x020000 | 6 |
| 19 | 0x61F00 | 0x020100 | 4 |
| 20 | 0x61F00 | 0x020100 | 6 |
| 21 | 0x61F00 | 0x010000 | 4 |
| 22 | 0x61F00 | 0x010000 | 6 |
| 23 | 0x61F00 | 0x000000 | 4 |
| 24 | 0x61F00 | 0x000000 | 6 |
| 25 | 0x61F50 | 0x020000 | 4 |
| 26 | 0x61F50 | 0x020000 | 6 |
| 27 | 0x61F50 | 0x020100 | 4 |
| 28 | 0x61F50 | 0x020100 | 6 |
| 29 | 0x61F50 | 0x010000 | 4 |
| 30 | 0x61F50 | 0x010000 | 6 |
| 31 | 0x61F50 | 0x000000 | 4 |
| 32 | 0x61F50 | 0x000000 | 6 |
| 33 | 0x28000 | 0x020000 | 4 |
| 34 | 0x28000 | 0x020000 | 6 |
| 35 | 0x28000 | 0x020100 | 4 |
| 36 | 0x28000 | 0x020100 | 6 |
| 37 | 0x28000 | 0x010000 | 4 |
| 38 | 0x28000 | 0x010000 | 6 |
| 39 | 0x28000 | 0x000000 | 4 |
| 40 | 0x28000 | 0x000000 | 6 |
| 41 | 0x80000 | 0x020000 | 4 |
| 42 | 0x80000 | 0x020000 | 6 |
| 43 | 0x80000 | 0x020100 | 4 |
| 44 | 0x80000 | 0x020100 | 6 |
| 45 | 0x80000 | 0x010000 | 4 |
| 46 | 0x80000 | 0x010000 | 6 |
| 47 | 0x80000 | 0x000000 | 4 |
| 48 | 0x80000 | 0x000000 | 6 |

Ktore proby sa najwazniejsze:

| proba | co powtarza | dlaczego wazna |
|---|---|---|
| 01 | `0x5E000`, `0x020000`, 4 | pierwszy werdykt calego przebiegu, na najbezpieczniejszym adresie |
| 18 | `0x61F00`, `0x020000`, 6 | dokladnie ta kombinacja, ktora wysyla latka PPR pod jaskinie runtime |
| 26 | `0x61F50`, `0x020000`, 6 | dokladnie ten zapis, od ktorego zatrzymala sie latka PPR w v3 i v4 |

Jesli 18 i 26 wypadna tak samo jak pomiar z 15.10.2026 (`artifacts/mbox_write-2026-10-15*.txt`),
to znaczy, ze powtorzenie daje ten sam wynik i wina nie lezy w przebiegu, tylko w mechanizmie.
Jesli ktoras z nich przyjmie zapis, to zmienia sie plan latki: szesc miejsc i dwie jaskinie
da sie wtedy zapisac, a punkt 2 rozdzialu 10 mowi, co dalej.

## 3. Jedna proba krok po kroku

1. **Odczyt 32 B** pod adresem proby, typ pamieci `0x020100`, dostep 1 (droga
   sprawdzona pomiarem). Odczyt jest wiarygodny tylko wtedy, gdy w odpowiedzi
   jest naglowek wyniku z zadanym adresem, `status` 0 i `przeslane` rowne 32.
   Bez tego zapis **nie jest wysylany**, bo nie byloby czym przywrocic oryginalu.
2. **Zapis 16 B** wzorca unikalnego dla proby. Wzorzec:
   `'W' 'P' <nr proby> <access> <mem_type:4 B> <adres:4 B> 'W' 'P' <xor> 0xAA`.
   Dzieki temu z hexa w logu (albo ze zrzutu pamieci po restarcie) da sie
   odczytac, ktora proba zostawila te bajty.
3. **Odczekanie 120 ms**, zeby A53 miala czas wykonac polecenie.
4. **Odczyt 32 B** po zapisie, tymi samymi parametrami co w kroku 1.
5. **Werdykt** z 16 bajtow:
   * `po == wzorzec` -> **zapis przyjety**,
   * `po == przed` -> **zapis odrzucony** (pamiec bez zmian, odczyt wiarygodny),
   * `po` rozne od obu -> **pamiec zmieniona inaczej niz wzorzec**,
   * brak wiarygodnego odczytu -> **brak werdyktu**.
6. **Przywrocenie oryginalu** (tylko gdy pamiec sie zmienila): zapis 16 B stanu
   sprzed proby tymi samymi parametrami, potem odczyt 32 B i porownanie ze stanem
   sprzed proby. Gdy roznily sie tez bajty 16 do 31, przywracane jest 32 B.
   Nigdy nie zapisujemy wiecej niz 32 B i nigdy nie jest to nowa tresc, tylko
   odczytany wczesniej oryginal.

Rozmiary: pakiet odczytu 120 B, pakiet zapisu 16 B to 144 B (32 B to 160 B),
odpowiedz A53 jest czytana od offsetu rownego rozmiarowi zadania.

## 4. Bramki bezpieczenstwa i warunki przerwania

Payload nie wysyla zadnego zapisu, dopoki nie przejda bramki:

1. **Firmware 13.60.** Inna wersja konczy sie odmowa (`ODMOWA: to nie firmware 13.60`).
2. **Skrzynka coredump gotowa.** Musza byc znalezione pola stanu, flag, bufora,
   IOMMU i rozmiaru; inaczej `ODMOWA: skrzynka coredump niegotowa, zero zapisow`.
3. **Transport czyta prawdziwa pamiec A53.** Piec kotwic 16-bajtowych
   (`0x28000` naglowek obrazu, `0x57AA8` helper, `0x5B964` dispatch_native,
   `0x5BC20` plaintext_direct, `0x5C7E8` common_return). Wymagany jest naglowek
   `0x28000` i razem co najmniej 3 kotwice. Sam naglowek nie wystarcza, bo przy
   zwracaniu stalej tresci bufora kazdy adres daje ten sam blok. Wszystkie piec
   nie sa wymagane, bo cztery pochodza z obrazu odtworzonego ze zrzutow, a tylko
   `0x28000` jest potwierdzony odczytem na konsoli.
4. **Brak wiarygodnego odczytu przed proba = brak zapisu.**
5. **Pominiecie `0x28000`, gdy zapis dziala.** Jesli ktoras z wczesniejszych prob
   przyjmie zapis, proba pod zywym obrazem jest pomijana: odpowiedz jest juz
   znana, a nie ma po co dotykac kodu.
6. **Przerwanie macierzy** po dwoch transakcjach pod rzad bez potwierdzenia A53
   lub po nieudanym przywroceniu. Log konczy sie wtedy linia `PRZERWANIE`.
7. **Budzet 600 s i plik stop** `/data/writeprobe.stop`, sprawdzane przed kazda
   proba.

Kontrola po calym przebiegu: ponowne sprawdzenie pieciu kotwic oraz porownanie
szesciu adresow macierzy ze stanem pierwotnym (odczytanym przed pierwszym
zapisem). To jest dowod, ze po przebiegu nic nie zostalo zmienione.

## 5. Jak czytac log `/data/writeprobe.txt`

Log jest zapisywany linia po linii z `fflush` i `fsync`, wiec przezywa zawieszenie
konsoli. Wazniejsze linie ida dodatkowo do klog z prefiksem `[writeprobe]`.

Poczatek:

```
writeprobe start: matryca 48 prob zapisu do pamieci A53
wersja systemu 0x13600007, budzet 600 s, stop plikiem /data/writeprobe.stop
wymagania: odczyt i zapis pamieci jadra (kstuff); latka PPR nie jest potrzebna
kontekst 0xffff..., BAR2 0xffff...
skrzynka gotowa: stan 0x..., flagi 0x..., bufor 0x..., iommu 0x70000000, rozmiar 0x200000
kotwice obrazu A53 (na poczatku):
  0x028000 naglowek obrazu   : zgodna
  ...
bramka odczytu: naglowek obrazu zgodny, kotwic zgodnych 5 z 5
```

Blok jednej proby (przyklad ukladu, nie pomiar):

```
-- proba 01/48: adres 0x5e000 (puste wypelnienie za kodem), mem_type 0x020000, access 4 --
  przed (32 B): 06 28 43 b5 ...
   wzorzec (16 B): 57 50 00 04 00 00 02 00 00 e0 05 00 57 50 .. aa
    pakiet zapisu: 144 B, typ 0x01040031, mem_type 0x020000, access 4, addr 0x5e000, 16 B danych
    transport: kod 0 (ukonczenie przyszlo), 12 ms
    odpowiedz: magic 0x73354450, rozmiar 0x60, src 0x80ff0201, dst 0x80ff0180, ...
    polecenie 0: self 0x20, total 0x20, typ 0x........, nr 0
    odpowiedz 0x60 B: 50 44 35 73 ...
    brak wyniku zapisu w odpowiedzi (A53 nie odeslala typu 0x02040031)
  po    (32 B): 06 28 43 b5 ...
   WERDYKT: zapis odrzucony (pamiec bez zmian, odczyt wiarygodny)
```

Co znacza poszczegolne pola:

| pole | znaczenie |
|---|---|
| `transport: kod` | 0 = przyszlo ukonczenie zrzutu, -2 = nie przyszlo w 3 s, -1 = blad dostepu do jadra |
| `odpowiedz: magic ...` | naglowek odpowiedzi A53: magic `0x73354450`, kierunek `src 0x80ff0201`, numer zlecenia |
| `polecenie N: ... typ` | typ polecenia w odpowiedzi; szukamy `0x02040031` (wynik zapisu) |
| `odpowiedz 0x60 B` | surowe 96 bajtow odpowiedzi, zeby uklad dalo sie sprawdzic po fakcie |
| `przed` / `po` | 32 bajty pamieci A53 przed i po probie |
| `przywracam` / `przywrocone` | przywracanie oryginalu i jego potwierdzenie odczytem |

Konstrukcje rozstrzygajace (dokladne napisy do szukania w logu):

| napis | znaczenie |
|---|---|
| `WERDYKT: ZAPIS PRZYJETY` | zapis wszedl: bajty po zapisie rowne wzorcowi |
| `WERDYKT: zapis odrzucony` | pamiec bez zmian, odczyt wiarygodny |
| `WERDYKT: pamiec zmieniona inaczej niz wzorzec` | cos sie stalo, ale nie zapis wzorca |
| `ODCZYT PRZED NIEUDANY` | proba pominieta, zapisu nie bylo |
| `BRAK WIARYGODNEGO ODCZYTU PO ZAPISIE` | nie wiadomo, czy zapis wszedl; oryginal przywrocony na slepo, macierz przerwana |
| `PRZYWRACANIE NIEPELNE` | przywrocenie sie nie potwierdzilo, macierz przerwana |
| `PRZERWANIE: ...` | macierz przerwana (sygnal, plik stop, budzet, brak potwierdzen) |

Koniec logu to tabela 48 prob (numer, adres, mem_type, access, kod transportu,
czy jest odpowiedz, typ polecenia w odpowiedzi, czy jest wynik zapisu, werdykt)
i podsumowanie z linia `[wniosek]`.

## 6. Co jest dowodem, ze zapis jest mozliwy

Dowod jest jeden i musi byc spelniony w calosci:

1. w linii `po (32 B)` **pierwsze 16 bajtow jest rowne wzorcowi proby**, a wzorzec
   niesie numer proby i jej parametry, wiec nie da sie go pomylic z przypadkowa
   trescia,
2. odczyt po zapisie jest wiarygodny: naglowek wyniku z zadanym adresem, `status`
   0, `przeslane` rowne 32 (czyli A53 naprawde oddala te bajty spod tego adresu),
3. oryginal zostal przywrocony i potwierdzony odczytem (`przywrocone: 32 B zgodne
   ze stanem przed proba`),
4. na koncu logu: `kotwice ... 5 z 5 zgodnych` i `stan koncowy adresow macierzy:
   6 z 6 zgodnych ze stanem pierwotnym`,
5. dodatkowo, choc nie jest warunkiem koniecznym: w odpowiedzi jest typ
   `0x02040031` (wynik zapisu). Jesli bajty sie zmienily, a tego typu nie ma,
   zapis i tak jest dowiedziony trescia pamieci, ale brak wyniku jest osobnym
   ustaleniem o protokole.

Co **nie** jest dowodem (i dlatego poprzedni pomiar nie wystarczal):

* `transport: kod 0`, bo transport potwierdza tylko przyjecie zlecenia,
* magic naglowka odpowiedzi, bo A53 odpowiada nawet na nieznane polecenie,
* echo adresu w naglowku wyniku, bo urzadzenie przepisuje adres z zadania,
* brak zmiany pamieci pod jednym adresem przy jednym typie, bo to nie rozstrzyga
  o pozostalych kombinacjach.

## 7. Uruchomienie na konsoli

1. Firmware 13.60, kstuff zaladowany (odczyt i zapis pamieci jadra), Payload
   Manager i ftpsrv uruchomione. **Latka PPR nie jest potrzebna.**
2. Uruchom `writeprobe.elf` z menedzera (`artifacts/pldmgr_writeprobe.json`).
3. Payload sam konczy po 48 probach albo po 600 s. Przebieg to okolo 15 do 60 s
   (48 prob po trzy transakcje plus 120 ms odczekania na probe).
4. Przerwanie: utworz plik `/data/writeprobe.stop` (sprawdzany przed kazda proba).
5. Log: `/data/writeprobe.txt`. Podglad: `tools/ftp-get.ps1` albo ftpsrv.

Kolejnosc ma znaczenie tylko w obrebie payloadu (adresy od najbezpieczniejszych);
payload nie patchuje jadra, nie otwiera wezlow poza `/data` i nie zmienia nosnika.

## 8. Po zawieszeniu konsoli: jak rozpoznac probe, ktora zaszkodzila

1. Po restarcie odczytaj `/data/writeprobe.txt`. Log jest fsyncowany po kazdej
   linii, wiec ostatni blok w pliku to blok proby, przy ktorej konsola stanela.
2. Numer proby jest w naglowku bloku (`-- proba NN/48 ...`) i w bajcie 2 wzorca,
   wiec z hexa `wzorzec (16 B)` od razu wiadomo, jakie byly parametry proby.
3. Te same linie sa w klog z prefiksem `[writeprobe]` (linie werdyktow, bramek
   i przerwan), wiec drugie zrodlo to zrzut klog po restarcie.
4. Jesli ostatnia linia to `przywracam ...`, a nie ma po niej `przywrocone`,
   to znak, ze konsola stanela w trakcie przywracania. Wtedy oryginal jest
   w linii `przed (32 B)` tego samego bloku i mozna go porownac z odczytem po
   restarcie (payload nie jest potrzebny do odczytu, wystarczy `tools/pprwatch`
   albo kolejne uruchomienie `writeprobe`, ktore najpierw wypisuje stan pierwotny).
5. Brak linii `-- proba ...` po `=== macierz prob ===` oznacza, ze konsola stanela
   przed pierwsza proba, czyli przy odczycie bramki albo przy odczycie stanu
   pierwotnego. To nie jest wina zapisu, bo zaden zapis nie zostal wyslany.

## 9. Weryfikacja bez konsoli

| co | wynik |
|---|---|
| `make -C tools/writeprobe test` (macierz, wzorzec, osad, kolejnosc adresow) | 672 sprawdzenia, 0 bledow, `TEST OK` |
| `python tools/writeprobe/verify.py` | `WERYFIKACJA OK: 0 bledow` |
| artefakt | `artifacts/writeprobe.elf`, 193 632 B, sha256 `16232d8c8a88c89f967df485ffdd436c7f88b7ce90b088331b96fbbc4dc644e4` |
| kotwice w zrodle kontra `artifacts/a53-obraz-odtworzony.bin` | 5 z 5 zgodnych (verify.py czyta obraz i porownuje 16 B pod kazdym adresem) |

Czego weryfikacja offline **nie** sprawdza: czy skrzynka na tej konsoli odpowiada
tak, jak zaklada parser. To rozstrzyga dopiero przebieg: log zawiera surowe
0x60 B kazdej odpowiedzi na zapis i pelny naglowek kazdego odczytu, wiec ewentualna
rozbieznosc ukladu jest widoczna w logu bez zgadywania.

## 10. Co wynika z kazdego z czterech mozliwych wynikow

| wynik | wniosek | nastepny krok |
|---|---|---|
| 48 z 48 `zapis odrzucony` | A53 nie przyjmuje zapisu zadnym z 48 zestawow: adres, typ pamieci i typ dostepu nie maja znaczenia, brakuje opcodu | droga zapisu `0x01040031` jest zamknieta dla 13.60; wrocic do rozdzialu 3.3 `notes/KSTUFF-PPR-V4.md` (podmiana obrazu przed zaladowaniem albo nosnik) |
| co najmniej jedna `ZAPIS PRZYJETY` | zapis jest mozliwy i wiadomo dokladnie, z jaka kombinacja | powtorzyc te kombinacje dla pelnych 160 B jaskini plaintext i 76 B runtime, potem wpiac ja do transportu w `ppr_patch.c` zamiast `MEM_TYPE_PA_TO_EL3` z `write_memory` |
| `pamiec zmieniona inaczej niz wzorzec` | A53 cos zapisuje, ale nie to, o co prosimy (przesuniecie, inny rozmiar, inny typ) | porownac bajty `przed` i `po` w tym bloku: roznica mowi, ile i czego A53 zapisala |
| `brak wiarygodnego odczytu` | transport niestabilny, macierz niewazna | powtorzyc przebieg po ustabilizowaniu skrzynki; nie wyciagac wnioskow o zapisie |

## 11. Czego ten pomiar nie rozstrzyga

1. **Innych opcodow zapisu.** Macierz zmienia adres, typ pamieci i typ dostepu,
   ale nie opcode: wszystkie 48 prob to `0x01040031`. Inne typy zapisu
   (`0x02040031`, `0x01050031`, `0x02050031` i podobne) nie byly probowane,
   bo nie wystepuja ani w jadrze, ani w firmware A53, wiec byly by zgadywaniem.
2. **Pol `pid`, `tid`, `flags`** pakietu zapisu: sa stale (0), tak jak w
   `tools/mboxwrite` i w transporcie referencyjnym.
3. **Wiekszych zapisow.** Payload nie zapisuje wiecej niz 16 B wzorca, wiec nie
   sprawdza, czy A53 przyjmie 160 B jaskini jednym pakietem. To celowe: przy
   nieznanym mechanizmie mniejszy zapis mniej psuje.
4. **Dostepu 1.** Wartosc 1 byla zmierzona wczesniej na `0x61F00` bez zmiany
   pamieci (`artifacts/mbox_write-2026-10-15.txt`), wiec macierz jej nie powtarza.
   Gdyby wszystkie 48 prob wypadly jako odrzucone, a ktos chcial domknac sprawe,
   dopisanie wiersza z `access` 1 to jedna linia w `writeprobe_core.c`.
5. **Semantyki typu w odpowiedzi.** Payload loguje typ i surowe bajty odpowiedzi,
   ale nie twierdzi, ze wie, co A53 chciala przez ten typ powiedziec.

## 12. Pliki

| plik | rola |
|---|---|
| `tools/writeprobe/writeprobe.c` | payload: transport SDBGP, bramki, przebieg macierzy, przywracanie, log |
| `tools/writeprobe/writeprobe_core.c`, `.h` | macierz, wzorzec proby, osad proby (bez zaleznosci od jadra) |
| `tools/writeprobe/test_core.c` | test macierzy na komputerze |
| `tools/writeprobe/verify.py` | weryfikacja statyczna artefaktu i zrodel |
| `tools/writeprobe/README.md` | budowa, warunki uruchomienia, podzial plikow |
| `artifacts/writeprobe.elf` | payload, 193 632 B, sha256 `16232d...c644e4` |
| `artifacts/pldmgr_writeprobe.json` | opis dla Payload Managera |
| `artifacts/writeprobe.elf.json` | manifest artefaktu (ta sama tresc opisu, inny format) |
