# kstuff 13.60 z przeniesiona jaskinia plaintext, build v5

Notatka z przebudowy kstuff dla firmware 13.60 (PS5 Pro): modul PPR, ktory w v3
i v4 zatrzymal sie na zapisie jaskin do pamieci A53. Data: 19.10.2026.
Artefakt: `artifacts/kstuff-1360-ppr-v5.elf`.

## 0. Wynik w szesciu zdaniach

1. Zapis jaskin robi `ppr_install_caves_with_retry` (`ppr_patch.c`), ktora wola
   `ppr_write_pair_checked` i dalej `ppr_write_checked` oraz `write_memory`
   w `a53_transport.c`, z opcodem SDBGP **0x01040031**.
2. Zdanie ze zlecenia, ze jaskinia runtime pod PA 0x61F00 "nie zglasza bledu",
   jest nieprawdziwe: `ppr_write_pair_checked` zapisuje **najpierw jaskinie
   plaintext** i po jej niepowodzeniu wraca, wiec zapis pod 0x61F00 nigdy nie
   byl nawet wyslany. Log to potwierdza brakiem linii o jaskini runtime.
3. Zaden z czterech sprawdzonych adresow w oknie transportu nie przyjal
   zapisu (0x61F00, 0x61F50, 0xC3000, 0x200000), przy zadnej wartosci pola
   dostepu (1, 4, 6). Adres, wyrownanie i rozmiar nie tlumacza awarii.
4. Co tlumaczy: firmware A53 na 13.60 **nie ma polecenia zapisu pamieci**.
   Stala 0x01040031 nie wystepuje ani razu w zrzucie jadra 64 MB, ani w
   dziewieciu zrzuconych regionach pamieci A53, a odpowiedz A53 na pakiet
   zapisu nie zawiera wyniku zapisu (0x02040031).
5. v5 przenosi jaskinie **danych** (plaintext, 160 B) z PA 0x61F50 do
   nieuzywanego wypelnienia pod PA 0x5E000, w osobna strone 4 kB. Jaskinia
   **kodu** (runtime, 76 B) zostaje pod PA 0x61F00 i pozostaje wykonywalna, jej
   slowa i galezie sa identyczne jak w v4.
6. v5 doklada dwie proby zapisu (nowy i stary adres) oraz zapis porcjami po
   32 B, wiec **jeden przebieg na konsoli** rozstrzyga, czy zapis dziala pod
   nowym adresem, czy nie dziala nigdzie. Przeniesienie samo w sobie nie
   naprawi zapisu, ktorego firmware nie ma.

## 1. Gdzie jest zapis jaskin: plik, funkcja, linie, opcode, adres, readback

Sciezka wywolania (numery linii z drzewa v5, po `przygotuj-zrodla-v5.py`):

| krok | plik | funkcja | linie |
|---|---|---|---|
| 1 | `ppr_patch.c` | `ppr_patch_run_target`, galez `if (before.native && ppr_install_caves_with_retry(...))` | 1597 |
| 2 | `ppr_patch.c` | `ppr_install_caves_with_retry` (dwie proby, potem petla prob) | 1338 do 1401 |
| 3 | `ppr_patch.c` | `ppr_write_pair_checked` (jaskinia plaintext jako pierwsza, potem runtime) | 1228 |
| 4 | `ppr_patch.c` | `ppr_write_checked` (zapis, odczyt kontrolny, porcjowanie) | 1019 |
| 5 | `ppr_patch.c` | `ppr_write_chunked` (porcje po 32 B) | 982 |
| 6 | `ppr_patch.c` | `ppr_write` → `ctx->transport->write` | 385 |
| 7 | `a53_transport.c` | `callback_write` → `write_memory` | 1362, 986 |
| 8 | `a53_transport.c` | `send_packet` (skrzynka coredump, `BAR2+0xf6000`) | 668 |

Polecenie, ktore naprawde leci do A53 (funkcja `write_memory`, linia 986):

```
initialize_outer(header, total, 1);   /* magic 0x73354450, self 0x28,
                                         src 0x80ff0180, dst 0x80ff0201,
                                         protocol 0x20000201, dcmp 0x18,
                                         code = total - 0x28, num_commands 1 */
packet->command.self  = 0x28;
packet->command.total = 0x28 + 0x18 + round_up_8(size);
packet->command.type  = SDBGP_WRITE_MEMORY;      /* 0x01040031 */
packet->command.args  = 1;                       /* n_args */
packet->argument.self_size   = 0x18;
packet->argument.access_size = access_size(address, size);
packet->argument.mem_type    = MEM_TYPE_PA_TO_EL3;  /* 0x020000 */
packet->argument.addr        = address;             /* adres fizyczny A53 */
packet->argument.size        = size;
memcpy(raw + 0x80, source, size);                   /* dane wprost w pakiecie */
```

Konkretne wartosci dla jaskin (do policzenia z powyzszych wzorow, potwierdzone
w klog przy kazdym zapisie):

| zapis | adres | rozmiar | access_size | pakiet | dane pod offsetem |
|---|---|---|---|---|---|
| jaskinia plaintext (v5) | PA 0x5E000 | 160 B | 6 | 288 B | 0x80 |
| jaskinia plaintext (v2 do v4) | PA 0x61F50 | 160 B | 6 | 288 B | 0x80 |
| jaskinia runtime | PA 0x61F00 | 76 B | 6 | 208 B | 0x80 |
| miejsce latki | VA - 0x4E00000 | 4 B | 6 | 136 B | 0x80 |
| proba nowego adresu | PA 0x5E000 | 160 B | 6 | 288 B | 0x80 |
| proba starego adresu | PA 0x61F00 | 32 B | 6 | 160 B | 0x80 |

`access_size()` (`a53_transport.c`, linia 385) to nie rozmiar porcji, a kod
wyrownania: adres i rozmiar razem, od bitu 0 do bitu 3. Dla obu jaskin wychodzi
**6**, dokladnie tyle samo, co dla 16-bajtowych odczytow kotwic, ktore dzialaja.

Readback jest scisly i dotyczy **tego samego adresu i rozmiaru**:

1. `ppr_write_checked` (1019) robi `ppr_write(ctx, pa, bytes, size)`, a zaraz
   potem `ppr_read(ctx, pa, verify, size)` na tej samej `pa`,
2. `ppr_read` (378) wymaga `transport->read(...) == (int)size`, inaczej zwraca -1,
3. `read_memory` (887) buduje pakiet odczytu typu 0x01040021, a odpowiedz
   przechodzi `parse_read_response`, ktory sprawdza typ wyniku (0x02040021),
   numer zlecenia, **adres i rozmiar z odpowiedzi** oraz status,
4. porownanie to `memcmp(verify, bytes, size)`, bajt w bajt.

Zapis uznaje sie za udany tylko wtedy, gdy odczyt spod tego samego adresu zwraca
dokladnie zadane bajty. Gdy tak nie jest, v5 loguje kod zapisu, kod odczytu,
hex zadanych i hex odczytanych bajtow, a nastepnie ponawia zapis porcjami po
32 B, kazda porcja z osobnym odczytem kontrolnym.

## 2. Dlaczego zapis pod 0x61F50 zawodzi, a 0x61F00 "nie zglasza bledu"

### 2.1 Kolejnosc zapisu: 0x61F00 nigdy nie byl probowany

Kod w `ppr_write_pair_checked` (1228) w trybie konserwatywnym, ktorym idzie v5,
wyglada tak:

```c
if (ppr_write_checked(ctx, pa0, bytes0, size0, name0) != 0)
    return -1;
return ppr_write_checked(ctx, pa1, bytes1, size1, name1);
```

gdzie `pa0` to jaskinia plaintext, a `pa1` to jaskinia runtime. Pierwszy
nieudany zapis konczy funkcje, wiec drugi nie jest wysylany. W klogu z konsoli
widac dokladnie to: sa dwie linie o jaskini plaintext pod 0x61f50, a **zadnej**
linii o jaskini runtime pod 0x61f00. Brak bledu nie znaczy sukcesu, znaczy brak
proby. v5 mowi to wprost linia `[*] kolejnosc: najpierw jaskinia plaintext`.

Warto tez odnotowac, ze wklejony wycinek klogu ma format **v3**, nie v4:
`[!] write/readback failed for ... @ PA 0x61f50` bez dopisku
`: transport write=..., readback=..., size=...`, brak linii `PPR write path`
i brak obu linii proby zapisu. Dodatkowo `failed after 2 attempts` wystepuje
w v4 tylko wtedy, gdyby proba zapisu sie UDALA (przy nieudanej probie v4
ustawia jedna probe i pisze `after 1 attempts`), co jest sprzeczne z porazka
w linii nizej. Najspojniejsze wyjasnienie: na konsoli poszedl build v3 albo
wycinek jest skrocony, i w obu przypadkach **kody zwrotu transportu nie byly
zmierzone**.

### 2.2 Hipotezy (a) do (e)

| hipoteza | jak sprawdzona | wynik |
|---|---|---|
| (a) ochrona zapisu obszaru wykonywalnego w A53 | `artifacts/mbox_write-*.txt`: zapis pod trzema adresami w trzech roznych obszarach (0x61F00 w segmencie io, 0xC3000 poza segmentami io i dev, 0x200000 w skrzynce) | **odrzucona jako jedyna przyczyna**: zapis nie trafia do pamieci w ZADNYM z tych obszarow, takze poza segmentem wykonywalnym. Przeniesienie w obrebie tego samego segmentu io (0x61F50 do 0x5E000) nie zmienia praw ochrony, wiec gdyby chroniony byl caly segment, ruch adresu by nie pomogl |
| (b) wyrownanie adresu albo rozmiaru | `access_size()` liczy sie z adresu i rozmiaru: 0x61F50 (16 B) i 160 B daja 6; 0x5E000 (4 kB) i 160 B daja 6; odczyty kotwic z tym samym kodem 6 dzialaja. Zapis 32 B pod adresem wyrownanym do 0x100 tez zawiodl | **odrzucona**: pole dostepu jest identyczne dla zapisow dzialajacych i niedzialajacych, a wyrownanie 16 B jest spelnione. v5 i tak poprawia wyrownanie do 4 kB, zeby ta hipoteza nie wracala |
| (c) rozmiar 160 B przekracza limit jednego polecenia | `artifacts/mbox_write-2026-10-15.txt`: 32 B pod 0x61F00 z polami dostepu 1, 4 i 6, wszystkie bez zmiany pamieci; pakiet 144 B i 160 B | **odrzucona dla tej awarii** (32 B tez nie przechodzi), ale nie da sie jej odrzucic bez pomiaru, wiec v5 obsluguje ja zapisem porcjami po 32 B. Test na hoscie, scenariusz 9, dowodzi ze przy limicie 32 B instalacja konczy sie powodzeniem |
| (d) adres nachodzi na strukture, ktorej A53 broni | `tools/kstuff-ppr-v5/analiza-ogona-io-v5.py`: bloki 4 kB od 0x5E000 do 0x62000 maja entropie 8.000 w obrazie i 7.84 do 7.96 w zrzucie zywym, 0.2 do 2.7 procent zer, brak kodu i brak odwolan; kotwice i miejsca latki leza przed 0x5DC40 | **odrzucona**: pod 0x61F50 nie ma zadnej struktury, to nieuzywany SRAM; ten sam blad wystapil tez pod 0xC3000 i 0x200000 |
| (e) readback czyta inny adres niz zapisany | `ppr_write_checked` czyta spod tej samej `pa` i tego samego rozmiaru, a `parse_read_response` porownuje adres i rozmiar z odpowiedzi A53; w hexie "odczytane" sa te same bajty, ktore "przed" pokazala proba odczytu tego adresu | **odrzucona**: adres i rozmiar readbacku sa te same, a tresc odpowiada stanowi przed zapisem, czyli adres jest poprawny i zapis nie dotarl |

### 2.3 Przyczyna, ktora zostaje: brak polecenia zapisu w A53 13.60

Trzy niezalezne pomiary, wszystkie powtarzalne offline
(`python3 tools/kstuff-ppr-v5/skan-zapisu-a53.py`):

| stala | znaczenie | zrzut jadra 64 MB | 9 regionow A53 |
|---|---|---|---|
| 0x01040031 | polecenie zapisu pamieci A53 | **0** | **0** |
| 0x02040031 | wynik zapisu pamieci A53 | 1 (poza tekstem jadra) | **0** |
| 0x01040021 | polecenie odczytu pamieci A53 | 29 | 0 |
| 0x02040021 | wynik odczytu pamieci A53 | 7 | 9 |
| 0x01050020 | lista regionow zrzutu | 6 | 9 |
| 0x01050030 | odczyt grupy rejestrow | 2 | 9 |
| 0x01200021 | zlecenie zrzutu | 3 | 9 |
| 0x02010001 | wpis listy regionow zrzutu | 14 | 31 |

Odczyt jest w jadrze budowany (29 wystapien polecenia) i A53 zna jego wynik
(9 wystapien), a **zapisu nie ma po zadnej stronie**: ani polecenia, ani wyniku.
Do tego pomiar z konsoli (`artifacts/mbox_write-*.txt`): A53 odpowiada na pakiet
zapisu naglowkiem bez wyniku zapisu, a pamiec pod adresem proby zostaje
niezmieniona, niezaleznie od adresu i pola dostepu.

Wniosek: awaria nie jest zwiazana z adresem 0x61F50 ani z rozmiarem 160 B.
Skrzynka SDBGP na 13.60 nie ma drogi zapisu pamieci A53 od strony x86, wiec
**zaden adres w oknie nie przyjmie zapisu** tym poleceniem. To jest wlasciwa
odpowiedz na pytanie "dlaczego 0x61f50 zawodzi".

## 3. Co przeniesiono i gdzie

### 3.1 Adres docelowy i dowody

| pole | v4 | v5 |
|---|---|---|
| `plaintext_cave_va` | 0x04E61F50 | **0x04E5E000** |
| adres fizyczny | PA 0x61F50 | **PA 0x5E000** |
| rozmiar | 160 B | 160 B (bez zmian) |
| koniec | PA 0x61FF0, 16 B do konca segmentu | PA 0x5E0A0, 16224 B do konca segmentu |
| strona 4 kB | 0x61000, wspolna z jaskinia kodu | **0x5E000, osobna** |
| `io_file_size` | 0x39F00 (wyprowadzone: mapped - 0x100) | **0x36000 (zmierzone)** |

Dlaczego 0x5E000 (pomiary z `analiza-ogona-io-v5.py`):

* bloki 4 kB pod 0x5C000 i 0x5D000 maja entropie 6.82 i 7.25, czyli zawieraja
  tresc; od 0x5E000 do 0x62000 entropia wynosi **8.000** i udzial zer 0.4
  procent, czyli jednolite wypelnienie,
* zrzut zywy segmentu io (`<work>\a53_regions\region_00028000.bin`, caly
  segment PA 0x28000 do 0x62000) pod 0x5E000 ma 111 zer na 4096 B i brak
  jakiejkolwiek struktury, wiec A53 tego obszaru nie uzywa,
* 0x5E000 jest wyrownane do 4 kB, wiec zapis nie dzieli strony z kodem,
* brak kolizji: 5 kotwic (0x28000, 0x57AA8, 0x5B964, 0x5BC20, 0x5C7E8),
  5 miejsc latki (0x4A120, 0x4B860, 0x57C14, 0x57D4C, 0x5BC00) i jaskinia
  runtime (0x61F00 do 0x61F4C) leza poza zakresem 0x5E000 do 0x5E0A0.

Dlaczego `io_file_size` = 0x36000: do v4 ta wartosc byla wyprowadzona przez
analogie do profilu 11.40, a nie zmierzona. Pomiar entropii stawia granice
tresci obrazu dokladnie na PA 0x5E000 (rel 0x36000). Sciezka statyczna, ktora
idzie 13.60, tego pola nie uzywa: `g6_size` wystepuje tylko w dopasowaniu
ukladu dynamicznego, w logu rekordu i w `ppr_map_g6`, ktore dla profilu
io-only nie jest wolane.

### 3.2 Wszystkie odwolania, ktore sie zmienily

| plik | co |
|---|---|
| `artifacts/kstuff-profile-1360-v5.h` | nowy profil: `plaintext_cave_va` 0x04E5E000, `io_file_size` 0x36000, reszta bez zmian |
| `tools/kstuff-ppr-v5/gen_tabela_v5.py` | generator tabeli a53patch dla v5 (podmienia dwa pola i wola `tools/a53patch/gen_patch.py`, wiec zostaje weryfikacja slow stock w obrazie i zasieg galezi) |
| `tools/kstuff-ppr-v5/include/ppr_patch_1360_v5.h` | tabela v5: `a53p_plaintext` z nowymi galeziami (0x97FFEA6D, 0x97FFE162, 0x17FFEA92), `a53p_jaskinie` z rel 0x36000 |
| `ppr_profiles.inc` (drzewo v5) | wygenerowany z profilu v5 i tabeli v5 przez `gen_profiles_1360_v3.py --profil --tabela` |
| `tools/kstuff-ppr-v5/test-walidacji-host.c` | nowe adresy jaskin i nowe slowo `sha_auth_site` (0x94000900) |
| `tools/kstuff-ppr-v5/verify_v5.py` | kontrola nowego ukladu |
| `tools/kstuff-ppr-v5/analiza-ogona-io-v5.py`, `skan-zapisu-a53.py` | narzedzia pomiarowe |

W kodzie C nie trzeba bylo zmieniac ani jednego literalnego adresu jaskini:
wszystkie odwolania ida przez `p->plaintext_cave_va` (kodowanie galezi w
`ppr_build_images`, `ppr_resolve`, `ppr_check_window`, miejsca latki). Dzieki
temu zmiana profilu przelicza galezie automatycznie, a `gen_tabela_v5.py`
potwierdza, ze sa w zasiegu.

### 3.3 Czego nie ruszono

* jaskinia **runtime** zostaje pod VA 0x04E61F00 / PA 0x61F00 i jest
  wykonywalna: szablon 19 slow w binarium jest identyczny jak w v4 (sprawdza
  to `verify_v5.py`, porownujac bajty obu ELF), a galezie `call` i `aes_site`
  nadal celuja w 0x04E61F00 i 0x04E61F2C,
* 5 miejsc latki, 5 kotwic, slowa stock i slowa po latce: bez zmian,
* walidacja obrazu 5/5 kotwicami i bramka fail-closed: bez zmian,
* `tools/a53patch/include/ppr_patch_1360.h` (tabela samodzielnego payloadu
  a53patch) zostaje w geometrii v4, bo jest niezaleznym zrodlem porownania dla
  bramek v2, v3 i v4. Jesli ktos uzywa payloadu a53patch, musi wygenerowac
  jego tabele przez `gen_tabela_v5.py`.

## 4. Co nowego w zapisie jaskin

1. **Dwie proby zapisu** zamiast jednej (`ppr_probe_a53_write_at`, 1091):
   najpierw nowy adres jaskini plaintext (PA 0x5E000, 160 B), potem kontrola
   pod starym adresem jaskini runtime (PA 0x61F00, 32 B). Werdykt obejmuje oba
   adresy, wiec nie da sie zwalic winy na adres bez pomiaru.
2. **Zapis porcjami po 32 B** (`ppr_write_chunked`, 982), uruchamiany tylko po
   nieudanym zapisie pelnego rozmiaru. Kazda porcja ma wlasny odczyt kontrolny
   i wlasna linie w klog. To jednoczesnie hipoteza (c) i realna droga ratunku.
3. **Log kolejnosci** i **VA obu jaskin z wyrownaniem** w
   `ppr_install_caves_with_retry` (1338).
4. Zachowana diagnostyka v4: kod zwrotu zapisu i odczytu osobno, hex zadanych
   i odczytanych bajtow, naglowek odpowiedzi A53, typ polecenia w odpowiedzi,
   rozmiar pakietu.

## 5. Artefakt i weryfikacja

| pole | wartosc |
|---|---|
| plik | `artifacts/kstuff-1360-ppr-v5.elf` |
| rozmiar | 1 802 240 B (tyle samo co v4) |
| sha256 | `58d34bd9184183bb33316d52b1561d7dccc3b3dae1bd071ae5344f53b70d6135` |
| opis menedzera | `artifacts/pldmgr_kstuff_ppr_v5.json` (name "kstuff v5 PPR", version "1360-v5") |
| zrodla | `tools/kstuff-ppr-v5/przygotuj-zrodla-v5.py`, budowa `build-v5.sh` |

Wyniki (wszystko offline, bez konsoli):

| kontrola | wynik |
|---|---|
| `python3 tools/kstuff-ppr-v5/verify_v5.py` | **105 sprawdzen, 0 bledow** (bramka v2 na profilu v5: 61, kontrole v5: 44), kod wyjscia 0 |
| `python3 tools/kstuff-ppr-v2/verify_v2.py` | 62 dobrze, 0 bledow (artefakt v2 nietkniety) |
| `python3 tools/kstuff-ppr-v3/verify_v3.py` | 53 dobrze, 0 bledow plus bramka v2 (61) |
| `python3 tools/kstuff-ppr-v4/verify_v4.py` | 61 plus 18 dobrze, 0 bledow |
| `bash tools/kstuff-ppr-v5/test-walidacji-host.sh` | **10 scenariuszy, 44 sprawdzenia, 0 bledow** |
| `python3 tools/kstuff-ppr-v5/analiza-ogona-io-v5.py` | granica paddingu 0x5E000, brak kolizji |
| `python3 tools/kstuff-ppr-v5/skan-zapisu-a53.py` | 0 wystapien 0x01040031 w jadrze i w 9 regionach A53 |

Najwazniejsze sprawdzenia v5:

* jaskinia plaintext pod PA 0x5E000, wyrownana do 4 kB, w paddingu, konczy sie
  przed koncem mapowania, 16224 B zapasu (v4 mialo 16 B),
* jaskinia runtime bez zmian: ten sam szablon w ELF co w v4, galezie `call`,
  `aes_site` i `sha_auth_site` celuja tam, gdzie maja (0x04E61F00, 0x04E61F2C,
  0x04E5E000),
* brak kolizji miedzy jaskiniami, kotwicami i miejscami latki,
* w binarium nie ma juz starego adresu 0x04E61F50 ani napisu 1360-ppr-v4.

## 6. Jak sprawdzic na konsoli i jakie linie klog oczekiwac

Wgrac `artifacts/kstuff-1360-ppr-v5.elf` tak, jak poprzednie wersje, i czytac
klog. Filtr: `jaskinie`, `A53 write probe`, `A53 zapis`, `write/readback`,
`porcja`, `dormant cave`, `patch state`, `Install result`.

### 6.1 Scenariusz A: zapis dziala pod nowym adresem (sukces)

```
[*] PPR v5: jaskinia plaintext (dane, 160 B) pod PA 0x5E000, jaskinia runtime (kod, 76 B) pod PA 0x61F00, kazda w osobnej stronie 4 kB
[*] dormant cave install: plaintext cave PA 0x5e000 (160 B), runtime cave PA 0x61f00 (76 B)
[*] jaskinie z profilu: plaintext VA 0x4e5e000 (wyrownanie 0x1000), runtime VA 0x4e61f00 (wyrownanie 0x100)
[*] kolejnosc: najpierw jaskinia plaintext (dane), potem runtime (kod); nieudany zapis pierwszej nie pozwala sprobowac drugiej
    przed zapisem: <32 B>
[*] A53 write probe (plaintext cave, nowy adres): typ 0x01040031, PA 0x5e000, 160 B, transport=0
    po zapisie   : 4b 53 54 35 50 50 52 20 ...          <- wzorzec KST5PPR
[+] A53 zapis dziala (plaintext cave, nowy adres): 160 bajtow pod PA 0x5e000 jest zgodne z zadanymi
[*] A53 write probe (runtime cave, stary adres (kontrola)): typ 0x01040031, PA 0x61f00, 32 B, transport=0
[+] A53 zapis dziala (runtime cave, stary adres (kontrola)): 32 bajtow pod PA 0x61f00 jest zgodne z zadanymi
[+] A53 przyjmuje zapis pod oboma adresami; instalacja pelnych jaskin
[*] A53 zapis: PA 0x5e000, 160 B, typ 0x01040031, access 6, mem_type 0x20000, pakiet 288 B
[*] A53 zapis: transport=0 (0 = A53 potwierdzila zlecenie)
[*] A53 zapis PA 0x5e000: odpowiedz magic 0x73354450 src 0x80ff0201 dst 0x80ff0180 seq 0x... polecen 1
[*] A53 zapis PA 0x5e000: typ w odpowiedzi 0x02040031 (wynik zapisu to 0x02040031) ...
[+] dynamic Native/PLAINTEXT_NOAUTH patch installed and read back
[+] PPR patch state: DYNAMIC_INSTALLED (2 callers + 3 internal hooks; FE/FF => ordered PLAINTEXT_NOAUTH)
[PPR] Install result: 0
```

Warunek sukcesu jest jeden i twardy: typ w odpowiedzi musi byc 0x02040031,
a bajty po zapisie musza byc rowne zadanym.

### 6.2 Scenariusz B: zapis nie dziala nigdzie (porazka z przyczyna)

```
[*] A53 write probe (plaintext cave, nowy adres): typ 0x01040031, PA 0x5e000, 160 B, transport=0
    po zapisie   : <te same 32 B co przed zapisem>
[!] A53 nie wykonala zapisu 0x01040031 pod PA 0x5e000: pamiec niezmieniona (plaintext cave, nowy adres)
[*] A53 write probe (runtime cave, stary adres (kontrola)): typ 0x01040031, PA 0x61f00, 32 B, transport=0
[!] A53 nie wykonala zapisu 0x01040031 pod PA 0x61f00: pamiec niezmieniona (runtime cave, stary adres (kontrola))
[!] A53 odrzuca zapis 0x01040031 pod OBOMA adresami (nowym 0x5e000 i starym 0x61f00); pelny zapis jaskin probujemy raz
[*] A53 zapis: PA 0x5e000, 160 B, typ 0x01040031, access 6, mem_type 0x20000, pakiet 288 B
[*] A53 zapis PA 0x5e000: typ w odpowiedzi 0x........ (wynik zapisu to 0x02040031) ...
    zadane    : ff f8 1f 71 01 04 00 54 ...
    odczytane : <bajty wypelnienia>
[!] write/readback failed for plaintext executable-tail cave @ PA 0x5e000: transport write=0, readback=0, size=160
[*] plaintext executable-tail cave: pelny zapis nie przeszedl, probuje porcjami po 32 B
    porcja 1/5 @ PA 0x5e000, 32 B: write=0, read=0, NIEZGODNA
[!] dormant cave install failed after 1 attempts; no entry hooks were connected
[PPR] Install result: -1
```

Ten scenariusz jest **oczekiwanym wynikiem**, jesli pomiar z rozdzialu 2.3 jest
poprawny: przeniesienie jaskini zmienia adres, wyrownanie, strone i zapas
miejsca, ale nie dodaje A53 polecenia zapisu. Rozni sie od v3 i v4 jednym:
klog podaje, ze zapis nie dziala pod **obu** adresami i ze probowano rowniez
porcjami, wiec adres i rozmiar sa wykluczone pomiarem, a nie domyslem.

### 6.3 Co rozstrzyga, ktory scenariusz zachodzi

| linia klog | wniosek |
|---|---|
| `[+] A53 zapis dziala (plaintext cave, nowy adres)` | przeniesienie bylo trafne, zapis dziala pod nowym adresem; dalej patrzec na `Install result` |
| `[!] A53 odrzuca zapis 0x01040031 pod OBOMA adresami` | zapis nie dziala w oknie transportu w ogole; przyczyna jest brak polecenia, nie adres |
| `[!] zapis pod starym adresem 0x61f00 dziala, a pod nowym 0x5e000 nie` | adres ma znaczenie i nowy jest zly; wrocic do 0x61F00 albo probowac innej strony |
| `[+] zapis porcjami zadzialal` | A53 ma limit dlugosci polecenia i porcjowanie go omija, instalacja konczy sie |
| `[PPR] Install result: 0` i `DYNAMIC_INSTALLED` | latka zalozona i potwierdzona odczytem |

## 7. Odtworzenie

```
python3 tools/kstuff-ppr-v5/gen_tabela_v5.py
python3 tools/kstuff-ppr-v5/przygotuj-zrodla-v5.py --wyjscie /mnt/c/tmp/kstuff-v5 --czysto
bash tools/kstuff-ppr-v5/build-v5.sh /mnt/c/tmp/kstuff-v5
cp /mnt/c/tmp/kstuff-v5/ps5-kstuff-ldr/kstuff.elf artifacts/kstuff-1360-ppr-v5.elf
python3 tools/kstuff-ppr-v5/verify_v5.py
bash tools/kstuff-ppr-v5/test-walidacji-host.sh /mnt/c/tmp/kstuff-v5
python3 tools/kstuff-ppr-v5/analiza-ogona-io-v5.py
python3 tools/kstuff-ppr-v5/skan-zapisu-a53.py
```

## 8. Czego nie udalo sie ustalic

1. **Czynny sposob zapisu pamieci A53 na 13.60.** Protokol skrzynki nie ma
   zapisu, a obraz A53 nie jest wysylany przez jadro x86. Sa dwie drogi
   posrednie, obie poza zakresem tego builda: podmiana obrazu A53 przed jego
   zaladowaniem (potrzebny punkt w lancuchu bootowania, ktorego w jadrze nie
   ma) albo podmiana oprogramowania A53 na nosniku.
2. **Czy A53 przyjmie zapis przy innym wypelnieniu pakietu** (`pid`, `tid`,
   `flags`, inny `mem_type`). Wyczerpano: adresy 0x61F00, 0x61F50, 0x5E000,
   0xC3000, 0x200000; rozmiary 32, 76, 144, 160 B; pola dostepu 1, 4, 6;
   typy pamieci 0x020000 i 0x020100. Kombinacja, ktora nie byla mierzona
   na zywej konsoli, to rozmiar 4 B z typem pamieci 0x020000 pod adresem
   miejsca latki; v5 wykona ja przy pierwszym udanym zapisie jaskin.
3. **Czy po skutecznej latce blad PFAuthClient zniknie.** Wymaga dzialajacej
   instalacji, ktorej ta droga nie daje.
