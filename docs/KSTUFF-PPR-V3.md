# kstuff 13.60 z poprawiona walidacja PPR, build v3

Notatka z naprawy walidacji, ktora blokowala zalozenie latki PPR na zywym A53
(PS5 Pro, firmware 13.60). Data: 19.10.2026.
Artefakt: `artifacts/kstuff-1360-ppr-v3.elf` (1 802 240 B).

## 0. Wynik w skrocie

| | v2 | v3 |
|---|---|---|
| rozmiar | 1 802 240 B | 1 802 240 B |
| sha256 | `5da70836aeaf...307f62bb` | `e2f58171e3ee...44079347b` |
| skad uklad segmentow A53 | odczyt strony ukladu PSP pod PA 0x887F0000 | profil (stale potwierdzone obrazem) plus 5 kotwic tozsamosci obrazu w SRAM |
| czy odczyt pod 0x887F0000 jest wykonywany | tak, i zawsze sie nie udaje | nie, ani razu |
| wynik na konsoli | `Install result: -1` | oczekiwane `Install result: 0` i `DYNAMIC_INSTALLED` |
| latka, profil, slowa, jaskinie | bez zmian | bez zmian (bramka `verify_v2.py` przechodzi na v3) |

Zmiana dotyczy wylacznie walidacji obrazu A53. Arytmetyka latki (adresy miejsc,
slowa stock i po latce, szablony jaskin, generowanie galezi) jest nietknieta,
co sprawdza `tools/kstuff-ppr-v3/porownaj-v2-v3.sh` i sekcja F `verify_v3.py`.

## 1. Gdzie jest walidacja, ktora blokowala instalacje

Zrodla: `artifacts/kstuff-a53-src/ppr/` (kopia w drzewie roboczym
`D:\tmp\kstuff-v3` po `przygotuj-zrodla-v3.py`).

| plik | funkcja | linie | co robi |
|---|---|---|---|
| `ppr_patch.h` | brak, stala | 62-63 | `#define PPR_PATCH_LAYOUT_PA 0x887F0000ULL` |
| `ppr_patch.c` | `ppr_read_layout()` | 374-481 | czyta spod tej stalej naglowek 0x148 B (linie 385-396), potem rekordy 0x50 B (415-420) i dopasowuje rekord `io` oraz `dev` (422-451) |
| `ppr_patch.c` | `ppr_resolve()` | 517-524 | wola `ppr_read_layout()`; przy bledzie loguje `[!] PPR exact runtime-layout validation failed` (522) i zwraca -1 |
| `ppr_patch.c` | `ppr_patch_run_target()` | 1201-1204 | `ppr_resolve()` przed jakimkolwiek zapisem, wiec blad konczy instalacje |
| `ppr_install_bridge.c` | `run_ppr_install_impl()` | 81-94 | `Install result: -1`, potem koniec |
| `a53_transport.c` | `read_memory()` | 883-926 | odczyt SDBGP; przy nieudanej odpowiedzi drukuje `[!] A53 read 0x%lx response validation failed` (921) |

Dwa dodatkowe odczyty tego samego adresu sa w probie szybkiego transportu:
`a53_transport.c`, `a53_transport_verify_and_enable_fast()` (1420-1575), gdzie
0x887F0000 jest uzyty jako "niezmienne slowo" punktu odniesienia (1453, 1464,
1505, 1507, 1516, 1525). To stad w logu z konsoli pierwsza linia
`A53 read 0x887f0000 response validation failed` i
`fast transport probe: persistent scalar baseline read failed`, a druga linia
`A53 read 0x887f0000 ...` pochodzi z `ppr_read_layout()`.

## 2. Po co ta walidacja istnieje i co dokladnie sprawdza

Walidacja nie jest ozdoba: `ppr_map_sram()` i `ppr_map_g6()` licza adres
fizyczny jako `baza + (VA - mapped_base)`, a baze (`sram_base`, `g6_base`) biora
z rekordu ukladu. Profil zna VA miejsc, ale nie zna `sram_base`, wiec bez
ukladu patcher nie wie, gdzie fizycznie pisac. Dlatego w v2 uklad byl jednym
zrodlem prawdy o mapowaniu i jednoczesnie bramka tozsamosci obrazu.

Warunki, ktore v2 sprawdzal dla rekordu `io` (i osobno dla `dev`):

```
flagi po odrzuceniu bitow 16 i 17 rowne 0x00000001
g6_base != 0 i wyrownane do 0x1000
g6_size    == io_file_size z profilu
sram_base  == io_sram_base z profilu
sram_size  >= io_mapped_size z profilu
mapped_base == io_mapped_base z profilu
mapped_size == io_mapped_size z profilu
oraz oba rekordy (io i dev) musza istniec
```

Czyli sens jest taki: "zanim wpisze bajty, udowodnij, ze obraz pod adresami
z profilu to ten obraz". Sam zapis jest pozniej dodatkowo zabezpieczony
sprawdzeniem slowa stock w kazdym miejscu i odczytem po zapisie.

## 3. Dlaczego tej walidacji nie da sie spelnic na 13.60

1. **Adres jest nieosiagalny.** Transport SDBGP czyta wylacznie SRAM A53
   `0x0..0xBFFFF` (768 kB, trzy banki po 256 kB). Pod `0xC0000` i wyzej kazdy
   odczyt konczy sie `przeslane 0x0, status 0x20`. Dowody: sekcja "Runda 133 do
   137" w `notes/STAN-KONCOWY-KSTUFF-NG.md` (czternascie adresow, kontrola na
   znanej zawartosci) oraz `artifacts/sdbgp-2026-10-15*.txt`.
2. **Nawet gdyby byl osiagalny, warunek `g6_size == io_file_size` nie ma szans
   przejsc.** `io_file_size = 0x39F00` w profilu jest wartoscia WYPROWADZONA
   z profilu 11.40, a nie zmierzona (v2, punkt 4 profilu i Runda 120:
   `io_file_size` to pole `g6_size` z ukladu, ktorego nikt nie odczytal).
   Pomiar obrazu z sekcji 4 pokazuje, ze kod i dane koncza sie okolo `0x5DC40`,
   a od tego miejsca do konca mapowania `0x62000` lezy losowe wypelnienie.
   Prawdziwe `g6_size` jest wiec mniejsze niz `0x39F00`, a nie rowne.

Wniosek: walidacja jest potrzebna, ale jej zrodlo danych (strona ukladu PSP)
jest na tym firmware nieosiagalne, wiec trzeba ja zastapic, a nie usunac.

## 4. Co jest osiagalne: pomiar obrazu A53

Wszystkie adresy patcha sa ponizej `0x70000`, czyli w oknie transportu:
`0x4A120`, `0x4B860`, `0x57C14`, `0x57D4C`, `0x5BC00`, jaskinie `0x61F00`
i `0x61F50`.

Pomiar `tools/kstuff-ppr-v3/analiza-ogona-io.py` na
`artifacts/a53-obraz-odtworzony.bin` (bloki 4 kB):

```
0x5D000  entropia 7.248  zera 7.0%
0x5E000  entropia 8.000  zera 0.4%  (kazdy bajt dokladnie 16 razy w bloku)
0x5F000  entropia 8.000  zera 0.4%
0x60000  entropia 8.000  zera 0.4%
0x61000  entropia 8.000  zera 0.4%
```

Czyli od `0x5DC40` (pierwsze okno 4 kB o rozkladzie jednostajnym) do konca
segmentu `0x62000` obraz to losowe wypelnienie, a nie kod. To wyjasnia, dlaczego
jaskinie moga tam lezec: leza w paddingu. Wnioski z pomiaru:

* kotwice tozsamosci musza lezec **przed** `0x5DC40`, w czesci kodu,
* jaskinie `0x61F00` i `0x61F50` leza w paddingu, wiec ich zapis nie niszczy
  kodu ani danych,
* najwyzsze odwolanie do VA z zakresu io w calym obrazie to `0x04E5DD00`
  (PA `0x5DD00`, 29 wartosci 32-bitowych i 26 osmiobajtowych), czyli kod i dane
  koncza sie najpozniej tam, a od `0x5DD00` do `0x62000` (0x4300 B) nic nie
  jest adresowane. Granica `0x5DC40` z detektora jednorodnosci jest wiec lekko
  zachowawcza, a jaskinie leza `0x4200` bajtow powyzej ostatniego odwolania.

## 5. Zamiennik: uklad z profilu plus 5 kotwic tozsamosci obrazu

Zasada: uklad `io` bierzemy z profilu (stale potwierdzone obrazem A53), a
zamiast porownywac rekord ukladu sprawdzamy **bajty obrazu** pod piecioma
adresami, ktore transport naprawde czyta. Tabela kotwic jest generowana z
`tools/a53patch/include/ppr_patch_1360.h` (tabela powstala niezaleznie, z obrazu
A53) i dodatkowo sprawdzana w `artifacts/a53-obraz-odtworzony.bin`:

| kotwica | rel w io | PA | co to jest |
|---|---|---|---|
| `io header` | 0x00000 | 0x28000 | naglowek segmentu io (potwierdzony odczytem z konsoli) |
| `dispatch_native` | 0x2FAA8 | 0x57AA8 | prolog funkcji rozgalezienia AES |
| `helper` | 0x33964 | 0x5B964 | prolog pomocnika PPR (potwierdzony odczytem z konsoli) |
| `common_return` | 0x33C20 | 0x5BC20 | wspolny powrot pomocnika |
| `plaintext_direct` | 0x347E8 | 0x5C7E8 | sciezka plaintext bezposrednia |

Kazda kotwica to 16 bajtow porownywanych bajt w bajt. Zadna nie jest miejscem
latki, wiec jej tresc nie zmienia sie po instalacji. Wszystkie leza w kodzie
(przed `0x5DC40`) i wszystkie ponizej `0xC0000`.

Dodatkowo, niezaleznie od kotwic:

1. kazdy wyliczony adres (5 miejsc, 2 jaskinie, 2 emerytowane strazniki) jest
   sprawdzany wobec granicy okna `PPR_SRAM_WINDOW_LIMIT = 0xC0000`,
2. profil musi byc "io only" (`merged_text = 0`, `cave_in_dev = 0`, dwa miejsca
   wywolania); profil, ktory wymaga segmentu `dev` w pamieci gospodarza, jest
   odrzucany z komunikatem `static layout covers io-only profiles`,
3. dotychczasowa bramka "kazde miejsce stock albo dokladnie po latce" zostaje
   bez zmian i dalej dziala po walidacji.

Ochrona przed zapisem w zly obraz jest wiec mocniejsza niz w v2 w tym sensie,
ze porownuje realne bajty kodu w tym samym segmencie, w ktorym leza miejsca
latki, a nie opis ukladu, ktorego pol `g6_size` nigdy nie zmierzono. Do tego
dochodzi bez zmian bramka "kazde miejsce stock albo dokladnie po latce" oraz
odczyt potwierdzajacy kazdy zapis.

## 6. Co zmieniono w zrodlach

Zmiany nanosi `tools/kstuff-ppr-v3/przygotuj-zrodla-v3.py`: najpierw uruchamia
skrypt v2 (cala praca v2), potem dokłada wylacznie ponizsze.

| plik | zmiana |
|---|---|
| `src/ppr/ppr_patch.h` | `PPR_SRAM_WINDOW_LIMIT 0xC0000` z uzasadnieniem i pomiarem |
| `src/ppr/ppr_patch.c` | `PPR_ANCHOR_SIZE`, `struct ppr_image_anchor`, pola profilu `.layout_static`, `.anchors`, `.anchor_count` |
| `src/ppr/ppr_patch.c` | nowe funkcje `ppr_layout_from_profile()`, `ppr_verify_image_anchors()`, `ppr_check_window()` |
| `src/ppr/ppr_patch.c` | `ppr_resolve()`: droga statyczna przy `layout_static`, droga dynamiczna (stara) zostaje dla innych firmware'ow |
| `src/ppr/ppr_patch.c` | odczyt stanu PO zapisie, zeby klog pokazal `DYNAMIC_INSTALLED`, a nie tylko stan sprzed instalacji |
| `src/ppr/ppr_profiles.inc` | wygenerowany na nowo: tabela 5 kotwic i `.layout_static = 1` |
| `src/ppr/ppr_install_bridge.c` | proba szybkiego transportu (odczyt slowa spod 0x887F0000) zastapiona jedna linia logu; mutacja idzie droga konserwatywna |
| `src/main.c` | napis `[PPR] kstuff 1360-ppr-v3 instalacja` |

Kod wstawek lezy w `tools/kstuff-ppr-v3/wstawki/` (`ppr_image_anchor.c`,
`ppr_layout_static.c`, `ppr_resolve_head.c`, `ppr_resolve_window.c`), zeby
zmiane dalo sie przeczytac bez grzebania w skrypcie.

Zakres zmiany, maszynowo (`bash tools/kstuff-ppr-v3/porownaj-v2-v3.sh`):

```
pliki rozne od v2:
  ps5-kstuff-ldr/src/main.c
  ps5-kstuff-ldr/src/ppr/ppr_install_bridge.c
  ps5-kstuff-ldr/src/ppr/ppr_patch.c
  ps5-kstuff-ldr/src/ppr/ppr_patch.h
  ps5-kstuff-ldr/src/ppr/ppr_profiles.inc
linii diffu: 322, dodanych 205, usunietych 21
arytmetyka latki: nietknieta (zaden hunk nie dotyka szablonow jaskin,
slowa hooka ani ppr_build_images)
```

Usuniete linie to wylacznie: napis `ppr-v2`, trzy linie struktury `fast`,
szesc linii proby szybkiego transportu, stary odczyt ukladu w `ppr_resolve`
i stary naglowek generowanego `.inc`. Nic wiecej.

Decyzja o wylaczeniu proby szybkiego transportu jest swiadoma i odwracalna.
Proba opiera sie na niezmiennym slowie spod `0x887F0000`, wiec na 13.60 nie
moze sie udac. Zamiast zostawiac w klog blad, ktory nic nie wnosi, mostek
printuje jedna linie `[*] A53 transport: conservative path ...` i idzie droga
konserwatywna (ta sama, ktora zostala zmierzona na konsoli: 153 ms). Aby
wlaczyc szybki transport, wystarczy podac transportowi punkt odniesienia w
oknie SRAM, np. `0x28000` (kotwica `io header`), i przywrocic blok
`a53_transport_verify_and_enable_fast()` w mostku. To osobny krok, ktory
wymaga wlasnego testu na konsoli.

## 7. Jak zbudowano

```
# 1. drzewo robocze poza repozytorium (najpierw cale v2, potem zmiany v3)
python tools/kstuff-ppr-v3/przygotuj-zrodla-v3.py --wyjscie D:\tmp\kstuff-v3 --czysto

# 2. budowa (WSL Debian, PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk)
bash tools/kstuff-ppr-v3/build-v3.sh /mnt/d/tmp/kstuff-v3

# 3. artefakt
cp /mnt/d/tmp/kstuff-v3/ps5-kstuff-ldr/kstuff.elf artifacts/kstuff-1360-ppr-v3.elf
```

Flagi te same, co w v2: `KSTUFF_OBS=1` i `EXTRA_CFLAGS=-DNPDRM_PORTING`.
Wynik: **1 802 240 B**, sha256
`e2f58171e3eefb5d9fa04a2634bb3dc6acfb59a2c4f69a9d6acf72f44079347b`.

Ten sam rozmiar co v2 nie znaczy "ten sam plik": `.text` urosl o `0x1F0`
bajtow, ale wzrost zmiescil sie w zaokragleniach sekcji przed `.dynamic`
(stale na `0x1B0000`), wiec plik konczy sie w tym samym miejscu. Tresciowo
rozni sie 1 444 879 bajtow, pierwszy juz pod `0x18` (adres wejscia).
Uklad sekcji v2 i v3 pokazuje `python3 tools/kstuff-ppr-v3/porownaj-sekcje-elf.py`.

Budowa jest powtarzalna: swiezo przygotowane drzewo (`D:\tmp\kstuff-v3b`) dalo
plik identyczny z artefaktem **co do bajtu** (0 roznic na 1 802 240 B).

## 8. Weryfikacja

### 8.1 Bramka v2 na artefakcie v3

```
python tools/kstuff-ppr-v2/verify_v2.py --nowy artifacts/kstuff-1360-ppr-v3.elf
wynik: 61 dobrze, 0 bledow
```

Ta bramka sprawdza miedzy innymi: 25 adresow profilu w binarium, 7 slow stock,
5 slow po latce, 2 slowa hooka emerytowanych straznikow, 6 slow galezi jaskin,
2 pelne szablony jaskin (19 i 40 slow), napisy modulu PPR i sciezke fPKG.
Wszystko przechodzi, czyli latka w v3 jest ta sama, co w v2.

Jedna zmiana w `verify_v2.py`: numer wersji w napisie instalacji nie jest juz
przypiety do `v2` (sprawdzane sa `[PPR] kstuff 1360-ppr-` i ` instalacja: %d`),
bo ta sama bramka ma przejsc takze na v3. Rozmiar i suma kontrolna zostaly
przypiete do pliku z repozytorium, tak jak byly.

### 8.2 Bramka v3

```
python tools/kstuff-ppr-v3/verify_v3.py \
    --drzewo-v2 /mnt/d/tmp/kstuff-v2 --drzewo-v3 /mnt/d/tmp/kstuff-v3
wynik: 62 dobrze, 0 bledow (plus bramka v2: 61 dobrze, 0 bledow)
```

Co sprawdza ponad v2:

* kazda z 5 kotwic jest w binarium dokladnie raz i jest zgodna z obrazem A53
  pod `io_sram_base + rel`,
* kazda kotwica i kazde miejsce latki lezy w oknie `0xC0000` i w kodzie
  (`< 0x5DC40`), a obie jaskinie w paddingu (`>= 0x5DC40`, koniec `<= 0x62000`),
* slowa stock z profilu sa zgodne z obrazem A53 pod adresami miejsc (5 z 5),
* w binarium sa napisy nowej walidacji, nie ma napisu instalacji v2,
* zrodla v3 roznia sie od v2 dokladnie w 5 plikach, a licznik szablonow jaskin,
  wywolan `ppr_encode_branch26()` i uzyc `site_hook[` jest identyczny.

### 8.3 Test funkcjonalny na hoscie (bez konsoli)

`tools/kstuff-ppr-v3/test-walidacji-host.sh` kompiluje prawdziwy `ppr_patch.c`
z drzewa v3 i podstawia transport w pamieci: 768 kB SRAM, a powyzej `0xC0000`
blad dokladnie taki, jak na konsoli. Dziewiec scenariuszy:

```
1. czysty obraz stock: instalacja                     -> 0, 5 miejsc po latce,
                                                         obie jaskinie zapisane,
                                                         0 dostepow poza okno
2. drugi przebieg                                     -> 0, zero zapisow
3. status                                             -> 0
4. odinstalowanie                                     -> 0, slowa stock wrocily,
                                                         jaskinie nietkniete
5. przeklamana kotwica "helper"                       -> -1, zero zapisow
6. wyzerowany naglowek io (inna wersja firmware'u)    -> -1, zero zapisow
7. obce slowo w miejscu latki                         -> -1, zero zapisow
8. zapis, ktory nie dochodzi do pamieci               -> -1, obraz nietkniety
9. inny firmware (0x11400000)                         -> -1, brak profilu
```

Log z pierwszego scenariusza (to jest ta sekwencja, ktora pojdzie w klog):

```
[+] PPR A53 image identity confirmed: 5 of 5 anchors match (io SRAM base 0x28000)
[+] PPR 13.60 addresses resolved from verified A53 image (layout page PA 0x887f0000 is outside the SDBGP window)
[*] IO fixed code: executable SRAM base 0x28000, mapped VA 0x4e28000
[+] PPR patch state: STOCK/NATIVE (unused tail ignored)
[+] dynamic Native/PLAINTEXT_NOAUTH patch installed and read back
[+] PPR patch state: DYNAMIC_INSTALLED (2 callers + 3 internal hooks; FE/FF => ordered PLAINTEXT_NOAUTH)
```

Scenariusz 1 dodatkowo sprawdza, ze **zaden** odczyt ani zapis nie wyszedl poza
`0xC0000`, czyli ze sciezka instalacji nie odwoluje sie juz do 0x887F0000.

## 9. Jak sprawdzic na konsoli

1. Czysty start bez innych patcher jadra: `elfldr`, Payload Manager, `klogsrv`
   (port 3232), `ftpsrv`, ShadowMountPlus. Nic nie moze byc uruchomione ani
   instalowane w trakcie, bo instalacja latki odmawia, gdy A53 jest zajete.
2. Zaladuj `kstuff-1360-ppr-v3.elf` (jako `kstuff.elf`) i od razu czytaj klog.
3. Poprawny przebieg daje te linie (w tej kolejnosci):

```
[PPR] System FW: 0x13600000
[PPR] A53: cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358
[*] A53 transport: conservative path (fast probe needs the layout page, outside the SDBGP window)
[+] PPR A53 image identity confirmed: 5 of 5 anchors match (io SRAM base 0x28000)
[+] PPR 13.60 addresses resolved from verified A53 image (layout page PA 0x887f0000 is outside the SDBGP window)
[*] IO fixed code: executable SRAM base 0x28000, mapped VA 0x4e28000
[+] PPR patch state: STOCK/NATIVE (unused tail ignored)
[+] dynamic Native/PLAINTEXT_NOAUTH patch installed and read back
[+] PPR patch state: DYNAMIC_INSTALLED (2 callers + 3 internal hooks; FE/FF => ordered PLAINTEXT_NOAUTH)
[+] PPR FAST stats: ... transactions, ... transport opens, 0x... ticks
[PPR] Install result: 0
[PPR] kstuff 1360-ppr-v3 instalacja: 0
```

W klog **nie ma** juz zadnej linii `A53 read 0x887f0000 response validation
failed` ani `fast transport probe` (oba adresy zniknely ze sciezki instalacji).

4. Linie `[TIME]` w `/data/kstuff-startup.log` i w klog: `A53 init`,
   `A53 clock scan`, `A53 GET_CONF`, `PPR install`, `A53/PPR total`.
5. Twardy dowod niezalezny od logu: odczytaj obraz A53 pod PA 0x4A120
   (np. `tools/a53readN` albo `a53dump`). Przed kstuff ma tam byc
   `0x94004611` (stock), po kstuff `0x94005F78`. Analogicznie 0x5BC00:
   `0x97FFF3B3` przed, `0x940018D4` po, oraz 0x61F00: po instalacji pierwsze
   slowo jaskini to `0xB9401BF0`, a 0x61F50: `0x711FF8FF`.

Co znacza linie bledu:

| linia w klog | znaczenie |
|---|---|
| `[!] PPR image anchor ... mismatch at PA 0x...` | obraz A53 nie jest obrazem 13.60, nic nie zapisano |
| `[!] PPR image anchor ... unreadable at PA 0x...` | transport nie dowiozl 16 bajtow kotwicy, nic nie zapisano |
| `[!] ... is outside the ... A53 SRAM window` | adres z profilu wypada poza okno 0xC0000, nic nie zapisano |
| `[!] install refused: exact stock or recoverable signatures are required` | ktorekolwiek miejsce nie jest ani stock, ani dokladnie po latce |
| `[!] write/readback failed for ...` | zapis nie potwierdzil sie odczytem; patcher ponawia i konczy na bledzie |
| `[!] PPR exact runtime-layout validation failed` | nie przeszla walidacja (kotwice albo droga dynamiczna) |

## 10. Ograniczenia i uczciwe zastrzezenia

1. **Nie ma jeszcze testu na zywej konsoli.** Dowody sa: statyczne (dwie bramki)
   i funkcjonalne na hoscie z symulowanym transportem, ktory powtarza zmierzone
   zachowanie SDBGP. Rozstrzygnie punkt 9.
2. **Szybki transport jest wylaczony** (punkt 6). Mutacja idzie droga
   konserwatywna: 5 osobnych zapisow miejsc i 2 zapisy jaskin, kazdy
   potwierdzony odczytem. To wolniejsze, ale prostsze i zgodne z pomiarem.
3. **Segment `dev` nie jest pokryty** (jak w v2): w tym obrazie nie ma czego
   latac, a droga statyczna swiadomie odrzuca profile, ktore go wymagaja.
4. **Rest mode** (jak w v2): po wybudzeniu A53 dostaje nowy obraz i latke
   trzeba zalozyc ponownie, bo nie ma `ppr_resume.c`.
5. **`io_file_size` w profilu jest nadal wartoscia wyprowadzona.** W v3 nie ma
   to juz znaczenia dla walidacji (nie jest porownywana), a jaskinie i tak leza
   w paddingu, co pokazuje pomiar z sekcji 4. Warto kiedys zmierzyc prawdziwe
   `g6_size` z ukladu, ale wymaga to odczytu nieosiagalnej strony.

## 11. Drugi watek: kod 0x8041013d w PFAuthClient

Pytanie: co to za kod i czy naprawa PPR odblokuje uruchamianie gier.

**Co to za kod.** `0x8041013d` to `SCE_NET_ERROR_ECONNREFUSED`, czyli blad
biblioteki sieciowej, a nie jadra. W publicznych wykazach PS5 ten kod odpowiada
`NW-102261-2`: "Unable to connect to the server". Zrodla:
[Error Codes na psdevwiki](https://www.psdevwiki.com/ps5/Error_Codes),
[strona Sony dla NW-102261-2](https://www.playstation.com/sv-se/support/error-codes/ps5/nw-102261-2/).

**Gdzie jest ten kod.** Nie w module PPR i nie w jadrze. Napis
`pf_auth_client_request_for_ppr` jest w `SceShellCore` (VSH), w tablicy
napisow pod offsetem `0x1D2C893` pliku
`artifacts/console-2026-10-02/SceShellCore_13_60.elf`, razem z:

```
W:\Build\J03950016\vsh\shell\shell_core\pf_auth_client\pf_auth_client.cpp
W:\Build\J03950016\vsh\shell\shell_core\pf_auth_client\pf_auth_client_request_for_ppr.cpp
W:\Build\J03950016\vsh\shell\shell_core\pf_auth_client\pf_auth_client_response.cpp
ret = 0x%x, serverError(%s, 0x%x, %d)
JWS payload not found.
```

a w czesci kodu (`0xC8A5B5` i dalej) leza inline napisy `pf_auth`, `s_token`,
`access_token`, `refresh_token`. W tym samym pliku jest tez napis
`https://ps5.%s.playstation.net/api/%s/%s`. Czyli PFAuthClient to klient HTTPS,
ktory pobiera podpisany token (JWS) z serwerow PlayStation.

W zrzucie jadra `artifacts/kernel-1360-13.60.bin` ten napis wystepuje 128 razy,
ale nie jako kod modulu, tylko w pierscieniu klog: w okolicy `0x39DA9C9` lezy
cala sekwencja z konsoli, miedzy statystykami FMEM i VM Stats:

```
[PFAuthClient][ERROR]pf_auth_client_request_for_ppr.cpp(464) Failed(ret=0x8041013d)
[PFAuthClient][ERROR]pf_auth_client_request_for_ppr.cpp(258) Failed(ret=0x8041013d)
[PFAuthClient][ERROR]pf_auth_client.cpp(84) Failed(ret=0x8041013d)
[PFAuthClient][ERROR]pf_auth_client.cpp(90) Notified error:(0x8041013d)
```

Cztery linie to propagacja jednego bledu: nieudane zadanie (464), jego warstwa
wyzej (258), klient (84) i powiadomienie o bledzie (90).

**Czy ma zwiazek z PPR i A53.** Nie ma. To blad sieci: konsola nie polaczyla
sie z serwerem PlayStation (brak internetu, zablokowany DNS, brak trasy).
Wystepuje niezaleznie od tego, czy latka PPR jest zalozona, i nie zniknie po
jej zalozeniu. Litera "ppr" w nazwie pliku nie znaczy "A53 PPR": w kodzie VSH
"PPR" to numer wymagania Sony (obok `PPRREQ86220_DISABLE_GEN2_ULTRABOOST`
w tej samej tablicy napisow), a nie modul kryptograficzny A53.

**Czy naprawa PPR odblokuje gry.** Naprawa PPR usuwa bramke, ktora stoi na
drodze odczytu i deszyfrowania pakietow fPKG, czyli dokladnie to, co blokowalo
instalacje latki i co odpowiada za sciezke PackageRead. To pierwszy warunek
uruchomienia gry z fPKG. Jednoczesnie jest jasne, ze PFAuthClient nie jest
skutkiem braku latki, wiec:

* jesli po `Install result: 0` gra ruszy, blad PFAuthClient byl nieistotny,
* jesli gra nadal konczy sie bledem (np. `CE-109297-8` z wczesniejszych prob),
  to blokada lezy poza PPR: w uprawnieniach, licencji albo wlasnie w tej
  sciezce autoryzacji, ktora wymaga sieci. Wtedy szukac trzeba tam, a nie w A53.

Rozstrzygnie to jeden przebieg z punktu 9: instalacja plus proba startu gry.

## 12. Pliki

| plik | rola |
|---|---|
| `artifacts/kstuff-1360-ppr-v3.elf` | wynik: kstuff 13.60 z poprawiona walidacja PPR (1 802 240 B) |
| `artifacts/pldmgr_kstuff_ppr_v3.json` | wpis dla Payload Managera, suma kontrolna zgodna z artefaktem |
| `tools/kstuff-ppr-v3/przygotuj-zrodla-v3.py` | drzewo robocze: cale v2 plus zmiany v3 |
| `tools/kstuff-ppr-v3/wstawki/*.c` | kod nowej walidacji, czytelny poza skryptem |
| `tools/kstuff-ppr-v3/gen_profiles_1360_v3.py` | generator `ppr_profiles.inc` z kotwicami |
| `tools/kstuff-ppr-v3/build-v3.sh` | budowa (te same flagi, co v2) |
| `tools/kstuff-ppr-v3/verify_v3.py` | 62 sprawdzenia v3 plus bramka v2 |
| `tools/kstuff-ppr-v3/test-walidacji-host.sh` | test funkcjonalny na hoscie (9 scenariuszy) |
| `tools/kstuff-ppr-v3/porownaj-v2-v3.sh` | zakres zmiany: pliki i arytmetyka latki |
| `tools/kstuff-ppr-v3/porownaj-sekcje-elf.py` | uklad sekcji v2 i v3 (skad ten sam rozmiar pliku) |
| `tools/kstuff-ppr-v3/analiza-ogona-io.py` | pomiar: gdzie konczy sie kod, a zaczyna padding io |
| `tools/kstuff-ppr-v2/verify_v2.py` | bramka v2 (jedna zmiana: numer wersji w napisie instalacji) |
