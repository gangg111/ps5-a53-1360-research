# kstuff 13.60 z pelna latka PPR, build v2

> Aktualizacja 19.10.2026: walidacja ukladu runtime spod `0x887F0000`, na ktorej
> opiera sie ten build, jest na 13.60 nieosiagalna przez transport SDBGP (odczyt
> konczy sie `przeslane 0x0, status 0x20`), wiec instalacja konczy sie
> `Install result: -1`. Poprawka jest w build v3: `notes/KSTUFF-PPR-V3.md`.

Notatka z przebudowy kstuff dla firmware 13.60 (PS5 Pro) z pelna latka PPR
w obrazie A53, oparta na profilu potwierdzonym realnym obrazem firmware'u.
Data: 19.10.2026. Artefakt: `artifacts/kstuff-1360-ppr-v2.elf`.

## 0. Wynik w skrocie

Stary build `artifacts/kstuff-1360-ppr.elf` **nie mial zadnego miejsca latki A53**.
Etykieta "PPR" w nim dotyczyla zupelnie innego mechanizmu: przechwytywania
plaintextu PPR po stronie jadra (`ps5-kstuff/uelf/fpkg.c` z bariera podniesiona
do `FWVER > 0x1360`). Dlatego porownywanie go z potwierdzonym profilem nie
wypada "niepelnie", tylko "zero miejsc": 0 z 25 adresow profilu, 0 z 5 slow po
latce, 0 z 2 szablonow jaskin, 0 napisow `[PPR]` w binarium.

Nowy build dokłada do tego samego kstuff-lite modul PPR z drzewa `kstuff-a53`
(transport SDBGP do A53 i patcher `ppr_patch.c`) z profilem 13.60 i zapisuje
**5 miejsc + 2 jaskinie** dokladnie tam, gdzie wskazuje potwierdzony profil.
Sciezka fPKG starego builda zostaje bez zmian.

| cecha | stary `kstuff-1360-ppr.elf` | nowy `kstuff-1360-ppr-v2.elf` |
|---|---|---|
| rozmiar | 1 753 088 B | 1 802 240 B |
| sha256 | `fb709641f1d4...66c8e45` | `5da70836aeaf...307f62bb` |
| adresy profilu w binarium | 0 z 25 | 25 z 25 |
| slowa po latce | 0 z 5 | 5 z 5 |
| jaskinie (szablony) | 0 z 2 | 2 z 2 |
| napisy `[PPR]` | 0 | 12 |
| co robi z A53 | nic, tylko emuluje klucze w jadrze | zapisuje 5 BL i 2 jaskinie w obrazie A53 |

## 1. Co bylo zle w starym buildzie

### 1.1 Stary artefakt to dokladnie plik z drzewa repozytorium

```
sha256(artifacts/kstuff-1360-ppr.elf)
  = fb709641f1d43bc6cdc3c66492372cb225bfd2d2ae5b4aa4c578061df66c8e45
sha256(build/kstuff-lite/kstuff-lite-main/ps5-kstuff-ldr/kstuff.elf)
  = fb709641f1d43bc6cdc3c66492372cb225bfd2d2ae5b4aa4c578061df66c8e45
```

Ta sama suma, ten sam rozmiar. Czyli drzewo w repozytorium jest zrodlem starego
artefaktu i mozna je odtworzyc.

### 1.2 Przebudowa odtwarza stary plik co do 20 bajtow

Polecenie wynikajace z `artifacts/pldmgr_kstuff_ppr1360.json` (flagi
`KSTUFF_OBS=1` i `-DNPDRM_PORTING`; w Makefile te zmienne trzeba podac
w linii polecen, bo plik `.build-config` tylko je zapisuje i nie jest czytany):

```
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -C <kopia>/ps5-kstuff-ldr KSTUFF_OBS=1 EXTRA_CFLAGS=-DNPDRM_PORTING
```

Wynik: 1 753 088 B i 20 roznych bajtow wzgledem artefaktu, na offsets
0x161C6C do 0x161C7F, czyli wylacznie identyfikator build-id. Reszta pliku
jest identyczna. To dowod, ze stary build powstal z tego drzewa i z tych flag.

### 1.3 "PPR" w starym buildzie to inny mechanizm

W drzewie `build/kstuff-lite/kstuff-lite-main` nie ma katalogu `src/ppr` ani
zadnego patchera A53. Jest natomiast `ps5-kstuff/uelf/fpkg.c`, ktory:

* trzyma profil ABI **jadra** (rejestry i sloty stosu funkcji
  `sceSblPfsClearKey`, delty wywolan `cleanup_*`, warianty `verifyImage`),
  a nie adresy w A53,
* zaklada pulapki na kod jadra i emuluje indeksy kluczy (`try_emulate_plaintext_key_index`,
  `try_emulate_plaintext_cleanup_put`), tlumaczac prywatne uchwyty
  `FE`/`FF` na indeksy, ktore A53 by dostalo,
* nigdy nie zapisuje ani jednego bajtu do pamieci A53,
* ma bariere `if(FWVER > 0x1360) return NULL;` (`fpkg.c`, linia 106), ktora
  w naszym drzewie jest juz podniesiona z 0x1160.

Uwaga na pulapke nazewnicza: w repo sa **dwie rozne** struktury o nazwie
`struct ppr_profile`. Jedna w `uelf/fpkg.c` (uklad rejestrow jadra), druga
w `ppr/ppr_patch.c` (adresy w A53). Stary build mial tylko te pierwsza.
Potwierdzony profil z `artifacts/kstuff-profile-1360.h` jest w formacie tej
drugiej, wiec do starego builda nie pasuje i nie mogl do niego pasowac.

### 1.4 Profile A53 w drzewie kstuff-a53 koncza sie na 11.40

`artifacts/kstuff-a53-src/ppr/ppr_profiles.inc` (107 305 B) ma wpisy do
`{ 0x11400000U, PPR_TARGET_RETAIL, 54U }` (11.40). Wpisu dla 0x12 ani 0x13
nie ma. Build referencyjny tego drzewa
(`artifacts/kstuff-a53-ref/kstuff-a53-fast-native.elf`, 1 589 224 B) ma modul
PPR i szablony jaskin, ale na 13.60 wypisalby
`[!] unsupported PPR A53 firmware 0x13600000`. Czyli 13.60 nie byl nigdy
wpiety w kstuff, niezaleznie od bariery w `fpkg.c`.

### 1.5 Rozbieznosci starego builda z potwierdzonym profilem

| element profilu | adres VA | jest w starym buildzie |
|---|---|---|
| `call_va[0]` | 0x04E4A120 | brak |
| `call_va[1]` | 0x04E4B860 | brak |
| `aes_site_va[0]` | 0x04E57C14 | brak |
| `aes_site_va[1]` | 0x04E57D4C | brak |
| `sha_auth_site_va` | 0x04E5BC00 | brak |
| `runtime_cave_va` | 0x04E61F00 | brak |
| `plaintext_cave_va` | 0x04E61F50 | brak |
| `precheck_va` | 0x04E5B9CC | brak |
| `dispatch_va` | 0x04E5BAF4 | brak |
| pozostale 16 pol adresowych (helper, deskryptory, sha, idma) | 0x04E2B124 do 0x04E5BC20 | brak |
| slowa stock (7) | 0x94004611, 0x94004041, 0x97FF4D44, 0x97FF4CF6, 0x97FFF3B3, 0x35000ABC, 0x97FFEFED | brak |

Czyli **zadne miejsce nie jest latane, bo nie ma ani jednego**. Nie ma tez
miejsc z blednym adresem, bo mechanizm w ogole nie operuje na adresach A53.

## 2. Generator `tools/a53patch/gen_patch.py` a to, co robil stary kstuff

To dwa rozne mechanizmy, ale generator i docelowy patcher maja **te sama
semantyke latki**. Zestawienie:

| pytanie | `tools/a53patch/gen_patch.py` | `ppr/ppr_patch.c` (drzewo kstuff-a53) | `uelf/fpkg.c` (stary build) |
|---|---|---|---|
| co jest latane | obraz A53 w buforze jadra | zywy obraz A53 przez SDBGP | kod jadra (pulapki) |
| nosnik | hook na `mp4_map_iommu_full_discont` | transport DECI5S/SDBGP do A53 | breakpointy jadra |
| wejscie | profil + obraz odniesienia | profil + uklad runtime z 0x887F0000 | profil ABI jadra |
| miejsca | 5 (call 0, call 1, aes 0, aes 1, sha_auth) | 5, te same | 0 |
| jaskinie | runtime 76 B, plaintext 160 B | te same, te same slowa | 0 |
| precheck, dispatch | rozpoznawane, nie zapisywane | rozpoznawane, nie zapisywane | brak |
| sprawdzenie stock | 5 z 5 musi sie zgadzac | kazde miejsce stock albo po latce | nie dotyczy |
| co widzi A53 | zmieniony kod | zmieniony kod | niezmieniony kod |

Sprawdzenie zgodnosci jest maszynowe: `tools/kstuff-ppr-v2/verify_v2.py`
przelicza 5 slow po latce i oba obrazy jaskin z profilu i porownuje je z tabela
wygenerowana przez `gen_patch.py` (`tools/a53patch/include/ppr_patch_1360.h`).
Wszystko zgadza sie co do slowa, mimo ze tabele powstaly niezaleznie.

Wniosek: generator a53patch nie jest konkurencja dla kstuff, tylko druga droga
do tej samej latki. Stary kstuff nie realizowal zadnej z tych dwoch drog.

## 3. Co zmieniono w build v2

Zmiany naniesione wylacznie na kopii zrodel poza repozytorium
(`...\_kstuff-v2-work\src\kstuff-lite-main`), przez
`tools/kstuff-ppr-v2/przygotuj-zrodla.py`. W repozytorium nie zmieniono ani
jednego pliku zrodlowego kstuff.

| plik | zmiana |
|---|---|
| `ps5-kstuff-ldr/src/ppr/a53_transport.c/.h` | dodane bez zmian z `artifacts/kstuff-a53-src/ppr` (transport SDBGP, 58 216 B) |
| `ps5-kstuff-ldr/src/ppr/ppr_patch.c/.h` | dodane; `PPR_CALL_COUNT` 10 na 2, nazwy miejsc skrocone do dwoch, log stanu podaje liczbe faktyczna |
| `ps5-kstuff-ldr/src/ppr/ppr_profiles.inc` | wygenerowany z `artifacts/kstuff-profile-1360.h`, jeden wpis 13.60 retail |
| `ps5-kstuff-ldr/src/ppr/ppr_install_bridge.c/.h` | dodane bez zmian (bramka instalacji, fail-closed, log etapow) |
| `ps5-kstuff-ldr/src/ppr/notify.c/.h` | dopisane: kazdy komunikat idzie takze do klog, zeby wynik dalo sie odczytac na konsoli |
| `ps5-kstuff-ldr/src/main.c` | `#include "ppr_install_bridge.h"` i wywolanie `run_ppr_install()` po wczytaniu payloadu jadra, z wynikiem w klog |
| `ps5-kstuff-ldr/Makefile` | `CPPFLAGS += -Iinclude -Isrc/ppr` |
| `ps5-kstuff/` | bez zmian, w tym bariera `FWVER > 0x1360` w `uelf/fpkg.c` |

Czego **nie** dodano: `ppr_resume.c` i `ppr_resume.h`. Ten plik wymaga symbolu
`backpork_request_resume_rearm()` z forka kstuff-a53 (hook jadra po wybudzeniu
z rest mode), ktorego nasze drzewo nie ma. Konsekwencja jest w punkcie 8.

Dlaczego `PPR_CALL_COUNT` wynosi 2: w odtworzonym obrazie A53
(`artifacts/a53-obraz-odtworzony.bin`) sa dokladnie **dwa** rozkazy `BL`
wchodzace w obszar pomocnika PPR, oba w segmencie io, i to sa dwa pierwsze
miejsca profilu. Pomiar (skan wszystkich rozkazow B i BL obrazu):

```
BL do obszaru 0x05B964..0x05BC20: 2
   plik 0x04A120  segment io  VA 0x04E4A120  slowo 0x94004611
   plik 0x04B860  segment io  VA 0x04E4B860  slowo 0x94004041
B  do tego obszaru: 5, wszystkie wewnatrz pomocnika (0x05B9B4 do 0x05BC58)
```

Profil 11.40 ma 10 miejsc, bo miejsca 2 do 9 leza w segmencie dev
(`ExtFs_*`, `NSID2_*`). W naszym obrazie segment dev (0x85000 do 0xB6000) to
**same zera**, wiec tych miejsc nie da sie dla 13.60 potwierdzic ani bezpiecznie
zapisac. Zostawienie ich z adresem 0 nie przeszloby walidacji patchera
(`[!] ... is outside its validated runtime segment`), dlatego licznik jest
zmniejszony, a build jest wylacznie dla 13.60. To jest swiadome ograniczenie,
nie przeoczenie.

## 4. Miejsca latki w v2

Wszystkie adresy w segmencie io (baza VA 0x04E28000, baza fizyczna 0x28000).
Stan "stock" jest sprawdzany przed zapisem, wiec obcy obraz konczy sie odmowa.

| miejsce | VA | fizyczny (rel w io) | slowo stock | slowo po latce |
|---|---|---|---|---|
| `call[0]` | 0x04E4A120 | 0x04A120 (0x22120) | 0x94004611 | 0x94005F78 |
| `call[1]` | 0x04E4B860 | 0x04B860 (0x23860) | 0x94004041 | 0x940059A8 |
| `aes_site[0]` | 0x04E57C14 | 0x057C14 (0x2FC14) | 0x97FF4D44 | 0x940028C6 |
| `aes_site[1]` | 0x04E57D4C | 0x057D4C (0x2FD4C) | 0x97FF4CF6 | 0x94002878 |
| `sha_auth_site` | 0x04E5BC00 | 0x05BC00 (0x33C00) | 0x97FFF3B3 | 0x940018D4 |
| `runtime_cave` | 0x04E61F00 | 0x061F00 (0x39F00) | 19 slow, 76 B | 3 galezie: helper, plaintext_descriptor, aes_descriptor |
| `plaintext_cave` | 0x04E61F50 | 0x061F50 (0x39F50) | 40 slow, 160 B | 3 galezie: sha_wait_idma_aes, submit_idma, sha_authenticate |

Miejsca rozpoznawane, ale **nie zapisywane** (tak samo jak w `gen_patch.py`):

| miejsce | VA | slowo stock | slowo hooka wyliczone |
|---|---|---|---|
| `precheck` | 0x04E5B9CC | 0x35000ABC | 0x94001956 |
| `dispatch` | 0x04E5BAF4 | 0x97FFEFED | 0x94001912 |

Granice: obie jaskinie leza w paddingu za danymi pliku (dane koncza sie na
0x061F00) i koncza sie przed koncem mapowanego segmentu (0x062000), wiec nie
nachodza na dane ani na siebie. Sprawdza to `verify_v2.py`.

## 5. Jak zbudowano

```
# 1. kopia zrodel poza repozytorium + naniesienie zmian
python tools/kstuff-ppr-v2/przygotuj-zrodla.py --wyjscie D:\tmp\kstuff-v2 --czysto

# 2. budowa (WSL Debian, PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk)
bash tools/kstuff-ppr-v2/build-v2.sh /mnt/d/tmp/kstuff-v2
```

Skrypt `build-v2.sh` robi dokladnie:

```
make -C <katalog>/ps5-kstuff-ldr KSTUFF_OBS=1 EXTRA_CFLAGS=-DNPDRM_PORTING
```

Srodowisko: WSL Debian, `PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk` (prospero-clang),
`gcc` 13.x dla payloadu jadra, `yasm`, `python3`. Biblioteki `libbearssl.a`
i `isa-l_crypto.a` byly juz zbudowane w kopiowanym drzewie, wiec ich nie
przebudowywano.

Powtarzalnosc: swiezo przygotowane drzewo daje plik o tym samym rozmiarze
(1 802 240 B) i rozni sie od artefaktu **tylko 20 bajtami build-id**.
Payload jadra (`ps5-kstuff/payload.bin`) rozni sie od tego z repozytorium tez
tylko 20 bajtami, czyli jest ta sama zawartoscia.

## 6. Weryfikacja

```
python tools/kstuff-ppr-v2/verify_v2.py
```

Skrypt sprawdza 61 warunkow w czterech grupach:

1. profil i generator: 5 miejsc, oba obrazy jaskin liczone z profilu sa rowne
   tabeli z `tools/a53patch` (ktora powstala z obrazu A53), brak kolizji miejsc
   i jaskin, jaskinie w paddingu io,
2. artefakt v2: naglowek ELF64, ET_DYN, x86-64, sekcje w pliku, brak kolizji
   sekcji, unikalne nazwy sekcji, rozmiar, sha256, wszystkie 25 adresow profilu,
   ciagi pol profilu, 7 slow stock, 5 slow po latce, 2 slowa hooka, 6 slow
   galezi jaskin, 2 pelne szablony jaskin, napisy logu modulu PPR,
3. zachowanie starej funkcjonalnosci: napisy sciezki fPKG i stala bramki 0x1360,
4. kontrola starego artefaktu: 0 adresow VA, 0 slow po latce, 0 szablonow
   jaskin, 0 napisow `[PPR]`, brak napisu 13.60.

Wynik ostatniego przebiegu: **61 dobrze, 0 bledow**, kod wyjscia 0. Weryfikacja
przeszla takze na swiezo zbudowanym pliku z punktu 5 (`--nowy <plik>`).

Dodatkowo `python tools/a53patch/gen_patch.py --tylko-sprawdz` potwierdza, ze
obraz odniesienia nadal zgadza sie z profilem (5 z 5 slow stock), a
`python -m py_compile` obu skryptow potwierdza skladnie.

## 7. Jak sprawdzic na konsoli, ze latka dziala

Kroki:

1. Czysty start bez innych patcher jadra. Zaladuj `elfldr`, Payload Manager,
   `klogsrv` (port 3232) i `ftpsrv`.
2. Zaladuj `kstuff-1360-ppr-v2.elf` (jako `kstuff.elf`) i od razu czytaj klog.
   Nic nie moze byc uruchomione ani instalowane w trakcie, bo instalacja latki
   odmawia, gdy A53 jest zajete.
3. Poprawny przebieg daje w klog te linie (w tej kolejnosci):

```
[PPR] System FW: 0x13600000
[PPR] A53: cex(1.1.2.01):Oberon-KDE ... releases/13.60 ...   (przyklad; napis pochodzi z odpowiedzi GET_CONF)
[+] PPR 13.60 addresses resolved from exact runtime layout
[*] IO fixed code: executable SRAM base 0x..., mapped VA 0x...
[+] PPR patch state: DYNAMIC_INSTALLED (2 callers + 3 internal hooks; FE/FF => ordered PLAINTEXT_NOAUTH)
    call1=94005f78 call2=940059a8 aes0=940028c6 aes1=94002878 sha=940018d4
[PPR] Install result: 0
[PPR] kstuff 1360-ppr-v2 instalacja: 0
```

4. `/data/kstuff-startup.log` zawiera czasy etapow, w tym
   `[TIME] PPR install: <N> ms` i `[TIME] A53/PPR total: <N> ms`.
5. Twardy dowod niezalezny od logu: odczytaj **obraz A53** pod adresem
   fizycznym 0x4A120 (np. `tools/a53readN` albo inny payload czytajacy pamiec
   A53). Przed kstuff ma tam byc `0x94004611` (stock), po kstuff `0x94005F78`.
   Analogicznie 0x5BC00: `0x97FFF3B3` przed, `0x940018D4` po. To rozstrzyga,
   czy latka naprawde jest w pamieci A53, niezaleznie od tego, co mowi kstuff.

Bledy i co znacza:

| linia w klog | znaczenie |
|---|---|
| `[PPR] No exact profile for FW 0x... target ...` | A53 zglosilo inna wersje niz 13.60, nic nie zapisano |
| `[!] PPR exact runtime-layout validation failed` | uklad runtime z 0x887F0000 nie zgadza sie z profilem, nic nie zapisano |
| `[!] ... is outside its validated runtime segment` | adres z profilu wypada poza segment deklarowany przez runtime |
| `[!] refusing A53 mutation: ...` | A53 nie jest bezczynne, trzeba przerwac odczyty pakietow i powtorzyc |
| `[+] PPR patch state: STOCK/NATIVE` po instalacji | patcha nie ma w pamieci, mimo ze instalacja nie zglosila bledu |

W kazdym z tych przypadkow zapisow jest zero albo brak, a nie "czesc latki".

## 8. Ograniczenia i uczciwe zastrzezenia

1. **Nie ma testu na konsoli.** Cala weryfikacja jest statyczna (binarium,
   profil, generator). Czy instalacja przejdzie na zywej konsoli, rozstrzygnie
   dopiero punkt 7. Mechanizm jest fail-closed: przy niezgodnosci ukladu
   runtime nie zapisuje nic.
2. **Segment dev nie jest pokryty.** Miejsca 2 do 9 z profili do 11.40
   (`ExtFs_*`, `NSID2_*`) leza w segmencie dev, ktorego w odtworzonym obrazie
   nie ma (same zera). Dla fPKG istotne sa dwa miejsca `call` z segmentu io
   (PackageRead) i wewnetrzne hooki pomocnika, i te sa latane.
3. **Rest mode.** Po wybudzeniu A53 dostaje nowy obraz i latka znika. W tym
   buildzie nie ma automatycznej reinstalacji po wybudzeniu, bo `ppr_resume.c`
   wymaga hooka `backpork_request_resume_rearm()` z forka kstuff-a53. Roboczo:
   po wybudzeniu zaladowac kstuff ponownie.
4. **CE-109297-8 nie jest rozstrzygniete.** Ten blad wystepowal **przed**
   zalozeniem latki, wiec nie mozna zakladac, ze latka go usunie. Nowy build
   daje natomiast odpowiedz na pytanie "czy PPR jest tym, co blokuje":
   jesli po `[PPR] Install result: 0` gra nadal konczy sie `CE-109297-8`,
   to blokada jest poza PPR (uprawnienia, npdrm, aktywacja, montowanie),
   i szukac trzeba tam.
5. **Build jest tylko dla 13.60.** Na innym firmware modul PPR odmowi
   ("No exact profile"), a kstuff-lite zadziala jak dotad. To celowe: profile
   innych wersji wymagaja swojego potwierdzonego obrazu.

## 9. Pliki

| plik | rola |
|---|---|
| `artifacts/kstuff-1360-ppr-v2.elf` | wynik: kstuff 13.60 z pelna latka PPR (1 802 240 B) |
| `artifacts/pldmgr_kstuff_ppr_v2.json` | wpis dla Payload Managera, suma kontrolna zgodna z artefaktem |
| `tools/kstuff-ppr-v2/gen_profiles_1360.py` | generator `ppr_profiles.inc` z potwierdzonego profilu |
| `tools/kstuff-ppr-v2/przygotuj-zrodla.py` | kopiuje drzewo i nanosi wszystkie zmiany v2 |
| `tools/kstuff-ppr-v2/build-v2.sh` | buduje kstuff.elf z przygotowanego drzewa |
| `tools/kstuff-ppr-v2/verify_v2.py` | 61 sprawdzen artefaktu, profilu i starego builda |
| `artifacts/kstuff-profile-1360.h` | potwierdzony profil 13.60 (zrodlo prawdy) |
| `tools/a53patch/include/ppr_patch_1360.h` | tabela tej samej latki wygenerowana z obrazu A53 |
| `notes/A53-LIVE-256MB-ANALIZA.md`, `notes/A53-FIRMWARE-W-ZRZUCIE.md` | dowody potwierdzenia profilu obrazem |
