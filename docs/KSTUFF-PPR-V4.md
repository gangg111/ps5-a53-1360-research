# kstuff 13.60 z diagnostyka zapisu A53, build v4

Notatka z przebudowy kstuff dla firmware 13.60 (PS5 Pro): modul PPR, ktory
w v3 zatrzymal sie na zapisie jaskin kodu do pamieci procesora A53.
Data: 19.10.2026. Artefakt: `artifacts/kstuff-1360-ppr-v4.elf`.

## 0. Wynik w czterech zdaniach

1. Zapis jaskin wykonuje `ppr_install_caves_with_retry` (`ppr_patch.c`), ktora
   wola `ppr_write_pair_checked` i dalej `write_memory` w `a53_transport.c`
   z opcodem SDBGP **0x01040031** (SDBGP_WRITE_MEMORY).
2. Na 13.60 ten opcode **nie istnieje**: 0 wystapien w obrazie jadra 64 MB,
   0 wystapien w dziewieciu zrzuconych regionach pamieci A53, a zmierzony
   wczesniej pakiet zapisu wraca bez wyniku zapisu i nie zmienia pamieci.
3. v3 tego nie pokazywala w klog, bo logowala jeden napis bez kodu zwrotu,
   a transport zapisu szedl bez odbioru odpowiedzi (`response = NULL`).
4. v4 nie zmienia adresow ani walidacji (5/5 kotwic dalej dziala), doklada
   pelny slad kazdego kroku zapisu i probe 32 bajtow, ktora jednym przebiegiem
   rozstrzyga, czy A53 przyjmuje 0x01040031.

| cecha | v3 | v4 |
|---|---|---|
| walidacja obrazu | 5 z 5 kotwic | 5 z 5 kotwic (bez zmian) |
| miejsca latki, jaskinie, profil | bez zmian | bez zmian |
| log przy nieudanym zapisie | 1 linia bez kodu | kod zapisu, kod odczytu, hex przed i po, typ odpowiedzi A53 |
| proba zapisu przed pelnym zapisem | brak | 32 B pod PA 0x61F00 z werdyktem |
| powtorka po odrzuconym zapisie | 2 proby po 0,5 s | 1 proba |
| napis instalacji | `1360-ppr-v3` | `1360-ppr-v4` |
| rozmiar | 1 802 240 B | 1 802 240 B |
| sha256 | `e2f58171...4079347b` | `da64f9a0...c3383ff8` |

## 1. Gdzie jest kod zapisu jaskin i jakiego opcode uzywa

Sciezka wywolania (numery linii z drzewa przed v4,
`artifacts/kstuff-a53-src/ppr/`, te same w drzewie v4 poza dodanymi blokami):

| krok | plik | funkcja | linie |
|---|---|---|---|
| 1 | `ppr_patch.c` | `ppr_patch_run_target`, galez `if (before.native && ppr_install_caves_with_retry(...))` | 1243 do 1245 |
| 2 | `ppr_patch.c` | `ppr_install_caves_with_retry` (petla prob) | 1035 do 1054 |
| 3 | `ppr_patch.c` | `ppr_write_pair_checked` (dwie jaskinie: plaintext, potem runtime) | 932 do 978 |
| 4 | `ppr_patch.c` | `ppr_write_checked` (zapis + natychmiastowy odczyt kontrolny) | 819 do 840 |
| 5 | `ppr_patch.c` | `ppr_write` -> `ctx->transport->write` | 369 do 372 |
| 6 | `a53_transport.c` | `callback_write` -> `write_memory` | 1290 do 1294, 928 do 967 |
| 7 | `a53_transport.c` | `send_packet` (skrzynka coredump, `BAR2+0xf6000`) | 664 do 863 |

Operacja zapisu, dokladnie (funkcja `write_memory`):

```
packet->command.type       = SDBGP_WRITE_MEMORY;   /* 0x01040031 */
packet->command.args       = 1;
packet->argument.access_size = access_size(address, size);
packet->argument.mem_type  = MEM_TYPE_PA_TO_EL3;   /* 0x020000 */
packet->argument.addr      = address;
packet->argument.size      = size;
memcpy(raw + sizeof(*packet), source, size);       /* dane wprost w pakiecie */
send_packet(&packet->header.header, total, NULL, 0, NULL);
```

Uklad pakietu: naglowek DECI5S 0x40 B, `sdbgp_write_command` 0x28 B,
`deci5s_mem_arg` 0x18 B, dane wyrownane do 8. Dla jaskini plaintext
(PA 0x61F50, 160 B) daje to `access_size = 6`, `mem_type = 0x020000`,
pakiet 0x120 B. Jaskinia plaintext idzie **pierwsza**, wiec to ona jest tym
zapisem, ktory pada.

Uwaga o drodze: v3 wylaczyl szybki transport (linia "conservative path"), wiec
`ppr_write_many_available` jest falszywe i zapis idzie dwoma **pojedynczymi**
transakcjami `ppr_write_checked`, a nie jednym pakietem mieszanym.

## 2. Dlaczego zapis zawodzi na 13.60

### 2.1 Co mowi pomiar z konsoli

Pelny klog v3 (`<work>\klog-v3.txt`, ten sam przebieg, z ktorego pochodzi
wycinek w zleceniu) ma wiecej linii niz wycinek:

```
540: [+] PPR patch state: STOCK/NATIVE (unused tail ignored)
577: [!] write/readback failed for plaintext executable-tail cave @ PA 0x61f50
578: [!] dormant cave install attempt 1 failed; retrying
615: [!] write/readback failed for plaintext executable-tail cave @ PA 0x61f50
616: [!] dormant cave install failed after 2 attempts; no entry hooks were connected
```

Czyli zapis **runtime** (PA 0x61F00) nigdy nie zostal nawet sprobowany: pada
juz pierwszy zapis z pary, jaskinia plaintext pod PA 0x61F50.

### 2.2 Czego v3 nie mowila

`ppr_write_checked` (v3) liczyla `write_result` i `read_result`, ale logowala
tylko:

```c
ppr_logf(ctx, "[!] write/readback failed for %s @ PA 0x%lx", name, pa);
```

Z tego napisu nie da sie odroznic trzech roznych sytuacji: (a) transport
odrzucil zapis, (b) transport przyjal zapis, ale A53 go nie wykonala,
(c) zapis sie wykonal, a nie udal sie odczyt kontrolny. Do tego `write_memory`
wolalo `send_packet(..., NULL)` z `response = NULL`, wiec **odpowiedz A53 nie
byla w ogole czytana**. `send_packet` zwraca 0, gdy tylko przyjdzie zdarzenie
ukonczenia zrzutu, a nie gdy zapis sie powiedzie, wiec "transport=0" nic nie
znaczylo.

To jest dokladnie ten brak, ktory zlecenie kazalo uzupelnic: kod bledu i
odpowiedz transportu nie byly logowane.

### 2.3 Co rozstrzyga pomiar z 15.10.2026 (payload `tools/mboxwrite`)

`artifacts/mbox_write-2026-10-15.txt` (test zapis-odczyt pod PA 0x61F00,
czyli pod adresem jaskini, z trzema wartosciami pola dostepu):

```
--- proba z dostepem 1 ---
  pakiet zapisu: 144 bajtow, typ 0x01040031
  zapis: naglowek wyniku self 0x20, adres 0x2010001, zadane 0x0, przeslane 0x10, status 0x10
    po zapisie: c7 39 24 d5 33 ba dc d6 6d 2d 91 87 99 ae 69 84
    pamiec bez zmian
  --- proba z dostepem 4 --- (to samo)
  --- proba z dostepem 6 --- (to samo)
```

Ten sam wynik jest w `mbox_write-2026-10-15c.txt` i `-d.txt` oraz
w podsumowaniu "zapis zadzialal: nie" z wzorcem `KSTUFF-NG-1360!!`.
Czyli: pakiet zapisu jest wysylany, A53 odpowiada, a pamiec pod adresem proby
zostaje bez zmian. Odpowiedz nie zawiera wyniku zapisu (typ 0x02040031),
tylko inny naglowek.

### 2.4 Wniosek

A53 na 13.60 **nie wykonuje polecenia 0x01040031**. Nie jest to problem
adresu, okna transportu, dlugosci pakietu ani uprawnien: te same adresy
(0x61F00, 0x61F50) sa w oknie 0x0 do 0xBFFFF, sa czytane bez bledu, a zapis
wraca potwierdzony przez transport i nie zmienia pamieci. Nie jest to tez
problem powtorzenia: druga proba po 0,5 s daje identyczny wynik.

## 3. Czy opcode jest w obrazie jadra 13.60

### 3.1 Skan jadra

`artifacts/kernel-1360-13.60.bin`, 67 108 864 B (64 MiB), skan calego pliku
dowolnego wyrownania, wzorzec 4-bajtowy:

| stala | znaczenie | trafien |
|---|---|---|
| `0x01040031` | zapis pamieci A53 (kstuff) | **0** |
| `0x02040031` | wynik zapisu pamieci | 1 (offset 0x3E1568F) |
| `0x01040021` | odczyt pamieci A53 | 29 |
| `0x01010010` | konfiguracja GET_CONF | 13 |
| `0x01050020` | lista regionow zrzutu | 6 |
| `0x01050030` | odczyt grupy rejestrow | 2 |
| `0x01200021` | zlecenie zrzutu | 3 |

Nazwy trzech ostatnich typow to interpretacja budownika jadra (pod obrazem
+0xc29568 i +0xc2959c widac liste adresow i rozmiarow regionow zrzutu oraz
kolejne zlecenia). Dla wniosku wazne jest cos innego: **zaden z tych typow nie
przenosi danych do pamieci A53**, a typu zapisu nie ma wsrod nich wcale.

Jedno trafienie `0x02040031` lezy pod offsetem 0x3E1568F, czyli **poza tekstem
jadra** (tekst konczy sie na 0xCC0000), a jego otoczenie to ciag danych ze
znacznikami 0xDE, nie kod:

```
... 31 00 04 02 de 23 00 01 00 08 b4 02 00 e8 08 19 a5 00 01 04 de ...
```

Zadnej instrukcji `mov [reg+disp], 0x01040031` w obrazie nie ma, wiec jadro
13.60 nigdy nie buduje polecenia zapisu do pamieci A53.

### 3.2 Skan pamieci A53

Dziewiec regionow zrzuconych przez jadro
(`<work>\a53_regions\region_*.bin`, razem 786 432 B):

| stala | trafien w 9 regionach |
|---|---|
| `0x01040031`, `0x02040031`, `0x01040030`, `0x02040030`, `0x01050031`, `0x02050031` | **0** |
| `0x01050020` | 9 (po jednym na region) |
| `0x01050030` | 9 |
| `0x01200021` | 9 |
| `0x02040021` (wynik odczytu) | 9 |
| `0x02010010` (wynik konfiguracji) | 6 |
| `0x02010001` (wpis listy regionow zrzutu) | 31 |

Tablica na poczatku kazdego regionu to lista deskryptorow regionow zrzutu,
np. w regionie 0x28000: `self 0x18, typ 0x02010001, adres 0x65000, rozmiar 0x3000`.
Czyli firmware A53 zna **odczyt pamieci, konfiguracje i zrzut**, a nie zna
zapisu pamieci, w zadna strone (nie ma ani polecenia, ani wyniku zapisu).

### 3.3 Jakim mechanizmem A53 przyjmuje zapisy na 13.60

To, co da sie udowodnic z materialu, ktory mamy:

1. **Protokol skrzynki nie ma zapisu.** Cztery typy zlecen, ktore jadro buduje
   (odczyt, konfiguracja, lista regionow zrzutu, zlecenie zrzutu), to caly
   zestaw. Typ nieznany (0x01040031) konczy sie odpowiedzia bez wyniku
   zapisu i brakiem zmiany pamieci (`mbox_write-*.txt`).
2. **Obraz A53 nie przechodzi przez jadro x86.** W 64 MB zrzutu jadra nie ma
   ani jednego rozkazu ARM64 (`notes/A53-FIRMWARE-W-ZRZUCIE.md`, rozdzial 5),
   a A53 ma swoj obraz po restarcie, choc zaden proces x86 go nie wyslal.
   Payload `a53patch.elf` z hookiem na `mp4_map_iommu_full_discont` mial to
   rozstrzygnac pomiarem `[wniosek]`: zadne mapowanie bufora dla A53 nie
   zawieralo obrazu (`notes/A53-BUFOR-I-PUNKT-HACZENIA.md`, rozdzial 5 i 6).
3. **Dane do SRAM A53 trafiaja z jego wlasnych ukladow.** A53 nie liczy
   kryptografii sam, tylko programuje uklad i DMA (`notes/INSTALATOR-1360.md`,
   runda 66), a jedna komenda dekompresji obejmuje najwyzej 128 KB. To sa
   zapisywane przez A53 i jego DMA, nie przez gospodarza.

Wniosek, ktory trzeba powiedziec wprost: **na 13.60 nie ma drogi zapisu
pamieci A53 od strony x86.** Sa dwie drogi posrednie, obie poza zakresem tego
builda: (a) podmiana obrazu A53 **przed** jego zaladowaniem (potrzebny punkt
w lancuchu bootowania, ktorego w jadrze nie ma), (b) podmiana oprogramowania
A53 na nosniku (SCF), czyli ingerencja w firmware poza kontrola systemu.

## 4. Co zmienil v4

Wszystkie zmiany sa w czterech plikach drzewa roboczego i sa **addytywne**:
profil, adresy, slowa stock i po latce, szablony jaskin oraz walidacja kotwic
zostaja bez zmian (bramka v2 przechodzi na artefakcie v4).

1. `src/ppr/a53_transport.c`, `write_memory` (linia 986) i nowa funkcja
   `report_write_response` (linia 938): pakiet zapisu idzie z `response`
   zamiast `NULL`, a odpowiedz A53 jest kopiowana i logowana: naglowek DECI5S,
   numer zlecenia, typ polecenia w odpowiedzi (z jawnym odniesieniem do
   oczekiwanego 0x02040031) i 32 bajty. Dodana stala `SDBGP_WRITE_RESULT`
   (linia 36). Kod zwrotu transportu jest logowany osobno.
2. `src/ppr/ppr_patch.c`, `ppr_write_checked` (linia 968): linia bledu ma
   teraz `transport write=%d, readback=%d, size=%u`, plus hex danych zadanych
   i odczytanych (`ppr_log_hex`, 32 B w jednej linii).
3. `src/ppr/ppr_patch.c`, `ppr_probe_a53_write` (linia 1007): odczyt 32 B pod
   PA 0x61F00, zapis wzorca `KST4PPR 13.60 write probe 32B!`, odczyt kontrolny, werdykt. Adres lezy
   w nieuzywanym ogonie segmentu io (plik obrazu konczy sie na rel 0x39F00),
   wiec proba nie rusza dzialajacego kodu, a pelny zapis jaskini runtime
   i tak nadpisuje te 32 bajty.
4. `src/ppr/ppr_patch.c`, `ppr_install_caves_with_retry` (linia 1242):
   loguje adresy i rozmiary jaskin, wola probe, a po odrzuconym zapisie robi
   **jedna** probe pelnego zapisu zamiast dwoch i konczy jawnym werdyktem.
5. `src/ppr/ppr_install_bridge.c` i `src/main.c`: jedna linia o drodze zapisu
   i napis wersji `1360-ppr-v4`.

Czego v4 **nie robi** i dlaczego: nie probuje innego opcode. Zaden inny typ
zapisu nie wystepuje ani w jadrze, ani w firmware A53, wiec proba byla by
zgadywaniem na zywej pamieci procesora bezpieczenstwa. Nie zmienia tez
`pid`/`tid` ani `flags` pakietu zapisu: to jedyne pozostale hipotezy
niepotwierdzone dowodem, a nowy log odpowiedzi je rozstrzygnie (jesli A53
odpowie wynikiem bledu zamiast wyniku zapisu, zobaczymy to w typie i bajtach).

## 5. Artefakt i weryfikacja

| pole | wartosc |
|---|---|
| plik | `artifacts/kstuff-1360-ppr-v4.elf` |
| rozmiar | 1 802 240 B |
| sha256 | `da64f9a089a6911509986bfc8db28ccc1acbe770cbde4dba73be50c9b3383ff8` |
| opis menedzera | `artifacts/pldmgr_kstuff_ppr_v4.json` (name "kstuff v4 PPR", version "1360-v4") |
| zrodla | `tools/kstuff-ppr-v4/przygotuj-zrodla-v4.py`, budowa `build-v4.sh` |

Weryfikacja (wszystko offline, bez konsoli):

* `python tools/kstuff-ppr-v4/verify_v4.py`:
  * bramka `verify_v2.py` na artefakcie v4: **61 dobrze, 0 bledow**
    (profil, 25 adresow, 5 slow stock, 5 slow po latce, 2 szablony jaskin,
    brak kolizji, sciezka fPKG, stary artefakt jako kontrola),
  * sprawdzenia v4: **18 dobrze, 0 bledow** (12 napisow diagnostyki,
    stale 0x01040031 i 0x02040031, brak napisu v3, zgodnosc manifestu).
* `bash tools/kstuff-ppr-v4/test-walidacji-host.sh`: **9 scenariuszy, 0 bledow**.
  Scenariusz 8 ("zapis, ktory nie dochodzi do pamieci") odtwarza zachowanie
  13.60 i sprawdza, ze klog podaje przyczyne:

```
[*] A53 write probe: typ 0x01040031, PA 0x61f00, 32 B, transport=0
    po zapisie   : 68 c4 d6 d7 9c 47 2e d4 (32 B, bez zmian)
[!] A53 nie wykonala zapisu 0x01040031: pamiec niezmieniona, wiec firmware A53 nie ma tego polecenia
[!] A53 odrzuca zapis 0x01040031; pelny zapis jaskin probujemy raz, bez powtorki
[!] write/readback failed for plaintext executable-tail cave @ PA 0x61f50: transport write=0, readback=0, size=160
    zadane    : ff f8 1f 71 ...
    odczytane : 49 04 ea e0 ...
```

## 6. Ktore linie klog potwierdza sukces, a ktore rozstrzygaja porazke

### 6.1 Sukces (gdyby zapis dzialal)

```
[*] PPR write path: SDBGP typ 0x01040031 przez skrzynke coredump ...
[*] dormant cave install: plaintext cave PA 0x61f50 (160 B), runtime cave PA 0x61f00 (76 B)
    przed zapisem: <32 B>
[*] A53 write probe: typ 0x01040031, PA 0x61f00, 32 B, transport=0
    po zapisie   : 4b 53 54 34 50 50 52 20 31 33 2e 36 ...   <- wzorzec KST4PPR
[+] A53 zapis dziala: 32 bajtow pod PA 0x61f00 jest zgodne z zadanymi
[*] A53 zapis: PA 0x61f00, 32 B, typ 0x01040031, access 6, mem_type 0x20000, pakiet 160 B
[*] A53 zapis: transport=0 (0 = A53 potwierdzila zlecenie)
[*] A53 zapis PA 0x61f00: odpowiedz magic 0x73354450 src 0x80ff0201 dst 0x80ff0180 seq 0x... polecen 1
[*] A53 zapis PA 0x61f00: typ w odpowiedzi 0x02040031 (wynik zapisu to 0x02040031) ...
[+] dynamic Native/PLAINTEXT_NOAUTH patch installed and read back
[+] PPR patch state: DYNAMIC_INSTALLED (2 callers + 3 internal hooks ...)
[PPR] Install result: 0
```

Warunek sukcesu jest jeden i twardy: **typ w odpowiedzi musi byc 0x02040031,
a bajty po zapisie musza byc rowne zadane**. Sama linia `transport=0` nic nie
znaczy, bo transport potwierdza tylko przyjecie zlecenia.

### 6.2 Porazka (oczekiwana na 13.60, z podana przyczyna)

```
[*] A53 write probe: typ 0x01040031, PA 0x61f00, 32 B, transport=0
    po zapisie   : <te same 32 B co przed zapisem>
[!] A53 nie wykonala zapisu 0x01040031: pamiec niezmieniona, wiec firmware A53 nie ma tego polecenia
[!] A53 odrzuca zapis 0x01040031; pelny zapis jaskin probujemy raz, bez powtorki
[*] A53 zapis: PA 0x61f50, 160 B, typ 0x01040031, access 6, mem_type 0x20000, pakiet 288 B
[*] A53 zapis: transport=0 (0 = A53 potwierdzila zlecenie)
[*] A53 zapis PA 0x61f50: odpowiedz magic ... polecen N
[*] A53 zapis PA 0x61f50: typ w odpowiedzi 0x........ (wynik zapisu to 0x02040031) ...
    odpowiedz bajty: <32 B>
    zadane    : ff f8 1f 71 01 04 00 54 ...
    odczytane : 49 04 ea e0 bd 87 12 e3 ...
[!] write/readback failed for plaintext executable-tail cave @ PA 0x61f50: transport write=0, readback=0, size=160
[!] dormant cave install failed after 1 attempts; no entry hooks were connected
[PPR] Install result: -1
```

Gdzie to czytac: klog (`artifacts/klog-*.txt` po zrzucie) i
`/data/kstuff-startup.log`. Filtr: `A53 zapis`, `write probe`,
`write/readback`, `dormant cave`. Czas instalacji bedzie **o jedna transakcje
dluzszy niz w v3** (proba 32 B to trzy transakcje, a v4 oszczedza tylko jedna
z dwoch prob pelnego zapisu, czyli ok. 0,6 s wiecej przy bledzie). To celowa
cena za werdykt, ktorego v3 nie dawala: przy nastepnym przebiegu wiadomo
od razu, czy problem jest w opcode, czy w odczycie kontrolnym.

## 7. Blad PFAuthClient a latka PPR

W tym samym klogu `[PFAuthClient] pf_auth_client_request_for_ppr.cpp ...
Failed(ret=0x8041013d)` wystepuje 24 razy, ale **przed** proba instalacji
(linie 17 do 25 i 66 do 69, instalacja to linie 540 do 620). Kod 0x8041013D
to **ECONNREFUSED** (SCE_NET, errno 61): klient PPR dostal odmowe polaczenia,
a nie blad klucza czy deszyfrowania. To blad warstwy uslugowej, niezalezny od
zapisu do A53 i od samej latki:

* wystepuje przed jakimkolwiek zapisem do A53, wiec nie moze byc jego przyczyna,
* latka PPR dziala na sciezce PackageRead w A53, a nie na polaczeniu klienta
  z usluga PPR, wiec skuteczna instalacja nie musi go usunac,
* jego znikniecie zalezy od tego, czy usluga PPR po stronie systemu jest
  osiagalna, a nie od stanu pamieci A53.

Wniosek: blad PFAuthClient nie ma zwiazku z blokada zapisu i nie jest
wyznacznikiem sukcesu latki. Wyznacznikiem jest typ odpowiedzi A53
(0x02040031) i zgodnosc bajtow po zapisie, opisane w rozdziale 6.

## 8. Odtworzenie

```
py tools\kstuff-ppr-v4\przygotuj-zrodla-v4.py --wyjscie D:\tmp\kstuff-v4 --czysto
wsl -d Debian -- bash -lc "cd /mnt/c/Users/Artur/Documents/Serwis/Programowanie/PS5/ps5-1360-fpkg && bash tools/kstuff-ppr-v4/build-v4.sh /mnt/c/Users/Artur/AppData/Local/Temp/kstuff-v4"
py tools\kstuff-ppr-v4\verify_v4.py
wsl -d Debian -- bash -lc "cd /mnt/c/Users/Artur/Documents/Serwis/Programowanie/PS5/ps5-1360-fpkg && bash tools/kstuff-ppr-v4/test-walidacji-host.sh /mnt/c/Users/Artur/AppData/Local/Temp/kstuff-v4"
```

## 9. Czego nie udalo sie ustalic

1. **Czy A53 przyjmie zapis przy innym wypelnieniu pakietu** (`pid`, `tid`,
   `flags`, inny `mem_type`). Dowodu nie ma; typ 0x01040031 nie wystepuje
   w firmware A53, wiec najbardziej prawdopodobne jest, ze nie ma go czym
   przyjac. Nowy log odpowiedzi rozstrzygnie to bez zgadywania: jesli A53
   odpowie typem innym niz 0x02040031 i bez zmiany pamieci, sprawa jest
   zamknieta dla tej drogi.
2. **Czy blad PFAuthClient zniknie po skutecznej latce.** Kod 0x8041013D to
   ECONNREFUSED, wiec raczej nie zalezy od latki. Rozstrzygnie to dopiero
   przebieg z dzialajaca usluga PPR po stronie systemu.
3. **Jaka droga obraz A53 trafia do SRAM.** Wiemy, ze nie przez jadro x86
   i nie przez skrzynke SDBGP. Ktory element lancuchu bootowania go wysyla,
   nie jest ustalone; to osobne zadanie, poza zakresem v4.
