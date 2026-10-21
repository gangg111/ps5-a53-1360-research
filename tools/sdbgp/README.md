# sdbgp: hook jadra na funkcji, ktora buduje pakiety SDBGP dla procesora A53

Payload zaklada hook jadra na **wejsciu** funkcji, ktora sklada pakiety protokolu
SDBGP (DECI5S) dla procesora bezpieczenstwa A53, i loguje **kazde jej wywolanie**:
numer, czas, rdzen, adres funkcji, wartosci argumentow w rejestrach, sonde
pierwszych 96 bajtow bufora pakietow oraz rozpoznane polecenia z typem, adresem
i rozmiarem.

Wynik: `/data/sdbgp.txt` (kazda linia z `fflush` i `fsync`).
Zatrzymanie przed czasem: plik `/data/sdbgp.stop`.
Tylko nowe tresci zamiast kazdego wywolania: plik `/data/sdbgp.nowe`.

## Budowa

```
env PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make
```

Flagi: `-Wall -Wextra -Werror -O2 -g`. Warianty:

```
make SDBGP_OKNO_MS=2000      krotsze okno obserwacji na jeden rdzen (domyslnie 6000 ms)
make SDBGP_RDZENIE_MAX=4     tylko cztery pierwsze rdzenie
make SDBGP_SAMOTEST=0        bez samotestu na SYS_GETUID
```

Test parsera pakietow (lokalnie, bez konsoli):

```
wsl -d Debian -- bash tools/sdbgp/test-parser.sh
```

Skrypt wycina blok parsera z `sdbgp.c` i uruchamia go na pakietach wzorcowych
odtworzonych z deasemblacji obu wariantow budowy pakietu. Wynik zapisany
w `artifacts/sdbgp-test-parser.txt` to `TEST OK (0 bledow)`.

## Cel hooka: adres, offset i dowod

| co | wartosc |
|---|---|
| funkcja | `0xffffffffc1889100` |
| offset od bazy obrazu kodu | `0xc29100` |
| koniec funkcji | `0xc2ee50` (tam zaczyna sie nastepna), dlugosc `0x5d50` = 23888 B |
| argumenty | `rdi` = softc sterownika MP4, `rsi` i `rdx` = dwa nastepne argumenty |
| 24-bajtowy prolog | `55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 48 06 00 00 4c 8d 25 f5` |
| plik | `artifacts/kernel-1360-13.60.bin`, baza obrazu `0xffffffffc0c60000` |

Wszystkie **trzy miejsca ze zlecenia** leza w tej samej funkcji i kazde jest
zapisem stalej SDBGP do pakietu w buforze `[softc+0x6b8]`:

| offset obrazu | rozkaz | odleglosc od poczatku funkcji |
|---|---|---|
| `0xc292be` | `mov qword [rcx+0x60], 0x01040021` (odczyt, pakiet od podstawy) | 446 B |
| `0xc296c8` | `mov qword [rcx+rsi+0x48], 0x01040021` (odczyt, pakiet doklejany) | 1480 B |
| `0xc292a7` | `mov qword [rcx+0x48], 0x01010010` (konfiguracja) | 423 B |

Dowody dodatkowe, wszystkie z `tools/sdbgp/offline-find-builders.py`
(wynik: `artifacts/sdbgp-offline.txt`):

1. Przemiatanie liniowe od `0xc29100` trafia w kazde z tych miejsc dokladnie na
   granicy rozkazu, a pod `0xc29100` stoi prolog funkcji poprzedzony paddingiem NOP.
2. Funkcja nie ma **zadnego** miejsca wywolania `call rel32` w calym obrazie,
   czyli jest wolana posrednio (skokiem albo z tabeli).
3. Skan calego obrazu daje 28 miejsc z typem `0x01040021`: 18 z nich lezy
   w przedziale tej funkcji (`0xc29100` do `0xc2ee4f`; 13 potwierdza
   przemiatanie liniowe, a 5 lezy w tym przedziale, choc przemiatanie gubi sie
   w nich na skokach posrednich), a 10 w sasiadujacych funkcjach `0xc2f3c0`,
   `0xc309b0`, `0xc30bd0` i `0xc314f0`. Miejsc z typem `0x01010010` jest jedno
   (`0xc292a7`, w tej samej funkcji), a z typem zapisu `0x01040031`
   **nie ma ani jednego**.

## Dlaczego hook na wejsciu funkcji, a nie na samym zapisie stalej

API hooka (`khook.c` z `tools/byepervisor`) ma wbudowany blok zapisu rejestrow
(`khook.c`, linie 417 do 427), ktory uzywa gadzetow `POP_RCX` i `POP_R8`, czyli
**klobruje `rax`, `rcx` i `r8`**. Rejestry `rdi`, `rsi` i `rdx` wracaja z slotow
(`khook.c`, linie 435 do 440), ale `rcx` juz nie.

Na wejsciu funkcji te trzy rejestry sa martwe (funkcja zapisuje je przed
pierwszym uzyciem: `rax` pod `+0xc2911e`, `rcx` pod `+0xc2915a`, `r8` pod
`+0xc291df`). Natomiast w miejscu `+0xc292be` rejestr `rcx` **trzyma adres
pakietu** i jest uzywany przez kilkadziesiat nastepnych rozkazow
(`+0xc292c6`, `+0xc292df`, `+0xc292e3`, `+0xc292ee`, `+0xc292f9` i dalej).
Hook w tym miejscu pisalby pola pakietu pod adres slotu w jaskini, czyli
w nasz wlasny lancuch ROP, i zepsulby transport A53.

Mechanizm pozwala na **jeden hook naraz** (`kh_install` pisze jedna brame IDT
wektora 1 i jeden wpis IST), wiec wybrany jest jeden cel: wejscie funkcji
zawierajacej **oba** budowniczych odczytu i budowniczego konfiguracji. Pakiet
i tak jest kompletny w chwili, gdy strona uzytkownika go czyta (hook nie
zatrzymuje jadra, tylko zapisuje rekord, a odczyt nastepuje przy najblizszych
odpytywaniach rekordu, co 1 ms), dlatego widac zarowno polecenie odczytu, jak
i pola adresu i rozmiaru dopisane po nim.

## Uklad pakietu, ktory czyta payload

Zgodny z ABI z `artifacts/kstuff-a53-src/ppr/a53_transport.c` i potwierdzony
deasemblacja tego jadra:

```
+0x00  deci5s_hdr: magic 0x73354450 ("PD5s"), self_size, packet_size,
       src 0x80ff0180 (jadro), dst 0x80ff0201 (MP4/A53), protocol 0x20000201
       (SDBGP; wariant 0x20000200), attr, user_data, timestamp
+0x28  deci5s_cmd_hdr: dcmp 0x18, code, sequence_no, packet_no, attr,
       num_commands
+0x40  polecenia, kazde o dlugosci total_size (self_size to sam naglowek):
       +0x00 self_size, +0x04 total_size, +0x08 typ, +0x0c flagi,
       +0x10 numer polecenia, +0x14 numer pakietu, +0x1c liczba argumentow
       +0x20 argumenty pamieciowe po 0x18:
             +0x00 self_size 0x18, +0x04 (typ pamieci << 8) | dostep,
             +0x08 adres, +0x10 rozmiar
```

Przyklad z deasemblacji wariantu "pakiet od podstawy" (`+0xc29234`):
konfiguracja pod `+0x40` (`self=0x18`), odczyt pod `+0x58`
(`self=0x20`, `total=0xb0`, `n_args=6`), szesc argumentow pod `+0x78`
(adresy `0`, `0x1b000`, `0x62000`, `0x68000`, `0x85000`, `0xb6000`),
a nastepne polecenie pod `+0x108`, czyli dokladnie `0x58 + 0xb0`.

Payload sonduje **dwa okna** bufora, bo jadro buduje pakiety dwoma wariantami:
od podstawy bufora (`+0xc29234`) i doklejany pod offsetem
`(packet_size + 7) & ~7` (`+0xc29611`).

## Co payload zmienia w pamieci jadra

1. Instalacja hooka: `kh_install` (jaskinia danych, brama IDT wektora 1, wpis
   IST wybranego rdzenia, DR0/DR7) oraz `kh_trigger`.
2. Zdjecie hooka: `kh_disarm` i `kh_restore` (przywrocenie bramy IDT i wpisu
   IST), takze przy bledzie, przy przerwanym starcie i przy sygnale
   `SIGINT`/`SIGTERM`/`SIGHUP`.
3. Zerowanie pola `magic` wlasnego rekordu w jaskini (uscisniecie dloni z jadrem).
4. Dowod rdzenia: podmiana **tylko** lancucha uzytkownika pod
   `KH_OFF_BIG_CHAIN + 0x58` na lancuch proby o dokladnie takiej samej
   dlugosci, a po kroku pojedynczym przywrocenie lancucha wlasciwego. Stub
   `pop rsp; wskaznik duzego lancucha` pod `KH_OFF_CHAIN_DISP` **zostaje
   nietkniety** (w `tools/mp4cmd` byl nadpisywany, co psuje ogon lancucha:
   przywrocenie `rdi`/`rsi`/`rdx` z slotow, RF i `iretq`).
5. Podmiana identyfikatora uprawnien procesu na `0x4800000000000007` na czas
   odczytow, przywracana przed wyjsciem.

Poza tym payload nie pisze nic: nie otwiera zadnego wezla urzadzenia, nie robi
ioctl, nie dotyka struktury sterownika ani rejestrow urzadzen, nie uzywa
kstuffa.

## Warunki uruchomienia na konsoli

1. Czysty start bez kstuff i bez ShadowMountPlus.
2. Uruchomione `elfldr`, Payload Manager i `ftpsrv`.
3. Jailbreak, payload `byepervisor_reborn.elf`, tryb rest i wybudzenie
   (hiperwizor zlamany).
4. **Bez restartu konsoli** wyslij `sdbgp.elf` (hook jadra wymaga wylaczonego
   XOTEXT, a to okno istnieje tylko w tej sesji).
5. Firmware 13.60 (payload to sprawdza i konczy z kodem 2).

## Czego sie spodziewac w logu

Naglowek z bramkami, potem punkt odniesienia bez hooka:

```
firmware: 0x13600007
[bramka] funkcja budujaca pakiety pod 0xffffffffc1b89100: 24 bajty prologu zgodne ze zrzutem
[stan] sterownik MP4 = 0xffffbd5a017e4000 (globalna obraz + 0x3deeb58)
[stan] bufor pakietow [+0x6b8] = 0xffffff8066800000, rozmiar [+0x6a8] = 0x200000, iommu [+0x6b0] = 0x70000000
[stan] pierwsze 96 bajtow bufora: 50 44 35 73 28 00 00 00 20 02 00 00 80 01 ff 80 ...
[samotest] OK, mechanizm hooka potwierdzony na tej konsoli
[rdzen 3] dowod krokiem pojedynczym: #DB z rdzenia 3, przypiecie zglosilo rdzen 3 -> przypiecie DZIALA
```

Kazde wywolanie funkcji (przyklad z testu parsera, te same linie pisze payload):

```
#000001 t=000001234ms rdzen=3 funkcja=0xffffffffc1b89100 (obraz+0xc29100) rdi=0xffffbd5a017e4000 rsi=0x... rdx=0x...
    [softc] rdi=0xffffbd5a017e4000 (zgadza sie z globalna sterownika) bufor=0xffffff8066800000 rozmiar=0x200000 iommu=0x70000000
    [sonda 96 B] 0xffffff8066800000: 50 44 35 73 28 00 00 00 20 02 00 00 80 01 ff 80 ...
    [pakiet] okno0 pod 0xffffff8066800000 magic=0x73354450 self=0x28 rozmiar_pakietu=0x220 src=0x80ff0180 (jadro) dst=0x80ff0201 (MP4/A53) proto=0x20000200 (SDBGP wariant B) numer=7 polecen=3
    [polecenie] okno0 +0x40 typ=0x01010010 SDBGP_GET_CONF (konfiguracja A53) self=0x18 total=0x18 flagi=0x0 nr=1 pkt=0 arg=- (typ bez argumentow pamieciowych)
    [polecenie] okno0 +0x58 typ=0x01040021 SDBGP_READ_MEMORY (odczyt pamieci A53) self=0x20 total=0xb0 flagi=0x0 nr=1 pkt=0 arg=6
      [argument 0] self=0x18 dostep=0x2010001 (typ pamieci 0x20100, dostep 1) adres=0x0 rozmiar=0x1b000
      [argument 1] self=0x18 dostep=0x2010001 (typ pamieci 0x20100, dostep 1) adres=0x1b000 rozmiar=0xd000
```

Zmiany pol struktury (surowiec do wnioskow o buforze roboczym):

```
[pole] t=000000031ms sterownik+0x440 adres urzadzenia A53 (to samo co rejestr) = 0x0000000064000000 (pierwszy odczyt)
[pole] t=000000039ms sterownik+0x6b8 bufor pakietow (strona: kandydat na bufor roboczy/deszyfrowania) = 0xffffff8066800000 (strona 0xffffff80668, pierwszy odczyt)
```

Na koncu podsumowanie: liczba wywolan i linii, typy polecen z licznikami, pary
adres/rozmiar z argumentow, adresy i rozmiary, rdzenie z wywolaniami oraz
odstepy czasu (minimum, maksimum, srednia, rozklad i pierwsze szesnascie).
Statystyka odstepow obejmuje **kazde** wywolanie, takze to pomiete w logu przy
wlaczonym pliku `.nowe`.

Rekord w jaskini jest jeden, a payload odczytuje go co 0,5 ms: jesli dwa
wywolania funkcji zdarza sie blizej niz w tym odstepie, log pokaze jedno z nich
(ta sama granica dotyczy `tools/mp4cmd`). Licznik `wywolan funkcji widzianych`
liczy to, co payload zobaczyl, a nie to, ile razy jadro naprawde zawolalo
funkcje.

## Co zrobic, jesli log jest pusty

1. Sprawdz, czy `/data/sdbgp.txt` w ogole istnieje i czy ma naglowek. Brak pliku
   znaczy, ze payload nie wystartowal albo nie otworzyl `/data`.
2. Przeczytaj sekcje `-- bramki --` w podsumowaniu. Nieudany samotest oznacza,
   ze payload **nie zalozyl** hooka na celu i zakonczyl prace z kodem 3.
   Niezgodny prolog oznacza, ze przesuniecie KASLR albo wersja firmware nie
   zgadzaja sie (payload konczy z kodem 4 i wypisuje bajty, ktore znalazl).
3. Sprawdz sekcje obchodu rdzeni. Gdy wszystkie rdzenie maja
   `przypiecenie NIE dziala`, maska `cpuset` nie dziala na tej konsoli i hook
   uzbraja sie na innym rdzeniu, niz trafiaja przerwania.
4. Sprawdz `[stan]` z poczatku logu: gdy `bufor pakietow [+0x6b8] = 0x0`,
   funkcja nie byla jeszcze wolana ani razu (bufor przydziela sama przy
   pierwszym wywolaniu), wiec brak trafien nie jest bledem hooka.
5. Jesli hooki byly uzbrojone, a trafien nie ma, znaczy to, ze funkcja nie byla
   wolana w oknie obserwacji. Ten budowniczy obsluguje sciezki odczytu pamieci
   A53 (m.in. zrzut i regiony), wiec w czasie okna uruchom to, co ma czytac
   pamiec A53: zrzut z konsoli, wejscie w zaszyfrowana tresc, uruchomienie gry.
   Domyslnie payload przechodzi wszystkie 16 rdzeni po 6 s, czyli okno pokrycia
   to okolo 96 s; mozna je wydluzyc przez `make SDBGP_OKNO_MS=30000`.
6. Jesli sa trafienia, ale `brak bufora pakietow`, to pierwsze wywolanie
   (bufor dopiero powstaje). Dalsze trafienia beda mialy co czytac.
7. Jesli sa trafienia, bufor istnieje, ale `nie rozpoznalem zadnego polecenia`,
   porownaj sonde 96 bajtow z sygnatura `50 44 35 73` ("PD5s"). Brak sygnatury
   znaczy, ze w tym wariancie pakiet lezy gdzie indziej niz w dwoch badanych
   oknach; wtedy trzeba zmienic offsety okien w `obsluz_wywolanie`
   (`OKNO_BAJTOW`, offset doklejania) i przebudowac payload.
8. Gdy konsola zginie zaraz po instalacji hooka, sprawdz w podsumowaniu
   `brama IDT przywrocona`. Payload zdejmuje hook takze przy sygnale, ale przy
   twardym zwisie konsoli pozostaje restart.

## Pokrycie: czy funkcja ma inne wejscia

Sprawdzone w calym obrazie: **nie ma ani jednego skoku** (`E9`/`EB`) z zewnatrz
do wnetrza przedzialu `0xc29100` do `0xc2ee4f` i nie ma w danych zadnego
wskaznika na adres wewnatrz tego przedzialu (szukane co `0x10`). Funkcja jest
wiec wchodzona tylko od poczatku, a hook na wejsciu pokrywa wszystkie jej
uzycia, takze oba budowniczych odczytu i budowniczego konfiguracji.

## Zapasowe cele, gdyby wejscie nic nie pokazalo

Te funkcje tez buduja polecenia odczytu (`0x01040021`) i maja wlasne wejscia.
Hook przenosi sie na nie zmieniajac `CEL_OFFSET` i `g_cel_prolog` w `sdbgp.c`:

| funkcja (obraz+) | VA | 24-bajtowy prolog | miejsc odczytu |
|---|---|---|---|
| `0xc2f3c0` | `0xffffffffc188a3c0` | `55 48 89 e5 41 57 41 56 41 54 53 4c 8d 35 ce f7 1b 03 4c 8d 3d 47 f8 1b` | 1 |
| `0xc309b0` | `0xffffffffc188b9b0` | `55 48 89 e5 41 57 41 56 41 55 41 54 53 50 41 89 f6 4c 8d 0d 38 e7 1b 03` | 1 |
| `0xc30bd0` | `0xffffffffc188bbd0` | `55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 48 8b b7 28 05 00 00` | 4 |
| `0xc314f0` | `0xffffffffc188c4f0` | `55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 48 8b b7 e8 05 00 00` | 4 |

Do tego dwa male pomocniki, ktore wypelniaja naglowek pakietu w buforze podanym
w `rsi` (zaczynaja od zapisu sygnatury `PD5s`): `0xc2f820` (prolog
`55 48 89 e5 48 b8 50 44 35 73 28 00 00 00 48 b9 18 00 00 00 18 00 00 00`,
wolany z `0xc2e6ee` i `0xc313ab`) oraz `0xc2f9e0` (prolog
`55 48 89 e5 41 57 41 56 41 55 41 54 53 50 48 b8 50 44 35 73 28 00 00 00`,
wolany z `0xc2e71c` i `0xc313d5`). Przy nich `rsi` od razu wskazuje pakiet, wiec
gdyby okazalo sie, ze w danym wariancie pakiet nie lezy w dwoch badanych oknach,
te dwa adresy sa najlepszym nastepnym celem.

## Pliki w tym katalogu

| plik | rola |
|---|---|
| `sdbgp.c` | payload: bramki, hook, odczyt i rozbior pakietow, log, podsumowanie |
| `khook.c`, `kdlsym.c`, `util.c`, `include/` | API hooka, skopiowane bez zmian z `tools/mp4cmd` (sumy kontrolne identyczne) |
| `Makefile` | budowa `sdbgp.elf` |
| `offline-find-builders.py` | offline: szuka funkcji budujacych pakiety, wypisuje prologi i wszystkie miejsca stalych |
| `test-parser.c`, `test-parser.sh` | test parsera na pakietach wzorcowych, wycina realny kod z `sdbgp.c` |
