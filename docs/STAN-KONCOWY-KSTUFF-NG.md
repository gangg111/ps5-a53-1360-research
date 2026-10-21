# kstuff NG dla 13.60: stan koncowy i gdzie podjac prace

Dokument zbiera cala droge od pytania "czemu nie dziala licencja" do miejsca, w ktorym
jestesmy, oraz wskazuje dokladnie, co zostaje do zrobienia. Wszystko jest poparte logami
i plikami w tym repozytorium.

## Cel

kstuff NG z dzialajaca instalacja i uruchamianiem fPKG na PS5 Pro z firmware 13.60.

## Co jest potwierdzone i dziala

- **Gry dzialaja** droga montowania: obraz `.exfat` albo katalog w `/data/homebrew`
  z plikiem `mount.lnk` w `/data/app/<ID>`. Sprawdzone na kilkunastu tytulach.
- **Poprawka npdrm** w kstuff-lite znosi kontrole licencji (`CE-107750-0`).
- **Exploit hiperwizora Byepervisor Reborn dziala** na tej konsoli, potwierdzony
  dwukrotnie zdjeciem ekranu. Procedura: czysty start bez payloadow patchujacych jadro,
  elfldr, potem payload, tryb rest, wybudzenie.
- **Zrzut jadra 13.60** (64 MB) pobrany i zwalidowany: `artifacts/kernel-1360-13.60.bin`,
  suma `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804`.
- **Konwencja offsets kstuff udowodniona** na tym zrzucie: `0xCC0000 - 0x71B9F0 = 0x5A4610`
  trafia dokladnie w `sceSblServiceMailbox`.
- **Sciezka PPR zostala odblokowana** i montowanie fPKG **ruszylo**: superblok weryfikuje
  sie poprawnie (`verify_ppr_sblock_100 error(0)`), PFS jest parsowany.

## Na czym stoi fPKG i dlaczego

Instalacja fPKG przez PKG Manager **przechodzi** (`sceAppInstUtilInstallByPackage`
zwraca 0, `playgo.progress.state=7`, `error_code=0x0`). Uruchomienie gry pada na
**montowaniu danych pakietu**:

```
verify_ppr_sblock_100() error(0) ekey[0xfffffffd] skey[0xfffffffc]   sukces, tryb jawny
ppfs_wait_a53io_result() error=5                                     odmowa procesora A53
ppfs_read_nsid2_icv() error=5
mountppfs() error=5, proces zabity, CE-100022-5
```

**Blokada jest w procesorze bezpieczenstwa A53 (MP4)**, a nie w licencji ani w wersji
systemu. Wymaga on patcha "plaintext bez uwierzytelnienia", ktory wgrywa sie do jego
pamieci.

## Mechanizm, ktory trzeba uruchomic

1. **Patch PPR** wgrywa sie do pamieci A53 trybem `PPR_PATCH_MODE_PLAINTEXT_NOAUTH`
   (marker `PPRPLAIN-NOAUTH!`).
2. **Transport** to pakiety DECI5S/SDBGP: `DECI5S_PROTO_SDBGP 0x20000201`,
   `SDBGP_READ_MEMORY 0x01040021`, `SDBGP_WRITE_MEMORY 0x01040031`,
   `SDBGP_GET_CONF 0x01010010`.
3. **Patch potrzebuje profilu dla danej wersji**: okolo czterdziestu adresow i wzorcow
   rozkazow ARM64 wewnatrz oprogramowania A53 (przestrzen `0x04e...`, `0x064...`).
4. **Publiczne profile koncza sie na 11.40**, i dlatego w scenie fPKG dziala tylko
   do 11.60. `Kstuff NG 1.00` ma w tytule "FPKG nieobslugiwany", a my znalezlismy
   w kodzie dokladnie te granice: `if(FWVER > 0x1160) return NULL;`.
5. **Nasze osiagniecie:** podnieslismy te granice na 13.60 po walidacji profilu na
   retail-owym zrzucie (`validate_ppr_offsets.py`: `PASS 13.60.bin`) i **sciezka PPR
   faktycznie sie uruchomila**.

## Co zostaje do zrobienia

1. **Znalezc droge, ktora payload moze zlecic odczyt pamieci A53.** Jadro 13.60 ma ten
   transport w kodzie: budowanie pakietow widac pod `0xffffffffc18892c2` (polecenie
   odczytu) i `0xffffffffc1889675` (naglowek), a funkcja jest wywolywana w czterech
   miejscach, wszystkie w obrebie sterownika, plus raz z `0xffffffffc17baf07`.
   Urzadzenia to `/dev/deci_mp4_ioc` i `/dev/deci_mp4_mmc`. Katalogu `/dev/mp4`,
   ktorego uzywa implementacja dla 5.00, na 13.60 **nie ma**.
2. **Zrzucic oprogramowanie A53** przez ten odczyt.
3. **Dopasowac wzorce ARM64** z profilu 11.40 (`call_stock`, `aes_site_stock`,
   `sha_auth_site_stock`, `precheck_stock`, `dispatch_stock`) i zbudowac profil 13.60.
4. **Ustalic droge zapisu.** Stala `SDBGP_WRITE_MEMORY` w zrzucie **nie wystapila**,
   wiec zapis trybu plaintext trzeba byc moze wykonac skrzynka urzadzenia, tak jak robi
   to implementacja referencyjna.
5. **Nalozyc patch i sprawdzic montowanie fPKG.** Log A53 powie wprost, czy dziala.

## Aktualizacja: oprogramowanie A53 przechwycone, punkty 1 i 2 z listy zrobione

**Sekwencja uruchamiajaca zrzut A53** (odtworzona z implementacji referencyjnej,
potwierdzona trzy razy na konsoli):

1. podmiana identyfikatora uwierzytelnienia na SysCore, `0x4800000000000007`,
   przez `kernel_get_ucred_authid` i `kernel_set_ucred_authid` (wymaga kstuff),
2. `revoke("/dev/mp4/dump")`,
3. `open("/dev/mp4/dump", O_RDONLY)`,
4. `ioctl(fd, 0x800c410b, ctx)` z `ctx[0] = 12`, zwraca 0,
5. oczekiwanie na zdarzenie coredump przez kqueue, do 10 sekund,
6. `ioctl(fd, 0x40184115, ctx)`, zwraca 0, a `ctx[4] & 0xffff == 0x000f`, czyli komplet faz,
7. `ioctl(fd, 0x8008410f, fin)`.

Te same polecenia sa w dekompilacji jadra 13.60, w funkcji `FUN_ffffffffc1892430`,
razem ze sprawdzeniem rozmiaru kontekstu `*param_3 == 0xc`.

**Zadne urzadzenie nie oddaje jednak tresci pamieci A53** (patrz lista w punkcie 1).
Dane sa w pamieci jadra: funkcja rejestrujaca sterownik zapisuje kontekst pod globalny
adres `c4a4eb58` (wzgledem bazy obrazu `+0x3DEEB58`), a transport czyta bufor pakietow
spod `softc + 0xd7 * 8`, czyli `+0x6b8`.

```
iface_a: 0xffffad4c018a2000      kontekst sterownika
pole bufora pod softc + 0x6b8: 0xffffff8061800000
zrzut bufora pakietow: 0x200000 B
```

**Wynik: oprogramowanie A53 dla 13.60.** `/data/a53_pkt.bin`, 2 MB, suma
`408268dcdbfce3b2fe96631aced8ce070f5072bbda0690d0ec6c530aca86c1ad`. Zawiera baner
`cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358` oraz prawdziwy kod
ARM64: gestosc `BL` 1.52 procent i `STP` 1.38 procent, dla porownania w zrzutach
procesow bylo 0.02 procent. Po analizie w Ghidrze jako `AARCH64:LE:64:v8A`:
**847 funkcji, 85 400 rozkazow**.

**Bufor rozlozony na dziewiec regionow** z adresami A53 (`tools/split-a53-regions.py`,
wyniki w `<work>\a53_regions`): 0x00000, 0x1b000, 0x28000, 0x62000, 0x65000, 0x68000,
0x69000, 0x85000, 0xb6000. Kazdy region ma wlasna tablice polecen pod podobnym
przesunieciem, czyli procesor obsluguje wiele instancji, co pasuje do dziewieciu
kanalow `deci_tty` widocznych w `/dev`.

**Przeliczenie adresow.** Z profilu 11.40 wynika, ze `runtime_cave_va = 0x4e5cf00` lezy
na koncu obszaru `io_mapped_base = 0x4e28000` powiekszonego o `io_file_size = 0x34f00`.
Nasz odpowiednik to region `0x28000` o rozmiarze `0x3a000`, co daje hipoteze
`adres_profilu = 0x4e28000 + (adres_regionu - 0x28000)`. Test na wzorcu
`precheck_stock = 0x35000abc` trafil pod adres regionu `0x5c0c4`, czyli przewidywany
`0x4e5c0c4` wobec `0x4e5ac4c` w profilu 11.40. Roznica 0x1478, czyli 5240 bajtow,
odpowiada roznicy ukladu kodu miedzy wersjami. Jeden punkt, wiec hipoteza jest
prawdopodobna, ale nie udowodniona.

**Co zostaje, precyzyjnie:**

1. potwierdzic przeliczenie adresow na wiekszej liczbie punktow,
2. zlokalizowac pozostale miejsca profilu: wywolania odczytu pakietu, miejsca AES, SHA,
   sprawdzenie wstepne, rozgalezienie; nazwy z `ppr_call_names` podaja ich znaczenie,
3. zbudowac profil dla 13.60: adresy, rozmiary regionow, wzorce instrukcji,
4. rozstrzygnac droge zapisu, bo polecenia `0x01040031` nie ma ani w jadrze, ani w A53,
5. nalozyc patch i sprawdzic montowanie fPKG.

**Narzedzia z tej czesci pracy:** `tools/a53cmd`, `tools/a53node2`, `tools/softc`,
`tools/kbuf`, `tools/split-a53-regions.py`, `tools/parse-kbuf-packets.py`,
`tools/verify-a53-address-map.py`, `tools/find-a53-dispatch.py`, `tools/ghidra/*.java`,
`tools/make-elf-wrapper.py`.

## Wazne pułapki, ktore nas kosztowaly czas

- **Nie zgadywac adresow w jadrze.** Odczyt spod niezamapowanej strony to panika
  i restart konsoli. Najpierw przejscie po tablicach stron, potem odczyt.
- **Podstawa mapy bezposredniej zmienia sie przy kazdym rozruchu** (widziano
  `0xffffbbc800000000`), wiec nie wolno jej zaszywac.
- **Zapis, ktory ma przezyc wylaczenie konsoli, wymaga `fflush` i `fsync`.**
- **Odczyt kodu jadra przy wlaczonym XOM wywala konsole.** Byepervisor jest warunkiem.
- **Payloady z elfldr nie moga ladowac modulow systemowych** przez
  `sceKernelLoadStartModule`; trzeba je linkowac albo uzywac gotowego procesu.
- **Dwie kopie kstuff naraz** wchodza w kolizje; tak samo kstuff i etaHEN.
- **Nie uruchamiac Byepervisora razem z payloadami patchujacymi jadro.**

## Narzedzia i artefakty

- `tools/ftp-*.ps1` - praca z konsola przez ftpsrv (2121).
- `tools/elfldr-send.ps1` - wstrzykiwanie payloadow przez elfldr (9021) z odczytem wyjscia.
- `tools/klog-capture.ps1`, `kstuff-metrics.ps1` - log jadra (3232) i liczniki kstuff.
- `tools/a53dump/` - bezpieczny zrzut ukladu A53 (wylicza mape i sprawdza strony).
- `tools/find-sdbgp-consts.py`, `find-sdbgp-callers.py`, `find-mp40-device.py`,
  `find-mp40-struct.py` - analiza zrzutu jadra.
- `tools/make-patches.py`, `apply-patches-check.py`, `scan-module.py` - analiza modulow.
- `artifacts/kstuff-1360-ppr.elf` - nasz build kstuff z odblokowana sciezka PPR.
- `artifacts/kstuff-a53-src/` - zrodla referencyjne A53/PPR wraz z profilami do 11.40.
- `artifacts/klog-2026-10-14-ppr-mount.txt` i `...kstuff-ng-test.txt` - logi z montowania.
- `notes/INSTALATOR-1360.md` - pelny dziennik tej pracy, runda po rundzie.

## Rundy 80 do 89: mechanizm profilu PPR, pola dla 13.60, zywy odczyt kodu

**Mechanizm profilu.** Dziesiec miejsc z pola `call_va` to **nie dziesiec funkcji**,
tylko **wszystkie wywolania jednego wspolnego pomocnika**. Patcher przechwytuje kazde
miejsce, ktore go wola. Pozostale miejsca to cele skokow: `aes_site_va` prowadzi do
`aes_descriptor_va`, `sha_auth_site_va` do `sha_authenticate_va`, `dispatch_va` do
`dispatch_native_va`. Pola `precheck_va`, `dispatch_va` i `sha_auth_site_va` leza
**wewnatrz pomocnika** pod stalymi przesunieciami: `+0x68`, `+0x190`, `+0x288`.

**Wzorce `BL` nie przechodza miedzy wersjami**, bo koduja odleglosc do celu; z 15
wzorcow profilu 11.40 trafil do 13.60 tylko `precheck_stock = 0x35000abc`, bo `CBNZ`
ma male lokalne przesuniecie. Ale z wzorca `BL` da sie policzyc cel:
`cel = adres + (imm26 << 2)`.

**Pomocnik dla 13.60:** `FUN_0005c05c`, 760 B, adres A53 `0x05C05C`. Pola wyprowadzone:

```
helper_va            0x05C05C   potwierdzone
precheck_va          0x05C0C4   potwierdzone co do bajtu: CBNZ W28, +0x154
dispatch_va          0x05C1EC   potwierdzone: BL, +0x190
dispatch_native_va   0x0581A0
sha_auth_site_va     0x05C2F8   kandydat, BL pod +0x29C
sha_authenticate_va  0x0591C4   kandydat
sha_wait_idma_aes    0x057E98   kandydat, cel skoku pod +0x128
submit_idma          0x0590C8   kandydat, cel skoku pod +0x210
```

Wywolania pomocnika: dwa w `io` (`0x04E4A818`, `0x04E4BF58`) i trzynascie w `dev`
(od `0x0641ADC8` do `0x0642615C`). Profil 11.40 ma dwa w `io` i osiem w `dev`.

**Zywy odczyt kodu dziala.** Sygnatura pomocnika zostala znaleziona w pamieci
czytanej na zadanie pod `0x932C`, `0x1932C` i `0x2932C`, czyli **pod tym samym
przesunieciem w kazdym bloku 64 kB**.

**Ograniczenie, ktore trzeba znac przed kazdym testem:** polecenie odczytu widzi
**okno 64 kB i ignoruje gorne bity adresu**. Dlatego odczyt pod `0x200000` nie czyta
`0x200000`, tylko to samo okno, i dlatego **test zapisu przez odczyt kontrolny jest
niewazny**. Regiony z coredumpu pochodza z innego okna, ktore jadro przełącza samo;
**mechanizm wyboru okna nie zostal znaleziony**.

**SPROSTOWANIE z rund 90 i 91: to bylo bledne rozumowanie i nie nalezy sie nim
kierowac.** Adres **jest** honorowany. Powtarzajaca sie sygnatura co 64 kB byla
skutkiem tego, ze zawartosc pamieci A53 powtarza sie w kolejnych blokach, a nie
ignorowania adresu. Prawdziwa przyczyna rozjazdu byla inna: **stare pliki regionow
byly przesuniete o 0x6F8**, bo wycinano je z odpowiedzi bez uwzglednienia naglowkow
wynikow. Po odtworzeniu obrazu z tych naglowkow okazalo sie, ze **odczyt i obraz
zgadzaja sie co do bajtu pod `0x5C05C`**. Szczegoly w sekcji o rundach 90 i 91 wyzej.


**Rejestry `BAR2+0xf7000`, `+0xf8000`, `+0xf9000` to mapowanie bufora gospodarza**
(IOMMU, jego polowy i rozmiar), a nie wybor okna pamieci A53. Jadro ustawia je na
`0x70000000` i `0x200000` samo.

**Wartosci polecen na tej konsoli:** jadro wpisuje `0x20303002` do `BAR2+0xf6000`,
do `softc+0x164` i do drugiego kanalu `BAR2+0xfa000`, a `0x20303003` do
`softc+0x168`. Referencja dla 5.00 uzywa `0x20303000`. Poprawienie tej wartosci
**nie zmienilo** odpowiedzi urzadzenia na pakiet zapisu.

**Nastepne kroki, w kolejnosci:**

1. znalezc, co przełącza okno odczytu po stronie procesora; jadro odczytalo dziewiec
   regionow, wiec mechanizm istnieje, a rejestry okna juz wykluczone,
2. dopiero potem wiarygodnie sprawdzic, czy zapis `0x01040031` dziala,
3. zlozyc profil 13.60 z pol wyprowadzonych z pomocnika,
4. nalozyc patch i sprawdzic montowanie fPKG.

## Rundy 90 do 91: znaleziona przyczyna rozjazdu adresow, pola profilu zweryfikowane

**Stare pliki regionow byly przesuniete o 0x6F8.** Wycinane byly z odpowiedzi
mechanizmu coredumpu, a odpowiedz ma **osobny naglowek wyniku dla kazdego argumentu**,
o rozmiarze 0x28:

```
struct sdbgp_read_result {
    uint32 self_size;        /* 0x28 */
    uint32 access_and_type;
    uint64 addr;
    uint64 requested;
    uint64 transferred;
    uint32 status;
    uint32 padding;
};                            /* 0x28, a dane dopiero za nim */
```

Region czytany jednym argumentem wyszedl dobrze, ale region `io`, czytany
trzyargumentowo, rozjechal sie o 0x6F8. Dlatego adresy nie chcialy sie zgadzac
z niczym, dlatego sygnatury nie trafialy i dlatego test zapisu nie mial szans.

**Odtworzony obraz jest poprawny i zgadza sie z zywym odczytem.** Nowe narzedzie
`tools/rebuild-a53-image2.py` przechodzi odpowiedzi w zrzucie, czyta naglowki wynikow
i sklada obraz pod prawdziwymi adresami. Wynikowy obraz `<work>\a53_image\obraz_a53.bin`
ma pod `0x5C05C` te same bajty, ktore zwrocil **zywy odczyt** pod tym adresem:
`37 ff ff 17 00 20 a0 52 00 5d 00 33 4f ...`. To znaczy, ze polecenie odczytu
adresuje te sama przestrzen co obraz, a rozjazd byl wylacznie w starych plikach.

**Pola profilu po przesunieciu o -0x6F8, wszystkie zweryfikowane i potwierdzone ZYWO:**

```
helper              0x05B964   sygnatura ff 43 03 d1 fd 7b 07 a9
precheck            0x05B9CC   slowo 0x35000abc, CBNZ W28, +0x154
dispatch            0x05BAF4   BL -> 0x057AA8
dispatch_native     0x057AA8   poczatek funkcji
sha_auth_site       0x05BC00   BL -> 0x058ACC
sha_authenticate    0x058ACC   poczatek funkcji
sha_wait_idma       0x0577A0   poczatek funkcji
submit_idma         0x0589D0   poczatek funkcji
```

**Kalibracja odpowiedzi (runda 92) i potwierdzenie na zywej konsoli.** Payload
`tools/a53cal` odczytal znane miejsca i poszukal ich bajtow w calej odpowiedzi:

```
odczyt 0x05B964 (pomocnik):  znane bajty znalezione pod offsetem 0x90
odczyt 0x05B9CC (sprawdzenie): znane bajty znalezione pod offsetem 0x90
```

Czyli **offset danych w odpowiedzi to 0x90**, a **odczyt pod 0x05B9CC zwraca zywo
rozkaz `bc 0a 00 35`**, czyli `CBNZ W28, +0x154`. To potwierdza zarowno poprawione
adresy, jak i to, ze polecenie odczytu adresuje te sama przestrzen co obraz.

**Werdykt o zapisie: nie dziala.** Test na wolnym adresie `0xC3000`, z poprawnym
offsetem danych `0x90`, nie wykazal zmiany zawartosci. Procesor odpowiada na pakiet
zapisu `0x01040031` (krotka odpowiedz, rozmiar `0x60`, zrodlo MP4), a w naglowku
wyniku widnieje `przeslane 0x10`, ale **pamiec sie nie zmienia**. Wniosek: **zapis do
pamieci A53 przez skrzynke jest na 13.60 niedostepny**, a patch PPR trzeba nalozyc
inna droga, na przyklad podmieniajac obraz oprogramowania przy rozruchu.

## Runda 93: profil z odtworzonego obrazu i czego jeszcze brakuje

**Dwa miejsca z okna io sa gotowe.** W odtworzonym obrazie pomocnik wystepuje dwa
razy (`0x05B0F8` i `0x05B964`), a wolaja go dwa rozkazy `BL`:

```
BL pod 0x04A120 -> 0x05B964   slowo 0x94004611
BL pod 0x04B860 -> 0x05B964   slowo 0x94004041
```

To zgadza sie z profilem 11.40, ktory ma **dwa miejsca w io**. Adresy w oknie io
liczy sie tak: `io = 0x04e28000 + (adres - 0x28000)`, czyli nasze dwa miejsca to
`0x04E4A120` i `0x04E4B860`.

**Brakuje osmiu miejsc z okna dev** (`dev = 0x06410000 + (adres - 0x85000)`).
W odtworzonym obrazie obszar `0x85000` do `0xB6000` ma **same zera**, czyli te
regiony nie zostaly wczytane.

**Dlaczego i co zrobic:** w zrzucie jest odpowiedz, ktorej naglowki wynikow maja
rozmiar **`0x38`**, a nie `0x28`, i parser ja odrzucil. To wlasnie ta odpowiedz
zawiera regiony `0x85000` i `0xb6000`. **Nastepny krok: obsluzyc wyniki o rozmiarze
`0x38`** (odczytac ich pola pod wlasciwymi przesunieciami), odtworzyc obraz ponownie
i wtedy osiem miejsc z okna dev pojawi sie samo. Potem zostanie juz tylko zlozyc
profil i czekac na droge zapisu.

## Rundy 94 do 95: obraz kompletny, przeliczniki ustalone, profil zlozony

**Obraz jest kompletny.** Zamiast chodzic po odpowiedziach krok po kroku, skrypt
`tools/rebuild-a53-image3.py` przeszukuje caly zrzut i rozpoznaje naglowek wyniku
odczytu po spojnosci pol (`self_size == 0x28`, `transferred == requested`,
`addr + requested <= 0x100000`). Znalazl **wszystkie dziewiec** wynikow, w tym
brakujace regiony `0x85000` i `0xb6000`:

```
0x000000 + 0x1b000   0x062000 + 0x3000   0x085000 + 0x31000
0x01b000 + 0xd000    0x065000 + 0x3000   0x0b6000 + 0xa000
0x028000 + 0x3a000   0x068000 + 0x1000
0x069000 + 0x1c000
```

Razem **786432 bajty**. Obraz jest w `artifacts/a53-obraz-odtworzony.bin`.

**Przeliczniki adresow ustalone pomiarami.** Okazalo sie, ze:

- adresy w transporcie (`0x28000`, `0x85000`) to **pamiec fizyczna procesora**,
- adresy w profilu (`0x04e28000`, `0x06410000`) to **adresy widziane przez sam
  procesor A53**, czyli jego wewnetrzna mapa pamieci,
- pola `io_mapped_base`, `io_sram_base` i `dev_mapped_base` opisuja przelicznik.

Sprawdzone: odczyt pod adresami z profilu **nie zwraca** danych z tych regionow,
a mapa bezposrednia jadra pod tymi adresami zawiera **zwykle dane**, a nie pamiec A53.
Czyli to nie sa adresy fizyczne gospodarza, tylko wewnetrzna mapa procesora.

**Profil dla 13.60 zlozony** w `artifacts/kstuff-profile-1360.h`: osiem pol
potwierdzonych odczytem, kazde w postaci fizycznej i widzianej przez procesor.

**Ustalenie, ktore zmienia obraz calosci:** miejsca wywolan pomocnika sa
**dwa w oknie `io`** i **trzynascie poza oknami** (regiony `0x0` i `0x1b000`).
**W oknie `dev` nie ma ani jednego**, bo w regionie `0x85000` **nie ma kopii
pomocnika**. Profil 11.40 ma tymczasem **osiem miejsc w `dev`**. To znaczy, ze
**miedzy 11.40 a 13.60 przebudowano kod** i sciezka `dev` nie przechodzi juz przez
tego pomocnika. Portu profilu nie da sie zrobic wprost, co potwierdza wczesniejsze
podejrzenia i zamyka temat przeliczania adresow.

## Runda 96: przesuniecie 0xD80 dziala tylko wewnatrz pomocnika

**Sprawdzone na polach, ktore mam zweryfikowane odczytem.** Przeliczenie adresow
11.40 na fizyczne i dodanie `0xD80`:

```
helper      0x5ABE4 + 0xD80 = 0x5B964   ZGADZA SIE z odczytem
precheck    0x5AC4C + 0xD80 = 0x5B9CC   ZGADZA SIE z odczytem
dispatch    0x5AD74 + 0xD80 = 0x5BAF4   ZGADZA SIE z odczytem
```

Trzy z trzech, wiec **funkcja pomocnika zachowala uklad wewnetrzny**, a jej kod
przesunal sie w calosci o `0xD80`.

**Ale poza pomoctnikiem przesuniecie nie obowiazuje:**

```
sha_auth_site     0x5AE6C + 0xD80 = 0x5BBEC, a jest 0x5BC00   (roznica 0x14)
sha_authenticate  0x57DE0 + 0xD80 = 0x58B60, a jest 0x58ACC   (roznica 0x94)
submit_idma       0x559B8 + 0xD80 = 0x56738, a jest 0x589D0   (daleko)
```

Czyli **kod poza pomoctnikiem przebudowano**. To domyka temat przenoszenia profilu
przez przeliczanie adresow: dziala tylko dla tego, co lezy wewnatrz pomocnika.

**Trzy brakujace funkcje sa jednak w zasiegu.** Pomocnik sam do nich skacze:

```
pomocnik + 0x128  -> 0x057E98
pomocnik + 0x210  -> 0x0590C8
pomocnik + 0x29C  -> 0x0591C4
```

Profil potrzebuje trzech takich procedur: `submit_idma_va`,
`sha_wait_idma_aes_va` i `sha_authenticate_va`. Kolejnosc adresow w 11.40 byla
`submit (0x559B8) < sha_wait (0x57CE4) < sha_auth (0x57DE0)`, wiec przy zachowaniu
kolejnosci w 13.60 wychodzi `submit_idma = 0x057E98`, `sha_wait_idma_aes = 0x0590C8`
i `sha_authenticate = 0x0591C4`. To kandydaci do potwierdzenia analiza ich cial.

## Rundy 97 do 100: narzedzia upstream, tabele ABI, komplet pol profilu

**Znalezione publiczne narzedzia.** Repozytorium `drakmor/ppr-patch` (sklonowane do
`<work>\ppr-patch`, kluczowe pliki zabezpieczone w `artifacts/ppr-patch-upstream/`)
zawiera:

- `generate_ppr_profiles.py` - **generator profili PPR z obrazu A53**, oparty na
  sygnaturach, nie na adresach,
- `verify_ppr_profiles.py` - walidator profili,
- `PPR_READ_PATHS.md` - dokument opisujacy mechanizm patcha.

**Co potwierdzily te narzedzia, niezaleznie od moich pomiarow:**

- prawdziwa nazwa pomocnika to
  `zcnDriverAddCommandsPackageDecryptToZcnBufferAndVerifySign`,
- **wszystkie sciezki wolaja jeden wspolny pomocnik**,
- profil obejmuje jego sygnature i **dziesiec rozkazow `BL`**,
- patch wymienia **wylacznie czesc kryptograficzna jednego odczytu 64 kB pakietu**,
- argumenty ABI: zrodlo polecenia zaleznosci, powiadomienie IDMA/AES, powiadomienie
  SHA/CMAC, fizyczny adres zrodla MP4, PASID, typ szyfrowania, indeks klucza AES,
  indeks klucza SHA.

**Tabela `ABI_LAYOUTS["PPR_ABI_LATE"]` trafila w moje pomiary co do bajtu:**

```
precheck         0x68     potwierdzone odczytem z konsoli
bies_dispatch    0x190    potwierdzone odczytem z konsoli
sha_wait         0x210    potwierdzone odczytem z konsoli
precheck_normal  0x6C     policzone, rozkaz 0x37080088
precheck_special 0xA0     policzone, rozkaz 0xB9406BA9
common_return    0x2BC    policzone, rozkaz 0x2A1F03E0
submit_call      0x324    policzone, rozkaz 0xAA0503FC
```

**Sygnatura pomocnika w 13.60 nie pasuje do zadnego z trzech znanych ABI** (ramka
stosu `0x1D0` wobec `0xD0` i mniejszych), ale **uklad pol jest ten sam**. To czwarty,
nieudokumentowany wariant ABI o znanym ukladzie.

**Skoki pomocnika, policzone wylacznie na odtworzonym obrazie:**

```
+0x128  BL -> 0x0577A0   776 B   submit_idma_va
+0x190  BL -> 0x057AA8   900 B   dispatch_native_va, potwierdzone tabela ABI
+0x210  BL -> 0x0589D0   252 B   sha_wait_idma_aes_va, potwierdzone tabela ABI
+0x29C  BL -> 0x058ACC   876 B   sha_authenticate_va
```

**Komplet osmioru pol funkcyjnych profilu dla 13.60:**

```
helper_va             0x05B964   potwierdzone odczytem z konsoli
precheck_va           0x05B9CC   potwierdzone odczytem, slowo 0x35000ABC
dispatch_va           0x05BAF4   potwierdzone odczytem
dispatch_native_va    0x057AA8   przesuniecie +0x190 z tabeli ABI
sha_auth_site_va      0x05BC00   skok pod +0x29C
sha_authenticate_va   0x058ACC   cel tego skoku
sha_wait_idma_aes_va  0x0589D0   przesuniecie +0x210 z tabeli ABI
submit_idma_va        0x0577A0   skok pod +0x128
```

Kazde pole trzeba jeszcze przeliczyc na postac widziana przez procesor wzorem
`io = 0x04e28000 + (adres - 0x28000)`.

**Stan publiczny, sprawdzony repozytoriami, nie opinia modelu:** 55 profili
konczacych sie na 11.40, zadnych zrzutow z 12.x ani 13.60, zadnego opisu polecenia
zapisu `0x01040031`. Jestesmy na froncie.

**Co zostaje, w kolejnosci:**

1. **Deskryptory AES i trybu jawnego.** Generator podaje sposob ich znalezienia:
   kazdy wywolujacy pomocnika **musi publikowac pola pod `SP+0x18` (AES) i `SP+0x20`
   (SHA)**. To jest gotowa recepta na `aes_site_va` i `sha_auth_site_va`.
2. **Miejsca na wstrzykiwany kod** - wystarczy wolny obszar SRAM, a obraz pokazuje,
   ze od `0x90000` do `0xC0000` sa same zera.
3. **Droga zapisu** - jedyna prawdziwa przeszkoda. Research potwierdza, ze istnieje
   wylacznie przy rozruchu konsoli, przez rejestry MMIO i zwolnienie wektorow resetu,
   czyli **zanim jakikolwiek nasz kod sie uruchomi**.

## Rundy 101 do 103: odczyt zbiorczy dziala, adresy potwierdzone na zywo

**To najwazniejsze ustalenie calej pracy i trzeba je znac przed kazdym testem.**

**Pole dostepu w pakiecie odczytu musi byc stale rowne `1`**, dokladnie jak w pakietach
jadra. Liczone z adresu i rozmiaru dawalo `6` i wtedy procesor zwracal **ciagle to samo
okno pamieci**, niezaleznie od podanego adresu. To bylo zrodlem wszystkich nieporozumien
z adresami w poprzednich rundach: wyniki skanow, ktore mowily o sygnaturze pod
`0x932C` w kazdym bloku 64 kB, pochodzily z tego zablokowanego okna i byly bezwartosciowe.

**Odczyt zbiorczy: jedno polecenie, wiele argumentow.** Uklad pakietu:

```
0x00 naglowek deci5s_hdr (0x28), potem dcmp, code, numer, liczba polecen
0x40 polecenie: self 0x20, total, type 0x01040021, ..., n_args
0x60 argumenty po 0x18: self 0x18, (typ pamieci << 8) | 1, adres, rozmiar
razem: 0x40 + 0x20 + n * 0x18
```

Odpowiedz zawiera po jednym naglowku wyniku na argument, o rozmiarze 0x28:

```
self 0x28, slowo, adres, zadane, przeslane, status
```

a dane leza zaraz za naglowkiem. Przy trzech argumentach odpowiedz ma 0x140 bajtow.

**Potwierdzone odczytem z zywej konsoli 15 pazdziernika 2026:**

```
odczyt 0x5B964 -> ff 43 03 d1 fd 7b 07 a9 fc 6f 08 a9 ...   sygnatura pomocnika
odczyt 0x28000 -> 1b 00 01 00 10 00 01 00 ...               zgodne z obrazem
odczyt zbiorczy na 0x190, 0x961C i 0x28000 -> trzy rozne wyniki, kazdy z wlasnym
                                                naglowkiem i wlasnymi danymi
```

**Wniosek: umiemy czytac dowolny fragment pamieci procesora A53, zbiorczo i pod
prawdziwym adresem.** Adresy wyprowadzone z odtworzonego obrazu sa prawdziwe, co
potwierdza zarowno sygnatura pomocnika pod `0x5B964`, jak i naglowek regionu `io`
pod `0x28000`.

**Co to otwiera:** mozna teraz zrzucic dowolny obszar pamieci A53, w tym ten, w ktorym
leza prawdziwe miejsca profilu, i poszukac w nim funkcji publikujacych pola pod
`SP+0x18` i `SP+0x20` - czyli prawdziwych miejsc `call_va`. W obecnym obrazie ich nie
ma, bo zrzut objal tylko dziewiec regionow wskazanych przez jadro.

## Runda 107: pelny zrzut 256 MB i okno 256 kB

**Zrzut zakonczony:** 256 MB, 1024 porcje po 256 kB, **zero bledow**. Plik
`<work>\a53_live.bin`, obraz bez naglowkow odpowiedzi, wiec offset w pliku to adres.

**Ale zrzut nie jest obrazem 256 MB pamieci.** Przeszukanie wykazalo:

```
sygnatura pomocnika:  3072 wystapienia   (3 na kazde 256 kB)
baner cex(:           1024 wystapienia   (1 na kazde 256 kB)
rozkaz CBNZ W28:         0 wystapien
```

Bloki po 256 kB sa **identyczne** (roznia sie jednym fragmentem czterech kilobajtow).
Czyli **odczyt widzi jedno okno 256 kB, powtarzane w kolko**, a gorne bity adresu sa
odrzucane.

**Unikalna zawartosc to 256 kB**, wyciagnieta do `<work>\a53_window.bin`:
baner pod `0x228`, trzy kopie pomocnika pod `0x96B4`, `0xC6FC` i `0x24BF4`, brak
rozkazu `CBNZ W28`.

**A teraz najwazniejsze: to okno zmienia sie miedzy uruchomieniami.** W jednym
uruchomieniu odczyt pod `0x5B964` zwracal sygnature pomocnika, a w zrzucie pomocnik
jest pod `0x96B4`. Przy oknie 256 kB adres `0x5B964` sprowadza sie do `0x1B964`
i tam sygnatury nie ma. To znaczy, ze **procesor wystawia rozne banki pamieci**,
a wybor banku zalezy od stanu, ktorego nie ustawiamy.

**Wniosek dla calej pracy:** sprzecznosci adresowe z poprzednich sesji braly sie
wlasnie z tego. Kazde uruchomienie pokazywalo inny bank, a ja wyciagalem z tego wnioski
o stalych adresach. **Odczyt podany w rundach 101-103 byl z jednego banku i nie da sie
na nim zbudowac profilu.**

**Co trzeba ustalic, zeby isc dalej:** jak wybierany jest bank. Kandydaci: pole
`mem_type` w pakiecie, rejestry okna `BAR2+0xf7000` do `+0xf9000`, albo pola kontekstu
sterownika zmieniane przed kazdym odczytem. Jadro odczytalo dziewiec regionow o roznej
zawartosci, wiec **musi** przełączac bank, a my robimy to samo polecenie bez tego
przelaczenia.

## Runda 108: SPROSTOWANIE - lustra nie ma, to byl rozmiar odczytu

**Poprzednia runda byla bledna i nie nalezy sie nia kierowac.** Zrzut 256 MB powstal
porcjami po 256 kB i wykazywal powtarzanie co 256 kB. Wyciagnalem z tego wniosek
o lustrzanej pamieci i o roznych bankach. **To nieprawda.**

**Pomiar rozstrzygajacy** (odczyt po 32 bajty, w jednym uruchomieniu):

```
0x496B4:  e3 03 13 2a 55 85 9f 1a 43 05 00 37 ...      rozne od siebie
0x896B4:  19 38 f4 24 e8 b1 9c 33 34 27 39 58 ...
0x5B964:  ff 43 03 d1 fd 7b 07 a9 fc 6f 08 a9 ...      sygnatura pomocnika
```

**Adresy oddalone o wielokrotnosc 256 kB zwracaja rozne dane, wiec pamiec nie jest
lustrzana.** Prawdziwa przyczyna jest inna i wazna na przyszlosc:

**Urzadzenie wyrownuje odczyt do jego rozmiaru.** Odczyt o rozmiarze 256 kB zwracal
ten sam blok wyrownany do 256 kB niezaleznie od podanego adresu, i stad wzielo sie
pozorne powtarzanie. Dlatego:

- **zrzut 256 MB (`<work>\a53_live.bin`) jest bezwartosciowy** i nie wolno na nim
  opierac zadnych wnioskow,
- **odczyty male, rzedu kilkudziesieciu bajtow, sa poprawne i powtarzalne**,
- **pomocnik jest pod `0x5B964`** - potwierdzone dwoma niezaleznymi odczytami
  w roznych uruchomieniach, wiec adres jest prawdziwy i stabilny,
- pole `cex(` pod `0x228` **nie** wystapilo, wiec i to bylo artefaktem zrzutu.

**Wniosek: adresy wyprowadzone z odtworzonego obrazu i potwierdzone malymi odczytami
sa prawdziwe.** Profil nie wymaga przerobki. Zrzutu 256 MB nie uzywamy.

## Runda 109: pakiet odczytu jadra, dokladnie taki, jakiego uzywa

**Z dekompilacji transportu jadra (`<work>\decomp_dump.txt`, okolice linii 195-250)
odczytalem, jak jadro buduje polecenie odczytu. To jest wzorzec, ktory trzeba nasladowac:**

```c
*(u64*)(+0x00) = 0x2873354450;            /* magic + self_size 0x28 */
*(u64*)(+0x08) = 0x80ff018000000028;      /* rozmiar i zrodlo */
*(u64*)(+0x10) = 0x2000020180ff0201;      /* cel i protokol */
*(u64*)(+0x20) = rdtsc();                 /* znacznik czasu */
*(u64*)(+0x28) = 0x1800000018;            /* dcmp i code */
*(u32*)(+0x40) = 0x20;                    /* self_size polecenia */
*(u64*)(+0x48) = 0x1040021;               /* typ: odczyt pamieci */
*(u32*)(+0x44) = 0x68;                    /* total_size polecenia */
*(u32*)(+0x5c) = 3;                       /* LICZBA ARGUMENTOW */
*(u64*)(+0x60) = 0x201000100000018;       /* argument: self 0x18, slowo 0x02010001 */
*(u64*)(+0x68) = 0x28000;                 /* adres */
*(u64*)(+0x70) = 0x3a000;                 /* rozmiar */
*(u64*)(+0x78) = 0x201000100000018;       /* drugi argument */
*(u64*)(+0x80) = 0x65000;                 /* adres */
*(u64*)(+0x88) = 0x3000;                  /* rozmiar */
*(u64*)(+0x90) = 0x201000100000018;       /* trzeci argument */
*(u64*)(+0x98) = 0x69000;                 /* adres */
*(u64*)(+0xa0) = 0x1c000;                 /* rozmiar */
```

**Co z tego wynika, punkt po punkcie:**

- **slowo argumentu to `0x02010001`**: typ pamieci `0x020100` i dostep `1`. Dokladnie to,
  co ustalilem pomiarem.
- **`n_args = 3`** - jadro czyta trzy regiony **jednym pakietem**, nie pojedynczo.
- **rozmiary to `0x3a000`, `0x3000`, `0x1c000`** - **zadna nie jest potega dwojki**,
  i to jest odpowiedz na zagadke z poprzedniej rundy: odczyt jest wyrownywany do
  swojego rozmiaru, a jadro celowo uzywa rozmiarow niebedacych potegami dwojki.
- `command.total_size = 0x68` to dokladnie `0x20 + 3 * 0x18`.

**Wniosek praktyczny:** zeby czytac poprawnie, trzeba uzywac **rozmiarow takich jak
jadro**, a nie okraglych, oraz czytac **zbiorczo**. Wtedy odczyty beda prawdziwe,
a nie wyrownywane.

## Runda 111: sterownik jadra NIE MA polecenia zapisu pamieci A53

**Caly slownik polecen SDBGP, jakich uzywa sterownik jadra** (policzony z dekompilacji
`<work>\decomp_dump.txt`):

```
0x1040021   odczyt pamieci A53            8 wystapien
0x1050020   konfiguracja                  4 wystapienia
0x1050030   konfiguracja, wariant +0x10   4 wystapienia
0x1080001   4 wystapienia
0x1200021   4 wystapienia
0x1010010   2 wystapienia
0x1180101   2 wystapienia
0x1190211   2 wystapienia
0x1190221   2 wystapienia
0x1200113   2 wystapienia
0x1000000, 0x1200000, 0x1400000  po 1
```

**Typu zapisu pamieci `0x1040031` nie ma ani razu.** Sterownik jadra **nigdy** nie
wysyla zapisu do pamieci procesora A53. Ma odczyt i konfiguracje rejestrow, i to
wszystko.

**Polecenie konfiguracji to tablica 32-bitowych przesuniec** (na przyklad `0x3a000000`,
`0x3c000010`, `0x3d2900c0`), czyli lista rejestrow do ustawienia. Widac pare
`0x1050020` i `0x1050030` rozniaca sie o `0x10`, dokladnie tak jak odczyt `0x1040021`
i hipotetyczny zapis `0x1040031`.

**Wniosek, ktory zamyka kwestie drogi zapisu:** droga zapisu pamieci A53 **nie istnieje
w sterowniku jadra**. To zgadza sie z researchem: dane trafiaja do pamieci procesora
wylacznie przy rozruchu konsoli, mechanizmem, do ktorego nasz kod nie ma dostepu.

**Co to znaczy dla patcha PPR:** nie da sie nalozyc patcha przez mailbox, bo mailbox
nie ma takiego polecenia, a jadro go nie uzywa. Patch wymagalby albo wstrzykniecia
na etapie rozruchu, albo znalezienia innej drogi zapisu, ktorej na razie nie znamy.

## Runda 112: dokladny warunek generatora, dwa miejsca wywolan, profil zgodny z upstream

**Bledy w moich wlasnych narzedziach, znalezione i naprawione:**

1. **Szukalem zapisow 64-bitowych** pod `SP+0x18` i `SP+0x20`, a generator upstream
   wymaga **32-bitowych**:
   ```python
   def is_str_w_to_sp(word, byte_offset):
       return word & 0xFFC003E0 == 0xB90003E0 and ((word >> 10) & 0xFFF) * 4 == byte_offset
   ```
2. **Profil mial zamienione pola** `sha_wait_idma_aes_va` i `submit_idma_va`.
3. **Profil uzywal nazw pol, ktorych upstream nie zna.** Prawdziwa struktura
   `struct ppr_profile` (ppr_patch.c, linia 54) ma pola: `abi`, `merged_text`,
   `cave_in_dev`, `io_file_size`, `io_mapped_size`, `dev_file_size`, `dev_mapped_size`,
   `runtime_cave_va`, `plaintext_cave_va`, `precheck_normal_va`, `precheck_special_va`,
   `common_error_va`, `aes_descriptor_va`, `plaintext_descriptor_va`,
   `plaintext_direct_va`, `plaintext_idma_va`, `common_return_va`, `aes_site_va[2]`,
   `aes_site_stock[2]`, `sha_auth_site_stock`, `dispatch_stock`.
   `PPR_CALL_COUNT` wynosi 10, `PPR_AES_SITE_COUNT` wynosi 2.

**Wynik dokladnego warunku: miejsca wywolan w 13.60 sa DWA, nie dziesiec.**

```
BL 0x04A120  widziany 0x04E4A120  rozkaz 0x94004611
BL 0x04B860  widziany 0x04E4B860  rozkaz 0x94004041
```

Sprawdzone rachunkiem: `0x5B964 - 0x4A120 = 0x11844`, przez cztery daje `0x4611`.
`0x5B964 - 0x4B860 = 0x10104`, przez cztery daje `0x4041`. Zgadza sie co do cyfry.
Sciezka z okna `dev` przestala wolac wspolnego pomocnika, dlatego jest dwoch, a nie
dziesieciu jak w 11.40.

**Wzorzec profilu 11.40 potwierdza moje wyprowadzenia** (`ppr_profiles.inc`, wpis 11.40):

```
precheck_va      = helper + 0x68     tabela ABI mowi 0x68    zgodne
dispatch_va      = helper + 0x190    tabela ABI mowi 0x190   zgodne
common_return_va = helper + 0x2BC    tabela ABI mowi 0x2BC   zgodne
sha_auth_site_va = helper + 0x288    u mnie +0x29C, ta sama struktura
dispatch_stock rozkodowany daje dokladnie dispatch_native_va
```

**Plik `artifacts/kstuff-profile-1360.h` przepisany** na prawdziwe nazwy pol, z zamienionymi
polami poprawionymi i z jawnym wykazem pol niewypelnionych, ktorych nie wolno zgadywac:
`io_file_size`, `io_mapped_size`, `dev_file_size`, `dev_mapped_size`,
`runtime_cave_va`, `plaintext_cave_va`, `aes_descriptor_va`, `plaintext_descriptor_va`,
`plaintext_direct_va`, `plaintext_idma_va`, `common_error_va`, `aes_site_va[]`,
`merged_text`, `cave_in_dev`.

**Jaskinia:** w 11.40 lezy pod `io + 0x34F00`, przy rozmiarze okna `0x35000`. W naszym
obrazie 13.60 okno `io` jest wypelnione po `0x39FFF`, wiec **wolnego miejsca na koncu
okna nie ma** i polozenia jaskini nie ustalam bez dalszych danych.

## Runda 113: deskryptory to adresy KODU, nie struktury danych

**Sprawdzone w obrazie.** W profilu 11.40 pola `aes_descriptor_va` i
`plaintext_descriptor_va` wskazuja na `io + 0x2E04` i `io + 0x2FD0`, czyli **w okno
`io`**. W naszym obrazie 13.60 pod tymi offsetami leza **rozkazy**, nie dane:

```
io + 0x02E04:  0a 69 69 38 4a 01 0b 2a 0a 69 29 38 c0 03 5f d6 ...
io + 0x02FD0:  ec 03 05 aa 08 51 09 aa 49 0c 40 39 0d 01 a0 92 ...
```

**Wniosek: te cztery pola (`aes_descriptor_va`, `plaintext_descriptor_va`,
`plaintext_direct_va`, `plaintext_idma_va`) to adresy fragmentow KODU, ktore buduja
deskryptor**, a nie gotowe struktury w pamieci. Szukanie ich jako danych jest bledna
droga. Trzeba szukac sciezek kodu.

**Przesuniecie pomocnika miedzy wersjami:** `0x04e5b964 - 0x04e5abe4 = 0xD80`, czyli
dokladnie to samo `0xD80`, ktore zmierzylem wczesniej wewnatrz pomocnika. Ta liczba
jest wiec prawdziwa, ale dziala **tylko** dla elementow, ktore przesunely sie razem
z pomoca.

**Polozenie pol z profilu 11.40 wzgledem jego pomocnika** (`helper = io + 0x32BE4`):

```
aes_descriptor_va        io + 0x02E04   helper - 0x3DE0
plaintext_descriptor_va  io + 0x02FD0   helper - 0x3C14
plaintext_idma_va        io + 0x02F86C  helper - 0x3378
plaintext_direct_va      io + 0x033A10  helper + 0x0E2C
```

**To sa hipotezy, nie ustalenia.** Wiem juz, ze przesuniecie wzgledne nie utrzymuje sie
poza pomoca (dla `sha_auth_site` roznica wynosi `+0x14`, nie `0xD80`), wiec nie wolno
tych czterech adresow wyliczac przez dodanie `0xD80` ani przez zachowanie odleglosci
od pomocnika. Kazdy trzeba znalezc osobno i potwierdzic odczytem z konsoli.

**Co jest potrzebne, zeby je znalezc:** albo obraz 11.40 do porownania sygnatur kodu,
albo analiza przeplywu w 13.60 w miejscu, gdzie pomocnik rozgalezia sie na sciezke
AES i na sciezke trybu jawnego.

## Runda 114: rozkodowany kod obu miejsc wywolan PPR

Tabela ABI z `PPR_READ_PATHS.md` mowi, ze wywolujacy publikuje `[sp+0x10]` typ
szyfrowania, `[sp+0x18]` indeks klucza AES i `[sp+0x20]` indeks klucza SHA.
Rozkodowalem oba miejsca i **uklad zgadza sie co do offsetu**:

```
miejsce 0x04A120:
  0x04A0E0  MOVZ W8, #0x16E0
  0x04A0F4  STR W31, [SP, #0x10]    typ szyfrowania = 0, W31 to rejestr zerowy
  0x04A0F8  STR W8,  [SP, #0x20]    0x16E0
  0x04A0FC  LDR W8, [X31, #0x188]
  0x04A10C  STR W8,  [SP, #0x18]    wartosc z ramki
  0x04A110  LDR W8, [X31, #0x128]   argument a8, PASID
  0x04A120  BL 0x05B964             wejscie do pomocnika

miejsce 0x04B860:
  0x04B824  MOVZ W9, #0x16E0
  0x04B848  STR W31, [SP, #0x10]    typ szyfrowania = 0
  0x04B850  STR W9,  [SP, #0x20]    0x16E0
  0x04B854  LDR W9, [X31, #0x1C0]
  0x04B85C  STR W9,  [SP, #0x18]    wartosc z ramki
  0x04B860  BL 0x05B964
```

**Wnioski:**

- **oba miejsca to prawdziwe wejscia profilu**, potwierdzone ukladem argumentow,
- **typ szyfrowania jest zerem w obu**, wiec o trybie jawnym nie decyduje ta wartosc
  po stronie wywolujacego,
- oba podaja te sama wartosc `0x16E0` pod `SP+0x20`,
- indeks klucza AES pochodzi z ramki stosu, wiec jest wyliczany wyzej w sterowniku.

**To jest punkt zaczepienia do szukania sciezki trybu jawnego:** skoro wywolujacy
zachowuje sie identycznie, przelaczenie musi byc **wewnatrz pomocnika albo w jego
podwykonawcach**, czyli tam, gdzie trzeba szukac `aes_descriptor_va`,
`plaintext_descriptor_va`, `plaintext_direct_va` i `plaintext_idma_va`.

## Runda 115: PROFIL KOMPLETNY, 24 z 24 sprawdzen generatora przechodzi

**To jest kamien milowy calej pracy.** Profil dla 13.60 ma teraz wszystkie pola
funkcyjne wyznaczone i **kazde przechodzi sprawdzenie wedlug regul publicznego
generatora**, a nie wedlug mojego wlasnego kryterium.

Skrypt `tools/check-profile-1360.py` sprawdza 24 reguly i wszystkie przechodza:

```
[PASS] lancuch danych pomocnika            5 slow pod stalymi przesunieciami
[PASS] precheck_stock                      slowo 35000ABC
[PASS] common_error z rozkazu precheck     cel 0x05BB20
[PASS] dispatch_stock                      slowo 97FFEFED
[PASS] dispatch_va prowadzi do dispatch_native
[PASS] sygnatura ukladu rozgalezienia      B9406BBB pod +0x40
[PASS] sygnatury ustawienia miejsc AES     4 z 4 i 3 z 3
[PASS] oba miejsca AES wolaja deskryptor AES
[PASS] sygnatura deskryptora AES           40 B, jedyne wystapienie w obrazie
[PASS] sygnatura deskryptora trybu jawnego 48 B, jedyne wystapienie
[PASS] sygnatura producenta trybu jawnego  48 B
[PASS] producent wybiera silnik 5          slowo 528000A5
[PASS] producent wola deskryptor trybu jawnego
[PASS] producent wola zlecenie
[PASS] merged_text = 0                     sygnatura zakonczenia pod +0x158
[PASS] sygnatura producenta przez IDMA     28 B
[PASS] sygnatura zlecenia                  12 B
[PASS] sha_authenticate to jedyny skok w zakresie
[PASS] miejsce uwierzytelnienia wola sha_authenticate
[PASS] sha_wait pod helper + 0x210
[PASS] miejsca wywolan publikuja pola AES i SHA   2 z 2
[PASS] slowa miejsc wywolan                94004611, 94004041
[PASS] oba miejsca wolaja pomocnika        cel 0x05B964
[PASS] precheck_normal, precheck_special, common_return z tabeli ABI
```

**Metoda, ktora doprowadzila do celu.** Generator nie szuka adresow, tylko sygnatur
i regul strukturalnych. Zastosowalem je po kolei:

- `submit_idma` to **cel skoku** w funkcji rozgalezienia, a nie skok pomocnika.
  Znaleziony drugi raz przez `plaintext_direct + 0x178`, co potwierdza oba.
- `plaintext_idma` to **cel skoku pod `wolajacy_sha_wait - 0x18`**, gdzie `sha_wait`
  ma dwoch wolajacych: miejsce w pomocniku i producenta trybu jawnego.
- `plaintext_descriptor` to **cel skoku pod `plaintext_direct + 0x80`**.
- `aes_site_va` to **skoki w funkcji rozgalezienia** prowadzace do deskryptora AES,
  a nie miejsca w pomocniku. W 11.40 potwierdza to arytmetyka: `dispatch_native
  + 0x15C` i `+ 0x284` daja dokladnie `aes_site_va` z profilu 11.40.
- `common_error` to **cel rozkazu precheck** (`CBNZ W28, +0x154`).

**Pola wyprowadzone, nie zmierzone:** rozmiary segmentow i polozenie jaskini.
Jadro zrzuca pamiec A53 dziewiecioma regionami o granicach zgodnych z ukladem
segmentow: `0x28000 + 0x3A000` dla io i `0x85000 + 0x31000` dla dev. W profilu 11.40
rozmiar pliku jest mniejszy od odwzorowanego o `0x100`, a jaskinia lezy pod
`mapped_size - 0x100`. Przyjete: `io_mapped_size 0x3A000`, `io_file_size 0x39F00`,
`runtime_cave_va 0x04E61F00`, `plaintext_cave_va 0x04E61F50`.

**Poprawiony blad rachunkowy:** `sha_auth_site_stock` to `0x97FFF3B3`, nie
`0x94000C4D`. Rozkodowanie jest poprawne w obie strony, ale zapisalem zly znak.

**Nieudowodnione: `dev_file_size`.** Generator uzywa go tylko do sprawdzenia, czy
jaskinia miesci sie w segmencie dev, a jaskinia jest w io, wiec nie wplywa na patch.

**Sygnatura uwolnienia SHA nie wystepuje w obrazie w ogole**, czyli wnętrze
`sha_authenticate` zostalo w 13.60 przepisane. Adres pozostaje poprawny, bo wyznacza
go regula strukturalna.

## Runda 117: segment dev lezy w pamieci GOSPODARZA, nie w SRAM

**To jest najwazniejsze ustalenie od czasu profilu i tlumaczy brakujace osiem miejsc.**

Patch mapuje segmenty dwiema roznymi drogami (`ppr_patch.c`):

```c
static int ppr_map_sram(const struct ppr_layout_record *s, uint64_t va, ...) {
    ...
    *pa = s->sram_base + (va - s->mapped_base);      /* io: pamiec SRAM procesora */
}
static int ppr_map_g6(const struct ppr_layout_record *s, uint64_t va, ...) {
    ...
    *pa = s->g6_base + (va - s->mapped_base);        /* dev: pamiec GOSPODARZA */
}
```

A miejsca wywolan dzieli na sztywno:

```c
const struct ppr_layout_record *segment = !p->merged_text && i < 2 ? &io : &dev;
int mapped = !p->merged_text && i < 2
    ? ppr_map_sram(segment, p->call_va[i], 4, &resolved->site[i])
    : ppr_map_g6(segment, p->call_va[i], 4, &resolved->site[i]);
```

**Czyli profil MUSI miec dwa miejsca w `io` i osiem w `dev`**, a `dev` nie jest
w pamieci SRAM procesora, tylko za oknem `g6`, ktore mapuje pamiec gospodarza.

**Dlatego w moim zrzucie SRAM nie ma tych osmiu miejsc i nigdy byc nie moglo.**
Zrzut objal pamiec A53 (0x0 do 0xC0000). Segment `dev` (adresy widziane przez procesor
od `0x06410000`) jest widokiem na pamiec gospodarza, a nie na SRAM. Moje wczesniejsze
poszukiwania w regionie `0x85000` byly szukaniem w zlym miejscu.

**Kontrola na profilu 11.40, ktora to potwierdza:** rozkodowanie osmego miejsca
`0x06413d2c` o slowie `0x97a91bae` daje cel `0x04e5abe4`, czyli dokladnie `helper_va`
z profilu 11.40. Kod z pamieci gospodarza wola pomocnika z pamieci SRAM, wiec oba
segmenty sa w tej samej przestrzeni adresowej procesora, ale podlozone rozna pamiecia.

**Skad wziac brakujace adresy: sam patch mowi gdzie.** `PPR_PATCH_LAYOUT_PA = 0x887F0000`
to fizyczny adres w pamieci gospodarza, pod ktorym PSP sklada uklad segmentow:

```
naglowek 0x148 B:  liczba segmentow pod +0x0c
                   indeks io pod +0x54, indeks dev pod +0x74
32 rekordy po 0x50 B:
   +0x00 id, +0x04 flagi, +0x08 g6_base, +0x10 g6_size,
   +0x18 sram_base, +0x20 sram_size, +0x30 mapped_base,
   +0x40 mapped_size, +0x48 name_va
```

**`g6_base` to prawdziwy adres fizyczny segmentu `dev` w pamieci gospodarza.**

**Napisane narzedzie:** `tools/a53layout/a53layout.c`, zbudowane do
`artifacts/a53layout.elf` (suma `ccb7f9c99c1abbd625857550b3702ed8bb07b80d919c59c6a5e28037c8a04cee`).
Czyta uklad spod `0x887F0000`, wypisuje kazdy segment z rozmiarami `g6`, `sram`
i widzianym, a nastepnie zrzuca caly segment `dev` z pamieci gospodarza do
`/data/a53_dev.bin`. Log do `/data/a53layout.txt`.

**Co to daje, gdy uruchomimy to na konsoli:**

1. **Dokladne rozmiary segmentow** zamiast wyprowadzanych: `io_mapped_size`,
   `io_file_size`, `dev_mapped_size`, `dev_file_size` oraz polozenie jaskini
   (`mapped_size - 0x100`), czyli pola, ktore dotad byly zgadywane.
2. **Zawartosc segmentu `dev`**, a w niej osiem brakujacych miejsc wywolan, ktore
   domkna profil do wymaganych dziesieciu i pozwola zbudowac patch, ktory patch
   upstream przyjmie bez zadnych zmian w jego kodzie.

**Wniosek o kolejnosci prac:** bez tego zrzutu patch nie ma jak dzialac, bo odrzuci
profil przy trzecim miejscu wywolan. To jest teraz pierwsza rzecz do zrobienia na
konsoli, przed testem zapisu.

## Runda 120: czego patch wymaga od profilu, pole po polu

**Patch porownuje profil z ukladem segmentow odczytanym w czasie dzialania.** Jesli
cokolwiek sie nie zgadza, odmawia pracy i wypisuje `PPR layout record mismatch`.
Warunki sa nastepujace (`ppr_patch.c`, petla po rekordach):

```
io:  flagi po odrzuceniu bitow 16 i 17 rowne 0x00000001
     g6_base != 0 i wyrownane do 0x1000
     g6_size    == p->io_file_size        <- UWAGA: to jest g6_size, nie rozmiar pliku
     sram_base  == p->io_sram_base
     sram_size  >= p->io_mapped_size
     mapped_base == p->io_mapped_base
     mapped_size == p->io_mapped_size

dev: flagi rowne 0x00000001 albo 0x00000011
     g6_base != 0 i wyrownane do 0x1000
     g6_size    == p->dev_file_size
     sram_base  == 0  ORAZ  sram_size == 0   <- dev NIE ma podkladu w SRAM
     mapped_base == p->dev_mapped_base
     mapped_size == p->dev_mapped_size
```

**Dwa wnioski, ktore prostuja moje wczesniejsze wyprowadzenia:**

1. **`io_file_size` i `dev_file_size` to pole `g6_size` z ukladu**, a nie rozmiar pliku
   mniejszy o `0x100`. Moje wyprowadzenie `0x39F00` bylo wiec zle i **nie da sie go
   zgadnac**: wartosc trzeba odczytac z ukladu. To potwierdza, ze zrzut `a53layout`
   jest obowiazkowy, a nie wygodny.
2. **`dev` nie ma podkladu w SRAM** (`sram_base` i `sram_size` rowne zero), co niezaleznie
   potwierdza, ze segment `dev` lezy w pamieci gospodarza.

**Rozroznienie io od dev** nie opiera sie na indeksie z naglowka, tylko na tym, ze
`dev` ma zerowy podklad SRAM. Finalizer wybiera rekordy ta sama regula, ktorej uzywa
patch, i dodatkowo wypisuje indeksy z naglowka do porownania.

**Lancuch od zrzutu do patcha jest gotowy i przetestowany bez konsoli.**
`tools/test-apply-dev-dump.py` buduje sztuczny uklad i sztuczny segment `dev` z osmiorna
skokami, przepuszcza je przez `apply-dev-dump.py`, a `finalize-profile-1360.py` sklada
z tego profil z dziesiecioma miejscami. Wygenerowany profil **kompiluje sie z `-Werror`**
wobec prawdziwej struktury upstream.

## Runda 121: pozycja danych w odpowiedzi zalezy od rozmiaru odczytu

**Zrzut 256 MB nie byl smieciem, tylko przesunietym obrazem.** Porownalem jego okno
z obrazem z odczytow jadra i okazalo sie, ze to **ten sam obraz SRAM, przesuniety
równo o `0xFB` bajtow**:

```
okno 0x228: cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358
obraz 0x12D: ten sam napis
okno 0x44E5 -> obraz 0x43EA
okno 0x3BCF -> obraz 0x3AD4
```

**Wniosek: offset danych w odpowiedzi zalezy od rozmiaru odczytu.** Dla 32 bajtow
jest to `0x90`, a dla odczytu 256 kB az `0x18B`. To wyjasnia, dlaczego zrzut wygladal
na bezsensowny: czytalem dane spod zlego offsetu.

**Drugi wniosek: duze odczyty zwracaja staly blok.** Wszystkie 1024 porcje zrzutu
zwrocily zawartosc **SRAM od 0 do 0x40000**, niezaleznie od podanego adresu. To
potwierdza regule: czytac tylko malymi porcjami.

**Trzeci wniosek, praktyczny: offsetu nie wolno przyjmowac na stale.** Narzedzie
`a53layout` ma teraz **samokalibracje**: czyta znany adres `0x28000` (tam w obrazie
lezy `1b 00 01 00 10 00 01 00 ...`, potwierdzone odczytem z konsoli), szuka tych
bajtow w odpowiedzi i uzywa znalezionego offsetu do wszystkich wlasciwych odczytow.
Log wypisuje zmierzony offset, wiec widac, jaka wartosc zostala uzyta.

Wersja: `artifacts/a53layout.elf`, suma
`05090063f02e563616fb088d61b49c1562242842f3461e0ad8a1ff14a44f88bd`.

## Runda 123: rozmiar segmentu dev jest znacznie wiekszy, niz zakladalem

**Policzylem wystapienia adresow z kazdego segmentu w obrazie SRAM.** Przy
rownomiernym rozkladzie przypadkowemu trafieniu odpowiada ulamek jednego wystapienia
na taki zakres, wiec kazde trafienie jest prawdziwym adresem uzytym w danych:

```
042xxxxx        237 wystapien, od 0x04200404 do 0x042C0B02
04E2xxxx io      13 wystapien, od 0x04E20CA0 do 0x04E2F784
04E4-5   io      11 wystapien, od 0x04E4252E do 0x04E5DD00
0641-66  dev     86 wystapien, od 0x06400EB8 do 0x066DE429
```

**Segment `dev` siega co najmniej `0x06410000 + 0x2CE429`, czyli prawie trzech
megabajtow**, a nie `0x31000`, jak przyjmowalem.

**Skad wzielo sie moje bledne zalozenie:** przyjalem, ze region SRAM
`[0x85000, 0xB6000)` z listy odczytow jadra to segment `dev`, bo zgadzal sie rozmiar
`0x31000`. To nieprawda: **ten region SRAM to nie segment `dev`**. `dev` lezy
w pamieci gospodarza za oknem `g6` i jest znacznie wiekszy.

**Dlaczego to nie psuje profilu:** finalizer **bierze wszystkie rozmiary z ukladu**,
a nie z moich wyprowadzen, wiec bledne zalozenie nie wchodzi do profilu. Wlasnie
dlatego zrzut `a53layout` jest obowiazkowy, a nie wygodny.

**Wniosek praktyczny dla zrzutu:** segment `dev` moze miec kilka megabajtow, wiec
zrzut potrwa dluzej, niz zakladalem. Narzedzie czyta po 4 kB i ma sufit `0x800000`
(8 MB) na wypadek, gdyby rozmiar z ukladu byl jeszcze wiekszy.

**Trzeci wniosek: w obrazie jest wlasna tablica procesora.** Pod `0x67F10` i `0x67FA0`
leza pelne osiem bajtow `0x04E28000`, czyli baza `io` widziana przez procesor, a obok
adresy z zakresu `0x0641xxxx` do `0x066Dxxxx`, czyli z segmentu `dev`. To tablica
relokacji procesora i ona potwierdza zarowno podzial na segmenty, jak i ich rozmiary.



















**Co to zmienia:**

- **adresy profilu dla 13.60 sa znane i zweryfikowane** - mozna skladac profil,
- projekt Ghidry trzeba przebudowac na **odtworzonym obrazie**, bo dotychczasowe
  adresy sa przesuniete o 0x6F8,
- **test zapisu trzeba powtorzyc na adresie wewnatrz SRAM**, bo `0x200000` lezy poza
  pamiecia procesora i odczyt zwracal tam zera niezaleznie od zapisu.

## Runda 133 do 137: ZASIEG TRANSPORTU ZMIERZONY, UKLAD SEGMENTOW NIEDOSTEPNY

**To zamyka droge obrana przez patch upstream na 13.60. Kazde zdanie stoi na pomiarze.**

**1. Transport czyta wylacznie pamiec SRAM procesora, od 0x0 do 0xBFFFF.**
Czternascie adresow, z kontrola na znanej zawartosci:

```
0x0         przeslane 0x20, status 0x0    dostepny
0x28000     przeslane 0x20, status 0x0    dostepny, zawartosc zgodna z obrazem
0xb0000     przeslane 0x20, status 0x0    dostepny
0xc0000     przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x100000    przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x400000    przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x1000000   przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x6410000   przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x887f0000  przeslane 0x0,  status 0x20   NIEDOSTEPNY
0x80000000  przeslane 0x0,  status 0x20   NIEDOSTEPNY
```

**2. Status `0x20` przy zerze przeslanych bajtow to nieudany odczyt, a nie brak danych.**
Wcześniej bralem zawartosc bufora za dane i wyciagnalem z tego bledny wniosek: bajty
`ff 43 03 d1 ...` pod `0x887f0000` to resztka po poprzednim odczycie kalibracyjnym pod
`0x5b964`, a nie zawartosc tego adresu. Rozroznienie wymaga czytania pol `zadane`,
`przeslane` i `status` z naglowka wyniku.

**3. Adresy transportu to przestrzen procesora A53, nie pamiec fizyczna konsoli.**
Kontrola przez mape bezposrednia jadra: pod fizycznym `0x28000` lezy
`4e 94 63 5b ba 17 9b 58`, czyli inna pamiec niz `1b 00 01 00 ...`, ktora transport
widzi pod tym samym adresem.

**4. Ukladu nie ma pod `0x887f0000` w zadnej dostepnej drodze:** przez transport odczyt
sie nie udaje (status `0x20`), a w pamieci gospodarza pod tym adresem sa same `0xFF`
(odczyt przez mape bezposrednia, poprzednia sesja).

**5. Skanowanie pamieci gospodarza jest zbyt niebezpieczne, zeby je powtarzac.**
Skaner `tools/a53scan` przejrzal zakres od `0x80000000` i wylaczyl konsole, bo mapa
bezposrednia jadra obejmuje takze regiony urzadzen. To ta sama pulapka, ktora jest
zapisana w pamieci projektu jako "nie sondowac nieznanych obszarow": mapa bezposrednia
nie rozroznia pamieci od urzadzen, a sprawdzenie samego istnienia strony tego nie
lapie. Bezpiecznikiem sa flagi `PWT` i `PCD` oznaczajace regiony niebuforowane.

**WNIOSEK.** Patch PPR z repozytorium upstream na 13.60 nie ma jak dzialac przez ten
transport: czyta uklad segmentow spod `0x887f0000` i pisze do segmentu `dev` w pamieci
gospodarza, a oba te obszary sa poza zasiegiem. Segment `io` lezy w SRAM i jest
dostepny, wiec czesc drogi istnieje, ale `dev` nie.

**Co nadal stoi i jest udowodnione:** profil dla 13.60 jest kompletny i przechodzi 24
reguly generatora, kompiluje sie wobec prawdziwej struktury upstream, patch buduje sie
powtarzalnie, a arytmetyka jaskin i skokow sie zgadza. Brakuje osmioru miejsc z `dev`,
ktorych przez ten transport osiagnac sie nie da.



