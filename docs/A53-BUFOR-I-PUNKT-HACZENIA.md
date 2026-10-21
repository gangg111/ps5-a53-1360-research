# Bufor obrazu A53 w jadrze 13.60 i punkt haczenia pod latke PPR

Data: 2026-10-19. Zakres: zrzut `artifacts/kernel-1360-13.60.bin` (64 MiB,
sha256 `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804`),
obraz odniesienia `artifacts/a53-obraz-odtworzony.bin`, profil
`artifacts/kstuff-profile-1360.h`, zrodla kstuff NG w `artifacts/kstuff-a53-src/`
oraz logi z zywej konsoli w `artifacts/` (pprbuf, pprhook, sdbgp).

Konwencja adresow: `VA = 0xffffffffc0c60000 + offset_w_pliku`. Baza danych to
`text + 0xCC0000`, zgodnie z `notes/ANALIZA-ZRZUTU-1360.md`.

## 0. Wniosek w czterech zdaniach

1. Funkcje `a53io_crypt_xts` i `a53io_decompress_block` **nie sa** sciezka ladowania
   firmware'u A53. To zlecenia kryptografii i dekompresji **danych pakietow PPR-PFS**,
   wysylane do procesora A53, ktory w tym momencie **juz dziala**.
2. Obraz docelowy tych funkcji to bufor **wolajacego** (rdi), o rozmiarze podanym przez
   wolajacego (rsi); jadro nie ma pod tym wzgledem zadnej globalnej zmiennej z obrazem.
3. W zrzucie **nie ma** buildera polecenia SDBGP `WRITE_MEMORY`, wiec jadro nigdy nie
   wysyla obrazu do pamieci A53. Wysylka (gdy jest) robi userland przez `kernel_copyin`
   do apertury i do rejestrow stanu, wiec **nie istnieje funkcja jadra "ostatnia przed
   wyslaniem obrazu"**, ktora mozna by zahaczyc.
4. Payload `artifacts/a53patch.elf` jest zbudowany tak, zeby to rozstrzygnac pomiarem:
   zaklada hook na jedynym bezpiecznym miejscu, gdzie bufor przeznaczony dla A53 jest
   widoczny razem z rozmiarem (`mp4_map_iommu_full_discont`), i zaklada latke PPR tylko
   wtedy, gdy bufor naprawde zawiera obraz (5 kotwic i 5 slow stock).

## 1. Metoda i jej weryfikacja

Praca czysto offline, bez konsoli. Narzedzia (w `_robocze-a53/`, poza repozytorium:
`x2b_xref.py`, `xcalls.py`, `xdis.py`, `xodcisk.py`):

* indeks odwolan RIP-wzglednych dla calego obrazu (775 302 cele), z weryfikacja na
  przypadkach znanych z wczesniejszych notatek: `sceSblServiceMailbox` (0x128c79c)
  ma dokladnie jedno odwolanie pod 0x5a4660, `iommu context` (0x126e60e) pod 0x4f9870,
  `a53io_map_iommu` (0x134bdf9) pod 0x9b8024. Metoda trafia w wszystkie trzy,
* skan `call rel32` do zadanego celu (bez deasemblacji calego obrazu),
* deasemblacja okien capstone 5.0.7 z licznikiem VA = baza + offset,
* "odcisk funkcji": prolog + wszystkie napisy wskazywane przez `lea`/`mov`
  rip-wzgledne, do przypisania funkcji do modulu po jej komunikatach.

## 2. Gdzie naprawde laduja sie odszyfrowane dane: funkcje a53io

### 2.1 Trzy funkcje i ich adresy

Napisy bledow z zadania podano jako offsety 0x1358B03 i 0x1358B2F, czyli poczatki
formatow `ERROR: %s(%d) ...`. Pierwszy indeks odwolan w tej sesji liczyl baze RIP
z blednym przesunieciem (o 2 bajty), dlatego poczatkowo nie bylo trafien; po poprawce
indeks zostal sprawdzony na trzech przypadkach znanych z wczesniejszych notatek
(punkt 1) i dopiero wtedy uzyty. Wlasciwe pary napis i funkcja:

| napis (offset) | odwolanie w kodzie | funkcja | VA funkcji | offset |
|---|---|---|---|---|
| `ERROR: %s(%d) a53io_crypt_xts() failed. %d` 0x1358b03 | 0xb94f51 | `a53io_crypt_xts` | 0xffffffffc12eb500 | 0x68b500 |
| `ERROR: %s(%d) a53io_decompress_block() failed. %d` 0x1358b2f | 0xb94cda | `a53io_decompress_block` | 0xffffffffc12eb0c0 | 0x68b0c0 |
| `ERROR: %s(%d) a53io_crypt_sha() failed. %d` 0x12a7454 | 0xb94c7a | `a53io_crypt_sha` | 0xffffffffc12eb550 | 0x68b550 |

Kazda z tych funkcji ma **dokladnie jedno** miejsce wywolania `call rel32` w calym
obrazie (skan `xcalls.py`): xts pod 0xb94e3b, decompress pod 0xb94cd1, sha pod 0xb94c6d.
Wszystkie trzy leza w **jednej** funkcji wolajacej, zaczynajacej sie pod 0xb94aa0.

### 2.2 Wolajacy: sciezka odczytu bloku SCF/pslink

Funkcja 0xb94aa0 ma odcisk modulu storage: napisy `inflate`, `xts`, `hmac`,
`/dev/ssd0.swapx1`, `/dev/ssd0.swapx2`, `pslinkService_v1Dfu_*`, `mmcsd`, `SDHC`.
Jej argument to jedna struktura zadan i czytane z niej pola:

```
0xb94b3c   mov r14,[rdi+0x18]     ; cel (dst)
0xb94b40   mov ebx,[rdi+8]        ; rozmiar zrodla
0xb94b43   mov r15d,[rdi+0xc]     ; pojemnosc celu
0xb94b47   mov rdx,[rdi+0x10]     ; zrodlo
...
0xb94ca5   mov rdi,[global 0x20000]  ; bufor posredni (alokowany w 0xb94a00)
0xb94cac   mov rsi,rdx
0xb94caf   mov rdx,rbx
0xb94cb2   call 0xc0eb90b0  ; kopiowanie do bufora posredniego
0xb94cb7   mov rdx,[global 0x20000]
0xb94cbe   lea r9,[rbp-0x100]
0xb94cc5   mov rdi,r14            ; dst = [req+0x18]
0xb94cc8   mov rsi,r15            ; dst_size = [req+0xc]
0xb94ccb   mov rcx,rbx            ; src_size = [req+8]
0xb94cd1   call a53io_decompress_block
```

Czyli **obraz docelowy nie jest niczym stalym**: to `[req+0x18]` struktury zadania,
a rozmiar to `[req+0xc]`. Bufor posredni (0x20000 B) jest jeden, alokowany raz przy
inicjalizacji modulu (0xb94a00, `mov edi,0x20000`, zapis do globalnej).

### 2.3 Co robi `a53io_decompress_block` (0x68b0c0)

Funkcja nie dekompresuje sama. Sprawdza wyrownanie celu do 16 KB (`shl rax,0x32` na
argumencie), a nastepnie buduje zlecenie w kontekscie i wysyla je do silnika:

```
0x68b127   cmp r14,0x10000          ; cel nie moze byc wiekszy niz 64 KB na jedno zlecenie
0x68b16e   cmp r12,0x10000
0x68b18f   cmp r12,0x20000          ; gorny limit 128 KB
0x68b137   call 0xc120c0c0          ; bufor posredni dla niezaalokowanego celu
0x68b144   mov [r15+0x60],rax       ; +0x60 cel
0x68b161   mov [r15+0x68],r14       ; +0x68 rozmiar celu
0x68b1cb   mov [r15+0x70],r14       ; +0x70 zrodlo
0x68b1d3   mov [r15+0x78],r12       ; +0x78 rozmiar zrodla
0x68b1d7   mov dword [r15+0x10],0x23; typ zlecenia 0x23
0x68b226   call 0xc1210c90          ; zlecenie
0x68b266   call 0xc1210670          ; oczekiwanie na wynik
```

Trzy fakty z tego kodu:

1. **Dane do celu zapisuje silnik po stronie A53** (albo IDMA), a nie procesor x86.
   Funkcja czeka na wynik, ale nie kopiuje nic sama.
2. **Jedno zlecenie to najwyzej 128 KB** (`cmp r12,0x20000`). Caly obraz A53 ma okolo
   745 KB (segment io 0x3A000 i dev 0x31000), wiec nigdy nie jest w jednym wywolaniu.
3. Wniosek logiczny: funkcja ta dziala **tylko wtedy, gdy A53 juz wykonuje firmware**
   (to ona zleca mu prace). Nie moze byc sciezka ladowania tego firmware'u.

### 2.4 Druga sciezka: pakiety PPR-PFS

`a53io_decompress_block` jest wolane z jeszcze jednego miejsca, przez funkcje
0x68b2e0 (odmiana wieloblokowa). Jej wolajacy to VA 0xffffffffc0fb53a7 i 0xffffffffc0fb5501,
w funkcji od 0x354ac0, ktorej odcisk to `ppr_pfs_cmp_bread`, `ppr_pfs_cmp_bread_kraken`,
`ppr_pfs_breadn`, `ppr_pfs_bwrite`, `ppr_pfs_ivc_breadn`, `ppfs_dir_init`. To jest sciezka
czytania **skompresowanych plikow pakietu** (Kraken), a nie firmware'u.

## 3. Bufor docelowy: odpowiedz na pytanie 1

**Odpowiedz: nie ma jednego bufora obrazu A53 w jadrze. Sa trzy rozne bufory, ktore
mozna pomylic z obrazem, i zaden z nich nim nie jest.**

### 3.1 Bufor apertury SDBGP, 2 MB (softc + 0x6b8)

* Pole `+0x6a8` = rozmiar 0x200000, `+0x6b0` = adres urzadzenia, `+0x6b8` = VA w jadrze.
* Wartosci z zywej konsoli (`artifacts/pprbuf-2026-10-15.txt`, `pprhook-2026-10-15.txt`):
  `+0x6a8 = 0x200000`, `+0x6b0 = 0x70000000`, `+0x6b8 = 0xffffff8...`, a w drugim
  przebiegu `0xffffff805a600000`.
* To bufor polecen i odpowiedzi SDBGP (`tools/sdbgp/README.md`: budowniczy pakietow pod
  0xc29100 sklada pakiety wlasnie w `[softc+0x6b8]`) oraz bufor zrzutu pamieci A53
  (`mp4_coredump_buffer_*`). **Wchodzi do niego to, co A53 odsyla, a nie obraz, ktory
  A53 ma dostac.**
* Dowod z pomiaru: po podlaczeniu sterownika bufor ma same zera do pierwszej transmisji
  (`artifacts/pprbuf-2026-10-15.txt`, "bufor 2: ocena SAME ZERA").

### 3.2 Bufor mapowany pod adresem urzadzenia 0x64000000

* Globalna struktura pod offsetem 0x2560E70 (VA 0xffffffffc31c0e70) trzyma:
  `+0x08` VA bufora, `+0x10` adres urzadzenia 0x64000000, `+0x18` flagi 0x50000000.
* Zapisuje je funkcja od 0x9b76b0 (w jej ciele jest napis `initialize_mp4_buf`),
  po alokacji `kmalloc(rozmiar)` pod 0x9b7b24 i po dwoch mapowaniach:
  `mp4_map_iommu_full_discont` (0xc187fef0) i `a53io_map_iommu` (0x9b7f50).
* Zmierzony rozmiar w logu pprhook: mapowanie `+0x08` = 0xffffff801012c000 przy
  `+0x10` = 0x64000000.
* **Tresc tego bufora zmienia sie co 2 do 4 sekund** i ma entropie danych
  (`artifacts/pprbuf-2026-10-15.txt`: zmiany pod 4175, 8195, 12216 i 14236 ms, po 64 B
  probki, "DANE: niezerowych 64 z 64"). Obraz firmware'u tak sie nie zachowuje: jest
  zapisany raz i stoi. To bufor roboczy kryptografii/DMA, nie obraz.

### 3.3 Okna pierscieni pod stalymi adresami IOV

Funkcja 0x9b76b0 mapuje trzy okna przez `0xc1877680` pod adresami IOV 0x24000 (0x4000 B),
0x8000000 (0x2000 B) i 0x40000. Sa to pierscienie polecen i statusu, nie obraz.

### 3.4 Gdzie wiec jest obraz A53

Obraz nalezy do pamieci A53 i jest w nia ladowany poza x86: `a53io_scf_*`,
`a53io_proc_select_scf_program`, `scf program: %u (%s)`, `select scf program(SYS)` i
`(APP)` opisuja wybor programu SCF, a nie transfer obrazu z jadra. Potwierdza to brak
w zrzucie calego kodu ARM64 (`notes/A53-FIRMWARE-W-ZRZUCIE.md`, rozdzial 5: zero `ret`,
zero `nop`, zero prologow `stp x29,x30` w 64 MB) oraz pomiar z konsoli: po restarcie
A53 ma swoj obraz, choc zaden proces x86 go nie wyslal.

## 4. Czy jadro wysyla obraz do A53: nie

1. **Brak buildera `SDBGP_WRITE_MEMORY`.** `tools/sdbgp/README.md` podaje wynik skanu
   calego obrazu: typ `0x01040021` (odczyt) wystepuje 28 razy, typ `0x01010010`
   (konfiguracja) raz, a typu zapisu `0x01040031` **nie ma ani jednego**.
2. **Wysylka jest po stronie userlandu.** `artifacts/kstuff-a53-src/ppr/a53_transport.c`
   otwiera `/dev/mp4/dump`, ioctl `START`/`ALTER_STATE`/`FINISH` sluza tylko do
   opublikowania bufora i jego pol (linie 455 do 590), a same pakiety i "dzwonek" ida
   przez `kernel_copyin` (linie 731 do 736 i 766: zapis paczki i zapis rejestru stanu).
3. **Wniosek dla haczenia.** Miedzy "pakiet gotowy w buforze" a "A53 go widzi" nie ma
   **zadnej funkcji jadra**; jest zapis do pamieci z procesu uzytkownika przez prymityw
   `kernel_copyin`. Nie istnieje wiec funkcja, ktora mozna by zahaczyc jako "ostatnia
   przed wyslaniem obrazu".

## 5. Punkt haczenia: wybor i alternatywy

### 5.1 Wybrany cel: `mp4_map_iommu_full_discont` (offset 0xC1FEF0)

Powody:

* sygnatura `(rdi = adres urzadzenia, rsi = bufor, rdx = rozmiar)` uzywa **tylko trzech
  rejestrow**, ktore mechanizm hooka zachowuje (`kh_install` zapisuje `rdi`, `rsi`, `rdx`
  do slotow, `tools/pprhook/README.md`),
* wolana raz na **jedno mapowanie** bufora, a nie w petli danych,
* to najwczesniejszy moment, w ktorym jadro wie o buforze przeznaczonym dla A53 **i o jego
  rozmiarze**; jesli obraz kiedykolwiek przejdzie przez jadro, ten bufor musi byc tu
  zmapowany,
* mechanizm jest sprawdzony na tej konsoli: `tools/pprhook` zaklada hook dokladnie na tej
  funkcji i przechodzi samotest (`artifacts/pprhook-2026-10-15.txt`, "samotest OK").

Ograniczenie, ktore trzeba znac: mapowanie moze nastapic **przed** wypelnieniem bufora.
Dlatego payload nie pisze "w ciemno": najpierw sprawdza piec kotwic i piec slow stock.
Jesli bufor jest pusty albo to nie obraz, log pokaze to wprost.

### 5.2 Odrzucone alternatywy i powod

| cel | powod odrzucenia |
|---|---|
| `a53io_decompress_block` 0x68B0C0 | w chwili wejscia zywe sa `rcx` (rozmiar zrodla) i `r8` (flagi), a lancuch hooka klobruje `rax`, `rcx` i `r8` (`tools/sdbgp/README.md`); hook zepsulby zlecenie. Dodatkowo cel jest wypelniany przez silnik **po** wejsciu, wiec latka z wejscia i tak by nie przetrwala, a jedno zlecenie obejmuje najwyzej 128 KB |
| `a53io_crypt_xts` 0x68B500 | `rcx` jest zywy juz w czwartej instrukcji (`test byte [rcx],0x80`), wiec klobrowanie `rcx` psuje wywolanie; dodatkowo na wejsciu bufor zawiera szyfrogram, nie jawny obraz |
| `a53io_map_iommu` 0x9B7F50 | sygnatura bezpieczna, ale to tylko mapowanie do IOMMU A53 danego bufora, bez tresci i bez rozmiaru obrazu |
| budowniczy pakietow SDBGP 0xC29100 | na wejsciu w buforze apertury lezy **poprzedni** pakiet, wiec latka trafialaby w dane juz wyslane |
| miejsca powrotu po `call` (np. 0xB94CD6) | w tych punktach zywe sa rejestry wyniku (`test eax,eax` po wywolaniu), wiec klobrowanie `rax` lamie kontrole statusu |
| `mp4_map_iommu_discont` 0x9B76B0 | `rcx` i `r8` sa argumentami, ten sam problem co wyzej |

**Wniosek uczciwy:** dla obrazu A53 nie istnieje w tym jadrze punkt haczenia, ktory
spelnia jednoczesnie trzy warunki: (a) bufor jest juz kompletny, (b) rejestry zywe
w tym miejscu mieszcza sie w `rdi`/`rsi`/`rdx`, (c) jest to miejsce wolane raz na proces.
Payload wybiera wiec miejsce najblizsze ideałowi i **mierzy** to, czego nie da sie
wywnioskowac ze zrzutu.

## 6. Payload `artifacts/a53patch.elf`

### 6.1 Co robi

1. Bramki startowe: firmware 13.60, KASLR z `KERNEL_ADDRESS_TEXT_BASE`, 24-bajtowy prolog
   celu ze zrzutu, IDT/TSS/jaskinia, samotest na `SYS_GETUID + 0xE`.
2. Hook na `mp4_map_iommu_full_discont` (rdzen 0, wektor 1, IST 6, `oneshot = 0`).
3. Przy kazdym mapowaniu: log `dev`, `bufor`, `rozmiar`; probka 16 B; liczba wzorcow
   obrazu w probce; przy rozmiarze co najmniej 0x3A000 proba zalozenia latki.
4. Co 250 ms: odczyt pol softc MP4 (`+0x6a8`, `+0x6b0`, `+0x6b8`) i struktury mapowania
   (`+0x08`, `+0x10`, `+0x18`) z odciskiem bufora, zeby log pokazywal, gdzie lezy co.
5. Podsumowanie z jawnym `[wniosek]`, gdy zaden bufor nie mial obrazu.

### 6.2 Latka: co dokladnie jest zapisywane

Tabela generowana z profilu 13.60 (`tools/a53patch/gen_patch.py`), semantyka z
`ppr_patch.c` (`ppr_build_images`). Wszystkie przesuniecia liczone od poczatku segmentu io
obrazu (fizyczny 0x28000):

| miejsce | rel | stock | po latce |
|---|---:|---|---:|
| `call[0]` | 0x22120 | 0x94004611 | 0x94005F78 |
| `call[1]` | 0x23860 | 0x94004041 | 0x940059A8 |
| `aes_site[0]` | 0x2FC14 | 0x97FF4D44 | 0x940028C6 |
| `aes_site[1]` | 0x2FD4C | 0x97FF4CF6 | 0x94002878 |
| `sha_auth_site` | 0x33C00 | 0x97FFF3B3 | 0x940018D4 |

Jaskinie: `runtime_cave` rel 0x39F00 (19 slow, 76 B), `plaintext_cave` rel 0x39F50
(40 slow, 160 B). Obie w paddingu za koncem danych pliku (plik konczy sie na rel 0x39F00)
i obie koncza sie przed rel 0x3A000.

Miejsca `precheck_va` (rel 0x339CC, stock 0x35000ABC) i `dispatch_va` (rel 0x33AF4,
stock 0x97FFEFED) sa **rozpoznawane, ale nie zapisywane**, tak jak w obecnej generacji
`ppr_patch.c` (sa to hooki poprzedniej generacji, `legacy_hook`).

### 6.3 Zabezpieczenia

1. 5 kotwic tozsamosci obrazu (naglowek, `helper`, `dispatch_native`, `plaintext_direct`,
   `common_return`), kazda 16 B.
2. 5 miejsc latki musi byc w stanie dokladnie stock albo dokladnie po latce.
3. Kazdy odczyt i zapis w granicach `min(rozmiar wolajacego, 0x3A000)`.
4. Powtorny odczyt przed kazdym zapisem (wykrycie zmiany w trakcie).
5. Weryfikacja po zapisie (5 miejsc i 2 jaskinie).
6. Idempotencja: druga proba daje "obraz juz po latce" i zero zapisow.
7. Zero wezlow poza `/data`, zero ioctl, zero zmian na nosniku, zero dotykania 40:00.0.

### 6.4 Weryfikacja (bez konsoli)

* `gen_patch.py`: 5 z 5 slow stock zgodnych z `a53-obraz-odtworzony.bin`, jaskinie
  w paddingu, prolog celu zgodny ze zrzutem, brak kolizji kotwic z miejscami latki.
* `make -C tools/a53patch test` (gcc, obraz prawdziwy): 6 scenariuszy, `TEST OK (0 bledow)`.
  Test 1 sprawdza, ze zmienilo sie 251 bajtow **wylacznie** w dozwolonych zakresach
  (7 zapisow: 2 jaskinie i 5 miejsc). Testy 3 do 6 sprawdzaja cztery odmowy, kazda
  z zerem zapisow.
* `python tools/a53patch/verify.py`: `WERYFIKACJA OK: 0 bledow` (naglowek ELF, tabela
  w binarium, zgodnosc z obrazem i ze zrzutem, brak nakladania zakresow).
* Pelny wynik: `artifacts/a53patch-weryfikacja.txt`.

### 6.5 Artefakt

| pole | wartosc |
|---|---|
| plik | `artifacts/a53patch.elf` |
| rozmiar | 222 328 B |
| sha256 | `026efe0c5b6f49f7bcf7b6b18dc124c73eb81c361ac4fc61d51070711991f63e` |
| opis dla menedzera | `artifacts/pldmgr_a53patch.json`, `artifacts/a53patch.elf.json` |

## 7. Czego nie udalo sie ustalic i jaki pomiar to rozstrzygnie

1. **Czy obraz A53 kiedykolwiek trafia do bufora jadra.** Zrzut tego nie rozstrzyga:
   wszystkie sciezki kryptografii i dekompresji obsluguja pakiety, a nie firmware.
   Pomiar: uruchomic `a53patch.elf` i przeczytac `/data/a53patch.txt`.
   * brak jakiegokolwiek mapowania o rozmiarze co najmniej 0x3A000 z kotwicami obrazu
     przez caly przebieg: zalozenie zadania jest obalone, obraz nie przechodzi przez jadro,
   * jest mapowanie z kotwicami: latka zostaje zalozona i log pokaze kazde slowo przed i po.
2. **Czy A53 dostaje obraz z wlasnej pamieci trwalej, czy od innego procesora.**
   Pomiar: odczyt SDBGP pamieci A53 0x0 do 0x1B000 zaraz po wybudzeniu i porownanie
   z `artifacts/a53-obraz-odtworzony.bin` (offsety 0x28000 i dalej). Jesli tresc jest
   identyczna przed jakimkolwiek zapisem gospodarza, obraz nie pochodzi z x86.
3. **Kiedy dokladnie bufor jest wypelniany.** Payload widzi bufor w chwili mapowania.
   Pomiar: ten sam hook plus odczyt tego bufora po 100 ms, 1 s i 5 s od mapowania
   (mozna dopisac do payloadu), albo hook na funkcji czekajacej na zlecenie.
4. **Czy da sie zahaczyc funkcje z zywym `rcx`/`r8`.** Nie da sie obecnym mechanizmem:
   `khook.c` klobruje `rax`, `rcx` i `r8`. Pomiar nie jest tu potrzebny, potrzebna jest
   zmiana mechanizmu: nowy lancuch, ktory zapisuje i przywraca `rcx` oraz `r8`
   (np. przez `mov [scratch], rcx` i `mov rcx, [scratch]` gadgetami, ktorych w tablicy
   `13_60.h` obecnie nie ma). To jest warunek konieczny kazdego przyszlego hooka na
   funkcje kryptografii i dekompresji A53.

## 8. Odtworzenie

```
# indeks odwolan i deasemblacja (Python z pakietu DSH, capstone 5.0.7)
py _robocze-a53\x2b_xref.py 0x01358b03 0x01358b2f 0x012a7454
py _robocze-a53\xcalls.py 0x68b0c0 0x68b500 0x3553a7
py _robocze-a53\xdis.py 0xb94c90 0xb94d00

# tabela latki i weryfikacja
py tools\a53patch\gen_patch.py
wsl -d Debian -- bash -lc "cd tools/a53patch && make test"
py tools\a53patch\verify.py
```

Pliki robocze skryptow analitycznych leza poza repozytorium, w
`<repo>\_robocze-a53\`.






