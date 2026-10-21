# 1360linux-hvstan: odczyt stanu shellcode'u AP po wybudzeniu z rest mode

Wariant payloadu `artifacts/1360linux-hvstan.elf` (sha256
`7c5b5968a1e74549cd85d3da33ea082afb1958417d51df896154804ed58229cf`, 237448 B) zbudowany
na `artifacts/1360linux-nodiag3.elf` (sha256 `3e05a728...2ba0b0`). Cel: rozstrzygnac, na czym
polega blad, przez ktory konsola po wybudzeniu zyje kilka sekund i gasnie, zamiast zgadywac.

## 1. Co zostalo zmienione (dokladnie dwa obszary pliku)

**(1) Ogon `main`, VA 0x8D96 (offset pliku 0xCD96), 16 B.** Nodiag3 konczyl `main` petla
`sleep(30)` bez konca:

    0x8D96  bf 1e 00 00 00        mov edi, 0x1e
    0x8D9B  ff 15 77 46 01 00     call [rip+0x14677]     ; sleep
    0x8DA1  e9 f0 ff ff ff        jmp 0x8D96

Teraz w tym miejscu jest:

    0x8D96  48 8d 3d 83 fd ff ff  lea rdi, [rip-0x27d]   ; rdi = B + 0x8B20 (adres main)
    0x8D9D  e8 9e b2 00 00        call 0x14040           ; hvstan_entry, nigdy nie wraca
    0x8DA2  eb fe                 jmp 0x8DA2             ; gdyby jednak wrocil: nie wchodzic
    0x8DA4  90 90                 nop nop                ; w sciezke bledu "Something went wrong"

Payload jest PIE (`e_type = ET_DYN`, 149 relokacji `R_X86_64_RELATIVE`), wiec jego wlasne
adresy sa przesuniete o baze zaladowania `B`. Latka przekazuje `B + 0x8B20` w `rdi`, a kod
liczy `r15 = rdi - 0x8B20 = B` i wszystkie stale adresy payloadu (GOT, `dmap`, funkcje)
adresuje jako `[r15 + stala]`. Biezaca wartosc `B` jest logowana w kazdym rekordzie
(pole `slide`), wiec z logu widac, czy zalozenie bylo prawidlowe.

**(2) Nowy kod, VA 0x14040 (offset pliku 0x18040), 2008 B.** Lezy w obszarze martwego kodu
`kernel_proc_copyin` (0x14040, 207 B), `kernel_proc_copyout` (0x14110), `kernel_proc_setchar`
(0x141E0), `setshort` (0x142E0), `setint` (0x143F0), `setlong` (0x14500), `getchar` (0x14610),
`getshort` (0x146B0), `getint` (0x14760); konczy sie na VA 0x14818, czyli przed zywym
`kernel_iommu_copyin` (0x148C0). Blob nie zawiera zadnej relokacji.

Dowod, ze obszar jest martwy (narzedzie `deadcode3.py`, skan calego `.text` 85366 B):
zbiera bezposrednie `call`/`jmp`, wszystkie operandy RIP-relative, immediate'y rowne adresowi
w `.text`, relokacje `RELATIVE` i 8-bajtowe wskazniki z `.rodata`/`.data.rel.ro`/`.got`/`.data`.
Dla tych osmiu funkcji liczba wejsc z zewnatrz wynosi 0; przed 0x14040 lezy wypelnienie `int3`
(0x14034..0x1403F) po bezwarunkowym `jmp` w `kernel_proc_getpaddr`, wiec zadne przejscie nie
wpada w blob. Po wstrzyknieciu ten sam skan powtorzono na gotowym pliku: 0 kolizji i 0 wejsc
z zewnatrz poza sama latka.

## 2. Jak dziala petla odczytu

`hvstan_entry` nigdy nie wraca. Prolog: 6 rejestrow na stos, ramka 0xA68 B (bufory na stosie,
zero alokacji). Petla, co 250 ms (`usleep(250000)`), robi dwa zapisy do pliku:

**Faza A (bezpieczne odczyty, zapis + fsync od razu).**
1. `rc_car = kernel_copyout(dmap + 0x3FFFF000 + 0xF00, buf, 0x100)` - 32 qwordy bloku
   argumentow strony nosnej. `dmap` jest brane z globalnej zmiennej payloadu (VA 0x6F1F0),
   nie zakladamy zadnego adresu jadra na sztywno. Gdy `dmap` nie wyglada na VA jadra
   (prog 0xffff000000000000), odczyt jest pomijany z kodem -98, a bufor zerowany.
2. `gettimeofday` (syscall 116) - znacznik czasu w kazdym rekordzie.
3. `rc_state = kernel_copyout(*(buf+0xF10), &state, 16)`, o ile wskaznik jest VA jadra.
   **To jest prawdziwe slowo stanu** (patrz rozdzial 3).
4. `snprintf` naglowka + 4 linie `car+F00/F40/F80/FC0` (po 8 qwordow).
5. `open("/data/hvstan.txt", O_WRONLY|O_APPEND|O_CREAT, 0644)` (zapas:
   `/mnt/usb0/hvstan.txt`), `write_all`, `fflush(NULL)`, `fsync(fd)` (syscall 95), `close`.
   Bez pliku petla dziala dalej (kody `wr_* = -1`).

**Faza B (odczyty pochodne, tez zapis + fsync).**
6. `rc_heap = kernel_copyout(dmap + [buf+0xF20], &heapvar, 8)` - zmienna przesuniecia sterty HV.
7. `rc_pcpbase = kernel_copyout(dmap + [buf+0xF28], &pcpus_base, 8)`, a gdy sie uda,
   `rc_pcp = kernel_copyout(dmap + [buf+0xF28], buf, 0x80)` - 16 qwordow tablicy pcpus.
8. `rc_win = kernel_copyout(dmap + [buf+0xF18] + 0x80000, buf, 0x80)` - 16 qwordow okna
   skanowania shellcode'u.
9. Naglowek fazy B, linia `--- pochodne`, 4 linie `win+000/040`, `pcp+000/040`, zapis,
   `fsync`, `close`.

Kolejnosc jest celowa: rekord A (blok nosny + slowo stanu) jest na dysku **przed** pierwszym
odczytem pochodnym, wiec nawet gdyby odczyt pochodny wywolal panic jadra, najwazniejsze dane
sa juz zapisane i zsynchronizowane.

**Bramki adresow (ochrona przed panic).** Kazdy odczyt pochodny wymaga, by wskaznik z bloku
nosnego byl w przedziale `0x1000 <= p < 0x10000000000` (1 TB). Odrzucane sa wiec 0, drobne
smieci i wszystkie VA jadra (0xffff...), ktore w `dmap` dalyby adres spoza mapy. Odrzucenie
jest logowane jako `rc = -99` i **zadnego odczytu nie ma**. Kazdy odczyt sprawdza kod powrotu
`kernel_copyout`; kod != 0 nie przerywa petli, tylko trafia do logu.

Zapis do pamieci jadra: **zaden**. Uzywany jest wylacznie `kernel_copyout` (VA 0xECF0), ten sam
mechanizm, ktorym payload robil zrzut jadra; `kernel_copyin`/`kwrite` nie sa wolane ani razu.
Kstuff nie jest uzywany.

Syscall `fsync = 95` i `gettimeofday = 116` potwierdzone dwoma niezaleznymi zrodlami:
naglowkiem `sys/syscall.h` z `/opt/ps5-payload-sdk` (zgodnym ze 230 stubami syscalli w tym
samym pliku, 0 rozbieznosci) oraz tablica `syscallnames[]` ze zrzutu jadra
(`artifacts/kernels/retail/13.60.bin`, offset 0x254BB10): `[95] fsync`, `[116] gettimeofday`.

## 3. Korekta wobec nodiag3: gdzie naprawde lezy slowo stanu

W nodiag3 (i w opisie zadania) przyjeto, ze slowo stanu lezy pod `dmap + 0x3FFFF000 + 0xF10`.
Rozbior `shellcode_ap_bin` (VA 0x24200, plik 0x28200) pokazuje, ze pod +0xF10 lezy **wskaznik**:

    0x24241  mov rax, [rdi+0x10]    ; rax = *(args+0x10) = wskaznik
    0x2424d  mov [rax], 0x1100      ; dopiero TU shellcode pisze stan
    0x24245  mov rbp, [rdi+8]       ; rbp = dmap
    0x24249  mov r10, [rdi+0x18]    ; r10 = kotwica regionu HV

a `hv_defeat_13xx` wpisuje w to pole `ktext + env[0x148] + 0x440` (dowody: `lea rdi,[rbp-0x110]`
= ktext+env[0x148] pod 0x39F7, `+0x1000` pod 0x39FE dla kodu shellcode'u, `lea rax,[rbp-0x110];
add rax,0x440` pod 0x3933..0x3940 i `kh_chain_store` do `carrier+0xF10` pod 0x3C17..0x3C37).
Ten wariant loguje i pole (`oracle=`), i wartosc pod nim (`state=`, `state_plus8=`), wiec jest
odporny na te pomylke.

Pola bloku nosnego wypelniane przez `hv_defeat_13xx` (do weryfikacji z logu):

| pole | wartosc | instrukcja |
|---|---|---|
| +0xF00 | `ktext + env[0x140]` (wektor powrotu AP) | 0x3BA3 |
| +0xF08 | `dmap` | 0x3BE4 |
| +0xF10 | `ktext + env[0x148] + 0x440` (wskaznik oracle) | 0x3C17 |
| +0xF18 | `H` z `derive_H` (kotwica, w shellcode `r10`) | 0x3C55 |
| +0xF20 | `H + 0x883028` (wskaznik zmiennej przesuniecia sterty HV) | 0x3C85, 0x3C90 |
| +0xF28 | `H + 0x882A60` (wskaznik tablicy pcpus) | 0x3CBC, 0x3CC7 |
| +0xF30 | `1` (bramka) | 0x3CF3, 0x3CFE |

Pola +0xF40..+0xFB8 (16 slotow VMCB), +0xFC0 (licznik), +0xFC8 (bias), +0xFD0 (trafienie
w oknie) wypelnia sam shellcode: 0x24353/0x2435B nadpisuje +0xF20/+0xF28 pozycja okna,
0x2435F/0x24366 wpisuje bias i trafienie, 0x24404 wpisuje sloty, 0x24499 wpisuje licznik.
Dlatego zmiana wartosci +0xF20/+0xF28 wzgledem `H + 0x883028`/`H + 0x882A60` jest dowodem, ze
shellcode wszedl w sciezke awaryjna ze skanem okna.

Semantyka sciezki (adresy z bloba 0x24200): walidacja wskaznikow 0x2425B..0x2427A; okno
`[r10+0x80000, r10+0x90000)` czytane **przez dmap** (`lea rdi,[rbp+rdx]`, 0x242B0); pcpus
czytane jako `*(dmap + [args+0x28] + i*8)` (0x243CA..0x243DF), a VMCB jako
`*(dmap + (pcpu - bias) + 0xA8)` (0x24392, 0x243DC); stany: 0x1100 (0x2424D), 0x1200 (0x24399),
0x13xx = 0x1300|liczba (0x244A0..0x244A3), 0x1400 (0x244EE), 0xF001 (0x24480),
0xF002 (0x2446A), 0xF003 (0x242C6).

## 4. Format logu

Przykladowy rekord (dwie iteracje, wartosci wymyslone):

    === HVSTAN iter=0 t=1750000000.123456 slide=0x200000000 dmap=0xffffca8400000000 rc_car=0 rc_state=0 prev_wr_b=-1 prev_fsync_b=-1 oracle=0xffffffff96049440 state=0x1400 state_plus8=0x0
    car+F00=ffffffff9377e9b8 ffffca8400000000 ffffffff96049440 00000008e0000000 00000008e0883028 00000008e0882a60 0000000000000001 0000000000000000
    car+F40=... (sloty VMCB 0..7, niezerowe = przyjete przez shellcode)
    car+F80=... (sloty VMCB 8..15)
    car+FC0=0000000000000010 000000008e0a0000 000000008e100000 0000000000000000 ...
    faza B: iter=0 state=0x1400 anchor=0x8e0000000 rc_win=0 rc_pcp=0 rc_heap=0 rc_pcpbase=0 wr_a=0 fsync_a=0
    pochodne: heapvar=0x8e0a0000 pcpus_base=0x8e2028000
    win+000=... (16 qwordow okna)
    win+040=...
    pcp+000=... (16 qwordow tablicy pcpus)
    pcp+040=...

Pola: `iter` = numer przebiegu, `t` = czas z `gettimeofday`, `slide` = baza zaladowania
obrazu, `rc_*` = kod `kernel_copyout` (0 sukces, <0 blad, -98 pominiety bo `dmap`
nieprawidlowe, -99 bramka adresu odrzucila wskaznik), `wr_*` = kod zapisu, `fsync_*` = kod
`fsync`. `prev_wr_b`/`prev_fsync_b` to kody fazy B z poprzedniej iteracji (w chwili budowania
naglowka A biezace jeszcze nie istnieja). Plik jest dopisywany (`O_APPEND`), wiec kolejne
uruchomienia payloadu dopisuja sie do tego samego logu.

## 5. Jak czytac werdykt

Najpierw `state` (slowo stanu):

| state | znaczenie |
|---|---|
| 0x1400 | shellcode doszedl do konca i zpatchowal 16 VMCB; blad jest **po** lataniu HV (przekazanie sterowania do Linuksa), nie w patchowaniu |
| 0x13xx | znalazl `0xN` VMCB (np. 0x1310 = 16); jesli licznik w `car+FC0` != 16, konczy sie 0xF002 |
| 0x1200 | shellcode jest w petli po tablicy pcpus (stan zapisany tuz przed nia) |
| 0x1100 | shellcode wpisal tylko znacznik wejscia i nie doszedl do skanu; patrz `heapvar`, `pcpus_base` i ich `rc` |
| 0xF001 | trafienie w oknie minus bias poza `[H, H+0x2029000)` albo nie wyrownane do 0x1000 |
| 0xF002 | mniej niz 16 VMCB przeszlo testy (patrz `car+FC0` i sloty) albo bramka `car+F30` != 1 |
| 0xF003 | w oknie `[H+0x80000, H+0x90000)` nie ma ani jednego niezerowego qworda: zla baza okna, czyli podejrzenie pada na stala +0x800000 z nodiag3 |

Potem pola pomocnicze:

- `rc_car < 0` przy `dmap` prawidlowym: `kernel_copyout` nie dziala po wybudzeniu (problem
  mechanizmu, nie shellcode'u). `rc_car = -98`: `dmap` wyzerowane.
- `car+F30` (bramka) musi byc 1; kazda inna wartosc prowadzi shellcode do 0xF002.
- `car+F18` to kotwica `H` z `derive_H`; `car+F20` i `car+F28` powinny byc rowne
  `H + 0x883028` i `H + 0x882A60`. Jesli sa inne, albo sa pozycjami okna (0x8E08xxxx), to
  shellcode wszedl w awaryjna sciezke ze skanem okna.
- `heapvar` = `*(dmap + [+0xF20])` to bias uzywany przy liczeniu VMCB; `pcpus_base` =
  `*(dmap + [+0xF28])` to baza tablicy pcpus. Dla sciezki bezposredniej (bez skanu) musi
  zachodzic `H <= pcpus_base - heapvar < H + 0x2029000`.
- 16 qwordow `win+*`: okno, w ktorym shellcode szuka niezerowego qworda. Zera w calym oknie
  wyjasniaja 0xF003.
- 16 qwordow `pcp+*`: wpisy tablicy pcpus. Zera albo smieci wyjasniaja, dlaczego VMCB nie
  zostaly znalezione (0xF002).
- `slide` != 0 potwierdza, ze obraz jest PIE i ze latka dobrze policzyla baze.

## 6. Weryfikacja wariantu

Wynik `verify.py` (PASS) na pliku gotowym:

- naglowek ELF, program headery, section headery, `.rela.dyn`, `.rela.plt`, `.dynamic`,
  `.dynsym` - bez zmian (`readelf -h -l -S -d -r -s --dyn-syms -n` daje wyjscie identyczne
  dla nodiag3 i hvstan),
- `.rodata` i `.data` bit w bit bez zmian; rozni sie wylacznie `.text`,
- 1976 roznych bajtow, wszystkie mieszcza sie w dwoch obszarach: 0xCD96..0xCDA6 (ogon main)
  i 0x18040..0x18818 (blob),
- 0 kolizji: zaden niezmieniony fragment kodu ani danych nie odwoluje sie do nadpisanych
  obszarow, a jedyne wejscie do bloba to latka w ogonie `main`,
- kazde odwolanie RIP-relative i kazdy `call`/`jmp` rel32 wewnatrz bloba zostaje w blobie,
- nietkniete: `hv_defeat_13xx` (1691 B), `derive_H`, `kh_install`, `kh_trigger`,
  `prepare_resume`, `fetch_linux`, `main` do 0x8D96, `kernel_copyout`, `shellcode_ap_bin`,
  `off_1360`.

Kod bloba zostal dodatkowo uruchomiony natywnie (WSL, x86-64) na atrapie pamieci jadra:
ten sam plik `.s`, ten sam binarny blob, z podstawionymi `kernel_copyout`, `open`, `write`,
`__crt_syscall`, `usleep` i niezerowym slide. Sprawdzone zostaly: formatowanie rekordu,
mechanizm slide, wyrownanie stosu przy `snprintf` z 12 argumentami, petla 250 ms, sciezki
bledow (`rc = -1`, `-98`, `-99`, brak pliku) i brak smieci w buforze przy pominiętym odczycie.
Narzedzia i harness leza poza repozytorium, w `<work>\hvstan` (`hvstan.s`, `harness.c`,
`inject.py`, `verify.py`, `deadcode3.py`, `syscallnames.py`, `run-all-tests.sh`).

## 7. Ograniczenia

- Petla zapisuje do `/data/hvstan.txt`; gdy ten system plikow nie jest zapisywalny dla
  payloadu, log trafi na `/mnt/usb0/hvstan.txt` (o ile USB jest zamontowany). Jesli oba
  zawioda, w logu nie ma nic, a kody `wr_* = -1` tez nie maja gdzie trafic.
- Proces payloadu nigdy nie konczy pracy (`main` nie wraca), wiec po tescie trzeba ubIC
  proces albo zrestartowac konsole.
- Odczyt pochodny okna i tablicy pcpus jest zabezpieczony tylko bramka zakresu. Jesli pole
  z bloku nosnego bedzie mialo wartosc w zakresie 0x1000..1 TB, ale adres w `dmap` nie bedzie
  zmapowany, kernel moze spanikowac. Dlatego rekord A jest zapisywany i synchronizowany
  wczesniej: w takim wypadku tracimy tylko dane pochodne, a werdykt ze slowa stanu zostaje.
- Wariant nie zmienia niczego w logice przygotowania ani w shellcode; jesli blad lezy
  w samym shellcode (np. w jego wyliczeniu VMCB), log pokaze to jako konkretny kod stanu,
  ale go nie naprawi.
