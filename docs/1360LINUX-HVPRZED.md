# 1360linux-hvprzed: odczyt danych wejsciowych shellcode'u AP przed rest mode

Wariant payloadu `artifacts/1360linux-hvprzed.elf` (sha256
`589287aec635674ba519f268993091908f6a0135f460dbf7eb0ff093ef1fc9cc`, 237448 B)
zbudowany na `artifacts/1360linux-hvstan.elf` (sha256 `7c5b5968...8229cf`).
Cel: zapisac na dysku wszystko, co shellcode AP czyta jako swoje wejscie, **zanim**
payload wejdzie w rest mode. Poprzednia proba (hvstan) raportowala po wybudzeniu
i log `/data/hvstan.txt` nie powstal, bo konsola pada w trakcie wznawiania, zanim
watek payloadu odzyska sterowanie.

## 1. Gdzie wpiety jest odczyt (dokladnie trzy obszary pliku)

Ogon `main` w nodiag3/hvstan wyglada tak (VA 0x8D76 do 0x8D95):

    0x8D76  lea rdi,[rip+0x14a86]      # tekst "Please wait for the orange light..."
    0x8D7D  mov al,0
    0x8D7F  call notify
    0x8D85  mov edi,5
    0x8D8A  call [rip+0x14688]         # sleep(5)
    0x8D90  call enter_rest_mode
    0x8D96  <ogon zajety przez hvstan>

Wybrane miejsce to **VA 0x8D8A**: jedyna instrukcja przed `call enter_rest_mode`,
ktorej skutkiem jest odroczony `sleep(5)` i nic wiecej. Zamiana na 6 bajtach:

    0x8D8A  e8 f1 1e 00 00   call 0xac80 (hvprzed_entry)
    0x8D8F  90              nop

Nowy kod odtwarza `sleep(5)` jako pierwsza czynnosc, wiec kolejnosc zostaje ta sama:
`notify` -> 5 s -> odczyt i zapis raportu -> `call enter_rest_mode`. Dzieki temu
raport powstaje okolo 5 sekund przed wejsciem w rest mode, a `enter_rest_mode`
i cala sciezka przygotowania (`setup_env`, `fetch_linux`, `prepare_resume`,
`hv_defeat_13xx`, `derive_H`, `kh_install`, `kh_trigger`) sa bajt w bajt nietkniete
(potwierdzone w rozdzialach 5 i 6).

Nowy kod lezy w dwoch pasmach martwego kodu (16-bajtowe stuby syscalli bez
zadnego odwolania z zewnatrz), bo jedno pasmo bylo za male:

| czesc | VA | dlugosc | zawartosc |
|---|---|---|---|
| A | 0xAC80..0xB64B | 2507 B | kod odczytu i raportu |
| B | 0xB6DE..0xBA77 | 921 B | napisy formatow i etykiet |

Miedzy nimi leza **14 zywych bajtow** pod VA 0xB6D0..0xB6DE (stub syscallu
`cpuset`, uzywany posrednio przez mechanizm `kernel_copyout`); nie sa ruszane.
Asembler widzi obie czesci w jednej przestrzeni adresowej (przez `.org`), wiec
wszystkie odwolania RIP-relative i `rel32` sa liczone poprawnie.

## 2. Co dokladnie czyta i co zapisuje

Kazdy odczyt to `kernel_copyout` (VA 0xECF0, odczyt; zero zapisow do pamieci
jadra), a jego kod zwrotny trafia do raportu. Kolejnosc jest celowa: faza A jest
na dysku **przed** pierwszym odczytem z regionu hiperwizora.

**Faza A (bezpieczna, zapis + fsync):**

1. `car+F00`..`car+FC0`: 32 qwordy bloku argumentow strony nosnej spod
   `dmap + 0x3FFFF000 + 0xF00`, czyli pola +0xF00, +0xF08, +0xF10, +0xF18,
   +0xF20, +0xF28, +0xF30, 16 slotow VMCB i licznik.
2. `state+00`, `state+40`: 9 qwordow pod wskaznikiem z +0xF10 (slowo stanu i 8
   nastepnych; drugi wiersz pokazuje tylko pierwszy qword, reszta to zera bufora).
3. `bias=...`: wartosc spod `dmap + [pole +0xF20]` i 16 qwordow od tego adresu.
4. `pcpus=...`: wartosc spod `dmap + [pole +0xF28]`, 16 qwordow od tego adresu
   i `rc_win` dla okna.
5. `win+000`, `win+040`: 16 qwordow spod `dmap + [pole +0xF18] + 0x80000`.
6. `zamierzone:`: wartosci pol +0xF00..+0xF30, ktore payload zamierza tam wpisac.
7. `chain_zero` i `ch+000`..`ch+140`: 0x180 B lancucha ROP z
   `hv_defeat_13xx.chain_buf` (VA 0x2E7B0), czyli pelny zapis tego, co lancuch
   wstawi do bloku przy wybudzeniu.

**Faza B (odczyty regionu HV, zapis + fsync, dopisywane po fazie A):**

8. Odczyty pod adresami docelowymi z kotwicy H (ta sama funkcja `derive_H`,
   ktorej uzyla `hv_defeat_13xx`): `zam_bias = *(dmap + H + 0x883028)` i 16
   qwordow, `zam_pcpb = *(dmap + H + 0x882A60)` i 16 qwordow, oraz 16 qwordow
   okna spod `dmap + H + 0x80000`.
9. `alias_id`: te same dwie wartosci pod aliasem tozsamosciowym (`H + 0x883028`,
   `H + 0x882A60`, bez `dmap`).
10. `faza B:` z kodami wszystkich odczytow HV i kodami zapisu fazy A.

Kody w raporcie: `0` sukces, `-1` blad `kernel_copyout`, `-97` odrzucona kotwica
H (derive_H zwrocilo 0), `-98` `dmap` nie wyglada na VA jadra (odczytu nie bylo),
`-99` bramka adresu odrzucila wskaznik (odczytu nie bylo). `wr_a` i
`fs_a` w naglowku fazy B to kody zapisu i fsync fazy A.

## 3. Dlaczego odczyty sa dwa razy (faza A i B)

Pola +0xF00..+0xF30 **nie sa zapisywane do strony nosnej w trakcie przygotowan**.
`hv_defeat_13xx` buduje lancuch ROP (`kh_chain_store`, `kh_chain_memcpy`) i tylko
go instaluje; same zapisy wykonuje lancuch po wybudzeniu, tuz przed skokiem do
shellcode'u. Dowod z disasemblacji `hv_defeat_13xx` (VA 0x3B62..0x3D03): kazde
pole to `kh_chain_store(&chain, dmap + 0x3FFFFF00 + n, wartosc)`, a nie
`kwrite64`. Dlatego:

- odczyty z fazy A pod wskaznikami **z bloku** przed rest mode zwracaja
  `rc = -99` (pola sa zerami) i to jest oczekiwany, poprawny wynik,
- odczyty z fazy B pod adresami **docelowymi z H** pokazuja prawdziwe dane
  wejsciowe shellcode'u, bo region HV istnieje niezaleznie od rest mode.

## 4. Jak czytac wynik

### 4.1 Naglowek i blok nosny

    === HVPRZED t=... slide=0x... dmap=0x... ktext=0x... H=0x... rc_car=0 rc_state=0

- `rc_car = 0` i caly blok `car+*` w zerach: strona nosna jest czytelna, ale
  lancuch jeszcze do niej nie pisal. To spodziewany obraz **przed** rest mode.
- `rc_car < 0`: `kernel_copyout` nie dziala w tym momencie (problem mechanizmu
  odczytu, nie shellcode'u); `rc_car = -98` oznacza, ze globalne `dmap` jest
  zerowe albo nie jest VA jadra.
- `H = 0x0`: `derive_H` nie zwrocilo kotwicy; wtedy wszystkie odczyty fazy B maja
  `rc = -97`, a linia `zamierzone` jest wyzerowana. To nie jest blad tego
  wariantu, tylko informacja, ze payload sam nie uzbroilby sie poprawnie.
- `car+F18` (pole +0xF18) to kotwica `H`, `car+F20` i `car+F28` to wskazniki
  zmiennej przesuniecia sterty HV i tablicy pcpus, `car+F30` to bramka. Po
  lancuchu (czyli na konsoli nigdy, bo czytamy przed rest mode) mialyby wartosci
  z linii `zamierzone`.

### 4.2 Linia `zamierzone` i lancuch ROP

    zamierzone: F00=0xffffffffc0ec9fb8 F08=0xffffca8400000000 F10=0xffffffffc3999440
                F18=0x8e0000000 F20=0x8e0883028 F28=0x8e0882a60 F30=0x1

To wartosci, ktore `hv_defeat_13xx` liczy dla pol bloku: `F00 = ktext +
env[0x140]` (wektor powrotu AP), `F08 = dmap`, `F10 = ktext + env[0x148] +
0x440` (wskaznik slowa stanu), `F18 = H`, `F20 = H + 0x883028`,
`F28 = H + 0x882A60`, `F30 = 1`.

**To jest miejsce, w ktorym widac, czy poprawka nodiag3 dziala.** Jesli `F20` i
`F28` sa rowne `H + 0x883028` i `H + 0x882A60`, to w pliku sa stale po
podmianie o +0x800000 (bajty 0x88 zamiast 0x08 pod offsetami 0x7C95 i 0x7CCC).
Jesli zamiast tego zobaczysz `H + 0x83028` i `H + 0x82A60` (albo `H + 0x83028` /
`H + 0x82A60` plus 0x800000 tylko w jednym polu), to znaczy, ze latka nodiag3
nie jest w pliku. Ten sam dowod jest niezaleznie w zrzucie lancucha: w wierszu
`ch+0C0` i `ch+100` widac surowe wartosci operandow zapisow dla +0xF20 i +0xF28,
a `chain_zero` oraz koniec niezerowych qwordow pokazuja, gdzie lancuch sie
konczy (uwaga: `chain_zero` to pierwszy **zerowy qword**, a nie dlugosc
lancucha, bo lancuch legalnie zapisuje zera, np. `kh_chain_store(..., 0)`).

### 4.3 Sensowny bias

`zam_bias` to `*(dmap + H + 0x883028)` (wiersz `zam_bias+000`). Semantyka z
shellcode'u (`shellcode_ap_bin`, VA 0x24254 i 0x243DC): to **przesuniecie**, od
ktorego odejmowane sa wskazniki pcpu, zeby dostac pozycje w regionie HV.
Sensowna wartosc to **mala liczba** rzedu od kilku KB do kilku MB, wyrownana do
0x1000:

- `zam_bias` w przedziale `[H, H + 0x2029000)` i wielokrotnosc 0x1000: dobrze.
- `zam_bias = 0x0` przy `rc_bias = 0`: zmienna istnieje, ale jest zerowa; wtedy
  shellcode liczy VMCB jako `pcpu + 0xa8` i bramka `H <= (pcpu - bias)` przepusci
  dowolny wskaznik z regionu HV. Warto wtedy porownac z `zam_pcpb`.
- `zam_bias` ogromne (np. `0x8Exxxxxxx`): to nie jest przesuniecie, tylko adres;
  najpewniej odczytales zle pole albo region HV ma inny uklad, niz zaklada
  shellcode.
- `rc_bias < 0`: regionu nie da sie przeczytac pod tym aliasem. Wtedy patrz na
  `alias_id`: jesli `id_bias` ma `rc = 0` i sensowna wartosc, to dziala alias
  tozsamosciowy (`H + offset`), a nie `dmap + H + offset`, i to jest konkretny,
  sprawdzalny trop w tym, co robi shellcode po wybudzeniu.
- `rc_bias = -97`: `H` odrzucone (`H = 0`), odczyt nie byl nawet probowany.

### 4.4 Sensowna tablica pcpus

`zam_pcpb` to `*(dmap + H + 0x882A60)` (pierwszy qword wiersza `zam_p+000`), a
16 kolejnych qwordow to wpisy tablicy. Shellcode (`0x243CA`..`0x24404`) wymaga,
zeby dla kazdego niezerowego wpisu `pcpu`:

- `H <= (pcpu - bias) < H + 0x2029000`,
- `(pcpu - bias)` bylo wielokrotnoscia 0x1000,
- a VMCB, czyli `*(dmap + (pcpu - bias) + 0xA8)`, bylo niezerowe.

Czyli sensowny obraz to **kilka niezerowych wskaznikow**, dla ktorych roznica z
`bias` jest wielokrotnoscia 0x1000 i lezy w `[H, H + 0x2029000)`. W praktyce na
PS5 Pro nalezy oczekiwac 16 wpisow (16 VMCB dla 16 rdzeni) albo przynajmniej
kilku; reszta moze byc zerami. Interpretacja:

- kilka wpisow spelniajacych warunki: tablica jest prawdziwa, a `zam_pcpb` jest
  poprawna baza.
- wszystkie wpisy zerowe: albo tablica jest pod innym adresem (zly `H` albo zly
  offset), albo w tym momencie nie jest jeszcze wypelniona.
- wpisy niezerowe, ale roznica z bias nie jest wyrownana do 0x1000 albo wypada
  poza `[H, H + 0x2029000)`: shellcode odrzuci je i skonczy na stanie `0xF002`
  (mniej niz 16 VMCB) nawet jesli dane sa czytelne.
- `rc_pcp < 0`: region nieczytelny pod tym aliasem; znow warto sprawdzic
  `alias_id` (`id_pcpb`).

### 4.5 Okno [H + 0x80000, H + 0x80080)

Shellcode skanuje `[H + 0x80000, H + 0x90000)` co 8 bajtow i szuka **pierwszego
niezerowego qworda** (0x242B0). Potem czyta 4 qwordy od `H + 0x80000` i wymaga,
zeby wiecej niz jeden byl niezerowy i przechodzil testy jak wyzej (0x242F8).
Interpretacja 16 qwordow z wierszy `win+000`, `win+040` oraz `zam_w+00`,
`zam_w+40`:

- **okno pelne zer**: shelcode nie znajdzie nic i skonczy na stanie `0xF003`
  ("w oknie nie ma ani jednego niezerowego qworda"). To znaczy, ze albo kotwica
  `H` jest zla, albo okno jest przesuniete (podejrzenie pada wtedy na stala
  +0x800000 uzyta w nodiag3 do pol +0xF20 i +0xF28), albo region HV nie jest
  jeszcze przygotowany. Dla wariantu hvprzed jest to najwazniejszy pojedynczy
  sygnal: jesli okno jest zerowe **przed** rest mode i pozostaje zerowe, to
  shellcode po wybudzeniu nie ma z czego wyliczyc VMCB.
- **okno pelne smieci** (wartosci niebedace wskaznikami, np. `0xdeadbeef`,
  przypadkowe liczby, powtorzone stale): region jest czytelny, ale to nie jest
  tablica wskaznikow pcpu. Wtedy shellcode odrzuci wszystkie kandydaty w skanie
  (bo nie spelniaja `[H, H + 0x2029000)` i wyrownania 0x1000) i pojdzie sciezka
  `0xF002`/`0xF003`.
- **kilka sensownych wskaznikow** (wielokrotnosci 0x1000 w `[H, H + 0x2029000)`):
  to jest obraz, ktorego oczekuje shellcode.
- `rc_win < 0` przy `rc_*` innych pol ujemnych: caly region HV jest nieczytelny
  pod danym aliasem; porownaj z `alias_id` i z `rc_bias`.

### 4.6 Jak odroznic "blok pusty" od "odczyt sie nie udal"

Jedna linia: `rc_car`. Wartosc `0` przy zerowych wierszach `car+*` oznacza, ze
odczyt sie udal i strona nosna naprawde jest pusta (lancuch jeszcze nie pisal).
Wartosc ujemna oznacza, ze nie wiemy, co tam jest, bo odczyt nie doszedl.
Dopiero `rc_car = 0` upowaznia do wniosku "pola +0xF00..+0xF30 sa przed rest mode
zerowe". Ten sam test stosuje sie do kazdego innego wiersza.

## 5. Weryfikacja wariantu

Wynik `verify2.py` (PASS) na pliku gotowym:

- naglowek ELF, program headery, section headery, `.rela.dyn`, `.rela.plt`,
  `.dynamic`, `.dynsym` i punkt wejscia - bez zmian,
- 3261 roznych bajtow wobec hvstan, wszystkie w trzech obszarach: latka
  0xCD8A..0xCD90 (6 B), czesc A 0xEC80..0xF64B (2507 B), czesc B
  0xF6DE..0xFAA2 (921 B); poza nimi 0 roznic,
- 14 zywych bajtow VA 0xB6D0..0xB6DE nietkniete, obszary sie nie nakladaja,
- 0 kolizji: zaden niezmieniony fragment kodu ani danych (call/jmp, operand
  RIP-relative, immediate, relokacja, wskaznik w danych) nie odwoluje sie do
  nadpisanych obszarow, a jedyne wejscia do nich to latka w `main` i wlasne
  odwolania wewnatrz bloba,
- 19 odwolan RIP-relative wewnatrz czesci A trafia w czesc A albo B, kazdy
  `call`/`jmp rel32` zostaje w czesci A,
- 8 wywolan `snprintf`: liczba zrzutow na stos rowna sie cofnieciu `rsp`,
  liczba zrzutow parzysta (wyrownanie 16 B) i liczba argumentow stosowych
  zgodna z liczba formatow w napisie,
- sciezka przygotowania i wejscie w rest mode nietkniete: `hv_defeat_13xx`,
  `derive_H`, `kh_install`, `kh_trigger`, `prepare_resume`, `fetch_linux`,
  `main` do 0x8D8A oraz `main` od 0x8D90, `kernel_copyout`, `shellcode_ap_bin`,
  `off_1360`, `chain_buf` i caly blob hvstan (0x14040..0x14818) - bajt w bajt jak
  w hvstan.

Bramka nie jest pozorna: po celowym zepsuciu jednego `add rsp` (0x30 na 0x28)
`verify2.py` konczy sie FAIL i wskazuje dokladnie to miejsce (`0xb043`, 6
zrzutow, cofniecie 40). Ten test uratowal wariant dwa razy w trakcie budowy:
wykryl zla stala adresu powrotu (blob liczyl slide od 0x8D90 zamiast od 0x8D8F,
co po dodaniu jednego zrzutu stosu daje przesuniecie wszystkich adresow o 1)
oraz nadmiarowy zrzut na stos w jednym wywolaniu `snprintf` (co konczylo sie
rozjazdem stosu o 16 B i skokiem w zerowa strone obrazu). Oba bledy sa juz
naprawione, a harness dodatkowo sprawdza po powrocie bloba, ze stos wrocil na
dokladnie te sama wysokosc (we wszystkich trybach `rozjazd stosu: 0`).

Kod zostal dodatkowo uruchomiony natywnie (WSL, x86-64) na atrapie obrazu
payloadu (mapa 0x10000000, latka w `main`, atrapy `kernel_copyout`,
`derive_H`, `open`, `snprintf`, `sleep`, `fflush`) i atrapie pamieci jadra
(`dmap`, strona nosna, region HV z biasem i tablica pcpus, lancuch ROP w formacie
`kh_chain_store`). Sprawdzone tryby i wyniki:

| tryb | co sprawdza | wynik |
|---|---|---|
| `przed` | blok nosny pusty, region HV wypelniony | `rc_car=0`, blok w zerach, `rc_state=-99`, odczyty HV `rc=0`, funkcja wraca do `main` |
| `wypelniony` | blok po lancuchu | `rc_state=0`, wszystkie odczyty `rc=0`, wartosci zgodne z oczekiwanymi |
| `smieci` | pola bloku to VA jadra, 0 i adres spoza 1 TB | bramki odrzucaja (`-99`), zadnego ryzykownego odczytu, payload idzie dalej |
| `nodmap` | `dmap = 0` | `rc_car=-98`, zero wywolan `kernel_copyout` |
| `noopen` | brak obu plikow | brak raportu, kody zapisu `-1`, payload idzie dalej i wraca |
| `noh` | `derive_H` zwraca 0 | `H=0x0`, odczyty HV `-97`, zero odczytow HV |
| `fail:N` | bledy odczytu od N-tego wywolania | kody `-1` w raporcie, przygotowanie nie przerywa sie |

## 6. Przykladowy raport (z testu natywnego, tryb "przed")

Tryb `przed` odpowiada stanowi na konsoli: strona nosna jest pusta, a region HV
wypelniony. Wiersze skrocone do dwoch qwordow, w prawdziwym raporcie jest ich 8.

    === HVPRZED t=1792177897.004865 slide=0x10000000 dmap=0xffffca8400000000 ktext=0xffffffffc0c60000 H=0x8e0000000 rc_car=0 rc_state=-99
    car+F00=0000000000000000 0000000000000000 ...
    car+F40=0000000000000000 0000000000000000 ...
    car+F80=0000000000000000 0000000000000000 ...
    car+FC0=0000000000000000 0000000000000000 ...
    state+00=0000000000000000 0000000000000000 ...
    state+40=0000000000000000 0000000000000000 ...
    bias=0x0 rc_bias8=-99 rc_bias16=-99 (pole +0xF20: 0x0)
    bias+000=0000000000000000 0000000000000000 ...
    bias+040=0000000000000000 0000000000000000 ...
    pcpus=0x0 rc_pcpb8=-99 rc_pcp16=-99 rc_win=-99 (pole +0xF28: 0x0)
    pcp+000=0000000000000000 0000000000000000 ...
    pcp+040=0000000000000000 0000000000000000 ...
    win+000=0000000000000000 0000000000000000 ...
    win+040=0000000000000000 0000000000000000 ...
    zamierzone: F00=0xffffffffc0ec9fb8 F08=0xffffca8400000000 F10=0xffffffffc3999440 F18=0x8e0000000 F20=0x8e0883028 F28=0x8e0882a60 F30=0x1 w_bloku: F18=0x0 F20=0x0 F28=0x0 F30=0x0
    chain_zero=0x18 (pierwszy zerowy qword)
    ch+000=ffffffffc0ef18b2 ffffffffc3999440 ...
    ch+040=ffffffffc0ec9fb8 ffffffffc10d4389 ...
    ch+080=ffffca843fffff10 ffffffffc17eca6d ...
    ch+0C0=ffffffffc10d4389 ffffffffc0ef18b2 ...
    ch+100=ffffffffc17eca6d 00000008e0882a60 ...
    ch+140=ffffffffc0ef18b2 ffffffffc0ef18b2 ...
    faza B: H=0x8e0000000 zam_bias=0x8e0a0000 rc_bias=0 zam_pcpb=0x8e2028000 rc_pcp=0 rc_bias16=0 rc_pcp16=0 rc_win=0 wr_a=0 fs_a=0
    zam_b+00=000000008e0a0000 0000000000000000 ...
    zam_b+40=0000000000000000 0000000000000000 ...
    zam_p+00=00000008e2028000 000000008e0a0000 ...
    zam_p+40=000000008e260000 000000008e2a0000 ...
    zam_w+00=000000008e100000 000000008e100008 ...
    zam_w+40=000000008e100040 000000008e100048 ...
    alias_id: id_bias=0x8e0a0000 rc=0 id_pcpb=0x8e2028000 rc=0

Jak to czytac w tym trybie: `rc_car = 0` mowi, ze blok nosny jest czytelny i
naprawde pusty (`rc_state = -99`, bo wskaznik z +0xF10 jest zerem, wiec bramka
nie dopuscila odczytu). Prawdziwe dane wejsciowe sa w fazie B: `zam_bias` i
`zam_pcpb` maja `rc = 0`, oba aliasy (dmap i tozsamosciowy) czytaja to samo, a
`zam_w+00` pokazuje niezerowe okno. Wiersz `zamierzone` potwierdza, ze w pliku sa
stale po poprawce nodiag3 (`F20 = H + 0x883028`, `F28 = H + 0x882A60`), a zrzut
lancucha pokazuje te same wartosci jako operandy zapisow.

## 7. Ograniczenia

- Plik `/data/hvstan-przed.txt`; gdy ten system plikow nie jest zapisywalny,
  raport trafia na `/mnt/usb0/hvstan-przed.txt`. Gdy oba zawioda, nie ma gdzie
  zapisac kodow bledow - brak pliku jest wtedy jedyna informacja.
- Odczyty z fazy B ida do regionu hiperwizora przez `dmap`. Ten sam region
  payload zapisuje w przygotowaniu (`kwrite(H + 0x1000, shellcode_ap_bin, len)`
  pod VA 0x3A17), wiec sciezka jest sprawdzona w praktyce, ale nie ma gwarancji,
  ze kazda strona `H + 0x883028` jest zmapowana w danej chwili. Dlatego faza A
  jest zapisywana i synchronizowana przed faza B: przy nieudanym odczycie
  pochodnym tracimy tylko dane fazy B, a raport fazy A zostaje.
- Wariant nie zmienia logiki przygotowania ani shellcode'u. Jesli blad lezy w
  samym shellcode (np. w wyliczeniu VMCB), raport pokaze dane wejsciowe i pozwoli
  to rozstrzygnac, ale niczego nie naprawi.
- Proces payloadu nigdy nie konczy pracy (`main` po powrocie z rest mode wchodzi
  w petle hvstan), wiec po tescie trzeba ubic proces albo zrestartowac konsole.

## 8. Narzedzia

Pliki robocze leza poza repozytorium, w `<work>\hvprzed`:

    hvprzed.s        zrodlo bloba (kod + napisy), asembler GNU as --64
    inject2.py       wstrzykniecie trzech obszarow do hvstan.elf -> hvprzed.elf
    verify2.py       weryfikacja strukturalna, kolizje, stosy i argumenty snprintf
    harness2.c       natywny tester (atrapa obrazu payloadu i pamieci jadra)
    one.sh, run-tests2.sh, check-modes.sh   uruchomienie testow natywnych
    gate-build.sh    test negatywny bramki (celowo zepsuty add rsp)

Budowa i testy (WSL):

    bash /mnt/d/Tools/hvprzed/run-tests2.sh all
    py -3.12 <work>\hvprzed\inject2.py <hvstan.elf> hvprzed.bin <wyjscie.elf>
    py -3.12 <work>\hvprzed\verify2.py <hvstan.elf> <hvprzed.elf> 0x9b3
