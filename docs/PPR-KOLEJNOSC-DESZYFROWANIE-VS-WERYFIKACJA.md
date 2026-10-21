# PPR A53 13.60: czy najpierw deszyfrowanie i zapis, czy najpierw weryfikacja podpisu

## 1. Odpowiedz na pytanie badawcze

**(a) Najpierw deszyfrowanie i zapis, potem weryfikacja.**

W obrazie A53 (`<work>\a53_image\obraz_a53.bin`) widac, ze dla jednego bloku danych pomocnik PPR `0x04e5b964` najpierw zleca sprzetowi operacje szyfrowa (deskryptory AES do kolejki 0 i wpis do rejestru drzwi `0x02021004`), a dopiero potem buduje i zleca komendy SHA na kolejce 1. Wyniku funkcji weryfikujacej nie sprawdza zaden fragment kodu w segmencie io: oba jej wywolania sa w calosci zignorowane.

Trzy rzeczy, ktorych sam segment io nie rozstrzyga, sa wypisane w rozdziale 6. Nie zmieniaja one odpowiedzi na pytanie o kolejnosc, bo kolejnosc zlecen jest widoczna wprost.

## 2. Metoda i kontrola mapowania

Material: `<work>\a53_image\obraz_a53.bin`, 1048576 bajtow, dziewiec ciaglych regionow od 0x0 do 0xC0000.

Przeliczenie przyjete za zleceniem: `adres fizyczny = 0x28000 + (adres widziany przez procesor - 0x04E28000)`, czyli okno io to plik `0x28000..0x62000` (237568 bajtow).

Kontrola sygnatury (odczyt bajtow z pliku, przed jakakolwiek analiza):

| offset w pliku | adres widziany przez CPU | bajty w pliku | wynik |
|---|---|---|---|
| 0x5B964 | 0x04E5B964 (pomocnik PPR) | `ff 43 03 d1 fd 7b 07 a9 fc 6f 08 a9 fa 67 09 a9` | zgodne z oczekiwanym |
| 0x4A120 | 0x04E4A120 (1. miejsce wywolania) | `11 46 00 94` | `bl 0x4e5b964` |
| 0x4B860 | 0x04E4B860 (2. miejsce wywolania) | `41 40 00 94` | `bl 0x4e5b964` |

Sygnatura sie zgadza, wiec przeliczenie jest poprawne i analiza mogla byc prowadzona dalej.

Deasemblacja (dwa niezalezne narzedzia, ten sam wynik):

```bash
# binutils w WSL na surowym binarium, z baza adresowa okna io
aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x04E28000 \
  --start-address=0x04E5B964 --stop-address=0x04E5BC58 io.bin

# kontrola krzyzowa: minimalny ELF (PT_LOAD, p_vaddr = 0x04E28000) plus llvm-objdump 19
/usr/lib/llvm-19/bin/llvm-objdump -d --triple=aarch64 \
  --start-address=0x04E5B964 --stop-address=0x04E5B9A0 io.elf
```

W `/opt/ps5-payload-sdk/bin/` nie ma `llvm-objdump` (jest m.in. `llvm-objcopy`, `llvm-nm`, `prospero-clang`), dlatego uzyto `aarch64-linux-gnu-objdump` (GNU Binutils 2.44) oraz, kontrolnie, `llvm-objdump` z LLVM 19 na pliku ELF. Obie deasemblacje daja instrukcje identyczne co do bajtow.

Pliki tymczasowe (poza repozytorium): `/root/ppr-analiza/` (`io.bin`, `io.dis`, `io.elf`, `*.dis`).

## 3. Fakty o ukladzie kodu (dowody)

### 3.1 Pomocnik PPR 0x04e5b964

Prolog i pobranie argumentow:

```
4e5b964:	d10343ff 	sub	sp, sp, #0xd0
4e5b968:	a9077bfd 	stp	x29, x30, [sp, #112]
...
4e5b984:	b940a3b4 	ldr	w20, [x29, #160]     ; arg ze stosu: offset w bloku (0..16)
4e5b98c:	b94073bc 	ldr	w28, [x29, #112]     ; arg ze stosu: przelacznik pomijajacy weryfikacje
4e5b990:	aa0003f3 	mov	x19, x0              ; x19 = kontekst kanalu krypto
```

Kolejnosc wywolan w ciele funkcji:

```
4e5baf4:	97ffefed 	bl	0x4e57aa8            ; (1) zadanie szyfrowe (AES) + drzwi kolejki 0
4e5baf8:	340001a0 	cbz	w0, 0x4e5bb2c        ; jedyne sprawdzenie wyniku (1)
...
4e5bb74:	97fff397 	bl	0x4e589d0            ; (2) funkcja opisywana jako sha_wait
4e5bb78:	4b150308 	sub	w8, w24, w21         ; brak sprawdzenia w0
...
4e5bc00:	97fff3b3 	bl	0x4e58acc            ; (3) funkcja opisywana jako sha_authenticate
4e5bc04:	394c226a 	ldrb	w10, [x19, #776]     ; brak cmp/cbz na w0 po powrocie
...
4e5bc20:	2a1f03e0 	mov	w0, wzr              ; sukces = 0
4e5bc50:	d65f03c0 	ret
```

Argumenty obu miejsc wywolania (oba w jednej duzej funkcji `0x04e490f8`):

| element | miejsce 0x04e4a120 | miejsce 0x04e4b860 |
|---|---|---|
| arg ze stosu dla `w28` | `4e4a0f4: str wzr, [sp, #16]` = 0 | `4e4b848: str wzr, [sp, #16]` = 0 |
| arg ze stosu dla `w20` | `4e4a0d8: str wzr, [sp, #64]` = 0 | `4e4b838: str wzr, [sp, #64]` = 0 |
| sprawdzenie wyniku | `4e4a124: cbnz w0, 0x4e4a274` | `4e4b864: cbz w0, 0x4e4b888` |

Czyli w obu miejscach `w28 = 0`, wiec galaz `cbnz w28` (`4e5bb84`) nie jest brana i `0x4e58acc` jest wywolywane. Przy `w20 = 0` wywolywana jest tez sciezka `bl 0x4e577a0` (`4e5ba8c`).

### 3.2 Funkcja 0x04e57aa8: buduje deskryptory AES i dzwoni na kolejke 0

```
4e57b9c:	91012260 	add	x0, x19, #0x48        ; kolejka 0 (blok kontrolny +8)
4e57bc0:	97ff4d3e 	bl	0x4e2b0b8             ; deskryptor 16-bajtowy (len 0x10)
4e57be8:	52820001 	mov	w1, #0x1000           ; 4096
4e57c14:	97ff4d44 	bl	0x4e2b124             ; deskryptor AES na strone 4 KB
4e57c5c:	b5fff9f5 	cbnz	x21, 0x4e57b98        ; petla po stronach
...
4e57ddc:	aa1303e0 	mov	x0, x19
4e57de0:	2a1f03e1 	mov	w1, wzr
4e57dec:	97fffa03 	bl	0x4e565f8             ; submit_idma(ctx, 0)
```

`0x4e565f8` konczy sie tail callem do funkcji drzwi:

```
4e56640:	91010260 	add	x0, x19, #0x40
4e5664c:	17ff4b83 	b	0x4e29458
```

a `0x4e29458` wykonuje zapis do rejestru MMIO:

```
4e29480:	5282008b 	mov	w11, #0x1004
4e29488:	72a0404b 	movk	w11, #0x202, lsl #16   ; 0x02021004
4e29490:	53196149 	lsl	w9, w10, #7
4e29494:	92741129 	and	x9, x9, #0x1f000            ; (ctx+8)<<7, indeks kolejki
4e29498:	b82b6928 	str	w8, [x9, w11]               ; drzwi kolejki 0
```

Wniosek: krok (1) pomocnika to realne zlecenie pracy sprzetowi, nie tylko przygotowanie danych.

Sasiednia funkcja `0x04e58214` (konczy sie `ret` w `0x04e589cc`) robi to samo dla polecen bez szyfrowania (deskryptor `0x04e2b2f0` w `0x4e585a4`, deskryptory AES w `0x4e587d4` i `0x4e58908`) i konczy sie `bl 0x4e565f8` z `w1 = wzr` (`4e5899c: mov w1, wzr`, `4e589a8: bl 0x4e565f8`), czyli tez kolejnka 0.

### 3.3 Funkcja 0x04e58acc: buduje deskryptory i dzwoni na kolejke 1

```
4e58bec:	9101a260 	add	x0, x19, #0x68        ; kolejka 1 (blok kontrolny +8)
4e58c08:	97ff492c 	bl	0x4e2b0b8
4e58c50:	97ff49de 	bl	0x4e2b3c8
4e58c90:	97ff4950 	bl	0x4e2b1d0
4e58d3c:	97ff4a3b 	bl	0x4e2b628             ; dopisz 32-bajtowy deskryptor do pierscienia
...
4e58e08:	aa1303e0 	mov	x0, x19
4e58e0c:	52800021 	mov	w1, #0x1              ; kolejka 1
4e58e10:	97fff5fa 	bl	0x4e565f8             ; submit_idma(ctx, 1) = drzwi kolejki 1
4e58e14:	b85dc3a0 	ldur	w0, [x29, #-36]       ; zwracana wartosc zapisana na wejsciu
```

`0x4e2b628` to dopisanie 32 bajtow do pierscienia (bez drzwi):

```
4e2b630:	b9401408 	ldr	w8, [x0, #20]
4e2b634:	b9400c09 	ldr	w9, [x0, #12]
4e2b638:	a9402c2a 	ldp	x10, x11, [x1]
4e2b63c:	8b080129 	add	x9, x9, x8
4e2b640:	a9002d2a 	stp	x10, x11, [x9]
4e2b644:	a9412828 	ldp	x8, x10, [x1, #16]
4e2b648:	a9012928 	stp	x8, x10, [x9, #16]
```

### 3.4 Kolejnosc zlecen do sprzetu dla jednego bloku

1. `0x4e5baf4` -> `0x4e57aa8` -> `0x4e57dec` `bl 0x4e565f8` z `w1 = 0`: deskryptory AES trafiaja do pierscienia kolejki 0 i zostaje wpisany rejestr drzwi `0x02021004`.
2. `0x4e5bb74` -> `0x4e589d0`: dopisanie komendy do bufora kolejki 1 (zapis slowa `4e58a9c: str w20, [x8, x9]`, inkrementacja licznika `4e58aa0: strh w10, [x19, #20]`).
3. `0x4e5bc00` -> `0x4e58acc` -> `0x4e58e10` `bl 0x4e565f8` z `w1 = 1`: deskryptory weryfikujace i drzwi kolejki 1.

Zlecenie deszyfrowania idzie wiec do sprzetu w kroku 1, a komenda weryfikujaca powstaje dopiero w kroku 3, na innej kolejce. Nie ma w tym ciagu zadnego oczekiwania na wynik weryfikacji.

### 3.5 Adresy w deskryptorach nie pochodza z lokalnego SRAM A53

Miejsce 0x04e4a120:

```
4e4a068:	97ff87e9 	bl	0x4e2c00c
4e4a070:	b2500016 	orr	x22, x0, #0x1000000000000
...
4e4a118:	f940bbe8 	ldr	x8, [sp, #368]
4e4a11c:	8b0802c6 	add	x6, x22, x8
4e4a120:	94004611 	bl	0x4e5b964
```

gdzie `0x4e2c00c` to odczyt rejestru bazowego:

```
4e2c00c:	52900d08 	mov	w8, #0x8068
4e2c010:	72a09c48 	movk	w8, #0x4e2, lsl #16    ; 0x04E28068
4e2c014:	f9400108 	ldr	x8, [x8]
4e2c018:	d3707d00 	ubfiz	x0, x8, #16, #32
4e2c01c:	d65f03c0 	ret
```

Miejsce 0x04e4b860 robi to samo:

```
4e4b78c:	97ff8220 	bl	0x4e2c00c
4e4b7c4:	b2500008 	orr	x8, x0, #0x1000000000000
4e4b83c:	8b170126 	add	x6, x9, x23
4e4b860:	94004041 	bl	0x4e5b964
```

Argument `x6` pomocnika wedruje do `0x4e57aa8` (`4e5bad0: mov x5, x6`), a tam do deskryptora AES:

```
4e57c0c:	f85f03a8 	ldur	x8, [x29, #-16]
4e57c10:	8b080142 	add	x2, x10, x8
4e57c14:	97ff4d44 	bl	0x4e2b124
```

Adres jest znakowany bitem 48 (`0x0001_0000_0000_0000`), czyli nalezy do przestrzeni adresowej sprzetu, a nie do lokalnego SRAM A53 (fiz. 0x0..0xC0000, gdzie lezy sam obraz firmware).

## 4. Wynik weryfikacji nie jest nigdzie sprawdzany w io

`0x4e58acc` ma w calym oknie io tylko dwa miejsca wywolania:

```
4e5bc00:	97fff3b3 	bl	0x4e58acc
4e5bc04:	394c226a 	ldrb	w10, [x19, #776]     ; brak jakiejkolwiek inspekcji w0
...
4e5bc20:	2a1f03e0 	mov	w0, wzr              ; funkcja zwraca 0

4e5c510:	97fff16f 	bl	0x4e58acc
4e5c514:	2a1f03e0 	mov	w0, wzr              ; w0 nadpisane bez czytania
4e5c518:	17fffee5 	b	0x4e5c0ac
```

To samo dotyczy `0x4e589d0`: po `4e5bb74: bl 0x4e589d0` nastepna instrukcja to `4e5bb78: sub w8, w24, w21`, bez testu `w0`.

Ksiegowosc wynikow istnieje, ale jest asynchroniczna i nie zawiera sciezki odrzucenia danych: tablica statusow na slot (`[ctx+1600]`) jest zapisywana tylko w `4e56fc8: str w1, [x9, #1600]`, `4e57344: str w20, [x10, #1600]` i `4e5d21c: str w14... str w20, [x8, #1600]`, a wpisywane wartosci pochodza z argumentow tych funkcji, nie z odczytu rejestru bledu. Stan postepu kolejki jest tylko odpytowany: `0x4e294ac` czyta `0x02021008` (`4e294b0: mov w8, #0x1008`, `4e294b4: movk w8, #0x202, lsl #16`, `4e294c0: ldr w8, [x9, x8]`) i porownuje z zapisanym licznikiem.

## 5. Granice okna io

Oba miejsca wywolania pomocnika leza w jednej duzej funkcji zaczynajacej sie w `0x04e490f8`:

```
4e490f8:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
4e49114:	d10cc3ff 	sub	sp, sp, #0x330
```

Zadna instrukcja `bl` w calym oknie io nie celuje w zakres `0x04e49000..0x04e4cfff` i zadne 8-bajtowe ani 4-bajtowe odwolanie do `0x04e490f8`, `0x04e4a120`, `0x04e4b860`, `0x04e5b964` nie wystepuje w obrazie. Warstwa wyzej jest wiec poza tym oknem.

Ta funkcja wola segmenty, ktorych nie mamy:

| miejsce wywolania | cel | segment |
|---|---|---|
| `4e491e8`, `4e493b0`, `4e494b0`, `4e4a724`, `4e4ad90` | `0x0501b1dc` | 0x0501xxxx |
| `4e4921c`, `4e493d8` | `0x0501c0c8`, `0x0501c38c` | 0x0501xxxx |
| `4e4968c`, `4e4b38c` | `0x0501b458` | 0x0501xxxx |
| `4e49d14`, `4e4a890`, `4e4a8ec` | `0x064245b4` | 0x0642xxxx |
| `4e4e61c`, `4e4e6d4` | `0x0643c6e8`, `0x0643c5f8` | 0x0643xxxx |
| `4e4e654` | `0x0643c51c` | 0x0643xxxx |
| `4e4e668` | `0x0641909c` | 0x0641xxxx |
| `4e4e704`, `4e4e728` | `0x0643a85c`, `0x0643aa34` | 0x0643xxxx |

Dodatkowo istnieje druga, blizniacza funkcja PPR z wlasnym prologiem w `0x04e5bc5c` (`4e5bc5c: sub sp, sp, #0xe0`), ktora rowniez wola `sha_wait` (`4e5be14: bl 0x4e589d0`) i `sha_authenticate` (`4e5c510`), a takze `submit_idma` (`4e5c7c0`) i deskryptor `0x04e2b2f0` (`4e5c220`); jej wynik jest ignorowany identycznie (`4e5c514: mov w0, wzr`). Ona tez nie jest wywolywana z zadnego miejsca w io.

## 6. Czego nie da sie rozstrzygnac z samego io

1. Czy adres znakowany `0x0001_0000_0000_0000` wskazuje finalny bufor gospodarza, czy bufor roboczy silnika. Wiadomo tylko, ze nie jest to lokalny SRAM A53 i ze pochodzi z rejestru apertury `0x04E28068`.
2. Czy sam silnik wstrzymuje zapis, gdy pozniejsza komenda z kolejki 1 wykryje niezgodnosc. To semantyka sprzetu. Nic w strumieniu komend nie wiaze kolejki 0 z kolejka 1: drzwi kolejki 0 sa wpisywane w `0x4e57dec`, drzwi kolejki 1 w `0x4e58e10`, miedzy nimi nie ma odczytu statusu.
3. Czy kod poza io (wolania do `0x0642xxxx`, `0x0643xxxx`) odrzuca albo zeruje bufor po nieudanej weryfikacji. Tej warstwy w obrazie nie ma: regiony koncza sie na 0xC0000, a adresy `0x0642xxxx` sa poza materialem.

Poza tymi trzema punktami obraz jest jednoznaczny: kolejnosc zlecen do sprzetu to deszyfrowanie, potem weryfikacja, a wynik weryfikacji nie jest w io nigdzie czytany.

## 7. Wniosek praktyczny

Dla celu "przechwycic odszyfrowana zawartosc niepodpisanego pakietu z pamieci gospodarza" obraz io daje nastepujaca odpowiedz: w warstwie io deszyfrowanie nie jest warunkowane wynikiem weryfikacji. Zlecenie AES z adresem docelowym w przestrzeni sprzetu jest wpisywane do pierscienia i natychmiast wykonywane (drzwi `0x02021004`), zanim komenda weryfikujaca w ogole powstanie, a funkcja ja zlecajaca nie jest nawet sprawdzana w dwoch miejscach, gdzie jest wywolywana.

Czego to nie przesadza: czy niepodpisany pakiet w ogole dojdzie do tego miejsca. To zalezy od logiki w segmentach `0x0642xxxx` i `0x0643xxxx`, ktorych nie mamy.

Co warto sprawdzic dalej, zeby domknac sprawe bez tych segmentow:

1. Zawartosc bufora wskazywanego przez `(rejestr 0x04E28068 << 16) | 0x0001_0000_0000_0000` plus offset, po wpisaniu drzwi `0x02021004` i przed jakimkolwiek zdarzeniem z kolejki 1. Jesli dane sa juz tam, weryfikacja nie bramkuje zapisu.
2. Rejestry kolejki 0 (`0x02021004` drzwi, `0x02021008` licznik postepu) w chwili, gdy kolejka 1 jeszcze nie ma wpisanych drzwi.

## 8. Odtworzenie

```bash
# 1. wyciagniecie okna io z obrazu (offset 0x28000, dlugosc 0x3A000)
#    wynik: /root/ppr-analiza/io.bin

# 2. pelna deasemblacja okna io z baza adresowa 0x04E28000
aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x04E28000 io.bin > io.dis

# 3. wybrane fragmenty
aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x04E28000 \
  --start-address=0x04E5B964 --stop-address=0x04E5BC58 io.bin

# 4. kontrola krzyzowa deasemblacji
/usr/lib/llvm-19/bin/llvm-objdump -d --triple=aarch64 \
  --start-address=0x04E5B964 --stop-address=0x04E5B9A0 io.elf
```
