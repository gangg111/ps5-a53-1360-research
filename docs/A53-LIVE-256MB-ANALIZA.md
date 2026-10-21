# Analiza zrzutu 256 MB pamieci A53 (`<work>\a53_live.bin`)

Notatka z pomiarow wykonanych 15.10.2026 na pliku z zywej konsoli PS5 Pro, firmware 13.60.
Analiza wylacznie odczytem, bez konsoli, bez kstuff, bez zmiany innych plikow repo.
Skrypty pomiarowe leza poza repo, w `<work>\_work_a53live\` (opis w rozdziale 9).

## 0. Tozsamosc pliku

| pole | wartosc |
|---|---|
| sciezka | `<work>\a53_live.bin` |
| rozmiar | 268 435 456 B = 0x10000000 = 256 MB |
| sha256 | `41105cc06b90b88c62ad9ef283153278811dc47e0f60f2e1ddf1ca0897d3fa0b` |
| czas modyfikacji | 15.10.2026 02:43:09 |
| pochodzenie | `tools/a53dump2` (log `<work>\a53dump-log.txt`): 1024 porcje po 0x40000, adresy 0x0 do 0x10000000, "dobrych porcji 1024, bledow 0" |

## 1. Czym jest ten zrzut

### 1.1 Plik to 1024 bloki po 0x40000, kazdy z naglowkiem wyniku

Plik nie jest ciaglym obrazem pamieci. Dzieli sie dokladnie na 1024 bloki po 0x40000 B,
a kazdy blok zaczyna sie od 0x28-bajtowego naglowka wyniku transportu. Naglowek bloku 0:

```
000000  28 00 00 00 01 00 01 02 00 00 00 00 00 00 00 00   (...............
000010  00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
000020  20 00 00 00 00 00 00 00 28 00 00 00 d0 00 00 00    .......(.......
```

Pola wedlug konwencji z `tools/pprwatch/pprwatch.c` (komentarz pod linia 187, kontrola pod 681):
self 0x28 pod +0x00, slowo pamieci 0x02010001 pod +0x04, adres pod +0x08, zadane pod +0x10,
przeslane pod +0x18, status pod +0x20.

| blok | self | slowo | adres | zadane | przeslane | status |
|---|---|---|---|---|---|---|
| 0 | 0x28 | 0x02010001 | 0x0 | 0x40000 | 0x0 | 0x20 |
| 1 | 0x28 | 0x02010001 | 0x40000 | 0x40000 | 0x0 | 0x20 |
| 16 | 0x28 | 0x02010001 | 0x400000 | 0x40000 | 0x0 | 0x20 |
| 1023 | 0x28 | 0x02010001 | 0xffc0000 | 0x40000 | 0x0 | 0x20 |

Naglowki sa **1024 rozne**, ale roznia sie wylacznie polem adresu.

### 1.2 Payload jest identyczny we wszystkich 1024 blokach

To najwazniejszy pomiar calej analizy. Sha1 fragmentu bloku od offsetu 0x28 do konca:

```
sha1(blok[i][0x28:0x40000]) = e9295a5d932064cf8b630821455c92b8fb91e472   dla kazdego i
liczba roznych wartosci: 1
```

Autokorelacja pliku: udzial bajtow rownych dla przesuniecia rownego 0x40000 wynosi 0.999996
(roznica to jeden bajt adresu w naglowku). Dla przesuniec 0x1000 do 0x20000 udzial wynosi
0.03 do 0.09, czyli przypadkowy.

**Wniosek: unikalnej tresci jest 0x40000 B (256 kB), a nie 256 MB.** Reszta to ta sama
tresc powtorzona 1024 razy. Naglowki zajmuja 1024 * 0x28 = 40 960 B, powtorzony payload
268 394 496 B.

### 1.3 Naglowek mowi, ze odczyt sie nie udal

Pola `przeslane` i `status` sa w kazdym z 1024 blokow takie same: przeslane 0, status 0x20.
Narzedzia repo traktuja taka kombinacje jako **odczyt nieudany** (`pprwatch.c`, linia 681:
`if (przeslane != size || status != 0)`). Ten sam status 0x20 opisuje runda 133 do 137 notatki
`STAN-KONCOWY-KSTUFF-NG.md`: "status 0x20 przy zerze przeslanych bajtow to nieudany odczyt",
a zawartosc bufora jest wtedy resztka po poprzednim odczycie.

Czyli `a53dump2` policzyl "1024 dobre porcje", sprawdzajac tylko magic naglowka odpowiedzi,
a nie pola wyniku. Pole `przeslane` jest zerowe w **kazdym** z 1024 zadan, takze pod adresem
0x0, wiec **payload zrzutu jest stala zawartoscia bufora transportu** (resztka po wczesniejszym
odczycie), powtarzana przy kazdym zadaniu. Runda 133 do 137 notatki `STAN-KONCOWY-KSTUFF-NG.md`
potwierdza, ze duze odczyty nie przechodza, a dostepny jest tylko SRAM 0x0 do 0xbffff
i to malymi porcjami.

To samo widac w plikach regionow czytanych przez jadro: `<work>\a53_regions\region_00000000.bin`,
`region_0001b000.bin` i `region_00062000.bin` zawieraja **ten sam blok** co zrzut. Probka 8 kB
zrzutu spod 0x800 wystepuje w nich w calosci (8192 z 8192 bajtow rowne) pod stalymi
przesunieciami 80, 56 i 32, ktore roznia sie dokladnie o 0x18, czyli o dlugosc kolejnego
naglowka wyniku. Odczyt jadra pod trzema roznymi adresami zwrocil te sama tresc.

### 1.4 Co widac pod offsetem 0

Pod offsetem 0 lezy naglowek wyniku (0x28 B, opisany wyzej), a nie poczatek pamieci ani kod.
Zaraz za nim zaczyna sie tresc, ktora wyglada jak poczatek obrazu firmware'u A53:

```
000028  28 00 00 00 d0 00 00 00 20 00 05 01 00 00 00 00   (....... .......
000038  02 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff   ........
000048  2a 00 00 00 00 00 00 00 00 00 01 ff 01 00 01 ff   *...............
000058  02 00 01 ff 03 00 01 ff 04 00 01 ff 05 00 01 ff   ................
...
0001ec  45 19 af ca fb 94 9f 4a a4 94 58 22 64 a1 4b 45   E......J..X"d.KE   <- build-id 16 B
0001fc  47 4e 55 00                                       GNU.
000228  63 65 78 28 31 2e 31 2e 32 2e 30 31 29 3a 4f 62   cex(1.1.2.01):Ob
000238  65 72 6f 6e 2d 4b 44 45 20 32 30 32 36 2f 30 37   eron-KDE 2026/07
000248  31 37 20 30 32 3a 32 32 20 72 65 6c 65 61 73 65   17 02:22 release
000258  73 2f 31 33 2e 36 30 20 32 32 39 33 35 38 00      s/13.60 229358.
```

Czyli pod offsetem 0 jest: naglowek transportu, potem deskryptor wersji z tablica wpisow
`xx 00 01 ff`, build-id i napis "GNU", potem pakiet SDBGP, a od 0x3A8 kod ARM64.

### 1.5 Czego w pliku nie ma

| wzorzec | wystapien w 256 MB |
|---|---|
| `Linux`, `FreeBSD`, `root=`, `console=`, `e820`, `EFI`, `systemd`, `/dev/` | 0 |
| naglowek ELF `7f 45 4c 46`, PE `MZ`, gzip, xz, zstd, lz4, bzip2, zip, FDT | 0 |

**Wniosek: to nie sa dane jadra, to nie jest pamiec fizyczna konsoli od zera i to nie jest
liniowy obraz pamieci.** To jeden blok 256 kB pamieci A53, ktory transport zwraca jako
stala odpowiedz, powtorzony w pliku 1024 razy.

## 2. Mapowanie offsetow na adresy

**Z tego pliku nie da sie ustalic adresu zadnego bajtu.** Adres w naglowku jest tylko echem
zadania: przy 1024 roznych adresach tresc jest identyczna, wiec adres nie wplywa na dane.
Nie ma tez w pliku zadnej tablicy stron ani naglowka mapy, ktore pozwolilyby to policzyc.

Jedyne dowody adresowe sa **wewnatrz** bloku, w jego wlasnych wskaznikach (8-bajtowe slowa
w malej kolejnosci, przedzial 0x10000 do 0x10000000, 288 wystapien):

| przedzial | wystapien | uwaga |
|---|---|---|
| 0x04080000 do 0x0408ffff | 72 | najczestszy, m.in. 0x040850c0 (13 razy) |
| 0x04c00000 do 0x04c0ffff | 42 | m.in. 0x04c064d4, 0x04c05ff0 |
| 0x04860000 do 0x0486ffff | 27 | m.in. 0x04864e10, 0x04864b70 |
| 0x06400000 do 0x0647ffff | 27 | segment `dev` z profilu PPR (0x06410000) |
| 0x00080000 do 0x0008ffff | 23 | 0x00085bc0, 0x00085c00, 0x00087a40 |
| 0x08000000 | 3 | baza |

Czyli blok zna przestrzen adresowa firmware'u (0x0400_0000, 0x0486_0000, 0x04c0_0000,
0x0641_0000 i niskie SRAM 0x85_000), ale to nie dowodzi, gdzie sam lezy.
**Adresu bloku nie ustalamy i nie nalezy go zgadywac.**

## 3. Regiony w unikalnym bloku

Offsety sa offsetami w bloku, czyli offset w pliku modulo 0x40000. Entropia liczona
z calego regionu.

| offset | rozmiar | entropia | typ | ocena |
|---|---|---|---|---|
| 0x00000 | 0x28 (40 B) | 0.95 | naglowek wyniku transportu | metadane, nie A53 |
| 0x00028 | 0x118 (280 B) | 3.36 | deskryptor wersji, build-id, "GNU", tablica `xx 00 01 ff` | naglowek obrazu firmware'u |
| 0x00140 | 0x68 (104 B) | 2.18 | pakiet SDBGP/DECI5S, magic 0x73354450 | metadane transportu w tresci |
| 0x001a8 | 0x80 (128 B) | 2.75 | naglowek komunikatu, slowo 0x13590001, 16 B hasha | naglowek obrazu firmware'u |
| 0x00228 | 0x44 (68 B) | 4.62 | baner ASCII `cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358` | identyfikacja firmware'u |
| 0x0026c | 0x13c (316 B) | 1.85 | tablice i deskryptory, slowo 0x02040021 pod 0x2d0 | dane obrazu |
| 0x003a8 | 0x27c58 (162 904 B) | 6.93 | **kod ARM64 i dane stale**, 519 rozkazow `ret` | firmware A53 |
| 0x28000 | 0x800 (2 048 B) | 4.14 | 838 bajtow losowych, reszta zera | dane |
| 0x28800 | 0x2800 (10 240 B) | 0.19 | zera (BSS) | dane |
| 0x2b000 | 0x2000 (8 192 B) | 2.52 | tablice wskaznikow (0x0408xxxx, 0x0486xxxx, 0x04c0xxxx, 0x06417d70) | dane |
| 0x2d000 | 0xe8f8 (59 640 B) | 7.884 | blok wysokiej entropii, w nim tablica deskryptorow 0x2ebb8 do 0x2edb8 (entropia 1.93) | dane nieprzejrzyste |
| 0x3b8f8 | 0x128 (296 B) | 0 | zera | dane |
| 0x3ba20 | 0x3ef0 (16 112 B) | 3.973 | powtarzajace sie rekordy: zera, 16 B danych, 496 B `ff`, 768 B danych, w tym dwie tablice 16-bitowe | dane |
| 0x3f910 | 0x6f0 (1 776 B) | 0 | wypelnienie `ff` do konca bloku | dane |

Pierwsze 64 bajty kazdego regionu:

```
0x00000  28 00 00 00 01 00 01 02 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00
         00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 28 00 00 00 d0 00 00 00
         20 00 05 01 00 00 00 00 02 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff
0x00140  50 44 35 73 28 00 00 00 28 7d 06 00 00 02 ff 80 80 01 ff 80 00 02 00 20
         00 00 00 00 00 00 00 00 dd 13 15 94 00 00 00 00 18 00 00 00 00 7d 06 00
         00 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00
0x00228  63 65 78 28 31 2e 31 2e 32 2e 30 31 29 3a 4f 62 65 72 6f 6e 2d 4b 44 45
         20 32 30 32 36 2f 30 37 2f 31 37 20 30 32 3a 32 32 20 72 65 6c 65 61 73
         65 73 2f 31 33 2e 36 30 20 32 32 39 33 35 38 00 ...
0x003a8  00 29 21 0b c0 03 5f d6 fd 7b be a9 f4 4f 01 a9 fd 03 00 91 49 3c 00 12
         e8 03 01 aa 29 6d 1c 53 f3 03 00 aa 29 21 00 51 02 20 00 79 4a 3c 40 92
         03 20 00 a9 e2 1f 80 52 41 f1 7d d3 09 14 00 b9
0x28000  46 92 26 fe b2 11 de fd ec 86 93 ac 18 05 6b af f3 76 32 34 07 f5 ca 37
         59 62 87 66 ad e1 7f 65 76 9a e2 de 82 19 1a dd dc 8e 57 8c 28 0d af 8f
0x2b000  98 4d 86 04 00 00 00 00 c0 4d 86 04 00 00 00 00 5c 54 08 04 00 00 00 00
         80 4e 86 04 00 00 00 00 24 20 c0 04 00 00 00 00 00 00 00 00 ...
0x2d000  8c 88 de b2 35 06 7a 36 c0 55 81 40 5d 61 31 79 c0 24 d0 88 47 31 22 9c
         4b 34 00 83 21 cd 00 22 98 32 58 88 d4 c7 85 14 0e e1 9f b2 a2 d5 c1 02
0x3e000  43 00 41 00 44 00 42 00 45 00 43 00 46 00 44 00 47 00 45 00 48 00 46 00
         49 00 47 00 4a 00 48 00 4b 00 49 00 4c 00 4a 00 4d 00 4b 00 4e 00 4c 00
```

## 4. Sygnatury kodu ARM

Liczby dla calego pliku 256 MB; dla unikalnego bloku dziela sie przez 1024.

| wzorzec | caly plik | unikalny blok | typ |
|---|---|---|---|
| ARM64 `nop` (0xd503201f, bajty `1f 20 03 d5`) | 106 496 | 104 | kod |
| ARM64 `ret` (0xd65f03c0, bajty `c0 03 5f d6`) | 531 456 | 519 | kod |
| ARM64 `B` (bity 31:26 = 0x05) | 1 589 248 | 1 552 | kod |
| ARM64 `BL` (bity 31:26 = 0x25) | 1 814 528 | 1 772 | kod |
| ARM32 `ldr pc,[pc,#0x1c]` (`1c f0 9f e5`) | **0** | **0** | brak |
| ARM32 `mov r0,r0` (`00 00 a0 e1`) | **0** | **0** | brak |
| ARM32 `bx lr` (`1e ff 2f e1`) | **0** | **0** | brak |

Na 65 536 slow 4-bajtowych w bloku przypada 3324 rozgalezien `B`/`BL`, czyli 5.1 procent,
co jest typowym udzialem dla kodu AArch64. Rozkazy `ret` wystepuja w 278 oknach po 256 B,
od 0x300 do 0x27500, ciaglymi pasmami (najdluzsze: 0x19100 do 0x1ed00, 23 kB).

**Regiony ARM32: zero. Region ARM64: jeden, 0x003a8 do 0x28000, 162 904 B.**
Wewnatrz niego sa kieszenie danych (na przyklad 0x27600 do 0x28000 ma entropie 7.1 do 7.2
i 37 procent bajtow ASCII, bez rozkazow `ret`), wiec granice regionu sa podane z zapasem.

### Tablica wektorow

Nie ma tablicy wektorow ARM32 (bajty `xx xx xx ea` na poczatku strony) ani tablicy wektorow
ARM64 (osiem galezi `B` co 0x80 B). Kod zaczyna sie od 0x3a8 rozkazem `ret`, a nie wektorem,
czyli blok nie zawiera poczatku wektoryzowanego wyjatku, tylko fragment kodu.

## 5. Napisy i magic

| wzorzec | caly plik | unikalny blok | gdzie |
|---|---|---|---|
| `50 44 35 73` (magic 0x73354450 malej kolejnosci) | 1024 | 1 | 0x140 |
| `44 45 43 49` (ASCII `DECI`) | 0 | 0 | brak |
| `DECI5S` | 0 | 0 | brak |
| `SDBGP` | 0 | 0 | brak |
| `deci`, `ppr`, `mp4`, `a53`, `sony`, `nxp`, `marvell`, `broadcom` | 0 | 0 | brak |
| `cex(` | 1024 | 1 | 0x228 |
| `Oberon` | 1024 | 1 | 0x236 |

W calym bloku sa 27 napisow o dlugosci co najmniej 8 znakow i tylko dwa z nich sa prawdziwe:
baner pod 0x228 oraz `PD5s(` pod 0x140, czyli magic pakietu. Reszta to przypadkowe ciagi
bajtow w kodzie i w danych losowych. **Obraz jest pozbawiony nazw symboli i napisow
diagnostycznych**, wiec identyfikacja opiera sie na banerze i na strukturach, nie na tekstach.

### Pakiet SDBGP pod 0x140

Rozbior pol wedlug mapy z notatek projektu (magic 0x73354450, host 0x80ff0180, urzadzenie
0x80ff0200, protokol 0x20000200):

```
+0x00  u64  0x00000028_73354450   magic i self_size 0x28
+0x08  u32  0x00067d28            rozmiar calkowity pakietu
+0x0c  u32  0x80ff0200            zrodlo (urzadzenie)
+0x10  u32  0x80ff0180            cel (host)
+0x14  u32  0x20000200            protokol
+0x20  u64  0x00000000_941513dd   znacznik rdtsc
+0x28  u64  0x00067d00_00000018   podnaglowek self 0x18
+0x40  u32  0x00000038            self_size wyniku
+0x44  u32  0x00000148            rozmiar calkowity wynikow
+0x48  u32  0x02010010            slowo pamieci
```

Kierunek jest odwrotny niz w zadaniu od hosta (zrodlo 0x80ff0200, cel 0x80ff0180),
czyli to pakiet odpowiedzi. W calym bloku nie ma ani jednego slowa 0x01040021 (typ odczytu
pamieci z notatek) ani 0x01010010 (konfiguracja); jest natomiast 0x02040021 pod 0x2d0
i 0x02010010 pod 0x188.

## 6. Firmware WiFi A53 (ARM32) nie ma go w tym zrzucie

Odniesienie: dane jadra pod `ktext + 0x1518160`, rozmiar 0x7a248 (500 296 B), plik zrodlowy
`lib/nxp/pcieuartiw620_combo_v1.bin`. Wyciagnalem ten fragment z `artifacts/kernel-1360-13.60.bin`:

```
sha1(fragment) = 5430462025d992eb81440306b9adaf143edb8570
entropia 6.83
pierwsze 64 B: 01 00 00 00 00 00 00 00 00 02 00 00 04 47 ba 08
               1c f0 9f e5 1c f0 9f e5 1c f0 9f e5 1c f0 9f e5
               1c f0 9f e5 1c f0 9f e5 1c f0 9f e5 1c f0 9f e5
               ...
wzorce ARM32: ldr pc,[pc,#0x1c] 8 razy (tablica wektorow), bx lr 35 razy
napisy: "SIGRTMEM: Out of heap memory", ": Heap memory corrupted" (0x5cc0, 0x5ce0)
```

To potwierdza, ze obraz WiFi jest kodem ARM 32-bit i ze ma tablice wektorow ARM32
(pod offsetem 0x10 osiem slow `1c f0 9f e5`). Ten sam fragment niezaleznie opisuje
`notes/A53-FIRMWARE-W-ZRZUCIE.md` (rozdzial 2), ktora dodatkowo wskazuje w zrzucie jadra
drugi obraz ARM32, firmware kontrolera Bluetooth od offsetu 0x01a1c000 (Thumb-2, ThreadX).
Zadna z tych tresci nie wystepuje w zrzucie 256 MB z `<work>\a53_live.bin`.

**W zrzucie go nie ma, trzy niezalezne dowody:**

1. **Rozmiar.** Fragment ma 500 296 B, a unikalna tresc zrzutu to 262 144 B. Nie miesci sie.
2. **Brak kodu ARM32.** Zero wystapien `1c f0 9f e5`, `00 00 a0 e1` i `1e ff 2f e1`
   w calym pliku 256 MB.
3. **Probki.** 24 probki po 64 B, rownomiernie z calej dlugosci obrazu WiFi: **0 trafien**
   w bloku zrzutu.

**W poblizu nie ma tez innych obrazow firmware'u.** W bloku jest jeden baner wersji
(1024 wystapienia w pliku to ten sam baner), jeden 16-bajtowy build-id, brak naglowkow
ELF, PE, gzip, xz, zstd, FDT. Drugi obraz, ktory mozna by nazwac firmware'em, to jedynie
blok wysokiej entropii pod 0x2d000 (rozdzial 7), ale jest nieprzejrzysty i nie ma przy nim
zadnego napisu identyfikujacego.

## 7. Struktury PPR i slady deszyfrowania

### 7.1 Sygnatury PPR: zero trafien

Wzielo sygnatury wprost z generatora `artifacts/ppr-patch-upstream/generate_ppr_profiles.py`
(linie 173 do 289) i slowa rozkazow z profilu `artifacts/kstuff-profile-1360.h`.

| sygnatura | w zrzucie 256 MB |
|---|---|
| AES_DESCRIPTOR LATE / CURRENT / LEGACY (40 B) | 0 / 0 / 0 |
| PLAINTEXT_DESCRIPTOR LATE / CURRENT / LEGACY (48 B) | 0 / 0 / 0 |
| SHA_AUTH_SETUP LATE / CURRENT | 0 / 0 |
| `precheck_stock` 0x35000abc (CBNZ W28) | 0 |
| `aes_site_stock[0]` 0x97ff4d44, `[1]` 0x97ff4cf6 | 0 / 0 |
| `sha_auth_site_stock` 0x97fff3b3 | 0 |
| `dispatch_stock` 0x97ffefed | 0 |
| `call_stock` 0x94004611, 0x94004041 | 0 / 0 |

Jedyne trafienie z rodziny PPR to 16-bajtowa sygnatura pomocnika z ramka 0xd0
(`ff 43 03 d1 fd 7b 07 a9 fc 6f 08 a9 fa 67 09 a9`), wystepujaca 3 razy w bloku
(0x96b4, 0xc6fc, 0x24bf4) i 3072 razy w pliku. To zwykle funkcje z taka sama ramka stosu,
a nie pomocnik PPR dla 13.60, ktory ma ramke 0x1d0 i inne bajty. Zgodnie z profilem
pomocnik dla 13.60 lezy pod adresem fizycznym 0x5b964, czyli **poza** zakresem bloku 0x0 do 0x40000.

### 7.2 Gdzie PPR faktycznie jest

Sprawdzilem te same sygnatury w pozostalych obrazach z dysku:

| plik | trafienia |
|---|---|
| `<work>\a53_live.bin` (ten zrzut) | brak jakiejkolwiek sygnatury PPR |
| `<work>\a53_window.bin`, `<work>\a53_dump.bin` | brak |
| `<work>\a53_regions\region_00028000.bin` | AES_DESCRIPTOR pod 0x381c, PLAINTEXT_DESCRIPTOR pod 0x39e8, precheck pod 0x340c4, aes_site 0x3030c i 0x30444, sha_auth_site 0x342f8, dispatch 0x341ec, call_va 0x22818 i 0x23f58 |
| `artifacts/a53-obraz-odtworzony.bin` (1 MB) | AES_DESCRIPTOR pod **0x2b124**, PLAINTEXT_DESCRIPTOR pod **0x2b2f0**, precheck pod **0x5b9cc**, aes_site **0x57c14** i **0x57d4c**, sha_auth_site **0x5bc00**, dispatch **0x5baf4**, call_va **0x4a120** i **0x4b860** |

Te offsety w obrazie odtworzonym sa **co do bajtu rowne adresom fizycznym z profilu**
(`artifacts/kstuff-profile-1360.h`, na przyklad `aes_descriptor_va` 0x04e2b124 przy
`io_sram_base` 0x28000 daje 0x2b124). To niezalezne potwierdzenie profilu 13.60
i jednoczesnie dowod, ze zrzut 256 MB **nie jest** tym obrazem: jego blok nie zawiera
ani jednej z tych sygnatur pod zadnym offsetem. Region `region_00028000.bin` ma je
przesuniete o 0x6f8, co zgadza sie z uwaga o 0x6f8 z notatek projektu.

### 7.3 Blok wysokiej entropii 0x2d000 do 0x3b8fc

```
offset 0x2d000, rozmiar 59 640 B (do 0x3b8f8), entropia 7.884, zer 2.2 procent
histogram bajtow: min 135, max 1311, srednia 224 (rozklad plaski)
16-bajtowych blokow: 3584, z tego roznych 3551
brak magic: ELF, gzip, xz, zstd, lz4, bzip2, zip, FDT, uImage
brak stalej AES: ani S-box `63 7c 77 7b f2 6b 6f c5`, ani Rcon, ani inizjalizacji SHA-256 `6a09e667bb67ae85`
```

Tresc jest nierozroznialna od losowej, czyli zaszyfrowana albo spakowana. Nie ma przy niej
napisu `deci`, `ppr` ani `mp4`, wiec nie da sie jej przypisac do PPR na podstawie tekstu.
Entropia 7.885 i brak jakichkolwiek stalych kryptograficznych oznacza, ze **nie ma tu
zadnego czytelnego kontekstu AES ani tablicy deskryptorow deszyfrowania**.

### 7.4 Co jednak w tym bloku jest: tablica deskryptorow 16 wpisow

Pod 0x2ebb8 lezy tablica 16 wpisow po 0x20 B, jedyna struktura w obszarze losowym:

```
0x2ebb8: 24 00 00 00 08 00 00 00 c0 5b 08 00 00 00 00 00 00 80 c0 50 00 00 03 00 01 00 00 00 00 00 00 00
         len 0x24    len2 0x8       zrodlo 0x85bc0            cel 0x0003000050c08000     1
0x2ebd8: len 0x24    len2 0x8       zrodlo 0x85c00            cel 0x0003000050c08050     1
0x2ebf8: len 0x24    len2 0x20      zrodlo 0x87a80            cel 0x0003000050c00080     1
```

Zrodla (0x85bc0, 0x85c00, 0x87a40, 0x87a80) leza w dolnym SRAM A53, cele
(0x0003_0050_c0xxxx) wygladaja na adresy po stronie gospodarza. Uklad pasuje do pierscienia
deskryptorow DMA/IDMA. To jedyna struktura w zrzucie, ktora przypomina deskryptory
uzywane przy deszyfrowaniu, ale **nie ma dowodu, ze nalezy do PPR**.

## 8. Wnioski

1. **Zrzut nie jest obrazem 256 MB pamieci.** To jeden blok 0x40000 B powtorzony 1024 razy,
   kazdy egzemplarz z wlasnym naglowkiem wyniku, ktory niesie adres zadania. Unikalnej
   tresci jest 256 kB. Transport nie wypelnil pola `przeslane` (0) i zwrocil `status` 0x20,
   wiec wedlug konwencji projektu sa to odczyty nieudane, a tresc jest stala zawartoscia bufora.

2. **Firmware A53 jest w zrzucie, ale tylko pierwsze 256 kB i bez adresu.** Chodzi o obraz
   ARM64 z banerem `cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358`,
   build-id `4519afcafb949f4aa494582264a14b45`, naglowkiem wersji pod 0x28, pakietem SDBGP
   pod 0x140 i kodem od 0x3a8 do 0x28000. Adresu tego fragmentu nie da sie ustalic
   z samego pliku, bo wszystkie 1024 zadania zwrocily ta sama tresc.

3. **Firmware WiFi (ARM32, 500 296 B) nie jest czescia tego zrzutu** i nie ma w nim
   zadnego innego obrazu firmware'u w czytelnej postaci.

4. **Struktur PPR w zrzucie nie ma.** Zero trafien wszystkich sygnatur generatora i wszystkich
   slow rozkazow profilu. PPR jest w `artifacts/a53-obraz-odtworzony.bin` pod adresami
   fizycznymi rownymi polom profilu oraz w `region_00028000.bin` pod offsetem przesunietym o 0x6f8.
   Blok wysokiej entropii 0x2d000 jest nieprzejrzysty i nie ma przy nim zadnego napisu
   wiazacego go z PPR albo z DECI.

5. **Korekta wczesniejszych notatek.** Rundy 107, 108 i 121 w `STAN-KONCOWY-KSTUFF-NG.md`
   opisuja ten plik jako "przesuniety obraz SRAM" z przesunieciem 0xfb i jako "okno 256 kB".
   Pomiar pokazuje, ze nie ma zadnego przesuniecia 0xfb: jest naglowek wyniku 0x28 bajtow,
   a tresc bloku to nie SRAM od zera, bo nie zawiera sygnatur PPR, ktore pod adresem
   fizycznym 0x2b124 byc musza. Wniosek "zrzut jest bezwartosciowy" (runda 108) jest
   **zbyt surowy**: blok jest prawdziwa trescia pamieci A53, tylko nie wiadomo ktorej,
   i jest jedynym miejscem w repo, gdzie widac obraz z banerem Oberon-KDE i build-id.

6. **Co robi robote:** male odczyty po 0x1000 B z samokalibracja (`tools/a53layout`)
   i skladanie obrazu z regionow, ktore jadro czyta roznymi rozmiarami. Ten zrzut jest
   dowodem, ze odczyt duzy (0x40000) zwraca stala odpowiedz i nie przenosi adresu,
   wiec nie nadaje sie do odtworzenia ukladu pamieci.

## 9. Odtworzenie pomiarow

Skrypty (Python 3 z numpy, tylko odczyt plikow) leza w `<work>\_work_a53live\`:

| skrypt | co mierzy |
|---|---|
| `p1_identity.py` | sha256, wielkosc, autokorelacja, entropia, zrzut 64 kB |
| `p2_align.py` | naglowki blokow, szukanie banera i sygnatury pomocnika |
| `p3_class.py` | klasyfikacja okien 4 kB, liczniki ARM32 i ARM64 |
| `p5_regions.py`, `p6_block.py` | porownanie z plikami regionow jadra, histogram wskaznikow |
| `p7_anchor.py` | kotwice adresowe (wzorzec spod 0x28000), napisy |
| `p8_scan.py` | liczniki dla calego pliku, wyciagniecie firmware'u WiFi, probki 64 B |
| `p9_ppr.py`, `p10_where_ppr.py` | sygnatury PPR w zrzucie i w pozostalych obrazach |
| `p11_regions.py`, `p12_final.py`, `p14_struct.py` | regiony, granice kodu, tablica deskryptorow |

Uruchomienie:

```
<dsh>\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe ^
  <work>\_work_a53live\p1_identity.py
```

Wyniki surowe w plikach `p1.out` do `p14.out` w tym samym katalogu.
