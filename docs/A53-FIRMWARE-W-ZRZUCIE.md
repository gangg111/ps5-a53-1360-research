# Firmware A53 w zrzucie jadra 13.60 (analiza pod katem oprogramowania procesora A53)

Data: 2026-10-19. Cel: sprawdzic, czy w istniejacym zrzucie jadra lezy oprogramowanie
procesora A53 (ten od transportu MP4), a nie tylko firmware WiFi.

Plik: `artifacts/kernel-1360-13.60.bin`, 67 108 864 B (64 MiB),
sha256 `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804` (sprawdzone ponownie,
zgadza sie). Baza obrazu `0xffffffffc0c60000`, wiec **offset w pliku = offset od ktext**,
a VA = `0xffffffffc0c60000 + offset`. Tekst jadra konczy sie na `0xCC0000`
(baza danych = ktext + 0xCC0000, zgodnie z `notes/ANALIZA-ZRZUTU-1360.md`), wszystko powyzej
to dane.

Skroty w notatce: ARM32 = kod ARM/Thumb-2 (AArch32), ARM64 = AArch64.

## 0. Wniosek w trzech zdaniach

1. Firmware WiFi (ARM32, wg payloadu NXP iw620) **jest** w zrzucie dokladnie tam, gdzie mowi
   tablica env payloadu: plik `0x01518160`, rozmiar `0x7A248` (500 296 B), kod Thumb-2
   z tablica wektorow ARM. Punkt zaczepienia potwierdzony co do bajtu.
2. Poza nim jest **jeden** inny obraz ARM32: firmware kontrolera Bluetooth (Thumb-2, ThreadX,
   Cortex-M3) od `0x01A1C000`, plus powiazany z nim blok danych/lancuchow patcha MCU
   od `0x0195F000`. To inna rodzina niz WiFi (podobienstwo zlepkow 16-bajtowych 0.016,
   wspolne jest tylko biblioteczne jadro ThreadX).
3. **ARM64 w zrzucie nie ma w ogole** (zero `ret`, zero `nop`, zero prologow `stp x29,x30`
   w calych 64 MiB), a obraz odniesienia A53 (`artifacts/a53-obraz-odtworzony.bin`) nie ma
   z zrzutem wspolnej tresci (0.16% przypadkowych 16-bajtowych zlepkow). Czyli oprogramowania
   A53 od MP4/PPR w tym zrzucie **nie ma**; jest tylko sterownik x86-64 `a53mm`/`deci5s`,
   ktory je obsluguje.

## 1. Metodyka i kalibracja detektorow

Zrzut jest obrazem jadra x86-64, wiec detektory kodu ARM trzeba najpierw wyskalowac na tym,
co w pliku jest na pewno kodem x86, na danych i na znanym kodzie ARM. Uzyte miary (na oknach
4 KiB, wyrownanie 4 B):

| miara | co liczy | x86-64 tekst | dane jadra | WiFi (ARM32, znany) | A53 ref (ARM64, znany) |
|---|---|---|---|---|---|
| `AL` | ulamek slow 32-bit z polem warunku 0xE | 0.059 | 0.000 | 0.071 | 0.005 |
| `BLarm` | slowa `0xEBxxxxxx` (BL w ARM) | 0.004 | 0.000 | **0.016** | 0.004 |
| `BLthumb` | pary polslow `0xF0xx` + `0xDxxx/0xFxxx` (BL w Thumb-2) | 0.005 | 0.000 | **0.055** | 0.001 |
| `push/pop` | `push {..,lr}` / `pop {..,pc}` w Thumb | 0.002 / 0.003 | 0.000 | 0.006 / 0.007 | 0.001 |
| `A64` | ulamek slow z bajtem 3 w {94,14,A9,F9,91,D1,B9} | 0.012 | 0.000 | 0.026 | **0.279** |
| `stp x29,x30` | slowa `(w & 0xFFC07FFF) == 0xA9807BFD` | 0 | 0 | 0 | **49 na 64 KiB** |
| `ret` | `0xD65F03C0` | 0 | 0 | 0 | **310 na 64 KiB** |
| `nop` | `0xD503201F` | 0 | 0 | 0 | 60 na 64 KiB |

Progi przyjete po kalibracji: `BLthumb > 0.020` albo `BLarm > 0.012` (ARM32),
`A64 > 0.12` albo `ret/nop/prolog > 0` (ARM64). Czulosc detektora ARM64: 4 KiB kodu AArch64
daje okolo 20 wystapien `ret`, wiec blok ARM64 mniejszy niz ~1 KiB nie moglby sie ukryc.
Skany pomocnicze: tablice wektorow (`ldr pc,[pc,#imm]` 8 razy pod rzad), naglowki ELF,
magic SELF, sygnatury kontenerow, lancuchy producentow.

## 2. Punkt zaczepienia: firmware WiFi A53 (potwierdzony)

| pole | wartosc |
|---|---|
| offset w pliku | `0x01518160` (`0x1518160`), wyrownany do 16 B |
| VA | `0xffffffffc2178160` |
| rozmiar z tablicy env (`env+0x130`) | `0x7A248` = **500 296 B** |
| koniec | plik `0x015923A8`, VA `0xffffffffc21F23A8` |
| entropia | 6.828 (cala), 6.45 srednio w oknach 4 KiB |
| typ | ARM32, rdzen Thumb-2, tablica wektorow w trybie ARM |

Pierwsze 64 B:

```
01 00 00 00 00 00 00 00 00 02 00 00 04 47 ba 08
1c f0 9f e5 1c f0 9f e5 1c f0 9f e5 1c f0 9f e5
1c f0 9f e5 1c f0 9f e5 1c f0 9f e5 1c f0 9f e5
03 82 11 35 c0 a7 10 00 d8 a6 10 00 00 a7 10 00
```

Dowody, ze to kod ARM, a nie przypadkowe bajty:

- 16-bajtowy naglowek (`01 00 00 00 | 00 00 00 00 | 00 02 00 00 | 04 47 ba 08`), a od `+0x10`
  **osiem identycznych slow `0xE59FF01C`, czyli `ldr pc,[pc,#0x1c]`**. To klasyczna tablica
  wektorow ARM (8 wyjatkow), kazda galez skacze przez wskaznik z puli literaliow pod `+0x30`.
- W calym zrzucie jest 233 slow `ldr pc,[pc,#imm]`: 232 z nich leza **wewnatrz tego obrazu**
  (w tym jeden ciag osmiu kolejnych pod `0x01518170`, zas `0x151B4C8`, `0x1526B9C`, ...,
  `0x1584488` to tabele veneerow), a jedyne trafienie poza nim (`0x1CA9C58`, slowo
  `0xE51FFE1A`) lezy w nieprzejrzystym bloku o entropii 8 i jest przypadkowe.
- Statystyki kodu: 1968 slow `BL` w trybie ARM, 35 `bx lr`, 228 `pop {..,pc}`,
  50 `push {..,lr}`, gestosc 32-bitowych instrukcji Thumb-2 `0.243`.
- Wewnatrz obrazu sa nazwy obiektow RTOS i warstwy 802.11 (dowod, ze to firmware WLAN,
  a nie dowolny kod ARM): `SleepConfirmTmr` (0x15897E8), `NullPktDoneTmr` (0x15897FC),
  `OSABytesPool` (0x1589CE8), `CBExecSema_i` (0x1589E84), `btsyncDeassertTmr` (0x1589F70),
  `wlApuPSFlags` (0x158A82C), `TkipWepAesSema` (0x158A84C), `TimerSema` (0x158B3C0),
  `CoexNullPktDoneTmr` (0x158B73C), `TxQFlags` (0x158B808), `TxNotifyFlags` (0x158B89C),
  `TimerCbMsgQ` (0x158BD70), `MacMgmtSMEMsgQ` (0x158BD8C), `scanAgentTableSema` (0x158BFAC),
  `TxMgmt80211MsgQ` (0x158C4B8). Nazwy `Coex*` i `btsync*` to wspolistnienie z BT,
  czyli typowy obraz combo.

Uwaga do rozmiaru: `notes/1360LINUX-OFFSETY-13.60.md` w wierszu `env+0x130` podaje
`0x7A248` i w nawiasie "500 040 B". To niespojnosc **w samej notatce**: `0x7A248` =
500 296 B i tyle bajtow lezy w zrzucie. Wartosc 500 040 = `0x7A148`, czyli o 256 B mniej.

Bezposrednio za koncem obrazu (`0x015923A8`) leza juz inne dane (`ff ff 00 00 ...`),
a w `0x01592000..0x01598000` sa tabele i lancuchy w stylu ThreadX (`%s[%d]:panic:`,
`[%s:%d ERR]<%d>`, `[%s:%d Info]<%d>`). Nie ma tam kodu ARM: `BLarm` 0.000, `push`/`pop` 0.000,
a podniesiony `BLthumb` (0.03 do 0.05) pochodzi wylacznie z tabel 16-bitowych (`62 42 f2 fe`
powtarzane w kolko), nie z instrukcji. To ogon tej samej rodziny firmware'u, ale juz poza
rozmiarem z tablicy env.

## 3. Drugi obraz ARM32 w zrzucie: firmware kontrolera Bluetooth

Znaleziony skanem jako jedyny inny rejon spelniajacy progi ARM32.

| pole | wartosc |
|---|---|
| offset w pliku | `0x01A1C000` (rdzen kodu `0x01A1C000..0x01A39400`, 119 808 B) |
| VA | `0xffffffffc267c000` |
| entropia | 6.933 (rdzen kodu), 6.85 dla `0x1A18000..0x1A3E000` |
| typ | ARM32, Thumb-2 (pod `0x1A1C000` stoi od razu funkcja, brak tablicy wektorow w tym miejscu) |
| podobienstwo do WiFi | 16-bajtowe zlepki: 465/29 572 = **0.0157** (wspolne tylko fragmenty biblioteki RTOS) |
| zlepki wspolne z obrazem A53 (ref) | 0 |

Pierwsze 64 B:

```
08 60 70 47 40 f0 02 00 fa e7 4f f0 29 42 01 29
b2 f8 24 11 03 d0 81 43 a2 f8 24 11 70 47 01 43
fa e7 07 49 01 28 09 68 08 68 03 d0 20 f0 01 00
08 60 70 47 40 f0 01 00 fa e7 00 00 64 01 00 a9
```

Dekodowanie Thumb-2 (capstone) daje spojny kod, nie smiec:

```
0x1a1c000  0860        str   r0, [r1]
0x1a1c002  7047        bx    lr
0x1a1c004  40f00200    orr   r0, r0, #2
0x1a1c008  fae7        b     #0x1a1c000
0x1a1c00a  4ff02942    mov.w r2, #-0x57000000
0x1a1c00e  0129        cmp   r1, #1
0x1a1c010  b2f82411    ldrh.w r1, [r2, #0x124]
0x1a1c014  03d0        beq   #0x1a1c01e
0x1a1c016  8143        bics  r1, r0
0x1a1c018  a2f82411    strh.w r1, [r2, #0x124]
0x1a1c01c  7047        bx    lr
```

Statystyki: `BLarm` 0.0162, `BLthumb` 0.0532, `push {..,lr}` 0.0106, `pop {..,pc}` 0.0115,
`AL` 0.0581, `A64` 0.0278 (poziom smieciowy), `ret`/`nop`/`stp` = 0.

Identyfikacja (lancuchy wewnatrz regionu):

| offset | lancuch |
|---|---|
| 0x1A28600 | `bt_hci` |
| 0x1A25960, 0x1A2AD24 | `bt_usb` |
| 0x1A2AF2C | `TRAN_Q` |
| 0x1A2AF38 | `TMSVR_Q` |
| 0x1A2AF48 | `HCI Thread` |
| 0x1A2AF60 | `LM Thread` |
| 0x1A2AF78 | `LL Thread` |
| 0x1A2AF90 | `TRAN Thread` |
| 0x1A2AFA8 | `TMSVR Thread` |
| 0x1A32488, 0x1A3249C | `BTDS_Q`, `BTDS_Thread` |
| 0x1A28CA4 | `IccQFlags` |
| 0x1A1E7B8, 0x1A1E818 | `CustomTask`, `CustomFlag` |
| 0x1A39518..0x1A3953E | `mdev_sbcDec2`, `mdev_sbcEnc2`, `mdev_sbcDec`, `mdev_sbcEnc` |
| 0x1A3A564 | `Copyright (c) 1996-2010 Express Logic Inc. * ThreadX Cortex-M3/RVDS Version G5.3.5.2 SN: 22471-108-1` |

Czyli: kontroler Bluetooth (watki HCI/LM/LL/TRAN/TMSVR, kodek SBC do HFP/A2DP) na ThreadX
dla Cortex-M3. `mdev_sbc*` (4 trafienia) i `HCI Thread` (1 trafienie) nie wystepuja nigdzie
indziej w zrzucie, wszystkie sa w tym regionie.

### 3.1 Powiazany blok danych i lancuchow patcha MCU

| pole | wartosc |
|---|---|
| offset | `0x0195F000..0x0196A400` (74 752 B) |
| entropia | 2.0 do 6.8 (tabele, lancuchy, wypelniacze) |
| typ | **dane**, nie kod: `BLthumb` 0.000, `push`/`pop` 0.000, brak tablicy wektorow |

Pierwsze 64 B (widac rekordy 12-bajtowe, nie kod):

```
2e 16 1f e1 f0 81 dd 22 b4 06 66 00 00 ff 58 00
00 11 b6 06 3c 1d 7b 38 f0 01 dd 21 b4 06 66 00
00 ff 58 00 00 12 b6 06 3c 2d 7b 37 f1 01 84 00
dd 22 b4 06 66 00 00 ff 58 00 00 13 b6 06 3c 2d
```

Lancuchy (dowod, ze to oprogramowanie ukladu connectivity/BT):

```
0x01963D38  ../patch/common/sys_patch_common_mcu.c
0x01964BC8  ../patch/bgf/sys_patch_mcu.c
0x01964E18  ../bluetooth/output/patch/hal/auto_gen/btsys17_a7972_pos/BT_Power_on_sequence_emi_rom.c
0x01964B98  MCU_Patch_init
0x01964A54  ;WF patch ccif error
0x01964234  ;;[CONNSYS] coredump start ..
0x01964574  ;ILM ROM PD SLP ACCESS DETECT
0x01964804  <<< There should be 2 core dump files. This one is %x. >>>
```

W srodku tego bloku (`0x01968000..0x0196A400`) lezy wypelniacz `81 bc 8a 90` powtarzany
w kolko. Miedzy tym blokiem a kodem z 3.0 (`0x0196A400..0x01A1C000`) sa rejony o entropii
7.3 do 7.95, czyli tresc zageszczona albo zaszyfrowana, bez znacznikow kodu.

## 4. Falszywe trafienia (co wyglada na ARM, a nie jest)

Kazdy rejon ponizej przechodzil jeden z progowych testow i zostal odrzucony po pelnym
zestawie miar. Warte zapisania, zeby nikt nie zaczynal od zera.

| offset | entropia | co zwiodlo | pierwsze 48 B | faktyczna tresc |
|---|---|---|---|---|
| `0x0102D000` | 7.45 | `AL` 0.30, `BLthumb` 0.058 | `db 12 98 f1 78 f8 0f 0d ...` | tabela wartosci 16- i 32-bitowych, gorny bajt 0x00/0x01/0x02 albo 0xE0..0xFF, brak `push`/`pop` |
| `0x01A46000` | 5.48 | `BLthumb` 0.288 | `1c c6 16 ff 1c c6 16 ff ...` | tabela slow 16-bit z bajtem 0xF0/0xF8; `AL` 0.001, `push` 0.0007 |
| `0x018CF000` | 4.81 | `BLthumb` 0.155 | `80 40 01 00 80 48 01 00 ...` | rekordy 4-bajtowe, obok lancuchy GPU (`[KERNEL] INFO: ... PPRREQ55470...`) |
| `0x018D8000` | 3.99 | `BLthumb` 0.142 | `80 40 01 00 ...` | to samo, inna instancja tabeli |
| `0x02E69000` | 2.09 | `BLthumb` 0.190 | `09 14 f5 c1 ff ff ff ff ...` | struktury FAT12/exFAT (`SCEI`, `ORBIS ROOT FAT12`, `EXFAT`) |
| `0x037D6000`, `0x03922000` | 6.85 / 6.05 | `A64` 0.0625 / 0.125 | `b3 12 b4 12 b5 12 b6 12 ...` | posortowane tabela bajtow; brak `ret`/`nop`/`stp` |
| `0x03E14000` | 5.80 | `A64` 0.144 | `00 00 06 09 04 00 00 00 e4 69 01 00 ...` | rekordy 16-bajtowe (klucz, rozmiar, hash); w tym rejonie leza tez 2 przypadkowe trafienia stalej `0x20000201` |
| `0x00264000` | 4.49 | `AL` 0.177 | `e9 ab 35 71 00 cc cc cc ...` | tekst x86-64: thunki `jmp rel32` z wypelnieniem `cc`, ktore podnosi licznik `AL` |

Reguly, ktore z tego wynikaja: `BLthumb` bez `push`/`pop` i bez `AL` to prawie zawsze tabela
danych (bajty 0xF0/0xF8 w slowach 16-bit), a samo `AL`/`A64` w danych to artefakt bajtow
0xE0..0xFF i 0x14..0x17.

## 5. ARM64: zero w calym zrzucie

To najwazniejszy wynik negatywny, wiec z pelnymi liczbami.

| miara w 64 MiB | wynik |
|---|---|
| `0xD65F03C0` (`ret`) | **0** |
| `0xD503201F` (`nop`) | **0** |
| `stp x29,x30,[sp,#-N]!` (maska `0xFFC07FFF` = `0xA9807BFD`) | **0** |
| `mov x29,sp` (`0x910003FD`) | **0** |
| `A64` (gestosc bajtow typowych dla AArch64) | 0.0076 (x86-64 tekst: 0.0117, prawdziwy kod A53: 0.2791) |
| naglowki ELF z `e_machine = 0xB7` (AArch64) | 0 z 12 trafien `\x7fELF` (osiem to prawdziwe naglowki, wszystkie `e_machine = 0x3E`, x86-64) |
| magic SELF (`bf 56 61 df 5a d7 15 4f`) | **0** wystapien |

Kalibracja wzgledem znanego kodu ARM64 z `artifacts/a53-obraz-odtworzony.bin`
(rejon `0x28000..0x38000`, 64 KiB): 310 `ret`, 60 `nop`, 49 prologow `stp`/`movsp`,
`A64` 0.2791. Gdyby w zrzucie lezal obraz A53 tej wielkosci, detektory dalyby setki trafien.
Daja zero. Wniosek: **w zrzucie nie ma zadnego bloku kodu AArch64 wiekszego niz ~1 KiB**.

Dodatkowo: obraz odniesienia A53 (sprezony z odczytow SDBGP, 1 MiB, 284 545 niezerowych
bajtow) nie ma z zrzutem wspolnej tresci. 16-bajtowe zlepki: 115 z 73 633 = 0.16%, i sa to
same ogolne wzorce (`00..`, `ff..`, wyrownania). Dla sekcji kodu A53 (`0x28000..0x38000`)
zlepki 32-bajtowe: 2 z 8060 = 0.02%. Czyli obraz A53 **nie jest** schowany w zrzucie
w postaci jawnej ani nawet we fragmentach.

## 6. Co jest, a czego nie ma, wokol A53, MP4, decyzji i PPR

Lancuchy w zrzucie (cala liczba trafien, wszystkie w danych jadra, czyli w rodata
sterownika x86-64):

| wzorzec | trafien | pierwsze offsety |
|---|---|---|
| `SDBGP` | 11 | 0x126FC0C, 0x12A2334, 0x12ABD87, 0x12FF05A, 0x131E765 |
| `DECI5S` | 24 | 0x126FC05, 0x128127C, 0x12A232D, 0x12A9EEC |
| `A53IO` / `a53io` | 61 / 61 | 0x126D918, 0x126F0B8, 0x1272235 |
| `deci` | 291 | 0x126EA53, 0x12743F4, 0x1274410 |
| `ppr` | 281 | 0x126D55C, 0x127465D, 0x1274859 |
| `mp4` | 1190 | 0x126E79D, 0x126F494, 0x127088A |
| `a53` | 1195 | 0x126D918, 0x126F0B8, 0x126F121 |
| `aarch64` | 1 | 0x128BEA8 `mp4:Info:%s:%s: payload->AARCH64_FAR       = 0x%016lx` |
| `armv`, `cortex` | 1 / 1 | 0x1DE5DB7 (`armV`), 0x1A3A564 (baner ThreadX Cortex-M3) |

Konkretne dowody, ze w zrzucie jest **obsluga** A53, a nie jej oprogramowanie:

- Kod sterownika (x86-64) budujacy naglowek pakietu DECI5S/SDBGP: pod `0x00C29626` lezy
  lancuch `PD5s`, a pod `0x00C2965C` i `0x00C2966F` instrukcje `movabs rax, 0x80FF018000000028`
  oraz `movabs rax, 0x2000020180FF0201`; wzorzec `0x20000201` trafiony pod `0x00C29675`.
  Stala `0x20000201` to `DECI5S_PROTO_SDBGP` z `notes/STAN-KONCOWY-KSTUFF-NG.md`.
  Naglowek jest skladany w rejestrze (`48 b8 ...`), a nie trzymany w danych.
- Sciezki zrodel sterownika w rodata: `W:/Build/J03950001/sys/mp4/x86/kernel/modules/a53mm/`
  (`a53mm.c`, `a53mm_page_table.c`, `a53mm_privilege_mode.c`, `a53mm_command.c`,
  `a53mm_input_ring.c`, `a53mm_trace.c`, `a53mm_error_handling.c`) oraz
  `sys/fs/devpfs/devpfs_a53ioctl.c` (0x129DA14).
- Lancuchy decydujace o ukladzie pamieci A53: `[A53MM] MM controller is ready.` (0x12CCE72),
  `a53mm_context.mimm.mimm_sdma0_mmio_va` (0x12CCE92), `mmSDMA0_PAGE_RB_BASE` (0x1274ED6).
- Sciezka kryptograficzno-kompresyjna obrazu (kluczowa dla pytania "skad wziac firmware"):
  `ERROR: %s(%d) a53io_crypt_sha() failed` (0x12A7454), `a53io_crypt_xts() failed` (0x1358B03),
  `a53io_decompress_block() failed` (0x1358B2F), `a53io_scf_read_revision_id failed` (0x135A88E).
  Czyli jadro **odszyfrowuje i dekompresuje** obraz A53 do bufora przed przekazaniem go
  procesorowi, wiec na dysku obraz jest w kontenerze (SCF/SELF), a nie w formie jawnej.
- Nazwy plikow-obiektow w rodata: `decid.self` (0x129CBDB), `a53.elf` (0x12BEF93),
  `mp4/dump_for_decid` (0x1274F61), `deci/deci5s/big/big_system` (0x1288213),
  `es0.crypt` (0x128822E).

Czego nie ma:

- Zandego obrazu ARM64 (patrz rozdzial 5).
- Zadnej tablicy deskryptorow obrazu A53 z adresami/docelowymi rozmiarami
  (`0x04E00000`, `0x04E28000`, `0x04E61F00`, `0x04E5B964`, `0x06410000` z profilu
  `artifacts/kstuff-profile-1360.h`): wszystkie trafienia tych stalych jako 4- i 8-bajtowych
  wzorcow (np. `0x04E00000` pod `0x155AA85`, `0x06410000` pod `0x179A2CE`) sa przypadkami
  w danych. Zadne nie sasiaduje z tablica adresow A53 ani z kodem `a53mm`.
- Zadnego naglowka SELF, ktory zwykle otwiera zaszyfrowany obraz.

## 7. Rejony nieprzejrzyste (entropia ~8). Czego nie da sie wykluczyc

Znalezione bloki o entropii 7.9 do 8.0 (czyli tresc zageszczona albo zaszyfrowana, bez
zadnych znacznikow kodu):

```
0x015C0000..0x01710000  1 376 256 B
0x018F0000..0x01950000    393 216 B
0x019F0000..0x01A10000    131 072 B
0x01B00000..0x01BA0000    655 360 B
0x01BC0000..0x01C00000    262 144 B
0x01C10000..0x01C70000    393 216 B
0x01C80000..0x01D40000    786 432 B
0x01D50000..0x020F0000  3 801 088 B
0x02100000..0x02110000     65 536 B
```

Suma 7 864 320 B (7.5 MiB) nieprzejrzystej tresci w 64 MiB. Naglowki tych blokow nie maja
zadnej sygnatury (sprawdzone: ELF, SELF, gzip, zlib, lzma, xz, zstd, FIT/DTB, ARM64 image,
uImage, UBI, lz4, bzip2). Uczciwe postawienie sprawy: **w tych blokach moze lezec zaszyfrowany
obraz A53 i tym skanem tego nie rozstrzygniemy**, ale nie ma zadnego dowodu, ktory by je z A53
laczyl (brak odwolan z kodu `a53mm`, brak nazw plikow w ich otoczeniu, brak naglowka SELF).
Zeby to zamknac, trzeba by znac klucz albo porownac z plikiem z konsoli.

## 8. Zestawienie znalezionych obrazow

| nr | region (plik) | VA | rozmiar | entropia | typ | poczatek | rodzina |
|---|---|---|---|---|---|---|---|
| A | 0x01518160..0x015923A8 | 0xffffffffc2178160 | 500 296 B | 6.83 | ARM32 Thumb-2 + tablica wektorow ARM | 16 B naglowka, 8 x `ldr pc,[pc,#0x1c]` | WiFi (NXP iw620 wg payloadu), nazwy 802.11 |
| B | 0x01A1C000..0x01A39400 | 0xffffffffc267c000 | 119 808 B | 6.93 | ARM32 Thumb-2 | funkcja `str r0,[r1]; bx lr` | BT (HCI/LM/LL/TRAN/TMSVR, SBC, ThreadX Cortex-M3) |
| B' | 0x0195F000..0x0196A400 | 0xffffffffc25BF000 | 74 752 B | 5.0 do 6.8 | dane i lancuchy, bez kodu | tabele + `sys_patch_mcu.c` | patch MCU / CONNSYS dla tego samego ukladu BT |
| brak | cale 64 MiB | | | | **ARM64: 0 blokow** | | A53/MP4/PPR: nieobecny |

Podobienstwo B do A (16-bajtowe zlepki): 0.0157, czyli ta sama rodzina biblioteczna
(ThreadX), ale inny obraz. Podobienstwo A do obrazu A53 z konsoli: 0.0003. Podobienstwo
obrazu A53 do calego zrzutu: 0.00156.

## 9. Wniosek koncowy i skad wziac oprogramowanie A53

Firmware WiFi A53 w zrzucie **jest** i zgadza sie z tablica env payloadu co do bajtu
(offset `0x1518160`, rozmiar `0x7A248`), wiec zrzut rzeczywiscie zawiera obrazy firmware'ow
dla procesorow pomocniczych i metoda "szukaj kodu ARM w danych jadra" jest poprawna.

Oprogramowania A53 od MP4/PPR (ARM64, przestrzen `0x04E...` i `0x064...`) w tym zrzucie
**nie ma**. Zrzut zawiera natomiast komplet strony x86-64: sterownik `a53mm` + `deci5s`
z protokolem SDBGP, tablica polecen, obsluga kryptografii XTS i dekompresji. Sam obraz
A53 jest poza jadrem: jadro go deszyfruje i dekompresuje do bufora, a zrodlem jest plik
z konsoli (`decid.self` albo `a53.elf`).

Skad go wziac, w kolejnosci od najtanszego:

1. **Z pamieci A53 przez SDBGP** (to juz czesciowo zrobione): `artifacts/a53-obraz-odtworzony.bin`
   ma 786 432 B z dziewieciu regionow i zawiera prawdziwy kod ARM64 (to on jest kalibracja
   w rozdziale 5). Brakuje pokrycia calego obrazu, a odczyt dziala, bo potwierdza go ten sam
   sterownik z rzutu (`SDBGP_READ_MEMORY`). To jedyna droga, ktora daje obraz **po**
   odszyfrowaniu i dekompresji, czyli ten, ktory realnie wykonuje A53.
   Uwaga praktyczna: rownolegle powstala `notes/A53-LIVE-256MB-ANALIZA.md` pokazuje, ze czesc
   odczytow konczy sie statusem 0x20 i zwraca powtorzona zawartosc bufora. Kazdy zrzut A53
   trzeba wiec weryfikowac polem przeslanych bajtow i statusem, nie samym naglowkiem
   odpowiedzi, inaczej "1024 dobre porcje" znacza 256 kB tresci powtorzone 1024 razy.
2. **Z pliku na konsoli**: `decid.self` (nazwa jest w rodata jadra, 0x129CBDB) to kontener
   SELF, wiec do analizy trzeba go odszyfrowac. Punktem wyjscia sa funkcje kryptograficzne
   jadra opisane w `notes/ANALIZA-ZRZUTU-1360.md`: `sceSblServiceCrypt` (odwolanie pod plikiem
   `0x2E8F17`) i `sceSblServiceMailbox` (w kstuff `-0x71B9F0`, czyli plik `0x5A4610`).
3. **Z bufora jadra w czasie startu gry**: `a53io_crypt_xts` i `a53io_decompress_block`
   dostaja obraz jawny. Zrzut 64 MiB zrobiony po starcie go nie zlapal (bufor zwolniony
   albo nadpisany), ale zrzut zrobiony w trakcie `deci5s_suspend_phase0`/`resume` powinien.
   Warto celowac w moment, w ktorym `[A53MM] MM controller is ready.` jeszcze nie wystapil.
4. Zrzut ukladu A53 przez `tools/sramwin` i `tools/a53dump` (jak w `notes/STAN-KONCOWY-KSTUFF-NG.md`).

## 10. Jak to odtworzyc

Pliki robocze leza poza repozytorium, w `<repo>\_robocze-a53\`:

| skrypt | co robi |
|---|---|
| `s1b_wifi.py` | weryfikacja regionu WiFi: bajty, tablica wektorow, statystyki ARM, mapa 8 KiB |
| `s3_metrics.py` | kalibracja miar na tekscie x86, danych, WiFi i obrazie A53 |
| `s4_scan.py` | skan calych 64 MiB oknami 4 KiB, klastrowanie rejonow, zapis `blocks.npy` |
| `s5_inspect.py` | gleboki wglad w kandydatow (bajty, entropia, zlepki, lancuchy) |
| `s7_strings.py` | 152 574 lancuchow ASCII i 1186 UTF-16, trafienia slow kluczowych |
| `s9_inv.py` | niezalezny skan z miara `S = BLarm + BLthumb + push + pop`, klastrowanie |
| `s11_files.py`, `s12_ctx.py` | nazwy plikow firmware, kontekst `decid.self`, `a53.elf`, stala `0x20000201` |
| `s14_elf.py` | naglowki ELF (`e_machine`), magic SELF, surowe `SDBGP`/`DECI5S`, banery RTOS |
| `s15_final.py` | wszystkie liczby z tej notatki w jednym przebiegu |

Uruchomienie (Python z pakietu DSH, numpy + capstone 5.0.7):

```
$py = "<dsh>\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
& $py "...\_robocze-a53\s15_final.py"
```

Deasemblacja fragmentu Thumb-2 poza Pythonem (WSL, binutils):

```
arm-none-eabi-objdump -D -b binary -m arm --disassembler-options=force-thumb \
  --adjust-vma=0x1a1c000 --start-address=0x1a1c000 --stop-address=0x1a1c400 kernel-1360-13.60.bin
```
