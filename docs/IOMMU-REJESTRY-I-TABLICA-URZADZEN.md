# IOMMU na 13.60: baza rejestrow, tablica urzadzen (DTE), device id MP4

Dokument odpowiada na trzy pytania: pod jakim adresem leza rejestry IOMMU, jak wyglada
wpis tablicy urzadzen i jaki identyfikator ma urzadzenie MP4. Kazde twierdzenie ma dowod:
offset w pliku i bajty albo adres instrukcji i jej tresc. Miejsca niepewne sa nazwane
wprost, bez zgadywania.

## Material i sposob liczenia adresow

- Zrzut: `artifacts/kernel-1360-13.60.bin`, 67 108 864 B, sha256
  `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804` (sprawdzone ponownie).
- Baza obrazu jadra `0xffffffffc0c60000`, wiec **offset w pliku = VA - 0xffffffffc0c60000**.
  Baza danych (`.data`) to `text + 0xCC0000` (`notes/ANALIZA-ZRZUTU-1360.md`).
- Deasemblacja: `objdump -D -b binary -m i386:x86-64 -M intel --adjust-vma=0xffffffffc0c60000`
  (binutils w WSL, pliki robocze w `/root/iommu-baza/`, `kernel.bin` to kopia zrzutu).
- Wyszukiwanie odwolan: wlasny skaner instrukcji `LEA/MOV r64,[rip+disp32]` po calym pliku
  (148 798 odwolan) plus skaner `call rel32` oraz szukanie wskaznikow 64-bit.
- Dolozone sa dwa logi z konsoli, ktore nie pochodza z tego zrzutu, ale dotycza tego samego
  sprzetu i tej samej wersji systemu (`0x13600007`): `artifacts/klog-2026-10-14-kstuff-ng-test.txt`
  (linia 6, payload kexp) i `artifacts/a53win-log.txt` (linia 2). Sa oznaczone jako ZEWNETRZNE.

## 1. Tabel ACPI nie ma, IVRS w zrzucie nie wystepuje

Przeszukanie calego pliku (64 MB) na ciagi bajtow:

| sygnatura | trafien |
|---|---|
| `IVRS` | 0 |
| `IVHD` | 0 |
| `IVMD` | 0 |

Sygnatury ACPI, ktore w zrzucie sa, wystepuja wylacznie jako wpisy tabeli obslugi ACPI
w danych jadra, na przyklad:

```
off 0x0e87390: 46 41 44 54 00 00 00 00 a6 de f0 c1 ff ff ff ff   "FADT"
off 0x0e873c0: 58 53 44 54 00 00 00 00 a6 de f0 c1 ff ff ff ff   "XSDT"
```

Wniosek: **jadro 13.60 nie ma czym odczytac IVRS i nie da sie z niego wyprowadzic bazy
rejestrow IOMMU po ACPI**. Baza jest wyliczana z przestrzeni konfiguracji urzadzenia
(punkt 3). Napis `AMD IOMMU` wystepuje dokladnie raz, w bloku diagnostycznym sterownika:

```
off 0x1370e9e: "AMD IOMMU"
off 0x1370e78: " raw dte[%d]:0x%08x"
off 0x1370e8d: "domain_id: %04x"
off 0x1370e65: "    pml4:0x%016lx"
off 0x1370e31: "Too large IOMMU Command Buffer 3 Tail Ptr:0x%lx"
off 0x1370ea8: "%s: %s specified too big bus addr 0x%lx"
```

Dwa skrajne napisy z tego bloku maja odwolania w kodzie sterownika (`0xffffffffc11596d2`
i `0xffffffffc115b79d`), ale `raw dte[%d]`, `domain_id: %04x` i `AMD IOMMU` **nie maja
zadnego odwolania** (sprawdzone skanerem LEA/MOV i szukaniem wskaznikow 64-bit). Funkcja,
ktora wypisuje surowe slowa DTE, nie lezy w tym obrazie, choc lezy w tym samym module
zrodlowym.

## 2. Sterownik IOMMU w zrzucie

Nazwy i wejscia potwierdzone napisami i kodem:

| co | VA | dowod |
|---|---|---|
| globalna zmienna ze wskaznikiem softc | `0xffffffffc41a3a70` | `mov r15,[rip+0x304ab11]` pod `0xffffffffc11592e8`, off 0x4f92e8, czyli obraz + 0x3543A70 |
| attach sterownika | `0xffffffffc115abd0` | napis `iommu` (off 0x133beda) ladowany pod `0xffffffffc115ae05` |
| mapa urzadzenia i rejestrow | opis w punkcie 3 | kod od `0xffffffffc115adc7` |
| dodanie wpisu tablicy urzadzen | `0xffffffffc115c2f0` | napis `iommu_add_device_table_entry` (off 0x12bed31) pod `0xffffffffc115c5b3` i `0xffffffffc115c809` |
| wpisanie mapowania (PASID) | `0xffffffffc1158b80` | `or rbx,1` i zapis do tablicy, punkt 6 |
| wyslanie polecenia do urzadzenia | `0xffffffffc1159670` | zapis rejestru `CB3TPR`, punkt 5 |
| zrzut stanu rejestrow | `0xffffffffc1159030` | napisy `IOMMU MMIO ...`, punkt 5 |
| obsluga bledu tlumaczenia | `0xffffffffc1158e10` | stale `0x2003`, punkt 7 |
| nazwy wewnetrzne | `iommu io` (off 0x12d47d9), `iommu cmd` (off 0x12a0a4b), `iommu dt` (off 0x12a0a55), `iommu bsf` (off 0x1351b63) | uzywane przy zakladaniu blokad i zasobow w attach |
| rozmiar softc | `0x60bc0` | `mov esi,0x60bc0` pod `0xffffffffc115adea`, off 0x4fadea |

Softc trzyma liste kontekstow urzadzen: `[softc+0xb8]` to glowa listy (`mov rbx,[r15+0xb8]`
pod `0xffffffffc1159312`, off 0x4f9312), a kazdy kontekst ma pole `+0x00` jako nastepnik
(`mov r13,[r13+0x0]` pod `0xffffffffc1158e90`, off 0x4f8e90).

## 3. Baza rejestrow: jak powstaje i jaka jest jej wartosc

### 3.1 Kod, ktory ja wylicza (attach, `0xffffffffc115abd0`)

```
ffffffffc115ac5d  mov r12,[rbp-0x58]        ; urzadzenie
ffffffffc115ac69  mov ecx,0x4
ffffffffc115ac6e  mov rsi,r12
ffffffffc115ac71  call r15                  ; odczyt konfiguracji, rejestr 0x44, szerokosc 4
ffffffffc115acd2  mov ecx,0x4
ffffffffc115accd  mov edx,0x48
ffffffffc115acda  call r12                  ; odczyt konfiguracji, rejestr 0x48, szerokosc 4
ffffffffc115ad3a  mov edx,0x4
ffffffffc115ad3f  mov ecx,0x2
ffffffffc115ad4b  call r13                  ; odczyt rejestru 0x04 (Command), 16 bit
ffffffffc115ad54  or  r13d,0x146            ; wlaczenie pamieci, bus master, SERR, PERR
ffffffffc115ad1e  and r14d,0xffffc000       ; maska dolnego slowa
ffffffffc115ad44  shl r15,0x20              ; gornej slowa
ffffffffc115ad90  or  r15,r14               ; baza = (cfg48 << 32) | (cfg44 & 0xffffc000)
ffffffffc115adc7  lea rdi,[r15+0x8000]      ; baza rejestrow = baza + 0x8000
ffffffffc115adce  mov esi,0x18000           ; rozmiar mapowania 96 kB
ffffffffc115add3  call 0xffffffffc154ba00   ; mapa pamieci fizycznej, zwraca VA
ffffffffc115add8  mov r12,rax
ffffffffc115adde  add r12,0xffffffffffff8000  ; VA - 0x8000
ffffffffc115ae0c  mov [r14+0x40],r12        ; softc + 0x40 = VA okna (przesuniete o 0x8000)
ffffffffc115ae10  mov [r14+0x48],r15        ; softc + 0x48 = baza z konfiguracji
```

Bajty kluczowych rozkazow: off 0x4fadde `49 81 c4 00 80 ff ff` (`add r12,-0x8000`),
off 0x4fae0c `4d 89 66 40`, off 0x4fae10 `4d 89 7e 48`.

Skutek: **adres rejestru = [softc+0x40] + offset**, a offset jest liczony wzgledem bazy
z konfiguracji (bo `[softc+0x40]` = VA mapy(baza + 0x8000) minus 0x8000). Obszar mapowany
to `[baza + 0x8000, baza + 0x20000)`.

### 3.2 Jaka jest wartosc bazy

Zrzut sam jej nie zawiera (jest czytana z konfiguracji w czasie startu), ale sa dwa
niezalezne pomiary na tej samej konsoli:

1. ZEWNETRZNE, `artifacts/klog-2026-10-14-kstuff-ng-test.txt` linia 6:

```
<118>[kexp] kaddrs { softc: 0xffffff8004568000 mmio: 0xffffa919fdd80000 cb3: 0xffffffff91422000 dmap: 0xffffa91900000000 cr3: 0x891d11000 }
```

   `mmio` = `dmap + 0xfdd80000`, czyli pole `[softc+0x40]` = `dmap(0xfdd80000)`, a wiec
   **baza z konfiguracji = 0xfdd80000**. Pole `cb3` = `0xffffffff91422000` lezy pod tym samym
   przesunieciem obrazu co `[softc+0x80]` w tym zrzucie (`0xffffffffc41b2000`), czyli jest to
   bufor polecen (punkt 5).

2. W zrzucie jest tablica zasobow MMIO modulu MP4/A53. Jej wpis o nazwie `iommummio`
   (dokladnie ta sama nazwa, co zasob rejestrowany przez sterownik IOMMU) lezy pod VA
   `0xffffffffc46d8820`, off 0x3a78820:

```
off 0x3a78820: 69 6f 6d 6d 75 6d 6d 69 6f 00 ...            "iommummio"
off 0x3a78840: 01 00 00 00 00 00 00 00                        +0x20 = 1
off 0x3a78848: 00 80 d8 fd 00 00 00 00                        +0x28 = 0xfdd88000  (adres fizyczny)
off 0x3a78850: 00 80 d8 fd 5a bd ff ff                        +0x30 = 0xffffbd5afdd88000 (VA mapy)
off 0x3a78858: 00 00 e0 50 00 00 00 00                        +0x38 = 0x50e00000  (adres w przestrzeni MP4)
off 0x3a78860: 00 40 00 00 00 00 00 00                        +0x40 = 0x4000      (rozmiar)
```

   Uklad pol jest potwierdzony kodem, ktory te wpisy wypelnia: `0xffffffffc140d610`
   dostaje `(wpis, adres, rozmiar, nazwa, 1)` i zapisuje `[wpis+0x38]` oraz `[wpis+0x40]`
   (`mov [r14+0x38],rsi` pod `0xffffffffc140d6c5`, `mov [r14+0x40],r15` pod
   `0xffffffffc140d6c9`), a wolajacy podaje dla `iommummio` rozmiar `0x4000`
   (`mov edx,0x4000` pod `0xffffffffc147fc6e`, off 0x81fc6e). Wpis jest zakladany w tej
   samej funkcji, ktora pyta sterownik IOMMU o adres: `call 0xffffffffc11593c0` pod
   `0xffffffffc147fc54`, a ta funkcja liczy `[softc+0x48] + 0x8000`:

```
ffffffffc11593c0  mov rax,[rip+0x3420741]  # 0xffffffffc41a3a70 (softc)
ffffffffc11593c7  mov ecx,0x8000
ffffffffc11593cc  add rcx,[rax+0x48]
ffffffffc11593d0  mov [rdi],rcx            ; wynik[0] = baza + 0x8000
ffffffffc11593d6  mov rdi,[rax+0x78]
ffffffffc11593db  call 0xffffffffc153e330 ; adres fizyczny bufora pierscienia
ffffffffc11593e2  mov [rbx+0x8],rax
ffffffffc11593e9  mov qword [rbx+0x10],0x2000
ffffffffc11593f1  mov dword [rbx+0x18],0x20032003
```

   Zgodnosc jest pelna: `0xfdd80000 + 0x8000 = 0xfdd88000` z wpisu tablicy. Dodatkowo
   `+0x30` wpisu (`0xffffbd5afdd88000`) rozni sie od `+0x28` dokladnie o `0xffffbd5a00000000`,
   czyli o baze mapy bezposredniej z tego rozruchu, co potwierdza, ze `+0x28` to adres
   fizyczny, a `+0x30` to jego VA w mapie bezposredniej.

**Ustalenie: okno urzadzenia ma baze fizyczna `0xfdd80000`, a blok rejestrow IOMMU
rejestrowany przez sterownik jako `iommummio` lezy pod `0xfdd88000` i ma `0x4000` bajtow.
Mapowany obszar to `0xfdd88000` do `0xfddA0000` (0x18000).**

## 4. Ktore rejestry sterownik naprawde czyta i zapisuje

W calym kodzie sterownika (`0xffffffffc1158000` do `0xffffffffc115d000`) wystepuja tylko
te dostepy do `[softc+0x40] + offset` (skan calej deasemblacji, jedyne trafienia z offsetem
0x8000 i wiekszym):

| offset | dostep | etykieta sterownika | dowod |
|---|---|---|---|
| `+0xc018` | odczyt 64 b | `CB3CR:0x%016lx` | off 0x128ba9a, `mov rsi,[rax+0xc018]` pod `0xffffffffc11590d9`, off 0x4f90d9 |
| `+0xe000` | odczyt 64 b | `CB3HPR:0x%016lx` | off 0x12deb42, `mov rsi,[rax+0xe000]` pod `0xffffffffc11590f2` |
| `+0xe008` | **zapis** 64 b | `CB3TPR:0x%016lx SW tail:0x%lx` | off 0x12a0a15, `mov [rax+0xe008],rbx` pod `0xffffffffc11596ab`, off 0x4f96ab |
| `+0xe010` | odczyt 64 b | `IOMMU MMIO %04lx: %016lx` | off 0x131233e, petla pod `0xffffffffc1159143` do `0xffffffffc11591ec` |
| `+0xe018` | odczyt 64 b | to samo | jak wyzej |
| `+0xe020` | odczyt 64 b | `IOMMU: wait command completion timed out: CB3SR: %016lx` | off 0x138ffba, `mov rsi,[rax+0xe020]` pod `0xffffffffc11590c0` |
| `+0xe028`, `+0xe030`, `+0xe038` | odczyt 64 b | `IOMMU MMIO ...` | petla jw., off 0x4f91ac, 0x4f91c3, 0x4f91da |

Zapis `+0xe008` jest ogonem pierscienia polecen: przed zapisem sterownik kopiuje 16 bajtow
polecenia do bufora `[softc+0x80]`, dodaje 0x10 i maskuje do 13 bitow:

```
ffffffffc1159677  mov rbx,[rdi+0x88]      ; programowy ogon
ffffffffc115967e  cmp rbx,0x2000          ; pierscien 8 kB
ffffffffc115968a  mov rdi,[rdi+0x80]      ; bufor polecen
ffffffffc1159699  call memcpy(...,0x10)   ; polecenie ma 16 bajtow
ffffffffc11596a5  and ebx,0x1fff
ffffffffc11596ab  mov [rax+0xe008],rbx    ; rejestr ogona
ffffffffc11596b2  mov [r14+0x88],rbx      ; zapis programowego ogona
```

### 4.1 Interpretacja offsetow

Offsety `0x18`, `0x2000`, `0x2008`, `0x2010`, `0x2018`, `0x2020`, `0x2030`, `0x2038` to
kanoniczne offsety rejestrow AMD IOMMU (Control Register, Command Buffer Head i Tail,
Event Log Head i Tail, Status Register, PPR Log Head i Tail). Ta mapa **nie pochodzi ze
zrzutu**, tylko z dokumentacji AMD i sluzy do interpretacji. Przyjmujac ja, offsety uzywane
przez sterownik ukladaja sie dokladnie tak, gdy plik rejestrow ma baze `baza + 0xc000`,
czyli `0xfdd8C000`:

```
0xfdd8C018 = Control Register          (sterownik: CB3CR)
0xfdd8E000 = Command Buffer Head       (sterownik: CB3HPR)
0xfdd8E008 = Command Buffer Tail       (sterownik: CB3TPR, zapisywany, maska 13 bitow = pierscien 0x2000)
0xfdd8E010 = Event Log Head
0xfdd8E018 = Event Log Tail
0xfdd8E020 = Status Register           (sterownik: CB3SR)
0xfdd8E030, 0xfdd8E038 = PPR Log Head i Tail
```

Sterownik sam nazywa te grupe `IOMMU MMIO Command and Log Registers:` (napis off 0x1331d19,
odwolanie pod `0xffffffffc1159120`), co zgadza sie z tym ukladem: to rejestry bufora polecen
i dziennikow, a nie przypadkowe offsety.

Dwa kandydaty, ktorych zrzut sam nie rozstrzyga:

- **Plik rejestrow = `0xfdd8C000`** (baza + 0xc000). Wtedy `Device Table Base Address`
  to `0xfdd8C000` (dolne 32 bity) i `0xfdd8C004` (gorne 32 bity), `Command Buffer Base
  Address` = `0xfdd8C008`, `Event Log Base Address` = `0xfdd8C010`, `Control` = `0xfdd8C018`.
  Ten wariant tlumaczy wszystkie offsety uzywane przez sterownik i jego wlasna nazwe grupy.
- **Plik rejestrow = `0xfdd88000`** (blok `iommummio`, 16 kB, podany firmware'owi MP4 jako
  adres urzadzenia `0x50e00000`). Wtedy te same offsety sterownika wypadaja pod
  `plik + 0x4018` i `plik + 0x6000`, czyli poza blokiem i poza mapa AMD, wiec ten wariant
  jest sprzeczny z nazwa `IOMMU MMIO Command and Log Registers`.

Zrzut nie zawiera ani jednego zapisu pod `baza + 0x8000`, `+0x8008`, `+0x8010` ani `+0x8018`,
wiec **rejestr `Device Table Base Address` nie jest programowany przez jadro**. Robi to
firmware (napisy i wywolania `hv_iommu_*` w tym sterowniku, np. `hv_iommu_bind_pasid`
off 0x12a09de, sciezka bledu pod `0xffffffffc1158c22`), dlatego wartosci tego rejestru nie
ma w zrzucie i trzeba ja odczytac z zywej konsoli.

## 5. Rejestry dla kontekstu MP4 i bufor polecen

- Bufor polecen sterownika: `[softc+0x80]` = VA `0xffffffffc41b2000` (obraz + 0x2892000),
  rozmiar pierscienia `0x2000`, polecenie 16 bajtow (`mov qword [r14+0x80],rax` w attach pod
  `0xffffffffc115aff1`; zapis ogona jak w punkcie 4).
- Bufor opisany jako `iommurb` w tablicy MP4 ma adres urzadzenia `0x51800000` i rozmiar
  `0x2000` (off 0x3a788b8 i 0x3a788c0), a rejestr `iommummio` adres urzadzenia `0x50e00000`
  i rozmiar `0x4000` (off 0x3a78858 i 0x3a78860). To jedyne miejsce, w ktorym widac, jak
  procesor A53 widzi rejestry IOMMU.

## 6. Tablica urzadzen i tablica stron

### 6.1 Tablica kontekstow urzadzen w pamieci jadra

Wpis dodaje funkcja `0xffffffffc115c2f0`. Konteksty leza w tablicy od `softc + 0xc8`, ze
skokiem `0x6088` bajtow, liczba w `[softc+0xc0]`, a identyfikator urzadzenia w
`[kontekst+0x6022]`:

```
ffffffffc115c32d  movsxd rax,[r15+0xc0]        ; liczba kontekstow
ffffffffc115c33e  lea r13,[r15+0xc8]           ; poczatek tablicy
ffffffffc115c345  imul rax,rax,0x6088          ; skok wpisu
ffffffffc115c350  cmp WORD PTR [r15+rbx+0x60ea],cx   ; = kontekst + 0x6022
ffffffffc115c63a  mov WORD PTR [r13+0x6020],cx ; identyfikator
ffffffffc115c642  mov WORD PTR [r13+0x6022],cx
```

### 6.2 Tablica GCR3 (tablica korzeni tablic stron), 8-bajtowe wpisy

Kazdy kontekst dostaje wlasna tablice `0x4000` bajtow, zerowana jako `0x800` slow
8-bajtowych, czyli **2048 wpisow po 8 bajtow** (to przestrzen PASID):

```
ffffffffc115c489  mov edi,0x4000          ; rozmiar
ffffffffc115c4aa  call alokacja
ffffffffc115c4d0  mov QWORD PTR [rbx+rax*8],0x0
ffffffffc115c4db  cmp rax,0x800           ; 2048 wpisow
ffffffffc115c560  error: "Can't allocate gcr3_base table memory"  (off 0x12d4828)
ffffffffc115c6bc  mov QWORD PTR [r13+0x6040],rbx   ; wskaznik tablicy w kontekscie
```

Wpis do tej tablicy zapisuje funkcja mapowania `0xffffffffc1158b80` i **jest to dokladnie
to, czego szukamy: fizyczny adres korzenia tablicy stron z bitem obecnosci**:

```
ffffffffc1158bad  movzx edi,WORD PTR [r15+0x6022]  ; identyfikator urzadzenia
ffffffffc1158bb5  mov esi,r14d                      ; indeks (PASID)
ffffffffc1158bb8  mov rdx,rbx                       ; adres fizyczny korzenia tablic stron
ffffffffc1158bbb  call 0xffffffffc1876b40           ; operacja "bind pasid"
ffffffffc1158bcd  mov rax,[r15+0x6040]              ; tablica GCR3
ffffffffc1158bd4  or  rbx,0x1                       ; bit 0 = obecnosc
ffffffffc1158be2  mov QWORD PTR [rax+rcx*8],rbx     ; wpis = adres | 1
```

Bajty: off 0x4f8bd4 `48 83 cb 01`, off 0x4f8be2 `48 89 1c c8`. Zdjecie mapowania
(`0xffffffffc1158d20`) wpisuje zero w to samo miejsce (off 0x4f8d75 `48 c7 04 c8 00 00 00 00`).

Czyli w tej implementacji **8-bajtowy wpis tablicy urzadzen dla danego PASID to
`(fizyczny adres korzenia tablicy stron, bity 51:12) | bit 0`**, a bit 0 jest bitem
obecnosci. Adres jest liczony przez `0xffffffffc154fd20`, ktora odejmuje od wartosci pola
`[obiekt+0x20]` baze mapy bezposredniej, skladana ze zmiennych globalnych
`0xffffffffc47a9294` i `0xffffffffc47a9298`:

```
ffffffffc154fd24  mov ecx,[0xffffffffc47a9294]
ffffffffc154fd2a  mov edx,[0xffffffffc47a9298]
ffffffffc154fd30  mov rax,[rdi+0x20]        ; VA korzenia tablicy stron
ffffffffc154fd34  movabs rsi,0xffff800000000000
ffffffffc154fd3e  shl rcx,0x27
ffffffffc154fd42  shl rdx,0x1e
ffffffffc154fd46  or  rdx,rcx
ffffffffc154fd49  or  rsi,rdx               ; baza mapy bezposredniej
ffffffffc154fd4c  sub rax,rsi               ; adres fizyczny
```

Docelowa tablica stron jest czteropoziomowa, po x86-64: ta sama funkcja, ktora
ja chodzi, wyciaga indeksy `(adres >> 30) & 0x1ff`, `bextr` z polami 21 i 9 bitow oraz
`(adres >> 12) & 0x1ff` i wypisuje je jako `pml4`, `pdpe`, `pde`, `pte`
(napisy off 0x1370e65, 0x12d47c6, 0x133bee0, 0x12967e4, kod pod `0xffffffffc115a642`).

### 6.3 Wpis 32-bajtowy z bitami obecnosci

Funkcja dodawania wpisu buduje **32-bajtowy** deskryptor (zerowanie `0x20` bajtow pod
`0xffffffffc115c65d`) i ustawia w nim bity 0 i 1 slowa zerowego:

```
ffffffffc115c65d  mov esi,0x20
ffffffffc115c691  call bzero                 ; 32 bajty
ffffffffc115c696  mov eax,0xcfffffff
ffffffffc115c69b  and eax,[rbp-0x3c]         ; slowo +0x14
ffffffffc115c6a8  or  eax,0x10000000
ffffffffc115c6b0  and BYTE PTR [rbp-0x40],0xfe   ; slowo +0x10, czyszczenie bitu 0
ffffffffc115c73c  mov eax,0xfffff1fc
ffffffffc115c741  and eax,[rbp-0x50]
ffffffffc115c744  or  eax,0x3                ; slowo +0x00: bity 0 i 1
ffffffffc115c747  mov [rbp-0x50],eax
```

Rozklad adresu fizycznego tablicy `0x4000` w tym deskryptorze (trzy przeliczenia tej samej
wartosci, `call 0xffffffffc153e330` pod `0xffffffffc115c6c3`, `0xffffffffc115c6e0`
i `0xffffffffc115c6ef`):

```
(adres & 0x700) << 14   -> slowo +0x04, bity 22..24
(adres >> 15) & 0xffff  -> slowo +0x0a (16 bit)
(adres >> 20) & 0xfffff800 -> slowo +0x0c, bity 11..31
```

**To nie jest uklad AMD-owski** (tam adres korzenia tablicy stron lezy ciagle w bitach
51:12 wpisu DTE), wiec tego deskryptora nie wolno brac za format DTE. Nazywam go roboczo
deskryptorem polecenia. Wpis 32-bajtowy ma jednak bity 0 i 1 slowa zerowego ustawione, tak
jak pola `V` i `TV` w DTE AMD, oraz pole 16-bitowe z identyfikatorem urzadzenia
(`mov WORD PTR [rbp-0x48],cx` pod `0xffffffffc115c725`, off 0x4fc725), co zgadza sie
z napisem `domain_id: %04x` i `## Device Table.  device_id(bsf):0x%x` (off 0x12b4fed).

Zastrzezenie do tego punktu: w tej samej funkcji struktura **nie jest juz nigdzie czytana**
i zaden wskaznik na nia nie idzie do wywolania (sprawdzone: wszystkie odwolania do slow
`[rbp-0x50]` do `[rbp-0x3c]` w calej funkcji `0xffffffffc115c2f0` do `0xffffffffc115c835`),
wiec nie wiem, kto ja pozniej konsumuje. Nie stawiam na jej podstawie tezy o formacie DTE.

**Uczciwe zastrzezenie: formatu sprzetowego DTE (rozmiar wpisu i dokladne bity) nie da sie
z tego zrzutu udowodnic.** Dowody, ktore sa, to: nazwy pol `domain_id`, `raw dte[%d]`,
`gcr3TableRootPtr:0x%lx (SPA)` (off 0x133befe) i `KERNEL IO_PAGE_FAULT. devid:0x%x pasid:%d`
(off 0x133bf40) oraz lista kodow bledow dziennika zdarzen, ktora jest lista AMD: 
`ILLEGAL_DEV_TABLE_ENTRY` (off 0x126e63b), `IO_PAGE_FAULT` (off 0x1331d40),
`DEV_TAB_HARDWARE_ERROR` (off 0x12a0a34), `PAGE_TAB_HARDWARE_ERROR` (off 0x13b02ff),
`ILLEGAL_COMMAND_ERROR` (off 0x12e8b3b), `IOTLB_INV_TIMEOUT` (off 0x128baaa),
`INVALID_DEVICE_REQUEST` (off 0x12967ba), `INVALID_PPR_REQUEST` (off 0x12f3039).
To znaczy, ze urzadzenie jest zgodne z AMD w warstwie dziennika zdarzen, ale sam wpis DTE
buduje firmware albo funkcja, ktorej w tym obrazie nie ma.

## 7. Identyfikator urzadzenia MP4

Identyfikator liczy funkcja `0xffffffffc11598a0`: chodzi w gore drzewa urzadzen do wezla
okreslonej klasy, czyta trzy wartosci z przestrzeni konfiguracji (offsety 0xc, 0xd, 0xe)
i sklada je tak:

```
ffffffffc1159a02  shl rcx,0x8
ffffffffc1159a06  shl rax,0x3
ffffffffc1159a0a  or  rax,rcx
ffffffffc1159a0d  or  rax,QWORD PTR [rbp-0x48]
```

czyli **identyfikator = (magistrala << 8) | (urzadzenie << 3) | funkcja**, standardowy
identyfikator zadan AMD IOMMU.

Wartosc dla MP4 wynika z obslugi bledu tlumaczenia (`0xffffffffc1158e10`). Ta funkcja
przechodzi liste kontekstow i szuka kontekstu o identyfikatorze **0x2003**, a potem buduje
polecenie dla tego urzadzenia:

```
ffffffffc1158e5e  mov r14d,ebx
ffffffffc1158e64  shl r14d,0x8
ffffffffc1158e6b  and r14d,0xff0000
ffffffffc1158e78  or  r14d,0x2003                 ; identyfikator 0x2003
ffffffffc1158e99  cmp WORD PTR [r13+0x6022],0x2003
ffffffffc1158ed0  lea rsi,[rbp-0x40]
ffffffffc1158ed4  call 0xffffffffc1159670         ; wyslanie polecenia
ffffffffc1158edc  call 0xffffffffc1159030         ; zrzut rejestrow IOMMU
```

Bajty: off 0x4f8e78 `41 81 ce 03 20 00 00`, off 0x4f8e99 `66 41 81 bd 22 60 00 00 03 20`.
Ten sam identyfikator jest wyrozniony w funkcji dodawania wpisu
(`cmp WORD PTR [rbp-0x5c],0x2006` pod `0xffffffffc115c797` i `cmp DWORD PTR [rbp-0x68],0x2003`
pod `0xffffffffc115c79f`), obok drugiego wyroznionego identyfikatora `0x2006`.

**Ustalenie: identyfikator urzadzenia MP4 to `0x2003`, czyli magistrala 0x20, urzadzenie 0,
funkcja 3.** Dowod jest posredni: to ten kontekst sterownik wybiera, gdy chce powiadomic
procesor bezpieczenstwa o zdarzeniu, i to jego identyfikator wklada do polecenia. Zrzut nie
zawiera napisu z gotowym `devid`, wiec nie jest to odczyt z zywej konsoli, tylko wniosek
z kodu. Drugi wyrozniony identyfikator to `0x2006` (magistrala 0x20, urzadzenie 0,
funkcja 6), ale jego roli nie ustalilem.

## 8. Czego nie da sie ustalic bez konsoli

1. **Wartosci rejestru `Device Table Base Address`** nie ma w zrzucie, bo jadro go nie
   zapisuje (brak jakiegokolwiek dostepu do offsetow 0x0000, 0x0008, 0x0010, 0x0018 bloku
   `iommummio`). Rejestr programuje firmware.
2. **Nie rozstrzygnieto, czy blokiem rejestrow jest `0xfdd8C000`, czy `0xfdd88000`.**
   Za pierwszym stoi zgodnosc wszystkich uzywanych offsetow z mapa AMD, za drugim nazwa
   `iommummio` i rozmiar `0x4000` w tablicy firmware'u.
3. **Polozenie tablicy DTE w pamieci** (tej sprzetowej) nie wynika z zrzutu, bo wskaznik
   do niej jest w rejestrze z punktu 1, a nie w pamieci jadra. Tablice w pamieci jadra
   (konteksty `0x6088` B i tablice GCR3 `0x4000` B) sa tablicami tego sterownika, nie
   sprzetu, i sprzet dostaje je przez operacje `bind pasid` (firmware, napisy `hv_iommu_*`).

## 9. Co odczytac na konsoli, zeby domknac temat

Kolejnosc i konkretne adresy (wszystkie w oknie mapowanym przez sterownik):

1. `0xfdd8C018` i `0xfdd88018`, po 8 bajtow. Rejestr Control ma sensowna wartosc tylko
   w prawdziwym pliku rejestrow (bity wlaczenia i trybu).
2. `0xfdd8C000` (8 bajtow) i `0xfdd88000` (8 bajtow). Ten, ktory trzyma adres fizyczny
   wyrownany do strony, wskazujacy na tablice wpisow, jest rejestrem
   `Device Table Base Address`.
3. `0xfdd8C008` i `0xfdd8C010`: adres bufora polecen i adres dziennika zdarzen. Bufor
   polecen powinien wypasc na bufor sterownika, ktory jest pod `[softc+0x80]`, albo na
   adres z wpisu `iommurb` (`0x50e00000` po stronie MP4, host nieznany).
4. Po odczytaniu bazy tablicy DTE: pierwsze wpisy pod tym adresem po 32 bajty. Wpis
   aktywny urzadzenia MP4 (identyfikator `0x2003`) ma miec ustawione bity 0 i 1 slowa
   zerowego, a w srodku adres korzenia tablicy stron; ten adres nalezy sprawdzic
   przejsciem po tablicach stron i wypisaniem `pml4`, `pdpe`, `pde`, `pte`.
5. `0xfdd8E000`, `0xfdd8E008`, `0xfdd8E020` to rejestry `CB3HPR`, `CB3TPR` i `CB3SR`;
   stan `CB3SR` po wyslaniu polecenia rozstrzyga, czy urzadzenie przyjmuje polecenia.

## 10. Skrocony werdykt

| pytanie | odpowiedz | jakosc dowodu |
|---|---|---|
| baza okna urzadzenia | `0xfdd80000` (odczyt z konfiguracji 0x44 i 0x48) | kod attach plus log kexp z konsoli |
| blok rejestrow IOMMU | `0xfdd88000`, rozmiar `0x4000`, adres urzadzenia MP4 `0x50e00000` | wpis `iommummio` w tablicy firmware'u plus ta sama wartosc liczona przez sterownik |
| obszar mapowany | `0xfdd88000` do `0xfddA0000` (0x18000) | kod attach |
| rejestry uzywane przez jadro | `+0xc018` (sterowanie), `+0xe000` do `+0xe038` (bufor polecen i dzienniki) | deasemblacja, offsety i etykiety napisow |
| prawdopodobna baza pliku rejestrow | `0xfdd8C000` (wtedy `Device Table Base Address` = `0xfdd8C000`) | zgodnosc offsetow z mapa AMD, niepewne |
| wpis dla danego PASID | 8 bajtow: adres fizyczny korzenia tablicy stron, bity 51:12, plus bit 0 obecnosci | `or rbx,1` i zapis pod `0xffffffffc1158be2` |
| wpis 32-bajtowy | 32 bajty, bity 0 i 1 slowa zerowego ustawione, pole 16-bitowe identyfikatora | kod pod `0xffffffffc115c65d` do `0xffffffffc115c747`, bez pelnej pewnosci co do sprzetowego DTE |
| identyfikator MP4 | `0x2003` (magistrala 0x20, urzadzenie 0, funkcja 3) | stala w obsludze bledu, dowod posredni |

Narzedzia tej analizy (poza repozytorium, w `/root/iommu-baza/`): `scan1.py` (sygnatury),
`napisy-pod.py` i `napisy-zakres.py` (napisy), `xrefs.py` (indeks odwolan RIP),
`szukaj-xref.py`, `xref-zakres.py`, `call-xref.py`, `rip-jeden.py`, `stale.py`.
