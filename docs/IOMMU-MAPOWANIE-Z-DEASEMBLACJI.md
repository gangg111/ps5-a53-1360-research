# IOMMU w sterowniku MP4: mapowanie i tablice stron z deasemblacji

Zrzut: `artifacts/kernel-1360-13.60.bin` (64 MB, 67 108 864 B), sha256
`306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804`.
Praca czysto offline, bez konsoli.

Konwencja adresow uzyta w calej notatce (ta sama co w `notes/ANALIZA-ZRZUTU-1360.md`):

    VA = 0xffffffffc0c60000 + offset_w_pliku

Baza `0xffffffffc0c60000` jest potwierdzona niezaleznie od tej notatki (bramka IDT,
`allproc`, `pmap_store`), a w tej analizie dodatkowo proba kontrolna opisana nizej.
Baza danych to `text + 0xCC0000`, czyli `0xffffffffc1920000`.

## 1. Metoda i jej weryfikacja

Odwolania do napisow na x86-64 sa wzgledne wobec licznika rozkazow, wiec dla pola
przesuniecia (disp32) pod offsetem `p` w pliku koniec instrukcji lezy pod `p+4`, a adres
docelowy to `baza + p + 4 + (int32)disp`. Przeskanowalem tym sposobem caly plik
(narzedzie `xref.c`, 893 119 kandydatow z modrm `mod=00, rm=101`).

Proba kontrolna metody, niezalezna od zadania: napis `sceSblServiceMailbox` lezy pod
offsetem pliku `0x128c79c` (`notes/ANALIZA-ZRZUTU-1360.md` uzywa go jako znanego punktu).
Skaner znalazl dokladnie jedno odwolanie:

    0xffffffffc120465e  48 8d 35 37 81 ce 00  lea rsi,[rip+0xce8137]  # 0xffffffffc1eec79c

czyli `0xffffffffc120465e + 7 + 0xce8137 = 0xffffffffc1eec79c = 0xffffffffc0c60000 + 0x128c79c`.
Metoda trafia. Pierwsza wersja skanera nie dodawala bazy do wyniku i dawala zero trafien,
co jest tu opisane, bo pokazuje, ze wynik nie jest przypadkowy.

Kazdy napis z zadania zostal odczytany z pliku i potwierdzony. Uwaga: czesc z nich ma
w zrzucie kropke na koncu, ktorej nie ma w tresci zadania (styl komunikatow tego sterownika).

| offset w pliku | VA | tresc w zrzucie |
|---|---|---|
| 0x0126e60e | 0xffffffffc1ece60e | `iommu context` |
| 0x0126e670 | 0xffffffffc1ece670 | `amd_iommu_map: nsegs == 0 for device %s.` |
| 0x012bed31 | 0xffffffffc1f1ed31 | `iommu_add_device_table_entry` |
| 0x012c9b01 | 0xffffffffc1f29b01 | `iommu_allocate_table_memory` |
| 0x012bbdae | 0xffffffffc1f1bdae | `mp4_map_iommu_full_discont` |
| 0x01302743 | 0xffffffffc1f62743 | `%s: mp4_map_iommu_discont() returned: %#x.` |
| 0x0134bdf9 | 0xffffffffc1fabdf9 | `a53io_map_iommu` |
| 0x012a01f9 | 0xffffffffc1f001f9 | `gc_map_iommu_region_for_mp4_sdma` |
| 0x0133923b | 0xffffffffc1f9923b | `mp4_coredump_buffer_iommu = 0x%016lx.` |
| 0x012f598c | 0xffffffffc1f5598c | `For now iommu support physcont only` |
| 0x01351ab4 | 0xffffffffc1fb1ab4 | ` 0x%016lx is mapped. iommu might be unknown state.` |
| 0x013aaac3 | 0xffffffffc200aac3 | `iommu0` |

Miejsca odwolan (offset pola disp i rozkaz, ktory go uzywa):

| napis | rozkazy odwolujace (VA) |
|---|---|
| `iommu context` | 0xffffffffc115986e |
| `amd_iommu_map: nsegs == 0 ...` | 0xffffffffc115b926 |
| `iommu_add_device_table_entry` | 0xffffffffc115c5b3, 0xffffffffc115c809 |
| `iommu_allocate_table_memory` | 0xffffffffc115c567, 0xffffffffc115c590 |
| `mp4_map_iommu_full_discont` | 0xffffffffc187ff10 |
| `%s: mp4_map_iommu_discont() returned: %#x.` | 0xffffffffc1617e20, 0xffffffffc1617e5c |
| `a53io_map_iommu` | 0xffffffffc1618024, 0xffffffffc161804c, 0xffffffffc1618090, 0xffffffffc16180fb |
| `gc_map_iommu_region_for_mp4_sdma` | 0xffffffffc10d9f3d, 0xffffffffc10d9f6a, 0xffffffffc10d9f96, 0xffffffffc10d9fde |
| `mp4_coredump_buffer_iommu = 0x%016lx.` | 0xffffffffc1883639, 0xffffffffc18837c8, 0xffffffffc188b60b |
| `For now iommu support physcont only` | 0xffffffffc140d893 |
| ` 0x%016lx is mapped ...` | 0xffffffffc115a4a0 |
| `iommu0` | 0xffffffffc16204bb, 0xffffffffc162053a, 0xffffffffc162156b |

Deasemblacja: minimalny ELF64 (`mkelf.py`) z jednym segmentem `PT_LOAD` pod adresem
`0xffffffffc0c60000` (prawa R+X) i sekcja `.text` obejmujaca caly obraz, deasemblacja
`objdump -d -M intel`. Bez symboli granice funkcji znajdowalem po prologach
(`55 48 89 e5` oraz `f3 0f 1e fa`), a narzedzie `win.py` samo sprawdza, ze pod zadanym
offsetem dekoduje sie rozkaz, ktory ma byc. ObjDump w tym opakowaniu pokazuje adresy
zgodne z konwencja `VA = baza + offset`, co sprawdzilem porownaniem bajtow pod dwoma
offsetami: 0x5a465e (`48 8d 35 37 81 ce 00`) i 0x4f986e (`48 8d 35 99 4d d7 00`).

## 2. Katalog ustalonych funkcji

| funkcja | VA (offset) | czym jest, dowod |
|---|---|---|
| inicjalizacja kontekstu IOMMU | 0xffffffffc1159850 (0x4f9850) | alokuje 0x328 B, `lockinit` z nazwa `iommu context`, zapis wskaznika do 0xffffffffc41a3a80 |
| `amd_iommu_map` | 0xffffffffc115b5c0 (0x4fb5c0) | uzywa napisu `amd_iommu_map: nsegs == 0 for device %s.` w 0xffffffffc115b926 |
| `iommu_add_device_table_entry` | 0xffffffffc115c2f0 (0x4fc2f0) | uzywa swojej nazwy w 0xffffffffc115c5b3 |
| `iommu_allocate_table_memory` (wciagnieta) | brak wlasnego prologu, kod w 0xffffffffc115c45a do 0xffffffffc115c5a3 | komunikaty `%s %d. Can't allocate gcr3_base table memory.` i `%s %d. Can't allocate pt_info memory.` z `%s` = `iommu_allocate_table_memory` |
| zapis wpisu do tablicy gcr3 | 0xffffffffc1158b80 (0x4f8b80) | `or rbx,0x1` i `mov [rax+rcx*8],rbx` na stronie z entry+0x6040 |
| mapowanie jednego segmentu (wypelnia tablice stron) | 0xffffffffc115c8d0 (0x4fc8d0) | wywoluje 0xc154fe40 z `lea rdi,[r12+0x6058]` |
| `mp4_map_iommu_discont` | 0xffffffffc16176b0 (0x9b76b0) | uzywa napisu `%s: mp4_map_iommu_discont() returned: %#x.` i wywoluje obie funkcje mapujace |
| `a53io_map_iommu` | 0xffffffffc1617f50 (0x9b7f50) | uzywa swojej nazwy w czterech miejscach |
| `mp4_map_iommu_full_discont` | 0xffffffffc187fef0 (0xc1fef0) | `lea r14,[rip+0x69be97] # 0xffffffffc1f1bdae` jako `__func__` |
| wypis pol coredump | 0xffffffffc1883590 (0xc23590) | czyta pola softc i wola funkcje wypisujaca z r15 |
| attach mp40 (ustawia pola coredump) | 0xffffffffc1883a20 (0xc23a20) | `call 0xc0f12b10` (softc), zapis wskaznika do 0xffffffffc4a4eb58 |
| mapowanie bufora coredump | 0xffffffffc1885d50 (0xc25d50) | ta sama sekwencja co `mp4_map_iommu_full_discont`: 0xc1877680 i 0xc15c3f90 |

Softc sterownika mp40 jest trzymany w globalnej komorce `0xffffffffc4a4eb58`.
Dowod, ze to wlasnie ta struktura: attach mp40 w 0xffffffffc1883a20 robi

    0xffffffffc1883a43  e8 c8 f0 68 ff        call   0xffffffffc0f12b10
    0xffffffffc1883a48  48 89 05 09 b1 1c 03  mov    [rip+0x31cb109],rax  # 0xffffffffc4a4eb58
    0xffffffffc1883a4f  4c 89 30              mov    [rax],r14
    0xffffffffc1883a52  48 89 c3              mov    rbx,rax

czyli zapisuje wskaznik softc do `0xffffffffc4a4eb58`, a pod `softc+0x0` kladzie wskaznik
urzedzenia, po czym dalej pracuje na tym samym obiekcie w `rbx`. W zrzucie (stan z zywego
jadra) `[0xffffffffc4a4eb58] = 0xffffbd5a017e4000`.

Kontekst o nazwie `iommu context` (0x328 B) jest osobna struktura, alokowana w
0xffffffffc1159850:

    0xffffffffc1159854  48 8d 35 b5 1f 70 02   lea    rsi,[rip+0x2701fb5]  # 0xffffffffc385b810
    0xffffffffc115985b  bf 28 03 00 00         mov    edi,0x328
    0xffffffffc1159860  ba 02 01 00 00         mov    edx,0x102
    0xffffffffc1159865  e8 e6 f2 70 00         call   0xffffffffc1868b50
    0xffffffffc115986a  48 8d 78 18            lea    rdi,[rax+0x18]
    0xffffffffc115986e  48 8d 35 99 4d d7 00   lea    rsi,[rip+0xd74d99]  # 0xffffffffc1ece60e "iommu context"
    0xffffffffc1159875  48 89 05 04 a2 04 03   mov    [rip+0x304a204],rax  # 0xffffffffc41a3a80
    0xffffffffc115987c  31 d2                  xor    edx,edx
    0xffffffffc115987e  31 c9                  xor    ecx,ecx
    0xffffffffc1159880  e8 4b e5 fc ff         call   0xffffffffc1127dd0   ; lockinit
    0xffffffffc1159885  48 8b 05 f4 a1 04 03   mov    rax,[rip+0x304a1f4]  # 0xffffffffc41a3a80
    0xffffffffc115988c  48 c7 80 20 03 00 00 00 00 00 00  mov QWORD PTR [rax+0x320],0x0
    0xffffffffc1159897  5d                     pop    rbp
    0xffffffffc1159898  c3                     ret

Ta funkcja jest wywolywana ogonowo z 0xffffffffc0ec2250 (`jmp 0xffffffffc1159850`),
wiec jest to sciezka inicjalizacji, a nie funkcja wywolywana z mapowania.

## 3. Odpowiedz 1: skad funkcje mapujace biora adres bufora, adres urzadzenia i rozmiar

Wniosek ogolny: **zadna z trzech funkcji mapujacych nie czyta tych trzech wartosci z pol
struktury.** Wszystkie trzy dostaja je w rejestrach, a pola struktury czyta ich otoczenie
(wolajacy albo warstwa wyzej). Ponizsze dowody rozdzielaja te dwa poziomy.

### 3.1 `mp4_map_iommu_full_discont` (0xffffffffc187fef0)

Sygnatura wedlug prologu i uzycia: `(rdi = adres urzadzenia, rsi = adres bufora, rdx = rozmiar)`.

    0xffffffffc187ff08  48 89 75 b0            mov    [rbp-0x50],rsi        ; zachowany bufor
    0xffffffffc187ff0c  48 89 7d a8            mov    [rbp-0x58],rdi        ; zachowany adres urzadzenia
    0xffffffffc187ff1e  48 89 d3               mov    rbx,rdx               ; rozmiar
    0xffffffffc187ff17  4c 8d a2 ff 3f 00 00   lea    r12,[rdx+0x3fff]
    0xffffffffc187ff30  49 c1 ec 0e            shr    r12,0xe               ; liczba stron 16 KB

Rozmiar jest przeliczany na liczbe segmentow przy stronie 0x4000 i to jest logowane:

    0xffffffffc187ff21  48 8d 35 2b 6b 6a 00   lea    rsi,[rip+0x6a6b2b]  # 0xffffffffc1f26a53 "%s:PAGE_SIZE=0x%x."
    0xffffffffc187ff52  48 8d 35 12 05 6d 00   lea    rsi,[rip+0x6d0512]  # 0xffffffffc1f5046b "%s:maxsize=0x%lx."
    0xffffffffc187ff69  48 8d 35 f6 6a 6a 00   lea    rsi,[rip+0x6a6af6]  # 0xffffffffc1f26a66 "%s:nsegments=0x%x."

Jedyne pole struktury, po ktore ta funkcja siega, to pierwsze pole softc mp40:

    0xffffffffc187ff3d  4c 8b 3d 14 ec 1c 03   mov    r15,[rip+0x31cec14]  # 0xffffffffc4a4eb58
    0xffffffffc187ff44  4d 8b 2f               mov    r13,[r15]            ; softc->0x0 = urzadzenie
    0xffffffffc187ff4a  e8 21 3d 69 ff         call   0xffffffffc0f18000

To pole jest ustawiane w attachu (`0xffffffffc1883a4f  mov [rax],r14`) i sluzy jako
uchwyt dla `0xc0f18000`, a nie jako adres bufora.

Skad wiec pochodza trzy argumenty, widac w jedynym wolajacym, w `mp4_map_iommu_discont`
(0xffffffffc16176b0). Najpierw kopiowany jest 0x30-bajtowy opis z softc:

    0xffffffffc1617b3b  48 8d 7d a0            lea    rdi,[rbp-0x60]
    0xffffffffc1617b3f  e8 fc 84 26 00         call   0xffffffffc1880040

    0xffffffffc1880044  48 8b 05 0d eb 1c 03   mov    rax,[rip+0x31ceb0d]  # 0xffffffffc4a4eb58
    0xffffffffc188004b  48 8b 88 40 04 00 00   mov    rcx,[rax+0x440]      ; pole +0x440
    0xffffffffc1880052  48 89 0f               mov    [rdi],rcx           ; pierwsze 8 B opisu
    0xffffffffc1880055  48 8b 88 48 04 00 00   mov    rcx,[rax+0x448]
    0xffffffffc188005c  48 89 4f 08            mov    [rdi+0x8],rcx
    0xffffffffc1880060  0f b7 88 50 04 00 00   movzx  ecx,WORD PTR [rax+0x450]
    0xffffffffc1880067  66 89 4f 10            mov    [rdi+0x10],cx
    0xffffffffc1880078  48 8b 88 58 04 00 00   mov    rcx,[rax+0x458]
    0xffffffffc1880083  48 8b 88 60 04 00 00   mov    rcx,[rax+0x460]
    0xffffffffc188008e  48 8b 80 68 04 00 00   mov    rax,[rax+0x468]

a potem wywolywana jest funkcja mapujaca:

    0xffffffffc1617b24  48 8d 35 d5 f1 12 01   lea    rsi,[rip+0x112f1d5] # 0xffffffffc2746d00 (typ alokacji)
    0xffffffffc1617b2b  48 89 df               mov    rdi,rbx               ; rozmiar = argument 3 wolajacego
    0xffffffffc1617b2e  ba 02 01 00 00         mov    edx,0x102
    0xffffffffc1617b33  e8 18 10 25 00         call   0xffffffffc1868b50     ; alokacja bufora
    0xffffffffc1617b44  48 8b 7d a0            mov    rdi,[rbp-0x60]        ; adres urzadzenia z softc+0x440
    0xffffffffc1617b51  4c 89 f6               mov    rsi,r14               ; adres bufora (swieza alokacja)
    0xffffffffc1617b54  48 89 da               mov    rdx,rbx               ; rozmiar
    0xffffffffc1617b57  e8 94 83 26 00         call   0xffffffffc187fef0     ; mp4_map_iommu_full_discont

Czyli dla sciezki MP4:

- **adres urzadzenia** = `softc + 0x440` (64-bit). To pole jest liczone w attachu jako adres
  w przestrzeni urzadzenia:
  `0xffffffffc18842fc  4c 89 9b 40 04 00 00  mov [rbx+0x440],r11`, gdzie
  `r11 = (rax + 0x13ffffff) & 0xfffffffffc000000` (`0xffffffffc1884225` i `0xffffffffc188422c`).
- **adres bufora** = swiezo zaalokowany obszar (r14) o rozmiarze rownym argumentowi 3
  wolajacego, a nie pole struktury.
- **rozmiar** = argument 3 funkcji `mp4_map_iommu_discont` (rejestr rdx, zachowany w rbx).

### 3.2 `a53io_map_iommu` (0xffffffffc1617f50)

Ta sama sygnatura `(rdi = urzadzenie/uchwyt, rsi = bufor, rdx = rozmiar)`, bez czytania pol
struktury poza przekazaniem rdi do `0xc0f18000`:

    0xffffffffc1617f6c  49 89 d6               mov    r14,rdx               ; rozmiar
    0xffffffffc1617f6f  49 89 f7               mov    r15,rsi               ; bufor
    0xffffffffc1617f72  49 89 fc               mov    r12,rdi               ; uchwyt
    0xffffffffc1617fd0  e8 2b 00 90 ff         call   0xffffffffc0f18000
    0xffffffffc1617ffd-0xffffffffc1618010    push ... ; 0x4000, liczba segmentow, rozmiar
    0xffffffffc1618010  e8 6b f6 25 00         call   0xffffffffc1877680

Wlasny zamek tej sciezki jest nazwany i to jedyne miejsce z nazwa A53IO:

    0xffffffffc1617f90  48 c7 45 c8 00 00 00 00  mov QWORD PTR [rbp-0x38],0x0
    0xffffffffc1617f75  48 8d 35 5c b1 93 00   lea    rsi,[rip+0x93b15c]  # 0xffffffffc1f530d8 "A53IO"
    0xffffffffc1617f7c  48 8d 15 ef e7 97 00   lea    rdx,[rip+0x97e7ef]  # 0xffffffffc1f96772 "A53IO IOMMU map lock"
    0xffffffffc1617fc8  e8 03 fe b0 ff         call   0xffffffffc1127dd0   ; lockinit

Dwa miejsca wywolania w `mp4_map_iommu_discont`:

    0xffffffffc1617b71  48 8b 7d 98            mov    rdi,[rbp-0x68]        ; uchwyt urzadzenia
    0xffffffffc1617b75  4c 89 f6               mov    rsi,r14               ; bufor
    0xffffffffc1617b78  48 89 da               mov    rdx,rbx               ; rozmiar
    0xffffffffc1617b7b  e8 d0 03 00 00         call   0xffffffffc1617f50

    0xffffffffc1617ccd  49 8b 3f               mov    rdi,[r15]             ; uchwyt z *argumentu wolajacego
    0xffffffffc1617cd0  4c 89 f6               mov    rsi,r14               ; bufor
    0xffffffffc1617cd3  e8 78 02 00 00         call   0xffffffffc1617f50

Uchwyt `[rbp-0x68]` pochodzi z lancucha `0xc187e9c0` (czyta softc mp40 z 0xc4a4eb58)
i `0xc1782810`, wiec jest obiektem wyprowadzonym z softc, a nie stalym polem.

### 3.3 `iommu_add_device_table_entry` (0xffffffffc115c2f0) i `amd_iommu_map` (0xffffffffc115b5c0)

Sygnatura: `(rdi = kontekst/softc IOMMU, rsi = device_t urzadzenia, edx = identyfikator urzadzenia)`.

    0xffffffffc115c30c  4c 8d a7 a8 00 00 00   lea    r12,[rdi+0xa8]        ; zamek kontekstu
    0xffffffffc115c313  49 89 ff               mov    r15,rdi               ; kontekst
    0xffffffffc115c316  89 d3                  mov    ebx,edx               ; identyfikator
    0xffffffffc115c308  48 89 75 a8            mov    [rbp-0x58],rsi        ; device_t

Pola kontekstu i wpisow, ktore ta funkcja czyta (to jest jednoczesnie odpowiedz na pytanie,
gdzie sterownik trzyma informacje o mapowaniu):

| offset | co to jest, dowod |
|---|---|
| `ctx+0xa8` | zamek chroniacy tablice wpisow: `0xffffffffc115c30c lea r12,[rdi+0xa8]` i `0xffffffffc115c31e mov rdi,r12` przed `call 0xc1126a00` |
| `ctx+0xb8` | glowa listy wpisow: `0xffffffffc115c5d9  49 8b 87 b8 00 00 00  mov rax,[r15+0xb8]`, `0xffffffffc115c5eb mov [r15+0xb8],r13` |
| `ctx+0xc0` | licznik wpisow (dword): `0xffffffffc115c32d 49 63 87 c0 00 00 00 movsxd rax,DWORD PTR [r15+0xc0]`, `0xffffffffc115c5f2 inc DWORD PTR [r15+0xc0]` |
| `ctx+0xc8` | poczatek tablicy wpisow: `0xffffffffc115c33e 4d 8d af c8 00 00 00 lea r13,[r15+0xc8]` |
| rozmiar wpisu `0x6088` | `0xffffffffc115c345 48 69 c0 88 60 00 00 imul rax,rax,0x6088`, `0xffffffffc115c35f add rbx,0x6088`, `0xffffffffc115c5c2 imul r13,rsi,0x6088` |
| limit wpisow 0xffff | `0xffffffffc115c51b 48 81 fe ff ff 00 00 cmp rsi,0xffff`, komunikat `IOMMU no device entry obj. %d.` |
| szukanie po identyfikatorze | `0xffffffffc115c350 66 41 39 8c 1f ea 60 00 00  cmp WORD PTR [r15+rbx*1+0x60ea],cx`, czyli pole `wpis+0x6022` |

Pola wypelniane w nowym wpisie (wpis = `r13`):

| offset wpisu | co, dowod |
|---|---|
| `+0x6020`, `+0x6022` | identyfikator urzadzenia (word): `0xffffffffc115c63a mov WORD PTR [r13+0x6020],cx`, `0xffffffffc115c642 mov WORD PTR [r13+0x6022],cx` |
| `+0x6028` | device_t: `0xffffffffc115c5f9 49 89 85 28 60 00 00 mov [r13+0x6028],rax` (rax = rsi = argument 2) |
| `+0x6030` | pamiec `pt_info` (alokacja 0x1818 B): `0xffffffffc115c66d 49 89 85 30 60 00 00 mov [r13+0x6030],rax` |
| `+0x6040` | **strona tablicy gcr3** (alokacja 0x4000 B): `0xffffffffc115c6bc 49 89 9d 40 60 00 00 mov [r13+0x6040],rbx` |
| `+0x6048`, `+0x6050` | zerowane: `0xffffffffc115c67b`, `0xffffffffc115c686` |
| `+0x6058` | struktura tablic stron, inicjowana `0xffffffffc115c6b4 call 0xffffffffc154fd60` |
| `+0x6018` | wskaznik na `wpis+0x8`: `0xffffffffc115c666 4d 89 a5 18 60 00 00 mov [r13+0x6018],r12` |
| `+0x6080` | indeks w tablicy gcr3: `0xffffffffc115c607 mov [r13+0x6080],eax` (z `ctx+0x60ba8`), alternatywnie `0xffffffffc115c625` (z `ctx+0x60bac`) |

Skad pochodzi identyfikator urzadzenia, widac w `amd_iommu_map`:

    0xffffffffc115b5ed  e8 1e 75 db ff         call   0xffffffffc0f12b10    ; softc urzadzenia IOMMU
    0xffffffffc115b5dc  4c 8b 7d 20            mov    r15,[rbp+0x20]        ; device_t (argument ze stosu)
    0xffffffffc115b5e0  89 d3                  mov    ebx,edx               ; liczba segmentow
    0xffffffffc115b5e2  49 89 f6               mov    r14,rsi               ; tablica segmentow
    0xffffffffc115b600  4c 89 fe               mov    rsi,r15
    0xffffffffc115b60a  e8 e1 0b 00 00         call   0xffffffffc115c1f0    ; identyfikator urzadzenia
    0xffffffffc115b61f  89 da                  mov    edx,ebx
    0xffffffffc115b621  e8 ca 0c 00 00         call   0xffffffffc115c2f0    ; iommu_add_device_table_entry

Adresy i rozmiary w tej warstwie nie pochodza z pol struktury, tylko z tablicy par
16-bajtowych (adres, dlugosc):

    0xffffffffc115b680  49 8b 14 0e            mov    rdx,[r14+rcx*1]
    0xffffffffc115b684  49 8b 74 0e 08         mov    rsi,[r14+rcx*1+0x8]
    0xffffffffc115b689  48 01 d6               add    rsi,rdx

Z wpisu czytane sa potem: `+0x6018` (obiekt odwzorowania, `0xffffffffc115b6cb mov r12,[rax+0x6018]`),
`+0x6022` (identyfikator w komunikatach, `0xffffffffc115b731 movzx esi,WORD PTR [rax+0x6022]`)
oraz `+0x6080` (indeks gcr3, `0xffffffffc115cac9 41 8b 84 24 80 60 00 00 mov eax,DWORD PTR [r12+0x6080]`).

## 4. Odpowiedz 2: gdzie funkcje zapisuja wynik mapowania

Trzy rozne miejsca, zaleznie od sciezki.

**(a) Wypelnienie tablic stron i wynik dla segmentu** (funkcja 0xffffffffc115c8d0).
Wolanie mapujace i zapis wyniku z powrotem do opisu segmentu:

    0xffffffffc115ca7d  49 8d bc 24 58 60 00 00  lea    rdi,[r12+0x6058]     ; struktura tablic stron wpisu
    0xffffffffc115ca89  48 8d 75 b8              lea    rsi,[rbp-0x48]
    0xffffffffc115ca95  4d 89 f0                 mov    r8,r14               ; adres fizyczny segmentu
    0xffffffffc115ca98  4d 89 f9                 mov    r9,r15               ; dlugosc
    0xffffffffc115ca9b  6a 06                    push   0x6
    0xffffffffc115ca9e  41 55                    push   r13                  ; adres I/O (iova)
    0xffffffffc115caa0  e8 9b 33 3f 00           call   0xffffffffc154fe40

    0xffffffffc115cb30  48 8b 01                 mov    rax,[rcx]            ; adres segmentu
    0xffffffffc115cb33  25 ff 3f 00 00           and    eax,0x3fff
    0xffffffffc115cb38  4c 01 f0                 add    rax,r14
    0xffffffffc115cb3b  48 89 02                 mov    [rdx],rax            ; wynik: adres w przestrzeni urzadzenia
    0xffffffffc115cb3e  48 8b 41 08              mov    rax,[rcx+0x8]
    0xffffffffc115cb49  48 89 42 08              mov    [rdx+0x8],rax        ; i rozmiar

Status calosci jest zwracany w `eax`: `0xffffffffc115b8ee 89 d8  mov eax,ebx`.

**(b) Strona A53IO/MP4.** `mp4_map_iommu_discont` zapisuje uchwyty i flagi do globalnej
struktury pod `0xffffffffc31c0e70`:

    0xffffffffc1617b89  48 8b 45 a0            mov    rax,[rbp-0x60]        ; adres urzadzenia
    0xffffffffc1617b8d  4c 89 35 e4 92 ba 01   mov    [rip+0x1ba92e4],r14  # 0xffffffffc31c0e78 (bufor)
    0xffffffffc1617b94  48 89 05 e5 92 ba 01   mov    [rip+0x1ba92e5],rax  # 0xffffffffc31c0e80 (adres urzadzenia)
    0xffffffffc1617b9b  48 89 0d e6 92 ba 01   mov    [rip+0x1ba92e6],rcx  # 0xffffffffc31c0e88 (flagi 0x50000000 albo 0)
    0xffffffffc1617ba7  48 8d 05 c2 92 ba 01   lea    rax,[rip+0x1ba92c2]  # 0xffffffffc31c0e70
    0xffffffffc1617bae  49 89 07               mov    [r15],rax            ; zwrot calosci przez argument wolajacego

Stan tych pol w zrzucie (wartosci z zywego jadra, nie stale):
`[0xffffffffc31c0e78] = 0xffffff8007d2c000`, `[0xffffffffc31c0e80] = 0x0000000064000000`,
`[0xffffffffc31c0e88] = 0x0000000050000000`.

Adres wynikowy dla sciezki A53IO jest dodatkowo liczony i wpisywany do opisu sprzetowego
pod `[0xffffffffc31c0ed8]`:

    0xffffffffc1617cd8  48 c7 05 b5 91 ba 01 00 00 00 50  mov QWORD PTR [rip+0x1ba91b5],0x50000000 # 0xffffffffc31c0e98
    0xffffffffc1617d30  48 8b 05 61 91 ba 01   mov    rax,[rip+0x1ba9161]  # 0xffffffffc31c0e98
    0xffffffffc1617d37  48 c1 e0 12            shl    rax,0x12
    0xffffffffc1617d3b  4c 21 e8               and    rax,r13              ; r13 = 0xfffffffc00000000
    0xffffffffc1617d4c  49 89 4c 24 70         mov    [r12+0x70],rcx       ; pole opisu sprzetowego

oraz do pol `+0x58`, `+0x60`, `+0x68` tego samego opisu:

    0xffffffffc1617bf6  49 89 74 24 58         mov    [r12+0x58],rsi
    0xffffffffc1617c17  49 89 74 24 60         mov    [r12+0x60],rsi
    0xffffffffc1617c1c  49 89 44 24 68         mov    [r12+0x68],rax

**(c) Pola softc mp40** ustawiane w attachu i w mapowaniu bufora coredump (patrz punkt 6).
Najwazniejsze z nich: `softc+0x440` (adres urzadzenia), `softc+0x378` (adres bufora coredump),
`softc+0x380` (adres urzadzenia dla tego bufora), `softc+0x388` i `softc+0x390` (rozmiar 0x200000),
`softc+0x6a8`, `softc+0x6b0`, `softc+0x6b8` (opisane nizej):

    0xffffffffc18843b8  e8 53 45 fe ff         call   0xffffffffc1868910    ; alokacja 0x200000
    0xffffffffc18843bd  48 89 83 78 03 00 00   mov    [rbx+0x378],rax
    0xffffffffc18843cd  48 8b b3 80 03 00 00   mov    rsi,[rbx+0x380]
    0xffffffffc18843d4  48 8b 8b 90 03 00 00   mov    rcx,[rbx+0x390]
    0xffffffffc18843ec  48 89 c2               mov    rdx,rax
    0xffffffffc18843ef  e8 5c 19 00 00         call   0xffffffffc1885d50

## 5. Odpowiedz 3: jak zbudowana jest tablica stron i gdzie jest jej korzen

Tablica stron dla urzadzenia jest zakorzeniona w tablicy `gcr3`, a nie bezposrednio we wpisie.

**Krok 1. Alokacja tablicy gcr3 i pamieci `pt_info`** (kod `iommu_allocate_table_memory`
wciagniety do `iommu_add_device_table_entry`):

    0xffffffffc115c482  48 8d 35 87 f3 6f 02   lea    rsi,[rip+0x26ff387]  # 0xffffffffc385b810 (typ)
    0xffffffffc115c489  bf 00 40 00 00         mov    edi,0x4000            ; 16 KB
    0xffffffffc115c48e  41 b9 00 40 00 00      mov    r9d,0x4000
    0xffffffffc115c494  ba 01 00 00 00         mov    edx,0x1
    0xffffffffc115c4aa  e8 61 c4 70 00         call   0xffffffffc1868910
    0xffffffffc115c4b9  0f 84 a1 00 00 00      je     0xffffffffc115c560    ; blad: gcr3_base

    0xffffffffc115c4d0  48 c7 04 c3 00 00 00 00  mov QWORD PTR [rbx+rax*8],0x0
    0xffffffffc115c4db  48 3d 00 08 00 00      cmp    rax,0x800            ; 2048 wpisow po 8 B = 0x4000

    0xffffffffc115c4ea  bf 18 18 00 00         mov    edi,0x1818            ; 6168 B na pt_info
    0xffffffffc115c4f4  e8 57 c6 70 00         call   0xffffffffc1868b50
    0xffffffffc115c500  74 73                  je     0xffffffffc115c575    ; blad: pt_info

Komunikaty bledow mowia wprost, co to za pamiec (oba z nazwa funkcji
`iommu_allocate_table_memory` w `rsi` i numerem linii w `edx`):

    0xffffffffc115c560  48 8d 3d c1 82 dd 00   lea    rdi,[rip+0xdd82c1]  # 0xffffffffc1f34828
        tresc: "%s %d. Can't allocate gcr3_base table memory."
    0xffffffffc115c567  48 8d 35 93 d5 dc 00   lea    rsi,[rip+0xdcd593]  # 0xffffffffc1f29b01 "iommu_allocate_table_memory"
    0xffffffffc115c56e  ba 59 06 00 00         mov    edx,0x659

    0xffffffffc115c589  48 8d 3d 12 21 d7 00   lea    rdi,[rip+0xd72112]  # 0xffffffffc1ece6a2
        tresc: "%s %d. Can't allocate pt_info memory."
    0xffffffffc115c597  ba 6a 06 00 00         mov    edx,0x66a

**Krok 2. Korzen tablicy stron trafia do tablicy gcr3** (funkcja 0xffffffffc1158b80):

    0xffffffffc1158b8b  4c 8b 25 de ae 04 03   mov    r12,[rip+0x304aede]  # 0xffffffffc41a3a70
    0xffffffffc1158ba1  49 83 c4 68            add    r12,0x68             ; zamek kontekstu
    0xffffffffc1158bad  41 0f b7 bf 22 60 00 00  movzx edi,WORD PTR [r15+0x6022]  ; identyfikator urzadzenia
    0xffffffffc1158bbb  e8 80 df 71 00         call   0xffffffffc1876b40    ; wywolanie hiperwizora
    0xffffffffc1158bc4  e8 77 de 71 00         call   0xffffffffc1876a40
    0xffffffffc1158bcd  49 8b 87 40 60 00 00   mov    rax,[r15+0x6040]     ; strona gcr3
    0xffffffffc1158bd4  48 83 cb 01            or     rbx,0x1              ; bit V
    0xffffffffc1158bd8  49 63 ce               movsxd rcx,r14d
    0xffffffffc1158be2  48 89 1c c8            mov    [rax+rcx*8],rbx      ; gcr3[indeks] = korzen | 1

Argumenty tego wywolania ustawia `iommu_add_device_table_entry`:

    0xffffffffc115c77b  41 8b 9d 80 60 00 00   mov    ebx,DWORD PTR [r13+0x6080]   ; indeks
    0xffffffffc115c782  4c 89 e7               mov    rdi,r12                      ; r12 = r13+0x6058
    0xffffffffc115c785  e8 a6 35 3f 00         call   0xffffffffc154fd20           ; wartosc = korzen
    0xffffffffc115c78a  4c 89 ef               mov    rdi,r13
    0xffffffffc115c78d  89 de                  mov    esi,ebx
    0xffffffffc115c78f  48 89 c2               mov    rdx,rax
    0xffffffffc115c792  e8 e9 c3 ff ff         call   0xffffffffc1158b80

Czyli lancuch jest taki:

    softc IOMMU (ctx)
      ctx+0xc8            tablica wpisow, rozmiar wpisu 0x6088, licznik w ctx+0xc0
      wpis+0x6022         identyfikator urzadzenia (po nim szuka sie wpisu)
      wpis+0x6040         strona tablicy gcr3 (0x4000 B, wyzerowana)
      wpis+0x6080         indeks w tablicy gcr3
      wpis+0x6058         struktura tablic stron
      wpis+0x6030         pamiec pt_info (0x1818 B)
      gcr3[indeks]        korzen tablicy stron, z bitem 0 ustawionym na 1

**Krok 3. Wypelnianie tablic stron** robi `0xffffffffc154fe40`, wywolywane z
`0xffffffffc115caa0` (argumenty: struktura z `wpis+0x6058`, adres fizyczny segmentu, dlugosc,
adres I/O, flagi). Pod tym adresem nie ma prologu funkcji (sprawdzone skanem prologow
w zakresie 0xc15afc00 do 0xc15b0200), wiec jest to etykieta wewnatrz wiekszej funkcji
obslugi tablic stron, zaczynajacej sie wczesniej.

**Krok 4. Uniewaznienie** wpisow w sprzecie po mapowaniu:

    0xffffffffc115cac9  41 8b 84 24 80 60 00 00  mov    eax,DWORD PTR [r12+0x6080]
    0xffffffffc115cad1  4c 8b 3d 98 6f 04 03   mov    r15,[rip+0x3046f98]  # 0xffffffffc41a3a70
    0xffffffffc115cae6  89 45 c0               mov    [rbp-0x40],eax
    0xffffffffc115caec  41 0f b7 84 24 20 60 00 00  movzx eax,WORD PTR [r12+0x6020]
    0xffffffffc115caf5  0d 00 00 00 30         or     eax,0x30000000
    0xffffffffc115cafa  89 45 c4               mov    [rbp-0x3c],eax
    0xffffffffc115cafd  48 89 4d c8            mov    [rbp-0x38],rcx       ; 0x7ffffffffffff007
    0xffffffffc115cb01  e8 6a cb ff ff         call   0xffffffffc1159670
    0xffffffffc115cb09  e8 22 c5 ff ff         call   0xffffffffc1159030

**Gdzie jest kontekst.** W sciezce mapowania wystepuja dwa rozne globalne wskazniki:

- `0xffffffffc41a3a70`: kontekst IOMMU uzywany przez `amd_iommu_map` i przez zapis do gcr3
  (zamek pod `+0x68`). W zrzucie `[0xffffffffc41a3a70] = 0xffffff8005768000`.
- `0xffffffffc41a3a80`: obiekt 0x328 B alokowany w 0xffffffffc1159850, z zamkiem o nazwie
  `iommu context` pod `+0x18` i zerowanym polem `+0x320`. W zrzucie
  `[0xffffffffc41a3a80] = 0xffffbd5a01752000`.

To sa rozne obiekty (rozne wartosci w zrzucie). Tablica wpisow jest indeksowana od kontekstu
przekazanego jako argument 1 do `iommu_add_device_table_entry`, czyli od softc urzadzenia
IOMMU z `0xc0f12b10`. Nie udalo sie dowiesc, ze to ten sam obiekt co `*(0xffffffffc41a3a80)`,
wiec nie stawiam takiej tezy.

## 6. Odpowiedz 4: co wypisuje format `mp4_coredump_buffer_iommu = 0x%016lx.`

Format jest uzywany w funkcji wypisujacej pola coredump (0xffffffffc1883590), ktora jako
argument dostaje wskaznik funkcji wypisujacej (`r15`) i czyta pola softc mp40:

    0xffffffffc1883597  48 8b 1d ba b5 1c 03   mov    rbx,[rip+0x31cb5ba]  # 0xffffffffc4a4eb58
    0xffffffffc18835a5  49 89 ff               mov    r15,rdi

    0xffffffffc1883632  48 8b b3 b0 06 00 00   mov    rsi,[rbx+0x6b0]
    0xffffffffc1883639  48 8d 3d fb 5b 71 00   lea    rdi,[rip+0x715bfb]  # 0xffffffffc1f9923b
    0xffffffffc1883640  31 c0                  xor    eax,eax
    0xffffffffc1883642  41 ff d7               call   r15

Ten sam format i to samo pole wystepuja w drugiej galezi tej funkcji:

    0xffffffffc18837c8  48 8b b3 b0 06 00 00   mov    rsi,[rbx+0x6b0]
    0xffffffffc18837cf  31 c0                  xor    eax,eax
    0xffffffffc18837d1  41 ff d7               call   r15

**Odpowiedz: format wypisuje 64-bitowe pole `softc + 0x6b0`**, czyli
`mp4_coredump_buffer_iommu`, jako szesnastke z 16 cyframi. Sa to sasiednie pola tego samego
bloku, odczytane z tych samych miejsc (formaty odczytane ze zrzutu):

| offset softc | format | nazwa w komunikacie |
|---|---|---|
| +0x4e8 (dword) | `mp4_coredump_count = 0x%08x.` | licznik |
| +0x4ec (dword) | `mp4_coredump_state        = 0x%08x.` | stan |
| +0x4f0 (dword) | `mp4_coredump_flags_dump   = 0x%08x.` | flagi zrzutu |
| +0x4f4 (dword) | `mp4_coredump_flags        = 0x%08x.` | flagi |
| +0x4f8 (dword) | `mp4_coredump_request      = 0x%08x.` | zadanie |
| +0x6a8 | `mp4_coredump_buffer_size  = 0x%016lx.` | rozmiar bufora |
| **+0x6b0** | **`mp4_coredump_buffer_iommu = 0x%016lx.`** | adres bufora w przestrzeni urzadzenia |
| +0x6b8 | `mp4_coredump_buffer_va    = 0x%016lx.` | adres w pamieci jadra |
| +0x6d0 | `mp4_coredump_data_size    = 0x%016lx.` | rozmiar danych |
| +0x748 | `mp4_cpdump_buffer_va      = 0x%016lx.` | adres drugiego bufora |
| +0x750 | `mp4_cpdump_buffer_size    = 0x%016lx.` | jego rozmiar |
| +0x758 | `mp4_cpdump_data_size      = 0x%016lx.` | jego dane |
| +0x760 | `mp4_mp4dump_get_info_size = 0x%016lx.` | rozmiar informacji |
| +0x768 | `mp4_cpdump_get_info_size  = 0x%016lx.` | rozmiar informacji |

Pola te sa ustawiane w attachcie mp40 (0xffffffffc1883a20), ktory najpierw zapisuje wskaznik
softc do globalnej komorki, a potem pracuje na tym samym obiekcie w `rbx`:

    0xffffffffc1883a43  e8 c8 f0 68 ff         call   0xffffffffc0f12b10
    0xffffffffc1883a48  48 89 05 09 b1 1c 03   mov    [rip+0x31cb109],rax  # 0xffffffffc4a4eb58
    0xffffffffc1883a52  48 89 c3               mov    rbx,rax
    0xffffffffc1883c9a  48 c7 83 a8 06 00 00 00 00 20 00  mov QWORD PTR [rbx+0x6a8],0x200000
    0xffffffffc1883ca5  48 c7 83 b8 06 00 00 00 00 00 00  mov QWORD PTR [rbx+0x6b8],0x0
    0xffffffffc1884323  48 89 8b b0 06 00 00   mov    [rbx+0x6b0],rcx

Wartosc wpisywana do `+0x6b0` jest liczona w tym samym attachu jako adres wyrownany do 64 MB:

    0xffffffffc188424f  49 8d 8f ff ff 1f 04   lea    rcx,[r15+0x41fffff]
    0xffffffffc1884256  48 81 e1 00 00 00 fc   and    rcx,0xfffffffffc000000
    0xffffffffc1884323  48 89 8b b0 06 00 00   mov    [rbx+0x6b0],rcx

W calym module mp40 (obszar 0xc187e000 do 0xc1884000 i dalej) to jedyny zapis do `+0x6b0`.
Pozostale zapisy do `+0x6b0` w pliku (0xc11281fa, 0xc1200fce, 0xc161a6f1, 0xc169c5d5, 0xc169c919)
dotycza innych struktur: na przyklad w 0xc161a6f1 te same dane sa kladzione pod `+0x20`,
`+0x250`, `+0x480` i `+0x6b0`, czyli w tablicy o skoku `0x230`, a nie w softc mp40.

Pole `+0x6a8` (rozmiar) jest potem nadpisywane realna wartoscia, a `+0x6b8` adresem w pamieci
jadra, w funkcji 0xffffffffc1881ec0, tylko przy `mp4_coredump_state == 0`:

    0xffffffffc1881f32  48 8b 35 1f cc 1c 03   mov    rsi,[rip+0x31ccc1f]  # 0xffffffffc4a4eb58
    0xffffffffc1881f60  83 be ec 04 00 00 00   cmp    DWORD PTR [rsi+0x4ec],0x0
    0xffffffffc1881f72  48 85 d2               test   rdx,rdx
    0xffffffffc1881f77  48 89 96 b8 06 00 00   mov    [rsi+0x6b8],rdx      ; adres bufora w pamieci jadra
    0xffffffffc1881f80  b9 00 00 20 00         mov    ecx,0x200000
    0xffffffffc1881f85  48 89 8e a8 06 00 00   mov    [rsi+0x6a8],rcx      ; rozmiar 2 MB

Sam bufor jest alokowany w attachu (0x200000 B) i mapowany przez 0xffffffffc1885d50, ktora
powtarza schemat `mp4_map_iommu_full_discont` (najpierw `0xc1877680`, potem `0xc15c3f90`
z funkcja zwrotna `0xc0ec9310`):

    0xffffffffc1884352  bf 00 00 20 00         mov    edi,0x200000
    0xffffffffc18843b8  e8 53 45 fe ff         call   0xffffffffc1868910
    0xffffffffc18843bd  48 89 83 78 03 00 00   mov    [rbx+0x378],rax
    0xffffffffc18843ef  e8 5c 19 00 00         call   0xffffffffc1885d50
    0xffffffffc1885db3  e8 c8 18 ff ff         call   0xffffffffc1877680
    0xffffffffc1885dd7  4c 8d 0d 32 35 64 ff   lea    r9,[rip+0xffffffffff643532]  # 0xffffffffc0ec9310

## 7. Czego nie udalo sie ustalic

1. **Nie ma odwolan RIP-wzglednych do wiekszosci z tych napisow w postaci lancucha jako
   calosci** poza podanymi wyzej miejscami. Wszystkie podane napisy maja odwolania (tabela
   w punkcie 1), ale w kilku wypadkach sa to odwolania z komunikatu bledu, a nie z miejsca
   uzycia funkcji.
2. **Nie ustalilem, gdzie dokladnie 32-bajtowy opis budowany w `iommu_add_device_table_entry`
   (zerowany `0xc115c691`, z bitami V|TV ustawianymi `0xffffffffc115c744 or eax,0x3`) jest
   zapisywany do tablicy urzadzen.** W kodzie widac tylko wywolania hiperwizora
   `0xc1876b20`, `0xc1876a40` i `0xc1876b40`; nie znalazlem zapisu tych 32 bajtow do pamieci.
   Nie moge wiec powiedziec, ktorym kanalem opis trafia do sprzetu.
3. **Nie ustalilem pelnej struktury poziomow tablicy stron.** Wiadomo, ze korzen jest
   w tablicy gcr3 (punkt 5) i ze mapowanie zakresu robi `0xc154fe40` na strukturze
   z `wpis+0x6058`, ale sama funkcja `0xc154fe40` lezy wewnatrz wiekszej funkcji (brak
   prologu pod tym adresem), a jej rozmiar i liczba poziomow nie zostaly wyprowadzone.
4. **Nie ustalilem relacji miedzy `0xffffffffc41a3a70` a `0xffffffffc41a3a80`.**
   W zrzucie to dwa rozne wskazniki (`0xffffff8005768000` i `0xffffbd5a01752000`).
   Sciezka mapowania uzywa pierwszego z nich.
5. Wartosci odczytane pod adresami globalnymi (`0xffffffffc31c0e78`, `0xffffffffc4a4eb58`
   i inne) to stan z zywego jadra w chwili zrzutu, wiec sluza jako ilustracja, a nie jako
   stala. Sa podane jawnie tam, gdzie ich uzywam.
6. Napisy `gc_map_iommu_region_for_mp4_sdma` i `For now iommu support physcont only`
   zostaly zlokalizowane i maja odwolania (tabela w punkcie 1), ale nie byly tematem
   pytan, wiec ich ciala nie sa tu rozpisane.

## 8. Odtworzenie

Pliki robocze: `/root/iommu-analiza/` w WSL (poza repozytorium).

    kernel.bin                      kopia zrzutu (sha256 zgodny z README)
    mkelf.py                        opakowanie obrazu w minimalny ELF64 pod baza
    xref.c                          skan odwolan RIP-wzglednych do napisow
    ref.c                           szukanie wywolan, lea i wskaznikow 64-bit
    wr.c                            szukanie dostepow do pol o zadanym przesunieciu
    win.py, dis.py, disva.py        deasemblacja okien i zakresow (z granica funkcji)

Podstawowe polecenia:

    python3 mkelf.py kernel.bin kernel.elf 0xffffffffc0c60000
    gcc -O2 -o xref xref.c && ./xref kernel.bin 0xffffffffc0c60000 0x012bbdae
    python3 disva.py 0xffffffffc187fef0 0xffffffffc1880020 --funkcja

Wyniki posrednie: `/root/iommu-analiza/out/` (`full_discont.txt`, `mp4_discont.txt`,
`iommu_add_dev.txt`, `a53io_map_iommu.txt`, `amd_iommu_map_nsegs.txt`, `coredump1.txt`,
`cd_fields.txt`, `more.txt`, `pagetables.txt` i inne).
