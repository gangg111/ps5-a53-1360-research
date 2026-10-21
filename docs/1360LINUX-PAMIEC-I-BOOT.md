# 1360linux.elf: jak payload siega do pamieci i jak uruchamia Linuksa

Analiza offline pliku `1360linux.elf` (237 448 B, sha256
`e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226`, czyli dokladnie
nazwa pliku w magazynie zalacznikow). Praca bez konsoli, na deasemblacji i danych z pliku.
Data analizy: patrz `git log` dla tego pliku.

## 0. Metoda i narzedzia

Plik **nie jest stripped**: ma pelna tablice `.symtab` (781 symboli) i `.dynsym` (46),
z nazwami plikow zrodlowych w symbolach `FILE`. To zmienia metode pracy wzgledem
`notes/IOMMU-MAPOWANIE-Z-DEASEMBLACJI.md` (tam byl surowy zrzut jadra bez symboli):
tutaj granice funkcji, nazwy i rozmiary pochodza wprost z ELF-a, a nie z heurystyki prologow.

Uzyte narzedzia. Do notatki zostaly dolaczone dwa skrypty, oba samodzielne, uruchamialne
lokalnym Pythonem z katalogu `tools/`:

| narzedzie | rola |
|---|---|
| `tools/check1360.py` | odczyt i weryfikacja tablicy `off_1360`: trzy grupy pol `offsets_present()`, werdykt `grupa1 AND (grupa2 OR grupa3)`, pelny dump 60 qwordow |
| `tools/checkbinds.py` | wiazanie (LOCAL/GLOBAL) i rozmiary wybranych symboli |
| `tools/elfsym.py` | czytnik ELF64: lista `FUNC`/`OBJECT` z adresami i rozmiarami (uzywany przez `checkbinds.py`) |
| `tools/elfstrings.py` | wszystkie napisy sekcji z adresami VA; `python3 elfstrings.py 1360linux.elf [filtr]` |
| `tools/elfrelacount.py` | zliczenie relokacji `.rela.dyn`/`.rela.plt` wedlug typu |
| `tools/findmovabs.py` | szukanie `movabs rax,imm64` w wyodrebnionym blobie (do obfuskownaego shellcode) |

Pozostale czynnosci robilem przez `objdump -d -M intel` z `C:\msys64\usr\bin\objdump.exe`
(GNU binutils 2.46) oraz krotkimi skryptami pisanymi na miejscu; tych skryptow nie
zalaczam, bo kazdy z nich to kilka linijek na jedno pytanie. Wszystkie liczby i adresy
w notatce pochodza z tych odczytow, nie z pamieci.

W WSL odpowiednik jest taki sam (`objdump` z binutils), a plik trzeba najpierw skopiowac
poza `/root` (uzytkownik WSL nie ma prawa wejscia do `/root` bez `sudo`).

ELF: `ET_DYN`, maszyna x86-64, entry `0xba70`, kompilator
`Ubuntu clang version 18.1.3`, linker `Ubuntu LLD 18.1.3`. Cztery segmenty `PT_LOAD`,
wszystkie wyrownane do **0x4000 (16 KB)**, co jest strona tej platformy (FreeBSD/PS5),
a nie 4 KB:

    LOAD off=0x004000 va=0x0000000000000000 filesz=0x014db0 memsz=0x014db0 RWE
    LOAD off=0x01c000 va=0x0000000000018000 filesz=0x008190 memsz=0x008190 RW
    LOAD off=0x028000 va=0x0000000000024000 filesz=0x00a6c0 memsz=0x04cf70 RW
    DYNAMIC off=0x024000 va=0x0000000000020000

`.bss` konczy sie na `0x70f70`, wiec caly obraz to 463 728 B pamieci. Relokacje:
`.rela.dyn` ma 187 wpisow (149 `R_X86_64_RELATIVE`, 38 `R_X86_64_GLOB_DAT`),
`.rela.plt` ma 2 (`R_X86_64_JUMP_SLOT`, do `memset` i `memcpy`). Dzieki relatywnym
latwo odczytac tablice wskaznikow: wszystkie osiem wpisow `file_paths` to
`R_X86_64_RELATIVE` z addendami wskazujacymi na napisy w `.rodata`. Uwaga przy czytaniu danych z pliku:
segment `0x28000` ma VA `0x24000`, wiec offset w pliku = VA + 0x4000 dla `.data`
i `.rodata`, a `check1360.py` rozwiazuje to po tablicy sekcji, nie po stalym dodawaniu.

## 1. Czym ten plik jest, a czym nie jest

10 pierwszych symboli `FILE` w `.symtab` (kolejnosc linkowania) pokazuje, z czego
powstal payload:

    firmware.c, gpu.c, mman.c, hv_defeat_0304.c, hv_defeat_0506.c, hv_defeat_0607.c,
    hv_defeat_13xx.c, iommu.c, khook.c, loader.c, main.c, offsets.c, prepare_resume.c,
    pipe2.c, tmr.c, utils.c, syscalls.c, crt.c, syscall.c, klog.c, nid.c, kernel.c,
    rtld.c, rtld_so.c, rtld_sprx.c, rtld_payload.c, rtld_dlfcn.c, mdbg.c, patch.c,
    kernel_procio.c, kernel_iommu.c

Napis z `.rodata` `0x1efae`:

    Welcome to ps5-linux-loader. We'll defeat HV and prepare the system to boot Linux on sleep resume.

To jest wiec **ps5-linux-loader** (payload uzytkownika PS5, FreeBSD) zlozony razem z
warstwa kread/kwrite oraz z silnikiem latania hipervisora (rodzina RobinHood/kstuff).
Plik jest `ET_DYN`, wiec jest podawany loaderowi payloadow platformy (elfldr) i
relokowany przez wlasny rtld (`__rtld_init`). Cztery `.rela.dyn` typu `R_X86_64_RELATIVE`
wskazuja miedzy innymi na tablice `file_paths`.

Kluczowy wniosek: **payload nie zawiera wlasnego bledu w jadrze.** Nie ma tu exploitacji
typu heap overflow ani UAF. Mechanizm czytania i pisania pamieci jadra dostaje **gotowy
od loadera hosta** (patrz rozdzial 4).

## 2. Sciezka uruchomienia

### 2.1 Wejscie i init

    __crt_start (0xbad0):
      zerowanie .bss (0x2e6c0..0x70f70)
      payload_args = rdi                                        # 0x70638
      __crt_syscall_init(payload_args)                          # 0xbe50
      __kernel_init(payload_args)                               # 0xdc00
      __klog_init()
      kernel_dynlib_dlsym(-1, 2, "__isthreaded"); *p = 1        # 0xbb36..0xbb57
      __patch_init()                                            # 0x13db0
      __rtld_init()                                             # 0x11430
      ... dlopen samego siebie jako "payload" i jego __init_array
      main()                                                    # 0x8b20

`main` (0x8b20, 677 B) to plaska sekwencja bramek:

    1. setup_env()       -> set_offsets(), init_global_vars()
    2. fetch_linux(&linux_i)          # tylko przygotowanie, bez skoku
    3. prepare_resume(&buf, &len)     # przygotowanie shellcode'u jadra
    4. rozgalezienie po fw: 0x300/0x500/0x650/0x800/0x1100/0x1300..0x13ff
       -> hv_defeat_0304 / 0506 / 0607 / 13xx
    5. notify("Finished preparation. Going to rest mode in 5 seconds.")
       sleep(5)
       enter_rest_mode()              # 0xa750
       petla: sleep(30) bez konca

`set_offsets` (0x97f0) czyta wersje z jadra przez `kernel_get_fw_version` (0xdbb0):
syscall `0x289` z argumentem `2`, zwracajacy wskaznik do struktury, z ktorej bierze
`[+0x14]`; nastepnie `fw = (ver >> 16) & 0xffff`. Dla 13.60 daje to `fw = 0x1360`.

Dopasowanie tablic offsetow nie jest zakresowe w calosci: `0x1300` lapie `0x1300..0x135f`,
ale `0x1360` ma **wlasny wpis** (`set_offsets+0x56a` kopiuje `off_1360`, 480 B, do
`env_offset`). Czyli 13.60 jest obslugiwany osobna, dedykowana tablica:

    set_offsets:  case 0x1300 -> memcpy(&env_offset, &off_1300, 0x1e0)
                  case 0x1360 -> memcpy(&env_offset, &off_1360, 0x1e0)
                  default    -> return -1

### 2.2 Skad pliki: sciezki i nadpisania

`find_and_get_size_of_file` (0x7f50) i `find_and_read_file` (0x8290) iteruja po
**8 wpisach** tablicy `file_paths` (0x24510). Wartosci odczytane z relokacji
`R_X86_64_RELATIVE` (`elfrela.py`):

    /mnt/usb0/          /mnt/usb1/          /mnt/usb2/          /mnt/usb3/
    /mnt/usb0/PS5/Linux/  /mnt/usb1/PS5/Linux/  /mnt/usb2/PS5/Linux/  /mnt/usb3/PS5/Linux/

Nazwa pliku skladana jest przez `snprintf(buf, 0x100, "%s%s", katalog, nazwa)`.
Dodatkowo `get_overridden_filename` (0x8060) czyta raz plik `path-override.txt` z tych
samych katalogow i pozwala podmienic nazwe dowolnego pliku, skladnia `nazwa=nowa_nazwa`
(separator `=`, koniec linii zamieniany na NUL). Wynikowy plik otwiera/statuje oryginalna
sciezka zbudowana z katalogu i nazwy.

`fetch_linux` (0x8460) robi dokladnie to:

    find_and_get_size_of_file("bzImage", &sciezka)      -> rozmiar albo abort
    rozmiar_zaokraglony = (size + 0x3fff) & ~0x3fff
    mmap(NULL, rozmiar_zaokraglony, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0)
    read_file(sciezka, buf, rozmiar_zaokraglony)        -> blad: "Something went wrong
                                                            while reading bzImage - Aborting"
    find_and_get_size_of_file("initrd.img", &sciezka)
    mmap(...) ; read_file(...)                          -> "Something went wrong while
                                                            reading initrd - Aborting"
    dump_device_firmwares()

Potem pliki konfiguracyjne (wszystkie przez te sama liste katalogow, blad nie przerywa):

| plik | rozmiar bufora | brak pliku | znaczenie |
|---|---|---|---|
| `vram.txt` | 16 B | `printf("File vram.txt not found at default paths - Using static fallback")` | `strtoull(..., 16)` -> wartosc VRAM; `0` tez daje fallback |
| `cmdline.txt` | 2048 B | `printf("File cmdline.txt not found at default paths - Using static fallback")` | wlasna linia polecen jadra |

Wartosci domyslne (stale z `.rodata`):

    vram  = 0x20000000 (512 MB)
    cmdline = "root=/dev/sda2 rw rootwait console=ttyTitania0 console=tty0
               video=DP-1:1920x1080@60 mitigations=off idle=halt pci=pcie_bus_perf"

Kernel nie jest **niczym weryfikowany**: brak sumy kontrolnej, brak podpisu, brak testu
naglowka bzImage. Sprawdzany jest tylko rozmiar pliku (`stat`) i to, ze `read` zwrocilo
wartosc nieujemna. Zawartosc `bzImage` idzie do jadra bajt w bajt.

### 2.3 Gdzie laduja obraz jadra i initrd

`fetch_linux` buduje strukture `linux_info_t` (nazwa z symbolu `linux_i`, 0x6fa00,
kopiowana do jadra jako 0xc38 B) i **mapuje strony uzytkownika wprost w przestrzeni
jadra** przez `install_page_syscore`:

    +0x00 = 0xffff80000000c000                       # boot_params / zero page
    +0x08 = 0xffff800000010000                       # obraz jadra (start)
    +0x10 = rozmiar bzImage
    +0x18 = 0xffff800000010000 + round_up(size)      # start initrd
    +0x20 = rozmiar initrd.img
    +0x28 = vram (z vram.txt albo 0x20000000)
    +0x30 = get_kit_type()                           # 0 Retail, 1 TestKit, 2 DevKit
    +0x438 = kopia cmdline.txt (0x800 B)

Kernel command line jest wiec przekazywany **jako tekst w tej strukturze**, a nie jako
argumenty procesu. `install_page_syscore` (0xab60) bierze pmap procesu 1
(`kernel_get_proc(1)`, potem `[vmspace+0x20]` = pml4) i dla kazdej strony 16 KB obrazu
wykonuje `install_page(pml4, va, pa, prot)` (0xa900), ktory buduje brakujace poziomy
tablic stron przez `kread64`/`kwrite64` i wpisuje PTE z flagami `pa | 2 | 1 | prot`.
Czyli **mapy uzytkownika sa wsuwane pod stala VA jadra**; nie ma kopiowania obrazu.

Struktura `linux_info_t` jest dodatkowo kopiowana do swiezej strony jadra przez
`kwrite(pa_to_dmap(alloc_page()), &linux_i, 0xc38)` (0x89b9..0x89c2), a ta sama strona
fizyczna jest mapowana pod `0xffff80000000c000`. Shellcode jadra dostaje jej adres
w argumentach.

Adresy `0xffff80000000c000` i `0xffff800000010000` sa **zaszyte na sztywno** (`movabs`).
To zakres `-2 GB` (canonical high, `kernel_map` w FreeBSD), wiec mapa jest ta sama na
kazdym firmware; rozni sie tylko to, co jest pod nia zajete.

### 2.4 Przygotowanie shellcode'u jadra

`prepare_resume` (0x8f80):

    if (env_offset[0xb8] == 0) -> "Error: missing code cave offset" (0x1e03b)
    ro = round_up(shellcode_kernel_bin_len, 0x4000)          # 26 896 B -> 0x7000
    buf = mmap(NULL, ro, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0)
    memcpy(buf, shellcode_kernel_bin, len)
    args = prepare_sck_args()                                 # 0x9130
    update_sck_args_ptr(buf, args)                            # 0x93e0
    for (i = 0; i < len; i += 0x4000)
        install_page_syscore(0xffff800000000000 + i, vtophys_user(buf + i), 0)

`update_sck_args_ptr` szuka w shellcode markeru `0x11aa11aa11aa11aa` w pierwszych 0x40
 bajtach i wpisuje tam adres strony argumentow. To marker z pierwszego `movabs` w bajtach
shellcode. `prepare_sck_args` buduje 0x98-bajtowy blok argumentow:

    +0x00 u16  fw                                  (0x1360)
    +0x08 u64  ktext        (z __kernel_init)
    +0x10 u64  kdata
    +0x18 u64  dmap
    +0x20..+0x50  == ktext + env_offset[{0xc0,0xc8,0xd0,0xd8,0xe0,0x108}]
    +0x58, +0x60, +0x68  == ktext + env_offset[{0x110,0x118,0x120}] albo 0
    +0x70..+0x90  == env_offset[{0xf8,0x100,0xf0,0xe8}] (bez dodawania ktext)
    +0x40  marker 0x11aa11aa11aa11aa, podmieniany na adres strony argumentow

Blok trafia do jadra przez `kernel_copyin(pa_to_dmap(alloc_page()), &args, 0x98)`.
Shellcode jest wiec umieszczony pod `0xffff800000000000` i tam z niego korzysta IDT.

Nastepnie `remove_xotext` (0x8dd0) idzie od `ktext` do `kdata` skokiem 0x1000 i dla kazdej
strony wola `page_chain_set_rw` (0xa170), ktora w lancuchu tablic stron ustawia bit RW
i kasuje bit NX (`0x8000000000000000`) w PTE. Inaczej pierwszy zapis shellcode'u do
`.text` jadra wywalilby sie. Potem `kernel_pmap_invalidate_all` (0x8e40) uniewaznia mapy
(`two_zero_pages`, 0x40000 B w .bss).

Diagnostyka, ktora payload zostawia w logu przed uzbrojeniem, jest bardzo konkretna:
`PTE STATE cr3=0x%lx dmap=0x%lx`, `DIAG: .text permission state (page tables only)`,
po jednej linii na obszar (`kernel_uart_override`, `kernel_cfi_check`, `KERNEL_CODE_CAVE`,
`GAD_ADD_RSP_28..RBP`, `FUN_MEMCPY`, `DATA_CAVE`, `CARRIER_PA via dmap`) w formacie
`%-26s va=0x%lx:` + ` L%d[P%d R%d X%d N%d S%d]`, i na koncu
`VERDICT: leaf XO/RW printed per line above.` oraz
`VERDICT: still execute-only and shellcode_kernel's first write WILL fault.`
To jest wprost narzedzie do sprawdzenia, czy `remove_xotext` zadzialalo.

### 2.5 Latania hipervisora dla 13.60 (`hv_defeat_13xx`, 0x37d0)

Funkcja dziala w nastepujacej kolejnosci (wszystkie adresy i offsety z `env_offset`):

1. `offsets_present()` (0x3e70) sprawdza **trzy grupy** pol `env_offset`: 20 pol,
   7 pol, 2 pola. Zwraca prawde, gdy grupa 2 **albo** grupa 3 jest kompletna
   (w kodzie `cmp [rsp-0x78],0` / `cmp [rsp-0x7c],0` z `setne` i OR-em). Brak kompletu to
   komunikat `13.60 offsets are incomplete - refusing to arm.` i
   `See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.`
2. Kontrola integralnosci jadra: czyta 7 qwordow z `ktext + env_offset[0x1d0]`
   (dla 13.60 `+0x1a1a030`) i porownuje z tablica `NVS_EXPECT` (0x1f2a0). Rozbieznosc to
   `validity gate failed - wrong firmware image?` i wyjscie.
3. `dump_text_perm()` (0x41f0) wypisuje stan uprawnien stron.
4. `derive_H()` (0x4390) przechodzi tablice deskryptorow EFI (typ `0x9004`) i wyciaga
   wartosc `H`; niepowodzenie to `could not derive H from the EFI map - refusing to arm.`
5. `kernel_set_ucred_authid(getpid(), 0x4800000000000007)` (0xfb70).
6. `pin_to_core_reborn(0)` + `sceKernelGetCurrentCpu()`; niepowodzenie to
   `could not pin to core %d - refusing to arm.`
7. Zapis 762-bajtowego `shellcode_ap_bin` pod `env_offset[0x148] + 0x1000` przez `kwrite`.
8. `kh_init(&kh, ...)` (0x5d10) z wlasnymi funkcjami odczytu i zapisu (`kh_read` 0x4680,
   `kh_write` 0x46b0) i dlugoscia 6, `kh_set_tables`, `kh_set_core(0)`,
   `kh_set_hook_target(ktext + env_offset[0x138])`,
   `kh_set_resume_rsi(dmap + 0x3ffff000)`, `kh_set_resume_rdx(cr3)`.
9. Budowa lancucha ROP w `chain_buf` (0x2e7b0) i `kh_chain_memcpy` do
   `dmap + 0x3ffff000 + 0xf00`, nastepnie kolejne `kh_chain_store` do przesuniec
   `+0x00, +0x08, +0x10, +0x18, +0x20, +0x28, +0x30` tego samego regionu.
10. `clear_execute_disable("carrier page", dmap + 0x3ffff000)` (0x46e0) kasuje bit 63
    w PTE, zeby strona nosna byla wykonywalna.
11. `kh_install(&kh, &chain)` (0x6170), `kh_trigger(&kh)` (0x7b50).
12. `build_sx_rop()` (0x4890) do swiezej strony, `kwrite64(ktext + env_offset[0x30] + 0x54, page + 0x1000)`.
13. `setidt(13, ktext + env_offset[0x60], 0xe, 0, 7)` i `setidt(30, ktext + env_offset[0x60], 0xe, 0, 7)`.
14. `kwrite64(ktext + env_offset[0x20], ktext + env_offset[0x20] - 8)`.

Punkty 12..14 sa **trwalym stanem w jadrze** (rozdzial 6). Wynik calej funkcji `0` pozwala
`main` przejsc do komunikatu o rest mode; `-1` daje
`Something went wrong while defeating Hypervisor.` + `Please make sure your fw is supported.`

Dokladne adresy dla 13.60 (odczytane z `off_1360`, `ktext = kdata - 0xcc0000`):

    krok 12: kwrite64(0xffffffffc4817014, <strona SX ROP> + 0x1000)
             bo ktext + 0x3bb6fe0 + 0x54 = 0xffffffffc4817014
    krok 13: setidt(13, 0xffffffffc0ec9fb8, 0xe, 0, 7)
             setidt(30, 0xffffffffc0ec9fb8, 0xe, 0, 7)
             bo ktext + 0x269fb8 = 0xffffffffc0ec9fb8
    krok 14: kwrite64(0xffffffffc4629490, 0xffffffffc4629488)
             bo ktext + 0x39c9490 = 0xffffffffc4629490

Oba `setidt` dostaja **ten sam adres handlera** i roznia sie tylko numerem wektora.

Dwie zaszyte stale dla 13.60 widoczne w kodzie (uzywane, gdy `env_offset[0x1d8]`
albo `env_offset[0x1d0]` jest zerowe):

    h     = env_offset[0x1d8] ? env_offset[0x1d8] : 0x3df1070
    gate  = env_offset[0x1d0] ? env_offset[0x1d0] : 0x1a1a030

W dostarczonym pliku oba pola `off_1360` sa niezerowe, wiec stale nie sa uzywane.

### 2.6 Przekazanie sterowania

Nie ma tu `kexec` ani zadnego wywolania jadra Linuksa z poziomu uzytkownika. Sterowanie
jest przekazywane **przez zaplanowany rest mode**:

    notify("Please wait for the orange light to stop blinking and then wakeup to Linux :)")
    enter_rest_mode():
        sceKernelOpenEventFlag(&h, "SceSystemStateMgrStatus")
        sceKernelNotifySystemSuspendStart()
        sceKernelSetEventFlag(h, 0x400)
        sceKernelCloseEventFlag(h)
    petla: sleep(30)

Przy wybudzeniu konsoli jadro PS5 wykonuje sciezke resume, ktora przechodzi przez
zahaczony punkt. Tam uruchamia sie lancuch ROP z jaskini kodu i shellcode jadra, ktory
korzystajac z `linux_info_t` (obraz jadra i initrd zmapowane pod `0xffff800000010000`,
cmdline w `+0x438`, vram w `+0x28`) przechodzi na obraz Linuksa. Z tego powodu komunikat
mowi o "sleep resume", a nie o natychmiastowym starcie.

Kernel command line i parametry portu szeregowego: payload **nie ustawia** zadnego z nich
sam. `kernel_uart_override`, `kernel_cfi_check`, `KERNEL_CODE_CAVE`, `GAD_ADD_RSP_28..RBP`,
`FUN_MEMCPY`, `DATA_CAVE`, `CARRIER_PA via dmap` wystepuja w tym pliku wylacznie jako
**etykiety diagnostyczne** przekazywane do `dump_pte_bits(etykieta, adres)`. Realny
`kernel_uart_override` jest opcja command line Linuksa, czyli trafia do jadra tylko wtedy,
gdy uzytkownik dopisze ja do `cmdline.txt` na USB; payload ma dla niej offset w tablicy
`off_1360` (`+0xf8`) i tylko go raportuje.

`vram.txt` sluzy do jednego: wartosc 16-kowa idzie do `linux_info_t+0x28` jako rozmiar
VRAM dla Linuksa. Brak pliku albo `0` to `0x20000000`.

### 2.7 Numeracja kontrolna: czy 13.60 jest kompletne

`tools/check1360.py 0x27bb0` czyta `off_1360` i sprawdza pola wymagane przez
`offsets_present()`:

    pola wymagane: 29
    pola zerowe  : 2  ['0x1c0', '0x1c8']
    grupa 1 (20 pol, offsety 0x138..0xb8): komplet
    grupa 2 (7 pol, offsety 0x158..0x190): komplet
    grupa 3 (2 pola, offsety 0x1c0, 0x1c8): PUSTA

Poniewaz warunkiem jest OR dwoch ostatnich grup, payload **uzbroi sie poprawnie**.
Zerowe sa tylko dwa gadzety konczace tablice `kgadget` (0x5570, przelacznik po indeksie
0..0x16): indeksy odpowiadajace `env_offset[0x1c0]` i `env_offset[0x1c8]` zwracaja 0.
Wszystkie indeksy uzywane przez `kh_install` (0..0x15) sa pokryte. Innymi slowy: brak
dwoch skrajnych gadzetow nie blokuje niczego w tej sciezce.

## 3. Co dokladnie robi alokacja i mapowanie pamieci

### 3.1 Odpowiedz wprost na pytanie z zadania

`sceKernelAllocateMainDirectMemory` i `sceKernelMapNamedDirectMemory` w tym pliku wystepuja
**wylacznie** w `gpu_alloc_dmem` (0x960). Jedyne dwa miejsca wywolania to:

    09aa:  call QWORD PTR [rip+...] # 1d380 <sceKernelAllocateMainDirectMemory>
    09ff:  call QWORD PTR [rip+...] # 1d390 <sceKernelMapNamedDirectMemory>

a `gpu_alloc_dmem` jest wolane tylko z `gpu_init_internal` (0x710) i `gpu_transfer_physical`
(0x10e0). `gpu_init` (0x670) **nie ma zadnego wolajacego** w tym pliku i nie jest wpisany
do `__init_array` (`.init_array` ma rozmiar 0). To samo dotyczy `gpu_test` (0xef0),
`gpu_read_phys*`, `gpu_write_phys*`, `gpu_submit_commands` i calego PM4 (`pm4_build_dma_data`,
`gpu_build_cmd_descriptor`, `pm4_type3_header`).

Czyli: **caly podsystem DMA przez GPU jest w tym pliku martwym kodem.** Sciezka
uruchomienia Linuksa nie dotyka go ani razu. Nie jest to mechanizm siegania do pamieci
jadra w tym payloadzie.

### 3.2 Czym payload siega do pamieci

Payload uzywa trzech warstw:

**(a) mmap uzytkownika + vtophys + wstawianie PTE do pmap jadra.** To jest glowne
narzedzie rozdzialu 2.3. `mmap(NULL, rozmiar, PROT_READ|PROT_WRITE, 0x1001, -1, 0)`
(flaga `0x1001` = `MAP_ANON|MAP_PRIVATE`), potem `vtophys_user` (0x9f40) chodzi po
tablicach stron pmap procesu biezacego i zwraca fizyczny adres, a `install_page_syscore`
wstawia ten sam fizyczny adres pod stala VA jadra. Adresy i rozmiary:

| co | VA w uzytkowniku | VA w jadrze | rozmiar |
|---|---|---|---|
| struct `linux_info_t` | swieza strona z `alloc_page` | `0xffff80000000c000` | 0x4000 |
| `bzImage` | `mmap` anonimowy | `0xffff800000010000` | round_up(size, 0x4000) |
| `initrd.img` | `mmap` anonimowy | `0xffff800000010000` + round_up(bzImage) | round_up(size, 0x4000) |
| `shellcode_kernel_bin` | `mmap` anonimowy | `0xffff800000000000` | round_up(26896, 0x4000) = 0x7000 |
| strona argumentow `sck_args` | `alloc_page` | `pa_to_dmap(pa)` | 0x4000 |
| strona lancucha SX ROP | `alloc_page` | `pa_to_dmap(pa)` | 0x4000 |

**(b) Wlasne mapy w pmap jadra, nie mapa bezposrednia.** `install_page(pml4, va, pa, prot)`
buduje brakujace poziomy (PML4 -> PDPT -> PD -> PT) **alokujac strony przez `alloc_page`**
i wpisujac PTE z prawami `pa | PTE_PRESENT(1) | PTE_RW(2) | prot`. Nie korzysta z gotowej
mapy bezposredniej jadra do samych danych. Mapa bezposrednia (`dmap`) sluzy wylacznie jako
**okno na pamiec fizyczna** przy pracy z tablicami stron i przy adresowaniu stron
alokowanych z jadra: `pa_to_dmap(pa)` = `dmap + pa`, gdzie `dmap = ktext - cr3`.

**(c) Gotowy kanal read/write jadra od loadera hosta** (rozdzial 4). To jedyna droga do
dowolnego adresu jadra.

### 3.3 Skad payload bierze `ktext`, `kdata`, `cr3`, `dmap`

`init_global_vars` (0x9da0):

    ktext = KERNEL_ADDRESS_TEXT_BASE ; kdata = KERNEL_ADDRESS_DATA_BASE
    kread(getpmap(kernel_get_proc(0)), &buf, 0x30)
    cr3   = buf[0x18]
    dmap  = buf[0x10] - buf[0x18]          # czyli dmap = kdata - cr3

To ostatnie jest rownowazne `dmap = ktext - cr3` przy zalozeniu stalej roznicy miedzy
`ktext` i `kdata`, ktora `__kernel_init` wylicza z bazy danych (patrz nizej).

`__kernel_init` (0xdc00, 3645 B) to duzy przelacznik po `(fw & 0xffff0000)`:

| fw | `ktext` | `allproc` | `security_flags` | `rootvnode` |
|---|---|---|---|---|
| 0x300/0x310 | `kdata-0xcc0000` | `kdata+0x28c9e80` | `kdata+0xd9c064` | `kdata+0x314b510` |
| 0x1300/0x1320 | `kdata-0xcb0000` | `kdata+0x28c5e00` | `kdata+0xd99064` | `kdata+0x3133510` |
| 0x1340/0x1342 | `kdata-0xcb0000` | `kdata+0x28c9e80` | `kdata+0xd99064` | `kdata+0x3137510` |
| **0x1360** | **`kdata-0xcc0000`** | **`kdata+0x28c9e80`** | **`kdata+0xd9c064`** | **`kdata+0x314b510`** |

Dla 13.60 (`0x13600000` po masce) obowiazuje wiersz pogrubiony. Dalej, wspolnie dla
wszystkich wariantow:

    bus_data_devices = kdata + 0x20981e8
    vmspace_p_root   = 0x1d0
    vmspace_vm_pmap  = 0x2e8
    targetid         = security_flags + 0x09
    qa_flags         = security_flags + 0x24
    utoken_flags     = security_flags + 0x8c

`get_kit_type` (0xa820) czyta `sceKernelIsDevKit()` -> 2 (`DevKit detected`), inaczej
`sceKernelIsTestKit()` -> 1 (`TestKit detected`), inaczej 0 (`Retail console detected`).
Wynik idzie do `linux_info_t+0x30` i **nie ma osobnej galezi dla PS5 Pro**: `main`,
`set_offsets`, `hv_defeat_13xx` i `fetch_linux` nie zawieraja zadnego testu modelu.
Jedyna osia roznicowania jest firmware (`fw`) i typ kita Retail/TestKit/DevKit.
Wniosek: dla PS5 Pro na 13.60 idzie ta sama sciezka `0x1360` + `hv_defeat_13xx`, co dla
zwyklego PS5 na tym samym firmware.

## 4. Ogolne czytanie i pisanie pamieci jadra (odpowiedz na pytanie 4)

### 4.1 TAK, istnieje i jest to gotowy interfejs

W pliku sa trzy funkcje, ktore sa dokladnie tym, o co pytanie:

    kernel_copyin (0xeb00, 488 B)   -> int kernel_copyin(u64 kaddr, void *ubuf, u64 len)
    kernel_copyout(0xecf0, 494 B)   -> int kernel_copyout(u64 kaddr, void *ubuf, u64 len)

Kierunek nazewnictwa jest "z punktu widzenia jadra": `kernel_copyin` kopiuje **z bufora
uzytkownika pod adres jadra** (czyli ZAPIS pamieci jadra), a `kernel_copyout` kopiuje
**z adresu jadra do bufora uzytkownika** (czyli ODCZYT). Obie zwracaja `0` przy sukcesie
i `-1` przy bledzie (`__error` = `EFAULT` przy zlych argumentach, `EINVAL` gdy
`pipe_addr >> 0x30 == 0`).

`kernel_copyin` i `kernel_copyout` sa jedynymi **GLOBAL** symbolami tej warstwy w calym
pliku (sprawdzone `tools/checkbinds.py`). Nad nimi leza cienkie wrappery o sygnaturach
wygodnych w uzyciu, ale wszystkie sa **LOCAL** i wystepuja w wielu kopiach, po jednej na
jednostke translacji:

    kread   LOCAL  0x04b0, 0x5040, 0x9e50      kread (u64 kaddr, void *dst, u64 len)
    kread64 LOCAL  0x41c0, 0x51d0, 0x9f10      u64   kread64(u64 kaddr)
    kread32 LOCAL  0x5070, 0x9610
    kwrite  LOCAL  0x2df0, 0x37a0, 0x4650, 0x52f0, 0x8af0, 0xa2f0
    kwrite64 LOCAL 0x2720, 0x33f0, 0x4cd0, 0x5320, 0xaad0
    kwrite32 LOCAL 0x95e0
    kread_q/kwrite_q LOCAL 0x7350/0x7a40   (przez wskazniki funkcji w strukturze kh)

Praktyczna konsekwencja: **nie ma jednego adresu "kread"**. Do uzycia z zewnatrz nadaja sie
wlasnie `kernel_copyin`/`kernel_copyout` (GLOBAL, 0xeb00/0xecf0) oraz GLOBAL
`kernel_setlong/-int/-short/-char` (0xeee0, 0xef10, 0xef40, 0xef70) dla wartosci stalych.
Wybrana kopia `kread`/`kwrite` jest wygodna tylko wewnatrz wlasnego `main`, bo linkowana
jest lokalnie. Warstwe o innym ABI tworza `mdbg_memop` (0x13a40) i `kernel_proc_*`
(0x13ec0..0x14d50).

**Uwaga na kolejnosc argumentow.** Oryginalne `kwrite` (0xa2f0) ma argumenty
`(kaddr, src, len)`, ale wewnatrz robi `kernel_copyin(rdi=src, rsi=kaddr, rdx=len)`,
czyli **zamienia dwa pierwsze**:

    kwrite: mov rdi,[rbp-0x10]   # src
            mov rsi,[rbp-0x8]    # kaddr
            mov rdx,[rbp-0x18]   # len
            call kernel_copyin

To ta sama konwencja, co `kernel_copyin(kaddr, ubuf, len)` z zamienionymi dwoma pierwszymi
argumentami. Wewnatrz pliku jest to spojne (kazde wywolanie `kwrite` widoczne w kodzie
przekazuje najpierw adres jadra, potem bufor), ale przy robieniu z tego osobnego narzedzia
trzeba to jawnie ustalic i sprawdzic testem, bo pomylka daje zapis pod zly adres.

Sa takze wyspecjalizowane warianty, wygodne, gdy nie chce sie znac `ktext`/`dmap`:

    kernel_iommu_copyin (0x148c0, 707 B) + kernel_iommu_setlong/-int/-short/-char
        (0x14cc0..0x14d50) - dziala przez IOMMU, korzysta z `iommu_mmio_kaddr`,
        `iommu_cb_base`, `iommu_cb_index` (0x70f58..0x70f68)
    kernel_proc_copyin/copyout (0x14040/0x14110) + kernel_proc_set*/get* (0x141e0..0x14810)
        - przez przestrzen adresowa wskazanego procesu, z `kernel_proc_getpaddr` (0x13ec0)

### 4.2 Jak dziala mechanizm pod spodem

`kernel_copyin`/`kernel_copyout` to **nie** jest wlasny exploit. To uzgodniony z loaderem
hosta uklad oparty na potoku jadra i syscallu `cpuset_setaffinity`. Dowod, krok po kroku
z `kernel_copyout` (0xecf0):

    # 1. odczyt rodziny z deskryptorow podanych przez loadera
    rax = [rdi+0x10]          # wskaznik do dwoch int
    ecx = [rax]               # rw_pair[0]
    if (ecx < 0) return -1
    esi = ecx

    # 2. "zapowiedz" - cpuset_setaffinity z maska = {ptr: pipe_addr}
    movabs rax,0x4000000040000000
    [rbp-0x40] = rax
    rax = pipe_addr                       # 0x707e0
    if (pipe_addr >> 0x30 == 0) { errno = EINVAL; return -1 }
    [rbp-0x60] = pipe_addr
    edi = 0x69            # SYS_cpuset_setaffinity
    esi = rw_pair[0]
    edx = 0x29            # which
    ecx = 0x2e            # level/domain
    r8  = &[rbp-0x60]     # maska 12 B: {u64 ptr; u32 siz}
    r9d = 0x14
    call __crt_syscall

    # 3. to samo dla rw_pair[1], maska = {ptr: 0x4000000040000000}
    # 4. powtorka kroku 2, ale maska wskazuje pipe_addr + 0xc
    #    (if (pipe_addr + 0xc >= 0x1000000000000) -> EINVAL)
    # 5. powtorka kroku 3
    # 6. read(rw_pipe[0], ubuf, len)
    edi = 3 ; esi = rw_pipe[0] ; rdx = ubuf ; rcx = len ; call __crt_syscall
    r15 = rax >> 63        # 0 sukces, -1 blad

`kernel_copyin` robi to samo, tylko zamiast `read` (numer 3) wola `write` (numer 4) na
`rw_pipe[1]`.

`__crt_syscall` (0xbe30) przenosi rejestry do konwencji FreeBSD (numer w `rax`, argumenty
w `rdi/rsi/rdx/r10/r8/r9`) i skacze pod `ptr_syscall` (0x70740). `ptr_syscall` jest
rozwiazywany w `__crt_syscall_init` (0xbe50) przez `sceKernelDlsym` z nazwa `syscall`
i przesuwany o `+0xa` (pomija prolog).

Warunki, ktore musza byc spelnione, zeby to dzialalo:

1. Loader hosta musi dostarczyc w `payload_args` **gotowa pare deskryptorow** i **adres
   potoku jadra**. W tym pliku to:
   `[+0x08]` -> para int (`rw_pipe`), `[+0x10]` -> para int (`rw_pair`),
   `[+0x18]` -> `pipe_addr` (adres jadra). `__kernel_init` dodatkowo wymaga, zeby oba
   deskryptory i `pipe_addr` byly niezerowe i nieujemne, i zeby `[+0x20]` (baza danych
   jadra) byla niezerowa.
2. `pipe_addr` i `pipe_addr + 0xc` musza lezec w canonical kernel space
   (`>= 0x1000000000000`), inaczej `EINVAL`.
3. Wartosci `rw_pair[0]` i `rw_pair[1]` nie moga byc ujemne.
4. Musi istniec mozliwosc wywolania `cpuset_setaffinity` (zwykle proces z podniesionymi
   uprawnieniami, co zalatwia sam loader).

Czyli: **ten payload jest konsumentem cudzego primitywu, nie jego zrodlem.** Zeby uzyc go
jako ogolnego narzedzia, trzeba miec srodowisko, ktore te trzy wartosci wypelnia, na
przyklad ten sam host, ktory uruchamia `elfldr` z tym payloadem.

### 4.3 Czy da sie to wywolac osobno

Tak, i to bez zadnej dodatkowej pracy: obie funkcje sa zwyklymi symbolami globalnymi
w `.symtab` i `.dynsym`-owym `kread/kwrite` na poziomie pliku. Trzy realne drogi:

1. **Ten sam plik, wlasny `main`.** `kread`/`kwrite` dzialaja po `__crt_start` ->
   `__kernel_init`, bez `setup_env`, bez `fetch_linux`, bez `hv_defeat_13xx`. To znaczy,
   ze minimalny payload czytajacy i piszacy pamiec jadra to `crt.c` + `kernel.c` +
   `syscall.c`, kilka kB, i nie potrzebuje udawania loadera Linuksa.

2. **Podmiana `main` w tym pliku.** `main` jest zwyklym `FUNC GLOBAL` w `.symtab`
   (0x8b20, 677 B). Podmiana bajtow `main` na wlasna petle, ktora robi
   `kread64/kwrite64` i wypisuje wynik przez `notify`, daje natychmiast narzedzie do
   czytania i pisania jadra na 13.60 bez zmiany czegokolwiek innego. Rozmiar 677 B jest
   wygodny: wieksza funkcja zmiesci sie w tym samym miejscu, a mniejsza nie psuje
   segmentow, bo `main` lezy w srodku `.text`.

3. **Uzycie jako biblioteki w innym payloadzie.** `kernel_copyin`, `kernel_copyout`,
   `kernel_setlong/-int/-short/-char`, `install_page`, `install_page_syscore`, `main`,
   `fetch_linux`, `prepare_resume` i `hv_defeat_13xx` sa `GLOBAL` (patrz
   `tools/checkbinds.py`), wiec mozna linkowac `kernel.c` bezposrednio. Kopie
   `kread`/`kwrite` sa `LOCAL`, wiec z zewnatrz ich nie zobaczysz: uzywaj
   `kernel_copyin`/`kernel_copyout` i sam je opakuj.

Praktyczna granica: **moment wykonania**. `kread`/`kwrite` sa uzywalne tylko od
`__kernel_init` do konca zycia procesu. Nie da sie ich uzyc "po" payloadzie, bo zyja
w jego przestrzeni adresowej. Chcac miec narzedzie trwale, trzeba je uruchomic jako
osobny payload na tej samej sesji, w ktorej loader hosta dziala.

## 5. Jak payload wykrywa model konsoli

Trzy miejsca w kodzie:

1. `get_kit_type` (0xa820): `sceKernelIsDevKit()` -> 2 + `notify("DevKit detected")`;
   inaczej `sceKernelIsTestKit()` -> 1 + `notify("TestKit detected")`;
   inaczej 0 + `notify("Retail console detected")`. Wynik idzie do `linux_info_t+0x30`.
2. `hv_defeat_13xx` sprawdza `offsets_present()` i integralnosc jadra, ale **nie model**.
3. `__kernel_init` rozroznia tylko firmware (`fw`).

`sceKernelIsTestKit` (0xa7e0) i `sceKernelIsDevKit` (0xa800) to 23-bajtowe wrappery:
`mov eax, 0x25a`/`0x25b` + `syscall` + `ret`. To dwa zwykle syscalle, a nie odczyt
jakiegos rejestru czy numeru seryjnego.

**Nie ma osobnej sciezki dla PS5 Pro.** Zadna funkcja w tym pliku nie zawiera testu
"Pro", "Trinity", "Oberon" ani niczego rownowaznego. Jedyne osie roznicowania to
`fw` (0x300, 0x500, 0x650, 0x700, 0x720, 0x800, 0x900, 0x1000, 0x1100, 0x1200, 0x1300,
0x1360) oraz typ kita. Jedyna poszlaka "modelowa" jest posrednia:
`hv_defeat_13xx` wymaga `pin_to_core_reborn(0)` i `sceKernelGetCurrentCpu()`, a rozmiar
VRAM i takty sa w `vram.txt` uzytkownika, wiec ewentualne roznice Pro sa poza payloadem.
Wniosek dla nas: dla PS5 Pro na 13.60 obowiazuje ta sama sciezka `0x1360` i ta sama
tablica `off_1360`, ktora jest kompletna (rozdzial 2.7).

## 6. Co payload zostawia po sobie w jadrze

To jest najwazniejsza czesc dla nas, bo stan jest **trwaly do restartu konsoli** i jest
widoczny z zewnatrz.

### 6.1 Trwale (do rebootu, widoczne w jadrze)

| # | co | gdzie | czym jest |
|---|---|---|---|
| 1 | jaskinia kodu z lancuchem ROP | `ktext + env_offset[0x148]` (13.60: `+0x2d39000`, 0x4000 B) | `kh_install` zapisuje tam skopiowany lancuch (`kh_chain_*` -> `kh_write` -> `kwrite`) i zostawia |
| 2 | brama IDT wektor 13 | `ktext + env_offset[0x28] + 0xd0` = `0xffffffffc46143d0` | najpierw `kh_install`, potem ostatecznie `setidt(13, ktext + env_offset[0x60], 0xe, 0, 7)`, handler `0xffffffffc0ec9fb8`, DPL = 3 |
| 3 | brama IDT wektor 30 | `ktext + env_offset[0x28] + 0x1e0` = `0xffffffffc46144e0` | `setidt(30, ktext + env_offset[0x60], 0xe, 0, 7)`, handler `0xffffffffc0ec9fb8`, DPL = 3 |
| 4 | wpis w tablicy wskaznikow funkcji jadra | `ktext + env_offset[0x20]` | `kwrite64(ktext + env_offset[0x20], ktext + env_offset[0x20] - 8)` |
| 5 | shellcode dla AP | `ktext + env_offset[0x148] + 0x1000` | `kwrite(..., shellcode_ap_bin, 762)` |
| 6 | strony uzytkownika mapowane w pmap jadra | `0xffff800000000000`, `0xffff80000000c000`, `0xffff800000010000` i wyzej | PTE wpisane przez `install_page`, RWX, wchodza do pmap procesu 1 |
| 7 | bit RW i wykasowany NX w `.text` | caly `ktext..kdata`, po 0x1000 | `remove_xotext` -> `page_chain_set_rw`; jadro zostaje z tekstem na zapis |
| 8 | zmiana uprawnien biezacego procesu | `ucred` procesu | `__patch_init`: `caps` i `attrs`; `hv_defeat_13xx`: `authid = 0x4800000000000007` |
| 9 | logi | bufor klog | `klog_printf`/`klog_puts`, miedzy innymi caly raport PTE STATE |

Punkty 1..5 to **zmodyfikowany kod i dane jadra**, ktore zostaja po tym, jak payload konczy
prace i wchodzi w rest mode. Sa widoczne w zrzucie jadra jako pociete `movabs`/RET gadzety
w `.text` i jako niemozliwe do wyjasnienia wpisy w IDT. To jest jednoczesnie:

- **uzyteczne**, bo daje nam gotowy kanal wykonania kodu w jadrze na wektorach 13 i 30
  oraz gotowy lancuch ROP w jaskini, bez ponownego latania hipervisora;
- **przeszkadzajace**, bo IDT i wskaznik funkcji sa przestawione, a `.text` jest zapisywalny.
  Kazde narzedzie, ktore zaklada oryginalne bramy IDT albo sprawdza sumy kontrolne `.text`,
  zobaczy roznice. W szczegolnosci kolejny `hv_defeat_13xx` na tym samym jadrze
  przejdzie `offsets_present` i kontrole `NVS_EXPECT` (bo one czytaja nietkniete obszary),
  ale `kh_install` moze sie nie powiesc, jesli brama juz jest podmieniona.

### 6.1.1 Co dokladnie trafia do bram IDT, i dlaczego DPL = 3

Bramy IDT sa ustawiane **dwa razy** i trzeba je rozroznic.

**(A) `kh_install` buduje brame przez `gate_encode` (0x7a80) i zapisuje 16 B pod
`ktext + env_offset[0x28] + wektor*16`** (dla 13.60 baza `0xffffffffc4614300`).
`gate_encode` bierze **dwa** argumenty, ktore razem tworza pelny 64-bitowy adres handlera:
pierwszy (`rdi`) daje dolne 16 bitow, drugi (7. argument na stosie, `[rsp+0x8]`) daje
wszystkie pozostale 48 bitow:

    bity  0..15  = rdi[15:0]
    bity 16..63  = arg7[47:0]      (przesuniete << 16, bez sprawdzania zakresu)
    bity 32..34  = cl & 0xf   -> IST
    bity 40..43  = dl & 0xf   -> typ
    bity 45..46  = r8b & 0x3  -> DPL
    bit  47      = (r9d != 0) -> P
    qword +8     = arg8 (8. argument na stosie)

Kluczowa pulapka w tym kodzie: instrukcje

    7a80: mov al,r8b
    7a83: mov r8,QWORD PTR [rsp+0x10]
    7a88: mov r8,QWORD PTR [rsp+0x8]
    7a9f: mov BYTE PTR [rsp-0xd],al

sprawiaja, ze **parametr DPL jest martwy**. `r8b` jest najpierw kopiowany do `al`,
a `al` jest pozniej **nadpisywane** przez `movzx eax,BYTE PTR [rsp-0xd]`. Efektywny DPL
liczy sie wiec z tego, co `kh_install` polozyl na stosie jako 7. argument, czyli z gornej
polowy adresu handlera. Wartosci dla sciezki 13.60:

    handler (rdi) = kgadget(0) = ktext + env_offset[0x90] = 0xffffffffc1570ee0
    arg7          = ten sam adres, wiec selektor (kh+0x50 = [kh+0x48] >> 16) = 0xffff
    IST           = 14 (mov ecx,0xe, stala)
    typ           = kh+0x40, w tej sciezce 6 (z argumentu kh_init)
    P             = 1 (mov r9d,1)

Dla adresu `0xffffffffc1570ee0` bity 45..46 to `11`, czyli **DPL = 3**, a bit 47 (P) = 1.

**(B) `setidt` (0x4d00) to druga, niezalezna droga i ona wygrywa dla wektorow 13 i 30.**
Sygnatura: `void setidt(int wektor, u64 handler, u32 typ, u32 ist, u32 dpl)`, zapis 16 B
pod `ktext + env_offset[0x28] + wektor*16` przez `kwrite`. Deskryptor jest skladany tak:

    bity  0..15  = handler[15:0]
    bity 16..31  = 0x20              (stala: selektor segmentu kodu 0x20, nie kh+0x50)
    bity 32..34  = 0                 (IST wyzerowany na sztywno w tym wariancie)
    bity 40..43  = typ & 0x1f        (0xE)
    bity 45..46  = dpl & 0x3         (7 & 3 = 3)
    bit  47      = 1                 (P)
    qword +8     = handler[63:32]    (handler & 0xffffffffffff maskowane przez bzhi)

Wywolania z `hv_defeat_13xx`: `setidt(13, ktext + env_offset[0x60], 0xe, 0, 7)` oraz`setidt(30, ktext + env_offset[0x60], 0xe, 0, 7)`. Oba wskazuja ten sam handler,
`0xffffffffc0ec9fb8` dla 13.60. Deskryptor wektora 13:

    handler  = 0xffffffffc0ec9fb8
    qword_lo = 0x9fb8 | (0x20 << 16) | (0xe << 40) | (0x3 << 45) | (1 << 47)
             = 0x0000ee0000209fb8
    qword_hi = 0x00000000ffffffff

Wniosek praktyczny: obie drogi daja **DPL = 3**, wiec **bramy 13 i 30 sa wywolywalne
z poziomu uzytkownika** przez `int 0x0d` i `int 0x1e`. To realny, trwaly kanal wejscia
w kod jadra. W wariancie (A) DPL nie jest ustawiany swiadomie (wynika z bitow 45..46
adresu handlera), a „selektor" 0xffff nie jest prawdziwym selektorem segmentu kodu
(to tez gorne bity adresu), wiec ten wariant jest wewnetrznie niespojny; w wariancie (B)
DPL jest podany jako argument `7`, ale maskowany do 2 bitow, wiec efektywnie 3.

Kolejnosc ma znaczenie: `kh_install` (wariant A) dziala pierwszy, a dwa `setidt`
(wariant B) nadpisuja te same dwa wpisy IDT pozniej, bo oba licza adres z
`ktext + env_offset[0x28] + wektor*16`. W zrzucie wlasciwe sa wiec wpisy z wariantu B.

Roznice w stosunku do pierwszej wersji tej notatki: najpierw policzylem DPL z `r8b`
w `gate_encode` i wyszlo 0, a druga iteracje `setidt` blednie przypisalem do
`dmap + 0x3ffff000`. Oba bledy wynikaly z czytania fragmentow bez przesledzenia calosci;
poprawne wartosci to DPL = 3 i ten sam handler `ktext + env_offset[0x60]` w obu wektorach.

Dwie hipotezy sprawdzone i odrzucone przy okazji: w calym `.text` payloadu **nie ma ani
jednego `iretq`** (bajty `48 cf` wystepuja tylko jako fragment `shr rax,0x2f` w `derive_H`),
a `emit_resume_tail` (0x7410) nie zawiera `iretq`, `swapgs` ani `sysret`. Powrot z lancucha
idzie wiec przez gadzety jadra wybierane przez `kgadget`, a nie przez gotowy kod w payloadzie.

### 6.2 Przemijajace (tylko w czasie zycia procesu)

- `__kernel_init` rozlozyl `pipe_addr`, `ktext`, `kdata`, `cr3`, `dmap` i tablice offsetow
  w `.bss` procesu; to ginie z procesem.
- `pin_to_core_reborn(0)` przypina proces do rdzenia 0; ginie z procesem.
- `__patch_init` zmienia `caps`/`attrs` **procesu** (przez `kernel_get_proc` + PID biezacego
  procesu), a nie globalnie, wiec po zakonczeniu procesu uprawnienia znikaja.
- Strony uzytkownika zmapowane pod stale VA jadra (punkty z tabeli 6.1 poz. 6) zostana
  wskazane na zwolniona pamiec po wyjsciu procesu. To jest realne ryzyko dla jadra, jesli
  proces zginie przed restartem, i warto o tym wiedziec, zanim ktokolwiek wytnie payload
  w polowie dzialania.

### 6.3 Czego payload NIE zmienia

- Nie ma `kexec`, nie ma modyfikacji tablicy ACPI ani niczego, co przetrwa reboot.
- Nie zapisuje nic na dysku konsoli. Wszystkie pliki sa czytane z `/mnt/usb*`, a jedyne
  zapisy w tym pliku (`write_all`, `mkdir_if_needed`, `create_firmware_dirs`) dotycza
  zrzutu firmware WiFi (`/lib/nxp/pcieuartiw620_combo_v1.bin`) i sa czescia osobnej,
  niezwiazanej z Linuksem funkcji `dump_device_firmwares`.
- Nie modyfikuje `bzImage`, `initrd.img` ani `cmdline.txt`; czyta je i mapuje bez zmian.
- Nie ustawia zadnych opcji jadra Linuksa poza tym, co jest w `cmdline.txt` (albo
  fallbackiem). `kernel_uart_override` i `kernel_cfi_check` obsluguje sie wylacznie
  tekstem `cmdline.txt`.

## 7. Odpowiedzi wprost na pytania z zadania

**1. Sciezka uruchomienia.** `main` -> `setup_env` (wersja z jadra przez syscall `0x289`,
`fw = 0x1360`, `off_1360` -> `env_offset`) -> `fetch_linux` (8 katalogow USB, `bzImage`
i `initrd.img` czytane w calosci przez `mmap` + `read`, bez zadnej weryfikacji;
`vram.txt` -> rozmiar VRAM, `cmdline.txt` -> linia polecen) -> `prepare_resume`
(shellcode jadra pod `0xffff800000000000`, argumenty w `sck_args` ze znacznikiem
`0x11aa11aa11aa11aa`, `remove_xotext`, uniewaznienie pmap) -> `hv_defeat_13xx`
(kontrola 7 qwordow jadra, `derive_H` z tablicy EFI, `authid`, przypiecie do rdzenia 0,
`kh_install` + `kh_trigger`, `setidt` 13 i 30, podmiana wskaznika w `ktext + env_offset[0x20]`,
dla 13.60 `0xffffffffc4629490`)-> komunikat o rest mode i `enter_rest_mode()`. Sterowanie do Linuksa przechodzi przy
wybudzeniu z rest mode, przez zahaczony punkt jadra i lancuch ROP z jaskini kodu.
`kernel_uart_override` i `kernel_cfi_check` nie sa ustawiane przez payload: wystepuja
tylko jako etykiety diagnostyczne, a realnie moga przyjsc wylacznie z `cmdline.txt`.

**2. Alokacja i mapowanie.** `sceKernelAllocateMainDirectMemory` i
`sceKernelMapNamedDirectMemory` sa w tym pliku **martwym kodem** (tylko `gpu_alloc_dmem`,
bez wolajacych). Payload nie uzywa mapy bezposredniej jadra do danych: `mmap`-uje obraz
w uzytkowniku, liczy `vtophys_user`, i **wstawia wlasne PTE do pmap procesu 1** przez
`install_page` (budujac brakujace poziomy tablic stron i alokujac je przez `alloc_page`).
Mapa bezposrednia (`dmap = kdata - cr3`) sluzy tylko jako okno na pamiec fizyczna przy
tablicach stron i stronach alokowanych z jadra. Rozmiary: `bzImage` i `initrd.img` po
`round_up(size, 0x4000)`, shellcode 0x7000, `linux_info_t` 0xc38 w stronie 0x4000.
Adresy: `0xffff80000000c000` (boot_params), `0xffff800000010000` (jadro), dalej initrd,
`0xffff800000000000` (shellcode).

**3. Model konsoli.** `get_kit_type` rozroznia tylko Retail / TestKit / DevKit przez
`sceKernelIsDevKit` i `sceKernelIsTestKit` (dwa syscalle, 0x25a i 0x25b) i wypisuje
`Retail console detected` / `TestKit detected` / `DevKit detected`. Nie ma zadnej galezi
dla PS5 Pro; jedyna osia jest `fw`. Dla PS5 Pro na 13.60 idzie ta sama sciezka `0x1360`.

**4. Ogolny mechanizm czytania i pisania.** **Tak, jest.** `kernel_copyin(kaddr, ubuf, len)`
(0xeb00) i `kernel_copyout(kaddr, ubuf, len)` (0xecf0), z wrapperami `kread`/`kread64`/
`kread32`/`kwrite`/`kwrite64`/`kwrite32` i `kernel_set*/get*`. Zwracaja 0 / -1. Dzialaja od
`__kernel_init` do konca procesu, bez `setup_env`, bez `fetch_linux` i bez
`hv_defeat_13xx`. Warunek: loader hosta musi dostarczyc w `payload_args` pare deskryptorow
potoku, pare deskryptorow socketu i adres potoku jadra w canonical kernel space
(patrz 4.2); mechanizm to `cpuset_setaffinity` przestawiajacy wskaznik bufora potoku,
a potem zwykle `read`/`write`. Uwaga: `kwrite` zamienia dwa pierwsze argumenty wobec
`kernel_copyin`. Zrobienie z tego osobnego narzedzia to podmiana `main` (677 B, symbol
`FUNC GLOBAL` w `.symtab`) albo wlasny payload z `crt.c` + `kernel.c` + `syscall.c`.

**5. Trwaly stan w jadrze.** Tak, i jest konkretny. Dla 13.60 (`kdata = 0xffffffffc1920000`,
`ktext = kdata - 0xcc0000`) daje to nastepujace adresy:

    jaskinia kodu z lancuchem ROP   ktext + 0x2d39000  = 0xffffffffc3999000
    shellcode AP                    ktext + 0x2d3a000  = 0xffffffffc399a000
    brama IDT 13 i 30               ktext + 0x269fb8   = 0xffffffffc0ec9fb8
    wpis w tablicy wskaznikow       ktext + 0x39c9490  = 0xffffffffc4629490
                                                         (nowa wartosc = 0xffffffffc4629488)

Do tego `.text` jadra z bitem RW i wykasowanym NX na calym zakresie `ktext..kdata`
(w praktyce 0xffffffffc0c60000 do 0xffffffffc1920000) oraz strony uzytkownika wpmap
procesu 1 pod stalymi VA jadra. Wszystko to zyje do restartu konsoli i jest widoczne
w zrzucie. Uprawnienia (`authid`, `caps`, `attrs`) sa natomiast procesowe, nie globalne.
Reboot czysci wszystko; payload nie zapisuje niczego trwalego na dysku konsoli.

## 8. Ograniczenia tej analizy

- Nie uruchamialem payloadu na konsoli. Wszystkie wnioski pochodza z deasemblacji i danych
  pliku. Werdykt o "dziala" opiera sie na potwierdzeniu uzytkownika, nie na moim pomiarze.
- Semantyka pol `linux_info_t` poza `+0x00..+0x30` i `+0x438` jest odczytana z kodu, ktory
  je zapisuje i czyta, a nie z naglowka zrodlowego. Naglowka nie mialem.
- Semantyka poszczegolnych pol `env_offset` jest znana tylko przez miejsca uzycia
  (nazwy etykiet diagnostycznych, `dump_text_perm`, `kgadget`, `build_sx_rop`).
  Nie mapowalem ich na nazwy funkcji jadra, bo nie mialem pod reka zrodel jadra 13.60.
- **Dokladny przebieg `kh_trigger` nie jest domkniety.** Trzy rzeczy sa pewne z kodu:
  `clear_execute_disable` kasuje bit 63 (Execute-Disable) w PTE strony nosnej, wiec mapa
  EPT hipervisora po tym zabiegu pozwala na wykonanie kodu z tej strony; `kh_install`
  zapisuje dwie bramy IDT (wektory 13 i 30) z DPL = 3 i P = 1 (rozklad w rozdziale 6.1.1),
  a wiec bramy sa wywolywalne z poziomu uzytkownika przez `int 0x0d` i `int 0x1e`;
  `kh_trigger` (0x7b50) zapisuje w jadrze pod `kh+0xc0` adres lancucha ROP i pod `kh+0xc8`
  wskaznik stosu uzytkownika, a nastepnie ustawia IF=1. Czego nie ustalilem bez
  uruchomienia: ktora z dwoch bram faktycznie odpala w tej sciezce i jak wyglada powrot.
- Wplyw podmiany bram IDT (wektor 30 to `#MC`, machine check; wektor 13 to `#GP`)
  na dalsze dzialanie jadra po powrocie z rest mode nie jest przeze mnie zmierzony.
  `kh_disarm` (0x7bf0) istnieje i buduje lancuch przywracajacy oryginalne bramy,
  ale nie znalazlem w tym pliku zadnego wolajacego `kh_disarm`, wiec w tej sciezce
  bramy zostaja podmienione.
- Obfuskowany fragment `shellcode_kernel_bin` (od offsetu ~0x3900, z markerami
  `SCK>5h-ps5-ops-begin` i `SCK>5h-ps5-ops-done` oraz napisami `IOMMU bs`, `TRM OK`,
  `VMCB OK`, `Back from HV`) analizowalem tylko powierzchownie. To warstwa
  antyforensyczna, nie wplywa na odpowiedzi na pytania z zadania.
- Wsad `shellcode_ap_bin` (762 B, dla dodatkowych rdzeni) i `shellcode_0607_bin` (495 B,
  dla firmware 6.00/6.02/6.50) sa w pliku, ale ich rola w tej konkretnej sciezce 13.60
  ogranicza sie do zapisu pod `env_offset[0x148] + 0x1000`; nie sledzilem ich wykonania.

