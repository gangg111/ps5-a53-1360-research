# 1360linux.elf: mapa strukturalna pliku

Notatka opisuje STRUKTURE i ZAWARTOSC pliku, nie semantyke kodu. Kazde twierdzenie ma offset
i dowod (bajty albo napis). Plik nie byl modyfikowany, analiza prowadzona na kopii.

## 0. Tozsamosc pliku

| Pole | Wartosc |
|---|---|
| Zrodlo (read-only) | `<dsh>\attachments\v1\files\e5\e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226\1360linux.elf` |
| Kopia w repo | `artifacts\1360linux.elf` |
| Rozmiar | 237448 B (0x39F88) |
| SHA256 | `e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226` |
| Zgodnosc | SHA256 identyczny z nazwa katalogu attachmentu, kopia bit w bit |
| Katalog roboczy analizy | `%TEMP%\linux-elf` (na tej maszynie nie istnieje `/root/linux-elf/`) |

Kompresor: `.comment` (offset 0x326C0, 66 B) zawiera
`\0Ubuntu clang version 18.1.3 (1ubuntu1)\0Linker: Ubuntu LLD 18.1.3\0`.

## 1. Naglowek ELF, segmenty, sekcje

### 1.1 Naglowek (offset 0x0, 64 B)

Dowod, pierwsze 64 B:
`7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 | 03 00 3e 00 01 00 00 00 70 ba 00 00 ...`

| Pole | Offset | Wartosc | Znaczenie |
|---|---|---|---|
| EI_CLASS | 0x4 | 2 | 64-bit |
| EI_DATA | 0x5 | 1 | little-endian |
| EI_OSABI | 0x7 | 0 | System V (payload PS5, nie FreeBSD ELF) |
| e_type | 0x10 | 0x3 | ET_DYN |
| e_machine | 0x12 | 0x3E | x86-64 |
| e_version | 0x14 | 1 | |
| e_entry | 0x18 | 0xBA70 | `_start` |
| e_phoff | 0x20 | 0x40 | |
| e_shoff | 0x28 | 0x399C8 | |
| e_flags | 0x30 | 0x0 | |
| e_ehsize | 0x34 | 64 | |
| e_phentsize / e_phnum | 0x36 / 0x38 | 56 / 4 | 4 segmenty |
| e_shentsize / e_shnum | 0x3A / 0x3C | 64 / 23 | 23 sekcje |
| e_shstrndx | 0x3E | 21 | `.shstrtab` |

Uwaga: `e_type = ET_DYN`, ale `PT_LOAD[0].p_vaddr = 0`, wiec obraz jest pozycyjnie niezalezny
i ladowany przez wlasny loader payloadu, ktory stosuje `.rela.dyn` z sekcji 8.

### 1.2 Segmenty programowe (4, tablica pod 0x40)

| # | Typ | Offset | Vaddr | Paddr | FileSz | MemSz | Flag | Align | Koniec w pliku |
|---|---|---|---|---|---|---|---|---|---|
| 0 | PT_LOAD | 0x4000 | 0x0 | 0x0 | 85424 | 85424 | RWX | 0x4000 | 0x18DB0 |
| 1 | PT_LOAD | 0x1C000 | 0x18000 | 0x18000 | 33168 | 33168 | RW- | 0x4000 | 0x24190 |
| 2 | PT_LOAD | 0x28000 | 0x24000 | 0x24000 | 42688 | 315248 | RW- | 0x4000 | 0x326C0 |
| 3 | PT_DYNAMIC | 0x24000 | 0x20000 | 0x20000 | 400 | 400 | RW- | 0x4000 | 0x24190 |

Dowod na RWX segmentu 0, pelne 56 B PHDR[0] pod offsetem 0x40:
`01 00 00 00 07 00 00 00 | 00 40 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00 | b0 4d 01 00 00 00 00 00 | b0 4d 01 00 00 00 00 00 | 00 40 00 00 00 00 00 00`
czyli p_type=1 (PT_LOAD), p_flags=7 (R|W|X), p_offset=0x4000, p_vaddr=p_paddr=0,
p_filesz=p_memsz=0x14DB0=85424, p_align=0x4000.
Dla porownania PHDR[1] pod 0x78: `01 00 00 00 06 00 00 00 | 00 c0 01 00 ... | 90 81 00 00 ...`
czyli p_flags=6 (R|W, bez X), p_offset=0x1C000, p_filesz=p_memsz=0x8190=33168.

Trzy obserwacje strukturalne:

* Segment 0 jest RWX. Caly kod (`.text`, `.plt`) i wejscie `_start` siedza w segmencie z prawem
  zapisu. To nie jest przypadkowa flaga: `.text` jest zapisywalny, bo payload sam lata siebie
  (m.in. funkcja `remove_xotext`, napis `Error: could not remove xo from text` pod 0x2254D).
* `PT_LOAD[2]` ma FileSz 42688, a MemSz 315248. Roznica 272560 B to `.bss` (patrz 1.3).
* Brak `PT_INTERP`, `PT_NOTE`, `PT_GNU_STACK`, `PT_GNU_RELRO`, `PT_TLS`. Nie ma tez zadnego
  segmentu SCE (`PT_SCE_*`). To zwykly ELF ladowany przez payload loader, nie SPRX.

### 1.3 Sekcje (23, tablica pod 0x399C8)

| # | Nazwa | Typ | Flag | Addr | Offset | Size | Align | EntSize |
|---|---|---|---|---|---|---|---|---|
| 0 | (pusta) | NULL | | 0 | 0 | 0 | | |
| 1 | .text | PROGBITS | AX | 0x0 | 0x4000 | 85366 | 0x4000 | |
| 2 | .plt | PROGBITS | AX | 0x14D80 | 0x18D80 | 48 | 0x10 | |
| 3 | .eh_frame_hdr | PROGBITS | A | 0x18000 | 0x1C000 | 3204 | 0x4000 | |
| 4 | .eh_frame | PROGBITS | A | 0x18C88 | 0x1CC88 | 9636 | 0x8 | |
| 5 | .dynsym | DYNSYM | A | 0x1B230 | 0x1F230 | 1104 | 0x8 | 0x18 |
| 6 | .gnu.hash | 0x6FFFFFF6 | A | 0x1B680 | 0x1F680 | 48 | 0x8 | |
| 7 | .dynstr | STRTAB | A | 0x1B6B0 | 0x1F6B0 | 572 | 0x1 | |
| 8 | .rela.dyn | RELA | A | 0x1B8F0 | 0x1F8F0 | 4488 | 0x8 | 0x18 |
| 9 | .rela.plt | RELA | AI | 0x1CA78 | 0x20A78 | 48 | 0x8 | 0x18 |
| 10 | .data.rel.ro | PROGBITS | WA | 0x1CAB0 | 0x20AB0 | 2192 | 0x10 | |
| 11 | .got | PROGBITS | WA | 0x1D340 | 0x21340 | 328 | 0x8 | |
| 12 | .got.plt | PROGBITS | WA | 0x1D488 | 0x21488 | 40 | 0x8 | |
| 13 | .rodata | PROGBITS | WA | 0x1D4B0 | 0x214B0 | 8368 | 0x10 | |
| 14 | .init_array | PROGBITS | A | 0x1F560 | 0x23560 | 0 | 0x1 | |
| 15 | .fini_array | PROGBITS | A | 0x1F560 | 0x23560 | 0 | 0x1 | |
| 16 | .dynamic | DYNAMIC | WA | 0x20000 | 0x24000 | 400 | 0x4000 | 0x10 |
| 17 | .data | PROGBITS | WA | 0x24000 | 0x28000 | 42688 | 0x4000 | |
| 18 | .bss | NOBITS | WA | 0x2E6C0 | 0x326C0 | 272560 | 0x10 | |
| 19 | .comment | PROGBITS | MS | 0 | 0x326C0 | 66 | 0x1 | 1 |
| 20 | .symtab | SYMTAB | | 0 | 0x32708 | 18744 | 0x8 | 0x18 |
| 21 | .shstrtab | STRTAB | | 0 | 0x37040 | 196 | 0x1 | |
| 22 | .strtab | STRTAB | | 0 | 0x37104 | 10434 | 0x1 | |

Warto zauwazyc: `.rodata` ma flagi WA (0x32), czyli alloc + write, bez execute. `.init_array`
i `.fini_array` maja rozmiar 0, wiec nie ma konstruktorow C; start to `_start` (0xBA70).

### 1.4 PT_DYNAMIC (offset 0x24000, 25 wpisow po 16 B)

| # | Tag | Wartosc |
|---|---|---|
| 0 | DT_NEEDED | 0x202 -> `libkernel_web.sprx` |
| 1 | DT_NEEDED | 0x215 -> `libSceLibcInternal.sprx` |
| 2 | DT_NEEDED | 0x22D -> `libSceNet.sprx` |
| 3 | DT_FLAGS_1 | 0x8000000 (PIE) |
| 4 | DT_DEBUG | 0x0 |
| 5 | DT_RELA | 0x1B8F0 |
| 6 | DT_RELASZ | 0x1188 (4488) |
| 7 | DT_RELAENT | 0x18 |
| 8 | DT_RELACOUNT | 0x95 (149) |
| 9 | DT_JMPREL | 0x1CA78 |
| 10 | DT_PLTRELSZ | 0x30 |
| 11 | DT_PLTGOT | 0x1D488 |
| 12 | DT_PLTREL | 7 (RELA) |
| 13 | DT_SYMTAB | 0x1B230 |
| 14 | DT_SYMENT | 0x18 |
| 15 | DT_STRTAB | 0x1B6B0 |
| 16 | DT_STRSZ | 0x23C |
| 17 | DT_GNU_HASH | 0x1B680 |
| 18 | 0x20 (DT_PREINIT_ARRAY) | 0x0 |
| 19 | 0x21 (DT_PREINIT_ARRAYSZ) | 0x0 |
| 20 | 0x19 (DT_INIT_ARRAY) | 0x1F560 |
| 21 | 0x1B (DT_INIT_ARRAYSZ) | 0x0 |
| 22 | 0x1A (DT_FINI_ARRAY) | 0x1F560 |
| 23 | 0x1C (DT_FINI_ARRAYSZ) | 0x0 |
| 24 | DT_NULL | 0x0 |

Dowod na 3 zaleznosci: `.dynstr` (offset 0x1F6B0) konczy sie napisami
`libkernel_web.sprx` (0x1F8B2), `libSceLibcInternal.sprx` (0x1F8C5), `libSceNet.sprx` (0x1F8DD).

Importy (`.dynsym`, 46 wpisow, dowod: kolejne nazwy w .dynstr pod 0x1F6B1):
`mprotect, mmap, dup, open, close, strrchr, snprintf, write, mkdir, __error, stat, memcpy,
memset, sceKernelAllocateMainDirectMemory, printf, sceKernelMapNamedDirectMemory, getpid,
usleep, ioctl, munmap, sceKernelGetCurrentCpu, signal, setjmp, longjmp, __stdoutp, fflush,
strcpy, malloc, strlen, strncmp, read, strtoull, sleep, pipe, fcntl, vsnprintf,
cpuset_setaffinity, bzero, sceKernelSendNotificationRequest, sceKernelOpenEventFlag,
sceKernelNotifySystemSuspendStart, sceKernelSetEventFlag, sceKernelCloseEventFlag`.
Cztery symbole maja definicje lokalne (shndx=1): `mprotect` (0x1670), `mmap` (0x16F0),
`dup` (0xAC70), `sceKernelIsTestKit` (0xA7E0), `sceKernelIsDevKit` (0xA800).

Relokacje: `.rela.dyn` ma 187 wpisow, typy 8 (R_X86_64_RELATIVE, 149 szt.) i 6
(R_X86_64_GLOB_DAT, 38 szt.). Zaden addend nie ma niezerowej gornej polowy (sprawdzone
wszystkie 187), czyli zadna relokacja nie wstawia do obrazu stalej spoza jego 32-bitowego
zakresu. `.rela.plt` ma 2 wpisy (r_offset 0x1D4A0 i 0x1D4A8, typ 7 R_X86_64_JUMP_SLOT,
sym 9 `memcpy` i sym 10 `memset`).

`.got` (328 B) jest w calosci wyzerowany w pliku, `.got.plt` (40 B) zawiera
`0x20000, 0, 0, 0x14D96, 0x14DA6` (dwie ostatnie to adresy resolvera w `.plt`).

### 1.5 `_start` i symbole

`.symtab` ma 781 wpisow (18744 B). Ostatni to `_start` = 0xBA70 (bind GLOBAL, typ FUNC),
zgodny z `e_entry`. Nie ma symboli `_init`/`_fini`, sa natomiast `__crt_start` (0xBAD0),
`__crt_syscall_init` (0xBE50), `__crt_syscall` (0xBE30).

## 2. Mapa pliku od bajtu do bajtu

| Zakres offsetow | Rozmiar | Co tam jest |
|---|---|---|
| 0x00000..0x00040 | 64 | naglowek ELF |
| 0x00040..0x0011A | 218 | 4 program headery (4 x 56 B) |
| 0x0011A..0x04000 | 16102 | zera (padding). Dowod: skan niezerowych bajtow w [0x0,0x4000) daje tylko 70 trafien, wszystkie w 0x0..0x4A i 0x60..0x11A |
| 0x04000..0x18D80 | 85376 | `.text` |
| 0x18D80..0x18DB0 | 48 | `.plt` |
| 0x18DB0..0x1C000 | 12880 | zera (padding, 0 niezerowych bajtow) |
| 0x1C000..0x1F230 | 12848 | `.eh_frame_hdr` + `.eh_frame` |
| 0x1F230..0x1F680 | 1104 | `.dynsym` |
| 0x1F680..0x1F6B0 | 48 | `.gnu.hash` (nbuckets=1, symoffset=41, nbloom=1, shift=26) |
| 0x1F6B0..0x1F8EC | 572 | `.dynstr` |
| 0x1F8F0..0x20A78 | 4488 | `.rela.dyn` |
| 0x20A78..0x20AA8 | 48 | `.rela.plt` |
| 0x20AB0..0x21340 | 2192 | `.data.rel.ro` = `sysmodtab` (BLOB 5) |
| 0x21340..0x214B0 | 368 | `.got` + `.got.plt` |
| 0x214B0..0x232A0 | 7680 | `.rodata`: 290 napisow (7537 B) + padding do granicy |
| 0x232A0..0x232D8 | 56 | `NVS_EXPECT` (BLOB 6) |
| 0x232D8..0x232DC | 4 | zera |
| 0x232DC..0x23334 | 88 | tabela 22 offsetow int32 (BLOB 7) |
| 0x23334..0x23340 | 12 | zera |
| 0x23340..0x23360 | 32 | wektor KAT SHA1 i oczekiwany skrot (BLOB 8) |
| 0x23360..0x23370 | 16 | `ff ff` i 14 zer |
| 0x23370..0x233B8 | 72 | alfabet base64 i 8 zer (BLOB 9) |
| 0x233B8..0x23430 | 120 | 15 x `KERNEL_OFFSET_*` (BLOB 10) |
| 0x23430..0x23544 | 276 | tabela skokow 69 x int32 (BLOB 11) |
| 0x23544..0x23550 | 12 | zera |
| 0x23550..0x23560 | 16 | `mdbg_memop.privcaps` (BLOB 12), koniec `.rodata` |
| 0x23560..0x24000 | 2720 | zera (padding) |
| 0x24000..0x24190 | 400 | `.dynamic` |
| 0x24190..0x28000 | 15984 | zera (padding) |
| 0x28000..0x326C0 | 42688 | `.data` = 2 shellcode + 30 tabel offsetow + duzy shellcode (BLOBY 1,2,3,4,12,13) |
| 0x326C0..0x32708 | 72 | `.comment` + padding |
| 0x32708..0x37040 | 18744 | `.symtab` (781 wpisow) |
| 0x37040..0x37104 | 196 | `.shstrtab` |
| 0x37104..0x399CA | 10434 | `.strtab` (nazwy symboli i plikow zrodlowych) |
| 0x399C8..0x39F88 | 1472 | tablica naglowkow sekcji (23 x 64) |

Kontrola sumy: 0x39F88 = 237448 = rozmiar pliku.

## 3. Wbudowane bloby

Ponizsze bloby sa danymi, nie kodem C. Kolejnosc wedlug offsetu.

### BLOB 1: `shellcode_0607_bin`, 495 B, file 0x28000..0x281EF (vaddr 0x24000)

Dowod na to, ze to shellcode x86-64, pierwsze 16 B:
`c7 44 24 0c aa 11 aa 11 8b 44 24 0c ba 40 d1 82`
czyli `mov dword [rsp+0xc], 0x11aa11aa` (wzorzec-znacznik do wykrycia przepisania), potem
`mov eax,[rsp+0xc]`, `mov edx, 0x6282d140`.

Uzasadnienie ze to nie kod C: nie ma prologu funkcji, nie ma sekcji `.text` (lezy w `.data`),
zawiera `mov eax, imm32` z 32-bitowymi adresami oraz konczy sie sekwencja `0f 30` (`wrmsr`)
i `c3` (`ret`). Ostatnie 15 B: `48 89 f2 48 89 f0 89 f9 48 c1 ea 20 0f 30 c3`.
Rozmiar potwierdza symbol `shellcode_0607_bin_len` (file 0x281F0): odczyt 4 B little-endian
daje `ef 01 00 00` = 495, czyli dokladnie rozmiar bloba.
Entropia: 99 unikalnych bajtow na 495. Symbol pochodzi z pliku `hv_defeat_0607.c`.

### BLOB 2: `shellcode_ap_bin`, 762 B, file 0x28200..0x284FA (vaddr 0x24200)

Pierwsze 16 B: `48 8d 25 f9 0e 00 00 53 56 57 48 83 ec 08 48 8d`, czyli
`lea rsp, [rip+0xef9]`, `push rbx`, `push rsi`, `push rdi`, `sub rsp, 8`.
Blob konczy sie skokiem posrednim `ff e1` (`jmp rcx`) i zawiera typowe dla AP (application
processor) petle po tablicach PTE: naprzemienne `4d 8d 82 00 00 08 00`,
`4d 8d 82 00 90 02 02`, `48 c7 00 00 11 00 00` (wpisy stanu: 0x1100, 0x1200, 0x1400).
150 unikalnych bajtow. Symbol `shellcode_ap_bin_len` w file 0x284FC ma wartosc 762,
zgodna z rozmiarem bloba.
Litery `ap` w nazwie = kod uruchamiany na dodatkowych rdzeniach.

### BLOB 3: 30 tabel offsetow jadra `off_XXXX`, 14400 B, file 0x28550..0x2BD90

30 struktur po dokladnie 480 B (60 x uint64). Kolejne symbole z `.symtab` (vaddr, w `.data`):

| Symbol | vaddr | file | Symbol | vaddr | file |
|---|---|---|---|---|---|
| off_0300 | 0x24550 | 0x28550 | off_0761 | 0x26CB0 | 0x2ACB0 |
| off_0310 | 0x24730 | 0x28730 | off_0761_khook | 0x26E90 | 0x2AE90 |
| off_0320 | 0x24910 | 0x28910 | off_1200 | 0x27070 | 0x2B070 |
| off_0321 | 0x24AF0 | 0x28AF0 | off_0800 | 0x27250 | 0x2B250 |
| off_0400 | 0x24CD0 | 0x28CD0 | off_0900 | 0x27430 | 0x2B430 |
| off_0402 | 0x24EB0 | 0x28EB0 | off_1000 | 0x27610 | 0x2B610 |
| off_0403 | 0x25090 | 0x29090 | off_1100 | 0x277F0 | 0x2B7F0 |
| off_0450 | 0x25270 | 0x29270 | off_1300 | 0x279D0 | 0x2B9D0 |
| off_0451 | 0x25450 | 0x29450 | off_1360 | 0x27BB0 | 0x2BBB0 |
| off_0500 | 0x25630 | 0x29630 | off_0600 | 0x25DB0 | 0x29DB0 |
| off_0502 | 0x25810 | 0x29810 | off_0602 | 0x25F90 | 0x29F90 |
| off_0510 | 0x259F0 | 0x299F0 | off_0650 | 0x26170 | 0x2A170 |
| off_0550 | 0x25BD0 | 0x29BD0 | off_0700 | 0x26350 | 0x2A350 |
| off_0701 | 0x26530 | 0x2A530 | off_0720 | 0x26710 | 0x2A710 |
| off_0740 | 0x268F0 | 0x2A8F0 | off_0760 | 0x26AD0 | 0x2AAD0 |

Numery w nazwach to wersje firmware (0300 = 3.00, 1360 = 13.60, 0761_khook = 7.61 wariant
z khook). 30 tabel odpowiada 30 wersjom obslugiwanym przez dolaczony kod hv_defeat.

### BLOB 4: `shellcode_kernel_bin`, slot 26896 B, file 0x2BD90..0x326A0 (vaddr 0x27D90)

Najwiekszy blob. Prolog (pierwsze 24 B):
`41 56 41 55 41 54 55 53 48 bb aa 11 aa 11 aa 11 aa 11 48 8d 35 b5 2d 00 00`
czyli `push r14; push r13; push r12; push rbp; push rbx; mov rbx, 0x11aa11aaaa11aa11;
lea rsi, [rip+0x2db5]`. Ten sam wzorzec `0x11aa11aa` co w BLOB 1 (znacznik przepisania).

Rozklad zawartosci wewnatrz slotu:

| Podzakres (file) | Rozmiar | Zawartosc |
|---|---|---|
| 0x2BD90..0x2DD90 | 8192 | kod x86-64 (entropia 4.3 do 5.8 na 1 kB, 76 do 89 procent niezerowych) |
| 0x2DD90..0x2ED90 | 4096 | zera + napisy (`[*] Booting Linux in bare metal...` pod 0x2DDA0, 34 napisy `SCK>`) |
| 0x2ED90..0x2EE10 | 128 | kod + napisy (`Linux prepared OK`, `Good Bye VM :)`, `We shouldn't be here :(`) |
| 0x2EE10..0x325D0 | 14272 | zera (rezerwa slotu) |
| 0x325D8..0x325E5 | 13 | ogon paddingu asemblera: `66 2e 0f 1f 84 00 00 00 00 00` (`nopw`), `0f 1f 40 00` (`nopl`) |

Czyli slot ma 26896 B, ale realnej tresci jest okolo 12416 B (do file 0x2EE10). Reszta to
wyzerowana rezerwa. Rozmiar potwierdza symbol `shellcode_kernel_bin_len` w file 0x326A0
(wartosc `10 69 00 00` = 0x6910 = 26896).

Blob zawiera 34 napisy diagnostyczne `SCK>` (dowod, offsety w pliku):
`SCK>B0-enter` 0x2EA2F, `SCK>B1-patch_hv-done` 0x2EA3D, `SCK>B2-install_hv_code-done` 0x2EA53,
`SCK>B3-vbios-done` 0x2EA70, `SCK>B4-dp-link-rc` 0x2EA83, `SCK>B4b-delay-done` 0x2EA95,
`SCK>B5a-mp3init-rc` 0x2EAA9, `SCK>B5b-hdcp-rc` 0x2EABC, `SCK>B5c-output-rc` 0x2EACC,
`SCK>B5-mp3-done` 0x2EADE, `SCK>B6-linux_info-copied` 0x2EAEF, `SCK>B7-linux_info-staged` 0x2EB09,
`SCK>B8-bzimage-copied` 0x2EB23, `SCK>B9-initrd-copied` 0x2EB3A, `SCK>0-entered` 0x2EB5E,
`SCK>1-uart` 0x2EB6D, `SCK>2-fw-dispatch-passed` 0x2EB79, `SCK>3-globals` 0x2EB93,
`SCK>4-cfi-patched` 0x2EBA2, `SCK>5-boot-linux-RETURNED` 0x2EBB5,
`SCK>5a-steps-reached=0x%llx` 0x2EBD0, `SCK>5b-transmitter-rc=0x%llx` 0x2EBED,
`SCK>5f-vswing-rc=0x%llx` 0x2EC0B, `SCK>5c-mp3init-rc=0x%llx` 0x2EC24,
`SCK>5d-hdcp-rc=0x%llx` 0x2EC3E, `SCK>5e-output-rc=0x%llx` 0x2EC55,
`SCK>5h-ps5-ops-begin` 0x2EC6E, `SCK>5h-op-%d-starting` 0x2EC84, `SCK>5h-op-%d-ok` 0x2EC9B,
`SCK>5h-ps5-ops-done` 0x2ECAC, `SCK>6-rendezvous-starting` 0x2ECE4,
`SCK>7-rendezvous-RETURNED` 0x2ECFF, `SCK>BR %s vspe=...` 0x2ED38 (dlugi format diagnostyczny),
`SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x` 0x2EDC8.

### BLOB 5: `sysmodtab`, 2192 B, file 0x20AB0..0x21340 (`.data.rel.ro`, vaddr 0x1CAB0)

Tablica 137 wpisow po 16 B. Kazdy wpis to para (0, identyfikator modulu systemowego).
Dowod, pierwsze wpisy jako qwordy: `0x0, 0x8000005F, 0x0, 0x80000058, 0x0, 0x800000A1,
0x0, 0x80000062, 0x0, 0x80000061, 0x0, 0x80000013, 0x0, 0x80000094, 0x0, 0x80000080, ...`
Stala 0x80000000 to flaga "modul systemowy", nizsze bity to numer modulu. Tablica jest
w sekcji read-only po relokacji i sluzy do ladowania listy SPRX (`sceSysmoduleLoadModuleInternal`,
napis `sceSysmoduleLoadModuleInternal: 0x%x` pod 0x2155F).

Uwaga o przeliczaniu adresow: dla KAZDEJ sekcji alokowanej obowiazuje
`offset_pliku = vaddr + 0x4000`, bo naglowek ELF i program headery zajmuja pierwsze 0x4000 B
pliku, a `PT_LOAD[0]` mapuje plik od offsetu 0x4000 na vaddr 0. Sprawdzone dla `.text`
(0x0 -> 0x4000), `.rodata` (0x1D4B0 -> 0x214B0), `.dynamic` (0x20000 -> 0x24000),
`.data.rel.ro` (0x1CAB0 -> 0x20AB0) i `.data` (0x24000 -> 0x28000). Delta wynosi 0x4000
w kazdym z tych przypadkow. Sekcje niealokowane (`.symtab`, `.strtab`, `.shstrtab`,
`.comment`) maja `addr = 0` i wlasne offsety plikowe.

### BLOB 6: `NVS_EXPECT`, 56 B, file 0x232A0..0x232D8 (vaddr 0x1F2A0)

Surowy zrzut, 7 qwordow: `0x2300, 0x200, 0x200, 0x0, 0x2000, 0x800, 0x1000`, czyli bajty
`00 23 00 00 00 00 00 00 | 00 02 00 00 00 00 00 00 | 00 02 00 00 00 00 00 00 | 00 00 00 00
00 00 00 00 | 00 20 00 00 00 00 00 00 | 00 08 00 00 00 00 00 00 | 00 10 00 00 00 00 00 00`.
Wszystkie wartosci to wielokrotnosci poteg dwojki (0x200 = 512, 0x800 = 2048, 0x1000 = 4096,
0x2000 = 8192, 0x2300 = 8960). Nazwa sugeruje oczekiwane wartosci odczytu z NVS (kontrola
poprawnosci odczytu), a wartosci wygladaja na rozmiary regionow i stron.

### BLOB 7: tabela 22 offsetow int32, 88 B, file 0x232DC..0x23334 (vaddr 0x1F2DC)

22 wartosci ze znakiem, wszystkie ujemne, w waskim zakresie `0xFFFE62E6` do `0xFFFE65A7`.
Kroki miedzy kolejnymi wartosciami wynosza 0x1F (3 razy) albo 0x22 (18 razy), czyli 31 lub
34 bajty. To sygnatura tablicy offsetow do rekordow o stalym rozmiarze 34 B. W odroznieniu
od BLOB 11 nie udalo sie tu ustalic statycznie podstawy: sprawdzone podstawy 0x1F2DC i 0x1F340
nie trafiaja w granice instrukcji, wiec podstawa jest wyznaczana w czasie dzialania. Wartosci
podaje jako fakt, interpretacje jako hipoteze.

### BLOB 8: wektor testowy SHA1 + oczekiwany skrot, 32 B, file 0x23340..0x23360

`01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10` to klasyczny wzorzec KAT ("known answer
test"). Uzasadnienie: pierwsza polowa to rosnaca sekwencja co 0x22 (`01 23 45 67 89 ab cd ef`),
druga polowa to ta sama sekwencja w odwrotnej kolejnosci (`fe dc ba 98 76 54 32 10`), co daje
razem 16-bajtowy blok wejsciowy dla funkcji skrotu. Drugie 16 B:
`51 8d 64 a6 35 de d8 c1 e6 b0 39 b1 c3 e5 52 30` to 16-bajtowy oczekiwany skrot tej samej
dlugosci. Calosc lezy bezposrednio przed alfabetem base64 i przed tabelami skokow, obok
symboli `SHA1Transform` (0xC7D0, rozmiar 5083) i `nid_encode` (0xC330, rozmiar 1173), wiec
jest to samosprawdzenie implementacji skrotu.

### BLOB 9: alfabet base64, 64 B, file 0x23370..0x233B0

`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-`
(64 znaki, po nich bajt NUL pod file 0x233B0, potem 8 zer). Zamiast standardowych `+/`
wystapilo `+-`, czyli wariant uzywany przy kodowaniu NID (identyfikatorow funkcji)
w SDK PlayStation.

### BLOB 10: blok 15 zmiennych `KERNEL_OFFSET_*`, 120 B, file 0x233B8..0x23430

To nie jest anonimowa tabela. Kazdy qword ma nazwe z `.symtab` (shndx 13, `.rodata`).
Sa to offsety pol struktur jadra FreeBSD, wpisane do pliku na sztywno:

| Offset pliku | vaddr | Symbol | Wartosc | Sens (offset w strukturze) |
|---|---|---|---|---|
| 0x233B8 | 0x1F3B8 | `KERNEL_OFFSET_PROC_P_UCRED` | 0x40 | `struct proc.p_ucred` |
| 0x233C0 | 0x1F3C0 | `KERNEL_OFFSET_PROC_P_FD` | 0x48 | `struct proc.p_fd` |
| 0x233C8 | 0x1F3C8 | `KERNEL_OFFSET_PROC_P_PID` | 0xBC | `struct proc.p_pid` |
| 0x233D0 | 0x1F3D0 | `KERNEL_OFFSET_PROC_P_VMSPACE` | 0x200 | `struct proc.p_vmspace` |
| 0x233D8 | 0x1F3D8 | `KERNEL_OFFSET_UCRED_CR_UID` | 0x4 | `struct ucred.cr_uid` |
| 0x233E0 | 0x1F3E0 | `KERNEL_OFFSET_UCRED_CR_RUID` | 0x8 | `cr_ruid` |
| 0x233E8 | 0x1F3E8 | `KERNEL_OFFSET_UCRED_CR_SVUID` | 0xC | `cr_svuid` |
| 0x233F0 | 0x1F3F0 | `KERNEL_OFFSET_UCRED_CR_RGID` | 0x14 | `cr_rgid` |
| 0x233F8 | 0x1F3F8 | `KERNEL_OFFSET_UCRED_CR_SVGID` | 0x18 | `cr_svgid` |
| 0x23400 | 0x1F400 | `KERNEL_OFFSET_UCRED_CR_PRISON` | 0x30 | `cr_prison` |
| 0x23408 | 0x1F408 | `KERNEL_OFFSET_UCRED_CR_SCEAUTHID` | 0x58 | pole SCE w ucred |
| 0x23410 | 0x1F410 | `KERNEL_OFFSET_UCRED_CR_SCECAPS` | 0x60 | pole SCE w ucred |
| 0x23418 | 0x1F418 | `KERNEL_OFFSET_UCRED_CR_SCEATTRS` | 0x80 | pole SCE w ucred |
| 0x23420 | 0x1F420 | `KERNEL_OFFSET_FILEDESC_FD_RDIR` | 0x10 | `struct filedesc.fd_rdir` |
| 0x23428 | 0x1F428 | `KERNEL_OFFSET_FILEDESC_FD_JDIR` | 0x18 | `fd_jdir` |

Uzasadnienie, ze to offsety pol, a nie adresy: wszystkie wartosci sa mniejsze od 0x200,
gorna polowa kazdego qwordu jest zerowa, a `p_ucred = 0x40`, `p_fd = 0x48`, `p_pid = 0xBC`
to znane offsety w `struct proc` z FreeBSD 9/11, na ktorym bazuje jadro PS5. To najwazniejsza
tabela stalych w calym pliku: jako jedyna ma pelne nazwy i dotyczy offsetow, nie adresow.

### BLOB 11: tabela skokow, 69 x int32, 276 B, file 0x23430..0x23544 (vaddr 0x1F430)

Wszystkie 69 wartosci sa ujemne (gorna polowa 0xFFFF), 26 unikalnych. Dowod na to, ze to
tablica skokow: `cel = 0x23430 + wartosc` (rownanie w offsetach pliku, rownowaznie
`cel_vaddr = 0x1F430 + wartosc`) wchodzi w `.text`. Zakres celow 0x15935..0x1722E,
klastry na stronach 0x15900 (28 wpisow) i 0x16D00 (19 wpisow).
Dwa sprawdzone przyklady:

* wpis [1] pod 0x23434 = `0f 25 ff ff` = -56049, cel = 0x23430 - 0xDAF1 = 0x1593F,
  a pod 0x1593F leza bajty `48 83 c6 10 48 8b 7e f8 48 83 ff 1c`, czyli poprawny
  poczatek instrukcji (`add rsi, 0x10; mov rdi, [rsi-8]; cmp rdi, 0x1c`),
* wpis [0] pod 0x23430 = `e0 25 ff ff` = -55840, cel = 0x23430 - 0xDA20 = 0x15A10,
  pod 0x15A10 leza bajty `48 89 5d b8 48 85 d2 74 7d 8b 32 48`.

To typowa tablica skokow dla pozycyjnie niezaleznego kodu: 32-bitowy offset wzgledem
poczatku tablicy, dlatego wszystkie wartosci sa ujemne (cele leza przed tabela).

### BLOB 12: `mdbg_memop.privcaps`, 16 B, file 0x23550..0x23560 (vaddr 0x1F550)

16 bajtow `0xFF`, czyli maska uprawnien z wszystkimi bitami ustawionymi, dla operacji
pamieciowych debuggera (mdbg). Lezy dokladnie na koncu `.rodata`, przed `.init_array`
(ktora ma rozmiar 0). To takze wyjasnia 8-bajtowe trafienia `0xFFFFFFFFFFFFFFFF`
z rozdzialu 4.1: to nie wypelnienie, a ta wlasnie maska.

### BLOB 13: `file_paths` i wskaznik `iommu`, 72 B, file 0x28500..0x28550

`iommu` (file 0x28500, vaddr 0x24500, 8 B) jest w pliku zerowy, wypelniany w czasie dzialania.
`file_paths` (file 0x28510, vaddr 0x24510, 64 B) to bufor na 4 sciezki po 16 B, w pliku
w calosci wyzerowany.

### BLOB 14: sentinele konca `.data`, 24 B, file 0x326A0..0x326B8

`10 69 00 00` = `shellcode_kernel_bin_len` (26896), potem 20 B wartosci `0xFFFFFFFF`:
`rw_pair.0` (vaddr 0x2E6A4), `rw_pair.1` (0x2E6A8), `rw_pipe.0` (0x2E6AC), `rw_pipe.1` (0x2E6B0),
`proc_cache_counter` (0x2E6B4), czyli deskryptory i licznik zainicjowane na -1.

### Bloby poza plikiem (`.bss`, 272560 B, nie zajmuja miejsca na dysku)

| Symbol | vaddr | Rozmiar | Uwaga |
|---|---|---|---|
| `kernel_pmap_invalidate_all.two_zero_pages` | 0x2EFF0 | 262144 | dwie wyzerowane strony 128 KB, uzyl bym ostroznie: to 96 procent calego BSS |
| `hv_defeat_13xx.chain_buf` | 0x2E7B0 | 2048 | bufor lancucha ROP dla 13.xx |
| `notify.buffer` | 0x6F200 | 2048 | bufor powiadomienia systemowego |
| `proc_cache` | 0x707F0 | 1600 | 100 wpisow po 16 B |
| `linux_i` | 0x6FA00 | 3128 | struktura informacji o Linuksie |
| `jmp_env` | 0x2E750 | 96 | |
| `jmpbuf` | 0x70640 | 256 | |

Suma: 13 blokow danych w pliku + 7 buforow w `.bss`.

## 4. Tabele stalych z offsetami jadra

### 4.1 Wynik kluczowy: to sa offsety od bazy jadra, nie adresy absolutne

W calym pliku nie ma ANI JEDNEJ 8-bajtowej stalej z zakresu 0xFFFFFFFF80000000 do
0xFFFFFFFFFFFFFFFF lezacej w sekcji danych. Skan bajt po bajcie po `.data.rel.ro`, `.rodata`,
`.dynamic` i `.data` zwrocil tylko:

* file 0x2354D..0x23558: koncowka maski `mdbg_memop.privcaps` (BLOB 12, 16 bajtow 0xFF
  pod file 0x23550) plus 8-bajtowe odczyty przesuniete o 1 do 3 bajtow przez poprzedzajace
  zera. To nie jest stala programu, a maska uprawnien,
* file 0x326A1..0x326B0: sentinele -1 w `.data` (BLOB 14),
* file 0x28165, 0x281C1, 0x2C215, 0x2C3DD, 0x2CBEa, 0x2CC5B, 0x2CC85, 0x2CE30, 0x2CF09,
  0x2CF6B, 0x2CFD3, 0x2D288, 0x2D2B4, 0x2DD17: przesuniete o 1 do 3 bajtow fragmenty
  instrukcji wewnatrz BLOB 1 i BLOB 4 (np. `0xFFFFFFFFB8480000` to bajty `48 b8 00 00 48 b8`).
  Zadna z tych wartosci nie jest stala programu.

Wniosek: obraz jest w calosci pozycyjnie niezalezny i 32-bitowy. Adresy jadra sa wyrazone
jako OFFSETY od bazy, a baza jest ustalana w czasie dzialania (napisy `SWEEP BOUNDS
ktext=0x%lx kdata=0x%lx -> loop runs? %s` pod 0x21621 oraz `PTE STATE cr3=0x%lx dmap=0x%lx`
pod 0x23170 pokazuja, ze baza jest wykrywana, nie zaszyta).

### 4.2 Tabele `off_XXXX` to offsety od bazy jadra (dowod przez porownanie z repo)

Najmocniejszy dowod: 24 wartosci z tabeli `off_1360` (file 0x2BBB0) zgadzaja sie co do bajtu
z udokumentowanymi offsetami 13.60 w repo, plik `tools/pprhook/include/offsets/13_60.h`.

| Indeks w off_1360 | Offset w pliku | Wartosc | Nazwa w repo |
|---|---|---|---|
| [5] | 0x2BBE0 | 0x3BB4300 | `KERNEL_SYM_IDT_ARRAY` |
| [6] | 0x2BBE8 | 0x3BB6FE0 | `KERNEL_SYM_COMMON_TSS` |
| [39] | 0x2BCE8 | 0xC16EE0 | `KERNEL_SYM_HV_MP_STARTUP_CALL` |
| [40] | 0x2BCF0 | 0x269FB8 | `KERNEL_SYM_MP_STARTUP_INIT_VECTOR` |
| [41] | 0x2BCF8 | 0x2D39000 | `KERNEL_SYM_DATA_CAVE` |
| [42] | 0x2BD00 | 0x25213E | `KERNEL_GADGET_PIVOT_ADD_RSP28_RET` |
| [13] | 0x2BC18 | 0x257B3D | `KERNEL_GADGET_IRETQ` |
| [15] | 0x2BC28 | 0x28CE6D | `KERNEL_GADGET_POP_RDI` |
| [16] | 0x2BC30 | 0x34CB91 | `KERNEL_GADGET_POP_RSI` |
| [17] | 0x2BC38 | 0x2A0F7B | `KERNEL_GADGET_POP_RDX` |
| [18] | 0x2BC40 | 0x2918B2 | `KERNEL_GADGET_POP_RCX` |
| [43] | 0x2BD08 | 0xB8CA6D | `KERNEL_GADGET_POP_R8` |
| [44] | 0x2BD10 | 0x474389 | `KERNEL_GADGET_STORE_RCX_R8` |
| [45] | 0x2BD18 | 0x32693F | `KERNEL_GADGET_STORE_RDI8_RCX` |
| [46] | 0x2BD20 | 0x321EA0 | `KERNEL_GADGET_OR_RCX_EAX` |
| [47] | 0x2BD28 | 0xA07BA6 | `KERNEL_GADGET_SET_DR7` |
| [48] | 0x2BD30 | 0x82B915 | `KERNEL_GADGET_ST_RCX_RDX` |
| [49] | 0x2BD38 | 0x2BB28F | `KERNEL_GADGET_ST_RCX_RAX` |
| [50] | 0x2BD40 | 0x8E3A44 | `KERNEL_GADGET_MOV_RAX_RSI` |
| [51] | 0x2BD48 | 0xBECDEA | `KERNEL_GADGET_MOV_RAX_RDI` |
| [52] | 0x2BD50 | 0x25D027 | `KERNEL_GADGET_REP_MOVSB` |
| [53] | 0x2BD58 | 0x30644F | `KERNEL_GADGET_CLD` |
| [54] | 0x2BD60 | 0x2912A2 | `KERNEL_GADGET_RET_TRAMP` |
| [55] | 0x2BD68 | 0x2529D8 | `KERNEL_GADGET_DBREG_RESUME` |

Uwaga metodyczna: nazwy w tablicy ELF nie pokrywaja sie indeksami z kolejnoscia w
`13_60.h`, wiec dopasowanie zrobiono po wartosciach, nie po pozycji. Dodatkowo te same
gadgety wystepuja w `off_1300` (file 0x2B9D0) z innymi wartosciami, np. [42] = 0x2520FE,
co potwierdza, ze kazda tabela jest osobna dla swojej wersji firmware.

### 4.3 Rozklad zapelnienia 30 tabel

Liczba niezerowych wpisow z 60 na tabele (dowod: odczyt 60 qwordow od file 0x28550 + i*0x1E0):

| Tabela | nz/60 | Tabela | nz/60 | Tabela | nz/60 |
|---|---|---|---|---|---|
| off_0300 | 21 | off_0650 | 29 | off_1000 | 40 |
| off_0310 | 21 | off_0700 | 28 | off_1100 | 44 |
| off_0320 | 21 | off_0701 | 28 | off_1300 | 45 |
| off_0321 | 21 | off_0720 | 28 | off_1360 | 53 |
| off_0400 | 21 | off_0740 | 28 | off_0900 | 13 |
| off_0402 | 21 | off_0760 | 28 | off_1200 | 34 |
| off_0403 | 21 | off_0761 | 28 | off_0800 | 39 |
| off_0450 | 21 | off_0761_khook | 41 | | |
| off_0451 | 21 | off_0500 | 30 | | |
| off_0502 | 30 | off_0510 | 30 | off_0550 | 30 |
| off_0600 | 30 | off_0602 | 30 | | |

Suma niezerowych wpisow we wszystkich 30 tabelach: 875.

Tabele dla 3.xx i 4.xx maja wypelnione tylko pierwsze 4 pola (np. off_0300: [0]=0x33175E0,
[1]=0x1E4, [2]=0x1D0, [3]=0x6423F80, reszta zer), a 0x1E4/0x1D0 to male offsety struktury.
off_1360 jest najpelniejsza: 53 z 60 wpisow. To wyjasnia napis
`13.60 offsets are incomplete - refusing to arm.` (0x225F9): kod ma bramke, ktora sprawdza
kompletnosc tabeli przed uzbrojeniem exploitu.

Dwie wartosci sa identyczne we WSZYSTKICH 30 tabelach: [29] = 0x62806F00 i [30] = 0x62847375
(dowod: off_0300 file 0x28638, off_1300 file 0x2BAC0, off_1360 file 0x2BC98). Skoro nie zaleza
od firmware, nie sa offsetami jadra. Ten sam przedrostek 0x62xxxxxx wystepuje jako 32-bitowe
adresy w BLOB 1, wiec najprawdopodobniej sa to adresy w przestrzeni hypervisora. Tego nie
potwierdzilem dowodem runtime, wiec traktuje to jako hipoteze, nie fakt.

### 4.4 Nazwy symboli jadra w `.strtab` (dowod, ze kod rozwiazuje struktury jadra po nazwie)

`.strtab` (file 0x37104) zawiera pelny zestaw nazw stalych, m.in.:
`KERNEL_ADDRESS_TEXT_BASE` 0x38D0D, `KERNEL_ADDRESS_DATA_BASE` 0x38599,
`KERNEL_ADDRESS_ALLPROC` 0x38FA0, `KERNEL_ADDRESS_SECURITY_FLAGS` 0x38FB7,
`KERNEL_ADDRESS_ROOTVNODE` 0x38FD5, `KERNEL_ADDRESS_BUS_DATA_DEVICES` 0x38FEE,
`KERNEL_ADDRESS_TARGETID` 0x39049, `KERNEL_ADDRESS_QA_FLAGS` 0x39061,
`KERNEL_ADDRESS_UTOKEN_FLAGS` 0x39079, `KERNEL_ADDRESS_PRISON0` 0x39095,
`KERNEL_ADDRESS_DMAP_BASE` 0x390AC, `KERNEL_ADDRESS_IOMMU_SOFTC` 0x390C5,
`KERNEL_OFFSET_PROC_P_VMSPACE` 0x384FF, `KERNEL_OFFSET_VMSPACE_P_ROOT` 0x3900E,
`KERNEL_OFFSET_VMSPACE_VM_PMAP` 0x3902B, `KERNEL_OFFSET_PROC_P_UCRED` 0x394E1,
`KERNEL_OFFSET_PROC_P_FD` 0x394FC, `KERNEL_OFFSET_PROC_P_PID` 0x39514,
`KERNEL_OFFSET_UCRED_CR_UID/RUID/SVUID/RGID/SVGID/PRISON/SCEAUTHID/SCECAPS/SCEATTRS`
(0x3952D do 0x39618), `KERNEL_OFFSET_FILEDESC_FD_RDIR` 0x39638,
`KERNEL_OFFSET_FILEDESC_FD_JDIR` 0x39657.

Te symbole sa typu OBJECT, rozmiar 8, sekcja 13 (`.rodata`), adresy 0x1F3B8 do 0x1F428,
czyli 15 zmiennych 8-bajtowych w `.rodata`. Sa to miejsca na offsety wypelniane w czasie
dzialania (dlatego w pliku maja wartosci zerowe lub male).

### 4.5 Stale 32-bitowe wygladajace na adresy, wewnatrz BLOB 4

Skan instrukcji `mov r32, imm32` z imm32 >= 0x60000000 w BLOB 4 (file 0x2BD90..0x326A0)
wypisal 45 trafien. Grupy tematyczne:

* Rejestry architektoniczne x86 (MSR i MMIO, nie jadro):
  `0xC0000080` EFER (file 0x2DBFE, 0x2DC0F), `0xC0010114` MSR_VM_CR (file 0x2DC1F, 0x2DC29),
  `0xFEE00900` LAPIC (w BLOB 1, file 0x28006), `0xFDD80018` (file 0x2DC97).
* Adresy z przedrostkiem 0x62 (przestrzen hypervisora, spojne z tabelami off_*):
  `0x6282E1A0`, `0x6282D140`, `0x6282E1B8` w BLOB 1 (file 0x28004, 0x28008, 0x2801E).
* Adresy z przedrostkiem 0xE06 (file 0x2DD07 `0xE060A5D8`, 0x2DD49 `0xE066A188`,
  0x2DD69 `0xE0624854`, 0x2DD8A `0xE062487C`). Nie potwierdzone dowodem, podaje jako
  kandydatow.
* Wzorce testowe i maski: `0xAAAAAAAA` (file 0x2C470, 0x2C48C), `0xFFFFFFFF` (file 0x2C218,
  0x2C3E0, 0x2CBED, 0x2CE33, 0x2CFD6, 0x2D28B, 0x2D2B7), `0x80000000` (file 0x2D507, 0x2DA48,
  0x2DA71), `0x70000000` (file 0x2D50D, 0x2D993, 0x2DCC9), `0x7F300000` (file 0x2DA00, 0x2DBB2).

Zadna z tych stalych nie jest adresem jadra w rozumieniu 0xFFFFFFFF80000000+.

## 5. Entropia na blokach 4 kB

Policzona dla calego pliku, 58 blokow po 4096 B (ostatni 3976 B), entropia Shannona na
rozkladzie bajtow. Maksimum mozliwe to 8.0.

Bloki o entropii 6.0 i wyzej (najwyzsze w pliku):

| Zakres | H | Co tam jest |
|---|---|---|
| 0x10000..0x11000 | 6.5265 | `.text` (najgestszy fragment kodu) |
| 0x11000..0x12000 | 6.2612 | `.text` |
| 0x15000..0x16000 | 6.1898 | `.text` |
| 0x17000..0x18000 | 6.0834 | `.text` |
| 0x16000..0x17000 | 6.0734 | `.text` |
| 0x2C000..0x2D000 | 6.0074 | BLOB 4 (shellcode_kernel_bin) |

Bloki zerowe (H = 0.0, jedenascie pelnych blokow): 0x1000, 0x2000, 0x3000, 0x19000, 0x1A000,
0x1B000, 0x25000, 0x26000, 0x27000, 0x30000, 0x31000. Bloki o bardzo niskiej entropii to
0x2F000 (H=0.1486, wyzerowany ogon `.data` z 13-bajtowym ogonem paddingu), 0x24000 (H=0.2172,
sam `.dynamic`) i 0x32000 (H=1.7239, koncowka `.data`, `.comment` pod 0x326C0 i tablica
symboli od 0x32708). Blok 0x23000 ma H=2.4021 i obejmuje ogon napisow `.rodata` oraz tabele
stalej (BLOBY 6 do 12), co potwierdza, ze tabele te sa danymi uporzadkowanymi, nie losowymi.

Wniosek: ZADEN blok nie przekracza 6.5265, czyli progu charakterystycznego dla danych
zaszyfrowanych lub spakowanych (praktycznie 7.9 do 8.0). Nie ma tu obrazu jadra, archiwum,
ani zaszyfrowanego payloadu. Najwyzsza entropia w danych to 6.0074 w BLOB 4 i wynika
z nagromadzenia rozkazow, nie z szyfrowania.

Kontrola krzyzowa braku kompresji, skan calego pliku (237448 B) pod sygnatury:
gzip `1f 8b 08` 0 trafien, xz `fd 37 7a 58 5a 00` 0, zstd `28 b5 2f fd` 0, lz4 `04 22 4d 18` 0,
bzip2 `42 5a 68` 0, 7z `37 7a bc af 27 1c` 0, zip `50 4b 03 04` 0, squashfs `68 73 71 73` 0,
lzo `89 4c 5a 4f` 0, lz4-legacy `02 21 4c 18` 0, compress `1f 9d` 0. Dodatkowo w calym pliku
nie ma drugiego naglowka ELF (szukane `7f 45 4c 46` poza offsetem 0: 0 trafien), wiec nie ma
zagniezdzonego obrazu ELF. Krotka sygnatura lzma `5d 00 00` daje 13 przypadkowych trafien
w `.text` i w tabelach, co przy 3 bajtach jest oczekiwanym szumem, nie dowodem kompresji.

## 6. Napisy dlugosci 6 i wiecej, posegregowane tematycznie

Razem 1049 unikalnych ciagow, ale 130 z nich to smieci odczytane z bajtow kodu w `.text`
(np. `AWAVSPA`, `[A\A]A^A_]`, `ffffff.`). Napisy sensowne to 290 w `.rodata` (7537 B),
34 w BLOB 4 i okolo 700 nazw symboli w `.strtab` oraz `.dynstr`.

Wszystkie offsety w tym rozdziale to offsety PLIKOWE (nie vaddr). Dla `.rodata` vaddr
otrzymamy odejmujac 0x4000, dla `.data` rowniez odejmujac 0x4000, dla `.strtab` offset
jest bezwzgledny (sekcja niealokowana).

### 6.1 Sciezki plikow i katalogi (`.rodata`)

| Offset | Napis |
|---|---|
| 0x21658 | `/mnt/usb2/` |
| 0x21663 | `/mnt/usb2/PS5/Linux/` |
| 0x21715 | `/mnt/usb0/PS5/Linux/` |
| 0x2172A | `/mnt/usb3/PS5/Linux/` |
| 0x21E73 | `/mnt/usb0/` |
| 0x22304 | `/mnt/usb1/PS5/Linux/` |
| 0x22E8F | `/mnt/usb1/` |
| 0x2324C | `/mnt/usb3/` |
| 0x21539 | `/user/homebrew/lib/%s` |
| 0x2168B | `__isthreaded` (nie sciezka, szukany symbol libc) |
| 0x21948 | `/system/common/lib/libSceSysmodule.sprx` |
| 0x21C48 | `/system_ex/common_ex/lib/%s` |
| 0x21C64 | `/%s/common/lib/%s` |
| 0x21F7E | `/system_ex/priv_ex/lib/%s` |
| 0x2205F | `/%s/priv/lib/%s` |
| 0x2249F | `/%s/common_ex/lib/%s` |
| 0x22694 | `/system/priv/lib/libSceDeci5Dtracep.sprx` |
| 0x226C5 | `/%s/priv_ex/lib/%s` |
| 0x227D8 | `/system/common/lib/%s` |
| 0x22A86 | `%s/lib` |
| 0x22D61 | `/dev/gc` |
| 0x22DD6 | `/system/priv/lib/%s` |
| 0x22F05 | `%s/lib/nxp` |
| 0x23067 | `/system/priv/lib/libSceDeci5Ttyp.sprx` |
| 0x21BF3 | `lib/nxp/pcieuartiw620_combo_v1.bin` |

### 6.2 Nazwy plikow konfiguracyjnych i obrazow rozruchowych

| Offset | Napis | Rola |
|---|---|---|
| 0x21678 | `bzImage` | obraz jadra Linuksa |
| 0x21680 | `initrd.img` | initramfs |
| 0x229FE | `cmdline.txt` | linia polecen jadra |
| 0x22255 | `vram.txt` | konfiguracja VRAM |
| 0x21F6C | `path-override.txt` | nadpisanie sciezek |
| 0x21F57 | `kernel_uart_override` | klucz nadpisania UART |
| 0x22244 | `kernel_cfi_check` | klucz kontroli CFI |

### 6.3 Domyslna linia polecen jadra (dowod, ze payload startuje Linuksa)

Offset 0x228AE:
`root=/dev/sda2 rw rootwait console=ttyTitania0 console=tty0 video=DP-1:1920x1080@60 mitigations=off idle=halt pci=pcie_bus_perf`

`ttyTitania0` to nazwa konsoli wlasciwa dla jadra PS5 (Titania to nazwa kodowa APU).

### 6.4 Komunikaty stanu i bledow (wybor najwazniejszych)

| Offset | Napis |
|---|---|
| 0x22FAE | `Welcome to ps5-linux-loader. We'll defeat HV and prepare the system to boot Linux on sleep resume.` |
| 0x21803 | `Finished preparation. Going to rest mode in 5 seconds.` |
| 0x2183A | `Please wait for the orange light to stop blinking and then wakeup to Linux :)` |
| 0x2DD9B (BLOB 4) | `[*] Booting Linux in bare metal...` |
| 0x2ECC1 (BLOB 4) | `Linux prepared OK` |
| 0x2ECD4 (BLOB 4) | `Good Bye VM :)` |
| 0x2ED1A (BLOB 4) | `We shouldn't be here :(` |
| 0x220C2 | `Something went wrong while defeating Hypervisor.` |
| 0x220F3 / 0x22340 | `Please make sure your fw is supported.` |
| 0x222D7 | `validity gate failed - wrong firmware image?` |
| 0x22319 | `Something went wrong while initiating.` |
| 0x22367 | `Something went wrong while installing linux files.` |
| 0x2245F | `Something went wrong while preparing resume.` |
| 0x22CA1 | `Something went wrong while dumping device firmwares - Continuing` |
| 0x21744 | `Something went wrong while reading bzImage - Aborting` |
| 0x23190 | `Something went wrong while reading initrd - Aborting` |
| 0x2279D | `File bzImage not found at default paths - Aborting` |
| 0x22B2B | `File cmdline.txt not found at default paths - Using static fallback` |
| 0x2286C | `File vram.txt not found at default paths - Using static fallback` |
| 0x21D0D | `Seems like the configured vram value is wrong - Using static fallback` |
| 0x229C3 | `[-] Error could not allocate initrd (%d bytes, errno %d).` |
| 0x22D92 | `[-] Error could not allocate bzimage (%d bytes, errno %d).` |
| 0x22761 | `Could not find offset of shellcode fw version - Aborting` |
| 0x22F78 | `Could not find offset of args_ptr address - Aborting` |
| 0x22F10 | `could not derive H from the EFI map - refusing to arm.` |
| 0x22F47 | `khook install failed (%d) - refusing to suspend.` |
| 0x23144 | `could not pin to core %d - refusing to arm.` |
| 0x2239B | `Unknown kernel I/O error` |
| 0x225F9 | `13.60 offsets are incomplete - refusing to arm.` |
| 0x22D2D | `PS5 WiFi firmware offset missing for firmware %04x` |
| 0x219D8 | `Unable to initialize patches` |
| 0x22B70 | `Unable to initialize rtld` |
| 0x22182 | `Unable to resolve '%s'` |
| 0x215D0 | `Unable to load %s` |
| 0x23052 | `unable to load '%s'` |

### 6.5 Napisy z slowami kluczowymi z zadania (pelny wykaz, przeskanowany caly plik)

| Slowo | Offset | Napis |
|---|---|---|
| HVBUG | 0x22629 | `See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.` |
| findings | 0x22629 | ten sam napis (jedno wystapienie w calym pliku) |
| CAVE | 0x2265C | `KERNEL_CODE_CAVE` |
| CAVE | 0x2299F | `DATA_CAVE` |
| cave | 0x2203B | `Error: missing code cave offset` |
| GAD | 0x22439 | `GAD_ADD_RSP_28..RBP` |
| gadget | 0x38930 | `kgadget` (nazwa symbolu w `.strtab`) |
| 13.60 | 0x225F9 | `13.60 offsets are incomplete - refusing to arm.` |
| 13.60 | 0x22629 | `See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.` |
| 13.60 | 0x2EDC8 | `SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x` |
| 1360 | 0x38BF6 | `off_1360` (nazwa symbolu) |
| shellcode | 0x22761 | `Could not find offset of shellcode fw version - Aborting` |
| shellcode | 0x22ADF | `VERDICT: still execute-only and shellcode_kernel's first write WILL fault.` |
| shellcode | 0x3878D, 0x387A4, 0x38817, 0x3882C, 0x38C62, 0x38C7B | `shellcode_0607_bin_len`, `shellcode_0607_bin`, `shellcode_ap_bin_len`, `shellcode_ap_bin`, `shellcode_kernel_bin_len`, `shellcode_kernel_bin` |
| bzImage | 0x21678, 0x21744, 0x2279D, 0x22D92, 0x2EB23 | `bzImage`, `...reading bzImage...`, `File bzImage not found...`, `...allocate bzimage...`, `SCK>B8-bzimage-copied` |
| initrd | 0x21680, 0x229C3, 0x23190, 0x2EB3A | `initrd.img`, `...allocate initrd...`, `...reading initrd...`, `SCK>B9-initrd-copied` |
| KERNEL | 0x2265C | `KERNEL_CODE_CAVE` (plus okolo 60 nazw `KERNEL_ADDRESS_*` i `KERNEL_OFFSET_*` w `.strtab`, patrz 4.4) |
| OFFSET | 0x2203B, 0x225F9, 0x22629, 0x22761, 0x22D2D, 0x22F78 | komunikaty bledow (pelna lista w 6.4) |
| OFFSET | 0x371A8, 0x371B6, 0x373A2, 0x37589, 0x38465, 0x38496, 0x384D8, 0x38CC0 | `s_gpu_offsets`, `s_offsets_set`, `offsets_present`, `offsets.c`, `env_offset`, `get_offset_va`, `gpu_set_offsets`, `set_offsets` |

### 6.6 Odwolania do repozytoriow i dokumentacji (wynik kluczowy)

W calym pliku jest DOKLADNIE JEDNO odwolanie do dokumentacji i ANI JEDNO do repozytorium:

* 0x22629: `See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.`

Skanowanie calego pliku pod `http`, `https`, `github`, `gitlab`, `readme` (bez wzgledu na
wielkosc liter) nie zwraca nic poza nazwami bibliotek SDK zawierajacymi `Http`
(`libSceHttp.sprx` 0x22E5B, `libSceHttp2.sprx` 0x216BE, `libSceHttpCache.sprx` 0x22BB6).
Sciezka `HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md` jest wiec jedynym tropem
proweniencji tabeli `off_1360` i warto ja zapamietac przy dalszej pracy.

### 6.7 Nazwy plikow zrodlowych zaszyte w `.strtab` (dowod na pochodzenie kodu)

Pliki `.c` (shndx = 65521, czyli ABS, symbole FILE) w kolejnosci z `.symtab`:
`firmware.c`, `gpu.c`, `mman.c`, `hv_defeat_0304.c`, `hv_defeat_0506.c`, `hv_defeat_0607.c`,
`hv_defeat_13xx.c`, `iommu.c`, `khook.c`, `loader.c`, `main.c`, `offsets.c`, `prepare_resume.c`,
`pipe2.c`, `tmr.c`, `utils.c`, `syscalls.c`, `crt.c`, `syscall.c`, `klog.c`, `nid.c`,
`kernel.c`, `rtld.c`, `rtld_so.c`, `rtld_sprx.c`, `rtld_payload.c`, `rtld_dlfcn.c`, `mdbg.c`,
`patch.c`, `kernel_procio.c`, `kernel_iommu.c`.

To zestaw z projektu byepervisor. Cztery pliki `hv_defeat_0304/0506/0607/13xx` tlumacza,
dlaczego w pliku jest 30 tabel offsetow: kazdy wariant obsluguje inna generacje hypervisora.
Nazwy `shellcode_0607_bin`, `shellcode_ap_bin`, `shellcode_kernel_bin` i `off_1360`
pochodza z tego samego zestawu zrodel.

### 6.8 Importy SDK i nazwy funkcji jadra rozwiazywane w czasie dzialania

Poza 42 importami z `.dynsym` (lista w 1.4) kod zawiera nazwy rozwiazywane dynamicznie
w `.rodata`: `sceKernelDlsym` 0x22CE3, `sceKernelLoadStartModule` 0x22E06,
`sceKernelStopUnloadModule` 0x21AAC, `sceSysmoduleLoadModuleInternal` 0x23012,
`SceSystemStateMgrStatus` 0x21A7B, `libkernel_sys.sprx` 0x22A10, `libkernel.sprx` 0x22E1F,
`libkernel_web.sprx` 0x226D8. Do tego 141 nazw `libSce*.sprx` i 28 napisow formatujacych.

## 7. Czego w pliku NIE ma (wyniki negatywne, istotne dla dalszej pracy)

1. Brak obrazu jadra Linuksa. `bzImage` i `initrd.img` wystepuja WYLACZNIE jako nazwy plikow
   do wczytania z `/mnt/usbN/PS5/Linux/` (0x21678, 0x21680). Skan sygnatur kompresji
   i entropia (rozdzial 5) to potwierdzaja.
2. Brak danych zaszyfrowanych lub spakowanych. Najwyzsza entropia bloku 4 kB to 6.5265
   (zwykly kod), braki naglowkow kompresji.
3. Brak 8-bajtowych adresow jadra w danych (rozdzial 4.1). Wszystko jest offsets lub
   32-bitowym adresem.
4. Brak segmentow SCE (`PT_SCE_*`) i brak `PT_INTERP`. To nie jest SPRX, mimo importow
   z `libkernel_web.sprx`.
5. Brak sekcji `.init_array`, `.fini_array` z zawartoscia (rozmiar 0).
6. Brak osobnego byepervisora. Kod hypervisora jest WKOMPILOWANY: 30 tabel offsetow,
   3 shellcody, `khook.c`, `hv_defeat_*.c`, `iommu.c` sa w tym samym obrazie. To potwierdza
   obserwacje uzytkownika, ze payload nie wymaga osobnego byepervisora.
7. Brak jakiegokolwiek odwolania do repozytorium lub URL (rozdzial 6.6).

## 8. Podsumowanie liczbowe

| Pozycja | Liczba |
|---|---|
| Segmenty programowe | 4 (3 x PT_LOAD + 1 x PT_DYNAMIC) |
| Sekcje | 23 (w tym 1 pusta) |
| Symbole w `.symtab` | 781 |
| Symbole w `.dynsym` | 46 (42 importy, 4 definicje lokalne) |
| Relokacje | 189 (187 w `.rela.dyn`, 2 w `.rela.plt`) |
| Wbudowane bloby w pliku | 14 |
| Bufory w `.bss` (poza plikiem) | 7 |
| Tabele offsetow jadra | 30 x 480 B = 14400 B (875 niezerowych wpisow 8-bajtowych) |
| Tabele stalych w `.rodata` | 6 (NVS_EXPECT, 22 offsety, KAT SHA1, alfabet base64, 15 x KERNEL_OFFSET_*, 69 skokow) |
| Shellcody | 3 (0607: 495 B, ap: 762 B, kernel: slot 26896 B / tresc okolo 12416 B) |
| Napisy >= 6 znakow | 1049 unikalnych (290 sensownych w `.rodata`, 34 w BLOB 4) |
| Bloki 4 kB o entropii >= 6.0 | 6 |
| Bloki 4 kB o entropii >= 7.0 | 0 |
| Odwolania do dokumentacji | 1 (`HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md`) |
| Odwolania do repozytoriow | 0 |

## 9. Ostrzezenie metodyczne dla dalszej pracy

Tabela `off_1360` w tym pliku jest zgodna co do bajtu z `tools/pprhook/include/offsets/13_60.h`
z tego repo, ale NIE z kopia w `build/kstuff-lite/kstuff-lite-main/prosper0gdb/offsets/13_60.h`.
Ta druga podaje `idt = 0x2EF4300`, a omawiany plik `0x3BB4300`. Roznica wynosi dokladnie
0xCC0000 i jest to roznica miedzy baza tekstu a baza danych jadra (repo ma na to skrypt
`tools/check-kernel-base.sh`). Przy porownywaniu offsetow z tego pliku z innymi zrodlami
trzeba najpierw ustalic, ktorej bazy dotyczy dana tabela, inaczej wynik bedzie przesuniety
o 0xCC0000.

## 10. Uwaga: pliki `tools/shellcode_*.bin` z poprzedniej sesji byly bledne

W chwili analizy w repo lezaly niezacommitowane pliki `tools/1360linux.elf`,
`tools/shellcode_0607.bin`, `tools/shellcode_ap.bin`, `tools/shellcode_kernel.bin` oraz
kilkanascie skryptow `tools/_tmp_*.py` i katalog `tools/dis/`. (Te pliki zostaly usuniete
z drzewa pracy przez inny proces w trakcie tej sesji, wiec ponizsze dotyczy ich stanu
sprzed usuniecia; wniosek metodyczny pozostaje aktualny dla kazdego, kto ekstrahowal bloby
z tego ELF.) Nie powstalem ich w tej sesji, ale sprawdzilem je, bo maja dokladnie te same
rozmiary co bloby z rozdzialu 3. Wniosek: ich TRESC byla bledna.

Dowod 1: `tools/1360linux.elf` ma ten sam SHA256 co analizowany plik (`e51a0298...`), wiec
zrodlo bylo to samo.

Dowod 2: zawartosc `tools/shellcode_0607.bin` to nie shellcode, a sekcja `.dynamic`.
Pierwsze 16 B tego pliku to `01 00 00 00 00 00 00 00 02 02 00 00 00 00 00 00`, czyli
DT_NEEDED (tag 1, wartosc 0x202), a to lezy w pliku pod offsetem 0x24000. Shellcode
`shellcode_0607_bin` ma vaddr 0x24000, ale lezy pod offsetem pliku 0x28000. Ktos uzyl
vaddr jako offsetu pliku i pominal delte 0x4000. Sprawdzone programowo:
`d[0x24000:0x24000+495]` jest bajt w bajt rowne `tools/shellcode_0607.bin`.

Dowod 3: `tools/shellcode_ap.bin` i `tools/shellcode_kernel.bin` zaczynaja sie od zer,
bo vaddr 0x24200 i 0x27D90 trafiaja w pliku w wyzerowany padding miedzy `.dynamic`
a `.data`. Sprawdzone programowo: `d[0x24200:0x24200+762]` rowne `tools/shellcode_ap.bin`.

Dowod 4: `tools/shellcode_kernel.bin` nie jest nawet zerami w calosci. Bajty od jego
przesuniecia +0xA0 to `e0 75 31 03 00 00 00 00 e4 01 00 00 ...`, czyli pierwszy wpis
tabeli `off_0300` z file 0x28550. Cala ta zawartosc pochodzi wiec z regionu tabel
offsetowych, a nie z BLOBU 4.

Praktyczny wniosek: jedynym wiarygodnym zrodlem tresci blobow jest `artifacts/1360linux.elf`
i offsety plikowe podane w rozdziale 3. Plikow `tools/shellcode_*.bin` nie nalezy uzywac
do dalszej analizy ani do porownan. Regula przeliczania: `offset_pliku = vaddr + 0x4000`
dla KAZDEJ sekcji alokowanej (`.text`, `.rodata`, `.dynamic`, `.data.rel.ro`, `.data`),
bo program headery zajmuja pierwsze 0x4000 B pliku. Sekcje niealokowane (`.symtab`,
`.strtab`, `.shstrtab`, `.comment`) maja wlasne offsety i `addr = 0`.
