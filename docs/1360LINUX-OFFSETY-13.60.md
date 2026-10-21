# 1360linux.elf: wszystkie offsety jadra 13.60, z dowodami

Notatka odpowiada na piec pytan z zadania: jakie stale jadra sa w `1360linux.elf`,
jak sie maja do naszych notatek, co jest nowe, czy offsety leza w jednej tablicy,
oraz zapisuje kazde twierdzenie z dowodem (offset w pliku, bajty albo wynik na zrzucie).

## 0. Material i metoda

- Plik: `1360linux.elf`, 237 448 B, sha256
  `e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226`.
  Identyczna kopia lezy juz w repo jako `artifacts/1360linux.elf` (ten sam sha256),
  wiec wszystko ponizej odnosi sie do obu.
- To ELF64 x86-64 PIE, `Type: DYN`, **nietkniety** (`.symtab`, 781 symboli), clang 18.1.3, LLD 18.1.3.
  Symbole sa kluczowe: `off_1360`, `env_offset`, `hv_defeat_13xx`, `derive_H`,
  `shellcode_kernel_bin`, `prepare_sck_args`, `KERNEL_CODE_CAVE` (jako napis).
- Praca: WSL (Debian), `objdump`, `readelf`, skrypty w Pythonie w `/root/linux-elf-offsety/`.
- **Regula offsetu w pliku**: dla wszystkich sekcji alokowanych `offset_w_pliku = VA + 0x4000`
  (segmenty: `0x0 -> 0x4000`, `0x18000 -> 0x1c000`, `0x24000 -> 0x28000`).
  Dlatego np. tablica `off_1360` ma VA `0x27bb0`, a w pliku lezy pod `0x2bbb0`.
- **Weryfikacja na zrzucie**: `artifacts/kernel-1360-13.60.bin` (64 MB, sha256
  `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804`).
  Konwencja repo: `VA = 0xffffffffc0c60000 + offset_w_pliku`, czyli offset w pliku jest
  jednoczesnie offsetem od bazy tekstu jadra (`ktext`). Baza danych `kdata = ktext + 0xCC0000`.
- Uzyte oznaczenia: `env+N` to pole N tablicy `off_1360` (kopia w `env_offset`).
  Wszystkie offsety w tabeli sa **wzgledne wobec ktext**, chyba ze napisane inaczej.

Test, ktory wiaze plik ze zrzutem i rozstrzyga konwencje baz (dowod, nie zalozenie):

    bramka w hv_defeat_13xx (VA 0x37d0, plik 0x77d0) czyta 7 qword pod
    ktext + env[0x1d0] i porownuje z NVS_EXPECT (VA 0x1f2a0, plik 0x232a0)
    = {0x2300, 0x200, 0x200, 0x0, 0x2000, 0x800, 0x1000}
    W calym 64 MB zrzucie ten ciag wystepuje DOKLADNIE RAZ, pod offsetem 0x1a1a030,
    i env[0x1d0] = 0x1a1a030. To dowodzi, ze offset w pliku zrzutu = offset od ktext
    uzywany przez payload, czyli ze oba zbiory liczb sa bezposrednio porownywalne.

## 1. Odpowiedz na pytanie 4: TAK, jest jedna tablica offsetow

Offsetow **nie ma rozsianych po kodzie**. Payload trzyma je w jednej tablicy na firmware:

- `off_0300`, `off_0310`, ... `off_1300`, `off_1360`: 29 tablic po `0x1E0` = 480 B
  (60 pol po 8 B) w sekcji `.data`, od VA `0x24550` do `0x27d90`.
- `off_1360`: VA `0x27bb0`, plik `0x2bbb0`, 480 B. To **caly zestaw stalych 13.60**.
- `set_offsets` (VA 0x97f0, plik 0xd7f0) wybiera tablice po wersji firmware:
  `if (fw == 0x1360) memcpy(env_offset, off_1360, 0x1E0)`. Wersje sa wpisane na sztywno jako
  ciag `sub eax,0x300 / sub eax,0x310 / ...` (dowody w tym samym bloku, np. `0x9a3b: sub eax,0x1360`,
  `0x9d5a: memcpy(env_offset, off_1360)`).
- `env_offset` to `OBJ .bss`, VA `0x6eff8`, rozmiar 480 B, czyli dokladnie kopia tablicy.
- Wyjatek, ktory trzeba znac: **off_1360 nie jest jedynym zrodlem stalych 13.60**. Drugie,
  niezalezne zrodlo to blok `if (fw == 0x1360)` w `__kernel_init` (adresy danych, patrz rozdzial 4),
  a trzecie to stale wpisane na sztywno w shellcode jadra (rozdzial 6). Reszta kodu nie zawiera
  ani jednego bezwzglednego adresu jadra (dowod w rozdziale 9).

## 2. Bazy obrazu kodu i danych, ktorych uzywa payload

Payload **nie zna zadnej bezwzglednej bazy jadra**. Baze danych dostaje w argumentach:

    __kernel_init (VA 0xdc00, plik 0x11c00):
      0xdc79: mov rax,[rdi+0x20]        ; arg[0x20] = baza danych
      0xdc7d: lea rcx,[rip+...]  # KERNEL_ADDRESS_DATA_BASE (.bss VA 0x70778)
      0xdc84: mov [rcx],rax
      0xdc87: test rax,rax ; je blad 0xfffffff2 (gdy baza = 0)

    Blok 13.60 (VA 0xddeb, plik 0x11deb), po porownaniu (fw & 0xffff0000) == 0x13600000
    (VA 0xddde, plik 0x11dde):
      KERNEL_ADDRESS_TEXT_BASE = KERNEL_ADDRESS_DATA_BASE - 0xCC0000
      KERNEL_ADDRESS_ALLPROC   = DATA_BASE + 0x28C9E80
      KERNEL_ADDRESS_SECURITY_FLAGS = DATA_BASE + 0xD9C064
      KERNEL_ADDRESS_ROOTVNODE = DATA_BASE + 0x314B510
      KERNEL_ADDRESS_BUS_DATA_DEVICES = DATA_BASE + 0x2098228
      (ogolny ogon bloku, VA 0xe791) KERNEL_OFFSET_VMSPACE_P_ROOT = 0x1D0,
      KERNEL_OFFSET_VMSPACE_VM_PMAP = 0x2E8

Stale danych sa liczone **identycznie jak w naszych materialach**: kstuff-lite
`build/kstuff-lite/.../prosper0gdb/offsets/13_60.h` podaje `DEF(allproc, 0x28C9E80)`
(data-relative), a nasza notatka `notes/STAN-KONCOWY-KSTUFF-NG.md` (linia 21) uzywa tej samej
arytmetyki `0xCC0000 - 0x71B9F0 = 0x5A4610` (czyli `kdata - N`). Payload liczy dokladnie tak samo.

Weryfikacja na zrzucie (offset = wartosc z payloadu przeliczona na ktext):

| pole | ktext + | w zrzucie | dowod |
|---|---|---|---|
| ALLPROC | 0x3589E80 | `0xffffbd62cb3da6d0` | niezerowy wskaznik kanoniczny, czyli LIST_HEAD zyje |
| SECURITY_FLAGS | 0x1A5C064 | `0x0100000000000017` | sensowna maska flag (bity 0,1,2,4) |
| ROOTVNODE | 0x3E0B510 | `0xffffbd5a01956940` | wskaznik na vnode |
| BUS_DATA_DEVICES | 0x2D58228 | `0xffffbd5a0176e300` | wskaznik na pierwszy wpis listy |

Uwaga do nazw pol VMSPACE: w ogonie `__kernel_init` (VA 0xe791) nazwy sa przypisane tak:
`[KERNEL_OFFSET_VMSPACE_P_ROOT] = rdx = 0x1D0`, `[KERNEL_OFFSET_VMSPACE_VM_PMAP] = rcx = 0x2E8`.
Zuzycie w kodzie potwierdza, ze nazwy sa wlasciwe:
`kernel_get_vmem_entry` (VA 0x10250) czyta `*(vmspace + [P_ROOT])`, a
`kernel_proc_getpaddr` (VA 0x13ec0) liczy `pmap = vmspace + [VM_PMAP]` i chodzi po tablicach stron.
Czyli dla 13.60: **vm_root = 0x1D0, pmap (wbudowany) = 0x2E8**, a `proc + 0x200 = vmspace`.

Dodatkowo, trzeci sposob dojscia do pmap: `getpmap` (VA 0x9e80) robi
`pmap = kread64(vmspace + env[0x10])`, a `env[0x10] = 0x1D8`. Skoro dla tego samego pmap
`__kernel_init` czyta `vmspace + 0x2E8`, pole `0x1D8` jest **wskaznikiem** do wbudowanego pmap
(vm_map.pmap), a nie pmapem. To nowy offset struktury (u nas nieudokumentowany).

Mapa bezposrednia jest wyliczana, nie wpisana:

    __kernel_init, VA 0xe860..0xea38:
      proc0 = kernel_get_proc(0)
      vmspace = kread64(proc0 + 0x200)
      a = kread64(vmspace + [VM_PMAP] + 0x20)
      b = kread64(vmspace + [VM_PMAP] + 0x28)
      KERNEL_ADDRESS_DMAP_BASE = a - b
    init_global_vars (VA 0x9da0) robi to samo przez getpmap:
      pmap = kread64(vmspace + 0x1D8); cr3 = kread64(pmap + 0x28); dmap = kread64(pmap + 0x20) - cr3
    a w hv_defeat_13xx (VA 0x3b20) cr3 idzie do kh_set_resume_rdx, a dmap + 0x3ffff000
    do kh_set_resume_rsi (strona "carrier").

## 3. Tablica off_1360: wszystkie 60 pol

Adresy pol: `plik = 0x2bbb0 + N`. "Dowod" to zachowanie bajtow w zrzucie pod `ktext + wartosc`.

### 3.1 Pola tablicy: adresy kodu i danych

Pola sprawdzane przez `offsets_present` (VA 0x3e70) to trzy grupy: 20 pol
`{0x20, 0x28, 0x30, 0x58, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xB8, 0x138, 0x140, 0x148, 0x150,
0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8}` (zero w ktoryms konczy prace), 7 pol
`{0x158, 0x160, 0x168, 0x178, 0x180, 0x188, 0x190}` i 2 pola `{0x1C0, 0x1C8}`.
Pola spoza tych trzech grup (miedzy innymi `0x00`, `0x08`, `0x10`, `0x18`, `0x60`, `0xC0` do `0x130`)
nie sa sprawdzane, ale sa uzywane przez kod. Pominiecie `0x60` w kontroli jest warte uwagi:
to gadzet pivota o nazwie `GAD_ADD_RSP_28..RBP`, bez ktorego lancuch ROP nie ma jak wrocic.
Gdy ktorekolwiek z 20 pol grupy pierwszej jest zerem, `hv_defeat_13xx` (VA 0x37e3) konczy prace
napisem `13.60 offsets are incomplete - refusing to arm.` (VA 0x1e5f9, plik 0x225f9).

| pole | wartosc | plik | znaczenie i dowod |
|---|---|---|---|
| env+0x00 | 0x3543A70 | 0x2bbb0 | globalna ze wskaznikiem IOMMU softc. W zrzucie pod ktext+0x3543A70 lezy `0xffffff8005768000` = wskaznik softc. To ta sama komorka, ktora nasza notatka `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md` (linia 65) opisuje jako "obraz + 0x3543A70". Uzywana w `prepare_sck_args` (argument SCK) |
| env+0x08 | 0x1EC | 0x2bbb8 | offset struktury, nie adres. `gpu_init` (VA 0x670) pakuje go do `s_gpu_offsets` jako pole 2 |
| env+0x10 | 0x1D8 | 0x2bbc0 | offset wskaznika na pmap w vmspace. Dowod: `getpmap` (VA 0x9e80) robi `kread64(vmspace + env[0x10])` |
| env+0x18 | 0x3BAA570 | 0x2bbc8 | adres danych dla GPU. `gpu_init` wklada do `s_gpu_offsets`; w zrzucie pod tym offsetem leza zera i slowo `0x000000FC` |
| env+0x20 | 0x39C9490 | 0x2bbd0 | struktura danych, ktora payload nadpisuje soba: `hv_defeat_13xx` (VA 0x3e36) robi `kwrite64(ktext+env[0x20], ktext+env[0x20]-8)`. W zrzucie tablica wskaznikow i rozmiarow (`0xffffbd5a7fd6e000`, `0x1000`, `0x9bf6000`) |
| env+0x28 | 0x3BB4300 | 0x2bbd8 | **IDT_ARRAY**. W zrzucie 16-bajtowe bramy: selektor 0x20, typ 0x8e, obsluga `0xffffffffc0eca300`. Identyczne z `KERNEL_SYM_IDT_ARRAY` w `tools/pprhook/include/offsets/13_60.h` i z `DEF(idt, 0x2EF4300)` + 0xCC0000 |
| env+0x30 | 0x3BB6FE0 | 0x2bbe0 | **COMMON_TSS**. W zrzucie rsp0 = `0xffffff805c423a40`. Identyczne z `KERNEL_SYM_COMMON_TSS` i z `DEF(tss_array, 0x2EF6FE0)` + 0xCC0000 |
| env+0x58 | 0x2590B0 | 0x2bc08 | **FUN_MEMCPY** (nazwa z napisu etykiety). Bajty: `55 48 89 e5 49 89 fa 49 01 d2 72 19`, czyli prolog funkcji kopiujacej |
| env+0x60 | 0x9E32B4 | 0x2bc10 | **GAD_ADD_RSP_28..RBP**. Bajty: `48 83 c4 28 5d c3` |
| env+0x68 | 0x257B3D | 0x2bc18 | **iretq**. Bajty: `48 cf`. Ten sam adres co `DEF(doreti_iret, -0xA684C3)` w kstuff-lite po przeliczeniu `kdata - 0xA684C3` |
| env+0x70 | 0xB8CA6E | 0x2bc20 | `pop rax ; ret` = `58 c3` (bajt +1 od gadzetu POP_R8) |
| env+0x78 | 0x28CE6D | 0x2bc28 | `pop rdi ; ret` = `5f c3` |
| env+0x80 | 0x34CB91 | 0x2bc30 | `pop rsi ; ret` = `5e c3` |
| env+0x88 | 0x2A0F7B | 0x2bc38 | `pop rdx ; ret` = `5a c3` |
| env+0x90 | 0x2918B2 | 0x2bc40 | `pop rcx ; ret` = `59 c3` |
| env+0x98 | 0xB8291B | 0x2bc48 | `pop rsp ; ret` = `5c c3` |
| env+0xB8 | 0xCB92C0 | 0x2bc68 | **KERNEL_CODE_CAVE**. W zrzucie ciag `90 90 90 ...` (NOP-y). Wymagane: `prepare_resume` (VA 0x8f97) przy zerze konczy prace napisem `Error: missing code cave offset` (VA 0x1e03b). `hv_defeat_0304` pisze do niej `kwrite_large` |
| env+0xF8 | 0x21F9598 | 0x2bca8 | etykieta **kernel_uart_override**. W zrzucie komorka `{0x20, 0x0, 0xffffffffc2e594d8}` |
| env+0x100 | 0x44F8C0 | 0x2bcb0 | etykieta **kernel_cfi_check**, prolog funkcji (`55 48 89 e5 41 57 41 56 53 50`). Shellcode jadra wpisuje tam `0xC3` (RET), komunikat `SCK>4-cfi-patched` |
| env+0x138 | 0xC16EE0 | 0x2bce8 | **HV_MP_STARTUP_CALL**. W zrzucie funkcja z `mov eax,0xf ; vmcall` (`0f 01 d9`). Identyczne z `KERNEL_SYM_HV_MP_STARTUP_CALL` w naszym 13_60.h |
| env+0x140 | 0x269FB8 | 0x2bcf0 | **MP_STARTUP_INIT_VECTOR**. W zrzucie `e9 83 8a fe ff` (jmp) + `cc` padding. Identyczne z `KERNEL_SYM_MP_STARTUP_INIT_VECTOR` |
| env+0x148 | 0x2D39000 | 0x2bcf8 | **DATA_CAVE**. W zrzucie 0x4000 B zer. Identyczne z `KERNEL_SYM_DATA_CAVE` i z etykieta `DATA_CAVE` w napisach |
| env+0x150 | 0x25213E | 0x2bd00 | pivot `add rsp,0x28 ; rep ret` = `48 83 c4 28 f3 c3` |
| env+0x158 | 0xB8CA6D | 0x2bd08 | `pop r8 ; ret` = `47 58 c3` |
| env+0x160 | 0x474389 | 0x2bd10 | `mov [rcx],r8 ; ret` = `4c 89 01 c3` |
| env+0x168 | 0x32693F | 0x2bd18 | `mov [rdi+8],rcx ; ret` = `48 89 4f 08 c3` |
| env+0x178 | 0xA07BA6 | 0x2bd28 | `mov dr7,rax ; mov eax,r8d ; ret` = `0f 23 f8 44 89 c0 c3` |
| env+0x180 | 0x82B915 | 0x2bd30 | `mov [rcx],rdx ; ret` = `48 89 11 c3` |
| env+0x188 | 0x2BB28F | 0x2bd38 | `mov [rcx],rax ; xor eax,eax ; ret` = `48 89 01 31 c0 c3` |
| env+0x190 | 0x8E3A44 | 0x2bd40 | `mov rax,rsi ; ret` = `48 89 f0 c3` |
| env+0x198 | 0xBECDEA | 0x2bd48 | `mov rax,rdi ; ret` = `48 89 f8 c3` |
| env+0x1A0 | 0x25D027 | 0x2bd50 | `rep movsb ; nop ; rep ret` = `f3 a4 66 90 f3 c3` |
| env+0x1A8 | 0x30644F | 0x2bd58 | `cld ; ret` = `fc c3` |
| env+0x1B0 | 0x2912A2 | 0x2bd60 | `ret` = `c3` |
| env+0x1B8 | 0x2529D8 | 0x2bd68 | `mov dr0,rax` + ogon wznawiania (`0f 23 c0 48 8b 87 80 00 00 00`) |
| env+0x1D0 | 0x1A1A030 | 0x2bd80 | bramka wersji (7 qword = NVS_EXPECT, unikat w zrzucie) |

### 3.2 Pola niekrytyczne i puste

| pole | wartosc | plik | rola |
|---|---|---|---|
| env+0x38, +0x40, +0x48, +0x50 | 0 | 0x2bbe8..0x2bc00 | cztery adresy ROP uzywane tylko w galezi "bit set" w `build_gp_rop` / `build_ipi_rop` (VA 0x20ca sprawdza `esi != 0`). **Dla 13.60 puste** |
| env+0xA0 | 0x255034 | 0x2bc50 | `wrmsr ; ret` = `0f 30 c3`. Ten sam adres co `DEF(wrmsr_ret, -0xA6AFCC)` w kstuff-lite |
| env+0xA8 | 0x3D3F2A | 0x2bc58 | `mov [rdi],rsi ; pop rbp ; ret` = `48 89 37 5d c3` |
| env+0xB0 | 0 | 0x2bc60 | uzywane tylko przez `hv_defeat_0304` (firmware 3.04), dla 13.60 puste |
| env+0xC0 | 0x25D410 | 0x2bc70 | **kotwica shellcode jadra**: `SCK` ustawia `[0x6908] = ktext + env[0xC0]` i dodaje do niej swoje offsety inline (rozdzial 6). W zrzucie `e9 4b 09 25 00 cc cc cc`, czyli thunk `jmp` |
| env+0xC8 | 0xC16B00 | 0x2bc78 | funkcja z `mov eax,6 ; vmcall` (VMCALL 6). SCK wola ja jako `[argi+0x28]` |
| env+0xD0 | 0xC16A40 | 0x2bc80 | funkcja z `mov eax,0xa ; vmcall` (VMCALL 0xA). SCK wola ja jako `[argi+0x30]` |
| env+0xD8 | 0xB03BA0 | 0x2bc88 | trampolina `mov r8,rcx ; ... ; mov rdi,[rip+...] ; pop rbp ; jmp rel32` |
| env+0xE0 | 0x261E08 | 0x2bc90 | thunk `jmp rel32` + `cc` padding |
| env+0xE8 | 0x62806F00 | 0x2bc98 | wartosc surowa przekazywana do SCK (pole +0x88); ten build SCK jej nie czyta |
| env+0xF0 | 0x62847375 | 0x2bca0 | wartosc surowa przekazywana do SCK (pole +0x80); nieczytana |
| env+0x108 | 0x3DDB9F0 | 0x2bcb8 | dane (w zrzucie `55 aa 69 e9 ...`), pole +0x60 argumentow SCK |
| env+0x110 | 0xC0EAA0 | 0x2bcc0 | funkcja (prolog `55 48 89 e5 41 56 53 41 89 fe`), pole +0x48 |
| env+0x118 | 0xA14130 | 0x2bcc8 | funkcja dotykajaca MMIO `0x05210550` i `0x05210544` (zapis `0x50000`), pole +0x50 |
| env+0x120 | 0xA12D30 | 0x2bcd0 | funkcja z ramka `0xA48`, pole +0x58 |
| env+0x128 | 0x1518160 | 0x2bcd8 | **VA firmware'u WiFi w jadrze**. W zrzucie kod ARM 32-bit (`1c f0 9f e5` = `ldr pc,[pc,#0x1c]`). `dump_ps5_wifi_firmware` zapisuje go jako `nxp/pcieuartiw620_combo_v1.bin` |
| env+0x130 | 0x7A248 | 0x2bce0 | rozmiar tego firmware'u (500 040 B) |
| env+0x170 | 0x321EA0 | 0x2bd20 | `or [rcx],eax ; ret` = `09 01 c3` |
| env+0x1C0, +0x1C8 | 0 | 0x2bd70, 0x2bd78 | dwa opcjonalne gadzety (indeksy 21 i 22 wlasnej tablicy `kgadget`, VA 0x5570, tablica przeskokow VA 0x1f2d8). Dla 13.60 puste, `offsets_present` traktuje je jako nieobowiazkowe |
| env+0x1D8 | 0x3DF1070 | 0x2bd88 | slot deskryptora HV dla `derive_H` (VA 0x4390). W zrzucie `0xffffffffc4a94000` = wskaznik kanoniczny, dalej `0xffffffffc1f6f921` |

Rachunek pol: 60 wszystkich, 53 niezerowe, 7 zerowych (`0x38, 0x40, 0x48, 0x50, 0xB0, 0x1C0, 0x1C8`).
Wsrod niezerowych: 48 to offsety/adresy jadra, 5 to wartosci nieadresowe
(`0x1EC`, `0x1D8`, rozmiar `0x7A248`, surowe `0x62806F00` i `0x62847375`).

Szesc pol ma wlasne etykiety wypisywane przez `dump_text_perm` (VA 0x41f0):
`kernel_uart_override` (env+0xF8), `kernel_cfi_check` (env+0x100), `KERNEL_CODE_CAVE` (env+0xB8),
`GAD_ADD_RSP_28..RBP` (env+0x60), `FUN_MEMCPY` (env+0x58), `DATA_CAVE` (env+0x148)
oraz `CARRIER_PA via dmap` (dmap + 0x3ffff000). Napisy etykiet sa pod VA 0x1df57, 0x1e244,
0x1e65c, 0x1e439, 0x1ed87, 0x1e99f, 0x1e858.

## 4. Drugie zrodlo stalych 13.60: blok w __kernel_init

`__kernel_init` (VA 0xdc00, plik 0x11c00) zawiera rozgalezienie po `(fw & 0xffff0000)` i dla kazdej
wersji komplet stalych danych. Dla 13.60 (`0x13600000`, skok z VA 0xddde) blok lezy pod
VA 0xddeb do 0xde3f (plik 0x11deb do 0x11e3f) i podaje (wszystko wzgledem DATA_BASE):

    delta tekstu   -0xCC0000
    allproc        +0x28C9E80
    security_flags +0xD9C064
    rootvnode      +0x314B510
    bus_data_devices +0x2098228
    (ogolny ogon, VA 0xe791) vm_root 0x1D0, pmap 0x2E8 wedlug nazw symboli

Po przeliczeniu na ktext (dodaj 0xCC0000): ALLPROC 0x3589E80, SECURITY_FLAGS 0x1A5C064,
ROOTVNODE 0x3E0B510, BUS_DATA_DEVICES 0x2D58228. Wszystkie cztery potwierdzone w zrzucie
(rozdzial 2), choc **zadnego z nich nie ma w tablicy off_1360**.

Dla porzadku, sasiednie wersje 13.xx pokazuja, jak waskie sa to roznice (dowodzi, ze stale sa
wersjonowane i nie da sie ich przenosic miedzy 13.40 i 13.60):

| fw | delta tekstu | allproc | security_flags | rootvnode |
|---|---|---|---|---|
| 13.00 / 13.20 | -0xCB0000 | +0x28C5E00 | +0xD99064 | +0x3133510 |
| 13.40 / 13.42 | -0xCB0000 | +0x28C9E80 | +0xD99064 | +0x3137510 |
| **13.60** | **-0xCC0000** | **+0x28C9E80** | **+0xD9C064** | **+0x314B510** |

Payload zna tez wiele innych wersji: w rozgalezieniu jest 98 porownan `cmp r14d,0x...`
(klucze dokladne i granice zakresow), od `0x1000000` do `0x13600000`, obejmujac
2.00 do 2.70, 3.00 do 3.21, 4.00 do 4.51, 5.00 do 5.50, 6.00 do 6.50, 7.00 do 7.61,
8.00 do 8.40, 9.00 do 9.60, 10.00 do 10.60, 11.00 do 11.40, 12.00 do 12.70, 13.00 do 13.60.

Pochodne stalych (wyliczane, nie wpisane):

    PRISON0        = kread64( proc0 + 0x40 ) + 0x30        (ucred, pole cr_prison)
    TARGETID       = SECURITY_FLAGS + 0x9
    QA_FLAGS       = SECURITY_FLAGS + 0x24
    UTOKEN_FLAGS   = SECURITY_FLAGS + 0x8C
    IOMMU_SOFTC    = skan w dol od ALLPROC do DATA_BASE+8: kandydat musi byc wskaznikiem
                     kanonicznym, 8-aligned, z niezerowym i nie-0xffff srodkiem, oraz
                     miec kread64(kandydat + 0x48) == 0xFDD80000
    DMAP_BASE      = kread64(pmap + 0x20) - kread64(pmap + 0x28)

## 5. Offsety struktur jadra ( KERNEL_OFFSET_* ) i stale PTE

Stale w `.rodata`, kazda 8-bajtowa, plik = VA + 0x4000. Sa to offsety pol **struktur jadra**,
nie adresy:

| symbol | VA | plik | wartosc |
|---|---|---|---|
| KERNEL_OFFSET_PROC_P_UCRED | 0x1f3b8 | 0x233b8 | 0x40 |
| KERNEL_OFFSET_PROC_P_FD | 0x1f3c0 | 0x233c0 | 0x48 |
| KERNEL_OFFSET_PROC_P_PID | 0x1f3c8 | 0x233c8 | 0xBC |
| KERNEL_OFFSET_PROC_P_VMSPACE | 0x1f3d0 | 0x233d0 | 0x200 |
| KERNEL_OFFSET_UCRED_CR_UID | 0x1f3d8 | 0x233d8 | 0x04 |
| KERNEL_OFFSET_UCRED_CR_RUID | 0x1f3e0 | 0x233e0 | 0x08 |
| KERNEL_OFFSET_UCRED_CR_SVUID | 0x1f3e8 | 0x233e8 | 0x0C |
| KERNEL_OFFSET_UCRED_CR_RGID | 0x1f3f0 | 0x233f0 | 0x14 |
| KERNEL_OFFSET_UCRED_CR_SVGID | 0x1f3f8 | 0x233f8 | 0x18 |
| KERNEL_OFFSET_UCRED_CR_PRISON | 0x1f400 | 0x23400 | 0x30 |
| KERNEL_OFFSET_UCRED_CR_SCEAUTHID | 0x1f408 | 0x23408 | 0x58 |
| KERNEL_OFFSET_UCRED_CR_SCECAPS | 0x1f410 | 0x23410 | 0x60 |
| KERNEL_OFFSET_UCRED_CR_SCEATTRS | 0x1f418 | 0x23418 | 0x80 |
| KERNEL_OFFSET_FILEDESC_FD_RDIR | 0x1f420 | 0x23420 | 0x10 |
| KERNEL_OFFSET_FILEDESC_FD_JDIR | 0x1f428 | 0x23428 | 0x18 |

Dwie dalsze sa w `.bss` (ustawiane per firmware w `__kernel_init`): `KERNEL_OFFSET_VMSPACE_P_ROOT`
(VA 0x707d0) i `KERNEL_OFFSET_VMSPACE_VM_PMAP` (VA 0x707d8).
Cztery symbole (`PROC_P_UCRED`, `PROC_P_FD`, `FILEDESC_FD_RDIR`, `FILEDESC_FD_JDIR`) w tym pliku
**nie maja zadnego uzycia** (dowód: brak odwolan do ich adresow w `disasm.txt`), sa balastem
z biblioteki `mdbg`. Uzywane sa: `PROC_P_PID` (kernel_get_proc), `PROC_P_VMSPACE` (gpu_init,
getpmap, kernel_proc_getpaddr), `PROC_P_UCRED` przez stala 0x40 wpisana w kod (kernel_get_ucred).

Stale tablic stron i pamieci fizycznej (bity i poziomy):

| stale | gdzie | znaczenie |
|---|---|---|
| `0x27, 0x1e, 0x15, 0xc` z maska `0x1ff` i `shl 3` | `install_page` (VA 0xa900), `page_remove_global` (VA 0xa2f0), `kernel_proc_getpaddr` | indeksy PML4, PDPT, PD, PT (4 poziomy, wpisy 8 B) |
| `or 0x1`, `or 0x2` | `install_page` | bit P i RW nowego wpisu |
| `0x80` | `page_chain_set_rw`, `page_remove_global` | bit PS (strona 2 MB / 1 GB) |
| `and 0xfffffffffffffeff` | `page_remove_global` | czyszczenie bitu G (global) |
| `and 0xfff` | `page_remove_global` | dolne 12 bitow wpisu |
| `0x8000000000000000`, `0x7fffffffffffffff` | `clear_execute_disable` (VA 0x4390, 0x46f0 i 0x47a8/0x47c0), `dump_pte_bits` | bit NX i jego maska |
| zakres `ktext` do `kdata` | `remove_xotext` (VA 0x8dd0) | petla po 0x1000 od ktext do kdata (0xCC0000 = 3072 strony), dla kazdej `page_chain_set_rw` |
| `0x3ffff000` | `dump_text_perm`, `hv_defeat_13xx`, `build_sx_rop` | strona "carrier" w mapie bezposredniej (`dmap + 0x3ffff000`, etykieta `CARRIER_PA via dmap`) |

Sekwencja `0xffff800000000000` i jej pochodne to **adresy jadra wpisane na sztywno**
(jedyne bezwzgledne adresy w calym pliku, poza maskami):

| wartosc | plik (VA) | uzycie |
|---|---|---|
| 0xffff800000000000 | 0x2635 (build_gp_rop), 0x3646 i 0x4b10 (build_sx_rop), 0x9082 (prepare_resume) | baza mapowania shellcode jadra: `install_page_syscore(0xffff800000000000 + off, phys, 0)` dla kazdych 0x4000 |
| 0xffff800000008000 | 0x2ec5 (hv_defeat_0607), 0x31b7 (build_gp_rop) | przesuniecie w tym samym obszarze |
| 0xffff80000000c000 | 0x88f8, 0x89ce (fetch_linux) | jak wyzej |
| 0xffff800000010000 | 0x8909, 0x893f (fetch_linux) | jak wyzej |

## 6. Struktury i stale shellcode jadra (shellcode_kernel_bin)

`shellcode_kernel_bin`: `OBJ .data`, VA 0x27d90, 26 896 B (`0x6910`), plik 0x2bd90 do 0x326a0.
To nie jest kod PIE: pierwsza instrukcja to `movabs rbx,0x11AA11AA11AA11AA`, a `prepare_resume`
(VA 0x8f80) i `update_sck_args_ptr` (VA 0x93e0) podmieniaja ten magiczny qword na adres struktury
argumentow (magic lezy w pliku pod 0x2bd9a). Wewnatrz bloku:

- slot `[0x6908]` dostaje `ktext + env[0xC0]` (dowod: funkcja VA 0x13a0 kopiuje 0x98 B argumentow
  do 0x6860 i robi `mov [0x6908], [0x6880]`, a 0x6880 = 0x6860 + 0x20 = pole argumentow +0x20,
  ktore `prepare_sck_args` wypelnia jako `ktext + env[0xC0]`).
- **tablica operacji HDMI**: blob + 0x3080 (VA 0x2ae10, plik 0x2ee10), 29 wpisow po 0x18 B,
  `{u64 offset_od_ktext, u32 arg, u32 tryb, u64 arg2}`. Dyspozytor (blob + 0x5d0) liczy
  `cel = [0x6908] + wpis - 0x25D410`, czyli `ktext + wpis`. Wszystkie 26 unikalnych wartosci
  trafiaja w zrzucie w prolog funkcji (`55 48 89 e5`), co dowodzi konwencji:

      0x2BB8D0 0x2BBB20 0x2BBC70 0x2BBE30 0xBAECD0 0x28B970 0x6D4F00 0xA8F0D0
      0x4B12D0 0x4B14C0 0x2BBC40 0xB1BA50 0xB1C5B0 0xB1C7C0 0xB1C900 0x28CB20 (argi 0..3)
      0x2BBE60 0x4B1690 0x4B1810 0xB1BB40 0x6DA070 0x968DF0 (tryb 2, arg2 = 0x7F0)
      0x4B6AF0 0x4B2570 0x4B1FE0 0x4B1E80

  Te 26 offsetow to zestaw "13.60-only"; o innych firmware payload pisze
  `SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x` (blob + 0x3038) i w ogole nie
  wchodzi w petle operacji.
- **offsety inline** dodawane do `[0x6908]`: 0x70B990, 0x7E2080, 0x70B9B0, 0x8FA4D0, 0x8FA5E0.
  Po dodaniu kotwicy 0x25D410 daja offsety od ktext: **0x968DA0, 0xA3F490, 0x968DC0,
  0xB578E0, 0xB579F0** (cztery z pieciu to prologi funkcji w zrzucie; 0xA3F490 zaczyna sie od
  `80 3d 21 ff`, wiec jest cialem funkcji).
- stale wewnetrzne: `0x3AC4458` (+ kotwica = ktext + 0x3D21868) to komorka wskaznika do HV,
  `0x705F`, `0x6070`, `0x60F9`, `0x6208` to indeksy rejestrow NVS/VBIOS uzywane przez funkcje
  z ktext + 0x70B990 / 0x7E2080 / 0x70B9B0 (po korekcie: 0x968DA0, 0xA3F490, 0x968DC0),
  a `0x83028` i `0x82A60` to offsety od bazy HV (heap i pcpus).
- argumenty (`prepare_sck_args`, VA 0x9130, 0x98 B) i to, co SCK z nich czyta:
  `+0x00` fw, `+0x08` ktext, `+0x10` kdata, `+0x18` dmap, `+0x20` = ktext + env[0xC0],
  `+0x28` = ktext + env[0xC8] (VMCALL 6), `+0x30` = ktext + env[0xD0] (VMCALL 0xA),
  `+0x78` = ktext + env[0x100] (patch `ret` na kernel_cfi_check).
  Pola `+0x38 +0x40 +0x48 +0x50 +0x58 +0x60 +0x68 +0x70 +0x80 +0x88 +0x90` sa wypelniane
  (adresy z env+0xD8, +0xE0, +0x110, +0x118, +0x120, +0x108, +0x00, +0xF8, oraz surowe
  env+0xF0, env+0xE8 i `linux_i`), ale **ten build shellcode ich nie czyta** (brak odwolan
  do nich). To niedokonczony kontrakt ABI.
- dwa inne bloki: `shellcode_ap_bin` (VA 0x24200, 762 B, plik 0x28200) wgrywany do
  `ktext + env[0x148] + 0x1000`, oraz `shellcode_0607_bin` (VA 0x24000, 495 B, plik 0x28000)
  dla firmware 6.07.

## 7. Zgodnosci z tym, co mamy udokumentowane

### 7.1 Z `tools/pprhook/include/offsets/13_60.h` i `tools/mp4cmd/include/offsets/13_60.h`

Te same pliki, te same wartosci (rozne kopie w drzewie). Zgodnosc pelna:

| symbol w naszym 13_60.h | wartosc | pole w payloadzie |
|---|---|---|
| KERNEL_SYM_HV_MP_STARTUP_CALL | 0xC16EE0 | env+0x138 (identycznie) |
| KERNEL_SYM_MP_STARTUP_INIT_VECTOR | 0x269FB8 | env+0x140 (identycznie) |
| KERNEL_SYM_DATA_CAVE | 0x2D39000 | env+0x148 (identycznie) |
| KERNEL_SYM_IDT_ARRAY | 0x3BB4300 | env+0x28 (identycznie) |
| KERNEL_SYM_COMMON_TSS | 0x3BB6FE0 | env+0x30 (identycznie) |
| HV_SYM_HEAP_BASE | 0x83028 | `derive_H() + 0x83028` |
| HV_SYM_PCPUS | 0x82A60 | `derive_H() + 0x82A60` |

Gadzety: **19 z 21 adresow zgadza sie co do bajtu** (PIVOT 0x25213E, IRETQ 0x257B3D, POP_RCX
0x2918B2, POP_RDI 0x28CE6D, POP_RSI 0x34CB91, POP_RDX 0x2A0F7B, POP_R8 0xB8CA6D, STORE_RCX_R8
0x474389, STORE_RDI8_RCX 0x32693F, OR_RCX_EAX 0x321EA0, SET_DR7 0xA07BA6, ST_RCX_RDX 0x82B915,
ST_RCX_RAX 0x2BB28F, MOV_RAX_RSI 0x8E3A44, MOV_RAX_RDI 0xBECDEA, REP_MOVSB 0x25D027, CLD
0x30644F, RET_TRAMP 0x2912A2, DBREG_RESUME 0x2529D8). Roznia sie dwa, i to tylko **wyborem
miejsca, nie semantyka**: POP_RAX payload 0xB8CA6E kontra nasze 0x2912A1 (oba to `58 c3`;
0xB8CA6E = POP_R8 + 1, bajty potwierdzone) oraz POP_RSP payload 0xB8291B kontra nasze 0x291C42
(oba to `5c c3`). Siedem symboli z naszego 13_60.h nie ma odpowiednika w payloadzie
(DMPML4I 0x3B49294, DMPDPI 0x3B49298, PML4PML4I 0x3B47E4C, PMAP_STORE 0x3B48FF8, SYS_GETUID
0x2A8D60, PRINTF 0x4ADD60, ACPI_SLEEP_MACHDEP_HOOK 0x3913B0): payload
nie chodzi po pmapie recznie, tylko dostaje pmap z `vmspace + 0x2E8` i wylicza DMAP z pol pmap.

### 7.2 Z `build/kstuff-lite/.../prosper0gdb/offsets/13_60.h` (nasze narzedzie)

Ustalenie wazne dla calej konwencji: dodatnie wartosci w tym pliku sa **data-relative**,
a ujemne to `kdata - N`, czyli po przeliczeniu `ktext + (0xCC0000 - N)`. Sprawdzone na zrzucie:

| DEF w kstuff-lite | przeliczenie | ktext + | pole w payloadzie |
|---|---|---|---|
| allproc 0x28C9E80 | + 0xCC0000 | 0x3589E80 | `__kernel_init`, to samo |
| idt 0x2EF4300 | + 0xCC0000 | 0x3BB4300 | env+0x28, to samo |
| tss_array 0x2EF6FE0 | + 0xCC0000 | 0x3BB6FE0 | env+0x30, to samo |
| kernel_pmap_store 0x2E88FF8 | + 0xCC0000 | 0x3B48FF8 | brak w payloadzie, ale zgodne z PMAP_STORE z 7.1 |
| doreti_iret -0xA684C3 | 0xCC0000 - N | 0x257B3D (bajty `48 cf` = iretq) | env+0x68, to samo |
| wrmsr_ret -0xA6AFCC | 0xCC0000 - N | 0x255034 (bajty `0f 30 c3`) | env+0xA0, to samo |
| sceSblServiceMailbox -0x71B9F0 | 0xCC0000 - N | 0x5A4610 (prolog funkcji) | brak w payloadzie, zgodne z linia 21 `STAN-KONCOWY-KSTUFF-NG.md` |
| rep_movsb_pop_rbp_ret -0xA663D6 | 0xCC0000 - N | 0x259C2A (`f3 a4 5d c3`) | payload ma inny, tez poprawny: env+0x1A0 = 0x25D027 (`f3 a4 66 90 f3 c3`) |
| rdmsr_start -0xA69BFA | 0xCC0000 - N | 0x256406 (`0f 32` = rdmsr) | brak |
| mov_rax_cr0 -0xA6DE01 | 0xCC0000 - N | 0x2521FF (`0f 20 c0 0c 08 0f 22 c0`) | brak |

### 7.3 Z `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md`

- Globalna ze wskaznikiem IOMMU softc: u nas "obraz + 0x3543A70", w payloadzie **env+0x00 =
  0x3543A70**. Zrzut pod tym offsetem trzyma `0xffffff8005768000` (wskaznik softc). Zgodnosc
  pelna, do bitu.
- Baza okna urzadzenia `0xFDD80000`: payload uzywa jej jako **magicznej wartosci rozpoznajacej
  softc**, czytajac `kread64(kandydat + 0x48)`. Wartosc sie zgadza, nowy jest offset pola `+0x48`.
  W statycznym zrzucie nie ma ani jednego wyrownanego do 8 qword `0x00000000FDD80000` (trafien
  4-bajtowych jest 8, wszystkie z alignmentem 2, czyli przypadkowe w srodku instrukcji), co
  potwierdza wniosek z notatki, ze pole jest wypelniane w czasie attach z konfiguracji,
  a softc nie lezy w obrazie jadra.
- Payload nie dotyka rejestrow IOMMU bezposrednio w komponentach jadra: robi to dopiero
  shellcode jadra (napisy `IOMMU sb OK`, `IOMMU sb NO`, `TMR OK`, `TMR NO`, `VMCB OK`,
  `VMCB NO`, `Back from HV`) wolajac funkcje `ktext + env[0xC8]` i `ktext + env[0xD0]`
  (VMCALL 6 i VMCALL 0xA).

### 7.4 Z `notes/IOMMU-MAPOWANIE-Z-DEASEMBLACJI.md`

Zgodne bez zastrzezen: baza tekstu `0xffffffffc0c60000`, baza danych `text + 0xCC0000`,
sposob liczenia VA z offsetu w pliku oraz to, ze zrzut i payload posluguja sie tym samym
offsetem od ktext (u nas dowiedzione bramka NVS_EXPECT z rozdzialu 0). Payload nie wnosi
tu nowych stalych poza `0x48` z 7.3 i stalej `0xFDD80000`.

### 7.5 Z `artifacts/kstuff-profile-1360.h` i `notes/STAN-KONCOWY-KSTUFF-NG.md`

Brak zwiazku, i to jest wynik negatywny, sprawdzony:

- Zaden offset z profilu A53/PPR nie wystepuje w pliku: `0x04E28000`, `0x04E61F00`, `0x04E5B964`,
  `0x06410000` daja zero trafien w calej deasemblacji.
- Payload nie zawiera zadnego kodu piszacego do obrazu A53 ani zadnej stalej PPR.
- Jedyne dwa slady okolic MP4/A53 to: (a) **env+0x128 = 0x1518160 i env+0x130 = 0x7A248**,
  czyli obraz firmware'u WiFi (`lib/nxp/pcieuartiw620_combo_v1.bin`, kod ARM 32-bit) lezacy
  w danych jadra, zrzucany funkcja `dump_ps5_wifi_firmware`, oraz (b) dwie nazwy modulow
  w tabeli nazw do rozwijania symboli: `/system/priv/lib/libSceDeci5Dtracep.sprx` (VA 0x1e694)
  i `/system/priv/lib/libSceDeci5Ttyp.sprx`. Zadnego offsetu ani adresu MP4 w pliku nie ma.
  W tabeli `.rodata` jest 145 nazw `.sprx`, wiec to zwykla lista modulow, nie specjalna sciezka MP4.

## 8. Rozbieznosci i punkty otwarte

1. `notes/1360LINUX-LANCUCH-EXPLOITA.md` (powstala rownolegle) opisuje pole `+0x148` jako
   "jaskinia kodu jadra KERNEL_CODE_CAVE". W pliku to **dwie rozne jaskinie** i dowodem sa dwa
   rozne napisy etykiet przekazywane do `dump_text_perm`: `DATA_CAVE` (VA 0x1e99f) dla env+0x148
   oraz `KERNEL_CODE_CAVE` (VA 0x1e65c) dla env+0xB8. Poprawny podzial:
   env+0x148 = DATA_CAVE = 0x2D39000 (0x4000 B zer w obrazie), env+0xB8 = KERNEL_CODE_CAVE =
   0xCB92C0 (ciag NOP-ow w tekscie, miejsce na wgrywany kod). Dodatkowo `prepare_resume`
   wymaga wlasnie env+0xB8 (`Error: missing code cave offset`), a nie env+0x148.
2. `FUN_MEMCPY` (env+0x58 = 0x2590B0) jest w tej samej notatce nazwany "pivotem stosu".
   Napis etykiety w pliku mowi `FUN_MEMCPY`, a bajty `55 48 89 e5 49 89 fa 49 01 d2 72 19`
   to prolog funkcji kopiujacej (sprawdzenie przepelnienia `dst + len`). Pivotem jest env+0x150
   (0x25213E, `add rsp,0x28 ; rep ret`).
3. `env+0x38, +0x40, +0x48, +0x50, +0xB0` sa **zerowe** dla 13.60 (i dla 12.00 oraz 13.00).
   `build_gp_rop` uzywa ich w galezi, ktora wykonuje sie tylko przy `esi != 0`. Nie sprawdzilem,
   czy ktokolwiek wola te funkcje z niezerowym `esi` na 13.60; jesli tak, ta sciezka ROP jest
   dla 13.60 niedokonczona. Do rozstrzygniecia przy nastepnej sesji.
4. Pola env+0xE8 i env+0xF0 (0x62806F00, 0x62847375) sa przekazywane do shellcode i przez ten
   build nieczytane. Ich znaczenia nie ustalilem; wygladaja na resztki innej wersji ABI.
5. Stale z tablicy ops (rozdzial 6) sa adresami funkcji jadra 13.60, ktorych **nazw nie znamy**.
   To 26 nowych adresow do wykorzystania (miedzy innymi sciezka HDMI/VBIOS/DP), ale bez nazw.

## 9. Czego w pliku nie ma (wynik negatywny, z dowodem)

- **Zadnego bezwzglednego adresu tekstu jadra** (`0xffffffff8...` ani `0xffffffffc...`).
  Skan wszystkich stalych 16-cyfrowych w kodzie daje wylacznie maski i sentinele
  (`0xffffffffffffffff`, `0xffffffffffff0000`, `0xffffffffffffc000`, `0xfffffffffffffeff`,
  `0x8000000000000000`, `0x7fffffffffffffff`), ujemne przesuniecia rip-relative
  (`0xfffffffffffed22b` i tym podobne) oraz cztery adresy `0xffff80000000xxxx`
  z `0xffff800000000000` na czele. Baza tekstu i danych przychodzi w argumentach
  (`rdi+0x20`, sprawdzenie w rozdziale 2).
- **`vm_phys_segs` ani tablicy `phys_avail`**: zero trafien w nazwach symboli i w napisach
  (`grep -icE "phys_seg|phys_avail|vm_page"` na liscie 781 symboli daje 0).
  Pamiec fizyczna jest obslugiwana inaczej: `pa_to_dmap` (VA 0xa150), `install_page_syscore`
  (VA 0xab60), `alloc_page` (VA 0xa8b0), `vtophys_user` (VA 0x9f40), `kernel_proc_getpaddr`
  (VA 0x13ec0 chodzi po 4 poziomach tablic stron).
- **Zadnego kodu albo stalej dla A53/PPR/MP4** (patrz 7.5).
- **Zadnego napisu ani stalej o `deci`, `iommu` sprzetowym** poza wymienionymi w 7.3.

## 10. Podsumowanie liczbowe (odpowiedz na RAPORT)

Zestawienie wyciagnietych pozycji (kazda ma w notatce offset w pliku i dowod):

| grupa | ile | gdzie w notatce |
|---|---|---|
| pola tablicy `off_1360` | 60 (48 adresow i offsetow jadra, 7 pol pustych, 5 wartosci nieadresowych) | 3.1, 3.2 |
| stale danych dla 13.60 w `__kernel_init` | 5 (delta tekstu i cztery adresy danych) | 4 |
| stale offsetow struktur i bitow PTE | 17 | 5 |
| bezwzgledne adresy `0xffff80000000xxxx` | 4 | 5 |
| offsety tekstu jadra z shellcode | 31 (26 z tablicy ops i 5 inline) | 6 |
| stale magiczne i rozmiary | 7 | 2, 4, 6 |
| **razem** | **124** | |

- Zgodnych z naszymi ustaleniami: **30 co do wartosci**, czyli 26 z naszego
  `tools/pprhook/include/offsets/13_60.h` (7 symboli i 19 gadzetow), 2 z kstuff-lite
  (`doreti_iret` i `wrmsr_ret` po przeliczeniu), `allproc = data + 0x28C9E80` oraz konwencja
  `kdata = ktext + 0xCC0000`. Dodatkowo **2 gadzety zgodne semantycznie przy innym miejscu
  w pamieci** (POP_RAX i POP_RSP).
- Nowych, niezerowych, nieobecnych w naszych notatkach: **85**. Najwazniejsze:
  `KERNEL_CODE_CAVE = 0xCB92C0`, `kernel_uart_override = 0x21F9598`,
  `kernel_cfi_check = 0x44F8C0`, bramka wersji `0x1A1A030` (odcisk NVS_EXPECT, unikat w zrzucie),
  slot HV `0x3DF1070`, `FUN_MEMCPY = 0x2590B0`, `GAD_ADD_RSP_28..RBP = 0x9E32B4`,
  `wrmsr; ret = 0x255034`, `pop rax = 0xB8CA6E`, `pop rsp = 0xB8291B`,
  VMCALL 6 = `0xC16B00`, VMCALL 0xA = `0xC16A40`, kotwica SCK = `0x25D410`,
  firmware WiFi (A53) = `ktext + 0x1518160` o rozmiarze `0x7A248`,
  `vm_root = 0x1D0`, `pmap = 0x2E8`, wskaznik pmap w vmspace = `0x1D8`,
  `softc + 0x48 = 0xFDD80000`, pola `pmap + 0x20` i `pmap + 0x28` (DMAP i CR3),
  26 offsetow funkcji z tablicy ops HDMI.
- Odpowiedz na pytanie 4: **jedna tablica** (`off_1360`, 60 pol po 8 B, plik 0x2bbb0),
  wybierana po wersji firmware (`set_offsets`, VA 0x97f0) i kopiowana do `env_offset`.
  Poza nia stale 13.60 leza jeszcze w bloku `if (fw == 0x1360)` funkcji `__kernel_init`
  i w shellcode jadra. Po samym kodzie offsety nie sa rozsiane.

## 11. Jak to odtworzyc

Pliki robocze: `/root/linux-elf-offsety/`. Skrypty (kopiowane z Windows do WSL):

- `elfinfo.py sym|objdump|dumpdata <re>`: symbole, deasemblacja funkcji, zrzut danych symbolu.
- `disan.py envmap|env|vas`: mapowanie pol `env_offset` na funkcje i stale 16-cyfrowe.
- `tables.py jt|qwords|dwords|str`: dekoder tablic przeskokow i stalych w `.rodata`.
- `scanblob.py`, `extract.sh`: wyciagniecie i analiza `shellcode_kernel_bin`, `shellcode_ap_bin`.
- `verify_dump.py`, `charac.py`, `opscheck.py`, `softc.py`, `findpat.py`: weryfikacja na zrzucie
  (bajty pod offsetem, prologi funkcji, odcisk NVS_EXPECT, skan softc).
- `allproc.py`, `fwblocks.py`: skan struktury listy procesow i wyciaganie blokow per firmware.
