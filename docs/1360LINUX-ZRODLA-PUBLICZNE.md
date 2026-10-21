# Zrodla publiczne payloadu dla 13.60: co jest, a czego nie ma

Notatka odpowiada na zadanie: sklonowac `MecenasStudio/ps5-linux-1360`, przeczytac README,
sprobujac zbudowac payload, porownac go z `artifacts/1360linux.elf` i ustalic, czy istnieje
nowsza publiczna wersja payloadu dla 13.60.

Data pracy: 2026-10-16. Klon poza repozytorium: `<work>\ps5-linux-1360` (git, nie gh).
Budowa w WSL Debian 13 (trixie), SDK `/opt/ps5-payload-sdk`. Nic nie zostalo wyslane na konsole,
nic nie zostalo zacommitowane.

## 1. Repozytorium MecenasStudio/ps5-linux-1360

| Pole | Wartosc |
|---|---|
| URL | https://github.com/MecenasStudio/ps5-linux-1360 |
| Wlasciciel | organizacja MecenasStudio, autor commitow `HSgod <hsgodkontakt@gmail.com>` |
| Utworzone | 2026-10-12T20:21:20Z |
| Opis | `Linux loader for PS5 13.60 - hints (missing UART adapter)` |
| Galez | tylko `main` |
| HEAD | `5a754269721a817f4cf3cb6e459c5a807d3c89bc` |
| Data HEAD | 2026-10-14T14:53:44+02:00 (autor), push 2026-10-14T12:53:46Z |
| Tytul HEAD | `Stop tracking the two generated headers, and drop a stale ignore rule` |
| Liczba commitow | 18, wszystkie z data 2026-10-14 |
| Licencja | GPL-3.0 |
| Gwiazdki | 2 |

Pierwszy commit: `5143b67 ps5-linux-1360: boot Linux on a 13.60 PS5` (2026-10-14).

Commity po 2026-10-14: **brak** (`/commits?since=2026-10-14T12:53:47Z` zwraca pusta liste).
Publiczne zdarzenia repo koncza sie na `WatchEvent` z 2026-10-15T13:00:20Z (uzytkownik
`antonioacg`), zadnego pushu po 2026-10-14.

Uwaga o historii: zdarzenia `PushEvent` z 2026-10-13 wskazuja na SHAs (`a94f20bc`,
`7fa8c46c`, `e820c8e9`, `4b942500`, `1ba5cdb6` i inne), ktorych **nie ma juz w klonie**
(`git cat-file -t` zwraca `Not a valid object name` dla kazdego). Historia galezi `main`
zostala przepisana i wszystkie 18 widocznych commitow ma teraz date 2026-10-14.

Commity w historii, w kolejnosci od najstarszego (tylko naglowki):

```
5143b67 2026-10-14 ps5-linux-1360: boot Linux on a 13.60 PS5
ed5f78a 2026-10-14 Poll log: report every iteration, not every fifteenth
672fb05 2026-10-14 Ask for another suspend when the hook does not fire, instead of giving up
486f918 2026-10-14 Use the PS5 kernel's sleep in the poll loop, and re-pin each iteration
82ecea5 2026-10-14 Retry the suspend immediately instead of polling for a minute first
9d5a496 2026-10-14 Notice the resume with the wall clock instead of re-asking on a timer
7d31557 2026-10-14 Rebuild the runtime state when the cave is already armed
f4c8877 2026-10-14 Remove the VBIOS copy to 0xC0000 from the bare-metal handover
f251f3a 2026-10-14 Wait for the other CPUs, and let Linux bring its own up
0f08e76 2026-10-14 Fix the hypervisor loader base, which was sixteen times too high
f7ec791 2026-10-14 Write the VMEXIT redirect from the payload, and check that it took
8f47ca4 2026-10-14 Install the VMEXIT redirect last, immediately before the CPUs are kicked
175c97e 2026-10-14 Take one core out of the PS5, not all sixteen
9ab8939 2026-10-14 Skip the wait in the single-core build instead of bounding it for everyone
3cb5bcf 2026-10-14 Reduce the blob to the redirect and one VMMCALL
f3f1c4b 2026-10-14 Redirect the VMEXIT entry through the host state save area, and delegate
37cd449 2026-10-14 Clean out the diagnostics and correct what the README claims
5a75426 2026-10-14 Stop tracking the two generated headers, and drop a stale ignore rule
```

## 2. Co mowi README (cytat dokladny, nie streszczenie)

### 2.1 Model konsoli (linie 7 do 11, bez zmian od pierwszego commita)

> **13.60 is the only firmware this handles.** The offsets are for it and anything else
> is refused at startup with *"make sure your fw is supported"*. Tested on a **Fat**.
> The **Slim** loads its hypervisor at the same address and should behave the same,
> but has not been tried. The **Pro** is not supported: it loads its hypervisor at
> `0x8e0800000` and `hv_base_pa()` does not distinguish the two.

### 2.2 Tabela stanu (linie 15 do 22, stan na HEAD)

```
arm the hypervisor hook                  works
resume, kernel hook fires, cookie        works
stage both Linux images in the cave      works, verified byte for byte
check the identity map and the dmap      works, every entry checked
install the VMEXIT redirect              lands where it is written
hand the machine to shellcode_hv         FAILS - platform powers off
```

Kluczowe zdania tuz pod tabela (linie 24 do 35):

> **It has never been observed to start Linux.** An earlier version of this file said
> it reached the initramfs and spent ninety seconds looking for the root filesystem.
> That was wrong: the two runs that lived that long are in the payload's own log as
> `still no cookie (46/300, 90s)`, meaning the hook had not fired and the payload was
> simply polling. There was no kernel and no root filesystem - only a console that had
> not powered itself off yet.
>
> **The fault is in the handoff, and it is deterministic.** Of seventy-nine runs in that
> log, fifteen reached `takeover armed; firing getuid() -> shellcode_hv` after streaming
> and verifying both images - and the console powered off in all fifteen, always in the
> same place. It is not `shellcode_hv`: replacing it in the cave with four bytes of
> `cli; hlt` changes nothing, so the platform is gone before that code runs.

### 2.3 Przekazanie sterowania (linie 37 do 54)

> **What is known about it.** The takeover writes a stub over the hypervisor's VMEXIT
> dispatcher, and that dispatcher belongs to the whole machine, not to the one core
> that issued the VMMCALL. The other cores are still running the PS5 and issuing
> hypercalls continuously, so they land in the stub too - which is why one core kicked
> or sixteen makes no difference, why writing the stub later makes no difference, and
> why the redirect now delegates instead: the entry is moved by rewriting the host RIP
> in the state save area named by `VM_HSAVE_PA`, and everything except our own
> hypercall goes to the untouched dispatcher. That is the current state of the code, and
> it is as far as the evidence goes. The next measurement needs a console.
>
> **There is no console anywhere on this path.** `shellcode_hv` prints to the UART at
> `0xc1010104`, which is the same port the kernel command line already names as
> `console=ttyTitania0`, and nothing else in the handoff can report anything: the
> payload's log stops at the point control leaves it, the PS5's kernel log stops at
> suspend, and `tty0` needs a framebuffer that the missing display bring-up never
> creates. A USB-TTL adapter on the console's UART pins would show, in one run, whether
> `shellcode_hv` is reached and where it stops - and after that the entire kernel log.

### 2.4 Czego nie wiedza (linie 56 do 66)

> - **`FUN_TRANSMITTER_CONTROL` and `FUN_MP3_INVOKE`.** [...] Those two offsets are in no
>   dump, no SDK and no public table for 13.60, and until the DP link is up `console=tty0`
>   has nowhere to draw. `G_VBIOS` and `FUN_MP3_INITIALIZE` are known.
> - **Whether the MP3 call is what keeps the platform alive.** [...] That is correlation
>   across a handful of runs, not a measurement, and it is why the call is back in the blob.

### 2.5 Uwaga o historii README (wazna dla oczekiwan)

README z pierwszego commita `5143b67` twierdzil cos przeciwnego:

```
escape the hypervisor                    works
stage the Linux images in the cave       works, verified byte for byte
start the kernel                         works
initramfs runs                           works
wait for the root filesystem             fails - not found, platform powers off
```

Commit `37cd449 Clean out the diagnostics and correct what the README claims` zamienil te
tabele na obecna i dopisal, ze poprzednia wersja byla bledna. Jesli ktos czytal README
13 albo 14 pazdziernika, widzial "start the kernel works / initramfs runs". To juz nie
jest prawda i samo repo to prostuje.

## 3. Budowa: proba i wynik

### 3.1 Czego wymaga Makefile

- `PS5_PAYLOAD_SDK` (sciezka do ps5-payload-sdk, w tym repo: `/opt/ps5-payload-sdk`),
- `LLVM_CONFIG` (wrapper `prospero-clang` czyta te zmienna; bez niej kazda kompilacja pada
  w sposob wygladajacy jak brak toolchainu),
- `x86_64-elf-gcc`, `x86_64-elf-ld`, `x86_64-elf-objcopy` dla trzech blobow shellcode
  (x86-64 freestanding, nie moga byc zbudowane kompilatorem hosta na macOS),
- `python3` dla `scripts/bin2c.py`.

Na tej maszynie: Windows nie ma `x86_64-elf-*` (sprawdzone, brak), WSL Debian 13 ma
`gcc 14`, `ld`, `objcopy`, `clang 19`, `make`, `python3` oraz `/opt/ps5-payload-sdk`.
`x86_64-elf-gcc` nie byl instalowany (celowo, to ciezka zaleznosc).

### 3.2 Co zostalo uruchomione

```
cd /root/ps5-linux-1360            # kopia klonu w systemie plikow WSL, nie na /mnt/d
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
export LLVM_CONFIG=/usr/lib/llvm-19/bin/llvm-config
make SC_CC=gcc SC_LD=ld SC_OBJCOPY=objcopy
```

Uzycie `SC_CC=gcc` to sciezka przewidziana przez samo repo: podkatalogi `shellcode/hv`
i `shellcode/hv_takeover` same wybieraja `gcc`/`ld`/`objcopy`, kiedy `uname -m` nie jest
`aarch64`, a README wprost pozwala nadpisac `SC_CC`, `SC_LD`, `SC_OBJCOPY`. Blob `break_hv`
kompiluje sie bez udzialu `SC_*`, bo ustawia `CC := gcc` na sztywno.

### 3.3 Wynik: ZBUDOWALO SIE

| Plik | Rozmiar | SHA256 |
|---|---|---|
| `bin/ps5-linux-1360.elf` (po `make clean`) | 181 968 B | `9d5360fb2f9100e06dc79e5e2afec26872826b5ad2b93ed29969fb6e2e2672e1` |
| `bin/ps5-linux-1360.elf` (pierwszy build, bez `make clean`) | 181 968 B | `ada6cbd1b5ca789b5b2f329c45d4241871cc6dcd3357616bf0703f359e46fd8a` |
| `shellcode/hv/shellcode_hv.bin` | 6 056 B | |
| `shellcode/hv_takeover/takeover.bin` | 216 B | |

Dwa kolejne buildy po `make clean` daja identyczny SHA256, wiec build jest powtarzalny,
ale **tylko po `make clean`**. Przyczyna roznicy `ada6cbd1` i `9d5360fb` jest w punkcie 3.4.

`.comment` zbudowanego pliku: `Ubuntu clang version 18.1.3 (1ubuntu1)`, `Debian clang
version 19.1.7 (3+b1)`, `Linker: Debian LLD 19.1.7`.

### 3.4 Defekt build w tym repo: `break_hv.h` jest generowany, ale i sledzony

- `shellcode/break_hv/Makefile` ma `DUMP := break_hv.h` i generuje ten naglowek przez
  `bin2c.py`. Jednoczesnie `git ls-files` pokazuje `shellcode/break_hv/break_hv.h` jako
  plik sledzony, a `.gitignore` ignoruje po nazwie tylko `shellcode/hv/shellcode_hv.h`
  i `shellcode/hv_takeover/takeover.h`. Komentarz w `.gitignore` twierdzi wprost, ze
  `break_hv.h` jest "written by hand", co nie jest prawda.
- Skutek: w swiezym klonie `make` uznaje `shellcode/break_hv/break_hv.h` za aktualny
  i **nie odbudowuje bloba**. Zsledzony naglowek opisuje blob 159 B, swiezo zbudowany ma
  172 B (`/* break_hv.bin: 159 bytes */` kontra `/* break_hv.bin: 172 bytes */`).
- Payload z pierwszego `make` embedsuje stary blob `break_hv` (159 B), payload po
  `make clean` nowy (172 B). `git status` w obu przypadkach jest czysty, wiec nikt tego
  nie zauwazy. Ostatni commit repo (`5a75426`) deklarowal uporzadkowanie dokladnie tej
  klasy problemu, ale objal tylko dwa z trzech generowanych naglowkow.

## 4. Czy `artifacts/1360linux.elf` pochodzi z tego zrodla: NIE

Dowody, kazdy sprawdzalny na pliku:

| Cecha | `artifacts/1360linux.elf` | build `MecenasStudio/ps5-linux-1360` |
|---|---|---|
| Rozmiar | 237 448 B | 181 968 B |
| SHA256 | `e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226` | `9d5360fb2f9100e06dc79e5e2afec26872826b5ad2b93ed29969fb6e2e2672e1` |
| `.comment` | `Ubuntu clang version 18.1.3 (1ubuntu1)` + `Linker: Ubuntu LLD 18.1.3` | `Ubuntu clang 18.1.3` + `Debian clang 19.1.7` + `Linker: Debian LLD 19.1.7` |
| Naglowek zapraszajacy | `Welcome to ps5-linux-loader. We'll defeat HV and prepare the system to boot Linux on sleep resume.` | brak takiego napisu |
| Funkcje 13.60 | `hv_defeat_13xx`, `derive_H`, `dump_text_perm`, `dump_pte_bits`, `off_1360` (29 tabel offsetow, `off_0300` do `off_1360`) | `hv_defeat_1360`, `stage_hv_boot`, `stage_identity_map`, `hv_base_pa`, `derive_H` nie istnieje |
| Nazwy blobow | `shellcode_0607_bin`, `shellcode_ap_bin`, `shellcode_kernel_bin` | `shellcode_hv_bin`, `break_hv_bin`, `takeover_bin` |
| Napisy 13.60 | `13.60 offsets are incomplete - refusing to arm.`, `See HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md.`, `SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x` | brak |
| Plik zrodlowy w symbolach | `hv_defeat_0607.c` | `hv_defeat_1360.c` |
| Symbole | obecne (781, `ET_DYN`, nie strippowany) | plik zbudowany z `-Wall` bez stripa tez ma symbole, ale innych nazw |

Wniosek: to **dwa niezalezne podejscia do tego samego celu**. Nasz plik to rozszerzenie
**ps5-linux-loader** (rodzina `ps5-linux/ps5-linux-loader`, nazewnictwo `hv_defeat_0304/0506/0607`,
`prepare_resume`, `prepare_sck_args`, `fetch_linux`, `build_sx_rop`, `kgadget`, `kh_chain_*`),
do ktorego ktos dopisal obsluge rodziny 13.xx (`hv_defeat_13xx`, `derive_H`, 30. tabela
`off_1360`). Repo Mecenasa to port od zera na bazie Byepervisor-Reborn plus shellcode
z ps5-linux-loader, ale z wlasnym przepisaniem.

### 4.1 Skad naprawde pochodzi nasz plik

- Nasz plik **nie** jest zbudowany z upstreamu `ps5-linux/ps5-linux-loader`: wydanie v2.5
  (2026-09-05) to 180 528 B i w calym jego drzewie nie ma ani jednego wystapienia `13xx`,
  `1360`, `13.60`, `derive_H` (sprawdzone `Select-String` po `source/`, `include/`,
  `shellcode_kernel/`, `README.md`). Upstream ma 22 tabele offsetow (`off_0300` do `off_0761`),
  nasz plik ma 29. Roznica jest dokladnie ta, ktorej szukamy: wszystkie 22 nazwy z upstreamu
  wystepuja u nas bez zmian, a dopisane zostaly `off_0800`, `off_0900`, `off_1000`, `off_1100`,
  `off_1200`, `off_1300` i `off_1360`. To znaczy, ze ktos rozszerzyl loader o siedem nowych
  rodzin firmware, w tym o 13.60.
- Zaden publiczny fork `ps5-linux-loader` nie ma galezi z 13.60. Najswiezsze forki po dacie
  pushu: `rmuxnet` (2026-10-16, zmiana tylko w README: VCN), `gzimbric` (2026-10-16, galezie
  `dev-wifi-fw` i `firmware-11.60-sonic-display`), `haxxordan` (2026-10-14, galaz `fw-12.70`),
  `GustaKir` (2026-10-13, tylko CI), `kernelpanicz/pslinux` (2026-10-08, 9.40). Zaden nie
  dotyczy 13.60.
- Napisy `13.60 offsets are incomplete`, `HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md`
  i `SCK>5h-skipped` nie wystepuja w zadnym publicznym repozytorium (`gh search code`,
  trzy zapytania, zero trafien). `HVBUG` jako katalog nie istnieje tez na tym dysku.
- **Trop potwierdzony:** repo `gzimbric/ps5-linux-porting`, plik
  `docs/sonic-13.60-reference.md` z 2026-10-15, opisuje dokladnie nasz plik, z tym samym
  rozmiarem i tym samym SHA256, i nazywa go "independently supplied `1360linux.elf`",
  "the private binary", "Sonic's". Ten sam dokument podaje, ze autorska sciezka Sonic
  **doszla do zalogowanego uzytkownika Linuksa na 11.60** (Run 10, 12, 14, 15), a binarka
  13.60 jest u nich tylko wzorcem architektonicznym i "is not redistributed".
  Repo autora tego tropu: https://github.com/soniciso1/ps5-hv-writeups (2026-10-12),
  oraz https://github.com/soniciso1/ps5-linux-archive (snapshot 2026-09-15).

## 5. Porownanie w miejscach naszych poprawek

Punkt odniesienia: `artifacts/1360linux.elf` (bazowy, bez naszych zmian) kontra warianty
`nodiag`, `nodiag2`, `nodiag3`, `hvstan`. Regula offsetu: `offset_w_pliku = VA + 0x4000`.
Wszystkie trzy miejsca z zadania zostaly potwierdzone bajt w bajt przez `cmp -l`.

### 5.1 Plik 0x81F0, diagnostyka

- VA 0x41F0 = symbol `dump_text_perm` (403 B, konczy sie na VA 0x437F).
- Wariant `nodiag` rozni sie od bazowego **jednym bajtem**: pod offsetem pliku 0x81F0
  bajt `0x55` (`push rbp`) zamieniony na `0xC3` (`ret`). Czyli cala funkcja diagnostyczna
  jest zbita do natychmiastowego powrotu.
- Co robi w oryginale: siega po globalne `cr3` i `dmap` (VA 0x6F1E8, 0x6F1F0), potem po
  `ktext` i `kdata` (VA 0x6F1D8, 0x6F1E0) i wysyla to przez `notify` (VA 0x9710) dwoma
  napisami z `.rodata` (VA 0x1F170 i VA 0x1EC7A). To zrzut stanu przed/po przejsciu.
- **W repo Mecenasa nie ma odpowiednika.** Nazwa `dump_text_perm` nie wystepuje w jego
  drzewie, a jego `37cd449` wrecz usunal diagnostyke ("Clean out the diagnostics").
  Nie ma czego porownywac: to inny kod pod tym samym offsetem.

### 5.2 Plik 0x85D5 do 0x85DA, limit 4 GB w `derive_H`

Dokladny rozkaz w pliku bazowym (VA 0x45C7 do 0x45DA):

```
45c7: 48 b8 00 00 00 00 01 00 00 00   movabs rax, 0x100000000
45d1: 48 39 45 88                     cmp    QWORD PTR [rbp-0x78], rax
45d5: 0f 83 0d 00 00 00               jae    45e8
45db: 48 8b 45 88                     mov    rax, QWORD PTR [rbp-0x78]
45df: 48 89 45 f8                     mov    QWORD PTR [rbp-0x8], rax    ; wynik H
45e3: e9 4d 00 00 00                  jmp    4635                        ; return H
```

- Wariant `nodiag2` zamienia **szesc bajtow** `0f 83 0d 00 00 00` (VA 0x45D5 do 0x45DA,
  plik 0x85D5 do 0x85DA) na szesc `0x90` (NOP), czyli znosi odrzucanie kandydata >= 4 GiB.
  To znaczy: `derive_H` szuka bazy hypervisora dynamicznie (skan struktury po `kread64(ktext
  + env_offset[0x1d8])`, petla do 0x40 wpisow, wzorzec `0x9004` jako pierwsze slowo 32-bit),
  i odrzucal kazdy wynik >= 0x100000000. Na Pro region HV to `0x8E0000000`, wiec limit go
  wycinal.
- W repo Mecenasa **nie ma `derive_H` ani zadnego skanu bazy HV**. Jego `hv_base_pa()`
  zwraca stala z tabeli (patrz rozdzial 6). Nie ma czego porownywac.

### 5.3 Plik 0x7C95 i 0x7CCC, pola adresowe HV

Oba leza w `hv_defeat_13xx` (VA 0x37D0, 1691 B, koniec VA 0x3E6B). Rozkazy w pliku bazowym:

```
3c90: 48 81 c2 28 30 08 00   add rdx, 0x00083028     ; imm32 na plik 0x7C93..0x7C96
3cc7: 48 81 c2 60 2a 08 00   add rdx, 0x00082A60     ; imm32 na plik 0x7CCA..0x7CCD
```

- Wariant `nodiag3` zmienia **dwa bajty**: plik 0x7C95 z `0x08` na `0x88` oraz plik 0x7CCC
  z `0x08` na `0x88`. To trzecie bajty obu immediatow, czyli podniesienie obu stalych
  o dokladnie `0x800000`: `0x00083028` staje sie `0x00883028`, `0x00082A60` staje sie
  `0x00882A60`. Zgadza sie z opisem rundy 175 ("dwa pola adresowe HV liczone od bazy
  loadera (+0x800000), zgodnie ze wzorem byepervisora").
- Te dwie stale to `HV_SYM_HEAP_BASE` i `HV_SYM_PCPUS`, wartosci identyczne jak w tabeli
  Mecenasa (`.HV_SYM_HEAP_BASE = 0x83028`, `.HV_SYM_PCPUS = 0x82A60`, obie oznaczone
  `/* BYEP */`). W calym naszym pliku kazda z nich wystepuje **dokladnie raz**, tylko tutaj.
- Reszta otoczenia (od VA 0x3C80) to `add rsi, 0xf00`, `add rsi, 0x20`, wczytanie
  `[rbp-0x120]` jako bazy i dodanie do niej stalej symbolu. Baza pochodzi z `derive_H`,
  nie z literalu.
- W repo Mecenasa te same dwie stale wystepuja w `source/offsets.c` (patrz rozdzial 6),
  ale kod, ktory je zuzywa, jest inny i lezy gdzie indziej. Nie da sie porownac bajt w bajt.

### 5.4 Czego w repo Mecenasa nie ma wcale

Sprawdzone `grep` po calym drzewie (bez `.git`):

| Szukane | Wynik w `MecenasStudio/ps5-linux-1360` |
|---|---|
| `hv_base_pa` | jest, `source/hv_defeat_1360.c` linia 207 |
| `0x8e0800000` | jest, `source/offsets.c` linia 96 jako `HV_LOADER_PA_PRO` (i w README) |
| `0x062800000` | jest, ale jako **stara, bledna wartosc w komentarzu** (`source/offsets.c` linia 82) oraz w mapie e820 (`shellcode/hv/boot_linux.c` linia 66, `E820_TYPE_RESERVED // HV`) |
| `soc_id` | tylko w komentarzu: `sceKernelGetMainSocId()` w `source/hv_defeat_1360.c` linia 196 |
| `0x840fd0` | **zero wystapien** |

W naszym `1360linux.elf` tez nie ma ani `0x8e0800000`, ani `0x062800000` jako imm64, ani
`0x840fd0`. Literal `0x62800000` wystepuje **dokladnie raz**, pod offsetem pliku 0x2D722
(VA 0x29722), i lezy wewnatrz 26 896-bajtowego bloba `shellcode_kernel_bin`
(VA 0x27D90 do 0x2E6C0), czyli w osadzonym shellcode wybudzenia, a nie w czesci userland.
Innymi slowy: czesc userland naszego pliku liczy baze HV dynamicznie (`derive_H`), ale
osadzony shellcode jadra nadal zaklada baze modelu regularnego. To jest dokladnie to
miejsce, ktore na Pro trzeba ruszyc obok limitu 4 GB z punktu 5.2.

## 6. Obsluga modelu Pro w zrodlach Mecenasa: jak jest zrobiona

Tabela ma wpis dla Pro, ale **nikt go nie uzywa**:

```c
/* source/offsets.c, linie 95 do 96 */
.HV_LOADER_PA_REGULAR = 0x62800000,   /* HW: 16x below the BYEP value; see above */
.HV_LOADER_PA_PRO = 0x8e0800000,      /* BYEP */
```

```c
/* source/hv_defeat_1360.c, linie 194 do 209 */
/* HV loader carveout base, hardcoded to the retail/"regular" SoC value.
 *
 * The earlier note here claimed sceKernelGetMainSocId() could not be resolved by
 * elfldr on retail. That is not so: the reference Byepervisor payload calls it
 * and reports "Regular model detected" on this console. The value below is
 * therefore right for a Phat, which is what this port was built and tested on,
 * but a Pro would need HV_LOADER_PA_PRO and this function does not distinguish
 * them. Left as-is rather than adding a probe that has never been run. */
static uint64_t hv_base_pa(void) {
  return env_offset.HV_LOADER_PA_REGULAR;
}
```

Czyli: rozpoznanie modelu jest **swiadomie pominiete**. Funkcja `sceKernelGetMainSocId()`
jest znana i dziala na retailu (tak twierdzi komentarz, powolujac sie na referencyjny payload
Byepervisora, ktory wypisuje "Regular model detected"), ale port jej nie wola i nie ma
zadnej galezi `if (pro)`. Wartosc dla Pro lezy w tabeli nietknieta.

Dodatkowo, w tym samym repo mapa e820 w `shellcode/hv/boot_linux.c` rezerwuje pod
hypervisora zakres `0x062800000` do `0x064800000`, czyli zakres z **blednej, szesnastokrotnie
za duzej** bazy. Commit `0f08e76` poprawil stala w tabeli, ale nie poprawil e820.

### 6.1 Poprawka bazy loadera z commita "sixteen times too high"

**Jest w zrodlach.** Commit `0f08e76dd4cc25f79b34415e229d97a444a1ba55`,
`Wed Oct 14 14:00:12 2026 +0200`, zmienia tylko `source/offsets.c` (15 dodanych linii,
1 zmieniona): `.HV_LOADER_PA_REGULAR` z `0x062800000` na `0x62800000`. Uzasadnienie w commicie
i w komentarzu w kodzie: zmierzone na tej konsoli `HV_CODE_CAVE_PA = 0x62806F00`
i `HV_HANDLE_VMEXIT_PA = 0x6283D800` lezalyby szesnascie razy ponizej wlasnej bazy.

Wazne dla nas: ten sam commit twierdzi, ze to **nie** naprawilo przekazania sterowania.
Cytat z commita:

> The escape still fires with the wrong value, because patching the VMEXIT handler uses
> the absolute addresses rather than the base - which is why this survived so long. It
> is the state the hypervisor is left in that is wrong, and the log says the machine
> dies immediately after the takeover, fifteen times out of fifteen, with both images
> streamed, verified and the page tables checked.

Czyli po naprawie bazy loadera (commit jest w HEAD) README nadal opisuje `hand the machine
to shellcode_hv  FAILS - platform powers off`. Poprawka bazy nie jest rozwiazaniem.

## 7. Wydania, zalaczniki, forki

| Sprawdzenie | Wynik |
|---|---|
| `gh release list -R MecenasStudio/ps5-linux-1360` | pusto |
| `gh api .../tags` | `[]` |
| `gh api .../branches` | jedna galaz `main` na `5a754269` |
| `gh api .../forks` | jeden fork: `ke5adb/ps5-linux-1360`, utworzony 2026-10-15T04:29:36Z, `pushed_at` = 2026-10-14T12:53:46Z (taki sam jak rodzic), 0 wlasnych commitow |
| `gh api ".../commits?since=2026-10-14T12:53:47Z"` | `[]` |
| Zalaczniki z gotowym payloadem | brak jakichkolwiek |

Czyli z tego repo **nie da sie pobrac zbudowanego payloadu**. Trzeba go zbudowac samemu,
co jest mozliwe i zostalo zrobione (rozdzial 3).

## 8. Inne publiczne zrodla payloadu dla 13.60 (z datami)

| Zrodlo | Co to jest | Najswiezsza data | Payload do pobrania |
|---|---|---|---|
| https://github.com/MecenasStudio/ps5-linux-1360 | zrodla loadera 13.60, wlasny port (nie dziala na przekazaniu) | 2026-10-14 | nie, brak releases i tagow |
| https://github.com/ps5-linux/ps5-linux-loader | oficjalny loader, **bez obslugi 13.60** (22 tabele, do 7.61) | v2.5 z 2026-09-05, ostatni push 2026-09-05T10:39:33Z | tak, `ps5-linux-loader.elf` 180 528 B, sha256 `9fc48733077145d1d204a4c9cdb879baaab1e711a604dd73af0dd4a807d6bc49`, 3 245 pobran |
| https://github.com/ps5-linux/ps5-linux-image | obraz dysku do Linuksa | 2026-08-29 | tak, obraz |
| https://github.com/ps5-linux/ps5-linux-patches | latki jadra | 2026-10-09 | nie |
| https://github.com/ps5-linux/ps5-linux-tools | narzedzia | 2026-07-04 | nie |
| https://github.com/ps5-linux/ps5-linux-mwifiex | sterownik WiFi | 2026-10-01 | nie |
| https://github.com/soniciso1/ps5-linux-archive | archiwum snapshotu ekosystemu ps5-linux (loader, latki, obraz, narzedzia) | 2026-09-15 | tak, kernel packages i obrazy dystrybucji; **loadera dla 13.60 nie ma** |
| https://github.com/soniciso1/ps5-hv-writeups | writeupy o HV, m.in. `s3-resume-startup_mp-ap-launch.md` | 2026-10-12 | nie |
| https://github.com/gzimbric/ps5-linux-porting | analiza naszego pliku, port na 11.60 | 2026-10-16 (`docs/sonic-13.60-reference.md` z 2026-10-15) | nie, repo dokumentacyjne |
| https://github.com/NotSoTypicalGamer/HV-Bypass-13.60 | research HV/jadra 13.60 (README plus ok. 200 plikow dokumentacji i sond) | 2026-10-13 | nie, brak releases |
| https://github.com/PS5Dev/Byepervisor-Reborn | hook jadra, zrodlo `khook`, `break_hv`, gadgetow | uzywane przez oba porty | tak, zrodla |

Organizacja `ps5-linux`: **nic nowszego niz 5 wrzesnia 2026** (v2.5 loadera, push
2026-09-05T10:39:33Z). Zaden jej projekt nie wspiera 13.60.

`gh search repos` po frazach `ps5 linux 1360` (pusto), `1360 linux payload` (pusto),
`ps5-linux-1360` (tylko MecenasStudio), `1360linux` (pusto), `ps5 13.60` (dziesiec repo,
wszystkie to payloady homebrew, dumpy jadra albo dokumentacja, zaden nie jest loaderem
Linuksa). `gh search code` po `hv_defeat_13xx` trafia tylko w dokumentacje `gzimbric`,
po `off_1360` tylko w `MecenasStudio`, po `13.60 offsets are incomplete`,
`LINUX-OFFSETS-13.60` i `SCK>5h-skipped` nie trafia w nic.

## 9. Wnioski

1. **Zbudowac sie udalo.** `MecenasStudio/ps5-linux-1360` kompiluje sie w WSL Debian
   z `/opt/ps5-payload-sdk` i `SC_CC=gcc SC_LD=ld SC_OBJCOPY=objcopy`, wynik
   `bin/ps5-linux-1360.elf`, 181 968 B, sha256 `9d5360fb...2672e1`. `x86_64-elf-gcc` nie byl
   potrzebny i nie byl instalowany. Build jest powtarzalny tylko po `make clean`, bo
   zsledzony `break_hv.h` jest plikiem generowanym i w swiezym klonie jest nieaktualny.
2. **Nasz `1360linux.elf` nie pochodzi z tego zrodla.** To prywatna binarka z rodziny
   ps5-linux-loader z dopisana obsluga 13.xx (ktora gzimbric nazywa "Sonic"), o czym
   rozstrzygaja rozmiar, SHA256, zestaw symboli, nazwy blobow i napisy.
3. **Nie ma nowszej publicznej wersji payloadu dla 13.60.** Repo Mecenasa stoi na
   2026-10-14, nie ma wydan ani zalacznikow, nie ma forkow z wlasnymi zmianami, nie ma
   commitow po 2026-10-14. Organizacja `ps5-linux` nie ma nic po 2026-09-05 i w ogole nie
   obsluguje 13.60. Publiczny trop "Sonic" (`gzimbric/ps5-linux-porting`) sam pisze, ze
   binarki nie rozprowadza.
4. **Pro nadal nie jest obslugiwany nigdzie publicznie.** Repo Mecenasa ma stala
   `HV_LOADER_PA_PRO = 0x8e0800000`, ale `hv_base_pa()` jej nie uzywa i nie ma rozpoznania
   modelu. Nasz plik jako jedyny liczy baze dynamicznie (`derive_H`), ale obcina wyniki
   >= 4 GiB, co wycina pro-owy region `0x8E0000000`. Nasza poprawka `nodiag2` (NOP na
   `jae` pod plikiem 0x85D5 do 0x85DA) znosi dokladnie ten limit, a `nodiag3` koryguje oba
   pola adresowe HV o `0x800000` (plik 0x7C95 i 0x7CCC).
5. **Poprawka "loader base sixteen times too high" jest w zrodlach Mecenasa** (commit
   `0f08e76`, w HEAD), ale samo repo mowi, ze jej nie wystarczyla: przekazanie sterowania
   nadal konczy sie wylaczeniem konsoli w pietnastu probach na pietnastie. To niezalezne
   potwierdzenie naszego wyniku, tyle ze na Fat, nie na Pro.
