# A53 knowledge handover: PS5 Pro, firmware 13.60

This document collects what this repository knows about the A53 security co-processor
(the MP4/DECI5S side) on PS5 Pro firmware 13.60, so that someone who is already dumping
A53 memory can start from verified numbers instead of rediscovering them. Every claim
below points at a file in this repository and gives the number that supports it. Where a
number in an older note did not survive re-measurement, the corrected value is given and
the old one is named. Where something was not measured, it is marked as not measured.

Scope: firmware 13.60 on PS5 Pro (system version word 0x13600007). Nothing here is
tested on retail PS5 (non-Pro) and nothing here is a PPR installation guide.

Section map: Environment, How the A53 image was obtained, What the image is and its
checksums, Confirmed PPR profile addresses, Hard negative result about the write opcode
with evidence, Transport limits and protocol, The 256 MB file is not a dump, Available
tooling, Open questions.

## Environment

| item | value | where it is written down |
|---|---|---|
| console | PS5 Pro, retail, firmware 13.60 | `notes/STAN-KONCOWY-KSTUFF-NG.md` lines 9 and 19 to 20 |
| system version word | 0x13600007 | `artifacts/writeprobe-log.txt` line 2, `notes/WRITEPROBE-MACIERZ.md` line 205 |
| kernel image file | `artifacts/kernel-1360-13.60.bin`, 67,108,864 B (64 MiB), sha256 `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804` | `notes/A53-FIRMWARE-W-ZRZUCIE.md` lines 6 to 7 |
| kernel image base | 0xffffffffc0c60000, so file offset = offset from kernel text and VA = base + offset | `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md` line 12 |
| kernel data base | 0xffffffffc1920000 (kernel text + 0xCC0000) | `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md` line 13, `notes/1360LINUX-PAMIEC-I-BOOT.md` line 774 |
| KERNEL_CODE_CAVE | 0xCB92C0 (a run of 0x90 NOP bytes in the image, used as a code cave) | `notes/1360LINUX-OFFSETY-13.60.md` line 146 |
| DATA_CAVE | 0x2D39000 (0x4000 bytes of zeros in the image) | `notes/1360LINUX-OFFSETY-13.60.md` line 151 |
| hypervisor region PA on Pro | 0x8E0000000 | `notes/1360LINUX-HVPRZED.md` line 275, `notes/1360LINUX-ZRODLA-PUBLICZNE.md` line 287 |
| hypervisor loader PA on Pro | 0x8E0800000 | `notes/1360LINUX-ZRODLA-PUBLICZNE.md` line 322 (upstream `source/offsets.c` line 96) |
| HV loader on Pro confirmed? | no, the value is source-defined and `hv_base_pa()` does not use it | `notes/KSTUFF-NG-CEL.md` line 27, `notes/1360LINUX-ZRODLA-PUBLICZNE.md` line 445 |
| A53 mailbox entry | `/dev/mp4/dump`, ioctl START 0x800c410b, ALTER_STATE 0x40184115, FINISH 0x8008410f, command word 0x20303000, buffer 2 MB | `artifacts/kstuff-a53-src/ppr/a53_transport.c` lines 39 to 44, `notes/STAN-KONCOWY-KSTUFF-NG.md` lines 80 to 87 |
| what the host side needs | kstuff for kernel memory read/write; byepervisor for kernel code hooks (reading kernel text with XOM on panics the console) | `notes/STAN-KONCOWY-KSTUFF-NG.md` lines 139 to 151, `tools/sdbgp/README.md` lines 145 to 153 |

Two environment facts that cost us days and are worth repeating:

1. Never guess a kernel address. Reading an unmapped page panics the console, and the
   direct-map base changes between boots (observed 0xffffbbc800000000). Walk page tables
   first (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 141 to 144).
2. The A53 buffer and the IOMMU register window are separate things. `softc + 0x40` is the
   register map VA (map of base + 0x8000 minus 0x8000), `softc + 0x48` is the base read
   from PCI configuration, `softc + 0x6a8` is the mailbox buffer size (0x200000),
   `softc + 0x6b0` is the device/IOMMU address (0x70000000), `softc + 0x6b8` is the kernel
   VA of the mailbox buffer. See `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md` lines 80 to
   113 and `tools/sdbgp/README.md` line 163.

Correction to one item that circulated in our own notes: there is no documented field
`softc + 0xa0` for a register map. The register map is `softc + 0x40` and `softc + 0x48`
as above. The value 0xa0 appears inside read packets as a size field, not as a softc
offset (`notes/STAN-KONCOWY-KSTUFF-NG.md` line 612).

## How the A53 image was obtained

The data path is the MP4 coredump mailbox, protocol SDBGP (DECI5S), not any device node
that returns memory directly (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 92 to 95). The host
publishes the 2 MB mailbox buffer with three ioctls on `/dev/mp4/dump`, the buffer VA is
read from `softc + 0x6b8`, and the host dumps the whole 2 MB buffer with kernel read
primitives. Result: `/data/a53_pkt.bin`, 2,097,152 B, sha256
`408268dcdbfce3b2fe96631aced8ce070f5072bbda0690d0ec6c530aca86c1ad`
(`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 103 to 104). A copy of that file sits outside the
repository at `<work>\a53_pkt.bin` and hashes to the same value. The buffer starts with a
device to host SDBGP packet: magic `0x73354450` at offset 0x0, a configuration command of
type 0x01010010 at offset 0x40 (self 0x18, total 0x18) and a read request of type
0x01040021 at offset 0x50 (self 0x20, total 0xb0) with six memory arguments.

Inside that 2 MB buffer there are nine read results. Each result is a 0x28 byte header:

```
+0x00 u32 self_size      = 0x28
+0x04 u32 access/type    = 0x02010001 (memory type 0x020100, access 1)
+0x08 u64 address
+0x10 u64 requested
+0x18 u64 transferred
+0x20 u32 status
+0x24 u32 padding
```

Layout confirmed against `tools/pprwatch/pprwatch.c` (comment near line 187 and check near
line 681: a read counts only when `transferred == requested` and `status == 0`) and against
the live logs `artifacts/a53layout-zasieg-2026-10-15b.txt` lines 10 to 23.

The nine results found in the 2 MB buffer, all with `status == 0` and
`transferred == requested`, measured with a scan that applies exactly the consistency rules
of `tools/rebuild-a53-image3.py` lines 8 to 17:

| address | requested | status | nonzero bytes in payload | first 8 bytes |
|---|---|---|---|---|
| 0x000000 | 0x01b000 | 0 | 101,621 | `00 1a 05 00 10 00 01 00` |
| 0x01b000 | 0x00d000 | 0 | 48,838 | `08 08 40 79 68 04 00 34` |
| 0x028000 | 0x03a000 | 0 | 219,508 | `1b 00 01 00 10 00 01 00` |
| 0x062000 | 0x003000 | 0 | 549 | `00 00 00 00 00 00 00 00` |
| 0x065000 | 0x003000 | 0 | 751 | `00 00 00 00 00 00 00 00` |
| 0x068000 | 0x001000 | 0 | 515 | `ff db ee 2e ff a3 cc b7` |
| 0x069000 | 0x01c000 | 0 | 64,286 | `c0 21 00 10 00 00 01 00` |
| 0x085000 | 0x031000 | 0 | 83,135 | `00 00 00 00 02 00 00 00` |
| 0x0b6000 | 0x00a000 | 0 | 40,564 | `7c 1a fb ff df 85 c3 7e` |

Total covered address space: 786,432 B. That is the number quoted in
`notes/STAN-KONCOWY-KSTUFF-NG.md` line 333 and `notes/A53-FIRMWARE-W-ZRZUCIE.md` line 348.
Total nonzero bytes: 559,767. Sum of 0x1b000 + 0xd000 + 0x3a000 + 0x3000 + 0x3000 + 0x1000
+ 0x1c000 + 0x31000 + 0xa000 = 0xC0000 = 786,432.

`tools/rebuild-a53-image3.py` walks the whole 2 MB buffer, accepts any position where
`self_size == 0x28`, `transferred == requested`, `1 <= requested <= 0x40000`,
`addr < 0x100000` and `addr + requested <= 0x100000`, and copies
`header + 0x28 .. header + 0x28 + requested` to image offset `addr`. The image is a 1 MiB
zero-filled buffer, so the nine regions sit at their physical addresses and everything else
is zero.

The raw reads were done in small pieces and verified per read. Two practical rules that
made reads reliable: check `status` and `transferred` in every result, and never treat the
buffer content as data unless the read succeeded. Our own notes describe one wrong
conclusion that came from ignoring this: bytes `ff 43 03 d1 ...` read back from
0x887f0000 were the leftover of a previous calibration read, not memory content
(`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 1084 to 1088).

What not to use as a source:

1. `<work>\a53_live.bin` is not a dump. See the dedicated section below.
2. `<work>\a53_regions\region_*.bin` (nine files, 786,432 B total) are the old extracts
   taken before the result-header fix. They are shifted by 0x6F8 and do not match the
   reconstructed image byte for byte. This was measured again for this handover:
   none of the nine files equals the corresponding image slice. Their history is in
   `notes/STAN-KONCOWY-KSTUFF-NG.md` lines 234 to 252. The file name
   `artifacts/region_00028000.bin` used in earlier internal lists does not exist in this
   repository; the only region files are the stale ones on D:.

## What the image is and its checksums

| file | size | sha256 | status |
|---|---|---|---|
| `artifacts/a53-obraz-odtworzony.bin` | 1,048,576 B | `884e741b79ba83d45698aa2571018a9156909ee9ceae570e81d62fe5ed9ace23` | PARTIAL: only 3 of the 9 regions carry data, 284,545 nonzero bytes |
| `<work>\a53_image\obraz_a53.bin` | 1,048,576 B | `c5784e05dd0b9eb75b04a66263d1fb5092eaa45c3a0fdbe3bc992ce560dab532` | COMPLETE: all 9 regions, 559,767 nonzero bytes, identical to a fresh run of `tools/rebuild-a53-image3.py` on the 2 MB dump |
| `<work>\a53_pkt.bin` | 2,097,152 B | `408268dcdbfce3b2fe96631aced8ce070f5072bbda0690d0ec6c530aca86c1ad` | raw mailbox dump, source of both images |

The difference between the two 1 MiB images is important and was re-measured for this
document. In `artifacts/a53-obraz-odtworzony.bin` only three regions match the dump:
0x028000 (219,508 nonzero bytes), 0x065000 (751) and 0x069000 (64,286). The regions
0x000000, 0x01b000, 0x062000, 0x068000, 0x085000 and 0x0b6000 are all zeros there, although
the dump holds 101,621, 48,838, 549, 515, 83,135 and 40,564 nonzero bytes respectively.
The complete image on D: is the one produced by the repository script from the same dump,
so the in-repo copy is a stale partial build. Share the checksums with the file; never mix
the two.

What the complete image contains (all offsets are physical, that is offsets in the file
and in the 0x0 to 0xC0000 space):

* io segment header at 0x028000: `1b 00 01 00 10 00 01 00 00 00 00 10 00 00 01 00`,
  then `c0 99 01 67 00 00 00 00 88 88 88 88 88 88 88 88`. The same 16 bytes came back from
  a live read at 0x28000 (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 501 to 508), so the
  reconstruction is byte-exact for the io segment.
* five copies of the PPR helper prologue `ff 43 03 d1 fd 7b 07 a9` at 0x00939C, 0x00C3E4,
  0x0248B4, 0x05B0F8 and 0x05B964 in the complete image. The copy at 0x05B964 is the one the
  profile uses; the copy at 0x05B0F8 is the second one visible in the io segment.
* the image has no strings, no symbol table and no SDBGP command or result constant as a
  32-bit literal. Measured on the complete image: 0 hits for 0x01040021, 0x01040031,
  0x02040021, 0x02040031, 0x01010010, 0x02010010, 0x01050020, 0x01050030, 0x01200021 and
  0x02010001. This matters for the negative result below and is discussed there.

Relationship to the 64 MiB kernel dump: the kernel contains no AArch64 code block larger
than about 1 KiB. In 64 MiB there are 0 instructions `ret` (0xD65F03C0), 0 `nop`
(0xD503201F), 0 prologues `stp x29,x30` (mask 0xFFC07FFF against 0xA9807BFD) and 0
`mov x29,sp` (0x910003FD);
16-byte chunk similarity between the A53 image and the kernel is 0.16 percent, and for the
code window 0x28000 to 0x38000 it is 0.02 percent measured on 32-byte chunks. The details
and calibration are in `notes/A53-FIRMWARE-W-ZRZUCIE.md` lines 222 to 245. The kernel is
not a source of the A53 image.

## Confirmed PPR profile addresses

The profile is `artifacts/kstuff-profile-1360.h` (5,446 B, sha256
`4bd4c29e85e299e51a3c121b0235e7f01e19fbad7f81a4075316b7ca9352a772`). It uses the
upstream `struct ppr_profile` from `drakmor/ppr-patch` with `PPR_ABI_LATE`.

Address translation used by the profile and verified as arithmetic: A53 VA (io) =
0x04E28000 + (PA - 0x28000); A53 VA (dev) = 0x06410000 + (PA - 0x85000). For example
helper PA 0x5B964 becomes VA 0x04E5B964, and 0x04E28000 + 0x33964 is exactly that.

The addresses below were each checked against the image at its offset.
The "stock word" is the 4-byte value at the physical offset; for branch sites the encoded
target was also computed from the immediate.

| profile field | PA (image offset) | A53 VA | stock word at offset | verified target or meaning |
|---|---|---|---|---|
| `helper_va` | 0x05B964 | 0x04E5B964 | prologue `ff 43 03 d1 fd 7b 07 a9` | PPR helper, 5 copies in the image |
| `precheck_va` | 0x05B9CC | 0x04E5B9CC | 0x35000ABC | CBNZ W28, +0x154, helper + 0x68 |
| `dispatch_va` | 0x05BAF4 | 0x04E5BAF4 | 0x97FFEFED | BL to 0x057AA8, helper + 0x190 |
| `aes_site_va[0]` | 0x057C14 | 0x04E57C14 | 0x97FF4D44 | BL to 0x02B124 (AES descriptor) |
| `aes_site_va[1]` | 0x057D4C | 0x04E57D4C | 0x97FF4CF6 | BL to 0x02B124 (AES descriptor) |
| `sha_auth_site_va` | 0x05BC00 | 0x04E5BC00 | 0x97FFF3B3 | BL to 0x058ACC, helper + 0x29C |
| `call_va[0]` | 0x04A120 | 0x04E4A120 | 0x94004611 | BL to 0x05B964 (helper) |
| `call_va[1]` | 0x04B860 | 0x04E4B860 | 0x94004041 | BL to 0x05B964 (helper) |
| `aes_descriptor_va` | 0x02B124 | 0x04E2B124 | 0xD100C3FF (`sub sp,sp,#0x30`) | AES_DESCRIPTOR, `PPR_ABI_LATE`, 40 B |
| `plaintext_descriptor_va` | 0x02B2F0 | 0x04E2B2F0 | 0xD100C3FF (`sub sp,sp,#0x30`) | PLAINTEXT_DESCRIPTOR, `PPR_ABI_LATE`, 48 B |
| `plaintext_direct_va` | 0x05C7E8 | 0x04E5C7E8 | prologue `fd 7b ba a9 fc 6f 01 a9` | plaintext direct path |
| `plaintext_idma_va` | 0x058534 | 0x04E58534 | prologue `fd 7b bb a9 fa 67 01 a9` | plaintext IDMA path |
| `common_return_va` | 0x05BC20 | 0x04E5BC20 | 0x2A1F03E0 (`mov w0,wzr`) | helper + 0x2BC |
| `common_error_va` | 0x05BB20 | 0x04E5BB20 | derived | helper + 0x1BC |
| `dispatch_native_va` | 0x057AA8 | 0x04E57AA8 | prologue `ff 43 02 d1 fd 7b 03 a9` | start of function |

How these were confirmed, in order of strength:

1. The AES descriptor and the plaintext descriptor match the upstream generator
   signatures byte for byte. `PPR_ABI_LATE` AES signature, 40 bytes
   `ffc300d1fd7b02a9fd83009148fc6fd3490080522801280a5f0000f16a00e0d24bbc60d3083d50d3`
   from `artifacts/ppr-patch-upstream/generate_ppr_profiles.py` lines 250 to 263 is exactly
   the content at offset 0x02B124. The 48-byte plaintext signature from lines 265 to 282 is
   exactly the content at 0x02B2F0. Both are unique occurrences in the image.
2. The five branch sites carry stock words that decode to the expected targets (table
   above). This is a check of the image against the profile, not a disassembly claim: the
   immediate is extracted from the 32-bit word at the offset and the target is computed.
3. The four helper-relative fields satisfy the profile arithmetic (precheck +0x68,
   dispatch +0x190, sha_auth_site +0x29C, common_return +0x2BC) and the image bytes at
   those offsets are the stock words listed by the profile.
4. Live reads agree with the image. The read at 0x28000 returned the io header bytes, the
   read at 0x5B964 returned the helper prologue, and the read at 0x5B9CC returned
   `bc 0a 00 35` (CBNZ W28), all quoted in `notes/STAN-KONCOWY-KSTUFF-NG.md` lines 274 to
   284 and 501 to 508.

What is derived rather than measured, per the profile's own header comment
(`artifacts/kstuff-profile-1360.h` lines 41 to 64): `io_mapped_size`, `io_file_size`,
`dev_mapped_size`, `dev_file_size`, `runtime_cave_va`, `plaintext_cave_va`, and
`dev_file_size` is explicitly marked unconfirmed. The profile has only two `call_va`
entries filled (0x04E4A120 and 0x04E4B860) because the dev window call sites were not in
the image we had. The complete image does contain dev window data (see Open questions).

## Hard negative result about the write opcode with evidence

Result: firmware 13.60 does not expose a host to A53 memory write through the mailbox.
Opcode `SDBGP_WRITE_MEMORY` 0x01040031 does not exist in the kernel image and no write
attempt changes A53 memory. The corrected conclusion in one line: there is no write path
through the mailbox, so anything that needs to modify A53 code has to go through code
execution, not through a write command.

Evidence, in the order it should be checked:

1. Kernel scan, 64 MiB, byte search for the little-endian value:
   0x01040031 has 0 occurrences. For comparison 0x01040021 (read) has 29 occurrences, all
   inside kernel text (below 0xCC0000), in the range 0xC292C2 to 0xC31B9A, which is the
   packet builder area. The result type 0x02040031 has 1 occurrence at 0x3E1568F, which is
   above 0xCC0000, so it is data, not a builder. `tools/sdbgp/README.md` line 64 reports 28
   instruction sites for the read opcode from its instruction sweep; our raw 4-byte scan
   gives 29 occurrences. The one-hit difference is a counting difference and does not
   change the result: the two read builders sit at instructions 0xC292BE and 0xC296C8, both
   inside the function 0xC29100 to 0xC2EE50, and no write builder exists anywhere.
   Machine-checked command scan is in `tools/sdbgp/offline-find-builders.py`, output
   `artifacts/sdbgp-offline.txt` lines 35 and 65.
2. A53 memory scan. 0x01040031 has 0 occurrences and 0x02040031 has 0 occurrences in the
   A53 image, both in the partial in-repo copy and in the complete 1 MiB reconstruction.
   State this honestly: the same scan finds 0 occurrences of the read opcode 0x01040021 and
   of every other known SDBGP command or result constant, so the A53 image alone cannot
   prove the absence of write. It only fails to contradict it. The discriminating evidence
   is the kernel scan (where packets are built), the measured write, and the command
   inventory in the 256 MB block (below).
3. Measured write, `tools/mboxwrite`. Packets of type 0x01040031 with a 16-byte marker were
   sent to A53 at paused code locations. Three access widths (1, 4, 6), memory type
   0x020000. Result header in the response: self 0x20, access/type word 0x02010001,
   requested 0x0, transferred 0x10, status 0x10. Memory read back identical to the state
   before the write. Response was a 0x60 byte packet with magic 0x73354450 from
   0x80ff0201 and no result of type 0x02040031. Raw logs:
   `artifacts/mbox_write-2026-10-15.txt` lines 6 to 20 (address 0x61F00, accesses 1, 4, 6),
   `artifacts/mbox_write-2026-10-15c.txt` lines 6 to 24, `artifacts/mbox_write-log.txt` and
   `artifacts/mbox_write7-log.txt` (address 0xc3000), `artifacts/mbox_write4-log.txt`,
   `mbox_write5-log.txt`, `mbox_write6-log.txt` and `mbox_write2-log.txt` (address
   0x200000). Summary: `notes/KSTUFF-PPR-V4.md` lines 120 to 135, especially line 126
   ("the response contains no write result, type 0x02040031") and line 131 ("A53 on 13.60
   does not execute command 0x01040031").
4. The 48-probe write matrix (`tools/writeprobe`) was designed to close the remaining
   doubt about address, memory type and access width (6 addresses, 4 memory types, 2
   access widths). It is built and offline-verified: 672 checks with 0 errors and
   `WERYFIKACJA OK` (`notes/WRITEPROBE-MACIERZ.md` lines 318 to 321), artifact
   `artifacts/writeprobe.elf` 193,632 B sha256
   `16232d8c8a88c89f967df485ffdd436c7f88b7ce90b088331b96fbbc4dc644e4`. But it was NOT
   executed successfully on the console: the run log `artifacts/writeprobe-log.txt` lines 9
   to 20 shows the five image anchors failing with transport code -2 after 3175 to 3182 ms
   each, and the summary line `kotwice na poczatku: 0 z 5 zgodnych`. No probe was sent.
   Do not cite the 48-probe matrix as a measurement.

The A53 command set we did observe on the wire, from the unique 256 kB mailbox block in
the 256 MB file: command types 0x01050020 (region list, command header at 0x28 with
self 0x28 and total 0xd0), 0x01050030 (register group read, header at 0xF8, type at 0x100)
and 0x01200021 (dump request, type at 0x128); result types 0x02010010 (configuration, at
0x188) and 0x02040021 (read, at 0x2d0). The word 0x02010001 at 0x4 is not a result type:
it is the access/type field of the read result header (memory type 0x020100, access 1).
There is no write command and no write result in that inventory. The semantic labels for
the three command types come from our notes (`notes/KSTUFF-PPR-V4.md` lines 150 to 152,
`tools/sdbgp/sdbgp.c` lines 242 to 244); they are labels, not proven semantics.

One more negative that matters for anyone trying to port the upstream PPR patch: the
transport cannot reach the layout page at 0x887F0000. The layout read returns
`segmentow 0, indeks io 2034264680, indeks dev 1895829823` and the tool reports
`BLAD: liczba segmentow nieprawdopodobna` (`artifacts/a53layout-zasieg-2026-10-15b.txt`
lines 52 to 55). That is why the profile replaces layout validation with five image
anchors (`notes/KSTUFF-PPR-V3.md` lines 117 to 134).

## Transport limits and protocol

Read window: only A53 SRAM from 0x0 to 0xBFFFF is readable, 768 kB, described in our notes
as three banks of 256 kB. Measured at twenty byte reads, one address at a time
(`artifacts/a53layout-zasieg-2026-10-15b.txt` lines 10 to 51):

| address | transferred | status | meaning |
|---|---|---|---|
| 0x0 | 0x20 | 0x0 | readable |
| 0x28000 | 0x20 | 0x0 | readable, content matches the image |
| 0xb0000 | 0x20 | 0x0 | readable (zeros at that time) |
| 0xc0000 | 0x0 | 0x20 | not readable |
| 0x100000, 0x200000, 0x400000, 0x4000000 | 0x0 | 0x20 | not readable |
| 0x6410000, 0x887f000, 0x887f0000, 0x9000000, 0x80000000 | 0x0 | 0x20 | not readable |

Rules that follow from this and from the 256 MB measurement:

1. `transferred == 0` with `status == 0x20` is a failed read, not an empty region. The
   buffer then holds the previous read's leftovers (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines
   1084 to 1088).
2. Big reads do not work. Reads of 0x40000 all failed with the same result
   (transferred 0, status 0x20) and returned one identical block 1024 times (the 256 MB
   file). Small reads are address-correct: 32 bytes and 4 KiB reads returned different
   content for addresses far apart, for example 0x496B4 and 0x896B4 returned different
   bytes while 0x5B964 returned the helper prologue (`notes/STAN-KONCOWY-KSTUFF-NG.md`
   lines 558 to 587). Use reads of a few KiB and verify every header.
3. Addresses in the protocol are A53 physical addresses, not host physical addresses.
   Proof: a host direct-map read at 0x28000 returns `4e 94 63 5b ba 17 9b 58`, while the
   transport at the same address returns `1b 00 01 00 10 00 01 00`
   (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 1090 to 1093).

Packet format, confirmed against `artifacts/kstuff-a53-src/ppr/a53_transport.c` lines 46 to
86 and against captured buffers:

```
+0x00 deci5s_hdr:
      u32 magic       0x73354450 ("PD5s" little endian)
      u32 self_size   0x28
      u32 packet_size
      u32 src         0x80ff0180 (kernel) or 0x80ff0200 (device/MP4)
      u32 dst         0x80ff0201 (MP4/A53) or 0x80ff0180 (kernel)
      u32 protocol    0x20000201 (SDBGP) or 0x20000200 (variant seen in the block)
      u32 attr, u32 user_data, u64 timestamp
+0x28 deci5s_cmd_hdr:
      u32 dcmp 0x18, u32 code, u32 sequence_no, u32 packet_no, u32 attr,
      u8 num_commands, u8 reserved[3]
+0x40 commands, step = total_size (not self_size), each:
      u32 self_size, u32 total_size, u32 type, u32 flags,
      u32 command_no, u32 packet_no, u32 pid, u32 tid, u32 n_args
+0x20 from the start of a read command: memory arguments, 0x18 bytes each:
      u32 self_size 0x18, u32 (mem_type << 8) | access_size, u64 addr, u64 size
```

Numbers that were measured or read out of code and that are safe to reuse:

* `SDBGP_READ_MEMORY` 0x01040021, `SDBGP_WRITE_MEMORY` 0x01040031,
  `SDBGP_GET_CONF` 0x01010010, results 0x02040021 and 0x02010010,
  `MEM_TYPE_PA_TO_EL3` 0x020000, `MP4_COREDUMP_CMD` 0x20303000,
  ioctls 0x800c410b, 0x40184115, 0x8008410f: `a53_transport.c` lines 23 to 44.
* The read memory argument word seen in every successful read is 0x02010001, that is
  memory type 0x020100 with access 1 (`artifacts/a53layout-zasieg-2026-10-15b.txt` lines 10
  to 18).
* The data of a read result starts at header + 0x28. Inside the raw mailbox buffer the
  offset that works is 0x90 from the start of the packet for a 4 KiB read; a 32-byte read
  did not carry the pattern at that offset, so the tool calibrates the offset on every run
  (`artifacts/a53layout-zasieg-2026-10-15b.txt` lines 5 to 8).
* A command chain is walked with `total_size`, not `self_size`; a read command has
  self 0x20 and total 0xb0, and the next command is 0xb0 bytes later
  (`tools/sdbgp2/README.md` lines 88 to 96).
* The kernel builds packets in two windows: from the buffer base and at offset
  `(packet_size + 7) & ~7`. Both are parsed by `tools/sdbgp` and `tools/sdbgp2`
  (`tools/sdbgp/README.md` lines 120 to 122).
* The mailbox buffer is at `softc + 0x6b8`, size 0x200000, device address 0x70000000;
  observed values in `[stan]` lines of `tools/sdbgp/README.md` line 163 and in every
  `mbox_write*.txt` log, for example `artifacts/mbox_write-2026-10-15.txt` line 5.

## The 256 MB file is not a dump

File: `<work>\a53_live.bin`, 268,435,456 B, sha256
`41105cc06b90b88c62ad9ef283153278811dc47e0f60f2e1ddf1ca0897d3fa0b`. It is 1024 blocks of
0x40000 bytes. Each block starts with a 0x28 result header and the payload is identical in
all 1024 blocks: one payload, sha1 `e9295a5d932064cf8b630821455c92b8fb91e472`. Measured
again for this handover: all 1024 headers carry status 0x20 and transferred 0, and all
1024 requests were 0x40000 with distinct addresses from 0x0 to 0xFFC0000. Unique content is
one block, 262,144 B, of which the payload after the header is 262,104 B.

So it is one mailbox buffer, repeated 1024 times, not 256 MB of A53 memory. The read
failed in every block (status 0x20, transferred 0), and the tool that produced it counted
"good chunks" by checking only the response magic. The full analysis is
`notes/A53-LIVE-256MB-ANALIZA.md` lines 17 to 73 and 360 to 393. Do not hand this file to
anyone as data, and do not derive addresses from it.

It is still useful for one reason: its single unique block contains a real captured A53
mailbox packet, and that packet is the only place where we see the A53 firmware version
descriptor and banner. Measured offsets inside the block (block 0, identical in all 1024
blocks):

| offset | content |
|---|---|
| 0x00 | result header, self 0x28, access/type 0x02010001, address 0x0, requested 0x40000, transferred 0x0, status 0x20 |
| 0x28 | command header, self 0x28, total 0xd0, type 0x01050020, flags 0, command number 2 |
| 0x48 | descriptor, length 0x2a, followed by entries `xx 00 01 ff` (00, 01, 02, 03, 04, 05) |
| 0x100 | type 0x01050030 (command header starts at 0xF8) |
| 0x128 | type 0x01200021 |
| 0x140 | nested SDBGP packet: magic 0x73354450, self 0x28, packet size 0x00067d28, src 0x80ff0200, dst 0x80ff0180, protocol 0x20000200 |
| 0x188 | result type 0x02010010 |
| 0x1e0 | 16-byte build id `45 19 af ca fb 94 9f 4a a4 94 58 22 64 a1 4b 45` (an earlier note said 0x1ec, the measured offset is 0x1e0) |
| 0x1f0 | `04 00 00 00 10 00 00 00 03 00 00 00` |
| 0x1fc | `47 4e 55 00` ("GNU") |
| 0x200 | 0x13590001, 0x00000000, 0x00000001, 0x13600007 |
| 0x228 | banner `cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358` |
| 0x2d0 | result type 0x02040021 |
| 0x3a8 to 0x28000 | ARM64 code and constants, 162,904 B, 519 `ret`, first bytes `00 29 21 0b c0 03 5f d6` |

Whole file statistics that match the note: 531,456 `ret` and 106,496 `nop` in 256 MB
(519 and 104 per unique block), no ELF, PE, gzip, xz, zstd, lz4 or FDT header anywhere
(`notes/A53-LIVE-256MB-ANALIZA.md` lines 187 to 195 and 105 to 109).

The block's address in A53 memory is unknown and must not be guessed: all 1024 requests
returned the same content, so the address field in the header is only an echo of the
request. The block itself contains plausible A53 pointers in the ranges 0x0408xxxx,
0x0486xxxx, 0x04c0xxxx and 0x0641xxxx, which is why it is likely a genuine A53 memory
window, but that does not identify where it lives
(`notes/A53-LIVE-256MB-ANALIZA.md` lines 114 to 134 and 360 to 371).

## Available tooling

| path | what it does | size | status |
|---|---|---|---|
| `tools/sdbgp/` | kernel hook on the SDBGP packet builder (function at image + 0xC29100, VA 0xffffffffc1889100), logs every call, parses both packet windows, one hook at a time | 16 files, 393,648 B, `sdbgp.elf` 256,528 B | builds; parser test `TEST OK` (`artifacts/sdbgp-test-parser.txt`); console run needs byepervisor and no kstuff |
| `tools/mboxwrite/` | sends a type 0x01040031 write packet through the mailbox and verifies memory before and after; the tool that produced the write negative | 2 files, 22,024 B, `mboxwrite.c` 21,819 B | used on console, logs in `artifacts/mbox_write*.txt` |
| `tools/a53layout/` | reads A53 memory under real addresses with per-run data offset calibration; also tries to read the layout page at 0x887F0000 | 2 files, 25,988 B, `a53layout.c` 25,781 B | used on console, logs in `artifacts/a53layout-*` |
| `tools/a53win/` | read-only watcher of the window registers `BAR2+0xf6000` to `+0xfa000` and driver context fields during a coredump, to find what switches the read window | 2 files, 8,905 B, `a53win.c` 8,709 B | built, log `artifacts/a53win-log.txt` |
| `tools/mp4cmd/` | kernel hook on the queue insert function (image + 0x4F9670), logs the 16-byte IOMMU command and its device id; does not hook SDBGP | 13 files, 330,199 B, `mp4cmd.elf` 230,192 B | built; manifest `artifacts/mp4cmd.elf.json`; it established that the queue opcodes are not SDBGP opcodes |
| `tools/kstuff-ppr-v5/` | kstuff build with the PPR module and a write probe per cave, plus `skan-zapisu-a53.py` which counts 0x01040031 and 0x02040031 in the kernel and the nine regions | 12 files, 64,620 B | offline verified, `verify_v5.py` 105 checks 0 errors; the console run is scripted but its result is not in the repo |
| `tools/writeprobe/` | 48-probe write matrix (6 addresses x 4 memory types x 2 access widths) with per-probe read, marker write, wait, read back, restore and verdict | 8 files, 273,041 B, `writeprobe.elf` 193,632 B | built, offline 672 checks 0 errors; console run aborted at the anchor gate (`artifacts/writeprobe-log.txt`) |
| `tools/kcore.py` | read-only `/proc/kcore` reader: list PT_LOAD segments, peek/read by VA, read by physical base + offset | 4,543 B | helper, no console risk |
| `tools/rebuild-a53-image3.py` | rebuilds the 1 MiB image from the 2 MB mailbox dump using result header consistency | 3,216 B | produced the complete image `c5784e05...` |
| `tools/split-a53-regions.py` | splits the dump into the nine region files | 3,403 B | produced the stale D: region files, do not trust them |
| `artifacts/kstuff-a53-src/ppr/a53_transport.c` | reference transport used for the packet layout and constants | 58,216 B | read-only reference, 1,596 lines |

Payloads worth shipping together with the sources: `artifacts/sdbgp.elf`,
`artifacts/mp4cmd.elf`, `artifacts/writeprobe.elf`, `artifacts/a53patch.elf` (bounded PPR
patch payload, 222,328 B, sha256 `026efe0c5b6f49f7bcf7b6b18dc124c73eb81c361ac4fc61d51070711991f63e`;
see `notes/A53-BUFOR-I-PUNKT-HACZENIA.md` lines 223 to 288). All payloads are built with
`PS5_PAYLOAD_SDK` and `prospero-clang`; the hook API is the byepervisor `khook.c`, and it
clobbers `rax`, `rcx` and `r8`, which is why hooks must be placed only where those
registers are dead (`tools/sdbgp/README.md` lines 72 to 86).

## Open questions

These are the things this repository does not know. They are listed with the measurement
that would settle each.

1. How does A53 dispatch command types? The image contains no SDBGP command or result
   constant as a 32-bit literal (0 hits for all ten constants we know). Either the
   dispatcher compares decoded fields, or the table lives in a region we do not have, or
   the host bridge translates types. Measurement: find the handler that consumes the
   packet at the io base and trace the comparisons; our attempts are
   `tools/a53-command-tables.py`, `tools/a53-find-handler-table.py`,
   `tools/a53-resolve-handlers.py`, `tools/classify-a53-procedures.py`.
2. What do 0x01050020, 0x01050030 and 0x01200021 do exactly? Our labels (region list,
   register group read, dump request) come from packet shapes, not from handler analysis
   (`notes/KSTUFF-PPR-V4.md` lines 150 to 152). If one of them accepts a program payload,
   that is the code execution path. Not proven either way.
3. Where are the dev window call sites? The complete image has 83,135 nonzero bytes at
   0x85000 and 209 `BL` instructions in that window; none of the 209 targets, computed with
   the dev VA formula, resolves to the helper VA 0x04E5B964, and the five helper copies all
   sit below 0x5C000. So the earlier conclusion stands: in 13.60 the dev window has no copy
   of this helper and does not call it (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 349 to 355).
   What is still open is what the 83,135 nonzero bytes in that window actually are and
   whether the dev path uses a different dispatch function. The profile has only the two io
   call sites filled.
4. Why does the in-repo image lack six regions? The file is a stale partial build; the
   script and the dump produce the full one. Not a firmware question, a repository hygiene
   question.
5. What address does the unique 256 kB block live at? Unknown; the address field is an echo.
   Measurement: correlate the block's pointers with live reads from a known address window,
   or capture the request that produced it.
6. Is the code at 0x3a8 to 0x28000 in that block a loaded program image, a firmware region,
   or a dump payload? It has a version descriptor, build id, banner and 519 `ret`, so it is
   ARM64 code, but its entry point and mapping are unknown.
7. Are there other write opcodes? The matrix changed address, memory type and access width
   but not the opcode; 0x01050031, 0x02050031 and similar were never tried because they
   appear neither in the kernel nor in A53 memory (`notes/WRITEPROBE-MACIERZ.md` lines 337
   to 353).
8. Is the hypervisor loader address 0x8E0800000 real on Pro? Only the source says so; the
   note marks the Pro path as unconfirmed (`notes/KSTUFF-NG-CEL.md` line 27).
9. Does the read window change? Reads of 0x40000 fail while smaller reads are
   address-correct, and the kernel itself read nine different regions, so some mechanism
   selects what the transport sees. `BAR2+0xf6000` to `+0xfa000` were excluded as the
   selector (`notes/STAN-KONCOWY-KSTUFF-NG.md` lines 215 to 228), and `tools/a53win` was
   written to look there; its log `artifacts/a53win-log.txt` is 1,437 B and does not settle
   it.

If you have an A53 dump and working code execution on the A53 side, the three things that
would help most in return are: the address of the unique 256 kB block, the handler
addresses for the command types above, and whether 0x01050020 or 0x01200021 accepts a
payload that is later executed.
