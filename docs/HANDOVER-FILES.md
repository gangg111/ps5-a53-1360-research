# Handover files: what to share with EchoStretch

This list covers the material behind `notes/HANDOVER-A53-13.60-EN.md`. It is written so
that a single archive can be assembled without guesswork. Rules that matter more than the
list itself:

1. Always ship the sha256 with the file. Two different 1 MiB A53 images exist in this
   project (one partial, one complete) and mixing them silently invalidates the profile
   check.
2. Do not ship `<work>\a53_live.bin` as data. It is not a dump (see the DO NOT SHIP
   section).
3. Do not ship the `<work>\a53_regions\region_*.bin` files. They are the old extracts
   taken before the result-header fix and they do not match the rebuilt image.
4. The 64 MiB kernel dump is the only large necessary file. Everything else together is a
   few megabytes.

Flags: IMPORTANT means needed to reproduce or verify a claim. LARGE means over 10 MiB.
OPTIONAL means useful context but not needed for the core claims. DO NOT SHIP marks files
that would mislead the receiver.

## Documents (start here)

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `notes/HANDOVER-A53-13.60-EN.md` | 34,827 | `b0b2cc15ed0d774694a637d0394b8f425a42b46fb411899d755eeb8ac738ebe6` | the main English document: environment, image, profile, write negative, transport, 256 MB warning, tooling, open questions | IMPORTANT |
| `notes/HANDOVER-MESSAGE-EN.txt` | 1,322 | `31665e112e682ec6f641d4074bea7e2ba0e6127c2239673534c92bc83609daa9` | short cover message, ready to send on X or as a comment | IMPORTANT |
| `notes/HANDOVER-FILES.md` | this file | hash changes whenever this file is edited, so it is not listed | the file list itself | OPTIONAL |

## A53 data

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `<work>\a53_image\obraz_a53.bin` | 1,048,576 | `c5784e05dd0b9eb75b04a66263d1fb5092eaa45c3a0fdbe3bc992ce560dab532` | COMPLETE A53 image: nine regions, 559,767 nonzero bytes, byte-identical to a fresh run of `tools/rebuild-a53-image3.py` on the 2 MB dump. This is the file to share as "the A53 image". | IMPORTANT |
| `<work>\a53_pkt.bin` | 2,097,152 | `408268dcdbfce3b2fe96631aced8ce070f5072bbda0690d0ec6c530aca86c1ad` | raw mailbox buffer dump (`/data/a53_pkt.bin` on the console), source of both images; starts with the device to host SDBGP packet and contains nine read results with status 0 | IMPORTANT |
| `artifacts/a53-obraz-odtworzony.bin` | 1,048,576 | `884e741b79ba83d45698aa2571018a9156909ee9ceae570e81d62fe5ed9ace23` | PARTIAL in-repo image: only 3 of 9 regions carry data, 284,545 nonzero bytes. Ship only together with the explanation in the main document, otherwise the receiver will find zeros where the dev window should be. | OPTIONAL |
| `artifacts/kernel-1360-13.60.bin` | 67,108,864 | `306bed7b7317b5b339457bb45c190f8dd9003d456e84824228daf7a2609bd804` | 64 MiB kernel dump, base 0xffffffffc0c60000; the file all kernel offsets and the opcode counts refer to | IMPORTANT, LARGE |

## Profile

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `artifacts/kstuff-profile-1360.h` | 5,446 | `4bd4c29e85e299e51a3c121b0235e7f01e19fbad7f81a4075316b7ca9352a772` | confirmed PPR profile for 13.60 in upstream `struct ppr_profile` form, `PPR_ABI_LATE`; every stock word in it was checked against the image | IMPORTANT |
| `artifacts/ppr-1360/ppr_profiles_1360.inc` | 111,468 | `37c04d426aadaf2a7eb6afefd56cce47d8cea077ecd6a2fbe2f4c739cb7332eb` | generated profile table in the upstream `ppr_profiles[]` format (13.60 entry at line 2425); useful if the receiver builds the upstream `ppr_patch.c` tree | OPTIONAL |

## Evidence logs (small, they carry the negative result)

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `artifacts/mbox_write-2026-10-15.txt` | 1,223 | `f7629bd5c20dfdc5b1ca1f040ff74f95582c0c4a3c9853f98532f6e43047cc21` | write attempt at PA 0x61F00, access widths 1, 4 and 6: result header self 0x20, transferred 0x10, status 0x10, memory unchanged, no write result in the response | IMPORTANT |
| `artifacts/mbox_write-log.txt` | 695 | `7c5e2007dbbf1f4b66ee8cc0eae61b1e3ca19ec8aba969de91b45e5ad31a5e75` | write attempt at 0x200000, read before and after identical, marker not written | IMPORTANT |
| `artifacts/a53layout-zasieg-2026-10-15b.txt` | 3,883 | `2dbd382f89d37a3c5532f89d4ee73bd57a4873348b004167336b4cd5a2f1c54b` | transport range measurement: 0x0, 0x28000, 0xb0000 readable with transferred 0x20 and status 0; 0xc0000 and everything above with transferred 0 and status 0x20; layout page at 0x887F0000 unreadable | IMPORTANT |
| `artifacts/writeprobe-log.txt` | 1,092 | `9592680d4feb90df72c58dcbf1c32d0a5a98e6c988d16c2ace0ae16eebf4cc6c` | proof that the 48-probe write matrix did NOT run: five anchors failed with code -2, summary "0 z 5 zgodnych", no probe sent | IMPORTANT |
| `artifacts/sdbgp-offline.txt` | 5,903 | `ac064507ee7d301721aaa0923f11909999751529221842c12fffa6cb6c39ca96` | offline scan of the kernel: 28 read opcode sites, 1 configuration site, 0 write opcode sites | IMPORTANT |
| `artifacts/sdbgp-test-parser.txt` | 5,154 | `b88907d2faa27c3600987dcefbdb1ae7f76f640930f038f02702608db6a57b1a` | parser test on reconstructed packets, result TEST OK (0 errors) | OPTIONAL |
| `artifacts/a53win-log.txt` | 1,437 | `0ed91367ed524086d305db5caf6d67c57da59d1fe5cb8a0f2059824d73bb7fd5` | window register watcher log; does not settle what switches the read window | OPTIONAL |

## Notes that back the document

All are Polish; the English document is the translation of the verified content. Sizes and
hashes are for the exact revision that the handover was built from.

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `notes/A53-FIRMWARE-W-ZRZUCIE.md` | 21,576 | `8cbc964c2f92536fde88fda02c4c64d860c16b10e139737db06016d368f6c235` | what is in the 64 MiB kernel: WiFi ARM32 firmware, BT ARM32 firmware, zero AArch64, calibration of the ARM detectors | IMPORTANT |
| `notes/A53-LIVE-256MB-ANALIZA.md` | 22,274 | `86e831ca2f4ca8178fa134088bebed7bbda1d5429548fdabf9ff8cc4e5bfc148` | proof that the 256 MB file is one 256 kB block repeated 1024 times, plus the block content map and offsets | IMPORTANT |
| `notes/A53-BUFOR-I-PUNKT-HACZENIA.md` | 18,112 | `1510b351227b35b7a98477582804a68afa27c49e74e3d19c223ee52e19d3aeea` | where the A53 buffer lives in the kernel, why there is no kernel function to hook before upload, the `a53patch.elf` payload | IMPORTANT |
| `notes/STAN-KONCOWY-KSTUFF-NG.md` | 54,024 | `427d0bb64c8ad67dca5e5ff65eca8e2e617d1850652de957e2d6bc463da29675` | the long project log: transport discovery, profile confirmation, write verdict, transport range measurement (rounds 133 to 137), tool inventory | IMPORTANT, largest text |
| `notes/1360LINUX-OFFSETY-13.60.md` | 34,817 | `aaa98b329a8f0f4d1e43138ac4e912397459615391e3f6914b0aefe17cc1a9c4` | kernel and loader offsets for 13.60, including both code caves and the env table | IMPORTANT |
| `notes/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md` | 25,140 | `0643bcce7d838ca3c51a7f0d4fc591f7581582d8b3096e9649d2e2e34a0a4cdb` | how the IOMMU register base is derived, softc fields, device table entry, MP4 device id | IMPORTANT |
| `notes/KSTUFF-PPR-V3.md` | 23,197 | `bbc29f903027333447be17f97bba49b41d5917effc0ae182176359505a21dd2b` | why the upstream layout validation cannot work on 13.60, the 768 kB SRAM window, the five image anchors | OPTIONAL |
| `notes/KSTUFF-PPR-V4.md` | 18,494 | `ccb7cbaaa841b57f78be9bb658f1fd2e2422759b4dab6c3aeb99eb95e389d168` | write diagnostics and the command type table (read, configuration, region list, dump request; no write) | IMPORTANT |
| `notes/KSTUFF-PPR-V5.md` | 22,444 | `027cd5a8ad9aee909b1586904b99240d99df09b6a1f20e8bb81f07aed8372485` | v5 build, cave layout, the two expected console outcomes, the verification list | OPTIONAL |
| `notes/WRITEPROBE-MACIERZ.md` | 19,388 | `26d9707c1d0c1cf7415da68dbc2267422b65ad6e09da98927798895b57ae5126` | design of the 48-probe write matrix, safety gates, how to read its log | OPTIONAL |

## Tools

Directory rows give file count and total bytes. Key files inside them are hashed
separately.

| path | bytes | sha256 of key file | description | flag |
|---|---|---|---|---|
| `tools/sdbgp/` (16 files, 393,648 B) | `sdbgp.c` 67,770 | `3ca684af1e3a977d3f4adaa4bffa8bf3280c82874db04b2a686849f0fa3306f3` | kernel hook on the SDBGP builder at image + 0xC29100, parses both packet windows; `sdbgp.elf` 256,528 B sha256 `6964734967521ffc8bb1d8a18cf5d7bd62d4ee9e727b2eee66a2876e3ea895d1` | IMPORTANT |
| `tools/mboxwrite/` (2 files, 22,024 B) | `mboxwrite.c` 21,819 | `20a2b3772a512b5b9b34e186a47d41e06bf30164a0763a645163223534421ba1` | mailbox write test; the tool that produced the write negative | IMPORTANT |
| `tools/a53layout/` (2 files, 25,988 B) | `a53layout.c` 25,781 | `7a2e1e5d7f2a973c269755f1ed2c462cb860b365bc02f385406f34df5648ca08` | A53 memory reader with per-run data offset calibration; produced the range log | IMPORTANT |
| `tools/a53win/` (2 files, 8,905 B) | `a53win.c` 8,709 | `3eda79997e57a88fa92d86a93b9e52dcc382368f0610e95169e23a3af71342df` | read-only window register watcher, seeks what switches the read window | OPTIONAL |
| `tools/mp4cmd/` (13 files, 330,199 B) | `mp4cmd.c` 57,043 | `cf1ae95d9e60b8e347c1b09ca27e39fc5a166fc6a027071822622e85600bc61d` | kernel hook on the IOMMU queue insert at image + 0x4F9670; `mp4cmd.elf` 230,192 B sha256 `ce821b5c783d18b56cf629cf696ec6e5b1a6c6a704ce8d7119614ac08994e288` | OPTIONAL |
| `tools/kstuff-ppr-v5/` (12 files, 64,620 B) | `verify_v5.py` 15,659 | `a70198a44534d1fc0f142ae9c6a5aebeb053276a1b222112468513c41ef1d5bd` | kstuff build with PPR and write probe, plus `skan-zapisu-a53.py`; offline checks pass, no console result archived | OPTIONAL |
| `tools/writeprobe/` (8 files, 273,041 B) | `writeprobe.c` 50,049 | `d24540dc86a2d1440a7a157c58cf1f414cd131519d340c5236987bc56ccb80f7` | 48-probe write matrix; `writeprobe.elf` 193,632 B sha256 `16232d8c8a88c89f967df485ffdd436c7f88b7ce90b088331b96fbbc4dc644e4` | IMPORTANT |
| `tools/kcore.py` | 4,543 | `04c8ddb07531a0d3bd7df5b5de65aaf7fa8bfe004b63e900efae26afd0e832d5` | read-only `/proc/kcore` reader | OPTIONAL |
| `tools/rebuild-a53-image3.py` | 3,216 | `1ebfbec6a32694577abc8945994c7f70c4ad3ee7ef33e3c87a38be7d6f390ab3` | rebuilds the 1 MiB image from the 2 MB dump | IMPORTANT |
| `tools/split-a53-regions.py` | 3,403 | `c22c4bb246ae43f2cd321f1930331e4c2be28cbed73c37fa4c58a392a870e2bb` | splitter that produced the stale region files; keep for history, do not use its output | OPTIONAL |

## Reference sources and extra payloads

| file | bytes | sha256 | description | flag |
|---|---|---|---|---|
| `artifacts/kstuff-a53-src/` (20 files, 349,137 B) | `ppr/a53_transport.c` 58,216 | `6f4e449b688a12546ff64b305cc19d15b72873733e241df03200dcc29353c57a` | reference A53 transport and PPR sources; `ppr/ppr_patch.c` 50,611 B sha256 `00e0c02b0ffeb1f42265ec2c2268b44f63dbaccafa22eedfcfaca708b3e96c37` | IMPORTANT |
| `artifacts/a53patch.elf` | 222,328 | `026efe0c5b6f49f7bcf7b6b18dc124c73eb81c361ac4fc61d51070711991f63e` | PPR patch payload with five image anchors, bounds on every read and write, and verification after writing; writes only inside the io segment | OPTIONAL |
| `artifacts/sdbgp.elf` | 256,528 | `6964734967521ffc8bb1d8a18cf5d7bd62d4ee9e727b2eee66a2876e3ea895d1` | built payload for `tools/sdbgp` | OPTIONAL |
| `artifacts/mp4cmd.elf` | 230,192 | `ce821b5c783d18b56cf629cf696ec6e5b1a6c6a704ce8d7119614ac08994e288` | built payload for `tools/mp4cmd` | OPTIONAL |
| `artifacts/writeprobe.elf` | 193,632 | `16232d8c8a88c89f967df485ffdd436c7f88b7ce90b088331b96fbbc4dc644e4` | built payload for the 48-probe matrix | OPTIONAL |

## DO NOT SHIP as data

| file | bytes | sha256 | why not |
|---|---|---|---|
| `<work>\a53_live.bin` | 268,435,456 | `41105cc06b90b88c62ad9ef283153278811dc47e0f60f2e1ddf1ca0897d3fa0b` | not a memory dump: one 256 kB buffer repeated 1024 times, every block with status 0x20 and transferred 0. Useful only as an example of how a failed read looks. LARGE. |
| `<work>\a53_regions\region_*.bin` (9 files) | 786,432 total | not hashed here | old extracts taken before the result-header fix, shifted by 0x6F8 and not byte-identical to the rebuilt image; they would send the receiver chasing a 0x6F8 offset that does not exist in the corrected image |

## How to package

1. Small archive for a first message: the two handover notes, `kstuff-profile-1360.h`,
   the two A53 images (complete and partial, clearly labelled), the 2 MB dump, the seven
   evidence logs and the ten notes. This is a few megabytes and carries every claim in the
   main document.
2. Large item on request: the 64 MiB kernel dump. Everything in the kernel scan can be
   re-checked from it, so it should be offered, but it does not need to be in the first
   message.
3. Never include the 256 MB file in an archive without a name that says it is not a dump,
   and never include the old region files.
