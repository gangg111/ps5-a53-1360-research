# PS5 A53 (ZCN/MP4) research, firmware 13.60

Tools and measurements from a PS5 Pro on firmware 13.60. Everything here is read only. We are sharing it because someone else is about to build the same read path, and because the negative results below should save time.

This is a research dump, not a supported tool. Expect rough edges.

## What is in here

```
tools/sdbgp         SDBGP packet builder and mailbox reader (the read path)
tools/a53layout     A53 memory layout probe, self calibrating
tools/a53win        A53 window reader
tools/mboxwrite     Mailbox write attempt (kept for the negative result)
tools/pprbuf        Buffer observer, page table walk with PWT/PCD rejection
tools/pprwatch      Same read path, earlier version
tools/writeprobe    48 probe matrix over addresses x memory types x access sizes
tools/kstuff-ppr-v5 PPR patch generator and profile data
docs/               24 notes, every claim tied to a measured number
kstuff-profile-1360.h, kstuff-profile-1360-v5.h
```

Start with `docs/HANDOVER-A53-13.60-EN.md`, it is the summary of everything below.

## Answering the questions from the issue

**Which source produced the successful reads.** The read path is `tools/sdbgp/sdbgp.c` together with `tools/a53layout/a53layout.c`. The packet builder lives in our reverse engineering notes, the constants are:

| item | value |
| --- | --- |
| packet magic | 0x73354450 ("PD5s") |
| src | 0x80ff0180 or 0x80ff0200 |
| dst | 0x80ff0201 or 0x80ff0180 |
| protocol | 0x20000201 / 0x20000200 |
| read command | 0x01040021 |
| read result | 0x02040021 |
| config command | 0x01010010 |
| config result | 0x02010010 |
| dump command | 0x01050020 / 0x01050030 |

**MP4 setup and handshake.** The mailbox context is found through the kernel driver structure: `softc` holds the packet buffer at +0x6B8, its size at +0x6A8 and the iommu device address at +0x6B0. The register map is at `softc+0x40` (VA) and `softc+0x48` (base from config, 0xFDD80000 on our unit). Opening the transport needs `IOCTL_START` and `IOCTL_ALTER_STATE` through the device node; both returned 0 on our console. Details in `docs/IOMMU-REJESTRY-I-TABLICA-URZADZEN.md`.

**How we validate a reply, and this is the important part.** A reply is only considered successful when *all* of the following hold:

1. The result header carries the address we asked for.
2. `status` is 0.
3. `transferred` equals the requested length.

A reply with `transferred = 0` and `status = 0x20` is a **failed read**, even though the header looks well formed and the function may return 0. We lost weeks to that. Do not trust a return code of 0 on its own, and do not trust the echo of the address in the header. Check `transferred` and `status`.

The offsets in the 0x28 byte result header we use: +0x08 address echo, +0x10 requested size, +0x18 transferred bytes, +0x20 status.

**Timeouts.** Reads that fail do not fail fast. In our write probe the failing anchor reads each took about **3.2 seconds** before returning the failure, while a good GET_CONF read takes about **150 ms**. If you set a short timeout on a Slim you will misclassify a slow failure as success. We use several seconds and then check `transferred`, not the elapsed time.

**What is Pro specific and what is not.** Honest answer: we only tested on a Pro, so treat everything as unverified on a Slim.

- Almost certainly model independent: the SDBGP protocol, the packet layout, the result header layout, the read window size.
- Pro specific on our unit: the hypervisor region base 0x8E0000000 and the loader base 0x8E0800000. Those are not needed for a read test.
- The read window itself is **0x0 to 0xBFFFF** (768 kB, three banks of 256 kB). Reads above the window return `transferred = 0, status = 0x20`. A Slim may have a different base or a different window size; that is the first thing worth measuring.
- The io SRAM base we observed is 0x28000, with three anchors matching in all five places we check.

## Confirmed PPR profile, firmware 13.60

Confirmed against a reconstructed firmware image, not against disassembly alone. Full table and evidence in `docs/HANDOVER-A53-13.60-EN.md`.

AES descriptor 0x2b124, plaintext descriptor 0x2b2f0, precheck 0x5b9cc, aes_site 0x57c14 and 0x57d4c, sha_auth_site 0x5bc00, dispatch 0x5baf4, call sites 0x4a120 and 0x4b860.

## Hard negative: there is no host to A53 memory write on 13.60

Measured three independent ways:

1. The write opcode `0x01040031` appears **0 times** in the whole 64 MB kernel image, while the read opcode `0x01040021` appears **29 times**, all inside text, in the range 0xC292C2..0xC31B9A.
2. A direct write attempt: transport returns 0, memory stays unchanged, and the response carries no write result. The result opcode `0x02040031` is absent from the A53 regions.
3. The inventory of opcodes present in the 256 kB firmware block that we do have lists read, config and dump, and no write type.

Consequence for the usual plan: a kernel side PPR patch cannot be installed over the mailbox on 13.60, because the write command does not exist. The workable direction is code execution on the A53, which is what EchoStretch is working on.

A warning about a file that circulates: a 256 MB capture described as an A53 memory dump is **not a dump**. It is 1024 blocks of 0x40000, every block identical, each with a result header where `transferred = 0` and `status = 0x20`. Only the first 256 kB holds real data, and that real data is the first megabyte worth of the A53 firmware header with 162 904 bytes of ARM64 code. Do not treat the rest as memory.

## What we can offer for a Slim test

We have no Slim, so we cannot verify anything on it. What we can do:

- Share the full read path source, which is in this repo.
- Share our reconstructed A53 image and its checksums on request, if the community considers that acceptable. We did not publish it here because it is Sony firmware.
- Compare your Slim readings against our Pro readings, address by address, and say whether the protocol or the window differs.

If you get a controlled read working on the Slim, the first useful measurements are: the io SRAM base, the result of a read just above the window, and whether the five anchors at 0x28000, 0x57AA8, 0x5B964, 0x5BC20, 0x5C7E8 match.

## Status and honesty

We did not get fPKG or PPR working on 13.60. We got Linux running, we confirmed the PPR profile, and we measured why the mailbox route cannot write. The negative results above are the useful part.

Corrections to our own early numbers are documented in `docs/HANDOVER-A53-13.60-EN.md`. If something here contradicts what you measure, your measurement wins, tell us and we will fix it.

## Credits

Built on prior work by EchoStretch (byepervisor, kstuff), PS5Dev, and the wider PS5 homebrew scene. Read only tooling, no kernel patches of our own.

Work performed on a retail PS5 Pro, firmware 13.60, for interoperability research on hardware we own.
