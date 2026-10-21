# A53 (ZCN/MP4) on FW 13.60: confirmed PPR profile, plus a measured hard negative on host to A53 memory write

Hello, and thanks for byepervisor and kstuff. We spent the last days on 13.60 (PS5 Pro) and we would like to hand over what we measured, in case it saves you time while you work on A53 code exec.

## Short version

1. We have a **reconstructed A53 image for FW 13.60** and the **PPR structure addresses confirmed against that image**, not against disassembly alone.
2. We measured a **hard negative**: the 13.60 A53 firmware **does not implement SDBGP_WRITE_MEMORY (0x01040031)**. Zero hits in the 64 MB kernel image, zero hits across 9 A53 regions (786 432 B), and a direct write attempt returns transport 0 while memory stays unchanged. The result opcode 0x02040031 is absent from the A53 regions too. For comparison 0x01040021 (read) appears 29 times in the kernel and the A53 knows its result.
3. Consequence: a kernel side PPR patch cannot be installed over the mailbox on 13.60. The workable direction is the one you named, code exec on the A53.

## Confirmed PPR profile (FW 13.60)

Confirmed by comparing with the reconstructed A53 image, not by static analysis:

| item | address (A53 PA) |
| --- | --- |
| AES descriptor | 0x2b124 |
| plaintext descriptor | 0x2b2f0 |
| precheck | 0x5b9cc |
| aes_site[0] | 0x57c14 |
| aes_site[1] | 0x57d4c |
| sha_auth_site | 0x5bc00 |
| dispatch | 0x5baf4 |
| call[0] | 0x4a120 |
| call[1] | 0x4b860 |

Stock words observed: call[0] 0x94004611, call[1] 0x94004041, aes[0] 0x97FF4D44, aes[1] 0x97FF4CF6, sha 0x97FFF3B3.

## The image

- Reconstructed from SDBGP reads, 0x40000 per read, every read verified by status and transferred byte count.
- 1 048 576 B, available on request (we can publish it with checksums).
- It contains two usable code areas: 0x28000 (io SRAM base) and a second region; the helper area sits around 0x4A120 and 0x4B860 and is exactly two BL sites, not ten. The dev segment of the image is zeros, so the other sites from the older profiles cannot be confirmed on 13.60.
- Firmware banner: `cex(1.1.2.01):Oberon-KDE 2026/07/17 02:22 releases/13.60 229358`.

## A warning about a 256 MB file that circulates

A 256 MB capture often described as an A53 memory dump is **not a dump**. It is 1024 blocks of 0x40000, every block identical (single sha1), each with a response header where transferred = 0 and status = 0x20, meaning all reads failed and the payload is a constant transport buffer. Only the first 256 kB holds real data, and that real data is the beginning of the A53 firmware (version descriptor, build id 4519afca... + GNU, an SDBGP packet at 0x140, then 162 904 B of ARM64 code). Do not treat the rest as memory.

## Transport limits we measured

- Read window: 0x0 to 0xBFFFF (768 kB SRAM, three banks of 256 kB). Above the window: transferred 0x0, status 0x20.
- Packet magic 0x73354450, src 0x80ff0180 or 0x80ff0200, dst 0x80ff0201 or 0x80ff0180, protocol 0x20000201 / 0x20000200.
- Packet buffer at softc+0x6b8, map at softc+0xa0, iommu address 0x70000000, size 0x200000.

## Environment we worked on

- PS5 Pro, FW 13.60, kernel version 0x13600007, image base 0xffffffffc0c60000, data base 0xffffffffc1920000.
- KERNEL_CODE_CAVE 0xCB92C0 (not DATA_CAVE), DATA_CAVE 0x2D39000, HV region 0x8E0000000 on Pro, loader base 0x8E0800000.

## Tools we built (all read only where possible)

- SDBGP packet builder analysis, mailbox read with status verification, A53 layout/window probes.
- A write probe matrix: 6 addresses x 4 memory types x 2 access sizes, each write restored immediately. It never reached a write because the anchor validation refused first, and a separate scan already showed the write opcode is absent.
- We can share all of it, including the reconstructed image and the checksums.

## Questions we could not answer

- Where the 64 bit A53 image lives outside the SRAM window (we scanned 18.72 GB of Linux RAM: no ARM64 image, so it is either in a reserved buffer or loaded by the hardware).
- Whether the write opcode ever existed for 13.60 in a different transport.

If there is a better place to send this, tell us and we will move it. Happy to test anything you publish.

Attached below: the reconstructed image checksums on request.
