/*
 * Test zapisu do pamieci A53 przez skrzynke urzadzenia.
 *
 * Transport jest potwierdzony w obie strony: wyslany pakiet odczytu wraca
 * z odpowiedzia niosa nasz numer zlecenia. Teraz sprawdzamy zapis.
 *
 * Test rozlicza sie sam:
 *   1) odczyt 16 bajtow spod adresu kontrolnego,
 *   2) zapis tamze wzorca,
 *   3) ponowny odczyt i porownanie.
 *
 * Adres kontrolny 0x200000 lezy poza dziewiecioma regionami, ktore czyta jadro
 * w swoim zrzucie, wiec zapis tam nie rusza dzialajacego oprogramowania.
 *
 * Uklad pakietu zapisu (0x40 + 0x28 + 0x18 + dane, wyrownane do 8):
 *   0x00 deci5s_hdr
 *   0x28 dcmp, code, sequence_no, packet_no, attr, num_commands
 *   0x40 sdbgp_write_command: self_size 0x28, total_size, type 0x01040031,
 *        flags, command_no, packet_no, pid, tid, n_args, padding
 *   0x68 deci5s_mem_arg: self_size 0x18, (mem_type << 8) | access_size, addr, size
 *   0x80 dane wpisane w pakiet
 *
 * Wymaga kstuff. Wynik: /data/mbox_write.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>

#define SYSCORE_AUTH_ID 0x4800000000000007ULL

#define IOCTL_START        0x800c410bU
#define IOCTL_FINISH       0x8008410fU
#define IOCTL_ALTER_STATE  0x40184115U

#define CONTROL_PATH "/dev/mp4/dump"
#define OUT_LOG      "/data/mbox_write.txt"

#define OFF_IFACE_A 0x3DEEB58ULL

#define DECI5S_MAGIC        0x73354450U
#define DECI5S_SRC_KERNEL   0x80FF0180U
#define DECI5S_DST_MP4      0x80FF0201U
#define DECI5S_PROTO_SDBGP  0x20000201U
#define DECI5S_DCMP         0x18U
#define MEM_TYPE_PA_TO_EL3  0x020100U
/* Wartosc polecenia zaobserwowana na tej konsoli: jadro wpisuje 0x20303002,
 * a nie 0x20303000, ktore pochodzi z implementacji referencyjnej dla 5.00.
 * Drugi kanal polecen (BAR2+0xfa000) i pole softc+0x168 jadro ustawia na 0x20303003. */
#define MP4_COREDUMP_CMD    0x20303002U
#define MP4_COREDUMP_CMD2   0x20303003U
#define SDBGP_READ_MEMORY   0x01040021U
#define SDBGP_WRITE_MEMORY  0x01040031U

#define SNAPSHOT_SIZE 0x1000U
/* Adres testu lezy w pustym obszarze pamieci A53: obraz pokazuje, ze oprogramowanie
 * zajmuje 0x20000 do 0x90000, a od 0x90000 do 0xC0000 sa same zera. Poprzedni adres
 * 0x200000 lezal poza pamiecia procesora, wiec odczyt zwracal tam zera niezaleznie
 * od tego, czy zapis sie udal. */
/* Adresy probne. 0x61F00 lezy w WOLNYM miejscu wewnatrz segmentu io (od 0x28000 do
 * 0x62000), czyli dokladnie tam, gdzie patch stawia jaskinie. 0xC3000 lezy POZA
 * segmentami io i dev, wiec zapis tam moze byc odrzucany niezaleznie od mechanizmu
 * i nie rozstrzyga o niczym. Dlatego probujemy obu i rozroznic to w logu. */
static const uint64_t TEST_ADDRS[2] = { 0x61F00ULL, 0xC3000ULL };
static const char *const TEST_ADDR_OPIS[2] = {
    "wolne miejsce w segmencie io",
    "poza segmentami io i dev",
};
/* Rozmiar probny. USTALONE POMIAREM: 16 bajtow jest za malo albo zle wyrównane,
 * bo rozne adresy zwracaly IDENTYCZNE dane, mimo ze naglowek wyniku odbijal
 * zadany adres. Odczyty 32-bajtowe byly poprawne i rozne dla roznych adresow,
 * wiec probujemy 32. Uwaga: odbicie adresu w naglowku NIE dowodzi, ze dane
 * dotycza tego adresu, urzadzenie po prostu przepisuje adres z zadania. */
#define TEST_SIZE   32U

#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL

static FILE *g_log;
static unsigned long g_dmap;
static unsigned long g_cr3;

static uint64_t g_softc, g_bar2, g_buffer, g_iommu, g_raw_size;
static uint64_t g_state_slot, g_flags_slot, g_buffer_slot;
static int g_ctl = -1;

static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
    klog_printf("[mboxwrite] %s", buf);
    if (g_log) {
        fputs(buf, g_log);
        fflush(g_log);
        fsync(fileno(g_log));
    }
}

static unsigned long vmspace_pmap(unsigned long v) {
    switch (kernel_get_fw_version() >> 16) {
        case 0x100 ... 0x102: return v + 0x2C0;
        case 0x105 ... 0x550: return v + 0x2E0;
        case 0x600 ... 0x1360: return v + 0x2E8;
        default: return 0;
    }
}

static int init_map(void) {
    unsigned long proc = kernel_get_proc(-1);
    if (!proc) return -1;
    unsigned long vmspace = kernel_getlong(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
    if (!vmspace) return -1;
    unsigned long pmap = vmspace_pmap(vmspace);
    if (!pmap) return -1;
    unsigned long d[2];
    if (kernel_copyout(pmap + 32, d, sizeof(d))) return -1;
    g_dmap = d[0] - d[1];
    g_cr3 = d[1];
    return 0;
}

static int present(uint64_t va) {
    uint64_t pml = g_cr3 & PG_FRAME;
    for (int i = 39; i >= 12; i -= 9) {
        unsigned long idx = (va >> i) & 0x1FF;
        pml = kernel_getlong(g_dmap + pml + idx * 8);
        if (!(pml & X86_PG_V)) return 0;
        if ((pml & X86_PG_PS) || i == 12) return 1;
        pml &= PG_FRAME;
    }
    return 0;
}

static int safe_read(uint64_t va, void *dst, size_t size) {
    if (!present(va)) return -1;
    return kernel_copyout(va, dst, size);
}

static int safe_read64(uint64_t va, uint64_t *out) { return safe_read(va, out, 8); }
static int safe_read32(uint64_t va, uint32_t *out) { return safe_read(va, out, 4); }

static int safe_write(uint64_t va, const void *src, size_t size) {
    if (!present(va)) return -1;
    return kernel_copyin(src, va, size);
}

static int safe_write32(uint64_t va, uint32_t value) {
    return safe_write(va, &value, sizeof(value));
}

static uint64_t swap_auth(uint64_t auth_id) {
    pid_t pid = getpid();
    uint64_t original = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, auth_id);
    return original;
}

/* Wartosc pola dostepu, ustawiana przed kazda proba. Ustalone pomiarem, ze odczyt
 * wymaga stalej jedynki; dla zapisu sprawdzamy kilka wartosci w jednym przebiegu. */
static uint32_t g_access = 1;

static uint32_t access_size(uint64_t address, uint32_t length) {
    (void) address;
    (void) length;
    return g_access;
}

static uint32_t round_up_8(uint32_t v) { return (v + 7U) & ~7U; }

/* Naglowek wspolny dla obu typow pakietow. */
static void build_header(unsigned char *out, uint32_t total, uint32_t sequence) {
    *(uint32_t *)(out + 0x00) = DECI5S_MAGIC;
    *(uint32_t *)(out + 0x04) = 0x28;
    *(uint32_t *)(out + 0x08) = total;
    *(uint32_t *)(out + 0x0c) = DECI5S_SRC_KERNEL;
    *(uint32_t *)(out + 0x10) = DECI5S_DST_MP4;
    *(uint32_t *)(out + 0x14) = DECI5S_PROTO_SDBGP;
    *(uint64_t *)(out + 0x20) = (uint64_t) 1;
    *(uint32_t *)(out + 0x28) = DECI5S_DCMP;
    *(uint32_t *)(out + 0x2c) = total - 0x28;
    *(uint32_t *)(out + 0x30) = sequence;
    *(uint8_t  *)(out + 0x3c) = 1;
}

/* Pakiet odczytu, 0x78 bajtow. */
static uint32_t build_read(unsigned char *out, uint64_t addr, uint32_t size, uint32_t seq) {
    memset(out, 0, 0x80);
    build_header(out, 0x78, seq);
    *(uint32_t *)(out + 0x40) = 0x20;
    *(uint32_t *)(out + 0x44) = 0x38;
    *(uint32_t *)(out + 0x48) = SDBGP_READ_MEMORY;
    *(uint32_t *)(out + 0x5c) = 1;
    *(uint32_t *)(out + 0x60) = 0x18;
    *(uint32_t *)(out + 0x64) = (MEM_TYPE_PA_TO_EL3 << 8) | access_size(addr, size);
    *(uint64_t *)(out + 0x68) = addr;
    *(uint64_t *)(out + 0x70) = size;
    return 0x78;
}

/* Pakiet zapisu: 0x40 naglowek, 0x28 polecenie, 0x18 argument, dane. */
static uint32_t build_write(unsigned char *out, uint64_t addr, const void *data,
                            uint32_t size, uint32_t seq) {
    uint32_t inline_size = round_up_8(size);
    uint32_t command_size = 0x28 + 0x18 + inline_size;
    uint32_t total = 0x40 + command_size;
    memset(out, 0, total);
    build_header(out, total, seq);

    *(uint32_t *)(out + 0x40) = 0x28;                  /* self_size */
    *(uint32_t *)(out + 0x44) = command_size;          /* total_size */
    *(uint32_t *)(out + 0x48) = SDBGP_WRITE_MEMORY;
    *(uint32_t *)(out + 0x58) = 0;                     /* pid */
    *(uint32_t *)(out + 0x5c) = 0;                     /* tid */
    *(uint32_t *)(out + 0x60) = 1;                     /* n_args */
    *(uint32_t *)(out + 0x64) = 0;                     /* padding */

    *(uint32_t *)(out + 0x68) = 0x18;                  /* self_size argumentu */
    *(uint32_t *)(out + 0x6c) = (MEM_TYPE_PA_TO_EL3 << 8) | access_size(addr, size);
    *(uint64_t *)(out + 0x70) = addr;
    *(uint64_t *)(out + 0x78) = size;
    memcpy(out + 0x80, data, size);
    return total;
}

/* Naglowek wyniku ma 0x28 bajtow: self_size 0x28, slowo typu pamieci i dostepu,
 * adres, zadane, przeslane, status. Jego polozenie w odpowiedzi ZALEZY OD ROZMIARU
 * odczytu, wiec szukamy go po polu adresu, a nie przyjmujemy stalego offsetu.
 * To samo podejscie co w a53layout, po wykryciu ze stale 0x90 bylo zle. */
static long znajdz_naglowek_wyniku(const unsigned char *resp, uint32_t limit,
                                   uint64_t addr, uint32_t size) {
    for (uint32_t i = 0; i + 0x28 + size <= limit; i += 4) {
        uint32_t self = 0, slowo = 0;
        uint64_t a = 0;
        memcpy(&self, resp + i, 4);
        memcpy(&slowo, resp + i + 4, 4);
        memcpy(&a, resp + i + 8, 8);
        if (self == 0x28 && (slowo >> 8) == MEM_TYPE_PA_TO_EL3 && a == addr) {
            return (long) i;
        }
    }
    return -1;
}

/* Zapasowy wariant dla zapisu: naglowek moze nie trzymac adresu, wiec szukamy
 * pierwszego naglowka o zgodnym typie pamieci. */
static long znajdz_naglowek_luzny(const unsigned char *resp, uint32_t limit) {
    for (uint32_t i = 0; i + 0x28 <= limit; i += 4) {
        uint32_t self = 0, slowo = 0;
        memcpy(&self, resp + i, 4);
        memcpy(&slowo, resp + i + 4, 4);
        if (self == 0x28 && (slowo >> 8) == MEM_TYPE_PA_TO_EL3) {
            return (long) i;
        }
    }
    return -1;
}

static void log_result(const char *what, uint64_t addr, const unsigned char *resp, uint32_t limit) {
    long h = znajdz_naglowek_wyniku(resp, limit, addr, 0);
    int luzny = 0;
    if (h < 0) {
        h = znajdz_naglowek_luzny(resp, limit);
        luzny = 1;
    }
    if (h < 0) {
        log_line("  %s: nie znalazlem naglowka wyniku w odpowiedzi\n", what);
        return;
    }
    uint32_t self = 0, slowo = 0, status = 0;
    uint64_t a = 0, zadane = 0, przeslane = 0;
    memcpy(&self, resp + h, 4);
    memcpy(&slowo, resp + h + 4, 4);
    memcpy(&a, resp + h + 8, 8);
    memcpy(&zadane, resp + h + 0x10, 8);
    memcpy(&przeslane, resp + h + 0x18, 8);
    memcpy(&status, resp + h + 0x20, 4);
    log_line("  %s: naglowek pod 0x%lx%s, slowo 0x%08x, adres 0x%llx, zadane 0x%llx, przeslane 0x%llx, status 0x%x\n",
             what, h, luzny ? " (szukany luźno)" : "", slowo,
             (unsigned long long) a, (unsigned long long) zadane,
             (unsigned long long) przeslane, status);
}

static int send_packet(unsigned char *packet, uint32_t total, uint32_t sequence) {
    uint32_t request = 0;
    if (safe_read32(g_softc + 0x160, &request)) return -1;
    request++;
    *(uint32_t *)(packet + 0x30) = request;

    uint32_t st = ~0x10U, fl = 0x210U;
    if (safe_write32(g_state_slot, st) || safe_write32(g_flags_slot, fl)) return -1;
    if (safe_write(g_buffer, packet, total)) return -1;
    if (safe_write32(g_bar2 + 0xf7000, (uint32_t) (g_iommu >> 32))) return -1;
    if (safe_write32(g_bar2 + 0xf8000, (uint32_t) g_iommu)) return -1;
    if (safe_write32(g_bar2 + 0xf9000, (uint32_t) g_raw_size)) return -1;
    if (safe_write32(g_softc + 0x160, request)) return -1;
    if (safe_write32(g_softc + 0x164, MP4_COREDUMP_CMD)) return -1;
    /* Drugi kanal polecen, tak jak robi to jadro. */
    if (safe_write32(g_softc + 0x168, MP4_COREDUMP_CMD2)) return -1;
    if (safe_write32(g_bar2 + 0xfa000, MP4_COREDUMP_CMD)) return -1;
    if (safe_write32(g_bar2 + 0xf6000, MP4_COREDUMP_CMD)) return -1;

    for (int i = 0; i < 50; i++) {
        uint32_t flags_now = 0;
        if (!safe_read32(g_flags_slot, &flags_now) && (flags_now & 0xffffU) != 0x210U) {
            return 0;
        }
        usleep(100 * 1000);
    }
    return 0;
}

/* Odczytuje odpowiedz spod offsetu rownego rozmiarowi zadania. */
static int read_response(uint32_t offset, unsigned char *out, size_t size) {
    return safe_read(g_buffer + offset, out, size);
}

int main(void) {
    static unsigned char snapshot[SNAPSHOT_SIZE];
    static unsigned char packet[0x200];
    static unsigned char before[TEST_SIZE], after[TEST_SIZE];
    static unsigned char response[0x180];
    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    uint32_t finish[2] = {8, 0};
    int kq = -1;
    const unsigned char pattern[TEST_SIZE] = {
        0x4b, 0x53, 0x54, 0x55, 0x46, 0x46, 0x2d, 0x4e,
        0x47, 0x2d, 0x31, 0x33, 0x36, 0x30, 0x21, 0x21,
        0x4b, 0x53, 0x54, 0x55, 0x46, 0x46, 0x2d, 0x4e,
        0x47, 0x2d, 0x31, 0x33, 0x36, 0x30, 0x21, 0x21
    };

    g_log = fopen(OUT_LOG, "w");
    log_line("mboxwrite start, test zapis-odczyt pod adresami 0x%llx i 0x%llx\n",
             (unsigned long long) TEST_ADDRS[0], (unsigned long long) TEST_ADDRS[1]);

    if (init_map() != 0) { log_line("BLAD: brak mapy jadra\n"); return 2; }

    uint64_t text = KERNEL_ADDRESS_TEXT_BASE;
    if (safe_read64(text + OFF_IFACE_A, &g_softc) || !g_softc) {
        log_line("BLAD: brak kontekstu sterownika\n");
        if (g_log) fclose(g_log);
        return 3;
    }
    uint64_t res = 0;
    if (safe_read64(g_softc + 0x18, &res) || !res || safe_read64(res + 0x10, &g_bar2)) {
        log_line("BLAD: brak BAR2\n");
        if (g_log) fclose(g_log);
        return 4;
    }
    log_line("kontekst 0x%llx, BAR2 0x%llx\n",
             (unsigned long long) g_softc, (unsigned long long) g_bar2);

    uint64_t original = swap_auth(SYSCORE_AUTH_ID);
    (void) revoke(CONTROL_PATH);
    g_ctl = open(CONTROL_PATH, O_RDONLY);
    if (g_ctl < 0) { log_line("otwarcie nieudane, errno=%d\n", errno); swap_auth(original); return 5; }
    errno = 0;
    int r = ioctl(g_ctl, IOCTL_START, context);
    log_line("IOCTL_START: %d, errno=%d\n", r, errno);
    if (r < 0) { close(g_ctl); swap_auth(original); return 6; }
    kq = kqueue();
    if (kq >= 0) {
        struct kevent ev;
        EV_SET(&ev, (uintptr_t) g_ctl, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (kevent(kq, &ev, 1, NULL, 0, NULL) == 0) {
            struct timespec ts = {10, 0};
            (void) kevent(kq, NULL, 0, &ev, 1, &ts);
        }
    }
    errno = 0;
    r = ioctl(g_ctl, IOCTL_ALTER_STATE, context);
    log_line("IOCTL_ALTER_STATE: %d, errno=%d, stan 0x%x\n", r, errno, context[4]);

    if (safe_read(g_softc, snapshot, sizeof(snapshot))) {
        log_line("BLAD: brak migawki\n");
        goto done;
    }
    for (uint32_t off = 4; off + 4 <= SNAPSHOT_SIZE; off += 4) {
        uint32_t flags = 0;
        memcpy(&flags, snapshot + off, 4);
        if ((flags & 0xffffU) != 0x212U) continue;
        const uint32_t dist[2] = {4, 8};
        for (int k = 0; k < 2; k++) {
            if (off < dist[k]) continue;
            uint32_t state = 0;
            memcpy(&state, snapshot + off - dist[k], 4);
            uint32_t phases = (state & 0xffffU) & ~0x10U;
            if (!g_flags_slot) {
                g_state_slot = g_softc + off - dist[k];
                g_flags_slot = g_softc + off;
            }
            if (phases == 3U || phases == 7U || phases == 0xfU) {
                g_state_slot = g_softc + off - dist[k];
                g_flags_slot = g_softc + off;
                break;
            }
        }
        if (g_flags_slot && (flags & 0xffffU) == 0x212U) {
            uint32_t ph = 0;
            memcpy(&ph, snapshot + (off - 8), 4);
            if (((ph & 0xffffU) & ~0x10U) == 0xfU) break;
        }
    }
    errno = 0;
    (void) ioctl(g_ctl, IOCTL_FINISH, finish);
    if (kq >= 0) { close(kq); kq = -1; }

    if (g_state_slot && !safe_read(g_softc, snapshot, sizeof(snapshot))) {
        uint64_t first = (g_flags_slot - g_softc) / 8;
        for (uint64_t idx = first; idx < SNAPSHOT_SIZE / 8; idx++) {
            uint64_t v = 0;
            memcpy(&v, snapshot + idx * 8, 8);
            if ((v >> 40) == 0xffffffULL && (v & 0xfffffULL) == 0) {
                g_buffer_slot = g_softc + idx * 8;
                break;
            }
        }
    }
    if (!g_state_slot || !g_buffer_slot) { log_line("BLAD: brak pol skrzynki\n"); goto done; }
    if (safe_read64(g_buffer_slot, &g_buffer) || safe_read64(g_buffer_slot - 8, &g_iommu) ||
        safe_read64(g_buffer_slot - 16, &g_raw_size)) {
        log_line("BLAD: brak pol bufora\n");
        goto done;
    }
    log_line("skrzynka gotowa: bufor 0x%llx, iommu 0x%llx, rozmiar 0x%llx\n",
             (unsigned long long) g_buffer, (unsigned long long) g_iommu,
             (unsigned long long) g_raw_size);

    /* 1. i 2. proby zapisu pod dwoma adresami, kazda z trzema wartosciami dostepu */
    static const uint32_t access_values[3] = {1, 4, 6};
    int any_ok = 0;
    for (int t = 0; t < 2 && !any_ok; t++) {
        uint64_t addr = TEST_ADDRS[t];
        log_line("=== adres testowy 0x%llx (%s) ===\n",
                 (unsigned long long) addr, TEST_ADDR_OPIS[t]);

        g_access = 1;
        uint32_t total = build_read(packet, addr, TEST_SIZE, 0);
        if (send_packet(packet, total, 0)) { log_line("  odczyt poczatkowy nieudany\n"); continue; }
        if (read_response(total, response, sizeof(response))) {
            log_line("  brak odpowiedzi na odczyt poczatkowy\n");
            continue;
        }
        long h_pocz = znajdz_naglowek_wyniku(response, sizeof(response), addr, TEST_SIZE);
        if (h_pocz < 0) {
            log_line("  BLAD: brak naglowka wyniku dla adresu 0x%llx, odczyt niewiarygodny\n",
                     (unsigned long long) addr);
        } else {
            memcpy(before, response + h_pocz + 0x28, TEST_SIZE);
            log_line("  dane pod naglowkiem 0x%lx, odczyt poczatkowy: ", h_pocz);
            for (int i = 0; i < TEST_SIZE; i++) log_line("%02x ", before[i]);
            log_line("\n");
        }
        /* Surowa odpowiedz zapisujemy zawsze, nawet gdy naglowek sie nie zgadza,
         * zeby mozna bylo ja przejrzec po fakcie. */
        {
            char sciezka[64];
            snprintf(sciezka, sizeof(sciezka), "/data/mbox_przed_%08llx.bin",
                     (unsigned long long) addr);
            FILE *rf = fopen(sciezka, "wb");
            if (rf) { fwrite(response, 1, sizeof(response), rf); fclose(rf); }
        }

        for (int ai = 0; ai < 3; ai++) {
            uint32_t access = access_values[ai];
            log_line("  --- proba z dostepem %u ---\n", access);

            g_access = access;
            total = build_write(packet, addr, pattern, TEST_SIZE, 0);
            if (t == 0 && ai == 0)
                log_line("  pakiet zapisu: %u bajtow, typ 0x%08x\n", total, SDBGP_WRITE_MEMORY);
            if (send_packet(packet, total, 0)) { log_line("    wyslanie nieudane\n"); continue; }
            if (read_response(total, response, sizeof(response)) == 0) {
                log_result("zapis", addr, response, sizeof(response));
                char sciezka[64];
                snprintf(sciezka, sizeof(sciezka), "/data/mbox_zapis_%08llx_%u.bin",
                         (unsigned long long) addr, access);
                FILE *rf = fopen(sciezka, "wb");
                if (rf) { fwrite(response, 1, sizeof(response), rf); fclose(rf); }
            }

            /* odczyt kontrolny z dostepem 1, bo to jest sprawdzone */
            g_access = 1;
            uint32_t total2 = build_read(packet, addr, TEST_SIZE, 0);
            if (send_packet(packet, total2, 0)) { log_line("    odczyt kontrolny nieudany\n"); continue; }
            if (read_response(total2, response, sizeof(response))) { log_line("    brak odpowiedzi\n"); continue; }
            long h_po = znajdz_naglowek_wyniku(response, sizeof(response), addr, TEST_SIZE);
            if (h_po < 0) {
                log_line("    BLAD: brak naglowka wyniku przy odczycie kontrolnym\n");
            } else {
                memcpy(after, response + h_po + 0x28, TEST_SIZE);
            }
            {
                char sciezka[64];
                snprintf(sciezka, sizeof(sciezka), "/data/mbox_po_%08llx_%u.bin",
                         (unsigned long long) addr, access);
                FILE *rf = fopen(sciezka, "wb");
                if (rf) { fwrite(response, 1, sizeof(response), rf); fclose(rf); }
            }
            log_line("    po zapisie: ");
            for (int i = 0; i < TEST_SIZE; i++) log_line("%02x ", after[i]);
            log_line("\n");

            if (memcmp(after, pattern, TEST_SIZE) == 0) {
                any_ok = 1;
                log_line("    *** ZAPIS ZADZIALAL pod 0x%llx z dostepem %u ***\n",
                         (unsigned long long) addr, access);
                break;
            } else if (memcmp(after, before, TEST_SIZE) == 0) {
                log_line("    pamiec bez zmian\n");
            } else {
                log_line("    pamiec sie zmienila, ale inaczej niz wzorzec\n");
            }
        }
    }

    log_line("--- wynik ---\n");
    log_line("  zapis zadzialal: %s\n", any_ok ? "TAK" : "nie");
    log_line("  wzorzec: ");
    for (int i = 0; i < TEST_SIZE; i++) log_line("%02x ", pattern[i]);
    log_line("\n");

done:
    if (g_ctl >= 0) close(g_ctl);
    if (kq >= 0) close(kq);
    swap_auth(original);
    log_line("identyfikator przywrocony, koniec\n");
    if (g_log) fclose(g_log);
    return 0;
}



