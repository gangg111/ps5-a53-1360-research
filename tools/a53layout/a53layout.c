/*
 * Zrzuca obszar pamieci A53 odczytem pod prawdziwym adresem.
 *
 * Teraz, gdy pole dostepu jest stale rowne 1 (ustalone pomiarem), pojedynczy odczyt
 * trafia pod wskazany adres. Mozemy wiec zrzucic dowolny obszar pamieci procesora,
 * a nie tylko dziewiec regionow, ktore wybiera jadro.
 *
 * Zrzut zapisujemy do /data/a53_live.bin, z adresem poczatkowym w naglowku pliku,
 * zeby dalo sie go pozniej zlozyc i przeszukac.
 *
 * Wynik: /data/a53dump.txt oraz /data/a53_live.bin
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
#define OUT_LOG      "/data/a53layout.txt"
#define OUT_BIN      "/data/a53_dev.bin"
#define OUT_LAYOUT   "/data/a53_layout.bin"

/* Uklad segmentow A53, wypelniany przez PSP w pamieci gospodarza. Te same stale
 * i ta sama struktura, ktorych uzywa patch PPR (ppr_patch.c). */
#define PPR_LAYOUT_PA          0x887F0000ULL
#define PPR_LAYOUT_HEADER_SIZE 0x148U
#define PPR_LAYOUT_MAX_SEGMENTS 32U
#define PPR_LAYOUT_RECORD_SIZE 0x50U
/* Rozmiar odczytu ukladu, wyrownany do 32 bajtow. USTALONE POMIAREM: rozmiary
 * niebedace wielokrotnoscia 32 moga zwracac staly blok zamiast zadanych danych,
 * bo odczyt 16-bajtowy zwracal te sama zawartosc dla roznych adresow. */
#define PPR_LAYOUT_READ_SIZE   0xB60U
#define OFF_IFACE_A 0x3DEEB58ULL

#define DECI5S_MAGIC        0x73354450U
#define DECI5S_SRC_KERNEL   0x80FF0180U
#define DECI5S_DST_MP4      0x80FF0201U
#define DECI5S_PROTO_SDBGP  0x20000201U
#define DECI5S_DCMP         0x18U
#define MEM_TYPE_PA_TO_EL3  0x020100U

/* Typ pamieci w pakiecie odczytu. Ustawiany przed proba, zeby mozna bylo porownac
 * rozne typy na tym samym adresie i zobaczyc, ktory widzi dane. */
static uint32_t g_mem_type = MEM_TYPE_PA_TO_EL3;
#define MP4_COREDUMP_CMD    0x20303002U
#define MP4_COREDUMP_CMD2   0x20303003U
#define SDBGP_READ_MEMORY   0x01040021U

#define SNAPSHOT_SIZE 0x1000U
/* Rozmiar porcji odczytu. USTALONE POMIAREM: duze odczyty sa niewiarygodne.
 * Zrzut 256 MB porcjami po 256 kB dal plik, ktory nie zgadza sie z obrazem
 * z odczytow jadra w ANI JEDNYM fragmencie, a na jego poczatku lezy naglowek
 * wyniku zamiast danych. Male odczyty, rzedu kilkudziesieciu bajtow, sa
 * poprawne i takie tez stosuje jadro (zbiorczo, rozmiarami niebedacymi
 * potegami dwojki). Dlatego czytamy po 4 kB. */
#define CHUNK         0x1000U          /* 4 kB na jedno polecenie */
#define DATA_OFFSET   0x90U            /* tu leza dane w odpowiedzi na odczyt */
#define START_ADDR    0x00000000ULL
#define END_ADDR      0x10000000ULL    /* nieuzywane, zostawione dla zgodnosci */

#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL

static FILE *g_log;
static unsigned long g_dmap, g_cr3;
static uint64_t g_softc, g_bar2, g_buffer, g_iommu, g_raw_size;
static uint64_t g_state_slot, g_flags_slot, g_buffer_slot;

/* Powiadomienie systemowe. Uklad struktury i wywolanie takie same, jakich uzywa
 * repozytorium drakmor/ppr-patch, sprawdzone na tej konsoli. */
typedef struct {
    char reserved[45];
    char message[3075];
} notify_request_t;

extern int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static void notify(const char *text) {
    notify_request_t request;
    memset(&request, 0, sizeof(request));
    snprintf(request.message, sizeof(request.message), "%s", text);
    (void) sceKernelSendNotificationRequest(0, &request, sizeof(request), 0);
}

static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
    klog_printf("[a53dump] %s", buf);
    if (g_log) { fputs(buf, g_log); fflush(g_log); fsync(fileno(g_log)); }
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

static int readable(uint64_t va) {
    uint64_t pml = g_cr3 & PG_FRAME;
    for (int i = 39; i >= 12; i -= 9) {
        unsigned long idx = (va >> i) & 0x1FF;
        pml = kernel_getlong(g_dmap + pml + idx * 8);
        if (!(pml & X86_PG_V)) return 0;
        if ((pml & X86_PG_PS) || i == 12) return !(pml & (X86_PG_PWT | X86_PG_PCD));
        pml &= PG_FRAME;
    }
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

static int safe_read(uint64_t va, void *dst, size_t n) {
    if (!readable(va)) return -1;
    return kernel_copyout(va, dst, n);
}
static int safe_read64(uint64_t va, uint64_t *o) { return safe_read(va, o, 8); }
static int safe_read32(uint64_t va, uint32_t *o) { return safe_read(va, o, 4); }
static int safe_write32(uint64_t va, uint32_t v) {
    if (!present(va)) return -1;
    return kernel_copyin(&v, va, 4);
}
static int safe_write(uint64_t va, const void *s, size_t n) {
    if (!present(va)) return -1;
    return kernel_copyin(s, va, n);
}

static uint64_t swap_auth(uint64_t id) {
    pid_t pid = getpid();
    uint64_t o = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, id);
    return o;
}

static uint32_t build_read(unsigned char *out, uint64_t addr, uint32_t size, uint32_t seq) {
    memset(out, 0, 0x80);
    *(uint32_t *)(out + 0x00) = DECI5S_MAGIC;
    *(uint32_t *)(out + 0x04) = 0x28;
    *(uint32_t *)(out + 0x08) = 0x78;
    *(uint32_t *)(out + 0x0c) = DECI5S_SRC_KERNEL;
    *(uint32_t *)(out + 0x10) = DECI5S_DST_MP4;
    *(uint32_t *)(out + 0x14) = DECI5S_PROTO_SDBGP;
    *(uint64_t *)(out + 0x20) = 1;
    *(uint32_t *)(out + 0x28) = DECI5S_DCMP;
    *(uint32_t *)(out + 0x2c) = 0x78 - 0x28;
    *(uint32_t *)(out + 0x30) = seq;
    *(uint8_t  *)(out + 0x3c) = 1;
    *(uint32_t *)(out + 0x40) = 0x20;
    *(uint32_t *)(out + 0x44) = 0x38;
    *(uint32_t *)(out + 0x48) = SDBGP_READ_MEMORY;
    *(uint32_t *)(out + 0x5c) = 1;
    *(uint32_t *)(out + 0x60) = 0x18;
    *(uint32_t *)(out + 0x64) = (g_mem_type << 8) | 1;
    *(uint64_t *)(out + 0x68) = addr;
    *(uint64_t *)(out + 0x70) = size;
    return 0x78;
}

static int send_packet(unsigned char *packet, uint32_t total) {    uint32_t request = 0;
    if (safe_read32(g_softc + 0x160, &request)) return -1;
    request++;
    *(uint32_t *)(packet + 0x30) = request;
    if (safe_write32(g_state_slot, ~0x10U) || safe_write32(g_flags_slot, 0x210U)) return -1;
    if (safe_write(g_buffer, packet, total)) return -1;
    if (safe_write32(g_bar2 + 0xf7000, (uint32_t) (g_iommu >> 32))) return -1;
    if (safe_write32(g_bar2 + 0xf8000, (uint32_t) g_iommu)) return -1;
    if (safe_write32(g_bar2 + 0xf9000, (uint32_t) g_raw_size)) return -1;
    if (safe_write32(g_softc + 0x160, request)) return -1;
    if (safe_write32(g_softc + 0x164, MP4_COREDUMP_CMD)) return -1;
    if (safe_write32(g_softc + 0x168, MP4_COREDUMP_CMD2)) return -1;
    if (safe_write32(g_bar2 + 0xfa000, MP4_COREDUMP_CMD)) return -1;
    if (safe_write32(g_bar2 + 0xf6000, MP4_COREDUMP_CMD)) return -1;
    for (int i = 0; i < 50; i++) {
        uint32_t fl = 0;
        if (!safe_read32(g_flags_slot, &fl) && (fl & 0xffffU) != 0x210U) return 0;
        usleep(50 * 1000);
    }
    return 0;
}

/* Offset danych w odpowiedzi zalezy od rozmiaru odczytu. USTALONE POMIAREM:
 * dla 32 bajtow to 0x90, a dla odczytu 256 kB az 0x18B. Dlatego offset wyznaczamy
 * pomiarem na znanym adresie, a nie stala, i uzywamy go do wlasciwych odczytow. */
static uint32_t g_data_offset = DATA_OFFSET;

static const unsigned char ZNANE[16] = {
    0x1b, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00,
};

/* Drugi znany wzorzec, tym razem z drugiego bloku 256 kB. Jest konieczny, bo duze
 * odczyty zwracaly staly blok SRAM od 0 do 0x40000, a pierwszy wzorzec (spod 0x28000)
 * lezy wlasnie w tym bloku. Sam jeden nie odroznilby poprawnego odczytu od stalej
 * odpowiedzi. */
static const unsigned char ZNANE2[16] = {
    0xff, 0x43, 0x03, 0xd1, 0xfd, 0x7b, 0x07, 0xa9,
    0xfc, 0x6f, 0x08, 0xa9, 0xfa, 0x67, 0x09, 0xa9,
};

static int szukaj_wzoru(const unsigned char *resp, uint32_t limit,
                        const unsigned char *wzor, uint32_t *gdzie) {
    for (uint32_t i = 0; i + 16 <= limit; i += 4) {
        if (memcmp(resp + i, wzor, 16) == 0) { *gdzie = i; return 0; }
    }
    return -1;
}

/* Znajduje naglowek wyniku dla zadanego adresu i zwraca offset danych.
 *
 * USTALONE POMIAREM, na podstawie zrzutu 256 MB: naglowek wyniku ma 0x28 bajtow
 * i zawiera pod +0x00 self_size (0x28), pod +0x04 slowo typu pamieci i dostepu
 * (0x02010001), a pod +0x08 ZADANY ADRES. W zrzucie 256 MB bloki roznily sie
 * wylacznie tym polem, co to potwierdza. Dane leza zaraz za naglowkiem.
 *
 * Dlatego danych nie szukamy po wzorcach ani nie przyjmujemy offsetu na stale:
 * znajdujemy naglowek, ktorego adres sie zgadza, i bierzemy to, co za nim lezy. */
static uint32_t znajdz_dane(const unsigned char *resp, uint32_t limit, uint64_t addr, uint32_t size) {
    for (uint32_t i = 0; i + 0x28 + size <= limit; i += 4) {
        uint32_t self = 0, slowo = 0;
        uint64_t a = 0;
        memcpy(&self, resp + i, 4);
        memcpy(&slowo, resp + i + 4, 4);
        memcpy(&a, resp + i + 8, 8);
        if (self == 0x28 && (slowo >> 8) == g_mem_type && a == addr) {
            return i + 0x28;
        }
    }
    return 0xFFFFFFFFU;
}

/* Czyta dwa znane adresy i sprawdza oba wzorce. Offset ustawiamy tylko wtedy, gdy oba
 * sie zgadzaja, czyli odczyt trafia pod wskazany adres, a nie zwraca stalej odpowiedzi. */
static void kalibruj(unsigned char *packet, unsigned char *resp, uint32_t bufor,
                     uint64_t addr1, uint64_t addr2, uint32_t size) {
    uint32_t total = build_read(packet, addr1, size, 0);
    if (send_packet(packet, total)) { log_line("  rozmiar %u B: wyslanie nieudane\n", size); return; }
    if (safe_read(g_buffer + total, resp, bufor)) { log_line("  rozmiar %u B: brak odpowiedzi\n", size); return; }
    uint32_t off1 = 0;
    if (szukaj_wzoru(resp, bufor, ZNANE, &off1)) {
        log_line("  rozmiar %u B: pierwszego wzoru nie ma\n", size);
        return;
    }

    total = build_read(packet, addr2, size, 0);
    if (send_packet(packet, total)) { log_line("  rozmiar %u B: drugie wyslanie nieudane\n", size); return; }
    if (safe_read(g_buffer + total, resp, bufor)) { log_line("  rozmiar %u B: brak drugiej odpowiedzi\n", size); return; }
    uint32_t off2 = 0;
    if (szukaj_wzoru(resp, bufor, ZNANE2, &off2)) {
        log_line("  rozmiar %u B: drugiego wzoru nie ma, odczyt NIE trafia pod adres\n", size);
        return;
    }

    if (off1 != off2) {
        log_line("  rozmiar %u B: offsety rozne (0x%x i 0x%x), odczyt niestabilny\n", size, off1, off2);
        return;
    }
    log_line("  rozmiar %u B: OBA wzorce pod offsetem 0x%x, odczyt poprawny\n", size, off1);
    g_data_offset = off1;
}

int main(void) {
    static unsigned char snapshot[SNAPSHOT_SIZE];
    static unsigned char packet[0x100];
    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    uint32_t finish[2] = {8, 0};
    int kq = -1, ctl = -1;
    FILE *out = NULL;
    uint64_t written = 0;
    int ok_chunks = 0, bad_chunks = 0;

    /* bufor na odpowiedz: naglowek odpowiedzi 0x40, naglowek wyniku 0x28,
     * dane od zmierzonego offsetu, potem zapas na kalibracje */
    static unsigned char resp[0x40 + 0x28 + CHUNK + 0x400];

    g_log = fopen(OUT_LOG, "w");
    log_line("a53dump: zrzut pamieci A53 od 0x%llx do 0x%llx, porcjami po 0x%x\n",
             (unsigned long long) START_ADDR, (unsigned long long) END_ADDR, CHUNK);
    notify("a53dump2: zrzut pamieci A53 startuje, potrwa kilkanascie minut");

    if (init_map() != 0) { log_line("BLAD: brak mapy jadra\n"); if (g_log) fclose(g_log); return 2; }
    uint64_t text = KERNEL_ADDRESS_TEXT_BASE;
    if (safe_read64(text + OFF_IFACE_A, &g_softc) || !g_softc) {
        log_line("BLAD: brak kontekstu\n"); if (g_log) fclose(g_log); return 3;
    }
    uint64_t res = 0;
    if (safe_read64(g_softc + 0x18, &res) || !res || safe_read64(res + 0x10, &g_bar2)) {
        log_line("BLAD: brak BAR2\n"); if (g_log) fclose(g_log); return 4;
    }
    log_line("kontekst 0x%llx, BAR2 0x%llx\n",
             (unsigned long long) g_softc, (unsigned long long) g_bar2);

    uint64_t original = swap_auth(SYSCORE_AUTH_ID);
    (void) revoke(CONTROL_PATH);
    ctl = open(CONTROL_PATH, O_RDONLY);
    if (ctl < 0) { log_line("otwarcie nieudane errno=%d\n", errno); swap_auth(original); return 5; }
    if (ioctl(ctl, IOCTL_START, context) < 0) {
        log_line("IOCTL_START blad errno=%d\n", errno);
        close(ctl); swap_auth(original); return 6;
    }
    kq = kqueue();
    if (kq >= 0) {
        struct kevent ev;
        EV_SET(&ev, (uintptr_t) ctl, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (kevent(kq, &ev, 1, NULL, 0, NULL) == 0) {
            struct timespec ts = {10, 0};
            (void) kevent(kq, NULL, 0, &ev, 1, &ts);
        }
    }
    (void) ioctl(ctl, IOCTL_ALTER_STATE, context);
    log_line("stan 0x%x\n", context[4]);

    if (safe_read(g_softc, snapshot, sizeof(snapshot))) { log_line("BLAD: brak migawki\n"); goto done; }
    for (uint32_t off = 4; off + 4 <= SNAPSHOT_SIZE; off += 4) {
        uint32_t flags = 0;
        memcpy(&flags, snapshot + off, 4);
        if ((flags & 0xffffU) != 0x212U) continue;
        const uint32_t dist[2] = {4, 8};
        for (int k = 0; k < 2; k++) {
            if (off < dist[k]) continue;
            uint32_t st = 0;
            memcpy(&st, snapshot + off - dist[k], 4);
            uint32_t ph = (st & 0xffffU) & ~0x10U;
            if (!g_flags_slot) { g_state_slot = g_softc + off - dist[k]; g_flags_slot = g_softc + off; }
            if (ph == 3U || ph == 7U || ph == 0xfU) {
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
    (void) ioctl(ctl, IOCTL_FINISH, finish);
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
        log_line("BLAD: brak pol bufora\n"); goto done;
    }
    log_line("skrzynka gotowa: bufor 0x%llx\n", (unsigned long long) g_buffer);

    /* Kalibracja offsetu na dwoch znanych adresach: 0x28000 lezy w pierwszym bloku
     * 256 kB, a 0x5B964 w drugim. Sam pierwszy nie wystarcza, bo duze odczyty
     * zwracaly wlasnie pierwszy blok. */
    log_line("--- kalibracja offsetu danych ---\n");
    kalibruj(packet, resp, 0x40 + 0x28 + 0x1000 + 0x400, 0x28000ULL, 0x5B964ULL, 0x20);
    kalibruj(packet, resp, 0x40 + 0x28 + 0x1000 + 0x400, 0x28000ULL, 0x5B964ULL, CHUNK);
    log_line("uzywam offsetu danych 0x%x\n", g_data_offset);

    /* Proba roznych typow pamieci na adresie ukladu i na znanym adresie SRAM.
     * Kontrola na SRAM potrzebna, zeby odroznic zly typ pamieci od zlego adresu. */
    log_line("--- proba typow pamieci ---\n");
    {
        static const uint32_t typy[1] = { 0x020100U };
        /* Sonda zasiegu: sprawdzamy, ktore fragmenty przestrzeni procesora da sie
         * czytac. Dotad udawalo sie tylko dla pamieci SRAM do 0xC0000, a adresy
         * spoza tego zakresu zwracaly status 0x20 i zero przeslanych bajtow. */
        static const uint64_t adresy[14] = {
            0x00000000ULL, 0x00028000ULL, 0x000B0000ULL, 0x000C0000ULL,
            0x00100000ULL, 0x00200000ULL, 0x00400000ULL, 0x01000000ULL,
            0x04000000ULL, 0x06410000ULL, 0x0887F000ULL, 0x0887F0000ULL,
            0x09000000ULL, 0x80000000ULL,
        };
        for (int ai = 0; ai < 14; ai++) {
            for (int ti = 0; ti < 1; ti++) {
                g_mem_type = typy[ti];
                uint32_t total = build_read(packet, adresy[ai], 0x20, 0);
                if (send_packet(packet, total)) {
                    log_line("  typ 0x%06x, adres 0x%llx: wyslanie nieudane\n",
                             typy[ti], (unsigned long long) adresy[ai]);
                    continue;
                }
                if (safe_read(g_buffer + total, resp, sizeof(resp))) {
                    log_line("  typ 0x%06x, adres 0x%llx: brak odpowiedzi\n",
                             typy[ti], (unsigned long long) adresy[ai]);
                    continue;
                }
                uint32_t off = znajdz_dane(resp, sizeof(resp), adresy[ai], 0x20);
                log_line("  typ 0x%06x, adres 0x%llx: dane pod 0x%x\n",
                         typy[ti], (unsigned long long) adresy[ai], off);
                if (off != 0xFFFFFFFFU) {
                    /* Pola naglowka wyniku: zadane, przeslane, status. To one
                     * rozstrzygaja, czy odczyt sie udal, a nie sama zawartosc. */
                    uint64_t zadane = 0, przeslane = 0;
                    uint32_t status = 0;
                    uint32_t naglowek = off - 0x28;
                    memcpy(&zadane, resp + naglowek + 0x10, 8);
                    memcpy(&przeslane, resp + naglowek + 0x18, 8);
                    memcpy(&status, resp + naglowek + 0x20, 4);
                    log_line("    naglowek pod 0x%x: zadane 0x%llx, przeslane 0x%llx, status 0x%x\n",
                             naglowek, (unsigned long long) zadane,
                             (unsigned long long) przeslane, status);
                }
                log_line("    dane (od offsetu 0x90): ");
                for (int i = 0; i < 32; i++) log_line("%02x ", resp[0x90 + i]);
                log_line("\n");
            }
        }
    }
    g_mem_type = MEM_TYPE_PA_TO_EL3;

    /* Odczyt ukladu segmentow z pamieci gospodarza i zrzut segmentu dev. */
    static unsigned char uklad[PPR_LAYOUT_HEADER_SIZE + PPR_LAYOUT_MAX_SEGMENTS * PPR_LAYOUT_RECORD_SIZE];
    {
        uint32_t total = build_read(packet, PPR_LAYOUT_PA, PPR_LAYOUT_READ_SIZE, 0);
        log_line("odczyt ukladu z adresu 0x%llx, %u bajtow\n",
                 (unsigned long long) PPR_LAYOUT_PA, (unsigned) PPR_LAYOUT_READ_SIZE);
        if (send_packet(packet, total)) { log_line("BLAD: wyslanie nieudane\n"); goto done; }
        if (safe_read(g_buffer + total, resp, sizeof(resp))) {
            log_line("BLAD: brak odpowiedzi na odczyt ukladu\n"); goto done;
        }
        uint32_t off_uklad = znajdz_dane(resp, sizeof(resp), PPR_LAYOUT_PA, PPR_LAYOUT_READ_SIZE);
        if (off_uklad == 0xFFFFFFFFU) {
            log_line("BLAD: brak naglowka wyniku dla adresu ukladu, dane niewiarygodne\n");
            goto done;
        }
        log_line("dane ukladu pod offsetem 0x%x\n", off_uklad);
        memcpy(uklad, resp + off_uklad, sizeof(uklad));

        uint32_t ile = 0, io_idx = 0xffffffffU, dev_idx = 0xffffffffU;
        memcpy(&ile, uklad + 0x0c, 4);
        memcpy(&io_idx, uklad + 0x54, 4);
        memcpy(&dev_idx, uklad + 0x74, 4);
        log_line("uklad: segmentow %u, indeks io %u, indeks dev %u\n", ile, io_idx, dev_idx);
        if (ile == 0 || ile > PPR_LAYOUT_MAX_SEGMENTS) {
            log_line("BLAD: liczba segmentow nieprawdopodobna, uklad nieczytelny\n");
            goto done;
        }
        /* Surowy uklad zapisujemy do pliku, zeby dalo sie go przetworzyc na komputerze
         * bez zgadywania formatu logu. */
        {
            FILE *lf = fopen(OUT_LAYOUT, "wb");
            if (lf) {
                fwrite(uklad, 1, sizeof(uklad), lf);
                fflush(lf);
                fsync(fileno(lf));
                fclose(lf);
                log_line("surowy uklad zapisany do %s (%u bajtow)\n",
                         OUT_LAYOUT, (unsigned) sizeof(uklad));
            } else {
                log_line("UWAGA: nie moge zapisac %s\n", OUT_LAYOUT);
            }
        }

        uint64_t dev_g6 = 0, dev_size = 0;
        for (uint32_t i = 0; i < ile; i++) {
            const unsigned char *r = uklad + PPR_LAYOUT_HEADER_SIZE + i * PPR_LAYOUT_RECORD_SIZE;
            uint32_t id = 0, flags = 0;
            uint64_t g6b = 0, g6s = 0, sb = 0, ss = 0, mb = 0, ms = 0, nm = 0;
            memcpy(&id, r + 0x00, 4);
            memcpy(&flags, r + 0x04, 4);
            memcpy(&g6b, r + 0x08, 8);
            memcpy(&g6s, r + 0x10, 8);
            memcpy(&sb, r + 0x18, 8);
            memcpy(&ss, r + 0x20, 8);
            memcpy(&mb, r + 0x30, 8);
            memcpy(&ms, r + 0x40, 8);
            memcpy(&nm, r + 0x48, 8);
            log_line("  segment %u: id %u flagi 0x%08x\n", i, id, flags);
            log_line("     g6   0x%llx + 0x%llx\n", (unsigned long long) g6b, (unsigned long long) g6s);
            log_line("     sram 0x%llx + 0x%llx\n", (unsigned long long) sb, (unsigned long long) ss);
            log_line("     widziany 0x%llx + 0x%llx, nazwa 0x%llx%s%s\n",
                     (unsigned long long) mb, (unsigned long long) ms,
                     (unsigned long long) nm,
                     (i == io_idx) ? "  <- io" : "", (i == dev_idx) ? "  <- dev" : "");
            if (i == dev_idx) { dev_g6 = g6b; dev_size = g6s; }
        }

        if (!dev_g6 || !dev_size) {
            log_line("BLAD: segment dev nie ma bazy g6, nie moge go zrzucic\n");
            goto done;
        }
        log_line("segment dev lezy w pamieci gospodarza pod 0x%llx, rozmiar 0x%llx\n",
                 (unsigned long long) dev_g6, (unsigned long long) dev_size);

        out = fopen(OUT_BIN, "wb");
        if (!out) { log_line("BLAD: nie moge zapisac %s\n", OUT_BIN); goto done; }

        uint64_t do_zrzutu = dev_size;
        if (do_zrzutu > 0x800000ULL) do_zrzutu = 0x800000ULL;
        for (uint64_t off = 0; off < do_zrzutu; off += CHUNK) {
            /* Zawsze czytamy pelna porcje, bo rozmiar odczytu musi byc wielokrotnoscia
             * 32. Zapisujemy tylko tyle, ile jeszcze brakuje. */
            uint32_t porcja = CHUNK;
            uint64_t zostalo = do_zrzutu - off;
            if (zostalo < porcja) porcja = (uint32_t) zostalo;
            uint32_t t2 = build_read(packet, dev_g6 + off, CHUNK, 0);
            if (send_packet(packet, t2) || safe_read(g_buffer + t2, resp, sizeof(resp))) {
                log_line("  dev +0x%06llx: odczyt nieudany\n", (unsigned long long) off);
                bad_chunks++;
                memset(resp, 0xee, porcja);
                fwrite(resp, 1, porcja, out);
                written += porcja;
                continue;
            }
            uint32_t doff = znajdz_dane(resp, sizeof(resp), dev_g6 + off, porcja);
            if (doff == 0xFFFFFFFFU) {
                log_line("  dev +0x%06llx: brak naglowka wyniku dla tego adresu\n",
                         (unsigned long long) off);
                bad_chunks++;
                memset(resp, 0xdd, porcja);
                fwrite(resp, 1, porcja, out);
                written += porcja;
                continue;
            }
            fwrite(resp + doff, 1, porcja, out);
            written += porcja;
            ok_chunks++;
            log_line("  dev +0x%06llx: zrzucone %u bajtow\n",
                     (unsigned long long) off, porcja);
            fflush(out);
        }
        fflush(out);
        fsync(fileno(out));
        fclose(out);
        out = NULL;
        log_line("zrzut segmentu dev zakonczony: %llu bajtow, dobrych porcji %d, bledow %d\n",
                 (unsigned long long) written, ok_chunks, bad_chunks);
        {
            char msg[256];
            snprintf(msg, sizeof(msg), "a53layout: dev zrzucony, %llu bajtow",
                     (unsigned long long) written);
            notify(msg);
        }
    }

done:
    if (out) fclose(out);
    if (ctl >= 0) close(ctl);
    if (kq >= 0) close(kq);
    swap_auth(original);
    log_line("identyfikator przywrocony, koniec\n");
    if (g_log) fclose(g_log);
    return 0;
}


