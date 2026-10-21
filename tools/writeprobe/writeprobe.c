/*
 * writeprobe: matryca prob zapisu do pamieci procesora A53 przez skrzynke
 * coredump urzadzenia MP4 (protokol SDBGP/DECI5S).
 *
 * Po co: dotychczas sprawdzony byl jeden adres i jeden typ pamieci
 * (PA 0x61F00, mem_type 0x020000, access 6), a pomiar pokazywal, ze transport
 * przyjmuje pakiet, pamiec sie nie zmienia, a w odpowiedzi nie ma wyniku
 * zapisu. To nie wystarcza do wyroku, bo nie wiadomo, czy zapis odrzuca typ
 * pamieci, typ dostepu, sam adres, czy caly opcode 0x01040031.
 *
 * Co robi: 48 prob, czyli 6 adresow x 4 typy pamieci x 2 typy dostepu. Kazda
 * proba:
 *   1) odczyt 32 B pod adresem (stan przed),
 *   2) zapis 16 B wzorca unikalnego dla proby,
 *   3) odczekanie 120 ms,
 *   4) odczyt 32 B pod tym samym adresem (stan po),
 *   5) werdykt: zapis przyjety / odrzucony / pamiec zmieniona / brak odczytu,
 *   6) jesli pamiec sie zmienila, natychmiastowe przywrocenie oryginalu
 *      i odczyt kontrolny. Nigdy nie zapisujemy wiecej niz 16 B.
 *
 * Kolejnosc jest czescia zabezpieczenia: najpierw puste wypelnienie za kodem
 * (0x5E000, 0x60000), potem jaskinie latki PPR (0x61F00, 0x61F50), na koncu
 * zywy kod (0x28000) i trzeci bank SRAM (0x80000). Jesli zapis przyjmie sie
 * w ktorejs z wczesniejszych prob, proba pod 0x28000 jest POMIJANA, bo odpowiedz
 * jest juz znana, a nie ma po co dotykac zywego obrazu.
 *
 * Bramki przed pierwszym zapisem:
 *   - firmware musi byc 13.60,
 *   - transport musi byc gotowy (skrzynka, bufor, IOMMU, rozmiar),
 *   - piec kotwic obrazu A53 (16 B pod stalymi adresami) musi sie zgadzac,
 *     co dowodzi, ze odczyt trafia pod zadany adres, a nie zwraca stalej tresci.
 * Bez tych bramek payload nie wysyla ani jednego zapisu.
 *
 * Log: /data/writeprobe.txt, kazda linia z fflush i fsync. Stop: plik
 * /data/writeprobe.stop. Budzet: 600 s.
 *
 * Wymaga odczytu i zapisu pamieci jadra (kstuff). NIE wymaga latki PPR:
 * A53 zostaje nietknieta poza probami i kazda proba jest natychmiast wycofywana.
 * Wynik: /data/writeprobe.txt
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "writeprobe_core.h"

#define SYSCORE_AUTH_ID     0x4800000000000007ULL

#define IOCTL_START         0x800c410bU
#define IOCTL_FINISH        0x8008410fU
#define IOCTL_ALTER_STATE   0x40184115U

#define CONTROL_PATH        "/dev/mp4/dump"
#define OUT_LOG             "/data/writeprobe.txt"
#define STOP_FILE           "/data/writeprobe.stop"

/* Pole globalne ze wskaznikiem softc sterownika MP4, to samo co w tools/a53layout,
 * tools/mboxwrite i tools/a53patch. */
#define OFF_IFACE_A         0x3DEEB58ULL
#define SNAPSHOT_SIZE       0x1000U

#define DECI5S_MAGIC        0x73354450U
#define DECI5S_SRC_KERNEL   0x80FF0180U
#define DECI5S_DST_MP4      0x80FF0201U
#define DECI5S_PROTO_SDBGP  0x20000201U
#define DECI5S_DCMP         0x18U

#define SDBGP_READ_MEMORY        0x01040021U
#define SDBGP_WRITE_MEMORY       0x01040031U
#define SDBGP_RES_READ_MEMORY    0x02040021U
#define SDBGP_RES_WRITE_MEMORY   0x02040031U
#define SDBGP_RES_GET_CONF       0x02010010U

/* Odczyt idzie typem sprawdzonym pomiarem (0x020100, access 1): to on zwraca
 * prawdziwa tresc obrazu A53 pod 0x28000 (patrz artifacts/pprwatch-*.txt).
 * Zapis idzie typem z macierzy, bo to jest przedmiot pomiaru. */
#define MEM_TYPE_ODCZYT     0x020100U
#define ACCESS_ODCZYT       1U

/* Wartosc polecenia zaobserwowana na tej konsoli: jadro wpisuje 0x20303002,
 * a drugi kanal polecen 0x20303003 (tools/mboxwrite, tools/pprwatch). */
#define MP4_COREDUMP_CMD    0x20303002U
#define MP4_COREDUMP_CMD2   0x20303003U

#define FW_1360             0x1360U
#define BUDZET_S            600U
/* Okno transportu: 768 kB SRAM w trzech bankach po 256 kB. Powyzej A53 zwraca
 * status 0x20 i zero przeslanych bajtow, wiec zapis tam nic nie rozstrzyga. */
#define OKNO_SRAM           0xC0000ULL

#define CZAS_OSADZENIA_MS   120U
#define LIMIT_MS_ODPOWIEDZI 3000U
#define LIMIT_BEZ_ODPOWIEDZI 2
#define LIMIT_POLECEN_ODP   8

#define ODP_NAGLOWEK        0x40U
#define ODP_WYNIK           0x28U
#define ODP_ROZMIAR         (ODP_NAGLOWEK + ODP_WYNIK + 0x100U + 0x40U)

#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL

/* Kotwice tozsamosci obrazu A53: 16 bajtow pod stalymi adresami fizycznymi.
 * Wartosci pochodza z artifacts/a53-obraz-odtworzony.bin (offsecie = adres
 * fizyczny) i zgadzaja sie z odczytem na konsoli (artifacts/pprwatch-2026-10-15c.txt,
 * kontrola pod 0x28000). Sprawdzenie ich przed pierwszym zapisem rozstrzyga, czy
 * transport naprawde czyta pamiec A53, czy zwraca resztke bufora. */
typedef struct {
    uint64_t pa;
    const char *nazwa;
    uint8_t  bajty[WP_WZORZEC];
} kotwica;

static const kotwica KOTWICE[] = {
    { 0x28000ULL, "naglowek obrazu", {
        0x1b, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00 } },
    { 0x57AA8ULL, "helper", {
        0xff, 0x43, 0x02, 0xd1, 0xfd, 0x7b, 0x03, 0xa9,
        0xfc, 0x6f, 0x04, 0xa9, 0xfa, 0x67, 0x05, 0xa9 } },
    { 0x5B964ULL, "dispatch_native", {
        0xff, 0x43, 0x03, 0xd1, 0xfd, 0x7b, 0x07, 0xa9,
        0xfc, 0x6f, 0x08, 0xa9, 0xfa, 0x67, 0x09, 0xa9 } },
    { 0x5BC20ULL, "plaintext_direct", {
        0xe0, 0x03, 0x1f, 0x2a, 0x28, 0xb5, 0x05, 0xb9,
        0x03, 0x00, 0x00, 0x14, 0x00, 0x20, 0xa0, 0x52 } },
    { 0x5C7E8ULL, "common_return", {
        0xfd, 0x7b, 0xba, 0xa9, 0xfc, 0x6f, 0x01, 0xa9,
        0xfa, 0x67, 0x02, 0xa9, 0xf8, 0x5f, 0x03, 0xa9 } },
};

#define LICZBA_KOTWIC ((unsigned) (sizeof(KOTWICE) / sizeof(KOTWICE[0])))

/* Wynik jednej proby, zebrany do tabeli podsumowania. */
typedef struct {
    unsigned  nr;
    uint64_t  adres;
    uint32_t  mem_type;
    uint32_t  access;
    int       rc;            /* kod zwrotu transportu */
    int       ma_odpowiedz;  /* naglowek odpowiedzi zgodny z oczekiwanym */
    uint32_t  typ_w_odp;     /* pierwszy typ polecenia w odpowiedzi, 0 = brak */
    unsigned  liczba_typow;
    int       wynik_w_odp;   /* czy w odpowiedzi jest wynik zapisu 0x02040031 */
    wp_osad   osad;
    int       pominieto;
    int       przywrocono;   /* -1 nie dotyczy, 0 nie, 1 tak */
} wynik_proby;

/* Wynik odczytu jednego obszaru. */
typedef struct {
    int      rc;             /* kod zwrotu transportu */
    int      wiarygodny;     /* 1 = dane sa spod zadanego adresu i kompletne */
    uint32_t slowo;          /* slowo typu pamieci i dostepu z naglowka wyniku */
    uint64_t zadane;
    uint64_t przeslane;
    uint32_t status;
    long     naglowek;       /* offset naglowka wyniku w odpowiedzi, -1 = brak */
} odczyt_wynik;

/* Wynik zapisu. */
typedef struct {
    int      rc;             /* kod zwrotu transportu */
    int      ma_odpowiedz;
    uint32_t seq_zadany;
    uint32_t seq_odpowiedz;
    uint32_t polecen;
    uint32_t typy[LIMIT_POLECEN_ODP];
    unsigned liczba_typow;
    int      ma_wynik;       /* wynik zapisu 0x02040031 w odpowiedzi */
    uint32_t wynik_slowo;
    uint64_t wynik_adres;
    uint64_t wynik_zadane;
    uint64_t wynik_przeslane;
    uint32_t wynik_status;
    long     wynik_off;
} zapis_wynik;

static FILE *g_log;
static uint64_t g_start_ms;
static int g_czas_ok = 1;

static uint64_t g_dmap, g_cr3;
static uint64_t g_softc, g_bar2, g_buffer, g_iommu, g_raw_size;
static uint64_t g_state_slot, g_flags_slot, g_buffer_slot;
static int g_ctl = -1;

static volatile sig_atomic_t g_stop;
static int g_bez_odpowiedzi;
static int g_przerwano;
static int g_nr_przyjetej = -1;   /* numer pierwszej proby, ktora przyjela zapis */

static wynik_proby g_wyniki[64];
static unsigned g_wynikow;

static uint8_t g_stan_pierwotny[8][WP_ODCZYT];
static unsigned g_adresow_stanu;

/* ---------------------------------------------------------------- czas, log */

static uint64_t ms_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        if (g_czas_ok) {
            g_czas_ok = 0;
            fprintf(stderr, "UWAGA: clock_gettime nie dziala, czasy beda zerowe\n");
        }
        return 0;
    }
    return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) (ts.tv_nsec / 1000000L);
}

static uint64_t ms_od_startu(void) { return ms_now() - g_start_ms; }

static void log_impl(int do_klog, const char *fmt, va_list ap) {
    char buf[768];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    printf("%s", buf);
    fflush(stdout);
    if (do_klog) klog_printf("[writeprobe] %s", buf);
    if (g_log) {
        fputs(buf, g_log);
        fflush(g_log);
        fsync(fileno(g_log));
    }
}

static void log_line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_impl(0, fmt, ap);
    va_end(ap);
}

/* Linie, ktore musza przetrwac takze zawieszenie konsoli (klog przezywa restart
 * w postaci zrzutu), wiec ida dodatkowo do klog. */
static void log_key(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_impl(1, fmt, ap);
    va_end(ap);
}

static void hex_do(const uint8_t *p, unsigned n, char *dst, size_t cap) {
    size_t k = 0;
    if (!dst || cap == 0) return;
    dst[0] = 0;
    for (unsigned i = 0; i < n && k + 4 < cap; i++)
        k += (size_t) snprintf(dst + k, cap - k, "%02x ", p[i]);
}

static void log_hex(const char *etykieta, const uint8_t *p, unsigned n) {
    char hex[3 * WP_ODCZYT + 1] = {0};
    hex_do(p, n, hex, sizeof(hex));
    log_line("%s%s\n", etykieta, hex);
}

static void obsluz_sygnal(int sig) {
    (void) sig;
    g_stop = 1;
}

/* ------------------------------------------------------ dostep do jadra x86 */

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
    unsigned long vmspace, pmap, d[2];

    if (!proc) return -1;
    vmspace = kernel_getlong(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
    if (!vmspace) return -1;
    pmap = vmspace_pmap(vmspace);
    if (!pmap) return -1;
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

static int safe_read32(uint64_t va, uint32_t *out) { return safe_read(va, out, 4); }
static int safe_read64(uint64_t va, uint64_t *out) { return safe_read(va, out, 8); }

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

/* ------------------------------------------------------------- skrzynka MP4 */

static int mailbox_init(void) {
    uint64_t text = (uint64_t) KERNEL_ADDRESS_TEXT_BASE;
    uint64_t res = 0;

    if (safe_read64(text + OFF_IFACE_A, &g_softc) || !g_softc) return -1;
    if (safe_read64(g_softc + 0x18, &res) || !res) return -1;
    if (safe_read64(res + 0x10, &g_bar2) || !g_bar2) return -1;
    return 0;
}

/* Odnalezienie pol skrzynki: stanu, flag, bufora, IOMMU i rozmiaru. Kolejnosc
 * i warunki przejete z tools/mboxwrite (sprawdzone pomiarowo na tej konsoli):
 * w migawce softc szukamy slowa flag 0x212, a pole stanu lezy 4 albo 8 bajtow
 * przed nim. Po zakonczeniu zrzutu bufor pakietow to pierwsze pole, ktore
 * wyglada jak zaokraglony w dol adres w polowie jadra. */
static int mailbox_open(void) {
    static unsigned char snapshot[SNAPSHOT_SIZE];
    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    uint32_t finish[2] = {8, 0};
    uint64_t original;
    int kq = -1;
    int rc = -1;

    original = swap_auth(SYSCORE_AUTH_ID);
    (void) revoke(CONTROL_PATH);
    g_ctl = open(CONTROL_PATH, O_RDONLY);
    if (g_ctl < 0) {
        log_key("BLAD: open %s: errno=%d (%s)\n", CONTROL_PATH, errno, strerror(errno));
        swap_auth(original);
        return -1;
    }
    errno = 0;
    if (ioctl(g_ctl, IOCTL_START, context) < 0) {
        log_key("BLAD: IOCTL_START: errno=%d (%s)\n", errno, strerror(errno));
        close(g_ctl);
        g_ctl = -1;
        swap_auth(original);
        return -1;
    }
    log_line("IOCTL_START: 0\n");

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
    if (ioctl(g_ctl, IOCTL_ALTER_STATE, context) < 0) {
        log_key("BLAD: IOCTL_ALTER_STATE: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        log_line("IOCTL_ALTER_STATE: 0, stan 0x%x\n", context[4]);
    }

    if (safe_read(g_softc, snapshot, sizeof(snapshot))) {
        log_key("BLAD: brak migawki softc\n");
        goto out;
    }
    for (uint32_t off = 4; off + 4 <= SNAPSHOT_SIZE; off += 4) {
        uint32_t flags = 0;
        memcpy(&flags, snapshot + off, 4);
        if ((flags & 0xffffU) != 0x212U) continue;
        {
            static const uint32_t dist[2] = {4, 8};
            for (int k = 0; k < 2; k++) {
                uint32_t state = 0;
                if (off < dist[k]) continue;
                memcpy(&state, snapshot + off - dist[k], 4);
                if (!g_flags_slot) {
                    g_state_slot = g_softc + off - dist[k];
                    g_flags_slot = g_softc + off;
                }
                if ((((state & 0xffffU) & ~0x10U) == 3U) ||
                    (((state & 0xffffU) & ~0x10U) == 7U) ||
                    (((state & 0xffffU) & ~0x10U) == 0xfU)) {
                    g_state_slot = g_softc + off - dist[k];
                    g_flags_slot = g_softc + off;
                    break;
                }
            }
        }
        if (g_flags_slot) {
            uint32_t ph = 0;
            if (off >= 8) memcpy(&ph, snapshot + (off - 8), 4);
            if (((ph & 0xffffU) & ~0x10U) == 0xfU) break;
        }
    }

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
    if (!g_state_slot || !g_buffer_slot) {
        log_key("BLAD: nie znalazlem pol skrzynki (stan 0x%llx, bufor 0x%llx)\n",
                (unsigned long long) g_state_slot, (unsigned long long) g_buffer_slot);
        goto out;
    }
    if (safe_read64(g_buffer_slot, &g_buffer) || safe_read64(g_buffer_slot - 8, &g_iommu) ||
        safe_read64(g_buffer_slot - 16, &g_raw_size)) {
        log_key("BLAD: brak pol bufora skrzynki\n");
        goto out;
    }
    if (!g_buffer || !g_raw_size) {
        log_key("BLAD: bufor skrzynki nieprawidlowy (0x%llx, rozmiar 0x%llx)\n",
                (unsigned long long) g_buffer, (unsigned long long) g_raw_size);
        goto out;
    }
    log_line("skrzynka gotowa: stan 0x%llx, flagi 0x%llx, bufor 0x%llx, iommu 0x%llx, rozmiar 0x%llx\n",
             (unsigned long long) g_state_slot, (unsigned long long) g_flags_slot,
             (unsigned long long) g_buffer, (unsigned long long) g_iommu,
             (unsigned long long) g_raw_size);
    rc = 0;

out:
    swap_auth(original);
    return rc;
}

/* ------------------------------------------------------------------ pakiety */

static uint32_t round_up_8(uint32_t v) { return (v + 7U) & ~7U; }

static void build_header(unsigned char *out, uint32_t total) {
    *(uint32_t *)(out + 0x00) = DECI5S_MAGIC;
    *(uint32_t *)(out + 0x04) = 0x28;                 /* self_size naglowka */
    *(uint32_t *)(out + 0x08) = total;                /* packet_size */
    *(uint32_t *)(out + 0x0c) = DECI5S_SRC_KERNEL;
    *(uint32_t *)(out + 0x10) = DECI5S_DST_MP4;
    *(uint32_t *)(out + 0x14) = DECI5S_PROTO_SDBGP;
    *(uint64_t *)(out + 0x20) = 1;                    /* znacznik czasu: jak w mboxwrite */
    *(uint32_t *)(out + 0x28) = DECI5S_DCMP;
    *(uint32_t *)(out + 0x2c) = total - 0x28;         /* code */
    *(uint32_t *)(out + 0x30) = 0;                    /* numer zlecenia, wpisze send_packet */
    *(uint8_t  *)(out + 0x3c) = 1;                    /* num_commands */
}

/* Pakiet odczytu: 0x78 bajtow, uklad bez zmian wzgledem tools/mboxwrite. */
static uint32_t build_read(unsigned char *out, uint64_t addr, uint32_t size) {
    memset(out, 0, 0x80);
    build_header(out, 0x78);

    *(uint32_t *)(out + 0x40) = 0x20;                 /* self_size polecenia */
    *(uint32_t *)(out + 0x44) = 0x38;                 /* total_size polecenia */
    *(uint32_t *)(out + 0x48) = SDBGP_READ_MEMORY;
    *(uint32_t *)(out + 0x5c) = 1;                    /* n_args */
    *(uint32_t *)(out + 0x60) = 0x18;                 /* self_size argumentu */
    *(uint32_t *)(out + 0x64) = (MEM_TYPE_ODCZYT << 8) | ACCESS_ODCZYT;
    *(uint64_t *)(out + 0x68) = addr;
    *(uint64_t *)(out + 0x70) = size;
    return 0x78;
}

/* Pakiet zapisu: 0x40 naglowek, 0x28 polecenie, 0x18 argument, dane wyrownane
 * do 8. Uklad bez zmian wzgledem tools/mboxwrite (0x01040031); zmienne sa
 * wylacznie mem_type, access i adres, czyli osie macierzy. */
static uint32_t build_write(unsigned char *out, uint64_t addr, const void *data,
                            uint32_t size, uint32_t mem_type, uint32_t access) {
    uint32_t inline_size = round_up_8(size);
    uint32_t command_size = 0x28 + 0x18 + inline_size;
    uint32_t total = 0x40 + command_size;

    memset(out, 0, total);
    build_header(out, total);

    *(uint32_t *)(out + 0x40) = 0x28;                 /* self_size polecenia */
    *(uint32_t *)(out + 0x44) = command_size;         /* total_size polecenia */
    *(uint32_t *)(out + 0x48) = SDBGP_WRITE_MEMORY;
    *(uint32_t *)(out + 0x4c) = 0;                    /* flags */
    *(uint32_t *)(out + 0x50) = 0;                    /* command_no */
    *(uint32_t *)(out + 0x54) = 0;                    /* packet_no */
    *(uint32_t *)(out + 0x58) = 0;                    /* pid */
    *(uint32_t *)(out + 0x5c) = 0;                    /* tid */
    *(uint32_t *)(out + 0x60) = 1;                    /* n_args */
    *(uint32_t *)(out + 0x64) = 0;                    /* padding */

    *(uint32_t *)(out + 0x68) = 0x18;                 /* self_size argumentu */
    *(uint32_t *)(out + 0x6c) = (mem_type << 8) | (access & 0xffU);
    *(uint64_t *)(out + 0x70) = addr;
    *(uint64_t *)(out + 0x78) = size;
    if (size) memcpy(out + 0x80, data, size);
    return total;
}

/* Wyslanie pakietu do skrzynki. Zwraca 0, gdy przyszlo ukonczenie zrzutu,
 * -2 gdy nie przyszlo w LIMIT_MS_ODPOWIEDZI, -1 przy bledzie dostepu do jadra. */
static int send_packet(unsigned char *packet, uint32_t total, uint32_t *seq_out,
                       long *ms_out) {
    uint32_t request = 0;
    uint64_t start;

    if (total > g_raw_size) {
        log_line("  pakiet %u B wiekszy niz bufor skrzynki 0x%llx\n",
                 total, (unsigned long long) g_raw_size);
        return -1;
    }
    if (safe_read32(g_softc + 0x160, &request)) return -1;
    request++;
    *(uint32_t *)(packet + 0x30) = request;
    if (seq_out) *seq_out = request;

    if (safe_write32(g_state_slot, ~0x10U) || safe_write32(g_flags_slot, 0x210U))
        return -1;
    if (safe_write(g_buffer, packet, total)) return -1;
    if (safe_write32(g_bar2 + 0xf7000, (uint32_t) (g_iommu >> 32))) return -1;
    if (safe_write32(g_bar2 + 0xf8000, (uint32_t) g_iommu)) return -1;
    if (safe_write32(g_bar2 + 0xf9000, (uint32_t) g_raw_size)) return -1;
    if (safe_write32(g_softc + 0x160, request)) return -1;
    if (safe_write32(g_softc + 0x164, MP4_COREDUMP_CMD)) return -1;
    if (safe_write32(g_softc + 0x168, MP4_COREDUMP_CMD2)) return -1;
    if (safe_write32(g_bar2 + 0xfa000, MP4_COREDUMP_CMD)) return -1;
    if (safe_write32(g_bar2 + 0xf6000, MP4_COREDUMP_CMD)) return -1;

    start = ms_now();
    for (uint32_t i = 0; i < LIMIT_MS_ODPOWIEDZI / 2; i++) {
        uint32_t flags_now = 0;
        if (!safe_read32(g_flags_slot, &flags_now) && (flags_now & 0xffffU) != 0x210U) {
            if (ms_out) *ms_out = (long) (ms_now() - start);
            return 0;
        }
        usleep(2000);
    }
    if (ms_out) *ms_out = (long) (ms_now() - start);
    return -2;
}

static int read_response(uint32_t offset, unsigned char *out, size_t size) {
    return safe_read(g_buffer + offset, out, size);
}

/* ------------------------------------------------------ analiza odpowiedzi A53 */

/* Naglowek wyniku ma 0x28 bajtow: self_size, slowo typu pamieci i dostepu,
 * zadany adres, zadane, przeslane, status. Jego polozenie w odpowiedzi zalezy
 * od rodzaju polecenia, wiec szukamy go po polu adresu, a nie po stalym offsetcie
 * (ta sama zasada co w tools/a53layout i tools/pprwatch). */
static long znajdz_wynik(const unsigned char *resp, uint32_t limit, uint64_t addr,
                         uint32_t *slowo_out) {
    for (uint32_t i = 0; i + ODP_WYNIK <= limit; i += 4) {
        uint32_t self = 0, slowo = 0;
        uint64_t a = 0;
        memcpy(&self, resp + i, 4);
        memcpy(&slowo, resp + i + 4, 4);
        memcpy(&a, resp + i + 8, 8);
        if (self != ODP_WYNIK) continue;
        if (a != addr) continue;
        if (slowo_out) *slowo_out = slowo;
        return (long) i;
    }
    return -1;
}

/* Sprawdzenie naglowka odpowiedzi i zbior typow polecen. Zwraca 1, gdy naglowek
 * jest zgodny z odpowiedzia A53 (magic, kierunek, protokol), 0 gdy nie. */
static int sprawdz_odpowiedz(const unsigned char *resp, uint32_t limit, uint32_t seq_zadany,
                             zapis_wynik *z) {
    uint32_t magic = 0, self = 0, psize = 0, src = 0, dst = 0, proto = 0;
    uint32_t dcmp = 0, code = 0, seq = 0, num = 0;

    if (limit < ODP_NAGLOWEK) return 0;
    memcpy(&magic, resp + 0x00, 4);
    memcpy(&self, resp + 0x04, 4);
    memcpy(&psize, resp + 0x08, 4);
    memcpy(&src, resp + 0x0c, 4);
    memcpy(&dst, resp + 0x10, 4);
    memcpy(&proto, resp + 0x14, 4);
    memcpy(&dcmp, resp + 0x28, 4);
    memcpy(&code, resp + 0x2c, 4);
    memcpy(&seq, resp + 0x30, 4);
    num = resp[0x3c];

    if (z) {
        z->seq_odpowiedz = seq;
        z->polecen = num;
    }
    log_line("    odpowiedz: magic 0x%08x, rozmiar 0x%x, src 0x%08x, dst 0x%08x, "
             "protokol 0x%08x, dcmp 0x%x, code 0x%x, seq 0x%x (zadany 0x%x), polecen %u\n",
             magic, psize, src, dst, proto, dcmp, code, seq, seq_zadany, num);
    if (magic != DECI5S_MAGIC || self != 0x28 || src != DECI5S_DST_MP4 ||
        dst != DECI5S_SRC_KERNEL || proto != DECI5S_PROTO_SDBGP) {
        log_hex("    odpowiedz bajty: ", resp, 0x40);
        return 0;
    }
    if (seq != seq_zadany)
        log_line("    UWAGA: numer zlecenia w odpowiedzi rozny od zadanego, dane moga byc nieaktualne\n");

    /* Opis polecen w odpowiedzi. Typ jest tym, czego szukamy: wynik zapisu ma
     * typ 0x02040031, wynik odczytu 0x02040021, wynik konfiguracji 0x02010010. */
    {
        long off = (long) ODP_NAGLOWEK;
        uint32_t widziane = 0;
        while (widziane < num && widziane < LIMIT_POLECEN_ODP &&
               off + 0x18 <= (long) limit) {
            uint32_t cself = 0, ctotal = 0, ctype = 0, cno = 0;
            memcpy(&cself, resp + off + 0x00, 4);
            memcpy(&ctotal, resp + off + 0x04, 4);
            memcpy(&ctype, resp + off + 0x08, 4);
            memcpy(&cno, resp + off + 0x0c, 4);
            if (cself < 0x18 || ctotal < cself || off + (long) ctotal > (long) limit) {
                log_line("    polecenie %u: naglowek niespojny (self 0x%x, total 0x%x)\n",
                         widziane, cself, ctotal);
                break;
            }
            if (z && z->liczba_typow < LIMIT_POLECEN_ODP)
                z->typy[z->liczba_typow++] = ctype;
            if (z && ctype == SDBGP_RES_WRITE_MEMORY) z->ma_wynik = 1;
            log_line("    polecenie %u: self 0x%x, total 0x%x, typ 0x%08x, nr %u\n",
                     widziane, cself, ctotal, ctype, cno);
            if (ctype == SDBGP_RES_WRITE_MEMORY)
                log_line("    typ 0x%08x to WYNIK ZAPISU pamieci\n", ctype);
            else if (ctype == SDBGP_RES_READ_MEMORY)
                log_line("    typ 0x%08x to wynik odczytu pamieci\n", ctype);
            else if (ctype == SDBGP_RES_GET_CONF)
                log_line("    typ 0x%08x to wynik konfiguracji\n", ctype);
            else
                log_line("    typ 0x%08x to zaden znany wynik (zapis to 0x%08x)\n",
                         ctype, (unsigned) SDBGP_RES_WRITE_MEMORY);
            off += (long) ctotal;
            widziane++;
        }
    }
    return 1;
}

/* ---------------------------------------------------------------- odczyt A53 */

/* Jeden odczyt 32 B pod adresem A53. Zwraca 0 tylko wtedy, gdy dane sa
 * wiarygodne: naglowek wyniku pod zadanym adresem, status 0 i przeslane tyle,
 * ile zadalismy. Inaczej 0 nie jest zwracane i nic nie wolno na tym opierac. */
static int read_at(const char *co, uint64_t addr, uint32_t size, uint8_t *out,
                   odczyt_wynik *w) {
    static unsigned char packet[0x100];
    static unsigned char resp[ODP_ROZMIAR];
    uint32_t total;
    uint32_t seq = 0;
    long ms = 0;
    long h;
    uint32_t slowo = 0;

    memset(w, 0, sizeof(*w));
    w->naglowek = -1;
    total = build_read(packet, addr, size);
    w->rc = send_packet(packet, total, &seq, &ms);
    if (w->rc != 0) {
        log_line("  %s: transport nie potwierdzil ukonczenia, kod %d, %ld ms\n", co, w->rc, ms);
        return -1;
    }
    if (read_response(total, resp, sizeof(resp))) {
        log_line("  %s: nie moge odczytac odpowiedzi ze skrzynki\n", co);
        return -1;
    }
    {
        zapis_wynik tymczasowy;
        memset(&tymczasowy, 0, sizeof(tymczasowy));
        if (!sprawdz_odpowiedz(resp, sizeof(resp), seq, &tymczasowy)) {
            log_line("  %s: naglowek odpowiedzi nie pasuje do A53 (%ld ms)\n", co, ms);
            return -1;
        }
    }
    h = znajdz_wynik(resp, sizeof(resp), addr, &slowo);
    if (h < 0) {
        log_line("  %s: brak naglowka wyniku dla adresu 0x%llx (odczyt niepotwierdzony)\n",
                 co, (unsigned long long) addr);
        log_hex("    odpowiedz bajty: ", resp, 0x80);
        return -1;
    }
    memcpy(&w->zadane, resp + h + 0x10, 8);
    memcpy(&w->przeslane, resp + h + 0x18, 8);
    memcpy(&w->status, resp + h + 0x20, 4);
    w->slowo = slowo;
    w->naglowek = h;
    if (w->przeslane != size || w->status != 0) {
        log_line("  %s: odczyt nieudany (zadane 0x%llx, przeslane 0x%llx, status 0x%x)\n",
                 co, (unsigned long long) w->zadane, (unsigned long long) w->przeslane,
                 w->status);
        return -1;
    }
    if (h + (long) ODP_WYNIK + (long) size > (long) sizeof(resp)) {
        log_line("  %s: dane wyniku poza odpowiedzia\n", co);
        return -1;
    }
    memcpy(out, resp + h + ODP_WYNIK, size);
    w->wiarygodny = 1;
    return 0;
}

/* ---------------------------------------------------------------- zapis A53 */

/* Jeden zapis 16 B pod adresem A53. Zwraca kod zwrotu transportu (0 = ukonczenie
 * przyszlo). Pelny opis odpowiedzi laduje w z. */
static int write_at(uint64_t addr, const void *data, uint32_t size, uint32_t mem_type,
                    uint32_t access, zapis_wynik *z) {
    static unsigned char packet[0x100];
    static unsigned char resp[ODP_ROZMIAR];
    uint32_t total;
    uint32_t seq = 0;
    long ms = 0;
    long h;
    uint32_t slowo = 0;

    memset(z, 0, sizeof(*z));
    z->wynik_off = -1;
    total = build_write(packet, addr, data, size, mem_type, access);
    log_line("    pakiet zapisu: %u B, typ 0x%08x, mem_type 0x%06x, access %u, addr 0x%llx, %u B danych\n",
             total, (unsigned) SDBGP_WRITE_MEMORY, mem_type, access,
             (unsigned long long) addr, size);
    z->rc = send_packet(packet, total, &seq, &ms);
    z->seq_zadany = seq;
    log_line("    transport: kod %d (%s), %ld ms\n", z->rc,
             z->rc == 0 ? "ukonczenie przyszlo" : "brak ukonczenia", ms);
    if (z->rc != 0) return z->rc;
    if (read_response(total, resp, sizeof(resp))) {
        log_line("    nie moge odczytac odpowiedzi ze skrzynki\n");
        return z->rc;
    }
    z->ma_odpowiedz = sprawdz_odpowiedz(resp, sizeof(resp), seq, z);
    /* Surowa odpowiedz zapisujemy zawsze, zeby uklad naglowka (a nie tylko nasza
     * interpretacja) byl widoczny po fakcie, takze dla prob odrzuconych. */
    log_hex("    odpowiedz 0x60 B: ", resp, 0x60);
    h = znajdz_wynik(resp, sizeof(resp), addr, &slowo);
    if (h >= 0) {
        z->ma_wynik = 1;
        z->wynik_off = h;
        z->wynik_slowo = slowo;
        memcpy(&z->wynik_adres, resp + h + 0x08, 8);
        memcpy(&z->wynik_zadane, resp + h + 0x10, 8);
        memcpy(&z->wynik_przeslane, resp + h + 0x18, 8);
        memcpy(&z->wynik_status, resp + h + 0x20, 4);
        log_line("    naglowek wyniku pod 0x%lx: slowo 0x%08x, adres 0x%llx, zadane 0x%llx, "
                 "przeslane 0x%llx, status 0x%x\n",
                 h, slowo, (unsigned long long) z->wynik_adres,
                 (unsigned long long) z->wynik_zadane,
                 (unsigned long long) z->wynik_przeslane, z->wynik_status);
    } else if (z->ma_wynik) {
        log_line("    typ wyniku zapisu jest w odpowiedzi, ale nie ma naglowka pod zadanym adresem\n");
        log_hex("    odpowiedz bajty: ", resp, 0x80);
    } else {
        log_line("    brak wyniku zapisu w odpowiedzi (A53 nie odeslala typu 0x%08x)\n",
                 (unsigned) SDBGP_RES_WRITE_MEMORY);
        log_hex("    odpowiedz bajty: ", resp, 0x80);
    }
    return z->rc;
}

/* ------------------------------------------------------------- bramki, pomoc */

static int budzet_wyczerpany(void) {
    return ms_od_startu() >= (uint64_t) BUDZET_S * 1000ULL;
}

static int stop_plik(void) { return access(STOP_FILE, F_OK) == 0; }

/* Sprawdzenie pieciu kotwic obrazu A53. Zwraca liczbe zgodnych. */
static unsigned sprawdz_kotwice(const char *kiedy) {
    static unsigned char dane[WP_ODCZYT];
    unsigned zgodne = 0;

    log_line("kotwice obrazu A53 (%s):\n", kiedy);
    for (unsigned i = 0; i < LICZBA_KOTWIC; i++) {
        odczyt_wynik w;
        if (read_at("kotwica", KOTWICE[i].pa, WP_ODCZYT, dane, &w) != 0) {
            log_line("  0x%06llx %-16s: odczyt nieudany\n",
                     (unsigned long long) KOTWICE[i].pa, KOTWICE[i].nazwa);
            continue;
        }
        if (memcmp(dane, KOTWICE[i].bajty, WP_WZORZEC) == 0) {
            zgodne++;
            log_line("  0x%06llx %-16s: zgodna\n",
                     (unsigned long long) KOTWICE[i].pa, KOTWICE[i].nazwa);
        } else {
            log_line("  0x%06llx %-16s: NIEZGODNA\n",
                     (unsigned long long) KOTWICE[i].pa, KOTWICE[i].nazwa);
            log_hex("    oczekiwane: ", KOTWICE[i].bajty, WP_WZORZEC);
            log_hex("    odczytane : ", dane, WP_WZORZEC);
        }
    }
    log_line("kotwice %s: %u z %u zgodnych\n", kiedy, zgodne, LICZBA_KOTWIC);
    return zgodne;
}

/* Kopia stanu spod adresu do g_stan_pierwotny (na wypadek, gdyby po restarcie
 * trzeba bylo sprawdzic, co bylo przed probami). */
static void zapisz_stan_pierwotny(unsigned idx, uint64_t addr) {
    odczyt_wynik w;
    if (idx >= sizeof(g_stan_pierwotny) / sizeof(g_stan_pierwotny[0])) return;
    if (read_at("stan pierwotny", addr, WP_ODCZYT, g_stan_pierwotny[idx], &w) != 0) {
        log_line("  stan pierwotny 0x%llx: odczyt nieudany\n", (unsigned long long) addr);
        return;
    }
    log_line("  stan pierwotny 0x%llx: ", (unsigned long long) addr);
    {
        char hex[3 * WP_ODCZYT + 1];
        hex_do(g_stan_pierwotny[idx], WP_ODCZYT, hex, sizeof(hex));
        log_line("%s\n", hex);
    }
    if (idx + 1 > g_adresow_stanu) g_adresow_stanu = idx + 1;
}

/* Przywrocenie oryginalu. Zapisujemy dokladnie te bajty, ktore sie roznily:
 * 16 B, gdy roznil sie tylko wzorzec, 32 B, gdy zapis siegnal sasiednich bajtow.
 * Nigdy wiecej niz 32 B i zawsze jest to tresc odczytana przed proba. */
static int przywroc(uint64_t addr, const uint8_t *przed, const uint8_t *po, uint32_t size,
                    uint32_t mem_type, uint32_t access) {
    static unsigned char po_przywroceniu[WP_ODCZYT];
    uint32_t rozmiar = WP_WZORZEC;
    odczyt_wynik w;
    zapis_wynik z;
    int rc;

    if (size > WP_WZORZEC) {
        for (uint32_t i = WP_WZORZEC; i < size; i++) {
            if (przed[i] != po[i]) { rozmiar = size; break; }
        }
    }
    log_line("    przywracam %u B oryginalu pod 0x%llx (mem_type 0x%06x, access %u)\n",
             rozmiar, (unsigned long long) addr, mem_type, access);
    rc = write_at(addr, przed, rozmiar, mem_type, access, &z);
    if (rc != 0) {
        log_key("    PRZYWRACANIE NIEUDANE: transport kod %d\n", rc);
        return -1;
    }
    if (read_at("po przywroceniu", addr, WP_ODCZYT, po_przywroceniu, &w) != 0) {
        log_key("    PRZYWRACANIE NIEPOTWIERDZONE: brak wiarygodnego odczytu kontrolnego\n");
        return -1;
    }
    if (memcmp(po_przywroceniu, przed, size) == 0) {
        log_line("    przywrocone: %u B zgodne ze stanem przed proba\n", size);
        return 0;
    }
    log_key("    PRZYWRACANIE NIEPELNE: odczyt po przywroceniu rozny od stanu przed proba\n");
    log_hex("    przed : ", przed, size);
    log_hex("    po    : ", po_przywroceniu, size);
    return -1;
}

/* --------------------------------------------------------------- glowna praca */

static int wykonaj_probe(unsigned nr) {
    const wp_proba *p = wp_proba_dla(nr);
    const wp_adres *a;
    static unsigned char przed[WP_ODCZYT], po[WP_ODCZYT];
    uint8_t wzorzec[WP_WZORZEC];
    odczyt_wynik w;
    zapis_wynik z;
    wynik_proby wynik;
    unsigned idx_adresu;
    int rc;

    if (!p) return -1;
    memset(&wynik, 0, sizeof(wynik));
    wynik.nr = nr;
    wynik.adres = p->adres;
    wynik.mem_type = p->mem_type;
    wynik.access = p->access;
    wynik.osad = WP_ODCZYT_NIEWIARYGODNY;   /* domyslnie: nie ma werdyktu */
    wynik.przywrocono = -1;

    idx_adresu = nr / (wp_typow() * wp_dostepow());
    a = wp_adres_dla(idx_adresu);

    log_line("-- proba %02u/%u: adres 0x%llx (%s), mem_type 0x%06x, access %u --\n",
             nr + 1, wp_prob(), (unsigned long long) p->adres,
             a ? a->opis : "?", p->mem_type, p->access);

    /* Bramka adresu: poza oknem transportu nie ma czego mierzyc. */
    if (p->adres + WP_WZORZEC > OKNO_SRAM) {
        log_key("   POMINIETA: adres poza oknem transportu 0x0-0x%llx\n",
                (unsigned long long) (OKNO_SRAM - 1));
        wynik.pominieto = 1;
        wynik.osad = WP_ODCZYT_NIEWIARYGODNY;
        g_wyniki[g_wynikow++] = wynik;
        return 0;
    }

    /* Bramka bezpieczenstwa: gdy zapis dziala, nie ma po co dotykac zywego kodu. */
    if (g_nr_przyjetej >= 0 && p->adres == 0x28000ULL) {
        log_key("   POMINIETA: zapis dziala (proba %02d), nie dotykam zywego obrazu A53\n",
                g_nr_przyjetej + 1);
        wynik.pominieto = 1;
        wynik.osad = WP_ODCZYT_NIEWIARYGODNY;
        g_wyniki[g_wynikow++] = wynik;
        return 0;
    }

    /* 1. stan przed. Bez wiarygodnego odczytu NIE piszemy, bo nie byloby czym
     * przywrocic oryginalu. */
    if (read_at("przed", p->adres, WP_ODCZYT, przed, &w) != 0) {
        log_key("   ODCZYT PRZED NIEUDANY, zapisu nie wysylam (nie ma czym przywrocic)\n");
        wynik.rc = w.rc;
        wynik.osad = WP_ODCZYT_NIEWIARYGODNY;
        wynik.pominieto = 1;
        g_wyniki[g_wynikow++] = wynik;
        if (++g_bez_odpowiedzi >= LIMIT_BEZ_ODPOWIEDZI) {
            log_key("   PRZERWANIE: transport nie odpowiada (%d odczyty pod rzad nieudane)\n",
                    g_bez_odpowiedzi);
            g_przerwano = 1;
        }
        return 0;
    }
    g_bez_odpowiedzi = 0;
    log_hex("   przed (32 B): ", przed, WP_ODCZYT);

    /* 2. zapis wzorca 16 B. */
    wp_wzorzec(nr, wzorzec);
    log_hex("   wzorzec (16 B): ", wzorzec, WP_WZORZEC);
    rc = write_at(p->adres, wzorzec, WP_WZORZEC, p->mem_type, p->access, &z);
    wynik.rc = rc;
    wynik.ma_odpowiedz = z.ma_odpowiedz;
    wynik.liczba_typow = z.liczba_typow;
    wynik.typ_w_odp = z.liczba_typow ? z.typy[0] : 0;
    wynik.wynik_w_odp = z.ma_wynik;
    if (rc != 0) {
        log_key("   BRAK ODPOWIEDZI na zapis (transport kod %d)\n", rc);
        wynik.osad = WP_ODCZYT_NIEWIARYGODNY;
        g_wyniki[g_wynikow++] = wynik;
        if (++g_bez_odpowiedzi >= LIMIT_BEZ_ODPOWIEDZI) {
            log_key("   PRZERWANIE: %d transakcji pod rzad bez potwierdzenia A53\n",
                    g_bez_odpowiedzi);
            g_przerwano = 1;
        }
        return 0;
    }

    /* 3. odczekanie, zeby A53 miala czas wykonac polecenie. */
    usleep(CZAS_OSADZENIA_MS * 1000U);

    /* 4. stan po. */
    if (read_at("po", p->adres, WP_ODCZYT, po, &w) != 0) {
        log_key("   BRAK WIARYGODNEGO ODCZYTU PO ZAPISIE: nie wiem, czy zapis wszedl\n");
        wynik.osad = WP_ODCZYT_NIEWIARYGODNY;
        /* Najbezpieczniejszy ruch: przywrocic znany oryginal na slepo i przerwac. */
        log_key("   przywracam oryginal na slepo i koncze macierz\n");
        if (przywroc(p->adres, przed, przed, WP_WZORZEC, p->mem_type, p->access) == 0)
            wynik.przywrocono = 1;
        g_wyniki[g_wynikow++] = wynik;
        g_przerwano = 1;
        return 0;
    }
    g_bez_odpowiedzi = 0;
    log_hex("   po    (32 B): ", po, WP_ODCZYT);
    wynik.osad = wp_ocen(przed, po, wzorzec, WP_WZORZEC);

    /* 5. werdykt + natychmiastowe przywrocenie oryginalu, gdy pamiec sie zmienila. */
    switch (wynik.osad) {
        case WP_ZAPIS_PRZYJETY:
            log_key("   WERDYKT: ZAPIS PRZYJETY (bajty po zapisie rowne wzorcowi)\n");
            if (g_nr_przyjetej < 0) g_nr_przyjetej = (int) nr;
            break;
        case WP_ZAPIS_ODRZUCONY:
            log_line("   WERDYKT: zapis odrzucony (pamiec bez zmian, odczyt wiarygodny)\n");
            break;
        case WP_PAMIEC_ZMIENIONA:
            log_key("   WERDYKT: pamiec zmieniona inaczej niz wzorzec\n");
            break;
        default:
            break;
    }
    if (wynik.osad != WP_ZAPIS_ODRZUCONY) {
        if (przywroc(p->adres, przed, po, WP_ODCZYT, p->mem_type, p->access) == 0)
            wynik.przywrocono = 1;
        else {
            log_key("   PRZERWANIE: nie udalo sie przywrocic oryginalu, dalsze zapisy wstrzymane\n");
            g_przerwano = 1;
        }
    }
    if (wynik.ma_odpowiedz && !wynik.wynik_w_odp) {
        log_line("   uwaga: odpowiedz nie zawierala wyniku zapisu 0x%08x; A53 odpowiedziala "
                 "innym typem polecenia (patrz linie wyzej)\n",
                 (unsigned) SDBGP_RES_WRITE_MEMORY);
    }
    g_wyniki[g_wynikow++] = wynik;
    return 0;
}

static void wypisz_podsumowanie(unsigned zgodne_przed, unsigned zgodne_po) {
    unsigned przyjete = 0, odrzucone = 0, zmienione = 0, brak_odczytu = 0, pominiete = 0;
    unsigned z_wynikiem = 0, bez_odp = 0;

    for (unsigned i = 0; i < g_wynikow; i++) {
        const wynik_proby *w = &g_wyniki[i];
        if (w->pominieto) { pominiete++; continue; }
        switch (w->osad) {
            case WP_ZAPIS_PRZYJETY:   przyjete++; break;
            case WP_ZAPIS_ODRZUCONY:  odrzucone++; break;
            case WP_PAMIEC_ZMIENIONA: zmienione++; break;
            default:                  brak_odczytu++; break;
        }
        if (w->wynik_w_odp) z_wynikiem++;
        if (w->rc != 0) bez_odp++;
    }

    log_key("\n=== tabela prob ===\n");
    log_line("nr  adres     mem_type access transport odpowiedz typ_polecenia wynik_zapisu werdykt\n");
    for (unsigned i = 0; i < g_wynikow; i++) {
        const wynik_proby *w = &g_wyniki[i];
        char typ[16];
        if (w->pominieto) {
            log_line("%02u  0x%06llx  0x%06x   %u      -         -        -              -            pominiety\n",
                     w->nr + 1, (unsigned long long) w->adres, w->mem_type, w->access);
            continue;
        }
        if (w->liczba_typow) snprintf(typ, sizeof(typ), "0x%08x", w->typ_w_odp);
        else snprintf(typ, sizeof(typ), "brak");
        log_line("%02u  0x%06llx  0x%06x   %u      %d         %s %s %s %s\n",
                 w->nr + 1, (unsigned long long) w->adres, w->mem_type, w->access,
                 w->rc, w->ma_odpowiedz ? "tak" : "nie ", typ,
                 w->wynik_w_odp ? "tak" : "nie", wp_osad_opis(w->osad));
    }

    log_key("\n=== podsumowanie ===\n");
    log_key("prob w macierzy: %u (adresy %u x typy %u x dostepy %u)\n",
            wp_prob(), wp_adresow(), wp_typow(), wp_dostepow());
    log_key("wykonanych: %u, przyjetych: %u, odrzuconych: %u, zmienionych inaczej: %u, "
            "bez wiarygodnego odczytu: %u, pominietych: %u\n",
            g_wynikow, przyjete, odrzucone, zmienione, brak_odczytu, pominiete);
    log_key("odpowiedzi z wynikiem zapisu 0x%08x: %u, transakcje bez potwierdzenia: %u\n",
            (unsigned) SDBGP_RES_WRITE_MEMORY, z_wynikiem, bez_odp);
    log_key("kotwice na poczatku: %u z %u, na koncu: %u z %u\n",
            zgodne_przed, LICZBA_KOTWIC, zgodne_po, LICZBA_KOTWIC);

    /* Stan koncowy adresow macierzy kontra stan pierwotny: dowod, ze po przebiegu
     * nic nie zostalo zmienione. */
    {
        unsigned zgodnych = 0, sprawdzonych = 0;
        for (unsigned i = 0; i < g_adresow_stanu; i++) {
            const wp_adres *a = wp_adres_dla(i);
            static unsigned char teraz[WP_ODCZYT];
            odczyt_wynik w;
            if (!a) continue;
            sprawdzonych++;
            if (read_at("stan koncowy", a->adres, WP_ODCZYT, teraz, &w) != 0) {
                log_line("  stan koncowy 0x%llx: odczyt nieudany\n",
                         (unsigned long long) a->adres);
                continue;
            }
            if (memcmp(teraz, g_stan_pierwotny[i], WP_ODCZYT) == 0) {
                zgodnych++;
            } else {
                log_key("  stan koncowy 0x%llx ROZNY od pierwotnego\n",
                        (unsigned long long) a->adres);
                log_hex("    pierwotny: ", g_stan_pierwotny[i], WP_ODCZYT);
                log_hex("    teraz    : ", teraz, WP_ODCZYT);
            }
        }
        log_key("stan koncowy adresow macierzy: %u z %u zgodnych ze stanem pierwotnym\n",
                zgodnych, sprawdzonych);
    }

    if (przyjete > 0) {
        log_key("[wniosek] A53 PRZYJMUJE zapis pamieci. Kombinacje, ktore zadzialaly:\n");
        for (unsigned i = 0; i < g_wynikow; i++) {
            const wynik_proby *w = &g_wyniki[i];
            if (w->osad != WP_ZAPIS_PRZYJETY) continue;
            log_key("  proba %02u: adres 0x%llx, mem_type 0x%06x, access %u, typ w odpowiedzi 0x%08x\n",
                    w->nr + 1, (unsigned long long) w->adres, w->mem_type, w->access,
                    w->typ_w_odp);
        }
        log_key("[wniosek] warunek dowodu spelniony: bajty po zapisie rowne wzorcowi, a oryginal przywrocony\n");
    } else if (zmienione > 0) {
        log_key("[wniosek] A53 nie zapisala wzorca w zadnej probie, ale pamiec zmienila sie "
                "w %u probach: to nie jest zwykly zapis, trzeba przejrzec te wpisy\n", zmienione);
    } else if (brak_odczytu > 0) {
        log_key("[wniosek] zadna proba nie zostala rozstrzygnieta (brak wiarygodnego odczytu): "
                "macierz niewazna, powtorzyc po ustabilizowaniu transportu\n");
    } else {
        log_key("[wniosek] A53 nie przyjmuje zapisu pamieci w ZADNEJ z %u kombinacji "
                "(adres x mem_type x access). Droga zapisu opcodem 0x%08x jest zamknieta "
                "dla tego firmware, niezaleznie od adresu i typu.\n",
                wp_prob(), (unsigned) SDBGP_WRITE_MEMORY);
    }
    if (g_przerwano)
        log_key("[uwaga] macierz przerwana przed czasem, patrz linie PRZERWANIE wyzej\n");
    if (budzet_wyczerpany())
        log_key("[uwaga] budzet %u s wyczerpany, macierz moze byc niekompletna\n", BUDZET_S);
}

int main(void) {
    unsigned zgodne_przed = 0, zgodne_po = 0;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = obsluz_sygnal;
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGTERM, &sa, NULL);

    g_start_ms = ms_now();
    g_log = fopen(OUT_LOG, "w");
    log_key("writeprobe start: matryca %u prob zapisu do pamieci A53\n", wp_prob());
    log_key("wersja systemu 0x%x, budzet %u s, stop plikiem %s\n",
            kernel_get_fw_version(), BUDZET_S, STOP_FILE);
    log_key("wymagania: odczyt i zapis pamieci jadra (kstuff); latka PPR nie jest potrzebna\n");
    if (g_log) log_line("log: %s\n", OUT_LOG);

    if ((kernel_get_fw_version() >> 16) != FW_1360) {
        log_key("ODMOWA: to nie firmware 13.60 (wersja 0x%x). Payload nie wysyla zadnego zapisu.\n",
                kernel_get_fw_version());
        goto done;
    }
    if (stop_plik()) {
        log_key("ODMOWA: plik stop %s istnieje przed startem\n", STOP_FILE);
        goto done;
    }
    if (init_map() != 0) {
        log_key("ODMOWA: brak mapy bezposredniej jadra (odczyt pamieci jadra nie dziala; "
                "payload wymaga kstuff, latka PPR nie jest potrzebna)\n");
        goto done;
    }
    if (mailbox_init() != 0) {
        log_key("ODMOWA: nie znalazlem sterownika MP4 (softc/BAR2)\n");
        goto done;
    }
    log_line("kontekst 0x%llx, BAR2 0x%llx\n",
             (unsigned long long) g_softc, (unsigned long long) g_bar2);
    if (mailbox_open() != 0) {
        log_key("ODMOWA: skrzynka coredump niegotowa, zero zapisow\n");
        goto done;
    }

    /* Bramka 1: czy transport czyta prawdziwa pamiec A53.
     *
     * Warunek: naglowek obrazu (0x28000) musi sie zgadzac, a razem z nim co
     * najmniej dwie kotwice z kodu. Sam naglowek nie wystarcza, bo przy zwracaniu
     * stalej tresci bufora kazdy adres daje ten sam blok. Piec kotwic z rzedu
     * nie jest wymagane: cztery z nich pochodza z obrazu odtworzonego ze zrzutow,
     * a tylko 0x28000 jest potwierdzony odczytem na konsoli. */
    zgodne_przed = sprawdz_kotwice("na poczatku");
    {
        int naglowek_ok = 0;
        static unsigned char dane[WP_ODCZYT];
        odczyt_wynik w;
        if (read_at("kotwica", KOTWICE[0].pa, WP_ODCZYT, dane, &w) == 0 &&
            memcmp(dane, KOTWICE[0].bajty, WP_WZORZEC) == 0)
            naglowek_ok = 1;
        if (!naglowek_ok || zgodne_przed < 3) {
            log_key("ODMOWA: %u z %u kotwic zgodnych, naglowek obrazu %s. Transport nie "
                    "potwierdza, ze czyta prawdziwa pamiec A53 (wymagane: naglowek i razem "
                    "co najmniej 3 kotwice), wiec zapis nie rozstrzygnie o niczym.\n",
                    zgodne_przed, LICZBA_KOTWIC, naglowek_ok ? "zgodny" : "niezgodny");
            goto done;
        }
        log_key("bramka odczytu: naglowek obrazu zgodny, kotwic zgodnych %u z %u\n",
                zgodne_przed, LICZBA_KOTWIC);
    }

    /* Bramka 2: stan pierwotny wszystkich adresow macierzy, zeby po restarcie
     * wiedziec, co bylo przed probami. */
    log_key("\nstan pierwotny adresow macierzy:\n");
    for (unsigned i = 0; i < wp_adresow(); i++) {
        const wp_adres *a = wp_adres_dla(i);
        if (!a) continue;
        zapisz_stan_pierwotny(i, a->adres);
    }

    log_key("\n=== macierz prob ===\n");
    log_key("kolejnosc adresow: ");
    for (unsigned i = 0; i < wp_adresow(); i++) {
        const wp_adres *a = wp_adres_dla(i);
        if (a) log_key("0x%llx ", (unsigned long long) a->adres);
    }
    log_key("\ntypy pamieci:");
    for (unsigned i = 0; i < wp_typow(); i++)
        log_key(" 0x%06x", wp_typ_dla(i));
    log_key("\ntypy dostepu:");
    for (unsigned i = 0; i < wp_dostepow(); i++)
        log_key(" %u", wp_dostep_dla(i));
    log_key("\n");

    for (unsigned nr = 0; nr < wp_prob(); nr++) {
        if (g_stop) { log_key("PRZERWANIE: sygnal\n"); g_przerwano = 1; break; }
        if (stop_plik()) { log_key("PRZERWANIE: plik stop %s\n", STOP_FILE); g_przerwano = 1; break; }
        if (budzet_wyczerpany()) { log_key("PRZERWANIE: budzet %u s\n", BUDZET_S); g_przerwano = 1; break; }
        if (g_przerwano) break;
        if (g_wynikow >= sizeof(g_wyniki) / sizeof(g_wyniki[0])) break;
        wykonaj_probe(nr);
    }

    /* Bramka 3: po calym przebiegu obraz A53 ma byc nietkniety. */
    zgodne_po = sprawdz_kotwice("na koncu");
    wypisz_podsumowanie(zgodne_przed, zgodne_po);

done:
    if (g_ctl >= 0) { close(g_ctl); g_ctl = -1; }
    log_key("writeprobe koniec, czas %llu ms\n", (unsigned long long) ms_od_startu());
    if (g_log) { fflush(g_log); fsync(fileno(g_log)); fclose(g_log); g_log = NULL; }
    return 0;
}
