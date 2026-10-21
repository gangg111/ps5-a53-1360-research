/*
 * Podglada rejestry okna urzadzenia podczas zrzutu jadra.
 *
 * Ustalone: polecenie odczytu widzi okno 64 kB, ktore powtarza sie niezaleznie od
 * podanego adresu. Jadro potrafilo odczytac wszystkie dziewiec regionow, wiec musi
 * przełączac okno, a wiec zapisywac cos do rejestrow. Ten payload NIC NIE ZAPISUJE
 * poza sekwencja startu zrzutu: tylko czyta rejestry BAR2+0xf6000..+0xfa000 oraz
 * pola kontekstu sterownika i zapisuje, jakie wartosci sie pojawiaja.
 *
 * Wymaga kstuff. Wynik: /data/a53win.txt
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
#define OUT_LOG      "/data/a53win.txt"
#define OFF_IFACE_A 0x3DEEB58ULL

#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL

/* Rejestry okna: od wyzwalacza do konca okna. */
static const uint32_t WINDOW_OFFSETS[] = {
    0xf6000, 0xf7000, 0xf8000, 0xf9000, 0xfa000
};
#define WINDOW_COUNT (sizeof(WINDOW_OFFSETS) / sizeof(WINDOW_OFFSETS[0]))

/* Pola kontekstu, ktore warto obserwowac. */
static const uint32_t SOFT_OFFSETS[] = {0x160, 0x164, 0x168, 0x16c};
#define SOFT_COUNT (sizeof(SOFT_OFFSETS) / sizeof(SOFT_OFFSETS[0]))

#define SAMPLES 400
#define SAMPLE_DELAY_US 2000

static FILE *g_log;
static unsigned long g_dmap, g_cr3;
static uint64_t g_softc, g_bar2;

static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
    klog_printf("[a53win] %s", buf);
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

/* Rejestry urzadzenia sa na stronach niebuforowanych, wiec czytamy je bez
 * wykluczania takich stron. To odczyt rejestru, nie pamieci. */
static int reg_read32(uint64_t va, uint32_t *out) {
    uint64_t pml = g_cr3 & PG_FRAME;
    for (int i = 39; i >= 12; i -= 9) {
        unsigned long idx = (va >> i) & 0x1FF;
        pml = kernel_getlong(g_dmap + pml + idx * 8);
        if (!(pml & X86_PG_V)) return -1;
        if ((pml & X86_PG_PS) || i == 12) break;
        pml &= PG_FRAME;
    }
    return kernel_copyout(va, out, 4);
}

static int safe_read(uint64_t va, void *dst, size_t n) {
    if (!readable(va)) return -1;
    return kernel_copyout(va, dst, n);
}
static int safe_read64(uint64_t va, uint64_t *o) { return safe_read(va, o, 8); }
static int safe_read32(uint64_t va, uint32_t *o) { return safe_read(va, o, 4); }

static uint64_t swap_auth(uint64_t id) {
    pid_t pid = getpid();
    uint64_t o = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, id);
    return o;
}

int main(void) {
    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    uint32_t finish[2] = {8, 0};
    uint32_t prev_win[WINDOW_COUNT], cur_win[WINDOW_COUNT];
    uint32_t prev_soft[SOFT_COUNT], cur_soft[SOFT_COUNT];
    int kq = -1, ctl = -1;
    long changes = 0;

    g_log = fopen(OUT_LOG, "w");
    log_line("a53win: podgladam rejestry okna podczas zrzutu jadra, nic nie zapisuje\n");

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

    /* stan poczatkowy rejestrow */
    for (size_t i = 0; i < WINDOW_COUNT; i++) prev_win[i] = 0;
    for (size_t i = 0; i < SOFT_COUNT; i++) prev_soft[i] = 0;
    log_line("--- rejestry przed sekwencja ---\n");
    for (size_t i = 0; i < WINDOW_COUNT; i++) {
        uint32_t v = 0;
        if (reg_read32(g_bar2 + WINDOW_OFFSETS[i], &v) == 0) {
            prev_win[i] = v;
            log_line("  BAR2+0x%x = 0x%08x\n", WINDOW_OFFSETS[i], v);
        } else {
            log_line("  BAR2+0x%x nieczytelny\n", WINDOW_OFFSETS[i]);
        }
    }
    for (size_t i = 0; i < SOFT_COUNT; i++) {
        uint32_t v = 0;
        if (safe_read32(g_softc + SOFT_OFFSETS[i], &v) == 0) {
            prev_soft[i] = v;
            log_line("  softc+0x%x = 0x%08x\n", SOFT_OFFSETS[i], v);
        }
    }

    uint64_t original = swap_auth(SYSCORE_AUTH_ID);
    (void) revoke(CONTROL_PATH);
    ctl = open(CONTROL_PATH, O_RDONLY);
    if (ctl < 0) { log_line("otwarcie nieudane errno=%d\n", errno); swap_auth(original); return 5; }

    log_line("--- IOCTL_START, zaczynam podglad ---\n");
    if (ioctl(ctl, IOCTL_START, context) < 0) {
        log_line("IOCTL_START blad errno=%d\n", errno);
        close(ctl); swap_auth(original);
        return 6;
    }

    /* podglad w trakcie pracy urzadzenia */
    for (int s = 0; s < SAMPLES; s++) {
        for (size_t i = 0; i < WINDOW_COUNT; i++) {
            uint32_t v = 0;
            if (reg_read32(g_bar2 + WINDOW_OFFSETS[i], &v)) continue;
            cur_win[i] = v;
            if (v != prev_win[i]) {
                changes++;
                log_line("  krok %d: BAR2+0x%x  0x%08x -> 0x%08x\n",
                         s, WINDOW_OFFSETS[i], prev_win[i], v);
                prev_win[i] = v;
            }
        }
        for (size_t i = 0; i < SOFT_COUNT; i++) {
            uint32_t v = 0;
            if (safe_read32(g_softc + SOFT_OFFSETS[i], &v)) continue;
            cur_soft[i] = v;
            if (v != prev_soft[i]) {
                changes++;
                log_line("  krok %d: softc+0x%x  0x%08x -> 0x%08x\n",
                         s, SOFT_OFFSETS[i], prev_soft[i], v);
                prev_soft[i] = v;
            }
        }
        usleep(SAMPLE_DELAY_US);
    }
    log_line("--- koniec podgladu, zmian: %ld ---\n", changes);

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

    log_line("--- rejestry po sekwencji ---\n");
    for (size_t i = 0; i < WINDOW_COUNT; i++) {
        uint32_t v = 0;
        if (reg_read32(g_bar2 + WINDOW_OFFSETS[i], &v) == 0) {
            log_line("  BAR2+0x%x = 0x%08x  (bylo 0x%08x)\n",
                     WINDOW_OFFSETS[i], v, cur_win[i]);
        }
    }
    for (size_t i = 0; i < SOFT_COUNT; i++) {
        uint32_t v = 0;
        if (safe_read32(g_softc + SOFT_OFFSETS[i], &v) == 0) {
            log_line("  softc+0x%x = 0x%08x  (bylo 0x%08x)\n",
                     SOFT_OFFSETS[i], v, cur_soft[i]);
        }
    }

    log_line("--- IOCTL_FINISH ---\n");
    (void) ioctl(ctl, IOCTL_FINISH, finish);
    if (kq >= 0) close(kq);
    close(ctl);
    swap_auth(original);
    log_line("koniec, nic nie zapisano poza sekwencja startu\n");
    if (g_log) fclose(g_log);
    return 0;
}
