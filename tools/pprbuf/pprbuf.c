/*
 * pprbuf: obserwuje BUFOR DESZYFROWANIA sterownika MP4 w pamieci jadra i zapisuje
 * to, co sie w nim pojawi.
 *
 * To jest payload WYLACZNIE ODCZYTUJACY. Nie otwiera zadnego wezla urzadzenia, nie
 * robi ioctl i nie zapisuje niczego do struktury sterownika MP4 ani do rejestrow
 * urzadzen. Jedyne, co zmienia poza wlasnymi plikami w /data, to wlasny identyfikator
 * uprawnien na czas odczytu (kernel_copyout tego wymaga; przed wyjsciem wraca do
 * wartosci pierwotnej) oraz wiersze w dzienniku jadra przez klog_printf, dokladnie
 * tak jak tools/softc2 i tools/iommu3 (dziennik to bufor komunikatow, nie pamiec
 * sterownika).
 *
 * PO CO TO JEST:
 * test rozstrzygajacy, czy odszyfrowana zawartosc MP4 trafia do pamieci gospodarza,
 * zanim werdykt podpisu cokolwiek zablokuje. Patrzymy na dwa bufory:
 *   bufor 1: globalna struktura mapowania MP4, pole +0x08, do ktorego
 *            mp4_map_iommu_discont zapisuje adres bufora w pamieci jadra
 *            (w zrzucie 0xffffff8007d2c000),
 *   bufor 2: struktura sterownika MP4, pole +0x6b8, czyli mp4_coredump_buffer_va
 *            (adres bufora w pamieci jadra).
 *
 * SKAD WIEMY, GDZIE PATRZEC (dowody w notes/IOMMU-MAPOWANIE-Z-DEASEMBLACJI.md):
 *   - w zrzucie artifacts/kernel-1360-13.60.bin baza obrazu kodu to 0xffffffffc0c60000,
 *     a baza danych 0xffffffffc1920000,
 *   - sciezka mapowania zapisuje wynik do globalnej struktury pod 0xffffffffc31c0e70:
 *     +0x08 to adres bufora w pamieci jadra (w zrzucie 0xffffff8007d2c000),
 *     +0x10 to adres urzadzenia (0x64000000), +0x18 to flagi (0x50000000),
 *   - pola struktury sterownika: +0x6a8 mp4_coredump_buffer_size (0x200000),
 *     +0x6b0 mp4_coredump_buffer_iommu (adres urzadzenia wyrownany do 64 MB),
 *     +0x6b8 mp4_coredump_buffer_va (adres w pamieci jadra),
 *   - wskaznik struktury sterownika lezy w globalnej komorce 0xffffffffc4a4eb58,
 *     czyli pod offsetem 0x3DEEB58 od bazy obrazu (OFF_IFACE_A, ta sama stala co
 *     w tools/a53layout/a53layout.c).
 *
 * PRZESUNIECIE KASLR (bez zalozenia stalego adresu):
 * adresy wyzej pochodza z jednego rozruchu. Baza obrazu w danym rozruchu jest inna,
 * wiec bierzemy baze z tego rozruchu (KERNEL_ADDRESS_TEXT_BASE z SDK, ktore ja czyta
 * z parametrow zaladowania jadra) i liczymy
 *     przesuniecie = baza_tego_rozruchu - 0xffffffffc0c60000
 * a potem stosujemy je do KAZDEGO adresu z zestawu:
 *     globalna zmienna ze wskaznikiem sterownika = baza + (0xffffffffc4a4eb58 - baza_zrzutu)
 *     globalna struktura mapowania             = baza + (0xffffffffc31c0e70 - baza_zrzutu)
 * W dwoch logach z roznych rozruchow ta sama globalna wystapila pod roznymi adresami
 * (artifacts/softc2-2026-10-15.txt: 0xffffffff8dffeb58, artifacts/iommu-2026-10-15b.txt:
 * 0xffffffffd7ddeb58), wiec stala jest wylacznie offset, a nie adres.
 * Przesuniecie jest POTWIERDZANE przed uzyciem, trzema niezaleznymi bramkami:
 *   1. pod baza + 0x3DEEB58 lezy wskaznik jadra, ktorego pole +0x6a8 wynosi dokladnie
 *      0x200000 (znany rozmiar bufora coredump sterownika MP4),
 *   2. pola globalnej struktury mapowania sa spojne: adres urzadzenia wyrownany do
 *      64 MB i niezerowy, flagi 0 albo 0x50000000,
 *   3. 16 bajtow kodu pod baza + 0x10 zgadza sie co do bajtu ze zrzutem.
 * Gdy zadna nie przechodzi, payload NIE czyta zadnego adresu z tego wyliczenia i
 * konczy z kodem 4. Dzieki bramce 3 payload dziala takze wtedy, gdy sterownik MP4
 * nie jest jeszcze podlaczony: wskaznik i adres bufora sa wtedy zerowe, payload to
 * wypisuje i czeka na nie w petli obserwacji.
 *
 * CO ROBI, KROK PO KROKU:
 *   1. wylicza cr3 i podstawe mapy bezposredniej tak samo jak tools/softc2,
 *   2. wylicza przesuniecie KASLR i wypisuje je razem z obiema bazami,
 *   3. wypisuje globalna zmienna z 0x3DEEB58 oraz jej wskaznik struktury sterownika,
 *   4. wypisuje pola globalnej struktury mapowania (+0x08, +0x10, +0x18) i pola
 *      struktury sterownika (+0x6a8, +0x6b0, +0x6b8, +0x378, +0x380, +0x388,
 *      +0x390, +0x440), kazde z offsetem i nazwa tam, gdzie ja znamy,
 *   5. wypisuje pierwsze 64 bajty OBU buforow wraz z ocena, czy to dane, czy same
 *      zera albo same ff,
 *   6. obserwuje oba bufory przez 600 s, co 2 s, i loguje WYLACZNIE zmiany pierwszych
 *      64 bajtow; przy kazdej zmianie dopisuje 4096 bajtow bufora do /data/pprbuf.bin
 *      z naglowkiem 8 B numeru porcji, 8 B adresu, 8 B czasu w ms od startu i 4 B
 *      numeru bufora,
 *   7. na koncu wypisuje podsumowanie: ile zmian, ile porcji, jakie adresy wystapily.
 *
 * BEZPIECZENSTWO ODCZYTU:
 *   - kazdy odczyt pamieci jadra idzie po przejsciu po tablicach stron (bramka
 *     "readable" z tools/softc2, z warunkiem PWT i PCD, bo czytamy pamiec jadra,
 *     a nie rejestry urzadzen),
 *   - odczyty dziela sie na granicach stron, zeby jedno wywolanie nie wyszlo poza
 *     sprawdzona strone,
 *   - pole zerowe albo nieprzechodzace bramki jest wypisywane i NIE jest czytane,
 *   - budzet odczytu danych to 256 kB na caly przebieg obserwacji, z rezerwa na
 *     ogladanie obu buforow do konca (czyli liczba porcji 4096 B jest ograniczona
 *     do 52 i limit jest wypisany w logu); wpisy tablic stron licza sie osobno.
 *
 * Wymaga kstuff.
 *
 * Wynik: /data/pprbuf.txt oraz /data/pprbuf.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>

#define SYSCORE_AUTH_ID 0x4800000000000007ULL

#define OUT_LOG "/data/pprbuf.txt"
#define OUT_BIN "/data/pprbuf.bin"

/* --- Adresy i offsety ze zrzutu jadra 13.60 (jedno miejsce prawdy) --- */
#define REF_TEXT_BASE     0xffffffffc0c60000ULL  /* baza obrazu kodu w zrzucie */
#define REF_DATA_BASE     0xffffffffc1920000ULL  /* baza danych w zrzucie */
#define REF_GLOBAL_IFACE  0xffffffffc4a4eb58ULL  /* wskaznik struktury sterownika MP4 */
#define REF_GLOBAL_STRUCT 0xffffffffc31c0e70ULL  /* globalna struktura mapowania MP4 */

/* Offsety wzgledem bazy obrazu. Liczy je kompilator, zeby nie bylo pomylek z recznym
 * odejmowaniem. OFF_GLOBAL_IFACE to ta sama stala co OFF_IFACE_A w tools/a53layout. */
#define OFF_GLOBAL_IFACE  (REF_GLOBAL_IFACE - REF_TEXT_BASE)
#define OFF_GLOBAL_STRUCT (REF_GLOBAL_STRUCT - REF_TEXT_BASE)
#define OFF_BAZ            0xcc0000ULL           /* dane minus kod w zrzucie */

/* --- Pola struktury sterownika MP4 (offsety z deasemblacji) --- */
#define SOFTC_CPDUMP_BUF_VA     0x378ULL  /* bufor coredump w pamieci jadra */
#define SOFTC_CPDUMP_BUF_IOMMU  0x380ULL  /* adres urzadzenia tego bufora */
#define SOFTC_CPDUMP_SIZE_ALIGN 0x388ULL  /* rozmiar po wyrownaniu */
#define SOFTC_CPDUMP_SIZE       0x390ULL  /* rozmiar bufora */
#define SOFTC_DEV_A53IO         0x440ULL  /* adres urzadzenia sciezki A53IO/MP4 */
#define SOFTC_BUF_SIZE          0x6a8ULL  /* mp4_coredump_buffer_size */
#define SOFTC_BUF_IOMMU         0x6b0ULL  /* mp4_coredump_buffer_iommu */
#define SOFTC_BUF_VA            0x6b8ULL  /* mp4_coredump_buffer_va */

/* Pola globalnej struktury mapowania. */
#define STRUCT_BUF   0x08ULL  /* adres bufora w pamieci jadra: BUFOR 1 */
#define STRUCT_DEV   0x10ULL  /* adres urzadzenia */
#define STRUCT_FLAGS 0x18ULL  /* flagi (0x50000000 albo 0) */

/* Znane wartosci kontrolne z deasemblacji i z logow. */
#define BUF_SIZE_ZNAMY   0x200000ULL    /* mp4_coredump_buffer_size w attachu mp40 */
#define FLAGI_MAPOWANIA  0x50000000ULL  /* flagi z mp4_map_iommu_discont */
#define WYROWNANIE_64M   0x3ffffffULL   /* maszyna adresu urzadzenia (64 MB) */

/* --- Geometria stron --- */
#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL
#define STRONA     0x1000U

/* --- Obserwacja --- */
#define OKNO          64U               /* ile bajtow porownujemy i logujemy */
#define PORCJA        4096U             /* ile bajtow dopisujemy do pliku przy zmianie */
#define NAGLOWEK      28U               /* 8 + 8 + 8 + 4 bajty naglowka porcji */
#define PRZEBIEGI     300               /* 300 przebiegow po 2 s to 600 s */
#define PRZERWA_US    2000000U          /* 2 s miedzy przebiegami */
#define LIMIT_PRZERWY 3                 /* ile razy z rzedu blad odczytu logujemy */

/* Budzet odczytu danych na caly przebieg obserwacji. Rezerwa na przebieg to dwa
 * wskazniki (2 x 8 B) i dwa okna (2 x 64 B) z zapasem; dzieki niej porcje nie zjedza
 * budzetu potrzebnego na ogladanie obu buforow do konca. */
#define BUDZET_BAJTOW        (256U * 1024U)
#define REZERWA_NA_PRZEBIEG  160U
#define LIMIT_ADRESOW        8           /* ile roznych adresow pamietamy w podsumowaniu */

/* Bajty kodu w zrzucie pod baza + 0x10, uzywane jako odcisk przesuniecia. */
static const unsigned char ODCISK[16] = {
    0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec,
    0x18, 0x48, 0x8d, 0x1d, 0xf0, 0xc2, 0x91, 0x03,
};

typedef struct {
    int ktory;                    /* 1 albo 2 */
    const char *opis;
    uint64_t pole_va;             /* adres pola ze wskaznikiem na bufor, 0 = nie znamy */
    uint64_t adres;               /* adres bufora, 0 = brak */
    uint64_t odrzucone;           /* ostatnia odrzucona wartosc pola, zeby nie logowac w kolo */
    unsigned char okno[OKNO];     /* ostatnio widziane okno */
    int mam_okno;
    int blad;                     /* trwa seria nieudanych odczytow */
    int blad_ile;
    unsigned long zmian;
    uint64_t adresy[LIMIT_ADRESOW];
    unsigned long na_adresie[LIMIT_ADRESOW];
    int ile_adresow;
    unsigned long inne_adresy;
} bufor_t;

static FILE *g_log;
static FILE *g_bin;
static unsigned long g_dmap;
static unsigned long g_cr3;
static uint64_t g_start_ms;
static int g_czas_ok = 1;

static size_t g_odczytane;
static size_t g_limit_porcji;
static unsigned long g_porcje;
static int g_porcje_stop;
static int g_budzet_stop;

/* Globalna ze wskaznikiem sterownika MP4 i sam wskaznik, potwierdzony bramka.
 * Sterownik moze byc podlaczony dopiero w trakcie obserwacji, dlatego wskaznik
 * jest sprawdzany takze w petli. */
static uint64_t g_adres_globalnej;
static uint64_t g_softc;
static int g_softc_czekam_log;

static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
    klog_printf("[pprbuf] %s", buf);
    if (g_log) {
        fputs(buf, g_log);
        fflush(g_log);
        fsync(fileno(g_log));
    }
}

/* --- Mapa jadra, bez zmian wobec tools/softc2 --- */

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

/* Przejscie po tablicach stron: obecna, rozmiar strony i flagi niebuforowane. */
static int chodz(uint64_t va, int *pcd, int *pwt) {
    static const int poziomy[4] = { 39, 30, 21, 12 };
    uint64_t tab = (uint64_t) g_cr3 & PG_FRAME;
    for (int k = 0; k < 4; k++) {
        int i = poziomy[k];
        uint64_t idx = (va >> i) & 0x1FFULL;
        uint64_t wpis = (uint64_t) kernel_getlong((unsigned long) (g_dmap + tab + idx * 8));
        if (!(wpis & X86_PG_V)) return -1;
        if ((wpis & X86_PG_PS) || k == 3) {
            if (pcd) *pcd = (wpis & X86_PG_PCD) ? 1 : 0;
            if (pwt) *pwt = (wpis & X86_PG_PWT) ? 1 : 0;
            return 0;
        }
        tab = wpis & PG_FRAME;
    }
    return -1;
}

/* Bramka z tools/softc2: strona obecna i nie jest oknem urzadzenia. */
static int readable(uint64_t va) {
    int pcd = 0, pwt = 0;
    if (chodz(va, &pcd, &pwt)) return 0;
    return !(pcd || pwt);
}

/* Odczyt danych z twardym budzetem. Zwraca 0, gdy sie udalo. */
static int safe_read(uint64_t va, void *dst, size_t n) {
    if (g_odczytane + n > BUDZET_BAJTOW) {
        g_budzet_stop = 1;
        return -1;
    }
    if (!readable(va)) return -1;
    if (kernel_copyout(va, dst, n)) return -1;
    g_odczytane += n;
    return 0;
}

/* Odczyt ciagly, ktory nie przechodzi granicy strony w jednym wywolaniu. */
static int safe_read_span(uint64_t va, void *dst, size_t n, size_t *ile_out) {
    unsigned char *p = (unsigned char *) dst;
    size_t zrobione = 0;
    while (zrobione < n) {
        size_t do_konca = STRONA - (size_t) ((va + zrobione) & (STRONA - 1));
        size_t porcja = n - zrobione;
        if (porcja > do_konca) porcja = do_konca;
        if (safe_read(va + zrobione, p + zrobione, porcja)) break;
        zrobione += porcja;
    }
    if (ile_out) *ile_out = zrobione;
    return (zrobione == n) ? 0 : -1;
}

static int safe_read64(uint64_t va, uint64_t *out) {
    return safe_read(va, out, sizeof(*out));
}

static uint64_t swap_auth(uint64_t auth_id) {
    pid_t pid = getpid();
    uint64_t original = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, auth_id);
    return original;
}

static int wskaznik_jadra(uint64_t v) {
    return v >= 0xffff800000000000ULL;
}

/* --- Czas od startu payloadu --- */

static uint64_t pobierz_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        if (g_czas_ok) {
            g_czas_ok = 0;
            log_line("UWAGA: clock_gettime nie dziala, czasy beda zerowe\n");
        }
        return 0;
    }
    return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) (ts.tv_nsec / 1000000L);
}

static uint64_t ms_od_startu(void) {
    return pobierz_ms() - g_start_ms;
}

/* --- Opisy pol --- */

static const char *nazwa_softc(uint64_t off) {
    switch (off) {
        case SOFTC_CPDUMP_BUF_VA:     return "  bufor coredump w pamieci jadra";
        case SOFTC_CPDUMP_BUF_IOMMU:  return "  adres urzadzenia tego bufora";
        case SOFTC_CPDUMP_SIZE_ALIGN: return "  rozmiar po wyrownaniu";
        case SOFTC_CPDUMP_SIZE:       return "  rozmiar bufora coredump";
        case SOFTC_DEV_A53IO:         return "  adres urzadzenia sciezki A53IO/MP4";
        case SOFTC_BUF_SIZE:          return "  mp4_coredump_buffer_size";
        case SOFTC_BUF_IOMMU:         return "  mp4_coredump_buffer_iommu (64 MB)";
        case SOFTC_BUF_VA:            return "  mp4_coredump_buffer_va";
        default:                      return "";
    }
}

static const char *nazwa_struktury(uint64_t off) {
    switch (off) {
        case STRUCT_BUF:   return "  adres bufora w pamieci jadra (BUFOR 1)";
        case STRUCT_DEV:   return "  adres urzadzenia";
        case STRUCT_FLAGS: return "  flagi";
        default:           return "";
    }
}

/* Slowo 64-bitowe pod adresem, z offsetem i nazwa pola. */
static void wypisz_slowo(uint64_t baza, uint64_t off, int struktura) {
    uint64_t v = 0;
    const char *opis = struktura ? nazwa_struktury(off) : nazwa_softc(off);
    if (safe_read64(baza + off, &v)) {
        log_line("  0x%03llx: blad odczytu (strona nie przechodzi bramki)%s\n",
                 (unsigned long long) off, opis);
        return;
    }
    log_line("  0x%03llx: 0x%016llx%s\n",
             (unsigned long long) off, (unsigned long long) v, opis);
}

/* --- Ocena zawartosci --- */

static void wypisz_bajty(const unsigned char *b, size_t n) {
    static const char cyfry[] = "0123456789abcdef";
    char linia[3 * 32 + 1];
    for (size_t i = 0; i < n; i += 32) {
        size_t ile = n - i;
        if (ile > 32) ile = 32;
        size_t p = 0;
        for (size_t k = 0; k < ile; k++) {
            linia[p++] = cyfry[(b[i + k] >> 4) & 0xf];
            linia[p++] = cyfry[b[i + k] & 0xf];
            linia[p++] = ' ';
        }
        linia[p] = '\0';
        log_line("    +0x%02x: %s\n", (unsigned) i, linia);
    }
}

/* Czy to dane, czy same zera albo same ff. */
static void ocena_danych(const unsigned char *b, size_t n) {
    unsigned char widziane[256];
    size_t zera = 0, ff = 0;
    int roznych = 0;
    memset(widziane, 0, sizeof(widziane));
    for (size_t i = 0; i < n; i++) {
        if (!widziane[b[i]]) { widziane[b[i]] = 1; roznych++; }
        if (b[i] == 0) zera++;
        else if (b[i] == 0xff) ff++;
    }
    if (zera == n) {
        log_line("    ocena: SAME ZERA (%zu z %zu bajtow), to nie wyglada na dane\n",
                 zera, n);
    } else if (ff == n) {
        log_line("    ocena: SAME FF (%zu z %zu bajtow), to nie wyglada na dane\n",
                 ff, n);
    } else {
        log_line("    ocena: DANE: niezerowych %zu z %zu, zer %zu, ff %zu, "
                 "roznych wartosci %d\n", n - zera, n, zera, ff, roznych);
    }
}

/* Czy pole nadaje sie na adres bufora. Zwraca 0, gdy tak. Opis trafia do wspolnego
 * bufora, bo w logu uzywamy go od razu po wywolaniu (jedno wywolanie naraz). */
static char g_powod[192];

static int ocen_adres(uint64_t a, const char **powod) {
    int pcd = 0, pwt = 0;
    if (a == 0) { *powod = "pole zerowe, nie czytam"; return -1; }
    if (!wskaznik_jadra(a)) { *powod = "to nie adres jadra, nie czytam"; return -1; }
    if (chodz(a, &pcd, &pwt)) {
        *powod = "strona poczatku okna nieobecna w tablicach stron, nie czytam";
        return -1;
    }
    if (pcd || pwt) {
        snprintf(g_powod, sizeof(g_powod), "strona poczatku okna jest niebuforowana "
                 "(PCD=%d PWT=%d), bramka ja odrzuca, nie czytam", pcd, pwt);
        *powod = g_powod;
        return -1;
    }
    if (chodz(a + OKNO - 1, &pcd, &pwt) || pcd || pwt) {
        *powod = "strona konca okna nie przechodzi bramki, nie czytam";
        return -1;
    }
    *powod = "wskaznik przechodzi bramke";
    return 0;
}

/* --- Porcje do pliku --- */

static void zapisz_porcje(bufor_t *b, uint64_t ms) {
    static unsigned char dane[PORCJA];
    unsigned char naglowek[NAGLOWEK];
    uint64_t nr, adres, czas;
    uint32_t ktory;
    size_t ile = 0;

    if (!g_bin) return;
    if (g_porcje >= g_limit_porcji) {
        if (!g_porcje_stop) {
            g_porcje_stop = 1;
            log_line("  limit porcji (%lu) osiagniety, dalsze zmiany bez zapisu do %s\n",
                     g_porcje, OUT_BIN);
        }
        return;
    }
    if (safe_read_span(b->adres, dane, PORCJA, &ile) || ile != PORCJA) {
        log_line("  bufor %d: porcja %u B nieczytelna (%zu B), nie zapisuje\n",
                 b->ktory, (unsigned) PORCJA, ile);
        return;
    }

    nr = (uint64_t) g_porcje;
    adres = b->adres;
    czas = ms;
    ktory = (uint32_t) b->ktory;
    memcpy(naglowek + 0, &nr, 8);
    memcpy(naglowek + 8, &adres, 8);
    memcpy(naglowek + 16, &czas, 8);
    memcpy(naglowek + 24, &ktory, 4);

    if (fwrite(naglowek, 1, sizeof(naglowek), g_bin) != sizeof(naglowek) ||
        fwrite(dane, 1, PORCJA, g_bin) != PORCJA) {
        log_line("  BLAD: zapis porcji %llu nieudany\n", (unsigned long long) nr);
        return;
    }
    fflush(g_bin);
    fsync(fileno(g_bin));
    g_porcje++;
    log_line("  porcja %llu zapisana: bufor %d, adres 0x%llx, %llu ms, %u B danych\n",
             (unsigned long long) nr, b->ktory, (unsigned long long) adres,
             (unsigned long long) czas, (unsigned) PORCJA);
}

/* --- Obserwacja --- */

/* Rejestruje adres w podsumowaniu, bez zliczania zmiany. */
static void zauwaz_adres(bufor_t *b, uint64_t a) {
    for (int i = 0; i < b->ile_adresow; i++) {
        if (b->adresy[i] == a) return;
    }
    if (b->ile_adresow < LIMIT_ADRESOW) {
        b->adresy[b->ile_adresow] = a;
        b->na_adresie[b->ile_adresow] = 0;
        b->ile_adresow++;
        return;
    }
    b->inne_adresy++;
}

/* Zlicza zmiane na aktualnym adresie bufora. */
static void policz_zmiane(bufor_t *b) {
    for (int i = 0; i < b->ile_adresow; i++) {
        if (b->adresy[i] == b->adres) { b->na_adresie[i]++; return; }
    }
}

/* Czyta pole ze wskaznikiem i przejmuje nowy adres bufora, gdy sie pojawil. */
static void odswiez_wskaznik(bufor_t *b, uint64_t ms) {
    uint64_t v = 0;
    const char *powod = "";
    if (!b->pole_va) return;
    if (safe_read64(b->pole_va, &v)) return;

    if (v == b->adres) return;

    if (v == 0) {
        if (b->adres) {
            log_line("  bufor %d: pole 0x%llx wyzerowane (bylo 0x%llx), %llu ms\n",
                     b->ktory, (unsigned long long) b->pole_va,
                     (unsigned long long) b->adres, (unsigned long long) ms);
            b->adres = 0;
            b->mam_okno = 0;
        }
        b->odrzucone = 0;
        return;
    }
    if (ocen_adres(v, &powod)) {
        if (v != b->odrzucone) {
            b->odrzucone = v;
            log_line("  bufor %d: nowa wartosc pola 0x%llx odrzucona (%s), %llu ms\n",
                     b->ktory, (unsigned long long) v, powod, (unsigned long long) ms);
        }
        return;
    }
    b->odrzucone = 0;
    log_line("  bufor %d: NOWY ADRES 0x%llx (poprzednio 0x%llx), %llu ms\n",
             b->ktory, (unsigned long long) v, (unsigned long long) b->adres,
             (unsigned long long) ms);
    b->adres = v;
    b->mam_okno = 0;   /* pierwszy odczyt nowego bufora liczy sie jako zmiana */
    b->blad = 0;
    b->blad_ile = 0;
    zauwaz_adres(b, v);
}

/* Czy wskaznik wyglada na strukture sterownika MP4: wskaznik jadra, strona przechodzi
 * bramke, a pole +0x6a8 (mp4_coredump_buffer_size) wynosi dokladnie 0x200000. */
static int ocen_softc(uint64_t p) {
    uint64_t rozmiar = 0;
    if (!wskaznik_jadra(p)) return 0;
    if (!readable(p)) return 0;
    if (!readable(p + SOFTC_BUF_SIZE)) return 0;
    if (safe_read64(p + SOFTC_BUF_SIZE, &rozmiar)) return 0;
    return rozmiar == BUF_SIZE_ZNAMY;
}

/* Sterownik MP4 moze byc podlaczony dopiero w trakcie obserwacji, a bez niego nie ma
 * bufora 2. Dlatego wskaznik z globalnej jest sprawdzany w kazdym przebiegu, az sie
 * pojawi; wtedy bufor 2 dostaje pole +0x6b8 tego sterownika. */
static void odswiez_softc(bufor_t *b2, uint64_t ms) {
    uint64_t p = 0;
    if (g_softc) return;
    if (safe_read64(g_adres_globalnej, &p)) return;
    if (p == 0) {
        if (!g_softc_czekam_log) {
            g_softc_czekam_log = 1;
            log_line("  sterownik MP4 jeszcze nie podlaczony (globalna zerowa), %llu ms\n",
                     (unsigned long long) ms);
        }
        return;
    }
    if (!ocen_softc(p)) {
        if (!g_softc_czekam_log) {
            g_softc_czekam_log = 1;
            log_line("  globalna 0x%llx = 0x%llx, ale to nie potwierdzony sterownik MP4 "
                     "(pole +0x6a8 nie wynosi 0x%llx), czekam, %llu ms\n",
                     (unsigned long long) g_adres_globalnej, (unsigned long long) p,
                     (unsigned long long) BUF_SIZE_ZNAMY, (unsigned long long) ms);
        }
        return;
    }
    g_softc = p;
    g_softc_czekam_log = 0;
    log_line("  STEROWNIK MP4 PODLACZONY w trakcie obserwacji: 0x%llx, %llu ms; "
             "bufor 2 to teraz pole +0x%llx\n", (unsigned long long) p,
             (unsigned long long) ms, (unsigned long long) SOFTC_BUF_VA);
    b2->pole_va = g_softc + SOFTC_BUF_VA;
}

static void zbadaj_bufor(bufor_t *b, uint64_t ms) {
    unsigned char okno[OKNO];
    size_t ile = 0;
    int nowy;

    if (!b->adres) return;
    if (safe_read_span(b->adres, okno, OKNO, &ile) || ile != OKNO) {
        if (b->blad_ile < LIMIT_PRZERWY) {
            log_line("  bufor %d (0x%llx): odczyt okna nieudany (%zu z %u B), %llu ms\n",
                     b->ktory, (unsigned long long) b->adres, ile, (unsigned) OKNO,
                     (unsigned long long) ms);
        } else if (b->blad_ile == LIMIT_PRZERWY) {
            log_line("  bufor %d (0x%llx): dalsze bledy odczytu pomijam w logu\n",
                     b->ktory, (unsigned long long) b->adres);
        }
        b->blad = 1;
        b->blad_ile++;
        return;
    }
    if (b->blad) {
        b->blad = 0;
        b->blad_ile = 0;
        log_line("  bufor %d (0x%llx): odczyt znow dziala, %llu ms\n",
                 b->ktory, (unsigned long long) b->adres, (unsigned long long) ms);
    }

    nowy = !b->mam_okno;
    if (!nowy && memcmp(okno, b->okno, OKNO) == 0) return;

    memcpy(b->okno, okno, OKNO);
    b->mam_okno = 1;
    b->zmian++;
    zauwaz_adres(b, b->adres);
    policz_zmiane(b);

    log_line("ZMIANA bufor %d (0x%llx), zmiana nr %lu, %llu ms%s\n",
             b->ktory, (unsigned long long) b->adres, b->zmian,
             (unsigned long long) ms, nowy ? " (pierwszy odczyt tego bufora)" : "");
    wypisz_bajty(okno, OKNO);
    ocena_danych(okno, OKNO);
    zapisz_porcje(b, ms);
}

/* Wiersz podsumowania z adresami danego bufora. */
static void wypisz_adresy(const bufor_t *b, const char *opis) {
    char linia[384];
    int p = snprintf(linia, sizeof(linia), "%s:", opis);
    for (int i = 0; i < b->ile_adresow; i++) {
        if (p < 0 || (size_t) p >= sizeof(linia)) break;
        p += snprintf(linia + p, sizeof(linia) - (size_t) p, " 0x%llx (%lu zmian)",
                      (unsigned long long) b->adresy[i], b->na_adresie[i]);
    }
    if (p >= 0 && (size_t) p < sizeof(linia) && b->inne_adresy) {
        p += snprintf(linia + p, sizeof(linia) - (size_t) p,
                      " oraz %lu adresow spoza limitu", b->inne_adresy);
    }
    if (p >= 0 && (size_t) p < sizeof(linia) && b->ile_adresow == 0 &&
        b->inne_adresy == 0) {
        p += snprintf(linia + p, sizeof(linia) - (size_t) p,
                      " brak (zaden adres nie przeszedl bramki)");
    }
    if (p >= 0 && (size_t) p < sizeof(linia)) {
        snprintf(linia + p, sizeof(linia) - (size_t) p, " | ostatni 0x%llx",
                 (unsigned long long) b->adres);
    }
    linia[sizeof(linia) - 1] = '\0';
    log_line("%s\n", linia);
}

/* Pierwszy odczyt w punkcie 4 zadania: wypis i ustawienie punktu odniesienia. */
static void pierwszy_odczyt(bufor_t *b) {
    unsigned char okno[OKNO];
    size_t ile = 0;
    const char *powod = "";
    if (!b->adres) {
        log_line("  bufor %d (%s): brak adresu, nie czytam\n", b->ktory, b->opis);
        return;
    }
    if (ocen_adres(b->adres, &powod)) {
        log_line("  bufor %d (0x%llx): %s\n", b->ktory,
                 (unsigned long long) b->adres, powod);
        return;
    }
    log_line("  bufor %d (%s): adres 0x%llx, %s\n", b->ktory, b->opis,
             (unsigned long long) b->adres, powod);
    if (safe_read_span(b->adres, okno, OKNO, &ile) || ile != OKNO) {
        log_line("    odczyt okna nieudany (%zu z %u bajtow)\n", ile, (unsigned) OKNO);
        return;
    }
    wypisz_bajty(okno, OKNO);
    ocena_danych(okno, OKNO);
    memcpy(b->okno, okno, OKNO);
    b->mam_okno = 1;
}

int main(void) {
    bufor_t b1, b2;
    uint64_t base, base_danych, przesuniecie;
    uint64_t adres_globalnej, adres_struktury;
    uint64_t softc = 0, pole_struktury = 0;
    uint64_t g_bufor = 0, g_dev = 0, g_flagi = 0;
    uint64_t pole_b2 = 0;
    int bramka_softc = 0, bramka_struktury = 0, bramka_struktury_ok = 0;
    int bramka_odcisku = 0;
    uint64_t start, koniec;
    const char *powod = "";
    long long sl;

    memset(&b1, 0, sizeof(b1));
    memset(&b2, 0, sizeof(b2));

    g_start_ms = pobierz_ms();
    g_log = fopen(OUT_LOG, "w");
    log_line("pprbuf start (tylko odczyt, bez ioctl i bez wezlow urzadzen)\n");

    if (init_map() != 0) {
        log_line("BLAD: nie udalo sie wyliczyc mapy jadra\n");
        if (g_log) fclose(g_log);
        return 2;
    }
    log_line("mapa bezposrednia 0x%lx, cr3 0x%lx\n", g_dmap, g_cr3);
    log_line("kernel_get_fw_version(): 0x%08x\n", kernel_get_fw_version());

    /* --- 1. Przesuniecie KASLR --- */
    base = (uint64_t) KERNEL_ADDRESS_TEXT_BASE;
    base_danych = (uint64_t) KERNEL_ADDRESS_DATA_BASE;
    przesuniecie = base - REF_TEXT_BASE;
    sl = (long long) przesuniecie;

    log_line("--- przesuniecie KASLR ---\n");
    log_line("baza obrazu w tym rozruchu: kod 0x%016llx, dane 0x%016llx "
             "(roznica 0x%llx, w zrzucie 0x%llx)\n",
             (unsigned long long) base, (unsigned long long) base_danych,
             (unsigned long long) (base_danych - base),
             (unsigned long long) OFF_BAZ);
    log_line("baza obrazu w zrzucie: kod 0x%016llx, dane 0x%016llx\n",
             (unsigned long long) REF_TEXT_BASE, (unsigned long long) REF_DATA_BASE);
    log_line("przesuniecie = baza kodu - baza zrzutu = 0x%016llx (%lld)\n",
             (unsigned long long) przesuniecie, sl);
    if ((base_danych - base) != OFF_BAZ) {
        log_line("UWAGA: roznica baz w tym rozruchu nie zgadza sie ze zrzutem\n");
    }

    adres_globalnej = base + OFF_GLOBAL_IFACE;
    adres_struktury = base + OFF_GLOBAL_STRUCT;
    g_adres_globalnej = adres_globalnej;
    log_line("offset globalnej ze wskaznikiem sterownika MP4: 0x%llx "
             "(0x%016llx - 0x%016llx)\n",
             (unsigned long long) OFF_GLOBAL_IFACE,
             (unsigned long long) REF_GLOBAL_IFACE, (unsigned long long) REF_TEXT_BASE);
    log_line("offset globalnej struktury mapowania: 0x%llx "
             "(0x%016llx - 0x%016llx)\n",
             (unsigned long long) OFF_GLOBAL_STRUCT,
             (unsigned long long) REF_GLOBAL_STRUCT, (unsigned long long) REF_TEXT_BASE);
    log_line("po przesunieciu: globalna sterownika 0x%016llx, struktura mapowania "
             "0x%016llx\n", (unsigned long long) adres_globalnej,
             (unsigned long long) adres_struktury);

    /* --- 2. Bramka przesuniecia i wskaznik struktury sterownika --- */
    uint64_t oryginal = swap_auth(SYSCORE_AUTH_ID);

    log_line("--- bramka przesuniecia ---\n");
    {
        unsigned char odcisk[16];
        size_t ile = 0;
        if (safe_read_span(base + 0x10, odcisk, sizeof(odcisk), &ile) == 0) {
            bramka_odcisku = (memcmp(odcisk, ODCISK, sizeof(ODCISK)) == 0);
            log_line("odcisk kodu pod baza + 0x10: %s\n",
                     bramka_odcisku ? "zgodny ze zrzutem" : "NIE zgadza sie ze zrzutem");
        } else {
            log_line("odcisku kodu pod baza + 0x10 nie udalo sie odczytac (%zu B)\n", ile);
        }
    }

    if (safe_read64(adres_globalnej, &pole_struktury)) {
        log_line("globalna 0x%016llx: odczyt nieudany (strona nie przechodzi bramki)\n",
                 (unsigned long long) adres_globalnej);
    } else if (pole_struktury == 0) {
        log_line("globalna 0x%016llx: pole zerowe, sterownik MP4 jeszcze nie podlaczony\n",
                 (unsigned long long) adres_globalnej);
    } else {
        log_line("globalna 0x%016llx (baza + 0x%llx) = wskaznik struktury sterownika "
                 "MP4: 0x%016llx\n", (unsigned long long) adres_globalnej,
                 (unsigned long long) OFF_GLOBAL_IFACE,
                 (unsigned long long) pole_struktury);
        if (ocen_softc(pole_struktury)) {
            uint64_t rozmiar = 0;
            softc = pole_struktury;
            g_softc = pole_struktury;
            bramka_softc = 1;
            (void) safe_read64(softc + SOFTC_BUF_SIZE, &rozmiar);
            log_line("  sterownik + 0x%llx (mp4_coredump_buffer_size) = 0x%llx, "
                     "zgodne z deasemblacja\n", (unsigned long long) SOFTC_BUF_SIZE,
                     (unsigned long long) rozmiar);
        } else {
            log_line("  wskaznik NIEPOTWIERDZONY (pole +0x6a8 nie wynosi 0x%llx albo "
                     "strona nie przechodzi bramki), pol sterownika nie czytam\n",
                     (unsigned long long) BUF_SIZE_ZNAMY);
        }
    }

    /* Druga bramka, niezalezna od pierwszej: pola globalnej struktury mapowania. */
    if (safe_read64(adres_struktury + STRUCT_BUF, &g_bufor) == 0 &&
        safe_read64(adres_struktury + STRUCT_DEV, &g_dev) == 0 &&
        safe_read64(adres_struktury + STRUCT_FLAGS, &g_flagi) == 0) {
        bramka_struktury_ok = 1;
        if (g_dev != 0 && (g_dev & WYROWNANIE_64M) == 0 && g_dev <= 0xffffffffULL &&
            (g_flagi == 0 || g_flagi == FLAGI_MAPOWANIA)) {
            bramka_struktury = 1;
        }
    }

    log_line("bramka 1 (wskaznik sterownika + pole 0x6a8 = 0x%llx): %s\n",
             (unsigned long long) BUF_SIZE_ZNAMY,
             bramka_softc ? "PRZESZLA" : "nie przeszla");
    log_line("bramka 2 (struktura mapowania: adres urzadzenia i flagi): %s\n",
             bramka_struktury ? "PRZESZLA" : "nie przeszla");
    log_line("bramka 3 (odcisk kodu pod baza + 0x10): %s\n",
             bramka_odcisku ? "PRZESZLA" : "nie przeszla");
    if (!bramka_softc && !bramka_struktury && !bramka_odcisku) {
        log_line("BLAD: przesuniecie NIEPOTWIERDZONE. Nie czytam zadnego adresu "
                 "z tego wyliczenia. Koncze.\n");
        swap_auth(oryginal);
        if (g_log) fclose(g_log);
        return 4;
    }
    log_line("przesuniecie POTWIERDZONE, uzywam wyliczonych adresow\n");

    /* --- 3. Pola struktury sterownika MP4 --- */
    if (softc) {
        log_line("--- struktura sterownika MP4 0x%016llx ---\n",
                 (unsigned long long) softc);
        wypisz_slowo(softc, SOFTC_BUF_SIZE, 0);
        wypisz_slowo(softc, SOFTC_BUF_IOMMU, 0);
        wypisz_slowo(softc, SOFTC_BUF_VA, 0);
        wypisz_slowo(softc, SOFTC_CPDUMP_BUF_VA, 0);
        wypisz_slowo(softc, SOFTC_CPDUMP_BUF_IOMMU, 0);
        wypisz_slowo(softc, SOFTC_CPDUMP_SIZE_ALIGN, 0);
        wypisz_slowo(softc, SOFTC_CPDUMP_SIZE, 0);
        wypisz_slowo(softc, SOFTC_DEV_A53IO, 0);
        if (safe_read64(softc + SOFTC_BUF_VA, &pole_b2) == 0 && pole_b2) {
            b2.pole_va = softc + SOFTC_BUF_VA;
        } else {
            log_line("  pole 0x%llx (mp4_coredump_buffer_va) puste albo nieczytelne, "
                     "bufor 2 bez adresu\n", (unsigned long long) SOFTC_BUF_VA);
        }
    } else {
        log_line("--- struktura sterownika MP4: brak potwierdzonego wskaznika, pol nie "
                 "czytam (sprawdze to w kazdym przebiegu) ---\n");
    }

    log_line("--- globalna struktura mapowania 0x%016llx ---\n",
             (unsigned long long) adres_struktury);
    if (bramka_struktury_ok) {
        wypisz_slowo(adres_struktury, STRUCT_BUF, 1);
        wypisz_slowo(adres_struktury, STRUCT_DEV, 1);
        wypisz_slowo(adres_struktury, STRUCT_FLAGS, 1);
    } else {
        log_line("  pol nie udalo sie odczytac\n");
    }

    /* --- 4. Bufory i pierwszy odczyt --- */
    b1.ktory = 1;
    b1.opis = "globalna struktura mapowania + 0x08";
    b1.pole_va = adres_struktury + STRUCT_BUF;
    if (g_bufor == 0) {
        log_line("bufor 1: pole +0x08 struktury mapowania jest zerowe (mapowanie MP4 "
                 "jeszcze sie nie odbylo), bede sprawdzal to pole co 2 s\n");
    } else if (ocen_adres(g_bufor, &powod) == 0) {
        b1.adres = g_bufor;
        zauwaz_adres(&b1, g_bufor);
    } else {
        log_line("bufor 1: pole +0x08 = 0x%llx odrzucone (%s)\n",
                 (unsigned long long) g_bufor, powod);
    }

    b2.ktory = 2;
    b2.opis = "sterownik MP4 + 0x6b8";
    if (!b2.pole_va) {
        log_line("bufor 2: brak potwierdzonego sterownika, bede szukal wskaznika "
                 "i pola +0x6b8 w kazdym przebiegu\n");
    } else if (pole_b2 == 0) {
        log_line("bufor 2: pole +0x6b8 jest zerowe, bede sprawdzal to pole co 2 s\n");
    } else if (ocen_adres(pole_b2, &powod) == 0) {
        b2.adres = pole_b2;
        zauwaz_adres(&b2, pole_b2);
    } else {
        log_line("bufor 2: pole +0x6b8 = 0x%llx odrzucone (%s)\n",
                 (unsigned long long) pole_b2, powod);
    }

    log_line("--- pierwszy odczyt buforow ---\n");
    pierwszy_odczyt(&b1);
    pierwszy_odczyt(&b2);

    /* --- 5. Obserwacja --- */
    g_limit_porcji = 0;
    {
        size_t rezerwa = (size_t) PRZEBIEGI * REZERWA_NA_PRZEBIEG;
        if (BUDZET_BAJTOW > rezerwa) g_limit_porcji = (BUDZET_BAJTOW - rezerwa) / PORCJA;
    }
    g_bin = fopen(OUT_BIN, "wb");
    if (!g_bin) {
        log_line("UWAGA: nie moge zapisac %s, zmiany beda tylko w logu\n", OUT_BIN);
    }

    log_line("--- obserwacja ---\n");
    log_line("przebiegi: %d co %u ms, okno %u B, porcja %u B, budzet danych %u B, "
             "limit porcji %zu\n", PRZEBIEGI, (unsigned) (PRZERWA_US / 1000),
             (unsigned) OKNO, (unsigned) PORCJA, (unsigned) BUDZET_BAJTOW,
             g_limit_porcji);
    start = ms_od_startu();

    for (int przebieg = 0; przebieg < PRZEBIEGI; przebieg++) {
        uint64_t ms = ms_od_startu();
        odswiez_softc(&b2, ms);
        odswiez_wskaznik(&b1, ms);
        odswiez_wskaznik(&b2, ms);
        zbadaj_bufor(&b1, ms);
        zbadaj_bufor(&b2, ms);
        if (przebieg + 1 < PRZEBIEGI) usleep(PRZERWA_US);
    }

    koniec = ms_od_startu();

    /* --- 6. Podsumowanie --- */
    log_line("--- podsumowanie ---\n");
    log_line("czas obserwacji: %llu ms (od %llu do %llu ms od startu), przebiegi: %d\n",
             (unsigned long long) (koniec - start), (unsigned long long) start,
             (unsigned long long) koniec, PRZEBIEGI);
    log_line("zmiany: bufor 1: %lu, bufor 2: %lu, razem: %lu\n",
             b1.zmian, b2.zmian, b1.zmian + b2.zmian);
    log_line("porcje: zapisane %lu z limitu %zu, bajtow w pliku %llu "
             "(%u naglowek + %u danych na porcje)\n",
             g_porcje, g_limit_porcji,
             (unsigned long long) g_porcje * (NAGLOWEK + PORCJA),
             (unsigned) NAGLOWEK, (unsigned) PORCJA);
    if (g_porcje_stop) {
        log_line("  limit porcji zostal osiagniety, pozniejsze zmiany nie trafily do "
                 "pliku (budzet odczytu chroni ogladanie buforow do konca)\n");
    }
    wypisz_adresy(&b1, "adresy bufora 1 (globalna + 0x08)");
    wypisz_adresy(&b2, "adresy bufora 2 (sterownik + 0x6b8)");
    log_line("odczytane bajty danych: %zu z budzetu %u (wpisy tablic stron liczone "
             "osobno)\n", g_odczytane, (unsigned) BUDZET_BAJTOW);
    if (g_budzet_stop) {
        log_line("  budzet danych wyczerpany, czesc odczytow odbila sie od limitu\n");
    }
    log_line("softc 0x%llx, struktura mapowania 0x%llx, przesuniecie 0x%llx\n",
             (unsigned long long) (g_softc ? g_softc : softc),
             (unsigned long long) adres_struktury,
             (unsigned long long) przesuniecie);

    if (g_bin) {
        fflush(g_bin);
        fsync(fileno(g_bin));
        fclose(g_bin);
        g_bin = NULL;
    }
    swap_auth(oryginal);
    log_line("identyfikator przywrocony, koniec (nic nie zapisano do pamieci jadra)\n");
    if (g_log) fclose(g_log);
    return 0;
}
