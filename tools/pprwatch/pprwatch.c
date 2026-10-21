/*
 * pprwatch: gdzie procesor A53 zapisuje odszyfrowana zawartosc i co tam lezy.
 *
 * Cel: ustalic adres bufora docelowego silnika PPR i obserwowac jego zawartosc.
 *
 * WERSJA 1.2. Adres bufora po stronie gospodarza liczymy z REJESTROW OKNA urzadzenia
 * MP4, a nie z rejestru A53. Rejestr A53 jest nadal czytany i obserwowany, ale sluzy
 * tylko jako wskaznik etapu pracy procesora.
 *
 * DLACZEGO NIE Z REJESTRU A53. Rejestr pod adresem FIZYCZNYM 0x28068 procesora A53
 * trzyma adres w przestrzeni URZADZENIA, nie w pamieci gospodarza. Kod procesora
 * czyta go tak (z dekompilacji, notes/PPR-KOLEJNOSC-...):
 *   ldr  x8, [0x04E28068]
 *   ubfiz x0, x8, #16, #32          czyli (x8 & 0xFFFFFFFF) << 16
 *   orr  x22, x0, #0x1000000000000  znacznik bitu 48
 *   add  x6, x22, offset
 * USTALONE POMIAREM na tej konsoli: rejestr zawiera 0x0000000000006400, wiec kod
 * procesora liczy 0x64000000. Ten adres NIE jest zamapowany w mapie bezposredniej
 * jadra, bo ta mapa pokazuje pamiec fizyczna KONSOLI, czyli zupelnie inna pamiec niz
 * ta, ktora widzi procesor A53. Nie ma wiec zadnego cofania sie do mapy jadra po
 * adresy A53: mapa sluzy wylacznie do sprawdzenia i odczytu adresu GOSPODARZA
 * wyliczonego z rejestrow okna. Gdy odczyt rejestru transportem sie nie uda, payload
 * to zglasza i konczy prace bez liczenia adresu bufora.
 *
 * Transport A53 (wezel /dev/mp4/dump) czyta TYLKO pamiec SRAM procesora, adresy
 * od 0x0 do 0xBFFFF. Powyzej zwraca status 0x20 i zero przeslanych bajtow. Adresy
 * w pakiecie sa adresami FIZYCZNYMI procesora A53.
 *
 * REJESTRY OKNA. Adres bufora gospodarza jest programowany w rejestrach okna
 * urzadzenia MP4. Konwencja i jej dowody sa wypisane przy tablicy OKNO_OFFS oraz
 * przy funkcji okno_read32.
 *
 * Zaraz po odczycie rejestru payload robi kontrole drogi odczytu na znanym adresie
 * 0x28000 i wymaga ciagu 1b 00 01 00 10 00 01 00. Nieudana kontrola przerywa prace,
 * bo znaczy to, ze sama droga odczytu nie dziala.
 *
 * Sekwencja startu zrzutu (podmiana identyfikatora, revoke, otwarcie, IOCTL_START,
 * oczekiwanie, IOCTL_ALTER_STATE), budowa pakietu odczytu i szukanie danych po
 * naglowku wyniku sa przejete bez zmian z tools/a53layout/a53layout.c.
 *
 * BEZPIECZENSTWO. Konsola raz zrestartowala sie przy odczycie pamieci jadra, dlatego:
 *   - KAZDY odczyt pamieci jadra idzie przez safe_read(), ktore NAJPIERW przechodzi
 *     po tablicach stron, a dopiero potem wola kernel_copyout,
 *   - strony z flagami PWT albo PCD (regiony niebuforowane, czyli urzadzenia) sa
 *     pomijane przy KAZDYM odczycie PAMIECI, bo odczyt pamieci spod okna urzadzenia
 *     potrafi wylaczyc konsole. Warunek na flage jest ten sam, co w funkcji
 *     readable() z tools/a53cal/a53cal.c. Jedyny wyjatek to cztery rejestry okna:
 *     to nie pamiec, tylko rejestry urzadzenia, i dla nich istnieje osobna,
 *     sprawdzona na tej konsoli sciezka opisana przy okno_read32,
 *   - zakres jest sprawdzany co do KONCA: kazda strona, ktorej dotyka odczyt, musi
 *     byc obecna i bez flag PWT/PCD, zeby odczyt nie przeszedl na sasiednia strone
 *     o innych flagach,
 *   - zadnych zapisow do pamieci jadra i zadnych zapisow do urzadzenia poza
 *     sprawdzona sekwencja startu zrzutu i pakietami odczytu,
 *   - jedyne czytane adresy to rejestr 0x28068 i kontrola 0x28000 przez transport,
 *     cztery rejestry okna BAR2+0xf6000 do +0xf9000 przez kstuff oraz, po ocenie
 *     wiarygodnosci, adresy wariantow wyliczone z rejestrow okna, czytane przez mape
 *     bezposrednia jadra,
 *   - otwierany jest tylko jeden wezel: /dev/mp4/dump.
 *
 * Wymaga kstuff.
 *
 * Wynik: /data/pprwatch.txt oraz /data/pprwatch2.bin (porcje po 4096 bajtow, naglowek:
 * 8 bajtow numeru porcji, 8 bajtow adresu, 8 bajtow czasu, 4 bajty numeru wariantu).
 * Stary plik /data/pprwatch.bin nie jest juz zapisywany: jego naglowek nie mial pola
 * wariantu, a adres liczony z rejestru A53 nie jest adresem gospodarza.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
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
#define OUT_LOG      "/data/pprwatch.txt"
/* Porcje ida do pprwatch2.bin, bo ich naglowek niesie numer wariantu. Stara nazwa
 * pprwatch.bin nie jest juz uzywana, zeby nie mieszac dwoch formatow naglowka. */
#define OUT_BIN      "/data/pprwatch2.bin"

/* Adres FIZYCZNY procesora A53, pod ktorym lezy rejestr apertury bufora. */
#define REG_PA        0x28068ULL
/* Znany adres kontrolny w pamieci procesora A53. USTALONE POMIAREM na tej konsoli
 * (kalibracja w tools/a53layout/a53layout.c oraz a53scan): pod 0x28000 lezy ciag
 * ZNANE_CTRL. Kontrola rozstrzyga, czy transport naprawde trafia pod zadany adres
 * A53, a nie zwraca stalej odpowiedzi. */
#define CTRL_PA       0x28000ULL
/* Pole adresu w rejestrze, sposob odczytu z kodu procesora: ubfiz x0, x8, #16, #32. */
#define REG_SHIFT     16
/* Znacznik przestrzeni sprzetu, dokladany przez kod procesora. */
#define REG_MARKER    0x1000000000000ULL

/*
 * REJESTRY OKNA urzadzenia MP4, pod BAR2. To z nich liczymy adres bufora po stronie
 * gospodarza.
 *
 * KONWENCJA (wariant 0): adres jest 64-bitowy i lezy ROZBITY NA DWIE POLOWY 32-bitowe,
 * gorna pod 0xf7000, dolna pod 0xf8000. Rozmiar bufora lezy pod 0xf9000 i ma 32 bity.
 * Rejestr 0xf6000 to wyzwalacz polecenia, nie adres.
 *
 * Na jakiej podstawie tak sadze (nie zgaduje, cytaty z plikow referencyjnych):
 *   - tools/a53layout/a53layout.c, linie 214 do 216:
 *         safe_write32(g_bar2 + 0xf7000, (uint32_t) (g_iommu >> 32))
 *         safe_write32(g_bar2 + 0xf8000, (uint32_t) g_iommu)
 *         safe_write32(g_bar2 + 0xf9000, (uint32_t) g_raw_size)
 *     czyli gorna polowa 64-bitowego pola g_iommu idzie pod 0xf7000, dolna pod
 *     0xf8000, a rozmiar pod 0xf9000.
 *   - tools/mboxwrite/mboxwrite.c, linie 310 do 312: te same trzy zapisy, slowo
 *     w slowo, z tymi samymi typami.
 *   - artifacts/kstuff-a53-src/ppr/a53_transport.c, linie 741 do 744 (implementacja
 *     referencyjna, z ktorej cala droga transportu jest przejeta):
 *         uint32_t buffer_size = (uint32_t)raw_buffer_size;
 *         kwrite32(g_zcn_bar2 + 0xf7000, (uint32_t)(iommu >> 32))
 *         kwrite32(g_zcn_bar2 + 0xf8000, (uint32_t)iommu)
 *         kwrite32(g_zcn_bar2 + 0xf9000, buffer_size)
 *     Ta sama funkcja pilnuje w linii 714, ze raw_buffer_size <= UINT32_MAX
 *     (sprawdzenie: "raw_buffer_size > UINT32_MAX ... goto out"), co potwierdza, ze
 *     rozmiar jest 32-bitowy, a nie rozbity na polowy.
 *   - notes/STAN-KONCOWY-KSTUFF-NG.md, linie 215 do 217, ustalenie z pomiarow:
 *     "Rejestry BAR2+0xf7000, +0xf8000, +0xf9000 to mapowanie bufora gospodarza
 *     (IOMMU, jego polowy i rozmiar), a nie wybor okna pamieci A53. Jadro ustawia je
 *     na 0x70000000 i 0x200000 samo."
 *   - POMIAR z konsoli, artifacts/a53win-log.txt: przed transferem rejestry mialy
 *     0xf7000 = 0x00010000, 0xf8000 = 0xfee00000, 0xf9000 = 0x00000058 (linie 5 do 7),
 *     a po starcie zrzutu 0xf7000 = 0x00000000, 0xf8000 = 0x70000000,
 *     0xf9000 = 0x00200000 (linie 15 do 17). Do tego artifacts/mbox_write-log.txt
 *     linia 5 podaje pola kontekstu dla tego samego mechanizmu: "iommu 0x70000000,
 *     rozmiar 0x200000". Czyli wartosc pola iommu pojawila sie w 0xf8000, jego gorna
 *     polowa (zero) w 0xf7000, a rozmiar w 0xf9000. To niezalezne potwierdzenie
 *     podzialu na polowy, bo pole iommu jest 64-bitowe, a w rejestrach widac je
 *     rozbite.
 *
 * Konwencja jest wiec jednoznaczna dla wariantu 0. Mimo to oceniamy trzy warianty
 * i kazdy dostaje osobny werdykt:
 *   0: adres = (0xf7000 << 32) | 0xf8000         konwencja z referencji,
 *   1: adres = 0xf8000                           tylko dolna polowa, gdyby gorna
 *                                                polowa byla nieuzywana,
 *   2: adres = (0xf8000 << 32) | 0xf7000         kontrola: odwrotna kolejnosc pol.
 * Wariant 2 jest kontrola, ktora ma pokazac, ze kolejnosc pol nie jest obojetna.
 * Uwaga na przyszlosc: gdy gorna polowa jest zerem (tak bylo na tej konsoli),
 * warianty 0 i 1 daja ten sam adres i payload obserwuje go tylko raz.
 */
#define WIN_TRIGGER   0xf6000U
#define WIN_ADDR_HI   0xf7000U
#define WIN_ADDR_LO   0xf8000U
#define WIN_SIZE      0xf9000U
#define OKNO_REJESTRY 4

/* Ile wariantow adresu gospodarza oceniamy. Kolejnosc jak w komentarzu wyzej. */
#define WARIANTY 3

/* Ustalenia z a53layout: identyfikatory protokolu, typ pamieci i polecenie odczytu. */
#define DECI5S_MAGIC        0x73354450U
#define DECI5S_SRC_KERNEL   0x80FF0180U
#define DECI5S_DST_MP4      0x80FF0201U
#define DECI5S_PROTO_SDBGP  0x20000201U
#define DECI5S_DCMP         0x18U
#define MEM_TYPE_PA_TO_EL3  0x020100U
#define MP4_COREDUMP_CMD    0x20303002U
#define MP4_COREDUMP_CMD2   0x20303003U
#define SDBGP_READ_MEMORY   0x01040021U

/* pole kontekstu sterownika, to samo co w a53layout */
#define OFF_IFACE_A 0x3DEEB58ULL

#define SNAPSHOT_SIZE 0x1000U
#define READ_SIZE     32U
#define OBS_SIZE      64U
#define DUMP_SIZE     4096U
#define RESP_SIZE     0x40 + 0x28 + 0x1000 + 0x400

/* Naglowek wyniku odczytu: self_size 0x28, slowo typu pamieci, pole adresu pod
 * +0x08, zadane pod +0x10, przeslane pod +0x18, status pod +0x20. Dane leza
 * zaraz za naglowkiem, czyli pod naglowek + 0x28. NIE przyjmujemy offsetu na
 * sztywno: szukamy naglowka, ktorego pole adresu zgadza sie z zadanym. */
#define RESULT_HEADER_SIZE 0x28U
#define POLA_NIEZNANE      0xFFFFFFFFU

/* Ciag, ktory transport musi zwrocic spod CTRL_PA. Ten sam wzorzec, ktorym
 * kalibruje sie tools/a53layout. Jego brak znaczy, ze droga odczytu nie dziala. */
static const unsigned char ZNANE_CTRL[8] = {
    0x1b, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00,
};

/* Flagi tablic stron. Warunek PWT/PCD przejety z readable() w tools/a53cal. */
#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL

/* Ile trwa obserwacja i co ile sekund. */
#define OBS_CALKOWITY_CZAS 600
#define OBS_OKRES          2

static FILE *g_log;
static FILE *g_bin;
static unsigned long g_dmap, g_cr3;
static uint64_t g_softc, g_bar2, g_buffer, g_iommu, g_raw_size;
static uint64_t g_state_slot, g_flags_slot, g_buffer_slot;

/* Rejestry okna i warianty adresu gospodarza. Typy trzymamy na poziomie pliku, bo
 * korzysta z nich odczyt poczatkowy, petla obserwacyjna i podsumowanie. */
enum { OKNO_TRIG = 0, OKNO_HI = 1, OKNO_LO = 2, OKNO_SIZE = 3 };

typedef struct {
    uint32_t wart[OKNO_REJESTRY];
    int      ok[OKNO_REJESTRY];   /* 1, gdy wartosc pochodzi z udanego odczytu */
} okno_t;

typedef struct {
    uint64_t adres;         /* kandydat wyliczony z rejestrow okna */
    uint64_t obserwowany;   /* adres przyjety do obserwacji, 0 gdy zaden */
    int      wiarygodny;    /* 1, gdy kandydat przeszedl ocene */
    int      unikalny;      /* 1, gdy nie dzieli adresu z wczesniejszym wariantem */
    int      pierwszy;      /* 1, gdy nastepny odczyt ma tylko ustawic odniesienie */
    int      zmian;         /* ile razy zmienila sie zawartosc bufora */
    unsigned char poprzedni[OBS_SIZE];
} wariant_t;

static okno_t g_okno;
static wariant_t g_warianty[WARIANTY];

/* Opisy wariantow, kolejnosc jak przy WARIANTY. */
static const char *const WARIANT_OPIS[WARIANTY] = {
    "hi<<32 | lo, konwencja z implementacji referencyjnej",
    "tylko slowo nizsze (lo)",
    "lo<<32 | hi, kontrola z odwrotna kolejnoscia pol",
};

/* Offsety i opisy pol rejestrow okna. Kolejnosc musi sie zgadzac z OKNO_TRIG,
 * OKNO_HI, OKNO_LO, OKNO_SIZE. */
static const uint32_t OKNO_OFFS[OKNO_REJESTRY] = {
    WIN_TRIGGER, WIN_ADDR_HI, WIN_ADDR_LO, WIN_SIZE
};
static const char *const OKNO_OPIS[OKNO_REJESTRY] = {
    "wyzwalacz polecenia",
    "gorna polowa adresu bufora gospodarza",
    "dolna polowa adresu bufora gospodarza",
    "rozmiar bufora",
};

/* Liczniki obserwacji. Trzymamy je na poziomie pliku, bo korzysta z nich zarowno
 * petla, jak i sprawdzenie po zmianie adresu oraz podsumowanie. */
static int g_porcji = 0;
static int g_zmian_okna = 0;

/* Powiadomienie systemowe. Uklad struktury i wywolanie takie same, jakich uzywa
 * repozytorium drakmor/ppr-patch oraz tools/a53layout. */
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

/* Log idzie na trzy miejsca: ekran, log jadra i plik. Po kazdej linii plik jest
 * oprozniany i zsynchronizowany, zeby po restarcie konsoli zostalo to, co juz bylo. */
static void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
    klog_printf("[pprwatch] %s", buf);
    if (g_log) { fputs(buf, g_log); fflush(g_log); fsync(fileno(g_log)); }
}

/* Sekundy od startu systemu. Czas w naglowku porcji to ta wartosc. */
static uint64_t czas_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) (ts.tv_nsec / 1000000);
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

/*
 * Sprawdza JEDNA strone, przechodzac po tablicach stron.
 *
 * Zwraca 0, gdy strone wolno czytac, albo -1, gdy nie. Warunek na flage jest
 * DOKLADNIE ten sam, co w readable() z tools/a53cal/a53cal.c: strona musi byc
 * obecna, a gdy jest strona duza albo ostatnim poziomem, odrzucamy ja, jesli ma
 * flage PWT albo PCD. To sa regiony niebuforowane, czyli okna urzadzen; odczyt
 * spod takiego okna przewrocil te konsole.
 */
static int readable_strona(uint64_t va, const char **powod) {
    uint64_t pml = g_cr3 & PG_FRAME;
    for (int i = 39; i >= 12; i -= 9) {
        uint64_t idx = (va >> i) & 0x1FF;
        pml = kernel_getlong((intptr_t) (g_dmap + pml + idx * 8));
        if (!(pml & X86_PG_V)) { if (powod) *powod = "strona nieobecna"; return -1; }
        if ((pml & X86_PG_PS) || i == 12) {
            if (pml & (X86_PG_PWT | X86_PG_PCD)) {
                if (powod) *powod = "strona niebuforowana (PWT albo PCD)";
                return -1;
            }
            return 0;
        }
        pml &= PG_FRAME;
    }
    if (powod) *powod = "nie doszedlem do strony";
    return -1;
}

/*
 * Sprawdza zakres [va, va+n), strona po stronie.
 *
 * Zwraca 0, gdy CALY zakres nadaje sie do odczytu, albo -1, gdy nie. Kazda strona,
 * ktorej dotyka odczyt, przechodzi przez readable_strona(), wiec odczyt nie przejdzie
 * ani na strone nieobecna, ani na strone o innych flagach.
 *
 * UWAGA: wczesniej ta funkcja wymagala, zeby CALY zakres zmiescil sie na JEDNEJ
 * stronie 4 kB. Odczyt odpowiedzi ze skrzynki ma RESP_SIZE wieksze od 4 kB i z tego
 * powodu byl odrzucany ZAWSZE, przy kazdym adresie, przez co kazdy odczyt transportem
 * konczyl sie komunikatem "nie moge odczytac odpowiedzi ze skrzynki".
 */
static int readable(uint64_t va, size_t n, const char **powod) {
    if (n == 0) { if (powod) *powod = "zerowy rozmiar"; return -1; }
    if (va + (uint64_t) n < va) {
        if (powod) *powod = "zakres poza przestrzenia adresowa";
        return -1;
    }
    uint64_t ostatnia = (va + (uint64_t) n - 1) & ~0xFFFULL;
    for (uint64_t strona = va & ~0xFFFULL; ; strona += 0x1000ULL) {
        if (readable_strona(strona, powod)) return -1;
        if (strona >= ostatnia) break;
    }
    return 0;
}


/* Bezpieczny odczyt pamieci jadra: NAJPIERW tablice stron, POTEM kernel_copyout.
 * Odwrotna kolejnosc albo jej brak to wlasnie to, co restartuje konsole. */
static int safe_read_n(uint64_t va, void *dst, size_t n, const char **powod) {
    if (readable(va, n, powod)) return -1;
    return kernel_copyout((intptr_t) va, dst, n);
}
static int safe_read(uint64_t va, void *dst, size_t n) { return safe_read_n(va, dst, n, NULL); }
static int safe_read64(uint64_t va, uint64_t *o) { return safe_read(va, o, 8); }
static int safe_read32(uint64_t va, uint32_t *o) { return safe_read(va, o, 4); }

/* Schodzi po tablicach stron i zwraca wpis ostatniego poziomu, ktory dotyka adresu.
 * Zwraca 0, gdy strona jest obecna (wpis w *wpis), albo -1, gdy po drodze trafilo sie
 * ogniwo nieobecne. Wpis daje sie wypisac razem z flagami PWT i PCD, czego potrzebuje
 * ocena wiarygodnosci wariantu adresu gospodarza. */
static int wpis_strony(uint64_t va, uint64_t *wpis) {
    uint64_t pml = g_cr3 & PG_FRAME;
    for (int i = 39; i >= 12; i -= 9) {
        unsigned long idx = (va >> i) & 0x1FF;
        pml = kernel_getlong((intptr_t) (g_dmap + pml + idx * 8));
        if (!(pml & X86_PG_V)) return -1;
        if ((pml & X86_PG_PS) || i == 12) { if (wpis) *wpis = pml; return 0; }
        pml &= PG_FRAME;
    }
    return -1;
}

/*
 * Odczyt JEDNEGO rejestru okna, 4 bajty.
 *
 * Sciezka podstawowa jest ta zadana: safe_read_n(), czyli najpierw bramka readable()
 * z warunkiem na PWT i PCD, a potem kernel_copyout. Rejestry okna leza jednak na
 * stronach urzadzenia i bramka moze je odrzucic komunikatem "strona niebuforowana".
 * Wtedy rejestr czytamy druga, sprawdzona na tej konsoli sciezka:
 *   - tools/a53win/a53win.c, funkcja reg_read32(), linie 106 do 118, z komentarzem:
 *     "Rejestry urzadzenia sa na stronach niebuforowanych, wiec czytamy je bez
 *      wykluczania takich stron. To odczyt rejestru, nie pamiec."
 *     Ta funkcja sprawdza WYLACZNIE obecnosc strony i wola kernel_copyout,
 *   - pomiar z tej konsoli: artifacts/a53win-log.txt pokazuje wartosci tych czterech
 *     rejestrow odczytane wlasnie tak (linie 4 do 7 oraz 25 do 28).
 * To nadal wylacznie ODCZYT, nigdy zapis, i dotyczy samych czterech rejestrow okna,
 * a nie pamieci jadra: bramka readable() dla pamieci zostaje bez zmian.
 *
 * Zwraca 0 przy powodzeniu. W *droga zapisuje uzyta sciezke, w *powod przyczyne
 * niepowodzenia.
 */
enum { DROGA_BRAMKA = 0, DROGA_REJESTR = 1 };

static int okno_read32(uint32_t off, uint32_t *out, int *droga, const char **powod) {
    const char *p = NULL;
    uint64_t wpis = 0;
    static int zgloszone = 0;

    if (!safe_read_n(g_bar2 + off, out, 4, &p)) {
        if (droga) *droga = DROGA_BRAMKA;
        if (!zgloszone) {
            zgloszone = 1;
            log_line("  BAR2+0x%x: bramka readable przepuscila rejestr (strona buforowana)\n", off);
        }
        return 0;
    }
    if (wpis_strony(g_bar2 + off, &wpis)) {
        if (powod) *powod = "strona rejestru nieobecna";
        return -1;
    }
    if (kernel_copyout((intptr_t) (g_bar2 + off), out, 4)) {
        if (powod) *powod = "kernel_copyout nieudany";
        return -1;
    }
    if (droga) *droga = DROGA_REJESTR;
    if (!zgloszone) {
        zgloszone = 1;
        log_line("  bramka readable odrzucila rejestr okna (%s), czytam go tak jak tools/a53win: strona obecna, wpis 0x%llx\n",
                 p ? p : "nieznany powod", (unsigned long long) wpis);
    }
    return 0;
}

/* Odczyt czterech rejestrow okna. Wartosci nieudanych odczytow zostaja takie, jakie
 * byly, a w ok[] zerujemy informacje, ze sa swieze. Zwraca liczbe udanych odczytow. */
static int okno_czytaj(okno_t *o, int zglaszaj) {
    int udane = 0;
    for (int i = 0; i < OKNO_REJESTRY; i++) {
        uint32_t v = 0;
        int droga = DROGA_BRAMKA;
        const char *powod = NULL;
        if (okno_read32(OKNO_OFFS[i], &v, &droga, &powod) == 0) {
            o->wart[i] = v;
            o->ok[i] = 1;
            udane++;
        } else {
            o->ok[i] = 0;
            if (zglaszaj) {
                log_line("  BAR2+0x%x nieodczytany (%s)\n", OKNO_OFFS[i],
                         powod ? powod : "nieznany powod");
            }
        }
    }
    return udane;
}

/* Adres gospodarza wedlug wariantu id. Znaczenie pol i kolejnosc: komentarz przy
 * WIN_ADDR_HI. Warianty 0 i 1 daja ten sam adres, gdy gorna polowa jest zerem. */
static uint64_t wariant_adres(int id, const okno_t *o) {
    uint64_t hi = (uint64_t) o->wart[OKNO_HI];
    uint64_t lo = (uint64_t) o->wart[OKNO_LO];
    switch (id) {
        case 0:  return (hi << 32) | lo;
        case 1:  return lo;
        default: return (lo << 32) | hi;
    }
}

/* Ocenia wiarygodnosc kandydata: niezerowy, wyrownany do 0x1000, strona obecna
 * w mapie bezposredniej jadra i bez flag PWT oraz PCD. Werdykt wypisuje OSOBNO dla
 * kazdego wariantu. Zwraca 1, gdy kandydat przeszedl ocene. */
static int ocena_wariantu(int id, uint64_t adres, int zglaszaj) {
    uint64_t wpis = 0;
    int niezerowy = adres != 0;
    int wyrownany = (adres & 0xFFFULL) == 0;
    int obecna = 0, czysta = 0;
    int wynik;

    if (wyrownany) {
        obecna = wpis_strony(g_dmap + adres, &wpis) == 0;
        czysta = obecna && (wpis & (X86_PG_PWT | X86_PG_PCD)) == 0;
    }
    wynik = niezerowy && wyrownany && obecna && czysta;

    if (zglaszaj) {
        log_line("  wariant %d (%s): adres 0x%llx\n",
                 id, WARIANT_OPIS[id], (unsigned long long) adres);
        log_line("    niezerowy:            %s\n", niezerowy ? "TAK" : "NIE");
        log_line("    wyrownany do 0x1000:  %s\n", wyrownany ? "TAK" : "NIE");
        log_line("    strona obecna:        %s\n", obecna ? "TAK" : "NIE");
        if (obecna) {
            log_line("    bez PWT i PCD:        %s (wpis strony 0x%llx%s%s)\n",
                     czysta ? "TAK" : "NIE", (unsigned long long) wpis,
                     (wpis & X86_PG_PWT) ? ", PWT" : "",
                     (wpis & X86_PG_PCD) ? ", PCD" : "");
        } else {
            log_line("    bez PWT i PCD:        nie sprawdzam, strony nie ma\n");
        }
        log_line("    WERDYKT: %s\n", wynik
                 ? "wariant wiarygodny, czytam pod nim bufor"
                 : "wariant NIEWIARYGODNY, nie czytam pod nim nic");
    }
    return wynik;
}

/* Przelicza i ocenia wszystkie warianty. Zwraca liczbe wariantow wiarygodnych, ktore
 * nie dziela adresu z wczesniejszym wariantem: tylko takie obserwujemy. */
static int ocena_wariantow(const okno_t *o, int zglaszaj) {
    int wiarygodnych = 0;

    if (zglaszaj) {
        log_line("  zrodlo: BAR2+0x%x = 0x%08x (gora), BAR2+0x%x = 0x%08x (dol), BAR2+0x%x = 0x%08x (rozmiar)\n",
                 WIN_ADDR_HI, o->wart[OKNO_HI], WIN_ADDR_LO, o->wart[OKNO_LO],
                 WIN_SIZE, o->wart[OKNO_SIZE]);
    }
    for (int i = 0; i < WARIANTY; i++) {
        g_warianty[i].adres = wariant_adres(i, o);
        g_warianty[i].wiarygodny = ocena_wariantu(i, g_warianty[i].adres, zglaszaj);
        g_warianty[i].unikalny = 0;
        if (!g_warianty[i].wiarygodny) continue;
        {
            int wspolny = 0;
            for (int j = 0; j < i; j++) {
                if (g_warianty[j].wiarygodny && g_warianty[j].adres == g_warianty[i].adres) {
                    wspolny = 1;
                    if (zglaszaj) {
                        log_line("    ten sam adres co wariant %d, nie obserwuje go drugi raz\n", j);
                    }
                    break;
                }
            }
            g_warianty[i].unikalny = !wspolny;
            if (!wspolny) wiarygodnych++;
        }
    }
    if (zglaszaj) {
        log_line("  wariantow wiarygodnych do obserwacji: %d\n", wiarygodnych);
    }
    return wiarygodnych;
}

/* Zapis do pamieci jadra wystepuje WYLACZNIE w sekwencji startu zrzutu, tak jak
 * w a53layout. Warunek obecnosci strony jest ten sam co tam. */
static int present(uint64_t va) { return wpis_strony(va, NULL) == 0; }
static int safe_write32(uint64_t va, uint32_t v) {
    if (!present(va)) return -1;
    return kernel_copyin(&v, (intptr_t) va, 4);
}
static int safe_write(uint64_t va, const void *s, size_t n) {
    if (!present(va)) return -1;
    return kernel_copyin(s, (intptr_t) va, n);
}

static uint64_t swap_auth(uint64_t id) {
    pid_t pid = getpid();
    uint64_t o = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, id);
    return o;
}

/* Budowa pakietu odczytu pamieci A53. Bez zmian wzgledem tools/a53layout. */
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
    *(uint32_t *)(out + 0x64) = (MEM_TYPE_PA_TO_EL3 << 8) | 1;
    *(uint64_t *)(out + 0x68) = addr;
    *(uint64_t *)(out + 0x70) = size;
    return 0x78;
}

/* Wyslanie pakietu do skrzynki. Bez zmian wzgledem tools/a53layout. */
static int send_packet(unsigned char *packet, uint32_t total) {
    uint32_t request = 0;
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

/* Znajduje naglowek wyniku dla zadanego adresu i zwraca offset danych, czyli
 * naglowek + 0x28. Warunek: self_size musi byc rowne 0x28, a pole adresu musi sie
 * zgadzac z tym, o co prosilismy. Slow typu pamieci nie porownujemy na sztywno,
 * tylko wypisujemy, zeby nie odrzucic poprawnego wyniku po zmianie typu. */
static uint32_t znajdz_dane(const unsigned char *resp, uint32_t limit, uint64_t addr,
                            uint32_t size, uint32_t *slowo_out) {
    for (uint32_t i = 0; i + RESULT_HEADER_SIZE + size <= limit; i += 4) {
        uint32_t self = 0, slowo = 0;
        uint64_t a = 0;
        memcpy(&self, resp + i, 4);
        memcpy(&slowo, resp + i + 4, 4);
        memcpy(&a, resp + i + 8, 8);
        if (self != RESULT_HEADER_SIZE) continue;
        if (a != addr) continue;
        if (slowo_out) *slowo_out = slowo;
        return i + RESULT_HEADER_SIZE;
    }
    return POLA_NIEZNANE;
}

/* Jeden odczyt przez transport A53: buduje pakiet, wysyla i wyciaga dane spod
 * naglowka wyniku. Zwraca 0 przy powodzeniu. */
static int transport_read(unsigned char *packet, unsigned char *resp, uint64_t addr,
                          uint32_t size, unsigned char *dst) {
    const char *powod = NULL;
    uint32_t total = build_read(packet, addr, size, 0);
    if (send_packet(packet, total)) { log_line("  wyslanie pakietu nieudane\n"); return -1; }
    if (safe_read_n(g_buffer + total, resp, RESP_SIZE, &powod)) {
        log_line("  nie moge odczytac odpowiedzi ze skrzynki pod 0x%llx (%u bajtow): %s\n",
                 (unsigned long long) (g_buffer + total), RESP_SIZE,
                 powod ? powod : "nieznany powod");
        return -1;
    }
    uint32_t slowo = 0;
    uint32_t off = znajdz_dane(resp, RESP_SIZE, addr, size, &slowo);
    if (off == POLA_NIEZNANE) {
        /* Naglowka nie ma. Wypisujemy, co odpowiedz niesie, zeby dalo sie to
         * rozpoznac: przy adresie poza SRAM status jest rowny 0x20 i przeslano 0. */
        uint32_t psize = 0, src = 0;
        memcpy(&psize, resp + 0x08, 4);
        memcpy(&src, resp + 0x0c, 4);
        log_line("  brak naglowka wyniku dla adresu 0x%llx (magic 0x%08x, rozmiar 0x%x, zrodlo 0x%08x)\n",
                 (unsigned long long) addr, *(uint32_t *) resp, psize, src);
        return -1;
    }
    uint32_t naglowek = off - RESULT_HEADER_SIZE;
    uint64_t zadane = 0, przeslane = 0;
    uint32_t status = 0;
    memcpy(&zadane, resp + naglowek + 0x10, 8);
    memcpy(&przeslane, resp + naglowek + 0x18, 8);
    memcpy(&status, resp + naglowek + 0x20, 4);
    if (przeslane != size || status != 0) {
        log_line("  odczyt 0x%llx nieudany: zadane 0x%llx, przeslane 0x%llx, status 0x%x\n",
                 (unsigned long long) addr, (unsigned long long) zadane,
                 (unsigned long long) przeslane, status);
        return -1;
    }
    if (dst) memcpy(dst, resp + off, size);
    return 0;
}

/* Szesnastkowo, po 16 bajtow w wierszu. */
static void hex_zrzut(const unsigned char *d, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        char linia[128];
        int p = 0;
        p += snprintf(linia + p, sizeof(linia) - (size_t) p, "    %04x  ", (unsigned) i);
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            p += snprintf(linia + p, sizeof(linia) - (size_t) p, "%02x ", d[i + j]);
        }
        log_line("%s\n", linia);
    }
}

/* Dopisek porcji 4096 bajtow do pliku, z naglowkiem 8 + 8 + 8 + 4 bajtow:
 * numer porcji, adres, czas, numer wariantu. Zwraca 0 przy powodzeniu. */
static int zapisz_porcje(uint64_t numer, uint64_t adres, uint64_t czas, uint32_t wariant,
                         const unsigned char *dane) {
    if (!g_bin) return -1;
    if (fwrite(&numer, 1, 8, g_bin) != 8) return -1;
    if (fwrite(&adres, 1, 8, g_bin) != 8) return -1;
    if (fwrite(&czas, 1, 8, g_bin) != 8) return -1;
    if (fwrite(&wariant, 1, 4, g_bin) != 4) return -1;
    if (fwrite(dane, 1, DUMP_SIZE, g_bin) != DUMP_SIZE) return -1;
    fflush(g_bin);
    fsync(fileno(g_bin));
    return 0;
}

/*
 * Odczyt 64 bajtow pod adresem wariantu i wypis szesnastkowo. Sluzy do pokazania
 * stanu poczatkowego oraz stanu po przyjeciu nowego adresu. Nie melduje zmian i nic
 * nie zapisuje, bo od tego jest sprawdz_bufor.
 *
 * Zwraca 0, gdy odczyt sie udal.
 */
static int pokaz_bufor(int id, const char *etap) {
    wariant_t *w = &g_warianty[id];
    static unsigned char teraz[OBS_SIZE];
    const char *powod = NULL;

    if (safe_read_n(g_dmap + w->adres, teraz, OBS_SIZE, &powod)) {
        log_line("BLAD: wariant %d, nie moge odczytac %u bajtow pod 0x%llx (%s)\n",
                 id, OBS_SIZE, (unsigned long long) w->adres,
                 powod ? powod : "nieznany powod");
        return -1;
    }
    log_line("wariant %d (%s): adres gospodarza 0x%llx, adres w mapie 0x%llx, %u bajtow\n",
             id, etap, (unsigned long long) w->adres,
             (unsigned long long) (g_dmap + w->adres), OBS_SIZE);
    hex_zrzut(teraz, OBS_SIZE);
    return 0;
}

/*
 * Odczyt 64 bajtow pod adresem wariantu i porownanie z poprzednim odczytem.
 *
 * Gdy zawartosc sie rozni: wypisujemy 64 bajty, a nastepnie dopisujemy 4096 bajtow
 * pod tym samym adresem do /data/pprwatch2.bin, z naglowkiem numeru porcji, adresu,
 * czasu i numeru wariantu. Punkt odniesienia ustawia sie bez meldunku o zmianie
 * (pole "pierwszy"), zeby pierwszy odczyt po zmianie adresu nie zameldowal zmiany,
 * ktorej nie bylo.
 *
 * Zwraca 0, gdy odczyt sie udal.
 */
static int sprawdz_bufor(int id, const char *etap, int zglaszaj) {
    wariant_t *w = &g_warianty[id];
    static unsigned char teraz[OBS_SIZE];
    const char *powod = NULL;

    if (safe_read_n(g_dmap + w->adres, teraz, OBS_SIZE, &powod)) {
        if (zglaszaj) {
            log_line("ODCZYT BUFORA WARIANTU %d NIEUDANY pod 0x%llx (%s)\n",
                     id, (unsigned long long) w->adres, powod ? powod : "nieznany powod");
        }
        return -1;
    }

    if (w->pierwszy) {
        memcpy(w->poprzedni, teraz, OBS_SIZE);
        w->pierwszy = 0;
        return 0;
    }
    if (memcmp(teraz, w->poprzedni, OBS_SIZE) == 0) return 0;

    memcpy(w->poprzedni, teraz, OBS_SIZE);
    w->zmian++;
    log_line("ZMIANA ZAWARTOSCI BUFORA pod 0x%llx (wariant %d, %s):\n",
             (unsigned long long) w->adres, id, etap);
    hex_zrzut(teraz, OBS_SIZE);

    {
        static unsigned char porcja[DUMP_SIZE];
        const char *powod2 = NULL;
        if (safe_read_n(g_dmap + w->adres, porcja, DUMP_SIZE, &powod2)) {
            log_line("  nie moge odczytac %u bajtow do zapisu (%s)\n",
                     DUMP_SIZE, powod2 ? powod2 : "nieznany powod");
        } else {
            g_porcji++;
            if (zapisz_porcje((uint64_t) g_porcji, w->adres, czas_ms(), (uint32_t) id,
                              porcja) == 0) {
                log_line("  zapisano porcje %d do %s (adres 0x%llx, wariant %d)\n",
                         g_porcji, OUT_BIN, (unsigned long long) w->adres, id);
            } else {
                log_line("  zapis porcji %d nieudany\n", g_porcji);
            }
        }
    }
    return 0;
}

/*
 * KROK 1. Sekwencja startu zrzutu i zdobycie skrzynki pocztowej.
 *
 * Kolejnosc jest dokladnie ta sama, co w tools/a53layout/a53layout.c: podmiana
 * identyfikatora uprawnien, revoke, otwarcie /dev/mp4/dump, IOCTL_START,
 * oczekiwanie na zdarzenie czytania, IOCTL_ALTER_STATE, odnalezienie pol skrzynki
 * w migawce kontekstu, IOCTL_FINISH i odczyt pol bufora pakietow.
 *
 * Zwraca 0, gdy skrzynka jest gotowa. Przy kazdym wyjsciu przywraca identyfikator.
 */
static int setup_transport(uint64_t *auth_original) {
    static unsigned char snapshot[SNAPSHOT_SIZE];
    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    uint32_t finish[2] = {8, 0};
    int kq = -1, ctl = -1;
    int wynik = -1;

    log_line("--- 1. sekwencja startu zrzutu ---\n");

    /* Kontekst sterownika z globalnej zmiennej obrazu jadra i z niego BAR2. */
    if (safe_read64(KERNEL_ADDRESS_TEXT_BASE + OFF_IFACE_A, &g_softc) || !g_softc) {
        log_line("BLAD: brak kontekstu sterownika\n");
        return -1;
    }
    {
        uint64_t res = 0;
        if (safe_read64(g_softc + 0x18, &res) || !res || safe_read64(res + 0x10, &g_bar2)) {
            log_line("BLAD: brak BAR2\n");
            return -1;
        }
    }
    log_line("kontekst 0x%llx, BAR2 0x%llx\n",
             (unsigned long long) g_softc, (unsigned long long) g_bar2);

    *auth_original = swap_auth(SYSCORE_AUTH_ID);
    (void) revoke(CONTROL_PATH);
    ctl = open(CONTROL_PATH, O_RDONLY);
    if (ctl < 0) {
        log_line("BLAD: otwarcie %s nieudane errno=%d\n", CONTROL_PATH, errno);
        goto koniec;
    }
    if (ioctl(ctl, IOCTL_START, context) < 0) {
        log_line("BLAD: IOCTL_START errno=%d\n", errno);
        goto koniec;
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

    /* Migawka kontekstu: szukamy pol stanu i flag skrzynki. */
    if (safe_read(g_softc, snapshot, sizeof(snapshot))) {
        log_line("BLAD: brak migawki kontekstu\n");
        goto koniec;
    }
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

    if (!g_state_slot) {
        log_line("BLAD: nie znalazlem pol skrzynki w migawce\n");
        goto koniec;
    }

    /* Druga migawka po zakonczeniu zrzutu: szukamy pola bufora pakietow. */
    if (safe_read(g_softc, snapshot, sizeof(snapshot))) {
        log_line("BLAD: brak drugiej migawki kontekstu\n");
        goto koniec;
    }
    {
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
    if (!g_buffer_slot) {
        log_line("BLAD: nie znalazlem pola bufora pakietow\n");
        goto koniec;
    }
    if (safe_read64(g_buffer_slot, &g_buffer) || safe_read64(g_buffer_slot - 8, &g_iommu) ||
        safe_read64(g_buffer_slot - 16, &g_raw_size)) {
        log_line("BLAD: brak pol bufora pakietow\n");
        goto koniec;
    }
    log_line("skrzynka gotowa: bufor pakietow 0x%llx, pole iommu 0x%llx, pole rozmiaru 0x%llx\n",
             (unsigned long long) g_buffer, (unsigned long long) g_iommu,
             (unsigned long long) g_raw_size);
    log_line("te dwa pola ida do rejestrow okna w kazdym pakiecie (send_packet), wiec odczyt rejestrow pokaze je z powrotem\n");
    wynik = 0;

koniec:
    if (ctl >= 0) close(ctl);
    if (kq >= 0) close(kq);
    if (wynik != 0) swap_auth(*auth_original);
    return wynik;
}

/* Skrocony opis wartosci rejestru A53, zeby log byl czytelny przy kazdej zmianie.
 * Liczymy i wypisujemy to, co policzylby kod procesora, ale WYLACZNIE jako informacje
 * o etapie pracy A53: ten adres nalezy do przestrzeni urzadzenia, wiec nie sluzy jako
 * adres bufora gospodarza i nic pod nim nie czytamy. */
static void opis_rejestru(uint64_t wartosc, uint64_t *adres_a53_out) {
    uint32_t slowo = (uint32_t) (wartosc & 0xFFFFFFFFULL);
    uint64_t adres_a53 = ((uint64_t) slowo & 0xFFFFFFFFULL) << REG_SHIFT;
    log_line("  pierwsze slowo 32-bit 0x%08x, adres po stronie A53 0x%llx (przestrzen urzadzenia, nie gospodarza), bit 48 %s\n",
             slowo, (unsigned long long) adres_a53,
             (wartosc & REG_MARKER) ? "USTAWIONY" : "wyzerowany");
    if (adres_a53_out) *adres_a53_out = adres_a53;
}

int main(void) {
    static unsigned char packet[0x100];
    static unsigned char resp[RESP_SIZE];
    static unsigned char surowe[READ_SIZE];
    uint64_t auth_original = 0;
    uint64_t adresy_a53[64];
    int ile_adresow = 0;
    int zmian_rejestru = 0, nieudanych = 0;
    int wiarygodnych = 0, obserwacja = 0;
    /* Powod przerwania przed obliczeniem adresu bufora. NULL, gdy doszlo do obliczenia. */
    const char *przerwano = NULL;
    uint64_t rejestr = 0, rejestr_poprzedni = 0;
    uint64_t adres_a53 = 0;

    g_log = fopen(OUT_LOG, "w");
    log_line("pprwatch 1.2 start: szukam bufora docelowego A53 i obserwuje go\n");
    log_line("wersja systemu: 0x%x\n", kernel_get_fw_version());
    log_line("rejestr A53 pod adresem fizycznym 0x%llx daje po stronie A53 adres (rejestr & 0xFFFFFFFF) << %d, ale adresu bufora gospodarza szukam w rejestrach okna\n",
             (unsigned long long) REG_PA, REG_SHIFT);

    if (init_map() != 0) {
        log_line("BLAD: brak mapy jadra, koncze bez czytania czegokolwiek\n");
        if (g_log) fclose(g_log);
        return 2;
    }
    log_line("mapa bezposrednia 0x%lx, cr3 0x%lx\n", g_dmap, g_cr3);

    if (setup_transport(&auth_original) != 0) {
        log_line("BLAD: skrzynka pocztowa niedostepna, koncze bez odczytu rejestru\n");
        swap_auth(auth_original);
        przerwano = "skrzynka pocztowa niedostepna";
        goto podsumowanie;
    }

    /* --- 2. Odczyt rejestru 0x28068 przez transport A53 --- */
    log_line("--- 2. odczyt rejestru 0x%llx, %u bajtow transportem A53 ---\n",
             (unsigned long long) REG_PA, READ_SIZE);
    if (transport_read(packet, resp, REG_PA, READ_SIZE, surowe)) {
        log_line("BLAD: odczyt rejestru 0x%llx przez transport nieudany\n",
                 (unsigned long long) REG_PA);
        log_line("BLAD: koncze bez liczenia adresu bufora, mapa bezposrednia jadra pokazuje inna pamiec\n");
        przerwano = "odczyt rejestru przez transport nieudany";
        goto podsumowanie;
    }
    log_line("surowe %u bajty spod 0x%llx (transport A53):\n",
             READ_SIZE, (unsigned long long) REG_PA);
    hex_zrzut(surowe, READ_SIZE);

    memcpy(&rejestr, surowe, 8);
    log_line("wartosc 64-bit zlozona z rejestru: 0x%016llx\n", (unsigned long long) rejestr);
    opis_rejestru(rejestr, &adres_a53);
    log_line("rejestr A53 sluzy tu tylko jako wskaznik etapu pracy procesora: adres 0x%llx nalezy do przestrzeni urzadzenia, wiec nie czytam pod nim nic\n",
             (unsigned long long) adres_a53);

    /* --- 3. Kontrola drogi odczytu na znanym adresie 0x28000 --- */
    log_line("--- 3. kontrola odczytu na znanym adresie 0x%llx ---\n",
             (unsigned long long) CTRL_PA);
    {
        unsigned char kontrola[READ_SIZE];
        if (transport_read(packet, resp, CTRL_PA, READ_SIZE, kontrola)) {
            log_line("BLAD: kontrola na 0x%llx nieudana (brak odczytu przez transport), przerywam\n",
                     (unsigned long long) CTRL_PA);
            przerwano = "kontrola drogi odczytu nieudana (brak odczytu)";
            goto podsumowanie;
        }
        log_line("kontrola %u bajtow spod 0x%llx (transport A53):\n",
                 READ_SIZE, (unsigned long long) CTRL_PA);
        hex_zrzut(kontrola, READ_SIZE);
        if (memcmp(kontrola, ZNANE_CTRL, sizeof(ZNANE_CTRL)) != 0) {
            log_line("BLAD: pod 0x%llx nie ma ciagu %02x %02x %02x %02x %02x %02x %02x %02x\n",
                     (unsigned long long) CTRL_PA,
                     ZNANE_CTRL[0], ZNANE_CTRL[1], ZNANE_CTRL[2], ZNANE_CTRL[3],
                     ZNANE_CTRL[4], ZNANE_CTRL[5], ZNANE_CTRL[6], ZNANE_CTRL[7]);
            log_line("BLAD: droga odczytu nie dziala, przerywam bez liczenia adresu bufora\n");
            przerwano = "kontrola drogi odczytu nieudana (zla zawartosc)";
            goto podsumowanie;
        }
        log_line("kontrola OK: transport czyta pamiec A53 pod zadanym adresem\n");
    }

    /* --- 4. Rejestry okna urzadzenia MP4 --- */
    log_line("--- 4. odczyt rejestrow okna pod BAR2 0x%llx ---\n",
             (unsigned long long) g_bar2);
    {
        int udane = okno_czytaj(&g_okno, 1);
        for (int i = 0; i < OKNO_REJESTRY; i++) {
            if (g_okno.ok[i]) {
                log_line("  BAR2+0x%x = 0x%08x  (%s)\n",
                         OKNO_OFFS[i], g_okno.wart[i], OKNO_OPIS[i]);
            } else {
                log_line("  BAR2+0x%x = nieodczytany  (%s)\n", OKNO_OFFS[i], OKNO_OPIS[i]);
            }
        }
        log_line("  odczytanych rejestrow okna: %d z %d\n", udane, OKNO_REJESTRY);
    }

    /* --- 5. Warianty adresu bufora gospodarza, ocena kazdego osobno --- */
    log_line("--- 5. budowa i ocena wariantow adresu bufora gospodarza ---\n");
    wiarygodnych = ocena_wariantow(&g_okno, 1);
    log_line("  WERDYKT ZBIORCZY: %s\n", wiarygodnych
             ? "co najmniej jeden wariant wiarygodny, zaczynam obserwacje"
             : "zaden wariant nie przeszedl oceny, nie czytam pod zadnym z nich nic");

    /* --- 6. Stan poczatkowy obserwowanych buforow --- */
    if (wiarygodnych) {
        log_line("--- 6. stan poczatkowy obserwowanych buforow ---\n");
        for (int i = 0; i < WARIANTY; i++) {
            if (!g_warianty[i].wiarygodny || !g_warianty[i].unikalny) continue;
            (void) pokaz_bufor(i, "stan poczatkowy");
        }
    }

    /* Obserwacje prowadzimy zawsze, gdy droga odczytu przeszla kontrole: rejestry okna
     * wskazuja moment, w ktorym urzadzenie programuje okno, wiec warto je widziec nawet
     * wtedy, gdy zaden wariant nie nadaje sie do czytania. */
    obserwacja = 1;

    /* --- 7. Petla obserwacyjna --- */
    if (obserwacja) {
        uint64_t start = 0, nastepne = 0;
        int poprzedni_stan_odczytu = 1;
        int poprzedni_stan_okna = 1;
        int tura = 0;

        rejestr_poprzedni = rejestr;
        adresy_a53[ile_adresow++] = adres_a53;

        g_bin = fopen(OUT_BIN, "wb");
        if (!g_bin) log_line("UWAGA: nie moge zapisac %s, porcje beda tylko w logu\n", OUT_BIN);

        /* Pierwsze sprawdzenie kazdego wariantu ustawia punkt odniesienia na zawartosci
         * ze stanu poczatkowego, zeby pierwszy obieg petli nie zameldowal zmiany, ktorej
         * nie ma, i przyjmuje jego adres do obserwacji. */
        for (int i = 0; i < WARIANTY; i++) {
            if (!g_warianty[i].wiarygodny || !g_warianty[i].unikalny) continue;
            g_warianty[i].obserwowany = g_warianty[i].adres;
            g_warianty[i].pierwszy = 1;
            if (sprawdz_bufor(i, "stan poczatkowy", 1)) nieudanych++;
        }

        log_line("--- 7. obserwacja: %d sekund, sprawdzenie co %d sekundy ---\n",
                 OBS_CALKOWITY_CZAS, OBS_OKRES);
        notify("pprwatch 1.2: obserwacja rejestrow okna i buforow startuje na 10 minut");

        start = czas_ms();
        nastepne = start;
        for (;;) {
            uint64_t teraz = czas_ms();
            if (teraz - start >= (uint64_t) OBS_CALKOWITY_CZAS * 1000ULL) break;
            if (teraz < nastepne) { usleep(200 * 1000); continue; }
            nastepne += (uint64_t) OBS_OKRES * 1000ULL;
            tura++;

            /* 7a. rejestr A53 przez transport. Obserwujemy go jako wskaznik etapu pracy
             * procesora; adresu bufora gospodarza z niego NIE liczymy. */
            {
                unsigned char swieze[READ_SIZE];
                uint64_t rejestr_teraz = 0;
                int ok = transport_read(packet, resp, REG_PA, READ_SIZE, swieze) == 0;
                if (ok) {
                    memcpy(&rejestr_teraz, swieze, 8);
                    if (rejestr_teraz != rejestr_poprzedni) {
                        zmian_rejestru++;
                        log_line("ZMIANA REJESTRU A53 [%llu s]: 0x%016llx -> 0x%016llx\n",
                                 (unsigned long long) ((teraz - start) / 1000),
                                 (unsigned long long) rejestr_poprzedni,
                                 (unsigned long long) rejestr_teraz);
                        opis_rejestru(rejestr_teraz, &adres_a53);
                        if (ile_adresow < 64 && adresy_a53[ile_adresow - 1] != adres_a53) {
                            adresy_a53[ile_adresow++] = adres_a53;
                        }
                        rejestr_poprzedni = rejestr_teraz;
                    }
                } else {
                    nieudanych++;
                    if (poprzedni_stan_odczytu == 0) {
                        log_line("ODCZYT REJESTRU A53 NIEUDANY [%llu s], dalsze nieudane bez logu\n",
                                 (unsigned long long) ((teraz - start) / 1000));
                    }
                }
                poprzedni_stan_odczytu = ok ? 0 : 1;
            }

            /* 7b. rejestry okna przez kstuff. Logujemy TYLKO zmiany. */
            {
                okno_t swieze = g_okno;
                int udane = okno_czytaj(&swieze, 0);
                int zmiana = 0;
                if (udane == 0) {
                    nieudanych++;
                    if (poprzedni_stan_okna == 0) {
                        log_line("ODCZYT REJESTROW OKNA NIEUDANY [%llu s], dalsze nieudane bez logu\n",
                                 (unsigned long long) ((teraz - start) / 1000));
                    }
                    poprzedni_stan_okna = 1;
                } else {
                    poprzedni_stan_okna = 0;
                    for (int i = 0; i < OKNO_REJESTRY; i++) {
                        if (!swieze.ok[i]) {
                            if (g_okno.ok[i]) {
                                log_line("ODCZYT REJESTRU OKNA [%llu s]: BAR2+0x%x nieodczytany w tej turze\n",
                                         (unsigned long long) ((teraz - start) / 1000),
                                         OKNO_OFFS[i]);
                                g_okno.ok[i] = 0;
                                zmiana = 1;
                            }
                            continue;
                        }
                        if (g_okno.ok[i] && swieze.wart[i] == g_okno.wart[i]) continue;
                        if (g_okno.ok[i]) {
                            log_line("ZMIANA REJESTRU OKNA [%llu s]: BAR2+0x%x 0x%08x -> 0x%08x  (%s)\n",
                                     (unsigned long long) ((teraz - start) / 1000),
                                     OKNO_OFFS[i], g_okno.wart[i], swieze.wart[i],
                                     OKNO_OPIS[i]);
                        } else {
                            log_line("ODCZYT REJESTRU OKNA [%llu s]: BAR2+0x%x = 0x%08x  (%s, wczesniej nieodczytany)\n",
                                     (unsigned long long) ((teraz - start) / 1000),
                                     OKNO_OFFS[i], swieze.wart[i], OKNO_OPIS[i]);
                        }
                        g_okno.wart[i] = swieze.wart[i];
                        g_okno.ok[i] = 1;
                        zmiana = 1;
                    }
                    if (zmiana) {
                        g_zmian_okna++;
                        log_line("  przeliczam warianty adresu gospodarza po zmianie rejestrow okna\n");
                        wiarygodnych = ocena_wariantow(&g_okno, 1);
                        for (int i = 0; i < WARIANTY; i++) {
                            if (g_warianty[i].wiarygodny && g_warianty[i].unikalny) {
                                if (g_warianty[i].obserwowany != g_warianty[i].adres) {
                                    g_warianty[i].obserwowany = g_warianty[i].adres;
                                    g_warianty[i].pierwszy = 1;
                                    log_line("  wariant %d: nowy adres 0x%llx przyjety do obserwacji\n",
                                             i, (unsigned long long) g_warianty[i].adres);
                                    (void) pokaz_bufor(i, "po zmianie adresu");
                                    (void) sprawdz_bufor(i, "po zmianie adresu", 1);
                                }
                            } else if (g_warianty[i].obserwowany) {
                                log_line("  wariant %d: adres 0x%llx przestaje byc obserwowany\n",
                                         i, (unsigned long long) g_warianty[i].obserwowany);
                                g_warianty[i].obserwowany = 0;
                                g_warianty[i].pierwszy = 1;
                            }
                        }
                    }
                }
            }

            /* 7c. zawartosc buforow obserwowanych wariantow przez kstuff */
            for (int i = 0; i < WARIANTY; i++) {
                if (!g_warianty[i].wiarygodny || !g_warianty[i].unikalny) continue;
                if (g_warianty[i].obserwowany != g_warianty[i].adres) continue;
                if (sprawdz_bufor(i, "w petli", 1)) nieudanych++;
            }
        }
        log_line("obserwacja zakonczona po %llu sekundach, tur %d\n",
                 (unsigned long long) ((czas_ms() - start) / 1000), tura);
    }

podsumowanie:
    /* --- 8. Podsumowanie --- */
    log_line("--- 8. podsumowanie ---\n");
    if (przerwano) {
        log_line("PRZERWANE bez liczenia adresu bufora: %s\n", przerwano);
    } else if (!wiarygodnych) {
        log_line("zaden wariant adresu bufora gospodarza nie przeszedl oceny, buforow nie czytalem\n");
    }
    log_line("zmian rejestru A53 0x%llx: %d\n", (unsigned long long) REG_PA, zmian_rejestru);
    log_line("tur ze zmiana rejestrow okna: %d\n", g_zmian_okna);
    {
        int zmian_bufora = 0;
        for (int i = 0; i < WARIANTY; i++) zmian_bufora += g_warianty[i].zmian;
        log_line("zmian zawartosci obserwowanych buforow (pierwsze %u bajtow): %d\n",
                 OBS_SIZE, zmian_bufora);
        for (int i = 0; i < WARIANTY; i++) {
            log_line("  wariant %d (%s): adres 0x%llx, wiarygodny %s, zmian zawartosci %d\n",
                     i, WARIANT_OPIS[i], (unsigned long long) g_warianty[i].adres,
                     g_warianty[i].wiarygodny ? "TAK" : "NIE", g_warianty[i].zmian);
        }
    }
    log_line("zapisanych porcji po %u bajtow do %s: %d\n", DUMP_SIZE, OUT_BIN, g_porcji);
    log_line("nieudanych odczytow: %d\n", nieudanych);
    log_line("adresy po stronie A53, ktore wystapily (%d), NIE sa adresami gospodarza:\n",
             ile_adresow);
    for (int i = 0; i < ile_adresow; i++) {
        log_line("  0x%llx\n", (unsigned long long) adresy_a53[i]);
    }
    log_line("koniec podsumowania\n");

    if (g_bin) { fflush(g_bin); fsync(fileno(g_bin)); fclose(g_bin); g_bin = NULL; }
    swap_auth(auth_original);
    log_line("identyfikator przywrocony, koniec\n");
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "pprwatch: koniec, porcji %d", g_porcji);
        notify(msg);
    }
    if (g_log) fclose(g_log);
    return 0;
}

