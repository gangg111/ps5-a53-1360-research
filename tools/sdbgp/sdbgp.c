/*
 * sdbgp: hook jadra na funkcji, ktora buduje pakiety SDBGP dla procesora A53.
 *
 * PO CO TO JEST:
 * jadro rozmawia z procesorem bezpieczenstwa A53 protokolem SDBGP (DECI5S).
 * Pakiety tego protokolu powstaja w JEDNEJ duzej funkcji pod obraz+0xc29100
 * (VA 0xffffffffc1889100). To ta funkcja zleca A53 prace: odczyt pamieci
 * (typ 0x01040021) i konfiguracje (typ 0x01010010). Ten payload zaklada na jej
 * wejsciu hook jadra i loguje KAZDE wywolanie: numer, czas, rdzen, adres
 * funkcji, wartosci argumentow w rejestrach, 96-bajtowa sonde pakietu oraz
 * rozpoznane polecenia z typem, adresem i rozmiarem.
 *
 * GDZIE TA FUNKCJA JEST I SKAD TO WIEMY (offline, na zrzucie jadra):
 *   plik: artifacts/kernel-1360-13.60.bin, baza obrazu 0xffffffffc0c60000
 *   funkcja: 0xffffffffc1889100, czyli obraz + 0xc29100
 *   prolog 24 bajtow (bramka w payloadzie):
 *     55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 48 06 00 00 4c 8d 25 f5
 *   Dowod, ze to ta funkcja: leza w niej WSZYSTKIE TRZY miejsca ze zlecenia,
 *   kazde jako zapis stalej SDBGP do pakietu w buforze [softc+0x6b8]:
 *     obraz+0xc292be  48 c7 41 60 21 00 04 01  mov qword [rcx+0x60], 0x01040021
 *     obraz+0xc296c8  48 c7 44 31 48 21 00 04 01  mov qword [rcx+rsi+0x48], 0x01040021
 *     obraz+0xc292a7  48 c7 41 48 10 00 01 01  mov qword [rcx+0x48], 0x01010010
 *   Funkcja konczy sie przed obraz+0xc2ee50 (tam zaczyna sie nastepna), czyli ma
 *   0x5d50 = 23888 bajtow, a w niej 15 miejsc z typem odczytu (skan calego
 *   obrazu: 28 miejsc 0x01040021, 1 miejsce 0x01010010, ZERO miejsc 0x01040031).
 *   Narzedzie: tools/sdbgp/offline-find-builders.py, wynik w
 *   artifacts/sdbgp-offline.txt.
 *
 * DLACZEGO HOOK NA WEJSCIU FUNKCJI, A NIE NA SAMYM ZAPISIE STALEJ:
 * API hooka (khook.c z tools/byepervisor) ma wbudowany blok zapisu rejestrow
 * (khook.c, linie 417 do 427), ktory uzywa gadzetow POP_RCX i POP_R8, czyli
 * KLOBRUJE rax, rcx i r8 (rdi, rsi i rdx wracaja z slotow, patrz ogon lancucha
 * w khook.c, linie 435 do 440). Na wejsciu funkcji te trzy rejestry sa martwe
 * (volatile w ABI, funkcja zapisuje je przed pierwszym uzyciem: rax pod
 * +0xc2911e, rcx pod +0xc2915a, r8 pod +0xc291df). Natomiast w miejscu
 * obraz+0xc292be rejestr rcx TRZYMA ADRES PAKIETU i jest uzywany dalej przez
 * kilkadziesiat rozkazow (+0xc292c6, +0xc292df, +0xc292e3, +0xc292ee, ...),
 * wiec hook w tym miejscu pisalby pola pakietu pod adres slotu w jaskini,
 * czyli w nasz wlasny lancuch. Dlatego celuje sie w wejscie funkcji: jest
 * bezpieczne, a pakiet i tak czyta sie z bufora po wywolaniu.
 *
 * JAK CZYTA SIE PAKIET:
 * argument rdi na wejsciu to softc sterownika MP4 (ta sama struktura, ktora
 * tools/mp4cmd obserwuje przez globalna obraz+0x3deeb58). Funkcja sklada
 * polecenia w buforze:
 *   [softc+0x6b8] bufor pakietow w pamieci jadra (rozmiar [softc+0x6a8])
 *   [softc+0x6b0] adres IOMMU tego bufora
 * Uklad pakietu (zgodny z ABI z artifacts/kstuff-a53-src/ppr/a53_transport.c
 * i z deasemblacja tego jadra):
 *   +0x00  deci5s_hdr: magic 0x73354450, self_size, packet_size, src 0x80ff0180,
 *          dst 0x80ff0201, protocol 0x20000201 (SDBGP), attr, user_data,
 *          timestamp; od +0x28 dcmp/code/numer/num_commands
 *   +0x40  polecenia, kazde o dlugosci self_size:
 *          +0x00 self_size, +0x04 total_size, +0x08 typ, +0x0c flagi,
 *          +0x10 numer polecenia, +0x14 numer pakietu, +0x1c liczba argumentow
 *          +0x20 argumenty pamieciowe po 0x18:
 *                +0x00 self_size 0x18, +0x04 (typ pamieci << 8) | dostep,
 *                +0x08 adres, +0x10 rozmiar
 *   Wariant "doklejany" (obraz+0xc296c8) buduje identyczny pakiet, ale pod
 *   offsetem wyliczonym z pola packet_size pierwszego pakietu (w jadrze:
 *   (packet_size + 7) & ~7), dlatego payload sonduje OBA okna.
 *
 * CO PAYLOAD ROBI, KROK PO KROKU:
 *   1. bramka firmware 13.60 i podmiana identyfikatora uprawnien na SYSCORE,
 *   2. mapa bezposrednia i cr3 (bramka "readable" do odczytu pakietow),
 *   3. adres celu z przesunieciem KASLR i bramka 24 bajtow prologu,
 *   4. samotest mechanizmu na SYS_GETUID+0xE (jak w tools/byepervisor/main.c),
 *   5. obchod rdzeni: przypiecie (pin_to_core_mask z tools/mp4cmd/util.c),
 *      kh_install, kh_trigger, DOWOD rdzenia krokiem pojedynczym,
 *   6. dla kazdego wywolania: numer, czas, rdzen, adres funkcji, rdi/rsi/rdx,
 *      adres powrotu, sonda 96 bajtow pakietu (bramka readable, strony PWT i PCD
 *      odrzucane), rozpoznane polecenia z typem, adresem i rozmiarem,
 *   7. rownolegle zmiany pol softc+0x440, +0x6a8, +0x6b0, +0x6b8, +0x858,
 *      +0x860, +0x868, +0x870 wraz ze strona kazdej wartosci (bufor pakietow
 *      jest jedynym buforem, ktory da sie wskazac z argumentow),
 *   8. na koncu zdjecie hooka, przywrocenie bramy IDT, wpisu IST i
 *      identyfikatora uprawnien oraz podsumowanie: ile polecen, jakie typy,
 *      jakie pary adres/rozmiar, jakie odstepy czasu.
 *
 * DOWOD RDZENIA JEST ZROBIONY TAK, ZEBY NIE PSUL MECHANIZMU:
 * kh_install pisze do jaskini pod KH_OFF_CHAIN_DISP (obraz +0x240) stub
 * "pop rsp; wskaznik duzego lancucha", ktory musi tam zostac. Zamiast
 * podmieniac ten stub (jak robil to tools/mp4cmd), payload buduje lancuch
 * proby o DOKLADNIE TAKIEJ SAMEJ dlugosci jak lancuch wlasciwy i wpisuje go
 * pod KH_OFF_BIG_CHAIN + 0x58, czyli w miejsce, gdzie kh_install kladzie
 * lancuch uzytkownika (khook.c, linie 409 do 432). Ogon lancucha (przywrocenie
 * rejestrow, RF i iretq) zostaje nietkniety, bo dlugosc sie zgadza, a wypelnienie
 * stanowi gadzet "ret".
 *
 * ZAPISY DO PAMIECI JADRA: wylacznie instalacja hooka, jego zdjecie, zerowanie
 * pola magic wlasnego rekordu, podmiana lancucha na lancuch proby i z powrotem
 * (dokladnie w miejscu lancucha uzytkownika, ta sama dlugosc) oraz podmiana
 * identyfikatora uprawnien na czas odczytow. Zaden ioctl, zaden wezel
 * urzadzenia, zaden zapis do struktury sterownika ani do rejestrow urzadzen,
 * brak kstuffa.
 *
 * WYNIK: /data/sdbgp.txt (kazda linia z fflush i fsync).
 * Zatrzymanie przed czasem: plik /data/sdbgp.stop.
 * Domyslnie do logu idzie KAZDE wywolanie; gdy istnieje plik
 * /data/sdbgp.nowe, tylko pierwsze wystapienie kazdej roznej tresci.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

#include <ps5/kernel.h>

#include "khook.h"
#include "kdlsym.h"
#include "util.h"

/* --- tozsamosc, pliki, budzet --- */
#define SYSCORE_AUTH_ID   0x4800000000000007ULL
#define OUT_LOG           "/data/sdbgp.txt"
#define STOP_FILE         "/data/sdbgp.stop"

#define BUDZET_CALKOWITY_S 600          /* zlecenie: 600 sekund */
#define BUDZET_LINII       2000         /* zlecenie: nie wiecej niz 2000 linii polecen */
#define NOWE_FILE         "/data/sdbgp.nowe"  /* opcjonalnie: tylko nowe tresci */
#define LIMIT_OBSEWACJI    400          /* osobny sufit na linie zmian pol struktury */
#define OKRES_ODPYTYWANIA  500          /* przerwa miedzy odczytami rekordu, mikrosekundy */
#define OKRES_POL_MS       200          /* co ile sprawdzac pola softc */
#define OKRES_STOPU_MS     1000         /* co ile sprawdzac plik-stop */

/* Okno obserwacji na jeden rdzen. Krotsze okno = wiecej rdzeni w budzecie. */
#ifndef SDBGP_OKNO_MS
#define SDBGP_OKNO_MS      6000
#endif

/* Sufit rdzeni w obchodzie. */
#ifndef SDBGP_RDZENIE_MAX
#define SDBGP_RDZENIE_MAX  16
#endif

#ifndef SDBGP_SAMOTEST
#define SDBGP_SAMOTEST     1
#endif

/* --- adresy wzgledem bazy obrazu ze zrzutu (jedno miejsce prawdy) --- */
#define REF_TEXT_BASE     0xffffffffc0c60000ULL  /* baza obrazu kodu w zrzucie 13.60 */
#define OFF_IFACE_A       0x3DEEB58ULL           /* globalna: wskaznik sterownika MP4 */

/* --- cel hooka: wejscie funkcji budujacej pakiety SDBGP --- */
#define CEL_OFFSET        0xc29100ULL
#define CEL_KONIEC        0xc2ee50ULL   /* poczatek nastepnej funkcji (granica) */
#define CEL_PROLOG_LEN    24

/* Pola struktury sterownika MP4 (z deasemblacji tej samej funkcji). */
#define SOFTC_DEV_A53IO   0x440ULL   /* adres urzadzenia A53 (rejestr) */
#define SOFTC_BUF_SIZE    0x6a8ULL   /* rozmiar bufora pakietow */
#define SOFTC_BUF_IOMMU   0x6b0ULL   /* adres IOMMU bufora pakietow */
#define SOFTC_BUF_VA      0x6b8ULL   /* bufor pakietow w pamieci jadra */
#define SOFTC_STAN_A      0x858ULL   /* pola zerowane na wejsciu funkcji */
#define SOFTC_STAN_B      0x860ULL
#define SOFTC_STAN_C      0x868ULL
#define SOFTC_STAN_D      0x870ULL

/* --- protokol SDBGP / DECI5S --- */
#define DECI5S_MAGIC      0x73354450U    /* "PD5s" */
#define DECI5S_SRC_KERNEL 0x80ff0180U
#define DECI5S_DST_MP4    0x80ff0201U
#define SDBGP_PROTO       0x20000201U
#define SDBGP_PROTO_B     0x20000200U
#define SDBGP_READ        0x01040021U
#define SDBGP_WRITE       0x01040031U
#define SDBGP_CONF        0x01010010U

#define HDR_POLEB        0x40U    /* naglowek deci5s (0x28) + deci5s_cmd_hdr (0x18) */
#define CMD_ARGS_OFF      0x20U   /* argumenty zaczynaja sie tu od poczatku polecenia */
#define ARG_LEN           0x18U
#define ARG_MAX           16
#define CMD_MAX           16
#define SONDA_BAJTOW      96      /* zlecenie: pierwsze 96 bajtow sondy */
#define OKNO_BAJTOW       0x200   /* okno odczytu do rozbioru pakietu */

/* --- hook --- */
#define HOOK_IST          6        /* ten sam wpis IST co w tools/byepervisor/main.c */
#define REC_OFF           0x800ULL /* rekord w jaskini; 0x600 i 0x620 zostawiamy byepervisorowi */
#define REC_MAGIC         0x5344424750303031ULL  /* 'SDBGP001' */
#define HB_MAGIC          0x5344424750425431ULL  /* 'SDBGPBT1' */
#define HB_ID             0xEEULL                 /* numer kanalu dla kroku pojedynczego */
#define KANAL_HOOK        1ULL

/* --- bramka "readable" z tools/pprbuf/pprbuf.c, bez zmian --- */
#define PG_FRAME   0x000FFFFFFFFFF000ULL
#define X86_PG_V   0x001ULL
#define X86_PG_PS  0x080ULL
#define X86_PG_PWT 0x008ULL
#define X86_PG_PCD 0x010ULL

/* Budzet odczytu: 8 MB. Jedno wywolanie to sonda 96 B + dwa okna po 0x200 B,
 * czyli okolo 1 KB, wiec 2000 linii miesci sie z zapasem. */
#define BUDZET_ODCZYTU (8ULL * 1024ULL * 1024ULL)

/* Rekord w jaskini. Kolejnosc pol jest wazna: magic idzie na koncu.
 * Lancuch zapisuje pola; "rsp_slot" to ADRES slotu z RSP w ramce przerwania,
 * bo lancuch nie umie dodawac stalej do rejestru. */
typedef struct {
  uint64_t kanal;     /* +0x00 KANAL_HOOK, HB_ID (krok), 99 (samotest) */
  uint64_t cel;       /* +0x08 offset celu, kontrola pochodzenia rekordu */
  uint64_t rsi;       /* +0x10 rsi w chwili przerwania */
  uint64_t rsp_slot;  /* +0x18 ADRES, pod ktorym lezy RSP z ramki przerwania */
  uint64_t rdi;       /* +0x20 rdi w chwili przerwania (softc sterownika) */
  uint64_t rdx;       /* +0x28 rdx w chwili przerwania */
  uint64_t zapas1;    /* +0x30 */
  uint64_t zapas2;    /* +0x38 */
  uint64_t magic;     /* +0x40 wpisywane jako ostatnie */
} rekord_t;

#define REC_OFF_MAGIC 0x40

_Static_assert(sizeof(rekord_t) == 0x48, "rekord_t musi miec 0x48 bajtow");
_Static_assert(sizeof(khook_t) == 208, "khook_t musi sie zgadzac z artefaktem z konsoli");

/* Prolog 24 bajtow ze zrzutu pod offsetem CEL_OFFSET, czyli bramka
 * rozstrzygajaca, ze pod wyliczonym adresem naprawde jest nasza funkcja. */
static const unsigned char g_cel_prolog[CEL_PROLOG_LEN] = {
  0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x81, 0xec,
  0x48, 0x06, 0x00, 0x00, 0x4c, 0x8d, 0x25, 0xf5,
};

/* Typy polecen SDBGP widziane w tym obrazie i znane z ABI. */
typedef struct {
  uint32_t    typ;
  const char *nazwa;
  const char *opis;
} typ_t;

static const typ_t g_typy[] = {
  { SDBGP_READ,  "SDBGP_READ_MEMORY",  "odczyt pamieci A53 (to polecenie widzi hook)" },
  { SDBGP_CONF,  "SDBGP_GET_CONF",     "konfiguracja A53" },
  { SDBGP_WRITE, "SDBGP_WRITE_MEMORY", "zapis pamieci A53 (w tym obrazie nie wystepuje)" },
  { 0x01050020U, "SDBGP_0x01050020",   "polecenie z lista identyfikatorow regionow" },
  { 0x01050030U, "SDBGP_0x01050030",   "polecenie z lista identyfikatorow regionow" },
  { 0x01200021U, "SDBGP_0x01200021",   "polecenie nieustalone" },
  { 0x02040021U, "SDBGP_RES_READ",     "odpowiedz odczytu" },
  { 0x02010010U, "SDBGP_RES_CONF",     "odpowiedz konfiguracji" },
};

/* --- stan globalny --- */
static FILE   *g_log;
static uint64_t g_start_ms;
static int      g_czas_ok = 1;
static int      g_mapa_ok;
static uint64_t g_dmap;
static uint64_t g_cr3;
static uint64_t g_odczytane;
static uint64_t g_baza_kodu;
static uint64_t g_jaskinia;
static uint64_t g_big;          /* jaskinia + KH_OFF_BIG_CHAIN */
static uint64_t g_rekord;
static uint64_t g_brama_idt;
static uint64_t g_tss;
static uint64_t g_iface;        /* globalna: wskaznik sterownika MP4 */
static uint64_t g_auth_pierwotny;
static int      g_auth_oddane;
static int      g_limit_linii;

/* Statystyki. */
static unsigned long long g_wywolania;
static unsigned long long g_linie;
static unsigned long long g_obce;
static unsigned long long g_bez_bufora;
static unsigned long long g_czytelne;
static unsigned long long g_nieczytelne;
static unsigned long long g_linie_obserwacji;
static unsigned long long g_powtorzenia;
static unsigned long long g_rdzenie_uzbrojone;
static unsigned long long g_rdzenie_odrzucone;
static unsigned long long g_rdzenie_sprawdzone;
static unsigned long long g_cmd_wszystkie;
static unsigned long long g_arg_wszystkie;
static unsigned long long g_bez_polecen;

/* Odstepy czasu miedzy wywolaniami. */
#define GAP_MAX 16
static uint64_t g_gap[GAP_MAX];
static int      g_gap_n;
static uint64_t g_poprzedni_czas;
static int      g_mam_poprzedni;
static uint64_t g_gap_min, g_gap_max;
static unsigned long long g_gap_suma, g_gap_ile;
static uint64_t g_gap_kubelek[5];   /* <1, 1..10, 10..100, 100..1000, >1000 ms */
static uint64_t g_koniec_obserwacji;

/* Rozpoznane polecenia i argumenty. */
#define MAX_POZYCJI 64
typedef struct {
  uint64_t           klucz;
  uint64_t           klucz2;
  unsigned long long ile;
  char               opis[80];
} pozycja_t;

static pozycja_t g_typy_widziane[MAX_POZYCJI];
static int       g_typy_n;
static pozycja_t g_arg_widziane[MAX_POZYCJI];
static int       g_arg_n;
static pozycja_t g_adresy_widziane[MAX_POZYCJI];
static int       g_adresy_n;
static pozycja_t g_rozmiary_widziane[MAX_POZYCJI];
static int       g_rozmiary_n;
static pozycja_t g_rdzenie_widziane[MAX_POZYCJI];
static int       g_rdzenie_n;

/* Bramki. */
static int g_bramka_fw, g_bramka_prolog, g_bramka_idt;
static int g_bramka_samotest, g_samotest_wlaczony;

/* Kanaly robocze: lancuch wlasciwy i lancuch proby (ta sama dlugosc). */
static khook_t  g_hook;
static uint8_t  g_lancuch_buf[0x600];
static uint8_t  g_lancuch_proby[0x600];
static size_t   g_lancuch_len;
static int      g_rdzen_hooka;

static void log_line(const char *fmt, ...);

/* --- czas --- */

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

/* --- log: kazda linia z fflush i fsync, bo konsola bywa niestabilna --- */

static void log_line(const char *fmt, ...) {
  char buf[768];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  printf("%s", buf);
  fflush(stdout);
  if (g_log) {
    fputs(buf, g_log);
    fflush(g_log);
    fsync(fileno(g_log));
  }
}

/* Ten sam log, ale bez powtarzania na standardowe wyjscie (dla blokow tekstu). */
static void log_chunk(const char *tekst) {
  if (!tekst || !tekst[0]) return;
  printf("%s", tekst);
  fflush(stdout);
  if (g_log) {
    fputs(tekst, g_log);
    fflush(g_log);
    fsync(fileno(g_log));
  }
}

/* --- odczyt pamieci jadra: kazdy odczyt idzie przez bramke "readable" --- */

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
  unsigned long vmspace, pmap;
  unsigned long d[2];

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

static int chodz(uint64_t va, int *pcd, int *pwt) {
  static const int poziomy[4] = { 39, 30, 21, 12 };
  uint64_t tab = g_cr3 & PG_FRAME;

  for (int k = 0; k < 4; k++) {
    uint64_t idx = (va >> poziomy[k]) & 0x1FFULL;
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

static int page_stan(uint64_t va, int *pcd, int *pwt) {
  if (!g_mapa_ok) return -1;
  return chodz(va, pcd, pwt);
}

/* Strona obecna i nie jest oknem urzadzenia (PWT/PCD). */
static int readable(uint64_t va) {
  int pcd = 0, pwt = 0;
  if (!g_mapa_ok) return 0;
  if (chodz(va, &pcd, &pwt)) return 0;
  return !(pcd || pwt);
}

static int safe_read(uint64_t va, void *dst, size_t n) {
  if (g_odczytane + n > BUDZET_ODCZYTU) return -1;
  if (!readable(va)) return -1;
  if (kernel_copyout((intptr_t) va, dst, n)) return -1;
  g_odczytane += n;
  return 0;
}

static int safe_read64(uint64_t va, uint64_t *out) {
  return safe_read(va, out, sizeof(*out));
}

static int wskaznik_jadra(uint64_t v) {
  return v >= 0xffff800000000000ULL;
}

/* Odczyt z rozroznieniem bledu (util.c kread64 ignoruje wynik kernel_copyout). */
static int czytaj64(uint64_t adres, uint64_t *out) {
  return kernel_copyout((intptr_t) adres, out, sizeof(*out));
}

static uint64_t swap_auth(uint64_t auth_id) {
  pid_t pid = getpid();
  uint64_t original = kernel_get_ucred_authid(pid);
  kernel_set_ucred_authid(pid, auth_id);
  return original;
}

/* --- opisy typow --- */

static const typ_t *znajdz_typ(uint32_t typ) {
  for (unsigned i = 0; i < sizeof(g_typy) / sizeof(g_typy[0]); i++) {
    if (g_typy[i].typ == typ) return &g_typy[i];
  }
  return NULL;
}

static const char *nazwa_typu(uint32_t typ) {
  const typ_t *t = znajdz_typ(typ);
  return t ? t->nazwa : "NIEZNANE";
}

static const char *opis_typu(uint32_t typ) {
  const typ_t *t = znajdz_typ(typ);
  return t ? t->opis : "typ spoza tabeli, surowa wartosc w linii";
}

/* Czy wartosc wyglada na typ polecenia/odpowiedzi SDBGP (rodzina 0x01 / 0x02). */
static int rodzina_sdbgp(uint32_t typ) {
  return (typ & 0xff000000U) == 0x01000000U || (typ & 0xff000000U) == 0x02000000U;
}

/* --- statystyki --- */

static void policz(pozycja_t *tab, int *n, uint64_t klucz, uint64_t klucz2,
                   const char *opis) {
  for (int i = 0; i < *n; i++) {
    if (tab[i].klucz == klucz && tab[i].klucz2 == klucz2) {
      tab[i].ile++;
      return;
    }
  }
  if (*n < MAX_POZYCJI) {
    tab[*n].klucz = klucz;
    tab[*n].klucz2 = klucz2;
    tab[*n].ile = 1;
    snprintf(tab[*n].opis, sizeof(tab[*n].opis), "%s", opis ? opis : "");
    (*n)++;
  }
}

/* --- lancuch hooka: zapis do rekordu, bez ani jednego wywolania funkcji --- */

static int zbuduj_lancuch(kh_chain_t *chain, uint64_t rec, uint64_t kanal,
                          uint64_t cel) {
  uint64_t g_rdi = kgadget(KERNEL_GADGET_MOV_RAX_RDI);
  uint64_t g_rsi = kgadget(KERNEL_GADGET_MOV_RAX_RSI);
  uint64_t g_rcx = kgadget(KERNEL_GADGET_POP_RCX);
  uint64_t g_rax = kgadget(KERNEL_GADGET_ST_RCX_RAX);
  uint64_t g_rdx = kgadget(KERNEL_GADGET_ST_RCX_RDX);
  uint64_t g_r8  = kgadget(KERNEL_GADGET_POP_R8);
  uint64_t g_st8 = kgadget(KERNEL_GADGET_STORE_RCX_R8);

  /* Bramka: zero w ktoryms z tych miejsc znaczyloby skok jadra pod adres 0.
   * kh_chain_store korzysta z POP_RCX, POP_R8 i STORE_RCX_R8. */
  if (!g_rdi || !g_rsi || !g_rcx || !g_rax || !g_rdx || !g_r8 || !g_st8) {
    log_line("[!] ktorys gadzet jest zerem (rdi=%llx rsi=%llx rcx=%llx rax=%llx"
             " rdx=%llx r8=%llx st8=%llx), nie buduje lancucha\n",
             (unsigned long long) g_rdi, (unsigned long long) g_rsi,
             (unsigned long long) g_rcx, (unsigned long long) g_rax,
             (unsigned long long) g_rdx, (unsigned long long) g_r8,
             (unsigned long long) g_st8);
    return -1;
  }

  /* Co ten lancuch robi i czego nie robi:
   * - zapisuje do rekordu rsi, rdx i rdi (argumenty wywolania) oraz ADRES slotu
   *   z RSP w ramce przerwania, numer kanalu i offset celu,
   * - NIE czyta pamieci pod wskaznikiem, bo zestaw gadzetow tego API nie ma
   *   rozkazu czytajacego. Dlatego pakiet czyta strona uzytkownika przez
   *   kernel_copyout po adresie wyliczonym z rdi (softc), po przejsciu bramki
   *   readable. Tresc pakietu nie zmienia sie w trakcie, bo po wywolaniu
   *   funkcji lezy w buforze sterownika,
   * - magic wpisuje na koncu, a strona uzytkownika zeruje je po odczycie. */

  /* rsi do rekordu, pole +0x10 */
  kh_chain_q(chain, g_rsi);
  kh_chain_q(chain, g_rcx);
  kh_chain_q(chain, rec + 0x10);
  kh_chain_q(chain, g_rax);

  /* rdx do rekordu, pole +0x28 */
  kh_chain_q(chain, g_rcx);
  kh_chain_q(chain, rec + 0x28);
  kh_chain_q(chain, g_rdx);

  /* rdi (softc sterownika) do rekordu, pole +0x20 */
  kh_chain_q(chain, g_rdi);
  kh_chain_q(chain, g_rcx);
  kh_chain_q(chain, rec + 0x20);
  kh_chain_q(chain, g_rax);

  /* Adres slotu RSP z ramki przerwania. Ramka #DB lezy pod jaskinia
   * + KH_OFF_CHAIN_DISP - 0x28 (khook.c, linie 353 do 356), a zapisany RSP pod
   * +0x18 od poczatku ramki (RIP, CS, RFLAGS, RSP, SS). */
  kh_chain_store(chain, rec + 0x18, g_jaskinia + KH_OFF_CHAIN_DISP - 0x28 + 0x18);

  /* numer kanalu, offset celu i magic */
  kh_chain_store(chain, rec + 0x00, kanal);
  kh_chain_store(chain, rec + 0x08, cel);
  kh_chain_store(chain, rec + REC_OFF_MAGIC, REC_MAGIC);

  return chain->err ? -1 : 0;
}

/* Lancuch proby rdzenia: zapisuje tylko numer kanalu i magic, wypelniony
 * gadzetem "ret" do DOKLADNIE tej samej dlugosci co lancuch wlasciwy, zeby
 * ogon lancucha (przywrocenie rdi/rsi/rdx z slotow, RF, iretq) zostal nietkniety. */
static int zbuduj_lancuch_proby(kh_chain_t *chain, size_t dlugosc) {
  uint64_t g_ret = kgadget(KERNEL_GADGET_RET_TRAMP);

  if (!g_ret) return -1;
  kh_chain_init(chain, g_lancuch_proby, sizeof(g_lancuch_proby));
  kh_chain_store(chain, g_rekord + 0x00, HB_ID);
  kh_chain_store(chain, g_rekord + 0x08, CEL_OFFSET);
  kh_chain_store(chain, g_rekord + REC_OFF_MAGIC, HB_MAGIC);
  while (chain->len < dlugosc) {
    if (kh_chain_q(chain, g_ret) != 0) return -1;
  }
  if (chain->len != dlugosc) return -1;
  return 0;
}

/* Uscisk dloni: strona uzytkownika zeruje magic po odczytaniu rekordu. */
static void wyczysc_rekord(void) {
  uint64_t zero = 0;
  kernel_copyin(&zero, (intptr_t) (g_rekord + REC_OFF_MAGIC), sizeof(zero));
}

/* --- rozbior pakietu SDBGP --- */

/* Bufor tekstu dla jednego wywolania, zbierany i wypisywany jednym zapisem. */
typedef struct {
  char   buf[6144];
  size_t len;
  char   sygn[256];
  size_t sygn_len;
  int    polecen;
} raport_t;

static void rap_dodaj(raport_t *r, const char *fmt, ...) {
  va_list ap;
  int n;

  if (r->len + 256 >= sizeof(r->buf)) return;
  va_start(ap, fmt);
  n = vsnprintf(r->buf + r->len, sizeof(r->buf) - r->len, fmt, ap);
  va_end(ap);
  if (n > 0) {
    r->len += (size_t) n;
    if (r->len >= sizeof(r->buf)) r->len = sizeof(r->buf) - 1;
  }
}

static void rap_sygn(raport_t *r, const char *fmt, ...) {
  va_list ap;
  int n;

  if (r->sygn_len + 64 >= sizeof(r->sygn)) return;
  va_start(ap, fmt);
  n = vsnprintf(r->sygn + r->sygn_len, sizeof(r->sygn) - r->sygn_len, fmt, ap);
  va_end(ap);
  if (n > 0) r->sygn_len += (size_t) n;
}

static uint32_t rd32(const unsigned char *d) {
  uint32_t v;
  memcpy(&v, d, sizeof(v));
  return v;
}

static uint64_t rd64(const unsigned char *d) {
  uint64_t v;
  memcpy(&v, d, sizeof(v));
  return v;
}

/* Rozbior jednego polecenia pod offsetem `off` w oknie `dane` (dlugosc n).
 * Zwraca dlugosc polecenia (self_size) albo 0, gdy to nie polecenie. */
static uint32_t rozbierz_polecenie(raport_t *r, const char *etykieta, size_t off,
                                   const unsigned char *dane, size_t n, int loguj) {
  uint32_t self, total, typ, nargs;
  int znane;

  if (off + 0x18 > n) return 0;
  self  = rd32(dane + off);
  total = rd32(dane + off + 4);
  typ   = rd32(dane + off + 8);
  if (self < 0x18 || self > 0x1000 || (self & 7) || total < self || total > 0x100000) {
    return 0;
  }
  znane = rodzina_sdbgp(typ);
  if (!znane) return 0;

  g_cmd_wszystkie++;
  policz(g_typy_widziane, &g_typy_n, typ, 0, nazwa_typu(typ));
  rap_sygn(r, "%08x;", typ);

  nargs = ((typ == SDBGP_READ || typ == SDBGP_WRITE) && self >= 0x20)
              ? rd32(dane + off + 0x1c) : 0;

  if (loguj) {
    rap_dodaj(r, "    [polecenie] %s +0x%zx typ=0x%08x %s (%s)"
                 " self=0x%x total=0x%x flagi=0x%x nr=%u pkt=%u",
              etykieta, off, typ, nazwa_typu(typ), opis_typu(typ),
              self, total, rd32(dane + off + 0x0c), rd32(dane + off + 0x10),
              rd32(dane + off + 0x14));
    if (typ == SDBGP_READ || typ == SDBGP_WRITE) {
      rap_dodaj(r, " arg=%u\n", nargs);
    } else {
      rap_dodaj(r, " arg=- (typ bez argumentow pamieciowych)\n");
    }
    if (!znajdz_typ(typ)) {
      rap_dodaj(r, "      [!] typ NIEZNANE, surowa wartosc 0x%08x\n", typ);
    }
  }

  if ((typ == SDBGP_READ || typ == SDBGP_WRITE) && nargs > 0) {
    unsigned ile = nargs;
    if (ile > ARG_MAX) {
      if (loguj) {
        rap_dodaj(r, "      [!] argumentow %u, loguje pierwsze %d\n", nargs, ARG_MAX);
      }
      ile = ARG_MAX;
    }
    if (off + CMD_ARGS_OFF + (size_t) ile * ARG_LEN > n) {
      if (loguj) {
        rap_dodaj(r, "      [!] argumenty poza oknem odczytu (potrzeba 0x%zx bajtow)\n",
                  off + CMD_ARGS_OFF + (size_t) ile * ARG_LEN);
      }
    } else {
      for (unsigned a = 0; a < ile; a++) {
        const unsigned char *p = dane + off + CMD_ARGS_OFF + (size_t) a * ARG_LEN;
        uint32_t aself = rd32(p);
        uint32_t dostep = rd32(p + 4);
        uint64_t addr = rd64(p + 8);
        uint64_t size = rd64(p + 16);
        char opis[80];

        if (aself != ARG_LEN) {
          if (loguj) {
            rap_dodaj(r, "      [!] argument %u ma self=0x%x, nie 0x%x, pomijam\n",
                      a, aself, ARG_LEN);
          }
          break;
        }
        g_arg_wszystkie++;
        snprintf(opis, sizeof(opis), "adres 0x%llx rozmiar 0x%llx",
                 (unsigned long long) addr, (unsigned long long) size);
        policz(g_arg_widziane, &g_arg_n, addr, size, opis);
        policz(g_adresy_widziane, &g_adresy_n, addr, 0, "");
        policz(g_rozmiary_widziane, &g_rozmiary_n, size, 0, "");
        rap_sygn(r, "%llx:%llx;", (unsigned long long) addr, (unsigned long long) size);
        if (loguj) {
          rap_dodaj(r, "      [argument %u] self=0x%x dostep=0x%x (typ pamieci 0x%x,"
                       " dostep %u) adres=0x%llx rozmiar=0x%llx\n",
                    a, aself, dostep, (dostep >> 8) & 0xffffffU, dostep & 0xffU,
                    (unsigned long long) addr, (unsigned long long) size);
        }
      }
    }
  }
  r->polecen++;
  return self;
}

/* Naglowek pakietu deci5s + przejscie po lancuchu polecen. */
static int rozbierz_pakiet(raport_t *r, const char *etykieta, uint64_t adres,
                           const unsigned char *dane, size_t n, int loguj) {
  uint32_t magic, self, psize, src, dst, proto, seq, ncmd;
  size_t off = HDR_POLEB;
  int ile = 0;

  if (n < HDR_POLEB) return -1;
  magic = rd32(dane);
  if (magic != DECI5S_MAGIC) {
    if (loguj) {
      rap_dodaj(r, "    [pakiet] %s pod 0x%llx: brak magic 0x%08x (jest 0x%08x)"
                   " - to nie pakiet DECI5S\n",
                etykieta, (unsigned long long) adres, DECI5S_MAGIC, magic);
    }
    return -1;
  }
  self  = rd32(dane + 4);
  psize = rd32(dane + 8);
  src   = rd32(dane + 0x0c);
  dst   = rd32(dane + 0x10);
  proto = rd32(dane + 0x14);
  seq   = rd32(dane + 0x30);
  ncmd  = dane[0x3c];

  policz(g_adresy_widziane, &g_adresy_n, adres, 0, "");
  rap_sygn(r, "H%08x:%08x;", psize, ncmd);
  if (loguj) {
    rap_dodaj(r, "    [pakiet] %s pod 0x%llx magic=0x%08x self=0x%x"
                 " rozmiar_pakietu=0x%x src=0x%08x%s dst=0x%08x%s proto=0x%08x%s"
                 " numer=%u polecen=%u\n",
              etykieta, (unsigned long long) adres, magic, self, psize, src,
              src == DECI5S_SRC_KERNEL ? " (jadro)" : "",
              dst, dst == DECI5S_DST_MP4 ? " (MP4/A53)" : "",
              proto, proto == SDBGP_PROTO ? " (SDBGP)"
                   : (proto == SDBGP_PROTO_B ? " (SDBGP wariant B)" : ""),
              seq, ncmd);
  }

  for (int k = 0; k < CMD_MAX && off + 0x18 <= n; k++) {
    uint32_t dl = rozbierz_polecenie(r, etykieta, off, dane, n, loguj);
    uint32_t krok;
    if (!dl) break;
    /* Dalej idzie sie o total_size, nie o self_size: self_size to sam naglowek
     * polecenia (0x18 albo 0x20), a total_size obejmuje argumenty pamieciowe
     * (0x18 kazdy). W obrazie widac to wprost: polecenie odczytu pod +0x58 ma
     * self=0x20, total=0xb0, a nastepne polecenie stoi pod +0x108. */
    krok = rd32(dane + off + 4);
    if (krok < dl || krok > 0x100000) krok = dl;
    off += krok;
    ile++;
  }

  /* Zapas: gdy lancuch po self_size sie nie zgadza, szukamy typow rodzin
   * SDBGP skanem po slowach (bez logowania duplikatow lancucha). */
  if (!ile) {
    for (size_t o = HDR_POLEB; o + 0x18 <= n; o += 4) {
      uint32_t t = rd32(dane + o);
      if (!rodzina_sdbgp(t)) continue;
      if (rozbierz_polecenie(r, etykieta, o - 8, dane, n, loguj)) ile++;
      if (ile >= CMD_MAX) break;
    }
    if (ile && loguj) {
      rap_dodaj(r, "    [i] lancuch po self_size sie nie zlozyl, typy znalezione skanem\n");
    }
  }
  return ile;
}

/* --- deduplikacja po tresci pakietu (opcjonalna) ---
 * Domyslnie payload loguje KAZDE wywolanie, tak jak mowi zlecenie. Funkcja
 * budujaca pakiety bywa jednak wolana w petli z ta sama trescia, a limit to
 * 2000 linii, wiec gdy plik /data/sdbgp.nowe istnieje, do logu idzie tylko
 * pierwsze wystapienie kazdej ROZNEJ tresci (sygnatura z rozpoznanych polecen
 * i argumentow), a powtorzenia liczy podsumowanie i statystyka odstepow czasu
 * (odstepy mierzy sie dla KAZDEGO wywolania, takze pomietego w logu). */

#define WIDZ_TABELA 4096
#define WIDZ_MASKA  (WIDZ_TABELA - 1)

static uint64_t g_widz_klucz[WIDZ_TABELA];
static int      g_widz_zajete;
static int      g_widz_zapchane;
static int      g_tylko_nowe;
static unsigned long long g_powtorzen_tresci;

static uint64_t skrot(const char *s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (unsigned char) s[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}

/* 1 = tresc nowa (logujemy), 0 = powtorzenie. */
static int tresc_nowa(uint64_t k) {
  uint64_t i;
  uint64_t pierwsze_wolne = WIDZ_TABELA;

  if (!g_tylko_nowe) return 1;
  if (k == 0) k = 1;
  if (g_widz_zajete >= WIDZ_TABELA) {
    g_widz_zapchane = 1;
    return 1;
  }
  i = k & WIDZ_MASKA;
  for (int n = 0; n < WIDZ_TABELA; n++) {
    uint64_t j = (i + (uint64_t) n) & WIDZ_MASKA;
    if (g_widz_klucz[j] == 0) {
      if (pierwsze_wolne == WIDZ_TABELA) pierwsze_wolne = j;
      continue;
    }
    if (g_widz_klucz[j] == k) {
      g_powtorzen_tresci++;
      return 0;
    }
  }
  g_widz_klucz[pierwsze_wolne] = k;
  g_widz_zajete++;
  return 1;
}

/* --- obsluga jednego wywolania --- */

static void zapisz_odstep(uint64_t teraz) {
  uint64_t d;

  if (!g_mam_poprzedni) {
    g_mam_poprzedni = 1;
    g_poprzedni_czas = teraz;
    return;
  }
  d = teraz - g_poprzedni_czas;
  g_poprzedni_czas = teraz;
  if (g_gap_n < GAP_MAX) g_gap[g_gap_n] = d;
  g_gap_n++;
  g_gap_suma += d;
  g_gap_ile++;
  if (!g_gap_min || d < g_gap_min) g_gap_min = d;
  if (d > g_gap_max) g_gap_max = d;
  if (d < 1) g_gap_kubelek[0]++;
  else if (d < 10) g_gap_kubelek[1]++;
  else if (d < 100) g_gap_kubelek[2]++;
  else if (d < 1000) g_gap_kubelek[3]++;
  else g_gap_kubelek[4]++;
}

static void obsluz_wywolanie(void) {
  rekord_t rec;
  raport_t rap;
  unsigned char proba[SONDA_BAJTOW];
  unsigned char okno[OKNO_BAJTOW];
  uint64_t rsp = 0, zwrot = 0, ctx = 0, kbuf = 0, ksize = 0, kiommu = 0;
  uint64_t teraz;
  uint64_t klucz;
  int mamy_probe = 0, mamy_okno = 0;
  int rdzen;
  uint64_t off_append = 0;
  size_t i;

  if (kernel_copyout((intptr_t) g_rekord, &rec, sizeof(rec))) {
    log_line("[!] nie moge odczytac rekordu w jaskini pod 0x%llx\n",
             (unsigned long long) g_rekord);
    return;
  }
  if (rec.magic != REC_MAGIC) {
    if (rec.magic != 0 && rec.magic != HB_MAGIC) {
      g_obce++;
      log_line("[!] rekord ma obca wartosc magic 0x%016llx, zeruje\n",
               (unsigned long long) rec.magic);
      wyczysc_rekord();
    }
    return;
  }
  if (rec.cel != CEL_OFFSET) {
    g_obce++;
    log_line("[!] rekord z innego celu (0x%llx zamiast 0x%llx), zeruje\n",
             (unsigned long long) rec.cel, (unsigned long long) CEL_OFFSET);
    wyczysc_rekord();
    return;
  }
  if (g_limit_linii) {
    wyczysc_rekord();
    return;
  }

  if (!g_tylko_nowe) {
    struct stat st;
    if (stat(NOWE_FILE, &st) == 0) {
      g_tylko_nowe = 1;
      log_line("[i] plik %s istnieje: do logu idzie tylko pierwsze wystapienie"
               " kazdej roznej tresci\n", NOWE_FILE);
    }
  }

  g_wywolania++;
  teraz = ms_od_startu();
  rdzen = get_cpu_core();
  zapisz_odstep(teraz);
  policz(g_rdzenie_widziane, &g_rdzenie_n, (uint64_t) rdzen, 0, "");
  memset(&rap, 0, sizeof(rap));

  /* Adres powrotu: rekord trzyma ADRES slotu z RSP w ramce przerwania,
   * a pod nim lezy adres powrotu wolajacego. */
  if (rec.rsp_slot && wskaznik_jadra(rec.rsp_slot)) {
    if (safe_read64(rec.rsp_slot, &rsp) == 0 && wskaznik_jadra(rsp)) {
      (void) safe_read64(rsp, &zwrot);
    }
  }

  /* Argumenty: rdi = softc sterownika, rsi i rdx = dwa nastepne argumenty. */
  ctx = rec.rdi;
  if (ctx && wskaznik_jadra(ctx)) {
    (void) safe_read64(ctx + SOFTC_BUF_VA, &kbuf);
    (void) safe_read64(ctx + SOFTC_BUF_SIZE, &ksize);
    (void) safe_read64(ctx + SOFTC_BUF_IOMMU, &kiommu);
  }

  rap_dodaj(&rap, "#%06llu t=%010llums rdzen=%d funkcja=0x%016llx (obraz+0x%llx)"
                  " rdi=0x%016llx rsi=0x%016llx rdx=0x%016llx powrot=0x%016llx\n",
           g_wywolania, (unsigned long long) teraz, rdzen,
           (unsigned long long) (g_baza_kodu + CEL_OFFSET),
           (unsigned long long) CEL_OFFSET,
           (unsigned long long) rec.rdi, (unsigned long long) rec.rsi,
           (unsigned long long) rec.rdx, (unsigned long long) zwrot);
  rap_sygn(&rap, "rdi=%llx;rsi=%llx;", (unsigned long long) rec.rdi,
           (unsigned long long) rec.rsi);

  if (ctx && wskaznik_jadra(ctx)) {
    uint64_t iface_now = 0;
    (void) safe_read64(g_iface, &iface_now);
    rap_dodaj(&rap, "    [softc] rdi=0x%llx%s bufor=0x%llx rozmiar=0x%llx"
                    " iommu=0x%llx\n",
              (unsigned long long) ctx,
              (iface_now == ctx) ? " (zgadza sie z globalna sterownika)" : "",
              (unsigned long long) kbuf, (unsigned long long) ksize,
              (unsigned long long) kiommu);
  } else {
    rap_dodaj(&rap, "    [!] rdi nie jest wskaznikiem jadra, nie mam skad czytac"
                    " pakietu\n");
  }

  if (!kbuf || !wskaznik_jadra(kbuf)) {
    g_bez_bufora++;
    rap_dodaj(&rap, "    [!] brak bufora pakietow ([softc+0x%llx] = 0x%llx):"
                    " funkcja dopiero go przydziela\n",
              (unsigned long long) SOFTC_BUF_VA, (unsigned long long) kbuf);
  } else {
    /* Sonda 96 bajtow, jak w zleceniu. */
    if (safe_read(kbuf, proba, sizeof(proba)) == 0) {
      char hex[3 * SONDA_BAJTOW + 2];
      char *p = hex;
      for (i = 0; i < sizeof(proba); i++) {
        p += snprintf(p, 4, "%02x ", proba[i]);
      }
      *p = 0;
      mamy_probe = 1;
      g_czytelne++;
      rap_dodaj(&rap, "    [sonda %d B] 0x%llx: %s\n", SONDA_BAJTOW,
                (unsigned long long) kbuf, hex);
    } else {
      int pcd = 0, pwt = 0;
      g_nieczytelne++;
      if (!g_mapa_ok) {
        rap_dodaj(&rap, "    [!] sonda: mapa bezposrednia niedostepna, nie moge"
                        " czytac bufora=0x%llx\n", (unsigned long long) kbuf);
      } else if (page_stan(kbuf, &pcd, &pwt)) {
        rap_dodaj(&rap, "    [!] sonda: strona bufora nieobecna (bramka readable"
                        " odrzuca), bufor=0x%llx\n", (unsigned long long) kbuf);
      } else {
        rap_dodaj(&rap, "    [!] sonda: strona bufora ma PWT=%d PCD=%d (okno"
                        " urzadzenia, odrzucone), bufor=0x%llx\n",
                  pwt, pcd, (unsigned long long) kbuf);
      }
    }

    /* Okno 0: poczatek bufora (wariant "pakiet od podstawy"). */
    if (safe_read(kbuf, okno, sizeof(okno)) == 0) {
      mamy_okno = 1;
      (void) rozbierz_pakiet(&rap, "okno0", kbuf, okno, sizeof(okno), 1);
    }

    /* Okno 1: offset doklejania liczony tak samo jak w jadrze:
     * (packet_size + 7) & ~7, gdzie packet_size to slowo +8 pierwszego pakietu. */
    if (mamy_probe) {
      uint32_t psize = rd32(proba + 8);
      off_append = ((uint64_t) psize + 7ULL) & ~7ULL;
    }
    if (off_append >= 0x40 && off_append < 0x100000 &&
        (!ksize || off_append + sizeof(okno) <= ksize)) {
      uint64_t adres1 = kbuf + off_append;
      if (safe_read(adres1, okno, sizeof(okno)) == 0) {
        (void) rozbierz_pakiet(&rap, "okno1", adres1, okno, sizeof(okno), 1);
      } else {
        rap_dodaj(&rap, "    [i] okno1 pod 0x%llx nieczytelne (bramka readable)\n",
                  (unsigned long long) adres1);
      }
    }
  }

  if (!mamy_okno && !mamy_probe) {
    rap_dodaj(&rap, "    [i] nie udalo sie przeczytac zadnego okna pakietu\n");
  }
  if (rap.polecen == 0) {
    g_bez_polecen++;
    rap_dodaj(&rap, "    [i] w odczytanych oknach nie rozpoznalem zadnego polecenia"
                    " SDBGP (typ rodziny 0x01/0x02 z sensownym self_size)\n");
  }

  /* Sygnatura tresci: rozpoznane polecenia i argumenty, a gdy ich nie ma,
   * sama sonda, zeby deduplikacja nie zjadla roznych przypadkow. */
  if (rap.sygn_len == 0 && mamy_probe) {
    rap_sygn(&rap, "raw:%016llx:%016llx;", (unsigned long long) rd64(proba),
             (unsigned long long) rd64(proba + 8));
  }
  klucz = skrot(rap.sygn, rap.sygn_len);

  if (!tresc_nowa(klucz)) {
    g_powtorzenia++;
    wyczysc_rekord();
    return;
  }

  rap_dodaj(&rap, "    [sygnatura] %s\n", rap.sygn);
  if (g_powtorzenia) {
    rap_dodaj(&rap, "    [i] takich samych tresci pominieto do tej pory: %llu\n",
              g_powtorzenia);
  }
  log_chunk(rap.buf);
  g_linie++;

  if (g_linie >= (unsigned long long) BUDZET_LINII) {
    g_limit_linii = 1;
    log_line("[i] sufit %d linii polecen osiagniety, koncze obserwacje\n", BUDZET_LINII);
  }
  wyczysc_rekord();
}

/* --- obserwacja pol struktury --- */

typedef struct {
  uint64_t wartosc;
  int      znane;
} pole_t;

static void obserwuj_pole(const char *zrodlo, uint64_t baza, uint64_t offset,
                          pole_t *stan, int strona) {
  uint64_t v;

  if (!baza || !wskaznik_jadra(baza)) return;
  if (safe_read64(baza + offset, &v)) return;

  if (!stan->znane) {
    stan->znane = 1;
    stan->wartosc = v;
    if (strona) {
      log_line("[pole] t=%010llums %s = 0x%016llx (strona 0x%llx, pierwszy odczyt)\n",
               (unsigned long long) ms_od_startu(), zrodlo, (unsigned long long) v,
               (unsigned long long) (v >> 12));
    } else {
      log_line("[pole] t=%010llums %s = 0x%016llx (pierwszy odczyt)\n",
               (unsigned long long) ms_od_startu(), zrodlo, (unsigned long long) v);
    }
    return;
  }
  if (v == stan->wartosc) return;
  if (g_linie_obserwacji >= LIMIT_OBSEWACJI) {
    stan->wartosc = v;
    return;
  }
  if (strona) {
    log_line("[pole] t=%010llums %s = 0x%016llx (strona 0x%llx, bylo 0x%016llx"
             " strona 0x%llx)\n",
             (unsigned long long) ms_od_startu(), zrodlo, (unsigned long long) v,
             (unsigned long long) (v >> 12), (unsigned long long) stan->wartosc,
             (unsigned long long) (stan->wartosc >> 12));
  } else {
    log_line("[pole] t=%010llums %s = 0x%016llx (bylo 0x%016llx)\n",
             (unsigned long long) ms_od_startu(), zrodlo, (unsigned long long) v,
             (unsigned long long) stan->wartosc);
  }
  stan->wartosc = v;
  g_linie_obserwacji++;
}

static void obserwuj_pola(void) {
  static pole_t dev_a53io, buf_size, buf_iommu, buf_va;
  static pole_t stan_a, stan_b, stan_c, stan_d;
  static uint64_t ostatni_iface;
  uint64_t iface_now = 0;

  if (!g_mapa_ok) return;

  /* Wskaznik sterownika czytamy za kazdym razem: po attachu moze sie zmienic. */
  if (safe_read64(g_iface, &iface_now) == 0 && iface_now != 0 && wskaznik_jadra(iface_now)) {
    if (iface_now != ostatni_iface) {
      log_line("[pole] t=%010llums wskaznik sterownika MP4 = 0x%016llx (bylo 0x%016llx)\n",
               (unsigned long long) ms_od_startu(), (unsigned long long) iface_now,
               (unsigned long long) ostatni_iface);
      ostatni_iface = iface_now;
      dev_a53io.znane = 0;
      buf_size.znane = 0;
      buf_iommu.znane = 0;
      buf_va.znane = 0;
      stan_a.znane = 0;
      stan_b.znane = 0;
      stan_c.znane = 0;
      stan_d.znane = 0;
    }
    obserwuj_pole("sterownik+0x440 adres urzadzenia A53 (to samo co rejestr)",
                  iface_now, SOFTC_DEV_A53IO, &dev_a53io, 0);
    obserwuj_pole("sterownik+0x6a8 rozmiar bufora pakietow",
                  iface_now, SOFTC_BUF_SIZE, &buf_size, 0);
    obserwuj_pole("sterownik+0x6b0 adres IOMMU bufora pakietow",
                  iface_now, SOFTC_BUF_IOMMU, &buf_iommu, 1);
    obserwuj_pole("sterownik+0x6b8 bufor pakietow (strona: kandydat na bufor"
                  " roboczy/deszyfrowania)", iface_now, SOFTC_BUF_VA, &buf_va, 1);
    obserwuj_pole("sterownik+0x858 pole stanu (zerowane na wejsciu funkcji)",
                  iface_now, SOFTC_STAN_A, &stan_a, 1);
    obserwuj_pole("sterownik+0x860 pole stanu (zerowane na wejsciu funkcji)",
                  iface_now, SOFTC_STAN_B, &stan_b, 1);
    obserwuj_pole("sterownik+0x868 pole stanu (zerowane na wejsciu funkcji)",
                  iface_now, SOFTC_STAN_C, &stan_c, 1);
    obserwuj_pole("sterownik+0x870 pole stanu (zerowane na wejsciu funkcji)",
                  iface_now, SOFTC_STAN_D, &stan_d, 1);
  }
}

/* Zrzut stanu przed uzbrojeniem hooka: sterownik, bufor pakietow i jego pierwsze
 * 96 bajtow z rozbiorem. To punkt odniesienia niezalezny od hooka: od razu
 * widac, czy bufor istnieje i czy parser rozpoznaje w nim polecenia. */
static void zrzut_stanu(void) {
  uint64_t ctx = 0, kbuf = 0, ksize = 0, kiommu = 0;
  unsigned char proba[SONDA_BAJTOW];
  raport_t rap;

  memset(&rap, 0, sizeof(rap));
  if (!g_mapa_ok) {
    log_line("[stan] bez mapy bezposredniej nie moge odczytac stanu sterownika\n");
    return;
  }
  if (safe_read64(g_iface, &ctx) || !wskaznik_jadra(ctx)) {
    log_line("[stan] pod 0x%016llx nie ma wskaznika sterownika\n",
             (unsigned long long) g_iface);
    return;
  }
  log_line("[stan] sterownik MP4 = 0x%016llx (globalna obraz + 0x%llx)\n",
           (unsigned long long) ctx, (unsigned long long) OFF_IFACE_A);
  (void) safe_read64(ctx + SOFTC_BUF_VA, &kbuf);
  (void) safe_read64(ctx + SOFTC_BUF_SIZE, &ksize);
  (void) safe_read64(ctx + SOFTC_BUF_IOMMU, &kiommu);
  log_line("[stan] bufor pakietow [+0x%llx] = 0x%016llx, rozmiar [+0x%llx] = 0x%llx,"
           " iommu [+0x%llx] = 0x%llx\n",
           (unsigned long long) SOFTC_BUF_VA, (unsigned long long) kbuf,
           (unsigned long long) SOFTC_BUF_SIZE, (unsigned long long) ksize,
           (unsigned long long) SOFTC_BUF_IOMMU, (unsigned long long) kiommu);
  if (!kbuf || !wskaznik_jadra(kbuf)) {
    log_line("[stan] bufor jest pusty: funkcja przydzieli go przy pierwszym"
             " wywolaniu i dopiero wtedy pojawi sie co czytac\n");
    return;
  }
  if (safe_read(kbuf, proba, sizeof(proba))) {
    log_line("[stan] nie moge odczytac pierwszych 96 bajtow bufora (bramka readable)\n");
    return;
  }
  {
    char hex[3 * SONDA_BAJTOW + 2];
    char *p = hex;
    for (size_t i = 0; i < sizeof(proba); i++) p += snprintf(p, 4, "%02x ", proba[i]);
    *p = 0;
    log_line("[stan] pierwsze 96 bajtow bufora: %s\n", hex);
  }
  (void) rozbierz_pakiet(&rap, "stan", kbuf, proba, sizeof(proba), 1);
  if (rap.len) log_chunk(rap.buf);
  if (!rap.polecen) {
    log_line("[stan] w buforze nie ma teraz rozpoznanego pakietu (to normalne przed"
             " pierwszym wywolaniem funkcji)\n");
  }
}

/* --- budowa lancucha i jego podmiana w jaskini --- */

static void zdjac_hook(const char *etap) {
  int a, b;

  a = kh_disarm(&g_hook);
  b = kh_restore(&g_hook);
  log_line("[%s] zdjecie hooka: rdzen_w_zamierzeniu=%d rdzen_przy_zdjeciu=%d"
           " kh_disarm = %d, kh_restore = %d\n", etap, g_rdzen_hooka, get_cpu_core(), a, b);
  if (a || b) {
    log_line("[!] UWAGA: zdjecie hooka zglosilo blad, hook moze byc nadal uzbrojony\n");
  }
}

/* Wpisuje lancuch proby w miejsce lancucha uzytkownika i przywraca wlasciwy.
 * Miejsce jest stala khook.c: KH_OFF_BIG_CHAIN + 0x58 (dlugosc bloku zapisu
 * rejestrow), a dlugosc obu lancuchow jest identyczna. */
static int podmien_lancuch(const uint8_t *dane, size_t dlugosc) {
  return kwrite(g_big + 0x58, dane, dlugosc);
}

/* Dowod, ze hook jest uzbrojony na TYM rdzeniu: krok pojedynczy wywoluje #DB
 * na biezacym rdzeniu, a lancuch proby zapisuje magic i numer kanalu. Numer
 * rdzenia bierzemy z sceKernelGetCurrentCpu zaraz po powrocie z kroku. */
static int dowod_rdzenia(void) {
  rekord_t rec;
  int rdzen = get_cpu_core();
  uint64_t zero = 0;

  for (int i = 0; i < 200; i++) {
    sceKernelUsleep(1000);
    if (kernel_copyout((intptr_t) g_rekord, &rec, sizeof(rec)) == 0 &&
        rec.magic == HB_MAGIC) {
      kernel_copyin(&zero, (intptr_t) (g_rekord + REC_OFF_MAGIC), sizeof(zero));
      if (rec.kanal == HB_ID) return rdzen;
      return -1;
    }
  }
  kernel_copyin(&zero, (intptr_t) (g_rekord + REC_OFF_MAGIC), sizeof(zero));
  return -1;
}

/* --- samotest na wolaniu systemowym --- */

static int samotest(void) {
  khook_t hook;
  uint8_t chain_buf[0x400];
  rekord_t rec;
  uint64_t adres;
  int i;

  memset(&hook, 0, sizeof(hook));
  memset(&rec, 0, sizeof(rec));
  adres = kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE;    /* jak w tools/byepervisor/main.c */

  log_line("\n=== samotest na SYS_GETUID + 0xE (adres 0x%016llx) ===\n",
           (unsigned long long) adres);
  if (!adres || !wskaznik_jadra(adres)) {
    log_line("[!] brak adresu SYS_GETUID dla tego firmware\n");
    return -1;
  }

  wyczysc_rekord();
  if (kh_init(&hook, kread, kwrite, g_baza_kodu, g_jaskinia, HOOK_IST)) {
    log_line("[samotest] kh_init nie powiodlo sie\n");
    return -1;
  }
  hook.tss_stride = KH_TSS_STRIDE;
  kh_set_tables(&hook, g_brama_idt, g_tss);
  kh_set_hook_target(&hook, adres);
  hook.oneshot = 1;

  {
    uint64_t g_rdi = kgadget(KERNEL_GADGET_MOV_RAX_RDI);
    uint64_t g_rcx = kgadget(KERNEL_GADGET_POP_RCX);
    uint64_t g_rax = kgadget(KERNEL_GADGET_ST_RCX_RAX);
    kh_chain_t chain;
    kh_chain_init(&chain, chain_buf, sizeof(chain_buf));
    if (!g_rdi || !g_rcx || !g_rax) return -1;
    kh_chain_store(&chain, g_rekord + 0x00, 99);
    kh_chain_store(&chain, g_rekord + 0x08, CEL_OFFSET);
    kh_chain_store(&chain, g_rekord + REC_OFF_MAGIC, REC_MAGIC);
    if (chain.err) return -1;
    if (kh_install(&hook, &chain)) {
      log_line("[samotest] kh_install nie powiodlo sie\n");
      return -1;
    }
  }
  log_line("[samotest] hook na getuid uzbrojony na rdzeniu %d\n", get_cpu_core());
  kh_trigger(&hook);

  for (i = 0; i < 200; i++) {
    (void) getuid();
    if (kernel_copyout((intptr_t) g_rekord, &rec, sizeof(rec)) == 0 && rec.magic == REC_MAGIC) {
      break;
    }
    sceKernelUsleep(200);
  }

  kh_disarm(&hook);
  kh_restore(&hook);

  if (i == 200) {
    log_line("[!] samotest nieudany: rekord nie pojawil sie po 200 wolaniach getuid\n");
    return -1;
  }
  log_line("[samotest] rekord widoczny po %d wolaniach getuid: kanal=%llu rdi=0x%llx\n",
           i + 1, (unsigned long long) rec.kanal, (unsigned long long) rec.rdi);
  if (rec.kanal != 99) {
    log_line("[!] samotest nieudany: w rekordzie numer kanalu %llu zamiast 99\n",
             (unsigned long long) rec.kanal);
    return -1;
  }
  log_line("[samotest] OK, mechanizm hooka potwierdzony na tej konsoli\n");
  return 0;
}

/* --- praca na jednym rdzeniu: przypiecie, instalacja, dowod, obserwacja --- */

typedef struct {
  int         rdzen;
  int         odwrotna;
  uint64_t    czas_ms;
  int         dziala;
} runda_t;

static int przypnij(int rdzen, int odwrotna) {
  int pin = pin_to_core_mask(rdzen, odwrotna);
  int gdzie = get_cpu_core();
  log_line("[rdzen %d] przypiecie (odwrotna maska = %d): pin_to_core_mask = %d,"
           " jestem na rdzeniu %d\n", rdzen, odwrotna, pin, gdzie);
  return gdzie;
}

static void runda_na_rdzeniu(runda_t *r) {
  uint64_t koniec;
  uint64_t ostatnie_pola = 0;
  uint64_t ostatni_stop = 0;
  int dowod;
  int proba;

  r->dziala = 0;

  for (proba = 0; proba < 2; proba++) {
    int gdzie;
    kh_chain_t chain;

    gdzie = przypnij(r->rdzen, proba == 0 ? 0 : 1);
    if (gdzie < 0) continue;

    wyczysc_rekord();
    memset(&g_hook, 0, sizeof(g_hook));
    if (kh_init(&g_hook, kread, kwrite, g_baza_kodu, g_jaskinia, HOOK_IST)) {
      log_line("[rdzen %d] kh_init nie powiodlo sie\n", r->rdzen);
      return;
    }
    g_hook.tss_stride = KH_TSS_STRIDE;
    kh_set_tables(&g_hook, g_brama_idt, g_tss);
    kh_set_core(&g_hook, gdzie);
    g_hook.oneshot = 0;
    kh_set_hook_target(&g_hook, g_baza_kodu + CEL_OFFSET);

    kh_chain_init(&chain, g_lancuch_buf, sizeof(g_lancuch_buf));
    if (zbuduj_lancuch(&chain, g_rekord, KANAL_HOOK, CEL_OFFSET)) {
      log_line("[rdzen %d] lancuch nie zmiescil sie w buforze (dlugosc %llu,"
               " pojemnosc %llu)\n", r->rdzen, (unsigned long long) chain.len,
               (unsigned long long) sizeof(g_lancuch_buf));
      return;
    }
    g_lancuch_len = chain.len;
    if (kh_install(&g_hook, &chain)) {
      log_line("[rdzen %d] kh_install nie powiodlo sie\n", r->rdzen);
      if (g_hook.saved_gate_lo || g_hook.saved_gate_hi) {
        kwrite64(g_brama_idt + 16 * KH_VEC_DB, g_hook.saved_gate_lo);
        kwrite64(g_brama_idt + 16 * KH_VEC_DB + 8, g_hook.saved_gate_hi);
        kwrite64(g_tss + (uint64_t) gdzie * KH_TSS_STRIDE + KH_TSS_IST(HOOK_IST),
                 g_hook.saved_ist);
        log_line("[rdzen %d] przywrocilem brame IDT i wpis IST\n", r->rdzen);
      }
      return;
    }
    g_rdzen_hooka = gdzie;
    g_big = g_jaskinia + KH_OFF_BIG_CHAIN;
    kh_trigger(&g_hook);
    g_rdzenie_uzbrojone++;
    log_line("[rdzen %d] hook uzbrojony (dlugosc lancucha %llu bajtow), DR0 = 0x%016llx\n",
             gdzie, (unsigned long long) g_lancuch_len,
             (unsigned long long) (g_baza_kodu + CEL_OFFSET));

    /* Dowod: podmieniamy TYLKO lancuch uzytkownika (ta sama dlugosc) na lancuch
     * proby, robimy krok pojedynczy i patrzymy, czy rekord ma nasz magic. */
    dowod = -1;
    {
      kh_chain_t pc;
      if (zbuduj_lancuch_proby(&pc, g_lancuch_len) == 0 &&
          podmien_lancuch(pc.buf, pc.len) == 0) {
        kh_trigger(&g_hook);
        dowod = dowod_rdzenia();
        (void) podmien_lancuch(g_lancuch_buf, g_lancuch_len);
      } else {
        log_line("[rdzen %d] nie udalo sie zbudowac lancucha proby\n", r->rdzen);
      }
    }
    g_rdzenie_sprawdzone++;

    log_line("[rdzen %d] dowod krokiem pojedynczym: #DB z rdzenia %d, przypiecie"
             " zglosilo rdzen %d -> %s\n", r->rdzen, dowod, gdzie,
             (dowod == gdzie) ? "przypiecie DZIALA" : "przypiecenie NIE dziala");

    if (dowod != gdzie) {
      zdjac_hook("rdzen odrzucony");
      g_rdzenie_uzbrojone--;
      g_rdzenie_odrzucone++;
      continue;
    }

    /* Przypiecie dziala: obserwujemy wywolania funkcji przez okno czasu. */
    r->dziala = 1;
    koniec = ms_od_startu() + (uint64_t) SDBGP_OKNO_MS;
    while (ms_od_startu() < koniec && !g_limit_linii) {
      rekord_t rec;
      uint64_t teraz = ms_od_startu();

      if (kernel_copyout((intptr_t) g_rekord, &rec, sizeof(rec)) == 0 &&
          rec.magic == REC_MAGIC) {
        obsluz_wywolanie();
      }
      if (teraz - ostatnie_pola >= OKRES_POL_MS) {
        ostatnie_pola = teraz;
        obserwuj_pola();
      }
      if (teraz - ostatni_stop >= OKRES_STOPU_MS) {
        struct stat st;
        ostatni_stop = teraz;
        if (stat(STOP_FILE, &st) == 0) {
          log_line("[i] plik %s istnieje, koncze obserwacje\n", STOP_FILE);
          g_limit_linii = 1;
          break;
        }
      }
      sceKernelUsleep(OKRES_ODPYTYWANIA);
    }
    g_koniec_obserwacji = ms_od_startu();

    zdjac_hook("rdzen zrobiony");
    {
      uint64_t lo2 = 0, hi2 = 0;
      if (czytaj64(g_brama_idt + 16 * KH_VEC_DB, &lo2) == 0 &&
          czytaj64(g_brama_idt + 16 * KH_VEC_DB + 8, &hi2) == 0) {
        log_line("[rdzen %d] kontrola po zdjeciu: brama #DB lo=0x%016llx hi=0x%016llx\n",
                 r->rdzen, (unsigned long long) lo2, (unsigned long long) hi2);
      }
    }
    r->czas_ms = ms_od_startu();
    return;
  }
  log_line("[rdzen %d] zadna proba przypiecia nie dala dowodu, pomijam\n", r->rdzen);
}

/* --- podsumowanie --- */

static void na_sygnal(int sig) {
  (void) sig;
  if (g_hook.installed) {
    kh_disarm(&g_hook);
    kh_restore(&g_hook);
  }
  _exit(9);
}

static void wypisz_liczby(const char *tytul, pozycja_t *tab, int n, int z_kluczem2,
                          int limit) {
  log_line("\n-- %s (%d roznych%s) --\n", tytul, n,
           n > limit ? ", wypisuje czesc" : "");
  for (int i = 0; i < n && i < limit; i++) {
    if (z_kluczem2 && tab[i].klucz2) {
      log_line("   0x%llx / 0x%llx  %llu x  %s\n",
               (unsigned long long) tab[i].klucz, (unsigned long long) tab[i].klucz2,
               tab[i].ile, tab[i].opis);
    } else {
      log_line("   0x%llx  %llu x  %s\n", (unsigned long long) tab[i].klucz,
               tab[i].ile, tab[i].opis);
    }
  }
}

static void podsumowanie(int rdzeni_przerobionych, int brama_wrocila) {
  log_line("\n=== podsumowanie ===\n");
  log_line("czas dzialania: %llu ms (budzet %d s), koniec obserwacji: %llu ms\n",
           (unsigned long long) ms_od_startu(), BUDZET_CALKOWITY_S,
           (unsigned long long) g_koniec_obserwacji);
  log_line("wywolan funkcji widzianych: %llu, linii w logu: %llu (limit %d),"
           " pominietych jako powtorzenie tresci: %llu\n",
           g_wywolania, g_linie, BUDZET_LINII, g_powtorzen_tresci);
  log_line("roznych sygnatur tresci: %d%s\n", g_widz_zajete,
           g_widz_zapchane ? " (tablica zapchana, dalsze ida do logu)" : "");
  log_line("tryb logowania: %s\n",
           g_tylko_nowe ? "tylko pierwsze wystapienie kazdej roznej tresci"
                        : "KAZDE wywolanie (nie bylo pliku .nowe)");
  log_line("polecen rozpoznanych: %llu (argumentow pamieciowych: %llu),"
           " wywolan bez rozpoznanego polecenia: %llu\n",
           g_cmd_wszystkie, g_arg_wszystkie, g_bez_polecen);
  log_line("rekordy obce: %llu, wywolania bez bufora pakietow: %llu\n",
           g_obce, g_bez_bufora);
  log_line("sondy czytelne: %llu, odrzucone przez bramke: %llu, bajtow odczytanych: %llu\n",
           g_czytelne, g_nieczytelne, (unsigned long long) g_odczytane);
  log_line("linie zmian pol struktury: %llu (sufit %d)\n", g_linie_obserwacji,
           LIMIT_OBSEWACJI);
  log_line("rdzenie sprawdzone: %llu, uzbrojone: %llu, odrzucone bez przypiecia: %llu,"
           " przerobione: %d\n", g_rdzenie_sprawdzone, g_rdzenie_uzbrojone,
           g_rdzenie_odrzucone, rdzeni_przerobionych);
  log_line("brama IDT przywrocona: %s\n", brama_wrocila ? "TAK" : "NIE");

  log_line("\n-- odstepy czasu miedzy wywolaniami --\n");
  if (g_gap_ile) {
    log_line("   minimum %llu ms, maksimum %llu ms, srednio %llu ms, pomiarow %llu\n",
             (unsigned long long) g_gap_min, (unsigned long long) g_gap_max,
             (unsigned long long) (g_gap_suma / g_gap_ile), g_gap_ile);
    log_line("   rozklad: <1 ms %llu, 1..10 ms %llu, 10..100 ms %llu,"
             " 100..1000 ms %llu, >1000 ms %llu\n",
             g_gap_kubelek[0], g_gap_kubelek[1], g_gap_kubelek[2],
             g_gap_kubelek[3], g_gap_kubelek[4]);
    log_line("   pierwsze odstepy [ms]:");
    for (int i = 0; i < g_gap_n && i < GAP_MAX; i++) {
      log_line(" %llu", (unsigned long long) g_gap[i]);
    }
    log_line("\n");
  } else {
    log_line("   brak dwoch wywolan, nie ma czego mierzyc\n");
  }

  wypisz_liczby("typy polecen", g_typy_widziane, g_typy_n, 0, MAX_POZYCJI);
  wypisz_liczby("pary adres / rozmiar z argumentow", g_arg_widziane, g_arg_n, 1,
                MAX_POZYCJI);
  wypisz_liczby("adresy (argumenty, naglowki pakietow)", g_adresy_widziane,
                g_adresy_n, 0, 24);
  wypisz_liczby("rozmiary (argumenty)", g_rozmiary_widziane, g_rozmiary_n, 0, 24);
  wypisz_liczby("rdzenie, na ktorych widziano wywolania", g_rdzenie_widziane,
                g_rdzenie_n, 0, 24);

  log_line("\n-- bramki --\n");
  log_line("   firmware 13.60: %s\n", g_bramka_fw ? "TAK" : "NIE");
  log_line("   prolog celu zgodny ze zrzutem: %s\n", g_bramka_prolog ? "TAK" : "NIE");
  log_line("   brama IDT, wpis IST i jaskinia: %s\n", g_bramka_idt ? "TAK" : "NIE");
  if (!g_samotest_wlaczony) {
    log_line("   samotest: wylaczony w budowie\n");
  } else {
    log_line("   samotest: %s\n", g_bramka_samotest ? "OK" : "NIEUDANY");
  }

  log_line("\n-- co ten hook widzi, a czego nie --\n");
  log_line("   Cel: obraz + 0x%llx, czyli funkcja budujaca pakiety SDBGP.\n",
           (unsigned long long) CEL_OFFSET);
  log_line("   W niej leza wszystkie trzy miejsca ze zlecenia:\n");
  log_line("     +0xc292be  mov qword [rcx+0x60], 0x01040021  (odczyt, pakiet od podstawy)\n");
  log_line("     +0xc296c8  mov qword [rcx+rsi+0x48], 0x01040021  (odczyt, doklejany)\n");
  log_line("     +0xc292a7  mov qword [rcx+0x48], 0x01010010  (konfiguracja)\n");
  log_line("   Zapisu 0x01040031 nie ma w tym obrazie ani razu (skan calego pliku),\n");
  log_line("   wiec jego brak w logu nie znaczy, ze cos zniknelo.\n");
  log_line("   Hook stoi na WEJSCIU funkcji, bo w miejscach +0xc292be i +0xc296c8\n");
  log_line("   rejestr rcx trzyma adres pakietu, a blok zapisu rejestrow w khook.c\n");
  log_line("   klobruje rcx; pakiet jest wiec czytany z bufora [softc+0x6b8]\n");
  log_line("   po wywolaniu, przez bramke readable, w dwoch oknach: od podstawy\n");
  log_line("   bufora i pod offsetem doklejania (packet_size + 7) & ~7.\n");
  log_line("koniec\n");
}

/* --- main --- */

int main(void) {
  uint64_t fw, idt, tss, jaskinia, brama_lo, brama_hi;
  unsigned char prolog[CEL_PROLOG_LEN];
  int rdzeni_przerobionych = 0;
  int brama_wrocila = 0;
  int kod = 0;

  memset(&g_hook, 0, sizeof(g_hook));
  g_start_ms = pobierz_ms();

  signal(SIGINT, na_sygnal);
  signal(SIGTERM, na_sygnal);
  signal(SIGHUP, na_sygnal);

  g_log = fopen(OUT_LOG, "w");
  if (!g_log) {
    printf("[!] nie moge otworzyc %s: %s\n", OUT_LOG, strerror(errno));
    return 1;
  }

  log_line("sdbgp 1.0, hook jadra na funkcji budujacej pakiety SDBGP dla A53\n");
  log_line("API z tools/byepervisor: kh_init, kh_set_tables, kh_set_core, kh_set_hook_target,\n");
  log_line("kh_install, kh_trigger, kh_disarm, kh_restore (khook.c, main.c)\n");
  log_line("cel: obraz + 0x%llx (wejscie funkcji), okno na rdzen: %d ms\n",
           (unsigned long long) CEL_OFFSET, SDBGP_OKNO_MS);
  log_line("limit linii polecen: %d, budzet czasu: %d s, budzet odczytu: %llu bajtow\n",
           BUDZET_LINII, BUDZET_CALKOWITY_S, (unsigned long long) BUDZET_ODCZYTU);
  log_line("tryb logowania: kazde wywolanie; plik %s przelacza na same nowe tresci\n",
           NOWE_FILE);

  fw = kernel_get_fw_version();
  log_line("firmware: 0x%08llx\n", (unsigned long long) fw);
  if ((fw & 0xffff0000ULL) != 0x13600000ULL) {
    log_line("[!] bramka firmware nie przeszla: offsety znamy tylko dla 13.60, koncze\n");
    fclose(g_log);
    return 2;
  }
  g_bramka_fw = 1;

  g_auth_pierwotny = swap_auth(SYSCORE_AUTH_ID);
  log_line("identyfikator uprawnien: bylo 0x%016llx, jest 0x%016llx\n",
           (unsigned long long) g_auth_pierwotny, (unsigned long long) SYSCORE_AUTH_ID);

  if (init_map()) {
    g_mapa_ok = 0;
    log_line("[!] nie udalo sie ustalic mapy bezposredniej i cr3: nie bede czytal\n");
    log_line("    pakietow ani pol sterownika (bramka readable niedostepna)\n");
  } else {
    g_mapa_ok = 1;
    log_line("mapa bezposrednia: 0x%016llx, cr3: 0x%016llx\n",
             (unsigned long long) g_dmap, (unsigned long long) g_cr3);
  }

  g_baza_kodu = (uint64_t) KERNEL_ADDRESS_TEXT_BASE;
  log_line("baza kodu jadra w tym rozruchu: 0x%016llx\n", (unsigned long long) g_baza_kodu);
  log_line("baza obrazu w zrzucie:           0x%016llx\n", (unsigned long long) REF_TEXT_BASE);
  log_line("przesuniecie KASLR:              0x%016llx\n",
           (unsigned long long) (g_baza_kodu - REF_TEXT_BASE));

  if (g_baza_kodu < 0xffffffff80000000ULL || (g_baza_kodu & 0xfff)) {
    log_line("[!] baza kodu jadra wyglada nierealnie, koncze bez zakladania hooka\n");
    kod = 4;
    goto sprzatanie;
  }

  g_iface = g_baza_kodu + OFF_IFACE_A;
  log_line("globalna wskaznika sterownika:  0x%016llx (offset 0x%llx)\n",
           (unsigned long long) g_iface, (unsigned long long) OFF_IFACE_A);

  /* Bramka 1: czy pod wyliczonym adresem jest naprawde funkcja budujaca pakiety. */
  {
    uint64_t adres = g_baza_kodu + CEL_OFFSET;
    if (kernel_copyout((intptr_t) adres, prolog, sizeof(prolog))) {
      log_line("[!] nie moge odczytac kodu pod 0x%016llx, koncze\n",
               (unsigned long long) adres);
      kod = 4;
      goto sprzatanie;
    }
    if (memcmp(prolog, g_cel_prolog, sizeof(prolog))) {
      log_line("[!] bramka prologu nie przeszla dla funkcji pod 0x%016llx\n",
               (unsigned long long) adres);
      log_line("    jest:  ");
      for (unsigned i = 0; i < sizeof(prolog); i++) log_line(" %02x", prolog[i]);
      log_line("\n    ma byc:");
      for (unsigned i = 0; i < sizeof(prolog); i++) log_line(" %02x", g_cel_prolog[i]);
      log_line("\n    koncze bez zakladania hooka\n");
      kod = 4;
      goto sprzatanie;
    }
    log_line("[bramka] funkcja budujaca pakiety pod 0x%016llx: 24 bajty prologu"
             " zgodne ze zrzutem\n", (unsigned long long) adres);
  }
  g_bramka_prolog = 1;

  /* Bramka 2: brama IDT, wpis IST i jaskinia. */
  idt = kdlsym(KERNEL_SYM_IDT_ARRAY);
  tss = kdlsym(KERNEL_SYM_COMMON_TSS);
  jaskinia = kdlsym(KERNEL_SYM_DATA_CAVE);
  brama_lo = 0;
  brama_hi = 0;

  if (!wskaznik_jadra(idt) || !wskaznik_jadra(tss) || !wskaznik_jadra(jaskinia)) {
    log_line("[!] brak ktoregos adresu jadra (IDT 0x%016llx, TSS 0x%016llx,"
             " jaskinia 0x%016llx), koncze\n",
             (unsigned long long) idt, (unsigned long long) tss,
             (unsigned long long) jaskinia);
    kod = 4;
    goto sprzatanie;
  }
  if (czytaj64(idt + 16 * KH_VEC_DB, &brama_lo) ||
      czytaj64(idt + 16 * KH_VEC_DB + 8, &brama_hi)) {
    log_line("[!] nie moge odczytac bramy #DB, koncze bez zakladania hooka\n");
    kod = 4;
    goto sprzatanie;
  }
  if (!(brama_lo & (1ULL << 47))) {
    log_line("[!] brama #DB nie ma bitu obecnosci, koncze bez zakladania hooka\n");
    kod = 4;
    goto sprzatanie;
  }
  {
    unsigned char test[0x40];
    if (kernel_copyout((intptr_t) jaskinia, test, sizeof(test)) == 0 &&
        kernel_copyout((intptr_t) (jaskinia + KH_OFF_BIG_CHAIN), test, sizeof(test)) == 0) {
      log_line("[bramka] jaskinia danych czytelna pod 0x%016llx i 0x%016llx\n",
               (unsigned long long) jaskinia,
               (unsigned long long) (jaskinia + KH_OFF_BIG_CHAIN));
    } else {
      log_line("[!] jaskinia danych nieczytelna, koncze bez zakladania hooka\n");
      kod = 4;
      goto sprzatanie;
    }
  }
  g_bramka_idt = 1;

  log_line("IDT: 0x%016llx, TSS: 0x%016llx, jaskinia: 0x%016llx\n",
           (unsigned long long) idt, (unsigned long long) tss,
           (unsigned long long) jaskinia);
  log_line("brama #DB przed hookiem: lo=0x%016llx hi=0x%016llx\n",
           (unsigned long long) brama_lo, (unsigned long long) brama_hi);

  g_brama_idt = idt;
  g_tss = tss;
  g_jaskinia = jaskinia;
  g_big = jaskinia + KH_OFF_BIG_CHAIN;
  g_rekord = jaskinia + REC_OFF;

  log_line("rekord: 0x%016llx (magic 0x%016llx), lancuch uzytkownika w jaskini pod"
           " 0x%016llx + 0x58\n",
           (unsigned long long) g_rekord, (unsigned long long) REC_MAGIC,
           (unsigned long long) g_big);

  /* Punkt odniesienia bez hooka: stan sterownika i bufora pakietow. */
  obserwuj_pola();
  zrzut_stanu();

#if SDBGP_SAMOTEST
  g_samotest_wlaczony = 1;
  if (samotest()) {
    log_line("[!] samotest nieudany: NIE zakladam hooka na funkcji budujacej pakiety\n");
    g_bramka_samotest = 0;
    kod = 3;
    goto sprzatanie;
  }
  g_bramka_samotest = 1;
#else
  log_line("[i] samotest wylaczony w budowie\n");
#endif

  log_line("\n=== obchod rdzeni: szukam tego, na ktorym da sie uzbroic hook ===\n");
  for (int rdzen = 0; rdzen < SDBGP_RDZENIE_MAX; rdzen++) {
    runda_t r;

    if (g_limit_linii || ms_od_startu() >= (uint64_t) BUDZET_CALKOWITY_S * 1000ULL) {
      log_line("[i] budzet wyczerpany, koncze obchod\n");
      break;
    }
    memset(&r, 0, sizeof(r));
    r.rdzen = rdzen;
    log_line("\n--- rdzen %d ---\n", rdzen);
    runda_na_rdzeniu(&r);
    if (r.dziala) {
      rdzeni_przerobionych++;
      log_line("[rdzen %d] obserwacja zakonczona, wywolan w logu: %llu\n",
               rdzen, g_linie);
    }
  }

  /* Kontrola bramy IDT po wszystkich rundach. */
  {
    uint64_t lo2 = 0, hi2 = 0;
    if (czytaj64(g_brama_idt + 16 * KH_VEC_DB, &lo2) ||
        czytaj64(g_brama_idt + 16 * KH_VEC_DB + 8, &hi2)) {
      log_line("[!] nie moge odczytac bramy #DB po zdjeciu hookow\n");
      brama_wrocila = 0;
    } else if (lo2 == brama_lo && hi2 == brama_hi) {
      log_line("[kontrola] brama #DB przywrocona do wartosci pierwotnej\n");
      brama_wrocila = 1;
    } else {
      log_line("[!] brama #DB NIE wrocila: lo=0x%016llx hi=0x%016llx (bylo 0x%016llx"
               " 0x%016llx)\n", (unsigned long long) lo2, (unsigned long long) hi2,
               (unsigned long long) brama_lo, (unsigned long long) brama_hi);
      brama_wrocila = 0;
    }
  }

sprzatanie:
  if (g_hook.installed) {
    log_line("[!] hook byl nadal zainstalowany, zdejmuje go przed wyjsciem\n");
    zdjac_hook("sprzatanie");
  }
  if (!g_auth_oddane) {
    kernel_set_ucred_authid(getpid(), g_auth_pierwotny);
    g_auth_oddane = 1;
  }
  log_line("identyfikator uprawnien przywrocony na 0x%016llx\n",
           (unsigned long long) g_auth_pierwotny);

  podsumowanie(rdzeni_przerobionych, brama_wrocila);
  fclose(g_log);
  return kod;
}
