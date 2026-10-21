/*
 * Test parsera pakietow SDBGP z tools/sdbgp/sdbgp.c.
 *
 * Ten plik to tylko rusztowanie: stale, tabele typow i main z pakietami
 * wzorcowymi. Sama logika parsera NIE jest tu kopiowana, tylko wycinana
 * z sdbgp.c przez test-parser.sh (od znacznika "--- rozbior pakietu SDBGP ---"
 * do "--- deduplikacja po tresci pakietu ---"), wiec testowana jest realna
 * tresc z payloadu.
 *
 * Pakiety wzorcowe odtwarzaja to, co jadro naprawde wpisuje do bufora
 * (z deasemblacji obraz+0xc29234 i obraz+0xc29611):
 *   wariant A: pakiet od podstawy bufora, GET_CONF + READ z szescioma argumentami
 *   wariant B: pakiet doklejany pod offsetem, READ z trzema argumentami
 * oraz przypadek bez magic i polecenie z typu spoza tabeli.
 *
 * Uruchomienie: wsl -d Debian -- bash tools/sdbgp/test-parser.sh
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>

/* --- stale potrzebne parserowi (te same wartosci co w sdbgp.c) --- */
#define DECI5S_MAGIC      0x73354450U
#define DECI5S_SRC_KERNEL 0x80ff0180U
#define DECI5S_DST_MP4    0x80ff0201U
#define SDBGP_PROTO       0x20000201U
#define SDBGP_PROTO_B     0x20000200U
#define SDBGP_READ        0x01040021U
#define SDBGP_WRITE       0x01040031U
#define SDBGP_CONF        0x01010010U
#define HDR_POLEB         0x40U
#define CMD_ARGS_OFF      0x20U
#define ARG_LEN           0x18U
#define ARG_MAX           16
#define CMD_MAX           16
#define MAX_POZYCJI       64

typedef struct {
  uint32_t    typ;
  const char *nazwa;
  const char *opis;
} typ_t;

static const typ_t g_typy[] = {
  { SDBGP_READ,  "SDBGP_READ_MEMORY",  "odczyt pamieci A53" },
  { SDBGP_CONF,  "SDBGP_GET_CONF",     "konfiguracja A53" },
  { SDBGP_WRITE, "SDBGP_WRITE_MEMORY", "zapis pamieci A53" },
  { 0x01050020U, "SDBGP_0x01050020",   "polecenie z lista identyfikatorow regionow" },
  { 0x01050030U, "SDBGP_0x01050030",   "polecenie z lista identyfikatorow regionow" },
  { 0x01200021U, "SDBGP_0x01200021",   "polecenie nieustalone" },
  { 0x02040021U, "SDBGP_RES_READ",     "odpowiedz odczytu" },
  { 0x02010010U, "SDBGP_RES_CONF",     "odpowiedz konfiguracji" },
};

typedef struct {
  uint64_t           klucz;
  uint64_t           klucz2;
  unsigned long long ile;
  char               opis[80];
} pozycja_t;

static unsigned long long g_cmd_wszystkie;
static unsigned long long g_arg_wszystkie;
static pozycja_t g_typy_widziane[MAX_POZYCJI];
static int       g_typy_n;
static pozycja_t g_arg_widziane[MAX_POZYCJI];
static int       g_arg_n;
static pozycja_t g_adresy_widziane[MAX_POZYCJI];
static int       g_adresy_n;
static pozycja_t g_rozmiary_widziane[MAX_POZYCJI];
static int       g_rozmiary_n;

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

static int rodzina_sdbgp(uint32_t typ) {
  return (typ & 0xff000000U) == 0x01000000U || (typ & 0xff000000U) == 0x02000000U;
}

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

/* --- w sdbgp.c log_chunk pisze do pliku; w tescie tylko na ekran --- */
static void log_chunk(const char *tekst) {
  if (tekst) fputs(tekst, stdout);
}

/* --- od tego miejsca wkleja sie wyciagniety z sdbgp.c blok parsera --- */
#include "sdbgp-parser.inc"

/* --- pakiety wzorcowe --- */

static unsigned char g_bufor[0x600];

static void wpisz32(size_t off, uint32_t v) { memcpy(g_bufor + off, &v, 4); }
static void wpisz64(size_t off, uint64_t v) { memcpy(g_bufor + off, &v, 8); }

static void naglowek(size_t baza, uint32_t packet_size, uint32_t proto,
                     uint32_t seq, uint8_t ncmd) {
  wpisz32(baza + 0x00, DECI5S_MAGIC);
  wpisz32(baza + 0x04, 0x28);
  wpisz32(baza + 0x08, packet_size);
  wpisz32(baza + 0x0c, DECI5S_SRC_KERNEL);
  wpisz32(baza + 0x10, DECI5S_DST_MP4);
  wpisz32(baza + 0x14, proto);
  wpisz64(baza + 0x20, 0x0000000100000002ULL);   /* znacznik czasu */
  wpisz32(baza + 0x28, 0x18);
  wpisz32(baza + 0x2c, 0x18);
  wpisz32(baza + 0x30, seq);
  wpisz32(baza + 0x34, 0);
  wpisz32(baza + 0x38, 0);
  g_bufor[baza + 0x3c] = ncmd;
}

static void polecenie(size_t baza, uint32_t self, uint32_t total, uint32_t typ,
                      uint32_t nargs) {
  wpisz32(baza + 0x00, self);
  wpisz32(baza + 0x04, total);
  wpisz32(baza + 0x08, typ);
  wpisz32(baza + 0x0c, 0);
  wpisz32(baza + 0x10, 1);
  wpisz32(baza + 0x14, 0);
  wpisz32(baza + 0x18, 0);
  wpisz32(baza + 0x1c, nargs);
}

static void argument(size_t baza, uint64_t addr, uint64_t size) {
  wpisz32(baza + 0x00, 0x18);
  wpisz32(baza + 0x04, 0x02010001);   /* typ pamieci PA_TO_EL3, dostep 1 */
  wpisz64(baza + 0x08, addr);
  wpisz64(baza + 0x10, size);
}

static int g_bledy;

static void sprawdz(const char *co, long long jest, long long ma_byc) {
  int ok = (jest == ma_byc);
  printf("  %-58s %-14lld %-14lld %s\n", co, jest, ma_byc, ok ? "OK" : "BLAD");
  if (!ok) g_bledy++;
}

/* Wyciaga z tekstu raportu wartosc po podanym kluczu: pierwsza albo ostatnia.
 * Przyklady kluczy: "adres=0x" (szesnastkowo), "arg=" (dziesietnie). */
static long long z_raportu(const char *tekst, const char *klucz, int szesnastkowo,
                           int ostatnia) {
  const char *p = tekst;
  const char *trafienie = NULL;
  while ((p = strstr(p, klucz)) != NULL) {
    trafienie = p + strlen(klucz);
    if (!ostatnia) break;
    p = trafienie;
  }
  if (!trafienie) return -1;
  return szesnastkowo ? (long long) strtoll(trafienie, NULL, 16)
                      : strtoll(trafienie, NULL, 10);
}

int main(void) {
  raport_t rap;

  /* Wariant A: pakiet od podstawy bufora (obraz+0xc29234). */
  naglowek(0x000, 0x220, SDBGP_PROTO_B, 7, 3);
  polecenie(0x040, 0x18, 0x18, SDBGP_CONF, 0);
  polecenie(0x058, 0x20, 0xb0, SDBGP_READ, 6);
  argument(0x078, 0x0000000000000000ULL, 0x1b000ULL);
  argument(0x090, 0x000000000001b000ULL, 0x0d000ULL);
  argument(0x0a8, 0x0000000000062000ULL, 0x03000ULL);
  argument(0x0c0, 0x0000000000068000ULL, 0x01000ULL);
  argument(0x0d8, 0x0000000000085000ULL, 0x31000ULL);
  argument(0x0f0, 0x00000000000b6000ULL, 0x0a000ULL);
  polecenie(0x108, 0x28, 0x150, 0x01050020U, 2);
  wpisz64(0x110, 0x01050020ULL);
  wpisz64(0x118, 2);
  wpisz64(0x120, 0xffffffffffffffffULL);

  /* Wariant B: pakiet doklejany pod offsetem (obraz+0xc29611). */
  naglowek(0x220, 0x28, SDBGP_PROTO, 8, 2);
  polecenie(0x260, 0x20, 0x68, SDBGP_READ, 3);
  argument(0x280, 0x0000000000028000ULL, 0x3a000ULL);
  argument(0x298, 0x0000000000065000ULL, 0x03000ULL);
  argument(0x2b0, 0x0000000000069000ULL, 0x1c000ULL);
  polecenie(0x2c8, 0x28, 0x60, 0x01050020U, 1);
  wpisz64(0x2d0, 0x01050020ULL);
  wpisz64(0x2d8, 1);
  wpisz64(0x2e0, 0xffffffffffffffffULL);

  printf("=== okno0: pakiet od podstawy bufora (wariant A) ===\n");
  memset(&rap, 0, sizeof(rap));
  {
    int ile = rozbierz_pakiet(&rap, "okno0", 0xffffffffc3a69000ULL, g_bufor, 0x200, 1);
    log_chunk(rap.buf);
    sprawdz("liczba rozpoznanych polecen w oknie0", ile, 3);
    sprawdz("liczba argumentow pamieciowych w oknie0", (long long) g_arg_wszystkie, 6);
    sprawdz("polecen READ w oknie0", (long long) g_typy_widziane[0].ile >= 1, 1);
  }

  printf("\n=== okno1: pakiet doklejany pod offsetem 0x220 (wariant B) ===\n");
  memset(&rap, 0, sizeof(rap));
  {
    int ile = rozbierz_pakiet(&rap, "okno1", 0xffffffffc3a69220ULL, g_bufor + 0x220,
                              0x200, 1);
    log_chunk(rap.buf);
    sprawdz("liczba rozpoznanych polecen w oknie1", ile, 2);
    sprawdz("pierwszy adres odczytu z okna1",
            z_raportu(rap.buf, "adres=0x", 1, 0), 0x28000);
    sprawdz("pierwszy rozmiar odczytu z okna1",
            z_raportu(rap.buf, "rozmiar=0x", 1, 0), 0x3a000);
    sprawdz("liczba argumentow w oknie1 (arg=3)",
            z_raportu(rap.buf, "arg=", 0, 0), 3);
    sprawdz("ostatni adres odczytu z okna1",
            z_raportu(rap.buf, "adres=0x", 1, 1), 0x69000);
    sprawdz("ostatni rozmiar odczytu z okna1",
            z_raportu(rap.buf, "rozmiar=0x", 1, 1), 0x1c000);
    sprawdz("liczba argumentow pamieciowych razem (6 z okna0 + 3 z okna1)",
            (long long) g_arg_wszystkie, 9);
  }

  printf("\n=== typ spoza tabeli: musi byc NIEZNANE z surowa wartoscia ===\n");
  memset(&rap, 0, sizeof(rap));
  {
    unsigned char kopia[0x200];
    memcpy(kopia, g_bufor + 0x220, sizeof(kopia));
    memcpy(kopia + 0x48, "\x55\x05\x05\x01", 4);   /* 0x01050555 */
    int ile = rozbierz_pakiet(&rap, "nieznany", 0xffffffffc3a69220ULL, kopia,
                              sizeof(kopia), 1);
    log_chunk(rap.buf);
    sprawdz("polecenie rozpoznane jako rodzina SDBGP", ile >= 1, 1);
    sprawdz("w raporcie slowo NIEZNANE", strstr(rap.buf, "NIEZNANE") != NULL, 1);
    sprawdz("w raporcie surowa wartosc 0x01050555",
            strstr(rap.buf, "0x01050555") != NULL, 1);
  }

  printf("\n=== brak magic: parser nie moze udawac pakietu ===\n");
  memset(&rap, 0, sizeof(rap));
  {
    unsigned char kopia[0x200];
    memset(kopia, 0xAA, sizeof(kopia));
    int ile = rozbierz_pakiet(&rap, "smieci", 0xffffffffc3a69000ULL, kopia,
                              sizeof(kopia), 1);
    log_chunk(rap.buf);
    sprawdz("brak rozpoznanych polecen", ile <= 0, 1);
    sprawdz("w raporcie brak magic", strstr(rap.buf, "brak magic") != NULL, 1);
  }

  printf("\n=== podsumowanie testu ===\n");
  printf("  polecen rozpoznanych lacznie: %llu, argumentow: %llu\n",
         g_cmd_wszystkie, g_arg_wszystkie);
  printf("  typy widziane: ");
  for (int i = 0; i < g_typy_n; i++) {
    printf("%s(0x%08llx)=%llu ", g_typy_widziane[i].opis,
           (unsigned long long) g_typy_widziane[i].klucz, g_typy_widziane[i].ile);
  }
  printf("\n  pary adres/rozmiar:\n");
  for (int i = 0; i < g_arg_n; i++) {
    printf("    adres 0x%llx rozmiar 0x%llx  %llu x\n",
           (unsigned long long) g_arg_widziane[i].klucz,
           (unsigned long long) g_arg_widziane[i].klucz2, g_arg_widziane[i].ile);
  }
  printf("\n%s (%d bledow)\n", g_bledy ? "TEST NIEUDANY" : "TEST OK", g_bledy);
  return g_bledy ? 1 : 0;
}
