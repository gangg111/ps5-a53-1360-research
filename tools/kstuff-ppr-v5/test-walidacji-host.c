/* Test funkcjonalny walidacji PPR i zapisu jaskin A53, na hoscie (v5).
 *
 * Modul ppr_patch.c nie zna API jadla PS5: dostaje transport przez strukture
 * ppr_patch_transport (odczyt, zapis, log). Podstawiamy transport w pamieci,
 * ktory zachowuje sie jak SDBGP na 13.60:
 *   - pamiec A53 to 768 kB SRAM (0x0..0xBFFFF),
 *   - odczyt albo zapis pod adresem 0xC0000 i wyzej konczy sie bledem
 *     "A53 read 0x... response validation failed", dokladnie jak na konsoli,
 *   - tryb "zjadaj_zapisy" odpowiada zmierzonemu zachowaniu 13.60: transport
 *     zwraca 0 (A53 potwierdzila zlecenie), ale pamiec sie nie zmienia,
 *   - tryb "zjadaj_powyzej" zjada tylko zapisy dluzsze niz N bajtow, czyli
 *     odtwarza hipoteze limitu dlugosci jednego polecenia zapisu.
 *
 * Nowosc v5: jaskinia plaintext lezy pod PA 0x5E000 (nie 0x61F50), a test
 * sprawdza, ze (a) przy sprawnym zapisie instaluje sie pod nowym adresem,
 * (b) przy zjedzonych zapisach klog podaje oba adresy prob i werdykt,
 * (c) przy limicie 32 B na jedno polecenie zapis porcjami ratuje instalacje.
 *
 * Uzycie:
 *   ./test-walidacji-host <obraz-a53.bin>
 * Kod wyjscia: 0 gdy wszystkie scenariusze przechodza.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ppr_patch.h"

#define OKNO_SRAM 0xC0000u
#define FIRMWARE 0x13600000u

#define LOG_MAX 160
#define LOG_DLUGOSC 512

/* Slowa po latce z tools/kstuff-ppr-v5/include/ppr_patch_1360_v5.h (tabela
 * powstala niezaleznie, z obrazu A53 i profilu v5). */
static const struct {
    uint64_t pa;
    uint32_t stock;
    uint32_t nowe;
    const char *nazwa;
} STRONY[] = {
    { 0x04A120, 0x94004611U, 0x94005F78U, "call[0]" },
    { 0x04B860, 0x94004041U, 0x940059A8U, "call[1]" },
    { 0x057C14, 0x97FF4D44U, 0x940028C6U, "aes_site[0]" },
    { 0x057D4C, 0x97FF4CF6U, 0x94002878U, "aes_site[1]" },
    { 0x05BC00, 0x97FFF3B3U, 0x94000900U, "sha_auth_site" },
};
#define ILE_STRON (sizeof(STRONY) / sizeof(STRONY[0]))

/* Adresy jaskin w v5: kod zostaje w ogonie obrazu, dane ida w wypelnienie. */
#define JASKINIA_RUNTIME_PA 0x061F00u
#define JASKINIA_PLAINTEXT_PA 0x05E000u
#define JASKINIA_RUNTIME_SLOWO0 0xB9401BF0U
#define JASKINIA_PLAINTEXT_SLOWO0 0x711FF8FFU
/* Pierwsze slowo jaskini plaintext to CMP, wiec pod nowym adresem ma byc
 * dokladnie to samo slowo, co pod starym: tresc jaskini nie zalezy od adresu,
 * zmieniaja sie tylko galezie (indeksy 7, 28, 33). Wartosci galezi sa
 * z tools/kstuff-ppr-v5/include/ppr_patch_1360_v5.h (a53p_plaintext[7]). */
#define JASKINIA_PLAINTEXT_SLOWO0 0x711FF8FFU
#define JASKINIA_PLAINTEXT_SLOWO7 0x97FFEA6DU

struct symulacja {
    uint8_t *ram;
    long odczyty;
    long zapisy;
    long poza_oknem;
    int zjadaj_zapisy;      /* zapis wraca 0, ale nie trafia do pamieci */
    uint32_t zjadaj_powyzej;/* >0: zjadaj tylko zapisy dluzsze niz tyle B */
    uint32_t max_czesc;     /* najwiekszy przyjety zapis (do raportu) */
};

static char g_logi[LOG_MAX][LOG_DLUGOSC];
static int g_ile_logow;

static void wyczysc_log(void) {
    g_ile_logow = 0;
}

static void zapisz_log(const char *tekst) {
    if (g_ile_logow >= LOG_MAX)
        return;
    snprintf(g_logi[g_ile_logow], LOG_DLUGOSC, "%s", tekst);
    g_ile_logow++;
}

static int log_zawiera(const char *fragment) {
    int i;
    for (i = 0; i < g_ile_logow; i++)
        if (strstr(g_logi[i], fragment))
            return 1;
    return 0;
}

static int sym_odczyt(void *context, uint64_t pa, void *dst, uint32_t size) {
    struct symulacja *s = context;
    s->odczyty++;
    if (pa >= OKNO_SRAM || size > OKNO_SRAM - pa) {
        /* Dokladnie ten napis drukuje a53_transport.c przy statusie 0x20. */
        printf("  [transport] [!] A53 read 0x%lx response validation failed\n",
               (unsigned long)pa);
        s->poza_oknem++;
        return -1;
    }
    memcpy(dst, s->ram + pa, size);
    return (int)size;
}

static int sym_zapis(void *context, uint64_t pa, const void *src,
                     uint32_t size) {
    struct symulacja *s = context;
    if (pa >= OKNO_SRAM || size > OKNO_SRAM - pa) {
        s->poza_oknem++;
        return -1;
    }
    if (s->zjadaj_zapisy || (s->zjadaj_powyzej && size > s->zjadaj_powyzej)) {
        s->zapisy++;
        return 0;
    }
    if (size > s->max_czesc)
        s->max_czesc = size;
    memcpy(s->ram + pa, src, size);
    s->zapisy++;
    return 0;
}

static void sym_log(void *context, const char *message) {
    (void)context;
    zapisz_log(message);
}

static uint64_t sym_transakcje(void *context) {
    struct symulacja *s = context;
    return (uint64_t)(s->odczyty + s->zapisy);
}

static uint64_t sym_otwarcia(void *context) { (void)context; return 1; }
static uint64_t sym_ticks(void *context) { (void)context; return 0; }

static int wynikow_bledow;

static void sprawdz(int warunek, const char *opis) {
    printf("  [%s] %s\n", warunek ? "OK  " : "BLAD", opis);
    if (!warunek)
        wynikow_bledow++;
}

static uint32_t slowo_w_ram(const struct symulacja *s, uint64_t pa) {
    uint32_t w = 0;
    memcpy(&w, s->ram + pa, sizeof(w));
    return w;
}

static void wypelnij_transport(struct ppr_patch_transport *t,
                               struct symulacja *s) {
    memset(t, 0, sizeof(*t));
    t->context = s;
    t->read = sym_odczyt;
    t->write = sym_zapis;
    t->log = sym_log;
    t->transaction_count = sym_transakcje;
    t->transport_open_count = sym_otwarcia;
    t->elapsed_ticks = sym_ticks;
    t->fast_mode = 0;
    t->batch_enabled = 0;
    t->mixed_io_enabled = 0;
}

static void resetuj(struct symulacja *s, const uint8_t *obraz) {
    memcpy(s->ram, obraz, OKNO_SRAM);
    s->odczyty = 0;
    s->zapisy = 0;
    s->poza_oknem = 0;
    s->zjadaj_zapisy = 0;
    s->zjadaj_powyzej = 0;
    s->max_czesc = 0;
    wyczysc_log();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "uzycie: %s <obraz-a53.bin>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    uint8_t *obraz = calloc(1, OKNO_SRAM);
    struct symulacja s = {0};
    s.ram = calloc(1, OKNO_SRAM);
    if (!obraz || !s.ram) {
        fprintf(stderr, "brak pamieci\n");
        return 2;
    }
    size_t ile = fread(obraz, 1, OKNO_SRAM, f);
    fclose(f);
    printf("obraz: %s, wczytano %zu B (okno SRAM 0x%X B)\n", argv[1], ile,
           OKNO_SRAM);
    if (ile < OKNO_SRAM) {
        fprintf(stderr, "obraz jest mniejszy niz okno SRAM\n");
        return 2;
    }

    struct ppr_patch_transport t;
    int zgodne;

    printf("\n=== 1. czysty obraz stock: instalacja (jaskinia plaintext pod nowym adresem) ===\n");
    resetuj(&s, obraz);
    wypelnij_transport(&t, &s);
    int rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                                  PPR_PATCH_INSTALL, 1);
    sprawdz(rc == 0, "instalacja zwrocila 0");
    sprawdz(s.poza_oknem == 0,
            "zaden odczyt ani zapis nie wyszedl poza okno 0xC0000");
    zgodne = 0;
    for (size_t i = 0; i < ILE_STRON; i++)
        if (slowo_w_ram(&s, STRONY[i].pa) == STRONY[i].nowe)
            zgodne++;
    sprawdz(zgodne == (int)ILE_STRON, "5 miejsc ma slowa po latce");
    sprawdz(slowo_w_ram(&s, JASKINIA_RUNTIME_PA) == JASKINIA_RUNTIME_SLOWO0,
            "jaskinia runtime ma slowo 0 z szablonu (kod zostal wykonywalny)");
    sprawdz(slowo_w_ram(&s, JASKINIA_PLAINTEXT_PA) ==
            JASKINIA_PLAINTEXT_SLOWO0,
            "jaskinia plaintext ma slowo 0 z szablonu pod nowym adresem PA 0x5E000");
    sprawdz(slowo_w_ram(&s, JASKINIA_PLAINTEXT_PA + 7 * 4) ==
            JASKINIA_PLAINTEXT_SLOWO7,
            "galaz 7 jaskini plaintext jest pod nowym adresem (0x54000401)");
    sprawdz(slowo_w_ram(&s, 0x061F50) != JASKINIA_PLAINTEXT_SLOWO0,
            "stary adres 0x61F50 nie dostal juz jaskini plaintext");
    sprawdz(log_zawiera("[+] A53 zapis dziala"),
            "log potwierdza dzialajacy zapis A53");
    sprawdz(!log_zawiera("write/readback failed"),
            "przy sprawnym zapisie nie ma zadnej linii o nieudanym zapisie");
    sprawdz(log_zawiera("kolejnosc: najpierw jaskinia plaintext"),
            "log mowi wprost, ktora jaskinia jest zapisywana pierwsza");
    sprawdz(log_zawiera("plaintext VA 0x4e5e000"),
            "log podaje VA nowej jaskini plaintext");

    printf("\n=== 2. drugi przebieg: stan juz zainstalowany ===\n");
    wypelnij_transport(&t, &s);
    long zapisy_przed = s.zapisy;
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == 0, "ponowna instalacja zwrocila 0");
    sprawdz(s.zapisy == zapisy_przed, "ponowna instalacja nic nie zapisala");

    printf("\n=== 3. status ===\n");
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_STATUS, 0);
    sprawdz(rc == 0, "status zwrocil 0 (patch obecny)");

    printf("\n=== 4. odinstalowanie ===\n");
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_UNINSTALL, 1);
    sprawdz(rc == 0, "odinstalowanie zwrocilo 0");
    zgodne = 0;
    for (size_t i = 0; i < ILE_STRON; i++)
        if (slowo_w_ram(&s, STRONY[i].pa) == STRONY[i].stock)
            zgodne++;
    sprawdz(zgodne == (int)ILE_STRON, "5 miejsc wrocilo do slow stock");
    sprawdz(slowo_w_ram(&s, JASKINIA_RUNTIME_PA) == JASKINIA_RUNTIME_SLOWO0,
            "odinstalowanie nie rusza jaskini runtime");
    sprawdz(s.poza_oknem == 0,
            "takze przy odinstalowaniu zero adresow poza oknem");

    printf("\n=== 5. obcy obraz: przeklamana kotwica tozsamosci ===\n");
    resetuj(&s, obraz);
    s.ram[0x05B964 + 3] ^= 0xFFu;    /* kotwica "helper" */
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == -1, "instalacja na obcym obrazie zwrocila -1");
    sprawdz(s.zapisy == 0, "nic nie zostalo zapisane");

    printf("\n=== 6. obraz innej wersji: inny naglowek segmentu io ===\n");
    resetuj(&s, obraz);
    memset(s.ram + 0x28000, 0, 16);  /* kotwica "io header" */
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == -1, "instalacja przy innym naglowku io zwrocila -1");
    sprawdz(s.zapisy == 0, "nic nie zostalo zapisane");

    printf("\n=== 7. obraz z obcym slowem w miejscu latki ===\n");
    resetuj(&s, obraz);
    s.ram[0x04A120] ^= 0x01u;
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == -1, "instalacja przy obcym slowie miejsca zwrocila -1");
    sprawdz(s.zapisy == 0, "nic nie zostalo zapisane");

    printf("\n=== 8. zapis, ktory nie dochodzi do pamieci (jak na 13.60) ===\n");
    resetuj(&s, obraz);
    s.zjadaj_zapisy = 1;
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == -1, "instalacja bez potwierdzenia zapisu zwrocila -1");
    zgodne = 0;
    for (size_t i = 0; i < ILE_STRON; i++)
        if (slowo_w_ram(&s, STRONY[i].pa) == STRONY[i].stock)
            zgodne++;
    sprawdz(zgodne == (int)ILE_STRON, "obraz zostal nietkniety");
    sprawdz(log_zawiera("A53 write probe (plaintext cave, nowy adres): typ 0x01040031, PA 0x5e000, 160 B"),
            "proba 1: nowy adres jaskini plaintext, 160 B, z kodem transportu");
    sprawdz(log_zawiera("A53 write probe (runtime cave, stary adres (kontrola)): typ 0x01040031, PA 0x61f00, 32 B"),
            "proba 2 (kontrola): stary adres jaskini runtime, 32 B");
    sprawdz(log_zawiera("A53 nie wykonala zapisu 0x01040031 pod PA 0x5e000"),
            "log mowi wprost, ze A53 nie wykonuje zapisu pod nowym adresem");
    sprawdz(log_zawiera("A53 odrzuca zapis 0x01040031 pod OBOMA adresami"),
            "werdykt obejmuje oba adresy, wiec nie da sie zwalic winy na adres");
    sprawdz(log_zawiera("transport write=0, readback=0, size=160"),
            "log rozdziela kod zwrotu zapisu i odczytu przy pelnym zapisie");
    sprawdz(log_zawiera("zadane    : "),
            "log pokazuje hex tego, co mialo byc zapisane");
    sprawdz(log_zawiera("odczytane : "),
            "log pokazuje hex tego, co naprawde lezy w pamieci");
    sprawdz(log_zawiera("probuje porcjami po 32 B"),
            "po nieudanym pelnym zapisie idzie proba porcjami");
    sprawdz(log_zawiera("porcja 1/5 @ PA 0x5e000, 32 B: write=0, read=0, NIEZGODNA"),
            "kazda porcja ma wlasna linie z adresem, rozmiarem i kodem");
    sprawdz(!log_zawiera("retrying"),
            "po odrzuconym zapisie nie ma drugiej proby (jedna proba pelna)");

    printf("\n=== 9. limit 32 B na jedno polecenie zapisu (hipoteza (c)) ===\n");
    resetuj(&s, obraz);
    s.zjadaj_powyzej = 32;
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, FIRMWARE, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == 0, "instalacja zakonczona mimo limitu 32 B na polecenie");
    sprawdz(log_zawiera("[+] zapis porcjami zadzialal"),
            "log nazywa ratunek: zapis porcjami");
    sprawdz(log_zawiera("[*] zapis porcjami: 5 z 5 porcji zgodnych"),
            "piec porcji po 32 B zapisalo 160 B jaskini plaintext");
    sprawdz(s.max_czesc <= 32,
            "zaden przyjety zapis nie byl dluzszy niz 32 B");
    zgodne = 0;
    for (size_t i = 0; i < ILE_STRON; i++)
        if (slowo_w_ram(&s, STRONY[i].pa) == STRONY[i].nowe)
            zgodne++;
    sprawdz(zgodne == (int)ILE_STRON, "5 miejsc ma slowa po latce");
    sprawdz(slowo_w_ram(&s, JASKINIA_RUNTIME_PA) == JASKINIA_RUNTIME_SLOWO0,
            "jaskinia runtime zapisana porcjami (76 B = 32+32+12)");
    sprawdz(slowo_w_ram(&s, JASKINIA_PLAINTEXT_PA) ==
            JASKINIA_PLAINTEXT_SLOWO0,
            "jaskinia plaintext zapisana porcjami pod nowym adresem");

    printf("\n=== 10. inny firmware: brak profilu ===\n");
    resetuj(&s, obraz);
    wypelnij_transport(&t, &s);
    rc = ppr_patch_run_target(&t, 0x11400000u, PPR_TARGET_RETAIL,
                              PPR_PATCH_INSTALL, 1);
    sprawdz(rc == -1, "instalacja dla 11.40 zwrocila -1 (brak profilu)");

    printf("\n============================================================\n");
    if (wynikow_bledow == 0)
        printf("WYNIK: wszystkie scenariusze przeszly\n");
    else
        printf("WYNIK: %d bledow\n", wynikow_bledow);
    free(obraz);
    free(s.ram);
    return wynikow_bledow == 0 ? 0 : 1;
}
