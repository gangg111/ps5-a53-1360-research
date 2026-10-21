/*
 * Macierz prob zapisu do pamieci A53: dane i reguly oceny.
 * Opis podzialu plikow: writeprobe_core.h.
 */
#include "writeprobe_core.h"

#include <string.h>

/* Adresy w kolejnosci prob. Uzasadnienie kazdego adresu:
 *
 * 0x5E000, 0x60000 - puste wypelnienie za kodem obrazu (plik konczy sie kolo
 *     0x5DD00, dopiero 0x62000 konczy segment io), wiec zapis tam nie rusza
 *     zadnej instrukcji ani stalej.
 * 0x61F00, 0x61F50 - dwie jaskinie latki PPR wewnatrz tego samego wypelnienia
 *     (rel 0x39F00 i 0x39F50 od poczatku segmentu io pod PA 0x28000).
 * 0x28000 - poczatek zywego obrazu A53 (naglowek i tablica deskryptorow).
 *     Najniebezpieczniejszy adres macierzy, dlatego przedostatni.
 * 0x80000 - poczatek trzeciego banku SRAM (okno transportu konczy sie na
 *     0xBFFFF). Nie wiemy, co A53 tam trzyma, wiec proba jest ostatnia.
 */
static const wp_adres ADRESY[] = {
    { 0x5E000ULL, "puste wypelnienie za kodem" },
    { 0x60000ULL, "puste wypelnienie za kodem, koniec segmentu io" },
    { 0x61F00ULL, "jaskinia runtime latki PPR" },
    { 0x61F50ULL, "jaskinia plaintext latki PPR" },
    { 0x28000ULL, "poczatek zywego obrazu A53 (naglowek)" },
    { 0x80000ULL, "poczatek trzeciego banku SRAM" },
};

/* Typy pamieci z zadania. 0x020000 to typ, ktorym idzie zapis w latce PPR,
 * 0x020100 to typ sprawdzony pomiarem przy odczycie i zrzucie (pprwatch,
 * a53layout, mboxwrite). 0x010000 i 0x000000 to sasiednie wartosci z tej samej
 * rodziny, zeby sprawdzic, czy A53 rozroznia typ po pelnym slowie. */
static const uint32_t TYPY[] = {
    0x020000U,
    0x020100U,
    0x010000U,
    0x000000U,
};

/* Typy dostepu z zadania: 4 (32-bit) i 6 (wartosc uzywana przy zapisie jaskini
 * 160-bajtowej, a takze wybierana przez access_size() w transporcie referencyjnym
 * dla adresow wyrownanych). */
static const uint32_t DOSTEPY[] = {
    4U,
    6U,
};

unsigned wp_adresow(void) { return (unsigned) (sizeof(ADRESY) / sizeof(ADRESY[0])); }

const wp_adres *wp_adres_dla(unsigned i) {
    return (i < wp_adresow()) ? &ADRESY[i] : (const wp_adres *) 0;
}

unsigned wp_typow(void) { return (unsigned) (sizeof(TYPY) / sizeof(TYPY[0])); }

uint32_t wp_typ_dla(unsigned i) {
    return (i < wp_typow()) ? TYPY[i] : 0xFFFFFFFFU;
}

unsigned wp_dostepow(void) { return (unsigned) (sizeof(DOSTEPY) / sizeof(DOSTEPY[0])); }

uint32_t wp_dostep_dla(unsigned i) {
    return (i < wp_dostepow()) ? DOSTEPY[i] : 0xFFFFFFFFU;
}

unsigned wp_prob(void) { return wp_adresow() * wp_typow() * wp_dostepow(); }

/* Numeracja: adres najwolniej sie zmienia, wiec cala seria typow i dostepow
 * dotyczy jednego adresu, zanim przejdziemy do nastepnego. To jest wlasnie
 * kolejnosc "od najbezpieczniejszych adresow".
 *
 * Tabela jest budowana raz i trzymana w pamieci, zeby wolajacy dostawal wskaznik
 * na wlasny wpis, a nie na wspolny bufor (inaczej nie da sie porownac dwoch prob). */
static wp_proba TABELA[WP_PROB_MAX];
static unsigned TABELA_GOTOWA;

static void zbuduj_tabele(void) {
    unsigned nr = 0;
    if (TABELA_GOTOWA) return;
    for (unsigned a = 0; a < wp_adresow(); a++) {
        for (unsigned t = 0; t < wp_typow(); t++) {
            for (unsigned d = 0; d < wp_dostepow(); d++) {
                if (nr >= WP_PROB_MAX) break;
                TABELA[nr].adres = ADRESY[a].adres;
                TABELA[nr].mem_type = TYPY[t];
                TABELA[nr].access = DOSTEPY[d];
                nr++;
            }
        }
    }
    TABELA_GOTOWA = nr;
}

const wp_proba *wp_proba_dla(unsigned nr) {
    zbuduj_tabele();
    if (nr >= TABELA_GOTOWA) return (const wp_proba *) 0;
    return &TABELA[nr];
}

void wp_wzorzec(unsigned nr, uint8_t out[WP_WZORZEC]) {
    const wp_proba *p = wp_proba_dla(nr);
    uint32_t adres32 = 0;
    uint8_t xor_sum = 0;

    if (!out) return;
    memset(out, 0, WP_WZORZEC);
    if (!p) return;

    adres32 = (uint32_t) p->adres;
    out[0] = 'W';
    out[1] = 'P';
    out[2] = (uint8_t) (nr & 0xFFU);
    out[3] = (uint8_t) (p->access & 0xFFU);
    memcpy(out + 4, &p->mem_type, 4);
    memcpy(out + 8, &adres32, 4);
    out[12] = 'W';
    out[13] = 'P';
    for (unsigned i = 0; i < 14; i++) xor_sum = (uint8_t) (xor_sum ^ out[i]);
    out[14] = xor_sum;
    out[15] = 0xAA;
}

wp_osad wp_ocen(const uint8_t *przed, const uint8_t *po, const uint8_t *wzorzec,
                unsigned rozm) {
    if (!przed || !po || !wzorzec || rozm == 0 || rozm > WP_WZORZEC)
        return WP_ODCZYT_NIEWIARYGODNY;
    if (memcmp(po, wzorzec, rozm) == 0) return WP_ZAPIS_PRZYJETY;
    if (memcmp(po, przed, rozm) == 0) return WP_ZAPIS_ODRZUCONY;
    return WP_PAMIEC_ZMIENIONA;
}

const char *wp_osad_opis(wp_osad osad) {
    switch (osad) {
        case WP_ZAPIS_PRZYJETY:   return "zapis przyjety";
        case WP_ZAPIS_ODRZUCONY:  return "zapis odrzucony";
        case WP_PAMIEC_ZMIENIONA: return "pamiec zmieniona inaczej niz wzorzec";
        default:                  return "brak wiarygodnego odczytu";
    }
}
