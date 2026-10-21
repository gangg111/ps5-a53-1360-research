/*
 * Test macierzy prob zapisu na komputerze (bez konsoli i bez A53).
 *
 * Sprawdza to, co da sie sprawdzic bez sprzetu: liczbe i unikalnosc prob,
 * kolejnosc adresow od najbezpieczniejszego, typy pamieci i dostepu, wzorzec
 * (16 B, unikalny, kodujacy numer proby i parametry) oraz regule osadu.
 *
 * Budowa i uruchomienie: make test
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "writeprobe_core.h"

static unsigned g_sprawdzen;
static unsigned g_bledow;

static void sprawdz(int warunek, const char *opis) {
    g_sprawdzen++;
    if (!warunek) {
        g_bledow++;
        printf("  BLAD: %s\n", opis);
    }
}

static int zawiera_adres(uint64_t a) {
    for (unsigned i = 0; i < wp_adresow(); i++) {
        const wp_adres *w = wp_adres_dla(i);
        if (w && w->adres == a) return 1;
    }
    return 0;
}

static int zawiera_typ(uint32_t t) {
    for (unsigned i = 0; i < wp_typow(); i++)
        if (wp_typ_dla(i) == t) return 1;
    return 0;
}

static int zawiera_dostep(uint32_t d) {
    for (unsigned i = 0; i < wp_dostepow(); i++)
        if (wp_dostep_dla(i) == d) return 1;
    return 0;
}

static int pozycja_adresu(uint64_t a) {
    for (unsigned i = 0; i < wp_adresow(); i++) {
        const wp_adres *w = wp_adres_dla(i);
        if (w && w->adres == a) return (int) i;
    }
    return -1;
}

int main(void) {
    static uint8_t wzorce[256][WP_WZORZEC];
    unsigned n = wp_prob();

    printf("test macierzy writeprobe\n");

    /* 1. Rozmiar macierzy: 6 adresow x 4 typy x 2 dostepy = 48. */
    sprawdz(wp_adresow() == 6, "szesc adresow macierzy");
    sprawdz(wp_typow() == 4, "cztery typy pamieci");
    sprawdz(wp_dostepow() == 2, "dwa typy dostepu");
    sprawdz(n == 48, "48 prob w macierzy");
    sprawdz(n <= 256, "macierz miesci sie w buforze testu");

    /* 2. Typy i dostepy dokladnie takie, jak w zleceniu. */
    sprawdz(zawiera_typ(0x020000U), "typ 0x020000 jest w macierzy");
    sprawdz(zawiera_typ(0x020100U), "typ 0x020100 jest w macierzy");
    sprawdz(zawiera_typ(0x010000U), "typ 0x010000 jest w macierzy");
    sprawdz(zawiera_typ(0x000000U), "typ 0x000000 jest w macierzy");
    sprawdz(zawiera_dostep(4U), "dostep 4 jest w macierzy");
    sprawdz(zawiera_dostep(6U), "dostep 6 jest w macierzy");

    /* 3. Adresy dokladnie takie, jak w zleceniu. */
    sprawdz(zawiera_adres(0x28000ULL), "adres 0x28000 (poczatek kodu)");
    sprawdz(zawiera_adres(0x5E000ULL), "adres 0x5E000 (puste wypelnienie)");
    sprawdz(zawiera_adres(0x61F00ULL), "adres 0x61F00 (jaskinia runtime)");
    sprawdz(zawiera_adres(0x61F50ULL), "adres 0x61F50 (jaskinia plaintext)");
    sprawdz(zawiera_adres(0x80000ULL), "adres 0x80000 (drugi bank)");
    sprawdz(zawiera_adres(0x60000ULL), "adres 0x60000");

    /* 4. Kolejnosc: najpierw wypelnienie, potem jaskinie, na koncu kod i bank.
     * To jest zabezpieczenie, wiec pilnuje go test. */
    sprawdz(pozycja_adresu(0x5E000ULL) < pozycja_adresu(0x61F00ULL),
            "wypelnienie 0x5E000 przed jaskinia 0x61F00");
    sprawdz(pozycja_adresu(0x60000ULL) < pozycja_adresu(0x61F00ULL),
            "wypelnienie 0x60000 przed jaskinia 0x61F00");
    sprawdz(pozycja_adresu(0x61F00ULL) < pozycja_adresu(0x28000ULL),
            "jaskinie przed zywym kodem 0x28000");
    sprawdz(pozycja_adresu(0x61F50ULL) < pozycja_adresu(0x28000ULL),
            "jaskinia plaintext przed zywym kodem 0x28000");
    sprawdz(pozycja_adresu(0x28000ULL) < pozycja_adresu(0x80000ULL),
            "zywy kod przed ostatnim adresem 0x80000");
    sprawdz(pozycja_adresu(0x80000ULL) == (int) wp_adresow() - 1,
            "0x80000 jest ostatnim adresem macierzy");

    /* 5. Kazda proba jest inna i kazda kombinacja wystepuje dokladnie raz. */
    for (unsigned i = 0; i < n; i++) {
        const wp_proba *pi = wp_proba_dla(i);
        unsigned powtorzen = 0;
        sprawdz(pi != NULL, "proba ma parametry");
        if (!pi) continue;
        sprawdz(zawiera_adres(pi->adres), "adres proby jest z listy");
        sprawdz(zawiera_typ(pi->mem_type), "typ pamieci proby jest z listy");
        sprawdz(zawiera_dostep(pi->access), "dostep proby jest z listy");
        for (unsigned j = i + 1; j < n; j++) {
            const wp_proba *pj = wp_proba_dla(j);
            if (!pj) continue;
            if (pi->adres == pj->adres && pi->mem_type == pj->mem_type &&
                pi->access == pj->access)
                powtorzen++;
        }
        sprawdz(powtorzen == 0, "zadna kombinacja adres/typ/dostep nie powtarza sie");
    }
    sprawdz(wp_prob() <= WP_PROB_MAX, "macierz miesci sie w limicie tabeli");
    sprawdz(wp_proba_dla(n) == NULL, "proba poza macierza nie istnieje");

    /* 6. Wzorzec: 16 bajtow, unikalny, koduje numer proby i parametry. */
    sprawdz(WP_WZORZEC == 16U, "wzorzec ma 16 bajtow");
    sprawdz(WP_ODCZYT == 32U, "odczyt ma 32 bajty");
    sprawdz(WP_ODCZYT > WP_WZORZEC, "odczyt jest wiekszy od wzorca (widac sasiednie bajty)");
    for (unsigned i = 0; i < n; i++) {
        const wp_proba *p = wp_proba_dla(i);
        uint8_t xor_sum = 0;
        unsigned unikalny = 1;
        wp_wzorzec(i, wzorce[i]);
        if (!p) continue;
        sprawdz(wzorce[i][0] == 'W' && wzorce[i][1] == 'P', "wzorzec ma znacznik WP");
        sprawdz(wzorce[i][2] == (uint8_t) (i & 0xFFU), "wzorzec niesie numer proby");
        sprawdz(wzorce[i][3] == (uint8_t) (p->access & 0xFFU), "wzorzec niesie typ dostepu");
        sprawdz(memcmp(wzorce[i] + 4, &p->mem_type, 4) == 0, "wzorzec niesie typ pamieci");
        {
            uint32_t adres32 = (uint32_t) p->adres;
            sprawdz(memcmp(wzorce[i] + 8, &adres32, 4) == 0, "wzorzec niesie adres");
        }
        for (unsigned k = 0; k < 14; k++) xor_sum = (uint8_t) (xor_sum ^ wzorce[i][k]);
        sprawdz(wzorce[i][14] == xor_sum, "suma kontrolna wzorca sie zgadza");
        sprawdz(wzorce[i][15] == 0xAA, "wzorzec konczy sie 0xAA");
        for (unsigned j = 0; j < i; j++)
            if (memcmp(wzorce[i], wzorce[j], WP_WZORZEC) == 0) unikalny = 0;
        sprawdz(unikalny, "wzorzec jest unikalny w calej macierzy");
    }

    /* 7. Osad proby. */
    {
        uint8_t przed[WP_ODCZYT], po[WP_ODCZYT], inny[WP_WZORZEC];
        for (unsigned i = 0; i < WP_ODCZYT; i++) {
            przed[i] = (uint8_t) (0x10 + i);
            po[i] = przed[i];
        }
        for (unsigned i = 0; i < WP_WZORZEC; i++) inny[i] = (uint8_t) (0x80 + i);

        sprawdz(wp_ocen(przed, przed, wzorce[0], WP_WZORZEC) == WP_ZAPIS_ODRZUCONY,
                "brak zmian = zapis odrzucony");
        sprawdz(wp_ocen(przed, wzorce[0], wzorce[0], WP_WZORZEC) == WP_ZAPIS_PRZYJETY,
                "bajty rowne wzorcowi = zapis przyjety");
        sprawdz(wp_ocen(przed, inny, wzorce[0], WP_WZORZEC) == WP_PAMIEC_ZMIENIONA,
                "inne bajty = pamiec zmieniona");

        /* Czesciowe trafienie (pierwsze 8 B wzorca, reszta stara) NIE jest
         * przyjetym zapisem: to zmiana inna niz wzorzec. */
        memcpy(po, przed, WP_ODCZYT);
        memcpy(po, wzorce[0], 8);
        sprawdz(wp_ocen(przed, po, wzorce[0], WP_WZORZEC) == WP_PAMIEC_ZMIENIONA,
                "polowiczny zapis = pamiec zmieniona, nie przyjety");

        sprawdz(wp_ocen(NULL, po, wzorce[0], WP_WZORZEC) == WP_ODCZYT_NIEWIARYGODNY,
                "brak stanu przed = brak werdyktu");
        sprawdz(wp_ocen(przed, po, wzorce[0], 0) == WP_ODCZYT_NIEWIARYGODNY,
                "zerowy rozmiar porownania = brak werdyktu");
        sprawdz(wp_ocen(przed, po, wzorce[0], WP_WZORZEC + 1) == WP_ODCZYT_NIEWIARYGODNY,
                "porownanie wieksze od wzorca = brak werdyktu");
    }

    /* 8. Wszystkie adresy leza w oknie transportu 0x0-0xBFFFF. */
    for (unsigned i = 0; i < wp_adresow(); i++) {
        const wp_adres *w = wp_adres_dla(i);
        if (!w) continue;
        sprawdz(w->adres + WP_WZORZEC <= 0xC0000ULL, "adres z zapasem w oknie transportu");
        sprawdz(w->opis != NULL && w->opis[0] != 0, "adres ma opis");
    }
    sprawdz(wp_adres_dla(wp_adresow()) == NULL, "adres poza lista nie istnieje");

    printf("%u sprawdzen, %u bledow\n", g_sprawdzen, g_bledow);
    if (g_bledow == 0) {
        printf("TEST OK\n");
        return 0;
    }
    printf("TEST NIEUDANY\n");
    return 1;
}
