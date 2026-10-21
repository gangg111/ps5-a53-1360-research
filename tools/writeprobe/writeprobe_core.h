/*
 * Macierz prob zapisu do pamieci A53: dane i reguly bez zaleznosci od jadra.
 *
 * Ten plik nie wola transportu i nie zna skrzynki urzadzenia. Trzyma wylacznie:
 *   - liste adresow w kolejnosci od najbezpieczniejszego,
 *   - liste typow pamieci i typow dostepu,
 *   - wzorzec 16 bajtow unikalny dla kazdej proby,
 *   - regule oceny "przed kontra po".
 *
 * Dzieki temu te sama macierz i ten sam osad mozna sprawdzic na komputerze
 * (`make test`), bez konsoli i bez ryzyka dla zywego oprogramowania A53.
 */
#ifndef WRITEPROBE_CORE_H
#define WRITEPROBE_CORE_H

#include <stdint.h>

/* Wzorzec ma zawsze 16 bajtow i nigdy nie zapisujemy wiecej. Odczyt 32 bajtow
 * pokazuje przy okazji, czy zapis nie siegnal sasiednich bajtow. */
#define WP_WZORZEC 16U
#define WP_ODCZYT  32U

/* Gorny limit macierzy (adresy x typy x dostepy). Jest zapas wobec obecnych
 * 6 x 4 x 2 = 48 prob, zeby dopisanie kolejnej osi nie wymagalo zmiany struktury. */
#define WP_PROB_MAX 64U

typedef struct {
    uint64_t    adres;
    const char *opis;
} wp_adres;

typedef struct {
    uint64_t adres;
    uint32_t mem_type;
    uint32_t access;
} wp_proba;

typedef enum {
    WP_ZAPIS_PRZYJETY   = 0, /* po == wzorzec: A53 wykonala zapis */
    WP_ZAPIS_ODRZUCONY  = 1, /* po == przed: pamiec bez zmian */
    WP_PAMIEC_ZMIENIONA = 2, /* po rozne od obu: cos sie stalo, ale nie to, o co prosilismy */
    WP_ODCZYT_NIEWIARYGODNY = 3 /* brak wiarygodnego odczytu, werdyktu nie ma z czego wydac */
} wp_osad;

/* Kolejnosc adresow jest czescia zabezpieczenia: od pustego wypelnienia za kodem,
 * przez jaskinie, do zywego kodu i drugiego banku. */
unsigned        wp_adresow(void);
const wp_adres *wp_adres_dla(unsigned i);

unsigned        wp_typow(void);
uint32_t        wp_typ_dla(unsigned i);

unsigned        wp_dostepow(void);
uint32_t        wp_dostep_dla(unsigned i);

/* Liczba prob calej macierzy: adresy x typy x dostepy. */
unsigned        wp_prob(void);
const wp_proba *wp_proba_dla(unsigned nr);

/* Wzorzec proby: 16 bajtow, unikalne dla numeru proby i jej parametrow.
 * uklad: 'W' 'P' nr access mem_type[4] adres[4] 'W' 'P' xor 0xaa */
void            wp_wzorzec(unsigned nr, uint8_t out[WP_WZORZEC]);

/* Osad jednej proby. "rozm" to liczba porownywanych bajtow (16 = sam wzorzec). */
wp_osad         wp_ocen(const uint8_t *przed, const uint8_t *po,
                        const uint8_t *wzorzec, unsigned rozm);

const char     *wp_osad_opis(wp_osad osad);

#endif /* WRITEPROBE_CORE_H */
