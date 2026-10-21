/*
 * Profil PPR dla firmware 13.60, wersja v5.
 *
 * Rozni sie od artifacts/kstuff-profile-1360.h (v2 do v4) DWOMA polami:
 *
 *   1. plaintext_cave_va: 0x04E61F50 -> 0x04E5E000
 *      Jaskinia danych (plaintext, 160 B) przeniesiona z ogona segmentu io do
 *      nieuzywanego wypelnienia pod PA 0x5E000. Powody i dowody:
 *      notes/KSTUFF-PPR-V5.md, rozdzial 2.
 *   2. io_file_size: 0x39F00 -> 0x36000
 *      W v2 do v4 ta wartosc byla WYPROWADZONA (mapped_size - 0x100, przez
 *      analogie do profilu 11.40). Teraz jest ZMIERZONA: ostatni blok 4 kB
 *      obrazu A53, ktory nie jest wypelnieniem, konczy sie pod PA 0x5E000
 *      (rel 0x36000), a od 0x5E000 do konca segmentu entropia wynosi 8.000
 *      (narzedzie tools/kstuff-ppr-v5/analiza-ogona-io-v5.py). Pola nie
 *      uzywa sciezka statyczna (layout_static = 1): g6_size wystepuje tylko
 *      w dopasowaniu ukladu dynamicznego, w logu rekordu i w ppr_map_g6,
 *      ktore dla profilu io-only nie jest wolane.
 *
 * Wszystkie pozostale pola, w tym miejsca latki, slowa stock i slowa po
 * latce, sa bez zmian wobec v2, v3 i v4.
 *
 * Zrodlo danych: odtworzony obraz pamieci A53 (artifacts/a53-obraz-odtworzony.bin),
 * zrzut zywego segmentu io (<work>\a53_regions\region_00028000.bin, PA
 * 0x28000..0x62000) oraz sygnatury generatora upstream.
 *
 * Adresy `*_va` sa widziane przez procesor A53. Adresy fizyczne wynikaja z przelicznikow:
 *     io  = 0x04e28000 + (fizyczny - 0x28000)
 *     dev = 0x06410000 + (fizyczny - 0x85000)
 *
 * DOWODY DLA KAZDEGO POLA
 *
 * Wariant ABI: 13.60 uzywa ukladu PPR_ABI_LATE. Pomocnik ma co do rozkazu te same
 * slowa lancucha danych, co wariant LATE, pod tymi samymi przesunieciami:
 *     +0x0C8 F94057B6, +0x0D0 B81F43A5, +0x164 B9407BA9, +0x188 B9000BE9, +0x208 AA1603E3
 * czyli 5 z 5. Sygnatura pomocnika rozni sie wylacznie wieksza ramka stosu (0x1D0
 * zamiast 0xD0), co przesuwa zapisy rejestrow o 0x10; slowa dziewiate i dziesiate,
 * B940A3B4 i AA0203FA, sa identyczne.
 *
 * Pola wewnatrz pomocnika, wszystkie zgodne z tabela ABI_LAYOUTS["PPR_ABI_LATE"]:
 *     precheck 0x68, precheck_normal 0x6C, precheck_special 0xA0,
 *     bies_dispatch 0x190, sha_wait 0x210, common_return 0x2BC
 * a sha_auth_site lezy pod 0x29C, czyli o 0x14 dalej niz w 11.40 (0x288), bo kod
 * wewnatrz pomocnika urosl o piec rozkazow.
 *
 * Pola potwierdzone sygnaturami generatora (dlugosc sygnatury w bajtach):
 *     dispatch_native_va       0x057AA8   AES_DISPATCH_DATAFLOW pod +0x40, ZGODNE
 *     aes_site_va[0]           0x057C14   AES_SITE_SETUP 4 z 4, BL do deskryptora AES
 *     aes_site_va[1]           0x057D4C   AES_SITE_SETUP 3 z 3, BL do deskryptora AES
 *     aes_descriptor_va        0x02B124   AES_DESCRIPTOR 40 B, jedyne wystapienie
 *     plaintext_descriptor_va  0x02B2F0   PLAINTEXT_DESCRIPTOR 48 B, jedyne wystapienie
 *     plaintext_direct_va      0x05C7E8   DIRECT 48 B, jedyne, slowo silnika 528000A5 pod +0x74
 *     plaintext_idma_va        0x058534   IDMA 28 B, ZGODNE
 *     submit_idma_va           0x0565F8   SUBMIT 12 B, wolany z plaintext_direct+0x178
 *
 * Pola wyprowadzone regula strukturalna generatora:
 *     sha_wait_idma_aes_va     cel skoku pod helper + sha_wait
 *     sha_authenticate_va      jedyny skok miedzy miejscem sha_wait a common_return
 *     common_error_va          cel rozkazu precheck (CBNZ W28, +0x154)
 *     aes_site_va              skoki w funkcji rozgalezienia prowadzace do aes_descriptor
 *     plaintext_descriptor_va  cel skoku pod plaintext_direct + 0x80
 *     submit_idma_va           cel skoku pod plaintext_direct + 0x178
 *
 * merged_text = 0, udowodnione dwoma niezaleznymi sprawdzeniami:
 *     DIRECT_COMPLETION_SIGNATURES[False] zgadza sie pod plaintext_direct + 0x158,
 *     a skok zlecenia jest pod +0x178, czyli w wariancie bez scalonego tekstu.
 *
 * ROZMIARY SEGMENTOW I JASKINIE. Jadro zrzuca pamiec A53 dziewiecioma regionami,
 * a ich granice odpowiadaja ukladowi segmentow: 0x28000 + 0x3A000 dla io oraz
 * 0x85000 + 0x31000 dla dev.
 *
 * Uklad jaskin w v5 (oba adresy 4-bajtowo wyrownane, kazda w osobnej stronie 4 kB):
 *     runtime_cave_va   0x04E61F00  PA 0x61F00  76 B   ogon obrazu io, kod
 *     plaintext_cave_va 0x04E5E000  PA 0x5E000 160 B   wypelnienie obrazu io, dane
 * Zaden z tych zakresow nie dotyka 5 kotwic (0x28000, 0x57AA8, 0x5B964, 0x5BC20,
 * 0x5C7E8), 5 miejsc latki (0x4A120, 0x4B860, 0x57C14, 0x57D4C, 0x5BC00) ani
 * drugiej jaskini. Jaskinia runtime zostaje tam, gdzie byla, czyli w wykonywalnym
 * ogonie segmentu io; jaskinia plaintext jest danymi i lezy w wypelnieniu.
 *
 * POLE NIEPOTWIERDZONE: dev_file_size. Generator uzywa go tylko do sprawdzenia,
 * czy jaskinia miesci sie w segmencie, a jaskinia jest w io, wiec nie wplywa na patch.
 */

static const struct ppr_profile ppr_profile_1360 = {
    .firmware = 0x13600000U,
    .name = "13.60",
    .abi = PPR_ABI_LATE,
    .merged_text = 0,
    .cave_in_dev = 0,

    .io_mapped_base = 0x04E28000ULL,
    .io_file_size = 0x00036000ULL,
    .io_mapped_size = 0x0003A000ULL,
    .io_sram_base = 0x00028000ULL,
    .dev_mapped_base = 0x06410000ULL,
    .dev_file_size = 0x00031000ULL,
    .dev_mapped_size = 0x00031000ULL,

    .runtime_cave_va = 0x04E61F00ULL,
    .plaintext_cave_va = 0x04E5E000ULL,

    .helper_va = 0x04E5B964ULL,
    .precheck_normal_va = 0x04E5B9D0ULL,
    .precheck_special_va = 0x04E5BA04ULL,
    .common_error_va = 0x04E5BB20ULL,
    .dispatch_native_va = 0x04E57AA8ULL,

    .aes_descriptor_va = 0x04E2B124ULL,
    .plaintext_descriptor_va = 0x04E2B2F0ULL,
    .plaintext_direct_va = 0x04E5C7E8ULL,
    .plaintext_idma_va = 0x04E58534ULL,

    .sha_wait_idma_aes_va = 0x04E589D0ULL,
    .sha_authenticate_va = 0x04E58ACCULL,
    .submit_idma_va = 0x04E565F8ULL,
    .common_return_va = 0x04E5BC20ULL,

    .call_va = {
        0x04E4A120ULL,
        0x04E4B860ULL,
        0, 0, 0, 0, 0, 0, 0, 0,
    },
    .call_stock = {
        0x94004611U,
        0x94004041U,
        0, 0, 0, 0, 0, 0, 0, 0,
    },

    .aes_site_va = { 0x04E57C14ULL, 0x04E57D4CULL },
    .aes_site_stock = { 0x97FF4D44U, 0x97FF4CF6U },

    .sha_auth_site_va = 0x04E5BC00ULL,
    .sha_auth_site_stock = 0x97FFF3B3U,

    .precheck_va = 0x04E5B9CCULL,
    .precheck_stock = 0x35000ABCU,

    .dispatch_va = 0x04E5BAF4ULL,
    .dispatch_stock = 0x97FFEFEDU,
};
