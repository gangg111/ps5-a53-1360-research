/*
 * Profil PPR dla firmware 13.60, w postaci zgodnej ze struktura `struct ppr_profile`
 * z repozytorium drakmor/ppr-patch (ppr_patch.c, linia 54).
 *
 * Nazwy pol sa dokladnie takie, jakich uzywa upstream, zeby ten wpis mozna bylo
 * wkleic do `ppr_profiles.inc` bez przerabiania.
 *
 * Zrodlo danych: odtworzony obraz pamieci A53 (786432 B, dziewiec regionow zrzuconych
 * przez jadro), odczyt z zywej konsoli malymi porcjami z polem dostepu rownym 1,
 * oraz sygnatury z generatora upstream.
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
 * ROZMIARY SEGMENTOW I JASKINIA. Jadro zrzuca pamiec A53 dziewiecioma regionami,
 * a ich granice odpowiadaja ukladowi segmentow: 0x28000 + 0x3A000 dla io oraz
 * 0x85000 + 0x31000 dla dev. W profilu 11.40 rozmiar pliku jest mniejszy od
 * odwzorowanego dokladnie o 0x100, a jaskinia lezy pod mapped_size - 0x100, co dla
 * io daje padding 0x100, czyli wiecej niz 0xF0 wymagane przez regule cave_in_dev.
 * Dlatego przyjmuje sie ten sam uklad. Sa to wartosci WYPROWADZONE, nie zmierzone:
 *     io_mapped_size = 0x3A000, io_file_size = 0x39F00
 *     dev_mapped_size = 0x31000, dev_file_size = 0x31000 (gorna granica)
 *     runtime_cave_va = 0x04E61F00, plaintext_cave_va = 0x04E61F50
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
    .io_file_size = 0x00039F00ULL,
    .io_mapped_size = 0x0003A000ULL,
    .io_sram_base = 0x00028000ULL,
    .dev_mapped_base = 0x06410000ULL,
    .dev_file_size = 0x00031000ULL,
    .dev_mapped_size = 0x00031000ULL,

    .runtime_cave_va = 0x04E61F00ULL,
    .plaintext_cave_va = 0x04E61F50ULL,

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
