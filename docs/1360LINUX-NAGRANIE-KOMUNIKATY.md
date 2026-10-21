# 1360LINUX: komunikaty z nagrania ekranu konsoli

Zrodlo: `<dsh>\attachments\v1\files\68\68207c8f71232e786e164cc8a9ec62cf5200b16b4ded97347318aa050cfef8b0\1.mp4`
Nagranie ekranu PS5 (kamera/telefon), 17,7 MB, 13,909 s, 30 fps, 414 klatek, HEVC 1440x1296 (obraz po rotacji 1296x1440), audio AAC.
Payload: `artifacts/1360linux.elf` (ps5-linux-loader), uruchamiany z Payload Manager v0.5.2 (PLK, e4e72dc).

Metoda: `ffmpeg` (Windows, 8.0.1) do klatek, `read_image` do odczytu. Klatki leza poza repo, w `<work>\klatki\` (pelne co 0,5 s: `klatka-NN-tXX.Xs.png` oraz gesto co 0,1 s w `dense\d_NNNN.png`, kadr na baner). OCR niedostepny (brak tesseract), odczyt wzrokowy.

Wazna wlasciwosc UI: baner z logiem jest **przewijany** (w klatkach przejsciowych widac dwa stany nalozone na siebie). Dlatego pojedyncza klatka pokazuje fragment listy, a kolejnosc komunikatow odtworzono, sledzac momenty ich pojawiania sie w kolejnych klatkach.

## 1. Co widac na ekranie poza logiem

Przed startem payloadu i w tle przez cale nagranie widoczny jest Payload Manager v0.5.2 (adres 127.0.0.1), kafelki payloadow: `1360linux`, `a53dump2` (1.0), `a53node2` (1.0), `a53read3` (1.0), po prawej kolumna `a53*`, przycisk `URUCHOM`. Menu boczne: PANEL GLOWNY, ZARZADZAJ, AUTOSTART, PROCESY, USTAWIENIA, WESPRZYJ. Kafelek `1360linux` ma ikone ladowania (koleczko) do konca nagrania, co znaczy, ze proces payloadu nie zostal zakonczony.

## 2. Klatki z odczytanymi komunikatami

Wszystkie komunikaty na ekranie maja naglowek `Debug:` i tresc w kolejnej linii (dluzsze lamia sie na 2 do 3 linii).

| klatka | czas | odczytane wpisy (od gory banera) |
|---|---|---|
| 01 | 0,0 s | brak banera, tylko Payload Manager |
| 02 | 0,5 s | brak banera, `1360linux` z ikona ladowania |
| 03 | 1,0 s | `File 'initrd.img' found in '/mnt/usb0/'`, `File 'bzImage' found in '/mnt/usb0/'`, `build: untagged`, `Welcome to ps5-linux-loader. We'll defeat HV and prepare the system to boot Linux on sleep resume.` |
| 04 | 1,5 s | to samo, baner w trakcie animacji wjazdu (przesuniety w lewo) |
| 05 | 2,0 s | to samo |
| d_0020 | 1,9 s | to samo (4 wpisy, baner kompletny) |
| d_0030 | 2,9 s | to samo (4 wpisy) |
| 07 | 3,0 s | `Retail console detected`, `File 'cmdline.txt' found in '/mnt/usb0/'`, `File 'vram.txt' found in '/mnt/usb0/'`, `Dumped PS5 WiFi firmware to /mnt/usb0/lib/nxp/pcieuartiw620_combo_v1.bin (500296 bytes)`, `File 'initrd.img' found in '/mnt/usb0/'`, `File 'bzImage' found in '/mnt/usb0/'`, `build: untagged` |
| 09 | 4,0 s | `Debug:` (pusto), `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `L1[P1 R1 X0 N0 S0]`, `L0[P1 R1 X0 N0 S0]`, `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:`, `Debug:` (pusto), `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `Debug:` (pusto) |
| 11, 13, 15 | 5,0 do 7,0 s | bez zmian, ten sam uklad co 4,0 s |
| 17 | 8,0 s | klatka przejsciowa, tekst nalozony: `Retail console detected`, `File 'cmdline.txt'...`, `File 'vram.txt'...`, `Dumped PS5 WiFi firmware...`, `File 'initrd.img'...`, `File 'bzImage'...`, `build: untagged` |
| d_0085 | 8,4 s | `Retail console detected`, `File 'cmdline.txt' found in '/mnt/usb0/'`, `File 'vram.txt' found in '/mnt/usb0/'`, `Dumped PS5 WiFi firmware to /mnt/usb0/lib/nxp/pcieuartiw620_combo_v1.bin (500296 bytes)`, `File 'initrd.img' found in '/mnt/usb0/'`, `File 'bzImage' found in '/mnt/usb0/'`, `build: untagged` |
| d_0086 | 8,5 s | `PTE STATE cr3=0x898355000 dmap=0xffffca8400000000`, `DIAG: .text permission state (page tables only)`, `Retail console detected`, `File 'cmdline.txt'...`, `File 'vram.txt'...`, `Dumped PS5 WiFi firmware...` |
| d_0087 | 8,6 s | przejsciowa: `L1[...]`, `L0[...]`, `kernel_uart_override va=0xffffffff95509598:`, `SWEEP BOUNDS ktext=0xffffffff93310000 kdata=0xffffffff93fd0000 -> loop runs? YES`, `PTE STATE cr3=0x898355000 dmap=0xffffca8400000000`, `DIAG: .text permission state (page tables only)`, `Retail console detected`, `File 'cmdline.txt'...`, `File 'vram.txt'...` |
| d_0088 | 8,7 s | `L1[P1 R1 X0 N0 S0]`, `L0[P1 R1 X0 N0 S0]`, `kernel_uart_override va=0xffffffff95509598:`, `SWEEP BOUNDS ktext=0xffffffff93310000 kdata=0xffffffff93fd0000 -> loop runs? YES`, `PTE STATE cr3=0x898355000 dmap=0xffffca8400000000`, `DIAG: .text permission state (page tables only)`, `Retail console detected` |
| d_0089 | 8,8 s | przejsciowa: `L0[...]`, `L3[P1 R1 X0 N1 S0]` + `kernel_cfi_check va=0xffffffff9375f8...`, `L2[...]`, `L3[...]`, `L2[...]`, `L1[...]` + `kernel_uart_override`, `SWEEP BOUNDS ... loop runs? YES`, `PTE STATE ...` |
| d_0090 | 8,9 s | przejsciowa: `L1[...]`, `L0[...]`, `kernel_cfi_check va=0xffffffff9375f8...`, `...`, `L3[P1 R1 X0 N1 S0]`, `L2[P1 R1 X0 N0 S0]`, `L1[...]`, `L0[...]`, `kernel_uart_override va=0xffffffff91f5...` |
| d_0091 | 9,0 s | `Debug:` (pusto), `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `L1[P1 R1 X0 N0 S0]`, `L0[P1 R1 X0 N0 S0]`, `kernel_cfi_check va=0xffffffff9375f8c0:`, `Debug:` (pusto), `L3[P1 R1 X0 N1 S0]`, `L2[P1 R1 X0 N0 S0]`, `Debug:` (pusto) |
| d_0092 | 9,1 s | przejsciowa: `L1[...]`, `L0[...]`, `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:`, `...`, `L3[...]`, `L2[...]`, `L1[...]`, `L0[...]`, `kernel_cfi_check va=0xffffffff9375f8c0:` |
| d_0093 | 9,2 s | przejsciowa: `Debug:` (pusto), `...`, `L3[...]`, `L2[...]`, `L1[...]`, `L0[...]`, `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:`, `Debug:` (pusto), `L3[...]`, `L2[...]`, doly wpis `Debug:` z duchem `kernel_cfi_check` |
| d_0094 do d_0137 | 9,3 s do 13,6 s | **stan stabilny, bez zmian**: `Debug:` (pusto), `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `L1[P1 R1 X0 N0 S0]`, `L0[P1 R1 X0 N0 S0]`, `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:`, `Debug:` (pusto), `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `Debug:` (pusto) |
| 21, 25, 27 | 10,0 / 12,0 / 13,0 s | ten sam uklad co powyzej |
| d_0137 | 13,6 s | ten sam uklad co powyzej, koniec nagrania |

Zblizenia koncowego stanu: gorny wpis banera to `Debug:` z **pusta** trescia, dolny wpis to tez `Debug:` z pusta trescia (dolna krawedz banera widoczna, baner nie jest uciety).

## 3. Pelna lista odczytanych komunikatow w kolejnosci pojawiania sie

1. `File 'initrd.img' found in '/mnt/usb0/'`
2. `File 'bzImage' found in '/mnt/usb0/'`
3. `build: untagged`
4. `Welcome to ps5-linux-loader. We'll defeat HV and prepare the system to boot Linux on sleep resume.`
5. `Retail console detected`
6. `File 'cmdline.txt' found in '/mnt/usb0/'`
7. `File 'vram.txt' found in '/mnt/usb0/'`
8. `Dumped PS5 WiFi firmware to /mnt/usb0/lib/nxp/pcieuartiw620_combo_v1.bin (500296 bytes)`
9. `SWEEP BOUNDS ktext=0xffffffff93310000 kdata=0xffffffff93fd0000 -> loop runs? YES`
10. `PTE STATE cr3=0x898355000 dmap=0xffffca8400000000`
11. `DIAG: .text permission state (page tables only)`
12. `L3[P1 R1 X0 N0 S0]`
13. `L2[P1 R1 X0 N0 S0]`
14. `L1[P1 R1 X0 N0 S0]`
15. `L0[P1 R1 X0 N0 S0]`
16. `kernel_uart_override va=0xffffffff95509598:`
17. `L3[P1 R1 X0 N1 S0]` (uwaga: N1, nie N0)
18. `L2[P1 R1 X0 N0 S0]`
19. `L1[P1 R1 X0 N0 S0]`
20. `L0[P1 R1 X0 N0 S0]`
21. `kernel_cfi_check va=0xffffffff9375f8c0:`
22. `...` (doslownie trzy kropki jako tresc powiadomienia)
23. `L3[P1 R1 X0 N0 S0]`
24. `L2[P1 R1 X0 N0 S0]`
25. `L1[P1 R1 X0 N0 S0]`
26. `L0[P1 R1 X0 N0 S0]`
27. `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:`
28. `Debug:` z pusta trescia (kilka wystapien, na gorze i na dole listy oraz miedzy sekcjami)

Kolejnosc 12 do 27 wynika z momentow pojawiania sie: `kernel_uart_override` widoczne od 8,7 s, `kernel_cfi_check` od 8,8 do 9,1 s, `KERNEL_CODE_CAVE` od 9,1 s. Zestaw `L3 L2 L1 L0` poprzedza nazwe kazdego obszaru (widoczne wprost w d_0091 dla `kernel_cfi_check` i w d_0094 dla `KERNEL_CODE_CAVE`).

## 4. Ostatni komunikat i zachowanie po nim

Ostatnia **zmiana** zawartosci logu nastapila miedzy 9,1 s a 9,3 s: na miejscu, gdzie wczesniej bylo `kernel_cfi_check va=0xffffffff9375f8c0:`, pojawilo sie `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:` wraz z towarzyszaca sekwencja `L3`, `L2`, `L1`, `L0` i pustym wpisem `Debug:`.

Od 9,3 s do konca nagrania (13,9 s), czyli przez **4,6 s**, obraz banera jest identyczny w szesciu sprawdzonych punktach (9,3 / 9,4 / 9,5 / 9,7 / 9,9 / 10,0 / 12,0 / 13,0 / 13,6 s). Nie pojawil sie zaden nowy komunikat.

Ostatni odczytany komunikat to `KERNEL_CODE_CAVE va=0xffffffff93fc92c0:` z sekwencja poziomow tablic stron `L3[P1 R1 X0 N0 S0]`, `L2[P1 R1 X0 N0 S0]`, `L1[P1 R1 X0 N0 S0]`, `L0[P1 R1 X0 N0 S0]` oraz pustym wpisem `Debug:`.

## 5. Wniosek: na jakim etapie payload sie zatrzymal

Zgodnie z `notes/1360LINUX-PAMIEC-I-BOOT.md` (rozdzial 2.5) kolejnosc jest nastepujaca:

    main: setup_env -> fetch_linux -> prepare_resume -> hv_defeat_13xx -> "Finished preparation..."
    hv_defeat_13xx: 1. offsets_present (bramka offsetow)
                    2. kontrola integralnosci jadra (validity gate)
                    3. dump_text_perm (PTE STATE, DIAG, obszary, VERDICT)
                    4. derive_H
                    ...
                    11. kh_install / kh_trigger
                    12..14. setidt i kwrite64

Nagranie pokazuje, ze payload wykonal:

- `setup_env` i `fetch_linux`: komunikaty o plikach `initrd.img`, `bzImage`, `cmdline.txt`, `vram.txt` oraz `Dumped PS5 WiFi firmware ... (500296 bytes)` i `Retail console detected`.
- `prepare_resume`: `SWEEP BOUNDS ktext=0xffffffff93310000 kdata=0xffffffff93fd0000 -> loop runs? YES` (petla remove_xotext przejdzie).
- wejscie w `hv_defeat_13xx` i krok 3, `dump_text_perm`: `PTE STATE cr3=0x898355000 dmap=0xffffca8400000000`, `DIAG: .text permission state (page tables only)`, a nastepnie sekcje dla obszarow `kernel_uart_override`, `kernel_cfi_check`, `KERNEL_CODE_CAVE`.

Payload **zatrzymal sie w srodku kroku 3 (dump_text_perm)**: wypisal trzy pierwsze obszary diagnostyczne z listy siedmiu (`kernel_uart_override`, `kernel_cfi_check`, `KERNEL_CODE_CAVE`), a nie wypisal kolejnego (`GAD_ADD_RSP_28..RBP`) ani konczacych ten krok komunikatow `VERDICT: leaf XO/RW printed per line above.` i `VERDICT: still execute-only and shellcode_kernel's first write WILL fault.`

Nie wypisal tez `Finished preparation. Going to rest mode in 5 seconds.` ani `Please wait for the orange light to stop blinking and then wakeup to Linux :)`, i konsola nie weszla w rest mode (brak zgaszenia obrazu do konca nagrania). Potwierdza to, ze krok 3 nie zostal dokonczony, wiec nie mogly zajsc dalsze kroki: `derive_H`, `pin_to_core_reborn`, `kh_install`, `kh_trigger` ani przygotowanie rest mode.

**Zaden** z komunikatow bledow z listy podejrzanych nie wystapil na nagraniu (sprawdzone wprost, klatka po klatce):

- `13.60 offsets are incomplete - refusing to arm.` nie wystapil
- `validity gate failed - wrong firmware image?` nie wystapil
- `could not derive H from the EFI map - refusing to arm.` nie wystapil
- `khook install failed (%d) - refusing to suspend.` nie wystapil
- `Error: missing code cave offset` nie wystapil
- `Something went wrong while reading bzImage - Aborting` nie wystapil
- `Something went wrong while installing linux files.` nie wystapil
- `Seems like the configured vram value is wrong - Using static fallback` nie wystapil
- `Detected pro model`, `DevKit detected`, `TestKit detected` nie wystapily, pojawilo sie `Retail console detected`
- `VERDICT: still execute-only and shellcode_kernel's first write WILL fault.` nie wystapil

Wszystkie te napisy sa obecne w `artifacts/1360linux.elf` (potwierdzone wyciagiem stringow), wiec brak komunikatu na ekranie nie wynika z braku takiego napisu w binarce, tylko z tego, ze kod do niego nie doszedl.

Znaczenie praktyczne: bramki wejsciowe `hv_defeat_13xx` (offsety i validity gate) przeszly bez komunikatu odmowy, bo `dump_text_perm` jest od nich pozniejszy. Zawieszenie (lub zablokowanie) nastepuje w petli odczytu stanu tablic stron, przy przejsciu od `KERNEL_CODE_CAVE` do kolejnego obszaru. Konsola zyje (UI Payload Managera i kafelek `1360linux` z ikona ladowania sa widoczne i stabilne), wiec to nie jest panic calego systemu, tylko zatrzymanie watku payloadu. Nagranie nie rozstrzyga, czy watek wisi na odczycie pamieci jadra, czy wypadl z petli bez komunikatu.

## 6. Czego nie udalo sie odczytac

- Brak OCR (tesseract nieobecny), caly odczyt wzrokowy z kamery nagrywajacej ekran, wiec pewnosc znakowa nie jest stuprocentowa.
- Wartosci VA w niektorych klatkach sa ucinane wielokropkiem przez samo UI: `kernel_cfi_check va=0xffffffff9375f8...`, `KERNEL_CODE_CAVE va=0xffffffff93...`, `kernel_uart_override va=0xffffffff91f5...`. Pelne wartosci udalo sie odczytac z innych klatek: `0xffffffff95509598`, `0xffffffff9375f8c0`, `0xffffffff93fc92c0`.
- W klatce d_0090 dolny wpis `kernel_uart_override` pokazuje uciete `va=0xffffffff91f5...`, co nie zgadza sie z `0xffffffff95509598` z klatki d_0088. Nie rozstrzygnieto, czy to drugi komunikat tego samego obszaru, czy znieksztalcenie odczytu (klatka przejsciowa z nalozonym tekstem).
- Nie udalo sie ustalic, jaka tresc maja puste wpisy `Debug:` (na gorze i na dole banera). Wygladaja na komunikaty z pusta trescia, a nie na wpisy uciete przez krawedz banera, bo dolna krawedz banera jest widoczna.
- Baner jest przewijany, wiec kolejnosc wpisow wewnatrz pojedynczej klatki nie jest rownoznaczna z chronologia; kolejnosc w rozdziale 3 odtworzono po momentach pojawiania sie w kolejnych klatkach. Miedzy 8,4 s a 9,3 s baner przewijal sie gwaltownie (klatki przejsciowe z podwojnym tekstem), wiec kolejnosc tam moze byc obarczona bledem.
- Nie widac, czy po 9,3 s payload nadal cos robil bez logowania, czy sie zatrzymal. Nagranie konczy sie 13,9 s, czyli 4,6 s po ostatniej zmianie logu.
- Klatek nie zostawiono w repozytorium (leza w `<work>\klatki\`).
