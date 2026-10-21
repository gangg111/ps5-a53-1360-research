# PS5 Linux na PS5 Pro, firmware 13.60: instalacja wedlug dokumentacji loadera

Notatka opracowana z dokumentacji i zrodel repozytoriow loadera oraz obrazu.
Kontekst: konsola PS5 Pro, firmware 13.60, loader `soniciso1/ps5-linux-loader` (wydanie v13.60),
Linux wystartowal (widac komunikaty jadra), ale zamiast pulpitu jest czarny ekran z migajacym
podkreslnikiem. Sekcja 9 jest poswiecona wlasnie temu stanowi.

## 1. Co zostalo sprawdzone i skad pochodza informacje

| Element | Ustalenie |
|---|---|
| README loadera | przeczytane w calosci, 343 linie, `gh api repos/soniciso1/ps5-linux-loader/readme` |
| Inne pliki dokumentacji | **brak**. `git/trees/HEAD?recursive=1` pokazuje w calym repo tylko jeden plik `.md`: `README.md`. Nie ma katalogu `docs`. Reszta to zrodla C, Makefile, `logo.webp`, `LICENSE` |
| Wydanie v13.60 | tag `v13.60`, nazwa "ps5-linux-loader 13.60 (PS5 Pro)", jeden zalacznik `ps5-linux-loader.elf`, 205 616 B, opublikowany 2026-10-19 |
| Suma kontrolna loadera | pobralem zalacznik i policzylem: sha256 `32041e7c54db8f1a86a0db0b8fb2a755d8f0209482e29ee903afd059d71b0989`, **zgodna** z podana przez uzytkownika |
| Sciezki i nazwy plikow | README ich **nie opisuje**. Ustalone z `source/loader.c` (funkcje `fetch_linux`, `find_and_get_size_of_file`, `find_and_read_file`) |
| Obraz Linuksa | `ps5-linux-image`, wydanie `latest`, plik `ps5-ubuntu2604.img.xz`, 2 046 295 744 B (1,91 GiB), jadro 7.1.7, patche `56922cf`, build 20260829-182609 |
| Uklad partycji obrazu | `docker/image-builder/entrypoint.sh`: GPT, ext4 od 500 MiB do konca (etykieta `ubuntu2604`), FAT32 1 MiB do 500 MiB (etykieta `boot`, flaga esp) |
| Zawartosc partycji FAT32 | tez `entrypoint.sh`: `bzImage`, `initrd.img`, `cmdline.txt`, `vram.txt`, `kexec.sh` |
| Ustawienia konsoli | README, sekcja "Configure PS5 settings" i "5. Send the payload" |

Uwaga o sumach obrazu: w release notes sa sumy sha256, ale zgloszenie
[ps5-linux-image #28](https://github.com/ps5-linux/ps5-linux-image/issues/28) pokazuje, ze
publikowane sumy nie zgadzaja sie z plikami, i to systemowo (autor sprawdzil dwa niezalezne
zrodla, plik jest zdrowy). Sumy traktuj jako informacyjne, a integralnosc sprawdzaj przez
`xz -t` albo przez Etcher, ktory waliduje strumien xz podczas zapisu.

## 2. Wymagany sprzet

- Nosnik USB **minimum 64 GB**, najlepiej zewnetrzny dysk SSD (README, "Hardwares").
- Klawiatura i mysz USB (adaptery bezprzewodowe tez dzialaja).
- Opcjonalnie: adapter USB WLAN (wbudowany WLAN dziala tylko na ukladach Marvell, patrz
  `ps5-linux-mwifiex`), dysk M.2 zgodny z PS5, adapter Bluetooth do DualSense.
- Do debugowania przy problemach: kabel UART 3,3 V TTL na piny testowe Titania, 230400 8N1
  (README, sekcja o portowaniu na inne firmware).

## 3. Ustawienia konsoli przed uruchomieniem (dokladnie)

README oznacza dwie pierwsze pozycje jako "VERY IMPORTANT".

1. **Rest mode, zasilanie portow USB**:
   `Settings` → `System` → `Power Saving` → `Features Available in Rest Mode` →
   `Supply Power to USB Ports` ustaw na **`Always`**.
   Bez tego nosnik traci zasilanie w rest mode. Loader wczytuje `bzImage` i `initrd.img` do
   pamieci **przed** uspieniem, ale system plikow root lezy na tym samym nosniku, wiec po
   wybudzeniu root sie nie zamontuje.
2. **Wylacz HDMI Device Link**:
   `Settings` → `HDMI` → `Enable HDMI Device Link` (wylaczone).
3. Zalecane, wylacz automatyczne aktualizacje:
   `Settings` → `System Software` → `System Software Update and Settings`.
4. Zalecane, wylacz automatyczne raportowanie bledow:
   `Settings` → `System Software` → `Report System Software Errors Automatically`.
5. **Wylacz etaHEN i kstuff** przed wyslaniem loadera. README: jesli konsola zawiesza sie
   zamiast wejsc w rest mode, to prawie zawsze wina etaHEN/kstuff, ktore sa niekompatybilne.
6. Po resecie ustawien konsoli albo po reinstalacji firmware te ustawienia trzeba ustawic
   ponownie (README mowi to wprost).

## 4. Przygotowanie nosnika USB

### 4.1 Ktory plik pobrac

Z wydania [ps5-linux-image, tag latest](https://github.com/ps5-linux/ps5-linux-image/releases/tag/latest)
plik **`ps5-ubuntu2604.img.xz`**. README loadera wskazuje ten plik jako zalecany.
Bezposredni adres z release notes:

```
https://pub-561df4012f1a46fbbdf618d5cc5941f6.r2.dev/ps5-ubuntu2604.img.xz
```

To obraz calej Ubuntu 26.04 (GNOME), nie sam rootfs. Alternatywy z tego samego wydania:
`ps5-arch.img.xz`, `ps5-cachyos.img.xz` (Gamescope + Steam), `ps5-fedora.img.xz` (GNOME),
`ps5-debian.img.xz`, `ps5-bazzite.img.xz`, `ps5-steamos.img.xz`, `ps5-proxmox.img.xz`.

### 4.2 Rozpakowanie

Plik jest skompresowany xz. Rozpakuj go do surowego `.img` (Etcher potrafi tez przyjac `.xz`
bezposrednio, wtedy pomijasz ten krok):

```
xz -d ps5-ubuntu2604.img.xz
```

Na Windows: 7-Zip albo `tar -xf` w PowerShell (Windows 11 ma xz w `tar`). Rozmiar po
rozpakowaniu to okolo 12 GB (obraz budowany z `--img-size 12000`).

### 4.3 Zapis na nosnik

Zapisujesz **obraz calego dysku**, nie plik na partycje. To kasuje tablice partycji nosnika.

Linux/macOS (README):

```
# nazwe dysku sprawdz przez lsblk albo diskutil list
sudo dd if=ps5-ubuntu2604.img of=/dev/sdX bs=4M status=progress conv=fsync
```

Windows (README): [Balena Etcher](https://etcher.balena.io/), wybierz `.img`, wybierz nosnik,
`Flash`. Etcher wymaga uprawnien administratora. Zamiennikiem jest Rufus (uzywany przez
zglaszajacych w issues).

### 4.4 Uklad po zapisie (wazne dla zrozumienia, gdzie loader szuka plikow)

Obraz ma tablice GPT i dwie partycje:

| Partycja | Polozenie | System plikow | Etykieta | Rola |
|---|---|---|---|---|
| p2 | 1 MiB do 500 MiB (fizycznie pierwsza) | FAT32, flaga esp | `boot` | `bzImage`, `initrd.img`, `cmdline.txt`, `vram.txt`, `kexec.sh`, `lib/nxp/` |
| p1 | 500 MiB do konca | ext4 | `ubuntu2604` | system plikow root Ubuntu |

Konsola montuje partycje FAT32 jako `/mnt/usb0`, co potwierdza zapisany w tym repo przebieg
startu: [1360LINUX-NAGRANIE-KOMUNIKATY.md](1360LINUX-NAGRANIE-KOMUNIKATY.md), linia 23,
zawiera komunikaty
`File 'initrd.img' found in '/mnt/usb0/'` i `File 'bzImage' found in '/mnt/usb0/'`.
Partycji ext4 konsola nie montuje i nie musi, wazna jest jej etykieta, bo jadro dostaje
`root=LABEL=ubuntu2604`.

### 4.5 Co lezy na partycji FAT32 i czy trzeba cos dokopiowywac

Nie trzeba nic dokopiowywac. Obraz jest kompletny: budowanie kopiuje `bzImage`, `initrd.img`,
`cmdline.txt`, `vram.txt` i `kexec.sh` na FAT32 (`entrypoint.sh`, etap "Assembling boot
partition"). Po zapisaniu nosnika na komputerze zobaczysz maly dysk okolo 499 MB z tymi
plikami. Windows nie zamontuje partycji ext4, to normalne, nie formatuj jej.

Jedyne, co warto zrobic na tym etapie, to zajrzec do `cmdline.txt` i ewentualnie go poprawic
(sekcja 9.3). Domyslna tresc dla Ubuntu:

```
root=LABEL=ubuntu2604 rw rootwait console=ttyTitania0 console=tty0 video=DP-1:1920x1080@60 mitigations=off idle=halt preempt=full
```

### 4.6 Weryfikacja przed wlozeniem do konsoli

Linux: `sudo blkid /dev/sdX2` powinien pokazac `LABEL="boot"` i `TYPE="vfat"`, a
`sudo blkid /dev/sdX1` `LABEL="ubuntu2604"` i `TYPE="ext4"`. Jesli etykieta root jest inna,
jadro nie zamontuje root i trzeba albo poprawic etykiete (`e2label`), albo `cmdline.txt`.

Windows: sprawdz, ze maly dysk FAT32 ma etykiete `boot` i zawiera `bzImage`, `initrd.img`,
`cmdline.txt`, `vram.txt`.

### 4.7 Porty USB

README, "3. Plug the USB drive into your PS5":

- przedni dolny port Type-C: tak,
- tylne porty Type-A: tak,
- przedni gorny port Type-A: to USB 2.0, wolniejszy, niezalecany.

Klawiature i mysz podlacz do pozostalych portow, najlepiej tylnych Type-A. Warto sprawdzic
kilka portow, bo w wydaniu 13.60 stabilnosc USB nie jest gwarantowana (ostrzezenie na gorze
README).

## 5. Skad loader bierze jadro i initrd

To najwazniejsza czesc, ktorej README nie opisuje. Zrodlo: `source/loader.c`.

### 5.1 Kolejnosc katalogow

Loader szuka plikow w tej kolejnosci i bierze pierwszy trafiony:

1. `/mnt/usb0/`
2. `/mnt/usb1/`
3. `/mnt/usb2/`
4. `/mnt/usb3/`
5. `/mnt/usb0/PS5/Linux/`
6. `/mnt/usb1/PS5/Linux/`
7. `/mnt/usb2/PS5/Linux/`
8. `/mnt/usb3/PS5/Linux/`

Praktyczne skutki:

- pliki lezace bezposrednio w katalogu glownym partycji FAT32 maja pierwszenstwo przed
  podkatalogiem `PS5/Linux/`,
- jesli do konsoli sa podlaczone dwa nosniki, wygrywa ten zamontowany jako `/mnt/usb0`,
- `usb0` to partycja FAT32 z obrazu. Loader czyta **tylko** partycje, ktore widzi system PS5,
  a ten montuje FAT32 (i exFAT), nie ext4.

### 5.2 Nazwy plikow, ktorych szuka loader

| Plik | Wymagany | Rola | Zachowanie przy braku |
|---|---|---|---|
| `bzImage` | tak | obraz jadra Linuksa, kopiowany bajt w bajt | `File bzImage not found at default paths - Aborting`, payload konczy prace |
| `initrd.img` | tak | initramfs | w kodzie jest blad: sprawdzany jest rozmiar `bzImage`, wiec przy braku initrd zobaczysz `[-] Error could not allocate initrd (...)` zamiast czytelnego komunikatu |
| `cmdline.txt` | nie | linia polecen jadra, do 2047 bajtow, konczacy sie znak nowej linii jest obcinany | wpisuje sie wbudowana domyslna linia (`root=/dev/sda2 rw rootwait console=ttyTitania0 console=tty0 video=DP-1:1920x1080@60 mitigations=off idle=halt pci=pcie_bus_perf`) |
| `vram.txt` | nie | rozmiar VRAM w hex, domyslnie `0x20000000` (512 MB); 0 albo smieci daja fallback | 512 MB |
| `path-override.txt` | nie | podmiana nazw plikow dla `bzImage` i `initrd.img` | brak |

`path-override.txt` dziala tylko dla `bzImage` i `initrd.img`. Format: jedna regula w linii,
`nazwa=inna_nazwa`, np. `bzImage=bzImage-7.1.7`. Dla `cmdline.txt` i `vram.txt` podmiana
nie dziala, bo te pliki sa czytane inna funkcja, ktora nie sprawdza override.

Struktura wielodystrybucyjna (obraz `--distro all`) ma na FAT32 `initrd-ubuntu2604.img`,
`cmdline-ubuntu2604.txt` i `kexec-<dystro>.sh`. Loader domyslnie czyta `initrd.img` i
`cmdline.txt`, wiec dla Ubuntu dostaje kopie wlasciwych plikow (budowanie robi je jako
`initrd.img` i `cmdline.txt`).

### 5.3 Co loader zapisuje na nosnik

Przed startem Linux loader zrzuca firmware WiFi konsoli na partycje FAT32, obok pliku
startowego:

```
/mnt/usb0/lib/nxp/pcieuartiw620_combo_v1.bin
```

W zapisanym przebiegu mial 500 296 B
([1360LINUX-NAGRANIE-KOMUNIKATY.md](1360LINUX-NAGRANIE-KOMUNIKATY.md)). Wynika z
tego, ze partycja FAT32 musi byc **zapisywalna** i miec miejsce. Ten sam plik czyta potem
usluga `ps5-stage-firmware` w Linuksie z `/boot/efi/lib/nxp/`.

### 5.4 Czego loader nie robi

- Nie sprawdza zawartosci `bzImage` ani `initrd.img` (zadnego magicznego naglowka), patrzy
  tylko na rozmiar i poprawnosc odczytu. Zly plik pod wlasciwa nazwa zostanie podany jadru.
- Nie montuje niczego sam i nie szuka plikow po etykietach.
- Nic nie kopiuje na nosnik poza firmware WiFi.

## 6. Kolejnosc dzialan przy pierwszym uruchomieniu

1. Ustaw wszystko z sekcji 3 (rest mode USB `Always`, HDMI Device Link off, etaHEN/kstuff off).
2. Przygotuj nosnik z sekcji 4 i wloz go do przedniego dolnego Type-C albo tylnego Type-A.
3. Zrob **zimny start** konsoli (wylacz i wlacz). Komentarz w `source/loader.c` mowi wprost,
   ze loader wymaga swiezego rozruchu, bo poprzednia sesja zostawia jadro z `.text` jako RW i
   wyczyszczone VMCB. Nie wysylaj loadera z rest mode ani po poprzedniej probie.
4. Uruchom jailbreak dla 13.60 i uzyskaj mozliwosc wyslania payloadu na port 9021.
   README loadera opisuje tylko firmware 3.00 do 7.61 (umtx2 albo Y2JB), dla 13.60 sciezka
   jest poza tym dokumentem.
5. Wyslij loader. Najpierw sprawdz sume pliku (Windows):

   ```
   (Get-FileHash .\ps5-linux-loader.elf -Algorithm SHA256).Hash
   ```

   Ma wyjsc `32041E7C54DB8F1A86A0DB0B8FB2A755D8F0209482E29EE903AFD059D71B0989`
   (wydanie v13.60, 205 616 B). Wysylka:

   ```
   socat -t 99999999 - TCP:$PS5IP:9021 < ps5-linux-loader.elf
   ```

   W tym repo ta sama czynnosc robi Payload Manager. Loader wypisze w logu m.in.
   `File 'bzImage' found in '/mnt/usb0/'`, `File 'cmdline.txt' found in '/mnt/usb0/'`,
   na PS5 Pro `PS5 Pro retail console detected`, a na koncu
   `Finished preparation. Going to rest mode in 5 seconds...`.
6. Loader sam wchodzi w rest mode (`sleep(5)`, potem `enter_rest_mode()`). Proces payloadu
   zostaje w petli `while(1) sleep(30)`, wiec w Payload Managerze wyglada jakby dzialal dalej.
   To normalne.
7. **Czekaj, az pomaranczowa dioda przestanie migac i bedzie swiecic ciagle.** Dopiero wtedy
   nacisnij przycisk zasilania. README: jesli konsola wroci do systemu PS5, to znaczy, ze
   przycisk nacisniety za wczesnie albo ustawienia rest mode nie sa wlaczone.
8. Przy udanym starcie dioda **zmienia kolor na bialy** i startuje jadro Linuksa. Komunikaty
   jadra leca na HDMI, bo w `cmdline.txt` jest `console=tty0`.

## 7. Etapy, ktore wygladaja jak zawieszenie

README nie podaje czasow. Konkretne liczby, ktore da sie ustalic z kodu i z zachowania obrazu:

| Etap | Co widac | Ile trwa | Zrodlo |
|---|---|---|---|
| po komunikacie loadera | 5 s do wejscia w rest mode | rowne 5 s | `source/main.c`, `sleep(5)` |
| rest mode | migajaca pomaranczowa dioda, potem ciagle swiatlo | nie podano, zwykle kilkadziesiat sekund | README |
| wybudzenie | czarny ekran, potem komunikaty jadra | kilka sekund | obserwacja |
| pierwszy start Ubuntu | brak pulpitu, konsola tekstowa, kreator lub GDM startuje pozniej | kilka minut, patrz nizej | obraz: `grow-rootfs` + GDM/GNOME |
| pierwszy start, powiekszanie rootfs | root rosnie z 12 GB do rozmiaru nosnika | `growpart` i `resize2fs` na USB, minuty | `distros/ubuntu2604/grow-rootfs` |

Praktyczna regula: po wybudzeniu nie wylaczaj konsoli przed uplywem **10 minut** bez dowodu,
ze system stoi. Dowody: brak migania diody na nosniku, brak odpowiedzi na przelaczenie
wirtualnej konsoli (sekcja 9), brak nowych komunikatow.

Objawy, ktore wygladaja groznie, a sa normalne:

- proces payloadu wisi w Payload Managerze (petla `sleep(30)`),
- po kolejnym rozruchu system PS5 pokazuje `Repairing` i `Your PS5 wasn't turned off
  properly` (README, FAQ: to normalne i nieszkodliwe),
- ekran gasnie po bezczynnosci i nie wraca (README, `Bugs`: wygaszacz nie dziala poprawnie,
  trzeba go wylaczyc; [issue #8](https://github.com/ps5-linux/ps5-linux-image/issues/8)).

## 8. Pierwszy start: kreator, ekran logowania, haslo

README, "First Boot", pierwsze zdanie: **"Configure your system and memorize your login
password."** Czyli konto i haslo ustawia sie na pierwszym starcie i trzeba je zapamietac.

Czego **nie** ma:

- Obraz Ubuntu **nie ma domyslnego konta ani hasla**. W `distros/ubuntu2604/image.yaml` nie ma
  ani `useradd`, ani `chpasswd`, a `post-update` robi `passwd -l root` (root zablokowany).
  W innych obrazach z tego samego repo domyslne konta sa i warto je znac dla porownania:

  | Obraz | Konto i haslo | Dowod |
  |---|---|---|
  | Arch | `ps5` / `ps5` | `distros/arch/image.yaml`; [issue #2](https://github.com/ps5-linux/ps5-linux-image/issues/2) |
  | Batocera | `ps5` / `ps5` oraz root `ps5` | `distros/batocera/build-rootfs.sh` |
  | SteamOS | `deck` / `deck`, sudo bez hasla | `distros/steamos/build-rootfs.sh` |
  | Fedora | `ps5` z autologinem GDM | `distros/fedora/image.yaml` |
  | Debian | `ps5` z autologinem LightDM | `distros/debian/image.yaml` |
  | Ubuntu 26.04 | konto tworzone na pierwszym starcie, brak wartosci domyslnych | j.w. |

- Pulpit to GNOME pod GDM (pakiety: `ubuntu-desktop`, `gnome-software`, `firefox`).
- `openssh-server` jest zainstalowany i wlaczony, z `PasswordAuthentication yes`, ale
  `PermitRootLogin no`. SSH przydaje sie do diagnostyki **dopiero gdy konto istnieje**.

Pierwsze kroki po zalogowaniu (README, "First Boot"):

1. Wylacz wygaszacz ekranu, jest zepsuty.
2. Jesli nie ma internetu, wylacz i wlacz polaczenie przewodowe/WLAN.
3. Zablokuj aktualizacje jadra:

   ```
   sudo apt-mark hold linux-generic linux-generic-hwe-24.04 linux-generic-hwe-26.04 linux-image-generic linux-image-generic-hwe-24.04 linux-image-generic-hwe-26.04 linux-headers-generic linux-headers-generic-hwe-24.04 linux-headers-generic-hwe-26.04
   ```

4. `sudo snap install firefox`
5. Mesa: `sudo snap refresh mesa-2404 --channel=latest/edge`, potem
   `sudo add-apt-repository ppa:kisak/kisak-mesa`, `sudo apt update`, `sudo apt upgrade`.
6. `git clone https://github.com/ps5-linux/ps5-linux-tools`, `make` (po `sudo apt install zlib1g-dev`).
7. Jesli `lspci -nn` pokaze Marvell `1b4b:2b56`, zainstaluj `ps5-linux-mwifiex`.

## 9. Czarny ekran z migajacym podkreslnikiem

Objaw: komunikaty jadra zniknely, ekran czarny, w lewym gornym rogu miga podkreslnik.
To znaczy, ze **jadro dziala i konsola tekstowa (`tty0`) dziala**, a nie uruchomil sie
srodowisko graficzne albo system jeszcze nie doszedl do GDM. README opisuje tylko przypadek
"dioda biala, ale czarny ekran" (sekcja 9.3), nie opisuje konsoli tekstowej, wiec ponizsza
sciezka jest wyprowadzona z dokumentacji, z kodu obrazu i z zgloszen w issues.

### 9.1 Najpierw ustal stan, w jakim konsola jest

| Obserwacja | Wniosek |
|---|---|
| dioda biala | Linux dziala, loader i resume zadzialaly |
| dioda pomaranczowa, brak bialej | start Linuksa sie nie zaczal, patrz sekcja 6 i rest mode |
| dioda na nosniku USB miga | system pracuje, root jest zamontowany, cos sie dzieje (np. `resize2fs`) |
| klawiatura reaguje na Num Lock/Caps Lock | konsola i USB zyja, mozna przelaczac wirtualne konsole |
| brak reakcji klawiatury | port USB albo sterownik, zmien port na tylny Type-A |

### 9.2 Cztery proby po kolei

1. **Daj czas.** Pierwszy start robi `growpart` i `resize2fs` na partycji ext4, potem startuje
   GDM i GNOME. Odczekaj do 10 minut, patrzac na diode nosnika.
2. **Przelacz wirtualna konsole.** Wcisnij `Ctrl+Alt+F2`, potem `Ctrl+Alt+F3`, `F4`.
   Jesli pojawi sie `ps5 login:` albo `ubuntu login:`, system zyje, a problem jest tylko w
   GDM. Wtedy zaloguj sie i sprawdz:

   ```
   systemctl status gdm
   journalctl -b -p 3
   ps aux | grep -E "gdm|gnome-shell|Xorg|gnome-initial-setup"
   ```

   Migajacy podkreslnik bez tekstu na tty1 to typowy obraz GDM, ktory zajal konsole i nie
   narysowal ekranu logowania. Uwaga: jesli sesja graficzna dziala, Wayland przechwytuje
   klawiature i skrot moze nie dzialac. Wtedy zostaje SSH (9.5) albo ratunek z 9.6.
3. **Zajrzyj na nosnik z komputera.** Po wylaczeniu konsoli sprawdz, czy na FAT32 nie ma
   smieciowych `bzImage` albo `initrd.img` w katalogu glownym, ktorys z nich moze byc podany
   zamiast wlasciwego. Loader nie weryfikuje zawartosci.
4. **Sprawdz, czy root w ogole sie zamontowal.** Na komputerze: `blkid` na partycji ext4
   nosnika musi dac `LABEL="ubuntu2604"`. Jesli etykieta jest inna, jadro nie znajdzie root i
   utknie. Popraw `e2label` albo `root=LABEL=` w `cmdline.txt`.

### 9.3 Poprawki `cmdline.txt` (README, sekcja o czarnym ekranie)

Plik lezy w katalogu glownym partycji FAT32. Kazda zmiana wymaga ponownego wyslania loadera,
bo `cmdline.txt` jest czytany przy kazdym uruchomieniu.

- Usun `video=DP-1:1920x1080@60`. README: niektore monitory daja czarny ekran przy tym
  parametrze, potwierdzone dzialanie bez niego na MSI MAG274Q QD E2, DELL S2721DGF,
  DELL U2515H.
- Dodaj `amdgpu.force_1080p=1`.
- Przetestuj HDCP na wlaczonym i na wylaczonym.
- Sprobuj innego monitora albo capture card, najlepiej w innej rozdzielczosci.
- Do diagnostyki warto dodac `drm.debug=0x116`, ale tylko krotko: zalewa UART i ekran.

### 9.4 Wejscie do systemu bez trybu graficznego

Dopisz do `cmdline.txt`:

```
systemd.unit=multi-user.target
```

Wtedy system nie startuje GDM, a na `tty1` powinien pojawic sie tekstowy login. Nadal
potrzebujesz konta. Jesli kreator pierwszego startu zdazyl je zalozyc, to jest to najprostsza
droga do sprawdzenia `journalctl` i do naprawy GDM. Jesli konta nie ma, uzyj 9.6.

### 9.5 SSH jako druga droga

Jesli konto istnieje (np. z poprzedniej instalacji), podlacz kabel Ethernet (sterownik `gbe`
dziala na wszystkich modelach), znajdz adres w routerze i wejdz po SSH:

```
ssh <uzytkownik>@<ip>
systemctl status gdm
journalctl -b -p 3
gdctl show
```

### 9.6 Ratunek: zalozenie konta bez logowania

Gdy nie ma zadnego konta, a ekran nie pokazuje kreatora, mozna wejsc do systemu jako root
bez hasla, podstawiajac wlasny program init. To standardowa technika ratunkowa Linuksa, nie
jest opisana w README loadera. W `cmdline.txt` dopisz na koncu:

```
init=/bin/bash
```

Po starcie dostaniesz powloke roota na konsoli (bez systemd, bez sieci). Wykonaj:

```
mount -o remount,rw /
useradd -m -s /bin/bash -G sudo,video,audio,input,render ps5
passwd ps5
sync
reboot -f
```

Potem **usun** `init=/bin/bash` z `cmdline.txt` i wyslij loader ponownie. Konto jest gotowe,
haslo znasz, a GDM powinien pokazac ekran logowania. Diagnostyke systemu robi sie juz normalnie
po zalogowaniu.

### 9.7 Gdy GDM dziala, ale ekran jest czarny na monitorze 4K

Znane zgloszenie: [ps5-linux-image #27](https://github.com/ps5-linux/ps5-linux-image/issues/27).
Na czesci monitorow 4K ekran logowania GDM jest czarny, choc system, SSH i GNOME dzialaja.
Obejscie: przestaw ekran GDM na 1920x1080 przez `gdctl`, wtedy logowanie staje sie widoczne,
a sesja uzytkownika po zalogowaniu sama przelacza sie na 4K. Skrot z issue:

```
GREETER_SESSION=$(loginctl list-sessions --no-legend | awk '$3=="gdm-greeter" && $4=="seat0" {print $1; exit}')
GREETER_UID=$(loginctl show-session "$GREETER_SESSION" -p User --value)
GNOME_PID=$(ps -u "$GREETER_UID" -o pid=,comm= | awk '$2=="gnome-shell" {print $1; exit}')
DBUS_ADDR=$(sudo cat "/proc/$GNOME_PID/environ" | tr '\0' '\n' | sed -n 's/^DBUS_SESSION_BUS_ADDRESS=//p')
RUNTIME_DIR=$(sudo cat "/proc/$GNOME_PID/environ" | tr '\0' '\n' | sed -n 's/^XDG_RUNTIME_DIR=//p')
sudo -u "#$GREETER_UID" env DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR" XDG_RUNTIME_DIR="$RUNTIME_DIR" gdctl set -P -L -M DP-1 --mode 1920x1080@60.000 --primary --scale 1.0
```

### 9.8 Gdy nic nie pomaga

README: zglos problem na
[Discord](https://discord.gg/PeMGVB7BAm) i **dolacz informacje EDID** monitora. Do raportu
warto dodac: firmware konsoli, model konsoli, wersje loadera i jego sha256, zawartosc
`cmdline.txt` i `vram.txt`, wynik `blkid` nosnika, zachowanie diody i to, co pokazuje UART
(sekcja 10).

## 10. Debug: UART, logi, tryb debugowania

- **UART** (README, sekcja o portowaniu): 3,3 V TTL na piny testowe Titania, 230400 8N1.
  W `cmdline.txt` jest `console=ttyTitania0`, wiec **komunikaty jadra ida takze na UART**.
  README mowi wprost: bez UART proba uruchomienia nowego firmware jest slepa, bo nieudany
  resume konczy sie brakiem sieci i brakiem obrazu.
- **Log loadera na dysku konsoli**: `notify()` w `source/utils.c` dopisuje kazdy komunikat do
  `/data/ps5lin_probe.log`. To najpewniejszy slad po przebiegu, bo log na ekranie PS5 jest
  przewijany. Plik da sie wyciagnac z konsoli przez ftpsrv/Payload Manager.
- **Tryb debugowania**: `include/config.h` ma `#define DEBUG 0` (0 wylacza logi). Szczegolowe
  `DEBUG_PRINT` sa w `source/gpu.c` i `source/iommu.c` i nie sa wlaczone w wydaniu.
- **Marker postepu**: shellcode wypisuje na UART markery `SCK>B8-bzimage-copied`,
  `SCK>B9-initrd-copied`, `SCK>0-entered`. Widac z nich, ktory etap resume doszedl.

## 11. Znane problemy (README, "Bugs", plus issues)

- wygaszacz ekranu nie dziala poprawnie; po zgaszeniu ekranu czesto nie da sie go obudzic,
  mimo ze system odpowiada ([issue #8](https://github.com/ps5-linux/ps5-linux-image/issues/8),
  [issue #15](https://github.com/ps5-linux/ps5-linux-image/issues/15)). Wylacz wygaszacz.
- dzwiek po HDMI nie dziala na czesci monitorow.
- wyjscie 1440p i 2160p nie dziala na czesci monitorow. Potwierdzone 1080p, 1440p, 2160p przy
  60 Hz; 1440p przy 120 Hz potwierdzone tylko na DELL S3225QC.
- ekran logowania GDM czarny na czesci monitorow 4K ([issue #27](https://github.com/ps5-linux/ps5-linux-image/issues/27)).
- publikowane sumy sha256 obrazow nie zgadzaja sie z plikami ([issue #28](https://github.com/ps5-linux/ps5-linux-image/issues/28)).
- wydanie 13.60 jest **eksperymentalne**: stabilnosc USB, obrazu i urzadzen peryferyjnych nie
  jest gwarantowana (ostrzezenie na gorze README).
- jesli w grach sa artefakty graficzne, dodaj `RADV_DEBUG=nohiz`.

## 12. Ograniczenia i czego nie robic

- To soft-mod: **kazde** uruchomienie Linuksa wymaga ponownego exploit i wyslania loadera.
  Nie ma dual bootu.
- Nie ma uspienia i wybudzenia Linuksa (FAQ: standby nie jest wspierany).
- Nie aktualizuj firmware, jesli jestes na 11.60 lub nizej, bo tracisz fPKG. Na 12.00 do 13.60
  aktualizacja do 13.60 jest bezpieczna.
- Nie zostawiaj `init=/bin/bash` w `cmdline.txt`.
- Nie zmieniaj ukladu partycji nosnika i nie formatuj go po zapisaniu obrazu.
- Fan i boost: `sudo ./ps5_control --fan on`, `sudo ./ps5_control --boost on`. Zawsze najpierw
  fan, potem boost, tak jak robi to system PS5.
- M.2 jako osobny dysk Linuksa jest opcjonalny: `m2_init`, `m2_install.sh --install <img>`,
  potem `m2_exec.sh`, a na stale `root=LABEL=ubuntu2604-m2` w `/boot/efi/cmdline.txt`.
- Aktualizacje Linuksa: `.deb` albo `.pkg.tar.zst` z
  [ps5-linux-patches](https://github.com/ps5-linux/ps5-linux-patches/releases).

## 13. Zrodla

- [soniciso1/ps5-linux-loader, README](https://github.com/soniciso1/ps5-linux-loader)
- [wydanie v13.60](https://github.com/soniciso1/ps5-linux-loader/releases/tag/v13.60)
- `source/loader.c`, `source/main.c`, `source/utils.c`, `source/firmware.c`, `include/config.h` (ten sam tag)
- [ps5-linux/ps5-linux-image, README](https://github.com/ps5-linux/ps5-linux-image) i wydanie `latest`
- `docker/image-builder/entrypoint.sh`, `distros/ubuntu2604/image.yaml`, `boot/cmdline.txt`,
  `boot/vram.txt`, `distros/ubuntu2604/grow-rootfs`
- [ps5-linux-image #27](https://github.com/ps5-linux/ps5-linux-image/issues/27),
  [#28](https://github.com/ps5-linux/ps5-linux-image/issues/28),
  [#8](https://github.com/ps5-linux/ps5-linux-image/issues/8),
  [#2](https://github.com/ps5-linux/ps5-linux-image/issues/2)
- [AMD BC250 Documentation](https://elektricm.github.io/amd-bc250-docs/)
- zapis przebiegu z tej konsoli: [1360LINUX-NAGRANIE-KOMUNIKATY.md](1360LINUX-NAGRANIE-KOMUNIKATY.md)
