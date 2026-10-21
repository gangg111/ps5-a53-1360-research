# sdbgp: payload z hookiem jadra na funkcji budujacej pakiety SDBGP dla A53.
#
# Budowa:  env PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make
#
# Warianty (opcjonalne):
#   make SDBGP_OKNO_MS=2000     krotsze okno obserwacji na jeden rdzen
#   make SDBGP_RDZENIE_MAX=4    tylko cztery pierwsze rdzenie
#   make SDBGP_SAMOTEST=0       bez samotestu na SYS_GETUID
#
# Zrodla hooka (khook.c, kdlsym.c, util.c, include/) sa skopiowane z
# tools/mp4cmd, ktory z kolei wzial je z tools/pprhook i projektu
# Byepervisor-Reborn; sumy kontrolne tych plikow sa identyczne. util.c ma
# pin_to_core_mask, ktora pozwala przelaczac kolejnosc bitow w masce procesora.

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang

WARN    := -Wall -Wextra -Werror -Wno-unused-function
CFLAGS  := $(WARN) -O2 -g -I./include
ifdef SDBGP_OKNO_MS
CFLAGS  += -DSDBGP_OKNO_MS=$(SDBGP_OKNO_MS)
endif
ifdef SDBGP_RDZENIE_MAX
CFLAGS  += -DSDBGP_RDZENIE_MAX=$(SDBGP_RDZENIE_MAX)
endif
ifdef SDBGP_SAMOTEST
CFLAGS  += -DSDBGP_SAMOTEST=$(SDBGP_SAMOTEST)
endif

ELF := sdbgp.elf
SRC := sdbgp.c khook.c kdlsym.c util.c

all: $(ELF)

$(ELF): $(SRC) include/khook.h include/kdlsym.h include/util.h \
        include/offsets/13_00.h include/offsets/13_20.h include/offsets/13_60.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(ELF)

.PHONY: all clean
