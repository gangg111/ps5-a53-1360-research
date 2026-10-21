# writeprobe: matryca prob zapisu do pamieci A53 (payload dla systemu Sony).
#
# Budowa payloadu:  env PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make
# Test na komputerze: make test   (gcc, bez konsoli i bez A53)
#
# Zrodla: writeprobe.c (payload: transport, bramki, log), writeprobe_core.c
# (macierz, wzorzec, osad), test_core.c (test hosta na tej samej macierzy).

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
HOSTCC ?= cc

WARN   := -Wall -Wextra -Werror
CFLAGS := $(WARN) -O2 -g

ELF := writeprobe.elf
SRC := writeprobe.c writeprobe_core.c
HDR := writeprobe_core.h

all: $(ELF)

$(ELF): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: test_core
	./test_core

test_core: test_core.c writeprobe_core.c writeprobe_core.h
	$(HOSTCC) -std=c11 $(WARN) -O1 -o test_core test_core.c writeprobe_core.c

clean:
	rm -f $(ELF) test_core

.PHONY: all test clean
