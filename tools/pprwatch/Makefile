PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -Wall -O2 -g

pprwatch.elf: pprwatch.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pprwatch.elf

.PHONY: clean
