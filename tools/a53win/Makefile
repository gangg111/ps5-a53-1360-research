PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -Wall -O2 -g

a53win.elf: a53win.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f a53win.elf

.PHONY: clean
