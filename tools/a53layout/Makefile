PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -Wall -O2 -g

a53layout.elf: a53layout.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f a53layout.elf

.PHONY: clean

