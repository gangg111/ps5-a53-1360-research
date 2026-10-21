PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -Wall -Wextra -Werror -O2 -g

pprbuf.elf: pprbuf.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pprbuf.elf

.PHONY: clean
