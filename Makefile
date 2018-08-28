# SPDX-License-Identifier: Beerware

CC := gcc
CFLAGS := -O2
LDFLAGS := -lm -lcrypto

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))

all: mox-imager

clean:
	rm -f mox-imager $(OBJS)

mox-imager: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o mox-imager $(OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
