# SPDX-License-Identifier: Beerware

CC := gcc
CFLAGS := -O2
LDFLAGS := -lm -lcrypto

SRCS = $(filter-out bin2c.c wtmi.c,$(wildcard *.c))
OBJS = $(patsubst %.c,%.o,$(SRCS))

all: mox-imager

clean:
	rm -f mox-imager $(OBJS) bin2c bin2c.o wtmi.c

mox-imager: $(OBJS)
	$(CC) $(CFLAGS) -o mox-imager $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

mox-imager.c: wtmi.c

wtmi.c: wtmi.bin bin2c
	./bin2c wtmi_data <wtmi.bin >wtmi.c

bin2c: bin2c.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
