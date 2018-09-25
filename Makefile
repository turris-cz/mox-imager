# SPDX-License-Identifier: Beerware

WTMI_PATH := ../wtmi

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

mox-imager.c: wtmi.c
	touch mox-imager.c

wtmi.c: $(WTMI_PATH)/wtmi.bin bin2c
	./bin2c wtmi_data <$(WTMI_PATH)/wtmi.bin >wtmi.c

bin2c: bin2c.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PHONY: wtmi.bin

$(WTMI_PATH)/wtmi.bin:
	make -C $(WTMI_PATH) DEPLOY=1
