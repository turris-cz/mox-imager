# SPDX-License-Identifier: Beerware

WTMI_PATH := ../wtmi

CC := gcc
CFLAGS := -O2
LDFLAGS := -lm -lcrypto

SRCS = $(filter-out gppc.c bin2c.c wtmi.c,$(wildcard *.c))
OBJS = $(patsubst %.c,%.o,$(SRCS))

GPPC_SRCS = gppc.c instr.c utils.c

GPPS = $(patsubst %.gpp,%.c,$(wildcard gpp/*.gpp))

all: mox-imager

clean:
	rm -f mox-imager $(OBJS) bin2c gppc bin2c.o wtmi.c $(GPPS)

mox-imager: $(OBJS)
	$(CC) $(CFLAGS) -o mox-imager $(OBJS) $(LDFLAGS)

mox-imager.c: wtmi.c
	touch mox-imager.c

tim.c: $(GPPS)

wtmi.c: $(WTMI_PATH)/wtmi.bin bin2c
	./bin2c wtmi_data <$(WTMI_PATH)/wtmi.bin >wtmi.c

bin2c: bin2c.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

gppc: $(GPPC_SRCS)
	$(CC) $(CPPFLAGS) -DGPP_COMPILER $(CFLAGS) -o $@ $(GPPC_SRCS)

$(GPPS): %.c: %.gpp gppc bin2c
	$(CC) -E -x assembler-with-cpp $< | ./gppc | ./bin2c GPP_$(patsubst gpp/%.c,%,$@) >$@

tim.c: $(GPPS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PHONY: wtmi.bin

$(WTMI_PATH)/wtmi.bin:
	make -C $(WTMI_PATH) DEPLOY=1
