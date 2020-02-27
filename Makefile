# SPDX-License-Identifier: Beerware

WTMI_PATH := ../wtmi

CC := gcc
CFLAGS := -O2
LDFLAGS := -lm -lcrypto

SRCS = $(filter-out gppc.c bin2c.c wtmi.c,$(wildcard *.c))
DEPS = $(patsubst %.c,%.d,$(SRCS))
OBJS = $(patsubst %.c,%.o,$(SRCS))

GPPC_SRCS = gppc.c instr.c utils.c

GPPS = $(patsubst %.gpp,%.c,$(wildcard gpp/*.gpp))
GPPS_DEPS = $(patsubst %.c,%.d,$(GPPS))

all: mox-imager

clean:
	rm -f mox-imager $(OBJS) bin2c gppc bin2c.o wtmi.c $(GPPS) $(patsubst %.c,%.gpp.bin,$(GPPS)) $(patsubst %.c,%.gpp.pre,$(GPPS)) $(DEPS) $(GPPS_DEPS)

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

$(patsubst %.c,%.gpp.pre,$(GPPS)): %.gpp.pre: %.gpp
	$(CC) -E -x assembler-with-cpp $< >$@

$(patsubst %.c,%.gpp.bin,$(GPPS)): %.gpp.bin: %.gpp.pre gppc
	./gppc -o $@ $<

$(GPPS): %.c: %.gpp.bin bin2c
	./bin2c GPP_$(patsubst gpp/%.c,%,$@) <$< >$@

$(GPPS_DEPS): %.d: %.gpp
	@set -e; rm -f $@; \
	$(CC) -x assembler-with-cpp -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

tim.c: $(GPPS)

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PHONY: wtmi.bin

$(WTMI_PATH)/wtmi.bin:
	make -C $(WTMI_PATH) DEPLOY=1

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS) $(GPPS_DEPS)
endif
