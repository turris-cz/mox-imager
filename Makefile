# SPDX-License-Identifier: Beerware

WTMI_PATH := ../wtmi

override TIM_VERSION = $(shell git describe --always --dirty --tags)
ifndef TIM_VERSION
$(error Repository is without git tags, please do a full git clone again)
endif

CC := gcc
CFLAGS := -O2 -Wall -pthread
ifeq ($(STATIC_LIBCRYPTO), 1)
	LDFLAGS_LIBCRYPTO := -l:libcrypto.a -ldl
else
	LDFLAGS_LIBCRYPTO := -lcrypto
endif
LDFLAGS := -lm -ltinfo $(LDFLAGS_LIBCRYPTO)

SRCS = $(filter-out gppc.c bin2c.c bundled-wtmi.c read-otp-%.c,$(wildcard *.c))
DEPS = $(patsubst %.c,%.d,$(SRCS))
OBJS = $(patsubst %.c,%.o,$(SRCS))

GPPC_SRCS = gppc.c instr.c utils.c

GPPS = $(patsubst %.gpp,%.c,$(wildcard gpp/*.gpp))
GPPS_DEPS = $(patsubst %.c,%.d,$(GPPS))

all: mox-imager

clean:
	rm -f mox-imager $(OBJS) bin2c gppc bin2c.o $(GPPS) $(patsubst %.c,%.gpp.bin,$(GPPS)) $(patsubst %.c,%.gpp.pre,$(GPPS)) $(DEPS) $(GPPS_DEPS) gpp/version gpp/version.gpp.inc

mox-imager: $(OBJS)
	$(CC) $(CFLAGS) -o mox-imager $(OBJS) $(LDFLAGS)

$(shell test "`cat gpp/version 2>/dev/null`" = "$(TIM_VERSION)" || echo $(TIM_VERSION) > gpp/version)

gpp/version.gpp.inc: gpp/version_gen gpp/version
	gpp/version_gen `cat gpp/version` > gpp/version.gpp.inc

gpp/gpp1.gpp: gpp/version.gpp.inc
gpp/gpp1_trusted.gpp: gpp/version.gpp.inc

tim.c: $(GPPS)

refresh-wtmi: bin2c
	make -C $(WTMI_PATH) clean
	make -C $(WTMI_PATH) DEPLOY=1 LTO=1
	./bin2c bundled_wtmi_data <$(WTMI_PATH)/wtmi.bin >bundled-wtmi.c
	git commit -sm "Refresh bundled-wtmi.c" bundled-wtmi.c

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

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS) $(GPPS_DEPS)
endif
