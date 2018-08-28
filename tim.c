// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <endian.h>
#include "tim.h"
#include "utils.h"
#include "wtptp.h"
#include "key.h"
#include "bn.h"
#include "images.h"

static reshdr_t *reserved_area(timhdr_t *timhdr)
{
	return ((void *) timhdr) + sizeof(timhdr_t) +
		le32toh(timhdr->numimages) * sizeof(imginfo_t) +
		le32toh(timhdr->numkeys) * sizeof(keyinfo_t);
}

static respkg_t *nextpkg(timhdr_t *timhdr, respkg_t *pkg)
{
	reshdr_t *reshdr;
	respkg_t *next, *end;

	reshdr = reserved_area(timhdr);

	next = ((void *) pkg) + le32toh(pkg->size);
	end = ((void *) reshdr) + le32toh(timhdr->sizeofreserved);

	if (next > end)
		die("Reserved area broken");
	else if (next == end)
		return NULL;
	else
		return next;
}

static respkg_t *firstpkg(timhdr_t *timhdr)
{
	reshdr_t *reshdr;
	respkg_t *first, *pkg;
	u32 i, id, pkgs, size;

	size = le32toh(timhdr->sizeofreserved);
	if (!size)
		return NULL;

	if (size < sizeof(reshdr_t))
		die("Size of reserved area (%u bytes) too small", size);

	reshdr = reserved_area(timhdr);

	id = le32toh(reshdr->id);
	pkgs = le32toh(reshdr->pkgs);

	if (id != RES_ID)
		die("Incorrect reserved area ID %s", id2name(id));

	if (size < sizeof(reshdr_t) + pkgs * sizeof(respkg_t))
		die("Size of reserved area (%u bytes) too small for "
		    "%u packages", size, pkgs);

	first = (respkg_t *) (reshdr + 1);

	i = 0;
	for (pkg = first; pkg; pkg = nextpkg(timhdr, pkg))
		++i;

	if (i != pkgs)
		die("Reserved area broken (expected %u packages, found %u)",
		    pkgs, i);

	return first;
}

static u32 getsizetohash(timhdr_t *timhdr)
{
	void *res;

	res = (void *) timhdr + sizeof(timhdr_t) +
	      le32toh(timhdr->numimages) * sizeof(imginfo_t) +
	      le32toh(timhdr->sizeofreserved) +
	      le32toh(timhdr->numkeys) * sizeof(keyinfo_t);

	if (timhdr->trusted) {
		platds_t *platds = res;

		res += (void *) &platds->ECDSA.sig - res;
	}

	return res - (void *) timhdr;
}

void tim_parse(image_t *tim, int *numimagesp)
{
	static const u32 zerohash[16];
	timhdr_t *timhdr;
	imginfo_t *i, *start, *end;
	respkg_t *pkg;
	u32 version, date, numimages, numkeys, bootfs, sizeofreserved;

	if (tim->size < sizeof(timhdr_t))
		die("TIMH length too small (%u, should be at least %zu)",
		    tim->size, sizeof(timhdr_t));

	timhdr = (timhdr_t *) tim->data;

	version = le32toh(timhdr->version);
	date = le32toh(timhdr->issuedate);
	numimages = le32toh(timhdr->numimages);
	numkeys = le32toh(timhdr->numkeys);
	bootfs = le32toh(timhdr->bootflashsign);
	sizeofreserved = le32toh(timhdr->sizeofreserved);

	printf("TIM version %u.%u.%u, issue date %02x.%02x.%04x, %s, %u images,"
	       " %u keys, boot flash sign %s\n",
	       version >> 16, (version >> 8) & 0xff, version & 0xff, date >> 24,
	       (date >> 16) & 0xff, date & 0xffff,
	       timhdr->trusted ? "trusted" : "non-trusted", numimages, numkeys,
	       bootfs2name(bootfs));

	printf("Reserved area packages:");
	for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg))
		printf(" %s", id2name(pkg->id));
	printf("\n");

	if (!timhdr->trusted && numkeys)
		die("Keys present in non-trusted TIM");

	if (tim->size != tim_size(timhdr))
		die("Invalid TIM length (%u, expected %u)", tim->size,
		    tim_size(timhdr));

	start = (imginfo_t *) (timhdr + 1);
	end = start + numimages;
	for (i = start; i < end; ++i) {
		image_t *img;
		int nohash;
		u32 id, size, nextid, hashid, hashalg, sizetohash;
		u32 hash[16];

		id = le32toh(i->id);
		size = le32toh(i->size);
		hashalg = le32toh(i->hashalg);
		sizetohash = le32toh(i->sizetohash);

		if (i->nextid != 0xffffffff &&
		    (i + 1 == end || (i + 1)->id != i->nextid))
			die("Next image ID check failed");

		img = image_find(id);
		if (img->size != size)
			die("Wrong length of %s image (%u, expected %u)",
			    id2name(id), img->size, size);

		nohash = !memcmp(i->hash, zerohash, sizeof(zerohash));

		printf("Found %s, hash %s%s, encryption %s\n", id2name(id),
		       hash2name(i->hashalg), nohash ? " (hash zeroed)" : "",
		       enc2name(le32toh(i->encalg)));

		if (nohash)
			continue;

		if (id == TIMH_ID && sizetohash > getsizetohash(timhdr))
			sizetohash = getsizetohash(timhdr);
		else if (sizetohash > size)
			sizetohash = size;

		image_hash(i->hashalg, img->data, sizetohash, hash,
			   id == TIMH_ID ? (u8 *) &i->hash[0] - tim->data : -1);

		if (memcmp(hash, i->hash, sizeof(hash)))
			die("Hash check failed for %s", id2name(id));
	}

	*numimagesp = numimages;
}

static void tim_grow(image_t *tim, u32 growby)
{
	image_t oldtim;

	oldtim = *tim;
	tim->data = xmalloc(oldtim.size + growby);
	memcpy(tim->data, oldtim.data, oldtim.size);
	tim->size += growby;

	free(oldtim.data);
}

static int hash_obmi;

void tim_hash_obmi(int set)
{
	hash_obmi = set;
}

void tim_rehash(image_t *tim)
{
	timhdr_t *timhdr;
	imginfo_t *img, *start, *end;
	u32 numimages, sizetohash, id;

	timhdr = (void *) tim->data;
	numimages = le32toh(timhdr->numimages);
	sizetohash = getsizetohash(timhdr);

	start = (imginfo_t *) (timhdr + 1);
	end = start + timhdr->numimages;

	for (img = start; img < end; ++img) {
		image_t *obmi;

		id = le32toh(img->id);
		if (id != OBMI_ID)
			continue;

		obmi = image_find(id);

		if (hash_obmi) {
			img->sizetohash = htole32(obmi->size);
			image_hash(le32toh(img->hashalg), obmi->data,
				   obmi->size, img->hash, -1);
		} else {
			img->sizetohash = 0;
			memset(img->hash, 0, sizeof(img->hash));
		}
	}

	for (img = start; img < end; ++img) {
		id = le32toh(img->id);

		if (id != TIMH_ID)
			continue;

		img->size = htole32(tim->size);
		img->sizetohash = htole32(sizetohash);

		if (timhdr->trusted)
			memset(img->hash, 0, sizeof(img->hash));
		else
			image_hash(le32toh(img->hashalg), tim->data, sizetohash,
				   img->hash, (u8 *) &img->hash[0] - tim->data);
	}
}

void tim_set_boot(image_t *tim, u32 boot)
{
	timhdr_t *timhdr = (void *) tim->data;

	timhdr->bootflashsign = htole32(boot);
	tim_rehash(tim);
}

static void tim_add_pkgs(image_t *tim, int npkgs, void *pkgs, size_t size)
{
	static int alloced;
	void *oldend;
	timhdr_t *timhdr;
	reshdr_t *reshdr;
	respkg_t *pkg;
	u32 sizeofreserved, toadd;
	imginfo_t *img, *start, *end;
	int i;

	timhdr = (timhdr_t *) tim->data;
	reshdr = reserved_area(timhdr);
	sizeofreserved = le32toh(timhdr->sizeofreserved);

	toadd = size;
	if (!sizeofreserved)
		toadd += sizeof(reshdr_t) + sizeof(respkg_t);

	tim_grow(tim, toadd);
	oldend = tim->data + tim->size - toadd;

	timhdr = (timhdr_t *) tim->data;
	reshdr = reserved_area(timhdr);

	if (!sizeofreserved) {
		/* add toadd bytes for reserved area */
		memmove(((void *) reshdr) + toadd, reshdr,
			oldend - (void *) reshdr);

		/* add reserved area header */
		reshdr->id = htole32(RES_ID);
		reshdr->pkgs = htole32(npkgs + 1);

		/* add packages */
		memcpy(reshdr + 1, pkgs, size);

		/* add Term package */
		pkg = ((void *) reshdr) + size;
		pkg->id = htole32(PKG_Term);
		pkg->size = htole32(sizeof(respkg_t));
	} else {
		respkg_t *lastpkg = NULL;
		int has_term = 0;

		/* find last package */
		for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg)) {
			lastpkg = pkg;
			if (le32toh(pkg->id) == PKG_Term) {
				has_term = 1;
				break;
			}
		}

		/* if last package was not found, use end of reserved area */
		if (!lastpkg)
			lastpkg = (void *) (reshdr + 1);

		/* add toadd bytes for reserved area */
		memmove(((void *) lastpkg) + toadd, lastpkg,
			oldend - (void *) lastpkg);

		/* add packages */
		memcpy(lastpkg, pkgs, size);

		/* add Term package if it was there */
		if (has_term) {
			pkg = ((void *) lastpkg) + size;
			pkg->id = htole32(PKG_Term);
			pkg->size = htole32(sizeof(respkg_t));
		}

		/* change reserved area header */
		reshdr->pkgs = htole32(le32toh(reshdr->pkgs) + npkgs);
	}

	timhdr->sizeofreserved = htole32(sizeofreserved + toadd);

	tim_rehash(tim);
}

void tim_add_pin(image_t *tim, u64 pin)
{
	u32 data[4];
	respkg_t *pinpkg;

	pinpkg = (respkg_t *) &data[0];

	pinpkg->id = htole32(PKG_PINP);
	pinpkg->size = htole32(0x10);
	pinpkg->data[0] = htole32(pin & 0xffffffff);
	pinpkg->data[1] = htole32(pin >> 32);

	tim_add_pkgs(tim, 1, data, sizeof(data));
}

void tim_sign(image_t *tim, EC_KEY *key)
{
	ECDSA_SIG *sig;
	timhdr_t *timhdr;
	platds_t *platds;
	u32 hash[16];
	u32 otphashbuf[129];
	int i;

	timhdr = (void *) tim->data;
	if (!timhdr->trusted)
		tim_grow(tim, sizeof(platds_t));

	timhdr = (void *) tim->data;
	platds = (void *) tim->data + tim->size - sizeof(platds_t);

	timhdr->trusted = htole32(1);
	tim_rehash(tim);

	memset(platds, 0, sizeof(platds_t));

	platds->dsalg = htole32(DSALG_ECDSA_521);
	platds->hashalg = htole32(HASH_SHA512);
	platds->keysize = htole32(521);

	key_get_tim_coords(key, platds->ECDSA.pub.x, platds->ECDSA.pub.y);

	memset(otphashbuf, 0, sizeof(otphashbuf));
	otphashbuf[0] = htole32(SIG_SCHEME_ECDSA_P521_SHA512);
	memcpy(&otphashbuf[1], platds->ECDSA.pub.x, 17);
	memcpy(&otphashbuf[18], platds->ECDSA.pub.y, 17);

	image_hash(HASH_SHA512, otphashbuf, sizeof(otphashbuf), hash, -1);

	printf("OTP key hash: ");
	for (i = 0; i < 16; ++i)
		printf("%08x%c", hash[i], i == 15 ? '\n' : ' ');

	image_hash(HASH_SHA512, tim->data, (u8 *) &platds->ECDSA.sig - tim->data,
		   hash, -1);

	sig = ECDSA_do_sign((void *) hash, sizeof(hash), key);
	if (!sig)
		die("Could not sign");

	bn2tim(sig->r, platds->ECDSA.sig.r, 17);
	bn2tim(sig->s, platds->ECDSA.sig.s, 17);
}

static u32 name2id(const char *name)
{
	return htole32(htobe32(*(u32 *) name));
}

#define NOP				0
#define WRITE				1
#define READ				2
#define DELAY				3
#define WAIT_FOR_BIT_SET		4
#define WAIT_FOR_BIT_CLEAR		5
#define AND_VAL				6
#define OR_VAL				7
#define SET_BITFIELD			8
#define WAIT_FOR_BIT_PATTERN		9
#define TEST_IF_ZERO_AND_SET		10
#define TEST_IF_NOT_ZERO_AND_SET	11
#define LOAD_SM_ADDR			12
#define LOAD_SM_VAL			13
#define STORE_SM_ADDR			14
#define MOV_SM_SM			15
#define RSHIFT_SM_VAL			16
#define LSHIFT_SM_VAL			17
#define AND_SM_VAL			18
#define OR_SM_VAL			19
#define OR_SM_SM			20
#define AND_SM_SM			21
#define TEST_SM_IF_ZERO_AND_SET		22
#define TEST_SM_IF_NOT_ZERO_AND_SET	23
#define LABEL				24
#define TEST_ADDR_AND_BRANCH		25
#define TEST_SM_AND_BRANCH		26
#define BRANCH				27
#define END				28
#define ADD_SM_VAL			29
#define ADD_SM_SM			30
#define SUB_SM_VAL			31
#define SUB_SM_SM			32
#define LOAD_SM_FROM_ADDR_IN_SM		33
#define STORE_SM_TO_ADDR_IN_SM		34

#define OP_EQ			1
#define OP_NE			2
#define OP_LT			3
#define OP_LTE			4
#define OP_GT			5
#define OP_GTE			6

static const int instr_params[35] = {
	[NOP]				= 0,
	[WRITE]				= 2,
	[READ]				= 2,
	[DELAY]				= 1,
	[WAIT_FOR_BIT_SET]		= 3,
	[WAIT_FOR_BIT_CLEAR]		= 3,
	[AND_VAL]			= 2,
	[OR_VAL]			= 2,
	[SET_BITFIELD]			= 3,
	[WAIT_FOR_BIT_PATTERN]		= 4,
	[TEST_IF_ZERO_AND_SET]		= 5,
	[TEST_IF_NOT_ZERO_AND_SET]	= 5,
	[LOAD_SM_ADDR]			= 2,
	[LOAD_SM_VAL]			= 2,
	[STORE_SM_ADDR]			= 2,
	[MOV_SM_SM]			= 2,
	[RSHIFT_SM_VAL]			= 2,
	[LSHIFT_SM_VAL]			= 2,
	[AND_SM_VAL]			= 2,
	[OR_SM_VAL]			= 2,
	[OR_SM_SM]			= 2,
	[AND_SM_SM]			= 2,
	[TEST_SM_IF_ZERO_AND_SET]	= 5,
	[TEST_SM_IF_NOT_ZERO_AND_SET]	= 5,
	[LABEL]				= 1,
	[TEST_ADDR_AND_BRANCH]		= 5,
	[TEST_SM_AND_BRANCH]		= 5,
	[BRANCH]			= 1,
	[END]				= 0,
	[ADD_SM_VAL]			= 2,
	[ADD_SM_SM]			= 2,
	[SUB_SM_VAL]			= 2,
	[SUB_SM_SM]			= 2,
	[LOAD_SM_FROM_ADDR_IN_SM]	= 2,
	[STORE_SM_TO_ADDR_IN_SM]	= 2,
};

static inline void _emit(u32 **ptr, u32 id, ...)
{
	va_list ap;
	int i;

	*(*ptr)++ = htole32(id);

	va_start(ap, id);
	for (i = 0; i < instr_params[id]; ++i)
		*(*ptr)++ = htole32(va_arg(ap, u32));
	va_end(ap);
}

#define emit(id, ...) _emit(ptr, id, ##__VA_ARGS__)

#define emit_putc(c)						\
	do {							\
		emit(WRITE, 0xC0012004, (u32) (c));		\
		emit(WAIT_FOR_BIT_SET, 0xC001200C, 0x20, 1);	\
	} while (0);

#define emit_print(str)					\
	do {						\
		int i;					\
		for (i = 0; i < strlen((str)); ++i)	\
			emit_putc((str)[i]);		\
	} while (0);

#define EFUSE_CTRL	0x40003430
#define EFUSE_RW	0x40003434
#define EFUSE_D0	0x40003438
#define EFUSE_D1	0x4000343c
#define EFUSE_AUX	0x40003440

#define EFUSE_RC(r,c)	((((r) & 0x3f) << 7) | ((c) & 0x7f))

static void emit_otp_read_row(u32 **ptr, u32 sm_row, u32 sm_store0,
			      u32 sm_store1, u32 sm_sfb)
{
	emit(WRITE, EFUSE_CTRL, 0x4);
	emit(DELAY, 1);
	emit(OR_VAL, EFUSE_CTRL, 0x8);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x7, 0x3);
	emit(LSHIFT_SM_VAL, sm_row, 7);
	emit(STORE_SM_ADDR, sm_row, EFUSE_RW);
	emit(RSHIFT_SM_VAL, sm_row, 7);
	emit(DELAY, 1);
	emit(OR_VAL, EFUSE_CTRL, 0x100);
	emit(DELAY, 1);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x100, 0);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x6, 0x4);
	emit(WAIT_FOR_BIT_SET, EFUSE_AUX, 0x80000000);
	emit(LOAD_SM_ADDR, sm_store0, EFUSE_D0);
	emit(LOAD_SM_ADDR, sm_store1, EFUSE_D1);
	emit(LOAD_SM_ADDR, sm_sfb, EFUSE_AUX);
	emit(RSHIFT_SM_VAL, sm_sfb, 4);
}

static void emit_print_sm(u32 **ptr, u32 sm, u32 *label)
{
	emit(LOAD_SM_VAL, 15, 0x80000000);
	emit(LABEL, *label + 2);
	emit(MOV_SM_SM, 3, sm);
	emit(AND_SM_SM, 3, 15);
	emit(TEST_SM_AND_BRANCH, 3, 0xffffffff, 0, OP_EQ, *label);
	emit_putc('1');
	emit(BRANCH, *label + 1);
	emit(LABEL, *label);
	emit_putc('0');
	emit(LABEL, *label + 1);
	emit(RSHIFT_SM_VAL, 15, 1);
	emit(TEST_SM_AND_BRANCH, 15, 0xffffffff, 0, OP_NE, *label + 2);

	*label += 3;
}

static void emit_otp_read(u32 **ptr)
{
	u32 label = 4;

	emit_print("OTP\r\n");
	emit(LOAD_SM_VAL, 0, 0);
	emit(LABEL, 1);
	emit_otp_read_row(ptr, 0, 1, 2, 3);
	emit(TEST_SM_AND_BRANCH, 3, 1, 1, OP_EQ, 2);
	emit_print("0 ");
	emit(BRANCH, 3);
	emit(LABEL, 2);
	emit_print("1 ");
	emit(LABEL, 3);
	emit_print_sm(ptr, 2, &label);
	emit_putc(' ');
	emit_print_sm(ptr, 1, &label);
	emit_print("\r\n");
	emit(ADD_SM_VAL, 0, 1);
	emit(TEST_SM_AND_BRANCH, 0, 0xffffffff, 44, OP_NE, 1);
}

static void tim_emit_gpp1(image_t *tim, void (*emit_func)(u32 **))
{
	timhdr_t *timhdr;
	respkg_t *pkg;
	void *pkgend;
	u32 *instr, *ptr, togrow, oldtimsize;

	ptr = instr = xmalloc(16384);

	emit_func(&ptr);

	togrow = (void *) ptr - (void *) instr;

	oldtimsize = tim->size;
	tim_grow(tim, togrow);

	timhdr = (void *) tim->data;
	for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg))
		if (le32toh(pkg->id) == name2id("GPP1"))
			break;

	if (!pkg)
		die("Cannot find GPP1 package!");

	pkgend = (void *) pkg + le32toh(pkg->size);
	memmove(pkgend + togrow, pkgend,
		oldtimsize - (pkgend - (void *) timhdr));
	memcpy(pkgend, instr, togrow);

	pkg->size = htole32(le32toh(pkg->size) + togrow);
	timhdr->sizeofreserved = htole32(le32toh(timhdr->sizeofreserved) + togrow);

	tim_rehash(tim);
}

void tim_emit_otp_read(image_t *tim)
{
	tim_emit_gpp1(tim, emit_otp_read);
}
