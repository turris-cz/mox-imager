// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#define _GNU_SOURCE
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
#include "instr.h"

static void tim_add_cidp_pkg(image_t *tim, const char *consumer, int npkgs,
			     ...);
static void tim_add_gpp_pkg(image_t *tim, const char *name, void *code,
			    size_t codesize, int init_ddr,
			    int enable_memtest, u32 memtest_start,
			    u32 memtest_size, int init_attempts,
			    int ignore_timeouts_op, int ignore_timeouts_val);

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

	if (size < sizeof(reshdr_t) + pkgs * SIZEOF_RESPKG_HDR)
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

static imginfo_t *tim_find_image(image_t *tim, u32 id)
{
	timhdr_t *timhdr;
	imginfo_t *img;
	int i;

	timhdr = (void *) tim->data;

	for (i = 0; i < tim_nimages(timhdr); ++i) {
		img = tim_image(timhdr, i);

		if (le32toh(img->id) == id)
			return img;
	}

	return NULL;
}

void tim_image_set_loadaddr(image_t *tim, u32 id, u32 loadaddr)
{
	imginfo_t *img;

	img = tim_find_image(tim, id);
	if (!img)
		return;

	img->loadaddr = htole32(loadaddr);
}

void tim_remove_image(image_t *tim, u32 id)
{
	timhdr_t *timhdr;
	imginfo_t *img;
	void *imgend;

	timhdr = (void *) tim->data;

	img = tim_find_image(tim, id);
	if (!img)
		return;

	if (img != tim_image(timhdr, 0))
		(img - 1)->nextid = img->nextid;

	imgend = img + 1;
	memmove(img, imgend, (void *) tim->data + tim->size - imgend);

	timhdr->numimages = htole32(tim_nimages(timhdr) - 1);
	tim->size -= sizeof(imginfo_t);

	img = tim_find_image(tim, tim->id);
	if (img) {
		img->size = htole32(tim->size);
		img->sizetohash = htole32(tim->size);
	}
}

static respkg_t *tim_find_pkg(image_t *tim, u32 id)
{
	timhdr_t *timhdr;
	reshdr_t *reshdr;
	respkg_t *pkg;
	u32 pkgsize;
	void *pkgend;

	timhdr = (void *) tim->data;
	reshdr = reserved_area(timhdr);

	for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg))
		if (le32toh(pkg->id) == id)
			break;

	return pkg;
}

static struct imap_map *tim_imap_pkg_find_map(image_t *tim, u32 id)
{
	respkg_t *pkg;
	int i;

	pkg = tim_find_pkg(tim, PKG_IMAP);
	if (!pkg)
		return NULL;

	for (i = 0; i < le32toh(pkg->imap.nmaps); ++i)
		if (le32toh(pkg->imap.maps[i].id) == id)
			return &pkg->imap.maps[i];

	return NULL;
}

u32 tim_imap_pkg_addr(image_t *tim, u32 id)
{
	struct imap_map *map = tim_imap_pkg_find_map(tim, id);

	if (!map)
		return -1;

	return le32toh(map->flashentryaddr[0]);
}

void tim_imap_pkg_addr_set(image_t *tim, u32 id, u32 flashentry, u32 partition)
{
	struct imap_map *map = tim_imap_pkg_find_map(tim, id);

	if (!map)
		die("Cannot find IMAP package or requested map %s", id2name(id));

	map->flashentryaddr[0] = htole32(flashentry);
	map->partitionnumber = htole32(partition);
}

static void tim_remove_pkg(image_t *tim, u32 id)
{
	timhdr_t *timhdr;
	reshdr_t *reshdr;
	respkg_t *pkg;
	u32 pkgsize;
	void *pkgend;

	pkg = tim_find_pkg(tim, id);

	if (!pkg)
		return;

	pkgsize = le32toh(pkg->size);
	pkgend = (void *) pkg + pkgsize;
	memmove(pkg, pkgend, (void *) tim->data + tim->size - pkgend);

	timhdr = (void *) tim->data;
	reshdr = reserved_area(timhdr);
	reshdr->pkgs = htole32(le32toh(reshdr->pkgs) - 1);
	timhdr->sizeofreserved = htole32(le32toh(timhdr->sizeofreserved) - pkgsize);
	tim->size -= pkgsize;
}

char minimal_secure_tim[] =
	"\x00\x06\x03\x00\x48\x4d\x49\x54\x00\x00\x00\x00\x18\x20\x09\x24"
	"\x43\x4e\x5a\x43\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff\x0a\x49\x50\x53\x01\x00\x00\x00"
	"\x00\x00\x00\x00\x30\x00\x00\x00\x48\x4d\x49\x54\xff\xff\xff\xff"
	"\x00\x00\x00\x00\x00\x60\x00\x20\x00\x04\x00\x00\x88\x01\x00\x00"
	"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x48\x54\x50\x4f\x02\x00\x00\x00\x50\x41\x4d\x49"
	"\x20\x00\x00\x00\x01\x00\x00\x00\x54\x4b\x53\x43\x00\x00\x00\x00"
	"\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6d\x72\x65\x54"
	"\x08\x00\x00\x00";

const size_t minimal_secure_tim_size = 212;

char minimal_secure_timn[] =
	"\x00\x06\x03\x00\x4e\x4d\x49\x54\x00\x00\x00\x00\x18\x20\x09\x24"
	"\x43\x4e\x5a\x43\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff\x0a\x49\x50\x53\x01\x00\x00\x00"
	"\x00\x00\x00\x00\x24\x00\x00\x00\x4e\x4d\x49\x54\xff\xff\xff\xff"
	"\x00\x10\x00\x00\x00\x30\x00\x20\xc8\x00\x00\x00\xc8\x00\x00\x00"
	"\x40\x00\x00\x00\x13\x85\x8c\xab\x34\x41\x46\xbc\xb4\x82\x92\xbb"
	"\x9c\xa3\x57\x55\xe3\x93\x15\x2a\x0f\xcd\xb4\x35\xf5\xed\x2d\xe3"
	"\x93\x17\xef\xad\x6e\x2e\x71\x6d\xaf\xc0\xfc\x4b\x96\x74\x49\x2d"
	"\x1d\x66\x39\x57\xcd\xae\x5f\x35\xd6\xa4\xa4\x87\xd6\xc6\x13\x5e"
	"\x69\xf3\x5d\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x48\x54\x50\x4f\x02\x00\x00\x00\x32\x56\x52\x43"
	"\x14\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\xff\x1f"
	"\x6d\x72\x65\x54\x08\x00\x00\x00";

const size_t minimal_secure_timn_size = 200;

char minimal_tim[] =
	"\x00\x06\x03\x00\x48\x4d\x49\x54\x00\x00\x00\x00\x18\x20\x09\x24"
	"\x4c\x56\x52\x4d\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff\x23\x52\x41\x55\x01\x00\x00\x00"
	"\x00\x00\x00\x00\x24\x00\x00\x00\x48\x4d\x49\x54\xff\xff\xff\xff"
	"\x00\x00\x00\x00\x00\x60\x00\x20\xc8\x00\x00\x00\xc8\x00\x00\x00"
	"\x40\x00\x00\x00\xb7\xb5\x3c\xf1\x40\xe5\xb4\xa2\x9f\x1d\x2e\x19"
	"\x1b\x76\x4b\xa2\x74\xab\xdc\xe8\x9f\x45\x74\xd7\xf3\xad\xb9\x62"
	"\x49\x77\x6f\xc4\x54\x8f\x9a\xc3\x5b\xe5\xd0\xc1\x01\xc8\x54\x5a"
	"\xe4\xf5\xdb\x1f\xa2\x0e\x37\xff\xb0\x7c\x8a\xa4\x42\xa3\x71\x92"
	"\xd5\x2e\x46\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x48\x54\x50\x4f\x02\x00\x00\x00\x32\x56\x52\x43"
	"\x14\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\xff\x1f"
	"\x6d\x72\x65\x54\x08\x00\x00\x00";

const size_t minimal_tim_size = 200;

#include "gpp/gpp1.c"
#include "gpp/gpp1_trusted.c"
#include "gpp/gpp2.c"
#include "gpp/ddr.c"
#include "gpp/ddr_uart.c"

void tim_minimal_image(image_t *tim, int trusted, u32 id, int support_fastmode)
{
	void *data, *from;
	u32 size;

	if (trusted) {
		if (id == TIMN_ID) {
			from = minimal_secure_timn;
			size = minimal_secure_timn_size;
		} else {
			from = minimal_secure_tim;
			size = minimal_secure_tim_size;
		}
	} else {
		from = minimal_tim;
		size = minimal_tim_size;
	}

	data = xmalloc(size);
	memcpy(data, from, size);

	if (tim->data)
		free(tim->data);

	tim->id = le32toh(*(u32 *) (from + 4));
	tim->data = data;
	tim->size = size;

	if (trusted && id != TIMN_ID)
		return;

	tim_add_cidp_pkg(tim, "TBRI", 3, "GPP1", "GPP2", "DDR3");

	if (trusted)
		tim_add_gpp_pkg(tim, "GPP1", GPP_gpp1_trusted,
				GPP_gpp1_trusted_size, 0, 0, 0, 0, 0, 1, 0);
	else
		tim_add_gpp_pkg(tim, "GPP1", GPP_gpp1, GPP_gpp1_size,
				0, 0, 0, 0, 0, 1, 0);

	tim_add_gpp_pkg(tim, "GPP2", GPP_gpp2, GPP_gpp2_size,
			0, 0, 0, 0, 0, 1, 0);

	if (support_fastmode)
		tim_add_gpp_pkg(tim, "DDR3", GPP_ddr_uart, GPP_ddr_uart_size,
				1, 0, 0, 0, 0, 0, 0);
	else
		tim_add_gpp_pkg(tim, "DDR3", GPP_ddr, GPP_ddr_size,
				1, 0, 0, 0, 0, 0, 0);
}

void tim_parse(image_t *tim, int *numimagesp, int disasm,
	       int *supports_baudrate_change)
{
	static const u32 zerohash[16];
	timhdr_t *timhdr;
	imginfo_t *i, *start, *end;
	respkg_t *pkg;
	platds_t *platds;
	u32 version, date, numimages, numkeys, bootfs, sizeofreserved;

	if (tim->size < sizeof(timhdr_t))
		die("TIMH length too small (%u, should be at least %zu)",
		    tim->size, sizeof(timhdr_t));

	if (supports_baudrate_change)
		*supports_baudrate_change = 0;

	timhdr = (timhdr_t *) tim->data;

	version = le32toh(timhdr->version);
	date = le32toh(timhdr->issuedate);
	numimages = le32toh(timhdr->numimages);
	numkeys = le32toh(timhdr->numkeys);
	bootfs = le32toh(timhdr->bootflashsign);
	sizeofreserved = le32toh(timhdr->sizeofreserved);

	printf("TIM version %u.%u.%u, issue date %04x-%02x-%02x, %s, %u images,"
	       " %u keys, boot flash sign %s\n",
	       version >> 16, (version >> 8) & 0xff, version & 0xff,
	       date & 0xffff, (date >> 16) & 0xff, date >> 24,
	       timhdr->trusted ? "trusted" : "non-trusted", numimages, numkeys,
	       bootfs2name(bootfs));

	printf("Reserved area packages:\n");
	for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg)) {
		u32 pkgid = le32toh(pkg->id);

		printf("  %s (size %u)\n", id2name(pkgid), le32toh(pkg->size));
		if (pkgid == PKG_IMAP) {
			int i;

			for (i = 0; i < le32toh(pkg->imap.nmaps); ++i) {
				typeof(pkg->imap.maps[0]) *map;
				map = &pkg->imap.maps[i];

				printf("    Image map %i: %s, %s, entry "
				       "address %08x, partition number %u\n", i,
				       id2name(map->id),
				       map->type ? "recovery" : "primary",
				       le32toh(map->flashentryaddr[0]),
				       le32toh(map->partitionnumber));
			}
		} else if (pkgid == PKG_CIDP) {
			struct cidp_t *cidp = &pkg->cidp.consumers[0];
			int i, j, n;

			for (i = 0; i < le32toh(pkg->cidp.nconsumers); ++i) {
				printf("    Consumer %s, packages:",
					id2name(le32toh(cidp->id)));

				n = le32toh(cidp->npkgs);
				for (j = 0; j < n; ++j)
					printf(" %s",
					       id2name(le32toh(cidp->pkgs[j])));
				printf("\n");

				cidp = (void *)cidp + sizeof(*cidp) +
				       n * sizeof(cidp->pkgs[0]);
			}
		} else if ((pkgid & 0xffffff00) == 0x47505000 || 
			   (pkgid & 0xffffff00) == 0x44445200) {
			struct gpp_op *op = &pkg->gpp.ops[0];
			u32 nops, ninst;
			void *code;
			int i, len;

			nops = le32toh(pkg->gpp.nops);
			ninst = le32toh(pkg->gpp.ninst);

			for (i = 0; i < nops; ++i) {
				u32 opid, opval;

				opid = le32toh(op->id);
				opval = le32toh(op->value);
				switch (opid) {
				case 0x01:
					printf("    Initialize DDR memory: %u\n", opval);
					break;
				case 0x02:
					printf("    Enable memtest: %u\n", opval);
					break;
				case 0x03:
					printf("    Memtest start: 0x%x\n", opval);
					break;
				case 0x04:
					printf("    Memtest size: 0x%x\n", opval);
					break;
				case 0x05:
					printf("    Init attempts: %u\n", opval);
					break;
				case 0x06:
					printf("    Ignore timeouts in instructions: %u\n", opval);
					break;
				}
				++op;
			}

			code = (void *)op;
			len = pkg->size - 4 * sizeof(u32) - nops * sizeof(pkg->gpp.ops[0]);

			if (supports_baudrate_change && !*supports_baudrate_change) {
				*supports_baudrate_change = memmem(code, len, "UArx", 4) &&
							    memmem(code, len, "UAtx", 4) &&
							    memmem(code, len, "baud", 4);
				if (*supports_baudrate_change)
					printf("    Contains code for baudrate change\n");
			}

			if (disasm) {
				printf("    Instructions:\n");
				disassemble("\t", code, len / 4);
			}
		}
	}

	if (!timhdr->trusted && numkeys)
		die("Keys present in non-trusted TIM");

	if (tim->size != tim_size(timhdr))
		die("Invalid TIM length (%u, expected %u)", tim->size,
		    tim_size(timhdr));

	platds = (void *) reserved_area(timhdr) + sizeofreserved;
	if (timhdr->trusted)
		printf("Platform digital signature algorithm %s, key size %u "
		       "bits, hash %s\n", dsalg2name(le32toh(platds->dsalg)),
		       le32toh(platds->keysize),
		       hash2name(le32toh(platds->hashalg)));

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
		if (img->size != size && i->sizetohash)
			die("Wrong length of %s image (%u, expected %u)",
			    id2name(id), img->size, size);

		nohash = !memcmp(i->hash, zerohash, sizeof(zerohash));

		printf("Found %s, hash %s%s, encryption %s, size %u, load 0x%08x, flash 0x%08x\n",
		       id2name(id), hash2name(i->hashalg),
		       nohash ? " (hash zeroed)" : "",
		       enc2name(le32toh(i->encalg)),
		       le32toh(i->size), le32toh(i->loadaddr),
		       le32toh(i->flashentryaddr));

		if (nohash)
			continue;

		if (id == tim->id && sizetohash > getsizetohash(timhdr))
			sizetohash = getsizetohash(timhdr);
		else if (sizetohash > size)
			sizetohash = size;

		image_hash(i->hashalg, img->data, sizetohash, hash,
			   id == tim->id ? (u8 *) &i->hash[0] - tim->data : -1);

		if (memcmp(hash, i->hash, sizeof(hash)))
			die("Hash check failed for %s", id2name(id));
	}

	printf("\n");

	if (numimagesp)
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

void tim_enable_hash(image_t *tim, u32 id, int enable)
{
	imginfo_t *img;

	img = tim_find_image(tim, id);
	if (img) {
		if (enable) {
			img->sizetohash = img->size ? img->size : 1;
		} else {
			img->sizetohash = 0;
			memset(img->hash, 0, sizeof(img->hash));
		}
	}
}

static u32 tim_issuedate_now(void)
{
	struct tm *tm;
	time_t now;
	u32 res;

	now = time(NULL);
	tm = gmtime(&now);
	tm->tm_mon += 1;
	tm->tm_year += 1900;

	res = (tm->tm_mday / 10) % 10;
	res <<= 4;
	res |= tm->tm_mday % 10;
	res <<= 4;
	res |= (tm->tm_mon / 10) % 10;
	res <<= 4;
	res |= tm->tm_mon % 10;
	res <<= 4;
	res |= (tm->tm_year / 1000) % 10;
	res <<= 4;
	res |= (tm->tm_year / 100) % 10;
	res <<= 4;
	res |= (tm->tm_year / 10) % 10;
	res <<= 4;
	res |= tm->tm_year % 10;

	return htole32(res);
}

void tim_rehash(image_t *tim)
{
	timhdr_t *timhdr;
	int i;
	imginfo_t *img;
	u32 sizetohash, id;

	timhdr = (void *) tim->data;
	sizetohash = getsizetohash(timhdr);
	timhdr->issuedate = tim_issuedate_now();

	for (i = 0; i < tim_nimages(timhdr); ++i) {
		image_t *image;

		img = tim_image(timhdr, i);

		id = le32toh(img->id);
		if (id == tim->id)
			continue;

		image = image_find(id);

		if (!img->sizetohash) {
			memset(img->hash, 0, sizeof(img->hash));
		} else {
			img->sizetohash = htole32(image->size);
			image_hash(le32toh(img->hashalg), image->data,
				   image->size, img->hash, -1);
		}
	}

	img = tim_find_image(tim, tim->id);
	if (img) {
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

void tim_add_image(image_t *tim, image_t *image, u32 after, u32 loadaddr,
		   u32 flashaddr, u32 partition, int hash)
{
	timhdr_t *timhdr;
	imginfo_t *timinfo, *prev, *this, *next;
	int i;
	u32 oldtimsize;

	oldtimsize = tim->size;
	tim_grow(tim, sizeof(imginfo_t));

	timinfo = prev = NULL;

	timhdr = (timhdr_t *) tim->data;
	for (i = 0; i < tim_nimages(timhdr); ++i) {
		imginfo_t *img;

		img = tim_image(timhdr, i);

		if (le32toh(img->id) == tim->id)
			timinfo = img;

		if (le32toh(img->id) == after)
			prev = img;
	}

	this = prev + 1;
	next = prev + 2;
	memmove(next, this, oldtimsize - ((void *) this - (void *) timhdr));

	memset(this, 0, sizeof(imginfo_t));
	this->id = htole32(image->id);
	this->nextid = prev->nextid;
	prev->nextid = this->id;
	this->size = htole32(image->size);
	this->flashentryaddr = htole32(flashaddr);
	this->partitionnumber = htole32(partition);
	this->loadaddr = htole32(loadaddr);
	this->hashalg = htole32(HASH_SHA512);
	this->sizetohash = hash ? this->size : 0;

	timhdr->numimages = htole32(tim_nimages(timhdr) + 1);

	if (timinfo) {
		timinfo->size = htole32(tim->size);
		timinfo->sizetohash = timinfo->size;
	}
}

static void tim_add_pkgs(image_t *tim, int npkgs, void *pkgs, size_t size)
{
	static int alloced;
	void *oldend;
	timhdr_t *timhdr;
	reshdr_t *reshdr;
	respkg_t *pkg;
	u32 sizeofreserved, toadd;
	int i;

	timhdr = (timhdr_t *) tim->data;
	reshdr = reserved_area(timhdr);
	sizeofreserved = le32toh(timhdr->sizeofreserved);

	toadd = size;
	if (!sizeofreserved)
		toadd += sizeof(reshdr_t) + SIZEOF_RESPKG_HDR;

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
		pkg->size = htole32(SIZEOF_RESPKG_HDR);
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
			pkg->size = htole32(SIZEOF_RESPKG_HDR);
		}

		/* change reserved area header */
		reshdr->pkgs = htole32(le32toh(reshdr->pkgs) + npkgs);
	}

	timhdr->sizeofreserved = htole32(sizeofreserved + toadd);

	tim_rehash(tim);
}

static void tim_add_cidp_pkg(image_t *tim, const char *consumer, int npkgs, ...)
{
	respkg_t *pkg;
	u32 size = 4 * (5 + npkgs);
	va_list ap;
	int i;

	pkg = xmalloc(size);
	pkg->id = htole32(PKG_CIDP);
	pkg->size = htole32(size);
	pkg->cidp.nconsumers = 1;
	pkg->cidp.consumers[0].id = htole32(name2id(consumer));
	pkg->cidp.consumers[0].npkgs = htole32(npkgs);

	va_start(ap, npkgs);
	for (i = 0; i < npkgs; ++i) {
		const char *arg = va_arg(ap, const char *);
		pkg->cidp.consumers[0].pkgs[i] = htole32(name2id(arg));
	}
	va_end(ap);

	tim_add_pkgs(tim, 1, pkg, size);

	free(pkg);
}

static void tim_append_gpp_code(image_t *tim, const char *name, void *code,
				size_t codesize)
{
	void *oldend, *codeend;
	timhdr_t *timhdr;
	respkg_t *pkg;

	if (codesize & 3)
		die("GPP code length must be a multiple of 4!");

	timhdr = (timhdr_t *) tim->data;

	tim_grow(tim, codesize);
	oldend = tim->data + tim->size - codesize;

	timhdr = (timhdr_t *) tim->data;

	/* find the package */
	for (pkg = firstpkg(timhdr); pkg; pkg = nextpkg(timhdr, pkg))
		if (pkg->id == htole32(name2id(name)))
			break;

	if (!pkg)
		die("Package %s not found!", name);


	/* make place at the end of the package for new code */
	codeend = ((void *) pkg) + le32toh(pkg->size);
	memmove(codeend + codesize, codeend, oldend - codeend);

	/* append code */
	memcpy(codeend, code, codesize);
	pkg->gpp.ninst = htole32(le32toh(pkg->gpp.ninst) +
				 disassemble(NULL, code, codesize / 4));

	/* change size members and rehash */
	pkg->size = htole32(le32toh(pkg->size) + codesize);
	timhdr->sizeofreserved = htole32(le32toh(timhdr->sizeofreserved) +
						 codesize);

	tim_rehash(tim);
}

#include "gpp/uart_baudrate_change.c"

void tim_inject_baudrate_change_support(image_t *tim)
{
	printf("Injecting baudrate change code into DDR3 GPP package\n\n");
	tim_append_gpp_code(tim, "DDR3", GPP_uart_baudrate_change,
			    GPP_uart_baudrate_change_size);
}

static void tim_add_gpp_pkg(image_t *tim, const char *name, void *code,
			    size_t codesize, int init_ddr,
			    int enable_memtest, u32 memtest_start,
			    u32 memtest_size, int init_attempts,
			    int ignore_timeouts_op, int ignore_timeouts_val)
{
	respkg_t *pkg;
	struct gpp_op *op;
	int nops = 0;
	u32 size;

	if (codesize & 3)
		die("GPP code length must be a multiple of 4!");

	if (init_ddr)
		++nops;
	if (enable_memtest)
		nops += 3;
	if (init_attempts)
		++nops;
	if (ignore_timeouts_op)
		++nops;

	size = 16 + 8 * nops + codesize;

	pkg = xmalloc(size);
	pkg->id = htole32(name2id(name));
	pkg->size = htole32(size);
	pkg->gpp.nops = htole32(nops);
	pkg->gpp.ninst = htole32(disassemble(NULL, code, codesize / 4));

	op = &pkg->gpp.ops[0];

	if (init_ddr) {
		op->id = htole32(0x01);
		op->value = htole32(1);
		++op;
	}

	if (enable_memtest) {
		op->id = htole32(0x02);
		op->value = htole32(1);
		++op;
		op->id = htole32(0x03);
		op->value = htole32(memtest_start);
		++op;
		op->id = htole32(0x04);
		op->value = htole32(memtest_size);
		++op;
	}

	if (init_attempts) {
		op->id = htole32(0x05);
		op->value = htole32(init_attempts);
		++op;
	}

	if (ignore_timeouts_op) {
		op->id = htole32(0x06);
		op->value = htole32(ignore_timeouts_val);
		++op;
	}

	memcpy(op, code, codesize);

	tim_add_pkgs(tim, 1, pkg, size);

	free(pkg);
}

static void key_hash(u32 alg, u32 *hash, const u32 *x, const u32 *y, int pad)
{
	u32 buf[129];

	memset(buf, 0, sizeof(buf));
	if (alg == HASH_SHA512)
		buf[0] = htole32(SIG_SCHEME_ECDSA_P521_SHA512);
	else
		buf[0] = htole32(SIG_SCHEME_ECDSA_P521_SHA256);
	memcpy(&buf[1], x, 68);
	memcpy(&buf[18], y, 68);

	image_hash(alg, buf, pad ? sizeof(buf) : 140, hash, -1);
}

void tim_add_key(image_t *tim, u32 id, EC_KEY *key)
{
	timhdr_t *timhdr;
	keyinfo_t *keyinfo;
	u32 oldtimsize;

	oldtimsize = tim->size;
	tim_grow(tim, sizeof(keyinfo_t));
	timhdr = (timhdr_t *) tim->data;

	keyinfo = ((void *) (timhdr + 1))
		  + sizeof(imginfo_t) * tim_nimages(timhdr)
		  + sizeof(keyinfo_t) * tim_nkeys(timhdr);

	memmove(keyinfo + 1, keyinfo,
		oldtimsize - ((void *) keyinfo - (void *) timhdr));

	timhdr->numkeys = htole32(le32toh(timhdr->numkeys) + 1);

	memset(keyinfo, 0, sizeof(keyinfo_t));
	keyinfo->id = htole32(id);
	keyinfo->hashalg = htole32(HASH_SHA256);
	keyinfo->size = htole32(521);
	keyinfo->publickeysize = htole32(521);
	keyinfo->encryptalg = htole32(DSALG_ECDSA_521);
	key_get_tim_coords(key, keyinfo->ECDSAcompx, keyinfo->ECDSAcompy);
	key_hash(HASH_SHA256, keyinfo->hash, keyinfo->ECDSAcompx,
		 keyinfo->ECDSAcompy, 0);
}

void tim_get_otp_hash(image_t *tim, u32 *hash)
{
	timhdr_t *timhdr;
	platds_t *platds;

	timhdr = (void *) tim->data;

	if (!timhdr->trusted)
		die("Cannot get OTP hash for non-trusted TIM");

	platds = (void *) tim->data + tim->size - sizeof(platds_t);

	key_hash(HASH_SHA256, hash, platds->ECDSA.pub.x, platds->ECDSA.pub.y,
		 1);
}

void tim_sign(image_t *tim, EC_KEY *key)
{
	const BIGNUM *sigr, *sigs;
	ECDSA_SIG *sig;
	timhdr_t *timhdr;
	platds_t *platds;
	u32 hash[16];

	timhdr = (void *) tim->data;
	if (!timhdr->trusted)
		tim_grow(tim, sizeof(platds_t));

	timhdr = (void *) tim->data;
	platds = (void *) tim->data + tim->size - sizeof(platds_t);

	timhdr->trusted = htole32(1);
	tim_rehash(tim);

	memset(platds, 0, sizeof(platds_t));

	platds->dsalg = htole32(DSALG_ECDSA_521);
	platds->hashalg = htole32(HASH_SHA256);
	platds->keysize = htole32(521);

	key_get_tim_coords(key, platds->ECDSA.pub.x, platds->ECDSA.pub.y);

	image_hash(HASH_SHA256, tim->data, (u8 *) &platds->ECDSA.sig - tim->data,
		   hash, -1);

	sig = ECDSA_do_sign((void *) hash, 32, key);
	if (!sig)
		die("Could not sign");

	ECDSA_SIG_get0(sig, &sigr, &sigs);
	bn2tim(sigr, platds->ECDSA.sig.r, 17);
	bn2tim(sigs, platds->ECDSA.sig.s, 17);
}
