// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

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
#include "gpp.h"

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

static void tim_remove_image(image_t *tim, u32 id)
{
	timhdr_t *timhdr;
	imginfo_t *img;
	void *imgend;
	int i;

	timhdr = (void *) tim->data;

	for (i = 0; i < tim_nimages(timhdr); ++i) {
		img = tim_image(timhdr, i);
		if (le32toh(img->id) == id)
			break;
	}

	if (i == tim_nimages(timhdr))
		return;

	if (i > 0)
		(img - 1)->nextid = img->nextid;

	imgend = img + 1;
	memmove(img, imgend, (void *) tim->data + tim->size - imgend);

	timhdr->numimages = htole32(tim_nimages(timhdr) - 1);
	tim->size -= sizeof(imginfo_t);
}

static void tim_remove_pkg(image_t *tim, u32 id)
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

	if (!pkg)
		return;

	pkgsize = le32toh(pkg->size);
	pkgend = (void *) pkg + pkgsize;
	memmove(pkg, pkgend, (void *) tim->data + tim->size - pkgend);

	reshdr = reserved_area(timhdr);
	reshdr->pkgs = htole32(le32toh(reshdr->pkgs) - 1);
	timhdr->sizeofreserved = htole32(le32toh(timhdr->sizeofreserved) - pkgsize);
	tim->size -= pkgsize;
}

void tim_minimal_image(image_t *tim)
{
	void *data;
	timhdr_t *timhdr;
	imginfo_t *img;
	reshdr_t *reshdr;
	respkg_t *pkg;

	data = xmalloc(228);
	memset(data, 0, 228);

	timhdr = data;
	timhdr->version = htole32(0x30600);
	timhdr->sizeofreserved = htole32(64);
	timhdr->bootflashsign = htole32(BOOTFS_UART);
	timhdr->identifier = htole32(TIMH_ID);
	timhdr->numimages = htole32(1);

	img = (void *) (timhdr + 1);
	img->id = htole32(TIMH_ID);
	img->loadaddr = htole32(0x20006000);
	img->hashalg = htole32(HASH_SHA512);
	img->nextid = 0xffffffff;
	img->size = img->sizetohash = htole32(228);

	reshdr = (void *) (img + 1);
	reshdr->id = htole32(RES_ID);
	reshdr->pkgs = 3;

	pkg = (void *) (reshdr + 1);
	pkg->id = htole32(name2id("CIDP"));
	pkg->size = htole32(24);
	pkg->data[0] = htole32(1);
	pkg->data[1] = htole32(name2id("TBRI"));
	pkg->data[2] = htole32(1);
	pkg->data[3] = htole32(name2id("GPP1"));

	pkg = (void *) pkg + 24;
	pkg->id = htole32(name2id("GPP1"));
	pkg->size = htole32(24);
	pkg->data[0] = htole32(1);
	pkg->data[1] = htole32(0xa);
	pkg->data[2] = htole32(6);
	pkg->data[3] = 0;

	pkg = (void *) pkg + 24;
	pkg->id = htole32(name2id("Term"));
	pkg->size = htole32(8);

	if (tim->data)
		free(tim->data);

	tim->data = data;
	tim->size = 228;
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
		printf("%08x%c", htole32(hash[i]), i == 15 ? '\n' : ' ');

	image_hash(HASH_SHA512, tim->data, (u8 *) &platds->ECDSA.sig - tim->data,
		   hash, -1);

	sig = ECDSA_do_sign((void *) hash, sizeof(hash), key);
	if (!sig)
		die("Could not sign");

	bn2tim(sig->r, platds->ECDSA.sig.r, 17);
	bn2tim(sig->s, platds->ECDSA.sig.s, 17);
}

static void tim_emit_gpp1(image_t *tim, void (*emit_func)(u32 *), u32 *args)
{
	timhdr_t *timhdr;
	respkg_t *pkg;
	void *pkgend;
	u32 *instrs, togrow, oldtimsize;

	tim_minimal_image(tim);

	gpp_emit_start();
	emit_func(args);
	instrs = gpp_emit_get(&togrow);

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
	memcpy(pkgend, instrs, togrow);
	gpp_emit_end();

	pkg->size = htole32(le32toh(pkg->size) + togrow);
	timhdr->sizeofreserved = htole32(le32toh(timhdr->sizeofreserved) +
					 togrow);

	tim_rehash(tim);
}

void tim_emit_otp_read(image_t *tim)
{
	tim_emit_gpp1(tim, gpp_emit_otp_read, NULL);
}

void tim_emit_otp_write(image_t *tim, int nrows, int *rows, u64 *vals,
			int *locks)
{
	int i;
	u32 *args;

	args = xmalloc(sizeof(u32) * (4 * nrows + 1));
	args[0] = nrows;
	for (i = 0; i < nrows; ++i) {
		args[1 + 4 * i] = rows[i];
		args[1 + 4 * i + 1] = vals[i] & 0xffffffff;
		args[1 + 4 * i + 2] = vals[i] >> 32;
		args[1 + 4 * i + 3] = locks[i];
	}

	tim_emit_gpp1(tim, gpp_emit_otp_write, args);
	free(args);
}
