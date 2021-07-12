// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <endian.h>
#include "tim.h"
#include "utils.h"
#include "wtptp.h"

static image_t images[32];

image_t *image_find(u32 id)
{
	int i;

	for (i = 0; i < 32; ++i) {
		if (images[i].id == id)
			return images + i;
	}

	die("Cannot find image %s (%08x)", id2name(id), id);
}

void image_hash(u32 alg, void *buf, size_t size, void *out, u32 hashaddr)
{
	static const u32 zeros[16];

	memset(out, 0, 64);

	if (alg == HASH_SHA256) {
		SHA256_CTX ctx;

		SHA256_Init(&ctx);
		if (hashaddr != -1U) {
			SHA256_Update(&ctx, buf, hashaddr);
			SHA256_Update(&ctx, zeros, 64);
			SHA256_Update(&ctx, buf + hashaddr + 64,
				      size - hashaddr - 64);
		} else {
			SHA256_Update(&ctx, buf, size);
		}
		SHA256_Final((void *) out, &ctx);
	} else if (alg == HASH_SHA512) {
		SHA512_CTX ctx;

		SHA512_Init(&ctx);
		if (hashaddr != -1U) {
			SHA512_Update(&ctx, buf, hashaddr);
			SHA512_Update(&ctx, zeros, 64);
			SHA512_Update(&ctx, buf + hashaddr + 64,
				      size - hashaddr - 64);
		} else {
			SHA512_Update(&ctx, buf, size);
		}
		SHA512_Final((void *) out, &ctx);
	} else {
		die("Unsupported hash %s", hash2name(alg));
	}
}

image_t *image_new(void *data, u32 size, u32 id)
{
	int i;

	for (i = 0; i < 32; ++i)
		if (images[i].id == id)
			die("More than one %s image", id2name(id));

	for (i = 0; i < 32; ++i)
		if (!images[i].id)
			break;

	if (i == 32)
		die("Too many images");

	images[i].id = id;
	images[i].data = data;
	images[i].size = size;

	return images + i;
}

void image_delete_all(void)
{
	int i;

	for (i = 0; i < 32; ++i) {
		if (images[i].id)
			if (images[i].id == TIMH_ID || images[i].id == TIMN_ID)
				free(images[i].data);

		images[i].id = images[i].size = 0;
		images[i].data = NULL;
	}
}

static int do_load(void *data, size_t data_size, u32 hdr_addr)
{
	if (!memcmp(data + hdr_addr + 4, "HMIT", 4) ||
	    !memcmp(data + hdr_addr + 4, "NMIT", 4)) {
		timhdr_t *timhdr;
		image_t *tim;
		void *timdata;
		size_t timsize;
		u32 cskt_addr;
		int i, f, do_rehash = 0;

		timhdr = data + hdr_addr;
		timsize = tim_size(timhdr);
		timdata = xmalloc(timsize);
		memcpy(timdata, timhdr, timsize);

		tim = image_new(timdata, timsize, le32toh(timhdr->identifier));
		timhdr = timdata;

		f = 0;
		for (i = 0; i < tim_nimages(timhdr); ++i) {
			imginfo_t *img = tim_image(timhdr, i);
			u32 entry, size;

			if (!img)
				break;

			entry = le32toh(img->flashentryaddr);
			size = le32toh(img->size);

			if (img->id == timhdr->identifier)
				continue;

			if (data_size < entry)
				continue;

			if (data_size < entry + size) {
				size = data_size - entry;
				if (img->sizetohash) {
					img->size = htole32(size);
					do_rehash = 1;
				}
			}

			image_new(data + entry, size, le32toh(img->id));
			++f;
		}

		cskt_addr = tim_imap_pkg_addr(tim, name2id("CSKT"));
		if (cskt_addr != -1U && cskt_addr < data_size)
			f += do_load(data, data_size, cskt_addr);

		if (do_rehash)
			tim_rehash(tim);

		if (!f && !hdr_addr)
			munmap(data, data_size);

		return f;
	} else {
		image_new(data + 4, data_size - 4, le32toh(*(u32 *) data));
		return 1;
	}
}

void image_load(const char *path)
{
	int fd;
	struct stat st;
	void *data;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		die("Cannot open %s: %m", path);

	if (fstat(fd, &st) < 0)
		die("Cannot stat %s: %m", path);

	if (!S_ISREG(st.st_mode))
		die("%s is not a regular file", path);

	if (st.st_size < 8)
		die("%s is too small (%zu bytes)", path, st.st_size);

	data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED)
		die("Cannot mmap %s: %m", path);

	close(fd);

	do_load(data, st.st_size, 0);
}
