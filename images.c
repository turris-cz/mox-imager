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
		if (hashaddr != -1) {
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
		if (hashaddr != -1) {
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

static void newimage(void *data, u32 size, u32 id)
{
	static int tim;
	int i;

	for (i = 0; i < 32; ++i)
		if (!images[i].id)
			break;

	if (i == 32)
		die("Too many images");

	if (id == TIMH_ID) {
		if (tim)
			die("More than one TIM image");
		tim = 1;
	}

	images[i].id = id;
	images[i].data = data;
	images[i].size = size;
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

	data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED)
		die("Cannot mmap %s: %m", path);

	close(fd);

	if (!memcmp(data + 4, "HMIT", 4)) {
		timhdr_t *timhdr = data;
		void *timdata;
		size_t timsize;
		int i, f;

		timsize = tim_size(timhdr);

		timdata = xmalloc(timsize);
		memcpy(timdata, timhdr, timsize);
		newimage(timdata, timsize, TIMH_ID);

		f = 0;
		for (i = 0; i < tim_nimages(timhdr); ++i) {
			imginfo_t *img = tim_image(timhdr, i);
			u32 entry, size;

			if (!img)
				break;

			entry = le32toh(img->flashentryaddr);
			size = le32toh(img->size);

			if (!entry || st.st_size < entry + size)
				continue;

			newimage(data + entry, size, le32toh(img->id));
			++f;
		}

		if (!f)
			munmap(data, st.st_size);
	} else {
		newimage(data + 4, st.st_size - 4, le32toh(*(u32 *) data));
	}
}

