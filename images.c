// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <endian.h>
#include "tim.h"
#include "utils.h"
#include "wtptp.h"

static image_t images[32];

static image_t *_image_find(u32 id)
{
	int i;

	for (i = 0; i < 32; ++i) {
		if (images[i].id == id)
			return images + i;
	}

	return NULL;
}

image_t *image_find(u32 id)
{
	image_t *img = _image_find(id);

	if (img)
		return img;

	die("Cannot find image %s (%08x)", id2name(id), id);
}

_Bool image_exists(u32 id)
{
	return _image_find(id);
}

void image_hash(u32 alg, void *buf, size_t size, void *out, u32 hashaddr)
{
	static const u32 zeros[16];
	const EVP_MD *type;
	EVP_MD_CTX *ctx;

	memset(out, 0, 64);

	if (alg == HASH_SHA256)
		type = EVP_sha256();
	else if (alg == HASH_SHA512)
		type = EVP_sha512();
	else
		die("Unsupported hash %s (ID = 0x%x)", hash2name(alg), alg);

	ctx = EVP_MD_CTX_new();

	if (!EVP_DigestInit(ctx, type))
		die("Failed initializing digest %s", hash2name(alg));

	if (hashaddr != -1U) {
		if (!EVP_DigestUpdate(ctx, buf, hashaddr) ||
		    !EVP_DigestUpdate(ctx, zeros, 64) ||
		    !EVP_DigestUpdate(ctx, buf + hashaddr + 64, size - hashaddr - 64))
			goto fail;
	} else {
		if (!EVP_DigestUpdate(ctx, buf, size))
			goto fail;
	}

	if (!EVP_DigestFinal_ex(ctx, (void *)out, NULL))
		goto fail;

	EVP_MD_CTX_free(ctx);

	return;
fail:
	die("Failed hashing (%s)", hash2name(alg));
}

void image_delete_all(void)
{
	for (int i = 0; i < 32; ++i) {
		if (!images[i].id)
			continue;

		if (images[i].id == TIMH_ID || images[i].id == TIMN_ID)
			free(images[i].data);

		images[i].id = 0;
		images[i].data = NULL;
		images[i].size = 0;
	}
}

image_t *image_new(void *data, u32 size, u32 id)
{
	int i;

	if (!is_id_valid(id))
		die("Invalid image file");

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

static int do_load(void *data, size_t data_size, u32 hdr_addr)
{
	static u32 wait_ids[32];

	if (!memcmp(data + hdr_addr + 4, "HMIT", 4) ||
	    !memcmp(data + hdr_addr + 4, "NMIT", 4)) {
		timhdr_t *timhdr;
		image_t *tim;
		void *timdata;
		size_t timsize;
		u32 cskt_addr;
		int i, j, f, do_rehash = 0;

		timhdr = data + hdr_addr;
		timsize = tim_size(timhdr);
		timdata = xmalloc(timsize);
		memcpy(timdata, timhdr, timsize);

		tim = image_new(timdata, timsize, le32toh(timhdr->identifier));
		timhdr = timdata;

		f = 0;
		for (i = 0; i < tim_nimages(timhdr); ++i) {
			imginfo_t *img = tim_image(timhdr, i);
			u32 entry, size, id;

			if (!img)
				break;

			id = le32toh(img->id);
			entry = le32toh(img->flashentryaddr);
			size = le32toh(img->size);

			if (img->id == timhdr->identifier)
				continue;

			/*
			 * If image entry is outside of the current file then
			 * wait for the image in another file.
			 */
			if (data_size <= entry) {
				if (!is_id_valid(id))
					die("Invalid image id");

				for (j = 0; j < 32; ++j)
					if (!wait_ids[j])
						break;

				if (j == 32)
					die("Too many images");

				wait_ids[j] = id;
				continue;
			}

			/*
			 * If image entry is inside of the current file but
			 * end of image is outside, then change the size, but
			 * only if the image is to be hashed. This is to avoid
			 * changing TIM in case it is signed. If the image is
			 * to be hashed and the size is incorrect, the hash,
			 * which is inside the TIM, will need to change anyway,
			 * and it that case the potential signature will be
			 * invalidated.
			 */
			if (data_size < entry + size) {
				size = data_size - entry;
				if (img->sizetohash) {
					img->size = htole32(size);
					img->sizetohash = htole32(size);
					do_rehash = 1;
				}
			}

			image_new(data + entry, size, id);
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
		u32 id;
		int i;

		if (data_size > 4 && is_id_valid(le32toh(*(u32 *) data))) {
			id = le32toh(*(u32 *) data);
			data += 4;
			data_size -= 4;
			for (i = 0; i < 32; ++i) {
				if (wait_ids[i] == id) {
					wait_ids[i] = 0;
					break;
				}
			}
		} else {
			for (i = 0; i < 32; ++i)
				if (wait_ids[i])
					break;

			if (i == 32) {
				/*
				 * If OBMI image was not yet loaded and this
				 * image contains "Trusted Firmware", consider
				 * it an OBMI image.
				 */
				if (!image_exists(OBMI_ID) &&
				    memmem(data, data_size, "Trusted Firmware",
					   strlen("Trusted Firmware"))) {
					id = OBMI_ID;
				} else {
					die("Invalid image file");
				}
			} else {
				id = wait_ids[i];
				wait_ids[i] = 0;
			}
		}

		image_new(data, data_size, id);

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

void image_load_bundled(void *data, size_t size)
{
	do_load(data, size, 0);
}
