/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _IMAGES_H_
#define _IMAGES_H_

#include <endian.h>
#include "utils.h"

typedef struct {
	u32 id;
	u32 size;
	u8 *data;
} image_t;

static inline const char *id2name(u32 type)
{
	static unsigned char name[5];

	*(u32 *) name = be32toh(type);
	name[4] = 0;

	return (const char *) name;
}

extern image_t *image_find(u32 id);
extern void image_hash(u32 alg, void *buf, size_t size, void *out, u32 hashaddr);
extern void image_load(const char *path);

#endif /* _IMAGES_H_ */
