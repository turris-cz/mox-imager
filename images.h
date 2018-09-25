/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _IMAGES_H_
#define _IMAGES_H_

#include "utils.h"

typedef struct {
	u32 id;
	u32 size;
	u8 *data;
} image_t;

extern image_t *image_find(u32 id);
extern void image_hash(u32 alg, void *buf, size_t size, void *out, u32 hashaddr);
extern image_t *image_new(void *data, u32 size, u32 id);
extern void image_delete_all(void);
extern void image_load(const char *path);

#endif /* _IMAGES_H_ */
