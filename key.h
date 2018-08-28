/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _KEY_H_
#define _KEY_H_

#include <openssl/ec.h>

extern EC_KEY *sharand_generate_key(void);
extern EC_KEY *load_key(const char *path);
extern void save_key(const char *path, const EC_KEY *key);
extern void key_get_tim_coords(const EC_KEY *key, u32 *x, u32 *y);

#endif /* _KEY_H_ */


