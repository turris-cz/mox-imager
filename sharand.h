/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _SHARAND_H_
#define _SHARAND_H_

extern void sharand_seed(const void *key, size_t klen, const void *seed, size_t slen);
extern void sharand_get(void *to, size_t len);

#endif /* _SHARAND_H_ */
