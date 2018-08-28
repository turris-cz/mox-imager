/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _UTILS_H_
#define _UTILS_H_

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern __attribute__((noreturn)) void die(const char *fmt, ...);
extern double now(void);
extern void *xmalloc(size_t sz);

#endif /* _UTILS_H_ */
