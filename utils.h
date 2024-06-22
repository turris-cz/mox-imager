/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdarg.h>
#include <stdio.h>
#include <endian.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

extern __attribute__((noreturn)) void die(const char *fmt, ...);
extern double now(void);
extern void *xmalloc(size_t sz);
extern void *xrealloc(void *ptr, size_t sz);
extern char *xstrdup(const char *s);
extern char *xstrndup(const char *s, size_t n);
extern void xgetrandom(void *buf, size_t len);

static inline u32 name2id(const char *name)
{
	return htole32(htobe32(*(u32 *) name));
}

static inline const char *id2name(u32 type)
{
	static unsigned char name[5];

	*(u32 *) name = be32toh(type);
	name[4] = 0;

	return (const char *) name;
}

static inline _Bool is_id_valid(u32 id)
{
	const char *name = id2name(id);
	int i;

	for (i = 0; i < 4; ++i)
		if (name[i] < 'A' || name[i] > 'Z')
			return 0;

	return 1;
}

#ifdef __GNUC__
extern inline __attribute__((__format__(printf, 2, 3), __gnu_inline__)) void
Fprintf(FILE *fp, const char * restrict fmt, ...)
{
	if (fp)
		fprintf(fp, fmt, __builtin_va_arg_pack());
}
#else /* ! __GNUC__ */
static inline __attribute__((__format__(printf, 2, 3))) void
Fprintf(FILE *fp, const char * restrict fmt, ...)
{
	va_list ap;

	if (!fp)
		return;

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}
#endif /* ! __GNUC__ */

#endif /* _UTILS_H_ */
