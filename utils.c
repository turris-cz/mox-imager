// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

__attribute__((noreturn)) void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n\n");

	exit(EXIT_FAILURE);
}

double now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0)
		die("Cannot get time: %m");

	return (double) ts.tv_sec + (double) ts.tv_nsec / 1000000000L;
}

void *xmalloc(size_t sz)
{
	void *res = malloc(sz);
	if (sz && !res)
		die("Out of memory");
	return res;
}
