// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtptp.h"

#pragma weak terminal_on_exit
int terminal_on_exit = 0;

#pragma weak uart_terminal
void uart_terminal(void) {}

__attribute__((noreturn)) void die(const char *fmt, ...)
{
	va_list ap;

#ifndef GPP_COMPILER
	closewtp();
#endif

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n\n");

	if (terminal_on_exit) {
		terminal_on_exit = 0;
		uart_terminal();
	}

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

void *xrealloc(void *ptr, size_t sz)
{
	void *res = realloc(ptr, sz);
	if (sz && !res)
		die("Out of memory");
	return res;
}

char *xstrdup(const char *s)
{
	char *res = strdup(s);
	if (!res)
		die("Out of memory");
	return res;
}

char *xstrndup(const char *s, size_t n)
{
	char *res = strndup(s, n);
	if (!res)
		die("Out of memory");
	return res;
}
