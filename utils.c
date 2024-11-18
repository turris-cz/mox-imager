// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <setjmp.h>

#include "mox-imager.h"
#include "wtptp.h"

static int vffprintf(unsigned int attr, FILE *fp, const char * restrict fmt, va_list ap)
{
	int saved_errno, fd, is_tty, ret;

	saved_errno = errno;

	fd = fileno(fp);
	is_tty = fd >= 0 ? isatty(fd) : 0;

	if (is_tty && attr)
		fprintf(fp, "\033[0m\033[%d%sm", 30 + (attr & 7), (attr & 8) ? ";1" : "");

	errno = saved_errno;

	ret = vfprintf(fp, fmt, ap);

	if (is_tty && attr) {
		fputs("\033[0m", fp);
		fflush(fp);
	}

	return ret;
}

__attribute__((__format__(printf, 1, 2))) void info(const char * restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vffprintf(6, stdout, fmt, ap);
	va_end(ap);
}

__attribute__((__format__(printf, 1, 2))) void notice(const char * restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vffprintf(8 | 3, stdout, fmt, ap);
	va_end(ap);
}

__attribute__((__format__(printf, 1, 2))) void error(const char * restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vffprintf(8 | 1, stdout, fmt, ap);
	va_end(ap);
}

static __attribute__((__noreturn__)) void vdie(const char *fmt, va_list ap)
{
#ifndef GPP_COMPILER
	int saved_errno = errno;
	closewtp();
	errno = saved_errno;
#endif

	vffprintf(8 | 1, stderr, fmt, ap);

	fprintf(stderr, "\n\n");

#ifndef GPP_COMPILER
	if (args.terminal_on_exit) {
		args.terminal_on_exit = 0;
		uart_terminal();
	}
#endif

	exit(EXIT_FAILURE);
}

__attribute__((__noreturn__, __format__(printf, 1, 2))) void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdie(fmt, ap);
	va_end(ap);
}

static jmp_buf *exception_buf;

__attribute__((__noreturn__, __format__(printf, 2, 3))) void throw_or_die(_Bool do_throw, const char *fmt, ...)
{
	va_list ap;

	if (do_throw && exception_buf)
		longjmp(*exception_buf, 1);

	va_start(ap, fmt);
	vdie(fmt, ap);
	va_end(ap);
}

_Bool try_catch(void (*cb)(void *), void *arg)
{
	jmp_buf buf;
	int res;

	exception_buf = &buf;
	res = setjmp(buf);
	if (res) {
		exception_buf = NULL;
		return 1;
	}

	cb(arg);
	exception_buf = NULL;

	return 0;
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

void xgetrandom(void *buf, size_t len)
{
	size_t has = 0;
	ssize_t rd;

	while (has < len) {
		rd = getrandom(buf + has, len - has, GRND_RANDOM);
		if (rd < 0)
			die("Cannot get entropy from getrandom(): %m");

		has += rd;
	}
}
