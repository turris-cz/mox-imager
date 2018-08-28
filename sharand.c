// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static unsigned char buffer[64], state[64];
static size_t fill;

void sharand_seed(const void *key, size_t klen, const void *seed, size_t slen)
{
	fill = 0;
	HMAC(EVP_sha512(), key, klen, seed, slen, state, NULL);
}

void sharand_get(void *to, size_t len)
{
	if (fill) {
		if (len <= fill) {
			memcpy(to, buffer, len);
			fill -= len;
			memmove(buffer, buffer + len, fill);
			return;
		} else {
			memcpy(to, buffer, fill);
			to += fill;
			len -= fill;
			fill = 0;
		}
	}

	while (len > 0) {
		SHA512(state, 64, state);

		if (len < 64) {
			memcpy(to, state, len);
			fill = 64 - len;
			memcpy(buffer, state + len, fill);
			return;
		}

		memcpy(to, state, 64);
		to += 64;
		len -= 64;
	}
}

#ifdef TEST
#include <stdlib.h>
#include <errno.h>

int main(int argc, char **argv)
{
	const unsigned char hash[64] =
		"\x3a\x7c\x04\x9c\x24\x41\xcd\x42\xab\x83\x5b\x30\x93\xaa\x7d"
		"\xdc\x13\xae\x3c\x80\x1f\x5c\x9e\xc0\x00\xc2\xc3\x2a\x03\x54"
		"\x58\x94\x5f\x34\xf2\xb3\xd1\xa0\x6d\xb3\xd5\x0a\x51\x35\xd4"
		"\x6c\x40\xf9\x07\xc2\x09\xc0\xe4\x4c\xee\x0c\xd8\x39\x4b\x66"
		"\x61\x3f\xe8\xcf";
	unsigned char buf1[1275], buf2[1275], *p;
	int i;

	sharand_seed("secret key", 10, "seed 1337", 9);

	for (i = 1, p = buf1; i <= 50; p += i, ++i)
		sharand_get(p, i);

	sharand_seed("secret key", 10, "seed 1337", 9);

	for (i = 50, p = buf2; i >= 1; p += i, --i)
		sharand_get(p, i);

	if (memcmp(buf1, buf2, 1275))
		exit(EXIT_FAILURE);

	SHA512(buf1, 1275, buf1);

	if (memcmp(buf1, hash, 64))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
#endif /* TEST */
