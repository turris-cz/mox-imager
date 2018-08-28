// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include "utils.h"
#include "bn.h"
#include "sharand.h"

void bn2tim(const BIGNUM *bn, u32 *data, int len)
{
	int i;

	if ((len + 1) / 2 < bn->top ||
	    (len & 1 && (len + 1) / 2 == bn->top && bn->d[bn->top - 1] >> 32))
		die("Bignum too long");

	memset(data, 0, len * sizeof(u32));

	for (i = 0; i < bn->top; ++i) {
		data[2*i] = htole32(bn->d[i] & 0xffffffff);
		if (2*i + 1 < len)
			data[2*i + 1] = htole32(bn->d[i] >> 32);
	}
}

void tim2bn(u32 *data, int len, BIGNUM *bn)
{
	int i;

	BN_zero(bn);
	BN_set_bit(bn, len * 32 - 1);

	for (i = 0; i < bn->top; ++i) {
		bn->d[i] = le32toh(data[2*i]);
		if (2*i + 1 < len)
			bn->d[i] |= ((u64) le32toh(data[2*i + 1])) << 32;
	}
}

void prbn(BIGNUM *bn)
{
	u32 d[17];
	int i;

	bn2tim(bn, d, 17);

	for (i = 0; i < 17; ++i)
		printf(" %08x", d[i]);
	printf("\n");
}
