// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include "utils.h"
#include "bn.h"
#include "sharand.h"

void bn2tim(const BIGNUM *bn, u32 *data, int len)
{
	int i, bnsz, lensz;

	bnsz = BN_num_bytes(bn);
	lensz = len * sizeof(u32);

	if (bnsz > lensz)
		die("Bignum too long");
	if (BN_is_negative(bn))
		die("Bignum is negative");

	memset(data, 0, lensz);
	BN_bn2bin(bn, (u8*)data + lensz - bnsz);

	for (i = 0; i < len; ++i)
		data[i] = bswap_32(data[i]);

	for (i = 0; i < len / 2; ++i) {
		u32 tmp = data[i];
		data[i] = data[len - 1 - i];
		data[len - 1 - i] = tmp;
	}
}

void tim2bn(const u32 *data, int len, BIGNUM *bn)
{
	u32 bdata[len];
	int i;

	for (i = 0; i < len; ++i)
		bdata[i] = bswap_32(data[len - i - 1]);

	BN_bin2bn((void *)bdata, len * sizeof(u32), bn);
}

void prbn(const BIGNUM *bn)
{
	u32 d[17];
	int i;

	bn2tim(bn, d, 17);

	for (i = 0; i < 17; ++i)
		printf(" %08x", d[i]);
	printf("\n");
}
