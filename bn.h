/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _BN_H_
#define _BN_H_

#include <openssl/bn.h>
#include "utils.h"

extern void bn2tim(const BIGNUM *bn, u32 *data, int len);
extern void tim2bn(const u32 *data, int len, BIGNUM *bn);
extern void prbn(const BIGNUM *bn);

#endif /* _BN_H_ */
