// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "bn.h"
#include "utils.h"
#include "sharand.h"

static void randrange(BIGNUM *dst, BIGNUM *range)
{
	int l, n;
	u32 *buf, *last;

	n = BN_num_bits(range);
	if (!n || n == 1) {
		BN_zero(dst);
		return;
	}

	l = (n + 31) / 32;
	buf = xmalloc(l * sizeof(u32));
	last = &buf[l - 1];

	do {
		sharand_get(buf, l * sizeof(u32));
		*last = htole32(le32toh(*last) & ((1 << (n % 32)) - 1));
		tim2bn(buf, l, dst);
	} while (BN_cmp(dst, range) >= 0);
}

static void compute_public_key(EC_KEY *key, const BIGNUM *priv, BN_CTX *ctx)
{
	EC_POINT *pub;
	const EC_GROUP *group;

	group = EC_KEY_get0_group(key);
	pub = EC_POINT_new(group);
	if (!pub)
		goto err;

	if (!EC_KEY_set_private_key(key, priv))
		goto err;

	if (!EC_POINT_mul(group, pub, priv, NULL, NULL, ctx))	
		goto err;

	if (!EC_KEY_set_public_key(key, pub))
		goto err;

	EC_POINT_free(pub);
	return;

err:
	die("Error computing public key");
}

EC_KEY *sharand_generate_key(void)
{
	EC_KEY *key;
	BN_CTX *ctx;
	BIGNUM *priv, *order;
	const EC_GROUP *group;

	key = EC_KEY_new_by_curve_name(NID_secp521r1);
	if (!key)
		goto err;

	group = EC_KEY_get0_group(key);

	ctx = BN_CTX_new();
	if (!ctx)
		goto err;

	BN_CTX_start(ctx);

	order = BN_CTX_get(ctx);
	priv = BN_CTX_get(ctx);
	if (!order || !priv)
		goto err;

	if (!EC_GROUP_get_order(group, order, ctx))
		goto err;

	do
		randrange(priv, order);
	while (BN_is_zero(priv));

	compute_public_key(key, priv, ctx);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return key;

err:
	die("Error generating EC key");
}

static EC_KEY *dec2key(const char *privstr)
{
	EC_KEY *key;
	BN_CTX *ctx;
	BIGNUM *priv;

	key = EC_KEY_new_by_curve_name(NID_secp521r1);
	if (!key)
		goto err;

	ctx = BN_CTX_new();
	if (!ctx)
		goto err;

	BN_CTX_start(ctx);

	priv = BN_CTX_get(ctx);
	if (!priv)
		goto err;

	if (!BN_dec2bn(&priv, privstr))
		goto err;

	compute_public_key(key, priv, ctx);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return key;

err:
	die("Cannot create key from decimal string");
}

EC_KEY *load_key(const char *path)
{
	int fd;
	char buf[166];
	ssize_t i, rd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		die("Cannot open key file %s: %m", path);

	rd = read(fd, buf, 166);
	if (rd < 0)
		die("Cannot read key file %s: %m", path);
	else if (!rd)
		die("Cannot read key file %s", path);

	close(fd);

	for (i = 0; i < rd; ++i)
		if (buf[i] < '0' || buf[i] > '9')
			break;

	if (!i || i == 165)
		die("Invalid private key file %s", path);

	buf[i] = '\0';

	return dec2key(buf);
}

void save_key(const char *path, const EC_KEY *key)
{
	int fd;
	char *priv;
	ssize_t wr;

	fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
		die("Cannot open key file %s: %m", path);

	priv = BN_bn2dec(EC_KEY_get0_private_key(key));
	if (!priv)
		die("Cannot convert private key");

	wr = write(fd, priv, strlen(priv));
	if (wr < 0)
		die("Cannot write key file %s: %m", path);
	else if (wr != strlen(priv))
		die("Cannot write whole key file %s", path);

	close(fd);
}

void key_get_tim_coords(const EC_KEY *key, u32 *x, u32 *y)
{
	const EC_POINT *pub;
	const EC_GROUP *group;
	BIGNUM *_x, *_y;

	pub = EC_KEY_get0_public_key(key);
	group = EC_KEY_get0_group(key);

	_x = BN_new();
	_y = BN_new();
	if (!_x || !_y)
		goto err;

	if (!EC_POINT_get_affine_coordinates_GFp(group, pub, _x, _y, NULL))
		goto err;

	bn2tim(_x, x, 17);
	bn2tim(_y, y, 17);

	return;
err:
	die("Cannot get key coordinates");
}
