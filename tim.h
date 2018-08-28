/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _TIM_H_
#define _TIM_H_

#include <stdlib.h>
#include <endian.h>
#include <openssl/ec.h>
#include "utils.h"
#include "images.h"

#define TIMH_ID	0x54494d48
#define OBMI_ID 0x4f424d49

#define BOOTFS_SPINOR	0x5350490a
#define BOOTFS_SPINAND	0x5350491a
#define BOOTFS_EMMC	0x454d4d08
#define BOOTFS_EMMCALT	0x454d4d0b
#define BOOTFS_SATA	0x53415432
#define BOOTFS_UART	0x55415223

typedef struct {
	u32 version;
	u32 identifier;
	u32 trusted;
	u32 issuedate;
	u32 oemuid;
	u32 reserved[5];
	u32 bootflashsign;
	u32 numimages;
	u32 numkeys;
	u32 sizeofreserved;
} timhdr_t;

#define HASH_SHA160	20
#define HASH_SHA256	32
#define HASH_SHA512	64

#define ENC_AESCTS_ECB128	0x0001e000
#define ENC_AESCTS_ECB256	0x0001e001
#define ENC_AESCTS_ECB192	0x0001e002
#define ENC_AESCTS_CBC128	0x0001e004
#define ENC_AESCTS_CBC256	0x0001e005
#define ENC_AESCTS_CBC192	0x0001e006

typedef struct {
	u32 id;
	u32 nextid;
	u32 flashentryaddr;
	u32 loadaddr;
	u32 size;
	u32 sizetohash;
	u32 hashalg;
	u32 hash[16];
	u32 partitionnumber;
	u32 encalg;
	u32 encryptoffset;
	u32 encryptsize;
} imginfo_t;

typedef struct {
	u32 id;
	u32 hashalg;
	u32 size;
	u32 publickeysize;
	u32 encryptalg;
	union {
		u32 data[128];
		struct {
			u32 RSAexp[64];
			u32 RSAmod[64];
		};
		struct {
			u32 ECDSAcompx[17];
			u32 ECDSAcompy[17];
		};
	};
	u32 hash[16];
} keyinfo_t;

#define RES_ID		0x4f505448

typedef struct {
	u32 id;
	u32 pkgs;
} reshdr_t;

#define PKG_PINP	0x50494e50
#define PKG_TOKE	0x544f4b45
#define PKG_Term	0x5465726d

typedef struct {
	u32 id;
	u32 size;
	u32 data[];
} respkg_t;

#define DSALG_ECDSA_256		5
#define DSALG_ECDSA_521		6
#define SIG_SCHEME_ECDSA_P521_SHA256	0x0000b311
#define SIG_SCHEME_ECDSA_P521_SHA512	0x0000b341

typedef struct {
	u32 dsalg;
	u32 hashalg;
	u32 keysize;
	u32 hash[8];
	union {
		u32 data[192];
		struct {
			struct {
				u32 exp[64];
				u32 mod[64];
			} pub;
			u32 sig[64];
		} RSA;
		struct {
			struct {
				u32 x[17];
				u32 y[17];
			} pub;
			struct {
				u32 r[17];
				u32 s[17];
			} sig;
		} ECDSA;
	};
} platds_t;

static inline const char *hash2name(u32 hash)
{
	switch (hash) {
	case HASH_SHA160:
		return "sha-160";
	case HASH_SHA256:
		return "sha-256";
	case HASH_SHA512:
		return "sha-512";
	case 0:
		return "none";
	default:
		return "unknown";
	}
}

static inline const char *enc2name(u32 enc)
{
	switch (enc) {
	case ENC_AESCTS_ECB128:
		return "aes-tb-cts-ecb128";
	case ENC_AESCTS_ECB256:
		return "aes-tb-cts-ecb128";
	case ENC_AESCTS_ECB192:
		return "aes-tb-cts-ecb128";
	case ENC_AESCTS_CBC128:
		return "aes-tb-cts-cbc128";
	case ENC_AESCTS_CBC256:
		return "aes-tb-cts-cbc256";
	case ENC_AESCTS_CBC192:
		return "aes-tb-cts-cbc192";
	case 0:
		return "none";
	default:
		return "unknown";
	}
}

static inline const char *bootfs2name(u32 bootfs)
{
	switch (bootfs) {
	case BOOTFS_SPINOR:
		return "SPI NOR";
	case BOOTFS_SPINAND:
		return "SPI NAND";
	case BOOTFS_EMMC:
		return "eMMC";
	case BOOTFS_EMMCALT:
		return "eMMC alternative";
	case BOOTFS_SATA:
		return "SATA";
	case BOOTFS_UART:
		return "UART";
	default:
		return "unknown";
	}
}

static inline int tim_nimages(const timhdr_t *timhdr)
{
	return le32toh(timhdr->numimages);
}

static inline imginfo_t *tim_image(timhdr_t *timhdr, int i)
{
	if (i < 0 || i >= tim_nimages(timhdr))
		return NULL;

	return ((imginfo_t *) (timhdr + 1)) + i;
}

static inline size_t tim_size(timhdr_t *timhdr)
{
	size_t res;

	res = sizeof(timhdr_t);
	res += tim_nimages(timhdr) * sizeof(imginfo_t);
	res += le32toh(timhdr->numkeys) * sizeof(keyinfo_t);
	res += le32toh(timhdr->sizeofreserved);
	if (timhdr->trusted)
		res += sizeof(platds_t);

	return res;
}

extern void tim_parse(image_t *tim, int *numimagesp);
extern void tim_add_pin(image_t *tim, u64 pin);
extern void tim_hash_obmi(int set);
extern void tim_rehash(image_t *tim);
extern void tim_sign(image_t *tim, EC_KEY *key);
extern void tim_set_boot(image_t *tim, u32 boot);

#endif /* _TIM_H_ */
