// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <openssl/ec.h>
#include "tim.h"
#include "utils.h"
#include "wtptp.h"
#include "sharand.h"
#include "key.h"
#include "images.h"

static void generate_key(const char *keypath, const char *seedpath)
{
	EC_KEY *key;
	int fd;
	struct stat st;
	void *seed;

	fd = open(seedpath, O_RDONLY);
	if (fd < 0)
		die("Cannot open random seed: %m");

	if (fstat(fd, &st) < 0)
		die("Cannot stat random seed: %m");

	if (st.st_size < 64)
		die("Random seed must be at least 64 bytes (%zu found)",
		    st.st_size);

	seed = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (seed == MAP_FAILED)
		die("Cannot mmap random seed: %m");

	close(fd);

	sharand_seed("Turris Mox", 10, seed, st.st_size);
	munmap(seed, st.st_size);

	key = sharand_generate_key();
	save_key(keypath, key);
	EC_KEY_free(key);
}

static void save_flash_image(image_t *tim, const char *path)
{
	int i, fd;
	void *data;
	u32 maxaddr = 0, endaddr;
	timhdr_t *timhdr;
	imginfo_t *info;

	timhdr = (void *) tim->data;

	for (i = 0; i < tim_nimages(timhdr); ++i) {
		info = tim_image(timhdr, i);

		endaddr = le32toh(info->flashentryaddr) + le32toh(info->size);
		if (endaddr > maxaddr)
			maxaddr = endaddr;
	}

	fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("Cannot open %s for writing: %m", path);

	if (ftruncate(fd, maxaddr) < 0)
		die("Cannot trucate %s to size %u: %m", path, maxaddr);

	data = mmap(NULL, maxaddr, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED)
		die("Cannot mmap %s: %m", path);

	close(fd);

	memset(data, 0, maxaddr);

	for (i = 0; i < tim_nimages(timhdr); ++i) {
		image_t *img;

		info = tim_image(timhdr, i);
		img = image_find(le32toh(info->id));

		memcpy(data + le32toh(info->flashentryaddr),
		       img->data, img->size);
	}

	if (munmap(data, maxaddr) < 0)
		die("Cannot unmap %s: %m", path);
}

static u64 secded_ecc(u64 data)
{
	static const u64 pos[8] = {
		0x145011110ff014ff, 0x24ff2222f000249f, 0x4c9f444400ff44d0,
		0x84d08888ff0f8c50, 0x0931f0ff11110b21, 0x0b22ff002222fa32,
		0xfa24000f4444ff24, 0xff280ff088880928
	};
	u64 ecc, tmp;
	int i, j, t;

	ecc = 0;
	for (i = 0; i < 8; ++i) {
		tmp = pos[i];
		t = 0;
		for (j = 0; j < 64; ++j) {
			if (tmp & 1)
				t ^= (data >> j) & 1;
			tmp >>= 1;
		}
		ecc |= t << i;
	}

	return ecc;
}

static int xdigit2i(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

static u64 mac2u64(const char *mac)
{
	int i, d1, d2;
	u64 res = 0;

	for (i = 0; i < 6; ++i) {
		d1 = xdigit2i(mac[i * 3]);
		d2 = xdigit2i(mac[i * 3 + 1]);

		if (d1 < 0 || d2 < 0 || (i < 5 && mac[i * 3 + 2] != ':') ||
		    (i == 5 && mac[i * 3 + 2]))
			die("Invalid MAC address \"%s\"", mac);

		res |= ((u64) d1) << ((5 - i) * 8 + 4);
		res |= ((u64) d2) << ((5 - i) * 8);
	}

	return res;
}

static void do_otp_write(image_t *tim, const char *serial_number,
			 const char *mac_address, const char *board_version)
{
	u64 mac, vals[2];
	u32 sn, bv;
	int rows[2], locks[2];
	char *end;
	time_t tm;

	sn = strtoul(serial_number, &end, 16);
	if (*end)
		die("Invalid serial number \"%s\"", serial_number);

	bv = strtoul(board_version, &end, 10);
	if (*end || bv > 0xff)
		die("Invalid board version \"%s\"", board_version);

	mac = mac2u64(mac_address);

	printf("Will write serial number %08X, board version %u and MAC address %s into OTP.\n",
	       sn, bv, mac_address);

	rows[0] = 42;
	vals[0] = (((u64) bv) << 48) | mac;
	locks[0] = 1;

	rows[1] = 43;
	vals[1] = (((u64) time(NULL)) << 32) | sn;
	locks[1] = 1;

	tim_emit_otp_write(tim, 2, rows, vals, locks);
}

static void help(void)
{
	fprintf(stdout,
		"Usage: mox-imager [OPTION]... [IMAGE]...\n\n"
		"  -D, --device=TTY         upload images via UART to TTY\n"
		"  -p, --pin=PIN            set PIN code (as hexadecimal number)\n"
		"  -o, --output=IMAGE       output SPI NOR flash image to IMAGE\n"
		"  -k, --key=KEY            read ECDSA-521 private key from file KEY\n"
		"  -r, --random-seed=FILE   read random seed from file\n"
		"  -R, --otp-read           read OTP memory\n"
		"  -W, --otp-write          write OTP memory\n"
		"      --serial-number=SN   serial number to write to OTP memory\n"
		"      --mac-address=MAC    MAC address to write to OTP memory\n"
		"      --board-version=BV   board version to write to OTP memory\n"
		"  -g, --gen-key=KEY        generate ECDSA-521 private key to file KEY\n"
		"  -s, --sign               sign TIM image with ECDSA-521 private key\n"
		"  -u, --hash-u-boot        save OBMI (U-Boot) image hash to TIM\n"
		"  -n, --no-u-boot          remove OBMI (U-Boot) image from TIM\n"
		"  -h, --help               show this help and exit\n"
		"\n");
	exit(EXIT_SUCCESS);
}

static const struct option long_options[] = {
	{ "device",		required_argument,	0,	'D' },
	{ "pin",		required_argument,	0,	'p' },
	{ "output",		required_argument,	0,	'o' },
	{ "key",		required_argument,	0,	'k' },
	{ "random-seed",	required_argument,	0,	'r' },
	{ "otp-read",		no_argument,		0,	'R' },
	{ "otp-write",		no_argument,		0,	'W' },
	{ "serial-number",	required_argument,	0,	'S' },
	{ "mac-address",	required_argument,	0,	'M' },
	{ "board-version",	required_argument,	0,	'B' },
	{ "gen-key",		required_argument,	0,	'g' },
	{ "sign",		no_argument,		0,	's' },
	{ "hash-u-boot",	no_argument,		0,	'u' },
	{ "no-u-boot",		no_argument,		0,	'n' },
	{ "help",		no_argument,		0,	'h' },
	{ 0,			0,			0,	0 },
};

int main(int argc, char **argv)
{
	const char *tty, *pin, *output, *keyfile, *seed, *genkey,
		   *serial_number, *mac_address, *board_version;
	int sign, hash_u_boot, no_u_boot, otp_read, otp_write;
	image_t *tim;
	int nimages;

	tty = pin = output = keyfile = seed = genkey = serial_number =
              mac_address = board_version = NULL;
	sign = hash_u_boot = no_u_boot = otp_read = otp_write = 0;

	while (1) {
		int optidx;
		char c;

		c = getopt_long(argc, argv, "D:p:o:k:r:RWg:sunh", long_options,
				NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'D':
			if (tty)
				die("Device already given");
			tty = optarg;
			break;
		case 'p':
			if (pin)
				die("Pin already given");
			pin = optarg;
			break;
		case 'o':
			if (output)
				die("Output file already given");
			output = optarg;
			break;
		case 'k':
			if (keyfile)
				die("Key file already given");
			keyfile = optarg;
			break;
		case 'r':
			if (seed)
				die("Random seed file already given");
			seed = optarg;
			break;
		case 'R':
			otp_read = 1;
			break;
		case 'W':
			otp_write = 1;
			break;
		case 'S':
			if (serial_number)
				die("Serial number already given");
			serial_number = optarg;
			break;
		case 'M':
			if (mac_address)
				die("Mac address already given");
			mac_address = optarg;
			break;
		case 'B':
			if (board_version)
				die("Board version already given");
			board_version = optarg;
			break;
		case 'g':
			if (genkey)
				die("File to which generate key already given");
			genkey = optarg;
			break;
		case 's':
			sign = 1;
			break;
		case 'u':
			hash_u_boot = 1;
			break;
		case 'n':
			no_u_boot = 1;
			break;
		case 'h':
			help();
			break;
		case '?':
			die("Try 'mox-imager --help' for more information");
		default:
			die("Error parsing command line");
		}
	}

	if (tty && output)
		die("Options --device and --output cannot be used together");

	if (sign && !keyfile)
		die("Option --key must be given when signing");

	if ((otp_read || otp_write) && !tty)
		die("Option --device must be specified when reading/writing OTP");

	if (otp_read && otp_write)
		die("Options to read and write OTP cannot be used together");

	if (otp_write && (!serial_number || !mac_address || !board_version))
		die("Serial number, MAC address and board version must be given when writing OTP");

	if (genkey) {
		if (!seed)
			die("Random seed file must be given when generating key");
		else if (optind < argc)
			die("Images must not be given when generating key");

		generate_key(genkey, seed);
		exit(EXIT_SUCCESS);
	}

	if (otp_read || otp_write) {
		if (optind < argc)
			die("Images given when trying to read/write OTP");

		tim = image_new(NULL, 0, TIMH_ID);
		tim_minimal_image(tim);
		if (otp_write)
			do_otp_write(tim, serial_number, mac_address, board_version);
		else
			tim_emit_otp_read(tim);

		nimages = 1;
	} else {
		if (optind == argc)
			die("No images given, try -h for help");

		for (; optind < argc; ++optind)
			image_load(argv[optind]);

		tim = image_find(TIMH_ID);
		if (no_u_boot) {
			tim_remove_image(tim, name2id("OBMI"));
			tim_rehash(tim);
		}
		tim_parse(tim, &nimages);
		tim_hash_obmi(hash_u_boot);
	}


	if (pin) {
		u64 pinnum = strtoull(pin, NULL, 16);

		tim_add_pin(tim, pinnum);
		printf("Added pin %016llx\n", pinnum);
	}

	if (tty)
		tim_set_boot(tim, BOOTFS_UART);
	else if (output)
		tim_set_boot(tim, BOOTFS_SPINOR);

	if (sign) {
		EC_KEY *key = load_key(keyfile);
		tim_sign(tim, key);
	} else {
		tim_rehash(tim);
	}

	if (tty) {
		int i;

		openwtp(tty);

		for (i = 0; i < nimages; ++i) {
			u32 imgtype;
			image_t *img;

			imgtype = selectimage();
			img = image_find(imgtype);

			printf("Sending image type %s\n", id2name(imgtype));
			sendimage(img, i == nimages - 1);

			if (otp_read || otp_write) {
				uart_otp_read();
				break;
			}
		}

		closewtp();
	}

	if (output) {
		save_flash_image(tim, output);
		printf("Saved to image %s\n\n", output);
	}

	exit(EXIT_SUCCESS);
}

