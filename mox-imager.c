// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#define _GNU_SOURCE
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

#include "wtmi.c"

struct mox_builder_data {
	u32 op;
	u32 serial_number;
	u32 manufacturing_time;
	u32 mac_addr_low;
	u32 mac_addr_high;
	u32 board_version;
	u32 otp_hash[8];
};

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
		die("Cannot truncate %s to size %u: %m", path, maxaddr);

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

static void do_create_secure_image(const char *keyfile, const char *output)
{
	EC_KEY *key;
	image_t *timh, *timn, *wtmi, *obmi;
	void *buf;
	ssize_t wr;
	int fd;

	wtmi = image_find(name2id("WTMI"));
	obmi = image_new(NULL, 0, name2id("OBMI"));
	obmi->size = (2 << 20) - 0x15000 - 0x10000;

	buf = xmalloc(0x15000);
	memset(buf, 0, 0x15000);

	key = load_key(keyfile);

	timh = image_new(NULL, 0, TIMH_ID);
	tim_minimal_image(timh, 1);
	tim_add_key(timh, name2id("CSK0"), key);
	tim_sign(timh, key);
	tim_parse(timh, NULL);

	memcpy(buf, timh->data, timh->size);

	timn = image_new(NULL, 0, TIMN_ID);
	tim_minimal_image(timn, 2);
	tim_add_image(timn, wtmi, TIMN_ID, 0x1fff0000, 0x4000, 1);
	tim_add_image(timn, obmi, name2id("WTMI"), 0x64100000, 0x15000, 0);
	tim_sign(timn, key);
	tim_parse(timn, NULL);

	memcpy(buf + 0x1000, timn->data, timn->size);
	memcpy(buf + 0x4000, wtmi->data, wtmi->size);

	fd = open(output, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("Cannot open %s for writing: %m", output);

	if (ftruncate(fd, 0) < 0)
		die("Cannot truncate %s to size 0: %m", output);

	wr = write(fd, buf, 0x15000);
	if (wr < 0)
		die("Cannot write to %s: %m", output);
	else if (wr < 0x15000)
		die("Cannot write whole output %s", output);

	close(fd);
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

struct mox_builder_data *find_mbd(void) {
	struct mox_builder_data needle = {
		0x05050505, htole32(0xdeaddead), 0,
		htole32(0xdeadbeef), htole32(0xbeefdead), 0xb7b7b7b7,
		0, 0, 0, 0, 0, 0, 0, 0
	};
	void *h, *n, *r;

	h = wtmi_data;
	n = &needle;
	r = memmem(h, wtmi_data_size, n, sizeof(needle));
	if (!r)
		die("Cannot find MBD structure in WTMI image");

	return r;
}

static void do_deploy(struct mox_builder_data *mbd, const char *serial_number,
		      const char *mac_address, const char *board_version)
{
	image_t *tim;
	u64 mac;
	u32 sn, bv;
	char *end;

	sn = strtoul(serial_number, &end, 16);
	if (*end)
		die("Invalid serial number \"%s\"", serial_number);

	bv = strtoul(board_version, &end, 10);
	if (*end || bv > 0xff)
		die("Invalid board version \"%s\"", board_version);

	mac = mac2u64(mac_address);

	printf("Deploying device SN %08X, board version %u, MAC %s\n",
	       sn, bv, mac_address);

	mbd->op = htole32(1);
	mbd->serial_number = htole32(sn);
	mbd->manufacturing_time = htole32(time(NULL));
	mbd->mac_addr_low = htole32(mac & 0xffffffff);
	mbd->mac_addr_high = htole32(mac >> 32);
	mbd->board_version = htole32(bv);

	tim = image_find(TIMH_ID);
	tim_get_otp_hash(tim, mbd->otp_hash);
}

static void help(void)
{
	fprintf(stdout,
		"Usage: mox-imager [OPTION]... [IMAGE]...\n\n"
		"  -D, --device=TTY           upload images via UART to TTY\n"
		"  -o, --output=IMAGE         output SPI NOR flash image to IMAGE\n"
		"  -k, --key=KEY              read ECDSA-521 private key from file KEY\n"
		"  -r, --random-seed=FILE     read random seed from file\n"
		"  -R, --otp-read             read OTP memory\n"
		"  -d, --deploy               deploy device (write OTP memory)\n"
		"      --serial-number=SN     serial number to write to OTP memory\n"
		"      --mac-address=MAC      MAC address to write to OTP memory\n"
		"      --board-version=BV     board version to write to OTP memory\n"
		"  -g, --gen-key=KEY          generate ECDSA-521 private key to file KEY\n"
		"  -s, --sign                 sign TIM image with ECDSA-521 private key\n"
		"      --create-secure-image  create secure image\n"
		"  -u, --hash-u-boot          save OBMI (U-Boot) image hash to TIM\n"
		"  -n, --no-u-boot            remove OBMI (U-Boot) image from TIM\n"
		"  -h, --help                 show this help and exit\n"
		"\n");
	exit(EXIT_SUCCESS);
}

static const struct option long_options[] = {
	{ "device",		required_argument,	0,	'D' },
	{ "output",		required_argument,	0,	'o' },
	{ "key",		required_argument,	0,	'k' },
	{ "random-seed",	required_argument,	0,	'r' },
	{ "otp-read",		no_argument,		0,	'R' },
	{ "deploy",		no_argument,		0,	'd' },
	{ "serial-number",	required_argument,	0,	'S' },
	{ "mac-address",	required_argument,	0,	'M' },
	{ "board-version",	required_argument,	0,	'B' },
	{ "gen-key",		required_argument,	0,	'g' },
	{ "sign",		no_argument,		0,	's' },
	{ "create-secure-image",no_argument,		0,	'c' },
	{ "hash-u-boot",	no_argument,		0,	'u' },
	{ "no-u-boot",		no_argument,		0,	'n' },
	{ "help",		no_argument,		0,	'h' },
	{ 0,			0,			0,	0 },
};

int main(int argc, char **argv)
{
	const char *tty, *output, *keyfile, *seed, *genkey,
		   *serial_number, *mac_address, *board_version;
	int sign, hash_u_boot, no_u_boot, otp_read, deploy, create_secure_image;
	image_t *tim;
	int nimages, images_given;

	tty = output = keyfile = seed = genkey = serial_number =
              mac_address = board_version = NULL;
	sign = hash_u_boot = no_u_boot = otp_read = deploy =
	     create_secure_image = 0;

	while (1) {
		int optidx;
		char c;

		c = getopt_long(argc, argv, "D:o:k:r:Rdg:sunh", long_options,
				NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'D':
			if (tty)
				die("Device already given");
			tty = optarg;
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
		case 'd':
			deploy = 1;
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
		case 'c':
			create_secure_image = 1;
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

	if (create_secure_image && (!keyfile || !output))
		die("Options --key and --output must be given when creating secure image");

	if (tty && output)
		die("Options --device and --output cannot be used together");

	if (sign && !keyfile)
		die("Option --key must be given when signing");

	if ((otp_read || deploy) && !tty)
		die("Option --device must be specified when reading/writing OTP");

	if (otp_read && deploy)
		die("Options to read OTP and deploy cannot be used together");

	if (deploy && (!serial_number || !mac_address || !board_version))
		die("Serial number, MAC address and board version must be given when deploying device");

	if (genkey) {
		if (!seed)
			die("Random seed file must be given when generating key");
		else if (optind < argc)
			die("Images must not be given when generating key");

		generate_key(genkey, seed);
		exit(EXIT_SUCCESS);
	}

	images_given = argc - optind;

	for (; optind < argc; ++optind)
		image_load(argv[optind]);

	if (create_secure_image) {
		do_create_secure_image(keyfile, output);
		exit(EXIT_SUCCESS);
	}

	if (otp_read || deploy) {
		struct mox_builder_data *mbd;
		image_t *wtmi;

		if (otp_read && images_given)
			die("Images given when trying to read/write OTP");

		mbd = find_mbd();

		if (deploy)
			do_deploy(mbd, serial_number, mac_address, board_version);
		else
			mbd->op = 0;

		image_delete_all();

		tim = image_new(NULL, 0, TIMH_ID);
		tim_minimal_image(tim, 0);
		wtmi = image_new((void *) wtmi_data, wtmi_data_size, WTMI_ID);
		tim_add_image(tim, wtmi, TIMH_ID, 0x1fff0000, 0, 1);
		tim_rehash(tim);
		nimages = 2;
	} else {
		if (!images_given)
			die("No images given, try -h for help");

		tim = image_find(TIMH_ID);
		if (no_u_boot) {
			tim_remove_image(tim, name2id("OBMI"));
			tim_rehash(tim);
		}
		tim_parse(tim, &nimages);
		tim_enable_hash(tim, OBMI_ID, hash_u_boot);
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
		}

		if (otp_read)
			uart_otp_read();
		else if (deploy)
			uart_deploy();

		closewtp();
	}

	if (output) {
		save_flash_image(tim, output);
		printf("Saved to image %s\n\n", output);
	}

	exit(EXIT_SUCCESS);
}

