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
#include <term.h>
#include "tim.h"
#include "utils.h"
#include "wtptp.h"
#include "sharand.h"
#include "key.h"
#include "images.h"

#include "wtmi.c"

#define MOX_TIMN_OFFSET		0x1000
#define MOX_WTMI_OFFSET		0x4000
#define MOX_U_BOOT_OFFSET	0x20000
#define MOX_ENV_OFFSET		0x180000

static int gpp_disassemble;
int terminal_on_exit = 0;

struct mox_builder_data {
	u32 op;
	u32 serial_number_low;
	u32 serial_number_high;
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

static void do_create_trusted_image(const char *keyfile, const char *output,
				    u32 bootfs, u32 partition)
{
	EC_KEY *key;
	image_t *timh, *timn, *wtmi, *obmi;
	void *buf;
	ssize_t wr;
	int fd;
	u32 timh_loadaddr, timn_loadaddr;

	if (bootfs == BOOTFS_SPINOR || bootfs == BOOTFS_EMMC) {
		timh_loadaddr = 0x20006000;
		timn_loadaddr = 0x20003000;
	} else if (bootfs == BOOTFS_UART) {
		timh_loadaddr = 0x20002000;
		timn_loadaddr = 0x20006000;
	} else {
		die("Only UART/SPI/EMMC modes are supported");
	}

	wtmi = image_find(name2id("WTMI"));
	obmi = image_new(NULL, 0, name2id("OBMI"));
	obmi->size = MOX_ENV_OFFSET - MOX_U_BOOT_OFFSET;

	buf = xmalloc(MOX_U_BOOT_OFFSET);
	memset(buf, 0, MOX_U_BOOT_OFFSET);

	key = load_key(keyfile);

	timh = image_new(NULL, 0, TIMH_ID);
	tim_minimal_image(timh, 1, TIMH_ID, 0);
	tim_set_boot(timh, bootfs);
	tim_imap_pkg_addr_set(timh, name2id("CSKT"), MOX_TIMN_OFFSET, partition);
	tim_image_set_loadaddr(timh, TIMH_ID, timh_loadaddr);
	tim_add_key(timh, name2id("CSK0"), key);
	tim_sign(timh, key);
	tim_parse(timh, NULL, gpp_disassemble, NULL);

	memcpy(buf, timh->data, timh->size);

	timn = image_new(NULL, 0, TIMN_ID);
	tim_minimal_image(timn, 1, TIMN_ID, bootfs == BOOTFS_UART);
	tim_set_boot(timn, bootfs);
	tim_image_set_loadaddr(timh, TIMN_ID, timn_loadaddr);
	tim_add_image(timn, wtmi, TIMN_ID, 0x1fff0000, MOX_WTMI_OFFSET, partition, 1);
	tim_add_image(timn, obmi, name2id("WTMI"), 0x64100000, MOX_U_BOOT_OFFSET,
		      partition, 0);
	tim_sign(timn, key);
	tim_parse(timn, NULL, gpp_disassemble, NULL);

	memcpy(buf + MOX_TIMN_OFFSET, timn->data, timn->size);
	memcpy(buf + MOX_WTMI_OFFSET, wtmi->data, wtmi->size);

	fd = open(output, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("Cannot open %s for writing: %m", output);

	if (ftruncate(fd, 0) < 0)
		die("Cannot truncate %s to size 0: %m", output);

	wr = write(fd, buf, MOX_U_BOOT_OFFSET);
	if (wr < 0)
		die("Cannot write to %s: %m", output);
	else if (wr < MOX_U_BOOT_OFFSET)
		die("Cannot write whole output %s", output);

	close(fd);
}

static void do_create_untrusted_image(const char *output, u32 bootfs,
				      u32 partition)
{
	image_t *timh, *wtmi, *obmi;
	void *buf;
	ssize_t wr;
	int fd;

	wtmi = image_find(name2id("WTMI"));
	obmi = image_new(NULL, 0, name2id("OBMI"));
	obmi->size = MOX_ENV_OFFSET - MOX_U_BOOT_OFFSET;

	buf = xmalloc(MOX_U_BOOT_OFFSET);
	memset(buf, 0, MOX_U_BOOT_OFFSET);

	timh = image_new(NULL, 0, TIMH_ID);
	tim_minimal_image(timh, 0, TIMH_ID, 0);
	tim_add_image(timh, wtmi, TIMH_ID, 0x1fff0000, MOX_WTMI_OFFSET, partition, 1);
	tim_add_image(timh, obmi, name2id("WTMI"), 0x64100000, MOX_U_BOOT_OFFSET,
		      partition, 0);
	tim_set_boot(timh, bootfs);
	tim_rehash(timh);
	tim_parse(timh, NULL, gpp_disassemble, NULL);

	memcpy(buf, timh->data, timh->size);
	memcpy(buf + MOX_WTMI_OFFSET, wtmi->data, wtmi->size);

	fd = open(output, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("Cannot open %s for writing: %m", output);

	if (ftruncate(fd, 0) < 0)
		die("Cannot truncate %s to size 0: %m", output);

	wr = write(fd, buf, MOX_U_BOOT_OFFSET);
	if (wr < 0)
		die("Cannot write to %s: %m", output);
	else if (wr < MOX_U_BOOT_OFFSET)
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

struct mox_builder_data *find_mbd(void)
{
	struct mox_builder_data needle = {
		0x05050505, htole32(0xdeaddead), 0,
		htole32(0xdeadbeef), htole32(0xbeefdead), 0xb7b7b7b7,
		{ 0, 0, 0, 0, 0, 0, 0, 0 },
	};
	void *h, *n, *r;

	h = wtmi_data;
	n = &needle;
	r = memmem(h, wtmi_data_size, n, sizeof(needle));
	if (!r)
		die("Cannot find MBD structure in WTMI image");

	return r;
}

static void do_get_otp_hash(u32 *hash)
{
	image_t *tim;

	tim = image_find(TIMH_ID);
	/* check if the TIM is correct by parsing it */
	tim_parse(tim, NULL, 0, NULL);
	tim_get_otp_hash(tim, hash);
}

static void do_deploy(struct mox_builder_data *mbd, const char *serial_number,
		      const char *mac_address, const char *board,
		      const char *board_version, const char *otp_hash)
{
	u64 mac, sn;
	u32 bv, bt;
	char *end;

	sn = strtoull(serial_number, &end, 16);
	if (*end)
		die("Invalid serial number \"%s\"", serial_number);

	if (!strcmp(board, "MOX"))
		bt = 0;
	else if (!strcmp(board, "RIPE"))
		bt = 2;
	else
		die("Invalid board \"%s\"", board);

	bv = strtoul(board_version, &end, 10);
	if (*end || bv > 0x3f)
		die("Invalid board version \"%s\"", board_version);

	mac = mac2u64(mac_address);

	printf("Deploying device SN %016llX, board version %u, MAC %s\n",
	       sn, bv, mac_address);

	mbd->op = htole32(1);
	mbd->serial_number_low = htole32(sn & 0xffffffff);
	mbd->serial_number_high = htole32(sn >> 32);
	mbd->mac_addr_low = htole32(mac & 0xffffffff);
	mbd->mac_addr_high = htole32(mac >> 32);
	mbd->board_version = htole32((bt << 6) | bv);

	if (otp_hash) {
		/* if OTP hash is given as arg, parse it */

		int i;
		char buf[9], *end;

		if (strlen(otp_hash) != 64)
			die("Invalid OTP hash (wrong length)");

		buf[8] = '\0';
		for (i = 0; i < 8; ++i) {
			memcpy(buf, &otp_hash[8 * i], 8);
			mbd->otp_hash[i] = strtoull(buf, &end, 16);
			if (*end)
				die("Invalid OTP hash (bad character)");
		}
	} else {
		/* else generate from given secure firmware */
		do_get_otp_hash(mbd->otp_hash);
	}
}

static void help(void)
{
	fprintf(stdout,
		"Usage: mox-imager [OPTION]... [IMAGE]...\n\n"
		"  -D, --device=TTY                            upload images via UART to TTY\n"
		"  -b, --baudrate=BAUD                         fast upload mode by switching to baudrate BAUD, if supported by image\n"
		"  -F, --fd=FD                                 TTY file descriptor\n"
		"  -E, --send-escape-sequence                  send escape sequence to force boot from UART\n"
		"  -t, --terminal                              run mini terminal after images are sent\n"
		"  -o, --output=IMAGE                          output SPI NOR flash image to IMAGE\n"
		"  -k, --key=KEY                               read ECDSA-521 private key from file KEY\n"
		"  -r, --random-seed=FILE                      read random seed from file\n"
		"  -R, --otp-read                              read OTP memory\n"
		"  -d, --deploy                                deploy device (write OTP memory)\n"
		"      --serial-number=SN                      serial number to write to OTP memory\n"
		"      --mac-address=MAC                       MAC address to write to OTP memory\n"
		"      --board=MOX/RIPE                        board type to write to OTP memory\n"
		"      --board-version=BV                      board version to write to OTP memory\n"
		"      --otp-hash=HASH                         secure firmware hash as given by --get-otp-hash\n"
		"  -g, --gen-key=KEY                           generate ECDSA-521 private key to file KEY\n"
		"  -s, --sign                                  sign TIM image with ECDSA-521 private key\n"
		"      --create-trusted-image=SPI/UART/EMMC    create secure image for SPI / UART (private key required)\n"
		"      --create-untrusted-image=SPI/UART/EMMC  create untrusted secure image (no private key required)\n"
		"  -S  --disassemble                           disassemble GPP code when parsing TIM\n"
		"      --get-otp-hash                          print OTP hash of given secure firmware image\n"
		"  -u, --hash-a53-firmware                     save A53 firmware (TF-A + U-Boot) image hash to TIM\n"
		"  -n, --no-a53-firmware                       remove A53 firmware (TF-A + U-Boot) image from TIM\n"
		"  -h, --help                                  show this help and exit\n"
		"\n");
	exit(EXIT_SUCCESS);
}

static const struct option long_options[] = {
	{ "device",			required_argument,	0,	'D' },
	{ "baudrate",			required_argument,	0,	'b' },
	{ "fd",				required_argument,	0,	'F' },
	{ "send-escape-sequence",	no_argument,		0,	'E' },
	{ "terminal",			no_argument,		0,	't' },
	{ "output",			required_argument,	0,	'o' },
	{ "key",			required_argument,	0,	'k' },
	{ "random-seed",		required_argument,	0,	'r' },
	{ "otp-read",			no_argument,		0,	'R' },
	{ "deploy",			no_argument,		0,	'd' },
	{ "serial-number",		required_argument,	0,	'N' },
	{ "mac-address",		required_argument,	0,	'M' },
	{ "board",			required_argument,	0,	'Z' },
	{ "board-version",		required_argument,	0,	'B' },
	{ "otp-hash",			required_argument,	0,	'H' },
	{ "gen-key",			required_argument,	0,	'g' },
	{ "sign",			no_argument,		0,	's' },
	{ "create-trusted-image",	required_argument,	0,	'c' },
	{ "create-untrusted-image",	required_argument,	0,	'C' },
	{ "disassemble",		no_argument,		0,	'S' },
	{ "get-otp-hash",		no_argument,		0,	'G' },
	{ "hash-a53-firmware",		no_argument,		0,	'u' },
	{ "no-a53-firmware",		no_argument,		0,	'n' },
	{ "help",			no_argument,		0,	'h' },
	{ 0,				0,			0,	0 },
};

int main(int argc, char **argv)
{
	const char *tty, *fdstr, *output, *keyfile, *seed, *genkey,
		   *serial_number, *mac_address, *board, *board_version,
		   *otp_hash;
	int sign, hash_a53_firmware, no_a53_firmware, otp_read, deploy,
	    get_otp_hash, create_trusted_image, create_untrusted_image,
	    send_escape, baudrate, dummy;
	u32 image_bootfs = 0, partition;
	image_t *timh = NULL, *timn = NULL;
	int nimages, nimages_timn, images_given, trusted;

	tty = fdstr = output = keyfile = seed = genkey = serial_number =
              mac_address = board = board_version = otp_hash = NULL;
	sign = hash_a53_firmware = no_a53_firmware = otp_read = deploy =
	       get_otp_hash = create_trusted_image = create_untrusted_image =
	       send_escape = baudrate = 0;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "D:b:F:Eo:k:r:Rdg:sStunh",
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'D':
			if (tty)
				die("Device already given");
			tty = optarg;
			break;
		case 'b':
			baudrate = atoi(optarg);
			if (baudrate > 6000000)
				die("Desired baudrate too high (maximum is 6 MBaud)");
			break;
		case 'F':
			if (fdstr)
				die("File descriptor already given");
			fdstr = optarg;
			break;
		case 'E':
			send_escape = 1;
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
		case 't':
			/*
			 * Get sequence for backspace key used by the current
			 * terminal. Every occurance of this sequence will be
			 * replaced by '\b' byte which is the only recognized
			 * backspace byte by Marvell BootROM.
			 *
			 * Note that we cannot read this sequence from termios
			 * c_cc[VERASE] as VERASE is valid only when ICANON is
			 * set in termios c_lflag, which is not case for us.
			 *
			 * Also most terminals do not set termios c_cc[VERASE]
			 * as c_cc[VERASE] can specify only one-byte sequence
			 * and instead let applications to read (possible
			 * multi-byte) sequence for backspace key from "kbs"
			 * terminfo database based on $TERM env variable.
			 *
			 * So read "kbs" from terminfo database via tigetstr()
			 * call after successfull setupterm(). Most terminals
			 * use byte 0x7F for backspace key, so replacement with
			 * '\b' is required.
			 */
			if (setupterm(NULL, STDOUT_FILENO, &dummy) == 0) {
				uart_terminal_kbs = tigetstr("kbs");
				if (uart_terminal_kbs == (char *)-1)
					uart_terminal_kbs = NULL;
			}
			terminal_on_exit = 1;
			break;
		case 'N':
			if (serial_number)
				die("Serial number already given");
			serial_number = optarg;
			break;
		case 'M':
			if (mac_address)
				die("Mac address already given");
			mac_address = optarg;
			break;
		case 'Z':
			if (board)
				die("Board already given");
			board = optarg;
			break;
		case 'B':
			if (board_version)
				die("Board version already given");
			board_version = optarg;
			break;
		case 'H':
			if (otp_hash)
				die("OTP hash already given");
			otp_hash = optarg;
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
		case 'C':
			if (!strcmp(optarg, "UART"))
				image_bootfs = BOOTFS_UART;
			else if (!strcmp(optarg, "SPI"))
				image_bootfs = BOOTFS_SPINOR;
			else if (!strcmp(optarg, "EMMC"))
				image_bootfs = BOOTFS_EMMC;
			else
				die("Invalid argument for parameter --create-[un]trusted-image");
			if (c == 'c')
				create_trusted_image = 1;
			else
				create_untrusted_image = 1;
			break;
		case 'S':
			gpp_disassemble = 1;
			break;
		case 'G':
			get_otp_hash = 1;
			break;
		case 'u':
			hash_a53_firmware = 1;
			break;
		case 'n':
			no_a53_firmware = 1;
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

	if (create_trusted_image && (!keyfile || !output))
		die("Options --key and --output must be given when creating trusted image");

	if (create_untrusted_image && !output)
		die("Option --output must be given when creating untrusted image");

	if ((tty || fdstr) && output)
		die("Options --device and --output cannot be used together");

	if (sign && !keyfile)
		die("Option --key must be given when signing");

	if ((otp_read || deploy) && !tty && !fdstr)
		die("Option --device must be specified when reading/writing OTP");

	if (otp_read && deploy)
		die("Options to read OTP and deploy cannot be used together");

	if (deploy && (!serial_number || !mac_address || !board || !board_version))
		die("Serial number, MAC address, board and board version must be given when deploying device");

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

	if (image_bootfs == BOOTFS_EMMC)
		/* Boot partition on eMMC is partition 2 */
		partition = 2;
	else
		partition = 0;

	if (create_trusted_image) {
		do_create_trusted_image(keyfile, output, image_bootfs, partition);
		exit(EXIT_SUCCESS);
	} else if (create_untrusted_image) {
		do_create_untrusted_image(output, image_bootfs, partition);
		exit(EXIT_SUCCESS);
	}

	if (!otp_read && !deploy && !images_given && !terminal_on_exit)
		die("No images given, try -h for help");

	if (otp_read || deploy) {
		struct mox_builder_data *mbd;
		image_t *wtmi;

		if (otp_read && images_given)
			die("Images given when trying to read/write OTP");

		mbd = find_mbd();

		if (deploy)
			do_deploy(mbd, serial_number, mac_address, board, board_version, otp_hash);
		else
			mbd->op = 0;

		image_delete_all();

		timh = image_new(NULL, 0, TIMH_ID);
		tim_minimal_image(timh, 0, TIMH_ID, 1);
		wtmi = image_new((void *) wtmi_data, wtmi_data_size, WTMI_ID);
		tim_add_image(timh, wtmi, TIMH_ID, 0x1fff0000, 0, 0, 1);
		tim_rehash(timh);
		nimages = 2;
		trusted = 0;
		images_given = 1;
	} else if (images_given) {
		int has_fast_mode;

		if (get_otp_hash) {
			u32 hash[8];
			int i;

			do_get_otp_hash(hash);
			printf("Secure firmware OTP hash: ");
			for (i = 0; i < 8; ++i)
				printf("%08x", hash[i]);
			printf("\n");
			exit(EXIT_SUCCESS);
		}

		timh = image_find(TIMH_ID);
		if (tim_imap_pkg_addr(timh, name2id("CSKT")) != -1U)
			timn = image_find(TIMN_ID);

		trusted = tim_is_trusted(timh);

		if (no_a53_firmware) {
			if (trusted)
				die("Cannot modify trusted image!");
			tim_remove_image(timh, name2id("OBMI"));
			tim_rehash(timh);
		}

		tim_parse(timh, &nimages, gpp_disassemble,
			  &has_fast_mode);
		if (timn)
			tim_parse(timn, &nimages_timn, gpp_disassemble,
				  &has_fast_mode);

		if (baudrate && !has_fast_mode) {
			if (trusted)
				die("Fast upload mode not supported by this image\n"
				    "and cannot inject the code into trusted image!");
			tim_inject_baudrate_change_support(timn ? : timh);
		}

		if (!trusted)
			tim_enable_hash(timh, OBMI_ID, hash_a53_firmware);
	} else {
		nimages_timn = 0;
		nimages = 0;
		trusted = 0;
	}

	if (images_given && !trusted) {
		if (tty || fdstr)
			tim_set_boot(timh, BOOTFS_UART);
		else if (output)
			tim_set_boot(timh, BOOTFS_SPINOR);

		if (sign) {
			EC_KEY *key = load_key(keyfile);
			tim_sign(timh, key);
			if (timn)
				tim_sign(timn, key);
		} else {
			tim_rehash(timh);
			if (timn)
				tim_rehash(timn);
		}
	}

	if (tty || fdstr) {
		int i, nimages_all;

		if (fdstr)
			setwtpfd(fdstr);
		else
			openwtp(tty);

		nimages_all = nimages;
		if (timn)
			nimages_all += nimages_timn;

		if (nimages_all || send_escape)
			initwtp(send_escape);

		for (i = 0; i < nimages_all; ++i) {
			u32 imgtype;
			image_t *img;

			imgtype = selectimage();
			img = image_find(imgtype);

			printf("Sending image type %s\n", id2name(imgtype));
			sendimage(img, i == nimages_all - 1);

			if (baudrate && img->id == (timn ? TIMN_ID : TIMH_ID))
				try_change_baudrate(baudrate);
		}

		if (baudrate && nimages_all)
			change_baudrate(115200);
		else if (baudrate)
			change_baudrate(baudrate);

		if (otp_read)
			uart_otp_read();
		else if (deploy)
			uart_deploy();

		if (terminal_on_exit)
			uart_terminal();

		closewtp();
	}

	if (output) {
		if (timn)
			die("TIMH + TIMN image saving not supported!");
		save_flash_image(timh, output);
		printf("Saved to image %s\n\n", output);
	}

	exit(EXIT_SUCCESS);
}

