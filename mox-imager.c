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
#include "mox-imager.h"

static const args_t def_args = {
	.timn_offset = 0x1000,
	.wtmi_offset = 0x4000,
	.obmi_offset = 0x20000,
	.obmi_max_size = 0x160000,
	.max_restarts = -1,
};

args_t args = def_args;

struct mox_builder_data {
	u32 op;
	u32 serial_number_low;
	u32 serial_number_high;
	u32 mac_addr_low;
	u32 mac_addr_high;
	u32 board_version;
	u32 otp_hash[8];
};

static void seed_from_file(const char *seedpath)
{
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
}

static void seed_from_getrandom(void)
{
	char seed[128];

	xgetrandom(seed, sizeof(seed));
	sharand_seed("Turris Mox", 10, seed, sizeof(seed));
}

static void generate_key(const char *keypath, const char *seedpath)
{
	EC_KEY *key;

	if (seedpath)
		seed_from_file(seedpath);
	else
		seed_from_getrandom();

	key = sharand_generate_key();
	if (keypath)
		save_key(keypath, key);
	else
		printf("%s\n", priv_key_to_str(key));
	EC_KEY_free(key);
}

static int open_and_truncate(const char *path, u32 size)
{
	int fd;

	fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("Cannot open %s for writing: %m", path);

	if (ftruncate(fd, size) < 0)
		die("Cannot truncate %s to size %u: %m", path, size);

	return fd;
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

	fd = open_and_truncate(path, maxaddr);

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

static void write_or_die(const char *path, int fd, const void *buf, size_t count)
{
	ssize_t wr = write(fd, buf, count);

	if (wr < 0)
		die("Cannot write to %s: %m", path);
	else if (wr < count)
		die("Cannot write whole output %s", path);
}

static image_t *obmi_for_creation(int needs_obmi, int hash_obmi)
{
	image_t *obmi;

	if (hash_obmi || image_exists(OBMI_ID)) {
		obmi = image_find(OBMI_ID);
	} else if (needs_obmi) {
		obmi = image_new(NULL, 0, OBMI_ID);
		obmi->size = args.obmi_max_size;
	} else {
		obmi = NULL;
	}

	return obmi;
}

static void loadaddrs_for_bootfs(u32 bootfs,
				 u32 *timh_loadaddr, u32 *timn_loadaddr)
{
	if (bootfs == BOOTFS_SPINOR || bootfs == BOOTFS_EMMC) {
		*timh_loadaddr = 0x20006000;
		*timn_loadaddr = 0x20003000;
	} else if (bootfs == BOOTFS_UART) {
		*timh_loadaddr = 0x20002000;
		*timn_loadaddr = 0x20006000;
	} else {
		die("Only UART/SPI/EMMC modes are supported");
	}
}

static image_t *timh_create_for_trusted(EC_KEY *key, u32 loadaddr,
					u32 bootfs, u32 partition)
{
	image_t *timh;

	timh = image_new(NULL, 0, TIMH_ID);
	tim_minimal_image(timh, 1, TIMH_ID, 0);
	tim_set_boot(timh, bootfs);
	tim_imap_pkg_addr_set(timh, name2id("CSKT"), args.timn_offset, partition);
	tim_image_set_loadaddr(timh, TIMH_ID, loadaddr);
	tim_add_key(timh, name2id("CSK0"), key);
	tim_sign(timh, key);

	return timh;
}

static void write_image(const char *output,
			image_t *timh, image_t *timn,
			image_t *wtmi, image_t *obmi)
{
	void *buf;
	u32 size;
	int fd;

	size = args.obmi_offset;
	buf = xmalloc(size);
	memset(buf, 0, size);

	memcpy(buf, timh->data, timh->size);
	if (timn)
		memcpy(buf + args.timn_offset, timn->data, timn->size);
	memcpy(buf + args.wtmi_offset, wtmi->data, wtmi->size);

	fd = open_and_truncate(output, 0);

	write_or_die(output, fd, buf, size);
	if (obmi && obmi->data)
		write_or_die(output, fd, obmi->data, obmi->size);

	close(fd);
}

static void do_sign_untrusted_image(const char *keyfile, const char *output,
				    u32 bootfs, u32 partition, int hash_obmi)
{
	image_t *timh, *timn, *wtmi, *obmi = NULL;
	u32 timh_loadaddr, timn_loadaddr;
	EC_KEY *key;

	loadaddrs_for_bootfs(bootfs, &timh_loadaddr, &timn_loadaddr);

	key = load_key(keyfile);

	if (image_exists(TIMN_ID))
		die("TIMN image is present withing given firmware, cannot sign");

	timh = image_find(TIMH_ID);
	if (tim_is_trusted(timh))
		die("Given image is already trusted, cannot sign");

	if (bootfs == BOOTFS_UART) {
		int has_fast_mode;

		tim_parse(timh, 0, &has_fast_mode, NULL);

		if (!has_fast_mode)
			tim_inject_baudrate_change_support(timh);
	}

	wtmi = image_find(WTMI_ID);
	if (image_exists(OBMI_ID))
		obmi = image_find(OBMI_ID);

	tim_set_id(timh, TIMN_ID);
	timn = timh;

	timh = timh_create_for_trusted(key, timh_loadaddr, bootfs, partition);
	tim_parse(timh, args.gpp_disassemble, NULL, output ? stdout : NULL);

	tim_set_boot(timn, bootfs);
	tim_image_set_loadaddr(timn, TIMN_ID, timn_loadaddr);
	tim_image_set_flashaddr(timn, TIMN_ID, args.timn_offset, partition);
	tim_enable_hash(timn, TIMN_ID, 1);
	tim_image_set_flashaddr(timn, WTMI_ID, args.wtmi_offset, partition);
	tim_enable_hash(timn, WTMI_ID, 1);
	if (obmi) {
		tim_image_set_flashaddr(timn, OBMI_ID, args.obmi_offset, partition);
		tim_enable_hash(timn, OBMI_ID, hash_obmi);
	}
	tim_sign(timn, key);
	tim_parse(timn, args.gpp_disassemble, NULL, output ? stdout : NULL);

	if (output)
		write_image(output, timh, timn, wtmi, obmi);
}

static void do_create_trusted_image(const char *keyfile, const char *output,
				    u32 bootfs, u32 partition, int needs_obmi,
				    int hash_obmi)
{
	EC_KEY *key;
	image_t *timh, *timn, *wtmi, *obmi;
	u32 timh_loadaddr, timn_loadaddr;

	loadaddrs_for_bootfs(bootfs, &timh_loadaddr, &timn_loadaddr);

	wtmi = image_find(name2id("WTMI"));
	obmi = obmi_for_creation(needs_obmi, hash_obmi);

	key = load_key(keyfile);

	timh = timh_create_for_trusted(key, timh_loadaddr, bootfs, partition);
	tim_parse(timh, args.gpp_disassemble, NULL, output ? stdout : NULL);

	timn = image_new(NULL, 0, TIMN_ID);
	tim_minimal_image(timn, 1, TIMN_ID, bootfs == BOOTFS_UART);
	tim_set_boot(timn, bootfs);
	tim_image_set_loadaddr(timn, TIMN_ID, timn_loadaddr);
	tim_add_image(timn, wtmi, TIMN_ID, 0x1fff0000, args.wtmi_offset, partition, 1);

	if (obmi)
		tim_add_image(timn, obmi, name2id("WTMI"), 0x64100000, args.obmi_offset,
			      partition, hash_obmi);

	tim_sign(timn, key);
	tim_parse(timn, args.gpp_disassemble, NULL, output ? stdout : NULL);

	if (output)
		write_image(output, timh, timn, wtmi, obmi);
}

static void do_create_untrusted_image(const char *output, u32 bootfs,
				      u32 partition, int needs_obmi, int hash_obmi)
{
	image_t *timh, *wtmi, *obmi;

	wtmi = image_find(name2id("WTMI"));
	obmi = obmi_for_creation(needs_obmi, hash_obmi);

	timh = image_new(NULL, 0, TIMH_ID);
	tim_minimal_image(timh, 0, TIMH_ID, bootfs == BOOTFS_UART);
	tim_add_image(timh, wtmi, TIMH_ID, 0x1fff0000, args.wtmi_offset, partition, 1);

	if (obmi)
		tim_add_image(timh, obmi, name2id("WTMI"), 0x64100000, args.obmi_offset,
			      partition, hash_obmi);

	tim_set_boot(timh, bootfs);
	tim_rehash(timh);
	tim_parse(timh, args.gpp_disassemble, NULL, output ? stdout : NULL);

	if (output)
		write_image(output, timh, NULL, wtmi, obmi);
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

#include "bundled-wtmi.c"

static struct mox_builder_data *find_mbd(void)
{
	struct mox_builder_data needle = {
		0x05050505, htole32(0xdeaddead), 0,
		htole32(0xdeadbeef), htole32(0xbeefdead), 0xb7b7b7b7,
		{ 0, 0, 0, 0, 0, 0, 0, 0 },
	};
	void *h, *n, *r;

	h = bundled_wtmi_data;
	n = &needle;
	r = memmem(h, bundled_wtmi_data_size, n, sizeof(needle));
	if (!r)
		die("Cannot find MBD structure in WTMI image");

	return r;
}

static void do_get_otp_hash(u32 *hash)
{
	image_t *tim;

	tim = image_find(TIMH_ID);
	/* check if the TIM is correct by parsing it */
	tim_parse(tim, 0, NULL, NULL);
	tim_get_otp_hash(tim, hash);
}

static void parse_otp_hash(struct mox_builder_data *mbd, const char *otp_hash)
{
	char *end, buf[9];
	int i;

	if (!strcmp(otp_hash, "0")) {
		memset(mbd->otp_hash, 0, sizeof(mbd->otp_hash));
		return;
	}

	if (strlen(otp_hash) != 64)
		die("Invalid OTP hash (wrong length)");

	buf[8] = '\0';
	for (i = 0; i < 8; ++i) {
		memcpy(buf, &otp_hash[8 * i], 8);
		mbd->otp_hash[i] = strtoull(buf, &end, 16);
		if (*end)
			die("Invalid OTP hash (bad character)");
	}
}

static void prepare_deploy(struct mox_builder_data *mbd, const args_t *args)
{
	u64 mac, sn;
	u32 bv, bt;
	char *end;

	sn = strtoull(args->serial_number, &end, 16);
	if (*end)
		die("Invalid serial number \"%s\"", args->serial_number);

	if (!strcmp(args->board, "MOX"))
		bt = 0;
	else if (!strcmp(args->board, "RIPE"))
		bt = 2;
	else
		die("Invalid board \"%s\"", args->board);

	bv = strtoul(args->board_version, &end, 10);
	if (*end || bv > 0x3f)
		die("Invalid board version \"%s\"", args->board_version);

	mac = mac2u64(args->mac_address);

	info("Deploying device SN %016llX, board version %u, MAC %s\n",
	     sn, bv, args->mac_address);

	mbd->op = htole32(1);
	mbd->serial_number_low = htole32(sn & 0xffffffff);
	mbd->serial_number_high = htole32(sn >> 32);
	mbd->mac_addr_low = htole32(mac & 0xffffffff);
	mbd->mac_addr_high = htole32(mac >> 32);
	mbd->board_version = htole32((bt << 6) | bv);

	parse_otp_hash(mbd, args->otp_hash);
}

static void prepare_deploy_no_board_info(struct mox_builder_data *mbd,
					 const args_t *args)
{
	mbd->op = htole32(2);
	mbd->serial_number_low = 0;
	mbd->serial_number_high = 0;
	mbd->mac_addr_low = 0;
	mbd->mac_addr_high = 0;
	mbd->board_version = 0;

	parse_otp_hash(mbd, args->otp_hash);
}

static void create_image_from_bundled_wtmi(const args_t *args)
{
	image_new((void *)bundled_wtmi_data, bundled_wtmi_data_size, WTMI_ID);

	if (args->sign)
		do_create_trusted_image(args->keyfile, NULL, BOOTFS_UART, 0, 0, args->hash_a53_firmware);
	else
		do_create_untrusted_image(NULL, BOOTFS_UART, 0, 0, args->hash_a53_firmware);
}

static void create_deploy_image(const args_t *args)
{
	struct mox_builder_data *mbd;

	if (image_exists(TIMH_ID) || image_exists(TIMN_ID) || image_exists(WTMI_ID))
		die("TIMH/TIMN/WTMI image should not be given when deploying");

	mbd = find_mbd();

	if (args->deploy_no_board_info)
		prepare_deploy_no_board_info(mbd, args);
	else
		prepare_deploy(mbd, args);

	if (image_exists(OBMI_ID))
		/* tell WTMI deploy() to not reset the SoC after deployment */
		mbd->op = htole32(le32toh(mbd->op) | (1 << 31));

	create_image_from_bundled_wtmi(args);
}

static int get_nimages_to_send(void)
{
	int nimages = 0;
	image_t *tim;

	if (image_exists(TIMH_ID)) {
		tim = image_find(TIMH_ID);
		nimages = tim_nimages((const timhdr_t *)tim->data);

		if (image_exists(TIMN_ID)) {
			tim = image_find(TIMN_ID);
			nimages += tim_nimages((const timhdr_t *)tim->data);
		}
	}

	return nimages;
}

static void do_uart(const args_t *args)
{
	_Bool has_timn = image_exists(TIMN_ID);
	int nimages, i;

	nimages = get_nimages_to_send();

	if (nimages)
		info("Going to send images to the device\n");

	if (args->fdstr)
		setwtpfd(args->fdstr);
	else
		openwtp(args->tty);

	if (nimages || args->send_escape)
		initwtp(args->send_escape, args->max_restarts);

	for (i = 0; i < nimages; ++i) {
		u32 imgtype;
		image_t *img;

		imgtype = selectimage();
		img = image_find(imgtype);

		info("Sending image type %s\n", id2name(imgtype));
		sendimage(img, i == nimages - 1, args);

		if (args->baudrate && img->id == (has_timn ? TIMN_ID : TIMH_ID))
			try_change_baudrate(args->baudrate);
	}

	if (args->baudrate && nimages)
		change_baudrate(115200);
	else if (args->baudrate)
		change_baudrate(args->baudrate);

	if (args->otp_read)
		uart_otp_read();
	else if (args->deploy)
		uart_deploy(args->deploy_no_board_info);

	if (args->terminal_on_exit)
		uart_terminal();

	closewtp();
}

static void load_bundled_otp_read_image(const char *otp_read)
{
	if (!strcmp(otp_read, "testing")) {
#include "bundled-read-otp-testing.c"
		image_load_bundled(bundled_read_otp_data, bundled_read_otp_data_size);
	} else if (!strcmp(otp_read, "RAD")) {
#include "bundled-read-otp-rad.c"
		image_load_bundled(bundled_read_otp_data, bundled_read_otp_data_size);
	} else {
		die("Invalid value for option --otp-read. Supported values: \"testing\", \"RAD\" and \"auto\"");
	}
}

static void create_otp_read_image(const args_t *args)
{
	find_mbd()->op = 0;

	create_image_from_bundled_wtmi(args);
}

static void _do_otp_read(void *arg)
{
	const args_t *args = arg;

	if (!strcmp(args->otp_read, ""))
		create_otp_read_image(args);
	else
		load_bundled_otp_read_image(args->otp_read);

	do_uart(args);
}

static __attribute__((__noreturn__)) void do_otp_read(const args_t *args)
{
	static const char * const vendors[3] = { "", "RAD", "testing" };
	args_t new_args;

	/* if VENDIR in --otp-read=VENDOR is not "auto", just call it */
	if (strcmp(args->otp_read, "auto")) {
		_do_otp_read((void *)args);
		exit(EXIT_SUCCESS);
	}

	/* otherwise try all vendors */
	new_args = *args;

	for_each_const(vendor, vendors) {
		char fw[64];

		if (!strcmp(*vendor, ""))
			strcpy(fw, "untrusted firmware");
		else
			snprintf(fw, sizeof(fw), "firmware signed by %s vendor key", *vendor);

		info("Trying to read OTP by sending %s\n", fw);

		new_args.otp_read = *vendor;

		if (try_catch(_do_otp_read, &new_args)) {
			info("Failed reading OTP with %s\n\n", fw);
			image_delete_all();
			continue;
		}

		exit(EXIT_SUCCESS);
	}

	die("Could not read OTP, tried firmware for all possible board vendors");
}

static void set_bootfs_if_possible(u32 bootfs)
{
	image_t *timh = image_find(TIMH_ID);

	if (tim_is_trusted(timh))
		return;

	tim_set_boot(timh, bootfs);
}

static void ensure_image_rehash_or_sign_if_possible(int sign, const char *keyfile)
{
	image_t *timh = image_find(TIMH_ID), *timn = NULL;

	if (tim_is_trusted(timh))
		return;

	if (image_exists(TIMN_ID))
		timn = image_find(TIMN_ID);

	if (sign) {
		EC_KEY *key = load_key(keyfile);
		tim_sign(timh, key);
	} else {
		tim_rehash(timh);
		if (timn)
			tim_rehash(timn);
	}
}

static u32 parse_u32_opt(const char *opt, const char *arg, u32 min, u32 max)
{
	unsigned long val;
	char *end;

	if (!arg)
		die("missing argument for option '--%s'", opt);

	val = strtoul(arg, &end, 0);

	if (*arg == '\0' || *end != '\0')
		die("invalid argument '%s' for integer option '--%s'", arg, opt);
	else if (val > max)
		die("value %s of option '--%s' exceeds maximum value %#x", arg, opt, max);
	else if (val < min)
		die("value %s of option '--%s' is below minimum value %#x", arg, opt, min);

	return val;
}

static void help(void)
{
	fprintf(stdout,
		"Usage: mox-imager [OPTION]... [IMAGE]...\n\n"
		"  -D, --device=TTY                            upload images via UART to TTY\n"
		"  -b, --baudrate=BAUD                         fast upload mode by switching to baudrate BAUD, if supported by image\n"
		"  -F, --fd=FD                                 TTY file descriptor\n"
		"  -E, --send-escape-sequence                  send escape sequence to force boot from UART\n"
		"      --max-restarts=N                        when forcing boot from UART, mox-imager can suggest the user to\n"
		"                                              restart the board when the forcing was unsuccessful. This option\n"
		"                                              specifies the maximum number of suggested restarts before aborting.\n"
		"  -t, --terminal                              run mini terminal after images are sent\n"
		"  -o, --output=IMAGE                          output SPI NOR flash image to IMAGE\n"
		"  -k, --key=KEY                               read ECDSA-521 private key from file KEY\n"
		"  -r, --random-seed=FILE                      read random seed from file (for deterministic private key generation)\n\n"
		"  -R, --otp-read[=VENDOR|auto]                read OTP memory (use the optional option VENDOR to read OTP on trusted\n"
		"                                              boards signed with VENDOR's key, or \"auto\" to try all possibilities)\n\n"
		"  -d, --deploy[=no-board-info]                deploy device (write OTP memory).\n"
		"                                              Serial number, MAC address, board type and board version\n"
		"                                              must not be given if the 'no-board-info' parameter is given.\n"
		"                                              In that case only OTP hash is written and the device is\n"
		"                                              provisioned for trusted boot.\n"
		"      --serial-number=SN                      serial number to write to OTP memory\n"
		"      --mac-address=MAC                       MAC address to write to OTP memory\n"
		"      --board=MOX/RIPE                        board type to write to OTP memory\n"
		"      --board-version=BV                      board version to write to OTP memory\n"
		"      --otp-hash=HASH                         secure firmware hash as given by --get-otp-hash\n\n"
		"  -g, --gen-key[=KEY]                         generate ECDSA-521 private key to file KEY or to stdout\n"
		"  -s, --sign                                  sign TIM image with ECDSA-521 private key\n"
		"      --create-trusted-image=SPI/UART/EMMC    create secure image for SPI / UART (private key required)\n"
		"      --create-untrusted-image=SPI/UART/EMMC  create untrusted secure image (no private key required)\n"
		"      --sign-untrusted-image=SPI/UART/EMMC    sign untrusted image to make it trusted (private key required)\n"
		"  -S  --disassemble                           disassemble GPP code when parsing TIM\n"
		"      --get-otp-hash                          print OTP hash of given secure firmware image\n"
		"  -u, --hash-a53-firmware                     save A53 firmware (TF-A + U-Boot) image hash to TIM\n"
		"  -n, --no-a53-firmware                       remove A53 firmware (TF-A + U-Boot) image from TIM\n"
		"      --timn-offset=OFFSET                    offset of TIMN header within TIM image (default: %#x)\n"
		"      --wtmi-offset=OFFSET                    offset of WTMI image (default: %#x)\n"
		"      --obmi-offset=OFFSET                    offset of OBMI image / A53 firmware (default: %#x)\n"
		"      --obmi-max-size=SIZE                    maximum size of OBMI image / A53 firmware (default: %#x)\n"
		"  -h, --help                                  show this help and exit\n"
		"\n", def_args.timn_offset, def_args.wtmi_offset, def_args.obmi_offset, def_args.obmi_max_size);
	exit(EXIT_SUCCESS);
}

static const int timn_offset_opt = 256;
static const int wtmi_offset_opt = 257;
static const int obmi_offset_opt = 258;
static const int obmi_max_size_opt = 259;

static const struct option long_options[] = {
	{ "device",			required_argument,	0,	'D' },
	{ "baudrate",			required_argument,	0,	'b' },
	{ "fd",				required_argument,	0,	'F' },
	{ "send-escape-sequence",	no_argument,		0,	'E' },
	{ "max-restarts",		required_argument,	0,	'T' },
	{ "terminal",			no_argument,		0,	't' },
	{ "output",			required_argument,	0,	'o' },
	{ "key",			required_argument,	0,	'k' },
	{ "random-seed",		required_argument,	0,	'r' },
	{ "otp-read",			optional_argument,	0,	'R' },
	{ "deploy",			optional_argument,	0,	'd' },
	{ "serial-number",		required_argument,	0,	'N' },
	{ "mac-address",		required_argument,	0,	'M' },
	{ "board",			required_argument,	0,	'Z' },
	{ "board-version",		required_argument,	0,	'B' },
	{ "otp-hash",			required_argument,	0,	'H' },
	{ "gen-key",			optional_argument,	0,	'g' },
	{ "sign",			no_argument,		0,	's' },
	{ "create-trusted-image",	required_argument,	0,	'c' },
	{ "create-untrusted-image",	required_argument,	0,	'C' },
	{ "sign-untrusted-image",	required_argument,	0,	'i' },
	{ "disassemble",		no_argument,		0,	'S' },
	{ "get-otp-hash",		no_argument,		0,	'G' },
	{ "hash-a53-firmware",		no_argument,		0,	'u' },
	{ "no-a53-firmware",		no_argument,		0,	'n' },
	{ "timn-offset",		required_argument,	0,	timn_offset_opt },
	{ "wtmi-offset",		required_argument,	0,	wtmi_offset_opt },
	{ "obmi-offset",		required_argument,	0,	obmi_offset_opt },
	{ "obmi-max-size",		required_argument,	0,	obmi_max_size_opt },
	{ "help",			no_argument,		0,	'h' },
	{ 0,				0,			0,	0 },
};

int main(int argc, char **argv)
{
	int images_given, dummy;
	u32 partition;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "D:b:F:Eo:k:r:R::dg:sStunh",
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'D':
			if (args.tty)
				die("Device already given");
			args.tty = optarg;
			if (access(args.tty, R_OK | W_OK))
				die("Don't have read/write access to device %s: %m", args.tty);
			break;
		case 'b':
			args.baudrate = atoi(optarg);
			if (args.baudrate > 6000000)
				die("Desired baudrate too high (maximum is 6 MBaud)");
			if (args.baudrate == 115200)
				args.baudrate = 0;
			break;
		case 'F':
			if (args.fdstr)
				die("File descriptor already given");
			args.fdstr = optarg;
			break;
		case 'E':
			args.send_escape = 1;
			break;
		case 'T':
			if (args.max_restarts != -1)
				die("Option '--max-restarts' already given");
			args.max_restarts = parse_u32_opt("max-restarts", optarg, 0, INT32_MAX);
			break;
		case 'o':
			if (args.output)
				die("Output file already given");
			args.output = optarg;
			break;
		case 'k':
			if (args.keyfile)
				die("Key file already given");
			args.keyfile = optarg;
			break;
		case 'r':
			if (args.seed)
				die("Random seed file already given");
			args.seed = optarg;
			break;
		case 'R':
			if (args.otp_read)
				die("Option --otp-read already given");
			if (optarg)
				args.otp_read = optarg;
			else
				args.otp_read = "";
			break;
		case 'd':
			if (args.deploy)
				die("Option --deploy already given");

			if (optarg) {
				args.deploy_no_board_info = !strcmp(optarg, "no-board-info");
				if (!args.deploy_no_board_info)
					die("value %s of option '--deploy' unrecognized", optarg);
			}

			args.deploy = 1;
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
				args.uart_terminal_kbs = tigetstr("kbs");
				if (args.uart_terminal_kbs == (char *)-1)
					args.uart_terminal_kbs = NULL;
			}
			args.terminal_on_exit = 1;
			break;
		case 'N':
			if (args.serial_number)
				die("Serial number already given");
			args.serial_number = optarg;
			break;
		case 'M':
			if (args.mac_address)
				die("Mac address already given");
			args.mac_address = optarg;
			break;
		case 'Z':
			if (args.board)
				die("Board already given");
			args.board = optarg;
			break;
		case 'B':
			if (args.board_version)
				die("Board version already given");
			args.board_version = optarg;
			break;
		case 'H':
			if (args.otp_hash)
				die("OTP hash already given");
			args.otp_hash = optarg;
			break;
		case 'g':
			if (args.genkey)
				die("File to which generate key already given");
			args.genkey = 1;
			args.genkey_output = optarg;
			break;
		case 's':
			args.sign = 1;
			break;
		case 'c':
		case 'C':
		case 'i':
			if (!strcmp(optarg, "UART"))
				args.image_bootfs = BOOTFS_UART;
			else if (!strcmp(optarg, "SPI"))
				args.image_bootfs = BOOTFS_SPINOR;
			else if (!strcmp(optarg, "EMMC"))
				args.image_bootfs = BOOTFS_EMMC;
			else
				die("Invalid argument for parameter --create-[un]trusted-image/--sign-untrusted-image");
			if (c == 'c')
				args.create_trusted_image = 1;
			else if (c == 'C')
				args.create_untrusted_image = 1;
			else
				args.sign_untrusted_image = 1;
			break;
		case 'S':
			args.gpp_disassemble = 1;
			break;
		case 'G':
			args.get_otp_hash = 1;
			break;
		case 'u':
			args.hash_a53_firmware = 1;
			break;
		case 'n':
			args.no_a53_firmware = 1;
			break;
		case timn_offset_opt:
			args.timn_offset = parse_u32_opt("timn-offset", optarg, 0x100, 0x4000);
			break;
		case wtmi_offset_opt:
			args.wtmi_offset = parse_u32_opt("wtmi-offset", optarg, 0x800, 0x20000);
			break;
		case obmi_offset_opt:
			args.obmi_offset = parse_u32_opt("obmi-offset", optarg, 0x1000, 0x100000);
			break;
		case obmi_max_size_opt:
			args.obmi_max_size = parse_u32_opt("obmi-max-size", optarg, 0, 0x1000000);
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

	if (args.create_trusted_image && (!args.keyfile || !args.output))
		die("Options --key and --output must be given when creating trusted image");

	if (args.create_untrusted_image && !args.output)
		die("Option --output must be given when creating untrusted image");

	if (args.sign_untrusted_image && (!args.keyfile || !args.output))
		die("Options --key and --output must be given when signing untrusted image");

	if ((args.tty || args.fdstr) && args.output)
		die("Options --device and --output cannot be used together");

	if (args.sign && !args.keyfile)
		die("Option --key must be given when signing");

	if ((args.otp_read || args.deploy) && !args.tty && !args.fdstr)
		die("Option --device must be specified when reading/writing OTP");

	if (args.otp_read && args.deploy)
		die("Options to read OTP and deploy cannot be used together");

	if (args.deploy) {
		if (args.deploy_no_board_info) {
			if (!args.otp_hash)
				die("Option --otp-hash must be given when deploying device with no board information");
			if (args.serial_number || args.mac_address || args.board || args.board_version)
				die("Options --serial-number, --mac-address, --board and --board-version must not be given when deploying device with no board information");
		} else {
			if (!args.serial_number || !args.mac_address || !args.board || !args.board_version || !args.otp_hash)
				die("Options --serial-number, --mac-address, --board, --board-version and --otp-hash must be given when deploying device");
		}
	}

	if (args.genkey) {
		if (optind < argc)
			die("Images must not be given when generating key");

		generate_key(args.genkey_output, args.seed);
		exit(EXIT_SUCCESS);
	}

	images_given = argc - optind;

	if (args.otp_read && images_given)
		die("Images given when trying to read OTP");

	for (; optind < argc; ++optind)
		image_load(argv[optind]);

	if (args.image_bootfs == BOOTFS_EMMC)
		/* Boot partition on eMMC is partition 2 */
		partition = 2;
	else
		partition = 0;

	if (args.create_trusted_image) {
		do_create_trusted_image(args.keyfile, args.output, args.image_bootfs, partition, 1, args.hash_a53_firmware);
		exit(EXIT_SUCCESS);
	} else if (args.create_untrusted_image) {
		do_create_untrusted_image(args.output, args.image_bootfs, partition, 1, args.hash_a53_firmware);
		exit(EXIT_SUCCESS);
	} else if (args.sign_untrusted_image) {
		do_sign_untrusted_image(args.keyfile, args.output, args.image_bootfs, partition, args.hash_a53_firmware);
		exit(EXIT_SUCCESS);
	}

	if (!args.otp_read && !args.deploy && !images_given && !args.terminal_on_exit)
		die("No images given, try -h for help");

	if (args.otp_read) {
		do_otp_read(&args);
	} else if (args.deploy) {
		create_deploy_image(&args);
	} else if (images_given) {
		image_t *timh = NULL, *timn = NULL;
		int has_fast_mode;

		if (args.get_otp_hash) {
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

		if (args.no_a53_firmware) {
			if (tim_is_trusted(timh))
				die("Cannot modify trusted image!");
			tim_remove_image(timh, name2id("OBMI"));
			tim_rehash(timh);
		}

		tim_parse(timh, args.gpp_disassemble, &has_fast_mode, stdout);
		if (timn)
			tim_parse(timn, args.gpp_disassemble, &has_fast_mode, stdout);

		if (args.baudrate && !has_fast_mode) {
			if (tim_is_trusted(timh))
				die("Fast upload mode not supported by this image\n"
				    "and cannot inject the code into trusted image!");
			tim_inject_baudrate_change_support(timn ? : timh);
		}

		if (!tim_is_trusted(timh))
			tim_enable_hash(timh, OBMI_ID, args.hash_a53_firmware);
	}

	if (images_given) {
		if (args.tty || args.fdstr)
			set_bootfs_if_possible(BOOTFS_UART);
		else if (args.output)
			set_bootfs_if_possible(BOOTFS_SPINOR);

		ensure_image_rehash_or_sign_if_possible(args.sign, args.keyfile);
	}

	if (args.tty || args.fdstr)
		do_uart(&args);

	if (args.output) {
		if (image_exists(TIMN_ID))
			die("TIMH + TIMN image saving not supported!");
		save_flash_image(image_find(TIMH_ID), args.output);
		info("Saved to image %s\n\n", args.output);
	}

	exit(EXIT_SUCCESS);
}

