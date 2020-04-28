// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <asm/termbits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <math.h>
#include <endian.h>
#include "utils.h"
#include "wtptp.h"

static int wtpfd;

static void xread(void *buf, size_t size)
{
	ssize_t rd, res;
	struct pollfd pfd;

	pfd.fd = wtpfd;
	pfd.events = POLLIN;

	rd = 0;
	while (rd < size) {
		pfd.revents = 0;
		res = poll(&pfd, 1, -1);
		if (res < 0)
			die("Cannot poll: %m\n");

		res = read(wtpfd, buf + rd, size - rd);
		if (res < 0)
			die("Cannot read %zu bytes: %m", size);

		rd += res;
	}
}

static void xwrite(const void *buf, size_t size)
{
	ssize_t res;

	res = write(wtpfd, buf, size);
	if (res < 0)
		die("Cannot write %zu bytes: %m", size);
	else if (res < size)
		die("Cannot write %zu bytes: written only %zi", size, res);
}

static int detect_char(u8 *c)
{
	ssize_t rd;
	u8 rcv;

	rd = read(wtpfd, &rcv, 1);
	if (rd < 0)
		die("Cannot detect char while sending escape sequence: %m");
	if (rd == 1 && c)
		*c = rcv;

	return rd == 1;
}

static void raw_escape_seq(void)
{
	int i, nacks;
	const u8 buf[8] = {0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	u8 rcv;

	for (i = 0, nacks; i < 10000 && nacks < 4; ++i) {
		xwrite(buf, 8);
		if (!detect_char(&rcv))
			continue;
		if (rcv == 0x3e)
			break;
		else if (rcv == 0x00)
			++nacks;
	}

	if (i == 10000)
		die("Escape sequence failed!");
}

static void start_wtp(void)
{
	u8 buf[5];

	xwrite("wtp\r", 4);
	xread(buf, 5);
	if (memcmp(buf, "wtp\r\n", 5))
		die("Wrong reply: \"%.*s\"", 5, buf);
}

static int escape_seq(void)
{
	size_t tot = 0;
	ssize_t rd, i;
	u8 buf[512];
	int prompt = 0;

	printf("Sending escape sequence, you have cca 5-10 seconds to power up MOX\n\n");

	raw_escape_seq();
	raw_escape_seq();
	xwrite("\r\r\r\r", 4);

	while (1) {
		usleep(500000);
		rd = read(wtpfd, buf, 512);
		if (rd < 0)
			die("Cannot read: %m\n");

		if (!rd)
			break;

		for (i = 0; i < rd; ++i)
			if (buf[i] == '>')
				prompt = 1;

		tot += rd;

	}

	return prompt;
}

static inline int tcdrain(int fd)
{
	return ioctl(fd, TCSBRK, 1);
}

static inline int tcflush(int fd, int q)
{
	return ioctl(fd, TCFLSH, q);
}

static void change_to_higher_baudrate(void)
{
	const char *cmd = "w c0012014 0f0f0f0f\r";
	struct termios2 opts;

	xwrite(cmd, strlen(cmd));
	tcdrain(wtpfd);
	usleep(10000);
	tcflush(wtpfd, TCIFLUSH);

	memset(&opts, 0, sizeof(opts));
	ioctl(wtpfd, TCGETS2, &opts);
	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= BOTHER;
	opts.c_ispeed = opts.c_ospeed = 230400;
	ioctl(wtpfd, TCSETS2, &opts);
	usleep(10000);
	tcflush(wtpfd, TCIFLUSH);
}

void setwtpfd(const char *fdstr)
{
	char *end;

	wtpfd = strtol(fdstr, &end, 10);
	if (*end || wtpfd < 0)
		die("Wrong file descriptor %s", fdstr);
}

void openwtp(const char *path)
{
	struct termios2 opts;

	wtpfd = open(path, O_RDWR | O_NOCTTY);

	if (wtpfd < 0)
		die("Cannot open %s: %m", path);

	memset(&opts, 0, sizeof(opts));
	ioctl(wtpfd, TCGETS2, &opts);
	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= B115200;
	opts.c_cc[VMIN] = 0;
	opts.c_cc[VTIME] = 0;
	opts.c_iflag = 0;
	opts.c_lflag = 0;
	opts.c_oflag = 0;
	opts.c_cflag &= ~(CSIZE | PARENB | PARODD | CSTOPB | CRTSCTS);
	opts.c_cflag |= CS8 | CREAD | CLOCAL;
	ioctl(wtpfd, TCSETS2, &opts);
	tcflush(wtpfd, TCIFLUSH);
}

void initwtp(int send_escape, int higher_baudrate)
{
	int prompt = 1;

	if (send_escape)
		prompt = escape_seq();

	if (prompt) {
		if (higher_baudrate)
			change_to_higher_baudrate();
		start_wtp();
	}
}

void closewtp(void)
{
	close(wtpfd);
}

static void readresp(u8 cmd, u8 seq, u8 cid, resp_t *resp)
{
	xread(resp, 6);

	if (resp->cmd != cmd || resp->seq != seq || resp->cid != cid)
		die("Comparison fail: cmd[%02x %02x %02x] != "
		    "resp[%02x %02x %02x]", cmd, seq, cid, resp->cmd, resp->seq,
		    resp->cid);

	if (resp->len > 0)
		xread(((void *) resp) + 6, resp->len);
}

static void _sendcmd(u8 cmd, u8 seq, u8 cid, u8 flags, u32 len,
		     const void *data, resp_t *resp)
{
	u8 *buf;

	buf = xmalloc(8 + len);
	buf[0] = cmd;
	buf[1] = seq;
	buf[2] = cid;
	buf[3] = flags;

	*(u32 *) &buf[4] = htole32(len);
	if (len)
		memcpy(buf + 8, data, len);

	xwrite(buf, 8 + len);
	free(buf);

	if (resp)
		readresp(cmd, seq, cid, resp);
}

static void checkresp(resp_t *resp)
{
	if (resp->status == 0x2)
		die("Sequence error on command %02x", resp->cmd);
	else if (resp->status == 0x1)
		die("NACK on command %02x", resp->cmd);
}

static void sendcmd(u8 cmd, u8 seq, u8 cid, u8 flags, u32 len, const void *data,
		    resp_t *resp)
{
	int ismsg;
	resp_t msgresp;

	_sendcmd(cmd, seq, cid, flags, len, data, resp);

	if (!resp)
		return;

	for (ismsg = resp->flags & 3; ismsg & 1; ismsg = msgresp.flags & 3) {
		_sendcmd(0x2b, 0, cid, 0, 0, NULL, &msgresp);
		if (ismsg & 2)
			printf("Message from target: 0x%08x\n",
			       *(u32 *) msgresp.data);
		else
			printf("Message from target: \"%.*s\"\n",
			       (int) msgresp.len, msgresp.data);
	}

	checkresp(resp);
}

static void preamble(void)
{
	u8 buf[6];

	xwrite("\x00\xd3\x02\x2b", 4);
	xread(buf, 4);

	if (!memcmp(buf, "TIM-", 4)) {
		xread(buf, 5);
		xread(buf, 4);
	}

	if (memcmp(buf, "\x00\xd3\x02\x2b", 4))
		die("Wrong reply to preamble: \"%.*s\" (%02x %02x %02x %02x)",
		    4, buf, buf[0], buf[1], buf[2], buf[3]);
}

static void getversion(void)
{
	static int printed;
	resp_t resp;
	u32 date;

	sendcmd(0x20, 0, 0, 0, 0, NULL, &resp);

	if (resp.len != 12)
		die("GetVersion response length = %i != 12", resp.len);

	date = *(u32 *) &resp.data[4];

	if (!printed) {
		printed = 1;

		printf("GetVersion response: stepping \"%.*s\", "
		       "date = %x/%x/%x, CPU \"%.*s\"\n", 4, &resp.data[0],
		       (date >> 24) & 0xff, (date >> 16) & 0xff, date & 0xffff,
		       4, &resp.data[8]);
	}
}

u32 selectimage(void)
{
	resp_t resp;

	preamble();
	getversion();

	sendcmd(0x26, 0, 0, 0, 0, NULL, &resp);

	if (resp.len != 4)
		die("SelectImage response length = %i != 4", resp.len);

	return *(u32 *) resp.data;
}

void sendimage(image_t *img, int fast)
{
	static int seq = 1;
	resp_t resp;
	u8 buf[4];
	u32 sent;
	double start;
	int diff;
	int istty = isatty(STDOUT_FILENO);

	buf[0] = 0;
	sendcmd(0x27, 0, 0, 0, 1, buf, &resp);

	start = now();
	sent = 0;
	while (sent < img->size) {
		u32 tosend;
		int eta;

		if ((fast && !sent) || !fast) {
			*(u32 *) buf = htole32(img->size - sent);

			sendcmd(0x2a, seq, 0, fast ? 4 : 0, 4, buf, &resp);
			if (resp.len != 4)
				die("DataHeader response length = %i != 4\n",
				    resp.len);

			if (fast && !(resp.flags & 4))
				die("Fast mode not supported");

			tosend = le32toh(*(u32 *) resp.data);
		}

		if (img->size - sent < tosend)
			tosend = img->size - sent;

		if (fast)
			xwrite(img->data + sent, tosend);
		else
			sendcmd(0x22, seq, 0, 0, tosend, img->data + sent,
				&resp);

		sent += tosend;

		if (istty) {
			eta = lrint((now() - start) * (img->size - sent) /
				    sent);
			printf("\r%u%% sent, ETA %02i:%02i",
			       100 * sent / img->size, eta / 60, eta % 60);
			fflush(stdout);
		} else {
			int pprev, p;

			pprev = 100 * (sent - tosend) / img->size;
			p = 100 * sent / img->size;

			if (p != pprev) {
				printf(".");
				fflush(stdout);
			}
		}
	}

	if (istty) {
		diff = lrint(now() - start);
		printf("\r100%% sent in %02i:%02i  \n", diff / 60, diff % 60);
	} else {
		printf("\n");
	}

	if (fast) {
		readresp(0x22, seq, 0, &resp);
		checkresp(&resp);
	}

	sendcmd(0x30, 0, 0, 0, 0, NULL, &resp);
}

static void eccread(void *_buf, size_t size)
{
	static const u8 ecc[128] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1,
		0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1,
		0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
		0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	};
	size_t i;
	int j;
	u8 eccbuf[8], *buf, c;

	buf = _buf;

	for (i = 0; i < size; ++i) {
		xread(eccbuf, 8);

		c = 0;
		for (j = 0; j < 8; ++j)
			c |= ecc[eccbuf[j] & 0x7f] << j;

		buf[i] = c;
	}
}

void uart_otp_read(void)
{
	u8 buf[19];
	int i;

	eccread(buf, 4);
	if (memcmp(buf, "OTP\n", 4))
		die("Wrong reply: \"%.*s\"", 4, buf);

	for (i = 0; i < 44; ++i) {
		u64 val;
		char *end;

		eccread(buf, 19);

		val = strtoull(buf + 2, &end, 16);

		if ((buf[0] != '0' && buf[0] != '1') || buf[1] != ' '
		    || buf[18] != '\n' || (u8 *) end != &buf[18])
			die("Wrong reply when reading OTP row %i", i);

		printf("OTP row %i %016llx %s\n", i, val,
		       buf[0] == '1' ? "locked" : "not locked");
	}

	printf("All done.\n");
}

void uart_deploy(void)
{
	u8 buf[134];
	int ram;

	eccread(buf, 4);
	if (memcmp(buf, "RAM", 3) || (buf[3] != '0' && buf[3] != '1'))
		goto wrong;

	ram = buf[3] == '1' ? 1024 : 512;

	printf("\n");
	printf("Found %i MiB RAM\n", ram);

	eccread(buf, 4);
	if (memcmp(buf, "SERN", 4))
		goto wrong;

	eccread(buf, 16);
	printf("Serial Number: %.*s\n", 16, buf);

	eccread(buf, 4);
	if (memcmp(buf, "BVER", 4))
		goto wrong;

	eccread(buf, 2);
	buf[2] = '\0';
	printf("Board version: %lu\n", strtol(buf, NULL, 16));

	eccread(buf, 4);
	if (memcmp(buf, "MACA", 4))
		goto wrong;

	eccread(buf, 12);
	printf("MAC address: %.*s\n", 12, buf);

	eccread(buf, 4);
	if (memcmp(buf, "PUBK", 4))
		goto wrong;

	eccread(buf, 134);

	printf("ECDSA Public Key: %.*s\n", 134, buf);

	printf("All done.\n");

	return;
wrong:
	if (memcmp(buf, "FAIL", 4))
		die("Wrong reply: \"%.*s\"", 4, buf);

	eccread(buf, 13);
	printf("FAIL%.*s\n", 13, buf);
}
