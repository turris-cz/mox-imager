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

static int wtpfd = -1;

static inline int tcdrain(int fd)
{
	return ioctl(fd, TCSBRK, 1);
}

static inline int tcflush(int fd, int q)
{
	return ioctl(fd, TCFLSH, q);
}

static int xread_timeout(void *buf, size_t size, int timeout)
{
	ssize_t rd, res;
	struct pollfd pfd;

	pfd.fd = wtpfd;
	pfd.events = POLLIN;

	rd = 0;
	while (rd < size) {
		pfd.revents = 0;
		res = poll(&pfd, 1, timeout);
		if (res < 0)
			die("Cannot poll: %m\n");
		else if (res == 0)
			break;

		res = read(wtpfd, buf + rd, size - rd);
		if (res < 0)
			die("Cannot read %zu bytes: %m", size);

		rd += res;
	}

	return rd;
}

static void xread(void *buf, size_t size)
{
	xread_timeout(buf, size, -1);
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
	u8 rcv;

	if (xread_timeout(&rcv, 1, 50) != 1)
		return 0;

	if (c)
		*c = rcv;

	return 1;
}

static int eat_zeros(u8 *after)
{
	int zeros;
	u8 rcv;

	*after = 0x00;

	for (zeros = 0; xread_timeout(&rcv, 1, 1000); ++zeros) {
		if (rcv != 0x00) {
			*after = rcv;
			break;
		}
	}

	return zeros;
}

static void raw_escape_seq(void)
{
	const u8 buf[8] = {0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	int i;

	tcflush(wtpfd, TCIOFLUSH);
	for (i = 0; i < 128; ++i) {
		xwrite(buf, 8);
		usleep(500);
	}
}

static int escape_seq(void)
{
	u8 rcv, after;

	printf("Sending escape sequence, please power up the device\n\n");

	do {
		raw_escape_seq();

		if (!detect_char(&rcv))
			continue;

		switch (rcv) {
		case 0x00:
			printf("\e[1KReceived NAK, try restarting again\r");
			break;
		case 0xff:
			printf("\e[1KReceived all ones byte\r");
			break;
		case 0x3e:
			printf("\nReceived ACK\n");
			break;
		default:
			die("\nInvalid reply to escape sequence: 0x%02x\n", rcv);
		}
	} while (rcv != 0x3e);

	raw_escape_seq();

	sleep(2);
	tcflush(wtpfd, TCIOFLUSH);

	xwrite("\r\r\r\r", 4);

	eat_zeros(&after);
	if (after == '\r') {
		sleep(1);
		tcflush(wtpfd, TCIOFLUSH);
		return 1;
	}

	return 0;
}

void setwtpfd(const char *fdstr)
{
	char *end;

	wtpfd = strtol(fdstr, &end, 10);
	if (*end || wtpfd < 0)
		die("Wrong file descriptor %s", fdstr);
}

static void reset_clocal(const char *path)
{
	struct termios2 opts;
	int fd;

	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY);
	if (fd < 0)
		die("Cannot open %s: %m", path);

	memset(&opts, 0, sizeof(opts));
	ioctl(wtpfd, TCGETS2, &opts);

	opts.c_cflag |= CLOCAL;

	ioctl(wtpfd, TCSETS2, &opts);

	close(fd);
}

void openwtp(const char *path)
{
	struct termios2 opts;

	/* to avoid hangs */
	reset_clocal(path);

	wtpfd = open(path, O_RDWR | O_NOCTTY);

	if (wtpfd < 0)
		die("Cannot open %s: %m", path);

	memset(&opts, 0, sizeof(opts));
	ioctl(wtpfd, TCGETS2, &opts);

	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= B115200;
	opts.c_cc[VMIN] = 1;
	opts.c_cc[VTIME] = 10;
	opts.c_iflag = 0;
	opts.c_lflag = 0;
	opts.c_oflag = 0;
	opts.c_cflag &= ~(CSIZE | PARENB | PARODD | CSTOPB | CRTSCTS);
	opts.c_cflag |= CS8 | CREAD | CLOCAL;

	ioctl(wtpfd, TCSETS2, &opts);
	tcflush(wtpfd, TCIFLUSH);
}

static void start_wtp(void)
{
	u8 buf[5];

	xwrite("wtp\r", 4);
	xread(buf, 5);
	if (memcmp(buf, "wtp\r\n", 5))
		die("Wrong reply: \"%.*s\"", 5, buf);
}

void initwtp(int send_escape)
{
	int prompt = 1;

	if (send_escape)
		prompt = escape_seq();

	if (prompt)
		start_wtp();
}

void closewtp(void)
{
	close(wtpfd);
}

/*
 * Some images may print additional characters on UART when loaded. We must
 * ignore this characters in WTPTP protocol.
 *
 * Try to receive the until character sequence in first up to max bytes, and
 * if stdout is a TTY, print anything that was sent before this sequence to
 * in yellow.
 */
static int read_until(const u8 *until, size_t ulen, size_t max)
{
	int i, pos, printed = 0, istty;
	u8 buf[ulen], last;

	istty = isatty(STDOUT_FILENO);

	pos = 0;
	for (i = 0; i < max; ++i) {
		xread(&buf[pos], 1);
		if (buf[pos] == until[pos]) {
			++pos;
		} else {
			if (istty) {
				if (!printed)
					printf("\033[33;1m");
				printf("%.*s", pos + 1, (char *)buf);
				printed += pos + 1;
				last = buf[pos];
			}
			pos = 0;
		}

		if (pos == ulen)
			break;
	}

	if (printed) {
		if (last != '\n')
			putchar('\n');
		printf("\033[0m");
	}

	return pos == ulen;
}

static int compute_tbg_freq(int xtal, int fbdiv, int refdiv, int vcodiv_sel)
{
	if (!refdiv)
		refdiv = 1;

	return 1000000 * (u64)xtal * (fbdiv << 2) / (refdiv * (1 << vcodiv_sel));
}

static int compute_best_uart_params(u32 clk, u32 desired_baud, u32 *div, u32 *m)
{
	u8 m1, m2, m3, m4, best_m1, best_m2, best_m3, best_m4;
	u64 ticks, ratio, err, best_err = -1ULL;
	u32 d, d_max, best_d;
	_Bool eq, best_eq;
	/*
	 * We are using fixed-point arithmetic to compute best possible
	 * parameters. We need to know the maximum possible parameter value for
	 * the integral part of the fixed-point number so that we know how many
	 * bits we must shift.
	 */
	const u64 fp_max_param =
		/* max ticks * max desired baud */
		(u64)((3 * (63 + 63) + 2 * (63 + 63)) * 1023) * 6000000;
	const int fp_shift = __builtin_clzll(fp_max_param) - 1;
	const u64 fp_1 = 1ULL << fp_shift;

	d_max = clk / (desired_baud * 16);
	if (d_max > 1023)
		d_max = 1023;

	for (d = 2; d <= d_max; ++d) {
		u8 lo, hi;

		m1 = clk / (desired_baud * d);
		if (m1 < 2 || m1 > 63)
			continue;

		lo = m1 == 2 ? 2 : m1 - 1;
		hi = m1 == 63 ? 63 : m1 + 1;

		for (m2 = lo; m2 <= hi; ++m2) {
			for (m3 = lo; m3 <= hi; ++m3) {
				if (abs((int)m2 - m3) > 1)
					continue;
				for (m4 = lo; m4 <= hi; ++m4) {
					if (abs((int)m3 - m4) > 1)
						continue;

					ticks = (3 * ((u32)m1 + m2) + 2 * ((u32)m3 + m4)) * d;
					ratio = ((ticks * desired_baud) << fp_shift) / (10ULL * clk);

					/* distance from 1 */
					if (ratio > fp_1)
						err = ratio - fp_1;
					else
						err = fp_1 - ratio;

					eq = (m1 == m2 && m2 == m3 && m3 == m4);
					if (err < best_err || (err == best_err && eq && !best_eq)) {
						best_err = err;
						best_d = d;
						best_m1 = m1;
						best_m2 = m2;
						best_m3 = m3;
						best_m4 = m4;
						best_eq = eq;
					}
				}
			}
		}
	}

	if (best_err == -1ULL)
		return -1;

	*div = best_d;
	*m = (best_m4 << 24) | (best_m3 << 16) | (best_m2 << 8) | best_m1;

	return 0;
}

static tcflag_t baudrate_to_cflag(int baudrate)
{
#define B(b) { B ## b, b }
	static const struct {
		tcflag_t cflag;
		int baudrate;
	} map[] = {
		B(50), B(75), B(110), B(134), B(150), B(200), B(300), B(600),
		B(1200), B(1800), B(2400), B(4800), B(9600), B(19200), B(38400),
		B(57600), B(115200), B(230400), B(460800), B(500000), B(576000),
		B(921600), B(1000000), B(1152000), B(1500000), B(2000000),
		B(2500000), B(3000000), B(3500000), B(4000000), B(0),
	};
#undef B
	int i;

	for (i = 0; map[i].baudrate; i++)
		if (map[i].baudrate == baudrate)
			return map[i].cflag;

	return BOTHER;
}

static void change_baudrate(int baudrate)
{
	struct termios2 opts = {};

	ioctl(wtpfd, TCGETS2, &opts);
	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= baudrate_to_cflag(baudrate);
	opts.c_ispeed = opts.c_ospeed = baudrate;
	ioctl(wtpfd, TCSETS2, &opts);
	usleep(10000);
	tcflush(wtpfd, TCIFLUSH);
}

void try_change_baudrate(int baudrate)
{
	struct termios2 opts;
	int tbg_freq;
	u32 div, m;
	u8 buf[6] = "baud";

	printf("Requesting baudrate change to %i baud\n", baudrate);

	/*
	 * Wait 100ms to make sure we send the "baud" command only after BootROM
	 * verified the TIM and is in execution of the GPP program.
	 */
	usleep(100000);

	xwrite(buf, 4);

	if (!read_until(buf, 4, 256))
		die("Did not receive \"baud\" command reply!");

	xread(buf, 5);

	tbg_freq = compute_tbg_freq(buf[0], buf[1],
				    ((buf[3] & 1) << 8) | buf[2], buf[4]);

	if (compute_best_uart_params(tbg_freq, baudrate, &div, &m))
		die("Failed computing A3720 UART parameters for baudrate %i!\n",
		    baudrate);

	*(u16 *)&buf[0] = htole16(div);
	*(u32 *)&buf[2] = htole32(m);

	xwrite(buf, 6);
	usleep(300000);

	change_baudrate(baudrate);
}

static void readresp(u8 cmd, u8 seq, u8 cid, resp_t *resp)
{
	const u8 chk[3] = { cmd, seq, cid };

	if (!read_until(chk, sizeof(chk), 256))
		die("Failed cmd[%02x %02x %02x]", cmd, seq, cid);

	memcpy(resp, chk, 3);
	xread(((void *) resp) + 3, 3);

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
	static const u8 chk[4] = { 0x00, 0xd3, 0x02, 0x2b };

	xwrite("\x00\xd3\x02\x2b", 4);

	if (!read_until(chk, sizeof(chk), 256))
		die("Wrong reply to preamble");
}

static void getversion(void)
{
	static int printed;
	resp_t resp;

	sendcmd(0x20, 0, 0, 0, 0, NULL, &resp);

	if (resp.len != 12)
		die("GetVersion response length = %i != 12", resp.len);

	if (!printed) {
		u32 date;

		date = le32toh(*(u32 *)&resp.data[4]);

		printf("GetVersion response: version %c.%c.%c%c, "
		       "date %04x-%02x-%02x, CPU %s\n",
		       resp.data[3], resp.data[2], resp.data[1], resp.data[0],
		       date & 0xffff, (date >> 24) & 0xff, (date >> 16) & 0xff,
		       id2name(*(u32 *)&resp.data[8]));

		printed = 1;
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
	if (memcmp(buf, "RAM", 3) || buf[3] < '0' || buf[3] > '3')
		goto wrong;

	ram = 512 << (buf[3] - '0');

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

static int uart_terminal_pipe(int in, int out, const char *quit, int *s)
{
	char _buf[128], *buf = _buf;
	ssize_t nin, nout;

	nin = read(in, buf, sizeof(_buf));
	if (nin <= 0)
		return -1;

	if (quit) {
		int i;

		for (i = 0; i < nin; i++) {
			if (*buf == quit[*s]) {
				(*s)++;
				if (!quit[*s])
					return 0;
				buf++;
				nin--;
			} else {
				while (*s > 0) {
					nout = write(out, quit, *s);
					if (nout <= 0)
						return -1;
					(*s) -= nout;
				}
			}
		}
	}

	while (nin > 0) {
		nout = write(out, buf, nin);
		if (nout <= 0)
			return -1;
		nin -= nout;
	}

	return 0;
}

void uart_terminal(void) {
	const char *quit = "\34c";
	struct termios2 otio, tio;
	int in, s;

	if (wtpfd < 0)
		return;

	change_baudrate(115200);

	in = isatty(STDIN_FILENO) ? STDIN_FILENO : -1;

	if (in >= 0) {
		memset(&otio, 0, sizeof(otio));
		ioctl(in, TCGETS2, &otio);
		tio = otio;
		/* cfmakeraw */
		tio.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
				| INLCR | IGNCR | ICRNL | IXON);
		tio.c_oflag &= ~OPOST;
		tio.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
		tio.c_cflag &= ~(CSIZE | PARENB);
		tio.c_cflag |= CS8;
		ioctl(in, TCSETS2, &tio);
		printf("\r\n[Type Ctrl-%c + %c to quit]\r\n\r\n",
		       quit[0] | 0100, quit[1]);
	}

	s = 0;

	do {
		fd_set rfds;
		int nfds = 0;

		FD_SET(wtpfd, &rfds);
		nfds = nfds < wtpfd ? wtpfd : nfds;

		if (in >= 0) {
			FD_SET(in, &rfds);
			nfds = nfds < in ? in : nfds;
		}

		nfds = select(nfds + 1, &rfds, NULL, NULL, NULL);
		if (nfds < 0)
			break;

		if (FD_ISSET(wtpfd, &rfds)) {
			if (uart_terminal_pipe(wtpfd, STDOUT_FILENO, NULL,
					       NULL))
				break;
		}

		if (FD_ISSET(in, &rfds)) {
			if (uart_terminal_pipe(in, wtpfd, quit, &s))
				break;
		}
	} while (quit[s] != 0);

	if (in >= 0)
		ioctl(in, TCSETS2, &otio);

	printf("\n");
}
