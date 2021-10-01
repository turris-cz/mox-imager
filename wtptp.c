// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <asm/termbits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <math.h>
#include <endian.h>
#include <pthread.h>
#include "utils.h"
#include "wtptp.h"

/* Some architectures don't have termios2 */
#ifndef TCGETS2
#define TCGETS2 TCGETS
#define TCSETS2 TCSETS
#define TCSETSW2 TCSETSW
#define TCSETSF2 TCSETSF
#define termios2 termios
#endif

static int wtpfd = -1;

static inline void xtcdrain(int fd)
{
	if (ioctl(fd, TCSBRK, 1) < 0)
		die("Cannot tcdrain: %m");
}

static inline void xtcflush(int fd, int q)
{
	if (ioctl(fd, TCFLSH, q) < 0)
		die("Cannot tcflush: %m");
}

static inline void xtcgetattr2(int fd, struct termios2 *t)
{
	if (ioctl(fd, TCGETS2, t) < 0)
		die("Failed getting tty attrs: %m");
}

static inline void xtcsetattr2(int fd, const struct termios2 *t)
{
	if (ioctl(fd, TCSETS2, t) < 0)
		die("Failed setting tty attrs: %m");
}

static void cfmakeraw2(struct termios2 *t)
{
	t->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR |
			ICRNL | IXON);
	t->c_oflag &= ~OPOST;
	t->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	t->c_cflag &= ~(CSIZE | PARENB);
	t->c_cflag |= CS8;
}

static void xread(void *buf, size_t size)
{
	ssize_t res;
	size_t rd;

	rd = 0;
	while (rd < size) {
		res = read(wtpfd, buf + rd, size - rd);
		if (res <= 0)
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
	else if ((size_t)res < size)
		die("Cannot write %zu bytes: written only %zi", size, res);
}

static enum escape_state {
	STATE_ESCAPE,
	STATE_SEQ_ESCAPE,
	STATE_WRITE_CLEAR,
	STATE_WRITE_WTP,
} state;
#define state_store(i) __atomic_store_n(&state, (i), __ATOMIC_RELEASE)
#define state_load() __atomic_load_n(&state, __ATOMIC_ACQUIRE)

static void seq_write(const void *seq, size_t len)
{
	const useconds_t one_cycle = 1000 * 1000 * 10 / 115200;

	usleep(one_cycle);
	xwrite(seq, len);
	xtcdrain(wtpfd);
}

static void *seq_write_handler(void *ptr __attribute__((unused)))
{
	const u8 esc_seq[] = { 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	const u8 clr_seq[] = { 0x0d, 0x0d, 0x0d, 0x0d };
	const u8 wtp_seq[] = { 0x03, 'w', 't', 'p', '\r' };
	enum escape_state prev_state = state_load();

	while (1) {
		enum escape_state new_state = state_load();

		if (new_state != STATE_ESCAPE && prev_state == STATE_ESCAPE) {
			xtcflush(wtpfd, TCOFLUSH);
			xtcdrain(wtpfd);
		}

		switch (new_state) {
		case STATE_ESCAPE:
			xwrite(esc_seq, sizeof(esc_seq));
			break;
		case STATE_SEQ_ESCAPE:
			seq_write(esc_seq, sizeof(esc_seq));
			break;
		case STATE_WRITE_CLEAR:
			seq_write(clr_seq, sizeof(clr_seq));
			return NULL;
		case STATE_WRITE_WTP:
			seq_write(wtp_seq, sizeof(wtp_seq));
			return NULL;
		default:
			__builtin_unreachable();
		}

		prev_state = new_state;
	}
}

static void seq_write_thread_start(pthread_t *write_thread)
{
	int ret;

	ret = pthread_create(write_thread, NULL, seq_write_handler, NULL);
	if (ret) {
		errno = ret;
		die("pthread_create failed: %m");
	}
}

static void seq_write_thread_join(pthread_t write_thread)
{
	int ret;

	ret = pthread_join(write_thread, NULL);
	if (ret) {
		errno = ret;
		die("pthread_join failed: %m");
	}
}

static int is_all_zeros(const u8 *buf, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		if (buf[i])
			return 0;

	return 1;
}

/*
 * This works when escape sequence is needed to force UART mode but also when
 * BootROM console is enabled and "wtp" command is needed.
 */
void initwtp(int escape_seq)
{
	const u8 bootrom_prompt_reply[] = {
		'>', '>', 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	};
	pthread_t write_thread;
	struct termios2 opts;
	struct pollfd pfd;
	tcflag_t iflag;
	int ack_count;
	u8 buf[8192];
	int len, i;
	int done;
	int ret;

	if (!escape_seq) {
		/* only send wtp command */
		xwrite("\x03wtp\r", 5);
		xread(buf, 8);
		if (memcmp(buf, "!\r\nwtp\r\n", 8))
			die("Invalid reply for command wtp, try again");
		printf("Initialized WTP download mode\n\n");
		return;
	}

	if (!isatty(wtpfd))
		die("Cannot send escape sequence on non-tty file descriptor");

	/* set PARMRK to distinguish between zero byte and break condition */
	xtcgetattr2(wtpfd, &opts);
	iflag = opts.c_iflag;
	opts.c_iflag |= PARMRK;
	xtcsetattr2(wtpfd, &opts);

	printf("Sending escape sequence, please power up the device\n");
	seq_write_thread_start(&write_thread);

	pfd.fd = wtpfd;
	pfd.events = POLLIN;

	len = 0;
	ack_count = 0;
	done = 0;

	while (!done) {
		if (state == STATE_WRITE_CLEAR || state == STATE_WRITE_WTP) {
			pfd.revents = 0;
			ret = poll(&pfd, 1, 300);
			if (ret < 0)
				die("poll failed: %m");
			else if (!ret && state == STATE_WRITE_CLEAR)
				break;
		}

		ret = read(wtpfd, buf + len, sizeof(buf) - len);
		if (ret <= 0)
			die("read failed: %m");

		len += ret;

		switch (state) {
		case STATE_ESCAPE:
			if (buf[len - 1] == 0x3e) {
				state_store(STATE_SEQ_ESCAPE);
				printf("\e[0KReceived sync reply\n");
				printf("Sending escape sequence with delay\n");
			}
			__attribute__((__fallthrough__));

		case STATE_SEQ_ESCAPE:
			for (i = 8; i > 0; i--)
				if (len >= i && !memcmp(buf + len - i, bootrom_prompt_reply, i))
					break;

			if (i > 0) {
				if (i == 8 || (len - i >= 8 && !memcmp(buf + len - i - 8, bootrom_prompt_reply, 8))) {
					state_store(STATE_WRITE_WTP);
					printf("\e[0KDetected BootROM command prompt\n");
					printf("Sending wtp sequence\n");
					seq_write_thread_join(write_thread);
					len = 0;
					/* it is required to wait at least 0.5s */
					usleep(500000);
				} else {
					memmove(buf, buf + len - i, i);
					len = i;
				}
			} else {
				if (len >= 16) {
					if (is_all_zeros(buf + len - 16, 16)) {
						state_store(STATE_WRITE_CLEAR);
						printf("\e[0KReceived ack reply\n");
						printf("Sending clearbuf sequence\n");
						seq_write_thread_join(write_thread);
						ack_count = 0;
					} else if (buf[len - 1] != 0x3e) {
						state_store(STATE_ESCAPE);
						printf("\e[0KInvalid reply 0x%02x, try restarting again\r", buf[len - 1]);
						fflush(stdout);
					}
					len = 0;
				}
			}
			break;

		case STATE_WRITE_CLEAR:
			if (is_all_zeros(buf, len)) {
				/*
				 * if we received too much ack replies after
				 * first read (ack_count is non-zero), send
				 * clearbuf sequence again
				 */
				if (ack_count && ack_count + len > 1000) {
					seq_write_thread_start(&write_thread);
					seq_write_thread_join(write_thread);
					ack_count = 0;
				} else {
					ack_count += len;
				}
				len = 0;
			} else {
				state_store(STATE_ESCAPE);
				seq_write_thread_start(&write_thread);
				printf("\e[0KInvalid reply, try restarting again\r");
				fflush(stdout);
			}
			break;

		case STATE_WRITE_WTP:
			/* 4095 bytes is size of kernel tty buffer, drop data from beginning of buffer and read remaining data */
			if (len >= 4095) {
				memmove(buf, buf + len - 7, 7);
				len = 7;
			} else if (len >= 8) {
				if (!memcmp(buf + len - 8, "!\r\nwtp\r\n", 8)) {
					done = 1;
				} else {
					state_store(STATE_ESCAPE);
					seq_write_thread_start(&write_thread);
					printf("\e[0KInvalid reply 0x%02x, try restarting again\r", buf[len - 1]);
					fflush(stdout);
				}
			}
			break;

		default:
			__builtin_unreachable();
		}
	}

	printf("\e[0KInitialized UART download mode\n\n");

	/* restore previous iflag */
	xtcgetattr2(wtpfd, &opts);
	opts.c_iflag = iflag;
	xtcsetattr2(wtpfd, &opts);
}

void setwtpfd(const char *fdstr)
{
	char *end;
	int flags;

	wtpfd = strtol(fdstr, &end, 10);
	if (*end || wtpfd < 0)
		die("Wrong file descriptor %s", fdstr);

	flags = fcntl(wtpfd, F_GETFL);
	if (flags < 0 && errno == EBADF)
		die("Wrong file descriptor %s", fdstr);

	if (flags < 0)
		die("Could not get file descriptor flags: %m");

	if (flags & O_NONBLOCK) {
		/* set to blocking mode */
		if (fcntl(wtpfd, F_SETFL, flags & ~O_NONBLOCK))
			die("Unsetting O_NONBLOCK failed: %m");
	}
}

void openwtp(const char *path)
{
	struct termios2 opts;
	int flags;

	/* O_NONBLOCK is required to avoid hangs when CLOCAL is not set */
	wtpfd = open(path, O_RDWR | O_NONBLOCK | O_NOCTTY);

	if (wtpfd < 0)
		die("Cannot open %s: %m", path);

	memset(&opts, 0, sizeof(opts));
	xtcgetattr2(wtpfd, &opts);

	cfmakeraw2(&opts);
	opts.c_cflag |= CREAD | CLOCAL;
	opts.c_cflag &= ~(CSTOPB | HUPCL | CRTSCTS);
	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= B115200;
#ifdef IBSHIFT
	opts.c_cflag &= ~(CBAUD << IBSHIFT);
	opts.c_cflag |= B0 << IBSHIFT;
#endif
	opts.c_cc[VMIN] = 1;
	opts.c_cc[VTIME] = 0;

	xtcsetattr2(wtpfd, &opts);

	xtcgetattr2(wtpfd, &opts);
	if ((opts.c_cflag & CBAUD) != B115200)
		die("Baudrate 115200 not supported");
#ifdef IBSHIFT
	if (((opts.c_cflag >> IBSHIFT) & CBAUD) != B0)
		die("Baudrate 115200 not supported");
#endif

	xtcflush(wtpfd, TCIFLUSH);

	flags = fcntl(wtpfd, F_GETFL);
	if (flags < 0)
		die("Failure getting file descriptor flags: %m");

	/* unset O_NONBLOCK */
	if (fcntl(wtpfd, F_SETFL, flags & ~O_NONBLOCK))
		die("Unsetting O_NONBLOCK failed: %m");
}

void closewtp(void)
{
	if (wtpfd != -1)
		close(wtpfd);
	wtpfd = -1;
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
	size_t i, pos, printed = 0;
	u8 buf[ulen], last;
	int istty;

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
				printf("%.*s", (int)pos + 1, (char *)buf);
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
		fflush(stdout);
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
	_Bool eq, best_eq = 0;
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

static tcflag_t baudrate_to_cflag(unsigned int baudrate)
{
#define B(b) { B ## b, b }
	static const struct {
		tcflag_t cflag;
		unsigned int baudrate;
	} map[] = {
		B(50), B(75), B(110), B(134), B(150), B(200), B(300), B(600),
		B(1200), B(1800), B(2400), B(4800), B(9600), B(19200), B(38400),
		B(57600), B(115200), B(230400), B(460800), B(500000), B(576000),
		B(921600), B(1000000), B(1152000), B(1500000), B(2000000),
#ifdef B2500000
		/* non-SPARC architectures support these Bnnn constants */
		B(2500000), B(3000000), B(3500000), B(4000000)
#else
		/* SPARC architecture supports these Bnnn constants */
		B(76800), B(153600), B(307200), B(614400)
#endif
	};
#undef B
	size_t i;

	if (!baudrate)
		die("Baudrate 0 not valid");

	for (i = 0; i < sizeof(map)/sizeof(*map); i++)
		if (map[i].baudrate == baudrate)
			return map[i].cflag;

#ifdef BOTHER
	return BOTHER;
#else
	die("Baudrate %u not supported", baudrate);
#endif
}

static int
is_within_tolerance(unsigned int value, unsigned int reference,
		    unsigned int tolerance)
{
	return 100 * value >= reference * (100 - tolerance) &&
	       100 * value <= reference * (100 + tolerance);
}

void change_baudrate(unsigned int baudrate)
{
	struct termios2 opts = {};
	tcflag_t cflag_speed = baudrate_to_cflag(baudrate);

	xtcgetattr2(wtpfd, &opts);
	opts.c_cflag &= ~CBAUD;
	opts.c_cflag |= cflag_speed;
#ifdef IBSHIFT
	opts.c_cflag &= ~(CBAUD << IBSHIFT);
	opts.c_cflag |= B0 << IBSHIFT;
#endif
#ifdef BOTHER
	opts.c_ispeed = opts.c_ospeed = baudrate;
#endif
	xtcsetattr2(wtpfd, &opts);
	xtcgetattr2(wtpfd, &opts);
#ifndef BOTHER
	if ((opts.c_cflag & CBAUD) != cflag_speed)
		die("Baudrate %u not supported", baudrate);
# ifdef IBSHIFT
	if (((opts.c_cflag >> IBSHIFT) & CBAUD) != B0)
		die("Baudrate %u not supported", baudrate);
# endif
#else
	/* Check that set baudrate is in 3% tolerance */
	if (!is_within_tolerance(opts.c_ospeed, baudrate, 3) ||
	    !is_within_tolerance(opts.c_ispeed, baudrate, 3))
		die("Baudrate %u not supported", baudrate);
#endif
	usleep(10000);
	xtcflush(wtpfd, TCIFLUSH);
}

void try_change_baudrate(unsigned int baudrate)
{
	u8 buf[6] = "baud";
	int tbg_freq;
	u32 div, m;

	printf("Requesting baudrate change to %u baud\n", baudrate);

	if (!isatty(wtpfd))
		die("File descriptor is not tty and does not support baudrate change");

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
		die("Failed computing A3720 UART parameters for baudrate %i!",
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
	u32 sent, tosend = 0;
	double start;
	int diff;
	int istty = isatty(STDOUT_FILENO);

	buf[0] = 0;
	sendcmd(0x27, 0, 0, 0, 1, buf, &resp);

	start = now();
	sent = 0;
	while (sent < img->size) {
		int eta;

		if ((fast && !sent) || !fast) {
			*(u32 *) buf = htole32(img->size - sent);

			sendcmd(0x2a, seq, 0, fast ? 4 : 0, 4, buf, &resp);
			if (resp.len != 4)
				die("DataHeader response length = %i != 4",
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

		val = strtoull((char *)buf + 2, &end, 16);

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
	printf("Board version: %lu\n", strtol((char *)buf, NULL, 16));

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

	in = isatty(STDIN_FILENO) ? STDIN_FILENO : -1;

	if (in >= 0) {
		memset(&otio, 0, sizeof(otio));
		xtcgetattr2(in, &otio);
		tio = otio;
		cfmakeraw2(&tio);
		xtcsetattr2(in, &tio);
		printf("\r\n[Type Ctrl-%c + %c to quit]\r\n\r\n",
		       quit[0] | 0100, quit[1]);
	}

	s = 0;

	do {
		fd_set rfds;
		int nfds = 0;

		FD_ZERO(&rfds);
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

		if (in >= 0 && FD_ISSET(in, &rfds)) {
			if (uart_terminal_pipe(in, wtpfd, quit, &s))
				break;
		}
	} while (quit[s] != 0);

	if (in >= 0)
		xtcsetattr2(in, &otio);

	printf("\n");
}
