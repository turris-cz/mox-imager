// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <ctype.h>
#include "utils.h"

struct insn {
	char *name;
	u8 code;
	u8 args;
	char *help;
};

#define DECL_INSN(n,c,h)	\
	{			\
		.name = #n,	\
		.code = c,	\
		.help = h,	\
	},

static struct insn insns[] = {
	DECL_INSN(NOP,				0,	"no operation")
	DECL_INSN(WRITE,			1,	"*%x = %x")
	DECL_INSN(READ,				2,	"val = *%x (%d times)")
	DECL_INSN(DELAY,			3,	"delay %d us")
	DECL_INSN(WAIT_FOR_BIT_SET,		4,	"wait till *%x has bits %x set (at most %d ms)")
	DECL_INSN(WAIT_FOR_BIT_CLEAR,		5,	"wait till *%x has bits %x cleared (at most %d ms)")
	DECL_INSN(AND_VAL,			6,	"*%x &= %x")
	DECL_INSN(OR_VAL,			7,	"*%x |= %x")
	DECL_INSN(SET_BITFIELD,			8,	"in *%x with mask %x set bits %x")
	DECL_INSN(WAIT_FOR_BIT_PATTERN,		9,	"wait till *%x & %x == %x (at most %d ms)")
	DECL_INSN(TEST_IF_ZERO_AND_SET,		10,	"if ((*%x & %x) == 0) in *%x with mask %x set bits %x")
	DECL_INSN(TEST_IF_NOT_ZERO_AND_SET,	11,	"if ((*%x & %x) != 0) in *%x with mask %x set bits %x")
	DECL_INSN(LOAD_SM_ADDR,			12,	"SM[%d] = *%x")
	DECL_INSN(LOAD_SM_VAL,			13,	"SM[%d] = %x")
	DECL_INSN(STORE_SM_ADDR,		14,	"*%2x = SM[%1d]")
	DECL_INSN(MOV_SM_SM,			15,	"SM[%d] = SM[%d]")
	DECL_INSN(RSHIFT_SM_VAL,		16,	"SM[%d] >>= %d")
	DECL_INSN(LSHIFT_SM_VAL,		17,	"SM[%d] <<= %d")
	DECL_INSN(AND_SM_VAL,			18,	"SM[%d] &= %x")
	DECL_INSN(OR_SM_VAL,			19,	"SM[%d] |= %x")
	DECL_INSN(OR_SM_SM,			20,	"SM[%d] |= SM[%d]")
	DECL_INSN(AND_SM_SM,			21,	"SM[%d] &= SM[%d]")
	DECL_INSN(TEST_SM_IF_ZERO_AND_SET,	22,	"if ((SM[%d] & %x) == 0) in SM[%d] with mask %x set bits %x")
	DECL_INSN(TEST_SM_IF_NOT_ZERO_AND_SET,	23,	"if ((SM[%d] & %x) != 0) in SM[%d] with mask %x set bits %x")
	DECL_INSN(LABEL,			24,	"label %s")
	DECL_INSN(TEST_ADDR_AND_BRANCH,		25,	"if ((*%1x & %2x) %4o %3x) goto %5s")
	DECL_INSN(TEST_SM_AND_BRANCH,		26,	"if ((SM[%1d] & %2x) %4o %3x) goto %5s")
	DECL_INSN(BRANCH,			27,	"goto %s")
	DECL_INSN(END,				28,	"end")
	DECL_INSN(ADD_SM_VAL,			29,	"SM[%d] += %d")
	DECL_INSN(ADD_SM_SM,			30,	"SM[%d] += SM[%d]")
	DECL_INSN(SUB_SM_VAL,			31,	"SM[%d] -= %d")
	DECL_INSN(SUB_SM_SM,			32,	"SM[%d] -= SM[%d]")
	DECL_INSN(LOAD_SM_FROM_ADDR_IN_SM,	33,	"SM[%d] = *SM[%d]")
	DECL_INSN(STORE_SM_TO_ADDR_IN_SM,	34,	"*SM[%2d] = SM[%1d]")
	{ NULL, 0, 0, NULL }
};

struct op {
	u8 code;
	char repr[3];
};

static struct op ops[] = {
	{ 1,	"==" },
	{ 2,	"!=" },
	{ 3,	"<" },
	{ 4,	"<=" },
	{ 5,	">" },
	{ 6,	">=" },
	{ 0,	"" },
};

static struct insn *find_insn(u32 code)
{
	int i;

	for (i = 0; insns[i].name; ++i)
		if (insns[i].code == code)
			return &insns[i];

	return NULL;
}

static struct op *find_op(u32 code)
{
	int i;

	for (i = 0; ops[i].code; ++i)
		if (ops[i].code == code)
			return &ops[i];

	return NULL;
}

static u8 count_args(const char *help)
{
	u8 res = 0, max = 0;

	while (*help) {
		if (*help++ == '%') {
			++res;
			if (*help >= '1' && *help <= '9') {
				if (*help - '0' > max)
					max = *help - '0';
				++help;
				continue;
			}
		}
	}

	return max ? max : res;
}

static __attribute__((constructor)) void insns_init(void)
{
	struct insn *insn;

	for (insn = insns; insn->name; ++insn)
		insn->args = count_args(insn->help);
}

static void disasm(const char *lineprefix, struct insn *insn, const u32 *params, int args, size_t pos)
{
	char buf[128];
	int len = 0, idx = 1, i;
	char *p = insn->help;
	struct op *op;

	if (lineprefix) {
		printf("%s%-27s", lineprefix, insn->name);
		for (i = 1; i <= args; ++i)
			printf(" 0x%08X", params[i]);
		for (; i <= 5; ++i)
			printf("           ");
		printf(" # ");
	}

	while (*p) {
		if (*p != '%') {
			buf[len++] = *p++;
			continue;
		}

		++p;
		if (*p >= '1' && *p <= '5') {
			idx = *p - '0';
			++p;
		}

		switch (*p) {
		case 'x':
			len += sprintf(buf + len, "0x%08X", params[idx]);
			break;
		case 'd':
			len += sprintf(buf + len, "%d", params[idx]);
			break;
		case 's':
			len += sprintf(buf + len, "%s", id2name(htobe32(params[idx])));
			break;
		case 'o':
			op = find_op(params[idx]);
			if (!op)
				die("Unrecognized operation %u for instruction %s at position %u (+%d)", params[idx], insn->name, pos, idx);
			len += sprintf(buf + len, "%s", op->repr);
			break;
		default:
			die("Unrecognized specifier %%%c", *p);
		}
		++p;
		++idx;
	}
	buf[len++] = '\0';

	if (lineprefix)
		printf("%s\n", buf);
}

int disassemble(const char *lineprefix, const u32 *input, size_t len)
{
	size_t pos = 0;
	int res = 0;

	while (len > 0) {
		struct insn *insn = find_insn(input[0]);

		if (!insn)
			die("Unrecognized instruction with code %d at position %u", input[0], pos);

		if (len - 1 < insn->args)
			die("Instruction %d (%s) at position %u has too few arguments (%d, needs %d)", input[0], insn->name, pos, len - 1, insn->args);

		disasm(lineprefix, insn, input, insn->args, pos);

		input += insn->args + 1;
		pos += insn->args + 1;
		len -= insn->args + 1;
		++res;
	}

	return res;
}

#ifdef GPP_COMPILER
static struct insn *find_insn_by_name(const char *name, size_t len)
{
	struct insn *insn;

	for (insn = insns; insn->name; ++insn)
		if (!strncasecmp(name, insn->name, len) && !insn->name[len])
			return insn;

	return NULL;
}

static void parse_op(u32 *op, const char **pp, const char *file, int line)
{
	const char *p = *pp;

	if (!*p)
		goto err;

	if (p[1] == '=') {
		*pp += 2;
		if (*p == '=')
			*op = 1;
		else if (*p == '!')
			*op = 2;
		else if (*p == '<')
			*op = 4;
		else if (*p == '>')
			*op = 6;
		else
			goto err;
	} else {
		*pp += 1;
		if (*p == '<')
			*op = 3;
		else if (*p == '>')
			*op = 5;
		else
			goto err;
	}

	return;
err:
	die("Cannot parse operator near \"%s\" (%s:%i)", *pp, file, line);
}

static void parse_label(u32 *lbl, const char **pp, const char *file, int line)
{
	const char *p = *pp;

	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		char *end;
		u64 x;

		p += 2;
		x = strtoull(p, &end, 16);
		if (end - p > 8)
			goto err;

		*lbl = x;
		*pp = end;
	} else {
		size_t i, len;

		len = strspn(p, "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_0123456789");
		if (!len || len > 4)
			goto err;

		*lbl = 0;
		for (i = 0; i < len; ++i) {
			*lbl <<= 8;
			*lbl |= p[len - i - 1];
		}

		*pp = p + len;
	}

	return;
err:
	die("Cannot parse label near \"%s\" (%s:%i)", *pp, file, line);
}

static const char *skip_spaces(const char *p)
{
	while (isspace(*p))
		++p;
	return p;
}

static int assemble_insn(u32 *out, const char *cmd, const char *file, int line)
{
	const char *p = cmd;
	struct insn *insn;
	int arg;
	size_t len;

	p = skip_spaces(p);
	if (*p == '\0' || *p == '\n')
		return 0;

	len = strspn(p, "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_");
	if (!len)
		die("Unrecognized token in command \"%s\" (%s:%i)", cmd, file, line);

	insn = find_insn_by_name(p, len);
	if (!insn)
		die("Unknown instruction \"%.*s\" (%s:%i)", (int)len, p, file, line);

	p += len;
	p = skip_spaces(p);

	if (*p == ':')
		p = skip_spaces(p + 1);

	out[0] = insn->code;

	for (arg = 1; arg < insn->args + 1; ++arg) {
		if (insn->code == 24 || insn->code == 27) {
			parse_label(&out[arg], &p, file, line);
		} else if ((insn->code == 25 || insn->code == 26) && (arg == 4 || arg == 5)) {
			if (arg == 4)
				parse_op(&out[arg], &p, file, line);
			if (arg == 5)
				parse_label(&out[arg], &p, file, line);
		} else if ((p[0] == 'l' || p[0] == 'L') &&
			   (p[1] == 'b' || p[1] == 'B') &&
			   (p[2] == 'l' || p[2] == 'L')) {
			p += 3;
			parse_label(&out[arg], &p, file, line);
		} else {
			char *end;
			u64 x;

			if ((p[0] == 's' || p[0] == 'S') && (p[1] == 'm' || p[1] == 'M'))
				p += 2;

			x = strtoull(p, &end, 0);
			if (x > 0xffffffff)
				die("Constant too big in command \"%s\" (%s:%i)", cmd, file, line);

			out[arg] = x;
			p = end;
		}

		if (*p == '\0' || *p == '\n') {
			++arg;
			break;
		}

		if (!isspace(*p))
			die("Unrecognized token in command \"%s\" (%s:%i)", cmd, file, line);

		p = skip_spaces(p);
	}

	if (arg < insn->args + 1)
		die("Too few arguments (%i < %i) in command \"%s\" (%s:%i)", arg - 1, insn->args, cmd, file, line);

	if (*p != '\0' & *p != '\n')
		die("Unrecognized token in command \"%s\" (%s:%i)", cmd, file, line);

	return arg;
}

static int parse_src_pos(const char *p, char **cur_file, int *line)
{
	long num;
	char *end;

	if (p[0] != '#' || p[1] != ' ')
		return -1;

	p += 2;
	num = strtol(p, &end, 10);

	if (p == end || *end != ' ')
		return -1;

	p = end + 1;
	if (*p != '"')
		return -1;

	++p;
	end = strchr(p, '"');
	if (!end)
		return -1;

	free(*cur_file);
	*cur_file = xstrndup(p, end - p);
	*line = num;

	return 0;
}

int assemble(u32 **out, FILE *fp, const char *file)
{
	int outlen, outsize, linenum;
	char *line, *cur_file;
	ssize_t rd;
	size_t n;

	outlen = 0;
	outsize = 64;
	*out = xmalloc(sizeof(u32) * outsize);

	line = NULL;
	n = 0;
	cur_file = xstrdup(file);
	linenum = 1;

	while ((rd = getline(&line, &n, fp) != -1)) {
		/* one line can contain multiple commands, separated by & */
		char *cmd, *semicolon;

		if (!parse_src_pos(line, &cur_file, &linenum))
			continue;

		/* ignore comments */
		semicolon = strchr(line, ';');
		if (semicolon)
			*semicolon = '\0';

		for (cmd = strtok(line, "&"); cmd; cmd = strtok(NULL, "&")) {
			int res;

			if (outlen + 6 > outsize) {
				outsize *= 2;
				*out = xrealloc(*out, sizeof(u32) * outsize);
			}

			res = assemble_insn(*out + outlen, cmd, cur_file, linenum);
			outlen += res;
		}

		++linenum;
	}

	free(cur_file);

	*out = xrealloc(*out, sizeof(u32) * outlen);
	return outlen;
}
#endif /* GPP_COMPILER */
