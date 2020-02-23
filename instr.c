// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include "utils.h"

struct insn {
	char *name;
	u8 code;
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
	DECL_INSN(SUB_SM_SM0,			32,	"SM[%d] -= SM[%d]")
	DECL_INSN(LOAD_SM_FROM_ADDR_IN_SM,	33,	"SM[%d] = *SM[%d]")
	DECL_INSN(STORE_SM_TO_ADDR_IN_SM,	34,	"*SM[%d] = SM[%d]")
	{ NULL, 0, NULL }
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

static int insn_args(const char *help)
{
	int res = 0;

	while (*help) {
		if (*help == '%')
			++res;
		++help;
	}

	return res;
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
		int args;

		if (!insn)
			die("Unrecognized instruction with code %d at position %u", input[0], pos);

		args = insn_args(insn->help);
		if (len - 1 < args)
			die("Instruction %d (%s) at position %u has too few arguments (%d, needs %d)", input[0], insn->name, pos, len - 1, args);

		disasm(lineprefix, insn, input, args, pos);

		input += args + 1;
		pos += args + 1;
		len -= args + 1;
		++res;
	}

	return res;
}
