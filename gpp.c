// SPDX-License-Identifier: Beerware
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include "utils.h"
#include "variadic-macro.h"

typedef u32 label_t;
typedef u32 sm32;

#define NOP				0
#define WRITE				1
#define READ				2
#define DELAY				3
#define WAIT_FOR_BIT_SET		4
#define WAIT_FOR_BIT_CLEAR		5
#define AND_VAL				6
#define OR_VAL				7
#define SET_BITFIELD			8
#define WAIT_FOR_BIT_PATTERN		9
#define TEST_IF_ZERO_AND_SET		10
#define TEST_IF_NOT_ZERO_AND_SET	11
#define LOAD_SM_ADDR			12
#define LOAD_SM_VAL			13
#define STORE_SM_ADDR			14
#define MOV_SM_SM			15
#define RSHIFT_SM_VAL			16
#define LSHIFT_SM_VAL			17
#define AND_SM_VAL			18
#define OR_SM_VAL			19
#define OR_SM_SM			20
#define AND_SM_SM			21
#define TEST_SM_IF_ZERO_AND_SET		22
#define TEST_SM_IF_NOT_ZERO_AND_SET	23
#define LABEL				24
#define TEST_ADDR_AND_BRANCH		25
#define TEST_SM_AND_BRANCH		26
#define BRANCH				27
#define END				28
#define ADD_SM_VAL			29
#define ADD_SM_SM			30
#define SUB_SM_VAL			31
#define SUB_SM_SM			32
#define LOAD_SM_FROM_ADDR_IN_SM		33
#define STORE_SM_TO_ADDR_IN_SM		34

#define OP_EQ			1
#define OP_NE			2
#define OP_LT			3
#define OP_LTE			4
#define OP_GT			5
#define OP_GTE			6

static const int instr_params[35] = {
	[NOP]				= 0,
	[WRITE]				= 2,
	[READ]				= 2,
	[DELAY]				= 1,
	[WAIT_FOR_BIT_SET]		= 3,
	[WAIT_FOR_BIT_CLEAR]		= 3,
	[AND_VAL]			= 2,
	[OR_VAL]			= 2,
	[SET_BITFIELD]			= 3,
	[WAIT_FOR_BIT_PATTERN]		= 4,
	[TEST_IF_ZERO_AND_SET]		= 5,
	[TEST_IF_NOT_ZERO_AND_SET]	= 5,
	[LOAD_SM_ADDR]			= 2,
	[LOAD_SM_VAL]			= 2,
	[STORE_SM_ADDR]			= 2,
	[MOV_SM_SM]			= 2,
	[RSHIFT_SM_VAL]			= 2,
	[LSHIFT_SM_VAL]			= 2,
	[AND_SM_VAL]			= 2,
	[OR_SM_VAL]			= 2,
	[OR_SM_SM]			= 2,
	[AND_SM_SM]			= 2,
	[TEST_SM_IF_ZERO_AND_SET]	= 5,
	[TEST_SM_IF_NOT_ZERO_AND_SET]	= 5,
	[LABEL]				= 1,
	[TEST_ADDR_AND_BRANCH]		= 5,
	[TEST_SM_AND_BRANCH]		= 5,
	[BRANCH]			= 1,
	[END]				= 0,
	[ADD_SM_VAL]			= 2,
	[ADD_SM_SM]			= 2,
	[SUB_SM_VAL]			= 2,
	[SUB_SM_SM]			= 2,
	[LOAD_SM_FROM_ADDR_IN_SM]	= 2,
	[STORE_SM_TO_ADDR_IN_SM]	= 2,
};

#define DEF_LABEL(lbl)	label_t lbl = get_label();
#define LABELS(...)	CALL_MACRO_FOR_EACH(DEF_LABEL, ##__VA_ARGS__)

#define DEF_VAR(var)	sm32 var __attribute__((cleanup(put_var))) = get_var();
#define VARS(...)	CALL_MACRO_FOR_EACH(DEF_VAR, ##__VA_ARGS__)

static inline label_t get_label(void)
{
	static label_t label = 1;
	return label++;
}

static sm32 _var;

static inline sm32 get_var(void)
{
	if (_var == 16)
		die("Error emitting TIM GPP1 code: too many variables used");

	return _var++;
}

static inline void put_var(sm32 *p)
{
	--_var;
}

static u32 *ip, *instrs;

void gpp_emit_start(void)
{
	ip = instrs = xmalloc(16384);
}

void *gpp_emit_get(u32 *size)
{
	*size = (void *) ip - (void *) instrs;

	return instrs;
}

void gpp_emit_end(void)
{
	free(instrs);
	instrs = ip = NULL;
}

static inline void emit(u32 id, ...)
{
	va_list ap;
	int i;

	*ip++ = htole32(id);

	va_start(ap, id);
	for (i = 0; i < instr_params[id]; ++i)
		*ip++ = htole32(va_arg(ap, u32));
	va_end(ap);
}

#define emit_putc(c)						\
	do {							\
		emit(WRITE, 0xc0012004, (u32) (c));		\
		emit(WAIT_FOR_BIT_SET, 0xc001200c, 0x20, 1);	\
	} while (0);

#define emit_print(str)					\
	do {						\
		int i;					\
		for (i = 0; i < strlen((str)); ++i)	\
			emit_putc((str)[i]);		\
	} while (0);

#define EFUSE_CTRL	0x40003430
#define EFUSE_RW	0x40003434
#define EFUSE_D0	0x40003438
#define EFUSE_D1	0x4000343c
#define EFUSE_AUX	0x40003440

#define EFUSE_RC(r,c)	((((r) & 0x3f) << 7) | ((c) & 0x7f))

static void emit_otp_read_row(sm32 row, sm32 low32, sm32 high32, sm32 locked)
{
	emit(WRITE, EFUSE_CTRL, 0x4);
	emit(DELAY, 1);
	emit(OR_VAL, EFUSE_CTRL, 0x8);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x7, 0x3);
	emit(LSHIFT_SM_VAL, row, 7);
	emit(STORE_SM_ADDR, row, EFUSE_RW);
	emit(RSHIFT_SM_VAL, row, 7);
	emit(DELAY, 1);
	emit(OR_VAL, EFUSE_CTRL, 0x100);
	emit(DELAY, 1);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x100, 0);
	emit(SET_BITFIELD, EFUSE_CTRL, 0x6, 0x4);
	emit(WAIT_FOR_BIT_SET, EFUSE_AUX, 0x80000000);
	emit(LOAD_SM_ADDR, low32, EFUSE_D0);
	emit(LOAD_SM_ADDR, high32, EFUSE_D1);
	emit(LOAD_SM_ADDR, locked, EFUSE_AUX);
	emit(RSHIFT_SM_VAL, locked, 4);
}

static void emit_print_sm(sm32 val)
{
	LABELS(next_bit, print_0, printed);
	VARS(mask, val_and_mask);

	emit(LOAD_SM_VAL, mask, 0x80000000);
	emit(LABEL, next_bit);
	emit(MOV_SM_SM, val_and_mask, val);
	emit(AND_SM_SM, val_and_mask, mask);
	emit(TEST_SM_AND_BRANCH, val_and_mask, 0xffffffff, 0, OP_EQ, print_0);
	emit_putc('U');
	emit(BRANCH, printed);
	emit(LABEL, print_0);
	emit_putc('?');
	emit(LABEL, printed);
	emit(RSHIFT_SM_VAL, mask, 1);
	emit(TEST_SM_AND_BRANCH, mask, 0xffffffff, 0, OP_NE, next_bit);
}

void gpp_emit_otp_read(void)
{
	LABELS(again, print_0, printed);
	VARS(row, low32, high32, locked);

	emit_print("OTP\r\n");
	emit(LOAD_SM_VAL, row, 0);
	emit(LABEL, again);
	emit_otp_read_row(row, low32, high32, locked);
	emit(TEST_SM_AND_BRANCH, locked, 1, 0, OP_EQ, print_0);
	emit_print("U ");
	emit(BRANCH, printed);
	emit(LABEL, print_0);
	emit_print("? ");
	emit(LABEL, printed);
	emit_print_sm(high32);
	emit_putc(' ');
	emit_print_sm(low32);
	emit_print("\r\n");
	emit(ADD_SM_VAL, row, 1);
	emit(TEST_SM_AND_BRANCH, row, 0xffffffff, 44, OP_NE, again);
}
