/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _INSTR_H_
#define _INSTR_H_

#include "utils.h"

extern void disassemble(const char *lineprefix, const u32 *input, size_t len);

#endif /* _INSTR_H_ */
