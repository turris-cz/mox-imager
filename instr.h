/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _INSTR_H_
#define _INSTR_H_

#include <stdio.h>
#include "utils.h"

extern int disassemble(const char *lineprefix, const u32 *input, size_t len);
extern int assemble(u32 **out, FILE *fp, const char *file);

#endif /* _INSTR_H_ */
