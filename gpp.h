/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _GPP_H_
#define _GPP_H_

#include "utils.h"

extern void gpp_emit_start(void);
extern void *gpp_emit_get(u32 *size);
extern void gpp_emit_end(void);
extern void gpp_emit_otp_read(u32 *args);
extern void gpp_emit_otp_write(u32 *args);

#endif /* _GPP_H_ */
