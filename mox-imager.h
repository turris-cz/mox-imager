// SPDX-License-Identifier: Beerware
/*
 * 2024 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef MOX_IMAGER_H
#define MOX_IMAGER_H

#include "utils.h"

typedef struct {
	const char *tty, *fdstr, *output, *keyfile, *seed, *genkey_output,
		   *serial_number, *mac_address, *board, *board_version,
		   *otp_hash, *otp_read, *uart_terminal_kbs;
	_Bool sign, hash_a53_firmware, no_a53_firmware, deploy, deploy_no_board_info,
	      get_otp_hash, create_trusted_image, create_untrusted_image,
	      sign_untrusted_image, send_escape, genkey, gpp_disassemble,
	      terminal_on_exit;
	int baudrate;
	u32 image_bootfs;

	u32 timn_offset;
	u32 wtmi_offset;
	u32 obmi_offset;
	u32 obmi_max_size;
} args_t;

extern args_t args;

#endif /* MOX_IMAGER_H */
