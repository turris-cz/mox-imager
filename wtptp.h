/* SPDX-License-Identifier: Beerware */
/*
 * 2018 by Marek Behun <marek.behun@nic.cz>
 */

#ifndef _WTPTP_H_
#define _WTPTP_H_

#include "utils.h"
#include "images.h"

typedef struct {
	u8 cmd;
	u8 seq;
	u8 cid;
	u8 status;
	u8 flags;
	u8 len;
	u8 data[255];
} resp_t;

extern void setwtpfd(const char *fdstr);
extern void openwtp(const char *path);
extern void initwtp(int send_escape);
extern void closewtp(void);
extern void change_baudrate(int baudrate);
extern void try_change_baudrate(int baudrate);
extern u32 selectimage(void);
extern void sendimage(image_t *img, int fast);
extern void uart_otp_read(void);
extern void uart_deploy(void);
extern void uart_terminal(void);

#endif /* _WTPTP_H_ */
