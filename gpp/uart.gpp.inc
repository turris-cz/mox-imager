#define UART_RX		0xC0012000
#define UART_TX		0xC0012004
#define UART_CTRL	0xC0012008
#define UART_STS	0xC001200C
#define UART_CLK_CTRL	0xC0012010
#define UART_SAMPLER	 0xC0012014

; serialize 4 bytes stored in 4 u32s starting at address SM0
; into one u32, returned in SM0
LABEL SERv

LOAD_SM_VAL SM3 0
LOAD_SM_VAL SM2 4
ADD_SM_VAL SM0 12

LABEL Ser1
LOAD_SM_FROM_ADDR_IN_SM SM1 SM0
AND_SM_VAL SM1 0xFF
LSHIFT_SM_VAL SM3 8
OR_SM_SM SM3 SM1
SUB_SM_VAL SM0 4
SUB_SM_VAL SM2 1
TEST_SM_AND_BRANCH SM2 3 0 > Ser1

MOV_SM_SM SM0 SM3

BRANCH RET

; read from UART SM0 bytes onto address SM1
;   address must be aligned to u32
;   each byte is stored into one u32
; returns:
;   SM0 = number of bytes read
LABEL UArx

; remaining = len
MOV_SM_SM SM2 SM0

; is there a byte within 200 ms?
DELAY 200000
TEST_ADDR_AND_BRANCH UART_STS 0x10 0x10 != endR

LABEL nxtR

DELAY 1000
TEST_ADDR_AND_BRANCH UART_STS 0x10 0x10 != endR

; read one byte
LOAD_SM_ADDR SM3 UART_RX
AND_SM_VAL SM3 0xFF

; store onto *addr
STORE_SM_TO_ADDR_IN_SM SM3 SM1

; addr += 4, remaining--
ADD_SM_VAL SM1 4
SUB_SM_VAL SM2 1

TEST_SM_AND_BRANCH SM2 0xFFFFFFFF 0 != nxtR

LABEL endR

; ret = len - remaining
SUB_SM_SM SM0 SM2

BRANCH RET



; write to UART SM0 bytes from address SM1
;   address must be aligned to u32
;   each byte is stored into one u32
LABEL UAtx

LABEL nxtT

LOAD_SM_FROM_ADDR_IN_SM SM2 SM1
AND_SM_VAL SM2 0xFF
STORE_SM_ADDR SM2 UART_TX
WAIT_FOR_BIT_SET UART_STS 0x20 1

; addr += 4, remaining--
ADD_SM_VAL SM1 4
SUB_SM_VAL SM0 1

TEST_SM_AND_BRANCH SM0 0xFFFFFFFF 0 != nxtT

BRANCH RET
