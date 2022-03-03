;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; The following code handles baudrate change when booting over UART ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; skip if we aren't booting via UART
TEST_ADDR_AND_BRANCH UART_STS 0x200 0x200 != uEND

; disable UART RX interrupt (which is handled by BootROM)
AND_VAL UART_CTRL 0xFFFFFFEF

; receive at most 32 bytes on UART
LOAD_SM_VAL SM0 0x20
LOAD_SM_VAL SM1 0x1FFFF000
CALL(UArx, Ru_1)

MOV_SM_SM SM14 SM0

; if no bytes were received, skip
TEST_SM_AND_BRANCH SM0 0xFFFFFFFF 0 == uEND

; we are expecting preamble or baudrate change request, exactly 4 bytes
TEST_SM_AND_BRANCH SM0 0xFFFFFFFF 4 != uTXB

LOAD_SM_VAL SM0 0x1FFFF000
CALL(SERv, Ru_2)

; baud rate change starts with "baud"
TEST_SM_AND_BRANCH SM0 0xFFFFFFFF 0x64756162 == uCHG

; we received something different (possibly preamble). Retrasmit via
; loopback so that BootROM can handle this.
LABEL uTXB

; enable loopback
OR_VAL 0xC0013804 0x80000000
OR_VAL UART_CTRL 0x00001000

; trasmit
MOV_SM_SM SM0 SM14
LOAD_SM_VAL SM1 0x1FFFF000
CALL(UAtx, Ru_7)

;DELAY 1000000
; disable loopback
AND_VAL UART_CTRL 0xFFFFEFFF
AND_VAL 0xC0013804 0x7FFFFFFF

BRANCH uEND

LABEL uCHG

; retransmit "baud" back to notify that we are doing this
LOAD_SM_VAL SM0 0x4
LOAD_SM_VAL SM1 0x1FFFF000
CALL(UAtx, Ru_8)

; to compute baudrate generator parameters the host will need to know
; TBG-A-P clock frequency:
;   1. XTAL frequency (from divider of counter 2, set by BootROM)
LOAD_SM_ADDR SM0 0xC0008320
RSHIFT_SM_VAL SM0 8
STORE_SM_ADDR SM0 0x1FFFF000
;   2. TBG_A_FBDIV value
LOAD_SM_ADDR SM0 0xC0013204
RSHIFT_SM_VAL SM0 2
STORE_SM_ADDR SM0 0x1FFFF004
;   3. TBG_A_REFDIV value
LOAD_SM_ADDR SM0 0xC0013220
STORE_SM_ADDR SM0 0x1FFFF008
RSHIFT_SM_VAL SM0 8
AND_SM_VAL SM0 0x1
STORE_SM_ADDR SM0 0x1FFFF00C
;   4. TBG_A_VCODIV_SEL_DIFF value
LOAD_SM_ADDR SM0 0xC0013230
RSHIFT_SM_VAL SM0 1
AND_SM_VAL SM0 0x7
STORE_SM_ADDR SM0 0x1FFFF010

; trasmit these 5 bytes over UART
LOAD_SM_VAL SM0 0x5
LOAD_SM_VAL SM1 0x1FFFF000
CALL(UAtx, Ru_3)

; receive UART parameters
LOAD_SM_VAL SM0 0x6
LOAD_SM_VAL SM1 0x1FFFF000
CALL(UArx, Ru_4)

; a delay is required here
DELAY 100000

; we are expecting 6 bytes
TEST_SM_AND_BRANCH SM0 0xFFFFFFFF 6 != uEND

LOAD_SM_VAL SM0 0x1FFFF000
CALL(SERv, Ru_5)

AND_SM_VAL SM0 0x3FF
MOV_SM_SM SM14 SM0

LOAD_SM_VAL SM0 0x1FFFF008
CALL(SERv, Ru_6)

; finally do the procedure for baudrate change
OR_VAL UART_DISABLE 0xA0000000
OR_VAL UART_CTRL 0x00001000
OR_VAL UART_CTRL 0x0000C000
DELAY 100
WAIT_FOR_BIT_SET UART_STS 0x40 100
OR_VAL UART_CLK_CTRL 0x300000
OR_VAL UART_CLK_CTRL 0x80000
AND_VAL UART_CLK_CTRL 0xFFFC0000
LOAD_SM_ADDR SM1 UART_CLK_CTRL
OR_SM_VAL SM1 0x9000
OR_SM_SM SM1 SM14
STORE_SM_ADDR SM1 UART_CLK_CTRL
STORE_SM_ADDR SM0 UART_SAMPLER
AND_VAL UART_CLK_CTRL 0xFFCFFFFF
AND_VAL UART_CTRL 0xFFFFEFFF
AND_VAL UART_CTRL 0xFFFF3FFF
AND_VAL UART_DISABLE 0x5FFFFFFF
DELAY 1000

; reenable UART RX interrupt
LABEL uEND
OR_VAL UART_CTRL 0x10
