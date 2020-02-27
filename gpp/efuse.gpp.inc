#define EFUSE_CTRL		0x40003430
#define EFUSE_RW		0x40003434
#define EFUSE_D0		0x40003438
#define EFUSE_D1		0x4000343c
#define EFUSE_AUX		0x40003440

; read eFuse row SM0, ECC row SM1, ECC position SM2
; returns:
;   SM0 = 0 if ok
;       = 1 if not read or ECC error
;   SM1 = 0 if not locked
;       = 1 if locked
;   SM2 = low word
;   SM3 = high word
LABEL eFus

TEST_SM_AND_BRANCH SM1 0x3f 0 == eFu1

; first read ECC row into shadow buffer
WRITE EFUSE_CTRL 0x4
DELAY 1
OR_VAL EFUSE_CTRL 0x8
SET_BITFIELD EFUSE_CTRL 0x7 0x3
LSHIFT_SM_VAL SM1 7
OR_SM_VAL SM1 0x80000000
STORE_SM_ADDR SM1 EFUSE_RW
RSHIFT_SM_VAL SM1 7
AND_SM_VAL SM1 0x3f
DELAY 1
OR_VAL EFUSE_CTRL 0x100
DELAY 1
SET_BITFIELD EFUSE_CTRL 0x100 0
WAIT_FOR_BIT_SET EFUSE_AUX 0x80000000 10
SET_BITFIELD EFUSE_CTRL 0x6 0x4

; now read requested row
LABEL eFu1
WRITE EFUSE_CTRL 0x4
DELAY 1
OR_VAL EFUSE_CTRL 0x8
SET_BITFIELD EFUSE_CTRL 0x7 0x3
LSHIFT_SM_VAL SM0 7
STORE_SM_ADDR SM0 EFUSE_RW
RSHIFT_SM_VAL SM0 7
LOAD_SM_ADDR SM3 EFUSE_CTRL
AND_SM_VAL SM2 0xf
LSHIFT_SM_VAL SM2 24
OR_SM_SM SM3 SM2
STORE_SM_ADDR SM3 EFUSE_CTRL
DELAY 1
OR_VAL EFUSE_CTRL 0x100
DELAY 1
SET_BITFIELD EFUSE_CTRL 0x100 0
WAIT_FOR_BIT_SET EFUSE_AUX 0x80000000 10
SET_BITFIELD EFUSE_CTRL 0x6 0x4

LOAD_SM_VAL SM0 1
; return if row was not read
TEST_ADDR_AND_BRANCH EFUSE_AUX 0x80000000 0x80000000 != RET
; return if ECC uncorrectible error
TEST_ADDR_AND_BRANCH EFUSE_AUX 0x00020000 0x00020000 == RET

LOAD_SM_VAL SM0 0
; read Lock bit into SM1
LOAD_SM_ADDR SM1 EFUSE_AUX
RSHIFT_SM_VAL SM1 4
AND_SM_VAL SM1 1

LOAD_SM_ADDR SM2 EFUSE_D0
LOAD_SM_ADDR SM3 EFUSE_D1

BRANCH RET