; tests if values written to 0x60000000 - 0x60000020 can be read afterwards
;
; first writes 0x5a5a5a5a, then counts how many times were these values read correctly
; then writes 0xaa55a5a5, then counts how many times were these values read correctly
; in total 16 writes and 16 reads, if at least 13 reads were correct, succeeds
;
; on success SM0 = 1, on failure SM0 = 0
; uses SM0 to SM4

LABEL TEST
LOAD_SM_VAL SM4 0x5a5a5a5a
LOAD_SM_VAL SM3 0

LABEL TES0
MOV_SM_SM SM1 SM4

LOAD_SM_VAL SM0 0x60000000
LABEL TES1
STORE_SM_TO_ADDR_IN_SM SM1 SM0
ADD_SM_VAL SM0 4
TEST_SM_AND_BRANCH SM0 0xffffffff 0x60000020 < TES1
DELAY 1

LOAD_SM_VAL SM0 0x60000000
LABEL TES2
LOAD_SM_FROM_ADDR_IN_SM SM2 SM0
SUB_SM_SM SM2 SM1
TEST_SM_AND_BRANCH SM2 0xffffffff 0 != TES3
ADD_SM_VAL SM3 1
LABEL TES3
ADD_SM_VAL SM0 4
TEST_SM_AND_BRANCH SM0 0xffffffff 0x60000020 < TES2

TEST_SM_AND_BRANCH SM4 0xffffffff 0x5a5a5a5a != TES4
LOAD_SM_VAL SM4 0xaa55a5a5
BRANCH TES0
LABEL TES4

LOAD_SM_VAL SM0 1
TEST_SM_AND_BRANCH SM3 0xffffffff 12 > RET
LOAD_SM_VAL SM0 0

BRANCH RET
