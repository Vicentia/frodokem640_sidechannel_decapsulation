PARAMS_N = 640
PARAMS_NBAR = 8
PARAMS_LOGQ = 15

CRYPTO_CIPHERTEXTBYTES = 9720
BYTES_CIPHERTEXT_C1 = (PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) // 8
BYTES_CIPHERTEXT_C2 = (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) // 8

s_length = 16
SEED_A_length = 16
b_length = 9600
S_length = PARAMS_N * PARAMS_NBAR * 2
pkh = 16

SIZE_PK = 9616
SIZE_SK = 19888
SIZE_CT = 9720

REG_NAMES = [
    "r0", "r1", "r2", "r3",
    "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11",
    "r12", "sp", "lr", "pc",
]

REG_ALIAS = {
    "sb": "r9",
    "sl": "r10",
    "fp": "r11",
    "ip": "r12",
}
