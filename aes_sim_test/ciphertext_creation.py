import csv
import os

from parameters_initialisation import (
    BYTES_CIPHERTEXT_C1,
    BYTES_CIPHERTEXT_C2,
    CRYPTO_CIPHERTEXTBYTES,
    PARAMS_LOGQ,
    PARAMS_N,
    PARAMS_NBAR,
)
from stop_tracing import StopEmulation


def generate_base_ciphertext(ct_path):
    os.makedirs(os.path.dirname(ct_path), exist_ok=True)

    c1_random = os.urandom(BYTES_CIPHERTEXT_C1)
    c2 = bytes(BYTES_CIPHERTEXT_C2)
    salt = bytes(CRYPTO_CIPHERTEXTBYTES - BYTES_CIPHERTEXT_C1 - BYTES_CIPHERTEXT_C2)
    base_ct = c1_random + c2 + salt

    with open(ct_path, "wb") as f:
        f.write(base_ct)

    print(f"[INFO] Base ciphertext created at {ct_path}")
    return base_ct


def load_base_ciphertext(ct_path):
    if not os.path.exists(ct_path):
        return generate_base_ciphertext(ct_path)

    with open(ct_path, "rb") as f:
        ct = f.read()

    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] Ciphertext has wrong size: {len(ct)} != {CRYPTO_CIPHERTEXTBYTES}"
        )

    print(f"[INFO] Loaded base ciphertext from {ct_path}")
    return ct


def zero_bits(data, start, D):
    for bit in range(start, start + D):
        byte_pos = bit >> 3
        bit_pos = 7 - (bit & 7)
        data[byte_pos] &= ~(1 << bit_pos)


def modify_ciphertext_c1_from_base(base_ct, index):
    c1_random = base_ct[:BYTES_CIPHERTEXT_C1]
    c1_altered = bytearray(c1_random)

    if index > PARAMS_N:
        print("[INFO] The index is bigger than the number of columns of Bp, ciphertext stays the same")
    else:
        for ind in range(index):
            for i in range(PARAMS_NBAR):
                start = (i * PARAMS_N + ind) * PARAMS_LOGQ
                zero_bits(c1_altered, start, PARAMS_LOGQ)

    c2 = base_ct[BYTES_CIPHERTEXT_C1: BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2]
    salt = base_ct[BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2:]

    return bytes(c1_random), bytes(c1_altered) + c2 + salt


def unpack_c1(c1):
    values = []

    for i in range(PARAMS_NBAR):
        for j in range(PARAMS_N):
            start = (i * PARAMS_N + j) * PARAMS_LOGQ
            val = 0

            for bit in range(PARAMS_LOGQ):
                byte_pos = (start + bit) >> 3
                bit_pos = 7 - ((start + bit) & 7)
                val |= ((c1[byte_pos] >> bit_pos) & 1) << (PARAMS_LOGQ - 1 - bit)

            values.append(val)

    return values


def test_modify_ciphertext_c1(index, c1_random=None, ct=None):
    if c1_random is None or ct is None:
        raise ValueError("c1_random and ct must be provided")

    c1_altered = ct[:BYTES_CIPHERTEXT_C1]

    random_vals = unpack_c1(c1_random)
    altered_vals = unpack_c1(c1_altered)

    # Test 1.1 - check the size of c1
    if len(c1_random) != BYTES_CIPHERTEXT_C1:
        raise StopEmulation(
            f"[ERROR] The size of c1_random {len(c1_random)} does not match expected {BYTES_CIPHERTEXT_C1}"
        )
    # Test 1.2 - check the size of ct   
    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] The size of ct {len(ct)} does not match expected {CRYPTO_CIPHERTEXTBYTES}"
        )
    # Test 2 - check that the first index columns are zeroed and the others are unchanged
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            val = altered_vals[i * PARAMS_N + ind]
            if val != 0:
                raise StopEmulation(
                    f"[ERROR] The first {index} columns should be zeroed, "
                    f"but column {ind} row {i} is not zero: {val}"
                )
    # Test 3 - check that the columns after the index are unchanged
    for ind in range(index, PARAMS_N):
        for i in range(PARAMS_NBAR):
            if altered_vals[i * PARAMS_N + ind] != random_vals[i * PARAMS_N + ind]:
                raise StopEmulation(f"[ERROR] Column {ind} row {i} was changed unexpectedly")

    # Test 4 - check that the sum of all values is correct
    q = 1 << PARAMS_LOGQ
    total_sum = sum(random_vals) % q
    removed_sum = sum(
        random_vals[i * PARAMS_N + ind]
        for ind in range(index)
        for i in range(PARAMS_NBAR)
    ) % q
    new_sum = sum(altered_vals) % q
    expected = (total_sum - removed_sum) % q

    if new_sum != expected:
        raise StopEmulation(f"[ERROR] Sum check failed: {new_sum} != {expected}")

    print(f"[TEST PASSED] Ciphertext modification for index {index} is correct")


def save_B_from_ciphertext_csv(ct, B_path):
    c1 = ct[:BYTES_CIPHERTEXT_C1]
    B_values = unpack_c1(c1)
    os.makedirs(os.path.dirname(B_path), exist_ok=True)
    with open(B_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["row"] + [f"B_col_{j}" for j in range(PARAMS_N)])

        for i in range(PARAMS_NBAR):
            row = []
            for j in range(PARAMS_N):
                row.append(B_values[i * PARAMS_N + j])
            writer.writerow([i] + row)
    print(f"B matrix saved as CSV to {B_path}")
