import os

PARAMS_N               = 640
PARAMS_NBAR            = 8
PARAMS_LOGQ            = 15
CRYPTO_CIPHERTEXTBYTES = 9720
BYTES_CIPHERTEXT_C1    = (PARAMS_LOGQ * PARAMS_N    * PARAMS_NBAR) // 8  
BYTES_CIPHERTEXT_C2    = (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) // 8 

def zero_bits(data, start, D):
    for bit in range(start, start + D):
        byte_pos = bit >> 3
        bit_pos  = 7 - (bit & 7)
        data[byte_pos] &= ~(1 << bit_pos)

def modify_ciphertext_c1(index):
    c1_random = bytearray(os.urandom(BYTES_CIPHERTEXT_C1))
    c1_altered = bytearray(c1_random)  # copy before zeroing 
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            start = (i * PARAMS_N + ind) * PARAMS_LOGQ
            zero_bits(c1_altered, start, PARAMS_LOGQ)
    c2   = bytes(BYTES_CIPHERTEXT_C2)
    salt = bytes(CRYPTO_CIPHERTEXTBYTES - BYTES_CIPHERTEXT_C1 - BYTES_CIPHERTEXT_C2)
    return bytes(c1_random), bytes(c1_altered) + c2 + salt

def unpack_c1(c1):
    values = []
    for i in range(PARAMS_NBAR):
        for j in range(PARAMS_N):
            start = (i * PARAMS_N + j) * PARAMS_LOGQ
            val = 0
            for bit in range(PARAMS_LOGQ):
                byte_pos = (start + bit) >> 3
                bit_pos  = 7 - ((start + bit) & 7)
                val |= ((c1[byte_pos] >> bit_pos) & 1) << bit
            values.append(val)
    return values

def test_modify_ciphertext_c1(index):
    c1_random, ct = modify_ciphertext_c1(index)
    c1_altered = ct[:BYTES_CIPHERTEXT_C1]

    random_vals  = unpack_c1(c1_random)
    altered_vals = unpack_c1(c1_altered)

    # Test 1: zeroed columns are actually zero
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            val = altered_vals[i * PARAMS_N + ind]
            assert val == 0, f"Column {ind} row {i} not zero: {val}"

    # Test 2: non-zeroed columns are unchanged
    for ind in range(index, PARAMS_N):
        for i in range(PARAMS_NBAR):
            assert altered_vals[i * PARAMS_N + ind] == random_vals[i * PARAMS_N + ind], \
                f"Column {ind} row {i} was changed unexpectedly"

    # Test 3: total_sum - removed_sum == new_sum
    q = 1 << PARAMS_LOGQ
    total_sum   = sum(random_vals) % q
    removed_sum = sum(random_vals[i * PARAMS_N + ind]
                      for ind in range(index)
                      for i in range(PARAMS_NBAR)) % q
    new_sum     = sum(altered_vals) % q
    expected    = (total_sum - removed_sum) % q
    assert new_sum == expected, f"Sum check failed: {new_sum} != {expected}"
    print(f"index={index}: total={total_sum}, removed={removed_sum}, new={new_sum}")

if __name__ == '__main__':
    for idx in range(PARAMS_N):
        test_modify_ciphertext_c1(idx)
    print("All tests passed!")