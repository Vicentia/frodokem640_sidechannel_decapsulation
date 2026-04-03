import os

from frodo_collect_traces import check_bp_logic

PARAMS_N    = 640
PARAMS_NBAR = 8
PARAMS_LOGQ = 15

# Extracted Bp 
def unpack_bp(bp_bytes):
    return [int.from_bytes(bp_bytes[i*2:(i+1)*2], 'little') for i in range(PARAMS_N * PARAMS_NBAR)]

def test_hook_check_bp(index):
    bp = [int.from_bytes(os.urandom(2), 'little') % (1 << PARAMS_LOGQ)
          for _ in range(PARAMS_N * PARAMS_NBAR)]
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            bp[i * PARAMS_N + ind] = 0
    bp_bytes = b''.join(v.to_bytes(2, 'little') for v in bp)
    result = check_bp_logic(bp_bytes, index)
    assert result, f"Test failed for index={index}"

if __name__ == '__main__':
    for idx in range(PARAMS_N):
        test_hook_check_bp(idx)
    print("All tests passed!")