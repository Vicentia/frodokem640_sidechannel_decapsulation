#!/usr/bin/env python3

import os
import csv
import sys
import argparse
import traceback

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

# Parameters for FrodoKEM-640
PARAMS_N               = 640
PARAMS_NBAR            = 8
PARAMS_LOGQ            = 15
CRYPTO_CIPHERTEXTBYTES = 9720
BYTES_CIPHERTEXT_C1    = (PARAMS_LOGQ * PARAMS_N    * PARAMS_NBAR) // 8  
BYTES_CIPHERTEXT_C2    = (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) // 8 

# --------------------------GLOBAL VARIABLES------------------------------

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

ins_trace = []
reg_trace = []

#initialisation adresses: 
main_addr = None
trigger_high_addr = None
trigger_low_addr = None
skip = None

#adresses for the key generation 
kem_keypair_addr = None
g_pk_addr = None
g_sk_addr = None
g_keypair_done_addr = None
# g_pk_check_addr = None
# g_sk_check_addr = None

#adress for the ciphertext in the encapsulation/decapsulation function
g_ct_addr = None
crypto_kem_dec_addr = None 

hit_main = False
hit_kem_keypair = False
hit_crypto_kem_dec = False 
hit_trigger_high = False
hit_trigger_low = False

trace_started = False
trace_saved = False

address_PK = None
address_SK = None
address_CT = None 

SIZE_PK = 9616
SIZE_SK = 19888
SIZE_CT = 9720 

instr_counter = 0

fault_index = 0
current_result_dir = None
current_traces_dir = None

REG_NAMES = [
    'r0', 'r1', 'r2', 'r3',
    'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11',
    'r12', 'sp', 'lr', 'pc'
]
#---------------------HELPERS FOR CIPHERTEXT------------------------------


def reset_globals():
    global hit_main, hit_kem_keypair, hit_crypto_kem_dec
    global hit_trigger_high, hit_trigger_low
    global trace_started, trace_saved, instr_counter
    global address_PK, address_SK
    global ins_trace, reg_trace

    hit_main = False
    hit_kem_keypair = False
    hit_crypto_kem_dec = False
    hit_trigger_high = False
    hit_trigger_low = False
    trace_started = False
    trace_saved = False
    instr_counter = 0
    address_PK = None
    address_SK = None
    ins_trace.clear()
    reg_trace.clear()

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

def test_modify_ciphertext_c1(index, c1_random=None, ct=None):
    if c1_random is None or ct is None:
        c1_random, ct = modify_ciphertext_c1(index)
    c1_altered = ct[:BYTES_CIPHERTEXT_C1]

    random_vals  = unpack_c1(c1_random)
    altered_vals = unpack_c1(c1_altered)

    # Test 0.1: check lengths
    if len(c1_random) != BYTES_CIPHERTEXT_C1:
        raise StopEmulation(f"[ERROR] The size of c1_random {len(c1_random)} does not match expected {BYTES_CIPHERTEXT_C1}")
    # Test 0.2: check lengths
    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(f"[ERROR] The size of ct {len(ct)} does not match expected {CRYPTO_CIPHERTEXTBYTES}")

    # Test 1: zeroed columns are actually zero
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            val = altered_vals[i * PARAMS_N + ind]
            if val != 0:
                raise StopEmulation(f"[ERROR] The first {fault_index} columns should be zeroed, but column {ind} row {i} is not zero: {val}")

    # Test 2: non-zeroed columns are unchanged
    for ind in range(index, PARAMS_N):
        for i in range(PARAMS_NBAR):
            if altered_vals[i * PARAMS_N + ind] != random_vals[i * PARAMS_N + ind]:
                raise StopEmulation(f"[ERROR] Column {ind} row {i} was changed unexpectedly")

    # Test 3: total_sum - removed_sum == new_sum
    q = 1 << PARAMS_LOGQ
    total_sum   = sum(random_vals) % q
    removed_sum = sum(random_vals[i * PARAMS_N + ind]
                      for ind in range(index)
                      for i in range(PARAMS_NBAR)) % q
    new_sum     = sum(altered_vals) % q
    expected    = (total_sum - removed_sum) % q
    if new_sum != expected:
        raise StopEmulation(f"[ERROR] Sum check failed: {new_sum} != {expected}")
    
    print(f"[TEST PASSED] Ciphertext modification for index {index} is correct")

#----------------------HELPERS FOR EMULATOR------------------------------
def normalize_addr(addr):
    if addr is None:
        return None
    return addr - 1 if (addr & 1) else addr


def get_label_address(elf_file, function_name):
    print(f"Looking for symbol: {function_name}")
    with open(elf_file, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == '.symtab':
                for symbol in section.iter_symbols():
                    if symbol.name == function_name:
                        addr = symbol['st_value']
                        print(f"Found {function_name} at {hex(addr)}")
                        return addr
    print(f"Symbol not found: {function_name}")
    return None


def disasm(ql, address):
    bytecode = ql.mem.read(address, 4)
    for insn in md.disasm(bytecode, address):
        return [insn.mnemonic, insn.op_str]
    return ["<unknown>", ""]


def save_csv(file_name):
    global trace_saved

    if trace_saved:
        return

    print(f"Saving trace to {file_name}")
    print(f"Trace length: {len(ins_trace)} instructions")

    with open(file_name, "w", newline="") as csvfile:
        writer_csv = csv.writer(csvfile)
        writer_csv.writerow([
            'pc', 'instruction', 'operands',
            'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
        ])

        for ins_info, regs in zip(ins_trace, reg_trace):
            regs_hex = [hex(x) for x in regs]
            writer_csv.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)

    trace_saved = True
    print("Trace saved")


def buffers(ql, results_dir):
    os.makedirs(results_dir, exist_ok=True)
    #The path for pk and sk should be all teh time the same because they are not changing with the fault index
    pk_path = f"{output_dir}/pk.bin"
    sk_path = f"{output_dir}/sk.bin"

    if g_pk_addr is not None:
        pk = ql.mem.read(g_pk_addr, SIZE_PK)
        with open(f"{pk_path}", "wb") as f:
            f.write(pk)
        print("PK saved")

    if g_sk_addr is not None:
        sk = ql.mem.read(g_sk_addr, SIZE_SK)
        with open(f"{sk_path}", "wb") as f:
            f.write(sk)
        print("SK saved")

    if g_ct_addr is not None:
        ct = ql.mem.read(g_ct_addr, SIZE_CT)
        with open(f"{results_dir}/ct.bin", "wb") as f:
            f.write(ct)
        print("CT saved")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")

    # if g_pk_check_addr is not None:
    #     pk_check = int.from_bytes(ql.mem.read(g_pk_check_addr, 4), "little")
    #     print(f"g_pk_check = 0x{pk_check:08x} ({pk_check})")

    # if g_sk_check_addr is not None:
    #     sk_check = int.from_bytes(ql.mem.read(g_sk_check_addr, 4), "little")
    #     print(f"g_sk_check = 0x{sk_check:08x} ({sk_check})")


class StopEmulation(Exception):
    pass


# Hooks
def full_tracing(ql: Qiling, address: int, size: int) -> None:
    global hit_main, hit_kem_keypair, hit_crypto_kem_dec
    global hit_trigger_high, hit_trigger_low
    global trace_started, address_PK, address_SK
    global instr_counter
    global skip
    global fault_index, current_result_dir, current_traces_dir

    instr_counter += 1

    if address == skip:
        ql.arch.regs.write('pc', ql.arch.regs.read('lr'))
        return

    ins, arg = disasm(ql, address)

    if instr_counter % 100000 == 0:
        print(
            f"[PROGRESS] instr={instr_counter} "
            f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
            f"lr={hex(ql.arch.regs.read('lr'))} "
            f"ins={ins} {arg}"
        )

    if main_addr and address == main_addr and not hit_main:
        hit_main = True
        print(f"main() hit at {hex(address)}")

    if kem_keypair_addr and address == kem_keypair_addr and not hit_kem_keypair:
        hit_kem_keypair = True
        address_PK = ql.arch.regs.read("r0")
        address_SK = ql.arch.regs.read("r1")
        print("----------------------------")
        print("Entering keypair generation:")
        print("----------------------------")
        print(f"pk ptr = {hex(address_PK)}")
        print(f"sk ptr = {hex(address_SK)}")
        print("----------------------------")

    if trigger_high_addr and address == trigger_high_addr and not hit_trigger_high:
        hit_trigger_high = True
        trace_started = True
        ins_trace.clear()
        reg_trace.clear()
        print(f"trigger_high() at {hex(address)}, so the trace starts")

    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not hit_crypto_kem_dec:
        hit_crypto_kem_dec = True
        ct_ptr = ql.arch.regs.read("r1")
        print("----------------------------")
        print("Entering decapsulation:")
        print("----------------------------")
        print(f"ct ptr = {hex(ct_ptr)}  (overwriting with altered ciphertext for indedx {fault_index})")

        c1_initial, altered_ct = modify_ciphertext_c1(fault_index)
        test_modify_ciphertext_c1(fault_index, c1_random=c1_initial, ct=altered_ct)
        ql.mem.write(ct_ptr, bytes(altered_ct))

    if trace_started:
        regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
        ins_trace.append([ins, arg])
        reg_trace.append(regs_now)

    if trigger_low_addr and address == trigger_low_addr and not hit_trigger_low:
        hit_trigger_low = True
        print(f"trigger_low() at {hex(address)}")
        print(f"The number of instructions collected: {len(ins_trace)}")
        buffers(ql, current_result_dir)
        save_csv(f"{current_traces_dir}/trace_{fault_index}.csv")

        print("Stop emulator")
        ql.emu_stop()
        raise StopEmulation("Trace captured, stopping emulator now")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fault-index", type=int, required=True)
    args = parser.parse_args()

    elf_file   = "firmware/simpleserial-frodo-CW308_STM32F4.elf"
    output_dir = "output_decapsulation"
    fault_index = args.fault_index
    trace_dir   = f"{output_dir}/TRACE_{fault_index}"

    print("Initialisation checks:")
    print("-----------------------")
    print("Starting script")
    print(f"ELF exists? {os.path.exists(elf_file)}")

    if not os.path.exists(elf_file):
        sys.exit(1)

    trigger_setup = get_label_address(elf_file, "trigger_setup")
    if trigger_setup:
        skip = normalize_addr(trigger_setup)

    main_addr = normalize_addr(get_label_address(elf_file, "main"))
    kem_keypair_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_keypair"))
    trigger_high_addr = normalize_addr(get_label_address(elf_file, "trigger_high"))
    crypto_kem_dec_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_dec"))
    trigger_low_addr = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr = get_label_address(elf_file, "g_pk")
    g_sk_addr = get_label_address(elf_file, "g_sk")
    g_ct_addr = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")
    # g_pk_check_addr = get_label_address(elf_file, "g_pk_check")
    # g_sk_check_addr = get_label_address(elf_file, "g_sk_check")

    stm32f407["PPB"]["type"] = "memory"

    current_result_dir = f"{trace_dir}/results_trace_{fault_index}"
    current_traces_dir = f"{trace_dir}/traces_{fault_index}"

    os.makedirs(current_result_dir, exist_ok=True)
    os.makedirs(current_traces_dir, exist_ok=True)

    reset_globals()
    # Initialize Qiling with the STM32F407 environment
    ql = Qiling(
        [elf_file],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f407,
        verbose=QL_VERBOSE.OFF
    )
    # Harware setup
    ql.hw.create("usart1")
    ql.hw.create("usart2")
    ql.hw.create("rcc")
    ql.hw.create("gpioa")

    try:
        # Map RNG memory region with read/write permissions (3) to avoid faults when the firmware tries to access it
        ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)
        ql.mem.write(0x50060800, b"\x00" * 0x400)
    except:
        pass

    ql.hook_code(full_tracing)
    print("-----------------------------")
    print("Running emulator...")
    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print("Error during execution:", e)
        traceback.print_exc()

    print("\nSummary:")
    print(f"main hit           = {hit_main}")
    print(f"keypair hit        = {hit_kem_keypair}")
    print(f"trigger_high hit   = {hit_trigger_high}")
    print(f"crypto_kem_dec hit = {hit_crypto_kem_dec}")
    print(f"trigger_low hit    = {hit_trigger_low}")
