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

SIZE_PK = 9616
SIZE_SK = 19888
SIZE_CT = 9720

REG_NAMES = [
    'r0', 'r1', 'r2', 'r3',
    'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11',
    'r12', 'sp', 'lr', 'pc'
]

# -------------------------- PATH CONFIGURATION --------------------------

# ELF_FILE   = "firmware/simpleserial-frodo-CW308_STM32F4.elf"
# OUTPUT_DIR = "output_decapsulation_sequantial"
# OUTPUT_DIR_TRIM = "output_decapsulation_sequentially_TRIM"

# PK_PATH      = os.path.join(OUTPUT_DIR, "pk.bin")
# SK_PATH      = os.path.join(OUTPUT_DIR, "sk.bin")
# CT_BASE_PATH = os.path.join(OUTPUT_DIR, "ct_base.bin")

# -------------------------- GLOBAL VARIABLES ----------------------------

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

ins_trace = []
reg_trace = []

# initialization addresses
main_addr         = None
trigger_high_addr = None
trigger_low_addr  = None
skip              = None

# addresses for the key generation
kem_keypair_addr    = None
g_pk_addr           = None
g_sk_addr           = None
g_keypair_done_addr = None

# address for the ciphertext in the encapsulation/decapsulation function
g_ct_addr           = None
crypto_kem_dec_addr = None

hit_main           = False
hit_kem_keypair    = False
hit_crypto_kem_dec = False
hit_trigger_high   = False
hit_trigger_low    = False

trace_started = False
trace_saved   = False

address_PK = None
address_SK = None
address_CT = None

instr_counter = 0

fault_index        = 0
current_traces_dir = None

# Whether PK/SK have already been saved 
keypair_saved = False

def get_trace_dir(index):
    return os.path.join(output_dir, f"TRACE_{index}")

def get_trace_csv_path(index):
    return os.path.join(get_trace_dir(index), f"trace_{index}.csv")

def get_ct_modified_path(index):
    return os.path.join(get_trace_dir(index), f"ct_modified_{index}.bin")

# ---------------------- RESET --------------------
def reset_globals():
    global hit_main, hit_kem_keypair, hit_crypto_kem_dec
    global hit_trigger_high, hit_trigger_low
    global trace_started, trace_saved, instr_counter
    global address_PK, address_SK, address_CT
    global ins_trace, reg_trace

    hit_main           = False
    hit_kem_keypair    = False
    hit_crypto_kem_dec = False
    hit_trigger_high   = False
    hit_trigger_low    = False
    trace_started      = False
    trace_saved        = False
    instr_counter      = 0
    address_PK         = None
    address_SK         = None
    address_CT         = None
    ins_trace.clear()
    reg_trace.clear()

# --------------------- EXCEPTIONS -----------------
# Exception to stop the emulator
class StopEmulation(Exception):
    pass


# --------------------- HELPERS FOR CIPHERTEXT --------------------------

def generate_base_ciphertext():
    os.makedirs(output_dir, exist_ok=True)

    c1_random = os.urandom(BYTES_CIPHERTEXT_C1)
    c2        = bytes(BYTES_CIPHERTEXT_C2)
    salt      = bytes(CRYPTO_CIPHERTEXTBYTES - BYTES_CIPHERTEXT_C1 - BYTES_CIPHERTEXT_C2)
    base_ct   = c1_random + c2 + salt

    with open(ct_base_path, "wb") as f:
        f.write(base_ct)

    print(f"[INFO] Base ciphertext created at {ct_base_path}")
    return base_ct


def load_base_ciphertext():
    if not os.path.exists(ct_base_path):
        return generate_base_ciphertext()

    with open(ct_base_path, "rb") as f:
        ct_base = f.read()

    if len(ct_base) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] Base ciphertext has wrong size: {len(ct_base)} != {CRYPTO_CIPHERTEXTBYTES}"
        )

    print(f"[INFO] Loaded base ciphertext from {ct_base_path}")
    return ct_base


def zero_bits(data, start, D):
    for bit in range(start, start + D):
        byte_pos = bit >> 3
        bit_pos  = 7 - (bit & 7)
        data[byte_pos] &= ~(1 << bit_pos)


def modify_ciphertext_c1(index):
    ct_random  = load_base_ciphertext()
    c1_random  = ct_random[:BYTES_CIPHERTEXT_C1]
    c1_altered = bytearray(c1_random)

    for ind in range(index):
        for i in range(PARAMS_NBAR):
            start = (i * PARAMS_N + ind) * PARAMS_LOGQ
            zero_bits(c1_altered, start, PARAMS_LOGQ)

    c2   = ct_random[BYTES_CIPHERTEXT_C1 : BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2]
    salt = ct_random[BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2 :]

    return bytes(c1_random), bytes(c1_altered) + c2 + salt


def unpack_c1(c1):
    values = []
    for i in range(PARAMS_NBAR):
        for j in range(PARAMS_N):
            start = (i * PARAMS_N + j) * PARAMS_LOGQ
            val   = 0
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

    random_vals = unpack_c1(c1_random)
    altered_vals = unpack_c1(c1_altered)

    # Test 1.1: check size of c1
    if len(c1_random) != BYTES_CIPHERTEXT_C1:
        raise StopEmulation(
            f"[ERROR] The size of c1_random {len(c1_random)} does not match expected {BYTES_CIPHERTEXT_C1}"
        )
    # Test 1.2: check size of ct
    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] The size of ct {len(ct)} does not match expected {CRYPTO_CIPHERTEXTBYTES}"
        )
    
    # Test 2: check that the first index columns are zeroed and the rest are unchanged
    for ind in range(index):
        for i in range(PARAMS_NBAR):
            val = altered_vals[i * PARAMS_N + ind]
            if val != 0:
                raise StopEmulation(
                    f"[ERROR] The first {index} columns should be zeroed, "
                    f"but column {ind} row {i} is not zero: {val}"
                )
    # Test 3: check that columns from index onward are unchanged
    for ind in range(index, PARAMS_N):
        for i in range(PARAMS_NBAR):
            if altered_vals[i * PARAMS_N + ind] != random_vals[i * PARAMS_N + ind]:
                raise StopEmulation(
                    f"[ERROR] Column {ind} row {i} was changed unexpectedly"
                )
            
    # Test 4: check that the sum of all values in c1 is consistent with the zeroing
    q            = 1 << PARAMS_LOGQ
    total_sum    = sum(random_vals) % q
    removed_sum  = sum(
        random_vals[i * PARAMS_N + ind]
        for ind in range(index)
        for i in range(PARAMS_NBAR)
    ) % q
    new_sum  = sum(altered_vals) % q
    expected = (total_sum - removed_sum) % q

    if new_sum != expected:
        raise StopEmulation(f"[ERROR] Sum check failed: {new_sum} != {expected}")

    print(f"[TEST PASSED] Ciphertext modification for index {index} is correct")


# ---------------------- HELPERS FOR EMULATOR ---------------------------

def normalize_addr(addr):
    if addr is None:
        return None
    return addr - 1 if (addr & 1) else addr


def get_label_address(elf_file, function_name):
    print(f"Looking for symbol: {function_name}")
    with open(elf_file, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == ".symtab":
                for symbol in section.iter_symbols():
                    if symbol.name == function_name:
                        addr = symbol["st_value"]
                        print(f"Found {function_name} at {hex(addr)}")
                        return addr
    print(f"Symbol not found: {function_name}")
    return None


def initialize_emulator():
    ql = Qiling(
        [elf_file],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f407,
        verbose=QL_VERBOSE.OFF
    )

    ql.hw.create("usart1")
    ql.hw.create("usart2")
    ql.hw.create("rcc")
    ql.hw.create("gpioa")

    try:
        ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)
        ql.mem.write(0x50060800, b"\x00" * 0x400)
    except Exception:
        pass

    return ql


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
            "pc", "instruction", "operands",
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
        ])

        for ins_info, regs in zip(ins_trace, reg_trace):
            regs_hex = [hex(x) for x in regs]
            writer_csv.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)

    # Trimmed trace
    os.makedirs(output_dir_trim, exist_ok=True)
    trim_file_name = os.path.join(output_dir_trim, f"trace_{fault_index}.csv")

    with open(trim_file_name, "w", newline="") as csvfile_trim:
        writer_trim = csv.writer(csvfile_trim)
        writer_trim.writerow(REG_NAMES[:-1]) 
        for regs in reg_trace:
            writer_trim.writerow([hex(x) for x in regs[:-1]])  

    print(f"Trimmed trace saved to {trim_file_name}")
    
    trace_saved = True
    print("Trace saved")


def save_keypair(ql):
    global keypair_saved

    if keypair_saved:
        return

    os.makedirs(output_dir, exist_ok=True)

    if g_pk_addr is not None:
        pk = ql.mem.read(g_pk_addr, SIZE_PK)
        with open(pk_path, "wb") as f:
            f.write(pk)
        print(f"PK saved to {pk_path}")

    if g_sk_addr is not None:
        sk = ql.mem.read(g_sk_addr, SIZE_SK)
        with open(sk_path, "wb") as f:
            f.write(sk)
        print(f"SK saved to {sk_path}")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")

    keypair_saved = True


def save_ciphertext(ql, index):

    trace_dir = get_trace_dir(index)
    os.makedirs(trace_dir, exist_ok=True)

    if g_ct_addr is not None:
        ct = ql.mem.read(g_ct_addr, SIZE_CT)
        ct_path = get_ct_modified_path(index)
        with open(ct_path, "wb") as f:
            f.write(ct)
        print(f"CT saved to {ct_path}")

    save_csv(get_trace_csv_path(index))


# Hooks
def full_tracing(ql: Qiling, address: int, size: int) -> None:
    global hit_main, hit_kem_keypair, hit_crypto_kem_dec
    global hit_trigger_high, hit_trigger_low
    global trace_started, address_PK, address_SK, address_CT
    global instr_counter
    global skip
    global fault_index

    instr_counter += 1

    if address == skip:
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    ins, arg = disasm(ql, address)

    if instr_counter % 10000 == 0:
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

    # Save PK/SK as soon as keypair generation is done (detected at trigger_high,
    # which fires right before the decapsulation measurement window begins)
    if trigger_high_addr and address == trigger_high_addr and not hit_trigger_high:
        hit_trigger_high = True
        save_keypair(ql)       
        trace_started = True
        ins_trace.clear()
        reg_trace.clear()
        print(f"trigger_high() at {hex(address)}, trace starts")

    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not hit_crypto_kem_dec:
        hit_crypto_kem_dec = True
        ct_ptr     = ql.arch.regs.read("r1")
        address_CT = ct_ptr

        print("----------------------------")
        print("Entering decapsulation:")
        print("----------------------------")
        print(f"ct ptr = {hex(ct_ptr)}  "
              f"(overwriting with altered ciphertext for index {fault_index})")

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
        print(f"Instructions collected: {len(ins_trace)}")

        save_ciphertext(ql, fault_index)

        print("Stopping emulator")
        ql.emu_stop()
        raise StopEmulation("Trace captured, stopping emulator")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--elf-file", 
        type = str,
        required = True,
        help="Path to the ELF firmware file"
    )
    parser.add_argument(
        "--fault-index",
        type=int, 
        required=True,
        help = "Fault indexes")
    parser.add_argument(
        "--output-dir",
        required=True, 
        help="The directory in which the entire trace will be save")
    parser.add_argument(
        "--output-dir-trim", 
        required=True, 
        help="The directory in which the trim capture will be saved")
    args = parser.parse_args()
    
    elf_file = args.elf_file 
    fault_index = args.fault_index
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim
    pk_path        = os.path.join(output_dir, "pk.bin")
    sk_path         = os.path.join(output_dir, "sk.bin")
    ct_base_path    = os.path.join(output_dir, "ct_base.bin")


    trace_dir   = get_trace_dir(fault_index)

    print("Initialisation checks:")
    print("-----------------------")
    print("Starting script")
    print(f"ELF exists? {os.path.exists(elf_file)}")

    if not os.path.exists(elf_file):
        sys.exit(1)

    trigger_setup = get_label_address(elf_file, "trigger_setup")
    if trigger_setup:
        skip = normalize_addr(trigger_setup)

    main_addr           = normalize_addr(get_label_address(elf_file, "main"))
    kem_keypair_addr    = normalize_addr(get_label_address(elf_file, "crypto_kem_keypair"))
    trigger_high_addr   = normalize_addr(get_label_address(elf_file, "trigger_high"))
    crypto_kem_dec_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_dec"))
    trigger_low_addr    = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    stm32f407["PPB"]["type"] = "memory"

    os.makedirs(trace_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    reset_globals()

    ql = initialize_emulator()
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