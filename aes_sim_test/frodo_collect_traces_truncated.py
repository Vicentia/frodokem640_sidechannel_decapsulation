#!/usr/bin/env python3

import queue
import os
import csv
import sys
import pickle
import argparse
import traceback
import multiprocessing

import pandas as pd
import numpy as np

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from unicorn import (
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
)

# Parameters for FrodoKEM-640
PARAMS_N               = 640
PARAMS_NBAR            = 8
PARAMS_LOGQ            = 15
CRYPTO_CIPHERTEXTBYTES = 9720
BYTES_CIPHERTEXT_C1    = (PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) // 8
BYTES_CIPHERTEXT_C2    = (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) // 8

# sk lengths
s_length               = 16 # the length of the secret key s 
SEED_A_length          = 16 # the length of the seed for generating A
b_length               = 9600 # the length of the b vector 
S_length               = PARAMS_N * PARAMS_NBAR * 2 # the length of the S matrix (each element is 2 bytes)
pkh                    = 16 # the length of the public key hash

SIZE_PK = 9616
SIZE_SK = 19888
SIZE_CT = 9720

REG_NAMES = [
    "r0", "r1", "r2", "r3",
    "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11",
    "r12", "sp", "lr", "pc"
]

REG_ALIAS = {
    "sb": "r9",
    "sl": "r10",
    "fp": "r11",
    "ip": "r12",
}

# -------------------------- GLOBAL VARIABLES --------------------------

md = None

main_addr           = None
trigger_high_addr   = None
trigger_low_addr    = None
skip_addrs          = set()
clear_bytes_addr    = None

kem_keypair_addr    = None
g_pk_addr           = None
g_sk_addr           = None
g_keypair_done_addr = None

g_ct_addr           = None
crypto_kem_dec_addr = None
dec_return_addr     = None

mul_bs_addr         = None
xs_addr             = None

hit_main           = False
hit_kem_keypair    = False
hit_trigger_high   = False
hit_crypto_kem_dec = False
snapshot_saved     = False
hit_trigger_low    = False
trace_started      = False
trace_saved        = False
stop_requested     = False

address_PK = None
address_SK = None
address_CT = None

global_output_dir = None
output_dir        = None
output_dir_trim   = None
snapshot_path     = None

instr_counter       = 0
current_run_index   = 0
current_fault_index = 0

ins_trace = []
reg_trace = []

in_mul_bs              = False
xs_call_counter        = 0
active_xs              = False
active_xs_id           = None
active_xs_return_addr  = None

xs_ins_traces = [[] for _ in range(PARAMS_NBAR)]
xs_reg_traces = [[] for _ in range(PARAMS_NBAR)]


# -------------------------- PATH HELPERS --------------------------

def get_snapshot_path(out_dir):
    return os.path.join(out_dir, "snapshot.pkl")

def get_ciphertext_path(run_index):
    return os.path.join(output_dir, f"ciphertext_{run_index}.bin")

def get_trace_csv_path(run_index, xs_id):
    return os.path.join(output_dir, f"trace_{run_index}_{xs_id}.csv")

def get_trim_csv_path(run_index, xs_id):
    return os.path.join(output_dir_trim, f"trace_{run_index}_{xs_id}.csv")

def get_B_dir():
    return os.path.join(output_dir, "B")

def get_S_dir():
    return os.path.join(output_dir, "S")

def get_B_csv_path(run_index):
    return os.path.join(get_B_dir(), f"B_{run_index}.csv")

def get_S_csv_path(run_index):
    return os.path.join(get_S_dir(), f"S_{run_index}.csv")

def get_B_from_registers_csv_path(run_index):
    return os.path.join(get_B_dir(), f"B_from_registers_{run_index}.csv")

# -------------------------- RESET --------------------------

def reset_decapsulation_globals():
    global hit_crypto_kem_dec, hit_trigger_high, hit_trigger_low
    global trace_started, trace_saved, instr_counter
    global ins_trace, reg_trace, address_CT
    global dec_return_addr
    global stop_requested

    global in_mul_bs, xs_call_counter
    global active_xs, active_xs_id, active_xs_return_addr
    global xs_ins_traces, xs_reg_traces

    stop_requested     = False
    hit_crypto_kem_dec = False
    hit_trigger_high   = False
    hit_trigger_low    = False
    trace_started      = False
    trace_saved        = False
    instr_counter      = 0
    address_CT         = None
    dec_return_addr    = None

    in_mul_bs             = False
    xs_call_counter       = 0
    active_xs             = False
    active_xs_id          = None
    active_xs_return_addr = None

    ins_trace.clear()
    reg_trace.clear()

    xs_ins_traces = [[] for _ in range(PARAMS_NBAR)]
    xs_reg_traces = [[] for _ in range(PARAMS_NBAR)]


# -------------------------- EXCEPTIONS --------------------------

class StopEmulation(Exception):
    pass


class SnapshotReady(Exception):
    pass


def hard_stop(ql):
    try:
        ql.uc.emu_stop()
    except Exception:
        pass

    try:
        ql.emu_stop()
    except Exception:
        pass


# -------------------------- CIPHERTEXT HELPERS --------------------------

def generate_base_ciphertext(run_index):
    os.makedirs(output_dir, exist_ok=True)

    ct_path = get_ciphertext_path(run_index)

    c1_random = os.urandom(BYTES_CIPHERTEXT_C1)
    c2        = bytes(BYTES_CIPHERTEXT_C2)
    salt      = bytes(CRYPTO_CIPHERTEXTBYTES - BYTES_CIPHERTEXT_C1 - BYTES_CIPHERTEXT_C2)
    base_ct   = c1_random + c2 + salt

    with open(ct_path, "wb") as f:
        f.write(base_ct)

    print(f"[INFO] Ciphertext for Run_{run_index + 1} created at {ct_path}")
    return base_ct


def load_base_ciphertext(run_index):
    ct_path = get_ciphertext_path(run_index)

    if not os.path.exists(ct_path):
        return generate_base_ciphertext(run_index)

    with open(ct_path, "rb") as f:
        ct = f.read()

    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] Ciphertext for Run_{run_index + 1} has wrong size: "
            f"{len(ct)} != {CRYPTO_CIPHERTEXTBYTES}"
        )

    print(f"[INFO] Loaded ciphertext for Run_{run_index + 1} from {ct_path}")
    return ct


def zero_bits(data, start, D):
    for bit in range(start, start + D):
        byte_pos = bit >> 3
        bit_pos  = 7 - (bit & 7)
        data[byte_pos] &= ~(1 << bit_pos)


def modify_ciphertext_c1(run_index, index):
    ct_random  = load_base_ciphertext(run_index)
    c1_random  = ct_random[:BYTES_CIPHERTEXT_C1]
    c1_altered = bytearray(c1_random)

    if index > PARAMS_N:
        print("[INFO] The index is bigger than the number of columns of Bp, ciphertext stays the same")
    else:
        for ind in range(index):
            for i in range(PARAMS_NBAR):
                start = (i * PARAMS_N + ind) * PARAMS_LOGQ
                zero_bits(c1_altered, start, PARAMS_LOGQ)

    c2   = ct_random[BYTES_CIPHERTEXT_C1: BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2]
    salt = ct_random[BYTES_CIPHERTEXT_C1 + BYTES_CIPHERTEXT_C2:]

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
                val |= ((c1[byte_pos] >> bit_pos) & 1) << (PARAMS_LOGQ - 1 - bit)

            values.append(val)

    return values


def test_modify_ciphertext_c1(run_index, index, c1_random=None, ct=None):
    if c1_random is None or ct is None:
        c1_random, ct = modify_ciphertext_c1(run_index, index)

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

    print(
        f"[TEST PASSED] Ciphertext modification for Run_{run_index + 1}, "
        f"index {index} is correct"
    )


# -------------------------- B/S CSV HELPERS --------------------------

def save_S_from_sk_csv(sk, S_path):
    """
    sk = s || seed_A || b || S || pkh
    """
    before_S = s_length + SEED_A_length + b_length
    S = sk[before_S: before_S + S_length]

    if len(S) != S_length:
        raise ValueError(f"S has wrong size: {len(S)} != {S_length}")

    S_by_xs = np.frombuffer(S, dtype="<i2").reshape(PARAMS_NBAR, PARAMS_N)
    S_matrix = S_by_xs.T

    os.makedirs(os.path.dirname(S_path), exist_ok=True)

    with open(S_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["row"] + [f"S_col_{j}" for j in range(PARAMS_NBAR)]
        writer.writerow(header)

        for i in range(PARAMS_N):
            writer.writerow([i] + S_matrix[i].astype(int).tolist())

    print(f"S matrix saved as CSV to {S_path}")

# we load the S vector from sk file 
def load_S_vectors_from_sk_file():
    sk_path = os.path.join(output_dir, "sk.bin")

    if not os.path.exists(sk_path):
        print(f"[ERROR] Missing sk.bin, cannot compare S against key: {sk_path}")
        return None

    with open(sk_path, "rb") as f:
        sk = f.read()

    before_S = s_length + SEED_A_length + b_length
    S = sk[before_S: before_S + S_length]

    if len(S) != S_length:
        raise ValueError(f"S has wrong size: {len(S)} != {S_length}")

    return np.frombuffer(S, dtype="<i2").reshape(PARAMS_NBAR, PARAMS_N)

# create csv B by unpacking c1 from ciphertext because B unpack(c1)
def save_B_from_ciphertext_csv(ct, B_path):
    c1 = ct[:BYTES_CIPHERTEXT_C1]

    B_values = unpack_c1(c1)

    os.makedirs(os.path.dirname(B_path), exist_ok=True)

    with open(B_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["row"] + [f"B_col_{j}" for j in range(PARAMS_N)]
        writer.writerow(header)
        for i in range(PARAMS_NBAR):
            row = []
            for j in range(PARAMS_N):
                value = B_values[i * PARAMS_N + j]
                row.append(value)
            writer.writerow([i] + row)

    print(f"B matrix saved as CSV to {B_path}")


def canonical_reg(reg):
    return REG_ALIAS.get(reg.strip(), reg.strip())


def split_u32_to_u16_pair(x):
    x = int(x, 0) & 0xffffffff
    low = x & 0xffff
    high = (x >> 16) & 0xffff
    return low, high

# for S which we want it as signed 16-bit
def split_u32_to_i16_pair(x):
    x = int(x, 0) & 0xffffffff
    low = x & 0xffff
    high = (x >> 16) & 0xffff
    if low >= 0x8000:
        low -= 0x10000
    if high >= 0x8000:
        high -= 0x10000
    return low, high

def extract_smlad_operands(trace_csv_path):
    df = pd.read_csv(trace_csv_path)
    df.fillna("0x0", inplace=True)

    B_values = []
    S_values = []

    for _, row in df.iterrows():
        if row["instruction"] != "smlad":
            continue

        ops = [x.strip() for x in row["operands"].split(",")]
        if len(ops) < 4:
            continue

        # From Ghidra: smlad r0, r2, r7, r0
        # r2 = B operand, r7 = S operand
        b_reg = canonical_reg(ops[1])
        s_reg = canonical_reg(ops[2])

        if b_reg not in row.index or s_reg not in row.index:
            print(f"[ERROR] Missing register column. operands={ops}, b_reg={b_reg}, s_reg={s_reg}")
            continue

        b_low, b_high = split_u32_to_u16_pair(row[b_reg])
        s_low, s_high = split_u32_to_i16_pair(row[s_reg])

        B_values.extend([b_low, b_high])
        S_values.extend([s_low, s_high])

    return (
        np.array(B_values, dtype=np.uint16),
        np.array(S_values, dtype=np.int16),
    )

def extract_B_from_registers_matrix_from_trace(run_index, xs_id):
    """
    Extract B' and S from trace 
    """
    trace_path = get_trim_csv_path(run_index, xs_id)

    B_from_registers, S_from_registers = extract_smlad_operands(trace_path)

    if len(B_from_registers) != PARAMS_N * PARAMS_NBAR:
        print(f"[ERROR] B_from_registers length is {len(B_from_registers)}, expected {PARAMS_N * PARAMS_NBAR} for run {run_index} xs_id {xs_id}")
        return None, S_from_registers

    return (
        B_from_registers.reshape(PARAMS_NBAR, PARAMS_N),
        # here S is just an xs() call because this is the way in which the subtrace is created 
        S_from_registers,
    )


def save_and_check_B_from_registers_from_traces(run_index):
    B_csv_path = get_B_csv_path(run_index)

    if not os.path.exists(B_csv_path):
        print(f"[MISSING CSV] {B_csv_path} does not exist")
        return

    B_csv = pd.read_csv(B_csv_path)
    B_expected = B_csv[[f"B_col_{j}" for j in range(PARAMS_N)]].to_numpy(dtype=np.uint16)

    reference_B = None
    matches_reference_count = 0
    total_checks = 0

    for xs_id in range(PARAMS_NBAR):
        trace_path = get_trim_csv_path(run_index, xs_id)

        if not os.path.exists(trace_path):
            print(f"[ERROR] Trace does not exist, cannot extract raw B: {trace_path}")
            continue

        B_matrix, _ = extract_B_from_registers_matrix_from_trace(run_index, xs_id)

        if B_matrix is None:
            continue

        if reference_B is None:
            reference_B= B_matrix

        for b_row in range(PARAMS_NBAR):
            B_row = B_matrix[b_row]

            matches_B = np.array_equal(B_row, B_expected[b_row])
            matches_reference = np.array_equal(B_row, reference_B[b_row])

            matches_reference_count += int(matches_reference)
            total_checks += 1

            if not matches_B:
                mismatch = np.where(B_row != B_expected[b_row])
                raise StopEmulation(
                    f"[B CHECK ERROR] run={run_index} xs_id={xs_id} B_row={b_row} "
                    f"does not match B_{run_index}.csv. first mismatches={mismatch}"
                )

            if not matches_reference:
                mismatch = np.where(B_row != reference_B[b_row])
                raise StopEmulation(
                    f"[B CHECK ERROR] run={run_index} xs_id={xs_id} B_row={b_row} "
                    f"does not match xs_id=0 B. first mismatches={mismatch}"
                )

    if reference_B is None:
        print(f"[ERROR] No valid B trace data found for run {run_index}")
        return

    os.makedirs(get_B_dir(), exist_ok=True)

    B_output_path = get_B_from_registers_csv_path(run_index)
    B_from_registers_df = pd.DataFrame(
        reference_B,
        columns=[f"B_col_{i}" for i in range(PARAMS_N)]
    )
    B_from_registers_df.insert(0, "row", range(PARAMS_NBAR))
    B_from_registers_df.to_csv(B_output_path, index=False)

    print(f"Saved B matrix from registers to {B_output_path}")
    print(
        f"[B CHECK] run={run_index}: B identical across xs traces "
        f"{matches_reference_count}/{total_checks}."
    )


def save_and_check_S_from_traces(run_index):
    S_expected = load_S_vectors_from_sk_file()

    if S_expected is None:
        return

    S_vectors = []
    matches_sk_count = 0
    matches_repeat_count = 0
    total_checks = 0

    for xs_id in range(PARAMS_NBAR):
        trace_path = get_trim_csv_path(run_index, xs_id)

        if not os.path.exists(trace_path):
            print(f"[ERROR] Trace does not exist, cannot extract S: {trace_path}")
            continue

        # S_from_registers represents just one xs() call and it needs to be concatenated witth all rows to create the full S matrix
        _, S_from_registers = extract_smlad_operands(trace_path)

        if len(S_from_registers) != PARAMS_N * PARAMS_NBAR:
            print(
                f"[ERROR] S_from_registers length is {len(S_from_registers)}, expected {PARAMS_N * PARAMS_NBAR}. "
                f"Cannot split into 8 xs() calls safely."
            )
            continue

        S_rows = S_from_registers.reshape(PARAMS_NBAR, PARAMS_N)
        S_vector = S_rows[0]
        S_vectors.append((xs_id, S_vector))

        expected_vector = S_expected[xs_id]

        # Check if the S vector from this trace matches the expected S vector from the key 
        # and if it matches the S vector from the first trace (e.g xs_id=0) because S is created by collecting all the xs() calls 
        for row in range(PARAMS_NBAR):
            S_row = S_rows[row]
            matches_sk = np.array_equal(S_row, expected_vector)
            matches_first_row = np.array_equal(S_row, S_vector)

            matches_sk_count += int(matches_sk)
            matches_repeat_count += int(matches_first_row)
            total_checks += 1

            if not matches_sk:
                mismatch = np.where(S_row != expected_vector)[0][:5]
                raise StopEmulation(
                    f"[S CHECK ERROR] run={run_index} xs_id={xs_id} B_row={row} "
                    f"does not match S from sk. first mismatches={mismatch}"
                )

            if not matches_first_row:
                mismatch = np.where(S_row != S_vector)[0][:5]
                raise StopEmulation(
                    f"[S CHECK ERROR] run={run_index} xs_id={xs_id} B_row={row} "
                    f"does not repeat first S row. first mismatches={mismatch}"
                )

    if len(S_vectors) != PARAMS_NBAR:
        print(f"[ERROR] Only extracted {len(S_vectors)}/{PARAMS_NBAR} S vectors for run {run_index}")

    if not S_vectors:
        print(f"[ERROR] No valid S trace data found for run {run_index}")
        return

    S_by_xs = np.zeros((PARAMS_NBAR, PARAMS_N), dtype=np.int16)
    for xs_id, S_vector in S_vectors:
        S_by_xs[xs_id] = S_vector

    S_path = get_S_csv_path(run_index)
    os.makedirs(os.path.dirname(S_path), exist_ok=True)
    S_matrix = S_by_xs.T
    S_df = pd.DataFrame(
        S_matrix,
        columns=[f"S_col_{i}" for i in range(PARAMS_NBAR)]
    )
    S_df.insert(0, "row", range(PARAMS_N))
    S_df.to_csv(S_path, index=False)

    print(f"[S] Saved S matrix from registers to {S_path}")
    print(
        f"[S CHECK] run={run_index}: S register rows match sk {matches_sk_count}/{total_checks}; "
        f"S repeated across B rows {matches_repeat_count}/{total_checks}."
    )


def compare_B_ciphertext_vs_trace(run_index, xs_id):
    B_csv_path = get_B_csv_path(run_index)
    trace_path = get_trim_csv_path(run_index, xs_id)

    if not os.path.exists(B_csv_path):
        print(f"[COMPARE ERROR] Missing B CSV: {B_csv_path}")
        return

    if not os.path.exists(trace_path):
        print(f"[COMPARE ERROR] Missing trace CSV: {trace_path}")
        return

    B_from_registers, S_from_registers = extract_smlad_operands(trace_path)

    B_csv = pd.read_csv(B_csv_path)
    B_expected = B_csv[[f"B_col_{j}" for j in range(PARAMS_N)]].to_numpy(dtype=np.uint16)
    print("-----------------------------------------")
    print("\n B from ciphertext vs B from register:")
    print(f"run_index       = {run_index}")
    print(f"xs_id           = {xs_id}")
    print(f"B csv path      = {B_csv_path}")
    print(f"trace path      = {trace_path}")
    print(f"B_from_registers length = {len(B_from_registers)}")
    print(f"S_trace length  = {len(S_from_registers)}")

    if len(B_from_registers) > 0:
        print(f"B_from_registers first 10 = {B_from_registers[:10]}")
        print(f"B_from_registers min/max  = {B_from_registers.min()} / {B_from_registers.max()}")

    if len(B_from_registers) != PARAMS_N * PARAMS_NBAR:
        print(
            f"[ERROR] B_from_registers length is {len(B_from_registers)}, expected {PARAMS_N * PARAMS_NBAR}. "
            f"Skipping chunked B comparison."
        )
        print("-----------------------------------------\n")
        return

    B_register_matrix = B_from_registers.reshape(PARAMS_NBAR, PARAMS_N)

    for row in range(PARAMS_NBAR):
        B_expected_row = B_expected[row]
        B_register_row = B_register_matrix[row]
        direct_match = np.array_equal(B_register_row, B_expected_row)
        first_mismatch = np.where(B_register_row != B_expected_row)[0][:5]

        print(
            f"B row {row}: "
            f"B_register_match={direct_match}, "
            f"first_B_row_mismatch={first_mismatch}"
        )

    print("-----------------------------------------\n")


# -------------------------- EMULATOR HELPERS --------------------------

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


def save_snapshot_manual(ql):
    print("Starting snapshot...")

    snapshot = {
        "regs": {r: ql.arch.regs.read(r) for r in REG_NAMES},
        "memory": [],
    }

    print(f"Registers saved: {snapshot['regs']}")

    SKIP_LABEL_KEYWORDS = [
        "BITBAND",
        "BBR",
        "FLASH",
        "REMAP",
        "SYSTEM",
        "FLASH OTP",
    ]

    for start, end, perms, label, _ in ql.mem.get_mapinfo():
        region_size = end - start
        label_str   = str(label)

        if any(k in label_str.upper() for k in SKIP_LABEL_KEYWORDS):
            print(f"[SKIP] Region {label}: {hex(start)}-{hex(end)}")
            continue

        if region_size > 0x400000:
            print(f"[SKIP TOO LARGE] Region {label}: {hex(start)}-{hex(end)}")
            continue

        try:
            data = bytes(ql.mem.read(start, region_size))
            snapshot["memory"].append((start, end, perms, label, data))
            print(f"Saved region {label}: {hex(start)}-{hex(end)} ({region_size} bytes)")
        except Exception as e:
            print(f"[SKIP] Failed to read region {label}: {e}")

    print(f"Snapshot complete: {len(snapshot['memory'])} regions")
    return snapshot


def restore_snapshot_manual(ql, snapshot):
    for start, end, perms, label, data in snapshot["memory"]:
        try:
            ql.mem.write(start, data)
            print(f"Restored region [{label}]: {hex(start)}-{hex(end)}")
        except Exception as e:
            print(f"[ERROR] Failed to restore region [{label}]: {e}")

    for reg, val in snapshot["regs"].items():
        try:
            ql.arch.regs.write(reg, val)
        except Exception as e:
            print(f"[ERROR] Failed to restore register {reg}: {e}")


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(f"[UNMAPPED] access={access} addr={hex(address)} size={size} value={value}")
    return False


def setup_qiling_instance(elf_file):
    stm32f407["PPB"]["type"] = "memory"

    ql = Qiling(
        [elf_file],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f407,
        verbose=QL_VERBOSE.OFF,
    )

    ql.hw.create("usart1")
    ql.hw.create("usart2")
    ql.hw.create("rcc")
    ql.hw.create("gpioa")

    class FakeUSART:
        def readable(self):
            return False

        def read(self, size=1):
            return bytes([0]) * size

        def write(self, data):
            return len(data) if data is not None else 0

        def flush(self):
            pass

    for usart_name in ("usart1", "usart2"):
        try:
            try:
                usart = ql.hw.get(usart_name)
            except TypeError:
                usart = getattr(ql.hw, usart_name, None)

            if usart is None:
                print(f"[ERROR] {usart_name} not available")
                continue

            try:
                usart.itube = FakeUSART()
                print(f"[INFO] Patched {usart_name}.itube with FakeUSART")
            except Exception as e:
                print(f"[ERROR] Could not replace {usart_name}.itube: {e}")

            try:
                usart.recv_from_user = lambda *args, **kwargs: 0x00
                print(f"[INFO] Patched {usart_name}.recv_from_user to return 0x00")
            except Exception as e:
                print(f"[ERROR] Could not patch {usart_name}.recv_from_user: {e}")

        except Exception as e:
            print(f"[ERROR] Could not patch {usart_name}: {e}")

    for hook_type in (
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
    ):
        ql.uc.hook_add(hook_type, hook_mem_invalid)

    try:
        ql.mem.map(0x22000000, 0x02000000, info="SRAM_BITBAND_ALIAS", perms=3)
        ql.mem.write(0x22000000, b"\x00" * 0x02000000)
    except Exception:
        pass

    try:
        ql.mem.map(0x42000000, 0x02000000, info="PERIPH_BITBAND_ALIAS", perms=3)
        ql.mem.write(0x42000000, b"\x00" * 0x02000000)
    except Exception:
        pass

    try:
        ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)
        ql.mem.write(0x50060800, b"\x00" * 0x400)
    except Exception:
        pass

    return ql


def make_disasm():
    return Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def disasm(ql, address):
    try:
        bytecode = ql.mem.read(address, 4)
        for insn in md.disasm(bytecode, address):
            return [insn.mnemonic, insn.op_str]
    except Exception:
        pass

    return ["<unknown>", ""]


def save_keys(ql, out_dir):
    os.makedirs(out_dir, exist_ok=True)

    if g_pk_addr is not None:
        pk = bytes(ql.mem.read(g_pk_addr, SIZE_PK))
        pk_path = os.path.join(out_dir, "pk.bin")

        with open(pk_path, "wb") as f:
            f.write(pk)

        print(f"PK saved to {pk_path}")

    if g_sk_addr is not None:
        sk = bytes(ql.mem.read(g_sk_addr, SIZE_SK))
        sk_path = os.path.join(out_dir, "sk.bin")
        S_path = os.path.join(out_dir, "S", "S.csv")

        with open(sk_path, "wb") as f:
            f.write(sk)

        save_S_from_sk_csv(sk, S_path)

        print(f"SK saved to {sk_path}")
        print(f"S saved to {S_path}")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")


# -------------------------- XS TRACE SAVE --------------------------

def write_trace_csv(path, ins_list, reg_list):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            "pc", "instruction", "operands",
            "r0", "r1", "r2", "r3",
            "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11",
            "r12", "sp", "lr", "pc"
        ])

        for ins_info, regs in zip(ins_list, reg_list):
            regs_hex = [hex(x) for x in regs]
            writer.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)


def save_xs_csvs(run_index):
    global trace_saved

    if trace_saved:
        return

    for xs_id in range(PARAMS_NBAR):
        full_path = get_trace_csv_path(run_index, xs_id)
        trim_path = get_trim_csv_path(run_index, xs_id)

        write_trace_csv(full_path, xs_ins_traces[xs_id], xs_reg_traces[xs_id])
        write_trace_csv(trim_path, xs_ins_traces[xs_id], xs_reg_traces[xs_id])

    trace_saved = True


# -------------------------- SNAPSHOT HOOK --------------------------

def snapshot_tracing(ql, address, size):
    global hit_main, hit_kem_keypair, hit_trigger_high, hit_crypto_kem_dec
    global instr_counter
    global address_PK, address_SK, address_CT
    global snapshot_saved, snapshot_path
    global stop_requested

    if stop_requested:
        return

    address = normalize_addr(address)
    instr_counter += 1

    if address in skip_addrs:
        print(f"[SKIP FUNC] Returning immediately from {hex(address)}")
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    ins, arg = disasm(ql, address)

    if instr_counter % 10000 == 0:
        print(
            f"[PROGRESS SNAPSHOT] instr={instr_counter} "
            f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
            f"lr={hex(ql.arch.regs.read('lr'))} "
            f"ins={ins} {arg}"
        )

    if clear_bytes_addr and address == clear_bytes_addr:
        mem_ptr = ql.arch.regs.read("r0")
        n       = ql.arch.regs.read("r1")

        print(f"[NATIVE] clear_bytes({hex(mem_ptr)}, {n})")

        try:
            ql.mem.write(mem_ptr, b"\x00" * n)
        except Exception as e:
            print(f"[ERROR] clear_bytes failed: {e}")

        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

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

    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not hit_crypto_kem_dec:
        hit_crypto_kem_dec = True
        address_CT = ql.arch.regs.read("r1")

        print(f"crypto_kem_dec() hit at {hex(address)}, ct ptr = {hex(address_CT)}")
        print("Keygen complete. Saving keys and taking snapshot at crypto_kem_dec entry.")

        save_keys(ql, global_output_dir)

        if not snapshot_saved:
            snapshot = save_snapshot_manual(ql)

            with open(snapshot_path, "wb") as f:
                pickle.dump(snapshot, f)

            snapshot_saved = True

            print(f"Snapshot saved successfully: {snapshot_path}")
            print(f"Snapshot file size: {os.path.getsize(snapshot_path)} bytes")

        stop_requested = True
        hard_stop(ql)

        raise SnapshotReady("Reached crypto_kem_dec and snapshot ready")


# -------------------------- DECAPSULATION HOOK --------------------------

def decapsulation_tracing(ql, address, size):
    global hit_trigger_high, hit_trigger_low
    global trace_started, instr_counter
    global dec_return_addr
    global stop_requested

    global in_mul_bs, xs_call_counter
    global active_xs, active_xs_id, active_xs_return_addr

    if stop_requested:
        return

    address = normalize_addr(address)
    instr_counter += 1

    if address in skip_addrs:
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if clear_bytes_addr and address == clear_bytes_addr:
        mem_ptr = ql.arch.regs.read("r0")
        n       = ql.arch.regs.read("r1")

        try:
            ql.mem.write(mem_ptr, b"\x00" * n)
        except Exception as e:
            print(f"[ERROR IN DECAPSULATION] clear_bytes failed: {e}")

        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if trigger_high_addr and address == trigger_high_addr and not hit_trigger_high:
        hit_trigger_high = True
        trace_started = True
        print(f"trigger_high() at {hex(address)}")
        print("[TRACE] Capturing only xs() blocks")

    if not trace_started:
        return

    if mul_bs_addr and address == mul_bs_addr:
        in_mul_bs = True
        xs_call_counter = 0
        print(f"[MUL_BS START] Entered mul_bs at {hex(address)}")

    if in_mul_bs and xs_addr and address == xs_addr and not active_xs:
        active_xs_id = xs_call_counter % PARAMS_NBAR
        active_xs_return_addr = normalize_addr(ql.arch.regs.read("lr"))
        active_xs = True

        print(
            f"[XS START] xs_call={xs_call_counter}, "
            f"xs_id={active_xs_id}, "
            f"return={hex(active_xs_return_addr)}"
        )

        xs_call_counter += 1

        if active_xs_id >= PARAMS_NBAR:
            print(f"[ERROR] Ignoring unexpected xs_call={xs_call_counter - 1}")
            active_xs = False
            active_xs_id = None
            active_xs_return_addr = None
            return

    if active_xs and active_xs_return_addr is not None and address == active_xs_return_addr:
        print(f"[XS END] xs_id={active_xs_id}")
        active_xs = False
        active_xs_id = None
        active_xs_return_addr = None
        return

    if active_xs and active_xs_id is not None:
        ins, arg = disasm(ql, address)
        regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
        xs_ins_traces[active_xs_id].append([ins, arg])
        xs_reg_traces[active_xs_id].append(regs_now)

    if trigger_low_addr and address == trigger_low_addr and not hit_trigger_low:
        hit_trigger_low = True
        print(f"trigger_low() at {hex(address)}")
        save_xs_csvs(current_run_index)
        stop_requested = True
        hard_stop(ql)
        raise StopEmulation("xs-product traces captured")

    if dec_return_addr is not None and address == dec_return_addr:
        print(f"[BACKUP STOP] Returned from crypto_kem_dec to {hex(address)}")
        save_xs_csvs(current_run_index)
        stop_requested = True
        hard_stop(ql)
        raise StopEmulation("Returned from crypto_kem_dec")


# -------------------------- WORKER --------------------------

def run_decapsulation_worker(worker_args):
    (
        run_index_local,
        fault_index_local,
        snapshot_path_local,
        elf_file,
        output_dir_local,
        output_dir_trim_local,
        trigger_high_addr_local,
        trigger_low_addr_local,
        skip_addrs_local,
        g_ct_addr_local,
        clear_bytes_addr_local,
        mul_bs_addr_local,
        xs_addr_local,
    ) = worker_args

    global current_run_index, current_fault_index
    global trigger_high_addr, trigger_low_addr
    global skip_addrs, g_ct_addr, global_output_dir, md
    global clear_bytes_addr
    global output_dir, output_dir_trim
    global dec_return_addr
    global mul_bs_addr, xs_addr

    current_run_index   = run_index_local
    current_fault_index = fault_index_local

    trigger_high_addr = trigger_high_addr_local
    trigger_low_addr  = trigger_low_addr_local
    skip_addrs        = set(skip_addrs_local)
    g_ct_addr         = g_ct_addr_local
    clear_bytes_addr  = clear_bytes_addr_local

    mul_bs_addr = mul_bs_addr_local
    xs_addr     = xs_addr_local

    output_dir        = output_dir_local
    output_dir_trim   = output_dir_trim_local
    global_output_dir = output_dir_local

    md = make_disasm()

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    reset_decapsulation_globals()
    ql = setup_qiling_instance(elf_file)

    with open(snapshot_path_local, "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)

    dec_return_addr = normalize_addr(snapshot["regs"]["lr"])

    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Backup return address = {hex(dec_return_addr)}"
    )

    del snapshot

    base_ct = load_base_ciphertext(run_index_local)

    ql.mem.write(g_ct_addr, bytes(base_ct))

    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Base CT written unchanged to g_ct ({hex(g_ct_addr)})"
    )

    ct_path = get_ciphertext_path(run_index_local)

    with open(ct_path, "wb") as f:
        f.write(base_ct)

    print(
        f"[WORKER run={run_index_local} fault={fault_index_local}] "
        f"ciphertext saved to {ct_path}"
    )

    # Save B from the exact ciphertext used in this run
    save_B_from_ciphertext_csv(base_ct, get_B_csv_path(run_index_local))

    ql.hook_code(decapsulation_tracing)

    print("\n-----------------------------")
    print(f"Running decapsulation for run {run_index_local}, fault index {fault_index_local}")
    print(f"Expected output traces: trace_{run_index_local}_0.csv ... trace_{run_index_local}_7.csv")
    print(f"mul_bs address: {hex(mul_bs_addr) if mul_bs_addr else None}")
    print(f"xs address: {hex(xs_addr) if xs_addr else None}")
    print(f"Skip addresses: {[hex(a) for a in sorted(skip_addrs)]}")
    print("-----------------------------")

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print(f"Error during decapsulation (run={run_index_local + 1} fault={fault_index_local}): {e}")
        traceback.print_exc()

    # B should be the same for every xs_id
    save_and_check_B_from_registers_from_traces(run_index_local)
    # S is reconstructed from registers and should match the S extracted from sk 
    save_and_check_S_from_traces(run_index_local)

    print(f"\nSummary for run {run_index_local}, fault index {fault_index_local}:")
    print(f"  trigger_high hit = {hit_trigger_high}")
    print(f"  trigger_low hit  = {hit_trigger_low}")


# -------------------------- MAIN --------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--elf-file",
        type=str,
        required=True,
        help="Path to the ELF firmware file"
    )

    parser.add_argument(
        "--num-runs",
        type=int,
        required=True,
        help="Number of independent runs to collect"
    )

    parser.add_argument(
        "--fault-indices",
        type=int,
        nargs="*",
        required=False,
        default=[0],
        help="Fault indices to use per run. For truncated xs traces, use only 0."
    )

    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Parallel workers"
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to save full traces and snapshots"
    )

    parser.add_argument(
        "--output-dir-trim",
        required=True,
        help="Directory to save xs-product traces"
    )

    parser.add_argument(
        "--skip-snapshot",
        action="store_true",
        help="Skip snapshot creation and load existing snapshot from disk"
    )

    args = parser.parse_args()

    elf_file      = args.elf_file
    num_runs      = args.num_runs
    fault_indices = args.fault_indices

    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim

    total_tasks = num_runs * len(fault_indices)
    jobs        = min(args.jobs or max(total_tasks, 1), 4)

    global_output_dir = output_dir

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    snapshot_path = get_snapshot_path(output_dir)

    print("--------------------------------")
    print("Solving symbol addresses from ELF:")
    print("--------------------------------")

    trigger_setup_addr = normalize_addr(get_label_address(elf_file, "trigger_setup"))
    init_uart_addr     = normalize_addr(get_label_address(elf_file, "init_uart"))

    skip_addrs = {
        a for a in [trigger_setup_addr, init_uart_addr] if a is not None
    }

    clear_bytes_addr    = normalize_addr(get_label_address(elf_file, "clear_bytes"))
    main_addr           = normalize_addr(get_label_address(elf_file, "main"))
    kem_keypair_addr    = normalize_addr(get_label_address(elf_file, "crypto_kem_keypair"))
    trigger_high_addr   = normalize_addr(get_label_address(elf_file, "trigger_high"))
    crypto_kem_dec_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_dec"))
    trigger_low_addr    = normalize_addr(get_label_address(elf_file, "trigger_low"))

    mul_bs_addr = normalize_addr(get_label_address(elf_file, "mul_bs"))
    xs_addr     = normalize_addr(get_label_address(elf_file, "xs"))

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    print(f"[INFO] Skip addresses = {[hex(a) for a in sorted(skip_addrs)]}")
    print(f"[INFO] mul_bs address = {hex(mul_bs_addr) if mul_bs_addr else None}")
    print(f"[INFO] xs address     = {hex(xs_addr) if xs_addr else None}")

    print("--------------------------------")
    print("Preparing base ciphertexts:")
    print("--------------------------------")

    for run_index in range(num_runs):
        load_base_ciphertext(run_index)

    if args.skip_snapshot:
        if not os.path.exists(snapshot_path):
            print(f"[ERROR] No snapshot found at {snapshot_path}")
            print("Run without --skip-snapshot first.")
            sys.exit(1)

        print(f"[SKIP SNAPSHOT] Loading existing snapshot from {snapshot_path}")
        sk_path = os.path.join(output_dir, "sk.bin")
        if os.path.exists(sk_path):
            with open(sk_path, "rb") as f:
                sk = f.read()
            save_S_from_sk_csv(sk, os.path.join(get_S_dir(), "S.csv"))
        else:
            print(f"[ERROR] Missing sk.bin, cannot refresh S/S.csv: {sk_path}")

    else:
        print("------------------------------")
        print("Snapshot preparation — running keygen + decapsulation entry:")
        print("------------------------------")

        md = make_disasm()
        ql = setup_qiling_instance(elf_file)
        ql.hook_code(snapshot_tracing)

        try:
            ql.run()
        except SnapshotReady as e:
            print(e)
        except StopEmulation as e:
            print(e)
            sys.exit(1)
        except Exception as e:
            print(f"Error during snapshot run: {e}")
            traceback.print_exc()
            sys.exit(1)

        print("\nSnapshot run summary:")
        print(f"main hit           = {hit_main}")
        print(f"keypair hit        = {hit_kem_keypair}")
        print(f"crypto_kem_dec hit = {hit_crypto_kem_dec}")

        if not hit_crypto_kem_dec:
            print("Did not reach crypto_kem_dec, cannot proceed")
            sys.exit(1)

        if not os.path.exists(snapshot_path):
            print(f"[ERROR] Snapshot file was not created at {snapshot_path}")
            sys.exit(1)

    print("-------------------------------")
    print(f"Starting {num_runs} runs with {len(fault_indices)} fault indices = {total_tasks} tasks")
    print(f"Fault indices per run: {fault_indices}")
    print(f"Parallel workers: {jobs}")
    print("-------------------------------")

    worker_args = [
        (
            run_index,
            fault_index,
            snapshot_path,
            elf_file,
            output_dir,
            output_dir_trim,
            trigger_high_addr,
            trigger_low_addr,
            tuple(skip_addrs),
            g_ct_addr,
            clear_bytes_addr,
            mul_bs_addr,
            xs_addr,
        )
        for run_index in range(num_runs)
        for fault_index in fault_indices
    ]

    ctx = multiprocessing.get_context("spawn")

    with ctx.Pool(processes=jobs) as pool:
        pool.map(run_decapsulation_worker, worker_args)

    print("\nAll traces have been collected successfully")
