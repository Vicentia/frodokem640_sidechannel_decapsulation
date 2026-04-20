#!/usr/bin/env python3

import queue
import os
import csv
import sys
import pickle
import argparse
import traceback
import multiprocessing

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
# Number of runs and fault indices per run
# NUM_RUNS      = 5
# FAULT_INDICES = [0, 1, 2, 4, 8, 16, 32, 64 , 128, 256, 512]

ELF_FILE        = "firmware/simpleserial-frodo-CW308_STM32F4.elf"
# OUTPUT_DIR      = "output_decapsulation_sample"
# OUTPUT_DIR_TRIM = "output_decapsulation_sample_TRIM"


# -------------------------- PATH HELPERS ---------------------------

# Snapshot lives once at the top level and is shared across all runs
def get_snapshot_path():
    return os.path.join(output_dir, "snapshot.pkl")


def get_pk_path():
    return os.path.join(output_dir, "pk.bin")


def get_sk_path():
    return os.path.join(output_dir, "sk.bin")


def get_run_dir(run_index):
    return os.path.join(output_dir, f"Run_{run_index + 1}")


def get_trace_dir(run_index, fault_index):
    return os.path.join(get_run_dir(run_index), f"Trace_{fault_index}")


def get_trace_csv_path(run_index, fault_index):
    return os.path.join(get_trace_dir(run_index, fault_index), f"trace_{fault_index}.csv")


def get_ct_modified_path(run_index, fault_index):
    return os.path.join(get_trace_dir(run_index, fault_index), f"ct_modified_{fault_index}.bin")


def get_trim_csv_path(run_index, fault_index):
    return os.path.join(output_dir_trim, f"Run_{run_index + 1}", f"trace_{fault_index}.csv")


# Per-run base ciphertext path
def get_ct_base_path(run_index):
    return os.path.join(get_run_dir(run_index), f"ct_base_run{run_index + 1}.bin")


# -------------------------- GLOBAL VARIABLES ---------------------------

md = None

clear_bytes_addr    = None
main_addr           = None
kem_keypair_addr    = None
trigger_high_addr   = None
trigger_low_addr    = None
crypto_kem_dec_addr = None
skip_addr           = None

g_pk_addr           = None
g_sk_addr           = None
g_ct_addr           = None
g_keypair_done_addr = None

global_output_dir   = None

hit_main           = False
hit_kem_keypair    = False
hit_trigger_high   = False
hit_crypto_kem_dec = False

address_PK = None
address_SK = None

instr_counter = 0

# ----------------------------- GLOBALS FOR DECAPSULATION ----------------------------

hit_trigger_low  = False
trace_started    = False
trace_saved      = False
address_CT       = None

current_run_index   = 0
current_fault_index = 0

ins_trace = []
reg_trace = []


def reset_decapsulation_globals():
    global hit_crypto_kem_dec, hit_trigger_high, hit_trigger_low
    global trace_started, trace_saved, instr_counter
    global ins_trace, reg_trace, address_CT

    hit_crypto_kem_dec = False
    hit_trigger_high   = False
    hit_trigger_low    = False
    trace_started      = False
    trace_saved        = False
    instr_counter      = 0
    address_CT         = None
    ins_trace.clear()
    reg_trace.clear()


# Exceptions to stop the emulator
class StopEmulation(Exception):
    pass


class SnapshotReady(Exception):
    pass


# --------------------- HELPERS FOR CIPHERTEXT --------------------------

def generate_base_ciphertext(run_index):
    run_dir = get_run_dir(run_index)
    os.makedirs(run_dir, exist_ok=True)

    ct_base_path = get_ct_base_path(run_index)

    c1_random = os.urandom(BYTES_CIPHERTEXT_C1)
    c2        = bytes(BYTES_CIPHERTEXT_C2)
    salt      = bytes(CRYPTO_CIPHERTEXTBYTES - BYTES_CIPHERTEXT_C1 - BYTES_CIPHERTEXT_C2)
    base_ct   = c1_random + c2 + salt

    with open(ct_base_path, "wb") as f:
        f.write(base_ct)

    print(f"[INFO] Base ciphertext for Run_{run_index + 1} created at {ct_base_path}")
    return base_ct


def load_base_ciphertext(run_index):
    ct_base_path = get_ct_base_path(run_index)

    if not os.path.exists(ct_base_path):
        return generate_base_ciphertext(run_index)

    with open(ct_base_path, "rb") as f:
        ct_base = f.read()

    if len(ct_base) != CRYPTO_CIPHERTEXTBYTES:
        raise ValueError(
            f"[ERROR] Base ciphertext for Run_{run_index + 1} has wrong size: "
            f"{len(ct_base)} != {CRYPTO_CIPHERTEXTBYTES}"
        )

    print(f"[INFO] Loaded base ciphertext for Run_{run_index + 1} from {ct_base_path}")
    return ct_base


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
                val |= ((c1[byte_pos] >> bit_pos) & 1) << bit
            values.append(val)
    return values


def test_modify_ciphertext_c1(run_index, index, c1_random=None, ct=None):
    if c1_random is None or ct is None:
        c1_random, ct = modify_ciphertext_c1(run_index, index)

    c1_altered = ct[:BYTES_CIPHERTEXT_C1]

    random_vals  = unpack_c1(c1_random)
    altered_vals = unpack_c1(c1_altered)

    if len(c1_random) != BYTES_CIPHERTEXT_C1:
        raise StopEmulation(
            f"[ERROR] The size of c1_random {len(c1_random)} does not match expected {BYTES_CIPHERTEXT_C1}"
        )

    if len(ct) != CRYPTO_CIPHERTEXTBYTES:
        raise StopEmulation(
            f"[ERROR] The size of ct {len(ct)} does not match expected {CRYPTO_CIPHERTEXTBYTES}"
        )

    for ind in range(index):
        for i in range(PARAMS_NBAR):
            val = altered_vals[i * PARAMS_N + ind]
            if val != 0:
                raise StopEmulation(
                    f"[ERROR] The first {index} columns should be zeroed, "
                    f"but column {ind} row {i} is not zero: {val}"
                )

    for ind in range(index, PARAMS_N):
        for i in range(PARAMS_NBAR):
            if altered_vals[i * PARAMS_N + ind] != random_vals[i * PARAMS_N + ind]:
                raise StopEmulation(
                    f"[ERROR] Column {ind} row {i} was changed unexpectedly"
                )

    q = 1 << PARAMS_LOGQ
    total_sum   = sum(random_vals) % q
    removed_sum = sum(
        random_vals[i * PARAMS_N + ind]
        for ind in range(index)
        for i in range(PARAMS_NBAR)
    ) % q
    new_sum  = sum(altered_vals) % q
    expected = (total_sum - removed_sum) % q

    if new_sum != expected:
        raise StopEmulation(f"[ERROR] Sum check failed: {new_sum} != {expected}")

    print(f"[TEST PASSED] Ciphertext modification for Run_{run_index + 1}, index {index} is correct")


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


def save_snapshot_manual(ql):
    print("Starting snapshot...")
    snapshot = {
        "regs": {r: ql.arch.regs.read(r) for r in REG_NAMES},
        "memory": [],
    }
    print(f"Registers saved: {snapshot['regs']}")

    SKIP_LABEL_KEYWORDS = [
        "BITBAND", "BBR", "FLASH", "REMAP", "SYSTEM", "FLASH OTP",
    ]

    for start, end, perms, label, _ in ql.mem.get_mapinfo():
        region_size = end - start
        label_str   = str(label)

        if any(k in label_str.upper() for k in SKIP_LABEL_KEYWORDS):
            print(f"[SKIP] Region {label}: {hex(start)}-{hex(end)} ({region_size} bytes)")
            continue

        if region_size > 0x400000:
            print(f"[SKIP LARGE] Region {label}: {hex(start)}-{hex(end)} ({region_size} bytes)")
            continue

        try:
            data = bytes(ql.mem.read(start, region_size))
            snapshot["memory"].append((start, end, perms, label, data))
            print(f"Saved region {label}: {hex(start)}-{hex(end)} ({region_size} bytes)")
        except Exception as e:
            print(f"[SKIP] Failed to read region {label} {hex(start)}-{hex(end)}: {e}")

    print(f"Snapshot complete: {len(snapshot['memory'])} regions")
    return snapshot


def restore_snapshot_manual(ql, snapshot):
    for start, end, perms, label, data in snapshot["memory"]:
        try:
            ql.mem.write(start, data)
            print(f"Restored region [{label}]: {hex(start)}-{hex(end)}")
        except Exception as e:
            print(f"[WARN] Failed to restore region [{label}] {hex(start)}-{hex(end)}: {e}")

    for reg, val in snapshot["regs"].items():
        try:
            ql.arch.regs.write(reg, val)
        except Exception as e:
            print(f"[WARN] Failed to restore register {reg}: {e}")


def hook_mem_invalid(uc, access, address, size, value, user_data):
    return True


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

    class NonBlockingQueue(queue.Queue):
        def get(self, block=True, timeout=None):
            try:
                return super().get(block=False)
            except queue.Empty:
                return 0x00

    for usart_name in ("usart1", "usart2"):
        try:
            usart = ql.hw.get(usart_name)
            old   = usart.itube
            new_q = NonBlockingQueue()
            while not old.empty():
                try:
                    new_q.put_nowait(old.get_nowait())
                except queue.Empty:
                    break
            usart.itube = new_q
            print(f"[INFO] Patched {usart_name}.itube with NonBlockingQueue")
        except Exception as e:
            print(f"[WARN] Could not patch {usart_name}: {e}")

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


def save_keys(ql, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    if g_pk_addr is not None:
        pk = bytes(ql.mem.read(g_pk_addr, SIZE_PK))
        pk_path = os.path.join(output_dir, "pk.bin")
        with open(pk_path, "wb") as f:
            f.write(pk)
        print(f"PK saved to {pk_path}")

    if g_sk_addr is not None:
        sk = bytes(ql.mem.read(g_sk_addr, SIZE_SK))
        sk_path = os.path.join(output_dir, "sk.bin")
        with open(sk_path, "wb") as f:
            f.write(sk)
        print(f"SK saved to {sk_path}")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")


def save_csv(run_index, fault_index):
    global trace_saved

    if trace_saved:
        return

    full_csv = get_trace_csv_path(run_index, fault_index)
    trim_csv = get_trim_csv_path(run_index, fault_index)

    print(f"Saving trace to {full_csv}")
    print(f"Trace length: {len(ins_trace)} instructions")

    os.makedirs(os.path.dirname(full_csv), exist_ok=True)
    os.makedirs(os.path.dirname(trim_csv), exist_ok=True)

    # Full trace
    with open(full_csv, "w", newline="") as csvfile:
        writer_csv = csv.writer(csvfile)
        writer_csv.writerow([
            "pc", "instruction", "operands",
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
        ])
        for ins_info, regs in zip(ins_trace, reg_trace):
            regs_hex = [hex(x) for x in regs]
            writer_csv.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)

    with open(trim_csv, "w", newline="") as csvfile_trim:
        writer_trim = csv.writer(csvfile_trim)
        writer_trim.writerow(REG_NAMES[:-1])
        for regs in reg_trace:
            writer_trim.writerow([hex(x) for x in regs[:-1]])

    print(f"Trimmed trace saved to {trim_csv}")

    trace_saved = True
    print("Trace saved")

    ins_trace.clear()
    reg_trace.clear()


# -------------------- SNAPSHOT TRACING HOOK ----------------------------

def snapshot_tracing(ql, address, size):
    global hit_main, hit_kem_keypair, hit_trigger_high, hit_crypto_kem_dec
    global instr_counter
    global address_PK, address_SK, address_CT

    instr_counter += 1

    if address == skip_addr:
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
            print(f"[WARN] clear_bytes({hex(mem_ptr)}, {n}) failed: {e}")
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
        ql.emu_stop()
        raise SnapshotReady("Reached crypto_kem_dec — snapshot ready")


# -------------------- DECAPSULATION TRACING HOOK -----------------------

def decapsulation_tracing(ql, address, size):
    global hit_trigger_high, hit_trigger_low
    global trace_started, instr_counter
    global ins_trace, reg_trace

    instr_counter += 1

    if address == skip_addr:
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    ins, arg = disasm(ql, address)

    if instr_counter % 10000 == 0:
        print(
            f"[PROGRESS DECAPSULATION] instr={instr_counter} "
            f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
            f"lr={hex(ql.arch.regs.read('lr'))} "
            f"ins={ins} {arg}"
        )

    if clear_bytes_addr and address == clear_bytes_addr:
        mem_ptr = ql.arch.regs.read("r0")
        n       = ql.arch.regs.read("r1")
        try:
            ql.mem.write(mem_ptr, b"\x00" * n)
        except Exception as e:
            print(f"[WARN IN DECAPSULATION] clear_bytes({hex(mem_ptr)}, {n}) failed: {e}")
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if trigger_high_addr and address == trigger_high_addr and not hit_trigger_high:
        hit_trigger_high = True
        trace_started    = True
        ins_trace.clear()
        reg_trace.clear()
        print(f"trigger_high() at {hex(address)}, trace starts here")

    if trace_started:
        regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
        ins_trace.append([ins, arg])
        reg_trace.append(regs_now)

    if trigger_low_addr and address == trigger_low_addr and not hit_trigger_low:
        hit_trigger_low = True
        print(f"trigger_low() at {hex(address)}")
        print(f"Number of instructions collected: {len(ins_trace)}")
        save_csv(current_run_index, current_fault_index)
        print("Stop emulator")
        ql.emu_stop()
        raise StopEmulation("Trace captured, stopping emulator now")


# -------------------- WORKER FOR PARALLEL EXECUTION --------------------

def run_decapsulation_worker(worker_args):
    (
        run_index_local,
        fault_index_local,
        snapshot_path,
        elf_file,
        output_dir_local,
        output_dir_trim_local, 
        trigger_high_addr_local,
        trigger_low_addr_local,
        skip_addr_local,
        g_ct_addr_local,
        clear_bytes_addr_local,
    ) = worker_args

    # Set all module-level globals needed by hooks
    global current_run_index, current_fault_index
    global trigger_high_addr, trigger_low_addr
    global skip_addr, g_ct_addr, global_output_dir, md
    global clear_bytes_addr
    global output_dir, output_dir_trim

    current_run_index   = run_index_local
    current_fault_index = fault_index_local
    trigger_high_addr   = trigger_high_addr_local
    trigger_low_addr    = trigger_low_addr_local
    skip_addr           = skip_addr_local
    g_ct_addr           = g_ct_addr_local
    clear_bytes_addr    = clear_bytes_addr_local
    global_output_dir   = output_dir_local
    global_output_dir_trim = output_dir_trim_local
    md                  = make_disasm()

    trace_dir = get_trace_dir(run_index_local, fault_index_local)
    os.makedirs(trace_dir, exist_ok=True)

    reset_decapsulation_globals()

    ql = setup_qiling_instance(elf_file)

    with open(snapshot_path, "rb") as f:
        snapshot = pickle.load(f)
    restore_snapshot_manual(ql, snapshot)
    del snapshot

    # IMPORTANT: each run has its own base ciphertext now
    c1_initial, altered_ct = modify_ciphertext_c1(run_index_local, fault_index_local)
    test_modify_ciphertext_c1(
        run_index_local,
        fault_index_local,
        c1_random=c1_initial,
        ct=altered_ct
    )

    ql.mem.write(g_ct_addr, bytes(altered_ct))
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Modified CT written to g_ct ({hex(g_ct_addr)})"
    )

    ct_path = get_ct_modified_path(run_index_local, fault_index_local)
    os.makedirs(os.path.dirname(ct_path), exist_ok=True)
    with open(ct_path, "wb") as f:
        f.write(altered_ct)
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"ct_modified saved to {ct_path}"
    )

    ql.hook_code(decapsulation_tracing)

    print(f"\n-----------------------------")
    print(f"Running decapsulation for Run_{run_index_local + 1}, fault index {fault_index_local}...")

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print(f"Error during decapsulation (run={run_index_local + 1} fault={fault_index_local}): {e}")
        traceback.print_exc()

    print(f"\nSummary for Run_{run_index_local + 1}, fault index {fault_index_local}:")
    print(f"  trigger_high hit = {hit_trigger_high}")
    print(f"  trigger_low hit  = {hit_trigger_low}")


# -------------------------------- MAIN ---------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--num-runs",
        type=int,
        required= True,
        help="Number of independent runs to collect"
    )
    parser.add_argument(
        "--fault-indices",
        type=int,
        nargs="*",        
        required=False, 
        default=[],
        help="Fault indices to use per run"
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Parallel workers (default: num_runs * len(fault_indices), capped at 4)"
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to save full traces"
    )
    parser.add_argument(
        "--output-dir-trim",
        required=True,
        help="Directory to save trimmed traces"
    )
    parser.add_argument(
        "--skip-snapshot",
        action="store_true",
        help="Skip snapshot creation and load existing snapshot from disk"
    )
    args = parser.parse_args()

    elf_file      = ELF_FILE
    NUM_RUNS      = args.num_runs
    FAULT_INDICES = args.fault_indices
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim 

    num_runs      = args.num_runs
    fault_indices = args.fault_indices
    total_tasks   = num_runs * len(fault_indices)
    jobs          = min(args.jobs or total_tasks, 4)

    global_output_dir = output_dir
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    snapshot_path = get_snapshot_path()

    print("--------------------------------")
    print("Solving symbol addresses from ELF:")
    print("--------------------------------")
    skip_addr           = normalize_addr(get_label_address(elf_file, "trigger_setup"))
    clear_bytes_addr    = normalize_addr(get_label_address(elf_file, "clear_bytes"))
    main_addr           = normalize_addr(get_label_address(elf_file, "main"))
    kem_keypair_addr    = normalize_addr(get_label_address(elf_file, "crypto_kem_keypair"))
    trigger_high_addr   = normalize_addr(get_label_address(elf_file, "trigger_high"))
    crypto_kem_dec_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_dec"))
    trigger_low_addr    = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    # Ensure each run has its own base ciphertext
    print("--------------------------------")
    print("Preparing per-run base ciphertexts:")
    print("--------------------------------")
    for run_index in range(num_runs):
        load_base_ciphertext(run_index)

    if args.skip_snapshot:
        if not os.path.exists(snapshot_path):
            print(f"[ERROR] No snapshot found at {snapshot_path}")
            print("Run without --skip-snapshot first to generate it.")
            sys.exit(1)
        print(f"[SKIP SNAPSHOT] Loading existing snapshot from {snapshot_path}")

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
        except Exception as e:
            print(f"Error during snapshot run: {e}")
            traceback.print_exc()
            sys.exit(1)

        print("\nSnapshot run summary:")
        print(f"  main hit             = {hit_main}")
        print(f"  keypair hit          = {hit_kem_keypair}")
        print(f"  crypto_kem_dec hit   = {hit_crypto_kem_dec}")

        if not hit_crypto_kem_dec:
            print("Did not reach crypto_kem_dec, cannot proceed")
            sys.exit(1)

        print(f"\nSaving snapshot to {snapshot_path}")
        snapshot = save_snapshot_manual(ql)
        print(f"Snapshot dict has {len(snapshot['memory'])} memory regions")
        print(f"Snapshot regs: {snapshot['regs']}")

        try:
            with open(snapshot_path, "wb") as f:
                pickle.dump(snapshot, f)
            print(f"Snapshot saved successfully, file size: {os.path.getsize(snapshot_path)} bytes")
        except Exception as e:
            print(f"[ERROR] Failed to save snapshot: {e}")
            traceback.print_exc()
            sys.exit(1)

    print("-------------------------------")
    print(f"Starting {num_runs} runs × {len(fault_indices)} fault indices = {total_tasks} tasks")
    print(f"Fault indices per run: {fault_indices}")
    print(f"Parallel workers: {jobs}")
    print("-------------------------------")

    # Build all (run_index, fault_index) pairs
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
            skip_addr,
            g_ct_addr,
            clear_bytes_addr,
        )
        for run_index in range(num_runs)
        for fault_index in fault_indices
    ]

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=jobs) as pool:
        pool.map(run_decapsulation_worker, worker_args)

    print("\nAll traces have been collected successfully")
