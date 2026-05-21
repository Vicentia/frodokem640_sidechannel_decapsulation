#!/usr/bin/env python3

import os
import sys
import argparse
import traceback

from path_helpers import get_flat_ct_modified_path, get_flat_trace_csv_path, get_flat_trim_csv_path
from ciphertext_creation import (
    load_base_ciphertext as load_base_ciphertext_from_path,
    modify_ciphertext_c1_from_base,
    save_B_from_ciphertext_csv,
    test_modify_ciphertext_c1,
)
from stop_tracing import SnapshotReady, StopEmulation, hard_stop
from tracing import save_current_trace, reset_trace_state, save_keys_from_qiling
from parameters_initialisation import (
    BYTES_CIPHERTEXT_C1,
    BYTES_CIPHERTEXT_C2,
    CRYPTO_CIPHERTEXTBYTES,
    PARAMS_LOGQ,
    PARAMS_N,
    PARAMS_NBAR,
    REG_NAMES,
    SIZE_CT,
    SIZE_PK,
    SIZE_SK,
    SEED_A_length,
    S_length,
    b_length,
    pkh,
    s_length,
)
from emulator_helpers import (
    disasm_with,
    get_label_address,
    make_disasm,
    normalize_addr,
    setup_qiling_instance,
)

# -------------------------- PATH CONFIGURATION --------------------------

# ELF_FILE   = "firmware/simpleserial-frodo-CW308_STM32F4.elf"
# OUTPUT_DIR = "output_decapsulation_sequantial"
# OUTPUT_DIR_TRIM = "output_decapsulation_sequentially_TRIM"

# PK_PATH      = os.path.join(OUTPUT_DIR, "pk.bin")
# SK_PATH      = os.path.join(OUTPUT_DIR, "sk.bin")
# CT_BASE_PATH = os.path.join(OUTPUT_DIR, "ct_base.bin")

# -------------------------- GLOBAL VARIABLES ----------------------------

md = make_disasm()

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

def save_keypair(ql):
    global keypair_saved

    if keypair_saved:
        return

    save_keys_from_qiling(ql, output_dir, g_pk_addr, g_sk_addr, g_keypair_done_addr)
    keypair_saved = True


def save_ciphertext(ql, index):
    os.makedirs(output_dir, exist_ok=True)

    if g_ct_addr is not None:
        ct = ql.mem.read(g_ct_addr, SIZE_CT)
        ct_path = get_flat_ct_modified_path(output_dir, index)
        with open(ct_path, "wb") as f:
            f.write(ct)
        print(f"CT saved to {ct_path}")
        save_B_from_ciphertext_csv(bytes(ct), os.path.join(output_dir, "B", f"B_{index}.csv"))

    save_current_trace(globals(), get_flat_trace_csv_path(output_dir, index), get_flat_trim_csv_path(output_dir_trim, index), output_dir, index)


# Hooks
def full_tracing(ql, address, size):
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

    ins, arg = disasm_with(ql, md, address)

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

        base_ct = load_base_ciphertext_from_path(ct_base_path)
        c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, fault_index)
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


def main():
    global elf_file, fault_index, output_dir, output_dir_trim
    global pk_path, sk_path, ct_base_path, current_traces_dir, skip, md
    global main_addr, kem_keypair_addr, trigger_high_addr, crypto_kem_dec_addr, trigger_low_addr
    global g_pk_addr, g_sk_addr, g_ct_addr, g_keypair_done_addr
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

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    reset_trace_state(globals(), include_main_flags=True)

    ql = setup_qiling_instance(elf_file, patch_uart=False, include_bitband=False)
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


if __name__ == "__main__":
    main()
