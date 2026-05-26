#!/usr/bin/env python3

import sys
import argparse
import traceback
import os
from functools import partial # for passing multiple arguments to pool.starmap

from TRACE_stop_tracing import StopEmulation
from TRACE_tracing import make_full_trace, reset_trace_state
from TRACE_emulator_helpers import (
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
crypto_kem_enc_addr = None
crypto_kem_dec_addr = None
randombytes_addr    = None

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
ciphertext_mode    = "modified"

# Whether PK/SK have already been saved 
keypair_saved = False


def main():
    global elf_file, fault_index, output_dir, output_dir_trim
    global ciphertext_mode
    global pk_path, sk_path, ct_base_path, current_traces_dir, skip, md
    global main_addr, kem_keypair_addr, trigger_high_addr, crypto_kem_enc_addr, crypto_kem_dec_addr, trigger_low_addr
    global randombytes_addr
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
    parser.add_argument(
        "--ciphertext-mode",
        choices=["valid", "modified"],
        default="modified",
        help="Use the firmware-generated valid ciphertext or a modified ciphertext",
    )
    args = parser.parse_args()
    
    elf_file = args.elf_file 
    fault_index = args.fault_index
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim
    ciphertext_mode = args.ciphertext_mode
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
    crypto_kem_enc_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_enc"))
    crypto_kem_dec_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_dec"))
    randombytes_addr    = normalize_addr(get_label_address(elf_file, "randombytes"))
    trigger_low_addr    = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    print(f"crypto_kem_enc address = {hex(crypto_kem_enc_addr) if crypto_kem_enc_addr else None}")
    print(f"crypto_kem_dec address = {hex(crypto_kem_dec_addr) if crypto_kem_dec_addr else None}")
    print(f"randombytes address    = {hex(randombytes_addr) if randombytes_addr else None}")
    print(f"ciphertext mode        = {ciphertext_mode}")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    reset_trace_state(globals(), include_main_flags=True)

    ql = setup_qiling_instance(elf_file, patch_uart=False, include_bitband=False)
    ql.hook_code(partial(make_full_trace, namespace=globals()))

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
