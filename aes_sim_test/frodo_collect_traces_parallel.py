#!/usr/bin/env python3
import os
import sys
import argparse
import traceback
import multiprocessing  # for running in parallel
from functools import partial # for passing multiple arguments to pool.starmap

from TRACE_path_helpers import get_snapshot_path
from TRACE_ciphertext_creation import load_base_ciphertext, save_B_from_ciphertext_csv
from TRACE_stop_tracing import SnapshotReady, StopEmulation
from TRACE_tracing import make_snapshot_tracing, run_decapsulation_worker
from TRACE_emulator_helpers import (
    get_label_address,
    make_disasm,
    normalize_addr,
    setup_qiling_instance,
)

# -------------------------- PATH CONFIGURATION --------------------------

# N_PARALLEL     = 641
# JOBS_PARALLEL  = 10
# OUTPUT_DIR_PARALLEL    = output_decapsulation_parallel
# OUTPUT_DIR_PARALLEL_TRIM = output_decapsulation_parallel_TRIM
# ELF_FILE = "firmware/simpleserial-frodo-CW308_STM32F4.elf"

# -------------------------- VARIABLES ------------------------------------

md = None

# initialization addresses
main_addr           = None
trigger_high_addr   = None
trigger_low_addr    = None
skip_addrs          = set()
clear_bytes_addr    = None

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
# fallback stop when crypto_kem_dec returns
dec_return_addr     = None

#flags for debugging 
hit_main           = False
hit_kem_keypair    = False
hit_crypto_kem_enc = False
hit_trigger_high   = False
hit_crypto_kem_dec = False
snapshot_saved     = False
hit_trigger_low    = False
trace_started      = False
trace_saved        = False
# prevents hook re-entrancy after emu_stop() is called
stop_requested     = False

address_PK = None
address_SK = None
address_CT = None

# globals 
global_output_dir   = None
output_dir          = None
output_dir_trim     = None
snapshot_path       = None
snapshot_at         = "crypto_kem_dec"
snapshot_mode       = "parallel"

# contors 
instr_counter = 0
current_run_index   = 0
current_fault_index = 0
use_host_randombytes = False

# instruction and registers initialisation
ins_trace = []
reg_trace = []

# main
def main():
    global elf_file, output_dir, output_dir_trim, pk_path, SK_PATH
    global global_output_dir, snapshot_path, snapshot_at, snapshot_mode, skip_addrs, clear_bytes_addr
    global main_addr, kem_keypair_addr, trigger_high_addr, crypto_kem_enc_addr, crypto_kem_dec_addr, trigger_low_addr
    global randombytes_addr
    global g_pk_addr, g_sk_addr, g_ct_addr, g_keypair_done_addr, md
    global use_host_randombytes

    parser = argparse.ArgumentParser()
    parser.add_argument(
    "--elf-file",
    required=True,
    help="Path to the ELF firmware file"
    )
    parser.add_argument(
        "--n",
        type=int,
        default=0,
        help="Number of decapsulation traces to collect (0 = snapshot only)"
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="The directory in which the entire trace will be save"
    )
    parser.add_argument(
        "--output-dir-trim",
        required=True,
        help="The directory in which the trim capture will be saved"
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Parallel workers (default: N, capped at 4)"
    )
    parser.add_argument(
        "--skip-snapshot",
        action="store_true",
        help="Skip snapshot creation and load existing snapshot from disk"
    )
    parser.add_argument(
        "--ciphertext-mode",
        choices=["valid", "modified"],
        default="modified",
        help="Use the firmware-generated ciphertext unchanged, or modify C1 before tracing"
    )
    parser.add_argument(
        "--use-host-randombytes",
        action="store_true",
        help="Hook firmware randombytes() during crypto_kem_enc so valid ciphertexts differ across snapshots",
    )
    args = parser.parse_args()

    elf_file        = args.elf_file
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim
    pk_path         = os.path.join(output_dir, "pk.bin")
    SK_PATH         = os.path.join(output_dir, "sk.bin")

    elf_file   = args.elf_file
    N          = args.n
    jobs       = min(args.jobs or max(N, 1), 4)
    use_host_randombytes = args.use_host_randombytes

    global_output_dir = output_dir
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir_trim, exist_ok=True)

    snapshot_path = get_snapshot_path(output_dir)

    print("--------------------------------")
    print("Solving symbol addresses from ELF:")
    print("--------------------------------")

    # Check if they have been hit 
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
    crypto_kem_enc_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_enc"))
    randombytes_addr    = normalize_addr(get_label_address(elf_file, "randombytes"))
    trigger_low_addr    = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    print(f"[INFO] Skip addresses = {[hex(a) for a in sorted(skip_addrs)]}")
    print(f"[INFO] crypto_kem_enc address = {hex(crypto_kem_enc_addr) if crypto_kem_enc_addr else None}")
    print(f"[INFO] crypto_kem_dec address = {hex(crypto_kem_dec_addr) if crypto_kem_dec_addr else None}")
    print(f"[INFO] randombytes address = {hex(randombytes_addr) if randombytes_addr else None}")
    print(f"[INFO] use host randombytes = {use_host_randombytes}")

    ct_base_path = os.path.join(output_dir, "ct_base.bin")

    if args.skip_snapshot:
        if not os.path.exists(snapshot_path):
            print(f"[ERROR] No snapshot found at {snapshot_path}")
            print("Run without --skip-snapshot first to generate it.")
            sys.exit(1)
        print(f"[SKIP SNAPSHOT] Loading existing snapshot from {snapshot_path}")

    else:
        print("------------------------------")
        print("Snapshot preparation — running keygen + encapsulation + crypto_kem_dec entry:")
        print("------------------------------")
        md = make_disasm()
        snapshot_at = "crypto_kem_dec"
        snapshot_mode = "parallel"
        ql = setup_qiling_instance(elf_file)
        ql.hook_code(partial(make_snapshot_tracing, namespace=globals()))

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
        print(f"  main hit             = {hit_main}")
        print(f"  keypair hit          = {hit_kem_keypair}")
        print(f"  crypto_kem_enc hit   = {hit_crypto_kem_enc}")
        print(f"  crypto_kem_dec hit   = {hit_crypto_kem_dec}")

        if not hit_crypto_kem_dec:
            print("Did not reach crypto_kem_dec, cannot proceed")
            sys.exit(1)

        if not os.path.exists(snapshot_path):
            print(f"[ERROR] Snapshot file was not created at {snapshot_path}")
            sys.exit(1)

        base_ct = load_base_ciphertext(ct_base_path, force_generate=True)
        save_B_from_ciphertext_csv(base_ct, os.path.join(output_dir, "B", "B_base.csv"))

        if N == 0:
            print("\nJust the snapshot was created")
            sys.exit(0)

    if N == 0:
        print("No traces requested (--n 0). Done.")
        sys.exit(0)

    print("-------------------------------")
    print("Starting decapsulation workers in parallel:")
    print("-------------------------------")

    worker_indices = [0] if args.ciphertext_mode == "valid" else range(N)
    worker_args = [
        (
            i,
            snapshot_path,
            elf_file,
            output_dir,
            output_dir_trim,
            trigger_high_addr,
            trigger_low_addr,
            tuple(skip_addrs),
            g_ct_addr,
            clear_bytes_addr,
            crypto_kem_dec_addr,
            args.ciphertext_mode,
            "crypto_kem_dec",
        )
        for i in worker_indices
    ]

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=jobs) as pool:
        pool.starmap(run_decapsulation_worker, [(args, "parallel") for args in worker_args])

    print("\nAll traces have been collected successfully")

if __name__ == "__main__":
    main()


    
