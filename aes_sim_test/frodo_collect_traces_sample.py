#!/usr/bin/env python3

import os
import sys
import argparse
import traceback
import multiprocessing

from path_helpers import (
    get_run_ciphertext_path,
    get_snapshot_path,
)
from ciphertext_creation import (
    load_base_ciphertext as load_base_ciphertext_from_path,
)
from stop_tracing import SnapshotReady, StopEmulation
from tracing import make_snapshot_tracing, run_sample_decapsulation_worker
from emulator_helpers import (
    get_label_address,
    make_disasm,
    normalize_addr,
    setup_qiling_instance,
)

# -------------------------- PATH CONFIGURATION --------------------------
# Number of runs and fault indices per run
# NUM_RUNS      = 5
# FAULT_INDICES = [0, 1, 2, 4, 8, 16, 32, 64 , 128, 256, 512]

# ELF_FILE        = "firmware/simpleserial-frodo-CW308_STM32F4.elf"
# OUTPUT_DIR      = "output_decapsulation_sample"
# OUTPUT_DIR_TRIM = "output_decapsulation_sample_TRIM"


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
crypto_kem_dec_addr = None
# fallback stop when crypto_kem_dec returns
dec_return_addr     = None

#flags for debugging 
hit_main           = False
hit_kem_keypair    = False
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

# contors 
instr_counter = 0
current_run_index   = 0
current_fault_index = 0

# instruction and registers initialisation
ins_trace = []
reg_trace = []


# -------------------------------- MAIN ---------------------------------

def main():
    global elf_file, output_dir, output_dir_trim, global_output_dir, snapshot_path
    global skip_addrs, clear_bytes_addr, main_addr, kem_keypair_addr
    global trigger_high_addr, crypto_kem_dec_addr, trigger_low_addr
    global g_pk_addr, g_sk_addr, g_ct_addr, g_keypair_done_addr, md
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

    elf_file      = args.elf_file 
    NUM_RUNS      = args.num_runs
    FAULT_INDICES = args.fault_indices
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim 

    num_runs      = args.num_runs
    fault_indices = args.fault_indices
    total_tasks   = num_runs * len(fault_indices)
    jobs          = min(args.jobs or max(total_tasks, 1), 4)

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

    g_pk_addr           = get_label_address(elf_file, "g_pk")
    g_sk_addr           = get_label_address(elf_file, "g_sk")
    g_ct_addr           = get_label_address(elf_file, "g_ct")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")

    print(f"[INFO] Skip addresses = {[hex(a) for a in sorted(skip_addrs)]}")

    # Ensure each run has its own base ciphertext
    print("--------------------------------")
    print("Preparing base ciphertexts:")
    print("--------------------------------")
    for run_index in range(num_runs):
        load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir, run_index))

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
        ql.hook_code(make_snapshot_tracing(globals()))

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
        print(f"  crypto_kem_dec hit   = {hit_crypto_kem_dec}")

        if not hit_crypto_kem_dec:
            print("Did not reach crypto_kem_dec, cannot proceed")
            sys.exit(1)

        if not os.path.exists(snapshot_path):
            print(f"[ERROR] Snapshot file was not created at {snapshot_path}")
            sys.exit(1)

    if total_tasks == 0:
        print("No traces requested. Done.")
        sys.exit(0)

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
        )
        for run_index in range(num_runs)
        for fault_index in fault_indices
    ]

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=jobs) as pool:
        pool.map(run_sample_decapsulation_worker, worker_args)

    print("\nAll traces have been collected successfully")


if __name__ == "__main__":
    main()
