#!/usr/bin/env python3

import os
import sys
import argparse
import traceback
import multiprocessing
from functools import partial # for passing multiple arguments to pool.starmap

from TRACE_path_helpers import (
    get_run_ciphertext_path,
    get_sample_snapshot_path,
    get_snapshot_path,
)
from TRACE_ciphertext_creation import load_base_ciphertext, save_B_from_ciphertext_csv
from TRACE_stop_tracing import SnapshotReady, StopEmulation
from TRACE_tracing import make_snapshot_tracing, reset_trace_state, run_decapsulation_worker
from TRACE_emulator_helpers import (
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
crypto_kem_enc_addr = None
crypto_kem_dec_addr = None
randombytes_addr    = None
# fallback stop when crypto_kem_dec returns
dec_return_addr     = None

#flags for debugging 
hit_main           = False
hit_kem_keypair    = False
hit_trigger_high   = False
hit_crypto_kem_enc = False
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

# contors 
instr_counter = 0
current_run_index   = 0
current_fault_index = 0
use_host_randombytes = False

# instruction and registers initialisation
ins_trace = []
reg_trace = []


def run_sample_snapshot_worker(worker_args):
    (
        run_index,
        elf_file_local,
        output_dir_local,
        trigger_high_addr_local,
        trigger_low_addr_local,
        skip_addrs_local,
        clear_bytes_addr_local,
        main_addr_local,
        kem_keypair_addr_local,
        crypto_kem_enc_addr_local,
        crypto_kem_dec_addr_local,
        randombytes_addr_local,
        g_pk_addr_local,
        g_sk_addr_local,
        g_ct_addr_local,
        g_keypair_done_addr_local,
        use_host_randombytes_local,
    ) = worker_args

    snapshot_path_local = get_sample_snapshot_path(output_dir_local, run_index)

    namespace = {
        "md": make_disasm(),
        "main_addr": main_addr_local,
        "trigger_high_addr": trigger_high_addr_local,
        "trigger_low_addr": trigger_low_addr_local,
        "skip_addrs": set(skip_addrs_local),
        "clear_bytes_addr": clear_bytes_addr_local,
        "kem_keypair_addr": kem_keypair_addr_local,
        "crypto_kem_enc_addr": crypto_kem_enc_addr_local,
        "crypto_kem_dec_addr": crypto_kem_dec_addr_local,
        "randombytes_addr": randombytes_addr_local,
        "g_pk_addr": g_pk_addr_local,
        "g_sk_addr": g_sk_addr_local,
        "g_ct_addr": g_ct_addr_local,
        "g_keypair_done_addr": g_keypair_done_addr_local,
        "global_output_dir": output_dir_local,
        "key_index": run_index,
        "output_dir": output_dir_local,
        "snapshot_path": snapshot_path_local,
        "snapshot_at": "crypto_kem_dec",
        "snapshot_mode": "sample",
        "use_host_randombytes": use_host_randombytes_local,
        "snapshot_progress_interval": 100_000,
        "current_run_index": run_index,
        "current_fault_index": 0,
        "ins_trace": [],
        "reg_trace": [],
    }
    reset_trace_state(namespace, include_main_flags=True)

    print("------------------------------")
    print(f"Snapshot preparation for run {run_index} — keygen + encapsulation + crypto_kem_dec entry:")
    print("------------------------------")

    ql = setup_qiling_instance(elf_file_local)
    ql.hook_code(partial(make_snapshot_tracing, namespace=namespace))

    try:
        ql.run()
    except SnapshotReady as e:
        print(e)
    except StopEmulation as e:
        print(e)
        raise
    except Exception:
        print(f"Error during snapshot run {run_index}:")
        traceback.print_exc()
        raise

    print("\nSnapshot run summary:")
    print(f"run                = {run_index}")
    print(f"main hit           = {namespace.get('hit_main')}")
    print(f"keypair hit        = {namespace.get('hit_kem_keypair')}")
    print(f"crypto_kem_enc hit = {namespace.get('hit_crypto_kem_enc')}")
    print(f"crypto_kem_dec hit = {namespace.get('hit_crypto_kem_dec')}")

    if not namespace.get("hit_crypto_kem_dec"):
        raise StopEmulation(f"Did not reach crypto_kem_dec for run {run_index}")

    if not os.path.exists(snapshot_path_local):
        raise FileNotFoundError(f"Snapshot file was not created at {snapshot_path_local}")

    base_ct_path = get_run_ciphertext_path(output_dir_local, run_index)
    base_ct = load_base_ciphertext(base_ct_path, force_generate=True)
    save_B_from_ciphertext_csv(base_ct, os.path.join(output_dir_local, "B", f"B_base_{run_index}.csv"))
    return snapshot_path_local


# -------------------------------- MAIN ---------------------------------

def main():
    global elf_file, output_dir, output_dir_trim, global_output_dir, snapshot_path, snapshot_at
    global skip_addrs, clear_bytes_addr, main_addr, kem_keypair_addr
    global trigger_high_addr, crypto_kem_enc_addr, crypto_kem_dec_addr, trigger_low_addr
    global randombytes_addr
    global g_pk_addr, g_sk_addr, g_ct_addr, g_keypair_done_addr, md
    global current_run_index, use_host_randombytes
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

    elf_file      = args.elf_file 
    NUM_RUNS      = args.num_runs
    FAULT_INDICES = args.fault_indices
    output_dir      = args.output_dir
    output_dir_trim = args.output_dir_trim 

    num_runs      = args.num_runs
    fault_indices = args.fault_indices
    total_tasks   = num_runs * len(fault_indices)
    jobs          = args.jobs or max(total_tasks, num_runs, 1)
    use_host_randombytes = args.use_host_randombytes

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

    if args.skip_snapshot:
        missing_snapshots = [
            get_sample_snapshot_path(output_dir, run_index)
            for run_index in range(num_runs)
            if not os.path.exists(get_sample_snapshot_path(output_dir, run_index))
        ]
        if missing_snapshots:
            print(f"[ERROR] Missing snapshots: {missing_snapshots[:5]}")
            print("Run without --skip-snapshot first to generate it.")
            sys.exit(1)
        print(f"[SKIP SNAPSHOT] Loading existing per-run snapshots from {output_dir}")

    else:
        print("------------------------------")
        print(f"Creating {num_runs} per-run sample snapshots with {jobs} worker(s)")
        print("------------------------------")

        snapshot_worker_args = [
            (
                run_index,
                elf_file,
                output_dir,
                trigger_high_addr,
                trigger_low_addr,
                tuple(skip_addrs),
                clear_bytes_addr,
                main_addr,
                kem_keypair_addr,
                crypto_kem_enc_addr,
                crypto_kem_dec_addr,
                randombytes_addr,
                g_pk_addr,
                g_sk_addr,
                g_ct_addr,
                g_keypair_done_addr,
                use_host_randombytes,
            )
            for run_index in range(num_runs)
        ]

        ctx = multiprocessing.get_context("spawn")
        try:
            with ctx.Pool(processes=jobs) as pool:
                pool.map(run_sample_snapshot_worker, snapshot_worker_args)
        except Exception:
            print("Error during parallel sample snapshot creation:")
            traceback.print_exc()
            sys.exit(1)

    if total_tasks == 0:
        print("No traces requested. Done.")
        sys.exit(0)

    print("-------------------------------")
    print(f"Starting {num_runs} runs with {len(fault_indices)} fault indices = {total_tasks} tasks")
    print(f"Fault indices per run: {fault_indices}")
    print(f"Parallel workers: {jobs}")
    print("-------------------------------")

    worker_fault_indices = [0] if args.ciphertext_mode == "valid" else fault_indices
    worker_args = [
        (
            run_index,
            fault_index,
            get_sample_snapshot_path(output_dir, run_index),
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
        for run_index in range(num_runs)
        for fault_index in worker_fault_indices
    ]

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=jobs) as pool:
        pool.starmap(run_decapsulation_worker, [(args, "sample") for args in worker_args])

    print("\nAll traces have been collected successfully")


if __name__ == "__main__":
    main()
