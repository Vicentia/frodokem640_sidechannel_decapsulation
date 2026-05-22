#!/usr/bin/env python3

import os
import sys
import argparse
import traceback
import multiprocessing
from functools import partial # for passing multiple arguments to pool.starmap

from TRACE_path_helpers import (
    get_S_dir,
    get_run_ciphertext_path,
    get_snapshot_path,
)
from TRACE_BS_extraction import (
    save_S_from_sk_csv,
)
from TRACE_ciphertext_creation import (
    load_base_ciphertext as load_base_ciphertext_from_path,
)
from TRACE_stop_tracing import SnapshotReady, StopEmulation
from TRACE_tracing import make_snapshot_tracing, run_decapsulation_worker
from TRACE_parameters_initialisation import (
    PARAMS_NBAR,
)
from TRACE_emulator_helpers import (
    get_label_address,
    make_disasm,
    normalize_addr,
    setup_qiling_instance,
)
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


# -------------------------- MAIN --------------------------

def main():
    global elf_file, output_dir, output_dir_trim, global_output_dir, snapshot_path
    global skip_addrs, clear_bytes_addr, main_addr, kem_keypair_addr
    global trigger_high_addr, crypto_kem_dec_addr, trigger_low_addr
    global mul_bs_addr, xs_addr, g_pk_addr, g_sk_addr, g_ct_addr, g_keypair_done_addr, md
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
        load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir, run_index))

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
            save_S_from_sk_csv(sk, os.path.join(get_S_dir(output_dir), "S.csv"))
        else:
            print(f"[ERROR] Missing sk.bin, cannot refresh S/S.csv: {sk_path}")

    else:
        print("------------------------------")
        print("Snapshot preparation — running keygen + decapsulation entry:")
        print("------------------------------")

        md = make_disasm()
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
        pool.starmap(run_decapsulation_worker, [(args, "truncated") for args in worker_args])

    print("\nAll traces have been collected successfully")


if __name__ == "__main__":
    main()
