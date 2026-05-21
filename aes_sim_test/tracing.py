import csv
import os
import pickle
import traceback

from parameters_initialisation import PARAMS_NBAR, REG_NAMES, SIZE_PK, SIZE_SK
from path_helpers import (
    get_B_csv_path,
    get_flat_ct_modified_path,
    get_flat_trace_csv_path,
    get_flat_trim_csv_path,
    get_run_ciphertext_path,
    get_sample_ct_modified_path,
    get_sample_trace_csv_path,
    get_sample_trim_csv_path,
    get_truncated_trace_csv_path,
    get_truncated_trim_csv_path,
)

from ciphertext_creation import (
    load_base_ciphertext as load_base_ciphertext_from_path,
    modify_ciphertext_c1_from_base,
    save_B_from_ciphertext_csv,
    test_modify_ciphertext_c1,
)

from BS_extraction import (
    save_S_from_sk_csv,
    save_and_check_B_from_registers_from_traces,
    save_and_check_S_from_traces,
)

from emulator_helpers import (
    disasm_with,
    make_disasm,
    normalize_addr,
    restore_snapshot_manual,
    save_snapshot_manual,
    setup_qiling_instance,
)

from stop_tracing import SnapshotReady, StopEmulation, hard_stop


def write_trace_csv(path, ins_list, reg_list):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "pc", "instruction", "operands",
            "r0", "r1", "r2", "r3",
            "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11",
            "r12", "sp", "lr", "pc",
        ])

        for ins_info, regs in zip(ins_list, reg_list):
            regs_hex = [hex(x) for x in regs]
            writer.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)


def write_trim_register_csv(path, reg_list, include_pc=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    regs_to_write = REG_NAMES if include_pc else REG_NAMES[:-1]

    with open(path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(regs_to_write)

        for regs in reg_list:
            values = regs if include_pc else regs[:-1]
            writer.writerow([hex(x) for x in values])


def save_trace_pair(full_csv, trim_csv, ins_trace, reg_trace, include_pc_in_trim=False):
    print(f"Saving trace to {full_csv}")
    print(f"Trace length: {len(ins_trace)} instructions")

    write_trace_csv(full_csv, ins_trace, reg_trace)
    write_trim_register_csv(trim_csv, reg_trace, include_pc=include_pc_in_trim)

    print(f"Trimmed trace saved to {trim_csv}")


def save_current_trace(namespace, full_csv, trim_csv, register_output_dir=None, register_label=None):
    if namespace.get("trace_saved"):
        return

    save_trace_pair(full_csv, trim_csv, namespace["ins_trace"], namespace["reg_trace"])

    if register_output_dir is not None and register_label is not None:
        from BS_extraction import save_register_operands_csv
        save_register_operands_csv(full_csv, register_output_dir, register_label)

    namespace["trace_saved"] = True
    print("Trace saved")

    namespace["ins_trace"].clear()
    namespace["reg_trace"].clear()


def reset_trace_state(namespace, *, include_main_flags=False, include_xs=False):
    if include_main_flags:
        namespace["hit_main"] = False
        namespace["hit_kem_keypair"] = False
        namespace["hit_crypto_kem_dec"] = False

    namespace["hit_trigger_high"] = False
    namespace["hit_trigger_low"] = False
    namespace["trace_started"] = False
    namespace["trace_saved"] = False
    namespace["instr_counter"] = 0
    namespace["address_CT"] = None
    namespace["dec_return_addr"] = None
    namespace["stop_requested"] = False

    namespace["ins_trace"].clear()
    namespace["reg_trace"].clear()

    if include_xs:
        from parameters_initialisation import PARAMS_NBAR

        namespace["in_mul_bs"] = False
        namespace["xs_call_counter"] = 0
        namespace["active_xs"] = False
        namespace["active_xs_id"] = None
        namespace["active_xs_return_addr"] = None
        namespace["xs_ins_traces"] = [[] for _ in range(PARAMS_NBAR)]
        namespace["xs_reg_traces"] = [[] for _ in range(PARAMS_NBAR)]


def save_keys_from_qiling(ql, out_dir, g_pk_addr=None, g_sk_addr=None, g_keypair_done_addr=None):
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
        with open(sk_path, "wb") as f:
            f.write(sk)

        S_path = os.path.join(out_dir, "S", "S.csv")
        save_S_from_sk_csv(sk, S_path)
        print(f"SK saved to {sk_path}")
        print(f"S saved to {S_path}")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")

# tracing until crypto_kem_dec entry, then save snapshot and keys, then stop
def make_snapshot_tracing(namespace):
    def snapshot_tracing(ql, address, size):
        if namespace.get("stop_requested"):
            return

        address = normalize_addr(address)
        namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

        if address in namespace.get("skip_addrs", set()):
            print(f"[SKIP FUNC] Returning immediately from {hex(address)}")
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        ins, arg = disasm_with(ql, namespace.get("md"), address)

        if namespace["instr_counter"] % 10000 == 0:
            print(
                f"[PROGRESS SNAPSHOT] instr={namespace['instr_counter']} "
                f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
                f"lr={hex(ql.arch.regs.read('lr'))} "
                f"ins={ins} {arg}"
            )

        clear_bytes_addr = namespace.get("clear_bytes_addr")
        if clear_bytes_addr and address == clear_bytes_addr:
            mem_ptr = ql.arch.regs.read("r0")
            n = ql.arch.regs.read("r1")
            print(f"[NATIVE] clear_bytes({hex(mem_ptr)}, {n})")
            try:
                ql.mem.write(mem_ptr, b"\x00" * n)
            except Exception as e:
                print(f"[WARNING] clear_bytes({hex(mem_ptr)}, {n}) failed: {e}")
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        main_addr = namespace.get("main_addr")
        if main_addr and address == main_addr and not namespace.get("hit_main"):
            namespace["hit_main"] = True
            print(f"main() hit at {hex(address)}")

        kem_keypair_addr = namespace.get("kem_keypair_addr")
        if kem_keypair_addr and address == kem_keypair_addr and not namespace.get("hit_kem_keypair"):
            namespace["hit_kem_keypair"] = True
            namespace["address_PK"] = ql.arch.regs.read("r0")
            namespace["address_SK"] = ql.arch.regs.read("r1")
            print("----------------------------")
            print("Entering keypair generation:")
            print("----------------------------")
            print(f"pk ptr = {hex(namespace['address_PK'])}")
            print(f"sk ptr = {hex(namespace['address_SK'])}")
            print("----------------------------")

        crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
        if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not namespace.get("hit_crypto_kem_dec"):
            namespace["hit_crypto_kem_dec"] = True
            namespace["address_CT"] = ql.arch.regs.read("r1")
            print(f"crypto_kem_dec() hit at {hex(address)}, ct ptr = {hex(namespace['address_CT'])}")
            print("Keygen complete. Saving keys and taking snapshot at crypto_kem_dec entry.")

            save_keys_from_qiling(
                ql,
                namespace.get("global_output_dir"),
                namespace.get("g_pk_addr"),
                namespace.get("g_sk_addr"),
                namespace.get("g_keypair_done_addr"),
            )

            if not namespace.get("snapshot_saved"):
                snapshot = save_snapshot_manual(ql)
                print(f"Snapshot dict has {len(snapshot['memory'])} memory regions")
                print(f"Snapshot regs: {snapshot['regs']}")

                with open(namespace["snapshot_path"], "wb") as f:
                    pickle.dump(snapshot, f)

                namespace["snapshot_saved"] = True
                print(
                    f"Snapshot saved successfully, file size: "
                    f"{os.path.getsize(namespace['snapshot_path'])} bytes"
                )

            namespace["stop_requested"] = True
            hard_stop(ql)
            raise SnapshotReady("Reached crypto_kem_dec — snapshot ready")

    return snapshot_tracing


def save_full_decapsulation_trace(namespace, mode):
    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]

    if mode == "parallel":
        fault_index = namespace["fault_index"]
        full_csv = get_flat_trace_csv_path(output_dir, fault_index)
        trim_csv = get_flat_trim_csv_path(output_dir_trim, fault_index)
        label = fault_index
    elif mode == "sample":
        run_index = namespace["current_run_index"]
        fault_index = namespace["current_fault_index"]
        full_csv = get_sample_trace_csv_path(output_dir, run_index, fault_index)
        trim_csv = get_sample_trim_csv_path(output_dir_trim, run_index, fault_index)
        label = f"{run_index}_{fault_index}"
    else:
        raise ValueError(f"Unknown full decapsulation mode: {mode}")

    save_current_trace(namespace, full_csv, trim_csv, output_dir, label)


def make_full_decapsulation_tracing(namespace, mode):
    def decapsulation_tracing(ql, address, size):
        if namespace.get("stop_requested"):
            return

        namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

        if address in namespace.get("skip_addrs", set()):
            print(f"[SKIP FUNC] Returning immediately from {hex(address)}")
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        ins, arg = disasm_with(ql, namespace.get("md"), address)

        if namespace["instr_counter"] % 10000 == 0:
            print(
                f"[PROGRESS DECAPSULATION] instr={namespace['instr_counter']} "
                f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
                f"lr={hex(ql.arch.regs.read('lr'))} "
                f"ins={ins} {arg}"
            )

        clear_bytes_addr = namespace.get("clear_bytes_addr")
        if clear_bytes_addr and address == clear_bytes_addr:
            mem_ptr = ql.arch.regs.read("r0")
            n = ql.arch.regs.read("r1")
            try:
                ql.mem.write(mem_ptr, b"\x00" * n)
            except Exception as e:
                print(f"[WARNING IN DECAPSULATION] clear_bytes({hex(mem_ptr)}, {n}) failed: {e}")
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        trigger_high_addr = namespace.get("trigger_high_addr")
        if trigger_high_addr and address == trigger_high_addr and not namespace.get("hit_trigger_high"):
            namespace["hit_trigger_high"] = True
            namespace["trace_started"] = True
            namespace["ins_trace"].clear()
            namespace["reg_trace"].clear()
            print(f"trigger_high() at {hex(address)}, trace starts here")

        if namespace.get("trace_started"):
            regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
            namespace["ins_trace"].append([ins, arg])
            namespace["reg_trace"].append(regs_now)

        trigger_low_addr = namespace.get("trigger_low_addr")
        if trigger_low_addr and address == trigger_low_addr and not namespace.get("hit_trigger_low"):
            namespace["hit_trigger_low"] = True
            print(f"trigger_low() at {hex(address)}")
            print(f"Number of instructions collected: {len(namespace['ins_trace'])}")
            save_full_decapsulation_trace(namespace, mode)
            print("Stop emulator")
            namespace["stop_requested"] = True
            hard_stop(ql)
            raise StopEmulation("Trace captured, stopping emulator now")

        dec_return_addr = namespace.get("dec_return_addr")
        if dec_return_addr is not None and address == dec_return_addr:
            print(f"[BACKUP STOP] Returned from crypto_kem_dec to {hex(address)}")
            if namespace.get("trace_started") and not namespace.get("trace_saved"):
                print(f"[BACKUP STOP] Saving partial/full trace with {len(namespace['ins_trace'])} instructions")
                save_full_decapsulation_trace(namespace, mode)

            namespace["stop_requested"] = True
            hard_stop(ql)
            raise StopEmulation("Returned from crypto_kem_dec")

    return decapsulation_tracing


def save_xs_csvs(namespace, run_index):
    if namespace.get("trace_saved"):
        return

    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]

    for xs_id in range(PARAMS_NBAR):
        full_path = get_truncated_trace_csv_path(output_dir, run_index, xs_id)
        trim_path = get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id)

        write_trace_csv(full_path, namespace["xs_ins_traces"][xs_id], namespace["xs_reg_traces"][xs_id])
        write_trace_csv(trim_path, namespace["xs_ins_traces"][xs_id], namespace["xs_reg_traces"][xs_id])

    namespace["trace_saved"] = True


def make_truncated_decapsulation_tracing(namespace):
    def decapsulation_tracing(ql, address, size):
        if namespace.get("stop_requested"):
            return

        address = normalize_addr(address)
        namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

        if address in namespace.get("skip_addrs", set()):
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        clear_bytes_addr = namespace.get("clear_bytes_addr")
        if clear_bytes_addr and address == clear_bytes_addr:
            mem_ptr = ql.arch.regs.read("r0")
            n = ql.arch.regs.read("r1")
            try:
                ql.mem.write(mem_ptr, b"\x00" * n)
            except Exception as e:
                print(f"[ERROR IN DECAPSULATION] clear_bytes failed: {e}")
            ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
            return

        trigger_high_addr = namespace.get("trigger_high_addr")
        if trigger_high_addr and address == trigger_high_addr and not namespace.get("hit_trigger_high"):
            namespace["hit_trigger_high"] = True
            namespace["trace_started"] = True
            print(f"trigger_high() at {hex(address)}")
            print("[TRACE] Capturing only xs() blocks")

        if not namespace.get("trace_started"):
            return

        if namespace.get("mul_bs_addr") and address == namespace.get("mul_bs_addr"):
            namespace["in_mul_bs"] = True
            namespace["xs_call_counter"] = 0
            print(f"[MUL_BS START] Entered mul_bs at {hex(address)}")

        if (
            namespace.get("in_mul_bs")
            and namespace.get("xs_addr")
            and address == namespace.get("xs_addr")
            and not namespace.get("active_xs")
        ):
            xs_call_counter = namespace["xs_call_counter"]
            active_xs_id = xs_call_counter % PARAMS_NBAR
            namespace["active_xs_id"] = active_xs_id
            namespace["active_xs_return_addr"] = normalize_addr(ql.arch.regs.read("lr"))
            namespace["active_xs"] = True

            print(
                f"[XS START] xs_call={xs_call_counter}, "
                f"xs_id={active_xs_id}, "
                f"return={hex(namespace['active_xs_return_addr'])}"
            )

            namespace["xs_call_counter"] += 1

            if active_xs_id >= PARAMS_NBAR:
                print(f"[ERROR] Ignoring unexpected xs_call={xs_call_counter}")
                namespace["active_xs"] = False
                namespace["active_xs_id"] = None
                namespace["active_xs_return_addr"] = None
                return

        if (
            namespace.get("active_xs")
            and namespace.get("active_xs_return_addr") is not None
            and address == namespace.get("active_xs_return_addr")
        ):
            print(f"[XS END] xs_id={namespace.get('active_xs_id')}")
            namespace["active_xs"] = False
            namespace["active_xs_id"] = None
            namespace["active_xs_return_addr"] = None
            return

        if namespace.get("active_xs") and namespace.get("active_xs_id") is not None:
            ins, arg = disasm_with(ql, namespace.get("md"), address)
            regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
            active_xs_id = namespace["active_xs_id"]
            namespace["xs_ins_traces"][active_xs_id].append([ins, arg])
            namespace["xs_reg_traces"][active_xs_id].append(regs_now)

        trigger_low_addr = namespace.get("trigger_low_addr")
        if trigger_low_addr and address == trigger_low_addr and not namespace.get("hit_trigger_low"):
            namespace["hit_trigger_low"] = True
            print(f"trigger_low() at {hex(address)}")
            save_xs_csvs(namespace, namespace["current_run_index"])
            namespace["stop_requested"] = True
            hard_stop(ql)
            raise StopEmulation("xs-product traces captured")

        dec_return_addr = namespace.get("dec_return_addr")
        if dec_return_addr is not None and address == dec_return_addr:
            print(f"[BACKUP STOP] Returned from crypto_kem_dec to {hex(address)}")
            save_xs_csvs(namespace, namespace["current_run_index"])
            namespace["stop_requested"] = True
            hard_stop(ql)
            raise StopEmulation("Returned from crypto_kem_dec")

    return decapsulation_tracing


def run_parallel_decapsulation_worker(worker_args):
    (
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
    ) = worker_args

    namespace = globals()
    namespace["fault_index"] = fault_index_local
    namespace["trigger_high_addr"] = trigger_high_addr_local
    namespace["trigger_low_addr"] = trigger_low_addr_local
    namespace["skip_addrs"] = set(skip_addrs_local)
    namespace["g_ct_addr"] = g_ct_addr_local
    namespace["clear_bytes_addr"] = clear_bytes_addr_local
    namespace["output_dir"] = output_dir_local
    namespace["output_dir_trim"] = output_dir_trim_local
    namespace["global_output_dir"] = output_dir_local
    namespace["md"] = make_disasm()
    namespace.setdefault("ins_trace", [])
    namespace.setdefault("reg_trace", [])

    os.makedirs(output_dir_local, exist_ok=True)
    os.makedirs(output_dir_trim_local, exist_ok=True)

    reset_trace_state(namespace)
    ql = setup_qiling_instance(elf_file)

    with open(snapshot_path_local, "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)
    namespace["dec_return_addr"] = normalize_addr(snapshot["regs"]["lr"])
    print(f"[WORKER {fault_index_local}] Backup return address = {hex(namespace['dec_return_addr'])}")

    del snapshot

    ct_base_path = os.path.join(output_dir_local, "ct_base.bin")
    base_ct = load_base_ciphertext_from_path(ct_base_path)
    c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, fault_index_local)
    test_modify_ciphertext_c1(fault_index_local, c1_random=c1_initial, ct=altered_ct)

    ql.mem.write(g_ct_addr_local, bytes(altered_ct))
    print(f"[WORKER {fault_index_local}] Modified CT written to g_ct ({hex(g_ct_addr_local)})")

    ct_path = get_flat_ct_modified_path(output_dir_local, fault_index_local)
    os.makedirs(os.path.dirname(ct_path), exist_ok=True)
    with open(ct_path, "wb") as f:
        f.write(altered_ct)
    print(f"[WORKER {fault_index_local}] ct_modified.bin saved to {ct_path}")
    save_B_from_ciphertext_csv(altered_ct, os.path.join(output_dir_local, "B", f"B_{fault_index_local}.csv"))

    ql.hook_code(make_full_decapsulation_tracing(namespace, "parallel"))

    print("\n-----------------------------")
    print(f"Running decapsulation for fault index {fault_index_local}...")
    print(f"Skip addresses: {[hex(a) for a in sorted(namespace['skip_addrs'])]}")

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print(f"Error during decapsulation (fault {fault_index_local}): {e}")
        traceback.print_exc()

    print(f"\nSummary for fault index {fault_index_local}:")
    print(f"  trigger_high hit = {namespace.get('hit_trigger_high')}")
    print(f"  trigger_low hit  = {namespace.get('hit_trigger_low')}")


def run_sample_decapsulation_worker(worker_args):
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
    ) = worker_args

    namespace = globals()
    namespace["current_run_index"] = run_index_local
    namespace["current_fault_index"] = fault_index_local
    namespace["trigger_high_addr"] = trigger_high_addr_local
    namespace["trigger_low_addr"] = trigger_low_addr_local
    namespace["skip_addrs"] = set(skip_addrs_local)
    namespace["g_ct_addr"] = g_ct_addr_local
    namespace["clear_bytes_addr"] = clear_bytes_addr_local
    namespace["output_dir"] = output_dir_local
    namespace["output_dir_trim"] = output_dir_trim_local
    namespace["global_output_dir"] = output_dir_local
    namespace["md"] = make_disasm()
    namespace.setdefault("ins_trace", [])
    namespace.setdefault("reg_trace", [])

    os.makedirs(output_dir_local, exist_ok=True)
    os.makedirs(os.path.dirname(get_sample_trim_csv_path(output_dir_trim_local, run_index_local, fault_index_local)), exist_ok=True)

    reset_trace_state(namespace)
    ql = setup_qiling_instance(elf_file)

    with open(snapshot_path_local, "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)
    namespace["dec_return_addr"] = normalize_addr(snapshot["regs"]["lr"])
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Backup return address = {hex(namespace['dec_return_addr'])}"
    )

    del snapshot

    base_ct = load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir_local, run_index_local))
    c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, fault_index_local)
    test_modify_ciphertext_c1(fault_index_local, c1_random=c1_initial, ct=altered_ct)

    ql.mem.write(g_ct_addr_local, bytes(altered_ct))
    print(
        f"[WORKER run={run_index_local} fault={fault_index_local}] "
        f"Modified CT written to g_ct ({hex(g_ct_addr_local)})"
    )

    ct_path = get_sample_ct_modified_path(output_dir_local, run_index_local, fault_index_local)
    os.makedirs(os.path.dirname(ct_path), exist_ok=True)
    with open(ct_path, "wb") as f:
        f.write(altered_ct)
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"ct_modified saved to {ct_path}"
    )
    save_B_from_ciphertext_csv(
        altered_ct,
        os.path.join(output_dir_local, "B", f"B_{run_index_local}_{fault_index_local}.csv"),
    )

    ql.hook_code(make_full_decapsulation_tracing(namespace, "sample"))

    print("\n-----------------------------")
    print(f"Running decapsulation for Run_{run_index_local + 1}, fault index {fault_index_local}...")
    print(f"Skip addresses: {[hex(a) for a in sorted(namespace['skip_addrs'])]}")

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print(f"Error during decapsulation (run={run_index_local + 1} fault={fault_index_local}): {e}")
        traceback.print_exc()

    print(f"\nSummary for Run_{run_index_local + 1}, fault index {fault_index_local}:")
    print(f"  trigger_high hit = {namespace.get('hit_trigger_high')}")
    print(f"  trigger_low hit  = {namespace.get('hit_trigger_low')}")


def run_truncated_decapsulation_worker(worker_args):
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

    namespace = globals()
    namespace["current_run_index"] = run_index_local
    namespace["current_fault_index"] = fault_index_local
    namespace["trigger_high_addr"] = trigger_high_addr_local
    namespace["trigger_low_addr"] = trigger_low_addr_local
    namespace["skip_addrs"] = set(skip_addrs_local)
    namespace["g_ct_addr"] = g_ct_addr_local
    namespace["clear_bytes_addr"] = clear_bytes_addr_local
    namespace["mul_bs_addr"] = mul_bs_addr_local
    namespace["xs_addr"] = xs_addr_local
    namespace["output_dir"] = output_dir_local
    namespace["output_dir_trim"] = output_dir_trim_local
    namespace["global_output_dir"] = output_dir_local
    namespace["md"] = make_disasm()
    namespace.setdefault("ins_trace", [])
    namespace.setdefault("reg_trace", [])

    os.makedirs(output_dir_local, exist_ok=True)
    os.makedirs(output_dir_trim_local, exist_ok=True)

    reset_trace_state(namespace, include_xs=True)
    ql = setup_qiling_instance(elf_file)

    with open(snapshot_path_local, "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)
    namespace["dec_return_addr"] = normalize_addr(snapshot["regs"]["lr"])
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Backup return address = {hex(namespace['dec_return_addr'])}"
    )

    del snapshot

    base_ct = load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir_local, run_index_local))
    ql.mem.write(g_ct_addr_local, bytes(base_ct))
    print(
        f"[WORKER run={run_index_local + 1} fault={fault_index_local}] "
        f"Base CT written unchanged to g_ct ({hex(g_ct_addr_local)})"
    )

    ct_path = get_run_ciphertext_path(output_dir_local, run_index_local)
    with open(ct_path, "wb") as f:
        f.write(base_ct)
    print(
        f"[WORKER run={run_index_local} fault={fault_index_local}] "
        f"ciphertext saved to {ct_path}"
    )

    save_B_from_ciphertext_csv(base_ct, get_B_csv_path(output_dir_local, run_index_local))
    ql.hook_code(make_truncated_decapsulation_tracing(namespace))

    print("\n-----------------------------")
    print(f"Running decapsulation for run {run_index_local}, fault index {fault_index_local}")
    print(f"Expected output traces: trace_{run_index_local}_0.csv ... trace_{run_index_local}_7.csv")
    print(f"mul_bs address: {hex(mul_bs_addr_local) if mul_bs_addr_local else None}")
    print(f"xs address: {hex(xs_addr_local) if xs_addr_local else None}")
    print(f"Skip addresses: {[hex(a) for a in sorted(namespace['skip_addrs'])]}")
    print("-----------------------------")

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print(f"Error during decapsulation (run={run_index_local + 1} fault={fault_index_local}): {e}")
        traceback.print_exc()

    save_and_check_B_from_registers_from_traces(output_dir_local, output_dir_trim_local, run_index_local)
    save_and_check_S_from_traces(output_dir_local, output_dir_trim_local, run_index_local)

    print(f"\nSummary for run {run_index_local}, fault index {fault_index_local}:")
    print(f"  trigger_high hit = {namespace.get('hit_trigger_high')}")
    print(f"  trigger_low hit  = {namespace.get('hit_trigger_low')}")


def update_globals_from_symbols(namespace, symbols):
    for name, value in symbols.items():
        namespace[name] = value
