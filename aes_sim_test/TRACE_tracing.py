import csv
import os
import pickle
import traceback
from functools import partial

from TRACE_parameters_initialisation import PARAMS_NBAR, REG_NAMES, SIZE_PK, SIZE_SK, SIZE_CT
from TRACE_path_helpers import (
    get_B_csv_path,
    get_ct_modified_path,
    get_trace_csv_path,
    get_trim_csv_path,
    get_run_ciphertext_path,
    get_sample_ct_modified_path,
    get_sample_trace_csv_path,
    get_sample_trim_csv_path,
    get_truncated_trace_csv_path,
    get_truncated_trim_csv_path,
)

from TRACE_ciphertext_creation import (
    load_base_ciphertext as load_base_ciphertext_from_path,
    modify_ciphertext_c1_from_base,
    save_B_from_ciphertext_csv,
    test_modify_ciphertext_c1,
)

from TRACE_BS_extraction import (
    save_S_from_sk_csv,
    save_and_check_B_from_registers_from_traces,
    save_and_check_S_from_traces,
)

from TRACE_emulator_helpers import (
    disasm_with,
    make_disasm,
    normalize_addr,
    restore_snapshot_manual,
    save_snapshot_manual,
    setup_qiling_instance,
)

from TRACE_stop_tracing import SnapshotReady, StopEmulation, hard_stop


def write_trace_csv(path, ins_list, reg_list):
    """
    Write trace to csv
    """
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
    """
    Write only the register values to csv
    """

    os.makedirs(os.path.dirname(path), exist_ok=True)
    regs_to_write = REG_NAMES if include_pc else REG_NAMES[:-1]

    with open(path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(regs_to_write)

        for regs in reg_list:
            values = regs if include_pc else regs[:-1]
            writer.writerow([hex(x) for x in values])


def save_trace_pair(full_csv, trim_csv, ins_trace, reg_trace, include_pc_in_trim=False):
    """
    Save the full trace and the trim version that does not contain the PC register, instruction and operands
    """
    print(f"Saving trace to {full_csv}")
    print(f"Trace length: {len(ins_trace)} instructions")

    write_trace_csv(full_csv, ins_trace, reg_trace)
    write_trim_register_csv(trim_csv, reg_trace, include_pc=include_pc_in_trim)

    print(f"Trimmed trace saved to {trim_csv}")


def save_current_trace(namespace, full_csv, trim_csv, register_output_dir=None, register_label=None):
    """
    Save the pair of in the outpur directory
    """
    if namespace.get("trace_saved"):
        return

    save_trace_pair(full_csv, trim_csv, namespace["ins_trace"], namespace["reg_trace"])

    if register_output_dir is not None and register_label is not None:
        from TRACE_BS_extraction import save_register_operands_csv
        save_register_operands_csv(full_csv, register_output_dir, register_label)

    namespace["trace_saved"] = True
    print("Trace saved")

    namespace["ins_trace"].clear()
    namespace["reg_trace"].clear()


def reset_trace_state(namespace, *, include_main_flags=False, include_xs=False):
    """
    Reset the states addresses as None and Flags as False
    """
    if include_main_flags:
        namespace["hit_main"] = False
        namespace["hit_kem_keypair"] = False
        namespace["hit_crypto_kem_dec"] = False
        namespace["keypair_saved"] = False

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
        from TRACE_parameters_initialisation import PARAMS_NBAR

        namespace["in_mul_bs"] = False
        namespace["xs_call_counter"] = 0
        namespace["active_xs"] = False
        namespace["active_xs_id"] = None
        namespace["active_xs_return_addr"] = None
        namespace["xs_ins_traces"] = [[] for _ in range(PARAMS_NBAR)]
        namespace["xs_reg_traces"] = [[] for _ in range(PARAMS_NBAR)]


def save_keys_from_qiling(ql, out_dir, g_pk_addr=None, g_sk_addr=None, g_keypair_done_addr=None):
    """
    Save PK and SK from qiling memory, and also save S extracted from SK in csv format
    """
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

def make_snapshot_tracing(ql, address, size, namespace):
    """
    Trace from the beginning until the entry of crypto_kem_dec, then save a snapshot and stop
    """
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


def save_full_trace(namespace, ql):
    """
    Save the sequential full trace, modified ciphertext, B matrix, and trimmed trace.
    """
    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]
    fault_index = namespace["fault_index"]
    g_ct_addr = namespace.get("g_ct_addr")

    os.makedirs(output_dir, exist_ok=True)

    if g_ct_addr is not None:
        ct = ql.mem.read(g_ct_addr, SIZE_CT)
        ct_path = get_ct_modified_path(output_dir, fault_index)

        with open(ct_path, "wb") as f:
            f.write(ct)

        print(f"CT saved to {ct_path}")
        save_B_from_ciphertext_csv(bytes(ct), os.path.join(output_dir, "B", f"B_{fault_index}.csv"))

    save_current_trace(
        namespace,
        get_trace_csv_path(output_dir, fault_index),
        get_trim_csv_path(output_dir_trim, fault_index),
        output_dir,
        fault_index,
    )


def make_full_trace(ql, address, size, namespace):
    """
    Trace from the entry of trigger_high until the entry of trigger_low
    """
    namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

    skip = namespace.get("skip")
    if skip is not None and address == skip:
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    ins, arg = disasm_with(ql, namespace.get("md"), address)

    if namespace["instr_counter"] % 10000 == 0:
        print(
            f"[PROGRESS] instr={namespace['instr_counter']} "
            f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
            f"lr={hex(ql.arch.regs.read('lr'))} "
            f"ins={ins} {arg}"
        )

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

    trigger_high_addr = namespace.get("trigger_high_addr")
    if trigger_high_addr and address == trigger_high_addr and not namespace.get("hit_trigger_high"):
        namespace["hit_trigger_high"] = True

        if not namespace.get("keypair_saved"):
            save_keys_from_qiling(
                ql,
                namespace["output_dir"],
                namespace.get("g_pk_addr"),
                namespace.get("g_sk_addr"),
                namespace.get("g_keypair_done_addr"),
            )
            namespace["keypair_saved"] = True

        namespace["trace_started"] = True
        namespace["ins_trace"].clear()
        namespace["reg_trace"].clear()
        print(f"trigger_high() at {hex(address)}, trace starts")

    crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not namespace.get("hit_crypto_kem_dec"):
        namespace["hit_crypto_kem_dec"] = True
        ct_ptr = ql.arch.regs.read("r1")
        namespace["address_CT"] = ct_ptr

        print("----------------------------")
        print("Entering decapsulation:")
        print("----------------------------")
        print(
            f"ct ptr = {hex(ct_ptr)}  "
            f"(overwriting with altered ciphertext for index {namespace['fault_index']})"
        )

        base_ct = load_base_ciphertext_from_path(namespace["ct_base_path"])
        c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, namespace["fault_index"])
        test_modify_ciphertext_c1(namespace["fault_index"], c1_random=c1_initial, ct=altered_ct)
        ql.mem.write(ct_ptr, bytes(altered_ct))

    if namespace.get("trace_started"):
        regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
        namespace["ins_trace"].append([ins, arg])
        namespace["reg_trace"].append(regs_now)

    trigger_low_addr = namespace.get("trigger_low_addr")
    if trigger_low_addr and address == trigger_low_addr and not namespace.get("hit_trigger_low"):
        namespace["hit_trigger_low"] = True
        print(f"trigger_low() at {hex(address)}")
        print(f"Instructions collected: {len(namespace['ins_trace'])}")

        save_full_trace(namespace, ql)

        print("Stopping emulator")
        namespace["stop_requested"] = True
        hard_stop(ql)
        raise StopEmulation("Trace captured, stopping emulator")


def save_full_decapsulation_trace(namespace, mode):
    """
    Save the full trace of the decapsulation, from trigger_high to trigger_low, and also save the trim version with only registers
    """
    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]

    if mode == "parallel":
        fault_index = namespace["fault_index"]
        full_csv = get_trace_csv_path(output_dir, fault_index)
        trim_csv = get_trim_csv_path(output_dir_trim, fault_index)
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


def make_full_decapsulation_tracing(ql, address, size, namespace, mode):
    """
    Capture the full trace of the decapsulation, from trigger_high to trigger_low, and also save the trim version with only registers
    """
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



def save_xs_csvs(namespace, run_index):
    """
    Save the dot products in separate csv files based on the xs() calls
    """
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


def make_truncated_decapsulation_tracing(ql, address, size, namespace):
    """
    Trace the xs() calls during decapsulation
    """
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



def unpack_decapsulation_worker_args(worker_args, mode):
    """
    Return the arguments of the worker based on the mode (parallel, sample or truncated)
    """
    if mode == "parallel":
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

        return {
            "run_index": None,
            "fault_index": fault_index_local,
            "snapshot_path": snapshot_path_local,
            "elf_file": elf_file,
            "output_dir": output_dir_local,
            "output_dir_trim": output_dir_trim_local,
            "trigger_high_addr": trigger_high_addr_local,
            "trigger_low_addr": trigger_low_addr_local,
            "skip_addrs": skip_addrs_local,
            "g_ct_addr": g_ct_addr_local,
            "clear_bytes_addr": clear_bytes_addr_local,
            "mul_bs_addr": None,
            "xs_addr": None,
        }

    if mode == "sample":
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

        return {
            "run_index": run_index_local,
            "fault_index": fault_index_local,
            "snapshot_path": snapshot_path_local,
            "elf_file": elf_file,
            "output_dir": output_dir_local,
            "output_dir_trim": output_dir_trim_local,
            "trigger_high_addr": trigger_high_addr_local,
            "trigger_low_addr": trigger_low_addr_local,
            "skip_addrs": skip_addrs_local,
            "g_ct_addr": g_ct_addr_local,
            "clear_bytes_addr": clear_bytes_addr_local,
            "mul_bs_addr": None,
            "xs_addr": None,
        }

    if mode == "truncated":
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

        return {
            "run_index": run_index_local,
            "fault_index": fault_index_local,
            "snapshot_path": snapshot_path_local,
            "elf_file": elf_file,
            "output_dir": output_dir_local,
            "output_dir_trim": output_dir_trim_local,
            "trigger_high_addr": trigger_high_addr_local,
            "trigger_low_addr": trigger_low_addr_local,
            "skip_addrs": skip_addrs_local,
            "g_ct_addr": g_ct_addr_local,
            "clear_bytes_addr": clear_bytes_addr_local,
            "mul_bs_addr": mul_bs_addr_local,
            "xs_addr": xs_addr_local,
        }

    raise ValueError(f"Unknown decapsulation worker mode: {mode}")


def configure_worker_namespace(namespace, config, mode):
    """
    Set the variables to their current values based on the mode (parallel, sample or truncated)
    """
    run_index = config["run_index"]
    fault_index = config["fault_index"]

    if mode == "parallel":
        namespace["fault_index"] = fault_index
    else:
        namespace["current_run_index"] = run_index
        namespace["current_fault_index"] = fault_index

    namespace["trigger_high_addr"] = config["trigger_high_addr"]
    namespace["trigger_low_addr"] = config["trigger_low_addr"]
    namespace["skip_addrs"] = set(config["skip_addrs"])
    namespace["g_ct_addr"] = config["g_ct_addr"]
    namespace["clear_bytes_addr"] = config["clear_bytes_addr"]
    namespace["output_dir"] = config["output_dir"]
    namespace["output_dir_trim"] = config["output_dir_trim"]
    namespace["global_output_dir"] = config["output_dir"]
    namespace["md"] = make_disasm()
    namespace.setdefault("ins_trace", [])
    namespace.setdefault("reg_trace", [])

    if mode == "truncated":
        namespace["mul_bs_addr"] = config["mul_bs_addr"]
        namespace["xs_addr"] = config["xs_addr"]


def load_snapshot_into_worker(namespace, config):
    """
    Load the snapshot saved at the entry of crypto_kem_dec into the qiling instance, and set the return address for backup stopping
    """
    ql = setup_qiling_instance(
        config["elf_file"],
        patch_uart=False,
        include_bitband=False,
    )

    with open(config["snapshot_path"], "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)
    namespace["dec_return_addr"] = normalize_addr(snapshot["regs"]["lr"])
    del snapshot

    return ql


def prepare_worker_ciphertext(ql, config, mode):
    """
    Create the ciphertext based on the worker mode as: 
    - parallel: modify c1 from the base ciphertext and write it to g_ct
    - sample: modify c1 from the base ciphertext of the current run and write it to g_ct
    - truncated: write the unmodified base ciphertext of the current run to g_ct
    Also save the modified ciphertext and the extracted B in csv format in the output directory
    """

    run_index = config["run_index"]
    fault_index = config["fault_index"]
    output_dir = config["output_dir"]
    g_ct_addr = config["g_ct_addr"]

    if mode == "parallel":
        base_ct = load_base_ciphertext_from_path(os.path.join(output_dir, "ct_base.bin"))
        c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, fault_index)
        test_modify_ciphertext_c1(fault_index, c1_random=c1_initial, ct=altered_ct)

        ql.mem.write(g_ct_addr, bytes(altered_ct))
        ct_path = get_ct_modified_path(output_dir, fault_index)
        b_path = os.path.join(output_dir, "B", f"B_{fault_index}.csv")
        os.makedirs(os.path.dirname(ct_path), exist_ok=True)
        with open(ct_path, "wb") as f:
            f.write(altered_ct)

        print(f"[WORKER {fault_index}] Modified CT written to g_ct ({hex(g_ct_addr)})")
        print(f"[WORKER {fault_index}] ct_modified.bin saved to {ct_path}")
        save_B_from_ciphertext_csv(altered_ct, b_path)
        return

    if mode == "sample":
        base_ct = load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir, run_index))
        c1_initial, altered_ct = modify_ciphertext_c1_from_base(base_ct, fault_index)
        test_modify_ciphertext_c1(fault_index, c1_random=c1_initial, ct=altered_ct)

        ql.mem.write(g_ct_addr, bytes(altered_ct))
        ct_path = get_sample_ct_modified_path(output_dir, run_index, fault_index)
        b_path = os.path.join(output_dir, "B", f"B_{run_index}_{fault_index}.csv")
        os.makedirs(os.path.dirname(ct_path), exist_ok=True)
        with open(ct_path, "wb") as f:
            f.write(altered_ct)

        print(f"[WORKER run={run_index} fault={fault_index}] Modified CT written to g_ct ({hex(g_ct_addr)})")
        print(f"[WORKER run={run_index + 1} fault={fault_index}] ct_modified saved to {ct_path}")
        save_B_from_ciphertext_csv(altered_ct, b_path)
        return

    if mode == "truncated":
        base_ct = load_base_ciphertext_from_path(get_run_ciphertext_path(output_dir, run_index))
        ql.mem.write(g_ct_addr, bytes(base_ct))

        ct_path = get_run_ciphertext_path(output_dir, run_index)
        with open(ct_path, "wb") as f:
            f.write(base_ct)

        print(f"[WORKER run={run_index + 1} fault={fault_index}] Base CT written unchanged to g_ct ({hex(g_ct_addr)})")
        print(f"[WORKER run={run_index} fault={fault_index}] ciphertext saved to {ct_path}")
        save_B_from_ciphertext_csv(base_ct, get_B_csv_path(output_dir, run_index))
        return

    raise ValueError(f"Unknown decapsulation worker mode: {mode}")


def hook_worker_tracing(ql, namespace, mode):
    """
    Hook the appropriate tracing function based on the worker mode (parallel, sample or truncated)
    """
    if mode == "truncated":
        ql.hook_code(partial(make_truncated_decapsulation_tracing, namespace=namespace))
    elif mode in {"parallel", "sample"}:
        ql.hook_code(partial(make_full_decapsulation_tracing, namespace=namespace, mode=mode))
    else:
        raise ValueError(f"Unknown decapsulation worker mode: {mode}")


def print_worker_start(config, namespace, mode):
    """
    Print the starting information of the worker based on the mode (parallel, sample or truncated)
    """
    run_index = config["run_index"]
    fault_index = config["fault_index"]

    print("\n-----------------------------")

    if mode == "parallel":
        print(f"[WORKER {fault_index}] Backup return address = {hex(namespace['dec_return_addr'])}")
        print(f"Running decapsulation for fault index {fault_index}...")
    elif mode == "sample":
        print(
            f"[WORKER run={run_index + 1} fault={fault_index}] "
            f"Backup return address = {hex(namespace['dec_return_addr'])}"
        )
        print(f"Running decapsulation for Run_{run_index + 1}, fault index {fault_index}...")
    elif mode == "truncated":
        print(
            f"[WORKER run={run_index + 1} fault={fault_index}] "
            f"Backup return address = {hex(namespace['dec_return_addr'])}"
        )
        print(f"Running decapsulation for run {run_index}, fault index {fault_index}")
        print(f"Expected output traces: trace_{run_index}_0.csv ... trace_{run_index}_7.csv")
        print(f"mul_bs address: {hex(config['mul_bs_addr']) if config['mul_bs_addr'] else None}")
        print(f"xs address: {hex(config['xs_addr']) if config['xs_addr'] else None}")

    print(f"Skip addresses: {[hex(a) for a in sorted(namespace['skip_addrs'])]}")
    print("-----------------------------")


def print_worker_summary(config, namespace, mode):
    """
    Print the summary of the worker execution, including whether the triggers were hit for debugging
    """
    run_index = config["run_index"]
    fault_index = config["fault_index"]

    if mode == "parallel":
        print(f"\nSummary for fault index {fault_index}:")
    elif mode == "sample":
        print(f"\nSummary for Run_{run_index + 1}, fault index {fault_index}:")
    elif mode == "truncated":
        print(f"\nSummary for run {run_index}, fault index {fault_index}:")

    print(f"  trigger_high hit = {namespace.get('hit_trigger_high')}")
    print(f"  trigger_low hit  = {namespace.get('hit_trigger_low')}")


def run_decapsulation_worker(worker_args, mode):
    """
    Run the decapsulation by: 
    - unpacking the worker arguments based on the mode (parallel, sample or truncated)
    - configuring the worker namespace with the appropriate variables
    - loading the snapshot into the qiling instance
    - preparing the ciphertext based on the mode and writing it to g_ct
    - hooking the appropriate tracing function based on the mode
    - stop the emulator when trigger_low is hit
    """
    config = unpack_decapsulation_worker_args(worker_args, mode)
    namespace = globals()

    configure_worker_namespace(namespace, config, mode)

    os.makedirs(config["output_dir"], exist_ok=True)
    os.makedirs(config["output_dir_trim"], exist_ok=True)

    reset_trace_state(namespace, include_xs=(mode == "truncated"))
    ql = load_snapshot_into_worker(namespace, config)
    prepare_worker_ciphertext(ql, config, mode)
    hook_worker_tracing(ql, namespace, mode)
    print_worker_start(config, namespace, mode)

    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        run_index = config["run_index"]
        fault_index = config["fault_index"]
        if mode == "parallel":
            print(f"Error during decapsulation (fault {fault_index}): {e}")
        else:
            print(f"Error during decapsulation (run={run_index + 1} fault={fault_index}): {e}")
        traceback.print_exc()

    if mode == "truncated":
        save_and_check_B_from_registers_from_traces(
            config["output_dir"],
            config["output_dir_trim"],
            config["run_index"],
        )
        save_and_check_S_from_traces(
            config["output_dir"],
            config["output_dir_trim"],
            config["run_index"],
        )

    print_worker_summary(config, namespace, mode)


def update_globals_from_symbols(namespace, symbols):
    """
    Update the global namespace with the given symbols dictionary
    """
    for name, value in symbols.items():
        namespace[name] = value
