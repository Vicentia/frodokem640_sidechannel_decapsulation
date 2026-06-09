import csv
import hashlib
import os
import pickle
import traceback
from functools import partial

from TRACE_parameters_initialisation import PARAMS_NBAR, REG_NAMES, SIZE_PK, SIZE_SK, SIZE_CT
from TRACE_path_helpers import (
    get_B_csv_path,
    get_B_valid_csv_path,
    get_ct_modified_path,
    get_ct_valid_path,
    get_trace_csv_path,
    get_trim_csv_path,
    get_run_ciphertext_path,
    get_sample_ct_modified_path,
    get_sample_ct_valid_path,
    get_sample_trace_csv_path,
    get_sample_trim_csv_path,
    get_truncated_trace_csv_path,
    get_truncated_trim_csv_path,
)

from TRACE_ciphertext_creation import (
    load_base_ciphertext,
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


def is_truncated_worker_mode(mode):
    return mode in {"truncated", "truncated_empirical"}


def handle_randombytes_call(ql, namespace, address):
    """
    The firmware randombytes are replaced with a hook that generates randombytes 
    - use_host_randombytes set to True = we want to replace the firmware randombytes with Python os.urandom
    - host_randombytes_enabled set to True = the hook is active and will replace randombytes calls 

    - it it used in truncated version to generate more valid ciphertexts 
    - it is used in emphirical version to generate more S and more valid ciphertexts 
    """
    randombytes_addr = namespace.get("randombytes_addr")
    if randombytes_addr is None or address != randombytes_addr:
        return False
    if not namespace.get("use_host_randombytes"):
        return False
    if not namespace.get("host_randombytes_enabled"):
        return False

    out_ptr = ql.arch.regs.read("r0")
    out_len = ql.arch.regs.read("r1")

    random_data = os.urandom(out_len)
    ql.mem.write(out_ptr, random_data)
    ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
    print(
        f"[RANDOM] randombytes({hex(out_ptr)}, {out_len}) "
        f"sha256={hashlib.sha256(random_data).hexdigest()}"
    )
    return True


def print_ciphertext_summary(label, ciphertext, path=None, preview_bytes=64):
    """
    print ciphertext and information about the ciphertext as the size and the first bytes in hex 
    """
    ciphertext = bytes(ciphertext)
    preview = ciphertext[:preview_bytes].hex()

    print(f"[CT] {label}")
    if path is not None:
        print(f"[CT] path = {path}")
    print(f"[CT] size = {len(ciphertext)} bytes")
    print(f"[CT] first_{preview_bytes}_bytes = {preview}")
    if ciphertext and all(byte == 0 for byte in ciphertext):
        print("[CT WARNING] ciphertext is all zero bytes")


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
    - it usese the functions write_trace_csv and write_trim_register_csv to save the traces in csv format
    """
    print(f"Trace length: {len(ins_trace)} instructions")

    print(f"Saving trimmed trace to {trim_csv}")
    write_trim_register_csv(trim_csv, reg_trace, include_pc=include_pc_in_trim)
    print(f"Trimmed trace saved to {trim_csv}")

    print(f"Saving full trace to {full_csv}")
    write_trace_csv(full_csv, ins_trace, reg_trace)
    print(f"Full trace saved to {full_csv}")


def save_current_trace(namespace, full_csv, trim_csv, register_output_dir=None, register_label=None):
    """
    Save the pair in the outpur directory and also the value from B' and S 
    The pair is made out of: 
        - the full trace with instructions and register values in csv format
        - the trimmed trace with only register values in csv format
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
        namespace["hit_crypto_kem_enc"] = False
        namespace["hit_crypto_kem_dec"] = False
        namespace["keypair_saved"] = False
        namespace["snapshot_saved"] = False

    namespace["hit_trigger_high"] = False
    namespace["hit_trigger_low"] = False
    namespace["trace_started"] = False
    namespace["trace_saved"] = False
    namespace["instr_counter"] = 0
    namespace["address_CT"] = None
    namespace["dec_return_addr"] = None
    namespace["stop_requested"] = False
    namespace["selected_ct"] = None
    namespace["selected_ct_ptr"] = None
    namespace["selected_ct_mode"] = None
    namespace["enc_active"] = False
    namespace["enc_ct_ptr"] = None
    namespace["enc_return_addr"] = None
    namespace["valid_ct_from_enc"] = None
    namespace["worker_ct_prepared_at_dec_entry"] = False
    namespace["host_randombytes_enabled"] = False

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


def save_keys_from_qiling(
    ql,
    out_dir,
    g_pk_addr=None,
    g_sk_addr=None,
    g_keypair_done_addr=None,
    key_index=None,
    save_s_csv=True,
):
    """
    Save PK and SK from qiling memory, and also save S extracted from SK in csv format
    """
    os.makedirs(out_dir, exist_ok=True)
    suffix = "" if key_index is None else f"_{key_index}"

    if g_pk_addr is not None:
        pk = bytes(ql.mem.read(g_pk_addr, SIZE_PK))
        pk_path = os.path.join(out_dir, f"pk{suffix}.bin")
        with open(pk_path, "wb") as f:
            f.write(pk)
        print(f"PK saved to {pk_path}")

    if g_sk_addr is not None:
        sk = bytes(ql.mem.read(g_sk_addr, SIZE_SK))
        sk_path = os.path.join(out_dir, f"sk{suffix}.bin")
        with open(sk_path, "wb") as f:
            f.write(sk)

        print(f"SK saved to {sk_path}")
        if save_s_csv:
            S_path = os.path.join(out_dir, "S", f"S{suffix}.csv")
            save_S_from_sk_csv(sk, S_path)
            print(f"S saved to {S_path}")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")

def make_snapshot_tracing(ql, address, size, namespace):
    """
    Trace from the beginning until the entry of crypto_kem_dec.
    After encapsulation, save ct_valid 
    """
    if namespace.get("stop_requested"):
        return

    address = normalize_addr(address)
    namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

    if address in namespace.get("skip_addrs", set()):
        print(f"[SKIP FUNC] Returning immediately from {hex(address)}")
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if handle_randombytes_call(ql, namespace, address):
        return

    ins, arg = disasm_with(ql, namespace.get("md"), address)

    snapshot_progress_interval = namespace.get("snapshot_progress_interval", 100_000)
    if snapshot_progress_interval and namespace["instr_counter"] % snapshot_progress_interval == 0:
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

    crypto_kem_enc_addr = namespace.get("crypto_kem_enc_addr")
    if crypto_kem_enc_addr and address == crypto_kem_enc_addr and not namespace.get("hit_crypto_kem_enc"):
        namespace["hit_crypto_kem_enc"] = True
        # This is for generating random valid ciphertexts
        namespace["host_randombytes_enabled"] = namespace.get("host_randombytes_for_encapsulation", True)
        print(
            f"crypto_kem_enc() hit during snapshot at {hex(address)}, "
            f"ct ptr = {hex(ql.arch.regs.read('r0'))}"
        )
        if namespace.get("snapshot_at") == "crypto_kem_enc":
            print("Saving snapshot at crypto_kem_enc entry, before encapsulation runs.")
            save_keys_from_qiling(
                ql,
                namespace.get("global_output_dir"),
                namespace.get("g_pk_addr"),
                namespace.get("g_sk_addr"),
                namespace.get("g_keypair_done_addr"),
                namespace.get("key_index"),
                namespace.get("save_key_s_csv", True),
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
            raise SnapshotReady("Reached crypto_kem_enc — snapshot ready")

    kem_keypair_addr = namespace.get("kem_keypair_addr")
    if kem_keypair_addr and address == kem_keypair_addr and not namespace.get("hit_kem_keypair"):
        namespace["hit_kem_keypair"] = True
        # This is for random keys
        namespace["host_randombytes_enabled"] = namespace.get("host_randombytes_for_keygen", True)
        namespace["address_PK"] = ql.arch.regs.read("r0")
        namespace["address_SK"] = ql.arch.regs.read("r1")
        print("----------------------------")
        print("Entering keypair generation:")
        print("----------------------------")
        print(f"pk ptr = {hex(namespace['address_PK'])}")
        print(f"sk ptr = {hex(namespace['address_SK'])}")
        if namespace.get("use_host_randombytes"):
            print("[RANDOM] host randombytes enabled for key generation")
        print("----------------------------")

    crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not namespace.get("hit_crypto_kem_dec"):
        namespace["hit_crypto_kem_dec"] = True
        namespace["address_CT"] = ql.arch.regs.read("r1")
        run_index = namespace.get("current_run_index")
        snapshot_mode = namespace["snapshot_mode"]
        output_dir = namespace.get("output_dir") or namespace.get("global_output_dir")

        print(
            f"crypto_kem_dec() hit during snapshot at {hex(address)}, "
            f"ct ptr = {hex(namespace['address_CT'])}"
        )
        print("Encapsulation complete. Saving valid ciphertext and snapshot at crypto_kem_dec entry.")

        save_keys_from_qiling(
            ql,
            namespace.get("global_output_dir"),
            namespace.get("g_pk_addr"),
            namespace.get("g_sk_addr"),
            namespace.get("g_keypair_done_addr"),
            namespace.get("key_index"),
            namespace.get("save_key_s_csv", True),
        )

        valid_ct = bytes(ql.mem.read(namespace["address_CT"], SIZE_CT))
        namespace["selected_ct"] = valid_ct
        namespace["selected_ct_ptr"] = namespace["address_CT"]
        namespace["selected_ct_mode"] = "valid"

        if snapshot_mode == "parallel":
            ct_path = get_ct_valid_path(output_dir)
            b_path = get_B_valid_csv_path(output_dir)
            label = "parallel valid ciphertext from snapshot"
        elif snapshot_mode == "sample":
            ct_path = get_sample_ct_valid_path(output_dir, run_index)
            b_path = get_B_valid_csv_path(output_dir, run_index)
            label = f"sample valid ciphertext from snapshot, run_index={run_index}"
        elif snapshot_mode == "truncated":
            ct_path = get_ct_valid_path(output_dir, run_index)
            b_path = get_B_valid_csv_path(output_dir, run_index)
            label = f"truncated valid ciphertext from snapshot, run_index={run_index}"
        else:
            raise ValueError(f"Unknown snapshot_mode: {snapshot_mode}")

        os.makedirs(os.path.dirname(ct_path), exist_ok=True)
        with open(ct_path, "wb") as f:
            f.write(valid_ct)
        print_ciphertext_summary(label, valid_ct, ct_path)
        save_B_from_ciphertext_csv(valid_ct, b_path)

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
    Save the sequential full trace: 
    - save the ciphertext used in decapsulation 
    - save the full trace with instructions and register values in csv format
    - save the ct, B' and S extracted from the trace in csv format
    """
    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]
    fault_index = namespace["fault_index"]
    ciphertext_mode = namespace.get("ciphertext_mode", "modified")
    is_valid = ciphertext_mode == "valid"

    os.makedirs(output_dir, exist_ok=True)

    ct = namespace.get("selected_ct")
    if ct is None:
        if ciphertext_mode == "valid":
            if namespace.get("valid_ct_from_enc") is not None:
                print("[CT] selected_ct missing; using cached crypto_kem_enc ciphertext")
                ct = namespace["valid_ct_from_enc"]
            elif namespace.get("enc_ct_ptr") is not None:
                enc_ct_ptr = namespace["enc_ct_ptr"]
                print(
                    f"[CT] selected_ct missing; reading crypto_kem_enc output "
                    f"from {hex(enc_ct_ptr)}"
                )
                ct = bytes(ql.mem.read(enc_ct_ptr, SIZE_CT))
            elif namespace.get("address_CT") is not None:
                address_CT = namespace["address_CT"]
                print(
                    f"[CT WARNING] selected_ct and crypto_kem_enc output missing; "
                    f"reading crypto_kem_dec ct pointer {hex(address_CT)}"
                )
                ct = bytes(ql.mem.read(address_CT, SIZE_CT))

        g_ct_addr = namespace.get("g_ct_addr")
        if ct is None and g_ct_addr is not None:
            print("[CT WARNING] selected_ct was not captured; reading g_ct as fallback")
            ct = bytes(ql.mem.read(g_ct_addr, SIZE_CT))

    if ct is not None:
        ct = bytes(ct)
        if ciphertext_mode == "valid" and all(byte == 0 for byte in ct):
            raise StopEmulation(
                "[CT ERROR] sequential valid ciphertext is all zero. "
                "crypto_kem_enc did not provide a usable ciphertext before saving."
            )

        ct_path = (
            get_ct_valid_path(output_dir, fault_index)
            if is_valid
            else get_ct_modified_path(output_dir, fault_index)
        )

        with open(ct_path, "wb") as f:
            f.write(ct)

        print(f"CT saved to {ct_path}")
        print_ciphertext_summary(
            f"sequential {ciphertext_mode} ciphertext, fault_index={fault_index}",
            ct,
            ct_path,
        )
        b_path = (
            get_B_valid_csv_path(output_dir, fault_index)
            if is_valid
            else os.path.join(output_dir, "B", f"B_{fault_index}.csv")
        )
        save_B_from_ciphertext_csv(bytes(ct), b_path)

    full_trace_path = (
        os.path.join(output_dir, f"trace_valid_{fault_index}.csv")
        if is_valid
        else get_trace_csv_path(output_dir, fault_index)
    )
    trim_trace_path = (
        os.path.join(output_dir_trim, f"trace_valid_{fault_index}.csv")
        if is_valid
        else get_trim_csv_path(output_dir_trim, fault_index)
    )
    register_label = f"valid_{fault_index}" if is_valid else fault_index

    save_current_trace(
        namespace,
        full_trace_path,
        trim_trace_path,
        output_dir,
        register_label,
    )


def make_full_trace(ql, address, size, namespace):
    """
    Trace in the sequential version the full trace that contains the decapsulation between the trigger_high and the trigger_low
    """
    if namespace.get("stop_requested"):
        return

    address = normalize_addr(address)
    namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

    skip = namespace.get("skip")
    if skip is not None and address == skip:
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if handle_randombytes_call(ql, namespace, address):
        return

    ins, arg = disasm_with(ql, namespace.get("md"), address)

    full_trace_progress_interval = namespace.get("full_trace_progress_interval", 100_000)
    if full_trace_progress_interval and namespace["instr_counter"] % full_trace_progress_interval == 0:
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
        namespace["host_randombytes_enabled"] = True
        namespace["address_PK"] = ql.arch.regs.read("r0")
        namespace["address_SK"] = ql.arch.regs.read("r1")
        print("----------------------------")
        print("Entering keypair generation:")
        print("----------------------------")
        print(f"pk ptr = {hex(namespace['address_PK'])}")
        print(f"sk ptr = {hex(namespace['address_SK'])}")
        if namespace.get("use_host_randombytes"):
            print("[RANDOM] host randombytes enabled for key generation")
        print("----------------------------")

    crypto_kem_enc_addr = namespace.get("crypto_kem_enc_addr")
    if crypto_kem_enc_addr and address == crypto_kem_enc_addr and not namespace.get("enc_active"):
        namespace["enc_active"] = True
        namespace["host_randombytes_enabled"] = True
        namespace["enc_ct_ptr"] = ql.arch.regs.read("r0")
        namespace["enc_return_addr"] = normalize_addr(ql.arch.regs.read("lr"))
        print(
            f"crypto_kem_enc() hit at {hex(address)}, "
            f"ct ptr = {hex(namespace['enc_ct_ptr'])}, "
            f"return = {hex(namespace['enc_return_addr'])}"
        )

    if (
        namespace.get("enc_active")
        and namespace.get("enc_return_addr") is not None
        and address == namespace.get("enc_return_addr")
        and namespace.get("valid_ct_from_enc") is None
    ):
        valid_ct = bytes(ql.mem.read(namespace["enc_ct_ptr"], SIZE_CT))
        namespace["valid_ct_from_enc"] = valid_ct
        namespace["enc_active"] = False
        print_ciphertext_summary("valid ciphertext captured after crypto_kem_enc", valid_ct)

        if namespace.get("ciphertext_mode", "modified") == "valid" and namespace.get("selected_ct") is None:
            namespace["selected_ct"] = valid_ct
            namespace["selected_ct_ptr"] = namespace["enc_ct_ptr"]
            namespace["selected_ct_mode"] = "valid"

    crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
    if crypto_kem_dec_addr and address == crypto_kem_dec_addr and not namespace.get("hit_crypto_kem_dec"):
        namespace["hit_crypto_kem_dec"] = True
        ct_ptr = ql.arch.regs.read("r1")
        namespace["address_CT"] = ct_ptr
        ciphertext_mode = namespace.get("ciphertext_mode", "modified")

        print("----------------------------")
        print("Entering decapsulation:")
        print("----------------------------")
        print(f"ct ptr = {hex(ct_ptr)}, ciphertext mode = {ciphertext_mode}")

        if ciphertext_mode == "modified":
            ct_base_path = namespace.get("ct_base_path")
            if ct_base_path is None:
                raise StopEmulation("[CT ERROR] Missing ct_base_path for sequential modified ciphertext")
            base_ct = load_base_ciphertext(ct_base_path)
            c1_initial, modified_ct = modify_ciphertext_c1_from_base(base_ct, namespace["fault_index"])
            test_modify_ciphertext_c1(namespace["fault_index"], c1_random=c1_initial, ct=modified_ct)
            selected_ct = bytes(modified_ct)
            ql.mem.write(ct_ptr, selected_ct)
            print(
                f"[CT] sequential modified ciphertext written to crypto_kem_dec ct ptr "
                f"({hex(ct_ptr)}) for fault_index={namespace['fault_index']}"
            )
            print_ciphertext_summary("sequential modified ciphertext selected for decapsulation", selected_ct)
        elif ciphertext_mode == "valid":
            selected_ct = bytes(ql.mem.read(ct_ptr, SIZE_CT))
            print("[CT] sequential valid ciphertext read from crypto_kem_dec ct pointer")
            ql.mem.write(ct_ptr, selected_ct)
        elif ciphertext_mode != "valid":
            raise ValueError(f"Unknown ciphertext_mode: {ciphertext_mode}")

        namespace["selected_ct"] = selected_ct
        namespace["selected_ct_ptr"] = ct_ptr
        namespace["selected_ct_mode"] = ciphertext_mode

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
                namespace.get("key_index"),
            )
            namespace["keypair_saved"] = True

        namespace["trace_started"] = True
        namespace["ins_trace"].clear()
        namespace["reg_trace"].clear()
        print(f"trigger_high() at {hex(address)}, trace starts")

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
    Save the full trace of the decapsulation, from trigger_high to trigger_low, and also save the trim version with only registers for parallel and sample modes
    """
    output_dir = namespace["output_dir"]
    output_dir_trim = namespace["output_dir_trim"]

    if mode == "parallel":
        fault_index = namespace["fault_index"]
        is_valid = namespace.get("ciphertext_mode") == "valid"
        full_csv = (
            os.path.join(output_dir, f"trace_valid_{fault_index}.csv")
            if is_valid
            else get_trace_csv_path(output_dir, fault_index)
        )
        trim_csv = (
            os.path.join(output_dir_trim, f"trace_valid_{fault_index}.csv")
            if is_valid
            else get_trim_csv_path(output_dir_trim, fault_index)
        )
        label = (
            f"valid_{fault_index}"
            if is_valid
            else fault_index
        )
    elif mode == "sample":
        run_index = namespace["current_run_index"]
        fault_index = namespace["current_fault_index"]
        is_valid = namespace.get("ciphertext_mode") == "valid"
        full_csv = (
            os.path.join(output_dir, f"trace_valid_{run_index}.csv")
            if is_valid
            else get_sample_trace_csv_path(output_dir, run_index, fault_index)
        )
        trim_csv = (
            os.path.join(output_dir_trim, f"trace_valid_{run_index}.csv")
            if is_valid
            else get_sample_trim_csv_path(output_dir_trim, run_index, fault_index)
        )
        label = (
            f"valid_{run_index}"
            if is_valid
            else f"{run_index}_{fault_index}"
        )
    else:
        raise ValueError(f"Unknown full decapsulation mode: {mode}")
    
    save_current_trace(namespace, full_csv, trim_csv, output_dir, label)


def make_full_decapsulation_tracing(ql, address, size, namespace, mode):
    """
    Capture the full trace of the decapsulation, from trigger_high to trigger_low, and also save the trim version with only registers for parallel and sample modes
    """
    if namespace.get("stop_requested"):
        return

    namespace["instr_counter"] = namespace.get("instr_counter", 0) + 1

    if address in namespace.get("skip_addrs", set()):
        print(f"[SKIP FUNC] Returning immediately from {hex(address)}")
        ql.arch.regs.write("pc", ql.arch.regs.read("lr"))
        return

    if handle_randombytes_call(ql, namespace, address):
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

    crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
    if (
        namespace.get("should_prepare_ciphertext_at_dec_entry")
        and crypto_kem_dec_addr
        and address == crypto_kem_dec_addr
        and not namespace.get("worker_ct_prepared_at_dec_entry")
    ):
        namespace["hit_crypto_kem_dec"] = True
        namespace["address_CT"] = ql.arch.regs.read("r1")
        namespace["dec_return_addr"] = normalize_addr(ql.arch.regs.read("lr"))
        print(
            f"crypto_kem_dec() hit in {mode} worker at {hex(address)}, "
            f"ct ptr = {hex(namespace['address_CT'])}"
        )
        prepare_ciphertext_at_dec_entry(ql, namespace, mode)
        namespace["worker_ct_prepared_at_dec_entry"] = True

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
    is_valid = namespace.get("ciphertext_mode") == "valid"
    fault_index = namespace.get("current_fault_index")
    random_index = namespace.get("current_random_index")
    random_suffix = "" if random_index is None else f"_random{random_index}"

    for xs_id in range(PARAMS_NBAR):
        full_path = (
            os.path.join(output_dir, f"trace_valid_{run_index}_{xs_id}{random_suffix}.csv")
            if is_valid
            else get_truncated_trace_csv_path(output_dir, run_index, xs_id, fault_index, random_index=random_index)
        )
        trim_path = (
            os.path.join(output_dir_trim, f"trace_valid_{run_index}_{xs_id}{random_suffix}.csv")
            if is_valid
            else get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id, fault_index, random_index=random_index)
        )

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

    if handle_randombytes_call(ql, namespace, address):
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

    crypto_kem_dec_addr = namespace.get("crypto_kem_dec_addr")
    if (
        namespace.get("should_prepare_ciphertext_at_dec_entry")
        and crypto_kem_dec_addr
        and address == crypto_kem_dec_addr
        and not namespace.get("worker_ct_prepared_at_dec_entry")
    ):
        namespace["hit_crypto_kem_dec"] = True
        namespace["address_CT"] = ql.arch.regs.read("r1")
        namespace["dec_return_addr"] = normalize_addr(ql.arch.regs.read("lr"))
        print(
            f"crypto_kem_dec() hit in truncated worker at {hex(address)}, "
            f"ct ptr = {hex(namespace['address_CT'])}"
        )
        prepare_ciphertext_at_dec_entry(ql, namespace, "truncated")
        namespace["worker_ct_prepared_at_dec_entry"] = True

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

    if (namespace.get("active_xs") and namespace.get("active_xs_return_addr") is not None and address == namespace.get("active_xs_return_addr")):
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
    Return worker arguments as a named config based on the selected tracing mode.
    """
    if mode == "parallel":
        ciphertext_mode = "modified"
        snapshot_at = "crypto_kem_dec"
        crypto_kem_dec_addr_local = None
        if len(worker_args) == 13:
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
                crypto_kem_dec_addr_local,
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 11:
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
                ciphertext_mode,
            ) = worker_args
        else:
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
            "crypto_kem_dec_addr": crypto_kem_dec_addr_local,
            "mul_bs_addr": None,
            "xs_addr": None,
            "ciphertext_mode": ciphertext_mode,
            "snapshot_at": snapshot_at,
        }

    if mode == "sample":
        ciphertext_mode = "modified"
        snapshot_at = "crypto_kem_dec"
        crypto_kem_dec_addr_local = None
        if len(worker_args) == 14:
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
                crypto_kem_dec_addr_local,
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 13:
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
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 12:
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
                ciphertext_mode,
            ) = worker_args
        else:
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
            "crypto_kem_dec_addr": crypto_kem_dec_addr_local,
            "mul_bs_addr": None,
            "xs_addr": None,
            "ciphertext_mode": ciphertext_mode,
            "snapshot_at": snapshot_at,
        }

    if is_truncated_worker_mode(mode):
        ciphertext_mode = "modified"
        snapshot_at = "crypto_kem_dec"
        crypto_kem_dec_addr_local = None
        random_index_local = None
        randombytes_addr_local = None
        use_host_randombytes_local = False
        if len(worker_args) == 19:
            (
                run_index_local,
                fault_index_local,
                random_index_local,
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
                crypto_kem_dec_addr_local,
                randombytes_addr_local,
                use_host_randombytes_local,
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 17:
            (
                run_index_local,
                fault_index_local,
                random_index_local,
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
                crypto_kem_dec_addr_local,
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 16:
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
                crypto_kem_dec_addr_local,
                ciphertext_mode,
                snapshot_at,
            ) = worker_args
        elif len(worker_args) == 14:
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
                ciphertext_mode,
            ) = worker_args
        else:
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
            "random_index": random_index_local,
            "snapshot_path": snapshot_path_local,
            "elf_file": elf_file,
            "output_dir": output_dir_local,
            "output_dir_trim": output_dir_trim_local,
            "trigger_high_addr": trigger_high_addr_local,
            "trigger_low_addr": trigger_low_addr_local,
            "skip_addrs": skip_addrs_local,
            "g_ct_addr": g_ct_addr_local,
            "clear_bytes_addr": clear_bytes_addr_local,
            "randombytes_addr": randombytes_addr_local,
            "use_host_randombytes": use_host_randombytes_local,
            "crypto_kem_dec_addr": crypto_kem_dec_addr_local,
            "mul_bs_addr": mul_bs_addr_local,
            "xs_addr": xs_addr_local,
            "ciphertext_mode": ciphertext_mode,
            "snapshot_at": snapshot_at,
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
        namespace["current_random_index"] = config.get("random_index")

    namespace["trigger_high_addr"] = config["trigger_high_addr"]
    namespace["trigger_low_addr"] = config["trigger_low_addr"]
    if config.get("crypto_kem_dec_addr") is not None:
        namespace["crypto_kem_dec_addr"] = config["crypto_kem_dec_addr"]
    namespace["skip_addrs"] = set(config["skip_addrs"])
    namespace["g_ct_addr"] = config["g_ct_addr"]
    namespace["clear_bytes_addr"] = config["clear_bytes_addr"]
    namespace["randombytes_addr"] = config.get("randombytes_addr")
    namespace["use_host_randombytes"] = config.get("use_host_randombytes", namespace.get("use_host_randombytes", False))
    namespace["host_randombytes_for_keygen"] = config.get("host_randombytes_for_keygen", namespace.get("host_randombytes_for_keygen", True))
    namespace["host_randombytes_for_encapsulation"] = config.get("host_randombytes_for_encapsulation", namespace.get("host_randombytes_for_encapsulation", True))
    namespace["output_dir"] = config["output_dir"]
    namespace["output_dir_trim"] = config["output_dir_trim"]
    namespace["global_output_dir"] = config["output_dir"]
    namespace["ciphertext_mode"] = config.get("ciphertext_mode", "modified")
    namespace["snapshot_at"] = config.get("snapshot_at", "crypto_kem_dec")
    namespace["should_prepare_ciphertext_at_dec_entry"] = (
        namespace["snapshot_at"] == "crypto_kem_enc"
    )
    namespace["host_randombytes_enabled"] = (
        namespace["should_prepare_ciphertext_at_dec_entry"]
        and namespace["use_host_randombytes"]
    )
    namespace["md"] = make_disasm()
    namespace.setdefault("ins_trace", [])
    namespace.setdefault("reg_trace", [])

    if is_truncated_worker_mode(mode):
        namespace["mul_bs_addr"] = config["mul_bs_addr"]
        namespace["xs_addr"] = config["xs_addr"]


def load_snapshot_into_worker(namespace, config):
    """
    Load the snapshot into the qiling instance, and set the return address for backup stopping.
    """
    ql = setup_qiling_instance(
        config["elf_file"],
        patch_uart=False,
        include_bitband=False,
    )
    
    with open(config["snapshot_path"], "rb") as f:
        snapshot = pickle.load(f)

    restore_snapshot_manual(ql, snapshot)
    if config.get("snapshot_at") == "crypto_kem_enc":
        namespace["dec_return_addr"] = None
    else:
        namespace["address_CT"] = snapshot["regs"].get("r1")
        namespace["dec_return_addr"] = normalize_addr(snapshot["regs"]["lr"])
    del snapshot

    return ql


def prepare_worker_ciphertext(ql, config, mode):
    """
    Create the ciphertext based on config["ciphertext_mode"]:
    - valid: the honest created ciphertext 
    - modified: altered ciphertext with fault indices 
    Also save the selected ciphertext and the extracted B in csv format in the output directory.
    """

    run_index = config["run_index"]
    fault_index = config["fault_index"]
    random_index = config.get("random_index")
    output_dir = config["output_dir"]
    ct_ptr = ql.arch.regs.read("r1") or config["g_ct_addr"]
    ciphertext_mode = config.get("ciphertext_mode", "modified")

    if ciphertext_mode not in {"valid", "modified"}:
        raise ValueError(f"Unknown ciphertext_mode: {ciphertext_mode}")

    if ciphertext_mode == "modified":
        if mode == "parallel":
            base_ct_path = os.path.join(output_dir, "ct_base.bin")
        else:
            base_ct_path = get_run_ciphertext_path(output_dir, run_index, random_index=random_index)

        base_ct = load_base_ciphertext(base_ct_path, force_generate=True)
        c1_initial, selected_ct = modify_ciphertext_c1_from_base(base_ct, fault_index)
        test_modify_ciphertext_c1(fault_index, c1_random=c1_initial, ct=selected_ct)
        ql.mem.write(ct_ptr, bytes(selected_ct))
        read_back = bytes(ql.mem.read(ct_ptr, SIZE_CT))
        if read_back != bytes(selected_ct):
            raise StopEmulation(f"[CT ERROR] overwrite failed at {hex(ct_ptr)}")
        print("[CT OK] modified ciphertext overwrite confirmed")
        action_label = "Modified"
    else:
        selected_ct = bytes(ql.mem.read(ct_ptr, SIZE_CT))
        action_label = "Valid"

    if mode == "parallel":
        ct_path = (
            get_ct_valid_path(output_dir)
            if ciphertext_mode == "valid"
            else get_ct_modified_path(output_dir, fault_index)
        )
        b_path = (
            get_B_valid_csv_path(output_dir)
            if ciphertext_mode == "valid"
            else os.path.join(output_dir, "B", f"B_{fault_index}.csv")
        )
        os.makedirs(os.path.dirname(ct_path), exist_ok=True)
        with open(ct_path, "wb") as f:
            f.write(selected_ct)

        print(f"[WORKER {fault_index}] {action_label} CT selected at dec ct ptr ({hex(ct_ptr)})")
        print(f"[WORKER {fault_index}] ciphertext saved to {ct_path}")
        if ciphertext_mode == "valid":
            print_ciphertext_summary(
                f"parallel valid ciphertext, fault_index={fault_index}",
                selected_ct,
                ct_path,
            )
        save_B_from_ciphertext_csv(selected_ct, b_path)
        return

    if mode == "sample":
        ct_path = (
            get_sample_ct_valid_path(output_dir, run_index)
            if ciphertext_mode == "valid"
            else get_sample_ct_modified_path(output_dir, run_index, fault_index)
        )
        b_path = (
            get_B_valid_csv_path(output_dir, run_index)
            if ciphertext_mode == "valid"
            else os.path.join(output_dir, "B", f"B_{run_index}_{fault_index}.csv")
        )
        os.makedirs(os.path.dirname(ct_path), exist_ok=True)
        with open(ct_path, "wb") as f:
            f.write(selected_ct)

        print(f"[WORKER run={run_index} fault={fault_index}] {action_label} CT selected at dec ct ptr ({hex(ct_ptr)})")
        print(f"[WORKER run={run_index + 1} fault={fault_index}] ciphertext saved to {ct_path}")
        if ciphertext_mode == "valid":
            print_ciphertext_summary(
                f"sample valid ciphertext, run_index={run_index}",
                selected_ct,
                ct_path,
            )
        save_B_from_ciphertext_csv(selected_ct, b_path)
        return

    if is_truncated_worker_mode(mode):
        ct_path = (
            get_ct_valid_path(output_dir, run_index, random_index=random_index)
            if ciphertext_mode == "valid"
            else get_sample_ct_modified_path(output_dir, run_index, fault_index, random_index=random_index)
        )
        with open(ct_path, "wb") as f:
            f.write(selected_ct)

        print(f"[WORKER run={run_index + 1} fault={fault_index}] {action_label} CT selected at dec ct ptr ({hex(ct_ptr)})")
        print(f"[WORKER run={run_index} fault={fault_index}] ciphertext saved to {ct_path}")
        if ciphertext_mode == "valid":
            print_ciphertext_summary(
                f"truncated valid ciphertext, run_index={run_index}, fault_index={fault_index}",
                selected_ct,
                ct_path,
            )
        b_path = (
            get_B_valid_csv_path(output_dir, run_index, random_index=random_index)
            if ciphertext_mode == "valid"
            else get_B_csv_path(output_dir, run_index, fault_index, random_index=random_index)
        )

        save_B_from_ciphertext_csv(selected_ct, b_path)
        return

    raise ValueError(f"Unknown decapsulation worker mode: {mode}")


def prepare_ciphertext_at_dec_entry(ql, namespace, mode):
    run_index = namespace.get("current_run_index")
    fault_index = namespace.get("fault_index") if mode == "parallel" else namespace.get("current_fault_index")
    random_index = namespace.get("current_random_index")
    output_dir = namespace["output_dir"]
    ciphertext_mode = namespace.get("ciphertext_mode", "modified")
    ct_ptr = namespace["address_CT"]

    if ciphertext_mode == "modified":
        if mode == "parallel":
            base_ct_path = os.path.join(output_dir, "ct_base.bin")
        else:
            base_ct_path = get_run_ciphertext_path(output_dir, run_index, random_index=random_index)

        base_ct = load_base_ciphertext(base_ct_path)
        c1_initial, selected_ct = modify_ciphertext_c1_from_base(base_ct, fault_index)
        test_modify_ciphertext_c1(fault_index, c1_random=c1_initial, ct=selected_ct)
        ql.mem.write(ct_ptr, bytes(selected_ct))

        if mode == "parallel":
            ct_path = get_ct_modified_path(output_dir, fault_index)
            b_path = os.path.join(output_dir, "B", f"B_{fault_index}.csv")
            label = f"parallel modified ciphertext, fault_index={fault_index}"
        elif mode == "sample":
            ct_path = get_sample_ct_modified_path(output_dir, run_index, fault_index)
            b_path = os.path.join(output_dir, "B", f"B_{run_index}_{fault_index}.csv")
            label = f"sample modified ciphertext, run_index={run_index}, fault_index={fault_index}"
        elif is_truncated_worker_mode(mode):
            ct_path = get_sample_ct_modified_path(output_dir, run_index, fault_index, random_index=random_index)
            b_path = get_B_csv_path(output_dir, run_index, fault_index, random_index=random_index)
            label = f"{mode} modified ciphertext, run_index={run_index}, fault_index={fault_index}"
        else:
            raise ValueError(f"Unknown decapsulation worker mode: {mode}")
    elif ciphertext_mode == "valid":
        selected_ct = bytes(ql.mem.read(ct_ptr, SIZE_CT))
        ql.mem.write(ct_ptr, bytes(selected_ct))

        if mode == "parallel":
            ct_path = get_ct_valid_path(output_dir)
            b_path = get_B_valid_csv_path(output_dir)
            label = "parallel valid ciphertext"
        elif mode == "sample":
            ct_path = get_sample_ct_valid_path(output_dir, run_index)
            b_path = get_B_valid_csv_path(output_dir, run_index)
            label = f"sample valid ciphertext, run_index={run_index}"
        elif is_truncated_worker_mode(mode):
            ct_path = get_ct_valid_path(output_dir, run_index, random_index=random_index)
            b_path = get_B_valid_csv_path(output_dir, run_index, random_index=random_index)
            label = f"{mode} valid ciphertext, run_index={run_index}, random_index={random_index}"
        else:
            raise ValueError(f"Unknown decapsulation worker mode: {mode}")
    else:
        raise ValueError(f"Unknown ciphertext_mode: {ciphertext_mode}")

    os.makedirs(os.path.dirname(ct_path), exist_ok=True)
    with open(ct_path, "wb") as f:
        f.write(selected_ct)

    namespace["selected_ct"] = bytes(selected_ct)
    namespace["selected_ct_ptr"] = ct_ptr
    namespace["selected_ct_mode"] = ciphertext_mode

    print(f"[WORKER mode={mode} run={run_index} fault={fault_index}] {ciphertext_mode} CT selected at dec ct ptr ({hex(ct_ptr)})")
    print(f"[WORKER mode={mode} run={run_index} fault={fault_index}] ciphertext saved to {ct_path}")
    print_ciphertext_summary(label, selected_ct, ct_path)
    save_B_from_ciphertext_csv(selected_ct, b_path)


def hook_worker_tracing(ql, namespace, mode):
    """
    Hook the appropriate tracing function based on the worker mode (parallel, sample or truncated)
    - truncated captures each dot products while the other capture the entire multiplication
    """
    if is_truncated_worker_mode(mode):
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
        backup = namespace.get("dec_return_addr")
        print(
            f"[WORKER {fault_index}] "
            f"Backup return address = {hex(backup) if backup is not None else None}"
        )
        print(f"Running decapsulation for fault index {fault_index}...")
    elif mode == "sample":
        backup = namespace.get("dec_return_addr")
        print(
            f"[WORKER run={run_index + 1} fault={fault_index}] "
            f"Backup return address = {hex(backup) if backup is not None else None}"
        )
        print(f"Running decapsulation for Run_{run_index + 1}, fault index {fault_index}...")
    elif is_truncated_worker_mode(mode):
        backup = namespace.get("dec_return_addr")
        print(
            f"[WORKER run={run_index + 1} fault={fault_index}] "
            f"Backup return address = {hex(backup) if backup is not None else None}"
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
    elif is_truncated_worker_mode(mode):
        print(f"\nSummary for run {run_index}, fault index {fault_index}:")

    print(f"  trigger_high hit = {namespace.get('hit_trigger_high')}")
    print(f"  trigger_low hit  = {namespace.get('hit_trigger_low')}")


def expected_worker_outputs(config, mode):
    output_dir = config["output_dir"]
    output_dir_trim = config["output_dir_trim"]
    ciphertext_mode = config.get("ciphertext_mode", "modified")
    fault_index = config["fault_index"]
    run_index = config["run_index"]
    random_index = config.get("random_index")

    if mode == "parallel":
        if ciphertext_mode == "valid":
            return [
                get_ct_valid_path(output_dir),
                get_B_valid_csv_path(output_dir),
                os.path.join(output_dir, "trace_valid_0.csv"),
                os.path.join(output_dir_trim, "trace_valid_0.csv"),
            ]
        return [
            get_ct_modified_path(output_dir, fault_index),
            os.path.join(output_dir, "B", f"B_{fault_index}.csv"),
            get_trace_csv_path(output_dir, fault_index),
            get_trim_csv_path(output_dir_trim, fault_index),
        ]

    if mode == "sample":
        if ciphertext_mode == "valid":
            return [
                get_sample_ct_valid_path(output_dir, run_index),
                get_B_valid_csv_path(output_dir, run_index),
                os.path.join(output_dir, f"trace_valid_{run_index}.csv"),
                os.path.join(output_dir_trim, f"trace_valid_{run_index}.csv"),
            ]
        return [
            get_sample_ct_modified_path(output_dir, run_index, fault_index),
            os.path.join(output_dir, "B", f"B_{run_index}_{fault_index}.csv"),
            get_sample_trace_csv_path(output_dir, run_index, fault_index),
            get_sample_trim_csv_path(output_dir_trim, run_index, fault_index),
        ]

    if is_truncated_worker_mode(mode):
        if ciphertext_mode == "valid":
            random_suffix = "" if random_index is None else f"_random{random_index}"
            return [
                get_ct_valid_path(output_dir, run_index, random_index=random_index),
                get_B_valid_csv_path(output_dir, run_index, random_index=random_index),
                os.path.join(output_dir, f"trace_valid_{run_index}_0{random_suffix}.csv"),
                os.path.join(output_dir_trim, f"trace_valid_{run_index}_0{random_suffix}.csv"),
            ]
        return [
            get_sample_ct_modified_path(output_dir, run_index, fault_index, random_index=random_index),
            get_B_csv_path(output_dir, run_index, fault_index, random_index=random_index),
            get_truncated_trace_csv_path(output_dir, run_index, 0, fault_index, random_index=random_index),
            get_truncated_trim_csv_path(output_dir_trim, run_index, 0, fault_index, random_index=random_index),
        ]

    return []


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

    reset_trace_state(namespace, include_xs=is_truncated_worker_mode(mode))
    if namespace.get("should_prepare_ciphertext_at_dec_entry") and namespace.get("use_host_randombytes"):
        namespace["host_randombytes_enabled"] = True
    ql = load_snapshot_into_worker(namespace, config)
    if not namespace.get("should_prepare_ciphertext_at_dec_entry"):
        namespace["address_CT"] = ql.arch.regs.read("r1")
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

    if is_truncated_worker_mode(mode):
        save_and_check_B_from_registers_from_traces(
            config["output_dir"],
            config["output_dir_trim"],
            config["run_index"],
            valid=config.get("ciphertext_mode") == "valid",
            fault_index=None if config.get("ciphertext_mode") == "valid" else config["fault_index"],
            random_index=config.get("random_index"),
        )
        save_and_check_S_from_traces(
            config["output_dir"],
            config["output_dir_trim"],
            config["run_index"],
            fault_index=None if config.get("ciphertext_mode") == "valid" else config["fault_index"],
            valid=config.get("ciphertext_mode") == "valid",
            random_index=config.get("random_index"),
        )

    missing_outputs = [
        path for path in expected_worker_outputs(config, mode)
        if not os.path.exists(path)
    ]
    if missing_outputs:
        raise FileNotFoundError(
            f"Worker finished without expected outputs for mode={mode}, "
            f"ciphertext_mode={config.get('ciphertext_mode')}, "
            f"run={config.get('run_index')}, fault={config.get('fault_index')}: "
            f"{missing_outputs}"
        )

    print_worker_summary(config, namespace, mode)


def update_globals_from_symbols(namespace, symbols):
    """
    Update the global namespace with the given symbols dictionary
    """
    for name, value in symbols.items():
        namespace[name] = value
