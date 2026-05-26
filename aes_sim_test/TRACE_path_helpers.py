import os


def get_snapshot_path(output_dir):
    return os.path.join(output_dir, "snapshot.pkl")


def get_sample_snapshot_path(output_dir, run_index):
    return os.path.join(output_dir, f"snapshot_{run_index}.pkl")


def get_trace_csv_path(output_dir, index):
    return os.path.join(output_dir, f"trace_{index}.csv")


def get_trim_csv_path(output_dir_trim, index):
    return os.path.join(output_dir_trim, f"trace_{index}.csv")


def get_ct_modified_path(output_dir, index):
    return os.path.join(output_dir, f"ct_modified_{index}.bin")


def get_ct_valid_path(output_dir, index=None):
    if index is None:
        return os.path.join(output_dir, "ct_valid.bin")
    return os.path.join(output_dir, f"ct_valid_{index}.bin")


def get_run_ciphertext_path(output_dir, run_index):
    return os.path.join(output_dir, f"ct_base_{run_index}.bin")


def get_truncated_trace_csv_path(output_dir, run_index, xs_id, fault_index=None):
    if fault_index is None:
        return os.path.join(output_dir, f"trace_{run_index}_{xs_id}.csv")
    return os.path.join(output_dir, f"trace_{run_index}_{xs_id}_{fault_index}.csv")


def get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id, fault_index=None):
    if fault_index is None:
        return os.path.join(output_dir_trim, f"trace_{run_index}_{xs_id}.csv")
    return os.path.join(output_dir_trim, f"trace_{run_index}_{xs_id}_{fault_index}.csv")


def get_sample_trace_csv_path(output_dir, run_index, fault_index):
    return os.path.join(output_dir, f"trace_{run_index}_{fault_index}.csv")


def get_sample_trim_csv_path(output_dir_trim, run_index, fault_index):
    return os.path.join(output_dir_trim, f"trace_{run_index}_{fault_index}.csv")


def get_sample_ct_modified_path(output_dir, run_index, fault_index):
    return os.path.join(output_dir, f"ct_modified_{run_index}_{fault_index}.bin")


def get_sample_ct_valid_path(output_dir, run_index, fault_index=None):
    if fault_index is None:
        return os.path.join(output_dir, f"ct_valid_{run_index}.bin")
    return os.path.join(output_dir, f"ct_valid_{run_index}_{fault_index}.bin")


def get_B_dir(output_dir):
    return os.path.join(output_dir, "B")


def get_S_dir(output_dir):
    return os.path.join(output_dir, "S")


def get_B_csv_path(output_dir, run_index, fault_index=None):
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_{run_index}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_{run_index}_{fault_index}.csv")


def get_B_valid_csv_path(output_dir, run_index=None):
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), "B_valid.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_{run_index}.csv")


def get_B_from_registers_csv_path(output_dir, run_index, fault_index=None):
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_from_registers_{run_index}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_from_registers_{run_index}_{fault_index}.csv")


def get_B_valid_from_registers_csv_path(output_dir, run_index=None):
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), "B_valid_from_registers.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers_{run_index}.csv")


def get_B_packed_from_registers_csv_path(output_dir, run_index, fault_index=None):
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_from_registers_packed_{run_index}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_from_registers_packed_{run_index}_{fault_index}.csv")


def get_B_valid_packed_from_registers_csv_path(output_dir, run_index=None):
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), "B_valid_from_registers_packed.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers_packed_{run_index}.csv")


def get_S_csv_path(output_dir, run_index):
    return os.path.join(get_S_dir(output_dir), f"S_{run_index}.csv")


def get_S_from_sk_csv_path(output_dir):
    return os.path.join(get_S_dir(output_dir), "S.csv")
