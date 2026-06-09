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


def get_ct_valid_path(output_dir, index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if index is None:
        return os.path.join(output_dir, f"ct_valid{random_suffix}.bin")
    return os.path.join(output_dir, f"ct_valid_{index}{random_suffix}.bin")


def get_run_ciphertext_path(output_dir, run_index, random_index=None):
    if random_index is None:
        return os.path.join(output_dir, f"ct_base_{run_index}.bin")
    return os.path.join(output_dir, f"ct_base_{run_index}_random{random_index}.bin")


def get_truncated_trace_csv_path(output_dir, run_index, xs_id, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(output_dir, f"trace_{run_index}_{xs_id}{random_suffix}.csv")
    return os.path.join(output_dir, f"trace_{run_index}_{xs_id}_{fault_index}{random_suffix}.csv")


def get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(output_dir_trim, f"trace_{run_index}_{xs_id}{random_suffix}.csv")
    return os.path.join(output_dir_trim, f"trace_{run_index}_{xs_id}_{fault_index}{random_suffix}.csv")


def get_sample_trace_csv_path(output_dir, run_index, fault_index):
    return os.path.join(output_dir, f"trace_{run_index}_{fault_index}.csv")


def get_sample_trim_csv_path(output_dir_trim, run_index, fault_index):
    return os.path.join(output_dir_trim, f"trace_{run_index}_{fault_index}.csv")


def get_sample_ct_modified_path(output_dir, run_index, fault_index, random_index=None):
    if random_index is None:
        return os.path.join(output_dir, f"ct_modified_{run_index}_{fault_index}.bin")
    return os.path.join(output_dir, f"ct_modified_{run_index}_{fault_index}_random{random_index}.bin")


def get_sample_ct_valid_path(output_dir, run_index, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(output_dir, f"ct_valid_{run_index}{random_suffix}.bin")
    return os.path.join(output_dir, f"ct_valid_{run_index}_{fault_index}{random_suffix}.bin")


def get_B_dir(output_dir):
    return os.path.join(output_dir, "B")


def get_S_dir(output_dir):
    return os.path.join(output_dir, "S")


def get_B_csv_path(output_dir, run_index, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_{run_index}{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_{run_index}_{fault_index}{random_suffix}.csv")


def get_B_valid_csv_path(output_dir, run_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_valid{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_{run_index}{random_suffix}.csv")


def get_B_from_registers_csv_path(output_dir, run_index, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_from_registers_{run_index}{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_from_registers_{run_index}_{fault_index}{random_suffix}.csv")


def get_B_valid_from_registers_csv_path(output_dir, run_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers_{run_index}{random_suffix}.csv")


def get_B_packed_from_registers_csv_path(output_dir, run_index, fault_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if fault_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_from_registers_packed_{run_index}{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_from_registers_packed_{run_index}_{fault_index}{random_suffix}.csv")


def get_B_valid_packed_from_registers_csv_path(output_dir, run_index=None, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if run_index is None:
        return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers_packed{random_suffix}.csv")
    return os.path.join(get_B_dir(output_dir), f"B_valid_from_registers_packed_{run_index}{random_suffix}.csv")


def get_S_csv_path(output_dir, run_index, fault_index=None, valid=False, random_index=None):
    random_suffix = "" if random_index is None else f"_random{random_index}"
    if valid:
        return os.path.join(get_S_dir(output_dir), f"S_valid_{run_index}{random_suffix}.csv")
    if fault_index is None:
        return os.path.join(get_S_dir(output_dir), f"S_{run_index}{random_suffix}.csv")
    return os.path.join(get_S_dir(output_dir), f"S_{run_index}_{fault_index}{random_suffix}.csv")


def get_S_from_sk_csv_path(output_dir):
    return os.path.join(get_S_dir(output_dir), "S.csv")
