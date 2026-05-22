import os
import re
from pathlib import Path

import numpy as np
import pandas as pd


from analysis_HW_HD_utils import create_HW_trace, create_HD_trace

def create_npy_file(name_npy_file, folder, leakage_model, cols):
    """
    create one .npy file from a folder containing trace CSV files
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []

    for count, file in enumerate(sorted(Path(folder).glob("*.csv"))):
        if count % 100 == 0:
            print(f"Trace {count} has been converted")

        if leakage_model == "HW":
            trace = create_HW_trace(file, cols)
        elif leakage_model == "HD":
            trace = create_HD_trace(file, cols)
        else:
            raise ValueError("leakage_model must be 'HW' or 'HD'")

        trace_list.append(trace)

    print(f"The last trace that was captured is Trace {len(trace_list)}")
    vectors_array = np.array(trace_list)
    np.save(name_npy_file, vectors_array)
    print(f"Finished creating {name_npy_file}.npy, shape = {vectors_array.shape}")


def create_grouped_npy_files(name_npy_file, folder, leakage_model, cols):
    """
    create one .npy file per trace index from Run_*/*.csv inputs
    """
    def get_trace_index_from_filename(file_path):
        index = re.search(r"trace_(\d+)\.csv$", file_path.name)
        if index is None:
            raise ValueError(f"Could not extract trace index from filename: {file_path}")
        return int(index.group(1))

    print(f"Creating grouped simulation traces for model: {leakage_model}")
    os.makedirs(name_npy_file, exist_ok=True)
    grouped_traces = {}

    files = sorted(
        Path(folder).glob("Run_*/*.csv"),
        key=lambda path: (path.parent.name, get_trace_index_from_filename(path)),
    )

    for count, file in enumerate(files):
        if count % 100 == 0:
            print(f"Trace {count} has been converted")

        trace_index = get_trace_index_from_filename(file)

        if leakage_model == "HW":
            trace = create_HW_trace(file, cols)
        elif leakage_model == "HD":
            trace = create_HD_trace(file, cols)
        else:
            raise ValueError("leakage_model must be 'HW' or 'HD'")

        if trace_index not in grouped_traces:
            grouped_traces[trace_index] = []
        grouped_traces[trace_index].append(trace)

    for trace_index, trace_list in grouped_traces.items():
        min_len = min(len(t) for t in trace_list)
        vectors_array = np.array([t[:min_len] for t in trace_list])
        output_path = os.path.join(name_npy_file, f"{leakage_model}_trace_{trace_index}.npy")
        np.save(output_path, vectors_array)
        print(f"Saved {output_path} with shape {vectors_array.shape}")

    print(f"Finished creating grouped files for {leakage_model}")


def create_sample_npy_files(name_npy_file, folder, leakage_model, cols):
    """
    Create one .npy file per run from trace_{run}_{fault}.csv inputs.
    Rows inside each .npy are ordered by fault index.
    """
    def parse_trace_name(path):
        match = re.match(r"trace_(\d+)_(\d+)\.csv$", path.name)
        if match is None:
            return None
        run_index = int(match.group(1))
        fault_index = int(match.group(2))
        return run_index, fault_index

    print(f"Creating sample simulation traces for model: {leakage_model}")
    os.makedirs(name_npy_file, exist_ok=True)

    files = []
    for file in Path(folder).glob("trace_*_*.csv"):
        parsed = parse_trace_name(file)
        if parsed is None:
            continue
        run_index, fault_index = parsed
        files.append((run_index, fault_index, file))

    files.sort(key=lambda item: (item[0], item[1]))
    print(f"Found {len(files)} sample trace files")

    traces_by_run = {}
    trace_order_rows = []

    for count, (run_index, fault_index, file) in enumerate(files):
        if count % 100 == 0:
            print(f"Trace {count} has been converted")

        if leakage_model == "HW":
            trace = create_HW_trace(file, cols)
        elif leakage_model == "HD":
            trace = create_HD_trace(file, cols)
        else:
            raise ValueError("leakage_model must be 'HW' or 'HD'")

        traces_by_run.setdefault(run_index, []).append((fault_index, trace))
        trace_order_rows.append({
            "run_index": run_index,
            "fault_index": fault_index,
            "trace_csv": file.name,
            "trace_path": str(file),
        })

        print(f"Run {run_index}, fault {fault_index} -> {file.name}")

    trace_order_df = pd.DataFrame(trace_order_rows)
    trace_order_path = os.path.join(name_npy_file, f"{leakage_model}_sample_order.csv")
    trace_order_df.to_csv(trace_order_path, index=False)
    print(f"Saved trace order debug file: {trace_order_path}")

    for run_index, rows in sorted(traces_by_run.items()):
        rows.sort(key=lambda item: item[0])
        fault_indices = [fault_index for fault_index, _ in rows]
        min_len = min(len(trace) for _, trace in rows)
        vectors_array = np.array([trace[:min_len] for _, trace in rows])

        output_path = os.path.join(name_npy_file, f"{leakage_model}_run_{run_index}.npy")
        np.save(output_path, vectors_array)

        fault_order_path = os.path.join(name_npy_file, f"{leakage_model}_run_{run_index}_fault_order.csv")
        pd.DataFrame({"row": range(len(fault_indices)), "fault_index": fault_indices}).to_csv(
            fault_order_path,
            index=False,
        )

        print(f"Saved {output_path} with shape {vectors_array.shape}")
        print(f"Saved fault order file: {fault_order_path}")

    print(f"Finished creating sample files for {leakage_model}")


def create_npy_file_truncated(name_npy_file, folder, leakage_model, cols):
    """
    create one .npy file per xs_id from trace_{run}_{xs}.csv inputs 
    """
    def parse_trace_name(path):
        match = re.match(r"trace_(\d+)_(\d+)\.csv", path.name)
        if match is None:
            return None
        run_index = int(match.group(1))
        xs_id = int(match.group(2))
        return run_index, xs_id

    print("Creating simulation traces model....", leakage_model)

    traces_by_xs = {xs_id: [] for xs_id in range(8)}
    run_indices_by_xs = {xs_id: [] for xs_id in range(8)}
    trace_order_rows = []
    files = []

    for file in Path(folder).glob("trace_*_*.csv"):
        parsed = parse_trace_name(file)
        if parsed is None:
            continue
        run_index, xs_id = parsed
        files.append((run_index, xs_id, file))

    files.sort(key=lambda item: (item[0], item[1]))

    print(f"Found {len(files)} truncated trace files")

    for count, (run_index, xs_id, file) in enumerate(files):
        if count % 100 == 0:
            print(f"Trace {count} has been converted")

        if leakage_model == "HW":
            trace = create_HW_trace(file, cols)
        elif leakage_model == "HD":
            trace = create_HD_trace(file, cols)
        else:
            raise ValueError("leakage_model must be 'HW' or 'HD'")

        row_in_xs = len(traces_by_xs[xs_id])
        traces_by_xs[xs_id].append(trace)
        run_indices_by_xs[xs_id].append(run_index)
        trace_order_rows.append({
            "row_in_xs": row_in_xs,
            "xs_id": xs_id,
            "run_index": run_index,
            "trace_csv": file.name,
            "trace_path": str(file),
        })

        print(f"Trace row {row_in_xs} for xs={xs_id} -> {file.name}")

    trace_order_df = pd.DataFrame(trace_order_rows)
    trace_order_path = os.path.join(os.path.dirname(name_npy_file), f"{leakage_model}_SUBTRACE_order.csv")
    trace_order_df.to_csv(trace_order_path, index=False)
    print(f"Saved trace order debug file: {trace_order_path}")

    for xs_id in range(8):
        if run_indices_by_xs[xs_id] != sorted(run_indices_by_xs[xs_id]):
            print(f"[WARNING] xs_id {xs_id} traces are not in run order: {run_indices_by_xs[xs_id][:10]}")

        vectors_array = np.array(traces_by_xs[xs_id])
        npy_name = f"{name_npy_file}_xs{xs_id}.npy"
        np.save(npy_name, vectors_array)
        print(f"Saved {npy_name}, shape = {vectors_array.shape}")

    print("Finished creating truncated npy files")
