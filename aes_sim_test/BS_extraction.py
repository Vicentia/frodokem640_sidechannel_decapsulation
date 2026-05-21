import csv
import os

import numpy as np
import pandas as pd

from parameters_initialisation import (
    PARAMS_N,
    PARAMS_NBAR,
    REG_ALIAS,
    SEED_A_length,
    S_length,
    b_length,
    s_length,
)
from path_helpers import (
    get_B_csv_path,
    get_B_dir,
    get_B_from_registers_csv_path,
    get_B_packed_from_registers_csv_path,
    get_S_csv_path,
    get_truncated_trim_csv_path,
)
from stop_tracing import StopEmulation


def save_S_from_sk_csv(sk, S_path):
    before_S = s_length + SEED_A_length + b_length
    S = sk[before_S: before_S + S_length]

    if len(S) != S_length:
        raise ValueError(f"S has wrong size: {len(S)} != {S_length}")

    S_by_xs = np.frombuffer(S, dtype="<i2").reshape(PARAMS_NBAR, PARAMS_N)
    S_matrix = S_by_xs.T

    os.makedirs(os.path.dirname(S_path), exist_ok=True)

    with open(S_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["row"] + [f"S_col_{j}" for j in range(PARAMS_NBAR)])

        for i in range(PARAMS_N):
            writer.writerow([i] + [int(S_matrix[i, j]) for j in range(PARAMS_NBAR)])

    print(f"S matrix saved as CSV to {S_path}")


def load_S_vectors_from_sk_file(sk_path):
    if not os.path.exists(sk_path):
        print(f"[ERROR] Missing sk.bin, cannot compare S against key: {sk_path}")
        return None

    with open(sk_path, "rb") as f:
        sk = f.read()

    before_S = s_length + SEED_A_length + b_length
    S = sk[before_S: before_S + S_length]

    if len(S) != S_length:
        raise ValueError(f"S has wrong size: {len(S)} != {S_length}")

    return np.frombuffer(S, dtype="<i2").reshape(PARAMS_NBAR, PARAMS_N)


def canonical_reg(reg):
    return REG_ALIAS.get(reg.strip(), reg.strip())


def split_u32_to_i16_pair(x):
    x = int(x, 0) & 0xffffffff
    low = x & 0xffff
    high = (x >> 16) & 0xffff

    if low >= 0x8000:
        low -= 0x10000
    if high >= 0x8000:
        high -= 0x10000

    return low, high


def extract_smlad_operands(trace_csv_path):
    df = pd.read_csv(trace_csv_path)
    df.fillna("0x0", inplace=True)

    B_packed_values = []
    B_values = []
    S_values = []

    for _, row in df.iterrows():
        if str(row["instruction"]).strip().lower() != "smlad":
            continue

        ops = [x.strip() for x in str(row["operands"]).split(",")]
        if len(ops) < 4:
            continue

        b_reg = canonical_reg(ops[1])
        s_reg = canonical_reg(ops[2])

        if b_reg not in row.index or s_reg not in row.index:
            print(f"[ERROR] Missing register column. operands={ops}, b_reg={b_reg}, s_reg={s_reg}")
            continue

        b_u32 = int(row[b_reg], 0) & 0xffffffff
        b_low, b_high = split_u32_to_i16_pair(row[b_reg])
        s_low, s_high = split_u32_to_i16_pair(row[s_reg])

        B_packed_values.append(b_u32)
        B_values.extend([b_low & 0xffff, b_high & 0xffff])
        S_values.extend([s_low, s_high])

    return (
        np.array(B_packed_values, dtype=np.uint32),
        np.array(B_values, dtype=np.uint16),
        np.array(S_values, dtype=np.int16),
    )


def extract_B_from_registers_matrix_from_trace(output_dir_trim, run_index, xs_id):
    trace_path = get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id)

    B_packed, B_from_registers, S_from_registers = extract_smlad_operands(trace_path)

    expected_packed_len = (PARAMS_N * PARAMS_NBAR) // 2
    if len(B_packed) != expected_packed_len:
        print(
            f"[ERROR] B_packed length is {len(B_packed)}, expected {expected_packed_len} "
            f"for run {run_index} xs_id {xs_id}"
        )
        return None, None, S_from_registers

    expected_unpacked_len = PARAMS_N * PARAMS_NBAR
    if len(B_from_registers) != expected_unpacked_len:
        print(
            f"[ERROR] B_from_registers length is {len(B_from_registers)}, expected {expected_unpacked_len} "
            f"for run {run_index} xs_id {xs_id}"
        )
        return None, None, S_from_registers

    return (
        B_packed.reshape(PARAMS_NBAR, PARAMS_N // 2),
        B_from_registers.reshape(PARAMS_NBAR, PARAMS_N),
        S_from_registers,
    )


def save_and_check_B_from_registers_from_traces(output_dir, output_dir_trim, run_index):
    B_csv_path = get_B_csv_path(output_dir, run_index)

    if not os.path.exists(B_csv_path):
        print(f"[MISSING CSV] {B_csv_path} does not exist")
        return

    B_csv = pd.read_csv(B_csv_path)
    B_expected = B_csv[[f"B_col_{j}" for j in range(PARAMS_N)]].to_numpy(dtype=np.uint16)

    reference_B = None
    reference_B_packed = None
    matches_reference_count = 0
    total_checks = 0

    for xs_id in range(PARAMS_NBAR):
        trace_path = get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id)

        if not os.path.exists(trace_path):
            print(f"[ERROR] Trace does not exist, cannot extract raw B: {trace_path}")
            continue

        B_packed_matrix, B_matrix, _ = extract_B_from_registers_matrix_from_trace(
            output_dir_trim,
            run_index,
            xs_id,
        )

        if B_packed_matrix is None or B_matrix is None:
            continue

        if reference_B is None:
            reference_B = B_matrix
            reference_B_packed = B_packed_matrix

        for b_row in range(PARAMS_NBAR):
            B_row = B_matrix[b_row]
            B_packed_row = B_packed_matrix[b_row]

            matches_B = np.array_equal(B_row, B_expected[b_row])
            matches_reference = np.array_equal(B_row, reference_B[b_row])
            matches_packed_reference = np.array_equal(B_packed_row, reference_B_packed[b_row])

            matches_reference_count += int(matches_reference)
            total_checks += 1

            if not matches_B:
                mismatch = np.where(B_row != B_expected[b_row])
                raise StopEmulation(
                    f"[B CHECK ERROR] run={run_index} xs_id={xs_id} B_row={b_row} "
                    f"does not match B_{run_index}.csv. first mismatches={mismatch}"
                )

            if not matches_reference:
                mismatch = np.where(B_row != reference_B[b_row])
                raise StopEmulation(
                    f"[B CHECK ERROR] run={run_index} xs_id={xs_id} B_row={b_row} "
                    f"does not match xs_id=0 B. first mismatches={mismatch}"
                )

            if not matches_packed_reference:
                mismatch = np.where(B_packed_row != reference_B_packed[b_row])
                raise StopEmulation(
                    f"[B CHECK ERROR] run={run_index} xs_id={xs_id} B_row={b_row} "
                    f"packed B does not match xs_id=0 packed B. first mismatches={mismatch}"
                )

    if reference_B is None:
        print(f"[ERROR] No valid B trace data found for run {run_index}")
        return

    os.makedirs(get_B_dir(output_dir), exist_ok=True)

    B_output_path = get_B_from_registers_csv_path(output_dir, run_index)
    B_from_registers_df = pd.DataFrame(
        reference_B,
        columns=[f"B_col_{i}" for i in range(PARAMS_N)],
    )
    B_from_registers_df.insert(0, "row", range(PARAMS_NBAR))
    B_from_registers_df.to_csv(B_output_path, index=False)

    B_packed_output_path = get_B_packed_from_registers_csv_path(output_dir, run_index)
    B_packed_from_registers_df = pd.DataFrame(
        reference_B_packed,
        columns=[f"B_pair_{i}" for i in range(PARAMS_N // 2)],
    )
    B_packed_from_registers_df.insert(0, "row", range(PARAMS_NBAR))
    B_packed_from_registers_df.to_csv(B_packed_output_path, index=False)

    print(f"Saved B matrix from registers to {B_output_path}")
    print(f"Saved packed B matrix from registers to {B_packed_output_path}")
    print(
        f"[B CHECK] run={run_index}: B identical across xs traces "
        f"{matches_reference_count}/{total_checks}."
    )


def save_and_check_S_from_traces(output_dir, output_dir_trim, run_index):
    S_expected = load_S_vectors_from_sk_file(os.path.join(output_dir, "sk.bin"))

    if S_expected is None:
        return

    S_vectors = []
    matches_sk_count = 0
    matches_repeat_count = 0
    total_checks = 0

    for xs_id in range(PARAMS_NBAR):
        trace_path = get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id)

        if not os.path.exists(trace_path):
            print(f"[ERROR] Trace does not exist, cannot extract S: {trace_path}")
            continue

        _, _, S_from_registers = extract_smlad_operands(trace_path)

        if len(S_from_registers) != PARAMS_N * PARAMS_NBAR:
            print(
                f"[ERROR] S_from_registers length is {len(S_from_registers)}, expected {PARAMS_N * PARAMS_NBAR}. "
                f"Cannot split into 8 xs() calls safely."
            )
            continue

        S_rows = S_from_registers.reshape(PARAMS_NBAR, PARAMS_N)
        S_vector = S_rows[0]
        S_vectors.append((xs_id, S_vector))

        expected_vector = S_expected[xs_id]

        for row in range(PARAMS_NBAR):
            S_row = S_rows[row]
            matches_sk = np.array_equal(S_row, expected_vector)
            matches_first_row = np.array_equal(S_row, S_vector)

            matches_sk_count += int(matches_sk)
            matches_repeat_count += int(matches_first_row)
            total_checks += 1

            if not matches_sk:
                mismatch = np.where(S_row != expected_vector)[0][:5]
                raise StopEmulation(
                    f"[S CHECK ERROR] run={run_index} xs_id={xs_id} B_row={row} "
                    f"does not match S from sk. first mismatches={mismatch}"
                )

            if not matches_first_row:
                mismatch = np.where(S_row != S_vector)[0][:5]
                raise StopEmulation(
                    f"[S CHECK ERROR] run={run_index} xs_id={xs_id} B_row={row} "
                    f"does not repeat first S row. first mismatches={mismatch}"
                )

    if len(S_vectors) != PARAMS_NBAR:
        print(f"[ERROR] Only extracted {len(S_vectors)}/{PARAMS_NBAR} S vectors for run {run_index}")

    if not S_vectors:
        print(f"[ERROR] No valid S trace data found for run {run_index}")
        return

    S_by_xs = np.zeros((PARAMS_NBAR, PARAMS_N), dtype=np.int16)
    for xs_id, S_vector in S_vectors:
        S_by_xs[xs_id] = S_vector

    S_path = get_S_csv_path(output_dir, run_index)
    os.makedirs(os.path.dirname(S_path), exist_ok=True)
    S_matrix = S_by_xs.T
    S_df = pd.DataFrame(S_matrix, columns=[f"S_col_{i}" for i in range(PARAMS_NBAR)])
    S_df.insert(0, "row", range(PARAMS_N))
    S_df.to_csv(S_path, index=False)

    print(f"[S] Saved S matrix from registers to {S_path}")
    print(
        f"[S CHECK] run={run_index}: S register rows match sk {matches_sk_count}/{total_checks}; "
        f"S repeated across B rows {matches_repeat_count}/{total_checks}."
    )


def compare_B_ciphertext_vs_trace(output_dir, output_dir_trim, run_index, xs_id):
    B_csv_path = get_B_csv_path(output_dir, run_index)
    trace_path = get_truncated_trim_csv_path(output_dir_trim, run_index, xs_id)

    if not os.path.exists(B_csv_path):
        print(f"[COMPARE ERROR] Missing B CSV: {B_csv_path}")
        return

    if not os.path.exists(trace_path):
        print(f"[COMPARE ERROR] Missing trace CSV: {trace_path}")
        return

    _, B_from_registers, S_from_registers = extract_smlad_operands(trace_path)

    B_csv = pd.read_csv(B_csv_path)
    B_expected = B_csv[[f"B_col_{j}" for j in range(PARAMS_N)]].to_numpy(dtype=np.uint16)
    print("-----------------------------------------")
    print("\n B from ciphertext vs B from register:")
    print(f"run_index       = {run_index}")
    print(f"xs_id           = {xs_id}")
    print(f"B csv path      = {B_csv_path}")
    print(f"trace path      = {trace_path}")
    print(f"B_from_registers length = {len(B_from_registers)}")
    print(f"S_trace length  = {len(S_from_registers)}")

    if len(B_from_registers) > 0:
        print(f"B_from_registers first 10 = {B_from_registers[:10]}")
        print(f"B_from_registers min/max  = {B_from_registers.min()} / {B_from_registers.max()}")

    if len(B_from_registers) != PARAMS_N * PARAMS_NBAR:
        print(
            f"[ERROR] B_from_registers length is {len(B_from_registers)}, expected {PARAMS_N * PARAMS_NBAR}. "
            f"Skipping chunked B comparison."
        )
        print("-----------------------------------------\n")
        return

    B_register_matrix = B_from_registers.reshape(PARAMS_NBAR, PARAMS_N)

    for row in range(PARAMS_NBAR):
        B_expected_row = B_expected[row]
        B_register_row = B_register_matrix[row]
        direct_match = np.array_equal(B_register_row, B_expected_row)
        first_mismatch = np.where(B_register_row != B_expected_row)[0][:5]

        print(
            f"B row {row}: "
            f"B_register_match={direct_match}, "
            f"first_B_row_mismatch={first_mismatch}"
        )

    print("-----------------------------------------\n")


def save_register_operands_csv(trace_csv_path, output_dir, label):
    """Extract B packed, B unpacked and S from registers"""
    B_packed, B_unpacked, S_values = extract_smlad_operands(trace_csv_path)

    B_dir = os.path.join(output_dir, "B")
    S_dir = os.path.join(output_dir, "S")
    os.makedirs(B_dir, exist_ok=True)
    os.makedirs(S_dir, exist_ok=True)

    packed_path = os.path.join(B_dir, f"B_from_registers_packed_{label}.csv")
    unpacked_path = os.path.join(B_dir, f"B_from_registers_{label}.csv")
    S_path = os.path.join(S_dir, f"S_{label}.csv")

    one_xs_packed_len = PARAMS_NBAR * (PARAMS_N // 2)
    one_xs_unpacked_len = PARAMS_NBAR * PARAMS_N
    full_mulbs_packed_len = PARAMS_NBAR * PARAMS_NBAR * (PARAMS_N // 2)
    full_mulbs_unpacked_len = PARAMS_NBAR * PARAMS_NBAR * PARAMS_N

    if len(B_unpacked) == one_xs_unpacked_len:
        B_matrix = B_unpacked.reshape(PARAMS_NBAR, PARAMS_N)
        B_df = pd.DataFrame(B_matrix, columns=[f"B_col_{i}" for i in range(PARAMS_N)])
        B_df.insert(0, "row", range(PARAMS_NBAR))
        B_df.to_csv(unpacked_path, index=False)

        B_packed_matrix = B_packed.reshape(PARAMS_NBAR, PARAMS_N // 2)
        B_packed_df = pd.DataFrame(
            B_packed_matrix,
            columns=[f"B_pair_{i}" for i in range(PARAMS_N // 2)],
        )
        B_packed_df.insert(0, "row", range(PARAMS_NBAR))
        B_packed_df.to_csv(packed_path, index=False)

        S_matrix = S_values.reshape(PARAMS_NBAR, PARAMS_N)
        S_df = pd.DataFrame(S_matrix, columns=[f"S_col_{i}" for i in range(PARAMS_N)])
        S_df.insert(0, "row", range(PARAMS_NBAR))
        S_df.to_csv(S_path, index=False)

    elif len(B_unpacked) == full_mulbs_unpacked_len:
        B_records = []
        B_unpacked_3d = B_unpacked.reshape(PARAMS_NBAR, PARAMS_NBAR, PARAMS_N)
        for b_row in range(PARAMS_NBAR):
            for xs_id in range(PARAMS_NBAR):
                for B_col in range(PARAMS_N):
                    B_records.append({
                        "b_row": b_row,
                        "xs_id": xs_id,
                        "B_col": B_col,
                        "B": int(B_unpacked_3d[b_row, xs_id, B_col]),
                    })
        pd.DataFrame(B_records).to_csv(unpacked_path, index=False)

        B_packed_records = []
        B_packed_3d = B_packed.reshape(PARAMS_NBAR, PARAMS_NBAR, PARAMS_N // 2)
        for b_row in range(PARAMS_NBAR):
            for xs_id in range(PARAMS_NBAR):
                for B_pair in range(PARAMS_N // 2):
                    B_packed_records.append({
                        "b_row": b_row,
                        "xs_id": xs_id,
                        "B_pair": B_pair,
                        "B_packed": int(B_packed_3d[b_row, xs_id, B_pair]),
                    })
        pd.DataFrame(B_packed_records).to_csv(packed_path, index=False)

        S_records = []
        S_3d = S_values.reshape(PARAMS_NBAR, PARAMS_NBAR, PARAMS_N)
        for b_row in range(PARAMS_NBAR):
            for xs_id in range(PARAMS_NBAR):
                for S_col in range(PARAMS_N):
                    S_records.append({
                        "b_row": b_row,
                        "xs_id": xs_id,
                        "S_col": S_col,
                        "S": int(S_3d[b_row, xs_id, S_col]),
                    })
        pd.DataFrame(S_records).to_csv(S_path, index=False)

    else:
        pd.DataFrame({"B_packed": B_packed.astype(np.uint32)}).to_csv(packed_path, index=False)
        pd.DataFrame({"B_unpacked": B_unpacked.astype(np.uint16)}).to_csv(unpacked_path, index=False)
        pd.DataFrame({"S": S_values.astype(np.int16)}).to_csv(S_path, index=False)

        print(
            f"[REGISTERS] Saved flat operands for {label}; lengths were "
            f"B_packed={len(B_packed)}, B_unpacked={len(B_unpacked)}, S={len(S_values)}"
        )

    print(f"[REGISTERS] Saved packed B, unpacked B, and S operands for {label}")
