import os
import shutil

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from HW_HD_utils import create_HD_trace, create_HW_trace


def reset_folder(folder_path):
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    os.makedirs(folder_path)


def information(data):
    print(f"The shape of the data is: {data.shape}")
    print(f"The type of the data is: {data.dtype}")
    print(f"The first 2 traces are: {data[:2]}")
    print(f"If there are any NaN values: {np.isnan(data).any()}")


def compute_correlation(traces, target_variable):
    corr = []
    for i in range(0, len(traces[0])):
        if np.std(traces[:, i]) == 0 or np.std(target_variable) == 0:
            corr.append(0)
        else:
            corr.append(np.corrcoef(traces[:, i], target_variable)[0][1])
    return corr


def plot_correlation(corr_array, title, save_path=None, figsize=(20, 6), no_instructions=None):
    plt.close("all")
    plt.figure(figsize=figsize)
    plt.xlim(0, no_instructions)
 
    for label, corr in sorted(corr_array.items()):
        plt.plot(corr, label=label, alpha=0.8, linewidth=0.8)

    plt.title(title)
    plt.xlabel("Instruction index")
    plt.ylabel("Correlation")
    plt.legend()
    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def plot_hw_hd_comparison(data_HW, data_HD, title="HW and HD comparison", save_path=None, max_traces=None, figsize=(30, 10), no_instructions=None):
    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)
    plt.xlim(0, no_instructions)

    number_traces = len(data_HW)
    if max_traces is not None:
        number_traces = min(number_traces, max_traces)

    for ind in range(number_traces):
        ax1.plot(data_HW[ind], alpha=0.5)
        ax2.plot(data_HD[ind], alpha=0.5)

    ax1.set_title("HW comparison")
    ax1.set_ylabel("HW value")

    ax2.set_title("HD comparison")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("HD value")

    plt.suptitle(title)
    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def plot_hw_hd_two_traces(data_HW, data_HD, index1, index2, save_path=None, figsize=(30, 10), no_instructions=None):
    plt.close("all")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)
    plt.xlim(0, no_instructions)

    ax1.plot(data_HW[index1], alpha=0.5, label=f"HW trace_{index1}")
    ax1.plot(data_HW[index2], alpha=0.5, label=f"HW trace_{index2}")
    ax1.set_title("HW comparison")
    ax1.set_ylabel("HW value")
    ax1.legend()

    ax2.plot(data_HD[index1], alpha=0.5, label=f"HD trace_{index1}")
    ax2.plot(data_HD[index2], alpha=0.5, label=f"HD trace_{index2}")
    ax2.set_title("HD comparison")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("HD value")
    ax2.legend()

    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def plot_hw_hd_difference(data_HW, data_HD, index1, index2, save_path=None, figsize=(30, 10), no_instructions=None):
    trace1_HW = data_HW[index1]
    trace2_HW = data_HW[index2]

    trace1_HD = data_HD[index1]
    trace2_HD = data_HD[index2]

    min_hw = min(len(trace1_HW), len(trace2_HW))
    min_hd = min(len(trace1_HD), len(trace2_HD))

    diff_HW = trace1_HW[:min_hw] - trace2_HW[:min_hw]
    diff_HD = trace1_HD[:min_hd] - trace2_HD[:min_hd]

    plt.close("all")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)
    plt.xlim(0, no_instructions)
    ax1.plot(diff_HW)
    ax1.set_title(f"Point-wise HW difference: trace_{index1} - trace_{index2}")
    ax1.set_ylabel("Difference")

    ax2.plot(diff_HD)
    ax2.set_title(f"Point-wise HD difference: trace_{index1} - trace_{index2}")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("Difference")

    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def plot_variance_and_std(data_HW, data_HD, result_dir=None, no_instructions=None):
    var_hw = np.var(data_HW, axis=0)
    var_hd = np.var(data_HD, axis=0)

    std_hw = np.std(data_HW, axis=0)
    std_hd = np.std(data_HD, axis=0)

    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(30, 10), sharex=True)
    plt.xlim(0, no_instructions)

    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(30, 10), sharex=True)

    ax1.plot(var_hw)
    ax1.set_title("Variance for HW")
    ax1.set_ylabel("Variance")

    ax2.plot(var_hd)
    ax2.set_title("Variance for HD")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("Variance")

    plt.tight_layout()

    if result_dir is not None:
        plt.savefig(os.path.join(result_dir, "variance_all_traces.png"), dpi=200)

    plt.show()

    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(30, 10), sharex=True)

    ax1.plot(std_hw)
    ax1.set_title("Standard deviation for HW")
    ax1.set_ylabel("Standard deviation")

    ax2.plot(std_hd)
    ax2.set_title("Standard deviation for HD")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("Standard deviation")

    plt.tight_layout()

    if result_dir is not None:
        plt.savefig(os.path.join(result_dir, "standard_deviation_all_traces.png"), dpi=200)

    plt.show()


def cross_correlation(trace1, trace2):
    n = min(len(trace1), len(trace2))

    trace1 = trace1[:n]
    trace2 = trace2[:n]

    std1 = trace1.std()
    std2 = trace2.std()

    if std1 == 0 or std2 == 0:
        return np.zeros(n)

    return np.correlate(trace1 - trace1.mean(), trace2 - trace2.mean(), mode="full")[n - 1:] / (std1 * std2 * n)


def plot_cross_correlation_hw_hd(data_HW, data_HD, pairs, save_path=None, figsize=(30, 10), no_instructions=None):
    plt.close("all")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)
    plt.xlim(0, no_instructions)

    for i, j in pairs:
        trace1_HW = data_HW[i]
        trace2_HW = data_HW[j]

        n = min(len(trace1_HW), len(trace2_HW))
        trace1_HW = trace1_HW[:n]
        trace2_HW = trace2_HW[:n]

        corr_hw = np.corrcoef(trace1_HW, trace2_HW)[0, 1]
        print(f"Correlation HW ({i},{j}) = {corr_hw:.4f}")

        ax1.plot(cross_correlation(trace1_HW, trace2_HW), lw=0.5, label=f"{i}-{j}")

    ax1.set_title("Cross Correlation HW")
    ax1.set_ylabel("Cross-Correlation")
    ax1.set_xlabel("Instruction index")
    ax1.legend()

    for i, j in pairs:
        trace1_HD = data_HD[i]
        trace2_HD = data_HD[j]

        n = min(len(trace1_HD), len(trace2_HD))
        trace1_HD = trace1_HD[:n]
        trace2_HD = trace2_HD[:n]

        corr_hd = np.corrcoef(trace1_HD, trace2_HD)[0, 1]
        print(f"Correlation HD ({i},{j}) = {corr_hd:.4f}")

        ax2.plot(cross_correlation(trace1_HD, trace2_HD), lw=0.5, label=f"{i}-{j}")

    ax2.set_title("Cross Correlation HD")
    ax2.set_ylabel("Cross-Correlation")
    ax2.set_xlabel("Instruction index")
    ax2.legend()

    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def compute_snr(trace1, trace2):
    """
    SNR = (mu_a - mu_b)^2 / (var_a + var_b)
    """
    min_len = min(trace1.shape[1], trace2.shape[1])

    a = trace1[:, :min_len]
    b = trace2[:, :min_len]

    mu_a = np.mean(a, axis=0)
    mu_b = np.mean(b, axis=0)

    var_a = np.var(a, axis=0)
    var_b = np.var(b, axis=0)

    denom = var_a + var_b

    snr = np.zeros_like(mu_a)
    mask = denom > 0
    snr[mask] = ((mu_a - mu_b)[mask] ** 2) / denom[mask]

    return snr


def plot_snr_single(snr, title, save_path=None, no_instructions=None):
    plt.close("all")
    plt.figure(figsize=(20, 6))
    plt.plot(snr)
    plt.title(title)
    plt.xlabel("Instruction index")
    plt.ylabel("SNR")
    plt.xlim(0, no_instructions)
    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def plot_snr_combined(snr_dict, title, save_path=None, no_instructions=None):
    plt.close("all")
    plt.figure(figsize=(20, 6))

    for label, snr in sorted(snr_dict.items()):
        plt.plot(snr, label=label, alpha=0.8, linewidth=0.8)

    plt.title(title)
    plt.xlabel("Instruction index")
    plt.ylabel("SNR")
    plt.legend()
    plt.xlim(0, no_instructions)
    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def print_top3_snr_indices(snr, label):
    top3_indices = np.argsort(snr)[-3:][::-1]

    print(f"\nTop 3 SNR values for {label}:")
    for rank, idx in enumerate(top3_indices, start=1):
        print(f"{rank}. instruction index = {idx}, SNR = {snr[idx]}")


def return_instruction_type(instruction):
    instruction = str(instruction).strip().lower()
    arithmetic_instructions = {
        "adc", "add", "add.w", "adds", "mla", "mls", "mul", "sbc", "smlad",
        "smull", "sub", "sub.w", "subs", "umull",
    }

    if instruction in arithmetic_instructions:
        return "arithmetic"

    return "other"


def plot_trace_with_arithmetic(csv_path, selected_registers, result_dir=None):
    df = pd.read_csv(csv_path)
    df.fillna("0x0", inplace=True)

    df["instruction_type"] = df["instruction"].apply(return_instruction_type)

    hw_trace = create_HW_trace(csv_path, selected_registers)
    hd_trace = create_HD_trace(csv_path, selected_registers)

    arithmetic_idx_hw = df.index[df["instruction_type"] == "arithmetic"].to_numpy()
    arithmetic_idx_hd = arithmetic_idx_hw[arithmetic_idx_hw < len(hd_trace)]

    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(30, 10), sharex=True)

    ax1.plot(hw_trace, alpha=0.7, label="HW trace")
    ax1.scatter(arithmetic_idx_hw, hw_trace[arithmetic_idx_hw], s=10, label="Arithmetic instructions")
    ax1.set_title("HW Trace with Arithmetic Instructions")
    ax1.set_ylabel("HW value")
    ax1.legend()

    ax2.plot(hd_trace, alpha=0.7, label="HD trace")
    ax2.scatter(arithmetic_idx_hd, hd_trace[arithmetic_idx_hd], s=10, label="Arithmetic instructions")
    ax2.set_title("HD Trace with Arithmetic Instructions")
    ax2.set_xlabel("Instruction index")
    ax2.set_ylabel("HD value")
    ax2.legend()

    plt.tight_layout()

    if result_dir is not None:
        save_path = os.path.join(result_dir, "trace_with_arithmetic.png")
        plt.savefig(save_path, dpi=200)

    plt.show()

    return df, hw_trace, hd_trace
