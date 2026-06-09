import os
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.colors import LogNorm
from ANALYSIS_HW_HD_utils import create_HD_trace, create_HW_trace


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


def plot_correlation(corr_array,title,save_path=None, figsize=(20, 6), no_instructions=None, style="line", marker_size=None):

    plt.close("all")
    plt.figure(figsize=figsize)
    plt.xlim(0, no_instructions)
 
    for label, corr in sorted(corr_array.items()):
        x = np.arange(len(corr))
        if style == "line":
            plt.plot(x, corr, label=label, alpha=0.75, linewidth=0.8)
        elif style == "points":
            plt.scatter(x, corr, label=label, alpha=0.75, s=marker_size)

    plt.title(title)
    plt.xlabel("Instruction index")
    plt.ylabel("Correlation")
    plt.legend()
    plt.tight_layout()

    if save_path is not None:
        plt.savefig(save_path, dpi=200)

    plt.show()


def green_red_map(higher_is_better=True):
    colors = ["#f60808", "#ffcc00", "#0b8309"] if higher_is_better else ["#0b8309", "#ffcc00", "#f60808"]
    map = LinearSegmentedColormap.from_list("green_red_score", colors)
    map.set_bad("#cfcfcf")
    return map


def plot_heatmap(values_df, title, save_path, x_label="pair index / fault index", y_label="xs_id", colorbar_label="value", higher_is_better=True, vmin=None, vmax=None, annotate=False, annotation_format="{:.0%}", show_row_success=False, success_value=1, x_tick_labels=None, y_tick_labels=None, summary_label="Value summary"):
    values_df = values_df.astype(float)
    values_matrix = values_df.to_numpy()
    masked_values = np.ma.masked_invalid(values_matrix)

    no_columns = values_matrix.shape[1]
    fig_width = max(14, no_columns / 6)
    plt.close("all")
    fig, ax = plt.subplots(figsize=(fig_width, 4.5))

    if vmin is None:
        vmin = np.nanmin(values_matrix)
    if vmax is None:
        vmax = np.nanmax(values_matrix)
    if not np.isfinite(vmin):
        vmin = 0
    if not np.isfinite(vmax):
        vmax = 1
    if vmin == vmax:
        vmax = vmin + 1

    im = ax.imshow(masked_values, aspect="auto", interpolation="nearest", map=green_red_map(higher_is_better=higher_is_better),
        vmin=vmin,
        vmax=vmax,
    )

    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_yticks(np.arange(values_df.shape[0]))
    ax.set_yticklabels(values_df.index.astype(str) if y_tick_labels is None else y_tick_labels)

    tick_step = max(1, no_columns // 20)
    x_ticks = np.arange(0, no_columns, tick_step)
    if x_tick_labels is None:
        x_tick_labels = [f"{pair_idx}\n{2 * pair_idx}" for pair_idx in x_ticks]
    else:
        x_tick_labels = [x_tick_labels[i] for i in x_ticks]
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_tick_labels, rotation=0)

    if annotate:
        for y in range(values_df.shape[0]):
            for x in range(values_df.shape[1]):
                value = values_matrix[y, x]
                if np.isfinite(value):
                    ax.text(x, y, annotation_format.format(value), ha="center", va="center", color="black", fontsize=8)

    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label(colorbar_label)

    if show_row_success:
        success_by_row = np.nanmean(values_matrix == success_value, axis=1)
        for row_idx, success_rate in enumerate(success_by_row):
            ax.text(no_columns + 1, row_idx, f"{success_rate:.0%}", va="center", fontsize=9)
        ax.text(no_columns + 1, -0.8, "correct", fontsize=9)

    fig.tight_layout()
    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.show()

    print(f"Saved heatmap to {save_path}")
    print(summary_label + ":")
    print(pd.Series(values_matrix.flatten()).dropna().describe())

    return save_path


def plot_rank_heatmap(rank_df, title, save_path, x_label="pair index / fault index", show_success=True):
    """
    Plot a rank matrix as a heatmap. Rows are xs_id values and columns are S-pair indices 
    """
    rank_df = rank_df.astype(float)
    vmax = np.nanmax(rank_df.to_numpy())
    if not np.isfinite(vmax) or vmax < 1:
        vmax = 1
    return plot_heatmap(
        rank_df,
        title=title,
        save_path=save_path,
        x_label=x_label,
        colorbar_label="rank (1 = best)",
        higher_is_better=False,
        vmin=1,
        vmax=max(2, vmax),
        show_row_success=show_success,
        success_value=1,
        summary_label="Rank summary",
    )


def plot_correctness_heatmap_from_details(
    details_df,
    title,
    save_path,
    x_label="pair index / fault index",
    pair_indices=None,
):
    """
    Plot correctness: green means correct, red means incorrect, grey means not analysed.
    """
    required_columns = {"xs_id", "pair_idx", "is_correct"}
    missing_columns = required_columns - set(details_df.columns)
    if missing_columns:
        raise ValueError(f"Details dataframe is missing columns {sorted(missing_columns)}")

    correctness_df = (
        details_df
        .assign(correctness=lambda df: np.where(df["is_correct"], 1, 0))
        .pivot_table(
            index="xs_id",
            columns="pair_idx",
            values="correctness",
            aggfunc="last",
        )
        .sort_index()
    )
    if pair_indices is not None:
        correctness_df = correctness_df.reindex(columns=list(pair_indices))
    correctness_df.columns = [
        f"S_pair_{int(pair_idx)}" for pair_idx in correctness_df.columns
    ]

    return plot_heatmap(
        correctness_df,
        title=title,
        save_path=save_path,
        x_label=x_label,
        colorbar_label="correctness (1 = correct)",
        higher_is_better=True,
        vmin=0,
        vmax=1,
        show_row_success=True,
        success_value=1,
        summary_label="Correctness summary",
    )


def plot_per_run_correctness_heatmaps(
    detail_paths,
    result_dir,
    title_template="Heatmap for S_{run_index}",
    filename_template="heatmap_for_S_{run_index}.png",
    run_pattern=r"S_pair_Run_(\d+)\.csv$",
    x_label="pair index / fault index",
):
    """
    Load per-run details CSVs and save one correctness heatmap for each run.
    """
    import re

    detail_paths = sorted(Path(path) for path in detail_paths)
    if not detail_paths:
        raise FileNotFoundError("No per-run details CSV files found")

    result_dir = Path(result_dir)
    saved_paths = []

    for details_path in detail_paths:
        run_details_df = pd.read_csv(details_path)

        if "run_index" in run_details_df.columns and not run_details_df.empty:
            run_index = int(run_details_df["run_index"].iloc[0])
        else:
            match = re.search(run_pattern, details_path.name)
            if match is None:
                raise ValueError(f"Could not infer run index from {details_path}")
            run_index = int(match.group(1))

        saved_paths.append(plot_correctness_heatmap_from_details(
            run_details_df,
            title=title_template.format(run_index=run_index),
            save_path=result_dir / filename_template.format(run_index=run_index),
            x_label=x_label,
        ))

    return saved_paths


def plot_success_by_pair_count(
    summary_df,
    result_dir,
    pair_counts,
    trace_count_column="trace_count",
    pair_count_column="pair_count",
    success_column="success_rate",
    mode_column="mode",
):
    saved_paths = []
    result_dir = Path(result_dir)

    for trace_count in sorted(summary_df[trace_count_column].unique()):
        subset = summary_df[summary_df[trace_count_column] == trace_count]
        plt.close("all")
        plt.figure(figsize=(10, 6))

        for mode, mode_df in subset.groupby(mode_column):
            mode_df = mode_df.sort_values(pair_count_column)
            plt.plot(
                mode_df[pair_count_column],
                mode_df[success_column] * 100,
                marker="o",
                linewidth=2,
                label=mode,
            )

        plt.xscale("log", base=2)
        plt.xticks(pair_counts, pair_counts)
        plt.ylim(0, 105)
        plt.xlabel("Number of packed S-pair guesses")
        plt.ylabel("Success rate (%)")
        plt.title(f"Valid vs altered DPA success rate, {trace_count} traces")
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()

        save_path = result_dir / f"success_rate_by_pair_count_{trace_count}_traces.png"
        plt.savefig(save_path, dpi=200)
        plt.show()
        print(f"Saved {save_path}")
        saved_paths.append(save_path)

    return saved_paths


def plot_success_heatmaps(
    summary_df,
    result_dir,
    trace_count_column="trace_count",
    pair_count_column="pair_count",
    success_column="success_rate",
    mode_column="mode",
):
    saved_paths = []
    result_dir = Path(result_dir)

    for mode, mode_df in summary_df.groupby(mode_column):
        heatmap_df = mode_df.pivot_table(
            index=trace_count_column,
            columns=pair_count_column,
            values=success_column,
            aggfunc="mean",
        ).sort_index()

        save_path = result_dir / f"success_rate_heatmap_{mode}.png"
        plot_heatmap(
            heatmap_df,
            title=f"{mode.capitalize()} DPA success rate",
            save_path=save_path,
            x_label="Number of packed S-pair guesses",
            y_label="Number of traces",
            colorbar_label="Success rate",
            higher_is_better=True,
            vmin=0,
            vmax=1,
            annotate=True,
            annotation_format="{:.0%}",
            x_tick_labels=[str(col) for col in heatmap_df.columns],
            y_tick_labels=[str(idx) for idx in heatmap_df.index],
            summary_label="Success-rate summary",
        )
        saved_paths.append(save_path)

    return saved_paths


def plot_secret_pair_abs_heatmap(S_matrix, title, save_path, pair_indices=None, x_label="pair index / fault index"):
    """
    Plot max(abs(S0), abs(S1)) using the shared green-to-red heatmap scale.
    """
    S_matrix = np.asarray(S_matrix)
    no_pairs_total = S_matrix.shape[0] // 2
    pair_values = np.full((S_matrix.shape[1], no_pairs_total), np.nan, dtype=float)

    selected_pairs = range(no_pairs_total) if pair_indices is None else pair_indices
    for pair_idx in selected_pairs:
        b_col = 2 * int(pair_idx)
        if b_col + 1 >= S_matrix.shape[0]:
            continue
        pair_values[:, int(pair_idx)] = np.maximum(
            np.abs(S_matrix[b_col, :]),
            np.abs(S_matrix[b_col + 1, :]),
        )

    pair_values_df = pd.DataFrame(
        pair_values,
        index=[str(i) for i in range(S_matrix.shape[1])],
        columns=[f"S_pair_{pair_idx}" for pair_idx in range(no_pairs_total)],
    )
    return plot_heatmap(
        pair_values_df,
        title=title,
        save_path=save_path,
        x_label=x_label,
        colorbar_label="max(|S0|, |S1|), grey = not guessed",
        higher_is_better=False,
        vmin=0,
        vmax=10,
        summary_label="Secret-pair absolute-value summary",
    )


def plot_single_S_grid_summary(
    summary_df,
    save_path,
    attack_column="attack",
    trace_count_column="trace_count",
    pair_count_column="pair_count",
    success_column="success_rate",
):
    if pair_count_column not in summary_df.columns and "fault_limit" in summary_df.columns:
        summary_df = summary_df.copy()
        summary_df[pair_count_column] = summary_df["fault_limit"] // 2

    attacks = list(summary_df[attack_column].drop_duplicates())
    fig, axes = plt.subplots(1, len(attacks), figsize=(6 * len(attacks), 4.5), sharey=True)
    if len(attacks) == 1:
        axes = [axes]

    for ax, attack in zip(axes, attacks):
        attack_df = summary_df[summary_df[attack_column] == attack]
        grid_df = (
            attack_df
            .pivot(index=trace_count_column, columns=pair_count_column, values=success_column)
            .sort_index()
            .sort_index(axis=1)
        )
        masked_values = np.ma.masked_invalid(grid_df.to_numpy(dtype=float))
        im = ax.imshow(masked_values, aspect="auto", interpolation="nearest", vmin=0, vmax=1, map=green_red_map(higher_is_better=True))
        ax.set_title(attack)
        ax.set_xlabel("number of guessed pairs")
        ax.set_ylabel("traces")
        ax.set_xticks(np.arange(len(grid_df.columns)))
        ax.set_xticklabels([str(col) for col in grid_df.columns])
        ax.set_yticks(np.arange(len(grid_df.index)))
        ax.set_yticklabels([str(idx) for idx in grid_df.index])

        for y, trace_count in enumerate(grid_df.index):
            for x, pair_count in enumerate(grid_df.columns):
                value = grid_df.loc[trace_count, pair_count]
                if pd.notna(value):
                    ax.text(x, y, f"{value:.0%}", ha="center", va="center", color="black", fontsize=8)

    cbar = fig.colorbar(im, ax=axes, fraction=0.03, pad=0.02)
    cbar.set_label("success rate")
    fig.tight_layout()
    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.show()
    print(f"Saved single-S grid plot to {save_path}")
    return save_path


def plot_single_S_secret_heatmaps( S_matrix, result_dir, fault_limits, title_template="S heatmap for fault indices < {fault_limit}", filename_template="S_heatmap_fault_limit_{fault_limit}.png"):
    result_dir = Path(result_dir)
    paths = []

    for fault_limit in fault_limits:
        pair_indices = list(range(len(range(0, int(fault_limit), 2))))
        paths.append(plot_secret_pair_abs_heatmap(
            S_matrix,
            title=title_template.format(fault_limit=fault_limit),
            save_path=result_dir / filename_template.format(fault_limit=fault_limit),
            pair_indices=pair_indices,
            x_label="pair index / fault index",
        ))

    return paths


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


def plot_trace_with_arithmetic(csv_path, selected_registers, result_dir=None, no_instructions=None):
    df = pd.read_csv(csv_path)
    df.fillna("0x0", inplace=True)

    df["instruction_type"] = df["instruction"].apply(return_instruction_type)

    hw_trace = create_HW_trace(csv_path, selected_registers)
    hd_trace = create_HD_trace(csv_path, selected_registers)

    arithmetic_idx_hw = df.index[df["instruction_type"] == "arithmetic"].to_numpy()
    arithmetic_idx_hd = arithmetic_idx_hw[arithmetic_idx_hw < len(hd_trace)]

    plt.close("all")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(30, 10), sharex=True)
    plt.xlim(0, no_instructions)

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
