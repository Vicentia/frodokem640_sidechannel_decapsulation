import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

REG_NAMES = ['r0','r1','r2','r3','r4','r5','r6','r7',
             'r8','r9','r10','r11','r12','sp','lr']

# compute the Hamming weight of a list of register values
def hw(regs):
    total_weight = 0
    for r in regs:
        total_weight += int(r, 16).bit_count()
    return total_weight

def load_trace(path):
    df = pd.read_csv(path)
    # Compute the sum of Hamming weights across all registers for each instruction
    return df[REG_NAMES].apply(hw, axis=1).values

def cross_correlation(t0, t1):
    # Compute the normalized cross-correlation between two traces
    n = len(t0)
    return np.correlate(t0 - t0.mean(), t1 - t1.mean(), mode='full')[n-1:] / (t0.std() * t1.std() * n)

if __name__ == "__main__":
    t0 = load_trace("output_decapsulation_parallel/TRACE_1/trace_1.csv")
    t1 = load_trace("output_decapsulation_parallel/TRACE_3/trace_3.csv")
    # Difference between the hamming weight between the two traces, should be small if they are similar
    diff = np.abs(t0 - t1)
    print(f"Maximum difference in HW sum: {diff.max():.4f}")

    n = min(len(t0), len(t1))
    t0, t1 = t0[:n], t1[:n]

    corr = np.corrcoef(t0, t1)[0, 1]
    print(f"Pearson r = {corr:.4f}")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 6), sharex=True)
    ax1.plot(t0, lw=0.5, label="trace 0")
    ax1.plot(t1, lw=0.5, label="trace 2")
    ax1.set_ylabel("HW sum"); ax1.legend()

    # Compute and plot the normalized cross-correlation
    ax2.plot(cross_correlation(t0, t1), lw=0.5, color="green")
    ax2.set_ylabel("Normalized Cross-Correlation"); ax2.set_xlabel("instruction index")

    plt.tight_layout()
    plt.savefig("traces.png", dpi=150)
    plt.show()