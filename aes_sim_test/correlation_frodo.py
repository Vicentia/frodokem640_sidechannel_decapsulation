import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

REG_NAMES = ['r0','r1','r2','r3','r4','r5','r6','r7',
             'r8','r9','r10','r11','r12','sp','lr']

#compute the Hamming weight of a list of register values
def hw(regs):
    total_weight = 0
    for r in regs:
        total_weight += int(r, 16).bit_count()
    return total_weight

def load_trace(path):
    df = pd.read_csv(path)
    # Compute the sum of Hamming weights across all registers for each instruction
    return df[REG_NAMES].apply(hw, axis=1).values

if __name__ == "__main__":

    t0 = load_trace("output_decapsulation/TRACE_0/traces_0/trace_0.csv")
    t1 = load_trace("output_decapsulation/TRACE_1/traces_1/trace_1.csv")

    n = min(len(t0), len(t1))
    t0, t1 = t0[:n], t1[:n]

    corr = np.corrcoef(t0, t1)[0, 1]
    print(f"Pearson r = {corr:.4f}")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 6), sharex=True)
    ax1.plot(t0, lw=0.5, label="trace 0")
    ax1.plot(t1, lw=0.5, label="trace 1")
    ax1.set_ylabel("HW sum"); ax1.legend()
    
    # Compute and plot the normalized cross-correlation
    ax2.plot(np.correlate(t0 - t0.mean(), t1 - t1.mean(), mode='full')[n-1:] / (t0.std() * t1.std() * n), lw=0.5, color="green")
    ax2.set_ylabel("correlation"); ax2.set_xlabel("instruction index")

    plt.tight_layout()
    plt.savefig("traces.png", dpi=150)
    plt.show()