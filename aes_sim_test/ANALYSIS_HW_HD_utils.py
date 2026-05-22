import numpy as np
import pandas as pd


def HW(a):
    return a.count("1")


def HD(a, b):
    return sum(c1 != c2 for c1, c2 in zip(a, b))


def hex_to_bin32(x):
    return bin(int(x, 0))[2:].rjust(32, "0")


def hw_u32(values):
    values = np.asarray(values, dtype=np.uint32)
    return np.array([int(v).bit_count() for v in values], dtype=np.float64)


def create_HD_trace(filename, cols):
    df = pd.read_csv(filename)
    df.fillna("0x0", inplace=True)

    reg_bin = []
    for col in cols:
        reg_bin.append(df[col].apply(hex_to_bin32).tolist())

    number_instructions = len(reg_bin[0])
    hd_ref = np.zeros((number_instructions - 1, len(cols)))

    for col in range(len(cols)):
        for i in range(number_instructions - 1):
            hd_ref[i, col] = HD(reg_bin[col][i], reg_bin[col][i + 1])

    return np.sum(hd_ref, axis=1)


def create_HW_trace(filename, cols):
    """
    Read an execution trace CSV and return the summed HW of selected registers
    for each instruction.
    """
    df = pd.read_csv(filename)
    df.fillna("0x0", inplace=True)

    reg_bin = []
    for col in cols:
        reg_bin.append(df[col].apply(hex_to_bin32).tolist())

    number_instructions = len(reg_bin[0])
    hw_ref = np.zeros((number_instructions, len(cols)))

    for col in range(len(cols)):
        for i in range(number_instructions):
            hw_ref[i, col] = HW(reg_bin[col][i])

    return np.sum(hw_ref, axis=1)
