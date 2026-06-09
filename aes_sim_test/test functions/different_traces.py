import pandas as pd
import numpy as np

B1 = pd.read_csv("../output_truncated_different_ciphertext_per_S/B/B_valid_0_random0.csv")
B2 = pd.read_csv("../output_truncated_different_ciphertext_per_S/B/B_valid_0_random1.csv")

# check if the values of B1 and B2 are different 
if np.array_equal(B1.values, B2.values):
    print("The values of B1 and B2 are the same.")
else:
    print("The values of B1 and B2 are different.")