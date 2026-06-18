# FrodoKEM Trace Collection

FrodoKEM-640 ([pqm3 - Round 3](https://github.com/mupq/pqm4)) decapsulation traces, captured by using STM32F4 target, [Qiling emulator](https://github.com/qilingframework/qiling) and [ChipWisperer enviorment](https://github.com/newaetech/chipwhisperer)

---

## Table of Contents

- [1. Running the Code](#1-running-the-code)
- [2. Code Explanation](#2-code-explanation)
  - [2.1 Firmware](#21-firmware)
  - [2.2 Capture Code](#22-capture-code)
  - [2.3 Code Output](#23-code-output)
    - [2.3.1 Sequential](#231-sequential)
    - [2.3.2 Parallel](#232-parallel)
    - [2.3.3 Sample](#233-sample)
    - [2.3.4 Truncated](#234-truncated)
    - [2.3.5 Truncated Empirical](#235-truncated-empirical)
- [3. Results](#3-results)
  - [3.1 Creating the Leackage Models](#31-creating-the-leackage-models)
  - [3.1 Plots](#32-plots)

---

## 1. Running the Code

### Step 1 — Build the firmware

Go to the firmware directory and build with the firmwae in the following way:

```bash
cd pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo
make PLATFORM=CW308_STM32F4
```

> **Warning:** The Makefile inside `simpleserial-frodo/` contains a hardcoded path:
> ```makefile
> PQMROOT = /Users/vicentiastroe/Documents/Thesis/FrodoKEM/pqm4-Round3
> ```
> This **must** be changed based on the actual local path

---

### Step 2 — Copy the ELF file

Copy the generated ELF file into the simulation directory:

```bash
cp <source> <destination>
```

Example:

```bash
cp Documents/Thesis/FrodoKEM/InitialVersion/pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf \
   Documents/Thesis/FrodoKEM/InitialVersion/aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf
```
> In the aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf it is already a a copy that can be used that contains just key generation and decapsulation
---

### Step 3 — Collect traces

The commands to run the files in `aes_sim_test/` are:

```bash
# Collect traces (sequential, parallel, sample. truncated or all — see Section 2.2)
make all_sequential
make all_parallel
make all_sample
make all_truncated
make all 
```

To clean up generated output:

```bash
# Clean traces (sequential, parallel, sample or all)
make clean_sequential 
make clean_parallel
make clean_sample
make clean_truncated
clean
```

---

## 2. Code Explanation

### 2.1 Firmware

**Source:** `pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/`

| File | Purpose |
|------|---------|
| `simpleserial-frodo.c` | Main firmware logic — defines what runs on the target |
| `hal_stub.c` | RNG logic used by the firmware |
| `Makefile` | Builds the ELF binary for the STM32F4 target |

The firmware is built using the FrodoKEM API from the `pqm4` repository. The instructions that are **captured** in the trace are those executed between `trigger_high` and `trigger_low`. All other instructions execute normally but are not captured in the traces. 

---

### 2.2 Capture Code

**Source:** `aes_sim_test/`

#### Scripts

| Script | Description |
|--------|-------------|
| `frodo_collect_traces_sequential.py` | Collects traces one at a time, for each fault index sequentially |
| `frodo_collect_traces_parallel.py` | Collects traces in parallel across N fault indices |
| `frodo_collect_traces_sample.py` | Collects multiple independent runs across a fixed set of fault indices |
| `frodo_collect_traces_truncated.py` | Collects subtraces for different ciphertexts |
| `frodo_collect_traces_truncated_empirical.py` | Collects subtraces for different ciphertexts and different keys |
| `[TRACE] FrodoKEM-640.ipynb` | Notebook that collects all the modes and the number of the traces ir the default indices can be changed|


All scripts (other than the sequantial one that does not use a snapshot because it is not needed) follow the same two-phase flow:
1. **Snapshot phase** — runs key generation (`crypto_kem_keypair`) and stops at the entry of `crypto_kem_dec`, saving the emulator state (registers + memory) to `snapshot.pkl`, along with the public key, secret key and matrix S (that is encouded in sk) as a csv file in the matrix shape (640 by 8). It also runs the encapsulation that creates a valid ciphertext that is different for every run. It saved this ciphertext as `ct_valid_<i>`, were i is the index of the run.
2. **Decapsulation phase** — restores the snapshot, writes a (possibly modified or valid) ciphertext into the emulator's memory, and records the instruction + register trace between `trigger_high` and `trigger_low`. If the mode of the ciphertext is valid, then it does not overwrite the addres of the ciphertext that has been obtained for encapsulation. If the mode is modified, then it rewrites it by using `ct_base_<i>` where i is the index. 

---

#### Makefile Configuration

The `Makefile` in `aes_sim_test/` controls all three collection modes. Key variables:

```makefile
PYTHON            = python3
SCRIPT_SEQUENTIAL = frodo_collect_traces_sequential.py
SCRIPT_PARALLEL   = frodo_collect_traces_parallel.py
SCRIPT_SAMPLE     = frodo_collect_traces_sample.py
ELF_FILE     	    = firmware/simpleserial-frodo-CW308_STM32F4.elf
```

**Sequential mode** — runs `N` traces one at a time:

```makefile
N                        = 2
OUTPUT_DIR_SEQUENTIAL    = output_decapsulation_sequential
OUTPUT_DIR_SEQUENTIAL_TRIM = output_decapsulation_sequential_TRIM
```

**Parallel mode** — runs up to `N_PARALLEL` fault indices using `JOBS_PARALLEL` worker processes:

```makefile
N_PARALLEL               = 641
JOBS_PARALLEL            = 10
OUTPUT_DIR_PARALLEL      = output_decapsulation_parallel
OUTPUT_DIR_PARALLEL_TRIM = output_decapsulation_parallel_TRIM
```

**Sample mode** — runs `NUM_RUNS` independent experiments, each over a fixed list of fault indices, using `JOBS_SAMPLE` workers:

```makefile
NUM_RUNS               = 5
FAULT_INDICES          = 0 1 2 4 8 16 32 64 128 256 512
JOBS_SAMPLE            = 4
OUTPUT_DIR_SAMPLE      = output_decapsulation_sample
OUTPUT_DIR_SAMPLE_TRIM = output_decapsulation_sample_TRIM
```

**Truncated mode** — runs `NUM_RUNS` independent experiments, each over random ciphertexts, using `JOBS_SAMPLE` workers:

```makefile
NUM_RUNS_TRUNCATED        = 80 
FAULT_INDICES_TRUNCATED   = 0
JOBS_TRUNCATED            = 10
OUTPUT_DIR_TRUNCATED      = output_decapsulation_truncated
OUTPUT_DIR_TRUNCATED_TRIM = output_decapsulation_truncated_TRIM
```

**Truncated Empirical mode** — runs `NUM_RUNS` independent experiments, each over random ciphertexts, using `JOBS_SAMPLE` workers:

```makefile
NUM_RUNS_TRUNCATED_EMPIRICAL        = 4
NUM_RANDOM_CIPHERTEXTS_TRUNCATED_EMPIRICAL = 80
FAULT_INDICES_TRUNCATED_EMPIRICAL   = $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range(0, 321, 2)))")
JOBS_TRUNCATED_EMPIRICAL            = 10
OUTPUT_DIR_TRUNCATED_EMPIRICAL      = output_decapsulation_empirical
OUTPUT_DIR_TRUNCATED_EMPIRICAL_TRIM = output_decapsulation_empirical_TRIM
```
**Notebook - [TRACE] FrodoKEM-640.ipynb** - everything can be changed from the notebook and it is easier to run and see the live results instead of the terminal
> Each fault index controls how many columns of the C_1 component of the FrodoKEM ciphertext are zeroed out before decapsulation.

> **Warning:** The number of traces, the number of jobs, the fault indicies or the outputfiles should all be changed in the Makefile. 

---

#### Makefile Targets

| Target | Description |
|--------|-------------|
| `make sequential` | Runs `N` sequential traces and it generates one valid ciphertext|
| `make snapshot_parallel` | Runs keygen, saves snapshot for parallel mode and it generates one valid ciphertext |
| `make decap_parallel` | Runs `N_PARALLEL` decapsulations in parallel (requires snapshot) and also the decapsulation for the valid ciphertext |
| `make parallel` | Runs `snapshot_parallel` then `decap_parallel` |
| `make snapshot_sample` | Runs keygen, saves snapshot for sample mode and generates one valid ciphertext per run|
| `make decap_sample` | Runs all sample traces (requires snapshot) and also the decapsulation for the valid ciphertext|
| `make snapshot_truncated` | Runs keygen, saves snapshot for truncated mode and generates one valid ciphertext per run |
| `make decap_truncated` | Runs all truncated traces (requires snapshot) and also the decapsulation for the valid ciphertext|
| `make truncated` | Runs `snapshot_sample` then `decap_sample` |
| `make snapshot_truncated_empirical` | Runs more keygen, saves snapshot for truncated mode and generates for each key, more ciphertexts|
| `make decap_truncated_empirical` | Runs all truncated traces (requires snapshot and ciphertexts) and also the decapsulation for the valid ciphertext|
| `make truncated_empirical` | Runs `snapshot_sample` then `decap_sample` |
| `make all` | Runs `all_sequential` `all_parallel` `all_sample` |
| `make clean_sequential` | Deletes sequential output directories |
| `make clean_parallel` | Deletes parallel output directories |
| `make clean_sample` | Deletes sample output directories |
| `make clean ` | Deletes all output directories |

> The snapshot and decapsulation steps are separated so you can regenerate traces without re-running the key generation that takes a lot (around 30 minutes)
### 2.3 Code Output 

#### 2.3.1 Sequential
> Trim version = version without "pc", "instruction", "operands" (just value from registers)
Traces are collected one by one, iterating over fault indices `0` through `N-1`. Each trace folder corresponds to a ciphertext where the first `i` columns of the B' have been zeroed out.
 
```
output_decapsulation_sequential/
|-- B/ #folder for all B' extracted/created from ciphertext
    |-- B_<i> / B_valid # value of B' / B'_valid where i is the index of the fault index
    |--B_from_register_<i> / B_valid_from_registers # value of B'/B'_valid extracted from the smlad instruction for fault index i 
    |--B_from_registers_packed_<i> / B_valid_from_registers_packed # value of B'/B'_valid packed extracted from the registers where one values has 32bits and it encodes 2 values of 16 bits, e.g b_0_packed= b_1 || b_0
|-- S / # folder for saving S
    |-- S_<i> # S extracted from smlad instruction where i is the index of the ciphertext
    |-- S_valid_<i> # S extracted from smald insstructions for the valid cipherext
    |-- S.csv # S extracted from sk
|-- ct_base.bin # Base ciphertext from where ct_modified_<i> will be derived 
|-- ct_modified_<i>.bin # Modified ciphertext with first i columns zeroed
|-- output_decapsulation_trace_i.txt # Log of executed instructions and addresses hit during key generation and decapsulation
|-- trace_i.csv # Captured power trace (first i index modified)
|-- pk.bin # Public key saved after key generation
|-- sk.bin # Private key saved after key generation
```
 
A trimmed version of each trace is saved to `output_decapsulation_sequential_TRIM/`.
 
---
 
#### 2.3.2 Parallel 
 
A single keygen is performed first and saved as a snapshot, then `N_PARALLEL` decapsulations are generated. All traces share the same base ciphertext and keypair that are in the main directory as: 
 
```
output_decapsulation_parallel/
|-- B/ #folder for all B' extracted/created from ciphertext
    |-- B_<i> / B_valid # value of B' / B'_valid where i is the index of the fault index
    |--B_from_register_<i> / B_valid_from_registers # value of B'/B'_valid extracted from the smlad instruction for fault index i 
    |--B_from_registers_packed_<i> / B_valid_from_registers_packed # value of B'/B'_valid packed extracted from the registers where one values has 32bits and it encodes 2 values of 16 bits, e.g b_0_packed= b_1 || b_0
|-- S / # folder for saving S
    |-- S_<i> # S extracted from smlad instruction where i is the index of the ciphertext
    |-- S_valid_<i> # S extracted from smald insstructions for the valid cipherext
    |-- S.csv # S extracted from sk
|-- ct_base.bin # Base ciphertext used for all fault injections
|-- ct_modified_i.bin # Ciphertext with first i columns modified
|-- ct_valid.bin # Valid ciphertext 
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication in the decapsulation phase
|-- snapshot.pkl # snapshotwith keygen until multiplication that is saved on the disk
|-- pk.bin # Public key saved after key generation
|-- sk.bin # Private key saved after key generation
|-- trace_<j>.csv # Trace for fault index j
|-- trace_valid_0.csv # Trace for valid ciphertext 
```
 
A trimmed version of each trace is saved to `output_decapsulation_parallel_TRIM/`.
 
---
 
#### 2.3.3 Sample
 
Similar to the parallel version, but traces are collected for a set of fault indicies nd more runs a perform. When a run is perform, a new random ciphertext is generated and the same fault indices are changed for the current ciphertext.
 
```
output_decapsulation_sample/
|-- B/ #folder for all B' extracted/created from ciphertext
    |-- B_<i> / B_valid_<i> # value of B' / B'_valid where i is the index of the fault index
    |--B_from_register_<i>_<j> / B_valid_from_registers # value of B'/B'_valid extracted from the smlad instruction for fault index i, j is the index fault  
    |--B_from_registers_packed_<i>_<j> / B_valid_from_registers_packed # value of B'/B'_valid packed extracted from the registers where one values has 32bits and it encodes 2 values of 16 bits, e.g b_0_packed= b_1 || b_0
|-- S / # folder for saving S
    |-- S_<i> # S extracted from smlad instruction where i is the index of the ciphertext
    |-- S_valid_<i> # S extracted from smald insstructions for the valid cipherext
    |-- S.csv # S extracted from sk
|-- ct_base_<i> # Base ciphertext used for fault injections where i is the run index
|-- ct_modified_<i>_<j>.bin # Modified ciphertext where i represents the run index and j represent the fault index
|-- ct_valid_<i> # Valid ciphertext for run i
|-- pk_<i>.bin # Public key for run i
|-- sk_<i>.bin # Secret key for run i 
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication
|-- snapshot_<i>.pkl # snapshotwith keygen until multiplication that is saved on the disk with run i
|-- trace_<i>_<j> # trace for cipheretxt at run i with fault index j
|-- trace_valid_<i> # trace for valid ciphertext for run i 


```
 
Fault indices are configured via `FAULT_INDICES` (foe example `0 1 2 4 8 16 32 64 128 256 512`). A trimmed version of each trace is saved to `output_decapsulation_sample_TRIM/`.
 
---
 
#### 2.3.4 Truncated 
 
This mode aims to capture every dot product. In FrodoKEM's decapsulation, the matrix multiplication **B' x S** is done by multiplying one row of B with a columns of S. When this is done, the columns index of S is increased and the same row of B' is multiplied with the new columns of S. Because of that, there are 8 dot products execited for each row of B', creating a 8 x 8 matrix. 
 
```
output_decapsulation_truncated/
output_decapsulation_sample/
|-- B/ #folder for all B' extracted/created from ciphertext
    |--B_base_<i> / B_valid_<i> # value of B' / B'_valid where i is the index of the run
    |--B_from_register_<i>_<j> / B_valid_from_registers # value of B'/B'_valid extracted from the smlad instruction for fault index i, j is the index fault  
    |--B_from_registers_packed_<i>_<j> / B_valid_from_registers_packed # value of B'/B'_valid packed extracted from the registers where one values has 32bits and it encodes 2 values of 16 bits, e.g b_0_packed= b_1 || b_0, j is the index fault  
    |--B_<i>_<j> # B' where i is the run index and j is the fault indices .
    |--B_from_register_<i>_<j> # B' for run i and fault index j 
|-- S / # folder for saving S
    |-- S_<i>_<j>. # S extracted from smlad instruction where i is the running index and j is the fault index. j does not change the value of S 
    |-- S_valid_<i> # S extracted from smald insstructions for the valid cipherext
    |-- S.csv # S extracted from sk
|-- ct_base_<i> # Base ciphertext used for fault injections where i is the run index
|-- ct_modified_<i>_<j>.bin # Modified ciphertext where i represents the run index and j represent the fault index
|-- ct_valid_<i> # Valid ciphertext for run i
|-- pk_<i>.bin # Public key for run i
|-- sk_<i>.bin # Secret key for run i 
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication
|-- snapshot.pkl # snapshotwith keygen until multiplication that is saved on the disk
|-- trace_<i>_<k>_<j> # trace for cipheretxt at run i with, targeting the k xs() dot products for ciphertext with fault index j
|-- trace_valid_<i>_<k> # trace for valid ciphertext for run i, targeting the l xs() dot product 
```
A trimmed version of each trace is saved to `output_decapsulation_truncated_TRIM/`.
 
---
#### 2.3.5 Truncated Empirical
 
This mode does exaclty the same as `Truncate mode`, but it creates different keys and it runs more valid ciphertexts and modified ciphertexts per key.  
```
output_decapsulation_truncated/
output_decapsulation_sample/
|-- B/ #folder for all B' extracted/created from ciphertext
    |--B_base_<i>_random<k>/ B_valid_<i>_random<k> # value of B' / B'_valid where i is the index of the run, and k is the index of the unique ciphertext for the run that used the keys at index i 
    |--B_from_register_<i>_<j> / B_valid_from_registers # value of B'/B'_valid extracted from the smlad instruction for fault index i 
    |--B_from_registers_packed_<i> / B_valid_from_registers_packed # value of B'/B'_valid packed extracted from the registers where one values has 32bits and it encodes 2 values of 16 bits, e.g b_0_packed= b_1 || b_0
    |--B_<i>_<j>_random<k> # B' where i is the run index and j is the fault indices, k is the randomly generated ciphertext with the keys at index i 
    |--B_from_register_<i>_<j>_<k> # B' for run i and fault index j, k is the randomly generated ciphertext with the keys at index i
|-- S / # folder for saving S
    |-- S_<i>_<j>_random<k> # S extracted from smlad instruction where i is the running index and j is the fault index. j does not change the value of S, k should not change the value 
    |-- S_valid_<i>_random<k> # S extracted from smald insstructions for the valid cipherext,  k should not change the value 
|-- ct_base_<i>_random<k> # Base ciphertext used for fault injections where i is the run index
|-- ct_modified_<i>_<j>_random<k> .bin # Modified ciphertext where i represents the run index and j represent the fault index, k is the index of the unique ciphertext for the run that used the keys at index i 
|-- ct_valid_<i>_random<k> # Valid ciphertext for run i, k is the index of the unique ciphertext for the run that used the keys at index i 
|-- pk_<i>.bin # Public key for run i
|-- sk_<i>.bin # Secret key for run i 
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication
|-- snapshot_<i>.pkl # snapshotwith keygen until multiplication that is saved on the disk where i is the index of the pairs 
|-- trace_<i>_<k>_<j>_random<l>  # trace for cipheretxt at run i with, targeting the k xs() dot products for ciphertext with fault index j, l is the index of the unique ciphertext for the run that used the keys at index i 
|-- trace_valid_<i>_<k>_random<k>  # trace for valid ciphertext for run i, targeting the k xs() dot product, l is the index of the unique ciphertext for the run that used the keys at index i 
```
A trimmed version of each trace is saved to `output_decapsulation_truncated_empirical_TRIM/`.
 
---
 
## 3. Results 

### 3.1 Creating the Leackage Models 

**Source:** `create_simulation_traces.ipynb` 

This notebook loads the collected execution traces, converts them into simulated power traces using leakage models (HW or HD), and runs a analysis on them. 

The output files are

| File | Description |
|---|---|
| `Results_decapsulation_parallel/RESULTS_HW.npy` | All HW traces in one array |
| `Results_decapsulation_parallel/RESULTS_HD.npy` | All HD traces in one array|
| `Results_decapsulation_sample/HW_trace_<j>.npy` | HW traces grouped by fault index `j` (sample mode) |
| `Results_decapsulation_sample/HD_trace_<j>.npy` | HD traces grouped by fault index `j` (sample mode) |
| `Results_decapsulation_truncated/HW_SUBTRACE_xs<j>.npy` | HW traces grouped by dot product index `j` (truncated mode) |
| `Results_decapsulation_truncated/HD_SUBTRACE_xs<j>.npy` | HD traces grouped by dot product index `j` (truncated mode) |

---

### 3.2 Plots

All plots are saved to the relevant results directory (e.g. `Results_decapsulation_parallel/`).

| Output file | What it shows |
|---|---|
| `traces_plot.png` | A plot with all the traces |
| `variance_all_traces.png` | Variance for all the traces|
| `standard_deviation_all_traces.png` | Standard deviation for all traces|
| `hw_and_hd_traces_comparison.png` | HW and HD between 2 selected traces |
| `pointwise_difference.png` | Point-wise difference between 2 traces |
| `correlation_between_<i>_<j>.png` | Cross-correlation between trace_i and trace_j |
| `correlation_between_pairs.png` | Cross-correlation between more pairs of 2 traces on top of each other to see the difference |
| `snr_HW_combined.png` | All HW SNR for multiple indices |
| `snr_HD_combined.png` | All HD SNR for multiple indices  |
| `trace_with_arithmetic.png` | HW and HD with points when an arithmetic operation is hit |
| `S_heatmaps_{run_index}.png` | Heatmaps of multiple S |
| `heatmap_valid_per_S_Run_{run_index}.png` | The rank heatmaps for valid ciphertext for more S |
| `heatmap_modified_for_S_{run_index}.png` | The rank heatmaps for modified ciphertext for more S |
| `S_success_rates.png` | The succes rate for guessing S |
| `heatmap_rank_altered_ciphertext.png` | The rank heatmaps for an altered attack without context check|
| `heatmap_rank_valid_ciphertext.png` | The rank heatmaps for a valid attack without trashold |
| `heatmap_valid_progressive_retry.png"` | The rank heatmaps for a valid attack with trashold |
| `heatmap_rank_combine.png` | The rank heatmaps for a combined attack with no HW |
| `heatmap_rank_combine_same_hw.png` | The rank heatmaps for a combined attack with HW |


**Modes** - there are 5 modes for analysis: sequantial, parallel, sample, truncated, truncated empirical (valid vs altered notebook) and each of them have their dedicated notebook


| Notebook name | What it shows |
|---|---|
| `[ANALYSIS] arithmetic_analysis.ipynb` | Plots points for every arithmetic instruction |
| `[ANALYSIS] parallel_analysis.ipynb` | Plots the HW, HD comparison between parallel traces|
| `[ANALYSIS] sample_analysis.ipynb` | Plots the HW, HD comparison between sample traces |
| `[ANALYSIS] sequential_analysis.ipynb` | Plots the HW, HD comparison between sequantial traces |
| `[ANALYSIS] truncated_analysis.ipynb` | Plots the HW, HD comparison between parallel traces and computes correlation between the traces and the value |
| `[ANALYSIS] valid_vs_altered.ipynb` | Guesses S an computes the heatmaps based on more attacks |

**[ANALYSIS] truncated_analysis.ipynb** - Creates correlation between the target value and the actual value for the columns of B' and for S. Based on the correlation, it takes S from an interval.

E.g if the correlation for value=3 is 1, S-guessed=3. If actual value of S=3, then rank=1. 

E.g if the correlation for value=2 is 1 and the correlation for value =3 is 0.8 and there is no other value with a correlation bigger than value=3, S_guessed=2. If actual value of S=3, then rank=2. 

**[ANALYSIS] valid_vs_altered.ipynb** - based on the correlation it guesses S and it computes the difference between multiple attacks


