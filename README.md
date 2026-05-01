# FrodoKEM Trace Collection

A simulation-based side-channel trace collection framework for FrodoKEM-640 decapsulation, running on an emulated STM32F4 target using [Qiling](https://github.com/qilingframework/qiling) and the [ChipWisperer enviorment](https://github.com/newaetech/chipwhisperer)

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
- [3. Results](#3-results)

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
cp /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf \
   /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf
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
clean_parallel
clean_sample
clean_truncated
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
| `frodo_collect_traces_truncated.py` | Collects subtraces for 80 different ciphertexts |


All scripts (other than the sequantial one that does not use a snapshot because it is not needed) follow the same two-phase flow:
1. **Snapshot phase** — runs key generation (`crypto_kem_keypair`) and stops at the entry of `crypto_kem_dec`, saving the emulator state (registers + memory) to `snapshot.pkl`, along with the public key and secret key.
2. **Decapsulation phase** — restores the snapshot, writes a (possibly modified) ciphertext into the emulator's memory, and records the instruction + register trace between `trigger_high` and `trigger_low`.

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

> Each fault index controls how many columns of the C_1 component of the FrodoKEM ciphertext are zeroed out before decapsulation.

> **Warning:** The number of traces, the number of jobs, the fault indicies or the outputfiles should all be changed in the Makefile. 

---

#### Makefile Targets

| Target | Description |
|--------|-------------|
| `make all_sequential` | Runs `N` sequential traces |
| `make snapshot_parallel` | Runs keygen and saves snapshot for parallel mode |
| `make decap_parallel` | Runs `N_PARALLEL` decapsulations in parallel (requires snapshot) |
| `make all_parallel` | Runs `snapshot_parallel` then `decap_parallel` |
| `make snapshot_sample` | Runs keygen and saves snapshot for sample mode |
| `make decap_sample` | Runs all sample traces (requires snapshot) |
| `make snapshot_truncated` | Runs keygen and saves snapshot for truncated mode |
| `make decap_truncated` | Runs all truncated traces (requires snapshot) |
| `make all_truncated` | Runs `snapshot_sample` then `decap_sample` |
| `make all` | Runs `all_sequential` `all_parallel` `all_sample` |
| `make clean_sequential` | Deletes sequential output directories |
| `make clean_parallel` | Deletes parallel output directories |
| `make clean_sample` | Deletes sample output directories |
| `make clean ` | Deletes all output directories |

> The snapshot and decapsulation steps are separated so you can regenerate traces without re-running the expensive key generation step — just pass `--skip-snapshot` (handled automatically by the `decap_*` targets).

### 2.3 Code Output 

#### 2.3.1 Sequential
> Trim version = version without "pc", "instruction", "operands" (just value from registers)
Traces are collected one by one, iterating over fault indices `0` through `N-1`. Each trace folder corresponds to a ciphertext where the first `i` columns of the B' have been zeroed out.
 
```
output_decapsulation_sequential/
|---Trace_i/
    |--ct_modified_i.bin # Modified ciphertext with first i columns zeroed
    |--output_decapsulation_trace_i.txt # Log of executed instructions and addresses hit during key generation and decapsulation
    |--trace_i.csv # Captured power trace (first i index modified)
```
 
A trimmed version of each trace is saved to `output_decapsulation_sequential_TRIM/`.
 
---
 
#### 2.3.2 Parallel 
 
A single keygen is performed first and saved as a snapshot, then `N_PARALLEL` decapsulations are generated. All traces share the same base ciphertext and keypair that are in the main directory as: 
 
```
output_decapsulation_parallel/
|--ct_base.bin # Base ciphertext used for all fault injections
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication in the decapsulation phase
|-- snapshot.pkl # snapshotwith keygen until multiplication that is saved on the disk
|-- pk.bin # Public key saved after key generation
|-- sk.bin # Private key saved after key generation
|-- Trace_i/
    |-- ct_modified_i.bin # Ciphertext with first i columns modified
    |-- trace_i.csv # Captured power trace
```
 
A trimmed version of each trace is saved to `output_decapsulation_parallel_TRIM/`.
 
---
 
#### 2.3.3 Sample
 
Similar to the parallel version, but traces are collected for a set of fault indicies nd more runs a perform. When a run is perform, a new random ciphertext is generated and the same fault indices are changed for the current ciphertext.
 
```
output_decapsulation_sample/
|-- keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication
|-- snapshot.pkl # snapshotwith keygen until multiplication that is saved on the disk
|-- pk.bin # Public key
|-- sk.bin # Private key
|-- Run_i/ # i-th run (with a fresh random ciphertext)
    |-- Trace_j/ # j is the fault index (number of zeroed columns)
        |-- ciphertext_j.bin # Ciphertext with j columns modified
        |-- trace_j.csv # Captured power trace
```
 
Fault indices are configured via `FAULT_INDICES` (foe example `0 1 2 4 8 16 32 64 128 256 512`). A trimmed version of each trace is saved to `output_decapsulation_sample_TRIM/`.
 
---
 
#### 2.3.4 Truncated 
 
This mode aims to capture every dot product. In FrodoKEM's decapsulation, the matrix multiplication **B' x S** is done by multiplying one row of B with a columns of S. When this is done, the columns index of S is increased and the same row of B' is multiplied with the new columns of S. Because of that, there are 8 dot products execited for each row of B', creating a 8 x 8 matrix. 
 
```
output_decapsulation_truncated/
|--keygen_snapshot_log.txt # Instruction log from key generation up to the multiplication
|--snapshot.pkl # snapshotwith keygen until multiplication that is saved on the disk
|-- pk.bin # Public key
|-- sk.bin # Private key
|-- trace_i_j.csv # Trace for the i-th run, targeting the j-th dot product
                  # e.g. trace_5_2 = 5th ciphertext, 3rd dot product (0-indexed), which means that it exploits the third column of S
|-- ciphertext_i.bin # Store the i-th randomly generated ciphertext 
```
A trimmed version of each trace is saved to `output_decapsulation_truncated_TRIM/`.
 
---
 
## 3. Results 

