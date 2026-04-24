# FrodoKEM Trace Collection

A simulation-based side-channel trace collection framework for FrodoKEM-640 decapsulation, running on an emulated STM32F4 target using [Qiling](https://github.com/qilingframework/qiling) and the [ChipWisperer enviorment](https://github.com/newaetech/chipwhisperer)

---

## Table of Contents

- [1. Running the Code](#1-running-the-code)
- [2. Code Explanation](#2-code-explanation)
  - [2.1 Firmware](#21-firmware)
  - [2.2 Capture Code](#22-capture-code)

---

## 1. Running the Code

### Step 1 — Build the firmware

Navigate to the firmware directory and build with the ChipWhisperer target:

```bash
cd pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo
make PLATFORM=CW308_STM32F4
```

> ⚠️ **Warning:** The Makefile inside `simpleserial-frodo/` contains a hardcoded path:
> ```makefile
> PQMROOT = /Users/vicentiastroe/Documents/Thesis/FrodoKEM/pqm4-Round3
> ```
> You **must** update this to match your local path before building.

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

---

### Step 3 — Collect traces

Run the capture script from the `aes_sim_test/` directory using the Makefile:

```bash
# Collect traces (sequential, parallel, sample or all — see Section 2.2)
make all_sequential
make all_parallel
make all_sample
make all 
```

To clean up generated output:

```bash
# Clean traces (sequential, parallel, sample or all)
make clean_sequential 
clean_parallel
clean_sample
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

The firmware is built using the FrodoKEM API from the `pqm4` repository. The instructions that are **captured** in the trace are those executed between `trigger_high` and `trigger_low`. All other instructions execute normally but are not captured.

---

### 2.2 Capture Code

**Source:** `aes_sim_test/`

#### Scripts

| Script | Description |
|--------|-------------|
| `frodo_collect_traces_sequential.py` | Collects traces one at a time, for each fault index sequentially |
| `frodo_collect_traces_parallel.py` | Collects traces in parallel across N fault indices |
| `frodo_collect_traces_sample.py` | Collects multiple independent runs across a fixed set of fault indices |

All scripts follow the same two-phase flow:
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

> Each fault index controls how many columns of the C₁ component of the FrodoKEM ciphertext are zeroed out before decapsulation.

The number of traces, the number of jobs, the fault indicies or the outputfiles should all be changed in the Makefile 

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
| `make all_sample` | Runs `snapshot_sample` then `decap_sample` |
| `make all` | Runs `all_sequential` `all_parallel` `all_sample` |
| `make clean_sequential` | Deletes sequential output directories |
| `make clean_parallel` | Deletes parallel output directories |
| `make clean_sample` | Deletes sample output directories |
| `make clean ` | Deletes all output directories |

> The snapshot and decapsulation steps are separated so you can regenerate traces without re-running the expensive key generation step — just pass `--skip-snapshot` (handled automatically by the `decap_*` targets).

