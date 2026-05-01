PYTHON            = python3
SCRIPT_SEQUENTIAL = frodo_collect_traces_sequential.py
SCRIPT_PARALLEL   = frodo_collect_traces_parallel.py
SCRIPT_SAMPLE     = frodo_collect_traces_sample.py
SCRIPT_TRUNCATED  = frodo_collect_traces_truncated.py
ELF_FILE          = firmware/simpleserial-frodo-CW308_STM32F4.elf

# Sequential 
N = 2
OUTPUT_DIR_SEQUENTIAL      = output_decapsulation_sequential
OUTPUT_DIR_SEQUENTIAL_TRIM = output_decapsulation_sequential_TRIM

# Parallel 
N_PARALLEL = 641
JOBS_PARALLEL = 10
OUTPUT_DIR_PARALLEL      = output_decapsulation_parallel
OUTPUT_DIR_PARALLEL_TRIM = output_decapsulation_parallel_TRIM

# Sample 
NUM_RUNS = 5
FAULT_INDICES = 0 1 2 4 8 16 32 64 128 256 512
JOBS_SAMPLE = 10
OUTPUT_DIR_SAMPLE      = output_decapsulation_sample
OUTPUT_DIR_SAMPLE_TRIM = output_decapsulation_sample_TRIM

# Truncated 
NUM_RUNS_TRUNCATED        = 80 
FAULT_INDICES_TRUNCATED   = 0
JOBS_TRUNCATED            = 10
OUTPUT_DIR_TRUNCATED      = output_decapsulation_truncated
OUTPUT_DIR_TRUNCATED_TRIM = output_decapsulation_truncated_TRIM


# for derivation of the indexes
INDICES := $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range($(N))))")

.PHONY: all all_sequential all_parallel all_sample all_truncated \
        snapshot_parallel decap_parallel \
        snapshot_sample decap_sample \
		snapshot_truncated decap_truncated \
        clean clean_parallel clean_sample clean_sequential clean_truncated clean_all

# running sequential
all_sequential:
	@echo "Sequential run started..."
	@echo "-------------------------"
	@mkdir -p $(OUTPUT_DIR_SEQUENTIAL) $(OUTPUT_DIR_SEQUENTIAL_TRIM)
	@for i in $(INDICES); do \
		echo "Trace $$i initialised"; \
		mkdir -p $(OUTPUT_DIR_SEQUENTIAL)/TRACE_$$i; \
		$(PYTHON) $(SCRIPT_SEQUENTIAL) \
			--elf-file $(ELF_FILE) \
			--fault-index $$i \
			--output-dir $(OUTPUT_DIR_SEQUENTIAL) \
			--output-dir-trim $(OUTPUT_DIR_SEQUENTIAL_TRIM) \
			> $(OUTPUT_DIR_SEQUENTIAL)/TRACE_$$i/output_decapsulation_trace_$$i.txt 2>&1; \
		echo "Trace $$i completed"; \
	done
	@echo "All sequential traces collected — see $(OUTPUT_DIR_SEQUENTIAL) and $(OUTPUT_DIR_SEQUENTIAL_TRIM)"
	@echo "--------------------"
	@echo "Sequential run ended"

# running parallel 
snapshot_parallel:
	@echo "Running keygen and saving snapshot..."
	@mkdir -p $(OUTPUT_DIR_PARALLEL) $(OUTPUT_DIR_PARALLEL_TRIM)
	@$(PYTHON) $(SCRIPT_PARALLEL) \
		--elf-file $(ELF_FILE) \
		--n 0 \
		--output-dir $(OUTPUT_DIR_PARALLEL) \
		--output-dir-trim $(OUTPUT_DIR_PARALLEL_TRIM) \
		> $(OUTPUT_DIR_PARALLEL)/keygen_snapshot_log.txt 2>&1
	@echo "Snapshot done"

decap_parallel:
	@echo "Running $(N_PARALLEL) decapsulations ($(JOBS_PARALLEL) workers)..."
	@mkdir -p $(OUTPUT_DIR_PARALLEL) $(OUTPUT_DIR_PARALLEL_TRIM)
	@$(PYTHON) $(SCRIPT_PARALLEL) \
		--elf-file $(ELF_FILE) \
		--n $(N_PARALLEL) \
		--jobs $(JOBS_PARALLEL) \
		--output-dir $(OUTPUT_DIR_PARALLEL) \
		--output-dir-trim $(OUTPUT_DIR_PARALLEL_TRIM) \
		--skip-snapshot \
		> $(OUTPUT_DIR_PARALLEL)/output_decapsulation_parallel.txt 2>&1
	@echo "All parallel traces collected — see $(OUTPUT_DIR_PARALLEL) and $(OUTPUT_DIR_PARALLEL_TRIM)"

all_parallel:
	@echo "Parallel run started..."
	@echo "-----------------------"
	@$(MAKE) snapshot_parallel
	@echo "Snapshot captured, decapsulation starts"
	@$(MAKE) decap_parallel
	@echo "------------------"
	@echo "Parallel run ended."

# running sample
snapshot_sample:
	@echo "Running keygen and saving snapshot for sample collection..."
	@mkdir -p $(OUTPUT_DIR_SAMPLE) $(OUTPUT_DIR_SAMPLE_TRIM)
	@$(PYTHON) $(SCRIPT_SAMPLE) \
		--elf-file $(ELF_FILE) \
		--num-runs 0 \
		--output-dir $(OUTPUT_DIR_SAMPLE) \
		--output-dir-trim $(OUTPUT_DIR_SAMPLE_TRIM) \
		> $(OUTPUT_DIR_SAMPLE)/keygen_snapshot_log.txt 2>&1
	@echo "Snapshot done"

decap_sample:
	@echo "Running $(NUM_RUNS) runs with fault indices: [$(FAULT_INDICES)] with $(JOBS_SAMPLE) workers..."
	@mkdir -p $(OUTPUT_DIR_SAMPLE) $(OUTPUT_DIR_SAMPLE_TRIM)
	@$(PYTHON) $(SCRIPT_SAMPLE) \
		--elf-file $(ELF_FILE) \
		--num-runs $(NUM_RUNS) \
		--fault-indices $(FAULT_INDICES) \
		--jobs $(JOBS_SAMPLE) \
		--output-dir $(OUTPUT_DIR_SAMPLE) \
		--output-dir-trim $(OUTPUT_DIR_SAMPLE_TRIM) \
		--skip-snapshot \
		> $(OUTPUT_DIR_SAMPLE)/output_sample.txt 2>&1
	@echo "All sample traces collected — see $(OUTPUT_DIR_SAMPLE) and $(OUTPUT_DIR_SAMPLE_TRIM)"

all_sample:
	@echo "Sample run started..."
	@echo "-------------------"
	@$(MAKE) snapshot_sample
	@echo "Snapshot captured, decapsulation starts"
	@$(MAKE) decap_sample
	@echo "----------------"
	@echo "Sample run ended."

snapshot_truncated:
	@echo "Running keygen and saving snapshot for truncated version..."
	@mkdir -p $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM)
	@$(PYTHON) $(SCRIPT_TRUNCATED) \
		--elf-file $(ELF_FILE) \
		--num-runs 0 \
		--output-dir $(OUTPUT_DIR_TRUNCATED) \
		--output-dir-trim $(OUTPUT_DIR_TRUNCATED_TRIM) \
		> $(OUTPUT_DIR_TRUNCATED)/keygen_snapshot_log.txt 2>&1
	@echo "Snapshot done"

decap_truncated:
	@echo "Running $(NUM_RUNS_TRUNCATED) runs with fault indices: [$(FAULT_INDICES_TRUNCATED)] with $(JOBS_SAMPLE) workers..."
	@mkdir -p $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM)
	@$(PYTHON) $(SCRIPT_TRUNCATED) \
		--elf-file $(ELF_FILE) \
		--num-runs $(NUM_RUNS_TRUNCATED) \
		--fault-indices $(FAULT_INDICES_TRUNCATED) \
		--jobs $(JOBS_TRUNCATED) \
		--output-dir $(OUTPUT_DIR_TRUNCATED) \
		--output-dir-trim $(OUTPUT_DIR_TRUNCATED_TRIM) \
		--skip-snapshot \
		> $(OUTPUT_DIR_TRUNCATED)/output_sample.txt 2>&1
	@echo "All truncated traces collected — see $(OUTPUT_DIR_TRUNCATED) and $(OUTPUT_DIR_TRUNCATED_TRIM)"

all_truncated:
	@echo "Truncated run started..."
	@echo "-------------------"
	@$(MAKE) snapshot_truncated
	@echo "Snapshot captured, decapsulation starts"
	@$(MAKE) decap_truncated
	@echo "----------------"
	@echo "Truncated run ended."

# Running all 
all: all_sequential all_parallel all_sample all_truncated 

# clean
clean_sequential:
	rm -rf $(OUTPUT_DIR_SEQUENTIAL) $(OUTPUT_DIR_SEQUENTIAL_TRIM)

clean_parallel:
	rm -rf $(OUTPUT_DIR_PARALLEL) $(OUTPUT_DIR_PARALLEL_TRIM)

clean_sample:
	rm -rf $(OUTPUT_DIR_SAMPLE) $(OUTPUT_DIR_SAMPLE_TRIM)

clean_truncated: 
		rm -rf $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM)

clean: clean_sequential clean_parallel clean_sample clean_truncated
