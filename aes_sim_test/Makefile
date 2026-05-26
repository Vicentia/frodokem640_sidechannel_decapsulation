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
CIPHERTEXT_MODE_SEQUENTIAL = modified
CIPHERTEXT_MODE_SEQUENTIAL_VALID = valid

# Parallel 
N_PARALLEL = 10
JOBS_PARALLEL = 10
OUTPUT_DIR_PARALLEL      = output_decapsulation_parallel
OUTPUT_DIR_PARALLEL_TRIM = output_decapsulation_parallel_TRIM
CIPHERTEXT_MODE_PARALLEL = modified
CIPHERTEXT_MODE_PARALLEL_VALID = valid

# Sample 
NUM_RUNS = 5
FAULT_INDICES = 0 1 2 4 8 16 32 64 128 256 512
JOBS_SAMPLE = 10
OUTPUT_DIR_SAMPLE      = output_decapsulation_sample
OUTPUT_DIR_SAMPLE_TRIM = output_decapsulation_sample_TRIM
CIPHERTEXT_MODE_SAMPLE = modified
CIPHERTEXT_MODE_SAMPLE_VALID = valid

# Truncated 
NUM_RUNS_TRUNCATED        = 80 
FAULT_INDICES_TRUNCATED   = 0
JOBS_TRUNCATED            = 10
OUTPUT_DIR_TRUNCATED      = output_decapsulation_truncated
OUTPUT_DIR_TRUNCATED_TRIM = output_decapsulation_truncated_TRIM
CIPHERTEXT_MODE_TRUNCATED = modified
CIPHERTEXT_MODE_TRUNCATED_VALID = valid

# for derivation of the indexes
INDICES := $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range($(N))))")

.PHONY: all \
		sequential \
        parallel \
        sample \
        truncated \
        snapshot_parallel decap_parallel \
        snapshot_sample decap_sample \
		snapshot_truncated decap_truncated \
        clean clean_parallel clean_sample clean_sequential clean_truncated clean_all

# running sequential
sequential:
	@echo "Sequential run started..."
	@echo "-------------------------"
	@mkdir -p $(OUTPUT_DIR_SEQUENTIAL) $(OUTPUT_DIR_SEQUENTIAL_TRIM)
	@for i in $(INDICES); do \
		echo "Trace $$i modified initialised"; \
		$(PYTHON) $(SCRIPT_SEQUENTIAL) \
			--elf-file $(ELF_FILE) \
			--fault-index $$i \
			--output-dir $(OUTPUT_DIR_SEQUENTIAL) \
			--output-dir-trim $(OUTPUT_DIR_SEQUENTIAL_TRIM) \
			--ciphertext-mode modified \
			> $(OUTPUT_DIR_SEQUENTIAL)/output_decapsulation_trace_$$i.txt 2>&1; \
		echo "Trace $$i modified completed"; \
	done
	@echo "Sequential valid reference initialised"
	@$(PYTHON) $(SCRIPT_SEQUENTIAL) \
		--elf-file $(ELF_FILE) \
		--fault-index 0 \
		--output-dir $(OUTPUT_DIR_SEQUENTIAL) \
		--output-dir-trim $(OUTPUT_DIR_SEQUENTIAL_TRIM) \
		--ciphertext-mode valid \
		> $(OUTPUT_DIR_SEQUENTIAL)/output_decapsulation_trace_valid.txt 2>&1
	@echo "Sequential valid reference completed"
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
	@if [ "$(CIPHERTEXT_MODE_PARALLEL)" = "valid" ]; then \
		echo "Running 1 valid parallel reference ($(JOBS_PARALLEL) workers configured)..."; \
	else \
		echo "Running $(N_PARALLEL) modified decapsulations ($(JOBS_PARALLEL) workers)..."; \
	fi
	@mkdir -p $(OUTPUT_DIR_PARALLEL) $(OUTPUT_DIR_PARALLEL_TRIM)
	@$(PYTHON) $(SCRIPT_PARALLEL) \
		--elf-file $(ELF_FILE) \
		--n $(N_PARALLEL) \
		--jobs $(JOBS_PARALLEL) \
		--output-dir $(OUTPUT_DIR_PARALLEL) \
		--output-dir-trim $(OUTPUT_DIR_PARALLEL_TRIM) \
		--ciphertext-mode $(CIPHERTEXT_MODE_PARALLEL) \
		--skip-snapshot \
		> $(OUTPUT_DIR_PARALLEL)/output_decapsulation_parallel_$(CIPHERTEXT_MODE_PARALLEL).txt 2>&1
	@echo "All parallel traces collected — see $(OUTPUT_DIR_PARALLEL) and $(OUTPUT_DIR_PARALLEL_TRIM)"

parallel:
	@echo "Parallel run started..."
	@echo "-----------------------"
	@$(MAKE) snapshot_parallel
	@echo "Snapshot captured, valid decapsulation starts"
	@$(MAKE) decap_parallel CIPHERTEXT_MODE_PARALLEL=valid
	@echo "Snapshot captured, modified decapsulation starts"
	@$(MAKE) decap_parallel CIPHERTEXT_MODE_PARALLEL=modified
	@echo "------------------"
	@echo "Parallel run ended."


# running sample
snapshot_sample:
	@echo "Running keygen and saving one snapshot per sample run..."
	@mkdir -p $(OUTPUT_DIR_SAMPLE) $(OUTPUT_DIR_SAMPLE_TRIM)
	@$(PYTHON) $(SCRIPT_SAMPLE) \
		--elf-file $(ELF_FILE) \
		--num-runs $(NUM_RUNS) \
		--jobs $(JOBS_SAMPLE) \
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
		--ciphertext-mode $(CIPHERTEXT_MODE_SAMPLE) \
		--skip-snapshot \
		> $(OUTPUT_DIR_SAMPLE)/output_sample_$(CIPHERTEXT_MODE_SAMPLE).txt 2>&1
	@echo "All sample traces collected — see $(OUTPUT_DIR_SAMPLE) and $(OUTPUT_DIR_SAMPLE_TRIM)"

sample:
	@echo "Sample run started..."
	@echo "-------------------"
	@$(MAKE) snapshot_sample
	@echo "Snapshot captured, valid decapsulation starts"
	@$(MAKE) decap_sample CIPHERTEXT_MODE_SAMPLE=valid FAULT_INDICES=0
	@echo "Snapshot captured, modified decapsulation starts"
	@$(MAKE) decap_sample CIPHERTEXT_MODE_SAMPLE=modified
	@echo "----------------"
	@echo "Sample run ended."


snapshot_truncated:
	@echo "Running keygen and saving one snapshot per truncated run..."
	@mkdir -p $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM)
	@$(PYTHON) $(SCRIPT_TRUNCATED) \
		--elf-file $(ELF_FILE) \
		--num-runs $(NUM_RUNS_TRUNCATED) \
		--jobs $(JOBS_TRUNCATED) \
		--output-dir $(OUTPUT_DIR_TRUNCATED) \
		--output-dir-trim $(OUTPUT_DIR_TRUNCATED_TRIM) \
		> $(OUTPUT_DIR_TRUNCATED)/keygen_snapshot_log.txt 2>&1
	@echo "Snapshot done"

decap_truncated:
	@echo "Running $(NUM_RUNS_TRUNCATED) runs with fault indices: [$(FAULT_INDICES_TRUNCATED)] with $(JOBS_TRUNCATED) workers..."
	@mkdir -p $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM)
	@$(PYTHON) $(SCRIPT_TRUNCATED) \
		--elf-file $(ELF_FILE) \
		--num-runs $(NUM_RUNS_TRUNCATED) \
		--fault-indices $(FAULT_INDICES_TRUNCATED) \
		--jobs $(JOBS_TRUNCATED) \
		--output-dir $(OUTPUT_DIR_TRUNCATED) \
		--output-dir-trim $(OUTPUT_DIR_TRUNCATED_TRIM) \
		--ciphertext-mode $(CIPHERTEXT_MODE_TRUNCATED) \
		--skip-snapshot \
		> $(OUTPUT_DIR_TRUNCATED)/output_truncated_$(CIPHERTEXT_MODE_TRUNCATED).txt 2>&1
	@echo "All truncated traces collected — see $(OUTPUT_DIR_TRUNCATED) and $(OUTPUT_DIR_TRUNCATED_TRIM)"

truncated:
	@echo "Truncated run started..."
	@echo "-------------------"
	@$(MAKE) snapshot_truncated
	@echo "Snapshot captured, valid decapsulation starts"
	@$(MAKE) decap_truncated CIPHERTEXT_MODE_TRUNCATED=valid
	@echo "Snapshot captured, modified decapsulation starts"
	@$(MAKE) decap_truncated CIPHERTEXT_MODE_TRUNCATED=modified
	@echo "----------------"
	@echo "Truncated run ended."


# Running all
all:
	@echo "make all started: $$(date)"
	@echo "Starting sequential..."
	@$(MAKE) sequential
	@echo "Sequential finished: $$(date)"
	@echo "Starting parallel..."
	@$(MAKE) parallel
	@echo "Parallel finished: $$(date)"
	@echo "Starting sample..."
	@$(MAKE) sample
	@echo "Sample finished: $$(date)"
	@echo "Starting truncated..."
	@$(MAKE) truncated
	@echo "Truncated finished: $$(date)"
	@echo "make all finished: $$(date)"


# clean
clean_sequential:
	rm -rf $(OUTPUT_DIR_SEQUENTIAL) $(OUTPUT_DIR_SEQUENTIAL_TRIM) $(OUTPUT_DIR_SEQUENTIAL_VALID) $(OUTPUT_DIR_SEQUENTIAL_VALID_TRIM)

clean_parallel:
	rm -rf $(OUTPUT_DIR_PARALLEL) $(OUTPUT_DIR_PARALLEL_TRIM) $(OUTPUT_DIR_PARALLEL_VALID) $(OUTPUT_DIR_PARALLEL_VALID_TRIM)

clean_sample:
	rm -rf $(OUTPUT_DIR_SAMPLE) $(OUTPUT_DIR_SAMPLE_TRIM) $(OUTPUT_DIR_SAMPLE_VALID) $(OUTPUT_DIR_SAMPLE_VALID_TRIM)

clean_truncated: 
	rm -rf $(OUTPUT_DIR_TRUNCATED) $(OUTPUT_DIR_TRUNCATED_TRIM) $(OUTPUT_DIR_TRUNCATED_VALID) $(OUTPUT_DIR_TRUNCATED_VALID_TRIM)

clean: clean_sequential clean_parallel clean_sample clean_truncated
