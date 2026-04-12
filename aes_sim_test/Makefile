PYTHON       = python3
SCRIPT1      = frodo_collect_traces.py
SCRIPT2      = frodo_collect_traces_parallel.py
SCRIPT3      = correlation_frodo.py
N            = 4
N_parallel   = 641
JOBS         = 10
OUTPUT_DIR1  = output_decapsulation
OUTPUT_DIR2  = output_decapsulation_parallel
INDICES := $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range($(N))))")

.PHONY: all_sequential all_parallel snapshot_parallel decap_parallel clean clean_parallel clean_all

all_sequantial:
	@for i in $(INDICES); do \
		echo "Trace $$i has been initialized"; \
		mkdir -p $(OUTPUT_DIR1)/TRACE_$$i; \
		$(PYTHON) $(SCRIPT1) --fault-index $$i > $(OUTPUT_DIR1)/TRACE_$$i/output_decapsulation_trace_$$i.txt 2>&1; \
		echo "Trace $$i has been completed"; \
	done
	@echo "All traces have been collected successfully"

# Run just key_generation+decapsulation until mult_bs
snapshot_parallel:
	@echo "Running keygen and saving snapshot at crypto_kem_dec entry..."
	@mkdir -p $(OUTPUT_DIR2)
	@$(PYTHON) $(SCRIPT2) --n 0 > $(OUTPUT_DIR2)/keygen_snapshot_log.txt 2>&1
	@echo "Snapshot creation completed"

# Run decapsulations only
decap_parallel:
	@echo "Running $(N_parallel) decapsulations in parallel with $(JOBS) workers using existing snapshot..."
	@mkdir -p $(OUTPUT_DIR2)
	@$(PYTHON) $(SCRIPT2) --n $(N_parallel) --jobs $(JOBS) --skip-snapshot > $(OUTPUT_DIR2)/output_decapsulation_parallel.txt 2>&1
	@echo "All parallel traces have been collected successfully"

all_parallel: snapshot_parallel decap_parallel

clean:
	rm -rf $(OUTPUT_DIR1)

clean_parallel:
	rm -rf $(OUTPUT_DIR2)

clean_all:
	rm -rf $(OUTPUT_DIR1) $(OUTPUT_DIR2) 