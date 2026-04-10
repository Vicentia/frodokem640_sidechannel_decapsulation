PYTHON      = python3

SCRIPT1     = frodo_collect_traces.py
SCRIPT2     = frodo_collect_traces_parallel.py
SCRIPT3     = correlate_traces.py

N           = 2
JOBS        = $(N)

OUTPUT_DIR1 = output_decapsulation
OUTPUT_DIR2 = output_decapsulation_parallel

INDICES := $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range($(N))))")

.PHONY: all all_parallel correlate full clean clean_parallel clean_all

all:
	@for i in $(INDICES); do \
		echo "Trace $$i has been initialized"; \
		mkdir -p $(OUTPUT_DIR1)/TRACE_$$i; \
		$(PYTHON) $(SCRIPT1) --fault-index $$i > $(OUTPUT_DIR1)/TRACE_$$i/output_decapsulation_trace_$$i.txt 2>&1; \
		echo "Trace $$i has been completed"; \
	done
	@echo "All traces have been collected successfully"

all_parallel:
	@echo "Running $(N) decapsulations in parallel with $(JOBS) workers..."
	@mkdir -p $(OUTPUT_DIR2)
	@$(PYTHON) $(SCRIPT2) --n $(N) --jobs $(JOBS) > $(OUTPUT_DIR2)/output_decapsulation_parallel.txt 2>&1
	@echo "All parallel traces have been collected successfully"

correlation:
	@echo "Running trace correlation analysis..."
	@$(PYTHON) $(SCRIPT3)
	@echo "Correlation analysis completed"

clean:
	rm -rf $(OUTPUT_DIR1)

clean_parallel:
	rm -rf $(OUTPUT_DIR2)

clean_correlation:
	rm -rf $(OUTPUT_DIR1) $(OUTPUT_DIR2) traces.png