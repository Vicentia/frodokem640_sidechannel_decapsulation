PYTHON     = python3
SCRIPT     = frodo_collect_traces.py
N          = 2 #Number of traces to collect 
OUTPUT_DIR = output_decapsulation

INDICES := $(shell $(PYTHON) -c "print(' '.join(str(i) for i in range($(N))))")

.PHONY: all clean

all:
	@for i in $(INDICES); do \
		mkdir -p $(OUTPUT_DIR)/TRACE_$$i; \
		$(PYTHON) $(SCRIPT) --fault-index $$i > $(OUTPUT_DIR)/TRACE_$$i/output_decapsulation_trace_$$i.txt 2>&1; \
	done

clean:
	rm -rf $(OUTPUT_DIR)
