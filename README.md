1. Running the file:
   - go to pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo
   - run the Makefile from the terminal: make PLATFORM=CW308_STM32F4
   - coppy the elf file that is generated in aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf by using the instruction: cp <source> <destination> (example: cp /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf)
   - run the capture traces script by using the Makefile from aes_sim_test with the instruction: make all
   - to clean/delete the traces use: make clean
  
2. Explanation of the code
   
2.1 Firmware: pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo.c together with the Makefile and the API from Frodo help in generating the firmware(elf file).
   pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo.c decides what it will be in the firmware and the instructions that are going to be captured are between trigger_high and trigger_low. The other instructions are executed, but not captured in the trace.
   [WARNING] the makefile contains the source of the pqm4 repository: PQMROOT  = /Users/vicentiastroe/Documents/Thesis/FrodoKEM/pqm4-Round3, which needs to be changed.
    pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/hal_stub.c contains the logic for the RNG
    
2.2 Capture code:
   frodo_collect_traces.py contain the logic for capturing the traces. The simulator will stop when trigger_low was hit and it will save the public key, the secret key and the ciphertext.
   Makefile: in order to execute the Makefile the following instructions can be used:
     - make all: creates N traces
     - make clean: delete the folders
   in order to run just one trace use the last command from aes_sim_test/frodo_experiment.ipynb
