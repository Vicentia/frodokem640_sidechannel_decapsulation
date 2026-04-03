1. Creation of the ELF file 
In order to create the elf file, go to pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo.c and use the Makefile:
- make PLATFORM=CW308_STM32F4
  
After this instruction, the elf file will be generated in: pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf that
needs to be coppied in the firmware of the aes_sim_test by using the instruction:
cp <sourse> <destination> (example: cp /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf)
After that the aes_sim_test main file should be run how it is explained in the third chapter.

2. Explanation of pqm4-Round3
The file with the chipwisperer enviroment is: pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo.c together with the makefile and the api sourse that contain the functions frrom the real frodo. In pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/hal_stub.c it is the logic for avoiding the RNG. The simpleserial-frodo.c contain the lofic that will be in the elf file after the execution. The trace is supposed to chapture from trigger_high to trigger_low and I the reason why now the key generation is not in between the triggers is because I tried to see if the algorithm is even getting to the trigger_low.

3. Explanation of aes_sim_test
frodo_collect_traces.py is the main code that contains the logic 
I decided that the capture will happen between the 2 triggers (trigger_high and trgger_low)
The behaviour of the algorithm is that one trigger_low was firred, then it will terminate
the code can be run by using the instruction: python3 frodo_collect_traces.py or from
frodo_experiment.ipynb 
The results will be saved in: outputs
