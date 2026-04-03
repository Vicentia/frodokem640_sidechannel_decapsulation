In order to create the elf file, go to pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo.c and use the Makefile:
- make PLATFORM=CW308_STM32F4
  
After this instruction, the elf file will be generated in: pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf that
needs to be coppied in the firmware of the aes_sim_test by using the instruction:
cp <sourse> <destination> (example: cp /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/pqm4-Round3/cw-full/firmware/mcu/simpleserial-frodo/simpleserial-frodo-CW308_STM32F4.elf /Users/vicentiastroe/Documents/Thesis/FrodoKEM/InitialVersion/aes_sim_test/firmware/simpleserial-frodo-CW308_STM32F4.elf)
After that the aes_sim_test main file should be run how it is example in the README inside that file. 
