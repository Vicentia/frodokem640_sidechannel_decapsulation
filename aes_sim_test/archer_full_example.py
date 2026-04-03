#!/usr/bin/env python3

import sys

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
#from tqs import inst_counter
from unicorn.arm_const import UC_ARM_REG_S0
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
import csv


#---------------------------------------------------GLOBALS-----------------
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

instructions = []
stack_writes = []
stack_reads = []
#trace = []
#log = []
#count = 0
end_kem_keypair = 0
end_kem_enc = 0
end_kem_dec = 0
# TODO Adjust values according to the implementation  (TARGET ML-KEM 768)
SIZE_PK = 1184
SIZE_SK = 2400
SIZE_CT = 1088
SIZE_SS = 32

address_coins_keypair = 0
address_coins_enc = 0
kem_keypair_arg1 = 0


#----------------------------------------------------------------------------


def get_label_address(elf_file, function_name):
    with open(elf_file, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == '.symtab':
                for symbol in section.iter_symbols():
                    if symbol.name == function_name:
                        return symbol['st_value']

def disasm(ql, address):
    bytecode = ql.mem.read(address, 4)
    info = []
    for insn in md.disasm(bytecode, address):
        return [insn.mnemonic, insn.op_str]
        #hex(insn.address), insn.bytes.hex()



def full_tracing(ql:Qiling, address:int, size:int)->None:
    global skip
    
    global kem_keypair
    
    global instructions
    global address_SK #secret key
    global address_PK #public key
    global address_CT #ciphertext
    global address_SS #shared secret
    
    global address_coins_keypair
    global address_coins_enc
 
    global end_kem_keypair
    global end_kem_enc
    global indcpa_keypair
    
    instructions.append(address)
    code = ql.mem.read(address, size)
    if address == skip:
        ql.arch.regs.write('pc', ql.arch.regs.read('lr'))
        return

    
      ### WHILE TRACING WE SAVE ALL REGISTERS
    uc = ql.uc 

    ins, arg = disasm(ql, address)
    row = [hex(address), ins, arg]
    for r in ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc']:
        row.append(hex(ql.arch.regs.read(r)))
        # uncomment for FPU registers
        # # FPU registers (s0-s31, fpscr, etc.)
        # uc = ql.uc  # Get underlying Unicorn instance
        # for i in range(32):
        #     tmp.append(hex(uc.reg_read(UC_ARM_REG_S0+i)))
        # log.append(tmp)
    writer.writerow(row)

    #Hook to overwrite the randomness for keypair generation
    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if address == kem_keypair:
        print("----------------------------")
        print("Entering keypair generation:") # the function call is of the form (crypto_kem_keypair(pk, sk, address_coins_keypair))
        print("----------------------------")
        end_kem_keypair = ql.arch.regs.read('lr')-1
        address_PK= ql.arch.regs.read("r0")  
        address_SK= ql.arch.regs.read("r1")
        print("[+] Should trace until ", hex(end_kem_keypair))
        return
     #Overwrite the randomness for keypair generation
    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if address == indcpa_keypair:
        address_coins_keypair = ql.arch.regs.read("r2")
        #fixed_coins_keypair=bytes("c8a580f66f3409da145762dc71b9c9f2df2874efaefdbca75f6414ee08d8b1e")
        ql.mem.write(address_coins_keypair, bytes(b"A"*0x20))
        return
    
    if address == end_kem_keypair:
        print("Exiting crypto_kem_keypair")
        # Read the public key from memory
        pk = ql.mem.read(address_PK, SIZE_PK)
        with open("output/results/pk.txt", "wb") as f:
            f.write(pk)
        print("[+] Public key written to output/results/kem_keypair_pk.txt")
        # Read the secret key from memory
        sk = ql.mem.read(address_SK, SIZE_SK)
        with open("output/results/sk.txt", "wb") as f:
            f.write(sk)
        print("[+] Secret key written to output/results/kem_keypair_sk.txt")
        return
    
    if address == kem_enc:
        print("----------------------------")
        print("Entering encapsulation:")
        print("----------------------------")
        end_kem_enc = ql.arch.regs.read('lr')-1
        address_CT= ql.arch.regs.read("r0")  
        address_SS= ql.arch.regs.read("r1")
        address_PK= ql.arch.regs.read("r2")  
        print("[+] Should trace until ", hex(end_kem_enc))
        return
    #Overwrite the randomness for encapsulation generation
    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if address == 0x08003d48:
        address_coins_keypair = ql.arch.regs.read("r1")
        # data = ql.mem.read(address_coins_keypair, 0x20)
        # print("Original coins kem_enc:", data.hex())
        # ptr points to third parameter of indcpa_keypair_derand
        # Overwrite it with 32 bytes set to 0x41 ('A')
        fixed_coins_enc=bytes(b"B"*0x20); 
        ql.mem.write(address_coins_keypair, fixed_coins_enc)
        print("New coins for encapsulation:", fixed_coins_enc.hex())


    if address == end_kem_enc:
        print("Exiting crypto_kem_enc")
        # Read the public key from memory
        ct = ql.mem.read(address_CT, SIZE_CT)
        with open("output/results/ct.txt", "wb") as f:
            f.write(ct)
        print("[+] Ciphertext written to output/results/ct.txt")
        # Read the secret key from memory
        ss = ql.mem.read(address_SS, SIZE_SS)
        with open("output/results/ss.txt", "wb") as f:
            f.write(ss)
        print("[+] Shared key written to output/results/ss.txt")
        print('SS =', ss.hex())
        return
    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if address == kem_dec:
        print("----------------------------")
        print("Entering decapsulation:")
        print("----------------------------")
        end_kem_dec = ql.arch.regs.read('lr')-1
        address_SS= ql.arch.regs.read("r1")
        address_SK= ql.arch.regs.read("r2")
        address_CT= ql.arch.regs.read("r0")  
        print("[+] Should trace until ", hex(end_kem_dec))
        return


#---------------------------------------------------MAIN call for simulation-----------------
if __name__ == "__main__":
    
    elf_file = sys.argv[1]
    tracing = False
    #target = get_label_address(sys.argv[1], sys.argv[2])-1
    #print('Target address:',hex(target))
    ### SKIP FUNCTION THAT USES UNSUPORTED HARDWARE 
    #-------------------------------------------------Prepare Qiling for ARM Cortex M4-----------------
    skip = get_label_address(sys.argv[1], "hal_setup")-1
    ### change PPB type to memory as DWT registers are located in this regeon and act like memory 
    stm32f407["PPB"]["type"] = 'memory'
    ql = Qiling([elf_file], archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU, env=stm32f407, verbose=QL_VERBOSE.OFF)
        
    
    ql.hw.create('usart1')
    ql.hw.create('usart2')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')

    # Map AHB2 RNG peripheral as r/w memory initialized with zeros
    ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)  # 0x400 = 1024 bytes, perms=7 (rwx)
    ql.mem.write(0x50060800, bytes(b"00" * 4))
    #-------------------------------------------------------------------------------------------
   
 

    kem_keypair = get_label_address(elf_file, "crypto_kem_keypair") - 1
    kem_enc = get_label_address(elf_file, "crypto_kem_enc") - 1
    kem_dec = get_label_address(elf_file, "crypto_kem_dec") - 1
    indcpa_keypair = get_label_address(elf_file, "indcpa_keypair_derand") - 1
    polyvec_ntt = get_label_address(elf_file, "polyvec_ntt") - 1

    print('Instrumenting addresses:')
    print("----------------------------")
    print("crypto_kem_keypair =", hex(kem_keypair or 0))
    print("crypto_kem_enc     =", hex(kem_enc or 0))
    print("crypto_kem_dec     =", hex(kem_dec or 0))    
    print("----------------------------")
    print("polyvec_ntt         =", hex(polyvec_ntt or 0))
    #------------------------------CODE TRACING-----------------
    ql.hook_code(full_tracing)
    
    #---------------------------------------------------writing to file-----------------
    header = ['PC', 'Ins', 'Operands', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'] 
    DSP_reg=['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 's12', 's13', 's14', 's15', 's16', 's17', 's18', 's19', 's20', 's21', 's22', 's23', 's24', 's25', 's26', 's27', 's28', 's29', 's30', 's31']
    name_trace_file='output/traces/trace.csv' 
    f = open(name_trace_file, 'w')
    writer = csv.writer(f)
    writer.writerow(header)
    #-----------------------------------------------------------------------------------    
    

     ### Start Simulation
    ql.run(end=0x8007531) # run until end of main, else it will crach 
    



