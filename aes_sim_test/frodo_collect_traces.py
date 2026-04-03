#!/usr/bin/env python3

import os
import csv
import sys
import traceback

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile


# ---------------------------------------------------GLOBALS-----------------

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

ins_trace = []
reg_trace = []

main_addr = None
kem_keypair_addr = None
trigger_high_addr = None
trigger_low_addr = None
skip = None

g_pk_addr = None
g_sk_addr = None
g_keypair_done_addr = None
g_pk_check_addr = None
g_sk_check_addr = None

hit_main = False
hit_kem_keypair = False
hit_trigger_high = False
hit_trigger_low = False

trace_started = False
trace_saved = False

address_PK = None
address_SK = None

SIZE_PK = 9616
SIZE_SK = 19888

instr_counter = 0

REG_NAMES = [
    'r0', 'r1', 'r2', 'r3',
    'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11',
    'r12', 'sp', 'lr', 'pc'
]


# -----------------------------------------------------------------

def normalize_addr(addr):
    if addr is None:
        return None
    return addr - 1 if (addr & 1) else addr


def get_label_address(elf_file, function_name):
    print(f"Looking for symbol: {function_name}")
    with open(elf_file, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == '.symtab':
                for symbol in section.iter_symbols():
                    if symbol.name == function_name:
                        addr = symbol['st_value']
                        print(f"Found {function_name} at {hex(addr)}")
                        return addr
    print(f"Symbol not found: {function_name}")
    return None


def disasm(ql, address):
    bytecode = ql.mem.read(address, 4)
    for insn in md.disasm(bytecode, address):
        return [insn.mnemonic, insn.op_str]
    return ["<unknown>", ""]


def save_csv(file_name):
    global trace_saved

    if trace_saved:
        return

    print(f"Saving ONE trace to {file_name}")
    print(f"Trace length: {len(ins_trace)} instructions")

    with open(file_name, "w", newline="") as csvfile:
        writer_csv = csv.writer(csvfile)
        writer_csv.writerow([
            'pc', 'instruction', 'operands',
            'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
        ])

        for ins_info, regs in zip(ins_trace, reg_trace):
            regs_hex = [hex(x) for x in regs]
            writer_csv.writerow([regs_hex[-1], ins_info[0], ins_info[1]] + regs_hex)

    trace_saved = True
    print("Trace saved")


def buffers(ql):
    os.makedirs("output/results", exist_ok=True)

    if g_pk_addr is not None:
        pk = ql.mem.read(g_pk_addr, SIZE_PK)
        with open("output/results/pk.bin", "wb") as f:
            f.write(pk)
        print("PK saved")

    if g_sk_addr is not None:
        sk = ql.mem.read(g_sk_addr, SIZE_SK)
        with open("output/results/sk.bin", "wb") as f:
            f.write(sk)
        print("SK saved")

    if g_keypair_done_addr is not None:
        done = ql.mem.read(g_keypair_done_addr, 1)[0]
        print(f"g_keypair_done = {done}")

    if g_pk_check_addr is not None:
        pk_check = int.from_bytes(ql.mem.read(g_pk_check_addr, 4), "little")
        print(f"g_pk_check = 0x{pk_check:08x} ({pk_check})")

    if g_sk_check_addr is not None:
        sk_check = int.from_bytes(ql.mem.read(g_sk_check_addr, 4), "little")
        print(f"g_sk_check = 0x{sk_check:08x} ({sk_check})")


class StopEmulation(Exception):
    pass

# Hooks
def full_tracing(ql: Qiling, address: int, size: int) -> None:
    global hit_main, hit_kem_keypair
    global hit_trigger_high, hit_trigger_low
    global trace_started, address_PK, address_SK
    global instr_counter
    global skip

    instr_counter += 1

    if address == skip:
        ql.arch.regs.write('pc', ql.arch.regs.read('lr'))
        return

    ins, arg = disasm(ql, address)

    if instr_counter % 10000 == 0:
        print(
            f"[PROGRESS] instr={instr_counter} "
            f"pc={hex(address)} sp={hex(ql.arch.regs.read('sp'))} "
            f"lr={hex(ql.arch.regs.read('lr'))} "
            f"ins={ins} {arg}"
        )

    if main_addr and address == main_addr and not hit_main:
        hit_main = True
        print(f"main() hit at {hex(address)}")

    if kem_keypair_addr and address == kem_keypair_addr and not hit_kem_keypair:
        hit_kem_keypair = True
        address_PK = ql.arch.regs.read("r0")
        address_SK = ql.arch.regs.read("r1")
        print("----------------------------")
        print("Entering keypair generation:")
        print("----------------------------")
        print(f"pk ptr = {hex(address_PK)}")
        print(f"sk ptr = {hex(address_SK)}")

    if trigger_high_addr and address == trigger_high_addr and not hit_trigger_high:
        hit_trigger_high = True
        trace_started = True
        ins_trace.clear()
        reg_trace.clear()
        print(f"trigger_high() at {hex(address)}, so the trace starts")

    if trace_started:
        regs_now = [ql.arch.regs.read(r) for r in REG_NAMES]
        ins_trace.append([ins, arg])
        reg_trace.append(regs_now)

    if trigger_low_addr and address == trigger_low_addr and not hit_trigger_low:
        hit_trigger_low = True
        print(f"trigger_low() at {hex(address)}")
        print(f"The number of instructions collected: {len(ins_trace)}")
        buffers(ql)
        save_csv("output/traces/trace.csv")

        print("Stop emulator")
        ql.emu_stop()
        raise StopEmulation("Trace captured, stopping emulator now")


if __name__ == "__main__":
    elf_file = "firmware/simpleserial-frodo-CW308_STM32F4.elf"

    print("Starting script")
    print(f"ELF exists? {os.path.exists(elf_file)}")

    if not os.path.exists(elf_file):
        sys.exit(1)

    os.makedirs("output/traces", exist_ok=True)
    os.makedirs("output/results", exist_ok=True)

    trigger_setup = get_label_address(elf_file, "trigger_setup")
    if trigger_setup:
        skip = normalize_addr(trigger_setup)

    main_addr = normalize_addr(get_label_address(elf_file, "main"))
    kem_keypair_addr = normalize_addr(get_label_address(elf_file, "crypto_kem_keypair"))
    trigger_high_addr = normalize_addr(get_label_address(elf_file, "trigger_high"))
    trigger_low_addr = normalize_addr(get_label_address(elf_file, "trigger_low"))

    g_pk_addr = get_label_address(elf_file, "g_pk")
    g_sk_addr = get_label_address(elf_file, "g_sk")
    g_keypair_done_addr = get_label_address(elf_file, "g_keypair_done")
    g_pk_check_addr = get_label_address(elf_file, "g_pk_check")
    g_sk_check_addr = get_label_address(elf_file, "g_sk_check")

    stm32f407["PPB"]["type"] = "memory"

    ql = Qiling(
        [elf_file],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f407,
        verbose=QL_VERBOSE.OFF
    )

    ql.hw.create("usart1")
    ql.hw.create("usart2")
    ql.hw.create("rcc")
    ql.hw.create("gpioa")

    try:
        ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)
        ql.mem.write(0x50060800, b"\x00" * 0x400)
    except:
        pass

    ql.hook_code(full_tracing)

    print("Running emulator...")
    try:
        ql.run()
    except StopEmulation as e:
        print(e)
    except Exception as e:
        print("Error during execution:", e)
        traceback.print_exc()

    print("\nSummary:")
    print(f"main hit         = {hit_main}")
    print(f"keypair hit      = {hit_kem_keypair}")
    print(f"trigger_high hit = {hit_trigger_high}")
    print(f"trigger_low hit  = {hit_trigger_low}")