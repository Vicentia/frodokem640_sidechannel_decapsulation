from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.core import Qiling
from qiling.extensions.mcu.stm32f4 import stm32f407
from unicorn import (
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
)

from TRACE_parameters_initialisation import REG_NAMES


def normalize_addr(addr):
    if addr is None:
        return None
    return addr - 1 if (addr & 1) else addr


def get_label_address(elf_file, function_name):
    print(f"Looking for symbol: {function_name}")

    with open(elf_file, "rb") as f:
        elf = ELFFile(f)

        for section in elf.iter_sections():
            if section.name == ".symtab":
                for symbol in section.iter_symbols():
                    if symbol.name == function_name:
                        addr = symbol["st_value"]
                        print(f"Found {function_name} at {hex(addr)}")
                        return addr

    print(f"Symbol not found: {function_name}")
    return None


def make_disasm():
    return Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def disasm_with(ql, md, address):
    try:
        bytecode = ql.mem.read(address, 4)
        for insn in md.disasm(bytecode, address):
            return [insn.mnemonic, insn.op_str]
    except Exception:
        pass

    return ["<unknown>", ""]


def save_snapshot_manual(ql):
    print("Starting snapshot...")

    snapshot = {
        "regs": {r: ql.arch.regs.read(r) for r in REG_NAMES},
        "memory": [],
    }

    print(f"Registers saved: {snapshot['regs']}")

    skip_label_keywords = [
        "BITBAND",
        "BBR",
        "FLASH",
        "REMAP",
        "SYSTEM",
        "FLASH OTP",
    ]

    for start, end, perms, label, _ in ql.mem.get_mapinfo():
        region_size = end - start
        label_str = str(label)

        if any(k in label_str.upper() for k in skip_label_keywords):
            print(f"[SKIP] Region {label}: {hex(start)}-{hex(end)}")
            continue

        if region_size > 0x400000:
            print(f"[SKIP TOO LARGE] Region {label}: {hex(start)}-{hex(end)}")
            continue

        try:
            data = bytes(ql.mem.read(start, region_size))
            snapshot["memory"].append((start, end, perms, label, data))
            print(f"Saved region {label}: {hex(start)}-{hex(end)} ({region_size} bytes)")
        except Exception as e:
            print(f"[SKIP] Failed to read region {label}: {e}")

    print(f"Snapshot complete: {len(snapshot['memory'])} regions")
    return snapshot


def restore_snapshot_manual(ql, snapshot):
    for start, end, perms, label, data in snapshot["memory"]:
        try:
            ql.mem.write(start, data)
            print(f"Restored region [{label}]: {hex(start)}-{hex(end)}")
        except Exception as e:
            print(f"[ERROR] Failed to restore region [{label}]: {e}")

    for reg, val in snapshot["regs"].items():
        try:
            ql.arch.regs.write(reg, val)
        except Exception as e:
            print(f"[ERROR] Failed to restore register {reg}: {e}")


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(f"[UNMAPPED] access={access} addr={hex(address)} size={size} value={value}")
    return False


def patch_usarts(ql):
    class FakeUSART:
        def readable(self):
            return False

        def read(self, size=1):
            return bytes([0]) * size

        def write(self, data):
            return len(data) if data is not None else 0

        def flush(self):
            pass

    for usart_name in ("usart1", "usart2"):
        try:
            try:
                usart = ql.hw.get(usart_name)
            except TypeError:
                usart = getattr(ql.hw, usart_name, None)

            if usart is None:
                print(f"[ERROR] {usart_name} not available")
                continue

            try:
                usart.itube = FakeUSART()
                print(f"[INFO] Patched {usart_name}.itube with FakeUSART")
            except Exception as e:
                print(f"[ERROR] Could not replace {usart_name}.itube: {e}")

            try:
                usart.recv_from_user = lambda *args, **kwargs: 0x00
                print(f"[INFO] Patched {usart_name}.recv_from_user to return 0x00")
            except Exception as e:
                print(f"[ERROR] Could not patch {usart_name}.recv_from_user: {e}")

        except Exception as e:
            print(f"[ERROR] Could not patch {usart_name}: {e}")


def map_helper_regions(ql, include_bitband=True):
    if include_bitband:
        try:
            ql.mem.map(0x22000000, 0x02000000, info="SRAM_BITBAND_ALIAS", perms=3)
            ql.mem.write(0x22000000, b"\x00" * 0x02000000)
        except Exception:
            pass

        try:
            ql.mem.map(0x42000000, 0x02000000, info="PERIPH_BITBAND_ALIAS", perms=3)
            ql.mem.write(0x42000000, b"\x00" * 0x02000000)
        except Exception:
            pass

    try:
        ql.mem.map(0x50060800, 0x400, info="RNG", perms=3)
        ql.mem.write(0x50060800, b"\x00" * 0x400)
    except Exception:
        pass


def setup_qiling_instance(elf_file, *, patch_uart=True, include_bitband=True):
    stm32f407["PPB"]["type"] = "memory"

    ql = Qiling(
        [elf_file],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f407,
        verbose=QL_VERBOSE.OFF,
    )

    ql.hw.create("usart1")
    ql.hw.create("usart2")
    ql.hw.create("rcc")
    ql.hw.create("gpioa")

    if patch_uart:
        patch_usarts(ql)

    for hook_type in (
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
    ):
        ql.uc.hook_add(hook_type, hook_mem_invalid)

    map_helper_regions(ql, include_bitband=include_bitband)
    return ql


def resolve_decapsulation_symbols(elf_file, *, include_mul_xs=False):
    trigger_setup_addr = normalize_addr(get_label_address(elf_file, "trigger_setup"))
    init_uart_addr = normalize_addr(get_label_address(elf_file, "init_uart"))

    symbols = {
        "trigger_setup_addr": trigger_setup_addr,
        "init_uart_addr": init_uart_addr,
        "skip_addrs": {a for a in [trigger_setup_addr, init_uart_addr] if a is not None},
        "clear_bytes_addr": normalize_addr(get_label_address(elf_file, "clear_bytes")),
        "main_addr": normalize_addr(get_label_address(elf_file, "main")),
        "kem_keypair_addr": normalize_addr(get_label_address(elf_file, "crypto_kem_keypair")),
        "trigger_high_addr": normalize_addr(get_label_address(elf_file, "trigger_high")),
        "crypto_kem_dec_addr": normalize_addr(get_label_address(elf_file, "crypto_kem_dec")),
        "trigger_low_addr": normalize_addr(get_label_address(elf_file, "trigger_low")),
        "g_pk_addr": get_label_address(elf_file, "g_pk"),
        "g_sk_addr": get_label_address(elf_file, "g_sk"),
        "g_ct_addr": get_label_address(elf_file, "g_ct"),
        "g_keypair_done_addr": get_label_address(elf_file, "g_keypair_done"),
    }

    if include_mul_xs:
        symbols["mul_bs_addr"] = normalize_addr(get_label_address(elf_file, "mul_bs"))
        symbols["xs_addr"] = normalize_addr(get_label_address(elf_file, "xs"))

    return symbols
