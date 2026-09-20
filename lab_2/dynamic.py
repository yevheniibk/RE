#!/usr/bin/env python3
"""ЛР 2, варіант 3: динамічна деобфускація у Unicorn."""

import sys
from pathlib import Path
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from static import STUB, load_encoded

BASE = 0x01001000
STACK = 0x02000000
STACK_SIZE = 0x10000


def emulate(raw, original_size, trace):
    wide = raw.decode("ascii").encode("utf-16le")

    jump_offset = 2 * (len(STUB) - len(b"u4JB"))
    entry = BASE + jump_offset + 2

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = (len(wide) + 0xFFF) & ~0xFFF
    # +0x2000: сторінка перед буфером і додаткова сторінка після нього.
    mu.mem_map(BASE - 0x1000, pages + 0x2000)
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_write(BASE, wide)
    mu.reg_write(UC_X86_REG_EAX, 0)
    mu.reg_write(UC_X86_REG_ECX, BASE)
    mu.reg_write(UC_X86_REG_ESP, STACK + STACK_SIZE // 2)

    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def hook_code(uc, address, size, user_data):
        code = bytes(uc.mem_read(address, size))
        instruction = next(cs.disasm(code, address), None)
        text = "?" if instruction is None else f"{instruction.mnemonic} {instruction.op_str}"
        ecx = uc.reg_read(UC_X86_REG_ECX)
        edx = uc.reg_read(UC_X86_REG_EDX)
        trace.write(
            f"{address:08x} +{address - BASE:04x}: {code.hex():20} "
            f"{text:40} ECX={ecx:08x} EDX={edx:08x}\n"
        )

    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(BASE, entry, timeout=5_000_000, count=200_000)
    if mu.reg_read(UC_X86_REG_EIP) != entry:
        raise ValueError("Досягнуто ліміт емуляції до завершення декодування.")

    restored = bytes(mu.mem_read(entry, original_size))
    after = bytes(mu.mem_read(BASE, len(wide)))
    return restored, wide, after, entry


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Використання: python _emu.py encoded.bin decoded_dynamic.bin")
    raw, pairs = load_encoded(sys.argv[1])
    original_size = len(pairs) // 2
    if original_size > 4096:
        raise ValueError("Цей навчальний приклад обмежено 4096 початковими байтами.")
    with open("trace.txt", "w", encoding="utf-8") as trace:
        restored, before, after, entry = emulate(raw, original_size, trace)
    Path(sys.argv[2]).write_bytes(restored)
    Path("memory.before.bin").write_bytes(before)
    Path("memory.after.bin").write_bytes(after)
    print("Режим: x86, 32 біти; BufferRegister=ECX; BufferOffset=0")
    print(f"UTF-16LE: {len(before)} байтів")
    print(f"Зупинка перед відновленим кодом: 0x{entry:08x}")
    print(f"Відновлено: {len(restored)} байтів")
    print(repr(restored))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UcError) as error:
        raise SystemExit(f"Помилка: {error}")
