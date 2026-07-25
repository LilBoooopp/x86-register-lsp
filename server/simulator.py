"""
x86_64 register simulator using Unicorn Engine.

Steps through parsed instructions, recording register state before each one.
"""

from dataclasses import dataclass, field

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

from server.parser import ParsedBlock, ParsedInstruction
from keystone import Ks, KS_ARCH_X86, KS_MODE_64


# ── GP registers we track ───────────────────────────────────────────────────

GP_REGS_64 = [
    "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip",
]

# register name → Unicorn constant
UC_REG: dict[str, int] = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
    "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
    "r8":  UC_X86_REG_R8,  "r9":  UC_X86_REG_R9,
    "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
    "rip": UC_X86_REG_RIP,
}


# ── data structures ─────────────────────────────────────────────────────────


@dataclass
class RegSnapshot:
    """Register state before one instruction executes."""
    instruction_index: int
    address: int                    # RIP at this point
    values: dict[str, int]          # reg name → value
    changed: list[str]              # which regs differ from previous snapshot
    stack: list[int] | None = None  # stack qwords around RSP (16 entries above RSP)
    error: str | None = None


@dataclass
class SimulationResult:
    """Full simulation output."""
    snapshots: list[RegSnapshot]
    errors: list[str]


# ── engine ──────────────────────────────────────────────────────────────────

_KS = Ks(KS_ARCH_X86, KS_MODE_64)


def simulate(
    block: ParsedBlock,
    initial_regs: dict[str, int] | None = None,
    stack_size: int = 0x10000,
) -> SimulationResult:
    """
    Simulate register state through every instruction in the parsed block.

    Args:
        block: parsed assembly block from parser.parse_assembly().
        initial_regs: dict of register name → initial value (e.g. {'rax': 42}).
        stack_size: bytes to allocate for the stack (default 64KB).

    Returns:
        SimulationResult with one snapshot per instruction.
    """
    if not block.instructions:
        return SimulationResult([], ["No instructions to simulate"])

    initial_regs = initial_regs or {}
    errors: list[str] = []

    # ── 1. re-assemble all instructions into a contiguous binary ────────
    all_bytes = bytearray()
    addr_to_index: dict[int, int] = {}  # address → instruction index
    base = block.instructions[0].address
    current = base

    for idx, inst in enumerate(block.instructions):
        try:
            code, count = _KS.asm(f"{inst.mnemonic} {inst.operands}", current)
            if count > 0:
                raw = bytes(code)
                all_bytes.extend(raw)
                addr_to_index[current] = idx
                current += len(raw)
        except Exception:
            pass  # should not happen if parser already validated

    if not all_bytes:
        return SimulationResult([], ["Failed to assemble any instructions"])

    code_end = current

    # ── 2. set up Unicorn ───────────────────────────────────────────────
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # map code region (page-aligned, just big enough)
    CODE_BASE = base & ~0xFFF
    code_size = ((code_end - CODE_BASE) + 0xFFF) & ~0xFFF
    mu.mem_map(CODE_BASE, max(code_size, 0x1000))
    mu.mem_write(base, bytes(all_bytes))

    # map stack
    STACK_BASE = 0x7FFF0000
    mu.mem_map(STACK_BASE, stack_size)

    # map user-defined memory regions from @mem directives
    for addr, data in block.memory_regions.items():
        # page-align the mapping
        page_base = addr & ~0xFFF
        page_end = (addr + len(data) + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(page_base, page_end - page_base)
            mu.mem_write(addr, data)
        except Exception as e:
            errors.append(f"@mem 0x{addr:X}: failed to map — {e}")

    # ── 3. set initial register values ──────────────────────────────────
    rsp_initial = STACK_BASE + stack_size - 8 - 128  # leave room for stack read
    mu.reg_write(UC_X86_REG_RSP, rsp_initial)
    mu.reg_write(UC_X86_REG_RBP, rsp_initial)

    for name, value in initial_regs.items():
        if name in UC_REG:
            mu.reg_write(UC_REG[name], value)
        elif name.upper() in UC_REG:
            mu.reg_write(UC_REG[name.upper()], value)

    mu.reg_write(UC_X86_REG_RIP, base)

    # ── 4. hook to capture state before each instruction ─────────────────
    snapshots: list[RegSnapshot] = []
    prev_values: dict[str, int] = {}
    step_count = 0
    MAX_STEPS = 10000

    def code_hook(uc: Uc, address: int, size: int, user_data):
        nonlocal step_count, prev_values
        step_count += 1
        if step_count > MAX_STEPS:
            uc.emu_stop()
            return

        idx = addr_to_index.get(address)
        if idx is None:
            return  # not one of our instructions

        inst = block.instructions[idx]

        # read all GP registers
        values: dict[str, int] = {}
        for name in GP_REGS_64:
            if name in UC_REG:
                try:
                    values[name] = uc.reg_read(UC_REG[name])
                except Exception:
                    values[name] = 0

        # compute changed registers vs previous
        changed: list[str] = []
        if not snapshots:
            changed = [n for n in GP_REGS_64 if values.get(n, 0) != 0]
        else:
            prev_inst = block.instructions[snapshots[-1].instruction_index]
            for name in GP_REGS_64:
                if values.get(name, 0) != prev_values.get(name, 0):
                    if name in prev_inst.reg_access.writes:
                        changed.append(name)

        # read stack
        stack_vals: list[int] | None = None
        try:
            rsp_val = values.get("rsp", 0)
            if rsp_val != 0:
                raw = uc.mem_read(rsp_val, 16 * 8)
                stack_vals = [
                    int.from_bytes(raw[i:i+8], 'little', signed=False)
                    for i in range(0, len(raw), 8)
                ]
        except Exception:
            pass

        snapshots.append(RegSnapshot(
            instruction_index=idx,
            address=address,
            values=values,
            changed=changed,
            stack=stack_vals,
        ))
        prev_values = values

    mu.hook_add(UC_HOOK_CODE, code_hook)

    # ── 5. run ──────────────────────────────────────────────────────────
    try:
        mu.emu_start(base, 0, timeout=5_000_000)  # 5-second timeout
    except Exception as e:
        if "UC_ERR_OK" not in str(e):
            errors.append(str(e))

    return SimulationResult(snapshots=snapshots, errors=errors)
