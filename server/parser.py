"""
x86_64 assembly parser.

Pipeline: source text → Keystone (assemble full block) → Capstone (disassemble + reg info)
Line mapping: code lines are tracked during scan, then zipped with Capstone output.
"""

import re
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
import capstone.x86_const as x86_const
from keystone import Ks, KS_ARCH_X86, KS_MODE_64


# ── register ID → name mapping ──────────────────────────────────────────────

REG_NAMES: dict[int, str] = {}
for _name in dir(x86_const):
    if _name.startswith("X86_REG_"):
        _id = getattr(x86_const, _name)
        REG_NAMES[_id] = _name[8:].lower()  # X86_REG_RAX → rax


# ── data structures ─────────────────────────────────────────────────────────


@dataclass
class RegAccess:
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


@dataclass
class ParsedInstruction:
    address: int
    mnemonic: str
    operands: str
    reg_access: RegAccess
    line_number: int        # 1-based line in source
    raw_line: str


@dataclass
class ParsedBlock:
    instructions: list[ParsedInstruction]
    labels: dict[str, int] = field(default_factory=dict)
    register_directives: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ── engines ─────────────────────────────────────────────────────────────────

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_CS = Cs(CS_ARCH_X86, CS_MODE_64)
_CS.detail = True


# ── helpers ─────────────────────────────────────────────────────────────────

_LABEL_RE = re.compile(r'^([\._a-zA-Z][\._a-zA-Z0-9]*):\s*(.*)$')
_REG_DIRECTIVE_RE = re.compile(r'\s*[;#]\s*@reg\s+(.*)')

_DIRECTIVES = {
    'section', 'global', 'extern', 'bits', 'default', 'align',
    'segment', 'org', 'cpu', 'bss', 'text', 'data',
}


def _access_from_capstone(insn) -> RegAccess:
    reads: set[str] = set()
    writes: set[str] = set()
    for op in insn.operands:
        if op.type == 1 and op.reg in REG_NAMES:
            name = REG_NAMES[op.reg]
            if op.access & CS_AC_READ:
                reads.add(name)
            if op.access & CS_AC_WRITE:
                writes.add(name)
    for rid in insn.regs_read:
        if rid in REG_NAMES:
            reads.add(REG_NAMES[rid])
    for rid in insn.regs_write:
        if rid in REG_NAMES:
            writes.add(REG_NAMES[rid])
    writes.discard("eflags")
    return RegAccess(reads=sorted(reads), writes=sorted(writes))


# ── parse ───────────────────────────────────────────────────────────────────


def parse_assembly(source: str, base_address: int = 0x1000) -> ParsedBlock:
    """Parse x86_64 assembly source. Assembles the entire code block at once
    for correct label resolution, then maps instructions back to source lines."""

    lines = source.split("\n")
    register_directives: dict[str, int] = {}
    errors: list[str] = []

    # ── scan: collect code lines and label positions ───────────────────
    code_lines: list[tuple[int, str, str]] = []  # (lineno, raw_line, code_text)
    labels: dict[str, int] = {}                  # name → expected instruction index
    asm_text_parts: list[str] = []               # lines of the full asm block

    for lineno, raw in enumerate(lines, 1):
        text = raw.rstrip()

        if not text:
            continue

        # @reg directives in comments
        if text.startswith((";", "#", "//")):
            reg_match = _REG_DIRECTIVE_RE.match(text)
            if reg_match:
                for pair in reg_match.group(1).split():
                    if "=" in pair:
                        reg, val = pair.split("=", 1)
                        try:
                            register_directives[reg.strip()] = int(val.strip(), 0)
                        except ValueError:
                            errors.append(f"Line {lineno}: invalid @reg value '{val}'")
            continue

        # extract label
        label_match = _LABEL_RE.match(text)
        label_name = None
        code = text
        if label_match:
            label_name = label_match.group(1)
            code = label_match.group(2).strip()

        if not code:
            if label_name:
                labels[label_name] = len(code_lines)  # points to next instruction
                asm_text_parts.append(f"{label_name}:")
        else:
            first_word = code.split()[0] if code.split() else ""
            if first_word.lower() in _DIRECTIVES:
                continue

            # record this as a code line
            if label_name:
                labels[label_name] = len(code_lines)  # points to this instruction's index
            code_lines.append((lineno, raw, code))
            if label_name:
                asm_text_parts.append(f"{label_name}: {code}")
            else:
                asm_text_parts.append(code)

    if not code_lines:
        return ParsedBlock([], labels=labels, register_directives=register_directives,
                           errors=errors)

    # ── assemble full block ────────────────────────────────────────────
    full_asm = "\n".join(asm_text_parts)
    try:
        encoding, stmt_count = _KS.asm(full_asm, base_address)
    except Exception as e:
        errors.append(f"Assembly failed: {e}")
        return ParsedBlock([], labels=labels, register_directives=register_directives,
                           errors=errors)

    if not encoding:
        return ParsedBlock([], labels=labels, register_directives=register_directives,
                           errors=errors)

    # ── disassemble with Capstone ───────────────────────────────────────
    instructions: list[ParsedInstruction] = []
    capstone_insts = list(_CS.disasm(bytes(encoding), base_address))

    if len(capstone_insts) != len(code_lines):
        errors.append(
            f"Mismatch: {len(capstone_insts)} instructions assembled but "
            f"{len(code_lines)} code lines. Some lines may have failed."
        )
        # best-effort: take min of both
        n = min(len(capstone_insts), len(code_lines))
    else:
        n = len(code_lines)

    for i in range(n):
        insn = capstone_insts[i]
        lineno, raw, _code = code_lines[i]
        reg_access = _access_from_capstone(insn)
        instructions.append(ParsedInstruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            operands=insn.op_str,
            reg_access=reg_access,
            line_number=lineno,
            raw_line=raw,
        ))

    return ParsedBlock(
        instructions=instructions,
        labels=labels,
        register_directives=register_directives,
        errors=errors,
    )
