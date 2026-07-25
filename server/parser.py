"""
x86_64 assembly parser.

Pipeline: source text → Keystone (assemble) → bytes → Capstone (disassemble + reg info)
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
    """Which registers an instruction reads and writes."""
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


@dataclass
class ParsedInstruction:
    """One decoded instruction with its register footprint."""
    address: int            # byte offset from start of code
    mnemonic: str           # "mov", "add", "push", ...
    operands: str           # "rax, qword ptr [rbx]"
    reg_access: RegAccess
    line_number: int        # 1-based line in source
    raw_line: str           # original source line text


@dataclass
class ParsedBlock:
    """Full parse result for an assembly source buffer."""
    instructions: list[ParsedInstruction]
    labels: dict[str, int] = field(default_factory=dict)          # name → instruction index
    register_directives: dict[str, int] = field(default_factory=dict)  # reg → value
    errors: list[str] = field(default_factory=list)


# ── engines (reusable module-level singletons) ──────────────────────────────

_KS = Ks(KS_ARCH_X86, KS_MODE_64)

_CS = Cs(CS_ARCH_X86, CS_MODE_64)
_CS.detail = True


# ── helpers ─────────────────────────────────────────────────────────────────

_COMMENT_RE = re.compile(r'^\s*(?:[;#]|//)')
_LABEL_RE = re.compile(r'^([\._a-zA-Z][\._a-zA-Z0-9]*):\s*(.*)$')
_REG_DIRECTIVE_RE = re.compile(r'\s*[;#]\s*@reg\s+(.*)')

# Assembler directives Keystone can't assemble — skip these lines silently
_DIRECTIVES = {
    'section', 'global', 'extern', 'bits', 'default', 'align',
    'segment', 'org', 'cpu', 'bits', 'bss', 'text', 'data',
}


def _access_from_capstone(insn) -> RegAccess:
    """
    Extract register read/write sets from a Capstone instruction.

    In Capstone v5, explicit operands carry per-operand access flags
    (CS_AC_READ / CS_AC_WRITE), while implicit registers (RSP for
    push/pop, EFLAGS for arithmetic) are in insn.regs_read/regs_write.
    """
    reads: set[str] = set()
    writes: set[str] = set()

    # explicit operands
    for op in insn.operands:
        if op.type == 1 and op.reg in REG_NAMES:  # type 1 = register
            name = REG_NAMES[op.reg]
            if op.access & CS_AC_READ:
                reads.add(name)
            if op.access & CS_AC_WRITE:
                writes.add(name)

    # implicit registers
    for rid in insn.regs_read:
        if rid in REG_NAMES:
            reads.add(REG_NAMES[rid])
    for rid in insn.regs_write:
        if rid in REG_NAMES:
            writes.add(REG_NAMES[rid])

    # remove eflags from writes (every arithmetic op touches it — noise)
    writes.discard("eflags")

    return RegAccess(reads=sorted(reads), writes=sorted(writes))


def _is_directive(word: str) -> bool:
    """Check if a word is an assembler directive (not an instruction)."""
    return word.lower() in _DIRECTIVES


# ── main parse function ─────────────────────────────────────────────────────

def parse_assembly(source: str, base_address: int = 0x1000) -> ParsedBlock:
    """
    Parse x86_64 assembly source into a block of instructions with register
    access information, labels, and @reg directives.

    Args:
        source: raw assembly text (Intel syntax).
        base_address: starting address for the code (default 0x1000).

    Returns:
        ParsedBlock with instructions, labels, register_directives, and errors.
    """
    lines = source.split("\n")
    instructions: list[ParsedInstruction] = []
    labels: dict[str, int] = {}
    register_directives: dict[str, int] = {}
    errors: list[str] = []

    address = base_address

    for lineno, raw in enumerate(lines, 1):
        text = raw.rstrip()

        # skip blank lines
        if not text:
            continue

        # check for @reg directive in comments (BEFORE generic comment skip)
        if not text.startswith((";", "#", "//")):
            pass  # not a comment line
        else:
            reg_match = _REG_DIRECTIVE_RE.match(text)
            if reg_match:
                for pair in reg_match.group(1).split():
                    if "=" in pair:
                        reg, val = pair.split("=", 1)
                        try:
                            register_directives[reg.strip()] = int(val.strip(), 0)
                        except ValueError:
                            errors.append(f"Line {lineno}: invalid @reg value '{val}'")
            continue  # skip all comment lines

        # extract label if present
        label_match = _LABEL_RE.match(text)
        label_name = None
        code = text
        if label_match:
            label_name = label_match.group(1)
            labels[label_name] = len(instructions)  # points to next instruction
            code = label_match.group(2).strip()

        if not code:
            continue  # label-only line

        # skip assembler directives
        first_word = code.split()[0] if code.split() else ""
        if _is_directive(first_word):
            continue

        # assemble → disassemble to get register detail
        try:
            encoding, count = _KS.asm(code, address)
        except Exception as e:
            errors.append(f"Line {lineno}: {e}")
            continue

        if count == 0:
            continue

        bytes_data = bytes(encoding)
        try:
            for insn in _CS.disasm(bytes_data, address):
                reg_access = _access_from_capstone(insn)
                instructions.append(ParsedInstruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    reg_access=reg_access,
                    line_number=lineno,
                    raw_line=raw,
                ))
                address = insn.address + insn.size
                break  # one source line → one instruction
        except Exception as e:
            errors.append(f"Line {lineno}: {e}")
            continue

    return ParsedBlock(
        instructions=instructions,
        labels=labels,
        register_directives=register_directives,
        errors=errors,
    )
root@a6e0618202e1:~/asm-nvim-lsp/server#
root@a6e0618202e1:~/asm-nvim-lsp/server# ls
__init__.py  __pycache__  parser.py  server.py  simulator.py  state.py
root@a6e0618202e1:~/asm-nvim-lsp/server# cat __init__.py
root@a6e0618202e1:~/asm-nvim-lsp/server# cat parser.py
"""
x86_64 assembly parser.

Pipeline: source text → Keystone (assemble) → bytes → Capstone (disassemble + reg info)
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
    """Which registers an instruction reads and writes."""
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


@dataclass
class ParsedInstruction:
    """One decoded instruction with its register footprint."""
    address: int            # byte offset from start of code
    mnemonic: str           # "mov", "add", "push", ...
    operands: str           # "rax, qword ptr [rbx]"
    reg_access: RegAccess
    line_number: int        # 1-based line in source
    raw_line: str           # original source line text


@dataclass
class ParsedBlock:
    """Full parse result for an assembly source buffer."""
    instructions: list[ParsedInstruction]
    labels: dict[str, int] = field(default_factory=dict)          # name → instruction index
    register_directives: dict[str, int] = field(default_factory=dict)  # reg → value
    errors: list[str] = field(default_factory=list)


# ── engines (reusable module-level singletons) ──────────────────────────────

_KS = Ks(KS_ARCH_X86, KS_MODE_64)

_CS = Cs(CS_ARCH_X86, CS_MODE_64)
_CS.detail = True


# ── helpers ─────────────────────────────────────────────────────────────────

_COMMENT_RE = re.compile(r'^\s*(?:[;#]|//)')
_LABEL_RE = re.compile(r'^([\._a-zA-Z][\._a-zA-Z0-9]*):\s*(.*)$')
_REG_DIRECTIVE_RE = re.compile(r'\s*[;#]\s*@reg\s+(.*)')

# Assembler directives Keystone can't assemble — skip these lines silently
_DIRECTIVES = {
    'section', 'global', 'extern', 'bits', 'default', 'align',
    'segment', 'org', 'cpu', 'bits', 'bss', 'text', 'data',
}


def _access_from_capstone(insn) -> RegAccess:
    """
    Extract register read/write sets from a Capstone instruction.

    In Capstone v5, explicit operands carry per-operand access flags
    (CS_AC_READ / CS_AC_WRITE), while implicit registers (RSP for
    push/pop, EFLAGS for arithmetic) are in insn.regs_read/regs_write.
    """
    reads: set[str] = set()
    writes: set[str] = set()

    # explicit operands
    for op in insn.operands:
        if op.type == 1 and op.reg in REG_NAMES:  # type 1 = register
            name = REG_NAMES[op.reg]
            if op.access & CS_AC_READ:
                reads.add(name)
            if op.access & CS_AC_WRITE:
                writes.add(name)

    # implicit registers
    for rid in insn.regs_read:
        if rid in REG_NAMES:
            reads.add(REG_NAMES[rid])
    for rid in insn.regs_write:
        if rid in REG_NAMES:
            writes.add(REG_NAMES[rid])

    # remove eflags from writes (every arithmetic op touches it — noise)
    writes.discard("eflags")

    return RegAccess(reads=sorted(reads), writes=sorted(writes))


def _is_directive(word: str) -> bool:
    """Check if a word is an assembler directive (not an instruction)."""
    return word.lower() in _DIRECTIVES


# ── main parse function ─────────────────────────────────────────────────────

def parse_assembly(source: str, base_address: int = 0x1000) -> ParsedBlock:
    """
    Parse x86_64 assembly source into a block of instructions with register
    access information, labels, and @reg directives.

    Args:
        source: raw assembly text (Intel syntax).
        base_address: starting address for the code (default 0x1000).

    Returns:
        ParsedBlock with instructions, labels, register_directives, and errors.
    """
    lines = source.split("\n")
    instructions: list[ParsedInstruction] = []
    labels: dict[str, int] = {}
    register_directives: dict[str, int] = {}
    errors: list[str] = []

    address = base_address

    for lineno, raw in enumerate(lines, 1):
        text = raw.rstrip()

        # skip blank lines
        if not text:
            continue

        # check for @reg directive in comments (BEFORE generic comment skip)
        if not text.startswith((";", "#", "//")):
            pass  # not a comment line
        else:
            reg_match = _REG_DIRECTIVE_RE.match(text)
            if reg_match:
                for pair in reg_match.group(1).split():
                    if "=" in pair:
                        reg, val = pair.split("=", 1)
                        try:
                            register_directives[reg.strip()] = int(val.strip(), 0)
                        except ValueError:
                            errors.append(f"Line {lineno}: invalid @reg value '{val}'")
            continue  # skip all comment lines

        # extract label if present
        label_match = _LABEL_RE.match(text)
        label_name = None
        code = text
        if label_match:
            label_name = label_match.group(1)
            labels[label_name] = len(instructions)  # points to next instruction
            code = label_match.group(2).strip()

        if not code:
            continue  # label-only line

        # skip assembler directives
        first_word = code.split()[0] if code.split() else ""
        if _is_directive(first_word):
            continue

        # assemble → disassemble to get register detail
        try:
            encoding, count = _KS.asm(code, address)
        except Exception as e:
            errors.append(f"Line {lineno}: {e}")
            continue

        if count == 0:
            continue

        bytes_data = bytes(encoding)
        try:
            for insn in _CS.disasm(bytes_data, address):
                reg_access = _access_from_capstone(insn)
                instructions.append(ParsedInstruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    reg_access=reg_access,
                    line_number=lineno,
                    raw_line=raw,
                ))
                address = insn.address + insn.size
                break  # one source line → one instruction
        except Exception as e:
            errors.append(f"Line {lineno}: {e}")
            continue

    return ParsedBlock(
        instructions=instructions,
        labels=labels,
        register_directives=register_directives,
        errors=errors,
    )
