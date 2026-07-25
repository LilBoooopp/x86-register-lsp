# x86-register-lsp

Neovim LSP plugin for tracking x86_64 register state. Write assembly, set initial
register values with inline directives, simulate execution, and see register
changes as inline hints + a live sidebar.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Neovim                                          │
│  ┌──────────────┐    LSP protocol     ┌────────┐ │
│  │ Lua client   │◄───────────────────►│ Python │ │
│  │ (sidebar,    │   JSON-RPC over     │ LSP    │ │
│  │  commands)   │   stdin/stdout      │ server │ │
│  └──────────────┘                     └───┬────┘ │
│                                           │      │
│                              ┌────────────┴────┐ │
│                              │ Keystone →      │ │
│                              │ Capstone →      │ │
│                              │ Unicorn         │ │
│                              └─────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Pipeline

```
source text → Keystone (assemble) → bytes → Capstone (disassemble + reg info)
                                                    │
                              ┌─────────────────────┘
                              ▼
                    Unicorn Engine (step execute)
                              │
                              ▼
                    register snapshots → inlay hints + sidebar
```

## Project Structure

```
asm-nvim-lsp/
├── pyproject.toml              # deps: pygls, capstone, unicorn, keystone
├── server/
│   ├── __init__.py
│   ├── server.py               # LSP server (inlay hints, code lens, commands)
│   ├── parser.py               # Assembly parser (Keystone→Capstone)
│   ├── simulator.py            # Register simulator (Unicorn)
│   └── state.py                # Per-document state manager
├── lua/
│   └── x86-register-lsp/
│       └── init.lua            # Neovim plugin entry point
├── .gitignore
└── README.md
```

## Installation

```bash
pip install -e .
```

Then in Neovim (lazy.nvim):

```lua
{
    "cbopp/x86-register-lsp.nvim",
    config = function()
        require("x86-register-lsp").setup()
    end,
}
```

## Usage

Write assembly with Intel syntax. Use `; @reg` comments to set initial values:

```asm
; @reg rax=42 rbx=100
section .text
global _start
_start:
    mov rcx, rax
    add rcx, rbx
    imul rcx, 4
    push rcx
    pop rdx
    xor rax, rax
    ret
```

Commands:

| Command | Description |
|---|---|
| `:X86RegRun` | Run register simulation |
| `:X86RegSidebar` | Toggle register sidebar |
| `:X86RegSet rax=42 rbx=100` | Set initial register values |

## Build Status

- [x] Task 1 — Project scaffold (pyproject.toml, deps, skeleton)
- [x] Task 2 — Assembly parser (Keystone → Capstone, reg access, labels, @reg)
- [x] Task 3 — Register simulator (Unicorn step-through)
- [x] Task 4 — LSP inlay hints + code lens + commands
- [ ] Task 5 — Neovim sidebar (Lua)
- [ ] Task 6 — @reg directive parsing from source (done in Task 2)
- [ ] Task 7 — Error diagnostics
- [ ] Task 8 — Plugin polish (keymaps, docs)

## Dependencies

- Python 3.11+
- [pygls](https://github.com/openlawlibrary/pygls) — LSP server framework
- [Capstone](https://www.capstone-engine.org/) — disassembler
- [Keystone](https://www.keystone-engine.org/) — assembler
- [Unicorn](https://www.unicorn-engine.org/) — CPU emulator
