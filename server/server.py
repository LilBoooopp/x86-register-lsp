"""
x86-register-lsp — LSP server for x86_64 register tracking.

Provides inlay hints (register deltas), code lens (run simulation),
and custom commands for setting initial register values.
"""

import logging
from pygls.lsp.server import LanguageServer
from lsprotocol.types import (
    # document sync
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    DidOpenTextDocumentParams,
    DidChangeTextDocumentParams,
    DidCloseTextDocumentParams,
    # inlay hints
    TEXT_DOCUMENT_INLAY_HINT,
    InlayHint,
    InlayHintParams,
    InlayHintLabelPart,
    # code lens
    TEXT_DOCUMENT_CODE_LENS,
    CodeLens,
    CodeLensParams,
    Command,
    # diagnostics
    Diagnostic,
    DiagnosticSeverity,
    Position,
    Range,
    # initialize
    INITIALIZE,
    InitializeParams,
    ServerCapabilities,
    InlayHintOptions,
    ExecuteCommandOptions,
)

from server.state import DocumentState

logging.basicConfig(level=logging.DEBUG, filename="/tmp/x86-register-lsp.log")

server = LanguageServer("x86-register-lsp", "v0.1.0")

# ── per-document state ──────────────────────────────────────────────────────

documents: dict[str, DocumentState] = {}


def _get_doc(uri: str) -> DocumentState | None:
    return documents.get(uri)


# ── initialize ──────────────────────────────────────────────────────────────


@server.feature(INITIALIZE)
def initialize(ls: LanguageServer, params: InitializeParams):
    """Advertise inlay hint and code lens capabilities."""
    return ServerCapabilities(
        inlay_hint_provider=InlayHintOptions(resolve_provider=False),
        code_lens_provider={},
        execute_command_provider=ExecuteCommandOptions(
            commands=["x86reg.runSimulation", "x86reg.setRegisters"]
        ),
    )


# ── document sync ───────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: LanguageServer, params: DidOpenTextDocumentParams):
    uri = params.text_document.uri
    doc = DocumentState(uri)
    doc.update_source(params.text_document.text)
    documents[uri] = doc
    logging.info(f"Opened {uri}")


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: LanguageServer, params: DidChangeTextDocumentParams):
    uri = params.text_document.uri
    doc = _get_doc(uri)
    if not doc:
        return
    if params.content_changes:
        doc.update_source(params.content_changes[-1].text)
    _publish_diagnostics(ls, uri, doc)


@server.feature(TEXT_DOCUMENT_DID_CLOSE)
def did_close(ls: LanguageServer, params: DidCloseTextDocumentParams):
    documents.pop(params.text_document.uri, None)


# ── inlay hints ─────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_INLAY_HINT)
def inlay_hints(ls: LanguageServer, params: InlayHintParams):
    """Return inline virtual text showing register changes per instruction."""
    uri = params.text_document.uri
    doc = _get_doc(uri)
    if not doc or not doc.simulation or not doc.parsed:
        return []

    hints: list[InlayHint] = []
    text_range = params.range

    for snap in doc.simulation.snapshots:
        inst = doc.parsed.instructions[snap.instruction_index]
        line = inst.line_number - 1  # LSP is 0-based

        # respect the requested range
        if text_range.start.line > line or text_range.end.line < line:
            continue

        if snap.instruction_index == 0:
            # first instruction: show initial register state
            label = "; init: " + ", ".join(
                f"{r}=0x{snap.values[r]:X}"
                for r in sorted(snap.changed)
            )
        elif snap.changed:
            label = "; " + ", ".join(
                f"{r}=0x{snap.values[r]:X}"
                for r in sorted(snap.changed)
            )
        else:
            continue  # nothing changed, skip hint

        hints.append(InlayHint(
            position=Position(line=line, character=0),
            label=[InlayHintLabelPart(
                value=label,
                tooltip=f"Line {inst.line_number}: {inst.mnemonic} {inst.operands}",
            )],
            padding_left=False,
            padding_right=True,
            kind=None,
        ))

    return hints


# ── code lens ───────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_CODE_LENS)
def code_lens(ls: LanguageServer, params: CodeLensParams):
    """Show 'Run Simulation' button and initial register values."""
    uri = params.text_document.uri
    doc = _get_doc(uri)
    if not doc or not doc.parsed or not doc.parsed.instructions:
        return []

    lenses: list[CodeLens] = []

    # "Run Simulation" button at the top
    title = "▶ Run Register Simulation" if not doc.simulation else "⟳ Re-run Simulation"
    lenses.append(CodeLens(
        range=Range(
            start=Position(line=0, character=0),
            end=Position(line=0, character=0),
        ),
        command=Command(
            title=title,
            command="x86reg.runSimulation",
            arguments=[uri],
        ),
    ))

    # Show @reg state if set
    if doc.initial_regs:
        regs_str = ", ".join(
            f"{r}=0x{v:X}" for r, v in sorted(doc.initial_regs.items())
        )
        lenses.append(CodeLens(
            range=Range(
                start=Position(line=0, character=0),
                end=Position(line=0, character=0),
            ),
            command=Command(
                title=f"Regs: {regs_str}",
                command="",
            ),
        ))

    return lenses


# ── custom notifications (sidebar cursor tracking) ──────────────────────────


@server.feature("$/x86reg/registerAtLine")
def register_at_line(ls: LanguageServer, params):
    """Return register state snapshot for the given 0-based line."""
    uri = params.uri
    line = params.line
    doc = _get_doc(uri)
    if not doc:
        return None
    result = doc.snapshot_at_line(line)
    if result:
        return {
            "values": result["values"],
            "changed": result["changed"],
            "instruction_index": result["instruction_index"],
            "stack": result.get("stack"),
        }
    return None


# ── custom commands ─────────────────────────────────────────────────────────


@server.command("x86reg.runSimulation")
def run_simulation(ls: LanguageServer, args):
    """Execute register simulation for the given URI."""
    uri = args[0] if args else ""
    doc = _get_doc(uri)
    if doc:
        doc.run_simulation()
        _publish_diagnostics(ls, uri, doc)
        # refresh inlay hints
        server.workspace_inlay_hint_refresh()


@server.command("x86reg.setRegisters")
def set_registers(ls: LanguageServer, args):
    """Set initial register values. args: [uri, "rax=42 rbx=100"]."""
    if len(args) < 2:
        return
    uri = args[0]
    regs_str = args[1]
    doc = _get_doc(uri)
    if not doc:
        return

    for pair in regs_str.split():
        if "=" in pair:
            reg, val = pair.split("=", 1)
            try:
                doc.set_initial_reg(reg.strip(), int(val.strip(), 0))
            except ValueError:
                pass
    _publish_diagnostics(ls, uri, doc)
    server.workspace_code_lens_refresh()


# ── diagnostics ─────────────────────────────────────────────────────────────


def _publish_diagnostics(ls: LanguageServer, uri: str, doc: DocumentState):
    """Publish parse errors and simulation errors as diagnostics."""
    diagnostics: list[Diagnostic] = []

    if doc.parsed:
        for err in doc.parsed.errors:
            # try to extract line number from error message
            import re
            m = re.match(r"Line (\d+): (.*)", err)
            if m:
                lineno = int(m.group(1)) - 1
                msg = m.group(2)
            else:
                lineno = 0
                msg = err
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=lineno, character=0),
                    end=Position(line=lineno, character=0),
                ),
                message=msg,
                severity=DiagnosticSeverity.Error,
                source="x86-register-lsp",
            ))

    if doc.simulation:
        for err in doc.simulation.errors:
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=0, character=0),
                    end=Position(line=0, character=0),
                ),
                message=err,
                severity=DiagnosticSeverity.Warning,
                source="x86-register-lsp (sim)",
            ))

    ls.publish_diagnostics(uri, diagnostics)


# ── entry point ─────────────────────────────────────────────────────────────


def main():
    server.start_io()


if __name__ == "__main__":
    main()
