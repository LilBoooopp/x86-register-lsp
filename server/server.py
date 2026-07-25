import logging
from pygls.lsp.server import LanguageServer
from lsprotocol.types import (
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_CHANGE,
    DidOpenTextDocumentParams,
    DidChangeTextDocumentParams,
)

logging.basicConfig(level=logging.DEBUG, filename="/tmp/x86-register-lsp.log")

server = LanguageServer("x86-register-lsp", "v0.1.0")


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: LanguageServer, params: DidOpenTextDocumentParams):
    """Called when Neovim opens a .s or .asm file."""
    ls.show_message(f"Opened {params.text_document.uri}")


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: LanguageServer, params: DidChangeTextDocumentParams):
    pass  # stub for now


def main():
    server.start_io()


if __name__ == "__main__":
    main()
