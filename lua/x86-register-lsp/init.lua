-- x86-register-lsp/init.lua
-- Bare plugin skeleton — starts the LSP server for .s/.asm files

local M = {}

function M.setup(opts)
    opts = opts or {}
    local cmd = opts.cmd or { "x86-register-lsp" }

    vim.api.nvim_create_autocmd("FileType", {
        pattern = { "asm", "nasm" },
        callback = function()
            vim.lsp.start({
                name = "x86-register-lsp",
                cmd = cmd,
                root_dir = vim.fn.getcwd(),
            })
        end,
    })
end

return M
