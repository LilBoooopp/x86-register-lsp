-- x86-register-lsp/init.lua
-- Neovim plugin: starts the LSP server, provides commands and cursor-tracking sidebar.

local sidebar = require("x86-register-lsp.sidebar")

local M = {}

function M.setup(opts)
    opts = opts or {}
    local cmd = opts.cmd or { "x86-register-lsp" }

    -- user commands
    vim.api.nvim_create_user_command("X86RegRun", function()
        local clients = vim.lsp.get_clients({ name = "x86-register-lsp" })
        if #clients == 0 then
            vim.notify("x86-register-lsp not running", vim.log.levels.WARN)
            return
        end
        clients[1].request("workspace/executeCommand", {
            command = "x86reg.runSimulation",
            arguments = { vim.uri_from_bufnr(0) },
        }, function(err)
            if err then
                vim.notify("Simulation error: " .. (err.message or "unknown"), vim.log.levels.ERROR)
            else
                vim.notify("Simulation complete", vim.log.levels.INFO)
            end
        end)
    end, {})

    vim.api.nvim_create_user_command("X86RegSidebar", function()
        sidebar.toggle()
    end, {})

    vim.api.nvim_create_user_command("X86RegSet", function(info)
        -- :X86RegSet rax=42 rbx=100
        local clients = vim.lsp.get_clients({ name = "x86-register-lsp" })
        if #clients == 0 then
            vim.notify("x86-register-lsp not running", vim.log.levels.WARN)
            return
        end
        clients[1].request("workspace/executeCommand", {
            command = "x86reg.setRegisters",
            arguments = { vim.uri_from_bufnr(0), info.args },
        })
    end, { nargs = "?" })

    -- keymaps
    vim.keymap.set("n", "<leader>xr", "<cmd>X86RegRun<cr>", { desc = "Run register simulation" })
    vim.keymap.set("n", "<leader>xs", "<cmd>X86RegSidebar<cr>", { desc = "Toggle register sidebar" })

    -- auto-start LSP for assembly files
    vim.api.nvim_create_autocmd("FileType", {
        pattern = { "asm", "nasm" },
        callback = function()
            local client_id = vim.lsp.start({
                name = "x86-register-lsp",
                cmd = cmd,
                root_dir = vim.fn.getcwd(),
            })

            if not client_id then
                return
            end

            -- cursor tracking → request register state at current line
            local augroup = vim.api.nvim_create_augroup("X86RegCursor", { clear = true })
            vim.api.nvim_create_autocmd({ "CursorMoved", "CursorMovedI" }, {
                group = augroup,
                buffer = 0,
                callback = function()
                    if not sidebar.is_open() then
                        return
                    end
                    local client = vim.lsp.get_client_by_id(client_id)
                    if not client then
                        return true -- remove autocmd
                    end
                    client.request("$/x86reg/registerAtLine", {
                        uri = vim.uri_from_bufnr(0),
                        line = vim.fn.line(".") - 1, -- 0-based
                    }, function(err, result)
                        if not err and result then
                            sidebar.update(result)
                        end
                    end)
                end,
            })
        end,
    })
end

return M
