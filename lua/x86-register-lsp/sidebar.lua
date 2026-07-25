-- x86-register-lsp/sidebar.lua
-- Floating sidebar showing full register state at cursor position.
-- Updates on CursorMoved via LSP custom request.

local M = {}

local buf = nil
local win = nil
local ns_id = vim.api.nvim_create_namespace("x86-register-sidebar")

local GP_ORDER = {
    "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip",
}


function M.is_open()
    return win and vim.api.nvim_win_is_valid(win)
end


function M.open()
    if win and vim.api.nvim_win_is_valid(win) then
        vim.api.nvim_set_current_win(win)
        return
    end

    buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_option(buf, "buftype", "nofile")
    vim.api.nvim_buf_set_option(buf, "bufhidden", "wipe")
    vim.api.nvim_buf_set_option(buf, "modifiable", false)
    vim.api.nvim_buf_set_name(buf, "x86-registers://")

    local width = 30
    local height = vim.o.lines - 4
    win = vim.api.nvim_open_win(buf, false, {
        relative = "editor",
        width = width,
        height = height,
        row = 1,
        col = vim.o.columns - width - 1,
        style = "minimal",
        border = "single",
        title = " Registers ",
        title_pos = "center",
    })

    vim.api.nvim_win_set_option(win, "cursorline", true)

    -- initial placeholder
    M.update(nil)
end


function M.close()
    if win and vim.api.nvim_win_is_valid(win) then
        vim.api.nvim_win_close(win, true)
    end
    win = nil
    buf = nil
end


function M.toggle()
    if win and vim.api.nvim_win_is_valid(win) then
        M.close()
    else
        M.open()
    end
end


function M.update(register_state)
    -- register_state: { values = {rax=42, ...}, changed = {"rcx", ...}, instruction_index = N }
    if not buf or not vim.api.nvim_buf_is_valid(buf) then
        return
    end

    local lines = {}
    local highlights = {}

    if not register_state or not register_state.values then
        table.insert(lines, "  Run :X86RegRun")
        table.insert(lines, "  to see register state")
    else
        local idx = (register_state.instruction_index or 0) + 1
        table.insert(lines, string.format("  Instruction: %d", idx))
        table.insert(lines, "  ──────────────────────────")
        table.insert(lines, string.format("  %-4s  %-18s", "Reg", "Value"))
        table.insert(lines, "  ──────────────────────────")

        local vals = register_state.values or {}
        local changed = register_state.changed or {}

        for _, reg in ipairs(GP_ORDER) do
            local val = vals[reg]
            if val then
                local line_text
                if val > 0xFFFFFFFF then
                    line_text = string.format("  %-4s  0x%016X", reg, val)
                else
                    line_text = string.format("  %-4s  0x%X", reg, val)
                end

                table.insert(lines, line_text)

                if vim.tbl_contains(changed, reg) then
                    table.insert(highlights, {
                        line = #lines - 1,
                        col_start = 0,
                        col_end = -1,
                        group = "DiffAdd",
                    })
                end
            end
        end

        -- stack display
        local stack = register_state.stack
        if stack and #stack > 0 then
            table.insert(lines, "")
            table.insert(lines, "  ── Stack (RSP→) ──")
            for i, qword in ipairs(stack) do
                local marker = (i == 1) and "→" or " "
                if qword ~= 0 then
                    table.insert(lines, string.format("  %s +%02d  0x%016X", marker, (i - 1) * 8, qword))
                end
            end
        end
    end

    vim.api.nvim_buf_set_option(buf, "modifiable", true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.api.nvim_buf_set_option(buf, "modifiable", false)

    -- apply highlights
    vim.api.nvim_buf_clear_namespace(buf, ns_id, 0, -1)
    for _, hl in ipairs(highlights) do
        vim.api.nvim_buf_add_highlight(
            buf, ns_id, hl.group, hl.line, hl.col_start, hl.col_end
        )
    end
end


return M
