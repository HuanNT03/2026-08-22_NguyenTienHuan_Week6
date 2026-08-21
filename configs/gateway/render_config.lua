-- ==============================================================================
-- PROJECT SENTINEL - KONG DECLARATIVE CONFIG RENDERER (BOOT-TIME LUAJIT)
-- File: configs/gateway/render_config.lua
-- Purpose: Đọc allowlist.json, trích xuất danh sách endpoint cho phép của AI Agent,
--          format thành chuỗi Lua table ["/path"] = true và thay thế các placeholder
--          (${ALLOWED_PATHS_LUA}, ${AGENT_API_KEY}) trong kong.yml.template
--          xuất ra tệp cấu hình hoàn chỉnh /tmp/kong.yml trước khi Kong khởi động.
-- Inputs:
--   - Template File: /usr/local/kong/declarative/kong.yml.template
--   - Allowlist File: /usr/local/kong/declarative/allowlist.json
--   - Environment Variables: KONG_VAULT_ENV_AGENT_API_KEY, AGENT_API_KEY
-- Output:
--   - Generated Declarative File: /tmp/kong.yml
-- ==============================================================================

-- Nạp cjson từ OpenResty LuaJIT
package.cpath = package.cpath .. ";/usr/local/openresty/lualib/?.so"
local cjson = require("cjson")

-- Danh sách endpoints mặc định cho Agent khi file bị rỗng hoặc lỗi JSON
local DEFAULT_AGENT_PATHS = {
    "/api/Quantitys",
    "/rest/products/search",
    "/rest/user/login",
    "/api/Products",
    "/rest/user/whoami"
}

--- Đọc toàn bộ nội dung của tệp tin
-- @param file_path Đường dẫn tuyệt đối tới tệp tin
-- @return Content (string) hoặc nil nếu đọc thất bại
local function read_file(file_path)
    local f, err = io.open(file_path, "r")
    if not f then
        return nil, err
    end
    local content = f:read("*a")
    f:close()
    return content
end

--- Ghi nội dung vào tệp tin
-- @param file_path Đường dẫn tuyệt đối tới tệp tin đích
-- @param content Chuỗi dữ liệu cần ghi
-- @return boolean (true nếu thành công, false nếu thất bại)
local function write_file(file_path, content)
    local f, err = io.open(file_path, "w")
    if not f then
        return false, err
    end
    f:write(content)
    f:close()
    return true
end

--- Loại bỏ khoảng trắng ở 2 đầu chuỗi (Trim whitespace)
-- @param s Chuỗi đầu vào
-- @return Chuỗi đã được làm sạch
local function trim(s)
    if type(s) ~= "string" then return "" end
    return s:match("^%s*(.-)%s*$")
end

--- Trích xuất danh sách allowed paths cho AI Agent từ allowlist.json
-- @param allowlist_path Đường dẫn file allowlist.json
-- @return Bảng chứa danh sách các path hợp lệ (table array)
local function get_agent_allowed_paths(allowlist_path)
    local raw_json, err = read_file(allowlist_path)
    if not raw_json or trim(raw_json) == "" then
        print("[WARN] File allowlist.json rỗng hoặc không tồn tại. Tự động sử dụng Default Fallback Agent Allowlist.")
        return DEFAULT_AGENT_PATHS
    end

    local success, decoded = pcall(cjson.decode, raw_json)
    if not success or type(decoded) ~= "table" then
        print("[WARN] Cú pháp JSON trong allowlist.json bị lỗi: " .. tostring(decoded) .. ". Sử dụng Default Fallback Agent Allowlist.")
        return DEFAULT_AGENT_PATHS
    end

    local valid_paths = {}
    local seen = {}

    -- Kiểm tra cấu trúc routes trong allowlist.json
    if type(decoded.routes) == "table" then
        for _, route in ipairs(decoded.routes) do
            local is_agent_allowed = false
            if type(route.allow) == "table" then
                for _, client in ipairs(route.allow) do
                    if client == "agent" then
                        is_agent_allowed = true
                        break
                    end
                end
            end

            if is_agent_allowed and type(route.paths) == "table" then
                for _, p in ipairs(route.paths) do
                    if type(p) == "string" then
                        local clean_path = trim(p)
                        if clean_path ~= "" and not clean_path:match("^~") and not seen[clean_path] then
                            seen[clean_path] = true
                            table.insert(valid_paths, clean_path)
                        end
                    end
                end
            end
        end
    end

    -- Fallback nếu không tìm thấy path nào
    if #valid_paths == 0 then
        print("[WARN] Không tìm thấy route nào cấp quyền cho 'agent' trong allowlist.json. Sử dụng Default Fallback Agent Allowlist.")
        return DEFAULT_AGENT_PATHS
    end

    return valid_paths
end

--- Hàm thực thi chính (Main Entrypoint)
local function main()
    local template_path = "/usr/local/kong/declarative/kong.yml.template"
    local allowlist_path = "/usr/local/kong/declarative/allowlist.json"
    local output_path = "/tmp/kong.yml"

    -- 1. Trích xuất danh sách path cho Agent và chuyển đổi thành chuỗi Lua lookup table: ["/path"] = true
    local paths = get_agent_allowed_paths(allowlist_path)
    local lua_entries = {}
    for _, p in ipairs(paths) do
        local safe_p = p:gsub('"', '\\"')
        table.insert(lua_entries, string.format('["%s"] = true', safe_p))
    end
    local lua_table_str = table.concat(lua_entries, ", ")

    -- 2. Đọc tệp template kong.yml.template
    local template_content, err = read_file(template_path)
    if not template_content then
        error("[ERROR] Không thể đọc template kong.yml.template: " .. tostring(err))
    end

    -- 3. Lấy API Key từ biến môi trường
    local agent_api_key = os.getenv("KONG_VAULT_ENV_AGENT_API_KEY") 
        or os.getenv("AGENT_API_KEY") 
        or "sentinel-agent-secure-key-2026"

    -- 4. Thay thế placeholder ${ALLOWED_PATHS_LUA} và ${AGENT_API_KEY}
    local rendered = template_content:gsub("%$%{ALLOWED_PATHS_LUA%}", lua_table_str)
    rendered = rendered:gsub("%$%{AGENT_API_KEY%}", agent_api_key)

    -- 5. Ghi kết quả hoàn chỉnh ra /tmp/kong.yml
    local ok, write_err = write_file(output_path, rendered)
    if not ok then
        error("[ERROR] Không thể ghi kết quả ra /tmp/kong.yml: " .. tostring(write_err))
    end

    print(string.format("[SUCCESS] Đã render thành công /tmp/kong.yml với %d allowed endpoints cho AI Agent.", #paths))
end

main()
