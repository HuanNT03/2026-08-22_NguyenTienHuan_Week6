-- ==============================================================================
-- PROJECT SENTINEL - KONG DECLARATIVE CONFIG RENDERER (BOOT-TIME LUAJIT)
-- File: src/gateway/render_config.lua
-- Purpose: Đọc allowlist.json, tự động sinh:
--          1. Khối YAML routes (${GENERATED_ROUTES_YAML}) cho Kong Gateway.
--          2. Bảng tra cứu allowed endpoints cho AI Agent (${ALLOWED_PATHS_LUA}).
--          3. Điền API Key (${AGENT_API_KEY}) vào kong.yml.template
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

-- Khối routes YAML mặc định an toàn khi không đọc được allowlist.json
local DEFAULT_FALLBACK_ROUTES_YAML = [[
      - name: route-spa-root
        paths:
          - ~/$
          - /index.html
        methods:
          - GET
          - HEAD
          - OPTIONS
        strip_path: false
        plugins:
          - name: acl
            config:
              allow:
                - agent-group
                - guest-group
                - user-group

      - name: route-spa-assets
        paths:
          - /assets
          - /vendor
          - ~/[a-zA-Z0-9_.-]+\.(js|css|ico|png|svg|woff2?|map)$
        methods:
          - GET
          - HEAD
          - OPTIONS
        strip_path: false
        plugins:
          - name: acl
            config:
              allow:
                - agent-group
                - guest-group
                - user-group

      - name: route-products-browse
        paths:
          - /api/Products
          - /rest/products/search
        methods:
          - GET
          - OPTIONS
        strip_path: false
        plugins:
          - name: acl
            config:
              allow:
                - agent-group
                - guest-group
                - user-group

      - name: route-user-login
        paths:
          - /rest/user/login
        methods:
          - POST
          - OPTIONS
        strip_path: false
        plugins:
          - name: acl
            config:
              allow:
                - agent-group
                - guest-group
                - user-group
]]

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

--- Trích xuất danh sách allowed paths cho AI Agent từ dữ liệu JSON đã giải mã
-- @param decoded Bảng Lua parse từ allowlist.json
-- @return Bảng chứa danh sách các path hợp lệ (table array)
local function extract_agent_paths(decoded)
    if type(decoded) ~= "table" or type(decoded.routes) ~= "table" then
        return DEFAULT_AGENT_PATHS
    end

    local valid_paths = {}
    local seen = {}

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

    if #valid_paths == 0 then
        return DEFAULT_AGENT_PATHS
    end

    return valid_paths
end

--- Tự động sinh khối cấu hình YAML 'routes:' cho Kong Gateway từ dữ liệu allowlist.json
-- Theo chuẩn Client-First & Route-level ACL Enforcement:
-- Mỗi route được gán trực tiếp plugin 'acl' với danh sách allow tương ứng
-- (agent -> agent-group, guest -> guest-group, user -> user-group)
-- @param decoded Bảng Lua parse từ allowlist.json
-- @return Chuỗi YAML chứa toàn bộ routes đã được định dạng chuẩn
local function generate_routes_yaml(decoded)
    if type(decoded) ~= "table" or type(decoded.routes) ~= "table" or #decoded.routes == 0 then
        return DEFAULT_FALLBACK_ROUTES_YAML
    end

    local route_blocks = {}
    for idx, route in ipairs(decoded.routes) do
        local name = route.name or string.format("route-%d", idx)
        local paths = route.paths or {}
        local methods = route.methods or {"GET"}
        local allow = route.allow or {"agent", "guest", "user"}

        local lines = {}
        table.insert(lines, string.format("      - name: %s", name))
        table.insert(lines, "        paths:")
        for _, p in ipairs(paths) do
            table.insert(lines, string.format("          - %s", p))
        end
        table.insert(lines, "        methods:")
        for _, m in ipairs(methods) do
            table.insert(lines, string.format("          - %s", m))
        end
        table.insert(lines, "        strip_path: false")

        -- Route-Level ACL Plugin: Enforces strict group access per route
        if type(allow) == "table" and #allow > 0 then
            table.insert(lines, "        plugins:")
            table.insert(lines, "          - name: acl")
            table.insert(lines, "            config:")
            table.insert(lines, "              allow:")
            for _, client in ipairs(allow) do
                local group = string.format("%s-group", client)
                table.insert(lines, string.format("                - %s", group))
            end
        end

        table.insert(route_blocks, table.concat(lines, "\n"))
    end

    return table.concat(route_blocks, "\n\n")
end

--- Hàm thực thi chính (Main Entrypoint)
local function main()
    local template_path = "/usr/local/kong/declarative/kong.yml.template"
    local allowlist_path = "/usr/local/kong/declarative/allowlist.json"
    local output_path = "/tmp/kong.yml"

    -- 1. Đọc tệp allowlist.json
    local raw_json, _ = read_file(allowlist_path)
    local decoded = nil
    if raw_json and trim(raw_json) ~= "" then
        local success, res = pcall(cjson.decode, raw_json)
        if success and type(res) == "table" then
            decoded = res
        else
            print("[WARN] Cú pháp JSON trong allowlist.json bị lỗi. Kích hoạt Fallback.")
        end
    else
        print("[WARN] File allowlist.json rỗng hoặc không tồn tại. Kích hoạt Fallback.")
    end

    -- 2. Trích xuất danh sách path cho Agent và chuyển đổi thành chuỗi Lua lookup table: ["/path"] = true
    local agent_paths = extract_agent_paths(decoded)
    local lua_entries = {}
    for _, p in ipairs(agent_paths) do
        local safe_p = p:gsub('"', '\\"')
        table.insert(lua_entries, string.format('["%s"] = true', safe_p))
    end
    local lua_table_str = table.concat(lua_entries, ", ")

    -- 3. Tự động sinh khối YAML cho toàn bộ các Routes từ allowlist.json
    local generated_routes_yaml = generate_routes_yaml(decoded)

    -- 4. Đọc tệp template kong.yml.template
    local template_content, err = read_file(template_path)
    if not template_content then
        error("[ERROR] Không thể đọc template kong.yml.template: " .. tostring(err))
    end

    -- 5. Lấy API Key từ biến môi trường
    local agent_api_key = os.getenv("KONG_VAULT_ENV_AGENT_API_KEY") 
        or os.getenv("AGENT_API_KEY") 
        or "sentinel-agent-secure-key-2026"

    -- 6. Thay thế placeholder ${GENERATED_ROUTES_YAML}, ${ALLOWED_PATHS_LUA} và ${AGENT_API_KEY}
    local rendered = template_content:gsub("%$%{GENERATED_ROUTES_YAML%}", generated_routes_yaml)
    rendered = rendered:gsub("%$%{ALLOWED_PATHS_LUA%}", lua_table_str)
    rendered = rendered:gsub("%$%{AGENT_API_KEY%}", agent_api_key)

    -- 7. Ghi kết quả hoàn chỉnh ra /tmp/kong.yml
    local ok, write_err = write_file(output_path, rendered)
    if not ok then
        error("[ERROR] Không thể ghi kết quả ra /tmp/kong.yml: " .. tostring(write_err))
    end

    local num_routes = (decoded and type(decoded.routes) == "table") and #decoded.routes or 4
    print(string.format("[SUCCESS] Đã render thành công /tmp/kong.yml với %d routes và %d allowed endpoints cho AI Agent.", num_routes, #agent_paths))
end

main()
