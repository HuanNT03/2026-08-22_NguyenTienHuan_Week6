"""Unit and contract tests for Kong API Gateway configuration files, allowlist matrix, and Lua renderer."""

import json
from pathlib import Path

import yaml

GATEWAY_DIR = Path(__file__).parent.parent.parent / "src" / "gateway"
ROOT_DIR = Path(__file__).parent.parent.parent


def test_allowlist_json_structure_and_clients() -> None:
    """Verify that allowlist.json is valid and contains the required Client-First schema."""
    allowlist_path = GATEWAY_DIR / "allowlist.json"
    assert allowlist_path.is_file(), "src/gateway/allowlist.json must exist"

    with open(allowlist_path, encoding="utf-8") as f:
        data = json.load(f)

    assert "clients" in data, "allowlist.json must define 'clients'"
    assert "routes" in data, "allowlist.json must define 'routes'"

    # Verify 3 required client categories
    clients = data["clients"]
    assert "agent" in clients
    assert "guest" in clients
    assert "user" in clients

    assert clients["agent"]["consumer"] == "ai-agent"
    assert clients["agent"]["auth_method"] == "key-auth"
    assert clients["agent"]["rate_limit_per_minute"] == 20

    assert clients["guest"]["consumer"] == "anonymous-user"
    assert clients["guest"]["auth_method"] == "anonymous"
    assert clients["guest"]["rate_limit_per_minute"] == 60

    assert clients["user"]["consumer"] == "juice-shop-users"
    assert clients["user"]["auth_method"] == "jwt"
    assert clients["user"]["rate_limit_per_minute"] == 100

    # Verify routes
    routes = data["routes"]
    assert len(routes) >= 10, "Must have at least 10 defined routes"
    allowed_client_keys = {"agent", "guest", "user"}

    for route in routes:
        assert "name" in route
        assert "paths" in route and isinstance(route["paths"], list) and len(route["paths"]) > 0
        assert "methods" in route and isinstance(route["methods"], list) and len(route["methods"]) > 0
        assert "allow" in route and isinstance(route["allow"], list) and len(route["allow"]) > 0
        for client in route["allow"]:
            assert client in allowed_client_keys, f"Unknown client '{client}' in route '{route['name']}'"


def test_allowlist_no_dangerous_wildcards() -> None:
    """Verify that no route permits unrestricted root '/' wildcard for dangerous HTTP methods."""
    allowlist_path = GATEWAY_DIR / "allowlist.json"
    with open(allowlist_path, encoding="utf-8") as f:
        data = json.load(f)

    for route in data["routes"]:
        # If paths contains literal "/", methods must strictly be read-only (GET, HEAD, OPTIONS)
        if "/" in route["paths"]:
            assert set(route["methods"]).issubset({"GET", "HEAD", "OPTIONS"}), (
                f"Route '{route['name']}' exposes wildcard '/' to dangerous methods: {route['methods']}"
            )

    # Verify route-guest-register does not allow agent
    guest_reg = next((r for r in data["routes"] if r["name"] == "route-guest-register"), None)
    assert guest_reg is not None, "route-guest-register must be defined"
    assert "agent" not in guest_reg["allow"], "agent must not be allowed in route-guest-register"


def test_payloads_json_validity() -> None:
    """Verify that payloads.json is valid and contains standard security test payload groups."""
    payloads_path = GATEWAY_DIR / "payloads.json"
    assert payloads_path.is_file(), "src/gateway/payloads.json must exist"

    with open(payloads_path, encoding="utf-8") as f:
        data = json.load(f)

    assert "payload_groups" in data
    groups = data["payload_groups"]
    assert "boundary_testing" in groups
    assert "character_encoding" in groups
    assert "sql_injection_probes" in groups
    assert "cross_site_scripting_probes" in groups


def test_kong_template_structure_and_placeholders() -> None:
    """Verify that kong.yml.template contains all necessary declarative sections and placeholders."""
    template_path = GATEWAY_DIR / "kong.yml.template"
    assert template_path.is_file(), "src/gateway/kong.yml.template must exist"

    content = template_path.read_text(encoding="utf-8")
    assert "${GENERATED_ROUTES_YAML}" in content, "Template must contain ${GENERATED_ROUTES_YAML} placeholder"
    assert "${ALLOWED_PATHS_LUA}" in content, "Template must contain ${ALLOWED_PATHS_LUA} placeholder"
    assert "${AGENT_API_KEY}" in content, "Template must contain ${AGENT_API_KEY} placeholder"

    # Simulate dynamic routes generation from allowlist.json to verify valid YAML compilation
    allowlist_path = GATEWAY_DIR / "allowlist.json"
    with open(allowlist_path, encoding="utf-8") as f:
        data = json.load(f)

    route_blocks = []
    for route in data["routes"]:
        r_name = route["name"]
        paths_str = "\n".join(f"          - {p}" for p in route["paths"])
        methods_str = "\n".join(f"          - {m}" for m in route["methods"])
        block = f"""      - name: {r_name}
        paths:
{paths_str}
        methods:
{methods_str}
        strip_path: false"""
        route_blocks.append(block)

    simulated_routes_yaml = "\n\n".join(route_blocks)

    simulated_yaml = (
        content.replace("${GENERATED_ROUTES_YAML}", simulated_routes_yaml)
        .replace("${ALLOWED_PATHS_LUA}", '["/api/Products"] = true')
        .replace("${AGENT_API_KEY}", "test-key-123")
    )
    parsed = yaml.safe_load(simulated_yaml)

    assert parsed.get("_format_version") == "3.0"
    assert "services" in parsed and len(parsed["services"]) > 0
    service = parsed["services"][0]
    assert service["name"] == "juice-shop-service"
    assert service["host"] == "juice-shop"
    assert service["port"] == 3000
    assert "routes" in service and len(service["routes"]) == len(data["routes"])
    assert "consumers" in parsed and len(parsed["consumers"]) >= 3
    assert "plugins" in parsed and len(parsed["plugins"]) >= 3


def test_lua_renderer_script_exists_and_syntax() -> None:
    """Verify that render_config.lua exists and contains required dynamic route compilation logic."""
    lua_path = GATEWAY_DIR / "render_config.lua"
    assert lua_path.is_file(), "src/gateway/render_config.lua must exist"

    content = lua_path.read_text(encoding="utf-8")
    assert "DEFAULT_AGENT_PATHS" in content
    assert "DEFAULT_FALLBACK_ROUTES_YAML" in content
    assert "cjson" in content
    assert "extract_agent_paths" in content
    assert "generate_routes_yaml" in content
    assert "GENERATED_ROUTES_YAML" in content
    assert "ALLOWED_PATHS_LUA" in content
    assert "AGENT_API_KEY" in content


def test_env_example_has_gateway_variables() -> None:
    """Verify that .env.example contains separated gateway and agent API keys."""
    env_path = ROOT_DIR / ".env.example"
    assert env_path.is_file(), ".env.example must exist"

    content = env_path.read_text(encoding="utf-8")
    assert "KONG_VAULT_ENV_AGENT_API_KEY=" in content
    assert "AGENT_API_KEY=" in content
    assert "GATEWAY_HOST=" in content
    assert "GATEWAY_PORT=" in content
    assert "KONG_ADMIN_PORT=" in content


def test_docker_compose_gateway_override() -> None:
    """Verify that docker-compose.gateway.yml defines kong-gateway and isolates juice-shop."""
    compose_gw_path = ROOT_DIR / "docker-compose.gateway.yml"
    assert compose_gw_path.is_file(), "docker-compose.gateway.yml must exist"

    with open(compose_gw_path, encoding="utf-8") as f:
        content = f.read()

    assert "kong:3.6.1" in content
    assert "sentinel-kong-gateway" in content
    assert "render_config.lua" in content
    assert "KONG_DATABASE" in content
