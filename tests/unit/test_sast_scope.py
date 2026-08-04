import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-sast-scope.py"


def _patterns(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _validate(tmp_path: Path, tool: str, payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    report = tmp_path / f"{tool}.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--tool", tool, "--report", str(report)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_semgrep_and_codeql_scope_configs_are_equivalent() -> None:
    includes = _patterns(ROOT / "configs/semgrep/includes.txt")
    excludes = _patterns(ROOT / "configs/semgrep/.semgrepignore")
    codeql = yaml.safe_load((ROOT / "configs/codeql/code-scanning.yml").read_text(encoding="utf-8"))

    assert codeql["paths"] == includes
    assert codeql["paths-ignore"] == excludes


def test_semgrep_scope_accepts_runtime_sources(tmp_path: Path) -> None:
    payload = {
        "paths": {
            "scanned": [
                "/src/target-app/juice-shop/routes/login.ts",
                "/src/target-app/juice-shop/lib/startup/validateConfig.ts",
                "/src/target-app/juice-shop/frontend/src/hacking-instructor/index.ts",
                "/src/target-app/juice-shop/data/datacreator.ts",
            ]
        },
        "results": [{"path": "/src/target-app/juice-shop/routes/login.ts"}],
    }

    result = _validate(tmp_path, "semgrep", payload)

    assert result.returncode == 0, result.stderr
    assert "scope is valid" in result.stdout


def test_semgrep_scope_rejects_non_runtime_sources(tmp_path: Path) -> None:
    forbidden = [
        ".github/workflows/ci.yml",
        "data/static/codefixes/unionSqlInjectionChallenge_1.ts",
        "test/api/login.test.ts",
        "frontend/src/app/login/login.component.spec.ts",
        "node_modules/example/index.js",
        "frontend/dist/main.js",
    ]
    payload = {
        "paths": {"scanned": [f"/src/target-app/juice-shop/{path}" for path in forbidden]},
        "results": [],
    }

    result = _validate(tmp_path, "semgrep", payload)

    assert result.returncode == 1
    assert "out-of-scope" in result.stderr
    for path in forbidden:
        assert path in result.stderr


def test_codeql_scope_checks_sarif_artifacts_and_data_flow_locations(tmp_path: Path) -> None:
    valid = {
        "runs": [
            {
                "artifacts": [{"location": {"uri": "server.ts"}}],
                "results": [
                    {
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "routes/search.ts"}}}],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {"artifactLocation": {"uri": "data/mongodb.ts"}}
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }
    invalid = {
        "runs": [
            {
                "artifacts": [{"location": {"uri": "test/api/search.test.ts"}}],
                "results": [],
            }
        ]
    }

    valid_result = _validate(tmp_path, "codeql", valid)
    invalid_result = _validate(tmp_path, "codeql", invalid)

    assert valid_result.returncode == 0, valid_result.stderr
    assert invalid_result.returncode == 1
    assert "test/api/search.test.ts" in invalid_result.stderr
