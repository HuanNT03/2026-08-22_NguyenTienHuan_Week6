from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TARGET_URL = "http://juice-shop:3000"
TARGET_INCLUDE = r"^http://juice-shop:3000(?:$|[/?#].*)$"


def _load_plan(name: str) -> dict:
    """Load one trusted repository-owned ZAP Automation plan for contract assertions."""
    value = yaml.safe_load((ROOT / "configs" / "zap" / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _jobs(plan: dict, job_type: str) -> list[dict]:
    """Return all jobs of a requested type from a parsed ZAP Automation plan."""
    return [job for job in plan["jobs"] if job.get("type") == job_type]


def test_all_zap_plans_define_the_exact_protected_target_context() -> None:
    for name in ("baseline.yaml", "baseline-low-memory.yaml", "full.yaml"):
        plan = _load_plan(name)
        context = plan["env"]["contexts"][0]
        assert context == {
            "name": "juice-shop",
            "urls": [TARGET_URL],
            "includePaths": [TARGET_INCLUDE],
        }
        assert plan["env"]["configs"]["view.mode"] == "protect"
        passive_config = _jobs(plan, "passiveScan-config")
        assert passive_config[0]["parameters"]["scanOnlyInScope"] is True


def test_spiders_are_explicitly_bound_to_juice_shop() -> None:
    for name in ("baseline.yaml", "baseline-low-memory.yaml", "full.yaml"):
        plan = _load_plan(name)
        spiders = _jobs(plan, "spider") + _jobs(plan, "spiderClient")
        assert spiders
        for spider in spiders:
            assert spider["parameters"]["context"] == "juice-shop"
            assert spider["parameters"]["url"] == TARGET_URL
        for spider in _jobs(plan, "spiderClient"):
            assert spider["parameters"]["scopeCheck"] == "Strict"

    assert not _jobs(_load_plan("baseline-low-memory.yaml"), "spiderClient")
    assert _jobs(_load_plan("baseline.yaml"), "spiderClient")


def test_only_full_plan_runs_an_explicitly_scoped_active_scan() -> None:
    for name in ("baseline.yaml", "baseline-low-memory.yaml"):
        assert not _jobs(_load_plan(name), "activeScan")

    full_plan = _load_plan("full.yaml")
    active_scan = _jobs(full_plan, "activeScan")
    assert len(active_scan) == 1
    assert active_scan[0]["parameters"]["context"] == "juice-shop"
    assert active_scan[0]["parameters"]["url"] == TARGET_URL
    assert full_plan["env"]["configs"]["scanner.maxScanDurationInMins"] == 30


def test_all_plans_generate_the_existing_json_report_contract() -> None:
    for name in ("baseline.yaml", "baseline-low-memory.yaml", "full.yaml"):
        reports = _jobs(_load_plan(name), "report")
        assert len(reports) == 1
        assert reports[0]["parameters"] == {
            "template": "traditional-json",
            "reportDir": "/zap/wrk",
            "reportFile": "zap.json",
            "displayReport": False,
        }


def test_all_plans_export_scoped_urls_and_sites_tree() -> None:
    expected_exports = [
        {
            "context": "juice-shop",
            "type": "url",
            "source": "all",
            "fileName": "/zap/wrk/zap-endpoints.txt",
        },
        {
            "context": "juice-shop",
            "type": "yaml",
            "source": "sitestree",
            "fileName": "/zap/wrk/zap-site-tree.yaml",
        },
    ]
    for name in ("baseline.yaml", "baseline-low-memory.yaml", "full.yaml"):
        exports = _jobs(_load_plan(name), "export")
        assert [job["parameters"] for job in exports] == expected_exports
        assert all(job["alwaysRun"] is True for job in exports)
