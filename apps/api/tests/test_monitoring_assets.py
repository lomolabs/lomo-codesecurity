from __future__ import annotations

import json
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_monitoring_assets_use_only_product_metrics_without_host_telemetry() -> None:
    prometheus = yaml.safe_load(
        (REPO_ROOT / "infra/prometheus/prometheus.yml").read_text(encoding="utf-8")
    )
    assert prometheus == {
        "global": {"scrape_interval": "15s"},
        "scrape_configs": [
            {
                "job_name": "kodesec-api",
                "static_configs": [{"targets": ["api:8080"]}],
            },
            {
                "job_name": "kodesec-scanner",
                "static_configs": [{"targets": ["scanner:8091"]}],
            },
        ],
    }

    dashboard = json.loads(
        (REPO_ROOT / "infra/grafana/dashboards/kodesec-overview.json").read_text(
            encoding="utf-8"
        )
    )
    panels = dashboard["panels"]
    process_panels = {
        panel["title"]: panel["targets"][0]["expr"]
        for panel in panels
        if panel.get("id") in {14, 15, 16, 17}
    }
    assert process_panels == {
        "API Process CPU %": (
            'sum(rate(process_cpu_seconds_total{job="kodesec-api"}[2m]) * 100) '
            "by (instance)"
        ),
        "API Process Memory": (
            'sum(process_resident_memory_bytes{job="kodesec-api"}) by (instance)'
        ),
        "Scanner Process CPU %": (
            'sum(rate(process_cpu_seconds_total{job="kodesec-scanner"}[2m]) * 100) '
            "by (instance)"
        ),
        "Scanner Process Memory": (
            'sum(process_resident_memory_bytes{job="kodesec-scanner"}) by (instance)'
        ),
    }
    serialized_assets = json.dumps(
        {"prometheus": prometheus, "dashboard": dashboard},
        sort_keys=True,
    ).lower()
    assert "cadvisor" not in serialized_assets
    assert "container_" not in serialized_assets
