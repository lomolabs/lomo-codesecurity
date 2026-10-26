"""Runtime-only process-local measurements; never canonical result evidence."""
from prometheus_client import Histogram


# Process-local telemetry is deliberately separate from canonical scan results.
# Labels are limited to the curated external-tool IDs admitted by the adapter.
adapter_duration = Histogram(
    "kodesec_scanner_tool_adapter_duration_seconds",
    "Whole adapter invocation elapsed time, including parsing, artifacts and scratch cleanup",
    ["scanner"],
)


