from prometheus_client import Counter, Histogram

scans_total = Counter("kodesec_scans_total", "Scans by status", ["status"])
findings_total = Counter("kodesec_findings_total", "Findings by severity", ["severity"])
findings_by_scanner_total = Counter("kodesec_findings_by_scanner_total", "Findings by scanner and severity", ["scanner", "severity"])
scanner_tool_runs_total = Counter("kodesec_scanner_tool_runs_total", "Scanner tool runs", ["scanner", "status"])
scanner_duration = Histogram("kodesec_scanner_duration_seconds", "Scanner call duration")
advisor_duration = Histogram("kodesec_advisor_duration_seconds", "Advisor call duration")
