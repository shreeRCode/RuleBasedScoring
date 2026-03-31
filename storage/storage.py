# storage/storage.py
import csv
import os
import logging
from dataclasses import fields, asdict
from datetime import datetime

from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# Output file for fully scored records
DEFAULT_SCORED_PATH = "data/scored_records.csv"

# Frequency counter store (read by frequency.py, updated here)
DEFAULT_COUNTERS_PATH = "data/counters.csv"

# Columns written to scored_records.csv — ordered for readability
SCORED_COLUMNS = [
    "timestamp",
    "host",
    "service",
    "log_level",
    "event_type",
    "event_action",
    "template_id",
    "message",
    # Scores
    "severity_score",
    "event_type_score",
    "anomaly_score",
    "event_weight",
    "frequency",
    "correlation_id",
    "correlation_score",
    "importance_score",
    "label",
]


# ---------------------------------------------------------------------------
# Write API
# ---------------------------------------------------------------------------

def append_records(
    records: list[LogRecord],
    scored_path: str = DEFAULT_SCORED_PATH,
) -> int:
    """
    Append a list of scored LogRecord objects to the output CSV.

    Creates the file with a header row if it does not exist.
    Returns the number of rows written.
    """
    _ensure_dir(scored_path)
    write_header = not os.path.exists(scored_path)

    written = 0
    with open(scored_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SCORED_COLUMNS, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        for record in records:
            row = _record_to_row(record)
            writer.writerow(row)
            written += 1

    logger.info("append_records: wrote %d rows to %s", written, scored_path)
    return written


def update_counters(
    records: list[LogRecord],
    counters_path: str = DEFAULT_COUNTERS_PATH,
) -> None:
    """
    Merge new template hit counts into data/counters.csv.

    counters.csv schema: template_id, count
    Called after every pipeline run so frequency.py sees updated counts
    on the next invocation.
    """
    _ensure_dir(counters_path)

    # Load existing counts
    existing: dict[str, int] = {}
    if os.path.exists(counters_path):
        with open(counters_path, "r", newline="") as fh:
            for row in csv.DictReader(fh):
                existing[row["template_id"]] = int(row.get("count", 0))

    # Merge in counts from this batch
    for record in records:
        tid = record.template_id or "UNKNOWN"
        existing[tid] = existing.get(tid, 0) + 1

    # Rewrite full file (counters are small — full rewrite is fine)
    with open(counters_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["template_id", "count"])
        writer.writeheader()
        for template_id, count in sorted(existing.items()):
            writer.writerow({"template_id": template_id, "count": count})

    logger.info("update_counters: %d templates in %s", len(existing), counters_path)


# ---------------------------------------------------------------------------
# Read API (used by query.py)
# ---------------------------------------------------------------------------

def read_records(
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """
    Load all rows from the scored CSV as plain dicts.

    Returns an empty list if the file does not exist.
    Each dict has keys matching SCORED_COLUMNS.
    """
    if not os.path.exists(scored_path):
        logger.warning("read_records: %s not found — returning empty list", scored_path)
        return []

    rows = []
    with open(scored_path, "r", newline="") as fh:
        for row in csv.DictReader(fh):
            # Coerce numeric fields back from string
            for num_field in (
                "severity_score", "event_type_score", "anomaly_score",
                "event_weight", "frequency", "correlation_score", "importance_score",
            ):
                try:
                    row[num_field] = float(row[num_field])
                except (ValueError, KeyError):
                    row[num_field] = 0.0
            rows.append(row)

    logger.debug("read_records: loaded %d rows from %s", len(rows), scored_path)
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record_to_row(record: LogRecord) -> dict:
    """Extract only the SCORED_COLUMNS fields from a LogRecord."""
    full = asdict(record)
    return {col: full.get(col, "") for col in SCORED_COLUMNS}


def _ensure_dir(path: str) -> None:
    """Create parent directory if it doesn't exist."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    with tempfile.TemporaryDirectory() as tmp:
        scored = os.path.join(tmp, "data", "scored_records.csv")
        counters = os.path.join(tmp, "data", "counters.csv")

        records = [
            LogRecord(
                timestamp="Mar 12 10:00:00", raw_line="",
                log_level="ERROR", host="sw-core-01",
                service="SNMP", event_type="SNMP", event_action="AUTH_FAILURE",
                message="Auth failure", template_id="SNMP_AUTH_FAILURE",
                severity_score=3.0, event_type_score=3.0, anomaly_score=1.0,
                event_weight=2.6, frequency=5,
                correlation_id="corr-00001-001", correlation_score=2.0,
                importance_score=2.4657, label="critical",
            ),
            LogRecord(
                timestamp="Mar 12 10:01:00", raw_line="",
                log_level="INFO", host="sw-access-02",
                service="PORT", event_type="PORT", event_action="PORT_UP",
                message="port up", template_id="PORT_UP",
                severity_score=1.0, event_type_score=1.0, anomaly_score=0.0,
                event_weight=0.8, frequency=200,
                correlation_id="corr-00002-001", correlation_score=0.0,
                importance_score=0.48, label="ignore",
            ),
        ]

        n = append_records(records, scored_path=scored)
        assert n == 2, f"Expected 2 rows, got {n}"

        update_counters(records, counters_path=counters)

        rows = read_records(scored_path=scored)
        assert len(rows) == 2
        assert rows[0]["label"] == "critical"
        assert rows[1]["label"] == "ignore"
        assert rows[0]["importance_score"] == 2.4657

        # Verify counters
        with open(counters, "r") as fh:
            counter_rows = list(csv.DictReader(fh))
        tids = {r["template_id"]: int(r["count"]) for r in counter_rows}
        assert tids["SNMP_AUTH_FAILURE"] == 1
        assert tids["PORT_UP"] == 1

        print("All storage tests PASS")