"""
scoring/scoring_utils.py
-------------------------
Utility functions for working with scored LogRecords.

Does NOT compute scores — that is event_weight.py and importance_score.py.
This module answers questions *about* a set of already-scored records:
    - What is the label distribution?
    - What is the noise suppression ratio?
    - Which records are critical?
    - Pretty-print a single record's scoring breakdown.

Used by main.py, tests, and the dashboard.
"""

import logging
from collections import Counter
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# Label constants (mirror importance_score.py — imported here for convenience)
LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_CRITICAL = "critical"

ALL_LABELS = [LABEL_IGNORE, LABEL_LOW, LABEL_MEDIUM, LABEL_CRITICAL]


# ---------------------------------------------------------------------------
# Label distribution
# ---------------------------------------------------------------------------
def label_distribution(records: list[LogRecord]) -> dict[str, int]:
    """
    Count how many records have each label.

    Args:
        records: List of scored LogRecords (label must be set).

    Returns:
        Dict e.g. {"ignore": 120, "low": 45, "medium": 12, "critical": 3}
    """
    counts: Counter = Counter(r.label for r in records)
    # Return all labels in fixed order, 0 for absent ones
    return {label: counts.get(label, 0) for label in ALL_LABELS}


def noise_suppression_ratio(records: list[LogRecord]) -> float:
    """
    Fraction of records labelled ignore or low (i.e. successfully suppressed).

    A high ratio (>0.8) means the system is filtering most noise.
    Design doc §Phase 4 — noise suppression analysis.

    Args:
        records: List of scored LogRecords.

    Returns:
        Float in [0.0, 1.0].  Returns 0.0 if records is empty.
    """
    if not records:
        return 0.0
    suppressed = sum(
        1 for r in records
        if r.label in (LABEL_IGNORE, LABEL_LOW)
    )
    return suppressed / len(records)


def critical_records(records: list[LogRecord]) -> list[LogRecord]:
    """Return only the records labelled 'critical'."""
    return [r for r in records if r.label == LABEL_CRITICAL]


def actionable_records(records: list[LogRecord]) -> list[LogRecord]:
    """Return records labelled 'medium' or 'critical' (operator follow-up needed)."""
    return [r for r in records if r.label in (LABEL_MEDIUM, LABEL_CRITICAL)]


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------
def format_record(record: LogRecord, verbose: bool = False) -> str:
    """
    Format a single LogRecord's scoring breakdown as a readable string.

    Args:
        record:  A fully scored LogRecord.
        verbose: If True, include all intermediate scores.

    Returns:
        Single-line (default) or multi-line (verbose) string.
    """
    label_upper = record.label.upper() if record.label else "UNSCORED"

    if not verbose:
        return (
            f"[{label_upper:8s}] score={record.importance_score:.3f}  "
            f"{record.timestamp}  {record.host}  {record.service}  "
            f"{record.event_type}/{record.event_action}"
        )

    lines = [
        f"{'─'*60}",
        f"  timestamp    : {record.timestamp}",
        f"  host         : {record.host}",
        f"  service      : {record.service}",
        f"  log_level    : {record.log_level}",
        f"  event        : {record.event_type}/{record.event_action}",
        f"  template_id  : {record.template_id}",
        f"  message      : {record.message[:80]}{'…' if len(record.message) > 80 else ''}",
        f"  ── features ─────────────────────────────────────────",
        f"  severity_score   : {record.severity_score:.1f}",
        f"  event_type_score : {record.event_type_score:.1f}",
        f"  anomaly_score    : {record.anomaly_score:.1f}",
        f"  frequency        : {record.frequency}",
        f"  ── scoring ──────────────────────────────────────────",
        f"  event_weight     : {record.event_weight:.4f}",
        f"  correlation_id   : {record.correlation_id or 'none'}",
        f"  correlation_score: {record.correlation_score:.4f}",
        f"  importance_score : {record.importance_score:.4f}",
        f"  label            : {label_upper}",
        f"{'─'*60}",
    ]
    return "\n".join(lines)


def print_summary(records: list[LogRecord]) -> None:
    """
    Print a summary table of label distribution and noise suppression ratio.

    Args:
        records: List of scored LogRecords.
    """
    dist  = label_distribution(records)
    total = len(records)
    nsr   = noise_suppression_ratio(records)

    print(f"\n{'═'*45}")
    print(f"  Scoring summary  ({total} records)")
    print(f"{'═'*45}")
    for label in ALL_LABELS:
        count = dist[label]
        pct   = (count / total * 100) if total else 0
        bar   = "█" * int(pct / 5)   # 1 block per 5%
        print(f"  {label:8s}  {count:5d}  ({pct:5.1f}%)  {bar}")
    print(f"{'─'*45}")
    print(f"  Noise suppression ratio : {nsr:.1%}")
    print(f"  Actionable (medium+crit): {len(actionable_records(records))}")
    print(f"  Critical                : {len(critical_records(records))}")
    print(f"{'═'*45}\n")


# ---------------------------------------------------------------------------
# Self-test  —  python -m scoring.scoring_utils
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    def _make(label: str, importance_score: float = 1.0) -> LogRecord:
        r = LogRecord(
            timestamp="Mar 12 10:00:00", raw_line="",
            log_level="INFO", host="sw-core-01", service="SNMP",
            event_type="SNMP", event_action="AUTH_FAILURE", message="",
        )
        r.label = label
        r.importance_score = importance_score
        r.event_weight = 1.0
        r.severity_score = 1.0
        r.event_type_score = 1.0
        return r

    records = (
        [_make(LABEL_IGNORE,   0.2)] * 80 +
        [_make(LABEL_LOW,      0.7)] * 30 +
        [_make(LABEL_MEDIUM,   1.5)] * 12 +
        [_make(LABEL_CRITICAL, 2.5)] * 3
    )

    print("=== Label distribution ===")
    dist = label_distribution(records)
    for label, count in dist.items():
        print(f"  {label}: {count}")
    assert dist == {"ignore": 80, "low": 30, "medium": 12, "critical": 3}
    print("PASS\n")

    print("=== Noise suppression ratio ===")
    nsr = noise_suppression_ratio(records)
    print(f"  NSR = {nsr:.1%}")
    assert abs(nsr - (110/125)) < 0.001
    print("PASS\n")

    print("=== critical_records / actionable_records ===")
    assert len(critical_records(records))  == 3
    assert len(actionable_records(records)) == 15
    print(f"  critical   : {len(critical_records(records))}")
    print(f"  actionable : {len(actionable_records(records))}")
    print("PASS\n")

    print("=== format_record (single line) ===")
    r = records[-1]   # a critical record
    r.template_id = "SNMP_AUTH_FAILURE"
    r.correlation_id = "corr-001"
    r.correlation_score = 2.0
    r.frequency = 5
    r.anomaly_score = 1.0
    r.event_weight = 2.6
    r.importance_score = 2.31
    r.label = LABEL_CRITICAL
    print(format_record(r))
    print()
    print(format_record(r, verbose=True))
    print()

    print("=== print_summary ===")
    print_summary(records)