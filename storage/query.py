# storage/query.py
import logging
from datetime import datetime

from storage.storage import read_records, DEFAULT_SCORED_PATH

logger = logging.getLogger(__name__)

# Valid labels in ascending severity order
LABEL_ORDER = ["ignore", "low", "medium", "critical"]


def get_by_label(
    label: str,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """
    Return all records whose label matches exactly.

    Example:
        get_by_label("critical")  →  all critical records
    """
    rows = read_records(scored_path)
    return [r for r in rows if r.get("label") == label]


def get_above_label(
    min_label: str,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """
    Return records at or above a minimum label severity.

    Example:
        get_above_label("medium")  →  medium + critical records
    """
    if min_label not in LABEL_ORDER:
        raise ValueError(f"Unknown label '{min_label}'. Valid: {LABEL_ORDER}")

    min_idx = LABEL_ORDER.index(min_label)
    valid_labels = set(LABEL_ORDER[min_idx:])
    rows = read_records(scored_path)
    return [r for r in rows if r.get("label") in valid_labels]


def get_by_host(
    host: str,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """Return all records from a specific host (exact match)."""
    rows = read_records(scored_path)
    return [r for r in rows if r.get("host") == host]


def get_by_service(
    service: str,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """Return all records for a specific service (e.g. 'SNMP', 'BGP')."""
    rows = read_records(scored_path)
    return [r for r in rows if r.get("service") == service]


def get_by_correlation(
    correlation_id_prefix: str,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """
    Return all records belonging to a correlation cluster.

    Matches on the cluster prefix (corr-NNNNN) so all members of a
    cluster are returned regardless of their per-record sequence suffix.

    Example:
        get_by_correlation("corr-00001")
        →  corr-00001-001, corr-00001-002, corr-00001-003 ...
    """
    rows = read_records(scored_path)
    return [
        r for r in rows
        if r.get("correlation_id", "").startswith(correlation_id_prefix)
    ]


def get_by_time_range(
    start: str,
    end: str,
    scored_path: str = DEFAULT_SCORED_PATH,
    fmt: str = "%b %d %H:%M:%S",
) -> list[dict]:
    """
    Return records whose timestamp falls within [start, end] (inclusive).

    Timestamps use syslog format by default: "Mar 12 10:00:00"
    Pass a custom fmt if your pipeline uses a different format.
    """
    from datetime import date
    year = date.today().year

    def parse(ts: str) -> datetime | None:
        try:
            return datetime.strptime(f"{year} {ts}", f"%Y {fmt}")
        except ValueError:
            return None

    t_start = parse(start)
    t_end = parse(end)

    if t_start is None or t_end is None:
        raise ValueError(f"Could not parse time range: '{start}' – '{end}' with fmt='{fmt}'")

    rows = read_records(scored_path)
    result = []
    for r in rows:
        t = parse(r.get("timestamp", ""))
        if t and t_start <= t <= t_end:
            result.append(r)
    return result


def query(
    label: str | None = None,
    min_label: str | None = None,
    host: str | None = None,
    service: str | None = None,
    correlation_id_prefix: str | None = None,
    start: str | None = None,
    end: str | None = None,
    scored_path: str = DEFAULT_SCORED_PATH,
) -> list[dict]:
    """
    Composable multi-filter query (all filters are AND-combined).

    Args:
        label:                  Exact label match ("critical", "medium", ...)
        min_label:              Minimum label severity (inclusive)
        host:                   Exact host match
        service:                Exact service match
        correlation_id_prefix:  Cluster prefix match
        start / end:            Syslog-format time range

    Example:
        query(min_label="medium", host="sw-core-01")
        →  medium + critical records from sw-core-01
    """
    rows = read_records(scored_path)

    if label is not None:
        rows = [r for r in rows if r.get("label") == label]

    if min_label is not None:
        if min_label not in LABEL_ORDER:
            raise ValueError(f"Unknown label '{min_label}'. Valid: {LABEL_ORDER}")
        min_idx = LABEL_ORDER.index(min_label)
        valid = set(LABEL_ORDER[min_idx:])
        rows = [r for r in rows if r.get("label") in valid]

    if host is not None:
        rows = [r for r in rows if r.get("host") == host]

    if service is not None:
        rows = [r for r in rows if r.get("service") == service]

    if correlation_id_prefix is not None:
        rows = [
            r for r in rows
            if r.get("correlation_id", "").startswith(correlation_id_prefix)
        ]

    if start is not None and end is not None:
        from datetime import date
        year = date.today().year
        fmt = "%b %d %H:%M:%S"

        def parse(ts):
            try:
                return datetime.strptime(f"{year} {ts}", f"%Y {fmt}")
            except ValueError:
                return None

        t_start, t_end = parse(start), parse(end)
        if t_start and t_end:
            rows = [r for r in rows if (t := parse(r.get("timestamp", ""))) and t_start <= t <= t_end]

    logger.debug("query: %d records matched", len(rows))
    return rows


def summary(scored_path: str = DEFAULT_SCORED_PATH) -> dict:
    """
    Return a label-count breakdown of all records in the store.

    Useful for a quick health-check print in main.py.

    Returns: {"total": N, "critical": N, "medium": N, "low": N, "ignore": N}
    """
    rows = read_records(scored_path)
    counts: dict[str, int] = {lbl: 0 for lbl in LABEL_ORDER}
    for r in rows:
        lbl = r.get("label", "ignore")
        if lbl in counts:
            counts[lbl] += 1
    return {"total": len(rows), **counts}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile
    import os
    from storage.storage import append_records
    from parsing.schema import LogRecord

    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "data", "scored_records.csv")

        records = [
            LogRecord(
                timestamp="Mar 12 10:00:00", raw_line="", log_level="ERROR",
                host="sw-core-01", service="SNMP", event_type="SNMP",
                event_action="AUTH_FAILURE", message="", template_id="SNMP_AUTH_FAILURE",
                severity_score=3.0, event_type_score=3.0, anomaly_score=1.0,
                event_weight=2.6, frequency=5,
                correlation_id="corr-00001-001", correlation_score=2.0,
                importance_score=2.47, label="critical",
            ),
            LogRecord(
                timestamp="Mar 12 10:01:00", raw_line="", log_level="WARNING",
                host="sw-core-01", service="BGP", event_type="BGP",
                event_action="NEIGHBOR_DOWN", message="", template_id="BGP_NEIGHBOR_DOWN",
                severity_score=2.0, event_type_score=2.0, anomaly_score=0.5,
                event_weight=1.5, frequency=2,
                correlation_id="corr-00002-001", correlation_score=1.0,
                importance_score=1.2, label="medium",
            ),
            LogRecord(
                timestamp="Mar 12 10:02:00", raw_line="", log_level="INFO",
                host="sw-access-02", service="PORT", event_type="PORT",
                event_action="PORT_UP", message="", template_id="PORT_UP",
                severity_score=1.0, event_type_score=1.0, anomaly_score=0.0,
                event_weight=0.8, frequency=200,
                correlation_id="corr-00003-001", correlation_score=0.0,
                importance_score=0.48, label="ignore",
            ),
        ]
        append_records(records, scored_path=path)

        assert len(get_by_label("critical", path)) == 1
        assert len(get_above_label("medium", path)) == 2
        assert len(get_by_host("sw-core-01", path)) == 2
        assert len(get_by_service("SNMP", path)) == 1
        assert len(query(min_label="medium", host="sw-core-01", scored_path=path)) == 2

        s = summary(path)
        assert s["total"] == 3
        assert s["critical"] == 1
        assert s["medium"] == 1
        assert s["ignore"] == 1

        print("All query tests PASS")
        print("Summary:", s)