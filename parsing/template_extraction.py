from parsing.schema import LogRecord
from parsing.drain_parser import drain_parser


def assign_template_id(record: LogRecord) -> LogRecord:
    """
    Use Drain to extract log templates dynamically.

    Assigns template_id for grouping/clustering purposes only.

    IMPORTANT: record.message is intentionally NOT overwritten here.
    The raw message (with actual values like user=jdoe src=10.0.0.5)
    must be preserved so it appears correctly in output and evidence lines.
    The Drain template (with <*> placeholders) is stored in template_id only.
    """
    cluster_id, template = drain_parser.parse(record.message)

    # Template ID used for correlation clustering and frequency counting
    record.template_id = f"TEMPLATE_{cluster_id}"

    # Do NOT overwrite record.message — keep the original raw message
    # record.message = template  ← removed: this was replacing real values with <*>

    return record


def assign_template_ids_batch(records: list[LogRecord]) -> list[LogRecord]:
    """
    Apply Drain-based template extraction to all records.
    """
    for record in records:
        assign_template_id(record)
    return records