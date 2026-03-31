import logging

from parsing.parse_logs import parse_file
from parsing.template_extraction import assign_template_ids_batch

from features.feature_service import compute_features_batch
from features.frequency import compute_frequency
from features.anomaly_proximity import (
    compute_anomaly_scores_batch,
    AnomalyIndex,
)

from scoring.event_weight import compute_event_weight
from scoring.importance_score import score_batch
from scoring.scoring_utils import print_summary, format_record

from correlation.correlation_engine import correlate_batch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main(log_file="data/logs.txt"):
    logger.info("Starting pipeline...")

    # ── Step 1: Parse ─────────────────────────────────────
    records = list(parse_file(log_file))
    logger.info("Parsed %d records", len(records))

    # ── Step 2: Template Extraction ───────────────────────
    assign_template_ids_batch(records)
    logger.info("Template extraction completed")

    # ── Step 3: Feature Engineering ───────────────────────
    compute_features_batch(records)
    logger.info("Feature computation completed")

    # ── Step 4: Frequency (sequential) ────────────────────
    for r in records:
        compute_frequency(r)

    # ── Step 5: Anomaly ───────────────────────────────────
    index = AnomalyIndex.empty()
    compute_anomaly_scores_batch(records, index)
    logger.info("Anomaly computation completed")

    # ── Step 6: Event Weight ──────────────────────────────
    for r in records:
        compute_event_weight(r)
    logger.info("Event weight computed")

    # ── Step 7: Correlation (IMPORTANT) ───────────────────
    correlate_batch(records)
    logger.info("Correlation completed")

    # ── Step 8: Importance Score ──────────────────────────
    score_batch(records)
    logger.info("Importance scoring completed")

    # ── Output ────────────────────────────────────────────
    print("\nDetailed Output:\n" + "-" * 80)
    for r in records[:10]:
        print(format_record(r))

    print_summary(records)


if __name__ == "__main__":
    main()