import logging
import yaml

from parsing.parse_logs import parse_file
from parsing.template_extraction import assign_template_ids_batch

from features.feature_service import compute_features_batch, gap_report
from features.frequency import compute_frequency
from features.novelty import compute_novelty_batch, NoveltyTracker
from features.anomaly_proximity import compute_anomaly_scores_batch, AnomalyIndex

from scoring.event_weight import compute_event_weight
from scoring.importance_score import score_batch
from scoring.scoring_utils import print_summary, format_record

from correlation.correlation_engine import CorrelationEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_config(config_path: str = "config/weights.yaml") -> dict:
    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        logger.info(
            "Config loaded | thresholds: low=%.1f medium=%.1f critical=%.1f | corr_window=%ds",
            cfg.get("threshold_low", 0.5),
            cfg.get("threshold_medium", 1.0),
            cfg.get("threshold_critical", 2.0),
            cfg.get("correlation_window_seconds", 300),
        )
        return cfg

    except FileNotFoundError:
        logger.critical("weights.yaml not found at %s", config_path)
        raise


def main(log_file: str = "data/logs.txt", config_path: str = "config/weights.yaml"):
    cfg = load_config(config_path)
    corr_window = cfg.get("correlation_window_seconds", 300)

    logger.info("Starting pipeline...")

    records = list(parse_file(log_file))
    logger.info("Parsed %d records", len(records))

    assign_template_ids_batch(records)
    compute_features_batch(records)

    for r in records:
        compute_frequency(r)

    tracker = NoveltyTracker()
    compute_novelty_batch(records, tracker=tracker)

    index = AnomalyIndex.empty()
    compute_anomaly_scores_batch(records, index)

    for r in records:
        compute_event_weight(r)

    engine = CorrelationEngine(window_seconds=corr_window)
    engine.correlate_batch(records)

    score_batch(records, config_path=config_path)

    gaps = gap_report(top_n=10)
    if gaps:
        print("\n--- TEMPLATE GAPS ---")
        for g in gaps:
            print(f"{g['event_type']} | {g['event_action']} → {g['miss_count']}")

    records_sorted = sorted(records, key=lambda r: r.importance_score, reverse=True)

    print("\nTop Important Logs:\n" + "-" * 60)
    for r in records_sorted[:10]:
        print(format_record(r))

    with open("output.txt", "w") as f:
        for r in records_sorted:
            f.write(format_record(r) + "\n")

    logger.info("Output saved to output.txt")

    clusters = engine.get_cluster_summary()

    with open("correlation_clusters.txt", "w") as f:
        f.write("Correlation Report\n" + "=" * 50 + "\n")
        for c in clusters:
            f.write(f"\nCluster size={c['size']} score={c['score']}\n")
            f.write(f"Key: {c['cluster_key']}\n")
            for m in c["members"]:
                f.write(f"{m['timestamp']} {m['host']} {m['service']} {m['correlation_id']}\n")

    logger.info("Correlation clusters saved")

    print_summary(records_sorted)


if __name__ == "__main__":
    main()