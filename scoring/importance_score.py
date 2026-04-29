import yaml
import os
import logging
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_HIGH     = "high"
LABEL_CRITICAL = "critical"

_DEFAULT_CONFIG: dict[str, float] = {
    "alpha": 0.6,
    "beta":  0.25,   # FIX: was hardcoded 0.1, now matches weights.yaml default
    "gamma": 0.35,

    "threshold_low":      0.5,
    "threshold_medium":   1.0,
    "threshold_high":     1.6,
    "threshold_critical": 2.0,
}

_config_cache: dict[str, dict[str, float]] = {}


def _load_config(config_path: str) -> dict[str, float]:
    if not os.path.exists(config_path):
        logger.warning("weights.yaml not found — using defaults")
        return _DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        return {
            key: float(cfg.get(key, default))
            for key, default in _DEFAULT_CONFIG.items()
        }

    except Exception as exc:
        logger.error("Failed to load config — using defaults: %s", exc)
        return _DEFAULT_CONFIG.copy()


def get_label(score: float, cfg: dict[str, float]) -> str:
    if score >= cfg["threshold_critical"]:
        return LABEL_CRITICAL
    if score >= cfg["threshold_high"]:
        return LABEL_HIGH
    if score >= cfg["threshold_medium"]:
        return LABEL_MEDIUM
    if score >= cfg["threshold_low"]:
        return LABEL_LOW
    return LABEL_IGNORE


def compute_importance_score(
    record: LogRecord,
    config_path: str = "config/weights.yaml",
) -> tuple[float, str]:

    if config_path not in _config_cache:
        _config_cache[config_path] = _load_config(config_path)

    cfg = _config_cache[config_path]

    # Novelty factor: softens penalty, rewards rare/spiking logs
    novelty_factor = 0.5 + 0.5 * record.novelty_score

    weighted_event = (
        cfg["alpha"]
        * record.event_weight
        * record.event_type_confidence
        * novelty_factor
    )

    # Novelty bonus: additive reward for novel events
    novelty_bonus = cfg["beta"] * record.novelty_score

    # Correlation boost
    correlation_term = cfg["gamma"] * record.correlation_score

    # Rarity boost: rare templates score higher
    rarity_boost = 1.0 / (1.0 + record.frequency)
    rarity_term = 0.3 * rarity_boost

    importance_score = (
        weighted_event
        + novelty_bonus
        + correlation_term
        + rarity_term
    )

    label = get_label(importance_score, cfg)

    record.importance_score = round(importance_score, 4)
    record.label = label

    logger.debug(
        "importance_score=%.4f label=%s "
        "[ew=%.2f × conf=%.2f × nov_factor=%.3f] "
        "[nov_bonus=%.3f] [corr=%.2f] [rarity=%.3f] "
        "host=%s %s/%s",
        importance_score, label,
        record.event_weight, record.event_type_confidence, novelty_factor,
        novelty_bonus, record.correlation_score, rarity_term,
        record.host, record.event_type, record.event_action,
    )

    return importance_score, label


def score_batch(
    records: list[LogRecord],
    config_path: str = "config/weights.yaml",
) -> list[LogRecord]:
    for record in records:
        compute_importance_score(record, config_path=config_path)
    return records
