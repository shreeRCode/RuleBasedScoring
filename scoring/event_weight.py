import logging
import yaml
import os
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

# w1 + w2 must sum to 1.0 now that anomaly is removed (ML phase only)
_DEFAULT_WEIGHTS = {
    "w1": 0.6,   # severity_score  (raised from 0.5 since w3 removed)
    "w2": 0.4,   # event_type_score (raised from 0.3)
}

_weights_cache: dict[str, dict[str, float]] = {}


def _load_weights(config_path: str) -> dict[str, float]:
    if not os.path.exists(config_path):
        logger.warning("Weights config not found. Using defaults.")
        return _DEFAULT_WEIGHTS.copy()

    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)

        return {
            "w1": float(cfg.get("w1", _DEFAULT_WEIGHTS["w1"])),
            "w2": float(cfg.get("w2", _DEFAULT_WEIGHTS["w2"])),
        }

    except Exception as e:
        logger.warning("Error loading config: %s. Using defaults.", e)
        return _DEFAULT_WEIGHTS.copy()


def compute_event_weight(
    record: LogRecord,
    config_path: str = "config/weights.yaml"
) -> float:
    """
    Rule-based phase:
        event_weight = w1 * severity_score + w2 * event_type_score

    anomaly_score is intentionally excluded here — it will be added
    back in the ML phase once Isolation Forest is implemented.
    """
    if record.severity_score == 0.0 or record.event_type_score == 0.0:
        raise ValueError("Feature computation missing before event_weight")

    if config_path not in _weights_cache:
        _weights_cache[config_path] = _load_weights(config_path)

    w = _weights_cache[config_path]

    event_weight = (
        w["w1"] * record.severity_score +
        w["w2"] * record.event_type_score
    )

    record.event_weight = round(event_weight, 4)

    logger.debug(
        "event_weight=%.4f (sev=%.1f × w1=%.1f) + (etype=%.1f × w2=%.1f)",
        record.event_weight,
        record.severity_score, w["w1"],
        record.event_type_score, w["w2"],
    )

    return record.event_weight