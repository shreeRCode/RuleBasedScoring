import math
import yaml
import os
import logging
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)

LABEL_IGNORE   = "ignore"
LABEL_LOW      = "low"
LABEL_MEDIUM   = "medium"
LABEL_CRITICAL = "critical"

_DEFAULT_CONFIG: dict[str, float] = {
    "alpha": 0.60,   # event_weight contribution
    "beta":  0.25,   # log-scaled frequency
    "gamma": 0.15,   # correlation cluster boost

    # Label thresholds (lower-bound inclusive)
    "threshold_low":      0.5,
    "threshold_medium":   1.0,
    "threshold_critical": 2.0,
}

# Module-level config cache
_config_cache: dict[str, dict[str, float]] = {}


def _load_config(config_path: str) -> dict[str, float]:
    """Load alpha, beta, gamma and thresholds from config/weights.yaml."""
    if not os.path.exists(config_path):
        logger.warning("weights.yaml not found at %s — using defaults", config_path)
        return _DEFAULT_CONFIG.copy()
    try:
        with open(config_path, "r") as fh:
            cfg = yaml.safe_load(fh)
        return {key: float(cfg.get(key, default))
                for key, default in _DEFAULT_CONFIG.items()}
    except Exception as exc:
        logger.error("Failed to load %s: %s — using defaults", config_path, exc)
        return _DEFAULT_CONFIG.copy()


def get_label(score: float, cfg: dict[str, float]) -> str:
    """
    Bucket a raw importance_score into a label string.

    Thresholds (from config/weights.yaml):
        score >= threshold_critical  -> "critical"
        score >= threshold_medium    -> "medium"
        score >= threshold_low       -> "low"
        below threshold_low          -> "ignore"
    """
    if score >= cfg["threshold_critical"]:
        return LABEL_CRITICAL
    if score >= cfg["threshold_medium"]:
        return LABEL_MEDIUM
    if score >= cfg["threshold_low"]:
        return LABEL_LOW
    return LABEL_IGNORE


def compute_importance_score(
    record: LogRecord,
    config_path: str = "config/weights.yaml",
) -> tuple[float, str]:
   
    # Guard: catch missing event_weight stage
    if record.event_weight == 0.0 and record.log_level not in ("", "INFO"):
        raise ValueError(
            f"compute_importance_score() called before event_weight.py ran — "
            f"event_weight is 0.0 but log_level='{record.log_level}' "
            f"(host={record.host}, service={record.service}). "
            f"Run compute_event_weight() first."
        )

    if config_path not in _config_cache:
        _config_cache[config_path] = _load_config(config_path)
    cfg = _config_cache[config_path]

    # frequency=0 is valid (first occurrence of a template) — log(0+1)=0.0
    freq_term = math.log(record.frequency + 1)

    importance_score = (
        (cfg["alpha"] * record.event_weight)
        + (cfg["beta"]  * freq_term)
        + (cfg["gamma"] * record.correlation_score)
    )

    label = get_label(importance_score, cfg)

    record.importance_score = round(importance_score, 4)
    record.label = label

    logger.info(
        "importance_score=%.4f  label=%s  "
        "[alpha=%.2f*ew=%.4f]  [beta=%.2f*log(%d+1)=%.4f]  [gamma=%.2f*corr=%.4f]  "
        "host=%s  service=%s  %s/%s",
        importance_score, label,
        cfg["alpha"], record.event_weight,
        cfg["beta"], record.frequency, freq_term,
        cfg["gamma"], record.correlation_score,
        record.host, record.service,
        record.event_type, record.event_action,
    )
    return importance_score, label


def score_batch(
    records: list[LogRecord],
    config_path: str = "config/weights.yaml",
) -> list[LogRecord]:

    for record in records:
        compute_importance_score(record, config_path=config_path)
    return records


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    print("=== Worked example from design doc §8 ===")
   
    record = LogRecord(
        timestamp="Mar 12 10:00:00", raw_line="",
        log_level="ERROR", host="sw-core-01",
        service="SNMP", event_type="SNMP", event_action="AUTH_FAILURE",
        message="Authentication failure from <IP>",
        template_id="SNMP_AUTH_FAILURE",
        # Simulating pipeline state after all prior stages have run
        severity_score=3.0,
        event_type_score=3.0,
        anomaly_score=1.0,
        event_weight=2.6,          # set by event_weight.py
        frequency=5,               # set by frequency.py
        correlation_id="corr-001",
        correlation_score=2.0,     # set by correlation_engine.py
    )
    score, label = compute_importance_score(record, config_path="config/weights.yaml")
    expected = (0.6 * 2.6) + (0.25 * math.log(6)) + (0.15 * 2.0)
    print(f"importance_score = {score:.4f}  (expected {expected:.4f})")
    print(f"label            = {label}  (expected critical)")
    assert abs(score - expected) < 0.001
    assert label == LABEL_CRITICAL
    assert record.importance_score == round(score, 4)
    assert record.label == label
    print("PASS\n")

    print("=== Noise suppression: high-frequency INFO should stay low ===")
   
    noise = LogRecord(
        timestamp="", raw_line="", log_level="INFO",
        service="PORT", event_type="PORT", event_action="PORT_UP",
        message="port <PORT> state to up", host="sw-access-02",
        severity_score=1.0, event_type_score=1.0, anomaly_score=0.0,
        event_weight=0.8,
        frequency=200,
        correlation_score=0.0,
    )
    noise_score, noise_label = compute_importance_score(noise)
    print(f"INFO noise score = {noise_score:.4f}  label = {noise_label}")
    assert noise_label in (LABEL_IGNORE, LABEL_LOW, LABEL_MEDIUM)
    assert noise_label != LABEL_CRITICAL, "Chatty INFO should never be critical"
    print("PASS\n")

    print("=== Label boundary checks ===")
    boundaries = [
        (0.0,  LABEL_IGNORE),
        (0.49, LABEL_IGNORE),
        (0.5,  LABEL_LOW),
        (0.99, LABEL_LOW),
        (1.0,  LABEL_MEDIUM),
        (1.99, LABEL_MEDIUM),
        (2.0,  LABEL_CRITICAL),
        (5.0,  LABEL_CRITICAL),
    ]
    cfg = _load_config("config/weights.yaml")
    for score_val, expected_label in boundaries:
        got = get_label(score_val, cfg)
        status = "PASS" if got == expected_label else "FAIL"
        print(f"  score={score_val:.2f} -> {got:8s}  [{status}]")
        assert got == expected_label, f"score={score_val} -> {got}, expected {expected_label}"
    print("All boundary checks PASS")