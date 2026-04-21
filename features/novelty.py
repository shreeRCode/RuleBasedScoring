


import math
import logging
from collections import defaultdict
from parsing.schema import LogRecord

logger = logging.getLogger(__name__)


class NoveltyTracker:
    """
    Tracks historical frequency counts per (event_type, event_action) pair
    and converts a current count into a novelty score.

    """

    def __init__(self, history_window: int = 30):
 
        self.history_window = history_window
        # (event_type, event_action) = list of past counts (floats)
        self._history: dict[tuple[str, str], list[float]] = defaultdict(list)

    def compute(self, record: LogRecord) -> float:
     
        key = (record.event_type.upper(), record.event_action.upper())
        history = self._history[key]
        current = float(record.frequency)

        score = self._score(history, current)
        record.novelty_score = round(score, 4)

        logger.debug(
            "novelty_score=%.4f  freq=%d  history_len=%d  key=%s",
            record.novelty_score, record.frequency, len(history), key,
        )
        return record.novelty_score

    def update_history(self, record: LogRecord) -> None:
      
        key = (record.event_type.upper(), record.event_action.upper())
        self._history[key].append(float(record.frequency))
        if len(self._history[key]) > self.history_window:
            self._history[key].pop(0)

    def _score(self, history: list[float], current: float) -> float:
        """
        Core novelty calculation.

        Cases:
            1. No history → first-time log → novelty = 1.0
            2. Spike (z > 2σ above baseline) → high novelty (0.5–1.0)
            3. Routine (at or below average) → low novelty (0.05–0.8)
        """
        # Case 1: never seen before
        if not history:
            return 1.0

        avg = sum(history) / len(history)
        variance = sum((x - avg) ** 2 for x in history) / len(history)
        std = math.sqrt(variance)

        if avg == 0:
       
            return 1.0

        z = (current - avg) / (std + 1e-9)      # 1e-9 avoids div-by-zero
        if z > 2.0:
            spike_score = min(0.5 + z * 0.1, 1.0)
            logger.debug("spike detected z=%.2f → novelty=%.4f", z, spike_score)
            return spike_score

        
        ratio = current / avg
        return max(0.05, 1.0 / (1.0 + math.log(ratio + 1)))

    def reset(self) -> None:
        """Clear all history. Call between independent batch runs."""
        self._history.clear()


#  Module-level default tracker for streaming use 

_default_tracker: NoveltyTracker | None = None


def get_default_tracker(history_window: int = 30) -> NoveltyTracker:
    global _default_tracker
    if _default_tracker is None:
        _default_tracker = NoveltyTracker(history_window=history_window)
    return _default_tracker


def compute_novelty(
    record: LogRecord,
    tracker: NoveltyTracker | None = None,
) -> float:
    """
    Convenience function. Uses the module-level tracker if none provided.
    Computes score, then updates history so future records see this one.
    """
    if tracker is None:
        tracker = get_default_tracker()
    score = tracker.compute(record)
    tracker.update_history(record)
    return score


def compute_novelty_batch(
    records: list[LogRecord],
    tracker: NoveltyTracker | None = None,
) -> list[LogRecord]:
  
    if tracker is None:
        tracker = NoveltyTracker()    # fresh tracker per batch for reproducibility
    for record in records:
        compute_novelty(record, tracker)
    return records


#  Self-test 

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    def _make(et: str, ea: str, freq: int) -> LogRecord:
        return LogRecord(
            timestamp="Mar 12 10:00:00", raw_line="",
            log_level="WARN", host="sw-core-01",
            service=et, event_type=et, event_action=ea,
            message="", frequency=freq,
        )

    tracker = NoveltyTracker()

    print("=== First-time log → novelty = 1.0 ===")
    r = _make("PORT", "PORT_DOWN", 1)
    score = tracker.compute(r)
    assert score == 1.0, f"Expected 1.0, got {score}"
    print(f"  PORT_DOWN first occurrence: novelty={score}  PASS")
    tracker.update_history(r)

    print("\n=== Routine log (build up history then check suppression) ===")
    # Simulate 10 periods of SYSLOG appearing ~500 times each
    syslog_tracker = NoveltyTracker()
    for i in range(10):
        r2 = _make("SYSLOG", "LOGGING_STARTED", 500)
        syslog_tracker.compute(r2)
        syslog_tracker.update_history(r2)
    # Now score another routine occurrence
    r_routine = _make("SYSLOG", "LOGGING_STARTED", 498)
    routine_score = syslog_tracker.compute(r_routine)
    assert routine_score < 0.2, f"Routine log should score low, got {routine_score}"
    print(f"  SYSLOG routine (498 occurrences, avg=500): novelty={routine_score:.4f}  PASS")

    print("\n=== Spike detection (same type, sudden burst) ===")
    # After 10 periods of ~1/hr PORT_DOWN, simulate sudden 45/hr burst
    spike_tracker = NoveltyTracker()
    for _ in range(10):
        r3 = _make("PORT", "PORT_DOWN", 1)
        spike_tracker.compute(r3)
        spike_tracker.update_history(r3)
    r_spike = _make("PORT", "PORT_DOWN", 45)
    spike_score = spike_tracker.compute(r_spike)
    assert spike_score > 0.7, f"Spike should score high, got {spike_score}"
    print(f"  PORT_DOWN spike (45 vs avg=1): novelty={spike_score:.4f}  PASS")

    print("\n=== Batch computation ===")
    records = [
        _make("OSPF", "NEIGHBOR_DOWN", 1),
        _make("SYSLOG", "LOGGING_STARTED", 500),
        _make("PORT", "PORT_DOWN", 1),
    ]
    compute_novelty_batch(records)
    for r in records:
        print(f"  {r.event_type}/{r.event_action}  freq={r.frequency}  novelty={r.novelty_score}")
    print("Batch PASS")