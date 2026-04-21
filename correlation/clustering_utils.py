# correlation/clustering_utils.py



import math
from datetime import datetime

# A single time-window bucket duration in seconds.
WINDOW_SECONDS: int = 300  # 5-minute sliding window


def bucket_timestamp(ts: datetime, window_seconds: int = WINDOW_SECONDS) -> int:
    """
    Snap a datetime to the start of its time-window bucket.

    Example: ts=10:07:43, window=300s → bucket=10:05:00 (epoch int)
    This makes all events within a 5-min window share the same bucket key.
    """
    epoch = int(ts.timestamp())
    return epoch - (epoch % window_seconds)


def make_cluster_key(
    host: str,
    event_type: str,
    event_action: str,
    bucket: int,
) -> str:
    """
    Build the dict key that uniquely identifies a correlation cluster.

    Format: "<host>|<event_type>|<event_action>|<bucket_epoch>"

    Two records share a cluster iff they have the same host, same
    event_type+action, AND fall in the same time-window bucket.
    """
    return f"{host}|{event_type}|{event_action}|{bucket}"


def compute_correlation_score(cluster_size: int) -> float:
    """
    Translate a cluster's member count into a correlation_score [0.0, 3.0].

    Formula: score = log2(cluster_size + 1), clamped to [0.0, 3.0]

    Rationale:
      - cluster_size=1  (isolated event)  → score ≈ 1.0   (baseline noise)
      - cluster_size=3  (small burst)     → score ≈ 2.0   (noteworthy)
      - cluster_size=7  (significant)     → score ≈ 3.0   (max, saturates)
      - cluster_size=50 (storm)           → still 3.0     (log prevents runaway)

    The log damping is intentional: the 2nd correlated event matters a lot;
    the 50th barely adds signal beyond "something is clearly wrong."
    """
    if cluster_size <= 0:
        return 0.0
    return round(min(math.log2(cluster_size + 1), 3.0), 4)


def make_correlation_id(cluster_key: str, seq: int) -> str:
    """
    Generate a human-readable correlation_id for a record.

    Format: "corr-<short_hash>-<seq>"
    The seq counter distinguishes records within the same cluster.
    """
    # Short stable hash of the cluster key (not cryptographic — just readable)
    key_hash = abs(hash(cluster_key)) % 100_000
    return f"corr-{key_hash:05d}-{seq:03d}"