"""
features/feature_service.py
----------------------------
Computes severity_score and event_type_score for each LogRecord.

CHANGES FROM ORIGINAL
─────────────────────
BUG 1 FIXED — Score compression:
    Old code returned a flat 1.0 for any log not in EVENT_TYPE_SCORE_TABLE.
    A "port timeout" and "some switch chatter" got identical scores.
    Fix: 5-tier lookup chain — exact → wildcard → regex pattern →
    keyword bucket → graceful fallback (1.2, not 1.0).

BUG 2 FIXED — Raw message ignored:
    Old get_event_type_score() never read the log message text.
    Fix: raw_message is now a parameter; Tiers 3 and 4 scan it.

BUG 3 FIXED — No confidence signal:
    Old code returned float only. Downstream formula had no way to
    discount uncertain scores vs expert-table scores.
    Fix: returns ScoredResult(score, confidence, tier).
    confidence is written to record.event_type_confidence and used
    in importance_score.py as event_weight × confidence.

NEW — Gap logging:
    Every fallback hit is counted in fallback_counter.
    Call gap_report() to get a ranked list of missing templates.
    This feeds Phase 4 precision/recall evaluation.
"""

import re
import logging
from dataclasses import dataclass
from collections import Counter

from parsing.schema import LogRecord

logger = logging.getLogger(__name__)


# ── Severity map ─────────────────────────────────────────────────────────────

SEVERITY_MAP: dict[str, float] = {
    "INFO":     1.0,
    "WARN":     2.0,
    "ERROR":    3.0,
    "CRITICAL": 4.0,
}


# ── Event type score table (unchanged from original) ─────────────────────────

EVENT_TYPE_SCORE_TABLE: dict[tuple[str, str], float] = {
    # OSPF routing failures
    ("OSPF", "NEIGHBOR_DOWN"):        4.0,
    ("OSPF", "STATE_CHANGE"):         2.5,
    ("OSPF", "*"):                    2.5,
    # SECURITY
    ("SECURITY", "PORT_SCAN"):        4.0,
    ("SECURITY", "MAC_BLOCKED"):      4.0,
    ("SECURITY", "GENERIC"):          3.0,
    ("SECURITY", "*"):                3.0,
    # SNMP
    ("SNMP", "AUTH_FAILURE"):         3.0,
    ("SNMP", "GENERIC"):              1.0,
    ("SNMP", "*"):                    1.0,
    # PORT
    ("PORT", "PORT_DOWN"):            3.0,
    ("PORT", "PORT_UP"):              1.0,
    ("PORT", "STATE_CHANGE"):         1.5,
    ("PORT", "*"):                    1.5,
    # DHCP_SNOOP
    ("DHCP_SNOOP", "PACKET_DROPPED"): 2.0,
    ("DHCP_SNOOP", "*"):              2.0,
    # VLAN
    ("VLAN", "VLAN_ADDED"):           1.0,
    ("VLAN", "VLAN_REMOVED"):         1.5,
    ("VLAN", "CHANGE"):               1.0,
    ("VLAN", "*"):                    1.0,
    # IDM
    ("IDM", "ACL_ERROR"):             2.5,
    ("IDM", "GENERIC"):               1.0,
    ("IDM", "*"):                     1.0,
    # CONFIG
    ("CONFIG", "CONFIG_CHANGE"):      1.0,
    ("CONFIG", "GENERIC"):            1.0,
    ("CONFIG", "*"):                  1.0,
    # SYSLOG
    ("SYSLOG", "LOGGING_STARTED"):    0.5,
    ("SYSLOG", "*"):                  0.5,
}


# ── NEW: ScoredResult dataclass ───────────────────────────────────────────────
# Previously get_event_type_score() returned only a bare float.
# Now it returns this so callers know HOW trustworthy the score is.

@dataclass
class ScoredResult:
    score:      float   # the event_type_score value
    confidence: float   # 0.0–1.0: how certain we are this score is correct
    tier:       str     # which tier produced it: exact/wildcard/pattern/keyword/fallback


# ── NEW: Regex pattern table (Tier 3) ────────────────────────────────────────
# Applied when both exact and wildcard table lookups miss.
# Each rule has its own confidence because specificity varies —
# "auth.*fail.*reject" is very precise (0.80) while "timeout" alone
# can appear in benign messages (0.65).

@dataclass
class PatternRule:
    pattern:    re.Pattern
    score:      float
    label:      str
    confidence: float


PATTERN_SCORE_TABLE: list[PatternRule] = [
    # Network failures
    PatternRule(re.compile(r"timeout|timed.out|unreachable", re.I),
                score=3.8, label="TIMEOUT", confidence=0.65),
    PatternRule(re.compile(r"(link|interface|port).*(down|fail)", re.I),
                score=3.5, label="LINK_DOWN", confidence=0.75),
    PatternRule(re.compile(r"(neighbor|adjacency).*(lost|drop|down)", re.I),
                score=3.5, label="NEIGHBOR_LOST", confidence=0.75),
    # Auth / security
    PatternRule(re.compile(r"(auth|authentication).*(fail|error|reject)", re.I),
                score=3.4, label="AUTH_FAIL", confidence=0.80),
    PatternRule(re.compile(r"(acl|access.list).*(deny|block|drop)", re.I),
                score=3.0, label="ACL_DENY", confidence=0.70),
    # Resource pressure
    PatternRule(re.compile(r"(cpu|memory|buffer).*(high|exceed|full)", re.I),
                score=2.8, label="RESOURCE_PRESSURE", confidence=0.70),
    PatternRule(re.compile(r"(queue|buffer).*(drop|overflow)", re.I),
                score=2.5, label="QUEUE_DROP", confidence=0.72),
    # State changes
    PatternRule(re.compile(r"(session|connection).*(reset|drop|close)", re.I),
                score=2.2, label="CONN_DROP", confidence=0.65),
    PatternRule(re.compile(r"(vlan|trunk).*(mismatch|error)", re.I),
                score=2.0, label="VLAN_MISMATCH", confidence=0.68),
    # Recovery (low score — informational)
    PatternRule(re.compile(r"(link|interface|port).*(up|recover|active)", re.I),
                score=1.2, label="LINK_UP", confidence=0.60),
    PatternRule(re.compile(r"(session|connection).*(established|success)", re.I),
                score=0.9, label="CONN_OK", confidence=0.65),
]


# ── NEW: Keyword tiers (Tier 4) ───────────────────────────────────────────────
# Last resort before true fallback. Splits unknowns into 3 buckets instead of
# collapsing everything to 1.0.

_KW_CRITICAL = [
    "fail", "down", "unreachable", "crash", "timeout",
    "critical", "error", "drop", "reject", "overflow", "corrupt",
]
_KW_WARNING = [
    "warn", "retry", "slow", "degrade", "mismatch",
    "exceed", "high", "threshold", "flap", "unstable",
]
_KW_INFO = [
    "start", "connect", "success", "complete", "ok",
    "up", "establish", "active", "ready",
]


# ── NEW: Gap tracking ─────────────────────────────────────────────────────────
# Counts how many times each (event_type, event_action) pair fell through
# to the fallback tier. Call gap_report() to see which templates to add next.

fallback_counter: Counter = Counter()


def gap_report(top_n: int = 20) -> list[dict]:
    """
    Return the most-missed (event_type, event_action) pairs in ranked order.
    Use this to prioritise which entries to add to EVENT_TYPE_SCORE_TABLE.
    """
    return [
        {"event_type": et, "event_action": ea, "miss_count": count}
        for (et, ea), count in fallback_counter.most_common(top_n)
    ]


def _record_gap(et: str, ea: str) -> None:
    key = (et, ea)
    fallback_counter[key] += 1
    count = fallback_counter[key]
    if count in (10, 50, 200):
        logger.warning(
            "TEMPLATE_GAP [%dx]: (%s, %s) — consider adding to EVENT_TYPE_SCORE_TABLE",
            count, et, ea,
        )


# ── Core scoring functions ────────────────────────────────────────────────────

def get_severity_score(log_level: str) -> float:
    """Map log_level string to a numeric severity score."""
    score = SEVERITY_MAP.get(log_level.upper() if log_level else "INFO", 1.0)
    logger.debug("severity_score(%s) = %.1f", log_level, score)
    return score


def get_event_type_score(
    event_type:   str,
    event_action: str,
    raw_message:  str = "",     # NEW: message text for Tiers 3 and 4
) -> ScoredResult:
    """
    5-tier lookup chain returning ScoredResult(score, confidence, tier).

    Tier 1 — exact match in EVENT_TYPE_SCORE_TABLE          confidence 1.00
    Tier 2 — category wildcard  e.g. ("OSPF", "*")          confidence 0.85
    Tier 3 — regex pattern match on raw_message             confidence per-rule
    Tier 4 — keyword bucket (CRITICAL / WARNING / INFO)     confidence 0.40
    Tier 5 — true fallback (1.2) + gap logged               confidence 0.20
    """
    et = (event_type   or "*").upper()
    ea = (event_action or "*").upper()

    # ── Tier 1: exact match ───────────────────────────────────────────────
    score = EVENT_TYPE_SCORE_TABLE.get((et, ea))
    if score is not None:
        logger.debug("event_type_score(%s, %s) = %.1f [exact]", et, ea, score)
        return ScoredResult(score=score, confidence=1.0, tier="exact")

    # ── Tier 2: category wildcard ─────────────────────────────────────────
    score = EVENT_TYPE_SCORE_TABLE.get((et, "*"))
    if score is not None:
        logger.debug("event_type_score(%s, %s) = %.1f [wildcard]", et, ea, score)
        return ScoredResult(score=score, confidence=0.85, tier="wildcard")

    # ── Tiers 3 & 4: message-based scoring ───────────────────────────────
    if raw_message:
        # Tier 3: regex pattern
        for rule in PATTERN_SCORE_TABLE:
            if rule.pattern.search(raw_message):
                logger.debug(
                    "event_type_score(%s, %s) = %.1f [pattern:%s]",
                    et, ea, rule.score, rule.label,
                )
                return ScoredResult(
                    score=rule.score,
                    confidence=rule.confidence,
                    tier="pattern",
                )

        # Tier 4: keyword bucket
        msg_lower = raw_message.lower()
        if any(k in msg_lower for k in _KW_CRITICAL):
            logger.debug("event_type_score(%s, %s) = 3.5 [keyword:critical]", et, ea)
            return ScoredResult(score=3.5, confidence=0.40, tier="keyword")
        if any(k in msg_lower for k in _KW_WARNING):
            logger.debug("event_type_score(%s, %s) = 2.0 [keyword:warning]", et, ea)
            return ScoredResult(score=2.0, confidence=0.40, tier="keyword")
        if any(k in msg_lower for k in _KW_INFO):
            logger.debug("event_type_score(%s, %s) = 0.8 [keyword:info]", et, ea)
            return ScoredResult(score=0.8, confidence=0.40, tier="keyword")

    # ── Tier 5: true fallback ─────────────────────────────────────────────
    # Score is 1.2 (not the original 1.0) to stay slightly above noise floor
    # while still being clearly below any keyword/pattern match.
    _record_gap(et, ea)
    logger.debug("event_type_score(%s, %s) = 1.2 [fallback]", et, ea)
    return ScoredResult(score=1.2, confidence=0.20, tier="fallback")


def compute_features(record: LogRecord) -> LogRecord:
    """
    Compute severity_score and event_type_score for a single record.
    Writes results directly onto the record, including the new
    event_type_confidence and event_type_tier fields.
    """
    record.severity_score = get_severity_score(record.log_level)

    result = get_event_type_score(
        record.event_type,
        record.event_action,
        record.message,         # NEW: pass message for Tiers 3/4
    )
    record.event_type_score      = result.score
    record.event_type_confidence = result.confidence
    record.event_type_tier       = result.tier

    logger.info(
        "features: severity_score=%.1f event_type_score=%.1f "
        "confidence=%.2f tier=%s  host=%s  service=%s  %s/%s",
        record.severity_score, record.event_type_score,
        record.event_type_confidence, record.event_type_tier,
        record.host, record.service,
        record.event_type, record.event_action,
    )
    return record


def compute_features_batch(records: list[LogRecord]) -> list[LogRecord]:
    for record in records:
        compute_features(record)
    return records


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    cases = [
        # (log_level, et, ea, message, exp_sev, exp_etype, exp_tier)
        ("CRITICAL", "OSPF",    "NEIGHBOR_DOWN", "",                           4.0, 4.0, "exact"),
        ("ERROR",    "SNMP",    "AUTH_FAILURE",  "",                           3.0, 3.0, "exact"),
        ("WARN",     "PORT",    "PORT_DOWN",     "",                           2.0, 3.0, "exact"),
        ("INFO",     "PORT",    "PORT_UP",       "",                           1.0, 1.0, "exact"),
        ("INFO",     "SYSLOG",  "LOGGING_STARTED","",                          1.0, 0.5, "exact"),
        # Tier 3 — regex on message
        ("WARN",     "UNKNOWN", "UNKNOWN",       "Interface timeout after 30s",1.0, 3.8, "pattern"),
        ("ERROR",    "UNKNOWN", "UNKNOWN",       "Authentication failure for admin", 1.0, 3.4, "pattern"),
        # Tier 4 — keyword
        ("WARN",     "FOO",     "BAR",           "CPU utilization exceeded 90%",1.0, 2.0, "keyword"),
        # Tier 5 — fallback
        ("INFO",     "UNKNOWN", "UNKNOWN",       "Some random event",          1.0, 1.2, "fallback"),
    ]

    print(f"{'log_level':<10} {'event_type':<12} {'action':<18} "
          f"{'sev':>5} {'etype':>6} {'tier':<10} status")
    print("─" * 78)

    all_pass = True
    for log_level, et, ea, msg, exp_sev, exp_etype, exp_tier in cases:
        r = LogRecord(
            log_level=log_level, event_type=et, event_action=ea,
            message=msg, timestamp="", raw_line="", host="", service="",
        )
        compute_features(r)
        ok = (
            r.severity_score     == exp_sev
            and r.event_type_score == exp_etype
            and r.event_type_tier  == exp_tier
        )
        status = "PASS" if ok else (
            f"FAIL (sev={r.severity_score} etype={r.event_type_score} tier={r.event_type_tier})"
        )
        print(f"{log_level:<10} {et:<12} {ea:<18} "
              f"{r.severity_score:>5.1f} {r.event_type_score:>6.1f} "
              f"{r.event_type_tier:<10} {status}")
        if not ok:
            all_pass = False

    print()
    print("Gap report (should show UNKNOWN/UNKNOWN):")
    for entry in gap_report():
        print(f"  {entry}")
    print()
    print("All tests PASS" if all_pass else "SOME TESTS FAILED")