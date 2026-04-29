import re
from pathlib import Path
from typing import Iterator

from parsing.schema import LogRecord, priority_to_log_level

_SYSLOG_RE = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)"
    r"\s+([A-Z_]+):\s*"
    r"(.+)$"
)


def _extract_event(service: str, message: str) -> tuple[str, str]:
    msg = message.lower()

    if service == "OSPF":
        if "full to down" in msg:
            return "OSPF", "NEIGHBOR_DOWN"
        return "OSPF", "STATE_CHANGE"

    if service in ("SECURITY", "SECURITY_PORT_SCAN"):
        if "port scan" in msg:
            return "SECURITY", "PORT_SCAN"
        if "mac" in msg and "blocked" in msg:
            return "SECURITY", "MAC_BLOCKED"
        return "SECURITY", "GENERIC"

    if service == "SNMP":
        if "authentication failure" in msg:
            return "SNMP", "AUTH_FAILURE"
        return "SNMP", "GENERIC"

    if service == "PORT":
        if "state to down" in msg:
            return "PORT", "PORT_DOWN"
        if "state to up" in msg:
            return "PORT", "PORT_UP"
        return "PORT", "STATE_CHANGE"

    if service == "DHCP_SNOOP":
        return "DHCP_SNOOP", "PACKET_DROPPED"

    if service == "VLAN":
        if "added" in msg:
            return "VLAN", "VLAN_ADDED"
        if "removed" in msg:
            return "VLAN", "VLAN_REMOVED"
        return "VLAN", "CHANGE"

    if service == "IDM":
        if "privilege escalation" in msg:
            return "IDM", "PRIVILEGE_ESCALATION"
        if "acl error" in msg:
            return "IDM", "ACL_ERROR"
        return "IDM", "GENERIC"

    if service == "Manager":
        if "configuration saved" in msg:
            return "CONFIG", "CONFIG_CHANGE"
        return "CONFIG", "GENERIC"

    if service == "syslog":
        return "SYSLOG", "LOGGING_STARTED"

    # APP service
    if service == "APP":
        if "authentication failed" in msg:
            return "APP", "AUTH_FAILED"
        if "database timeout" in msg:
            return "APP", "DB_TIMEOUT"
        if "service restarted" in msg:
            return "APP", "SERVICE_RESTART"
        if "user login success" in msg:
            return "APP", "LOGIN_SUCCESS"
        return "APP", "GENERIC"

    # FW (Firewall) service
    if service == "FW":
        if "connection denied" in msg:
            return "FW", "CONNECTION_DENIED"
        if "connection allowed" in msg:
            return "FW", "CONNECTION_ALLOWED"
        return "FW", "GENERIC"

    # SYS service
    if service == "SYS":
        if "health check failed" in msg or "health check fail" in msg:
            return "SYS", "HEALTH_CHECK_FAILED"
        if "periodic health check" in msg:
            return "SYS", "HEALTH_CHECK_OK"
        return "SYS", "GENERIC"

    # WEB service
    if service == "WEB":
        if "500" in msg:
            return "WEB", "HTTP_500"
        if "403" in msg:
            return "WEB", "HTTP_403"
        if "404" in msg:
            return "WEB", "HTTP_404"
        if "200" in msg:
            return "WEB", "HTTP_200"
        return "WEB", "GENERIC"

    # ROUTING service
    if service == "ROUTING":
        if "removed" in msg:
            return "ROUTING", "ROUTE_REMOVED"
        if "added" in msg:
            return "ROUTING", "ROUTE_ADDED"
        return "ROUTING", "GENERIC"

    return service, "UNKNOWN"


def parse_line(raw_line: str) -> LogRecord | None:
    line = raw_line.strip()
    if not line:
        return None

    match = _SYSLOG_RE.match(line)
    if not match:
        return None

    priority_str, timestamp, host, service, message = match.groups()
    priority = int(priority_str)
    log_level = priority_to_log_level(priority)
    event_type, event_action = _extract_event(service, message)

    return LogRecord(
        raw_line     = raw_line.rstrip(),
        timestamp    = timestamp.strip(),
        log_level    = log_level,
        host         = host,
        service      = service,
        event_type   = event_type,
        event_action = event_action,
        message      = message.strip(),
    )


def parse_file(log_path: str | Path) -> Iterator[LogRecord]:
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            record = parse_line(raw_line)
            if record is not None:
                yield record


if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "data/logs.txt"
    print(f"Parsing: {log_file}\n{'─'*60}")
    for i, record in enumerate(parse_file(log_file)):
        print(
            f"[{record.timestamp}] {record.host} | {record.log_level:8s} | "
            f"{record.service:12s} | {record.event_type}/{record.event_action}"
        )
        if i >= 14:
            print("... (truncated)")
            break
