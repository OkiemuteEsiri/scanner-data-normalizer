from .core import build_finding


def from_tenable(record: dict):
    return build_finding(
        scanner="tenable",
        asset_id=record["asset"]["uuid"],
        hostname=record["asset"].get("hostname", ""),
        ip_address=record["asset"].get("ipv4", ""),
        vulnerability_id=str(record["plugin"]["id"]),
        title=record["plugin"]["name"],
        severity=record["severity"],
        cves=record["plugin"].get("cves", []),
        first_seen=record["first_found"],
        last_seen=record["last_found"],
        status=record.get("state", "open"),
        evidence=record.get("output", ""),
        remediation=record["plugin"].get("solution", ""),
        source_metadata={"family": record["plugin"].get("family", "")},
    )


def from_qualys(record: dict):
    return build_finding(
        scanner="qualys",
        asset_id=str(record["asset_id"]),
        hostname=record.get("dns_name", ""),
        ip_address=record.get("ip", ""),
        vulnerability_id=str(record["qid"]),
        title=record["title"],
        severity=record["severity"],
        cves=record.get("cves", []),
        first_seen=record["first_detected"],
        last_seen=record["last_detected"],
        status=record.get("status", "active"),
        evidence=record.get("results", ""),
        remediation=record.get("solution", ""),
        source_metadata={"type": record.get("type", "")},
    )


def from_defender(record: dict):
    return build_finding(
        scanner="defender",
        asset_id=record["machineId"],
        hostname=record.get("deviceName", ""),
        ip_address=record.get("ipAddress", ""),
        vulnerability_id=record["vulnerabilityId"],
        title=record["name"],
        severity=record["severity"],
        cves=record.get("cves", []),
        first_seen=record["firstSeen"],
        last_seen=record["lastSeen"],
        status=record.get("status", "active"),
        evidence=record.get("evidence", ""),
        remediation=record.get("recommendedAction", ""),
        source_metadata={"product": record.get("product", "")},
    )


ADAPTERS = {"tenable": from_tenable, "qualys": from_qualys, "defender": from_defender}
