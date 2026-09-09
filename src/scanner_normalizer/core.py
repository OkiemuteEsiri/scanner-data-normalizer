import hashlib
import ipaddress
import re
from datetime import datetime, timezone

from .models import Finding

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SEVERITY_MAP = {
    "5": "critical", "critical": "critical",
    "4": "high", "high": "high",
    "3": "medium", "medium": "medium",
    "2": "low", "low": "low",
    "1": "info", "informational": "info", "info": "info",
}


def normalize_severity(value: object) -> str:
    key = str(value).strip().lower()
    if key not in SEVERITY_MAP:
        raise ValueError(f"unsupported severity: {value}")
    return SEVERITY_MAP[key]


def normalize_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_cves(values: list[str] | None) -> tuple[str, ...]:
    cleaned = sorted({v.upper().strip() for v in (values or []) if v.strip()})
    invalid = [v for v in cleaned if not CVE_RE.match(v)]
    if invalid:
        raise ValueError(f"invalid CVE identifiers: {invalid}")
    return tuple(cleaned)


def validate_ip(value: str) -> str:
    if not value:
        return ""
    ipaddress.ip_address(value)
    return value


def stable_hash(*parts: str) -> str:
    material = "|".join(part.strip().lower() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def build_finding(*, scanner: str, asset_id: str, hostname: str, ip_address: str,
                  vulnerability_id: str, title: str, severity: object, cves: list[str] | None,
                  first_seen: str, last_seen: str, status: str, evidence: str,
                  remediation: str, source_metadata: dict) -> Finding:
    required = {"scanner": scanner, "asset_id": asset_id, "vulnerability_id": vulnerability_id, "title": title}
    missing = [name for name, value in required.items() if not str(value).strip()]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    ip = validate_ip(ip_address)
    norm_cves = normalize_cves(cves)
    asset_fp = stable_hash(asset_id, hostname or "", ip or "")
    finding_fp = stable_hash(asset_fp, vulnerability_id, ",".join(norm_cves))
    return Finding(
        scanner=scanner.lower(), asset_id=asset_id, hostname=hostname, ip_address=ip,
        vulnerability_id=vulnerability_id, title=title, severity=normalize_severity(severity),
        cves=norm_cves, first_seen=normalize_timestamp(first_seen), last_seen=normalize_timestamp(last_seen),
        status=status.lower(), evidence=evidence, remediation=remediation,
        asset_fingerprint=asset_fp, finding_fingerprint=finding_fp, source_metadata=source_metadata,
    )
