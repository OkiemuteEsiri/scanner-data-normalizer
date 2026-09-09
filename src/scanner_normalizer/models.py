from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    scanner: str
    asset_id: str
    hostname: str
    ip_address: str
    vulnerability_id: str
    title: str
    severity: str
    cves: tuple[str, ...]
    first_seen: str
    last_seen: str
    status: str
    evidence: str
    remediation: str
    asset_fingerprint: str
    finding_fingerprint: str
    source_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["cves"] = list(self.cves)
        return result
