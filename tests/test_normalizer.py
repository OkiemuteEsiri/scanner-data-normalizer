import unittest

from src.scanner_normalizer.adapters import from_tenable, from_qualys, from_defender
from src.scanner_normalizer.core import normalize_cves, normalize_severity, stable_hash


class NormalizerTests(unittest.TestCase):
    def test_severity_mapping(self):
        self.assertEqual(normalize_severity(5), "critical")
        self.assertEqual(normalize_severity("High"), "high")

    def test_cve_normalization(self):
        self.assertEqual(normalize_cves(["cve-2025-1234", "CVE-2025-1234"]), ("CVE-2025-1234",))

    def test_invalid_cve_rejected(self):
        with self.assertRaises(ValueError):
            normalize_cves(["NOT-A-CVE"])

    def test_hash_is_deterministic(self):
        self.assertEqual(stable_hash("A", "B"), stable_hash("a", "b"))

    def test_tenable_adapter(self):
        record = {
            "asset": {"uuid": "asset-1", "hostname": "lab-app-01", "ipv4": "10.10.0.10"},
            "plugin": {"id": 10001, "name": "Synthetic TLS Finding", "cves": ["CVE-2025-1234"], "solution": "Apply vendor update", "family": "General"},
            "severity": 4, "first_found": "2026-09-01T10:00:00Z", "last_found": "2026-09-08T10:00:00Z", "state": "open", "output": "Synthetic evidence"
        }
        finding = from_tenable(record)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.scanner, "tenable")
        self.assertTrue(finding.finding_fingerprint)

    def test_qualys_adapter(self):
        record = {
            "asset_id": "q-1", "dns_name": "lab-db-01", "ip": "10.10.0.20", "qid": 20002,
            "title": "Synthetic Package Finding", "severity": 3, "cves": ["CVE-2024-5678"],
            "first_detected": "2026-08-01T09:00:00Z", "last_detected": "2026-09-08T09:00:00Z",
            "status": "active", "results": "Synthetic package version", "solution": "Upgrade package", "type": "Confirmed"
        }
        self.assertEqual(from_qualys(record).severity, "medium")

    def test_defender_adapter(self):
        record = {
            "machineId": "m-1", "deviceName": "lab-web-01", "ipAddress": "10.10.0.30",
            "vulnerabilityId": "CVE-2026-1111", "name": "Synthetic Browser Finding", "severity": "High",
            "cves": ["CVE-2026-1111"], "firstSeen": "2026-09-02T08:00:00Z", "lastSeen": "2026-09-08T08:00:00Z",
            "status": "active", "evidence": "Synthetic browser version", "recommendedAction": "Upgrade browser", "product": "Synthetic Browser"
        }
        self.assertEqual(from_defender(record).scanner, "defender")


if __name__ == "__main__":
    unittest.main()
