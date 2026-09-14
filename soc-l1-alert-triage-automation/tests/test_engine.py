import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_triage import TriageEngine


class TriageEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = TriageEngine.from_file(ROOT / "config" / "indicators.json")

    def load(self, name):
        return json.loads((ROOT / "samples" / name).read_text(encoding="utf-8"))

    def test_encoded_powershell_with_malicious_ip_escalates(self):
        result = self.engine.triage(self.load("alert-powershell.json"))
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["disposition"], "ESCALATE_TO_L2")
        self.assertIn("T1059.001", {x["technique_id"] for x in result["mitre_attack"]})

    def test_privileged_brute_force_escalates(self):
        result = self.engine.triage(self.load("alert-bruteforce.json"))
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["disposition"], "ESCALATE_TO_L2")
        self.assertIn("T1110", {x["technique_id"] for x in result["mitre_attack"]})

    def test_impossible_travel_requires_investigation(self):
        result = self.engine.triage(self.load("alert-impossible-travel.json"))
        self.assertEqual(result["risk_score"], 60)
        self.assertEqual(result["disposition"], "ANALYST_INVESTIGATION")

    def test_known_benign_scanner_closes(self):
        result = self.engine.triage(self.load("alert-benign.json"))
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["disposition"], "CLOSE_AS_BENIGN")

    def test_missing_required_field_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing required"):
            self.engine.triage({"id": "broken"})


if __name__ == "__main__":
    unittest.main()
