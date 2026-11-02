import copy
import unittest
from tools.validate_supply_chain import validate

VALID = {
    "record_version": "1.0.0",
    "artifact": {"name": "demo", "version": "1.0", "digest": {"algorithm": "sha256", "value": "a" * 64}},
    "source": {"repository": "https://github.com/example/demo", "commit": "b" * 40},
    "sbom": {"format": "CycloneDX", "uri": "https://example.invalid/sbom.json"},
    "verification": {"signature_present": False, "signature_verified": False},
}

class SupplyChainValidationTests(unittest.TestCase):
    def test_valid_record(self):
        self.assertEqual(validate(copy.deepcopy(VALID)), [])

    def test_rejects_wrong_digest_algorithm(self):
        record = copy.deepcopy(VALID); record["artifact"]["digest"]["algorithm"] = "md5"
        self.assertTrue(validate(record))

    def test_rejects_malformed_digest(self):
        record = copy.deepcopy(VALID); record["artifact"]["digest"]["value"] = "not-a-digest"
        self.assertTrue(validate(record))

    def test_rejects_non_https_source(self):
        record = copy.deepcopy(VALID); record["source"]["repository"] = "http://example.com/repo"
        self.assertTrue(validate(record))

    def test_rejects_bad_commit(self):
        record = copy.deepcopy(VALID); record["source"]["commit"] = "deadbeef"
        self.assertTrue(validate(record))

    def test_rejects_non_https_sbom(self):
        record = copy.deepcopy(VALID); record["sbom"]["uri"] = "file:///etc/passwd"
        self.assertTrue(validate(record))

    def test_rejects_contradictory_signature_state(self):
        record = copy.deepcopy(VALID); record["verification"] = {"signature_present": False, "signature_verified": True}
        self.assertTrue(validate(record))

    def test_rejects_unknown_top_level_field(self):
        record = copy.deepcopy(VALID); record["trust"] = "trusted"
        self.assertTrue(validate(record))

    def test_rejects_non_object(self):
        self.assertTrue(validate([]))

if __name__ == "__main__":
    unittest.main()
