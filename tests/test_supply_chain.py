import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from tools.validate_supply_chain import load_record, validate

ROOT = Path(__file__).resolve().parents[1]
VALID = {
    "record_version": "1.0.0",
    "artifact": {"name": "demo", "version": "1.0", "digest": {"algorithm": "sha256", "value": "a" * 64}},
    "source": {"repository": "https://github.com/example/demo", "commit": "b" * 40},
    "sbom": {"format": "CycloneDX", "uri": "https://example.invalid/sbom.json"},
    "verification": {"signature_present": False, "signature_verified": False},
}
SCHEMA = json.loads((ROOT / "schemas" / "supply-chain-artifact.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)
SCHEMA_VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


class SupplyChainValidationTests(unittest.TestCase):
    def assert_schema_rejects(self, record):
        self.assertTrue(validate(record))
        self.assertTrue(list(SCHEMA_VALIDATOR.iter_errors(record)))

    def test_valid_record_matches_schema(self):
        self.assertEqual(validate(copy.deepcopy(VALID)), [])
        self.assertEqual(list(SCHEMA_VALIDATOR.iter_errors(VALID)), [])

    def test_rejects_wrong_digest_algorithm_and_malformed_digest(self):
        record = copy.deepcopy(VALID); record["artifact"]["digest"]["algorithm"] = "md5"
        self.assert_schema_rejects(record)
        record = copy.deepcopy(VALID); record["artifact"]["digest"]["value"] = "not-a-digest"
        self.assert_schema_rejects(record)

    def test_rejects_non_https_and_missing_host(self):
        for uri in ("http://example.com/repo", "https:///missing-host"):
            record = copy.deepcopy(VALID); record["source"]["repository"] = uri
            self.assert_schema_rejects(record)

    def test_rejects_credentials_fragments_malformed_ipv6_and_bad_ports(self):
        for uri in ("https://user:pass@example.com/repo", "https://example.com/repo#fragment", "https://[::1", "https://example.com:99999/repo"):
            record = copy.deepcopy(VALID); record["source"]["repository"] = uri
            self.assertTrue(validate(record))

    def test_sbom_uri_uses_same_https_policy(self):
        for uri in ("file:///etc/passwd", "https://user:pass@example.com/sbom", "https://example.com/sbom#frag", "https:///missing-host"):
            record = copy.deepcopy(VALID); record["sbom"]["uri"] = uri
            self.assertTrue(validate(record))

    def test_rejects_bad_commit_and_unknown_nested_fields(self):
        record = copy.deepcopy(VALID); record["source"]["commit"] = "deadbeef"
        self.assert_schema_rejects(record)
        record = copy.deepcopy(VALID); record["source"]["unexpected"] = True
        self.assert_schema_rejects(record)

    def test_rejects_contradictory_signature_state(self):
        record = copy.deepcopy(VALID); record["verification"] = {"signature_present": False, "signature_verified": True}
        self.assertTrue(validate(record))

    def test_rejects_oversized_fields(self):
        for mutate in (
            lambda r: r["artifact"].update(name="n" * 161),
            lambda r: r["artifact"].update(version="v" * 65),
            lambda r: r["source"].update(repository="https://example.com/" + "x" * 2050),
            lambda r: r["sbom"].update(uri="https://example.com/" + "x" * 2050),
        ):
            record = copy.deepcopy(VALID); mutate(record)
            self.assert_schema_reject(record)

    def test_strict_json_parser_rejects_duplicate_keys_nonfinite_depth_and_size(self):
        raw_cases = (
            '{"record_version":"1.0.0","record_version":"1.0.0"}',
            '{"record_version":NaN}',
            '{"nested":' + ("[" * 33) + "0" + ("]" * 33) + "}",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            for raw in raw_cases:
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_record(path)
            path.write_bytes(b" " * 1_048_577)
            with self.assertRaisesRegex(ValueError, "byte limit"):
                load_record(path)


if __name__ == "__main__":
    unittest.main()
