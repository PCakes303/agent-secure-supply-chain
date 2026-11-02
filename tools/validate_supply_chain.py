#!/usr/bin/env python3
"""Bounded, schema-backed supply-chain record validator; performs no cryptography or network access."""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "supply-chain-artifact.schema.json"
MAX_RECORD_BYTES = 1_048_576
MAX_JSON_DEPTH = 32


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _check_depth(raw):
    depth = 0
    in_string = False
    escaped = False
    for char in raw:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds depth limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("invalid JSON structure")


def load_record(path):
    raw_bytes = Path(path).read_bytes()
    if len(raw_bytes) > MAX_RECORD_BYTES:
        raise ValueError("record exceeds byte limit")
    raw = raw_bytes.decode("utf-8")
    _check_depth(raw)
    return json.loads(
        raw,
        object_pairs_hook=_pairs_no_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON number: {value}")),
    )


def _https_uri_error(value, label):
    if not isinstance(value, str) or not value or len(value) > 2048:
        return f"{label} must be a non-empty HTTPS URI of at most 2048 characters"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return f"{label} contains malformed URI authority or port"
    if parsed.scheme != "https" or not parsed.hostname:
        return f"{label} must be an absolute HTTPS URI with a hostname"
    if parsed.username is not None or parsed.password is not None:
        return f"{label} must not contain embedded credentials"
    if parsed.fragment:
        return f"{label} must not contain a fragment"
    if port is not None and not 1 <= port <= 65535:
        return f"{label} port is outside permitted range"
    return None


def validate(record):
    errors = []
    if not isinstance(record, dict):
        return ["record must be an object"]
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schema_errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record),
            key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
        )
        for error in schema_errors:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            errors.append(f"schema violation at {location}: {error.message}")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"normative schema unavailable or invalid: {type(exc).__name__}"]
    if errors:
        return errors

    for label, value in (
        ("source.repository", record["source"]["repository"]),
        ("sbom.uri", record["sbom"]["uri"]),
    ):
        message = _https_uri_error(value, label)
        if message:
            errors.append(message)
    verification = record["verification"]
    if verification["signature_verified"] and not verification["signature_present"]:
        errors.append("signature_verified cannot be true when signature_present is false")
    return errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "examples" / "supply-chain-artifact.json"
    try:
        record = load_record(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        print(f"Unable to read record: {exc}", file=sys.stderr)
        return 2
    errors = validate(record)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Record structure valid. No signature or artifact verification was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
