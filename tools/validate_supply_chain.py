#!/usr/bin/env python3
"""Validate supply-chain record structure; this tool performs no cryptography or network access."""
import json, re, sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
TOP = {"record_version", "artifact", "source", "sbom", "verification"}

def validate(record):
    errors = []
    if not isinstance(record, dict):
        return ["record must be an object"]
    if set(record) != TOP:
        errors.append("record must contain exactly record_version, artifact, source, sbom, verification")
    if record.get("record_version") != "1.0.0":
        errors.append("record_version must be 1.0.0")
    artifact = record.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {"name", "version", "digest"}:
        errors.append("artifact must contain name, version, digest")
    else:
        for field in ("name", "version"):
            if not isinstance(artifact[field], str) or not artifact[field].strip():
                errors.append(f"artifact.{field} must be a non-empty string")
        digest = artifact["digest"]
        if not isinstance(digest, dict) or set(digest) != {"algorithm", "value"} or digest.get("algorithm") != "sha256" or not isinstance(digest.get("value"), str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest["value"]):
            errors.append("artifact.digest must be a 64-character SHA-256 hex value")
    source = record.get("source")
    if not isinstance(source, dict) or set(source) != {"repository", "commit"}:
        errors.append("source must contain repository and commit")
    else:
        parsed = urlparse(source["repository"]) if isinstance(source["repository"], str) else None
        if not parsed or parsed.scheme != "https" or not parsed.netloc:
            errors.append("source.repository must be an HTTPS URI")
        if not isinstance(source["commit"], str) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", source["commit"]):
            errors.append("source.commit must be a 40-64 character hexadecimal identifier")
    sbom = record.get("sbom")
    if not isinstance(sbom, dict) or set(sbom) != {"format", "uri"} or sbom.get("format") not in {"SPDX", "CycloneDX"}:
        errors.append("sbom must contain format (SPDX or CycloneDX) and uri")
    else:
        parsed = urlparse(sbom["uri"]) if isinstance(sbom["uri"], str) else None
        if not parsed or parsed.scheme != "https" or not parsed.netloc:
            errors.append("sbom.uri must be an HTTPS URI")
    verification = record.get("verification")
    if not isinstance(verification, dict) or set(verification) != {"signature_present", "signature_verified"} or not isinstance(verification.get("signature_present"), bool) or not isinstance(verification.get("signature_verified"), bool):
        errors.append("verification must contain boolean signature_present and signature_verified")
    elif verification["signature_verified"] and not verification["signature_present"]:
        errors.append("signature_verified cannot be true when signature_present is false")
    return errors

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "examples/supply-chain-artifact.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Unable to read record: {exc}", file=sys.stderr)
        return 2
    errors = validate(record)
    if errors:
        print("\\n".join(errors), file=sys.stderr)
        return 1
    print("Record structure valid. No signature or artifact verification was performed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
