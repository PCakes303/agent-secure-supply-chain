# Agent Secure Supply Chain

**Repository:** `PCakes303/agent-secure-supply-chain`  
**Portfolio position:** 08 / 31 public repositories  
**Maturity:** scaffolding  
**License:** [Scoped mixed-license policy](LICENSE.md).

## Purpose

Define and validate portable, evidence-backed records for software artifacts, software bills of materials (SBOMs), source provenance, and signature-verification state. The goal is to help downstream agents and release systems distinguish a well-formed claim from a cryptographically verified artifact.

## Current implementation

This repository currently provides an initial schema-backed contract and bounded validator:

- A JSON Schema for artifact, source, SBOM, and verification metadata.
- A Python validator that enforces the Draft 2020-12 schema, bounded JSON parsing, strict HTTPS URI policy, SHA-256 syntax, source commit syntax, and consistent signature flags.
- Positive and negative unit tests.
- A deliberately synthetic example record.

**Important:** the validator checks record structure and consistency only. It does not download artifacts, generate SBOMs, verify signatures, authenticate publishers, scan dependencies, or establish trust. A valid record is not proof that an artifact is safe or authentic.

## License status

This repository applies a scoped mixed-license policy: original source code and machine-readable contracts are licensed under Apache-2.0; original human-readable documentation is licensed under CC BY 4.0. Third-party material retains upstream terms. Datasets, evidence, fixtures, sample payloads, media, and material with uncertain provenance are not blanket-licensed and require separate review. See [LICENSE.md](LICENSE.md).

## Quick start

Requires Python 3.10+. Install the pinned development schema validator with `python -m pip install -r requirements-dev.txt`.

```bash
python -m pip install -r requirements-dev.txt
python tools/validate_supply_chain.py
python -m unittest discover -s tests -v
```

## Architecture and roadmap

- [Requirements](docs/REQUIREMENTS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Contract](docs/CONTRACT.md)
- [Architecture decision records](docs/adr/)
- [Master ecosystem registry](https://github.com/PCakes303/agent-intelligence-ecosystem)

### Planned next tiers

1. **Developer:** deterministic SBOM generation from reproducible builds; provenance binding source commit, build recipe, dependencies, and artifact digest.
2. **Verification:** signature verification using an explicit trust policy and pinned identity roots; fail-closed behavior for missing or invalid evidence.
3. **Production:** signed attestations, dependency and vulnerability policy gates, release workflow, immutable evidence retention, and install-from-artifact verification.

No production-readiness, SLSA conformance, or verified-signature claim is made at this stage.

## Security

See [SECURITY.md](SECURITY.md). Do not commit credentials, signing keys, private vulnerability details, or private operational material.
