# Threat Model

## Assets
Artifact identity records, source commit references, SBOM references, provenance metadata, signature state, and consumer decisions based on these records.

## Threat actors
Malicious package publishers, compromised build dependencies, attackers controlling metadata URLs, compromised CI credentials, and accidental maintainers' errors.

## Threats and controls
- **Digest substitution:** bind the digest to exact artifact bytes and independently recompute it during future verification implementation.
- **False provenance:** require signed attestations and verify signer identity against explicit trust policy; metadata strings alone are untrusted.
- **SBOM deception:** retrieve SBOMs through bounded, policy-controlled mechanisms and validate format/content before use.
- **Signature-state spoofing:** current flags are claims only; future verifier must derive verification outcome cryptographically rather than trusting input booleans.
- **Malicious build scripts:** current validator never executes build scripts or package hooks.
- **Compromised CI:** use read-only workflow permissions and immutable action references; future release workflows require isolated signing and short-lived credentials.
- **Resource exhaustion:** future parsers and retrieval tools must impose size, time, and nesting limits.

## Trust boundaries
This public repository is not a trust root. The master catalog, manifest, SBOM, source URL, and record validator do not confer identity or authorization. Private operational repositories and credentials are out of scope and must never be accessed by public workflows.

## Residual risk
No cryptographic verification, artifact retrieval, SBOM generation, dependency scanning, or release signing is implemented in the current scaffold.
