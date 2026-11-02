# Supply-Chain Record Contract 1.0.0

## Purpose
The record binds an artifact identity to a content digest, source repository and immutable commit, an SBOM reference, and an explicit signature state.

## Semantics
- `artifact.digest` is a SHA-256 digest of the artifact bytes. A syntactically valid digest is not evidence that it was computed correctly.
- `source.repository` identifies the source repository; `source.commit` is an immutable 40–64 hexadecimal commit identifier.
- `sbom.format` names SPDX or CycloneDX; `sbom.uri` points to the SBOM. The current validator checks HTTPS syntax only and does not retrieve or validate the SBOM.
- `signature_present` records whether a signature is asserted to exist.
- `signature_verified` records a claimed verification result. In this initial contract it must never be true when `signature_present` is false. The current validator cannot independently verify this claim; consumers must treat it as untrusted input.

## Security invariant
No consumer may infer trust, publisher identity, authorization, or artifact safety from this record alone. Trust requires independent cryptographic verification and policy evaluation.

## Versioning
Major versions may break required fields or security semantics. Minor versions add compatible optional fields. Patch versions make non-semantic corrections.
