# Requirements

| ID | Requirement | Initial status |
|---|---|---|
| SSC-001 | Define a machine-readable artifact record with digest, source, SBOM, and verification sections. | Scaffolded |
| SSC-002 | Reject malformed SHA-256 digests and source commit identifiers. | Scaffolded |
| SSC-003 | Require HTTPS for source repository and SBOM references. | Scaffolded |
| SSC-004 | Reject contradictory signature flags. | Scaffolded |
| SSC-005 | Separate metadata validation from cryptographic verification and trust decisions. | Documented |
| SSC-006 | Generate reproducible SBOMs from build artifacts. | Planned |
| SSC-007 | Verify signatures against an explicit trust policy. | Planned |
| SSC-008 | Bind provenance to immutable build inputs and outputs. | Planned |
| SSC-009 | Integrate policy gates and audit evidence with ecosystem components. | Planned |
| SSC-010 | Publish reproducible release attestations and verification instructions. | Planned |
