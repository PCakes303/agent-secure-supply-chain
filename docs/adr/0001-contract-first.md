# ADR 0001: Contract-first supply-chain validation

- **Status:** accepted
- **Decision:** Begin with a small, versioned artifact record and deterministic local validation before adding network retrieval, cryptographic verification, or release automation.
- **Rationale:** Separating syntax checks from cryptographic trust decisions reduces accidental overclaiming and keeps the initial attack surface small.
- **Consequences:** The first release is scaffolding only. It cannot establish publisher identity, artifact safety, or provenance authenticity.
