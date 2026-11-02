# Security Policy

## Scope
This repository handles public artifact metadata and supply-chain evidence contracts. The current implementation is a local structural validator; it does not verify signatures or execute artifacts.

## Reporting
Do not publish credentials, signing keys, private vulnerability details, or exploit instructions in issues. Use GitHub's private vulnerability reporting feature if enabled for this repository; otherwise contact the repository owner through the GitHub profile and request a private disclosure channel.

## Expectations
- Never commit secrets or private keys.
- Treat all external metadata and artifact references as untrusted.
- Do not treat a successful schema or validator run as proof of artifact authenticity or safety.
- Security-sensitive changes require negative tests and explicit review.
