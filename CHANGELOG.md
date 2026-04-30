# Changelog

All notable changes to ground will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 1 CloudFormation stacks — `ground deploy` now functional:
  - Logging stack: S3 audit bucket (KMS-encrypted, object-locked, HTTPS-only policy),
    org-wide CloudTrail with data events, AWS Config recorder and delivery channel
  - Security stack: GuardDuty (all data sources), Security Hub with NIST 800-53 Rev 5
    standard, Macie session — all enabled by default
- `internal/cfn`: CloudFormation template builder (`Template`, `Resource`, `Tag` helpers)
- `internal/deploy`: CloudFormation deployer with create/update, poll-to-terminal-state,
  "no updates to perform" handled gracefully
- `ground deploy --dry-run` prints full CloudFormation JSON without deploying
- `ground status` queries live CloudFormation stack status via AWS SDK
- `ground deploy --region` flag overrides config region
- AWS SDK v2 dependencies: `cloudformation`, `organizations`, `iam`, `config`
- SLSA Level 2 release workflow (`actions/attest-build-provenance` + cosign keyless + SBOM)
- SPDX-FileCopyrightText headers on all Go source files (2026 Scott Friedman)
- `LICENSE` (Apache 2.0), `LICENSES/Apache-2.0.txt`, `REUSE.toml`, `NOTICE`
- `ground.provabl.dev` documentation site (GitHub Pages from `docs/`)
- GitHub milestones: v0.2.0 (OU Foundation), v0.3.0 (attest Integration)
- GitHub issues: OU hierarchy, per-OU SCPs, account tagging SCP, IAM Identity Center
  permission sets, ground export-metadata

## [0.1.0] - 2026-04-29

### Added
- Initial project structure: CLI, internal packages, policy stubs
- `ground deploy --config ground.yaml` command with dry-run support
- `ground validate` command for config and policy validation
- `ground status` command
- Permission boundary policy with privilege escalation denial (tested)
- VPC endpoint policy with `aws:PrincipalOrgID` condition (tested)
- Tagging SCP with per-tag OR logic (tested)
- Policy unit tests verifying all three correctness guarantees
- Configuration schema: org, network, identity, logging, security, tagging
- `ground.example.yaml` reference configuration
- Stack stubs: accounts, network, identity, logging, security

[Unreleased]: https://github.com/provabl/ground/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/provabl/ground/releases/tag/v0.1.0
