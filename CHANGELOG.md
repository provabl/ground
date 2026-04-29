# Changelog

All notable changes to ground will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
