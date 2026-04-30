# Changelog

All notable changes to ground will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-30

### Added

- **OU hierarchy CloudFormation stack** (`internal/stack/accounts`): Security, Infrastructure, Research, SensitiveResearch, DoD/CMMC top-level OUs. NIHGenomic, HIPAAResearch, CUIResearch sub-OUs with correct `attest:data-classes` tags. `OrgRootId` parameter auto-populated via Organizations API.
- **IAM Identity Center stack** (`internal/stack/identity`): five permission sets — GroundUser, GroundSensitiveUser, GroundSREAdmin, GroundComplianceOfficer, GroundAuditor. FIDO2-only MFA enforcement for sensitive user set.
- **Per-OU SCP policies** (`policies/ou_scps/`): five JSON SCP files — Security, Infrastructure, Research, SensitiveResearch (MFA required), DoD/CMMC (GovCloud-only). Unit tested.
- **Account tagging SCP** (`policies/account_tagging_scp.json`): per-tag OR logic with five `attest:*` tag Deny statements. Unit tests verify OR semantics.
- **`ground export-metadata`**: exports ground deployment state to `ground-meta.json` for `attest init --ground-meta`. Now reads Identity Center instance ARN from CloudFormation stack outputs (`Deployer.StackOutput()`).
- **`internal/probe/`**: `ground-probe-*` binary interface for verifying external service declarations. Operator writes probe path and config in `ground.yaml`; probe binary receives config as JSON on stdin and returns a `ProbeResult` to stdout. 5 unit tests.
- **`ground.example.yaml`**: full reference config with inline comments. External services section with Globus, CrowdStrike, Splunk, Prisma examples.
- **IaC output** (`internal/iac/`): Terraform HCL and CDK TypeScript generators.
- **`customizing.html`**: complete `ground.yaml` reference — all options with explanations, probe contract, VPC endpoint selection table, log retention by framework table.

### Changed

- **Security model redesign**: ground no longer deploys detection services. GuardDuty, Security Hub, and Macie are activated by `attest apply` after `attest compile` selects the correct standard for active frameworks. Ground cannot know the correct standard without knowing which frameworks are active — activating NIST 800-53 for a FERPA-only institution floods Security Hub with irrelevant findings.
- **Security stack** (`internal/stack/security`): replaces the GuardDuty/SecurityHub/Macie deployment with a single logging-protection SCP that denies disabling CloudTrail and Config org-wide.
- **`SecurityConfig`**: removes `guardduty`, `security_hub`, `macie` boolean fields. New `external_services []ExternalService` field for declaring non-AWS services (Globus, CrowdStrike, Splunk, Palo Alto Prisma, Tenable, etc.).
- **`ExternalService`**: `name`, `vendor`, `category`, `features`, `scope`, `notes`, `probe`, `probe_config` fields. Category and feature enumerations documented in `customizing.html`.
- **`ground export-metadata`**: `GroundMeta` removes `guardduty_enabled`/`security_hub_enabled`; adds `external_services` and `probe_results`. `--config` flag populates external service data from `ground.yaml`.
- **`architecture.html`**: updated security section — shows logging-protection SCP + external services diagram. Detection services (yellow) clearly attributed to attest.

### Security

- **Probe path validation**: `svc.Name` must match `^[a-z0-9][a-z0-9-]{0,62}$`. `svc.Probe` must be an absolute path or empty — relative paths (`./evil`, `../traversal`, bare names) are rejected to prevent unintended binary execution via PATH lookup.

### Fixed

- **OU root ID**: replaced Lambda custom resource with CloudFormation Parameter (`OrgRootId`) auto-populated by `ground deploy` via Organizations API — eliminates Lambda IAM permissions requirement.
- **`integrating.html` JSON example**: removed stale `guardduty_enabled`/`security_hub_enabled` fields; shows current `external_services` schema.

## [0.1.0] - 2026-04-29

### Added
- Initial project structure: CLI, internal packages, policy stubs
- `ground deploy --config ground.yaml` with dry-run support
- `ground validate`, `ground status` commands
- Permission boundary, VPC endpoint, and tagging SCPs with unit tests
- Configuration schema: org, network, identity, logging, security, tagging
- `ground.example.yaml` reference configuration

[Unreleased]: https://github.com/provabl/ground/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/provabl/ground/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/provabl/ground/releases/tag/v0.1.0
