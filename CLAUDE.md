# ground — Project Rules

## Overview

ground deploys a correctly-configured AWS organization foundation for Secure Research
Environments. It is the infrastructure layer of the Provabl suite.

**Key principle**: ground makes zero compliance claims. It deploys correct AWS
foundations that attest can manage. attest makes the compliance claim after `attest scan`.

## What ground does

```
ground deploy → correct AWS organization foundation
                         ↓
              attest init reads AWS APIs
                         ↓
              attest compile + apply → framework-specific policies
                         ↓
              attest scan → compliance posture
```

## What ground deploys

1. **Account structure** — management, security/audit, network, shared-services, workload OUs
2. **Network foundation** — Transit Gateway, VPCs (hub-and-spoke), VPC endpoints WITH org conditions
3. **Identity Center** — permission sets (admin, compliance-officer, researcher, auditor)
4. **Logging foundation** — CloudTrail (org-wide), VPC Flow Logs, Config recorder, S3 audit bucket
5. **Security baseline** — GuardDuty, Security Hub, Macie (ON by default — unlike the template project)
6. **Permission boundaries** — Deny-scoped (not Allow * no-ops)
7. **Tagging policy** — per-tag separate statements (OR logic, not AND)

## What ground does NOT deploy

- Compliance claims (attest's job)
- Training content (qualify's job)
- Framework-specific SCPs (attest compile's job)
- Researcher-facing tooling

## The correctness guarantee

Every IAM/SCP policy ground deploys is tested before it ships:
- Permission boundary policies verified to deny privilege escalation
- VPC endpoint policies verified to have PrincipalOrgID condition
- Tagging SCPs verified to deny per-tag independently (OR, not AND)
- Cedar policy unit tests (same approach as attest)

## Architecture

Go + AWS CDK for Go. Cobra CLI. Same conventions as attest and qualify.

```
ground/
├── cmd/ground/          — CLI entry point
├── internal/
│   ├── stack/           — CDK stack definitions
│   │   ├── accounts/    — account vending
│   │   ├── network/     — Transit Gateway, VPCs, endpoints
│   │   ├── identity/    — Identity Center, permission sets
│   │   ├── logging/     — CloudTrail, Config, flow logs
│   │   └── security/    — GuardDuty, Security Hub, Macie
│   ├── policy/          — IAM/SCP policy definitions (tested)
│   └── config/          — deployment configuration
├── policies/            — JSON policy files with unit tests
└── docs/
```

## Versioning

- Follow Semantic Versioning 2.0.0
- Tag releases as vMAJOR.MINOR.PATCH
- CHANGELOG.md following keepachangelog 1.1.0

## Go Conventions

- Go 1.25+
- Module path: github.com/provabl/ground
- No init() functions. No global mutable state.
- Errors returned, not logged-and-continued.
- go vet ./... and go test ./... before committing.

## Branch Strategy

- main is the release branch, always deployable
- Feature branches: feat/<description>
