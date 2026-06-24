# ground

**SRE deployment foundation for AWS Secure Research Environments**

Part of the [Provabl](https://provabl.dev) suite:
- **ground** — deploy correct AWS foundations ← you are here
- **[attest](https://github.com/provabl/attest)** — compile, enforce, and prove compliance
- **[qualify](https://github.com/provabl/qualify)** — train and qualify researchers

> ground your infrastructure, attest your controls, qualify your people.

---

## What ground does

ground deploys a correctly-configured AWS organization that attest can manage.
It makes **zero compliance claims** — attest makes those after `attest scan`.

```mermaid
flowchart LR
    cfg["ground.yaml"] --> ground["<b>ground</b><br/>deploy org foundation"]
    ground --> org["AWS org<br/>accounts · OUs · network · logging · baseline SCPs"]
    ground --> meta["ground-meta.json"]
    org -->|"standard AWS Organizations APIs"| attest["<b>attest</b><br/>(attest init → scan → claims)"]
    meta -->|"optional handoff"| attest
```

```bash
ground deploy --config ground.yaml   # deploy AWS organization foundation
attest init --region us-east-1        # attest discovers the deployed org
attest frameworks add cmmc-level-2    # activate compliance frameworks
attest compile --scp-strategy merged  # compile policies from frameworks
attest apply --approve                # deploy policies to the org
attest scan                           # NOW we can make compliance claims
```

## Install

```bash
go install github.com/provabl/ground/cmd/ground@latest   # requires Go 1.26.4+
# or build from a clone: go build ./cmd/ground
```

**Prerequisites.** Go 1.26.4+, and AWS credentials for the **Organization management account** (ground
deploys org-wide structure: accounts, OUs, SCPs, logging). It needs Organizations + CloudFormation +
IAM-Identity-Center permissions — run `ground preflight` to verify the calling principal holds them
before `ground deploy`. `ground deploy --dry-run` renders every stack as CloudFormation JSON without
touching AWS.

## What it deploys

| Layer | Components |
|---|---|
| Account structure | Management, security/audit, network, shared-services, workload OUs |
| Network | Transit Gateway, hub-and-spoke VPCs, VPC endpoints (org-conditioned) |
| Identity | AWS Identity Center, permission sets (admin/compliance-officer/researcher/auditor) |
| Logging | Org-wide CloudTrail, VPC Flow Logs, Config recorder, centralized S3 audit |
| Security | GuardDuty, Security Hub, Macie — **all enabled by default** |
| Boundaries | Permission boundaries that actually restrict (Deny-scoped, not Allow \*) |
| Tagging | Per-tag enforcement with OR logic (not AND — each missing tag triggers deny) |

## What it does NOT deploy

- Compliance claims (that's attest's job)
- Researcher training (that's qualify's job)
- Framework-specific SCPs (that's `attest compile`'s job)

## Correctness guarantee

Every policy ground deploys is tested before it ships. Permission boundaries, VPC
endpoint policies, and tagging SCPs are verified by policy unit tests — the same
test-driven approach used across the Provabl suite.

## Trust model — what ground does and does not guarantee

Read this before relying on ground for a compliance claim:

- **ground makes zero compliance claims.** It deploys a *correct foundation* (org
  structure, network, logging, baseline SCPs). Whether that foundation *satisfies* a
  framework is **attest**'s judgment, made after `attest scan` — not ground's. ground
  shipping cleanly is necessary, not sufficient, for compliance.
- **SCPs do not restrict the Organization management account.** AWS Service Control
  Policies never apply to the management (payer) account or its root user. Every
  guardrail ground deploys gates *member* accounts; the management account is governed
  operationally, not by these SCPs. Run workloads in member accounts, not the root.
- **The runtime-attestation SCPs gate on tags a producer must write.** The
  enclave/boot-attestation SCPs deny data access unless `attest:enclave-attested` /
  `attest:boot-attested` is present — but ground does not *produce* those tags (nitro/tpm
  do). The gate is only as strong as the producer's attestation and the principal-tag
  integrity behind it.

## Status

🚧 **Under active development** — initial CDK stacks being built.

## Open source

ground is fully open source (Apache 2.0) with no commercial tier. It is the structural foundation that [attest](https://attest.provabl.dev) and [qualify](https://qualify.provabl.dev) build on. See [COMMERCIAL.md](COMMERCIAL.md).

## License

Apache 2.0. Copyright 2026 Playground Logic LLC.
