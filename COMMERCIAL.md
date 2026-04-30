# Open-Core Model

ground is fully open-source software (Apache 2.0). It deploys structural AWS plumbing — OU hierarchy, networking, logging, and Identity Center — and will always remain free and self-hostable.

ground has no commercial tier. It is the foundation layer of the [Provabl](https://provabl.dev) suite; the commercial products are [attest Cloud](https://attest.provabl.dev) and [qualify Cloud](https://qualify.provabl.dev), which build on top of a ground-deployed AWS organization.

---

## What ground does (all open source)

| Component | Description |
|---|---|
| OU hierarchy | Security, Infrastructure, Research, SensitiveResearch, DoD/CMMC OUs |
| Logging foundation | Org-wide CloudTrail, Config recorder, S3 audit bucket |
| Logging-protection SCP | Denies disabling CloudTrail and Config org-wide |
| Per-OU SCPs | Tiered service control policies for each OU |
| Account tagging SCP | Enforces required `attest:*` tags on resource creation |
| IAM Identity Center | Permission sets: GroundUser, GroundSensitiveUser, GroundSREAdmin, etc. |
| Network foundation | Transit Gateway, VPC endpoints with `aws:PrincipalOrgID` |
| IaC output | CloudFormation (default), Terraform HCL, CDK TypeScript |
| External service declarations | Declare Globus, CrowdStrike, Splunk, Prisma in `ground.yaml` |
| Probe interface | `ground-probe-*` binary contract for verifying service declarations |
| ground export-metadata | Exports deployment state to `ground-meta.json` for attest |

**Detection services** (GuardDuty, Security Hub, Macie) are not deployed by ground — that is `attest apply`'s job, because the correct Security Hub standard depends on which compliance frameworks are active.

---

## What ground does not do

ground makes **zero compliance claims**. It deploys the structural plumbing that makes compliance possible. Compliance claims come from `attest scan` after `attest compile` + `attest apply`.

- No compliance framework enforcement — that is attest's job
- No researcher training or access gating — that is qualify's job
- No supply chain verification — that is vet's job

---

## Suite relationship

```
ground deploy          — deploys structural AWS org foundation
  ↓
attest compile         — selects correct standards for active frameworks
attest apply           — enables detection services, deploys Cedar policies
attest scan            — computes compliance posture
  ↓
qualify train required — shows researchers what training is needed
qualify train start    — interactive training + IAM tag writes
  ↓
vet sign / verify      — supply chain verification for workload artifacts
```

For questions, open an issue at [github.com/provabl/ground](https://github.com/provabl/ground/issues).
