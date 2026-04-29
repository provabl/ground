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

```bash
ground deploy --config ground.yaml   # deploy AWS organization foundation
attest init --region us-east-1        # attest discovers the deployed org
attest frameworks add cmmc-level-2    # activate compliance frameworks
attest compile --scp-strategy merged  # compile policies from frameworks
attest apply --approve                # deploy policies to the org
attest scan                           # NOW we can make compliance claims
```

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

## Status

🚧 **Under active development** — initial CDK stacks being built.

## License

Apache 2.0
