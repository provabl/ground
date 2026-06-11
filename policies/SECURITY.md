<!--
SPDX-FileCopyrightText: 2026 Playground Logic LLC
SPDX-License-Identifier: Apache-2.0
-->

# SCP security notes: AMI-launch gating

The AMI-launch gate (provabl#13) is two SCPs working together. This note records
what they deny, the adversarial verification behind them, and — importantly — the
trust boundary they reduce to.

## The two policies

| Policy | Denies | Unless |
|---|---|---|
| `ami_launch_gating_scp.json` | `ec2:RunInstances` (on the image resource) | the AMI carries `ec2:ResourceTag/attest:vetted == "true"` |
| `ami_vetting_lockdown_scp.json` | `ec2:CreateTags` / `ec2:DeleteTags` of the `attest:vetted` key **and the `attest:pcr*` golden-boot-measurement keys** (on images) | the caller is the designated **vetter** principal (`ArnNotLike aws:PrincipalArn`) |

Together: only a **vetted** AMI may launch, and only the **vetter** may mark an AMI
vetted. The vetter is `vet`'s CI principal (`vet gate ami-… --tag-vetted` writes the
tag). The vetter ARN is a deploy-time placeholder (`VETTER_PRINCIPAL_ARN_PLACEHOLDER`)
that ground/vendor substitutes per account — SCPs cannot parameterize.

## Why an AMI tag (and how AWS permissions it)

AWS does not put an owner/permission on each individual tag (there is no per-tag
ACL). Instead it permissions the *act of tagging* and lets policy scope it with
condition keys: `aws:TagKeys` (which keys), `aws:RequestTag/<k>` (value being set),
`aws:ResourceTag/<k>` (value already present), plus the principal (`aws:PrincipalArn`).
The lockdown SCP uses `aws:TagKeys` + `aws:PrincipalArn` to deny mutating the
`attest:vetted` key for everyone but the vetter; the launch gate uses
`ec2:ResourceTag/attest:vetted` to gate `RunInstances`. So the granularity is real,
but it lives in policy, not as an attribute on the tag.

## Adversarial verification (against the live AWS IAM simulator)

`policies/scp_simulate_test.go` (build tag `awssim`) drives `iam:SimulateCustomPolicy`
with synthetic request contexts and asserts the decision for each path. It is the
faithful test because **SCPs never apply to an Organization's management account**, so
the policy cannot be observed denying in the suite's dev account; the simulator
evaluates the policy logic with no resources and no spend.

Verified matrix (all passing):

| Attempt | Decision |
|---|---|
| researcher `CreateTags attest:vetted` on an AMI | **explicitDeny** — self-marking blocked |
| researcher `DeleteTags attest:vetted` on an AMI | **explicitDeny** — can't strip/rewrite |
| researcher `CreateTags`/`DeleteTags` of a golden PCR (`attest:pcr0`, `attest:pcr7`) | **explicitDeny** — a forgeable golden PCR would defeat the runtime image binding |
| **vetter** `CreateTags attest:vetted` / `attest:pcr0` | allowed — the vetter can mark + record golden PCRs |
| researcher `CreateTags` of an unrelated key (`project`) | allowed — lockdown is scoped to the keys |
| `RunInstances` of an AMI tagged `attest:vetted=true` | allowed |
| `RunInstances` of an AMI tagged `attest:vetted=false` | **explicitDeny** |
| `RunInstances` of an **untagged** AMI | **explicitDeny** — a missing tag is not "vetted" |

Reproduce:

```bash
AWS_PROFILE=<creds> go test -tags awssim ./policies/ -v
```

## Trust boundary (the honest limits)

The gate's soundness against tag forgery is real, but it reduces to two things the
SCPs themselves cannot cover:

1. **Who can act as the vetter principal.** The lockdown carves out one principal ARN.
   If a researcher can assume that role (a weak trust policy on the vetter role) or its
   CI credentials leak, they can mint `attest:vetted` tags. Protect the vetter role's
   trust policy and credentials accordingly.
2. **The management-account root.** SCPs never restrict the Organization management
   account (or its root user). These policies gate member-account principals; they are
   not a control on the management account.

A coarser, tag-free alternative — AWS **Allowed AMIs** (an account-level setting
restricting launches to trusted owner accounts) — removes the tag (nothing to forge)
but gates by AMI *owner*, not per-AMI verdict. We chose the tag for per-AMI
granularity; the trade is that the vetter principal becomes the asset to protect.
