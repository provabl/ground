# ground — required AWS permissions

`ground preflight` verifies the calling AWS principal holds these actions, using
read-only `iam:SimulatePrincipalPolicy` against the caller ARN (from
`sts:GetCallerIdentity`). It **evaluates, it never acts** — running preflight changes
nothing. Each required action is reported allowed/denied; a denied action prints a
remediation and the command exits non-zero, before `ground deploy` can fail mid-way.

ground is the **highest-privilege tool in the suite**: `ground deploy` provisions an
entire AWS organization foundation — the OU tree, the baseline SCPs, and the
CloudFormation stacks for logging, security, accounts, identity, and network. These are
**Organization management-account permissions**, held by the management (payer) account,
not a member-account role. Run preflight there, and grant these actions to the deployer
principal — nothing wider.

| Action | Needed by | Status |
|--------|-----------|--------|
| `sts:GetCallerIdentity` | preflight itself (resolves the caller ARN to simulate) | live |
| `iam:SimulatePrincipalPolicy` | preflight itself (the permission self-check) | live |
| `organizations:DescribeOrganization` | discover the org (org ID for the org-conditioned VPC-endpoint policy) | live |
| `organizations:ListRoots` | discover the org root ID the OU/accounts tree attaches to | live |
| `organizations:CreateOrganizationalUnit` | deploy the tiered OU tree (management / security / network / shared / workload) | live |
| `organizations:CreatePolicy` | create the baseline SCPs (logging-protection, AMI gating, runtime-attestation gates) | live |
| `organizations:AttachPolicy` | attach those SCPs to the OUs so they apply to every member account inside | live |
| `organizations:TagResource` | tag the OUs/policies ground creates | live |
| `cloudformation:CreateStack` | deploy the baseline stacks on first run (logging, security, accounts, identity, network) | live |
| `cloudformation:UpdateStack` | re-apply the baseline stacks on subsequent runs | live |
| `cloudformation:DescribeStacks` | read stack status/outputs (`ground status`, `ground export-metadata`) | live |
| `iam:CreateRole` | the baseline stacks create the named IAM roles ground provisions | live |
| `iam:CreatePolicy` | the baseline stacks create the IAM policies attached to those roles | live |
| `iam:AttachRolePolicy` | attach those policies to the roles | live |

## How the actions group

- **preflight** (`sts:GetCallerIdentity`, `iam:SimulatePrincipalPolicy`) — the self-check
  resolves the caller ARN, then simulates the rest of the list against it. To run
  preflight alone, these two suffice; the others are simulated, not exercised.
- **Organizations** — `ground deploy` discovers the org (`DescribeOrganization`,
  `ListRoots`) and builds its structure: the OU tree (`CreateOrganizationalUnit`), the
  baseline SCPs (`CreatePolicy`, `AttachPolicy`), and the tags on what it creates
  (`TagResource`).
- **CloudFormation** — the baseline is deployed as stacks. `CreateStack`/`UpdateStack`
  apply them; `DescribeStacks` reads their status and outputs for `ground status` and
  `ground export-metadata`. `ground deploy --dry-run` renders every stack as
  CloudFormation JSON and touches none of this.
- **IAM** — the baseline stacks create named roles and policies (`CreateRole`,
  `CreatePolicy`, `AttachRolePolicy`). These run as part of stack deployment, not as
  direct API calls, which is why they appear here even though ground itself never calls
  them outside CloudFormation.

## Why preflight simulates the full list

The check is read-only, and simulating an action costs nothing whether or not it is later
exercised. Running the whole list up front lets an operator confirm the deployer principal
is ready **before** `ground deploy` starts creating org structure, rather than discovering
a missing grant after the first stacks are already live. preflight fails closed: an
un-runnable self-check (missing `iam:SimulatePrincipalPolicy`, bad credentials) is an
error, not a pass.

## Boundary

ground **deploys a correct foundation; it makes zero compliance claims.** Whether that
foundation *satisfies* a framework is **attest**'s judgment, made after `attest scan` —
not ground's. ground shipping cleanly is necessary, not sufficient, for compliance.

Two limits on these permissions are worth stating plainly:

- **SCPs do not restrict the Organization management account.** AWS Service Control
  Policies never apply to the management (payer) account or its root user. Every guardrail
  ground deploys gates *member* accounts; the management account — the one holding the
  permissions above — is governed operationally, not by these SCPs. Run workloads in
  member accounts, not the root.
- **The runtime-attestation SCPs gate on tags a producer must write.** ground's
  enclave/boot-attestation SCPs deny data access unless `attest:enclave-attested` /
  `attest:boot-attested` is present — but ground does not *produce* those tags (nitro/tpm
  do). The gate is only as strong as the producer's attestation behind it.

See the project `README.md` (Trust model) and the suite ADRs for the full picture.
