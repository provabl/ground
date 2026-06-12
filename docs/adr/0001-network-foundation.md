# ADR 0001 — Network foundation: hub-and-spoke VPCs, org-conditioned endpoints, compute-to-data egress

- **Status:** Proposed — design for the `internal/stack/network` stub and the routing half of `provabl/ground#10`.
- **Date:** 2026-06-12
- **Deciders:** Scott Friedman
- **Scope:** ground only (the AWS network plumbing it deploys). This is ground's first ADR; it
  establishes `docs/adr/` for ground-internal architecture decisions, distinct from the umbrella's
  suite-wide ADRs (`provabl/docs/adr`).

This records a decision **not yet implemented**. `internal/stack/network` is a stub today, and the
compute-to-data egress slice (provabl/ground#10) merged its *policy/config/metadata* surface
(`data_endpoints`, `data_endpoint_access_scp.json`, `ground-meta`) while explicitly deferring the
VPC-routing half to "once the network stack exists." This ADR designs that stack so the routing rides
on a real foundation rather than being bolted onto nothing.

---

## Context

ground's README, `CLAUDE.md`, and `COMMERCIAL.md` all promise a **network foundation** — "Transit
Gateway, hub-and-spoke VPCs, VPC endpoints with `aws:PrincipalOrgID` conditions." Four of ground's five
stacks are built (`accounts`, `identity`, `logging`, `security`); `network` is a 22-line stub with a
`New` constructor and no `Template()`. Everything network-shaped today is policy-only:
`policies/vpc_endpoint_policy.json` (the org-condition endpoint policy, unit-tested) exists but nothing
*creates* the endpoints it would attach to.

Two needs converge on this stack:

1. **The promised foundation.** A workload account needs a VPC with private subnets, the org-conditioned
   gateway/interface endpoints for the AWS services in `NetworkConfig.VPCEndpoints`, and (when
   `TransitGateway: true`) attachment to a shared hub for east-west and egress.
2. **Compute-to-data egress (ground#10).** `NetworkConfig.DataEndpoints` declares external research-data
   endpoints (dbGaP S3, AnVIL/Terra). The SCP (`data_endpoint_access_scp.json`) and attest's
   dataset-scoped Cedar policy (attest#100) already gate *whether a principal may reach* those
   endpoints; what's missing is the *network path* — a route from the SRE VPC to the external endpoint
   that stays inside AWS's backbone where possible and is itself org/posture-scoped.

The existing structure these must map to: ground deploys an OU tree
(`Security`/`Infrastructure`/`Research`/`SensitiveResearch{NIHGenomic,HIPAAResearch,CUIResearch}`/`DoD`)
with `ground:tier` + `attest:data-classes` OU tags. The network must align to those tiers, not invent a
parallel taxonomy.

## Decision

Build `internal/stack/network` as a CloudFormation template generator (same shape as the `security`
stack: `StackName()` + `Template() (*cfn.Template, error)`), deploying a **hub-and-spoke** topology with
**three deliberate decisions**:

### 1. Topology: one shared-services hub VPC + per-tier spoke VPCs, joined by Transit Gateway

- **Hub** (in the Infrastructure tier): holds the centralized **interface VPC endpoints** (PrivateLink
  ENIs for `sts`, `ssm`, `secretsmanager`, `kms`, `logs`, …) and the egress path. Centralizing interface
  endpoints in the hub — rather than duplicating per spoke — is the cost-control decision (interface
  endpoints bill per-AZ-per-endpoint; one set shared via TGW + Route 53 inbound resolver is materially
  cheaper at N spokes).
- **Spokes**: one VPC per workload tier, private-subnet-only by default (no IGW). Spokes reach AWS
  services through the hub's endpoints and reach each other only if a TGW route table permits it.
- **Transit Gateway** (gated on `NetworkConfig.TransitGateway`): the hub-and-spoke join. **Segregated TGW
  route tables per tier** — a `SensitiveResearch` spoke must not have a route to a `Research` spoke. This
  is where the data-class isolation the OU tags *describe* becomes a *network* control.
- When `TransitGateway: false`, degrade to a single self-contained VPC with its own gateway/interface
  endpoints (the small-deployment case); no hub.

### 2. CIDR allocation: deterministic carve from `NetworkConfig.CIDRBlock`

`CIDRBlock` (default `10.0.0.0/8`) is the supernet. ground carves it deterministically:
- hub: the first `/16`;
- each spoke: a subsequent `/16`, ordered by the OU tier list, so allocation is stable across runs
  (re-running `ground deploy` never renumbers an existing spoke);
- within a VPC: a `/20` private subnet per AZ across (default) 3 AZs.

Determinism matters because CIDR renumbering is destructive — the allocation function is pure
(`tier index → subnet`) and unit-testable without AWS, consistent with how the other stacks are tested
(template-as-data assertions, no live calls).

### 3. Compute-to-data egress: gateway endpoint for S3-backed datasets, PrivateLink/VPC-peering for the rest — never an open IGW

For each `NetworkConfig.DataEndpoints` entry, ground renders an egress path **scoped to that endpoint**,
choosing the mechanism by the endpoint's nature:
- **S3-backed** (dbGaP lives in S3, `url: s3.amazonaws.com`): a **gateway VPC endpoint for S3** with an
  endpoint policy restricting it to the declared dataset's buckets/prefixes. Traffic never leaves the
  AWS backbone; no NAT, no IGW.
- **Partner-endpoint-backed** (AnVIL/Terra and similar): an **interface endpoint / PrivateLink** to the
  partner's service, or a route to a TGW peering attachment when the partner exposes one. Declared via
  the endpoint's `url`; the mechanism is inferred (S3 host → gateway endpoint; otherwise interface/peer).
- **Never a public NAT/IGW egress for controlled data.** If an endpoint can only be reached over the
  public internet, ground emits it as a **declaration in `ground-meta` with a warning**, not a route —
  routing controlled-access data over the open internet is a posture decision ground refuses to make
  silently.

The egress path is the **network enforcement** that complements the two existing gates: the SCP says
"this principal class may call `s3:GetObject`," Cedar says "this researcher may read *this* dataset with
*their* DUA," and the route says "and there is a path to reach it, scoped to that dataset, staying on the
backbone." Three layers, one decision each.

## Consequences

- **ground#10 closes**: the routing half rides on this stack. `DataEndpoints` already declared in config
  + exported in `ground-meta` now also produce the scoped egress paths.
- **The data-class isolation becomes real.** Today `attest:data-classes` / `ground:tier` are *tags* an
  SCP/Cedar reads; segregated TGW route tables make tier isolation a *routing* fact — a SensitiveResearch
  spoke physically cannot route to a Research spoke.
- **Cost is a designed-in concern**, not an afterthought: centralized hub interface endpoints (vs
  per-spoke) and gateway endpoints for S3 (free) over NAT (metered) are the two biggest line items, and
  both are chosen for cost here.
- **Build is incremental and testable without AWS.** The CIDR allocator, endpoint-mechanism inference,
  and template generation are pure functions over config — unit-tested like the SCPs (template-as-data),
  with no live calls. The stack slots into `ground deploy`'s existing dry-run/JSON path beside the other
  four.
- **Cost of the decision:** the network stack is ground's largest single template, and TGW route-table
  segregation adds real complexity (one route table per tier, attachments wired per spoke). The
  degrade-to-single-VPC path (`TransitGateway: false`) keeps small deployments simple.

## Build order

1. **CIDR allocator** (pure, unit-tested) — `CIDRBlock` → hub + per-tier spoke `/16`s → per-AZ `/20`s.
2. **Single-VPC template** (the `TransitGateway: false` case) — VPC, private subnets, the gateway + the
   org-conditioned interface endpoints for `VPCEndpoints` (reusing `policies/vpc_endpoint_policy.json`'s
   `aws:PrincipalOrgID` condition). Wire into `ground deploy`; template-as-data tests.
3. **Hub-and-spoke + TGW** — hub VPC, spoke-per-tier, segregated TGW route tables.
4. **Compute-to-data egress** (ground#10 routing) — per-`DataEndpoint` scoped egress (S3 gateway
   endpoint / PrivateLink), the no-public-egress refusal, the `ground-meta` warning path.

Each step is its own PR; (1) and (2) deliver the long-promised foundation independently of the
compute-to-data routing in (4).

## What this explicitly does NOT do

- **No public ingress.** ground deploys no IGW/ALB for inbound; SRE access is via Identity Center +
  SSM/PrivateLink. Public-facing workloads are out of scope.
- **No DNS/Route 53 zones beyond the resolver** needed to share hub endpoints — full private-DNS design
  is deferred until a consumer needs it.
- **No data-residency / movement enforcement** — that stays attest's posture layer; ground provides the
  scoped *path*, not the data-handling policy on top of it.
- **No second taxonomy** — the network maps onto the existing OU `ground:tier` / `attest:data-classes`
  structure; it does not introduce network-only tiers.

## References

- Issue: `provabl/ground#10` (compute-to-data network routing); the policy/config/metadata half shipped
  in ground#22.
- Pairs with: `provabl/attest#100` (dataset-scoped Cedar gate) and the suite ADR
  `provabl/docs/adr/0002-compute-to-data-access.md` (the two-layer model).
- ground internals: `internal/stack/security/security.go` (the stack pattern to mirror),
  `internal/cfn/template.go`, `policies/vpc_endpoint_policy.json` (the org-condition endpoint policy),
  `internal/stack/accounts/accounts.go` (the OU tiers the network maps to),
  `internal/config/config.go` (`NetworkConfig`, `DataEndpoint`).
