# Changelog

All notable changes to ground will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Bump Go 1.26.5 → 1.26.6** to clear five `crypto/tls`, `net/url`, `net/http`, `encoding/xml`,
  and `encoding/asn1` standard-library advisories (**GO-2026-6218**, **GO-2026-6090**,
  **GO-2026-6088**, **GO-2026-5972**, **GO-2026-5026**), all fixed in go1.26.6. govulncheck
  flagged them as symbol-reachable through ground's deploy path (the CloudFormation/IAM SDK
  calls into `net/http`/`crypto/tls`) and the `probe` exec path. Toolchain bump only — no code
  changes.

### Added

- **`ground export-iac --format terraform|opentofu|cdk`** — the IaC export is now a
  discoverable top-level command instead of a flag on `deploy`, and **OpenTofu is
  explicitly supported**. It was previously reachable only as `deploy --output terraform`,
  so `ground --help` never mentioned it, and the name implied a deploy that never happened
  (it writes files and makes no AWS call). `--out-dir` overrides the destination. The
  deprecated `deploy --output` still works and warns.
- **The Terraform/OpenTofu export is now at parity with the CloudFormation deploy path**
  (#38). It previously emitted 12 of the ~62 resources a real deployment creates — no SCP,
  no logging, no network — so an operator could `terraform apply` it, get a clean apply, and
  reasonably believe they had a ground foundation while **nothing was enforcing anything**.
  The export now covers all of it: the 8-OU hierarchy, the S3 audit bucket (KMS, versioning,
  Object Lock, lifecycle) and its policy, the org-wide CloudTrail, the AWS Config recorder +
  delivery channel + role, the logging-protection SCP **and its attachment to the org root**,
  the Transit Gateway with per-tier VPCs/subnets/route tables/routes and the org-conditioned
  VPC endpoints, and the 5 Identity Center permission sets with their managed-policy
  attachments. 67 resources from `ground.example.yaml`; 74 with an Identity Center instance
  ARN configured.

  It closes the gap by **transpiling the same `cfn.Template` values `ground deploy` submits**
  rather than re-declaring the foundation in a second hand-written generator. That choice is
  the point: a hand-written generator is a second implementation of ground that has to be
  updated in lockstep, and silently drifts when it isn't. Transpiling means a resource added
  to `internal/stack` appears in the export automatically, and a construct the transpiler
  cannot render faithfully is a hard `UnsupportedError` — never a skip, never a commented
  placeholder. A partially-transpiled resource is the failure mode worth preventing: it
  applies cleanly and leaves the operator missing exactly the property they relied on.

  Structural CFN→Terraform mismatches are handled explicitly rather than approximated: the
  S3 sub-configurations and the policy/managed-policy attachments become standalone
  resources (the AWS provider v4+ shape), `Fn::Sub`/`Fn::GetAtt`/`Fn::Select`/`Fn::GetAZs`
  become HCL interpolations and index expressions, `OrgRootId`/`OrgId` become
  `aws_organizations_organization` data-source lookups — the same values `ground deploy`
  discovers via the Organizations API, so neither path asks the operator for them — and every
  TGW attachment carries `transit_gateway_default_route_table_association = false`, because
  CloudFormation expresses that opt-out on the gateway while Terraform expresses it on each
  attachment, and losing it would dissolve ground's tier isolation with a clean plan and no
  error.

  What still differs is **state ownership**, and the export says so: applying it makes your
  tool the owner of these resources, so applying it over an org `ground deploy` already
  created gives duplicate-name errors on the OUs and the SCP. Import first, or start from an
  untouched org.
- **First tests for `internal/iac`** (the package had none), built around parity rather than
  around a promise. `TestHCL_CoversEveryStackResource` builds the same templates `ground
  deploy` submits and asserts each resource appears in the export, so an untaught resource
  fails the build instead of vanishing; `TestHCL_EmitsNothingTheStacksDoNot` is the converse,
  since an export that grew a resource the deploy path lacks is just as much a divergence and
  harder to notice. Also covered: the stack Outputs, the guardrails (including that the SCP
  is *attached*, not merely created), TGW tier isolation, that no CloudFormation intrinsic
  survives untranslated, and that the declared data sources are exactly those referenced.
  Plus `terraform` and `opentofu` output byte-identical HCL that is `fmt`-clean and
  `validate`-clean under **both** toolchains — CI runs each and fails if either check *skips*,
  because an unenforced guarantee reads exactly like an enforced one — OU names still match
  vendor's lookup keys (read from the accounts stack, not retyped), and every deliberately
  dropped CFN property carries its reason.

### Fixed

- **`ground:version` was a hardcoded `0.2.0`, so every OU and permission set was tagged with
  a version that never deployed it** (#42). Two stacks stamped the literal (`accounts`,
  `identity`) and both still said `0.2.0` after ground shipped 0.3.0. The tag exists to answer
  "which ground built this?" — the question you ask when a resource looks wrong and you need
  to know whether a known-bad release created it — so a wrong value is *worse* than an absent
  one: absent prompts you to look elsewhere, wrong sends you to the wrong release.

  The literal in `cmd/ground` was the same bug one level up (`ground --version` reported
  `0.2.0` too), and it was the one that actually reached the export, which hoists the version
  it is handed into `local.managed_tags`. So the version now has exactly one home,
  `internal/version.Version`, injected at link time by the release workflow and defaulting to
  `"dev"` — an un-injected build says something true rather than claiming to be a release that
  shipped different code.

  A new `cfn.ManagedTags(extra...)` is the only way to build the shared tags, so a stack
  cannot reintroduce a literal without deleting the call. It also takes its extras as
  arguments instead of being appended to, which removes an aliasing hazard the old pattern
  carried: a shared `managedTags` slice plus `append(managedTags, ...)` per resource silently
  writes every resource's extra tag into the same backing array as soon as that literal has
  spare capacity.

  While in there, the `logging`, `security`, and `network` stacks were using bare `managed-by`
  tags with **no version at all** — 25 resources that couldn't answer the question either.
  All 33 tagged resources now carry the build version.

  Tests assert the tag equals `version.Version` rather than any fixed string, which is what
  catches a literal that is merely *stale* — the only way this bug appears — with a count
  floor so it can't vacuously pass if the tag stops being applied. Note the tag is written at
  *create* time and CloudFormation won't rewrite it on a resource it isn't otherwise updating,
  so **existing deployments keep the stale value**; there is no migration.
- **Five deploy-ordering constraints were declared where CloudFormation never reads them**
  (#41). `DependsOn` is a *resource-level* attribute — a sibling of `Type` and `Properties` —
  but five resources declared it *inside* `Properties`. That is not a schema violation
  CloudFormation rejects; it is simply not read, so the stack deployed successfully in
  whatever order the implicit `Ref` dependencies happened to imply and the declared ordering
  did nothing. Two of the five were guarding real failures: `OrgTrail` → `AuditBucketPolicy`
  (`CreateTrail` validates its S3 destination and fails unless the policy already grants
  `cloudtrail.amazonaws.com s3:PutObject`, and the trail `Ref`s the *bucket*, not its policy)
  and `ConfigDeliveryChannel` → `ConfigRecorder` (`PutDeliveryChannel` fails when no recorder
  exists, and nothing in that resource references it, so CloudFormation was free to create
  them concurrently). The three `SensitiveResearch` sub-OUs were ordered correctly anyway —
  they `Ref` the parent for `ParentId` — but are now stated properly too, since vendor
  resolves them by name through the nested tree.

  Fixed at the root rather than only at the five call sites: `cfn.Template.Validate` rejects
  any resource-level attribute (`DependsOn`, `Condition`, `DeletionPolicy`,
  `UpdateReplacePolicy`, `Metadata`) found at the top level of `Properties`, and `JSON` — the
  only path to CloudFormation — validates before serialising, so a template CloudFormation
  would misinterpret cannot reach a deployment. A new `cfn.DependsOn` helper makes the correct
  placement the easy one, rendering a single dependency as a string and several as a list.
  An error rather than a lint warning on purpose: anything that can be wrong *silently* should
  be impossible instead. First tests for `internal/cfn` (the package had none) cover the
  guard, the helper's shape, and the attribute's placement in the serialised JSON;
  `TestStackTemplates_PassTheCloudFormationGuard` checks every template the deploy path
  submits, in both the full and minimal configurations. `deploy --dry-run` now reports a
  serialisation failure instead of discarding it and printing an empty stack body. The
  generated HCL is byte-identical across the fix, because the transpiler already read
  `DependsOn` from both positions.

### Changed

- **Each export now states its own coverage in-band, and the two exports say different
  things.** The HCL export reports a complete transpile; the **CDK** export remains a
  hand-written subset (OU hierarchy and permission sets only, no guardrails) and still warns
  that applying it gives the organizational *shape* with nothing enforcing anything — worse
  than deploying nothing, because it looks finished. Both statements render from one
  `iac.Coverage` value into three places (stdout banner, header comment in `main.tf` /
  `stack.ts`, table in the generated README) so they cannot drift. Even the complete export
  names what *neither* path deploys: the framework SCPs and the detection services are
  attest's, applied after `attest compile` knows which frameworks are active. ground makes
  zero compliance claims either way — `attest scan` establishes posture.
- **Generated HCL is `terraform fmt`-canonical.** The output is stamped "Do not edit
  manually" yet failed `terraform fmt -check` (misaligned `locals`, one-line `output`
  blocks) — so an operator could neither leave it alone nor fix it, and it would fail CI in
  any repo that checks formatting. Canonicality is now structural rather than hand-padded:
  blocks are built as values and rendered once, with `=`-alignment in a single place. Checked
  in CI under both `terraform` and `tofu`, alongside `init -backend=false` + `validate`.
- **The generated artifacts stamp ground's real version.** `iac.NewGenerator` takes the
  version rather than hardcoding `0.2.0` in the `ground:version` tag. (The value it was handed
  was itself a stale literal until #42, above, gave the version one home.) Exports carry
  `ground:export = hcl` / `cdk-partial`, so an export-created OU is identifiable in the
  console — and distinguishable from one created by the partial CDK path.

## [0.3.0] - 2026-07-21

### Security

- **Bump Go 1.26.4 → 1.26.5** to clear **GO-2026-5856** (a `crypto/tls` standard-library vulnerability, fixed in go1.26.5). govulncheck flagged it as symbol-reachable via ground's TLS calls (AWS Organizations/CloudFormation/IAM SDK). Toolchain bump only — no code changes.

### Changed

- **Runtime-attestation SCP split per attestation kind, no conflation** (ground#29; provabl ADR 0003,
  epic provabl#30). The single `nitro_attestation_scp.json` gated data access on the conflated
  `attest:nitro-attested` tag — which couldn't distinguish enclave-grade isolation from measured-boot.
  Replaced with three composable SCPs an operator picks by the grade the data demands:
  `enclave_attestation_scp.json` (requires `attest:enclave-attested`, written by nitro),
  `boot_attestation_scp.json` (requires `attest:boot-attested`, written by tpm), and
  `runtime_attestation_either_scp.json` (one `StringNotEquals` block listing both tags → denies only
  when *neither* is present, i.e. permit if either). Tests (`TestRuntimeAttestationSCPs`) verify each
  single-kind SCP gates on its own tag and **not** the other (no conflation), and that the "either"
  SCP keeps both keys in one statement (separate statements would AND into "require both").
- **README trust-model section** (audit Tier-1): states the front-door honest limits — ground makes
  zero compliance claims (attest does, after a scan); SCPs do not restrict the Org management account;
  the runtime-attestation SCPs are only as strong as the producer (nitro/tpm) that writes their tags.

- **AMI-vetting lockdown SCP now also protects the golden-PCR tags** (provabl#13): `policies/ami_vetting_lockdown_scp.json`
  extends its `aws:TagKeys` condition (now `ForAnyValue:StringLike`) to cover `attest:pcr*` alongside
  `attest:vetted`, so only the vetter can write the golden boot-measurement tags `vet ami-reference`
  records. A forgeable golden PCR would defeat the runtime image binding. Adversarially verified against
  the live IAM simulator (forging/stripping `attest:pcr0`/`attest:pcr7` → explicitDeny); see
  `policies/SECURITY.md`.

### Changed

- **`ground deploy` wires in the network stack as a real deploy phase** and unifies the deploy
  sequence. Previously the network foundation was `--dry-run`-visible only, and the live deploy
  hardcoded brittle phase numbering (`[1/2]` then `[3/4]`/`[4/4]` split across an ad-hoc block and a
  loop). Now all five stacks (logging → security → accounts → identity → network) deploy through one
  ordered loop with consistent `[i/5]` numbering. The network stack's `OrgId` parameter (for its
  org-conditioned endpoint policy) is auto-filled via `organizations:DescribeOrganization`, the same
  way the accounts stack fills `OrgRootId` — so the org-conditioned VPC endpoints deploy without a
  manual parameter. Closes the deploy-wiring follow-up left by ADR 0001 steps 2–4.

### Added


- **Added a `Security Scan` workflow** (`.github/workflows/security.yml`): govulncheck + Trivy filesystem (dependency) + Trivy IaC scans on every push/PR and weekly, blocking on HIGH/CRITICAL. Trivy pinned to `v0.36.0`. Brings this repo in line with the rest of the suite — every Provabl tool now self-scans, fitting a security/compliance suite.
- **Compute-to-data egress per `DataEndpoint`** (`internal/stack/network/network.go`) — build step 4 of
  ADR 0001, the routing half of provabl/ground#10 (and its final piece). For each declared
  `network.data_endpoints` entry, the hub-and-spoke template now renders a hub-side scoped egress path
  whose mechanism is inferred from the endpoint URL: an **S3 host** (dbGaP) → an S3 **gateway endpoint**
  on the hub route table (reusing the foundation S3 endpoint when one already exists — a route table
  permits only one); a **`com.amazonaws.*` PrivateLink** service (AnVIL/Terra) → an **interface
  endpoint**; **any other (public) host → no route at all**, only a `ground-meta`/output declaration
  with a warning — ground refuses to route controlled data over a public IGW. This is the network gate
  that joins the SCP (`data_endpoint_access_scp`) and attest's dataset-scoped Cedar policy (attest#100):
  who-may-call, who-may-read-which-dataset, and now is-there-a-scoped-backbone-path. Unit-tested
  (classifier + all three render paths + the S3-reuse dedup); verified via `--dry-run`. **Completes the
  compute-to-data chain end to end** (provabl ADR 0002 + ground ADR 0001).
- **Network foundation: hub-and-spoke + Transit Gateway** (`internal/stack/network/network.go`) — build
  step 3 of ADR 0001. When `network.transit_gateway` is set and `org.workload_ous` lists tiers,
  `Template()` now builds a shared **hub** VPC (holding the centralized gateway + org-conditioned
  interface endpoints), one private **spoke** VPC per workload tier, and a **Transit Gateway** joining
  them with **segregated per-tier route tables**: each spoke's TGW route table carries a route to the
  hub (for the shared endpoints) but **none to sibling spokes**, so cross-tier traffic has no path —
  the `ground:tier`/`attest:data-classes` isolation becomes a routing fact, not just a tag. The TGW
  disables default route-table association/propagation (a new attachment must not silently join a
  shared table). Falls back to the single-VPC path (step 2) when TGW is off or no tiers are declared.
  Unit-tested as template data, including the **no-cross-spoke-route invariant** and the
  default-table-disable guard; verified via `--dry-run`. (provabl/ground#10)
- **Network foundation: single-VPC stack** (`internal/stack/network/network.go`) — build step 2 of
  ADR 0001 (the `TransitGateway:false` degrade path). `network.Stack.Template()` emits a private-only
  VPC (no Internet Gateway) on the deterministic hub `/16`, one private `/20` subnet per AZ (3 by
  default, region-portable via `Fn::GetAZs`), **gateway** VPC endpoints for S3/DynamoDB (route-table
  entries, no hourly cost), and **interface** endpoints for the remaining `NetworkConfig.VPCEndpoints`,
  each carrying an org-conditioned policy (allow same-org `aws:PrincipalOrgID` against a deploy-time
  `OrgId` parameter, deny external — mirrors `policies/vpc_endpoint_policy.json`; OrgId is resolved the
  same way the accounts stack resolves OrgRootId). Built as a `cfn.Template` (Go maps → JSON →
  CloudFormation SDK) like the other four stacks — **native CloudFormation is ground's deploy path; CDK
  remains an optional `--output cdk` export only.** Surfaced in `ground deploy --dry-run`. Template-as-
  data unit tests (VPC CIDR, private subnets, no-IGW, gateway-vs-interface split, org-scoped policy,
  determinism, defaults, outputs). The live-deploy numbered-phase wiring and the hub-and-spoke + Transit
  Gateway expansion (step 3) are follow-ups. (provabl/ground#10)
- **Deterministic CIDR allocator** (`internal/stack/network/cidr.go`) — build step 1 of ADR 0001. A
  pure function from the supernet (`NetworkConfig.CIDRBlock`) + the ordered tier list to a hub `/16`
  (index 0) plus one `/16` per spoke tier, each split into per-AZ `/20` subnets. Allocation is a stable
  function of `(supernet, tier index)` with no time or randomness, so re-running `ground deploy` never
  renumbers an existing spoke (renumbering is destructive) — guarded by a test that appends a tier and
  asserts existing spokes keep their blocks. Validates supernet size (must hold 1 hub + N spokes), AZ
  count (1–16 `/20`s per `/16`), and rejects empty/duplicate tier names. No AWS calls; unit-tested like
  the SCPs. (provabl/ground#10)
- **ADR 0001 — network foundation** (`docs/adr/0001-network-foundation.md`): design for the
  `internal/stack/network` stub and the routing half of provabl/ground#10. Decides a hub-and-spoke
  topology (shared-services hub holding centralized org-conditioned interface endpoints; per-tier spoke
  VPCs; segregated Transit Gateway route tables making the `ground:tier`/`attest:data-classes` isolation
  a *routing* fact), deterministic CIDR allocation from `NetworkConfig.CIDRBlock`, and a per-`DataEndpoint`
  **compute-to-data egress** mechanism (S3 gateway endpoint for dbGaP, PrivateLink/peering for AnVIL/Terra,
  never a public IGW for controlled data). Establishes ground's own `docs/adr/`. Status: Proposed;
  4-step build order. Pairs with attest#100 + suite ADR 0002.
- **Compute-to-data endpoint declarations + egress-gating SCP** (provabl/ground#10; provabl#11 Tier 2,
  ADR 0002 Decision 3). `NetworkConfig.data_endpoints` declares external research-data endpoints an SRE
  may reach in-place (NIH dbGaP S3, AnVIL/Terra) — name, url, required `data_class`, `sre_types`,
  `authorized_ous`. `policies/data_endpoint_access_scp.json` is the **coarse outer gate**: it denies the
  in-place data-access actions (`s3:GetObject`/`ListBucket`, `sagemaker:Create{Training,Processing}Job`)
  unless the principal carries an `attest:data-classes` posture tag (a `Null` check, so it never trips on
  the multi-valued tag's contents). `ground export-metadata` now emits declared endpoints in
  `ground-meta.json` for `attest init`. The **fine** per-DUA/per-dataset decision is attest's
  dataset-scoped Cedar policy (attest#100) — same two-layer model as AMI gating (provabl#13). Tested by
  `TestDataEndpointAccessSCPRequiresDataClassPosture` (Deny-only, posture condition present, egress
  actions covered). **The VPC-routing half — `internal/stack/network` is still a stub — is a follow-up;
  this is the policy + config + metadata surface, not the routing implementation.**
- **`ground preflight`** (provabl#16): verifies the calling principal holds the IAM actions `ground
  deploy` needs (Organizations create/attach/describe, CloudFormation create/update/describe, the
  `CAPABILITY_NAMED_IAM` create actions) via read-only `iam:SimulatePrincipalPolicy` against the
  caller ARN. Each action is reported allowed/denied; a denied action prints a remediation and the
  command exits non-zero. Fail-closed: an unresolvable caller or un-callable simulator is an error,
  not a pass. New `internal/preflight` (mock-driven tests). Mirrors attest's caller-permission check;
  the suite tools stay decoupled (each carries its own copy — the kernel is the only shared dep). The
  per-tool action lists live in the suite's `docs/required-permissions.md`.
- **AMI-launch gating SCPs** (provabl#13, slice 1 — the IAM-enforcement / Layer-1 half):
  - **`policies/ami_launch_gating_scp.json`** — denies `ec2:RunInstances` unless the AMI carries
    `ec2:ResourceTag/attest:vetted == "true"`. The Deny is scoped to the image ARN
    (`arn:aws:ec2:*::image/*`) so the tag condition evaluates only against the AMI, not the
    instance/volumes/ENIs the call also creates (a `Resource:"*"` scope would deny every launch).
  - **`policies/ami_vetting_lockdown_scp.json`** — denies `ec2:CreateTags`/`ec2:DeleteTags` of the
    `attest:vetted` key on AMIs for every principal except the designated vetter (an `ArnNotLike`
    `aws:PrincipalArn` exception). This solves the trust trap — a researcher cannot self-mark an AMI
    vetted (same "appraised, not asserted" principle as qualify#32's locked `attest:*` tags). The
    vetter ARN is a deploy-time placeholder (`VETTER_PRINCIPAL_ARN_PLACEHOLDER`) ground/vendor
    substitutes per account; SCPs cannot parameterize.
  - Tested by `TestAMILaunchGatingSCPDeniesUnvettedAMIs` and `TestAMIVettingLockdownDeniesTagMutation`
    (including image-scope and vetter-exception regression guards). The runtime half (an instance
    proving it booted the vetted image via PCR0) already exists in nitro/nitrotpm; the producer that
    *writes* `attest:vetted` (vet's AMI vetting) and vendor's per-account deployment are follow-ups.
  - **Adversarially verified against the live AWS IAM policy simulator** (`policies/scp_simulate_test.go`,
    build tag `awssim`): a non-vetter forging or stripping `attest:vetted` → `explicitDeny`; the vetter
    may set it; an unrelated tag key is unaffected; and `RunInstances` is denied for a `false`-tagged
    OR **untagged** AMI (a missing tag is not "vetted"). The simulator is the faithful test because SCPs
    never apply to an Organization's management account, so the policy can't be observed denying
    in-account. `policies/SECURITY.md` documents the matrix + the trust boundary (the gate reduces to
    who can assume the vetter principal; SCPs don't restrict the management-account root).
- **`policies/nitro_attestation_scp.json`** — an SCP that denies sensitive-data actions
  (`s3:GetObject`, `sagemaker:CreateTrainingJob`, …) unless the principal carries
  `aws:PrincipalTag/attest:nitro-attested == "true"`. The IAM-layer half of the evidence kernel's
  runtime attestation (the nitro provider produces the verdict; a tag carries it; this SCP gates on
  it). Tested by `TestNitroAttestationSCPRequiresAttestedTag`. Note: nothing writes the
  `attest:nitro-attested` tag yet — that attestation-tagging step is future work, mirroring how
  qualify writes `attest:*` training tags.

### Changed

- **SLSA L3 release provenance** (provabl#5): `release.yml` now generates provenance via the
  `slsa-framework/slsa-github-generator` reusable workflow (isolated, non-falsifiable builder)
  instead of `actions/attest-build-provenance` (L2). One runner cross-compiles all targets and emits
  a combined `hashes` output for the generator; cosign signatures + attested SBOM retained. Pattern
  proven on the vet pilot. The L3 proof is produced on the next tag.
- Copyright holder normalized to Playground Logic LLC.

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

[Unreleased]: https://github.com/provabl/ground/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/provabl/ground/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/provabl/ground/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/provabl/ground/releases/tag/v0.1.0
