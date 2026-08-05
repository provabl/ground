// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package iac generates Infrastructure-as-Code artifacts for ground stacks.
//
// **Native CloudFormation is ground's deploy path.** The generators here are
// *exports* for operators who standardise on another tool, and they are
// deliberately **partial** — see [Coverage]. Two things follow from that, and
// both are enforced rather than merely documented:
//
//   - An export is not a foundation. It creates the OU hierarchy and the
//     Identity Center permission sets, and **no guardrails at all** — no SCPs,
//     no CloudTrail/Config logging, no network. An operator who runs
//     `terraform apply` on an export has an org *shape* with nothing enforcing
//     anything, which is a strictly worse position than not deploying, because
//     it looks done. So every export carries the gap in-band: a banner on
//     stdout, a warning header in the artifact itself, and a coverage table in
//     the generated README.
//   - `attest scan` is what establishes posture either way. ground makes zero
//     compliance claims, and an export makes even fewer.
//
// Formats: terraform / opentofu (the same HCL — `hashicorp/aws ~> 5.0`, no
// tool-specific features, validated under both) and cdk (TypeScript, CDK v2).
package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/provabl/ground/internal/config"
)

// Format identifies the IaC output format.
type Format string

const (
	FormatCloudFormation Format = "cloudformation" // default — ground's own deploy path
	FormatTerraform      Format = "terraform"      // HCL, applied with terraform
	FormatOpenTofu       Format = "opentofu"       // the same HCL, applied with tofu
	FormatCDK            Format = "cdk"            // TypeScript CDK v2
)

// Coverage records exactly which parts of a ground foundation an export
// reproduces. It is the single source of truth for the banner, the artifact
// header, and the generated README, so the three cannot drift apart and quietly
// overstate what an export does.
//
// Keeping this as data (rather than prose in three places) is the point: when a
// generator gains SCP or logging support, moving one entry from Missing to
// Covered updates every warning at once.
type Coverage struct {
	// Covered is what the export actually creates.
	Covered []string
	// Missing is what a ground foundation has and the export does NOT create.
	Missing []string
}

// exportCoverage is the current, honest state of both generators. Terraform and
// CDK have the same gap because they were written from the same subset.
//
// Verified against the CloudFormation stacks in internal/stack: a dry-run of the
// example config emits 62 resources, of which the exports reproduce 12.
var exportCoverage = Coverage{
	Covered: []string{
		"Organizational Units — the full 8-OU hierarchy, including the nested sub-OUs",
		"IAM Identity Center permission sets (4) — when an instance ARN is supplied",
	},
	Missing: []string{
		"Service Control Policies — NO guardrails are created or attached (13 policy documents in ground/policies/, including the AMI-gating and runtime-attestation SCPs)",
		"Logging foundation — no S3 audit bucket, no org-wide CloudTrail, no AWS Config recorder",
		"Network — no VPCs, subnets, Transit Gateway, or VPC endpoints",
		"Security services — no GuardDuty, Security Hub, or Macie enablement",
	},
}

// IsPartial reports whether f produces a partial export. Every non-CloudFormation
// format currently does; this exists so callers ask the question rather than
// hardcoding the answer.
func IsPartial(f Format) bool { return f != FormatCloudFormation }

// IsHCL reports whether f is one of the HCL formats. terraform and opentofu
// generate byte-identical output — the HCL uses only hashicorp/aws and no
// tool-specific features, and is validated under both toolchains.
func IsHCL(f Format) bool { return f == FormatTerraform || f == FormatOpenTofu }

// Tool returns the CLI binary an operator runs for f.
func Tool(f Format) string {
	if f == FormatOpenTofu {
		return "tofu"
	}
	return "terraform"
}

// DefaultOutputDir is the conventional directory for f's artifacts.
func DefaultOutputDir(f Format) string {
	switch f {
	case FormatTerraform:
		return "ground-terraform"
	case FormatOpenTofu:
		return "ground-opentofu"
	case FormatCDK:
		return "ground-cdk"
	default:
		return ""
	}
}

// ParseFormat resolves a user-supplied format name.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatTerraform:
		return FormatTerraform, nil
	case FormatOpenTofu:
		return FormatOpenTofu, nil
	case FormatCDK:
		return FormatCDK, nil
	case FormatCloudFormation:
		return FormatCloudFormation, nil
	default:
		return "", fmt.Errorf("unknown IaC format %q (use terraform, opentofu, or cdk)", s)
	}
}

// Warning renders the partial-coverage warning, prefixing each line with prefix
// (e.g. "# " for HCL, "// " for TypeScript, "" for stdout).
//
// Deliberately tool-agnostic: it is embedded verbatim in the generated HCL, which
// must be byte-identical for terraform and opentofu. Callers that want
// tool-specific next steps print those alongside it.
func (c Coverage) Warning(prefix string) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(strings.TrimRight(prefix+s, " ") + "\n") }

	w("╔══════════════════════════════════════════════════════════════════════════╗")
	w("║  PARTIAL EXPORT — THIS IS NOT A COMPLETE ground FOUNDATION               ║")
	w("╚══════════════════════════════════════════════════════════════════════════╝")
	w("")
	w("Creates:")
	for _, s := range c.Covered {
		w("  ✓ " + s)
	}
	w("")
	w("Does NOT create:")
	for _, s := range c.Missing {
		w("  ✗ " + s)
	}
	w("")
	w("Applying this gives you the org SHAPE with NOTHING ENFORCING ANYTHING.")
	w("That is more dangerous than deploying nothing, because it looks finished.")
	w("")
	w("For a complete foundation use ground's own deploy path:")
	w("    ground deploy --config ground.yaml")
	w("")
	w("If you must standardise on another toolchain, deploy the guardrails some other")
	w("way and verify posture with 'attest scan' — ground makes zero compliance claims.")
	return b.String()
}

// Generator produces IaC artifacts for a given output format.
type Generator struct {
	format    Format
	outputDir string
	version   string
}

// NewGenerator creates an IaC generator. version is stamped into the generated
// artifacts' managed-by tags; pass ground's build version so a tagged
// foundation and its export cannot disagree about which ground produced them.
func NewGenerator(format Format, outputDir, version string) *Generator {
	if version == "" {
		version = "unknown"
	}
	return &Generator{format: format, outputDir: outputDir, version: version}
}

// Coverage reports what this generator's output does and does not include.
func (g *Generator) Coverage() Coverage { return exportCoverage }

// Generate produces IaC artifacts. It writes files and deploys nothing.
func (g *Generator) Generate(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	switch g.format {
	case FormatTerraform, FormatOpenTofu:
		return g.generateHCL(cfg)
	case FormatCDK:
		return g.generateCDK(cfg)
	case FormatCloudFormation:
		return fmt.Errorf("cloudformation is ground's deploy path, not an export: use 'ground deploy'")
	default:
		return fmt.Errorf("unknown IaC format %q", g.format)
	}
}

// writeFiles writes every artifact, failing on the first error. Files are
// written in sorted order so a partial failure is reproducible.
func (g *Generator) writeFiles(files map[string]string) error {
	if err := os.MkdirAll(g.outputDir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(g.outputDir, n), []byte(files[n]), 0o640); err != nil {
			return fmt.Errorf("write %s: %w", n, err)
		}
	}
	return nil
}

// readmeCoverageTable renders the coverage as Markdown for a generated README.
func (g *Generator) readmeCoverageTable() string {
	var b strings.Builder
	b.WriteString("## ⚠️ This is a PARTIAL export — not a complete ground foundation\n\n")
	b.WriteString("| | Component |\n|---|---|\n")
	for _, s := range exportCoverage.Covered {
		b.WriteString("| ✅ | " + s + " |\n")
	}
	for _, s := range exportCoverage.Missing {
		b.WriteString("| ❌ | **" + s + "** |\n")
	}
	b.WriteString("\nApplying this gives you the organizational *shape* with **nothing enforcing anything**.\n")
	b.WriteString("No SCP restricts any action; no CloudTrail records any API call. That is a worse\n")
	b.WriteString("position than deploying nothing, because it looks finished.\n\n")
	b.WriteString("For a complete foundation, use ground's own deploy path:\n\n")
	b.WriteString("```bash\nground deploy --config ground.yaml\n```\n\n")
	b.WriteString("ground makes **zero compliance claims** either way — run `attest scan` for posture.\n")
	return b.String()
}

// --- Terraform / OpenTofu (identical HCL) -------------------------------------

func (g *Generator) generateHCL(cfg *config.Config) error {
	tool := Tool(g.format)

	var b strings.Builder
	b.WriteString("# SPDX-FileCopyrightText: 2026 Playground Logic LLC\n")
	b.WriteString("# SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("# Generated by ground " + g.version + ". Do not edit manually.\n#\n")
	b.WriteString(exportCoverage.Warning("# "))
	b.WriteString("\n")

	// NOTE: this block is terraform-fmt-canonical (verified by TestHCL_IsFmtClean).
	// Alignment matters: `terraform fmt` aligns consecutive single-line
	// assignments, so hand-written padding that looks tidy is often wrong.
	b.WriteString(`terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "` + cfg.Org.Region + `"
}

variable "identity_center_instance_arn" {
  description = "IAM Identity Center instance ARN. Empty disables permission sets."
  type        = string
  default     = ""
}

data "aws_organizations_organization" "current" {}

locals {
  org_root_id = data.aws_organizations_organization.current.roots[0].id
  managed_tags = {
    "managed-by"     = "ground"
    "ground:version" = "` + g.version + `"
    "ground:export"  = "hcl-partial"
  }
}

# ── Organizational Units ───────────────────────────────────────────────────

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.org_root_id
  tags      = merge(local.managed_tags, { "ground:tier" = "security" })
}

resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = local.org_root_id
  tags      = merge(local.managed_tags, { "ground:tier" = "infrastructure" })
}

resource "aws_organizations_organizational_unit" "research" {
  name      = "Research"
  parent_id = local.org_root_id
  tags      = merge(local.managed_tags, { "ground:tier" = "research" })
}

resource "aws_organizations_organizational_unit" "sensitive_research" {
  name      = "SensitiveResearch"
  parent_id = local.org_root_id
  tags      = merge(local.managed_tags, { "ground:tier" = "sensitive" })
}

resource "aws_organizations_organizational_unit" "dod_cmmc" {
  name      = "DoD-CMMC"
  parent_id = local.org_root_id
  tags      = merge(local.managed_tags, { "ground:tier" = "dod" })
}

# Sub-OUs under SensitiveResearch. vendor resolves these BY NAME (ground-meta
# carries no OU ids), so renaming one breaks 'vendor provision --type'.
resource "aws_organizations_organizational_unit" "nih_genomic" {
  name      = "NIHGenomic"
  parent_id = aws_organizations_organizational_unit.sensitive_research.id
  tags      = merge(local.managed_tags, { "ground:tier" = "sensitive", "ground:data-scope" = "genomic" })
}

resource "aws_organizations_organizational_unit" "hipaa_research" {
  name      = "HIPAAResearch"
  parent_id = aws_organizations_organizational_unit.sensitive_research.id
  tags      = merge(local.managed_tags, { "ground:tier" = "sensitive", "ground:data-scope" = "phi" })
}

resource "aws_organizations_organizational_unit" "cui_research" {
  name      = "CUIResearch"
  parent_id = aws_organizations_organizational_unit.sensitive_research.id
  tags      = merge(local.managed_tags, { "ground:tier" = "sensitive", "ground:data-scope" = "cui" })
}

# ── IAM Identity Center Permission Sets ───────────────────────────────────
#
# These create the permission sets only. The MFA / IP-allowlist conditions the
# descriptions mention are enforced by SCPs and permission boundaries that this
# export does NOT create — the names below promise more than the HCL delivers.

resource "aws_ssoadmin_permission_set" "ground_user" {
  count            = var.identity_center_instance_arn != "" ? 1 : 0
  name             = "GroundUser"
  description      = "Standard user access — Research OU"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT1H"
  tags             = local.managed_tags
}

resource "aws_ssoadmin_permission_set" "ground_sensitive_user" {
  count            = var.identity_center_instance_arn != "" ? 1 : 0
  name             = "GroundSensitiveUser"
  description      = "Sensitive Research OU — FIDO2 MFA required, IP allowlist enforced"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT1H"
  tags             = local.managed_tags
}

resource "aws_ssoadmin_permission_set" "ground_sre_admin" {
  count            = var.identity_center_instance_arn != "" ? 1 : 0
  name             = "GroundSREAdmin"
  description      = "SRE administrator — phishing-resistant MFA, all sessions logged"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT1H"
  tags             = local.managed_tags
}

resource "aws_ssoadmin_permission_set" "ground_auditor" {
  count            = var.identity_center_instance_arn != "" ? 1 : 0
  name             = "GroundAuditor"
  description      = "Read-only auditor access — 8-hour session"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT8H"
  tags             = local.managed_tags
}

# ── Outputs ───────────────────────────────────────────────────────────────

output "security_ou_id" { value = aws_organizations_organizational_unit.security.id }
output "infrastructure_ou_id" { value = aws_organizations_organizational_unit.infrastructure.id }
output "research_ou_id" { value = aws_organizations_organizational_unit.research.id }
output "sensitive_research_ou_id" { value = aws_organizations_organizational_unit.sensitive_research.id }
output "dod_cmmc_ou_id" { value = aws_organizations_organizational_unit.dod_cmmc.id }
output "nih_genomic_ou_id" { value = aws_organizations_organizational_unit.nih_genomic.id }
output "hipaa_research_ou_id" { value = aws_organizations_organizational_unit.hipaa_research.id }
output "cui_research_ou_id" { value = aws_organizations_organizational_unit.cui_research.id }
`)

	readme := "# ground — " + tool + " export\n\n" +
		"Generated by `ground export-iac --format " + string(g.format) + "`.\n\n" +
		g.readmeCoverageTable() +
		"\n## Apply\n\n```bash\n" + tool + " init\n" + tool + " plan\n" + tool + " apply\n```\n\n" +
		"Set `identity_center_instance_arn` (or `TF_VAR_identity_center_instance_arn`) to create the\n" +
		"permission sets; leaving it empty skips them.\n\n" +
		"The HCL uses only `hashicorp/aws ~> 5.0` and no tool-specific features, so the same file\n" +
		"applies under both **Terraform** and **OpenTofu** — `--format terraform` and\n" +
		"`--format opentofu` differ only in the directory name and these instructions.\n"

	return g.writeFiles(map[string]string{
		"main.tf":   b.String(),
		"README.md": readme,
	})
}

// --- CDK TypeScript ----------------------------------------------------------

func (g *Generator) generateCDK(cfg *config.Config) error {
	stack := `// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0
// Generated by ground ` + g.version + `. Do not edit manually.
//
` + exportCoverage.Warning("// ") + `
import * as cdk from 'aws-cdk-lib';
import * as organizations from 'aws-cdk-lib/aws-organizations';
import * as sso from 'aws-cdk-lib/aws-sso';
import { Construct } from 'constructs';

export interface GroundFoundationProps extends cdk.StackProps {
  identityCenterInstanceArn?: string;
}

export class GroundFoundationStack extends cdk.Stack {
  public readonly securityOuId: string;
  public readonly sensitiveResearchOuId: string;

  constructor(scope: Construct, id: string, props: GroundFoundationProps = {}) {
    super(scope, id, props);

    const managedTags = [
      { key: 'managed-by', value: 'ground' },
      { key: 'ground:version', value: '` + g.version + `' },
      { key: 'ground:export', value: 'cdk-partial' },
    ];

    // ── Organizational Units ──────────────────────────────────────────────

    // The org root ID is obtained at deploy time via a custom resource.
    const orgRoot = new cdk.custom_resources.AwsCustomResource(this, 'OrgRoot', {
      onUpdate: {
        service: 'Organizations',
        action: 'listRoots',
        parameters: {},
        physicalResourceId: cdk.custom_resources.PhysicalResourceId.fromResponse('Roots.0.Id'),
      },
      policy: cdk.custom_resources.AwsCustomResourcePolicy.fromSdkCalls({
        resources: cdk.custom_resources.AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    });
    const rootId = orgRoot.getResponseField('Roots.0.Id');

    const securityOU = new organizations.CfnOrganizationalUnit(this, 'SecurityOU', {
      name: 'Security',
      parentId: rootId,
      tags: [...managedTags, { key: 'ground:tier', value: 'security' }],
    });

    const infrastructureOU = new organizations.CfnOrganizationalUnit(this, 'InfrastructureOU', {
      name: 'Infrastructure',
      parentId: rootId,
      tags: [...managedTags, { key: 'ground:tier', value: 'infrastructure' }],
    });

    const researchOU = new organizations.CfnOrganizationalUnit(this, 'ResearchOU', {
      name: 'Research',
      parentId: rootId,
      tags: [...managedTags, { key: 'ground:tier', value: 'research' }],
    });

    const sensitiveResearchOU = new organizations.CfnOrganizationalUnit(this, 'SensitiveResearchOU', {
      name: 'SensitiveResearch',
      parentId: rootId,
      tags: [...managedTags, { key: 'ground:tier', value: 'sensitive' }],
    });

    new organizations.CfnOrganizationalUnit(this, 'DoDCMMCOU', {
      name: 'DoD-CMMC',
      parentId: rootId,
      tags: [...managedTags, { key: 'ground:tier', value: 'dod' }],
    });

    // Sub-OUs under SensitiveResearch. vendor resolves these BY NAME
    // (ground-meta carries no OU ids), so renaming one breaks vendor.
    new organizations.CfnOrganizationalUnit(this, 'NIHGenomicOU', {
      name: 'NIHGenomic',
      parentId: sensitiveResearchOU.ref,
      tags: [...managedTags, { key: 'ground:tier', value: 'sensitive' }, { key: 'ground:data-scope', value: 'genomic' }],
    });
    new organizations.CfnOrganizationalUnit(this, 'HIPAAResearchOU', {
      name: 'HIPAAResearch',
      parentId: sensitiveResearchOU.ref,
      tags: [...managedTags, { key: 'ground:tier', value: 'sensitive' }, { key: 'ground:data-scope', value: 'phi' }],
    });
    new organizations.CfnOrganizationalUnit(this, 'CUIResearchOU', {
      name: 'CUIResearch',
      parentId: sensitiveResearchOU.ref,
      tags: [...managedTags, { key: 'ground:tier', value: 'sensitive' }, { key: 'ground:data-scope', value: 'cui' }],
    });

    this.securityOuId = securityOU.ref;
    this.sensitiveResearchOuId = sensitiveResearchOU.ref;

    // ── IAM Identity Center Permission Sets (optional) ────────────────────
    //
    // Permission sets only. The MFA / IP-allowlist conditions the descriptions
    // mention are enforced by SCPs and permission boundaries this export does
    // NOT create — the names promise more than the stack delivers.

    if (props.identityCenterInstanceArn) {
      new sso.CfnPermissionSet(this, 'GroundUser', {
        instanceArn: props.identityCenterInstanceArn,
        name: 'GroundUser',
        description: 'Standard user access — Research OU',
        sessionDuration: 'PT1H',
        tags: managedTags,
      });

      new sso.CfnPermissionSet(this, 'GroundSensitiveUser', {
        instanceArn: props.identityCenterInstanceArn,
        name: 'GroundSensitiveUser',
        description: 'Sensitive Research OU — FIDO2 MFA required, IP allowlist enforced',
        sessionDuration: 'PT1H',
        tags: managedTags,
      });

      new sso.CfnPermissionSet(this, 'GroundSREAdmin', {
        instanceArn: props.identityCenterInstanceArn,
        name: 'GroundSREAdmin',
        description: 'SRE administrator — phishing-resistant MFA, all sessions logged',
        sessionDuration: 'PT1H',
        tags: managedTags,
      });

      new sso.CfnPermissionSet(this, 'GroundAuditor', {
        instanceArn: props.identityCenterInstanceArn,
        name: 'GroundAuditor',
        description: 'Read-only auditor — 8-hour session',
        sessionDuration: 'PT8H',
        tags: managedTags,
      });
    }

    // ── Stack Outputs ─────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'SecurityOuId', { value: securityOU.ref });
    new cdk.CfnOutput(this, 'SensitiveResearchOuId', { value: sensitiveResearchOU.ref });
    new cdk.CfnOutput(this, 'InfrastructureOuId', { value: infrastructureOU.ref });
    new cdk.CfnOutput(this, 'ResearchOuId', { value: researchOU.ref });
  }
}

const app = new cdk.App();
new GroundFoundationStack(app, 'GroundFoundationStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region:  process.env.CDK_DEFAULT_REGION ?? '` + cfg.Org.Region + `',
  },
  identityCenterInstanceArn: process.env.IDENTITY_CENTER_INSTANCE_ARN,
});
`

	packageJSON := `{
  "name": "ground-foundation",
  "version": "` + g.version + `",
  "description": "ground IaC export (PARTIAL — OU hierarchy and permission sets only, no guardrails)",
  "scripts": {
    "build": "tsc",
    "cdk": "cdk"
  },
  "dependencies": {
    "aws-cdk-lib": "^2.100.0",
    "constructs": "^10.0.0"
  },
  "devDependencies": {
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  }
}
`
	cdkJSON := `{
  "app": "npx ts-node stack.ts",
  "context": {
    "@aws-cdk/core:enablePartitionLiterals": true
  }
}
`
	tsconfig := `{
  "compilerOptions": {
    "target": "ES2018",
    "module": "commonjs",
    "lib": ["es2018"],
    "declaration": true,
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "esModuleInterop": true,
    "outDir": "dist"
  },
  "exclude": ["node_modules", "dist"]
}
`
	readme := "# ground — CDK export\n\nGenerated by `ground export-iac --format cdk`.\n\n" +
		g.readmeCoverageTable() +
		"\n## Deploy\n\n```bash\nnpm install\nnpm run build\ncdk diff\ncdk deploy\n```\n\n" +
		"Set `IDENTITY_CENTER_INSTANCE_ARN` to create the permission sets.\n\n" +
		"Note this emits `Cfn*` L1 constructs and a `listRoots` custom resource — it is a CDK\n" +
		"wrapper around the same CloudFormation resources, not an idiomatic L2 stack.\n"

	return g.writeFiles(map[string]string{
		"stack.ts":      stack,
		"package.json":  packageJSON,
		"cdk.json":      cdkJSON,
		"tsconfig.json": tsconfig,
		"README.md":     readme,
	})
}
