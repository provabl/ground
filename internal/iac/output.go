// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package iac exports a ground foundation as Infrastructure-as-Code for
// operators who standardise on a toolchain other than CloudFormation.
//
// **CloudFormation remains ground's deploy path**; these are exports. The two
// formats differ in how they are produced, and that difference is what decides
// whether each can be trusted:
//
//   - **terraform / opentofu** — *transpiled* from the same [cfn.Template]
//     values `ground deploy` submits (see transpile.go). Because the HCL is
//     derived from the templates rather than written alongside them, a resource
//     added to internal/stack appears in the export automatically, and one the
//     transpiler cannot represent faithfully is an [UnsupportedError] rather
//     than a silent omission. This is at parity, enforced by tests that compare
//     the export against the stacks themselves.
//   - **cdk** — still a hand-written subset: the OU hierarchy and permission
//     sets, and no guardrails at all. Applying it yields an org *shape* with
//     nothing enforcing anything, which is worse than deploying nothing because
//     it looks done.
//
// [Coverage] carries that distinction as data, and every artifact states its own
// coverage in-band: a banner on stdout, a header in the generated file, and a
// table in the generated README, all rendered from the one record so they cannot
// drift.
//
// `attest scan` is what establishes posture in every case — ground makes zero
// compliance claims, whichever toolchain applied the foundation.
package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/provabl/ground/internal/config"
	"github.com/provabl/ground/internal/stack/accounts"
	"github.com/provabl/ground/internal/stack/identity"
	"github.com/provabl/ground/internal/stack/logging"
	"github.com/provabl/ground/internal/stack/network"
	"github.com/provabl/ground/internal/stack/security"
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
	// Complete reports whether the export reproduces every resource ground's
	// CloudFormation deploys. It selects the banner: a complete export gets a
	// caveat, an incomplete one gets a warning.
	Complete bool
	// Covered is what the export actually creates.
	Covered []string
	// Missing is what the export does NOT create. For a complete export these are
	// things the CloudFormation path does not create either.
	Missing []string
}

// hclCoverage describes the HCL export, which is transpiled from the same
// cfn.Templates `ground deploy` submits and therefore reproduces every resource
// in them. TestHCL_CoversEveryStackResource enforces that claim against the
// stacks themselves, so this cannot quietly become untrue.
//
// The remaining Missing entries are things the *CloudFormation path does not
// deploy either* — they are listed so an operator reading only the export's
// README does not mistake a complete export for a complete compliance posture.
var hclCoverage = Coverage{
	Complete: true,
	Covered: []string{
		"Organizational Units — the full 8-OU hierarchy, including the nested sub-OUs",
		"Logging foundation — S3 audit bucket (KMS, versioning, Object Lock, lifecycle), bucket policy, org-wide CloudTrail, AWS Config recorder + delivery channel + role",
		"The logging-protection SCP — created AND attached to the org root",
		"Network — Transit Gateway, hub and per-tier spoke VPCs, subnets, route tables, segregated TGW route tables/associations/routes, and the org-conditioned VPC endpoints",
		"IAM Identity Center permission sets (5) — including their managed-policy attachments, when an instance ARN is configured",
	},
	Missing: []string{
		"Framework SCPs — the policy documents in ground/policies/ are compiled and attached by 'attest compile' + 'attest apply', not by ground, in either path",
		"Security detection services — GuardDuty, Security Hub, and Macie are enabled by attest after it knows which frameworks are active; the CloudFormation path does not create them either",
		"Compliance claims — ground makes none. Run 'attest scan' for posture, whichever toolchain applied the foundation",
	},
}

// cdkCoverage describes the CDK export, which is still hand-written from a
// subset. It is listed separately from [hclCoverage] rather than sharing one
// blurred description, because a single Coverage covering both would have to
// describe the weaker of the two and would understate the HCL.
var cdkCoverage = Coverage{
	Covered: []string{
		"Organizational Units — the full 8-OU hierarchy, including the nested sub-OUs",
		"IAM Identity Center permission sets (4) — when an instance ARN is supplied",
	},
	Missing: []string{
		"Service Control Policies — the logging-protection SCP is NOT created or attached",
		"Logging foundation — no S3 audit bucket, no org-wide CloudTrail, no AWS Config recorder",
		"Network — no VPCs, subnets, Transit Gateway, or VPC endpoints",
		"Security services — no GuardDuty, Security Hub, or Macie enablement",
	},
}

// coverageFor returns the coverage record for f.
func coverageFor(f Format) Coverage {
	if IsHCL(f) {
		return hclCoverage
	}
	return cdkCoverage
}

// IsPartial reports whether f produces a partial export — one that does not
// reproduce every resource ground's CloudFormation deploys. The HCL export is
// transpiled from those templates and is complete; CDK is still a hand-written
// subset.
func IsPartial(f Format) bool { return f != FormatCloudFormation && !IsHCL(f) }

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
	if c.Complete {
		w("║  COMPLETE EXPORT — transpiled from ground's own CloudFormation           ║")
	} else {
		w("║  PARTIAL EXPORT — THIS IS NOT A COMPLETE ground FOUNDATION               ║")
	}
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
	if c.Complete {
		w("Every resource here is transpiled from the same templates 'ground deploy'")
		w("submits, so the two paths deploy the same foundation. What differs is the")
		w("state: applying this makes your tool the owner of these resources. Do not")
		w("apply it over an org ground already deployed — import first, or you will")
		w("get duplicate-name errors on the OUs and the SCP.")
	} else {
		w("Applying this gives you the org SHAPE with NOTHING ENFORCING ANYTHING.")
		w("That is more dangerous than deploying nothing, because it looks finished.")
		w("")
		w("For a complete foundation use ground's own deploy path:")
		w("    ground deploy --config ground.yaml")
	}
	w("")
	w("ground makes zero compliance claims either way — verify posture with 'attest scan'.")
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
func (g *Generator) Coverage() Coverage { return coverageFor(g.format) }

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
	c := coverageFor(g.format)

	var b strings.Builder
	if c.Complete {
		b.WriteString("## Coverage — transpiled from ground's own CloudFormation\n\n")
	} else {
		b.WriteString("## ⚠️ This is a PARTIAL export — not a complete ground foundation\n\n")
	}
	b.WriteString("| | Component |\n|---|---|\n")
	for _, s := range c.Covered {
		b.WriteString("| ✅ | " + s + " |\n")
	}
	for _, s := range c.Missing {
		b.WriteString("| ❌ | **" + s + "** |\n")
	}
	b.WriteString("\n")
	if c.Complete {
		b.WriteString("Every resource above is transpiled from the same `cfn.Template` values `ground deploy`\n")
		b.WriteString("submits to CloudFormation, so both paths deploy the same foundation. A resource the\n")
		b.WriteString("transpiler cannot represent faithfully is a hard error, never a silent omission.\n\n")
		b.WriteString("**State ownership is the real difference.** Applying this makes your tool the owner of\n")
		b.WriteString("these resources. Do not apply it over an org `ground deploy` already created — the OU\n")
		b.WriteString("names and the SCP name are unique, so you will get duplicate-name errors. Import the\n")
		b.WriteString("existing resources first, or start from an org neither tool has touched.\n\n")
	} else {
		b.WriteString("Applying this gives you the organizational *shape* with **nothing enforcing anything**.\n")
		b.WriteString("No SCP restricts any action; no CloudTrail records any API call. That is a worse\n")
		b.WriteString("position than deploying nothing, because it looks finished.\n\n")
		b.WriteString("For a complete foundation, use ground's own deploy path:\n\n")
		b.WriteString("```bash\nground deploy --config ground.yaml\n```\n\n")
	}
	b.WriteString("ground makes **zero compliance claims** either way — run `attest scan` for posture.\n")
	return b.String()
}

// --- Terraform / OpenTofu (identical HCL) -------------------------------------

// hclStacks builds every CloudFormation template ground would deploy, in the
// same order and from the same code path as `ground deploy`.
//
// The exports are transpiled from these, not written alongside them. That is the
// whole reason parity holds: a resource added to internal/stack appears in the
// export automatically, and one the transpiler cannot render is a hard error.
func hclStacks(cfg *config.Config) ([]stackTemplate, error) {
	logTmpl, err := logging.New(&cfg.Logging, &cfg.Org).Template()
	if err != nil {
		return nil, fmt.Errorf("logging stack: %w", err)
	}
	secTmpl, err := security.New(&cfg.Security, &cfg.Org).Template()
	if err != nil {
		return nil, fmt.Errorf("security stack: %w", err)
	}
	accountsTmpl, err := accounts.New(&cfg.Org).Template()
	if err != nil {
		return nil, fmt.Errorf("accounts stack: %w", err)
	}
	identityTmpl, err := identity.New(&cfg.Identity).Template()
	if err != nil {
		return nil, fmt.Errorf("identity stack: %w", err)
	}
	netTmpl, err := network.New(&cfg.Network, &cfg.Org).Template()
	if err != nil {
		return nil, fmt.Errorf("network stack: %w", err)
	}

	// Same order as runDeploy: logging and its protection SCP, then the org
	// structure, then the network that rides on it.
	return []stackTemplate{
		{title: "Logging foundation — S3 audit bucket, CloudTrail, AWS Config", template: logTmpl},
		{title: "Security — the logging-protection SCP", template: secTmpl},
		{title: "Account structure — the OU hierarchy", template: accountsTmpl},
		{title: "Identity — IAM Identity Center permission sets", template: identityTmpl},
		{title: "Network — Transit Gateway, VPCs, subnets, endpoints", template: netTmpl},
	}, nil
}

// dataSourceBlocks declares the Terraform data sources the transpiled
// expressions reference — exactly those, so there are no unused declarations and
// no dangling references.
var dataSourceBlocks = map[string]hclBlock{
	"aws_organizations_organization": {header: `data "aws_organizations_organization" "current"`},
	"aws_availability_zones": {
		header: `data "aws_availability_zones" "available"`,
		args:   []string{arg("state", `"available"`)},
	},
	"aws_caller_identity": {header: `data "aws_caller_identity" "current"`},
	"aws_region":          {header: `data "aws_region" "current"`},
	"aws_partition":       {header: `data "aws_partition" "current"`},
}

func (g *Generator) generateHCL(cfg *config.Config) error {
	tool := Tool(g.format)

	stacks, err := hclStacks(cfg)
	if err != nil {
		return err
	}

	t := newTranspiler()
	if err := t.plan(stacks); err != nil {
		return err
	}

	// Render resources first: it is what populates the data-source and variable
	// sets that the preamble has to declare.
	var body strings.Builder
	for _, st := range stacks {
		blocks, err := t.emitStack(st)
		if err != nil {
			return err
		}
		if len(blocks) == 0 {
			continue
		}
		body.WriteString("# ── " + st.title + " " + strings.Repeat("─", max(0, 68-len(st.title))) + "\n\n")
		for _, b := range blocks {
			body.WriteString(b.render(""))
			body.WriteString("\n")
		}
	}

	var b strings.Builder
	b.WriteString("# SPDX-FileCopyrightText: 2026 Playground Logic LLC\n")
	b.WriteString("# SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("# Generated by ground " + g.version + " from the same CloudFormation templates\n")
	b.WriteString("# 'ground deploy' submits. Do not edit manually — edit internal/stack and re-export.\n#\n")
	b.WriteString(hclCoverage.Warning("# "))
	b.WriteString("\n")

	// Terraform / provider requirements and the provider itself.
	b.WriteString(hclBlock{
		header: "terraform",
		args:   []string{arg("required_version", `">= 1.5"`)},
		nested: []hclBlock{{
			header: "required_providers",
			nested: []hclBlock{{
				// An attribute holding an object, not a block — `aws { ... }` is a parse
				// error inside required_providers.
				header: "aws =",
				args:   []string{arg("source", `"hashicorp/aws"`), arg("version", `"~> 5.0"`)},
			}},
		}},
	}.render(""))
	b.WriteString("\n")
	b.WriteString(hclBlock{header: `provider "aws"`, args: []string{arg("region", "var.region")}}.render(""))
	b.WriteString("\n")

	// Variables: region, plus one per CloudFormation parameter that `ground deploy`
	// does not auto-discover.
	b.WriteString(hclBlock{
		header: `variable "region"`,
		args: []string{
			arg("description", `"AWS region"`),
			arg("type", "string"),
			arg("default", quoteHCL(cfg.Org.Region)),
		},
	}.render(""))
	b.WriteString("\n")
	for _, name := range sortedVarNames(t.paramVars) {
		p := t.paramVars[name]
		vb := hclBlock{header: fmt.Sprintf("variable %q", tfName(name))}
		if p.description != "" {
			vb.args = append(vb.args, arg("description", quoteHCL(p.description)))
		}
		vb.args = append(vb.args, arg("type", "string"))
		if p.defaultVal != "" {
			vb.args = append(vb.args, arg("default", quoteHCL(p.defaultVal)))
		}
		b.WriteString(vb.render(""))
		b.WriteString("\n")
	}

	for _, name := range sortedBoolKeys(t.resolver.dataSources) {
		ds, ok := dataSourceBlocks[name]
		if !ok {
			// Unreachable unless a resolver gains a data source without declaring it
			// here; failing is better than emitting a dangling reference.
			return fmt.Errorf("internal: no declaration for data source %q", name)
		}
		b.WriteString(ds.render(""))
		b.WriteString("\n")
	}

	b.WriteString(hclBlock{
		header: "locals",
		nested: []hclBlock{{
			// An attribute holding an object literal, not a block — HCL renders the
			// two identically, so hclBlock can express it with a header ending in "=".
			header: "managed_tags =",
			args: []string{
				`"managed-by"     = "ground"`,
				`"ground:version" = ` + quoteHCL(g.version),
				`"ground:export"  = "hcl"`,
			},
		}},
	}.render(""))
	b.WriteString("\n")

	b.WriteString(body.String())

	// Outputs, transpiled from every stack's Outputs.
	outputs, err := t.emitOutputs(stacks)
	if err != nil {
		return err
	}
	if len(outputs) > 0 {
		b.WriteString("# ── Outputs " + strings.Repeat("─", 62) + "\n\n")
		for _, o := range outputs {
			b.WriteString(o.render(""))
			b.WriteString("\n")
		}
	}

	readme := "# ground — " + tool + " export\n\n" +
		"Generated by `ground export-iac --format " + string(g.format) + "` from the same\n" +
		"CloudFormation templates `ground deploy` submits.\n\n" +
		g.readmeCoverageTable() +
		"\n## Apply\n\n```bash\n" + tool + " init\n" + tool + " plan\n" + tool + " apply\n```\n\n" +
		"The org root ID and organization ID are read via the `aws_organizations_organization`\n" +
		"data source — the same values `ground deploy` discovers through the Organizations API, so\n" +
		"neither path asks you for them. Credentials must be for the **Organization management\n" +
		"account**.\n\n" +
		"Set `identity_center_instance_arn` in `ground.yaml` before exporting to include the\n" +
		"permission sets; without it ground's own identity stack emits nothing either.\n\n" +
		"## Regenerating\n\n" +
		"Do not hand-edit `main.tf`. It is transpiled output: change `ground.yaml` or\n" +
		"`internal/stack`, then re-run the export. Edits here are lost on the next export and\n" +
		"make the two deploy paths disagree.\n\n" +
		"The HCL uses only `hashicorp/aws ~> 5.0` and no tool-specific features, so the same file\n" +
		"applies under both **Terraform** and **OpenTofu** — `--format terraform` and\n" +
		"`--format opentofu` differ only in the directory name and these instructions. Both are\n" +
		"`fmt`-checked and `validate`-checked in CI.\n"

	return g.writeFiles(map[string]string{
		"main.tf":   b.String(),
		"README.md": readme,
	})
}

// emitOutputs transpiles every stack's CloudFormation Outputs into Terraform
// output blocks. CFN cross-stack Exports have no Terraform equivalent (Terraform
// uses remote state), so the export name is dropped and noted in a comment
// rather than silently discarded.
func (t *transpiler) emitOutputs(stacks []stackTemplate) ([]hclBlock, error) {
	var out []hclBlock
	seen := map[string]bool{}
	for _, st := range stacks {
		for _, name := range sortedKeys(st.template.Outputs) {
			o, ok := st.template.Outputs[name].(map[string]any)
			if !ok {
				continue
			}
			tfOut := tfName(name)
			if seen[tfOut] {
				return nil, &UnsupportedError{
					Construct: "output " + name,
					Reason:    "two stacks produce the Terraform output name " + tfOut,
				}
			}
			seen[tfOut] = true

			expr, err := t.resolver.resolveValue("output "+name, o["Value"])
			if err != nil {
				return nil, err
			}
			b := hclBlock{header: fmt.Sprintf("output %q", tfOut), args: []string{arg("value", expr)}}
			if desc, _ := o["Description"].(string); desc != "" {
				b.args = append(b.args, arg("description", quoteHCL(desc)))
			}
			if exp, ok := o["Export"].(map[string]string); ok && exp["Name"] != "" {
				b.comment = "CloudFormation exported this as " + exp["Name"] + "; Terraform has no\n" +
					"cross-stack Export — consumers read it from this module's remote state."
			}
			out = append(out, b)
		}
	}
	return out, nil
}

func sortedVarNames(m map[string]cfnParam) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- CDK TypeScript ----------------------------------------------------------

func (g *Generator) generateCDK(cfg *config.Config) error {
	stack := `// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0
// Generated by ground ` + g.version + `. Do not edit manually.
//
` + cdkCoverage.Warning("// ") + `
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
