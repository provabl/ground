// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
	"github.com/provabl/ground/internal/stack/accounts"
	"github.com/provabl/ground/internal/stack/logging"
)

// testConfig exercises every stack: without a Transit Gateway, endpoints, and an
// Identity Center instance ARN the corresponding templates emit nothing, and the
// parity test would pass while covering a third of the foundation.
func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Org.Name = "Test University"
	cfg.Org.Region = "us-west-2"
	cfg.Org.ManagementID = "123456789012"
	cfg.Org.AuditEmail = "audit@example.edu"
	cfg.Org.LoggingEmail = "logging@example.edu"
	cfg.Org.WorkloadOUs = []string{"research", "sandbox"}

	cfg.Network.TransitGateway = true
	cfg.Network.CIDRBlock = "10.0.0.0/8"
	cfg.Network.VPCEndpoints = []string{"s3", "ec2", "sts", "ssm", "kms", "logs", "secretsmanager"}
	cfg.Network.DataEndpoints = []config.DataEndpoint{{
		Name:          "ncbi-dbgap",
		Vendor:        "NCBI dbGaP",
		URL:           "s3.amazonaws.com",
		DataClass:     "GENOMIC",
		SRETypes:      []string{"nih-genomics"},
		AuthorizedOUs: []string{"SensitiveResearch/NIHGenomic"},
	}}

	cfg.Identity.IdentityCenter = true
	cfg.Identity.InstanceARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"

	cfg.Logging.RetentionDays = 365

	return cfg
}

// generate runs the generator into a temp dir and returns the artifacts by name.
func generate(t *testing.T, f Format) (string, map[string]string) {
	t.Helper()
	return generateWith(t, f, testConfig())
}

func generateWith(t *testing.T, f Format, cfg *config.Config) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := NewGenerator(f, dir, "9.9.9").Generate(cfg); err != nil {
		t.Fatalf("Generate(%s): %v", f, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	files := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		files[e.Name()] = string(b)
	}
	return dir, files
}

// --- Parity ------------------------------------------------------------------

// The claim hclCoverage makes is that the HCL export reproduces every resource
// ground's CloudFormation deploys. This is what makes that claim true rather than
// aspirational: it builds the same templates `ground deploy` submits and asserts
// each one's resources appear in the export.
//
// A resource added to internal/stack and not taught to the transpiler fails here
// (or, more likely, fails Generate with an UnsupportedError) instead of silently
// vanishing from the export — which is the failure mode the whole transpiler
// design exists to prevent.
func TestHCL_CoversEveryStackResource(t *testing.T) {
	cfg := testConfig()
	stacks, err := hclStacks(cfg)
	if err != nil {
		t.Fatalf("hclStacks: %v", err)
	}
	_, files := generateWith(t, FormatTerraform, cfg)
	tf := files["main.tf"]

	covered := 0
	for _, st := range stacks {
		if st.template == nil {
			t.Errorf("stack %q produced a nil template", st.title)
			continue
		}
		for _, logicalID := range sortedKeys(st.template.Resources) {
			res, ok := st.template.Resources[logicalID].(map[string]any)
			if !ok {
				t.Errorf("%s: resource %s is not an object", st.title, logicalID)
				continue
			}
			cfnType, _ := res["Type"].(string)
			m, known := cfnToTF[cfnType]
			if !known {
				t.Errorf("%s: %s is %s, which has no entry in cfnToTF — teach the transpiler "+
					"or the export silently omits it", st.title, logicalID, cfnType)
				continue
			}
			if m.tfType == "" {
				continue // deliberately not represented (WaitConditionHandle placeholder)
			}
			want := fmt.Sprintf("resource %q %q", m.tfType, tfName(logicalID))
			if !strings.Contains(tf, want) {
				t.Errorf("%s: %s (%s) is in the CloudFormation but not the export — expected %s",
					st.title, logicalID, cfnType, want)
			}
			covered++
		}
	}

	if covered < 40 {
		t.Fatalf("only %d resources checked — testConfig no longer exercises the stacks, so "+
			"this test would pass on an export that covers almost nothing", covered)
	}
}

// expansionTypes are the Terraform resource types that exist only because the AWS
// provider splits what CloudFormation nests (S3 sub-configs, attachment
// resources). They have no CFN logical ID of their own, so the parity test above
// cannot account for them — listing them here means a new expansion has to be
// declared deliberately rather than appearing unexplained in the output.
var expansionTypes = map[string]string{
	"aws_s3_bucket_public_access_block":                  "AWS::S3::Bucket.PublicAccessBlockConfiguration",
	"aws_s3_bucket_server_side_encryption_configuration": "AWS::S3::Bucket.BucketEncryption",
	"aws_s3_bucket_versioning":                           "AWS::S3::Bucket.VersioningConfiguration",
	"aws_s3_bucket_object_lock_configuration":            "AWS::S3::Bucket.ObjectLockConfiguration",
	"aws_s3_bucket_lifecycle_configuration":              "AWS::S3::Bucket.LifecycleConfiguration",
	"aws_iam_role_policy_attachment":                     "AWS::IAM::Role.ManagedPolicyArns",
	"aws_organizations_policy_attachment":                "AWS::Organizations::Policy.TargetIds",
	"aws_ssoadmin_managed_policy_attachment":             "AWS::SSO::PermissionSet.ManagedPolicies",
}

// The converse of the parity test: nothing appears in the export that isn't
// traceable back to the CloudFormation. An export that grew a resource the deploy
// path does not create would be just as much a divergence as one missing a
// resource — and harder to notice, because it plans and applies cleanly.
func TestHCL_EmitsNothingTheStacksDoNot(t *testing.T) {
	_, files := generate(t, FormatTerraform)

	fromMapping := map[string]bool{}
	for _, m := range cfnToTF {
		if m.tfType != "" {
			fromMapping[m.tfType] = true
		}
	}

	re := regexp.MustCompile(`(?m)^resource "([a-z0-9_]+)"`)
	for _, match := range re.FindAllStringSubmatch(files["main.tf"], -1) {
		tfType := match[1]
		if fromMapping[tfType] || expansionTypes[tfType] != "" {
			continue
		}
		t.Errorf("export emits %q, which is neither a cfnToTF target nor a declared expansion — "+
			"the export must not create resources 'ground deploy' does not", tfType)
	}
}

// Every stack Output has to survive the transpile too. These are what a consumer
// reads (the OU ids vendor needs, the audit bucket ARN attest reads), so dropping
// one breaks a downstream tool rather than the foundation.
func TestHCL_CoversEveryStackOutput(t *testing.T) {
	cfg := testConfig()
	stacks, err := hclStacks(cfg)
	if err != nil {
		t.Fatalf("hclStacks: %v", err)
	}
	_, files := generateWith(t, FormatTerraform, cfg)
	tf := files["main.tf"]

	for _, st := range stacks {
		for _, name := range sortedKeys(st.template.Outputs) {
			want := fmt.Sprintf("output %q", tfName(name))
			if !strings.Contains(tf, want) {
				t.Errorf("%s: output %s is in the CloudFormation but not the export (expected %s)",
					st.title, name, want)
			}
		}
	}
}

// The guardrails are the entire reason to deploy a foundation. The export used to
// omit every one of them; pin that they are present now, and — for the SCP —
// that it is *attached*, not merely created. An unattached SCP enforces nothing
// while looking like it does.
func TestHCL_EmitsTheGuardrails(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	tf := files["main.tf"]

	for _, want := range []string{
		`resource "aws_organizations_policy" "logging_protection_scp"`,
		`resource "aws_organizations_policy_attachment" "logging_protection_scp"`,
		`resource "aws_cloudtrail"`,
		`resource "aws_config_configuration_recorder"`,
		`resource "aws_config_delivery_channel"`,
		`resource "aws_s3_bucket"`,
		`resource "aws_s3_bucket_object_lock_configuration"`,
		`resource "aws_s3_bucket_policy"`,
		`resource "aws_vpc"`,
		`resource "aws_ec2_transit_gateway"`,
		`resource "aws_vpc_endpoint"`,
		`resource "aws_ssoadmin_permission_set"`,
	} {
		if !strings.Contains(tf, want) {
			t.Errorf("export no longer emits %s — hclCoverage claims a complete foundation", want)
		}
	}

	// The SCP must attach to the org root, which is discovered rather than asked
	// for: the CloudFormation path does not prompt the operator for it either.
	if !strings.Contains(tf, "target_id = data.aws_organizations_organization.current.roots[0].id") {
		t.Error("the logging-protection SCP is not attached to the discovered org root")
	}
}

// ground manages per-tier Transit Gateway route tables precisely so a spoke
// cannot reach another tier. CloudFormation expresses that on the gateway;
// Terraform expresses it on each attachment. If the synthesized arguments are
// dropped, every attachment silently joins the default route table and the tier
// isolation is gone — with a clean plan and no error.
func TestHCL_TGWAttachmentsPreserveTierIsolation(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	tf := files["main.tf"]

	attachments := strings.Count(tf, `resource "aws_ec2_transit_gateway_vpc_attachment"`)
	if attachments == 0 {
		t.Fatal("no TGW attachments emitted — testConfig should enable the Transit Gateway")
	}
	for _, arg := range []string{
		"transit_gateway_default_route_table_association = false",
		"transit_gateway_default_route_table_propagation = false",
	} {
		if got := strings.Count(tf, arg); got != attachments {
			t.Errorf("%s appears %d times for %d attachments — every attachment must opt out of "+
				"the default route table or tier isolation is lost", arg, got, attachments)
		}
	}
}

// A CloudFormation intrinsic that reached the output verbatim would be a string
// literal Terraform happily applies as nonsense. resolveValue is supposed to
// translate or reject every one, so none may survive.
func TestHCL_NoCloudFormationIntrinsicsSurvive(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	for _, leak := range []string{"Fn::", "${AWS::", `"Ref"`, "AWSTemplateFormatVersion"} {
		if strings.Contains(files["main.tf"], leak) {
			t.Errorf("untranslated CloudFormation construct %q reached the HCL", leak)
		}
	}
}

// Data sources are declared from what the rendered expressions actually
// referenced. Both halves matter: a missing declaration is a dangling reference
// that fails validate, and an extra one is dead config in a file the operator is
// told not to edit.
func TestHCL_DeclaresExactlyTheDataSourcesItUses(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	tf := files["main.tf"]

	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^data "([a-z0-9_]+)"`).FindAllStringSubmatch(tf, -1) {
		declared[m[1]] = true
	}
	used := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bdata\.([a-z0-9_]+)\.`).FindAllStringSubmatch(tf, -1) {
		used[m[1]] = true
	}

	for name := range used {
		if !declared[name] {
			t.Errorf("data.%s is referenced but never declared — the HCL would fail validate", name)
		}
	}
	for name := range declared {
		if !used[name] {
			t.Errorf("data %q is declared but never referenced — dead config in a generated file", name)
		}
	}
	if !used["aws_organizations_organization"] {
		t.Error("the org root should come from the organizations data source, not a variable")
	}
}

// --- Fail-loud contract ------------------------------------------------------

// An unmapped resource type must stop the export. Skipping it — or emitting a
// commented placeholder — produces HCL that applies cleanly and leaves the
// operator a foundation missing exactly the resource they were relying on.
func TestTranspile_UnmappedTypeIsAnError(t *testing.T) {
	tr := newTranspiler()
	err := tr.plan([]stackTemplate{{
		title: "hypothetical",
		template: &cfn.Template{Resources: map[string]any{
			"Detector": cfn.Resource("AWS::GuardDuty::Detector", map[string]any{}),
		}},
	}})
	if err == nil {
		t.Fatal("an unmapped resource type must be an error, not a silent omission")
	}
	var ue *UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("want *UnsupportedError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "AWS::GuardDuty::Detector") {
		t.Errorf("error should name the offending type, got %q", err)
	}
}

// Same argument one level down: a property nobody mapped and nobody explicitly
// dropped changes what the export deploys.
func TestTranspile_UnmappedPropertyIsAnError(t *testing.T) {
	tr := newTranspiler()
	props := map[string]any{"CidrBlock": "10.0.0.0/16", "Ipv6CidrBlock": "::/0"}
	_, err := tr.emitResource("VPC", "AWS::EC2::VPC", cfnToTF["AWS::EC2::VPC"], props, nil)
	if err == nil {
		t.Fatal("an unmapped property must be an error")
	}
	if !strings.Contains(err.Error(), "Ipv6CidrBlock") {
		t.Errorf("error should name the offending property, got %q", err)
	}
}

// Several of ground's stacks put DependsOn inside Properties, where
// CloudFormation ignores it — so those ordering constraints are inert in the
// deploy path today. The transpiler reads both positions so the export honours
// the declared intent now AND keeps honouring it once the stacks are corrected;
// reading only one position would silently drop constraints on one side or the
// other of that fix.
func TestTranspile_DependsOnIsReadFromBothPositions(t *testing.T) {
	tr := newTranspiler()
	tr.resolver.resources["Parent"] = "aws_organizations_organizational_unit.parent.id"
	tr.resolver.resources["Other"] = "aws_s3_bucket.other.id"

	cases := map[string]struct {
		resourceLevel any
		props         map[string]any
		want          string
	}{
		"resource level (where CloudFormation reads it)": {
			resourceLevel: "Parent",
			props:         map[string]any{"Name": "X"},
			want:          "depends_on = [aws_organizations_organizational_unit.parent]",
		},
		"inside Properties (where ground's stacks put it)": {
			props: map[string]any{"Name": "X", "DependsOn": "Parent"},
			want:  "depends_on = [aws_organizations_organizational_unit.parent]",
		},
		"both, deduplicated": {
			resourceLevel: []string{"Parent", "Other"},
			props:         map[string]any{"Name": "X", "DependsOn": "Parent"},
			want:          "depends_on = [aws_organizations_organizational_unit.parent, aws_s3_bucket.other]",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := cfnToTF["AWS::Organizations::OrganizationalUnit"]
			blocks, err := tr.emitResource("Child", "AWS::Organizations::OrganizationalUnit", m, tc.props, tc.resourceLevel)
			if err != nil {
				t.Fatalf("emitResource: %v", err)
			}
			got := blocks[0].render("")
			if !strings.Contains(got, tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, got)
			}
		})
	}

	// depends_on takes a resource address, never one of its attributes.
	if refs := tr.dependsOn("Other"); len(refs) != 1 || strings.HasSuffix(refs[0], ".id") {
		t.Errorf("dependsOn should strip the attribute, got %v", refs)
	}
	// An unknown target is skipped rather than emitted as a dangling address.
	if refs := tr.dependsOn("NoSuchResource"); len(refs) != 0 {
		t.Errorf("dependsOn should skip unknown targets, got %v", refs)
	}
}

// Every deliberate omission carries its reason, so a reader can tell a considered
// drop from an oversight. An empty reason is an oversight wearing a drop's
// clothes.
func TestCFNToTF_EveryDroppedPropertyExplainsItself(t *testing.T) {
	for cfnType, m := range cfnToTF {
		for prop, reason := range m.drop {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s.%s is dropped with no reason", cfnType, prop)
			}
		}
		if m.tfType == "" {
			continue
		}
		if m.tagStyle != "map" && m.tagStyle != "block" && m.tagStyle != "none" {
			t.Errorf("%s has tagStyle %q — must be map, block, or none", cfnType, m.tagStyle)
		}
	}
}

// The generated names are what an operator reads in a plan and types in an import
// command, so acronyms staying intact is a usability requirement, not cosmetics.
// Uniqueness is the correctness requirement, and plan enforces that.
func TestTfName(t *testing.T) {
	for in, want := range map[string]string{
		"PrivateSubnet1":       "private_subnet_1",
		"LoggingProtectionSCP": "logging_protection_scp",
		"SCPId":                "scp_id",
		"HubVPC":               "hub_vpc",
		"NIHGenomicOU":         "nih_genomic_ou",
		"CUIResearchOU":        "cui_research_ou",
		"TGWRouteTableHub":     "tgw_route_table_hub",
		"AuditBucket":          "audit_bucket",
	} {
		if got := tfName(in); got != want {
			t.Errorf("tfName(%q) = %q, want %q", in, got, want)
		}
	}
	// A Terraform name cannot begin with a digit.
	if got := tfName("2FA"); strings.HasPrefix(got, "2") {
		t.Errorf("tfName(%q) = %q, which is not a valid Terraform identifier", "2FA", got)
	}
}

// --- Coverage statements -----------------------------------------------------

// An operator must be able to read any single artifact and learn what it does
// and does not deploy. So the coverage statement appears in the code artifact AND
// the README, for every format — and the two formats say different things,
// because one is transpiled and one is hand-written.
func TestGenerate_EveryArtifactStatesItsCoverage(t *testing.T) {
	t.Run("hcl", func(t *testing.T) {
		for _, f := range []Format{FormatTerraform, FormatOpenTofu} {
			_, files := generate(t, f)
			code, readme := files["main.tf"], files["README.md"]
			if code == "" || readme == "" {
				t.Fatalf("%s: missing artifacts; got %v", f, keys(files))
			}
			if !strings.Contains(code, "COMPLETE EXPORT") {
				t.Errorf("%s: main.tf does not state that the export is complete", f)
			}
			if strings.Contains(code, "PARTIAL EXPORT") {
				t.Errorf("%s: main.tf still calls the export partial", f)
			}
			// Complete is not the same as compliant: what the CloudFormation path
			// also leaves to attest must still be named.
			for _, needle := range []string{"Framework SCPs", "GuardDuty", "attest scan"} {
				if !strings.Contains(code, needle) {
					t.Errorf("%s: main.tf never mentions %q", f, needle)
				}
				if !strings.Contains(readme, needle) {
					t.Errorf("%s: README never mentions %q", f, needle)
				}
			}
			// And it must warn about the one thing that really does differ.
			if !strings.Contains(code, "duplicate-name") || !strings.Contains(readme, "State ownership") {
				t.Errorf("%s: the export does not warn about applying over an org ground already deployed", f)
			}
		}
	})

	t.Run("cdk", func(t *testing.T) {
		_, files := generate(t, FormatCDK)
		code, readme := files["stack.ts"], files["README.md"]
		if code == "" || readme == "" {
			t.Fatalf("missing artifacts; got %v", keys(files))
		}
		if !strings.Contains(code, "PARTIAL EXPORT") {
			t.Error("stack.ts does not warn that the CDK export is partial")
		}
		if !strings.Contains(readme, "PARTIAL export") {
			t.Error("CDK README does not warn that the export is partial")
		}
		// Every missing component named, not gestured at. A vague "some things are
		// missing" is what let this ship misleading.
		for _, needle := range []string{"Service Control Policies", "CloudTrail", "Network"} {
			if !strings.Contains(code, needle) {
				t.Errorf("stack.ts never mentions missing %q", needle)
			}
			if !strings.Contains(readme, needle) {
				t.Errorf("CDK README never mentions missing %q", needle)
			}
		}
		if !strings.Contains(code, "ground deploy") || !strings.Contains(readme, "ground deploy") {
			t.Error("the partial export does not point the operator at 'ground deploy'")
		}
	})
}

// Coverage is the single source for three renderings (banner, artifact header,
// README table). That only holds if none of them hardcodes the list, so assert
// every entry flows through the rendered warning — for both records.
func TestCoverage_WarningRendersEveryEntry(t *testing.T) {
	for name, c := range map[string]Coverage{"hcl": hclCoverage, "cdk": cdkCoverage} {
		w := c.Warning("# ")
		for _, entry := range append(append([]string{}, c.Covered...), c.Missing...) {
			if !strings.Contains(w, entry) {
				t.Errorf("%s: warning omits entry %q", name, entry)
			}
		}
		for _, line := range strings.Split(strings.TrimRight(w, "\n"), "\n") {
			if !strings.HasPrefix(line, "#") {
				t.Errorf("%s: prefix not applied to line %q — would be invalid HCL", name, line)
			}
		}
		if len(c.Missing) == 0 {
			t.Errorf("%s: no Missing entries — even the complete export leaves posture to attest", name)
		}
	}
	if !hclCoverage.Complete {
		t.Error("hclCoverage should be Complete — it is transpiled from the deploy path's own templates")
	}
	if cdkCoverage.Complete {
		t.Error("cdkCoverage is hand-written from a subset and must not claim completeness")
	}
}

// --- Toolchain checks --------------------------------------------------------

// The generated file says "Do not edit manually", so the operator can't fix
// formatting without their edit being blown away on regeneration. That makes
// fmt-cleanliness the generator's responsibility, not theirs — and it is a real
// problem when the export lands in a repo whose CI runs 'terraform fmt -check'.
func TestHCL_IsFmtClean(t *testing.T) {
	bin := hclTool(t)
	dir, _ := generate(t, FormatTerraform)

	// 'fmt -check' is read-only: it exits non-zero and lists offenders, and
	// never contacts AWS or a provider registry.
	out, err := exec.Command(bin, "fmt", "-check", "-diff", "-no-color", dir).CombinedOutput()
	if err != nil {
		t.Errorf("generated HCL is not %s-fmt clean; the header says 'do not edit manually',\n"+
			"so the generator must emit canonical formatting:\n%s", filepath.Base(bin), out)
	}
}

// fmt only proves the HCL parses and is formatted. validate is what proves the
// arguments exist on the resources they are set on — the actual risk in a
// transpiler, where a plausible-but-wrong argument name is easy to emit.
//
// It needs the AWS provider from the registry, so it is opt-in via
// GROUND_IAC_VALIDATE=1 rather than skipping silently on a developer's machine:
// CI sets it, and the skip there would otherwise be invisible. Nothing here
// contacts AWS — 'init -backend=false' and 'validate' never use credentials.
func TestHCL_Validates(t *testing.T) {
	if os.Getenv("GROUND_IAC_VALIDATE") != "1" {
		t.Skip("set GROUND_IAC_VALIDATE=1 to run 'validate' (downloads the AWS provider)")
	}
	bin := hclTool(t)
	dir, _ := generate(t, FormatTerraform)

	if out, err := exec.Command(bin, "-chdir="+dir, "init", "-backend=false", "-no-color").CombinedOutput(); err != nil {
		t.Fatalf("%s init failed:\n%s", bin, out)
	}
	out, err := exec.Command(bin, "-chdir="+dir, "validate", "-no-color").CombinedOutput()
	if err != nil {
		t.Fatalf("generated HCL does not validate:\n%s", out)
	}
	// A deprecation warning means the export uses an argument the provider is
	// about to remove — worth failing on while it is still cheap to fix.
	if strings.Contains(string(out), "Warning:") {
		t.Errorf("%s validate emitted warnings:\n%s", bin, out)
	}
}

// hclTool locates the binary the toolchain checks run against.
//
// GROUND_IAC_TOOL selects one explicitly. The export's claim is that the *same*
// main.tf applies under both terraform and opentofu; a byte-comparison of the two
// generated files (TestTerraformAndOpenTofu_HCLIsIdentical) shows they are the
// same file, not that both tools accept it. CI runs these checks twice, once per
// tool, which is what actually establishes it.
func hclTool(t *testing.T) string {
	t.Helper()
	candidates := []string{"terraform", "tofu"}
	if want := os.Getenv("GROUND_IAC_TOOL"); want != "" {
		candidates = []string{want}
	}
	for _, name := range candidates {
		if bin, err := exec.LookPath(name); err == nil {
			return bin
		}
	}
	t.Skipf("none of %v on PATH", candidates)
	return ""
}

// --- Format plumbing ---------------------------------------------------------

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"terraform":      FormatTerraform,
		"TerraForm":      FormatTerraform,
		"  opentofu  ":   FormatOpenTofu,
		"cdk":            FormatCDK,
		"cloudformation": FormatCloudFormation,
	} {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) errored: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("tofu"); err == nil {
		t.Error("ParseFormat should reject 'tofu' (the binary name, not the format)")
	}
	if _, err := ParseFormat(""); err == nil {
		t.Error("ParseFormat should reject the empty string")
	}
}

// terraform and opentofu must produce byte-identical HCL — that is the claim the
// README makes, and the reason there is one transpiler rather than two.
func TestTerraformAndOpenTofu_HCLIsIdentical(t *testing.T) {
	_, tfFiles := generate(t, FormatTerraform)
	_, tofuFiles := generate(t, FormatOpenTofu)

	if tfFiles["main.tf"] != tofuFiles["main.tf"] {
		t.Error("terraform and opentofu main.tf differ — they must be the same HCL")
	}
	if strings.Contains(tfFiles["main.tf"], "tofu") {
		t.Error("main.tf names a specific tool; the HCL must stay tool-agnostic")
	}
	// The READMEs legitimately differ: each names its own CLI.
	if !strings.Contains(tofuFiles["README.md"], "tofu init") {
		t.Error("opentofu README should show 'tofu init'")
	}
	if !strings.Contains(tfFiles["README.md"], "terraform init") {
		t.Error("terraform README should show 'terraform init'")
	}
}

// Version is injected rather than hardcoded, so a ground release and the exports
// it generates cannot disagree about provenance.
func TestGenerate_StampsInjectedVersion(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	if !strings.Contains(files["main.tf"], `"ground:version" = "9.9.9"`) {
		t.Error("main.tf does not stamp the injected version")
	}
	_, cdk := generate(t, FormatCDK)
	if !strings.Contains(cdk["stack.ts"], "'9.9.9'") {
		t.Error("stack.ts does not stamp the injected version")
	}
	if !strings.Contains(cdk["package.json"], `"version": "9.9.9"`) {
		t.Error("package.json does not stamp the injected version")
	}
	// An empty version must not silently produce an empty tag value.
	dir := t.TempDir()
	if err := NewGenerator(FormatTerraform, dir, "").Generate(testConfig()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "main.tf"))
	if !strings.Contains(string(b), `"ground:version" = "unknown"`) {
		t.Error("empty version should render as \"unknown\", not empty")
	}
}

// The OU names are vendor's lookup key — ground-meta.json carries no OU ids, so
// 'vendor provision --type' resolves them by name. A rename here silently breaks
// the sibling tool, which is exactly the kind of coupling worth pinning.
//
// The list comes from the accounts stack rather than being retyped, so adding an
// OU there without exporting it fails here.
func TestHCL_OUNamesMatchVendorLookupKeys(t *testing.T) {
	cfg := testConfig()
	tmpl, err := accounts.New(&cfg.Org).Template()
	if err != nil {
		t.Fatalf("accounts template: %v", err)
	}
	var want []string
	for _, logicalID := range sortedKeys(tmpl.Resources) {
		res, _ := tmpl.Resources[logicalID].(map[string]any)
		if res["Type"] != "AWS::Organizations::OrganizationalUnit" {
			continue
		}
		props, _ := res["Properties"].(map[string]any)
		if name, ok := props["Name"].(string); ok {
			want = append(want, name)
		}
	}
	sort.Strings(want)
	if len(want) < 8 {
		t.Fatalf("expected the full OU hierarchy, found %d: %v", len(want), want)
	}

	_, files := generateWith(t, FormatTerraform, cfg)
	for _, name := range want {
		// fmt aligns the '=' per block, so match on whitespace rather than a fixed width.
		re := regexp.MustCompile(`name\s+= "` + regexp.QuoteMeta(name) + `"`)
		if !re.MatchString(files["main.tf"]) {
			t.Errorf("OU %q missing from the export — vendor resolves OUs by name, so this "+
				"breaks 'vendor provision'", name)
		}
	}
}

func TestGenerate_CloudFormationIsNotAnExport(t *testing.T) {
	err := NewGenerator(FormatCloudFormation, t.TempDir(), "1.0.0").Generate(testConfig())
	if err == nil {
		t.Fatal("cloudformation must not be generated as an export — it is the deploy path")
	}
	if !strings.Contains(err.Error(), "ground deploy") {
		t.Errorf("error should redirect to 'ground deploy', got %q", err)
	}
}

func TestGenerate_RejectsNilConfigAndUnknownFormat(t *testing.T) {
	if err := NewGenerator(FormatTerraform, t.TempDir(), "1.0.0").Generate(nil); err == nil {
		t.Error("nil config should error, not panic")
	}
	if err := NewGenerator(Format("pulumi"), t.TempDir(), "1.0.0").Generate(testConfig()); err == nil {
		t.Error("unknown format should error")
	}
}

// A minimal config must still export: the stacks that emit nothing (no Transit
// Gateway, no Identity Center instance) must not break the transpile, and the
// permission-set resources must genuinely be absent rather than half-rendered.
func TestHCL_MinimalConfigExportsWithoutOptionalStacks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Org.Name = "T"
	cfg.Org.Region = "us-west-2"
	cfg.Org.ManagementID = "123456789012"

	_, files := generateWith(t, FormatTerraform, cfg)
	tf := files["main.tf"]

	if strings.Contains(tf, "aws_ssoadmin_permission_set") {
		t.Error("permission sets exported without an Identity Center instance ARN")
	}
	if strings.Contains(tf, "aws_ec2_transit_gateway") {
		t.Error("Transit Gateway exported without transit_gateway: true")
	}
	// The guardrails do not depend on the optional stacks.
	for _, want := range []string{`resource "aws_organizations_policy_attachment"`, `resource "aws_cloudtrail"`} {
		if !strings.Contains(tf, want) {
			t.Errorf("minimal export is missing %s", want)
		}
	}
}

// Every stack's template must survive cfn.Validate — a resource-level attribute
// declared inside Properties is silently ignored by CloudFormation, so the deploy
// succeeds and the ordering it promised never happens (#41).
//
// This lives here rather than as five near-identical per-stack tests because
// hclStacks already builds exactly the set `ground deploy` submits: a stack added
// to the deploy path gets checked the moment it is added to the export.
func TestStackTemplates_PassTheCloudFormationGuard(t *testing.T) {
	minimal := &config.Config{}
	minimal.Org.Name = "T"
	minimal.Org.Region = "us-west-2"
	minimal.Org.ManagementID = "123456789012"

	// Both configurations: the optional stacks emit different resources when off,
	// and a misplaced attribute in either branch is the same bug.
	for name, cfg := range map[string]*config.Config{"full": testConfig(), "minimal": minimal} {
		t.Run(name, func(t *testing.T) {
			stacks, err := hclStacks(cfg)
			if err != nil {
				t.Fatalf("hclStacks: %v", err)
			}
			for _, st := range stacks {
				if err := st.template.Validate(); err != nil {
					t.Errorf("stack %q builds a template CloudFormation would misinterpret: %v", st.title, err)
				}
			}
		})
	}
}

// The two logging constraints are the ones that guard real failures: CreateTrail
// validates its S3 destination (and the trail Refs the bucket, not its policy),
// and PutDeliveryChannel fails with no recorder — which nothing in that resource
// references. Assert they survive as resource-level attributes, since inside
// Properties they would read identically in the source and do nothing at deploy.
func TestLoggingStack_OrderingConstraintsAreResourceLevel(t *testing.T) {
	cfg := testConfig()
	tmpl, err := logging.New(&cfg.Logging, &cfg.Org).Template()
	if err != nil {
		t.Fatalf("logging template: %v", err)
	}

	for logicalID, wantDep := range map[string]string{
		"OrgTrail":              "AuditBucketPolicy",
		"ConfigDeliveryChannel": "ConfigRecorder",
	} {
		res, ok := tmpl.Resources[logicalID].(map[string]any)
		if !ok {
			t.Fatalf("%s missing from the logging stack", logicalID)
		}
		if got := res["DependsOn"]; got != wantDep {
			t.Errorf("%s: DependsOn = %#v, want the resource-level string %q", logicalID, got, wantDep)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	if IsPartial(FormatCloudFormation) {
		t.Error("cloudformation is the full deploy path, not a partial export")
	}
	for _, f := range []Format{FormatTerraform, FormatOpenTofu} {
		if IsPartial(f) {
			t.Errorf("%s is transpiled from the deploy path's templates and is not partial", f)
		}
	}
	if !IsPartial(FormatCDK) {
		t.Error("cdk is still a hand-written subset and is partial")
	}
	if !IsHCL(FormatTerraform) || !IsHCL(FormatOpenTofu) || IsHCL(FormatCDK) {
		t.Error("IsHCL should be true for terraform/opentofu only")
	}
	if Tool(FormatOpenTofu) != "tofu" || Tool(FormatTerraform) != "terraform" {
		t.Error("Tool should map each HCL format to its own CLI binary")
	}
	if DefaultOutputDir(FormatOpenTofu) == DefaultOutputDir(FormatTerraform) {
		t.Error("terraform and opentofu should not share an output dir — regenerating one would clobber the other's README")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
