// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provabl/ground/internal/config"
)

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Org.Region = "us-west-2"
	return cfg
}

// generate runs the generator into a temp dir and returns the artifacts by name.
func generate(t *testing.T, f Format) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := NewGenerator(f, dir, "9.9.9").Generate(testConfig()); err != nil {
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

// The whole point of this package's warnings: an operator must not be able to
// read any one artifact and conclude they have a complete foundation. So the gap
// appears in the code artifact AND the README, for every format.
func TestGenerate_EveryArtifactCarriesThePartialWarning(t *testing.T) {
	cases := []struct {
		format Format
		code   string
	}{
		{FormatTerraform, "main.tf"},
		{FormatOpenTofu, "main.tf"},
		{FormatCDK, "stack.ts"},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			_, files := generate(t, tc.format)

			code, ok := files[tc.code]
			if !ok {
				t.Fatalf("no %s generated; got %v", tc.code, keys(files))
			}
			readme, ok := files["README.md"]
			if !ok {
				t.Fatalf("no README.md generated; got %v", keys(files))
			}

			// "PARTIAL" in the artifact itself — the file an operator opens.
			if !strings.Contains(code, "PARTIAL EXPORT") {
				t.Errorf("%s does not warn that the export is partial", tc.code)
			}
			if !strings.Contains(readme, "PARTIAL export") {
				t.Errorf("README does not warn that the export is partial")
			}

			// Every missing component must be named, not gestured at. A vague
			// "some things are missing" is what let this ship misleading.
			for _, needle := range []string{"Service Control Policies", "CloudTrail", "Network"} {
				if !strings.Contains(code, needle) {
					t.Errorf("%s never mentions missing %q", tc.code, needle)
				}
				if !strings.Contains(readme, needle) {
					t.Errorf("README never mentions missing %q", needle)
				}
			}

			// And it must point at the thing that IS complete.
			if !strings.Contains(code, "ground deploy") || !strings.Contains(readme, "ground deploy") {
				t.Error("export does not point the operator at 'ground deploy'")
			}
		})
	}
}

// The Coverage data is the single source for three renderings. If a generator
// gains SCP support, moving the entry must update all of them — which only holds
// if none of them hardcode the list. Assert the Missing entries actually flow
// through to the rendered warning.
func TestCoverage_WarningRendersEveryMissingEntry(t *testing.T) {
	w := exportCoverage.Warning("# ")
	for _, m := range exportCoverage.Missing {
		if !strings.Contains(w, m) {
			t.Errorf("warning omits missing entry %q", m)
		}
	}
	for _, c := range exportCoverage.Covered {
		if !strings.Contains(w, c) {
			t.Errorf("warning omits covered entry %q", c)
		}
	}
	for _, line := range strings.Split(strings.TrimRight(w, "\n"), "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Errorf("prefix not applied to line %q — would be invalid HCL", line)
		}
	}
}

// SCPs are the guardrails. If a future edit makes the export emit some but not
// all of them, the flat "NO guardrails" claim becomes a lie in the other
// direction. Pin the current truth: zero policy resources.
func TestHCL_ContainsNoGuardrailResources(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	tf := files["main.tf"]

	// Only inspect resource declarations — the prose warning naturally mentions
	// these words, and matching it would make the test vacuously pass.
	for _, line := range strings.Split(tf, "\n") {
		if !strings.HasPrefix(line, "resource ") {
			continue
		}
		for _, forbidden := range []string{"aws_organizations_policy", "cloudtrail", "aws_config", "_vpc", "s3_bucket", "guardduty", "securityhub", "macie"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("export now emits %q (%s) — update exportCoverage.Missing, the claim "+
					"of zero guardrails is no longer accurate", forbidden, strings.TrimSpace(line))
			}
		}
	}
}

// The generated file says "Do not edit manually", so the operator can't fix
// formatting without their edit being blown away on regeneration. That makes
// fmt-cleanliness the generator's responsibility, not theirs — and it is a real
// problem when the export lands in a repo whose CI runs 'terraform fmt -check'.
func TestHCL_IsFmtClean(t *testing.T) {
	bin, err := exec.LookPath("terraform")
	if err != nil {
		if bin, err = exec.LookPath("tofu"); err != nil {
			t.Skip("neither terraform nor tofu on PATH — cannot verify fmt cleanliness")
		}
	}
	dir, _ := generate(t, FormatTerraform)

	// 'fmt -check' is read-only: it exits non-zero and lists offenders, and
	// never contacts AWS or a provider registry.
	out, err := exec.Command(bin, "fmt", "-check", "-diff", "-no-color", dir).CombinedOutput()
	if err != nil {
		t.Errorf("generated HCL is not %s-fmt clean; the header says 'do not edit manually',\n"+
			"so the generator must emit canonical formatting:\n%s", filepath.Base(bin), out)
	}
}

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
// README makes, and the reason there is one generator rather than two.
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
func TestHCL_OUNamesMatchVendorLookupKeys(t *testing.T) {
	_, files := generate(t, FormatTerraform)
	tf := files["main.tf"]
	for _, name := range []string{
		"Security", "Infrastructure", "Research", "SensitiveResearch", "DoD-CMMC",
		"NIHGenomic", "HIPAAResearch", "CUIResearch",
	} {
		if !strings.Contains(tf, `name      = "`+name+`"`) {
			t.Errorf("OU %q missing — vendor resolves OUs by name, so this breaks 'vendor provision'", name)
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

func TestFormatHelpers(t *testing.T) {
	if IsPartial(FormatCloudFormation) {
		t.Error("cloudformation is the full deploy path, not a partial export")
	}
	for _, f := range []Format{FormatTerraform, FormatOpenTofu, FormatCDK} {
		if !IsPartial(f) {
			t.Errorf("%s is a partial export", f)
		}
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
	return out
}
