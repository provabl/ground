// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

//go:build awssim

// Adversarial verification of the AMI-gating SCPs against the LIVE AWS IAM policy
// simulator. Build-tagged `awssim` because it needs AWS credentials; it is excluded
// from the default `go test ./...` (and therefore CI). Run it with:
//
//	AWS_PROFILE=... go test -tags awssim ./policies/ -v
//
// Why the simulator and not "attach the SCP and try the call": this suite's dev
// account is its Organization's MANAGEMENT account, and SCPs never apply to the
// management account — so we cannot observe the SCP denying in-account. The
// simulator (iam:SimulateCustomPolicy) evaluates the policy LOGIC against synthetic
// request contexts with no resources and no spend, which is the faithful way to
// prove the lockdown actually blocks tag forgery. It reads the same policy JSON
// that ground deploys.
package policies_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	imageARN     = "arn:aws:ec2:us-west-2::image/ami-0adversarial"
	vetterARN    = "arn:aws:iam::942542972736:role/provabl-vetter"
	researcherID = "arn:aws:iam::942542972736:role/researcher"
)

// loadPolicyJSON reads a policy file verbatim and substitutes the deploy-time
// vetter-ARN placeholder so the simulator evaluates a concrete principal.
func loadPolicyJSON(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.ReplaceAll(string(b), "VETTER_PRINCIPAL_ARN_PLACEHOLDER", vetterARN)
}

func newIAM(t *testing.T) *iam.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Skipf("no AWS config (run with AWS creds for -tags awssim): %v", err)
	}
	return iam.NewFromConfig(cfg)
}

func ctxStr(key, val string) iamtypes.ContextEntry {
	return iamtypes.ContextEntry{
		ContextKeyName:   aws.String(key),
		ContextKeyType:   iamtypes.ContextKeyTypeEnumString,
		ContextKeyValues: []string{val},
	}
}

func ctxStrList(key string, vals ...string) iamtypes.ContextEntry {
	return iamtypes.ContextEntry{
		ContextKeyName:   aws.String(key),
		ContextKeyType:   iamtypes.ContextKeyTypeEnumStringList,
		ContextKeyValues: vals,
	}
}

// simDecision evaluates one (policy, action, resource, context) against the live
// simulator and returns the decision ("allowed" | "explicitDeny" | "implicitDeny").
func simDecision(t *testing.T, c *iam.Client, policyJSON, action, resourceARN string, ctxs []iamtypes.ContextEntry) string {
	t.Helper()
	out, err := c.SimulateCustomPolicy(context.Background(), &iam.SimulateCustomPolicyInput{
		PolicyInputList: []string{policyJSON},
		ActionNames:     []string{action},
		ResourceArns:    []string{resourceARN},
		ContextEntries:  ctxs,
	})
	if err != nil {
		t.Skipf("SimulateCustomPolicy unavailable (need iam:SimulateCustomPolicy): %v", err)
	}
	if len(out.EvaluationResults) != 1 {
		t.Fatalf("expected 1 evaluation result, got %d", len(out.EvaluationResults))
	}
	return string(out.EvaluationResults[0].EvalDecision)
}

// TestLockdownSCP_BlocksTagForgery is the core adversarial proof: a non-vetter
// principal cannot set or delete the attest:vetted tag, while the vetter can, and
// the lockdown does not over-reach to other tag keys.
func TestLockdownSCP_BlocksTagForgery(t *testing.T) {
	c := newIAM(t)
	lockdown := loadPolicyJSON(t, "ami_vetting_lockdown_scp.json")

	cases := []struct {
		name       string
		action     string
		principal  string
		tagKeys    []string
		wantDenied bool
	}{
		{"researcher forges attest:vetted (CreateTags)", "ec2:CreateTags", researcherID, []string{"attest:vetted"}, true},
		{"researcher strips attest:vetted (DeleteTags)", "ec2:DeleteTags", researcherID, []string{"attest:vetted"}, true},
		{"researcher forges golden PCR attest:pcr0", "ec2:CreateTags", researcherID, []string{"attest:pcr0"}, true},
		{"researcher forges golden PCR attest:pcr7", "ec2:CreateTags", researcherID, []string{"attest:pcr7"}, true},
		{"researcher strips a golden PCR (DeleteTags)", "ec2:DeleteTags", researcherID, []string{"attest:pcr0"}, true},
		{"vetter sets attest:vetted (CreateTags)", "ec2:CreateTags", vetterARN, []string{"attest:vetted"}, false},
		{"vetter sets a golden PCR attest:pcr0", "ec2:CreateTags", vetterARN, []string{"attest:pcr0"}, false},
		{"researcher sets an unrelated tag (project)", "ec2:CreateTags", researcherID, []string{"project"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := simDecision(t, c, lockdown, tc.action, imageARN, []iamtypes.ContextEntry{
				ctxStrList("aws:TagKeys", tc.tagKeys...),
				ctxStr("aws:PrincipalArn", tc.principal),
			})
			denied := dec == "explicitDeny"
			if denied != tc.wantDenied {
				t.Errorf("decision=%q deniedByLockdown=%v, want denied=%v", dec, denied, tc.wantDenied)
			}
		})
	}
}

// TestLaunchGatingSCP_DeniesUnlessVetted proves the launch gate: only an AMI tagged
// attest:vetted=true may RunInstances; tagged false OR the tag absent is denied
// (the deny-unless direction — a missing tag must NOT be treated as vetted).
func TestLaunchGatingSCP_DeniesUnlessVetted(t *testing.T) {
	c := newIAM(t)
	gate := loadPolicyJSON(t, "ami_launch_gating_scp.json")

	cases := []struct {
		name       string
		tagValue   string // "" means the tag is absent (no context entry)
		wantDenied bool
	}{
		{"vetted AMI launches", "true", false},
		{"explicitly-unvetted AMI denied", "false", true},
		{"untagged AMI denied (missing != true)", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ctxs []iamtypes.ContextEntry
			if tc.tagValue != "" {
				ctxs = append(ctxs, ctxStr("ec2:ResourceTag/attest:vetted", tc.tagValue))
			}
			dec := simDecision(t, c, gate, "ec2:RunInstances", imageARN, ctxs)
			denied := dec == "explicitDeny"
			if denied != tc.wantDenied {
				t.Errorf("decision=%q deniedByGate=%v, want denied=%v", dec, denied, tc.wantDenied)
			}
		})
	}
}
