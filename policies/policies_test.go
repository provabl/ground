// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package policies_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/provabl/ground/internal/policy"
)

func loadPolicy(t *testing.T, path string) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var p policy.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return &p
}

// TestPermissionBoundaryIsDenyScoped verifies that the permission boundary
// uses only Deny statements — not Allow *, which would be a no-op boundary.
func TestPermissionBoundaryIsDenyScoped(t *testing.T) {
	p := loadPolicy(t, "permission_boundary.json")

	if !p.AllDenyStatements() {
		t.Error("permission boundary must use only Deny statements; an Allow * boundary is a no-op")
	}
}

// TestPermissionBoundaryDeniesPrivilegeEscalation verifies that the boundary
// blocks the canonical privilege escalation actions.
func TestPermissionBoundaryDeniesPrivilegeEscalation(t *testing.T) {
	p := loadPolicy(t, "permission_boundary.json")

	escalationActions := []string{
		"iam:CreatePolicyVersion",
		"iam:AttachRolePolicy",
		"iam:PassRole",
	}

	for _, action := range escalationActions {
		if !statementDeniesAction(p, action) {
			t.Errorf("permission boundary does not deny %s — privilege escalation path open", action)
		}
	}
}

// TestPermissionBoundaryDeniesLoggingDisable verifies that the boundary
// blocks disabling of audit logging services.
func TestPermissionBoundaryDeniesLoggingDisable(t *testing.T) {
	p := loadPolicy(t, "permission_boundary.json")

	loggingActions := []string{
		"cloudtrail:DeleteTrail",
		"cloudtrail:StopLogging",
		"config:DeleteConfigurationRecorder",
		"guardduty:DeleteDetector",
		"securityhub:DisableSecurityHub",
	}

	for _, action := range loggingActions {
		if !statementDeniesAction(p, action) {
			t.Errorf("permission boundary does not deny %s — logging bypass possible", action)
		}
	}
}

// TestVPCEndpointPolicyHasOrgIDCondition verifies that the VPC endpoint policy
// requires aws:PrincipalOrgID — preventing access from outside the org.
func TestVPCEndpointPolicyHasOrgIDCondition(t *testing.T) {
	p := loadPolicy(t, "vpc_endpoint_policy.json")

	if !p.HasOrgIDCondition() {
		t.Error("VPC endpoint policy must have aws:PrincipalOrgID condition; without it, any AWS principal can access the endpoint")
	}
}

// TestTaggingSCPUsesORLogic verifies that the tagging SCP has separate
// statements per tag (OR logic) rather than a single combined statement (AND logic).
//
// With AND logic, a resource missing only tag "owner" would pass if "project"
// and "environment" are set — exactly the misconfiguration we're fixing.
func TestTaggingSCPUsesORLogic(t *testing.T) {
	p := loadPolicy(t, "tagging_scp.json")

	requiredTags := []string{"project", "environment", "owner", "data-classification"}

	// Each required tag must have its own deny statement.
	for _, tag := range requiredTags {
		if !hasSeparateDenyForTag(p, tag) {
			t.Errorf("tagging SCP does not have a separate Deny statement for tag %q — AND logic allows bypass when other tags are present", tag)
		}
	}
}

// TestTaggingSCPStatementCount verifies the SCP has exactly one statement per
// required tag (not a combined multi-tag statement).
func TestTaggingSCPStatementCount(t *testing.T) {
	p := loadPolicy(t, "tagging_scp.json")

	requiredTags := []string{"project", "environment", "owner", "data-classification"}

	if len(p.Statements) < len(requiredTags) {
		t.Errorf("tagging SCP has %d statements but requires at least %d (one per tag for OR logic)",
			len(p.Statements), len(requiredTags))
	}
}

// statementDeniesAction returns true if any Deny statement in p covers action.
func statementDeniesAction(p *policy.Policy, action string) bool {
	for _, s := range p.Statements {
		if s.Effect != "Deny" {
			continue
		}
		switch v := s.Action.(type) {
		case string:
			if v == action || v == "*" {
				return true
			}
		case []any:
			for _, a := range v {
				if str, ok := a.(string); ok && (str == action || str == "*") {
					return true
				}
			}
		}
	}
	return false
}

// ── Per-OU SCP tests ──────────────────────────────────────────────────────────

func TestSecurityOUSCPDeniesCloudTrailDisable(t *testing.T) {
	p := loadPolicy(t, "ou_scps/security_ou.json")
	actions := []string{"cloudtrail:DeleteTrail", "cloudtrail:StopLogging"}
	for _, a := range actions {
		if !statementDeniesAction(p, a) {
			t.Errorf("security_ou SCP does not deny %s — log tampering possible", a)
		}
	}
}

func TestSecurityOUSCPDeniesSecurityServiceDisable(t *testing.T) {
	p := loadPolicy(t, "ou_scps/security_ou.json")
	actions := []string{"guardduty:DeleteDetector", "securityhub:DisableSecurityHub"}
	for _, a := range actions {
		if !statementDeniesAction(p, a) {
			t.Errorf("security_ou SCP does not deny %s", a)
		}
	}
}

func TestInfrastructureOUSCPDeniesWorkloads(t *testing.T) {
	p := loadPolicy(t, "ou_scps/infrastructure_ou.json")
	if !statementDeniesAction(p, "ec2:RunInstances") {
		t.Error("infrastructure_ou SCP should deny ec2:RunInstances (workloads go in Research OU)")
	}
}

func TestSensitiveOUSCPDeniesUnencryptedS3(t *testing.T) {
	p := loadPolicy(t, "ou_scps/sensitive_research_ou.json")
	if !statementDeniesAction(p, "s3:PutObject") {
		t.Error("sensitive_research_ou SCP should deny s3:PutObject without KMS encryption")
	}
}

func TestSensitiveOUSCPDeniesCloudTrailDisable(t *testing.T) {
	p := loadPolicy(t, "ou_scps/sensitive_research_ou.json")
	if !statementDeniesAction(p, "cloudtrail:DeleteTrail") {
		t.Error("sensitive_research_ou SCP should deny cloudtrail:DeleteTrail")
	}
}

func TestDoDCMMCOUSCPDeniesNonGovCloud(t *testing.T) {
	p := loadPolicy(t, "ou_scps/dod_cmmc_ou.json")
	// The DoD OU uses Deny with StringNotEquals condition for non-GovCloud regions.
	// Verify at least one Deny statement exists.
	hasDeny := false
	for _, s := range p.Statements {
		if s.Effect == "Deny" {
			hasDeny = true
			break
		}
	}
	if !hasDeny {
		t.Error("dod_cmmc_ou SCP must have Deny statements to restrict to GovCloud only")
	}
}

// TestAccountTaggingUsesORLogic verifies the account tagging SCP uses separate
// Deny statements per tag (OR logic) rather than one combined statement (AND logic).
// With AND logic, resources missing only one tag could bypass the check.
func TestAccountTaggingUsesORLogic(t *testing.T) {
	p := loadPolicy(t, "account_tagging_scp.json")
	requiredTags := []string{
		"attest:environment-id",
		"attest:data-classes",
		"attest:compliance-tier",
		"attest:ou-path",
		"attest:owner",
	}
	for _, tag := range requiredTags {
		if !hasSeparateDenyForTag(p, tag) {
			t.Errorf("account_tagging_scp: no separate Deny statement for tag %q — AND logic bypass possible", tag)
		}
	}
}

func TestAccountTaggingHasFiveStatements(t *testing.T) {
	p := loadPolicy(t, "account_tagging_scp.json")
	required := 5
	if len(p.Statements) < required {
		t.Errorf("account_tagging_scp: want at least %d statements (one per tag), got %d",
			required, len(p.Statements))
	}
}

// TestNitroAttestationSCPRequiresAttestedTag verifies the nitro-attestation SCP
// denies sensitive-data actions unless the principal carries
// aws:PrincipalTag/attest:nitro-attested == "true". This is the IAM-layer half of
// the evidence kernel's runtime attestation: the nitro provider produces the
// verdict, a tag carries it, and this SCP gates data access on it.
func TestNitroAttestationSCPRequiresAttestedTag(t *testing.T) {
	p := loadPolicy(t, "nitro_attestation_scp.json")

	// Fail-closed: the policy must Deny (never Allow — an Allow would be a no-op).
	if !p.AllDenyStatements() {
		t.Error("nitro_attestation_scp must use only Deny statements; an Allow would be a no-op")
	}

	// The gating condition must be present.
	if !hasNitroAttestationCondition(p) {
		t.Error("nitro_attestation_scp must deny on StringNotEquals aws:PrincipalTag/attest:nitro-attested == \"true\"; " +
			"without it, an unattested principal can access sensitive data")
	}

	// The sensitive-data actions must be covered by the gated statement.
	sensitiveActions := []string{
		"s3:GetObject",
		"sagemaker:CreateTrainingJob",
	}
	for _, action := range sensitiveActions {
		if !statementDeniesAction(p, action) {
			t.Errorf("nitro_attestation_scp does not deny %s — unattested data-access path open", action)
		}
	}
}

// TestAMILaunchGatingSCPDeniesUnvettedAMIs verifies the AMI-launch-gating SCP
// denies ec2:RunInstances unless the AMI carries ec2:ResourceTag/attest:vetted ==
// "true" — Layer 1 of the AMI-gating epic (provabl#13). Crucially, the Deny must be
// scoped to the image resource ARN: a RunInstances call also creates instances,
// volumes, and ENIs, none of which carry the AMI's tag, so a Resource:"*" scope
// would evaluate the ResourceTag condition against those and deny every launch.
func TestAMILaunchGatingSCPDeniesUnvettedAMIs(t *testing.T) {
	p := loadPolicy(t, "ami_launch_gating_scp.json")

	// Fail-closed: Deny only (an Allow would be a no-op).
	if !p.AllDenyStatements() {
		t.Error("ami_launch_gating_scp must use only Deny statements; an Allow would be a no-op")
	}

	if !statementDeniesAction(p, "ec2:RunInstances") {
		t.Error("ami_launch_gating_scp does not deny ec2:RunInstances — the AMI launch gate is not active")
	}

	if !hasResourceTagVettedCondition(p) {
		t.Error("ami_launch_gating_scp must deny on StringNotEquals ec2:ResourceTag/attest:vetted == \"true\"; " +
			"without it, an un-vetted AMI can launch")
	}

	// The gating Deny must scope Resource to the image ARN, not "*".
	if !deniesScopedToImageResource(p, "ec2:RunInstances") {
		t.Error("ami_launch_gating_scp RunInstances Deny must scope Resource to the image ARN " +
			"(arn:aws:ec2:*::image/*); a \"*\" scope evaluates ec2:ResourceTag against the instance/" +
			"volumes/ENIs the call also creates and would deny every launch")
	}
}

// TestAMIVettingLockdownDeniesTagMutation verifies the lockdown SCP denies mutating
// the attest:vetted tag key on AMIs for everyone except the designated vetter
// principal — the tamper-resistance behind the launch gate (a researcher must not
// be able to self-mark an AMI vetted). Same "appraised, not asserted" principle as
// qualify#32's locked attest:* tags.
func TestAMIVettingLockdownDeniesTagMutation(t *testing.T) {
	p := loadPolicy(t, "ami_vetting_lockdown_scp.json")

	if !p.AllDenyStatements() {
		t.Error("ami_vetting_lockdown_scp must use only Deny statements")
	}

	for _, action := range []string{"ec2:CreateTags", "ec2:DeleteTags"} {
		if !statementDeniesAction(p, action) {
			t.Errorf("ami_vetting_lockdown_scp does not deny %s — the attest:vetted tag could be self-set", action)
		}
	}

	// The lockdown must (a) target the attest:vetted tag key AND the attest:pcr*
	// golden-PCR keys (forging either defeats the gate), and (b) carry a principal
	// exception — without the key scope it denies all tagging; without the exception
	// even the vetter can't mark an AMI (the gate would be unusable).
	if !lockdownTargetsTagKey(p, "attest:vetted") {
		t.Error("ami_vetting_lockdown_scp must scope to aws:TagKeys [attest:vetted]; " +
			"a broader scope denies all AMI tagging")
	}
	if !lockdownTargetsTagKey(p, "attest:pcr*") {
		t.Error("ami_vetting_lockdown_scp must also lock the attest:pcr* golden-PCR keys; " +
			"a forgeable golden PCR would defeat the runtime image binding (provabl#13)")
	}
	if !lockdownHasVetterArnException(p) {
		t.Error("ami_vetting_lockdown_scp must carry an ArnNotLike aws:PrincipalArn exception for the vetter; " +
			"without it, no principal (not even the vetter) can set attest:vetted")
	}
}

// hasResourceTagVettedCondition returns true if p has a Deny statement whose
// Condition is StringNotEquals on ec2:ResourceTag/attest:vetted = "true".
func hasResourceTagVettedCondition(p *policy.Policy) bool {
	const tagKey = "ec2:ResourceTag/attest:vetted"
	for _, s := range p.Statements {
		if s.Effect != "Deny" || s.Condition == nil {
			continue
		}
		cond, ok := s.Condition["StringNotEquals"]
		if !ok {
			continue
		}
		condMap, ok := cond.(map[string]any)
		if !ok {
			continue
		}
		if val, found := condMap[tagKey]; found {
			if str, ok := val.(string); ok && str == "true" {
				return true
			}
		}
	}
	return false
}

// deniesScopedToImageResource returns true if a Deny statement covering action
// scopes its Resource to the EC2 image ARN (not "*").
func deniesScopedToImageResource(p *policy.Policy, action string) bool {
	const imageARN = "arn:aws:ec2:*::image/*"
	resourceMatches := func(r any) bool {
		switch v := r.(type) {
		case string:
			return v == imageARN
		case []any:
			for _, e := range v {
				if str, ok := e.(string); ok && str == imageARN {
					return true
				}
			}
		}
		return false
	}
	actionCovers := func(a any) bool {
		switch v := a.(type) {
		case string:
			return v == action
		case []any:
			for _, e := range v {
				if str, ok := e.(string); ok && str == action {
					return true
				}
			}
		}
		return false
	}
	for _, s := range p.Statements {
		if s.Effect == "Deny" && actionCovers(s.Action) && resourceMatches(s.Resource) {
			return true
		}
	}
	return false
}

// lockdownTargetsTagKey returns true if a Deny statement scopes aws:TagKeys to the
// given key via a ForAnyValue:StringEquals or ForAnyValue:StringLike condition.
func lockdownTargetsTagKey(p *policy.Policy, key string) bool {
	for _, s := range p.Statements {
		if s.Effect != "Deny" || s.Condition == nil {
			continue
		}
		for _, op := range []string{"ForAnyValue:StringEquals", "ForAnyValue:StringLike"} {
			cond, ok := s.Condition[op]
			if !ok {
				continue
			}
			condMap, ok := cond.(map[string]any)
			if !ok {
				continue
			}
			keys, ok := condMap["aws:TagKeys"]
			if !ok {
				continue
			}
			if arr, ok := keys.([]any); ok {
				for _, k := range arr {
					if str, ok := k.(string); ok && str == key {
						return true
					}
				}
			}
		}
	}
	return false
}

// lockdownHasVetterArnException returns true if a Deny statement carries an
// ArnNotLike condition on aws:PrincipalArn (the vetter-principal carve-out).
func lockdownHasVetterArnException(p *policy.Policy) bool {
	for _, s := range p.Statements {
		if s.Effect != "Deny" || s.Condition == nil {
			continue
		}
		cond, ok := s.Condition["ArnNotLike"]
		if !ok {
			continue
		}
		if condMap, ok := cond.(map[string]any); ok {
			if _, found := condMap["aws:PrincipalArn"]; found {
				return true
			}
		}
	}
	return false
}

// hasNitroAttestationCondition returns true if p has a Deny statement whose
// Condition is StringNotEquals on aws:PrincipalTag/attest:nitro-attested = "true"
// (deny unless attested — covers both a missing and a non-"true" tag).
func hasNitroAttestationCondition(p *policy.Policy) bool {
	const tagKey = "aws:PrincipalTag/attest:nitro-attested"
	for _, s := range p.Statements {
		if s.Effect != "Deny" || s.Condition == nil {
			continue
		}
		cond, ok := s.Condition["StringNotEquals"]
		if !ok {
			continue
		}
		condMap, ok := cond.(map[string]any)
		if !ok {
			continue
		}
		if val, found := condMap[tagKey]; found {
			if str, ok := val.(string); ok && str == "true" {
				return true
			}
		}
	}
	return false
}

// hasSeparateDenyForTag returns true if p has a Deny statement whose
// Condition references only the given tag in a Null check.
func hasSeparateDenyForTag(p *policy.Policy, tag string) bool {
	tagKey := "aws:RequestTag/" + tag

	for _, s := range p.Statements {
		if s.Effect != "Deny" {
			continue
		}
		if s.Condition == nil {
			continue
		}
		nullCond, ok := s.Condition["Null"]
		if !ok {
			continue
		}
		condMap, ok := nullCond.(map[string]any)
		if !ok {
			continue
		}
		if val, found := condMap[tagKey]; found {
			if str, ok := val.(string); ok && str == "true" {
				return true
			}
		}
	}
	return false
}
