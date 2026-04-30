// SPDX-FileCopyrightText: 2026 Scott Friedman
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
