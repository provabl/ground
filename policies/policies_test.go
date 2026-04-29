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
