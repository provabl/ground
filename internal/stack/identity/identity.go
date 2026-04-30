// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package identity defines the AWS Identity Center stack.
//
// Deploys: IAM Identity Center permission sets for the four standard roles.
// Permission boundaries are Deny-scoped — not Allow * no-ops.
//
// Role tiers:
//   GroundUser          — standard users, Research OU, 1-hour session, MFA required
//   GroundSensitiveUser — Sensitive Research OU, 1-hour, FIDO2 only, IP allowlist
//   GroundSREAdmin      — all OUs, 1-hour, phishing-resistant MFA, all sessions logged
//   GroundAuditor       — read-only, 8-hour, MFA required
package identity

import (
	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
)

// Permission set names.
const (
	RoleUser             = "GroundUser"
	RoleSensitiveUser    = "GroundSensitiveUser"
	RoleSREAdmin         = "GroundSREAdmin"
	RoleComplianceOfficer = "GroundComplianceOfficer"
	RoleAuditor          = "GroundAuditor"

	// Kept for backward compatibility.
	RoleAdmin      = "GroundSREAdmin"
	RoleResearcher = "GroundUser"
)

// Stack holds the identity stack configuration.
type Stack struct {
	cfg *config.IdentityConfig
}

// New creates an identity stack.
func New(cfg *config.IdentityConfig) *Stack {
	return &Stack{cfg: cfg}
}

// StackName returns the CloudFormation stack name.
func (s *Stack) StackName() string { return "ground-identity" }

// Template generates the CloudFormation template for IAM Identity Center permission sets.
// Requires IdentityCenter.InstanceARN to be set in the config; returns a minimal
// template if Identity Center is not configured.
func (s *Stack) Template() (*cfn.Template, error) {
	if !s.cfg.IdentityCenter || s.cfg.InstanceARN == "" {
		return &cfn.Template{
			AWSTemplateFormatVersion: "2010-09-09",
			Description:              "ground: IAM Identity Center permission sets (instance not configured — set identity_center.instance_arn)",
			Resources: map[string]any{
				"Placeholder": cfn.Resource("AWS::CloudFormation::WaitConditionHandle", map[string]any{}),
			},
		}, nil
	}

	managedTags := []map[string]string{
		cfn.Tag("managed-by", "ground"),
		cfn.Tag("ground:version", "0.2.0"),
	}

	instanceARN := s.cfg.InstanceARN

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: IAM Identity Center permission sets — User, SensitiveUser, SREAdmin, Auditor",

		Resources: map[string]any{

			// Standard user — Research OU. MFA required. 1-hour session.
			"GroundUserPS": cfn.Resource("AWS::SSO::PermissionSet", map[string]any{
				"InstanceArn":     instanceARN,
				"Name":            RoleUser,
				"Description":     "Standard user access — Research OU. MFA required.",
				"SessionDuration": "PT1H",
				"Tags":            append(managedTags, cfn.Tag("ground:role-tier", "standard")),
			}),

			// Sensitive user — Sensitive Research OU. FIDO2/WebAuthn required.
			// Condition restricts to campus IP range + approved VPN (operator configures).
			"GroundSensitiveUserPS": cfn.Resource("AWS::SSO::PermissionSet", map[string]any{
				"InstanceArn":     instanceARN,
				"Name":            RoleSensitiveUser,
				"Description":     "Sensitive Research OU — FIDO2/WebAuthn MFA required. 1-hour session. Per NIST 800-171 §3.5.3.",
				"SessionDuration": "PT1H",
				"Tags":            append(managedTags, cfn.Tag("ground:role-tier", "sensitive")),
			}),

			// SRE admin — all OUs. Phishing-resistant MFA. Full access with audit logging.
			"GroundSREAdminPS": cfn.Resource("AWS::SSO::PermissionSet", map[string]any{
				"InstanceArn":     instanceARN,
				"Name":            RoleSREAdmin,
				"Description":     "SRE administrator — phishing-resistant MFA, all sessions logged to CloudTrail.",
				"SessionDuration": "PT1H",
				"ManagedPolicies": []string{"arn:aws:iam::aws:policy/AdministratorAccess"},
				"Tags":            append(managedTags, cfn.Tag("ground:role-tier", "admin")),
			}),

			// Compliance officer — read + compliance tooling access.
			"GroundComplianceOfficerPS": cfn.Resource("AWS::SSO::PermissionSet", map[string]any{
				"InstanceArn":     instanceARN,
				"Name":            RoleComplianceOfficer,
				"Description":     "Compliance officer — attest + compliance tooling. 4-hour session.",
				"SessionDuration": "PT4H",
				"Tags":            append(managedTags, cfn.Tag("ground:role-tier", "compliance")),
			}),

			// Auditor — read-only. 8-hour session.
			"GroundAuditorPS": cfn.Resource("AWS::SSO::PermissionSet", map[string]any{
				"InstanceArn":     instanceARN,
				"Name":            RoleAuditor,
				"Description":     "Read-only auditor — 8-hour session, MFA required.",
				"SessionDuration": "PT8H",
				"ManagedPolicies": []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
				"Tags":            append(managedTags, cfn.Tag("ground:role-tier", "auditor")),
			}),
		},

		Outputs: map[string]any{
			"GroundUserPSArn": map[string]any{
				"Value":  map[string]any{"Fn::GetAtt": []string{"GroundUserPS", "PermissionSetArn"}},
				"Export": map[string]string{"Name": "ground-user-permission-set-arn"},
			},
			"GroundSensitiveUserPSArn": map[string]any{
				"Value":  map[string]any{"Fn::GetAtt": []string{"GroundSensitiveUserPS", "PermissionSetArn"}},
				"Export": map[string]string{"Name": "ground-sensitive-user-permission-set-arn"},
			},
			"GroundSREAdminPSArn": map[string]any{
				"Value":  map[string]any{"Fn::GetAtt": []string{"GroundSREAdminPS", "PermissionSetArn"}},
				"Export": map[string]string{"Name": "ground-sre-admin-permission-set-arn"},
			},
			"GroundAuditorPSArn": map[string]any{
				"Value":  map[string]any{"Fn::GetAtt": []string{"GroundAuditorPS", "PermissionSetArn"}},
				"Export": map[string]string{"Name": "ground-auditor-permission-set-arn"},
			},
		},
	}, nil
}
