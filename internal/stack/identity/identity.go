// Package identity defines the AWS Identity Center stack.
//
// Deploys: IAM Identity Center instance, permission sets for
// admin, compliance-officer, researcher, and auditor roles.
// Permission boundaries are Deny-scoped — not Allow * no-ops.
package identity

import (
	"github.com/provabl/ground/internal/config"
)

// PermissionSet names for the standard role set.
const (
	RoleAdmin             = "GroundAdmin"
	RoleComplianceOfficer = "GroundComplianceOfficer"
	RoleResearcher        = "GroundResearcher"
	RoleAuditor           = "GroundAuditor"
)

// Stack holds the identity stack configuration.
type Stack struct {
	cfg *config.IdentityConfig
}

// New creates an identity stack.
func New(cfg *config.IdentityConfig) *Stack {
	return &Stack{cfg: cfg}
}
