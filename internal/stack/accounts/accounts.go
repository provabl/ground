// Package accounts defines the AWS Organization account structure stack.
//
// Deploys: management OU, security/audit accounts, network account,
// shared-services account, and workload OUs.
package accounts

import (
	"github.com/provabl/ground/internal/config"
)

// Stack holds the accounts stack configuration.
type Stack struct {
	cfg *config.OrgConfig
}

// New creates an accounts stack.
func New(cfg *config.OrgConfig) *Stack {
	return &Stack{cfg: cfg}
}
