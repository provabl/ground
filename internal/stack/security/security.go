// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package security defines the AWS security baseline stack.
//
// Deploys: GuardDuty (org-wide), Security Hub (org-wide, with NIST 800-53
// standard), Macie (enabled for all accounts).
//
// All three are ON by default — unlike most templates that ship with them off.
// ground's guarantee: if you run 'attest scan' after deploy, these will show
// aws_covered for their respective controls.
package security

import (
	"github.com/provabl/ground/internal/config"
)

// Stack holds the security stack configuration.
type Stack struct {
	cfg *config.SecurityConfig
}

// New creates a security stack.
func New(cfg *config.SecurityConfig) *Stack {
	return &Stack{cfg: cfg}
}
