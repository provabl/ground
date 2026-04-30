// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package network defines the AWS network foundation stack.
//
// Deploys: Transit Gateway, hub-and-spoke VPCs, VPC endpoints with
// aws:PrincipalOrgID conditions (verified by policy unit tests).
package network

import (
	"github.com/provabl/ground/internal/config"
)

// Stack holds the network stack configuration.
type Stack struct {
	cfg *config.NetworkConfig
}

// New creates a network stack.
func New(cfg *config.NetworkConfig) *Stack {
	return &Stack{cfg: cfg}
}
