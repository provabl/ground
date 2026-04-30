// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package policy defines IAM and SCP policies deployed by ground.
//
// Every policy in this package is tested before it ships. See policies/ for
// JSON policy files and their accompanying unit tests.
//
// Correctness guarantees:
//   - Permission boundaries: verified to deny privilege escalation
//   - VPC endpoint policies: verified to have aws:PrincipalOrgID condition
//   - Tagging SCPs: verified to deny per-tag independently (OR logic, not AND)
package policy

import (
	"encoding/json"
	"fmt"
)

// Statement is a single IAM policy statement.
type Statement struct {
	Sid       string            `json:"Sid,omitempty"`
	Effect    string            `json:"Effect"`
	Action    any               `json:"Action"`
	Resource  any               `json:"Resource"`
	Principal any               `json:"Principal,omitempty"`
	Condition map[string]any    `json:"Condition,omitempty"`
}

// Policy is an IAM or SCP policy document.
type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// JSON serializes the policy to a JSON string.
func (p *Policy) JSON() (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	return string(b), nil
}

// HasOrgIDCondition returns true if any statement has an aws:PrincipalOrgID condition.
// Used in VPC endpoint policy tests to verify org-scoping is present.
func (p *Policy) HasOrgIDCondition() bool {
	for _, s := range p.Statements {
		if s.Condition == nil {
			continue
		}
		for op, cond := range s.Condition {
			if m, ok := cond.(map[string]any); ok {
				for k := range m {
					if k == "aws:PrincipalOrgID" {
						_ = op
						return true
					}
				}
			}
		}
	}
	return false
}

// AllDenyStatements returns true if all statements have Effect: Deny.
// Used in permission boundary tests.
func (p *Policy) AllDenyStatements() bool {
	for _, s := range p.Statements {
		if s.Effect != "Deny" {
			return false
		}
	}
	return len(p.Statements) > 0
}
