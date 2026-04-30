// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package security defines the AWS security baseline stack.
//
// Deploys: GuardDuty (org-wide delegate), Security Hub (org-wide with NIST 800-53
// standard), Macie (org-wide). All three are ON by default — unlike most templates
// that ship with them disabled.
package security

import (
	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
)

// Stack builds the CloudFormation template for the security baseline.
type Stack struct {
	cfg *config.SecurityConfig
	org *config.OrgConfig
}

// New creates a security stack.
func New(cfg *config.SecurityConfig, org *config.OrgConfig) *Stack {
	return &Stack{cfg: cfg, org: org}
}

// StackName returns the CloudFormation stack name.
func (s *Stack) StackName() string { return "ground-security" }

// Template generates the CloudFormation template for the security baseline.
// This template must be deployed from the management account with delegated
// admin enabled for GuardDuty, Security Hub, and Macie.
func (s *Stack) Template() (*cfn.Template, error) {
	resources := map[string]any{}

	if s.cfg.GuardDuty {
		resources["GuardDutyDetector"] = cfn.Resource("AWS::GuardDuty::Detector", map[string]any{
			"Enable": true,
			"DataSources": map[string]any{
				"S3Logs":              map[string]bool{"Enable": true},
				"Kubernetes":          map[string]any{"AuditLogs": map[string]bool{"Enable": true}},
				"MalwareProtection":   map[string]any{"ScanEc2InstanceWithFindings": map[string]bool{"EbsVolumes": true}},
			},
			"FindingPublishingFrequency": "FIFTEEN_MINUTES",
			"Tags": []map[string]string{cfn.Tag("managed-by", "ground")},
		})
	}

	if s.cfg.SecurityHub {
		resources["SecurityHub"] = cfn.Resource("AWS::SecurityHub::Hub", map[string]any{
			"EnableDefaultStandards": true,
			"Tags":                   map[string]string{"managed-by": "ground"},
		})

		// Enable NIST 800-53 Rev 5 standard (the authoritative standard for FedRAMP/CMMC).
		resources["NIST80053Standard"] = cfn.Resource("AWS::SecurityHub::Standard", map[string]any{
			"StandardsArn": "arn:aws:securityhub:::ruleset/nist-800-53/v/5.0.0",
			"DependsOn":    "SecurityHub",
		})
	}

	if s.cfg.Macie {
		resources["MacieSession"] = cfn.Resource("AWS::Macie::Session", map[string]any{
			"Status":           "ENABLED",
			"FindingPublishingFrequency": "FIFTEEN_MINUTES",
		})
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: security baseline — GuardDuty, Security Hub (NIST 800-53), Macie",
		Resources:                resources,
		Outputs: map[string]any{
			"GuardDutyEnabled": map[string]any{
				"Description": "GuardDuty detector status",
				"Value":       s.cfg.GuardDuty,
			},
			"SecurityHubEnabled": map[string]any{
				"Description": "Security Hub status",
				"Value":       s.cfg.SecurityHub,
			},
			"MacieEnabled": map[string]any{
				"Description": "Macie session status",
				"Value":       s.cfg.Macie,
			},
		},
	}, nil
}
