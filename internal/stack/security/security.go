// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package security defines the logging-protection SCP stack.
//
// Ground deploys structural AWS plumbing only. Security detection services
// (GuardDuty, Security Hub, Macie) are NOT deployed here — that is attest's job
// after 'attest compile' selects the appropriate standards for active frameworks.
//
// What this stack deploys:
//   - A Service Control Policy (SCP) that denies disabling the logging infrastructure
//     ground itself deployed (CloudTrail, Config). This protects ground's own plumbing
//     from accidental or malicious disablement.
//   - The SCP is attached to the organization root so all member accounts inherit it.
//
// Non-AWS services (CrowdStrike, Globus, Splunk, Palo Alto Prisma, etc.) are declared
// in the ExternalServices section of ground.yaml. Ground records these declarations in
// its metadata so attest can assess which controls are satisfied by those services.
// Ground does not deploy, configure, or verify those services.
package security

import (
	"encoding/json"
	"fmt"

	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
)

// Stack builds the CloudFormation template for the logging-protection SCP.
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

// Template generates the logging-protection SCP.
// This SCP denies disabling CloudTrail and Config across all member accounts.
func (s *Stack) Template() (*cfn.Template, error) {
	// SCP content: deny disabling the logging infrastructure ground deployed.
	// Detection services are not mentioned here — attest enables GuardDuty,
	// Security Hub (with the correct standard), and Macie after 'attest compile'
	// determines which frameworks are active.
	scpPolicy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid":    "DenyDisableCloudTrail",
				"Effect": "Deny",
				"Action": []string{
					"cloudtrail:DeleteTrail",
					"cloudtrail:StopLogging",
					"cloudtrail:UpdateTrail",
				},
				"Resource": "*",
			},
			{
				"Sid":    "DenyDisableConfig",
				"Effect": "Deny",
				"Action": []string{
					"config:DeleteConfigRule",
					"config:DeleteConfigurationRecorder",
					"config:DeleteDeliveryChannel",
					"config:StopConfigurationRecorder",
				},
				"Resource": "*",
			},
		},
	}

	scpJSON, err := json.Marshal(scpPolicy)
	if err != nil {
		return nil, fmt.Errorf("marshal logging protection SCP: %w", err)
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: logging-protection SCP — deny disabling CloudTrail and Config",
		Parameters: map[string]any{
			"OrgRootId": map[string]any{
				"Type":           "String",
				"Description":    "AWS Organizations root ID (e.g., r-abcd). Retrieved automatically by 'ground deploy'.",
				"AllowedPattern": "^r-[a-z0-9]{4,32}$",
			},
		},
		Resources: map[string]any{
			"LoggingProtectionSCP": cfn.Resource("AWS::Organizations::Policy", map[string]any{
				"Name":        "ground-logging-protection",
				"Description": "Deny disabling CloudTrail and Config — protects ground logging infrastructure",
				"Type":        "SERVICE_CONTROL_POLICY",
				"Content":     string(scpJSON),
				"TargetIds":   []any{map[string]string{"Ref": "OrgRootId"}},
				"Tags":        []map[string]string{cfn.Tag("managed-by", "ground")},
			}),
		},
		Outputs: map[string]any{
			"LoggingProtectionSCPId": map[string]any{
				"Description": "ID of the logging-protection SCP attached to the org root",
				"Value":       map[string]any{"Ref": "LoggingProtectionSCP"},
				"Export":      map[string]string{"Name": "ground-logging-protection-scp-id"},
			},
		},
	}, nil
}
