// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package accounts defines the AWS Organization account structure stack.
//
// Deploys: Security, Infrastructure, Research, Sensitive Research, and
// DoD/CMMC OUs with sub-OUs for NIH Genomic, HIPAA Research, and CUI.
// Each OU gets the correct ground:tier tag for attest auto-discovery.
//
// The org root ID is passed as a CloudFormation parameter (OrgRootId).
// Retrieve it before deploying:
//
//	aws organizations list-roots --query 'Roots[0].Id' --output text
//	# Returns something like: r-abcd
//
// Then deploy:
//
//	ground deploy  (auto-discovers root ID from Organizations API)
package accounts

import (
	"github.com/provabl/ground/internal/cfn"
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

// StackName returns the CloudFormation stack name.
func (s *Stack) StackName() string { return "ground-accounts" }

// Template generates the CloudFormation template for the OU hierarchy.
// Uses a Parameter (OrgRootId) rather than a Lambda custom resource —
// ground deploy auto-populates this from the Organizations API, and
// operators can also pass it explicitly with --org-root-id.
func (s *Stack) Template() (*cfn.Template, error) {
	managedTags := []map[string]string{
		cfn.Tag("managed-by", "ground"),
		cfn.Tag("ground:version", "0.2.0"),
	}

	// Use the management account ID from config as the default, but the
	// root ID comes from the deployment context (injected by runDeploy).
	rootIDRef := map[string]string{"Ref": "OrgRootId"}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: OU hierarchy — Security, Infrastructure, Research, Sensitive Research, DoD/CMMC",

		Parameters: map[string]any{
			"OrgRootId": map[string]any{
				"Type":        "String",
				"Description": "AWS Organizations root ID (e.g., r-abcd). Retrieve with: aws organizations list-roots --query 'Roots[0].Id' --output text",
				"AllowedPattern": "^r-[a-z0-9]{4,32}$",
			},
		},

		Resources: map[string]any{

			// ── Top-level OUs ──────────────────────────────────────────────────
			"SecurityOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Security",
				"ParentId": rootIDRef,
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "security")),
			}),

			"InfrastructureOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Infrastructure",
				"ParentId": rootIDRef,
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "infrastructure")),
			}),

			"ResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Research",
				"ParentId": rootIDRef,
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "research")),
			}),

			"SensitiveResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "SensitiveResearch",
				"ParentId": rootIDRef,
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "sensitive")),
			}),

			"DoDCMMCOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "DoD-CMMC",
				"ParentId": rootIDRef,
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "dod")),
			}),

			// ── Sensitive Research sub-OUs ─────────────────────────────────────
			"NIHGenomicOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "NIHGenomic",
				"ParentId": map[string]string{"Ref": "SensitiveResearchOU"},
				"Tags": append(managedTags,
					cfn.Tag("ground:tier", "sensitive"),
					cfn.Tag("ground:data-scope", "genomic"),
					cfn.Tag("attest:data-classes", "CUI,GENOMIC")),
				"DependsOn": "SensitiveResearchOU",
			}),

			"HIPAAResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "HIPAAResearch",
				"ParentId": map[string]string{"Ref": "SensitiveResearchOU"},
				"Tags": append(managedTags,
					cfn.Tag("ground:tier", "sensitive"),
					cfn.Tag("ground:data-scope", "phi"),
					cfn.Tag("attest:data-classes", "PHI")),
				"DependsOn": "SensitiveResearchOU",
			}),

			"CUIResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "CUIResearch",
				"ParentId": map[string]string{"Ref": "SensitiveResearchOU"},
				"Tags": append(managedTags,
					cfn.Tag("ground:tier", "sensitive"),
					cfn.Tag("ground:data-scope", "cui"),
					cfn.Tag("attest:data-classes", "CUI")),
				"DependsOn": "SensitiveResearchOU",
			}),
		},

		Outputs: map[string]any{
			"SecurityOUID":          exportOU("SecurityOU", "ground-security-ou-id"),
			"InfrastructureOUID":    exportOU("InfrastructureOU", "ground-infrastructure-ou-id"),
			"ResearchOUID":          exportOU("ResearchOU", "ground-research-ou-id"),
			"SensitiveResearchOUID": exportOU("SensitiveResearchOU", "ground-sensitive-research-ou-id"),
			"DoDCMMCOUID":           exportOU("DoDCMMCOU", "ground-dod-cmmc-ou-id"),
			"NIHGenomicOUID":        exportOU("NIHGenomicOU", "ground-nih-genomic-ou-id"),
			"HIPAAResearchOUID":     exportOU("HIPAAResearchOU", "ground-hipaa-research-ou-id"),
			"CUIResearchOUID":       exportOU("CUIResearchOU", "ground-cui-research-ou-id"),
		},
	}, nil
}

func exportOU(logicalID, exportName string) map[string]any {
	return map[string]any{
		"Value": map[string]any{"Ref": logicalID},
		"Export": map[string]string{"Name": exportName},
	}
}
