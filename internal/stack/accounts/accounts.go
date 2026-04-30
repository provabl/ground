// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package accounts defines the AWS Organization account structure stack.
//
// Deploys: Security, Infrastructure, Research, Sensitive Research, and
// DoD/CMMC OUs with sub-OUs for NIH Genomic, HIPAA Research, and CUI.
// Each OU gets the correct ground:tier tag for attest auto-discovery.
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
// The org root ID is resolved at deploy time via a custom resource — the
// management account ID is known but the root ID requires an API call.
func (s *Stack) Template() (*cfn.Template, error) {
	managedTags := []map[string]string{
		cfn.Tag("managed-by", "ground"),
		cfn.Tag("ground:version", "0.2.0"),
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: OU hierarchy — Security, Infrastructure, Research, Sensitive Research, DoD/CMMC",

		Resources: map[string]any{

			// Discover org root ID at deploy time.
			"OrgRootLookup": cfn.Resource("AWS::CloudFormation::CustomResource", map[string]any{
				"ServiceToken": map[string]any{
					"Fn::Sub": "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:ground-org-root-lookup",
				},
			}),

			// ── Top-level OUs ──────────────────────────────────────────────────
			"SecurityOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Security",
				"ParentId": map[string]any{"Fn::GetAtt": []string{"OrgRootLookup", "RootId"}},
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "security")),
			}),

			"InfrastructureOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Infrastructure",
				"ParentId": map[string]any{"Fn::GetAtt": []string{"OrgRootLookup", "RootId"}},
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "infrastructure")),
			}),

			"ResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "Research",
				"ParentId": map[string]any{"Fn::GetAtt": []string{"OrgRootLookup", "RootId"}},
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "research")),
			}),

			"SensitiveResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "SensitiveResearch",
				"ParentId": map[string]any{"Fn::GetAtt": []string{"OrgRootLookup", "RootId"}},
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "sensitive")),
			}),

			"DoDCMMCOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "DoD-CMMC",
				"ParentId": map[string]any{"Fn::GetAtt": []string{"OrgRootLookup", "RootId"}},
				"Tags":     append(managedTags, cfn.Tag("ground:tier", "dod")),
			}),

			// ── Sensitive Research sub-OUs ─────────────────────────────────────
			// NIH Genomic Enclave: 800-171 + NIH GDS + optional HIPAA
			"NIHGenomicOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "NIHGenomic",
				"ParentId": map[string]any{"Ref": "SensitiveResearchOU"},
				"Tags": append(managedTags,
					cfn.Tag("ground:tier", "sensitive"),
					cfn.Tag("ground:data-scope", "genomic"),
					cfn.Tag("attest:data-classes", "CUI,GENOMIC")),
				"DependsOn": "SensitiveResearchOU",
			}),

			// HIPAA Research: HIPAA Security Rule + AWS BAA required
			"HIPAAResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "HIPAAResearch",
				"ParentId": map[string]any{"Ref": "SensitiveResearchOU"},
				"Tags": append(managedTags,
					cfn.Tag("ground:tier", "sensitive"),
					cfn.Tag("ground:data-scope", "phi"),
					cfn.Tag("attest:data-classes", "PHI")),
				"DependsOn": "SensitiveResearchOU",
			}),

			// CUI Research: 800-171 for non-DoD federal CUI
			"CUIResearchOU": cfn.Resource("AWS::Organizations::OrganizationalUnit", map[string]any{
				"Name":     "CUIResearch",
				"ParentId": map[string]any{"Ref": "SensitiveResearchOU"},
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
