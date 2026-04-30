// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package logging defines the AWS logging foundation stack.
//
// Deploys: centralized S3 audit bucket, org-wide CloudTrail, AWS Config recorder
// and delivery channel. All three are required for attest to assess compliance
// posture via 'attest scan'.
package logging

import (
	"fmt"

	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
)

// Stack builds the CloudFormation template for the logging foundation.
type Stack struct {
	cfg *config.LoggingConfig
	org *config.OrgConfig
}

// New creates a logging stack.
func New(cfg *config.LoggingConfig, org *config.OrgConfig) *Stack {
	return &Stack{cfg: cfg, org: org}
}

// StackName returns the CloudFormation stack name.
func (s *Stack) StackName() string { return "ground-logging" }

// Template generates the CloudFormation template for the logging foundation.
func (s *Stack) Template() (*cfn.Template, error) {
	bucketName := s.cfg.BucketName
	if bucketName == "" {
		bucketName = fmt.Sprintf("ground-audit-%s", s.org.ManagementID)
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: logging foundation — S3 audit bucket, CloudTrail, Config recorder",
		Resources: map[string]any{

			// ── S3 audit bucket ──────────────────────────────────────────────
			"AuditBucket": cfn.Resource("AWS::S3::Bucket", map[string]any{
				"BucketName":    bucketName,
				"AccessControl": "Private",
				"PublicAccessBlockConfiguration": map[string]bool{
					"BlockPublicAcls":       true,
					"BlockPublicPolicy":     true,
					"IgnorePublicAcls":      true,
					"RestrictPublicBuckets": true,
				},
				"BucketEncryption": map[string]any{
					"ServerSideEncryptionConfiguration": []map[string]any{
						{"ServerSideEncryptionByDefault": map[string]string{
							"SSEAlgorithm": "aws:kms",
						}},
					},
				},
				"VersioningConfiguration": map[string]string{"Status": "Enabled"},
				"ObjectLockEnabled":       true,
				"ObjectLockConfiguration": map[string]any{
					"ObjectLockEnabled": "Enabled",
					"Rule": map[string]any{
						"DefaultRetention": map[string]any{
							"Mode": "GOVERNANCE",
							"Days": s.cfg.RetentionDays,
						},
					},
				},
				"LifecycleConfiguration": map[string]any{
					"Rules": []map[string]any{{
						"Id":     "transition-to-ia",
						"Status": "Enabled",
						"Transitions": []map[string]any{{
							"TransitionInDays": 90,
							"StorageClass":     "STANDARD_IA",
						}},
					}},
				},
				"Tags": []map[string]string{
					cfn.Tag("managed-by", "ground"),
					cfn.Tag("ground:purpose", "audit-logging"),
				},
			}),

			"AuditBucketPolicy": cfn.Resource("AWS::S3::BucketPolicy", map[string]any{
				"Bucket": map[string]string{"Ref": "AuditBucket"},
				"PolicyDocument": map[string]any{
					"Version": "2012-10-17",
					"Statement": []map[string]any{
						{
							"Sid":       "DenyNonHTTPS",
							"Effect":    "Deny",
							"Principal": "*",
							"Action":    "s3:*",
							"Resource": []map[string]any{
								{"Fn::GetAtt": []string{"AuditBucket", "Arn"}},
								{"Fn::Sub": "${AuditBucket.Arn}/*"},
							},
							"Condition": map[string]any{
								"Bool": map[string]string{"aws:SecureTransport": "false"},
							},
						},
						{
							"Sid":       "AllowCloudTrailWrite",
							"Effect":    "Allow",
							"Principal": map[string]string{"Service": "cloudtrail.amazonaws.com"},
							"Action":    []string{"s3:GetBucketAcl", "s3:PutObject"},
							"Resource": []map[string]any{
								{"Fn::GetAtt": []string{"AuditBucket", "Arn"}},
								{"Fn::Sub": "${AuditBucket.Arn}/AWSLogs/*"},
							},
						},
						{
							"Sid":       "AllowConfigWrite",
							"Effect":    "Allow",
							"Principal": map[string]string{"Service": "config.amazonaws.com"},
							"Action":    []string{"s3:GetBucketAcl", "s3:PutObject"},
							"Resource": []map[string]any{
								{"Fn::GetAtt": []string{"AuditBucket", "Arn"}},
								{"Fn::Sub": "${AuditBucket.Arn}/AWSLogs/*"},
							},
						},
					},
				},
			}),

			// ── CloudTrail (org-wide) ─────────────────────────────────────────
			"OrgTrail": cfn.Resource("AWS::CloudTrail::Trail", map[string]any{
				"TrailName":                  "ground-org-trail",
				"S3BucketName":               map[string]string{"Ref": "AuditBucket"},
				"IsLogging":                  true,
				"IsMultiRegionTrail":         true,
				"IsOrganizationTrail":        true,
				"IncludeGlobalServiceEvents": true,
				"EnableLogFileValidation":    true,
				"EventSelectors": []map[string]any{{
					"ReadWriteType":           "All",
					"IncludeManagementEvents": true,
					"DataResources": []map[string]any{
						{"Type": "AWS::S3::Object", "Values": []string{"arn:aws:s3"}},
					},
				}},
				"Tags":      []map[string]string{cfn.Tag("managed-by", "ground")},
				"DependsOn": "AuditBucketPolicy",
			}),

			// ── AWS Config recorder ───────────────────────────────────────────
			"ConfigRole": cfn.Resource("AWS::IAM::Role", map[string]any{
				"RoleName": "ground-config-role",
				"AssumeRolePolicyDocument": map[string]any{
					"Version": "2012-10-17",
					"Statement": []map[string]any{{
						"Effect":    "Allow",
						"Principal": map[string]string{"Service": "config.amazonaws.com"},
						"Action":    "sts:AssumeRole",
					}},
				},
				"ManagedPolicyArns": []string{
					"arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
				},
			}),

			"ConfigRecorder": cfn.Resource("AWS::Config::ConfigurationRecorder", map[string]any{
				"Name": "ground-config-recorder",
				"RecordingGroup": map[string]any{
					"AllSupported":               true,
					"IncludeGlobalResourceTypes": true,
				},
				"RoleARN": map[string]any{"Fn::GetAtt": []string{"ConfigRole", "Arn"}},
			}),

			"ConfigDeliveryChannel": cfn.Resource("AWS::Config::DeliveryChannel", map[string]any{
				"Name":         "ground-config-delivery",
				"S3BucketName": map[string]string{"Ref": "AuditBucket"},
				"ConfigSnapshotDeliveryProperties": map[string]string{
					"DeliveryFrequency": "TwentyFour_Hours",
				},
				"DependsOn": "ConfigRecorder",
			}),
		},

		Outputs: map[string]any{
			"AuditBucketArn": map[string]any{
				"Description": "ARN of the centralized S3 audit bucket",
				"Value":       map[string]any{"Fn::GetAtt": []string{"AuditBucket", "Arn"}},
				"Export":      map[string]string{"Name": "ground-audit-bucket-arn"},
			},
			"CloudTrailArn": map[string]any{
				"Description": "ARN of the org-wide CloudTrail",
				"Value":       map[string]any{"Fn::GetAtt": []string{"OrgTrail", "Arn"}},
				"Export":      map[string]string{"Name": "ground-cloudtrail-arn"},
			},
		},
	}, nil
}
