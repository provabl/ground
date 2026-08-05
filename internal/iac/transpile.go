// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"fmt"
	"strings"
)

// This file transpiles the CloudFormation templates ground already builds into
// HCL, rather than re-declaring the foundation in a second hand-written
// generator.
//
// That choice is the whole design. A hand-written Terraform generator is a
// second implementation of ground: every stack change has to be mirrored, and
// when the mirror is missed the export silently drifts — producing a foundation
// an operator believes matches CloudFormation when it does not. Transpiling the
// *same* cfn.Template that `ground deploy` submits means a new resource in
// internal/stack shows up in the export automatically, and anything the
// transpiler cannot faithfully represent is a loud error instead of a silent
// omission (see [UnsupportedError]).
//
// The mapping is possible because the templates use a small, closed subset of
// CloudFormation: Ref, Fn::GetAtt, Fn::Sub, Fn::Select, Fn::GetAZs, and
// DependsOn. Each has a direct HCL equivalent. Anything outside that subset is
// rejected.

// UnsupportedError reports a CloudFormation construct the transpiler cannot
// faithfully render as HCL.
//
// This is deliberately a hard error rather than a skip or a commented-out
// placeholder. A partially-transpiled resource is the failure mode worth
// preventing: it applies cleanly and leaves the operator with a foundation that
// is missing exactly the property they were relying on.
type UnsupportedError struct {
	// LogicalID is the CloudFormation logical ID being transpiled ("" for a
	// template-level construct).
	LogicalID string
	// Construct names what wasn't supported (a resource type, an intrinsic, ...).
	Construct string
	// Reason explains why, and what to do about it.
	Reason string
}

func (e *UnsupportedError) Error() string {
	loc := "template"
	if e.LogicalID != "" {
		loc = "resource " + e.LogicalID
	}
	return fmt.Sprintf("cannot transpile %s: unsupported %s — %s", loc, e.Construct, e.Reason)
}

// resourceMapping describes how one CloudFormation resource type becomes a
// Terraform resource.
type resourceMapping struct {
	// tfType is the Terraform resource type.
	tfType string
	// props maps a CloudFormation property name to its Terraform argument name.
	// A CFN property absent from this map is an error: silently dropping a
	// property is how an export quietly stops matching the deployment.
	props map[string]string
	// drop lists CFN properties deliberately not carried over, each with the
	// reason. Being explicit here is what distinguishes a considered omission
	// from an oversight.
	drop map[string]string
	// tagStyle says how Tags are rendered: "map" for tags = {...}, "block" for
	// repeated tag {...} blocks, "none" if the resource takes no tags.
	tagStyle string
	// synthesize adds Terraform-only arguments with no CFN counterpart.
	synthesize map[string]string
}

// cfnToTF maps every resource type ground's stacks emit. The transpiler refuses
// any type not listed, so adding a resource to a stack without teaching the
// transpiler fails the build's parity test rather than shipping a short export.
var cfnToTF = map[string]resourceMapping{
	"AWS::Organizations::OrganizationalUnit": {
		tfType:   "aws_organizations_organizational_unit",
		props:    map[string]string{"Name": "name", "ParentId": "parent_id"},
		tagStyle: "map",
	},
	"AWS::Organizations::Policy": {
		tfType: "aws_organizations_policy",
		props: map[string]string{
			"Name":        "name",
			"Description": "description",
			"Type":        "type",
			"Content":     "content",
		},
		// TargetIds has no equivalent argument: in Terraform, attachment is a
		// separate aws_organizations_policy_attachment resource. transpileResources
		// expands it into one, so this is handled rather than dropped.
		drop:     map[string]string{"TargetIds": "expanded into aws_organizations_policy_attachment resources"},
		tagStyle: "map",
	},
	"AWS::S3::Bucket": {
		tfType: "aws_s3_bucket",
		props:  map[string]string{"BucketName": "bucket"},
		// Every one of these is a standalone resource in the AWS provider v4+.
		// transpileResources expands them; none is silently lost.
		drop: map[string]string{
			"AccessControl":                  "ACLs are deprecated; the bucket is private by default and public access is blocked below",
			"PublicAccessBlockConfiguration": "expanded into aws_s3_bucket_public_access_block",
			"BucketEncryption":               "expanded into aws_s3_bucket_server_side_encryption_configuration",
			"VersioningConfiguration":        "expanded into aws_s3_bucket_versioning",
			"ObjectLockConfiguration":        "expanded into aws_s3_bucket_object_lock_configuration",
			"LifecycleConfiguration":         "expanded into aws_s3_bucket_lifecycle_configuration",
			"ObjectLockEnabled":              "rendered as object_lock_enabled on the bucket",
		},
		synthesize: map[string]string{"object_lock_enabled": "true"},
		tagStyle:   "map",
	},
	"AWS::S3::BucketPolicy": {
		tfType:   "aws_s3_bucket_policy",
		props:    map[string]string{"Bucket": "bucket", "PolicyDocument": "policy"},
		tagStyle: "none",
	},
	"AWS::CloudTrail::Trail": {
		tfType: "aws_cloudtrail",
		props: map[string]string{
			"TrailName":                  "name",
			"S3BucketName":               "s3_bucket_name",
			"IsLogging":                  "enable_logging",
			"IsMultiRegionTrail":         "is_multi_region_trail",
			"IsOrganizationTrail":        "is_organization_trail",
			"IncludeGlobalServiceEvents": "include_global_service_events",
			"EnableLogFileValidation":    "enable_log_file_validation",
		},
		drop:     map[string]string{"EventSelectors": "expanded into an event_selector block"},
		tagStyle: "map",
	},
	"AWS::Config::ConfigurationRecorder": {
		tfType:   "aws_config_configuration_recorder",
		props:    map[string]string{"Name": "name", "RoleARN": "role_arn"},
		drop:     map[string]string{"RecordingGroup": "expanded into a recording_group block"},
		tagStyle: "none",
	},
	"AWS::Config::DeliveryChannel": {
		tfType: "aws_config_delivery_channel",
		props:  map[string]string{"Name": "name", "S3BucketName": "s3_bucket_name"},
		drop: map[string]string{
			"ConfigSnapshotDeliveryProperties": "expanded into a snapshot_delivery_properties block",
		},
		tagStyle: "none",
	},
	"AWS::IAM::Role": {
		tfType: "aws_iam_role",
		props: map[string]string{
			"RoleName":                 "name",
			"AssumeRolePolicyDocument": "assume_role_policy",
		},
		// aws_iam_role.managed_policy_arns exists but is deprecated in provider v5;
		// the supported form is a separate attachment resource, which expand emits.
		drop:     map[string]string{"ManagedPolicyArns": "expanded into aws_iam_role_policy_attachment resources"},
		tagStyle: "map",
	},
	"AWS::EC2::VPC": {
		tfType: "aws_vpc",
		props: map[string]string{
			"CidrBlock":          "cidr_block",
			"EnableDnsSupport":   "enable_dns_support",
			"EnableDnsHostnames": "enable_dns_hostnames",
		},
		tagStyle: "map",
	},
	"AWS::EC2::Subnet": {
		tfType: "aws_subnet",
		props: map[string]string{
			"VpcId":               "vpc_id",
			"CidrBlock":           "cidr_block",
			"AvailabilityZone":    "availability_zone",
			"MapPublicIpOnLaunch": "map_public_ip_on_launch",
		},
		tagStyle: "map",
	},
	"AWS::EC2::RouteTable": {
		tfType:   "aws_route_table",
		props:    map[string]string{"VpcId": "vpc_id"},
		tagStyle: "map",
	},
	"AWS::EC2::SubnetRouteTableAssociation": {
		tfType:   "aws_route_table_association",
		props:    map[string]string{"SubnetId": "subnet_id", "RouteTableId": "route_table_id"},
		tagStyle: "none",
	},
	"AWS::EC2::VPCEndpoint": {
		tfType: "aws_vpc_endpoint",
		props: map[string]string{
			"VpcId":             "vpc_id",
			"ServiceName":       "service_name",
			"VpcEndpointType":   "vpc_endpoint_type",
			"PrivateDnsEnabled": "private_dns_enabled",
			"RouteTableIds":     "route_table_ids",
			"SubnetIds":         "subnet_ids",
			"PolicyDocument":    "policy",
		},
		tagStyle: "map",
	},
	"AWS::EC2::TransitGateway": {
		tfType: "aws_ec2_transit_gateway",
		props: map[string]string{
			"Description":                  "description",
			"DefaultRouteTableAssociation": "default_route_table_association",
			"DefaultRouteTablePropagation": "default_route_table_propagation",
		},
		tagStyle: "map",
	},
	"AWS::EC2::TransitGatewayAttachment": {
		tfType: "aws_ec2_transit_gateway_vpc_attachment",
		props: map[string]string{
			"TransitGatewayId": "transit_gateway_id",
			"VpcId":            "vpc_id",
			"SubnetIds":        "subnet_ids",
		},
		// ground manages per-tier route tables explicitly; letting an attachment
		// auto-join the default table would defeat tier isolation. CFN expresses
		// this on the TGW itself, Terraform on each attachment — so it must be
		// synthesized here or the isolation guarantee silently weakens.
		synthesize: map[string]string{
			"transit_gateway_default_route_table_association": "false",
			"transit_gateway_default_route_table_propagation": "false",
		},
		tagStyle: "map",
	},
	"AWS::EC2::TransitGatewayRouteTable": {
		tfType:   "aws_ec2_transit_gateway_route_table",
		props:    map[string]string{"TransitGatewayId": "transit_gateway_id"},
		tagStyle: "map",
	},
	"AWS::EC2::TransitGatewayRouteTableAssociation": {
		tfType: "aws_ec2_transit_gateway_route_table_association",
		props: map[string]string{
			"TransitGatewayRouteTableId": "transit_gateway_route_table_id",
			"TransitGatewayAttachmentId": "transit_gateway_attachment_id",
		},
		tagStyle: "none",
	},
	"AWS::EC2::TransitGatewayRoute": {
		tfType: "aws_ec2_transit_gateway_route",
		props: map[string]string{
			"TransitGatewayRouteTableId": "transit_gateway_route_table_id",
			"DestinationCidrBlock":       "destination_cidr_block",
			"TransitGatewayAttachmentId": "transit_gateway_attachment_id",
		},
		tagStyle: "none",
	},
	"AWS::SSO::PermissionSet": {
		tfType: "aws_ssoadmin_permission_set",
		props: map[string]string{
			"InstanceArn":     "instance_arn",
			"Name":            "name",
			"Description":     "description",
			"SessionDuration": "session_duration",
		},
		drop: map[string]string{
			"ManagedPolicies": "expanded into aws_ssoadmin_managed_policy_attachment resources",
		},
		tagStyle: "map",
	},
	// A no-op placeholder CFN requires for an otherwise-empty template. Terraform
	// has no such requirement, so it is dropped entirely (handled in
	// transpileResources, which emits nothing for it).
	"AWS::CloudFormation::WaitConditionHandle": {
		tfType:   "",
		tagStyle: "none",
	},
}

// tfName converts a CloudFormation logical ID to a Terraform resource name —
// PrivateSubnet1 → private_subnet_1, LoggingProtectionSCPId →
// logging_protection_scp_id, HubEndpointEC2 → hub_endpoint_ec2.
//
// It keeps acronyms intact (an uppercase run is one word, split only where the
// run's last letter begins a new word) and does not split a digit off the
// acronym it belongs to. Correctness only requires determinism and uniqueness —
// plan enforces the latter — but readable names matter here, because this output
// is what an operator reads in a plan and writes in an import command.
func tfName(logicalID string) string {
	runes := []rune(logicalID)
	isUpper := func(i int) bool { return i >= 0 && i < len(runes) && runes[i] >= 'A' && runes[i] <= 'Z' }
	isLower := func(i int) bool { return i >= 0 && i < len(runes) && runes[i] >= 'a' && runes[i] <= 'z' }
	isDigit := func(i int) bool { return i >= 0 && i < len(runes) && runes[i] >= '0' && runes[i] <= '9' }

	var b strings.Builder
	for i, r := range runes {
		if i > 0 {
			switch {
			case isUpper(i) && isLower(i-1), isUpper(i) && isDigit(i-1):
				// aB / 1B — a new word starts here.
				b.WriteRune('_')
			case isUpper(i) && isUpper(i-1) && isLower(i+1):
				// The last letter of an acronym run begins the next word: SCPId → scp_id.
				b.WriteRune('_')
			case isDigit(i) && isLower(i-1):
				// Subnet1 → subnet_1, but EC2 stays ec2.
				b.WriteRune('_')
			}
		}
		if isUpper(i) {
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}

	out := b.String()
	// A Terraform name must start with a letter or underscore.
	if out != "" && out[0] >= '0' && out[0] <= '9' {
		out = "r_" + out
	}
	return out
}
