// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/provabl/ground/internal/cfn"
	"github.com/provabl/ground/internal/config"
)

// defaultAZCount is how many AZs the single-VPC template spreads private subnets
// across when the config does not say otherwise. Three is the AWS default for
// production-grade availability.
const defaultAZCount = 3

// gatewayEndpointServices are the AWS services exposed as *gateway* VPC endpoints
// (route-table entries, no ENI, no hourly cost) rather than interface endpoints.
// Everything else in NetworkConfig.VPCEndpoints becomes an interface endpoint.
var gatewayEndpointServices = map[string]bool{
	"s3":       true,
	"dynamodb": true,
}

// Stack builds the CloudFormation template for ground's network foundation.
//
// This is build step 2 of docs/adr/0001-network-foundation.md: the single-VPC
// template (the TransitGateway:false degrade path) — a VPC with private subnets
// across AZs, gateway endpoints for S3/DynamoDB, and org-conditioned interface
// endpoints for the remaining services in NetworkConfig.VPCEndpoints. The
// hub-and-spoke + Transit Gateway topology (steps 3) and compute-to-data egress
// (step 4, provabl/ground#10) build on this.
type Stack struct {
	cfg *config.NetworkConfig
	org *config.OrgConfig
}

// New creates a network stack. org supplies the region (interface endpoint
// service names are region-qualified) and is the anchor for the org-conditioned
// endpoint policy.
func New(cfg *config.NetworkConfig, org *config.OrgConfig) *Stack {
	return &Stack{cfg: cfg, org: org}
}

// StackName returns the CloudFormation stack name.
func (s *Stack) StackName() string { return "ground-network" }

// Template generates the single-VPC network foundation. The VPC CIDR is the hub
// /16 of the deterministic allocation (ADR 0001 step 1) carved from
// NetworkConfig.CIDRBlock; private subnets are its per-AZ /20s.
func (s *Stack) Template() (*cfn.Template, error) {
	supernet := s.cfg.CIDRBlock
	if supernet == "" {
		supernet = "10.0.0.0/8"
	}
	// Step 2 deploys a single self-contained VPC (no spokes); it occupies the hub
	// /16. The hub-and-spoke fan-out is step 3.
	plan, err := Allocate(supernet, nil, defaultAZCount)
	if err != nil {
		return nil, fmt.Errorf("allocate network CIDRs: %w", err)
	}
	vpc := plan.Hub

	resources := map[string]any{
		"VPC": cfn.Resource("AWS::EC2::VPC", map[string]any{
			"CidrBlock":          vpc.CIDR.String(),
			"EnableDnsSupport":   true,
			"EnableDnsHostnames": true,
			"Tags": []map[string]string{
				cfn.Tag("Name", "ground-vpc"),
				cfn.Tag("managed-by", "ground"),
			},
		}),
		// Private-only by design: no Internet Gateway. Egress to AWS services is via
		// endpoints; egress to external research endpoints is step 4 (ground#10).
		"PrivateRouteTable": cfn.Resource("AWS::EC2::RouteTable", map[string]any{
			"VpcId": ref("VPC"),
			"Tags": []map[string]string{
				cfn.Tag("Name", "ground-private"),
				cfn.Tag("managed-by", "ground"),
			},
		}),
	}

	// One private subnet per AZ. AZs are selected via Fn::Select on the region's
	// AZ list so the template is region-portable.
	subnetRefs := make([]any, 0, len(vpc.Subnets))
	for az, subnet := range vpc.Subnets {
		name := fmt.Sprintf("PrivateSubnet%d", az+1)
		resources[name] = cfn.Resource("AWS::EC2::Subnet", map[string]any{
			"VpcId":     ref("VPC"),
			"CidrBlock": subnet.String(),
			"AvailabilityZone": map[string]any{
				"Fn::Select": []any{az, map[string]any{"Fn::GetAZs": ""}},
			},
			"MapPublicIpOnLaunch": false,
			"Tags": []map[string]string{
				cfn.Tag("Name", fmt.Sprintf("ground-private-%d", az+1)),
				cfn.Tag("managed-by", "ground"),
			},
		})
		resources[name+"RTAssoc"] = cfn.Resource("AWS::EC2::SubnetRouteTableAssociation", map[string]any{
			"SubnetId":     ref(name),
			"RouteTableId": ref("PrivateRouteTable"),
		})
		subnetRefs = append(subnetRefs, ref(name))
	}

	// VPC endpoints. Gateway endpoints (S3/DynamoDB) attach to the private route
	// table; interface endpoints get ENIs in every private subnet and carry the
	// org-conditioned policy. Sorted for deterministic template output.
	for _, svc := range sortedUnique(s.cfg.VPCEndpoints) {
		logicalID := endpointLogicalID(svc)
		if gatewayEndpointServices[svc] {
			resources[logicalID] = cfn.Resource("AWS::EC2::VPCEndpoint", map[string]any{
				"VpcId":           ref("VPC"),
				"ServiceName":     serviceName(svc, s.org.Region),
				"VpcEndpointType": "Gateway",
				"RouteTableIds":   []any{ref("PrivateRouteTable")},
			})
			continue
		}
		resources[logicalID] = cfn.Resource("AWS::EC2::VPCEndpoint", map[string]any{
			"VpcId":             ref("VPC"),
			"ServiceName":       serviceName(svc, s.org.Region),
			"VpcEndpointType":   "Interface",
			"PrivateDnsEnabled": true,
			"SubnetIds":         subnetRefs,
			"PolicyDocument":    orgEndpointPolicy(),
		})
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: network foundation (single VPC) — private subnets, org-conditioned VPC endpoints",
		Parameters: map[string]any{
			"OrgId": map[string]any{
				"Type":           "String",
				"Description":    "AWS Organizations ID (e.g., o-abcd1234). Retrieved automatically by 'ground deploy'.",
				"AllowedPattern": "^o-[a-z0-9]{10,32}$",
			},
		},
		Resources: resources,
		Outputs: map[string]any{
			"VpcId": map[string]any{
				"Description": "ID of the ground network VPC",
				"Value":       ref("VPC"),
				"Export":      map[string]string{"Name": "ground-vpc-id"},
			},
			"VpcCidr": map[string]any{
				"Description": "CIDR block of the ground network VPC",
				"Value":       vpc.CIDR.String(),
				"Export":      map[string]string{"Name": "ground-vpc-cidr"},
			},
		},
	}, nil
}

// orgEndpointPolicy returns the org-conditioned interface-endpoint policy as an
// inline CloudFormation object: allow same-org principals (aws:PrincipalOrgID
// equals the deploy-time OrgId parameter), deny everyone else. Mirrors
// policies/vpc_endpoint_policy.json; the OrgId Ref is resolved at deploy time the
// same way the accounts stack resolves OrgRootId.
func orgEndpointPolicy() map[string]any {
	orgRef := map[string]string{"Ref": "OrgId"}
	return map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid":       "AllowOrgPrincipals",
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    "*",
				"Resource":  "*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"aws:PrincipalOrgID": orgRef},
				},
			},
			{
				"Sid":       "DenyExternalPrincipals",
				"Effect":    "Deny",
				"Principal": "*",
				"Action":    "*",
				"Resource":  "*",
				"Condition": map[string]any{
					"StringNotEquals": map[string]any{"aws:PrincipalOrgID": orgRef},
				},
			},
		},
	}
}

func ref(logicalID string) map[string]string { return map[string]string{"Ref": logicalID} }

// serviceName builds a region-qualified AWS endpoint service name
// (com.amazonaws.<region>.<svc>), used for both gateway and interface endpoints.
func serviceName(svc, region string) string {
	return fmt.Sprintf("com.amazonaws.%s.%s", region, svc)
}

// endpointLogicalID returns a CloudFormation-safe logical ID for a service's
// endpoint resource, e.g. "s3" → "Endpoints3", "elasticfilesystem" →
// "Endpointelasticfilesystem".
func endpointLogicalID(svc string) string {
	var b strings.Builder
	b.WriteString("Endpoint")
	for _, r := range svc {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
