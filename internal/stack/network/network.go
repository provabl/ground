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

// Template generates the network foundation. When NetworkConfig.TransitGateway is
// set and there are workload tiers to spoke out, it builds the hub-and-spoke
// topology (ADR 0001 step 3); otherwise it builds the single self-contained VPC
// (step 2, the degrade path). Both carve CIDRs from the deterministic allocation
// (step 1) over NetworkConfig.CIDRBlock.
func (s *Stack) Template() (*cfn.Template, error) {
	supernet := s.cfg.CIDRBlock
	if supernet == "" {
		supernet = "10.0.0.0/8"
	}
	tiers := spokeTiers(s.org.WorkloadOUs)
	if s.cfg.TransitGateway && len(tiers) > 0 {
		return s.hubSpokeTemplate(supernet, tiers)
	}
	return s.singleVPCTemplate(supernet)
}

// spokeTiers normalizes the workload OU list into spoke tier names, dropping
// empties and de-duping (the allocator rejects either, but normalizing here keeps
// the topology decision in one place).
func spokeTiers(workloadOUs []string) []string {
	return sortedUnique(workloadOUs)
}

// singleVPCTemplate is the TransitGateway:false degrade path (ADR 0001 step 2): a
// single private VPC on the hub /16 with gateway + org-conditioned interface
// endpoints.
func (s *Stack) singleVPCTemplate(supernet string) (*cfn.Template, error) {
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

// hubSpokeTemplate is the hub-and-spoke topology (ADR 0001 step 3): a shared hub
// VPC holding the centralized org-conditioned interface endpoints, one private
// spoke VPC per workload tier, and a Transit Gateway joining them with SEGREGATED
// per-tier route tables — the routing fact that makes the ground:tier /
// attest:data-classes isolation real (a spoke's TGW route table carries a route to
// the hub but NOT to sibling spokes, so cross-tier traffic has no path).
func (s *Stack) hubSpokeTemplate(supernet string, tiers []string) (*cfn.Template, error) {
	plan, err := Allocate(supernet, tiers, defaultAZCount)
	if err != nil {
		return nil, fmt.Errorf("allocate network CIDRs: %w", err)
	}

	resources := map[string]any{
		"TransitGateway": cfn.Resource("AWS::EC2::TransitGateway", map[string]any{
			"Description": "ground hub-and-spoke transit gateway",
			// Disable automatic association/propagation: ground manages per-tier route
			// tables explicitly, so a new attachment must NOT auto-join a shared table
			// (which would defeat tier isolation).
			"DefaultRouteTableAssociation": "disable",
			"DefaultRouteTablePropagation": "disable",
			"Tags": []map[string]string{
				cfn.Tag("Name", "ground-tgw"),
				cfn.Tag("managed-by", "ground"),
			},
		}),
	}
	outputs := map[string]any{}

	// Hub VPC: holds the centralized interface + gateway endpoints (shared by all
	// spokes via the TGW), plus its own attachment + route table.
	hubIDs := s.addVPC(resources, "Hub", plan.Hub, true)
	addTGWAttachment(resources, "Hub", hubIDs)
	resources["TGWRouteTableHub"] = tgwRouteTable("Hub")
	resources["TGWAssocHub"] = tgwAssociation("Hub", "Hub")
	outputs["HubVpcId"] = map[string]any{
		"Description": "ID of the shared-services hub VPC",
		"Value":       ref(hubIDs.vpc),
		"Export":      map[string]string{"Name": "ground-hub-vpc-id"},
	}

	// One spoke VPC per tier. Each gets its own TGW route table with a single route
	// to the hub — and crucially, no route to any sibling spoke. The hub's route
	// table propagates every spoke (the hub can reach all spokes for shared
	// endpoints); spoke tables do not propagate each other.
	for _, sp := range plan.Spokes {
		tier := sp.Name
		lid := tierLogicalID(tier)
		ids := s.addVPC(resources, lid, sp, false)
		addTGWAttachment(resources, lid, ids)

		// Spoke route table: associate the spoke's attachment, route 0/0-to-hub via
		// the hub attachment (for shared endpoints), nothing toward siblings.
		resources["TGWRouteTable"+lid] = tgwRouteTable(lid)
		resources["TGWAssoc"+lid] = tgwAssociation(lid, lid)
		resources["TGWRouteToHub"+lid] = cfn.Resource("AWS::EC2::TransitGatewayRoute", map[string]any{
			"TransitGatewayRouteTableId": ref("TGWRouteTable" + lid),
			"DestinationCidrBlock":       plan.Hub.CIDR.String(),
			"TransitGatewayAttachmentId": ref("TGWAttachmentHub"),
		})
		// Hub can reach this spoke: a route in the hub table to the spoke CIDR.
		resources["TGWRouteHubTo"+lid] = cfn.Resource("AWS::EC2::TransitGatewayRoute", map[string]any{
			"TransitGatewayRouteTableId": ref("TGWRouteTableHub"),
			"DestinationCidrBlock":       sp.CIDR.String(),
			"TransitGatewayAttachmentId": ref("TGWAttachment" + lid),
		})
		outputs[lid+"VpcId"] = map[string]any{
			"Description": fmt.Sprintf("ID of the %s spoke VPC", tier),
			"Value":       ref(ids.vpc),
		}
	}

	return &cfn.Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "ground: network foundation (hub-and-spoke) — Transit Gateway with segregated per-tier route tables",
		Parameters: map[string]any{
			"OrgId": map[string]any{
				"Type":           "String",
				"Description":    "AWS Organizations ID (e.g., o-abcd1234). Retrieved automatically by 'ground deploy'.",
				"AllowedPattern": "^o-[a-z0-9]{10,32}$",
			},
		},
		Resources: resources,
		Outputs:   outputs,
	}, nil
}

// vpcLogicalIDs holds the logical IDs of a VPC block's key resources, so the TGW
// wiring can reference them.
type vpcLogicalIDs struct {
	vpc        string
	routeTable string
	subnets    []string
}

// addVPC writes a private VPC block (VPC, private route table, per-AZ subnets +
// associations) into resources under the given prefix, and — when withEndpoints —
// the gateway + org-conditioned interface endpoints. Returns the logical IDs.
func (s *Stack) addVPC(resources map[string]any, prefix string, alloc VPCAlloc, withEndpoints bool) vpcLogicalIDs {
	vpcID := prefix + "VPC"
	rtID := prefix + "PrivateRouteTable"
	resources[vpcID] = cfn.Resource("AWS::EC2::VPC", map[string]any{
		"CidrBlock":          alloc.CIDR.String(),
		"EnableDnsSupport":   true,
		"EnableDnsHostnames": true,
		"Tags": []map[string]string{
			cfn.Tag("Name", "ground-"+strings.ToLower(prefix)),
			cfn.Tag("managed-by", "ground"),
		},
	})
	resources[rtID] = cfn.Resource("AWS::EC2::RouteTable", map[string]any{
		"VpcId": ref(vpcID),
		"Tags": []map[string]string{
			cfn.Tag("Name", "ground-"+strings.ToLower(prefix)+"-private"),
			cfn.Tag("managed-by", "ground"),
		},
	})

	ids := vpcLogicalIDs{vpc: vpcID, routeTable: rtID}
	subnetRefs := make([]any, 0, len(alloc.Subnets))
	for az, subnet := range alloc.Subnets {
		sid := fmt.Sprintf("%sPrivateSubnet%d", prefix, az+1)
		resources[sid] = cfn.Resource("AWS::EC2::Subnet", map[string]any{
			"VpcId":     ref(vpcID),
			"CidrBlock": subnet.String(),
			"AvailabilityZone": map[string]any{
				"Fn::Select": []any{az, map[string]any{"Fn::GetAZs": ""}},
			},
			"MapPublicIpOnLaunch": false,
			"Tags": []map[string]string{
				cfn.Tag("Name", fmt.Sprintf("ground-%s-private-%d", strings.ToLower(prefix), az+1)),
				cfn.Tag("managed-by", "ground"),
			},
		})
		resources[sid+"RTAssoc"] = cfn.Resource("AWS::EC2::SubnetRouteTableAssociation", map[string]any{
			"SubnetId":     ref(sid),
			"RouteTableId": ref(rtID),
		})
		ids.subnets = append(ids.subnets, sid)
		subnetRefs = append(subnetRefs, ref(sid))
	}

	if withEndpoints {
		for _, svc := range sortedUnique(s.cfg.VPCEndpoints) {
			epID := prefix + endpointLogicalID(svc)
			if gatewayEndpointServices[svc] {
				resources[epID] = cfn.Resource("AWS::EC2::VPCEndpoint", map[string]any{
					"VpcId":           ref(vpcID),
					"ServiceName":     serviceName(svc, s.org.Region),
					"VpcEndpointType": "Gateway",
					"RouteTableIds":   []any{ref(rtID)},
				})
				continue
			}
			resources[epID] = cfn.Resource("AWS::EC2::VPCEndpoint", map[string]any{
				"VpcId":             ref(vpcID),
				"ServiceName":       serviceName(svc, s.org.Region),
				"VpcEndpointType":   "Interface",
				"PrivateDnsEnabled": true,
				"SubnetIds":         subnetRefs,
				"PolicyDocument":    orgEndpointPolicy(),
			})
		}
	}
	return ids
}

// addTGWAttachment attaches a VPC's private subnets to the Transit Gateway.
func addTGWAttachment(resources map[string]any, prefix string, ids vpcLogicalIDs) {
	subnetRefs := make([]any, 0, len(ids.subnets))
	for _, sid := range ids.subnets {
		subnetRefs = append(subnetRefs, ref(sid))
	}
	resources["TGWAttachment"+prefix] = cfn.Resource("AWS::EC2::TransitGatewayAttachment", map[string]any{
		"TransitGatewayId": ref("TransitGateway"),
		"VpcId":            ref(ids.vpc),
		"SubnetIds":        subnetRefs,
		"Tags": []map[string]string{
			cfn.Tag("Name", "ground-tgw-attach-"+strings.ToLower(prefix)),
			cfn.Tag("managed-by", "ground"),
		},
	})
}

// tgwRouteTable builds a segregated Transit Gateway route table for a tier.
func tgwRouteTable(prefix string) map[string]any {
	return cfn.Resource("AWS::EC2::TransitGatewayRouteTable", map[string]any{
		"TransitGatewayId": ref("TransitGateway"),
		"Tags": []map[string]string{
			cfn.Tag("Name", "ground-tgw-rt-"+strings.ToLower(prefix)),
			cfn.Tag("managed-by", "ground"),
		},
	})
}

// tgwAssociation associates a tier's attachment with its own route table.
func tgwAssociation(rtPrefix, attachPrefix string) map[string]any {
	return cfn.Resource("AWS::EC2::TransitGatewayRouteTableAssociation", map[string]any{
		"TransitGatewayRouteTableId": ref("TGWRouteTable" + rtPrefix),
		"TransitGatewayAttachmentId": ref("TGWAttachment" + attachPrefix),
	})
}

// tierLogicalID turns a tier name into a CloudFormation-safe logical ID prefix,
// e.g. "DoD-CMMC" → "SpokeDoDCMMC".
func tierLogicalID(tier string) string {
	var b strings.Builder
	b.WriteString("Spoke")
	for _, r := range tier {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
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
