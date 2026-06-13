// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provabl/ground/internal/config"
)

func testStack() *Stack {
	return New(
		&config.NetworkConfig{
			CIDRBlock:    "10.0.0.0/8",
			VPCEndpoints: []string{"s3", "sts", "ssm", "kms"},
		},
		&config.OrgConfig{Region: "us-west-2", ManagementID: "123456789012"},
	)
}

// resourcesByType parses the template JSON and groups logical IDs by Type.
func resourcesByType(t *testing.T, s *Stack) map[string][]map[string]any {
	t.Helper()
	tmpl, err := s.Template()
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	out := map[string][]map[string]any{}
	for _, raw := range tmpl.Resources {
		r, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("resource is not a map: %T", raw)
		}
		typ, _ := r["Type"].(string)
		out[typ] = append(out[typ], r["Properties"].(map[string]any))
	}
	return out
}

func TestTemplate_VPCAndSubnets(t *testing.T) {
	res := resourcesByType(t, testStack())

	vpcs := res["AWS::EC2::VPC"]
	if len(vpcs) != 1 {
		t.Fatalf("got %d VPCs, want 1", len(vpcs))
	}
	if cidr := vpcs[0]["CidrBlock"]; cidr != "10.0.0.0/16" {
		t.Errorf("VPC CIDR = %v, want 10.0.0.0/16 (hub /16)", cidr)
	}

	subnets := res["AWS::EC2::Subnet"]
	if len(subnets) != defaultAZCount {
		t.Fatalf("got %d subnets, want %d (one per AZ)", len(subnets), defaultAZCount)
	}
	for _, sn := range subnets {
		if sn["MapPublicIpOnLaunch"] != false {
			t.Error("subnet must not auto-assign public IPs (private-only)")
		}
	}
}

func TestTemplate_NoInternetGateway(t *testing.T) {
	res := resourcesByType(t, testStack())
	if len(res["AWS::EC2::InternetGateway"]) != 0 {
		t.Error("network stack must deploy no Internet Gateway (private-only by design)")
	}
}

func TestTemplate_GatewayVsInterfaceEndpoints(t *testing.T) {
	res := resourcesByType(t, testStack())
	eps := res["AWS::EC2::VPCEndpoint"]
	if len(eps) != 4 {
		t.Fatalf("got %d endpoints, want 4 (s3, sts, ssm, kms)", len(eps))
	}

	byType := map[string]int{}
	var sawS3Gateway, sawInterfacePolicy bool
	for _, ep := range eps {
		etype, _ := ep["VpcEndpointType"].(string)
		byType[etype]++
		svc, _ := ep["ServiceName"].(string)
		if strings.HasSuffix(svc, ".s3") {
			if etype != "Gateway" {
				t.Errorf("s3 endpoint type = %s, want Gateway", etype)
			}
			if _, hasRT := ep["RouteTableIds"]; !hasRT {
				t.Error("s3 gateway endpoint must attach to a route table")
			}
			sawS3Gateway = true
		}
		if etype == "Interface" {
			if ep["PrivateDnsEnabled"] != true {
				t.Error("interface endpoint must enable private DNS")
			}
			if _, hasPolicy := ep["PolicyDocument"]; hasPolicy {
				sawInterfacePolicy = true
			}
		}
		// All service names must be region-qualified to the org region.
		if !strings.HasPrefix(svc, "com.amazonaws.us-west-2.") {
			t.Errorf("service name %q is not region-qualified to us-west-2", svc)
		}
	}
	if !sawS3Gateway {
		t.Error("expected an s3 gateway endpoint")
	}
	if byType["Gateway"] != 1 || byType["Interface"] != 3 {
		t.Errorf("endpoint split = %v, want 1 Gateway + 3 Interface", byType)
	}
	if !sawInterfacePolicy {
		t.Error("interface endpoints must carry the org-conditioned policy document")
	}
}

func TestTemplate_InterfaceEndpointPolicyIsOrgScoped(t *testing.T) {
	res := resourcesByType(t, testStack())
	for _, ep := range res["AWS::EC2::VPCEndpoint"] {
		if ep["VpcEndpointType"] != "Interface" {
			continue
		}
		// The policy is an inline CloudFormation object; it must round-trip to JSON
		// and reference aws:PrincipalOrgID against the OrgId parameter (both an Allow
		// for same-org and a Deny for external principals).
		raw, err := json.Marshal(ep["PolicyDocument"])
		if err != nil {
			t.Fatalf("endpoint policy not serializable: %v", err)
		}
		s := string(raw)
		if !strings.Contains(s, "aws:PrincipalOrgID") {
			t.Errorf("interface endpoint policy missing aws:PrincipalOrgID condition:\n%s", s)
		}
		if !strings.Contains(s, `"Ref":"OrgId"`) {
			t.Errorf("interface endpoint policy must compare against the OrgId parameter:\n%s", s)
		}
		if !strings.Contains(s, "DenyExternalPrincipals") {
			t.Errorf("interface endpoint policy missing the external-principal Deny:\n%s", s)
		}
	}
}

// TestTemplate_HasOrgIdParameter verifies the OrgId parameter exists for the
// endpoint policy to Ref (resolved at deploy time like the accounts stack's OrgRootId).
func TestTemplate_HasOrgIdParameter(t *testing.T) {
	tmpl, err := testStack().Template()
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	if _, ok := tmpl.Parameters["OrgId"]; !ok {
		t.Error("template missing OrgId parameter")
	}
}

func TestTemplate_Deterministic(t *testing.T) {
	a, err := testStack().Template()
	if err != nil {
		t.Fatalf("Template a: %v", err)
	}
	b, err := testStack().Template()
	if err != nil {
		t.Fatalf("Template b: %v", err)
	}
	aj, _ := a.JSON()
	bj, _ := b.JSON()
	if aj != bj {
		t.Error("Template is not deterministic across calls")
	}
}

func TestTemplate_DefaultsCIDRWhenEmpty(t *testing.T) {
	s := New(&config.NetworkConfig{}, &config.OrgConfig{Region: "us-east-1"})
	res := resourcesByType(t, s)
	if cidr := res["AWS::EC2::VPC"][0]["CidrBlock"]; cidr != "10.0.0.0/16" {
		t.Errorf("default VPC CIDR = %v, want 10.0.0.0/16", cidr)
	}
}

func TestTemplate_Outputs(t *testing.T) {
	tmpl, err := testStack().Template()
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	for _, want := range []string{"VpcId", "VpcCidr"} {
		if _, ok := tmpl.Outputs[want]; !ok {
			t.Errorf("template missing output %q", want)
		}
	}
}

// hubSpokeStack returns a TransitGateway:true stack with three workload tiers.
func hubSpokeStack() *Stack {
	return New(
		&config.NetworkConfig{
			CIDRBlock:      "10.0.0.0/8",
			TransitGateway: true,
			VPCEndpoints:   []string{"s3", "sts", "ssm"},
		},
		&config.OrgConfig{
			Region:       "us-west-2",
			ManagementID: "123456789012",
			WorkloadOUs:  []string{"research", "sensitive", "sandbox"},
		},
	)
}

func TestHubSpoke_TopologyShape(t *testing.T) {
	res := resourcesByType(t, hubSpokeStack())

	if n := len(res["AWS::EC2::TransitGateway"]); n != 1 {
		t.Fatalf("got %d transit gateways, want 1", n)
	}
	// 1 hub + 3 spokes = 4 VPCs.
	if n := len(res["AWS::EC2::VPC"]); n != 4 {
		t.Errorf("got %d VPCs, want 4 (hub + 3 spokes)", n)
	}
	// 4 TGW attachments (one per VPC).
	if n := len(res["AWS::EC2::TransitGatewayAttachment"]); n != 4 {
		t.Errorf("got %d TGW attachments, want 4", n)
	}
	// 4 segregated TGW route tables (hub + per spoke).
	if n := len(res["AWS::EC2::TransitGatewayRouteTable"]); n != 4 {
		t.Errorf("got %d TGW route tables, want 4 (segregated per tier)", n)
	}
	// No Internet Gateway anywhere.
	if n := len(res["AWS::EC2::InternetGateway"]); n != 0 {
		t.Errorf("got %d internet gateways, want 0 (private-only)", n)
	}
}

func TestHubSpoke_DisablesDefaultTGWTables(t *testing.T) {
	res := resourcesByType(t, hubSpokeStack())
	tgw := res["AWS::EC2::TransitGateway"][0]
	if tgw["DefaultRouteTableAssociation"] != "disable" {
		t.Error("TGW must disable default route-table association (else a new attachment auto-joins a shared table, breaking tier isolation)")
	}
	if tgw["DefaultRouteTablePropagation"] != "disable" {
		t.Error("TGW must disable default route-table propagation")
	}
}

// The isolation invariant: a spoke's TGW route table has a route to the hub but
// NEVER to a sibling spoke. This is the routing fact behind tier isolation.
func TestHubSpoke_NoCrossSpokeRoutes(t *testing.T) {
	tmpl, err := hubSpokeStack().Template()
	if err != nil {
		t.Fatalf("Template: %v", err)
	}

	// Spoke CIDRs (10.2/16 research?, order is sorted: research, sandbox, sensitive
	// → 10.1, 10.2, 10.3). Collect every TransitGatewayRoute and check no spoke
	// route table points at another spoke's CIDR.
	spokeCIDRs := map[string]bool{"10.1.0.0/16": true, "10.2.0.0/16": true, "10.3.0.0/16": true}

	for logicalID, raw := range tmpl.Resources {
		r := raw.(map[string]any)
		if r["Type"] != "AWS::EC2::TransitGatewayRoute" {
			continue
		}
		props := r["Properties"].(map[string]any)
		rtRef := props["TransitGatewayRouteTableId"].(map[string]string)["Ref"]
		dest := props["DestinationCidrBlock"].(string)

		// A route living in a spoke route table (TGWRouteTableSpoke*) must target the
		// hub CIDR (10.0.0.0/16), never a sibling spoke CIDR.
		if strings.HasPrefix(rtRef, "TGWRouteTableSpoke") {
			if spokeCIDRs[dest] {
				t.Errorf("%s: spoke route table %s has a route to spoke CIDR %s — cross-tier path must not exist",
					logicalID, rtRef, dest)
			}
			if dest != "10.0.0.0/16" {
				t.Errorf("%s: spoke route %s points at %s, expected only the hub CIDR 10.0.0.0/16", logicalID, rtRef, dest)
			}
		}
	}
}

// Endpoints live only on the hub (shared via TGW); spokes carry none.
func TestHubSpoke_EndpointsOnlyOnHub(t *testing.T) {
	tmpl, err := hubSpokeStack().Template()
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	for logicalID, raw := range tmpl.Resources {
		if raw.(map[string]any)["Type"] != "AWS::EC2::VPCEndpoint" {
			continue
		}
		if !strings.HasPrefix(logicalID, "Hub") {
			t.Errorf("VPC endpoint %s is not on the hub — endpoints are centralized on the hub and shared via TGW", logicalID)
		}
	}
}

func TestHubSpoke_Deterministic(t *testing.T) {
	a, _ := hubSpokeStack().Template()
	b, _ := hubSpokeStack().Template()
	aj, _ := a.JSON()
	bj, _ := b.JSON()
	if aj != bj {
		t.Error("hub-and-spoke template is not deterministic")
	}
}

// TransitGateway:true but no workload tiers → degrade to the single-VPC path.
func TestHubSpoke_DegradesWithoutTiers(t *testing.T) {
	s := New(
		&config.NetworkConfig{CIDRBlock: "10.0.0.0/8", TransitGateway: true},
		&config.OrgConfig{Region: "us-east-1"}, // no WorkloadOUs
	)
	res := resourcesByType(t, s)
	if len(res["AWS::EC2::TransitGateway"]) != 0 {
		t.Error("no workload tiers → should degrade to single VPC (no TGW)")
	}
	if len(res["AWS::EC2::VPC"]) != 1 {
		t.Errorf("got %d VPCs, want 1 (single-VPC degrade)", len(res["AWS::EC2::VPC"]))
	}
}
