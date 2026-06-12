// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"reflect"
	"testing"
)

// The OU tiers in their fixed allocation order (matches internal/stack/accounts).
var tiers = []string{"Infrastructure", "Research", "SensitiveResearch", "DoD-CMMC"}

func TestAllocate_CarvesExpectedBlocks(t *testing.T) {
	plan, err := Allocate("10.0.0.0/8", tiers, 3)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	// Hub is index 0 → first /16.
	if got := plan.Hub.CIDR.String(); got != "10.0.0.0/16" {
		t.Errorf("hub CIDR = %s, want 10.0.0.0/16", got)
	}
	if plan.Hub.Name != "hub" {
		t.Errorf("hub name = %q, want hub", plan.Hub.Name)
	}

	// Spokes follow in order: 10.1/16, 10.2/16, 10.3/16, 10.4/16.
	wantSpoke := map[string]string{
		"Infrastructure":    "10.1.0.0/16",
		"Research":          "10.2.0.0/16",
		"SensitiveResearch": "10.3.0.0/16",
		"DoD-CMMC":          "10.4.0.0/16",
	}
	if len(plan.Spokes) != len(tiers) {
		t.Fatalf("got %d spokes, want %d", len(plan.Spokes), len(tiers))
	}
	for _, sp := range plan.Spokes {
		if got := sp.CIDR.String(); got != wantSpoke[sp.Name] {
			t.Errorf("spoke %s CIDR = %s, want %s", sp.Name, got, wantSpoke[sp.Name])
		}
	}

	// Per-AZ /20 subnets of the hub: 10.0.0.0/20, 10.0.16.0/20, 10.0.32.0/20.
	wantHubSubnets := []string{"10.0.0.0/20", "10.0.16.0/20", "10.0.32.0/20"}
	var gotHubSubnets []string
	for _, s := range plan.Hub.Subnets {
		gotHubSubnets = append(gotHubSubnets, s.String())
	}
	if !reflect.DeepEqual(gotHubSubnets, wantHubSubnets) {
		t.Errorf("hub subnets = %v, want %v", gotHubSubnets, wantHubSubnets)
	}
}

func TestAllocate_Deterministic(t *testing.T) {
	a, err := Allocate("10.0.0.0/8", tiers, 3)
	if err != nil {
		t.Fatalf("Allocate a: %v", err)
	}
	b, err := Allocate("10.0.0.0/8", tiers, 3)
	if err != nil {
		t.Fatalf("Allocate b: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("Allocate is not deterministic: two calls produced different plans")
	}
}

// Appending a tier must not renumber the existing spokes — the destructive case
// the determinism guarantee exists to prevent.
func TestAllocate_AppendTierDoesNotRenumber(t *testing.T) {
	before, _ := Allocate("10.0.0.0/8", tiers, 3)
	after, _ := Allocate("10.0.0.0/8", append(append([]string{}, tiers...), "NewTier"), 3)

	beforeByName := map[string]string{}
	for _, sp := range before.Spokes {
		beforeByName[sp.Name] = sp.CIDR.String()
	}
	for _, sp := range after.Spokes {
		if was, existed := beforeByName[sp.Name]; existed && was != sp.CIDR.String() {
			t.Errorf("spoke %s renumbered: was %s, now %s", sp.Name, was, sp.CIDR.String())
		}
	}
}

func TestAllocate_SmallSupernet(t *testing.T) {
	// A /14 holds four /16s: hub + 3 spokes fits exactly.
	plan, err := Allocate("172.16.0.0/14", []string{"a", "b", "c"}, 2)
	if err != nil {
		t.Fatalf("Allocate /14 with 3 spokes: %v", err)
	}
	if plan.Hub.CIDR.String() != "172.16.0.0/16" {
		t.Errorf("hub = %s, want 172.16.0.0/16", plan.Hub.CIDR)
	}
	if got := plan.Spokes[2].CIDR.String(); got != "172.19.0.0/16" {
		t.Errorf("third spoke = %s, want 172.19.0.0/16", got)
	}
}

func TestAllocate_Errors(t *testing.T) {
	cases := []struct {
		name     string
		supernet string
		tiers    []string
		az       int
	}{
		{"malformed supernet", "not-a-cidr", tiers, 3},
		{"supernet smaller than /16", "10.0.0.0/17", tiers, 3},
		{"supernet too small for tiers", "10.0.0.0/16", tiers, 3}, // /16 = 1 VPC, need 5
		{"too few AZs", "10.0.0.0/8", tiers, 0},
		{"too many AZs", "10.0.0.0/8", tiers, 17},
		{"empty tier name", "10.0.0.0/8", []string{"a", ""}, 3},
		{"duplicate tier", "10.0.0.0/8", []string{"a", "a"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Allocate(tc.supernet, tc.tiers, tc.az); err == nil {
				t.Errorf("%s: want error, got nil", tc.name)
			}
		})
	}
}

func TestAllocate_NoSpokes(t *testing.T) {
	// Hub-only (TransitGateway:false degrade path uses a single VPC, but the
	// allocator must still handle zero spokes cleanly).
	plan, err := Allocate("10.0.0.0/8", nil, 3)
	if err != nil {
		t.Fatalf("Allocate hub-only: %v", err)
	}
	if len(plan.Spokes) != 0 {
		t.Errorf("got %d spokes, want 0", len(plan.Spokes))
	}
	if plan.Hub.CIDR.String() != "10.0.0.0/16" {
		t.Errorf("hub = %s, want 10.0.0.0/16", plan.Hub.CIDR)
	}
}
