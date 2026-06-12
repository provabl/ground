// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package network builds ground's network-foundation CloudFormation stack:
// a hub-and-spoke topology with org-conditioned VPC endpoints and compute-to-data
// egress. See docs/adr/0001-network-foundation.md.
//
// This file is the deterministic CIDR allocator (ADR 0001, build step 1): a pure
// function from the supernet + the ordered tier list to per-VPC /16 blocks and
// per-AZ /20 subnets. Determinism is the point — re-running ground deploy must
// never renumber an existing spoke (renumbering is destructive), so allocation is
// a stable function of (supernet, tier index), with no time or randomness.
package network

import (
	"fmt"
	"net/netip"
)

// Allocation prefix lengths (ADR 0001): each VPC is a /16 carved from the
// supernet; each per-AZ private subnet is a /20 carved from its VPC.
const (
	vpcPrefixLen    = 16
	subnetPrefixLen = 20
	maxAZs          = 1 << (subnetPrefixLen - vpcPrefixLen) // /20s per /16 = 16
)

// VPCAlloc is one VPC's address allocation: its /16 and the per-AZ /20 subnets.
type VPCAlloc struct {
	Name    string         // "hub", or a spoke tier name ("Research", …)
	CIDR    netip.Prefix   // the /16
	Subnets []netip.Prefix // one /20 per AZ, in order
}

// Plan is the full deterministic allocation: the hub plus one spoke per tier,
// each carved from Supernet in a stable order.
type Plan struct {
	Supernet netip.Prefix
	Hub      VPCAlloc
	Spokes   []VPCAlloc
}

// Allocate carves supernetCIDR into a hub /16 (index 0) followed by one /16 per
// spoke tier, in the order given, each split into azCount /20 subnets. The order
// of spokeTiers is the allocation order and MUST be stable across runs (pass the
// OU tier list in a fixed order); spoke N always lands on the same /16.
//
// Pure and deterministic: no time, no randomness, no AWS. Errors on a malformed
// supernet, a supernet too small to hold 1 hub + len(spokeTiers) /16s, an azCount
// outside 1..16, or a duplicate/empty tier name.
func Allocate(supernetCIDR string, spokeTiers []string, azCount int) (*Plan, error) {
	supernet, err := netip.ParsePrefix(supernetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse supernet %q: %w", supernetCIDR, err)
	}
	supernet = supernet.Masked()
	if !supernet.Addr().Is4() {
		return nil, fmt.Errorf("supernet %q must be IPv4 (AWS VPC primary CIDR is IPv4)", supernetCIDR)
	}
	if supernet.Bits() > vpcPrefixLen {
		return nil, fmt.Errorf("supernet %q is /%d — must be /%d or larger to carve /%d VPCs",
			supernetCIDR, supernet.Bits(), vpcPrefixLen, vpcPrefixLen)
	}
	if azCount < 1 || azCount > maxAZs {
		return nil, fmt.Errorf("azCount %d out of range (1..%d /20 subnets fit in a /16)", azCount, maxAZs)
	}

	available := 1 << (vpcPrefixLen - supernet.Bits()) // number of /16s in the supernet
	need := 1 + len(spokeTiers)                        // hub + spokes
	if need > available {
		return nil, fmt.Errorf("supernet /%d holds %d /%d VPCs but %d are needed (1 hub + %d spokes)",
			supernet.Bits(), available, vpcPrefixLen, need, len(spokeTiers))
	}

	seen := map[string]bool{}
	for _, t := range spokeTiers {
		if t == "" {
			return nil, fmt.Errorf("spoke tier name must not be empty")
		}
		if seen[t] {
			return nil, fmt.Errorf("duplicate spoke tier %q", t)
		}
		seen[t] = true
	}

	hub, err := vpcAlloc(supernet, "hub", 0, azCount)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Supernet: supernet, Hub: hub}
	for i, tier := range spokeTiers {
		sp, err := vpcAlloc(supernet, tier, i+1, azCount) // hub is index 0
		if err != nil {
			return nil, err
		}
		plan.Spokes = append(plan.Spokes, sp)
	}
	return plan, nil
}

// vpcAlloc carves the index-th /16 from supernet and splits it into azCount /20s.
func vpcAlloc(supernet netip.Prefix, name string, index, azCount int) (VPCAlloc, error) {
	cidr, err := nthSubnet(supernet, vpcPrefixLen, index)
	if err != nil {
		return VPCAlloc{}, fmt.Errorf("allocate /%d for %q: %w", vpcPrefixLen, name, err)
	}
	subnets := make([]netip.Prefix, 0, azCount)
	for az := 0; az < azCount; az++ {
		sub, err := nthSubnet(cidr, subnetPrefixLen, az)
		if err != nil {
			return VPCAlloc{}, fmt.Errorf("allocate /%d subnet %d for %q: %w", subnetPrefixLen, az, name, err)
		}
		subnets = append(subnets, sub)
	}
	return VPCAlloc{Name: name, CIDR: cidr, Subnets: subnets}, nil
}

// nthSubnet returns the index-th subnet of length newPrefixLen carved from base.
// E.g. nthSubnet(10.0.0.0/8, 16, 3) == 10.3.0.0/16. IPv4 only.
func nthSubnet(base netip.Prefix, newPrefixLen, index int) (netip.Prefix, error) {
	if newPrefixLen < base.Bits() || newPrefixLen > 32 {
		return netip.Prefix{}, fmt.Errorf("new prefix /%d invalid for base /%d", newPrefixLen, base.Bits())
	}
	subnetBits := newPrefixLen - base.Bits()
	if index < 0 || index >= (1<<subnetBits) {
		return netip.Prefix{}, fmt.Errorf("index %d out of range for %d subnet bits", index, subnetBits)
	}
	baseInt := addrToUint32(base.Addr())
	step := uint32(1) << (32 - newPrefixLen)
	addr := uint32ToAddr(baseInt + uint32(index)*step)
	return netip.PrefixFrom(addr, newPrefixLen), nil
}

func addrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
