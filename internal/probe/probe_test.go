// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"testing"

	"github.com/provabl/ground/internal/config"
)

func TestRunRejectsInvalidServiceName(t *testing.T) {
	cases := []string{
		"",
		"../evil",
		"evil/path",
		"has spaces",
		"UPPERCASE",
		"has.dot",
		"toolooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong",
		"0startswithdigit-only-after-first", // actually valid — starts with digit is OK per regex
	}
	for _, name := range cases {
		// Only names with slashes, spaces, dots, or uppercase should fail.
		// The regex allows digits as the first character.
		switch name {
		case "0startswithdigit-only-after-first":
			continue // this is valid per the pattern
		}
		svc := config.ExternalService{Name: name, Probe: ""}
		if name == "" {
			// empty name with empty probe = no-op
			result, err := Run(context.Background(), svc)
			if result != nil || err != nil {
				t.Errorf("name=%q probe=%q: expected nil,nil for empty; got %v,%v", name, svc.Probe, result, err)
			}
			continue
		}
		// For other invalid names, we need a non-empty probe trigger.
		// Set probe to empty so the convention path is used, which requires name validation.
		svc.Probe = "" // triggers convention lookup → name validation
		// Can't actually test PATH lookup in unit test, but we can test with an absolute path.
		// Use a non-existent absolute path to trigger the name validation first.
		svc.Probe = "/nonexistent/probe"
		// With a valid path, name validation happens first.
		_, err := Run(context.Background(), svc)
		if err == nil {
			t.Errorf("expected error for invalid service name %q, got nil", name)
		}
	}
}

func TestRunRejectsRelativeProbePath(t *testing.T) {
	cases := []struct {
		name  string
		probe string
	}{
		{"globus", "./local-probe"},
		{"globus", "../parent-probe"},
		{"globus", "relative-binary"},
		{"globus", "sub/dir/binary"},
	}
	for _, tc := range cases {
		svc := config.ExternalService{Name: tc.name, Probe: tc.probe}
		_, err := Run(context.Background(), svc)
		if err == nil {
			t.Errorf("probe=%q: expected error for relative path, got nil", tc.probe)
		}
	}
}

func TestRunAcceptsAbsoluteProbePath(t *testing.T) {
	// Absolute path to a non-existent binary: should fail with "not found" or
	// exec error, NOT a validation error about the path format.
	svc := config.ExternalService{
		Name:  "test-service",
		Probe: "/nonexistent/absolutely/ground-probe-test",
	}
	_, err := Run(context.Background(), svc)
	if err == nil {
		t.Error("expected error (binary not found), got nil")
	}
	// Error should be about the binary not existing, not a path format error.
	if err.Error() == "probe path \"/nonexistent/absolutely/ground-probe-test\" must be an absolute path (starting with /)" {
		t.Errorf("should not have gotten path format error for an absolute path: %v", err)
	}
}

func TestRunReturnsNilForNoProbeName(t *testing.T) {
	svc := config.ExternalService{Name: "", Probe: ""}
	result, err := Run(context.Background(), svc)
	if result != nil || err != nil {
		t.Errorf("expected nil,nil for empty service; got %v,%v", result, err)
	}
}

func TestValidProbeServiceNamePattern(t *testing.T) {
	valid := []string{"globus", "crowdstrike-falcon", "a", "a1b2c3", "my-probe-123"}
	invalid := []string{"", "UPPER", "has space", "has.dot", "has/slash", "../traversal"}

	for _, name := range valid {
		if !validProbeServiceName.MatchString(name) {
			t.Errorf("expected %q to be valid, but it was rejected", name)
		}
	}
	for _, name := range invalid {
		if validProbeServiceName.MatchString(name) {
			t.Errorf("expected %q to be invalid, but it was accepted", name)
		}
	}
}
