// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package probe implements the ground-probe-* binary interface for verifying
// external service declarations in ground.yaml.
//
// A probe is an external binary (e.g., ground-probe-globus) that queries a
// service's own API to verify that the features declared in ground.yaml are
// actually enabled. Probes are optional — if no probe is configured, ground
// uses the declared features as-is.
//
// Binary contract:
//   - Binary name: ground-probe-<service> (must be in PATH, or an absolute path)
//   - Stdin: probe_config from ground.yaml, JSON-encoded
//   - Stdout: ProbeResult, JSON-encoded
//   - Exit 0: all declared features verified
//   - Exit 1: partial — some features could not be verified
//   - Exit 2: error — probe failed (network unreachable, auth error, etc.)
//
// If a probe exits non-zero, ground falls back to the declaration and records
// the verification status in ground-meta.json.
//
// Security note on probe paths:
//   - svc.Name must match ^[a-z0-9][a-z0-9-]{0,62}$ — prevents path components
//     from being injected into the convention binary name.
//   - svc.Probe must be an absolute path (starts with /) or empty.
//     Relative paths are rejected outright. Empty uses the convention name
//     "ground-probe-<svc.Name>" resolved via PATH.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/provabl/ground/internal/config"
)

// validProbeServiceName restricts service names used to construct the convention
// binary name "ground-probe-<name>". Allows lowercase alphanumeric and hyphens only,
// preventing path traversal via embedded slashes or shell metacharacters.
var validProbeServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ProbeResult is the JSON structure written by a probe binary to stdout.
type ProbeResult struct {
	Service            string         `json:"service"`
	ProbedAt           time.Time      `json:"probed_at"`
	FeaturesVerified   []string       `json:"features_verified,omitempty"`
	FeaturesUnverified []string       `json:"features_unverified,omitempty"`
	Details            map[string]any `json:"details,omitempty"` // service-specific discovery data
	Error              string         `json:"error,omitempty"`   // set if probe failed non-fatally
}

// Run invokes the probe binary for the given service and returns the result.
// Returns nil if the service has no probe configured.
// Returns an error only for hard failures (binary not found, JSON decode error).
// Partial verification (exit 1) is returned as a ProbeResult with FeaturesUnverified populated.
func Run(ctx context.Context, svc config.ExternalService) (*ProbeResult, error) {
	if svc.Probe == "" && svc.Name == "" {
		return nil, nil
	}

	// Validate service name before using it to construct the convention binary name.
	if !validProbeServiceName.MatchString(svc.Name) {
		return nil, fmt.Errorf("probe: service name %q must be lowercase alphanumeric + hyphens (got invalid characters)", svc.Name)
	}

	var binary string

	if svc.Probe == "" {
		// No explicit probe path — use the convention name via PATH.
		convention := "ground-probe-" + svc.Name
		resolved, err := exec.LookPath(convention)
		if err != nil {
			return nil, fmt.Errorf("probe binary %s not found in PATH", convention)
		}
		binary = resolved
	} else {
		// Explicit probe path must be absolute. Relative paths are rejected to
		// prevent execution of unintended binaries from the current directory or
		// PATH lookup of arbitrary operator-supplied strings.
		if !strings.HasPrefix(svc.Probe, "/") {
			return nil, fmt.Errorf("probe path %q must be an absolute path (starting with /) — "+
				"use an empty probe field to use the ground-probe-%s convention via PATH",
				svc.Probe, svc.Name)
		}
		binary = svc.Probe
	}

	configJSON, err := json.Marshal(svc.ProbeConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal probe config: %w", err)
	}

	cmd := exec.CommandContext(ctx, binary) // #nosec G204 — validated: absolute path or PATH-resolved convention binary
	cmd.Stdin = bytes.NewReader(configJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	var result ProbeResult
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("probe %s failed (exit %v): %s", svc.Name, runErr, stderr.String())
		}
		return nil, fmt.Errorf("decode probe output for %s: %w", svc.Name, decodeErr)
	}

	// Exit 1 = partial — return result with whatever was verified.
	// Exit 2 = hard error — result.Error will be set by the probe.
	return &result, nil
}

// RunAll invokes probes for all external services that have one configured.
// Services without a probe are returned with a nil ProbeResult.
// Never returns an error — probe failures are recorded in the result's Error field.
func RunAll(ctx context.Context, services []config.ExternalService) map[string]*ProbeResult {
	results := make(map[string]*ProbeResult, len(services))
	for _, svc := range services {
		if svc.Probe == "" {
			results[svc.Name] = nil
			continue
		}
		result, err := Run(ctx, svc)
		if err != nil {
			results[svc.Name] = &ProbeResult{
				Service:  svc.Name,
				ProbedAt: time.Now(),
				Error:    err.Error(),
			}
			continue
		}
		results[svc.Name] = result
	}
	return results
}
