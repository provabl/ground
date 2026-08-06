// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package cfn provides helpers for building CloudFormation template documents.
// Templates are represented as plain Go maps and serialized to JSON for deployment.
package cfn

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/provabl/ground/internal/version"
)

// Template is a CloudFormation template document.
type Template struct {
	AWSTemplateFormatVersion string         `json:"AWSTemplateFormatVersion"`
	Description              string         `json:"Description"`
	Parameters               map[string]any `json:"Parameters,omitempty"`
	Resources                map[string]any `json:"Resources"`
	Outputs                  map[string]any `json:"Outputs,omitempty"`
}

// JSON serialises the template to a CloudFormation-compatible JSON string.
//
// It validates first, so a template CloudFormation would silently misinterpret
// never reaches a deployment. See [Template.Validate].
func (t *Template) JSON() (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Validate rejects templates CloudFormation would accept but misinterpret.
//
// The case it exists for: DependsOn is a *resource-level* attribute, a sibling of
// Type and Properties. Put inside Properties it is not a schema violation
// CloudFormation rejects — it simply is not read, so the declared ordering is
// silently ignored and the stack deploys in whatever order the implicit
// dependencies imply. Five of ground's resources shipped that way (#41), and
// nothing caught it because the deploy succeeded.
//
// So: a reserved resource-level key found inside Properties is an error, not a
// warning. Anything that can be wrong silently should be impossible instead.
func (t *Template) Validate() error {
	// The resource-level attributes worth guarding: each changes deploy behaviour
	// and each is silently inert inside Properties. Only the top level of
	// Properties is inspected — "Condition" nested inside an IAM policy statement
	// is a policy condition and entirely correct. If some resource type ever has a
	// legitimate top-level property with one of these names, remove it from this
	// list rather than working around the error.
	reserved := []string{"DependsOn", "Condition", "DeletionPolicy", "UpdateReplacePolicy", "Metadata"}

	for _, logicalID := range sortedKeys(t.Resources) {
		res, ok := t.Resources[logicalID].(map[string]any)
		if !ok {
			return fmt.Errorf("resource %s is not an object", logicalID)
		}
		props, ok := res["Properties"].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range reserved {
			if _, misplaced := props[key]; misplaced {
				return fmt.Errorf("resource %s: %q is inside Properties, where CloudFormation "+
					"ignores it — it is a resource-level attribute (a sibling of Type and Properties). "+
					"Use cfn.Resource(...) with cfn.DependsOn or set it on the resource entry directly",
					logicalID, key)
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Resource builds a CloudFormation resource entry.
func Resource(resourceType string, properties map[string]any) map[string]any {
	return map[string]any{
		"Type":       resourceType,
		"Properties": properties,
	}
}

// DependsOn sets a resource's explicit creation-order dependencies.
//
// It exists because the obvious-looking thing — adding "DependsOn" to the map
// passed to [Resource] — puts it inside Properties, where CloudFormation ignores
// it. Chain it onto Resource:
//
//	cfn.DependsOn(cfn.Resource("AWS::CloudTrail::Trail", props), "AuditBucketPolicy")
//
// A single dependency is rendered as a string and several as a list, matching
// what CloudFormation's own documentation shows.
func DependsOn(resource map[string]any, deps ...string) map[string]any {
	switch len(deps) {
	case 0:
		return resource
	case 1:
		resource["DependsOn"] = deps[0]
	default:
		resource["DependsOn"] = deps
	}
	return resource
}

// Tag builds a CloudFormation tag map.
func Tag(key, value string) map[string]string {
	return map[string]string{"Key": key, "Value": value}
}

// ManagedTags returns the tags every ground-created resource carries, plus any
// extra tags the caller supplies.
//
// It takes the extras rather than being appended to. The pattern it replaces —
// building a shared managedTags slice and calling append(managedTags, ...) per
// resource — is an aliasing bug waiting for someone to change the literal's
// length: once the shared slice has spare capacity, each append writes into the
// same backing array and the resources overwrite each other's tags. Passing the
// extras in means every call allocates its own.
//
// The version comes from [version.Version], not a literal. Two stacks used to
// hardcode it, both said 0.2.0 long after ground shipped 0.3.0, and every OU and
// permission set they created was tagged with a version that never deployed it
// (#42).
func ManagedTags(extra ...map[string]string) []map[string]string {
	tags := make([]map[string]string, 0, len(extra)+2)
	tags = append(tags,
		Tag("managed-by", "ground"),
		Tag("ground:version", version.Version),
	)
	return append(tags, extra...)
}
