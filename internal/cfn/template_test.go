// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cfn

import (
	"encoding/json"
	"strings"
	"testing"
)

// DependsOn is a resource-level attribute. Inside Properties it is not a schema
// violation CloudFormation rejects — it simply is not read, so the declared
// ordering is silently ignored and the stack still deploys. Five of ground's
// resources shipped that way and nothing caught it (#41), which is exactly why
// this is an error rather than a lint warning.
func TestValidate_RejectsResourceAttributesInsideProperties(t *testing.T) {
	for _, key := range []string{"DependsOn", "Condition", "DeletionPolicy", "UpdateReplacePolicy", "Metadata"} {
		t.Run(key, func(t *testing.T) {
			tmpl := &Template{Resources: map[string]any{
				"Trail": Resource("AWS::CloudTrail::Trail", map[string]any{
					"TrailName": "t",
					key:         "AuditBucketPolicy",
				}),
			}}
			err := tmpl.Validate()
			if err == nil {
				t.Fatalf("%q inside Properties must be an error — CloudFormation ignores it there", key)
			}
			// The error has to name the resource and the key, or it sends the reader
			// hunting through a template.
			for _, want := range []string{"Trail", key} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should mention %q, got %q", want, err)
				}
			}
		})
	}
}

// The guard must not fire on the correct placement, or it would make the right
// thing impossible.
func TestValidate_AcceptsResourceLevelDependsOn(t *testing.T) {
	tmpl := &Template{Resources: map[string]any{
		"Trail": DependsOn(Resource("AWS::CloudTrail::Trail", map[string]any{"TrailName": "t"}), "AuditBucketPolicy"),
	}}
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("resource-level DependsOn must be accepted: %v", err)
	}
}

// A misplaced attribute must not be able to reach a deployment, so JSON — the
// only path to CloudFormation — validates rather than leaving it to a caller who
// might forget.
func TestJSON_ValidatesBeforeSerialising(t *testing.T) {
	tmpl := &Template{Resources: map[string]any{
		"Trail": Resource("AWS::CloudTrail::Trail", map[string]any{"DependsOn": "Other"}),
	}}
	if _, err := tmpl.JSON(); err == nil {
		t.Fatal("JSON must refuse a template CloudFormation would misinterpret")
	}
}

// DependsOn renders a single dependency as a string and several as a list, which
// is what CloudFormation's documentation shows and what its own console emits.
func TestDependsOn_Shape(t *testing.T) {
	one := DependsOn(Resource("AWS::S3::Bucket", map[string]any{}), "A")
	if got := one["DependsOn"]; got != "A" {
		t.Errorf("single dependency should render as a string, got %#v", got)
	}

	many := DependsOn(Resource("AWS::S3::Bucket", map[string]any{}), "A", "B")
	got, ok := many["DependsOn"].([]string)
	if !ok || len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("multiple dependencies should render as a list, got %#v", many["DependsOn"])
	}

	// No dependencies must not leave an empty key behind: CloudFormation rejects
	// DependsOn with an empty value.
	none := DependsOn(Resource("AWS::S3::Bucket", map[string]any{}))
	if _, present := none["DependsOn"]; present {
		t.Error("DependsOn with no arguments should not set the key at all")
	}

	// And it lands as a sibling of Type/Properties, not inside Properties.
	props, _ := one["Properties"].(map[string]any)
	if _, misplaced := props["DependsOn"]; misplaced {
		t.Error("DependsOn must not be written into Properties")
	}
}

// The serialised shape is the contract with CloudFormation; assert the attribute
// actually appears at the resource level in the JSON, not just in the Go map.
func TestJSON_DependsOnIsAResourceLevelKey(t *testing.T) {
	tmpl := &Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Resources: map[string]any{
			"Trail": DependsOn(Resource("AWS::CloudTrail::Trail", map[string]any{"TrailName": "t"}), "Policy"),
		},
	}
	out, err := tmpl.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var doc struct {
		Resources map[string]struct {
			Type       string         `json:"Type"`
			Properties map[string]any `json:"Properties"`
			DependsOn  any            `json:"DependsOn"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	trail := doc.Resources["Trail"]
	if trail.DependsOn != "Policy" {
		t.Errorf("DependsOn should be a resource-level key, got %#v", trail.DependsOn)
	}
	if _, misplaced := trail.Properties["DependsOn"]; misplaced {
		t.Error("DependsOn leaked into Properties in the serialised template")
	}
}

func TestValidate_RejectsNonObjectResource(t *testing.T) {
	tmpl := &Template{Resources: map[string]any{"Bad": "not an object"}}
	if err := tmpl.Validate(); err == nil {
		t.Error("a non-object resource entry should be an error")
	}
}

func TestTag(t *testing.T) {
	if got := Tag("k", "v"); got["Key"] != "k" || got["Value"] != "v" {
		t.Errorf("Tag(k, v) = %#v", got)
	}
}
