// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package cfn provides helpers for building CloudFormation template documents.
// Templates are represented as plain Go maps and serialized to JSON for deployment.
package cfn

import "encoding/json"

// Template is a CloudFormation template document.
type Template struct {
	AWSTemplateFormatVersion string         `json:"AWSTemplateFormatVersion"`
	Description              string         `json:"Description"`
	Parameters               map[string]any `json:"Parameters,omitempty"`
	Resources                map[string]any `json:"Resources"`
	Outputs                  map[string]any `json:"Outputs,omitempty"`
}

// JSON serialises the template to a CloudFormation-compatible JSON string.
func (t *Template) JSON() (string, error) {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Resource builds a CloudFormation resource entry.
func Resource(resourceType string, properties map[string]any) map[string]any {
	return map[string]any{
		"Type":       resourceType,
		"Properties": properties,
	}
}

// Tag builds a CloudFormation tag map.
func Tag(key, value string) map[string]string {
	return map[string]string{"Key": key, "Value": value}
}
