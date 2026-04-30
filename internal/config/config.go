// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level ground configuration.
type Config struct {
	Org      OrgConfig      `yaml:"org"`
	Network  NetworkConfig  `yaml:"network"`
	Identity IdentityConfig `yaml:"identity"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
	Tagging  TaggingConfig  `yaml:"tagging"`
}

type OrgConfig struct {
	Name          string   `yaml:"name"`
	Region        string   `yaml:"region"`
	ManagementID  string   `yaml:"management_account_id"`
	AuditEmail    string   `yaml:"audit_email"`
	LoggingEmail  string   `yaml:"logging_email"`
	WorkloadOUs   []string `yaml:"workload_ous"`
}

type NetworkConfig struct {
	TransitGateway bool   `yaml:"transit_gateway"`
	CIDRBlock      string `yaml:"cidr_block"`
	VPCEndpoints   []string `yaml:"vpc_endpoints"`
}

type IdentityConfig struct {
	IdentityCenter bool   `yaml:"identity_center"`
	InstanceARN    string `yaml:"instance_arn,omitempty"`
}

type LoggingConfig struct {
	RetentionDays int    `yaml:"retention_days"`
	BucketName    string `yaml:"bucket_name,omitempty"`
}

type SecurityConfig struct {
	GuardDuty   bool `yaml:"guardduty"`
	SecurityHub bool `yaml:"security_hub"`
	Macie       bool `yaml:"macie"`
}

type TaggingConfig struct {
	RequiredTags []string `yaml:"required_tags"`
}

// Load reads and validates a ground configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 — operator-controlled config path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Org.Name == "" {
		return fmt.Errorf("org.name is required")
	}
	if c.Org.Region == "" {
		return fmt.Errorf("org.region is required")
	}
	if c.Org.ManagementID == "" {
		return fmt.Errorf("org.management_account_id is required")
	}
	if c.Logging.RetentionDays == 0 {
		c.Logging.RetentionDays = 365
	}
	return nil
}

// DefaultConfig returns a minimal valid configuration for reference.
func DefaultConfig() *Config {
	return &Config{
		Org: OrgConfig{
			Region:      "us-east-1",
			WorkloadOUs: []string{"research", "sandbox"},
		},
		Network: NetworkConfig{
			TransitGateway: true,
			CIDRBlock:      "10.0.0.0/8",
			VPCEndpoints: []string{
				"s3", "ec2", "sts", "ssm", "secretsmanager",
			},
		},
		Identity: IdentityConfig{
			IdentityCenter: true,
		},
		Logging: LoggingConfig{
			RetentionDays: 365,
		},
		Security: SecurityConfig{
			GuardDuty:   true,
			SecurityHub: true,
			Macie:       true,
		},
		Tagging: TaggingConfig{
			RequiredTags: []string{
				"project", "environment", "owner", "data-classification",
			},
		},
	}
}
