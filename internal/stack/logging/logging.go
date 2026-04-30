// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package logging defines the AWS logging foundation stack.
//
// Deploys: org-wide CloudTrail, VPC Flow Logs, AWS Config recorder,
// centralized S3 audit bucket with object-level logging.
package logging

import (
	"github.com/provabl/ground/internal/config"
)

// Stack holds the logging stack configuration.
type Stack struct {
	cfg *config.LoggingConfig
}

// New creates a logging stack.
func New(cfg *config.LoggingConfig) *Stack {
	return &Stack{cfg: cfg}
}
