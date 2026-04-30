// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package deploy provides a CloudFormation deployer for ground stacks.
// It creates or updates stacks and polls until the operation completes.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// Deployer deploys CloudFormation stacks for ground.
type Deployer struct {
	cf     *cloudformation.Client
	region string
}

// New creates a Deployer using the default AWS credential chain.
func New(ctx context.Context, region string) (*Deployer, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Deployer{
		cf:     cloudformation.NewFromConfig(cfg),
		region: region,
	}, nil
}

// StackResult describes the outcome of a Deploy call.
type StackResult struct {
	StackName string
	StackID   string
	Status    string
	Created   bool // true = new stack; false = updated existing
}

// Deploy creates or updates a CloudFormation stack with the given template JSON.
// It blocks until the stack reaches a terminal state (complete or failed).
func (d *Deployer) Deploy(ctx context.Context, stackName, templateBody string) (*StackResult, error) {
	existing, err := d.describe(ctx, stackName)
	if err != nil && !isNotFound(err) {
		return nil, fmt.Errorf("describe stack %s: %w", stackName, err)
	}

	var stackID string
	created := false

	if existing == nil {
		// Create new stack.
		out, createErr := d.cf.CreateStack(ctx, &cloudformation.CreateStackInput{
			StackName:    aws.String(stackName),
			TemplateBody: aws.String(templateBody),
			Capabilities: []cftypes.Capability{
				cftypes.CapabilityCapabilityIam,
				cftypes.CapabilityCapabilityNamedIam,
			},
			Tags: []cftypes.Tag{
				{Key: aws.String("managed-by"), Value: aws.String("ground")},
				{Key: aws.String("ground:version"), Value: aws.String("0.1.0")},
			},
		})
		if createErr != nil {
			return nil, fmt.Errorf("create stack %s: %w", stackName, createErr)
		}
		stackID = aws.ToString(out.StackId)
		created = true
	} else {
		// Update existing stack.
		_, updateErr := d.cf.UpdateStack(ctx, &cloudformation.UpdateStackInput{
			StackName:    aws.String(stackName),
			TemplateBody: aws.String(templateBody),
			Capabilities: []cftypes.Capability{
				cftypes.CapabilityCapabilityIam,
				cftypes.CapabilityCapabilityNamedIam,
			},
		})
		if updateErr != nil {
			// "No updates are to be performed" is not an error — the stack is already current.
			if isNoUpdates(updateErr) {
				return &StackResult{
					StackName: stackName,
					StackID:   aws.ToString(existing.StackId),
					Status:    string(existing.StackStatus),
					Created:   false,
				}, nil
			}
			return nil, fmt.Errorf("update stack %s: %w", stackName, updateErr)
		}
		stackID = aws.ToString(existing.StackId)
	}

	// Poll until terminal state.
	finalStatus, pollErr := d.poll(ctx, stackName)
	if pollErr != nil {
		return nil, fmt.Errorf("stack %s: %w", stackName, pollErr)
	}

	return &StackResult{
		StackName: stackName,
		StackID:   stackID,
		Status:    finalStatus,
		Created:   created,
	}, nil
}

// Status returns the current status of a CloudFormation stack, or "NOT_FOUND".
func (d *Deployer) Status(ctx context.Context, stackName string) (string, error) {
	stack, err := d.describe(ctx, stackName)
	if err != nil {
		if isNotFound(err) {
			return "NOT_FOUND", nil
		}
		return "", fmt.Errorf("describe %s: %w", stackName, err)
	}
	return string(stack.StackStatus), nil
}

// --- internal helpers ---------------------------------------------------------

func (d *Deployer) describe(ctx context.Context, stackName string) (*cftypes.Stack, error) {
	out, err := d.cf.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Stacks) == 0 {
		return nil, nil
	}
	return &out.Stacks[0], nil
}

// poll waits for the stack to reach a terminal CloudFormation state.
func (d *Deployer) poll(ctx context.Context, stackName string) (string, error) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			stack, err := d.describe(ctx, stackName)
			if err != nil {
				return "", err
			}
			if stack == nil {
				return "DELETED", nil
			}
			status := string(stack.StackStatus)
			if isTerminal(status) {
				if isFailure(status) {
					reason := aws.ToString(stack.StackStatusReason)
					return status, fmt.Errorf("stack reached %s: %s", status, reason)
				}
				return status, nil
			}
		}
	}
}

func isTerminal(status string) bool {
	switch cftypes.StackStatus(status) {
	case cftypes.StackStatusCreateComplete,
		cftypes.StackStatusCreateFailed,
		cftypes.StackStatusUpdateComplete,
		cftypes.StackStatusUpdateFailed,
		cftypes.StackStatusUpdateRollbackComplete,
		cftypes.StackStatusUpdateRollbackFailed,
		cftypes.StackStatusRollbackComplete,
		cftypes.StackStatusRollbackFailed,
		cftypes.StackStatusDeleteComplete,
		cftypes.StackStatusDeleteFailed:
		return true
	}
	return false
}

func isFailure(status string) bool {
	switch cftypes.StackStatus(status) {
	case cftypes.StackStatusCreateFailed,
		cftypes.StackStatusUpdateFailed,
		cftypes.StackStatusUpdateRollbackFailed,
		cftypes.StackStatusRollbackFailed,
		cftypes.StackStatusDeleteFailed:
		return true
	}
	return false
}

func isNotFound(err error) bool {
	var ae interface{ ErrorCode() string }
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "ValidationError"
	}
	return false
}

func isNoUpdates(err error) bool {
	return err != nil && fmt.Sprintf("%v", err) == "ValidationError: No updates are to be performed."
}
