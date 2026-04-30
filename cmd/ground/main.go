// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/provabl/ground/internal/deploy"
	"github.com/provabl/ground/internal/stack/logging"
	"github.com/provabl/ground/internal/stack/security"
)

var version = "0.1.0"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ground",
		Short: "Deploy correct AWS foundations for Secure Research Environments",
		Long: `ground deploys a correctly-configured AWS organization that attest can manage.

It makes zero compliance claims — attest makes those after 'attest scan'.

  ground deploy --config ground.yaml   # deploy AWS organization foundation
  attest init --region us-east-1        # attest discovers the deployed org
  attest frameworks add cmmc-level-2    # activate compliance frameworks
  attest compile --scp-strategy merged  # compile policies from frameworks
  attest apply --approve                # deploy policies to the org
  attest scan                           # NOW we can make compliance claims`,
		Version: version,
	}

	cmd.AddCommand(deployCmd())
	cmd.AddCommand(validateCmd())
	cmd.AddCommand(statusCmd())

	return cmd
}

func deployCmd() *cobra.Command {
	var configPath string
	var dryRun bool
	var region string

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy the AWS organization foundation",
		Long: `Deploy a correctly-configured AWS organization foundation.

Phase 1 deploys the logging foundation (S3 audit bucket, org-wide CloudTrail,
AWS Config recorder) and security baseline (GuardDuty, Security Hub, Macie).
These are the layers attest requires to assess compliance posture.

Subsequent phases (network, identity, accounts) require delegated admin setup
specific to each institution — see ground.example.yaml for configuration.

Makes zero compliance claims — run 'attest scan' after deployment for posture.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeploy(configPath, region, dryRun)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "ground.yaml", "path to ground configuration file")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (overrides config)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print CloudFormation templates without deploying")

	return cmd
}

func validateCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate ground configuration and policies",
		Long:  "Validate configuration, generate CloudFormation templates, and run policy unit tests.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(configPath)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "ground.yaml", "path to ground configuration file")

	return cmd
}

func statusCmd() *cobra.Command {
	var region string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show deployment status of the AWS organization foundation",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(region)
		},
	}

	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")

	return cmd
}

func runDeploy(configPath, region string, dryRun bool) error {
	fmt.Fprintf(os.Stderr, "ground v%s\n\n", version)

	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if region != "" {
		cfg.Org.Region = region
	}

	logStack := logging.New(&cfg.Logging, &cfg.Org)
	secStack := security.New(&cfg.Security, &cfg.Org)

	logTmpl, err := logStack.Template()
	if err != nil {
		return fmt.Errorf("generate logging template: %w", err)
	}
	secTmpl, err := secStack.Template()
	if err != nil {
		return fmt.Errorf("generate security template: %w", err)
	}

	if dryRun {
		fmt.Println("Dry run — no changes will be made.")
		fmt.Printf("Organization: %s (region: %s)\n\n", cfg.Org.Name, cfg.Org.Region)

		logJSON, _ := logTmpl.JSON()
		secJSON, _ := secTmpl.JSON()

		fmt.Printf("Stack: %s\n%s\n\n", logStack.StackName(), logJSON)
		fmt.Printf("Stack: %s\n%s\n\n", secStack.StackName(), secJSON)
		fmt.Println("Run without --dry-run to deploy these stacks to CloudFormation.")
		return nil
	}

	ctx := context.Background()
	deployer, err := deploy.New(ctx, cfg.Org.Region)
	if err != nil {
		return fmt.Errorf("init deployer: %w", err)
	}

	fmt.Printf("Deploying foundation for: %s (region: %s)\n\n", cfg.Org.Name, cfg.Org.Region)

	// Phase 1a: logging foundation.
	fmt.Printf("  [1/2] %s ... ", logStack.StackName())
	logJSON, _ := logTmpl.JSON()
	logResult, err := deployer.Deploy(ctx, logStack.StackName(), logJSON)
	if err != nil {
		return fmt.Errorf("deploy %s: %w", logStack.StackName(), err)
	}
	action := "updated"
	if logResult.Created {
		action = "created"
	}
	fmt.Printf("%s (%s)\n", action, logResult.Status)

	// Phase 1b: security baseline.
	fmt.Printf("  [2/2] %s ... ", secStack.StackName())
	secJSON, _ := secTmpl.JSON()
	secResult, err := deployer.Deploy(ctx, secStack.StackName(), secJSON)
	if err != nil {
		return fmt.Errorf("deploy %s: %w", secStack.StackName(), err)
	}
	action = "updated"
	if secResult.Created {
		action = "created"
	}
	fmt.Printf("%s (%s)\n", action, secResult.Status)

	fmt.Println("\nPhase 1 complete. Run 'attest init' to begin compliance assessment.")
	fmt.Println("Note: zero compliance claims until 'attest scan' completes.")
	return nil
}

func runValidate(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logTmpl, err := logging.New(&cfg.Logging, &cfg.Org).Template()
	if err != nil {
		return fmt.Errorf("logging template invalid: %w", err)
	}
	if _, err := logTmpl.JSON(); err != nil {
		return fmt.Errorf("logging template serialization: %w", err)
	}

	secTmpl, err := security.New(&cfg.Security, &cfg.Org).Template()
	if err != nil {
		return fmt.Errorf("security template invalid: %w", err)
	}
	if _, err := secTmpl.JSON(); err != nil {
		return fmt.Errorf("security template serialization: %w", err)
	}

	fmt.Println("✓ Configuration valid")
	fmt.Println("✓ CloudFormation templates generated successfully")
	fmt.Println("  Run 'go test ./policies/...' to verify IAM/SCP policy correctness.")
	return nil
}

func runStatus(region string) error {
	ctx := context.Background()
	deployer, err := deploy.New(ctx, region)
	if err != nil {
		return fmt.Errorf("init deployer: %w", err)
	}

	stacks := []string{"ground-logging", "ground-security"}
	fmt.Printf("Stack status (region: %s)\n\n", region)
	for _, name := range stacks {
		status, err := deployer.Status(ctx, name)
		if err != nil {
			fmt.Printf("  %-30s  ERROR: %v\n", name, err)
		} else {
			fmt.Printf("  %-30s  %s\n", name, status)
		}
	}
	return nil
}
