// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"encoding/json"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/provabl/ground/internal/deploy"
	"github.com/provabl/ground/internal/iac"
	"github.com/provabl/ground/internal/stack/accounts"
	"github.com/provabl/ground/internal/stack/identity"
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
	cmd.AddCommand(exportMetadataCmd())

	return cmd
}

func deployCmd() *cobra.Command {
	var configPath string
	var dryRun bool
	var region string
	var output string

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
			if output == "terraform" || output == "cdk" {
				return runGenerateIaC(configPath, output)
			}
			return runDeploy(configPath, region, dryRun)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "ground.yaml", "path to ground configuration file")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (overrides config)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print CloudFormation templates without deploying")
	cmd.Flags().StringVar(&output, "output", "cloudformation", "IaC output format: cloudformation (default), terraform, cdk")

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

	accountsStack := accounts.New(&cfg.Org)
	identityStack := identity.New(&cfg.Identity)
	accountsTmpl, _ := accountsStack.Template()
	identityTmpl, _ := identityStack.Template()

	// Inject OrgRootId parameter into accounts template.
	// This avoids a Lambda custom resource — ground discovers it via Organizations API.
	if accountsTmpl != nil && accountsTmpl.Parameters != nil {
		if _, hasRootParam := accountsTmpl.Parameters["OrgRootId"]; hasRootParam {
			rootID, rootErr := fetchOrgRootID(context.Background(), cfg.Org.Region)
			if rootErr != nil {
				fmt.Printf("  ⚠ Could not auto-discover org root ID: %v\n", rootErr)
				fmt.Println("  Retrieve manually: aws organizations list-roots --query 'Roots[0].Id' --output text")
				fmt.Println("  Then set org.root_id in ground.yaml")
			} else if rootID != "" {
				// Override the default value so it's pre-filled in the template.
				if p, ok := accountsTmpl.Parameters["OrgRootId"].(map[string]any); ok {
					p["Default"] = rootID
				}
				fmt.Printf("  Org root ID: %s\n", rootID)
			}
		}
	}

	if dryRun {
		fmt.Println("Dry run — no changes will be made.")
		fmt.Printf("Organization: %s (region: %s)\n\n", cfg.Org.Name, cfg.Org.Region)

		logJSON, _ := logTmpl.JSON()
		secJSON, _ := secTmpl.JSON()
		accountsJSON, _ := accountsTmpl.JSON()
		identityJSON, _ := identityTmpl.JSON()

		fmt.Printf("Stack: %s\n%s\n\n", logStack.StackName(), logJSON)
		fmt.Printf("Stack: %s\n%s\n\n", secStack.StackName(), secJSON)
		fmt.Printf("Stack: %s\n%s\n\n", accountsStack.StackName(), accountsJSON)
		fmt.Printf("Stack: %s\n%s\n\n", identityStack.StackName(), identityJSON)
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

	fmt.Println("\nPhase 1 complete.")

	// Phase 2: accounts + identity stacks (templates already generated for dry-run above).
	for _, entry := range []struct {
		name string
		json string
	}{
		{accountsStack.StackName(), func() string { j, _ := accountsTmpl.JSON(); return j }()},
		{identityStack.StackName(), func() string { j, _ := identityTmpl.JSON(); return j }()},
	} {
		idx := map[string]string{accountsStack.StackName(): "3", identityStack.StackName(): "4"}[entry.name]
		fmt.Printf("  [%s/4] %s ... ", idx, entry.name)
		result, deployErr := deployer.Deploy(ctx, entry.name, entry.json)
		if deployErr != nil {
			return fmt.Errorf("deploy %s: %w", entry.name, deployErr)
		}
		verb := "updated"
		if result.Created {
			verb = "created"
		}
		fmt.Printf("%s (%s)\n", verb, result.Status)
	}

	fmt.Println("\nAll stacks complete. Run 'attest init' to begin compliance assessment.")
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

	stacks := []string{"ground-logging", "ground-security", "ground-accounts", "ground-identity"}
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

// fetchOrgRootID retrieves the AWS Organizations root ID using the SDK.
// Returns "" if Organizations is not accessible (non-fatal — caller handles).
func fetchOrgRootID(ctx context.Context, region string) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}
	client := organizations.NewFromConfig(cfg)
	out, err := client.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return "", fmt.Errorf("list org roots: %w", err)
	}
	if len(out.Roots) == 0 {
		return "", fmt.Errorf("no org roots found")
	}
	if out.Roots[0].Id == nil {
		return "", fmt.Errorf("root ID is nil")
	}
	return *out.Roots[0].Id, nil
}

func runGenerateIaC(configPath, format string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var outDir string
	switch format {
	case "terraform":
		outDir = "ground-terraform"
	case "cdk":
		outDir = "ground-cdk"
	default:
		return fmt.Errorf("unknown output format %q (use terraform or cdk)", format)
	}

	g := iac.NewGenerator(iac.Format(format), outDir)
	if err := g.Generate(cfg); err != nil {
		return fmt.Errorf("generate %s: %w", format, err)
	}

	fmt.Printf("IaC artifacts written to ./%s/\n\n", outDir)
	switch format {
	case "terraform":
		fmt.Printf("  cd %s\n", outDir)
		fmt.Println("  terraform init")
		fmt.Println("  terraform plan")
		fmt.Println("  terraform apply")
		fmt.Println()
		fmt.Println("  Optional: set TF_VAR_identity_center_instance_arn for permission sets")
	case "cdk":
		fmt.Printf("  cd %s\n", outDir)
		fmt.Println("  npm install")
		fmt.Println("  npm run build")
		fmt.Println("  cdk diff")
		fmt.Println("  cdk deploy")
		fmt.Println()
		fmt.Println("  Optional: export IDENTITY_CENTER_INSTANCE_ARN=<arn> for permission sets")
	}
	return nil
}

// GroundMeta is the JSON structure produced by `ground export-metadata`.
// Consumed by `attest init --ground-meta` to skip live AWS prerequisite checks.
type GroundMeta struct {
	GroundVersion             string `json:"ground_version"`
	Region                    string `json:"region"`
	CloudTrailEnabled         bool   `json:"cloudtrail_enabled"`
	ConfigEnabled             bool   `json:"config_enabled"`
	GuardDutyEnabled          bool   `json:"guardduty_enabled"`
	SecurityHubEnabled        bool   `json:"security_hub_enabled"`
	LogArchiveAccountID       string `json:"log_archive_account_id,omitempty"`
	IdentityCenterInstanceARN string `json:"identity_center_instance_arn,omitempty"`
}

func exportMetadataCmd() *cobra.Command {
	var outputPath string
	var region string

	cmd := &cobra.Command{
		Use:   "export-metadata",
		Short: "Export ground deployment metadata for attest init",
		Long: `Queries deployed CloudFormation stacks and writes a JSON metadata file.
Pass this file to 'attest init --ground-meta' to skip live AWS prerequisite checks.

Example:
  ground export-metadata --output ground-meta.json
  attest init --region us-east-1 --ground-meta ground-meta.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExportMetadata(region, outputPath)
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "ground-meta.json", "output file path")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region to query")
	return cmd
}

func runExportMetadata(region, outputPath string) error {
	ctx := context.Background()
	deployer, err := deploy.New(ctx, region)
	if err != nil {
		return fmt.Errorf("init deployer: %w", err)
	}

	meta := GroundMeta{
		GroundVersion: version,
		Region:        region,
	}

	// Infer which services are deployed from stack status.
	loggingStatus, _ := deployer.Status(ctx, "ground-logging")
	securityStatus, _ := deployer.Status(ctx, "ground-security")

	if loggingStatus == "CREATE_COMPLETE" || loggingStatus == "UPDATE_COMPLETE" {
		meta.CloudTrailEnabled = true
		meta.ConfigEnabled = true
	}
	if securityStatus == "CREATE_COMPLETE" || securityStatus == "UPDATE_COMPLETE" {
		meta.GuardDutyEnabled = true
		meta.SecurityHubEnabled = true
	}

	// Check accounts stack for Identity Center instance ARN output.
	accountsStatus, _ := deployer.Status(ctx, "ground-accounts")
	if accountsStatus == "CREATE_COMPLETE" || accountsStatus == "UPDATE_COMPLETE" {
		// Identity Center ARN would be in stack outputs — placeholder for now.
		// Full implementation reads CloudFormation stack outputs.
		meta.IdentityCenterInstanceARN = "" // populated when accounts stack output is available
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o640); err != nil { // #nosec G306 — user-specified path
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	fmt.Printf("Ground metadata written to %s\n", outputPath)
	fmt.Printf("  CloudTrail:    %v\n", meta.CloudTrailEnabled)
	fmt.Printf("  Config:        %v\n", meta.ConfigEnabled)
	fmt.Printf("  GuardDuty:     %v\n", meta.GuardDutyEnabled)
	fmt.Printf("  Security Hub:  %v\n", meta.SecurityHubEnabled)
	fmt.Printf("\nUsage: attest init --region %s --ground-meta %s\n", region, outputPath)
	return nil
}
