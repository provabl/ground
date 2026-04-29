package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy the AWS organization foundation",
		Long: `Deploy a correctly-configured AWS organization foundation.

Deploys account structure, network, identity, logging, and security baselines.
Makes zero compliance claims — run 'attest scan' after deployment for posture.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeploy(configPath, dryRun)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "ground.yaml", "path to ground configuration file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deployed without making changes")

	return cmd
}

func validateCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate ground configuration and policies",
		Long:  "Validate all configuration and run policy unit tests before deployment.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(configPath)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "ground.yaml", "path to ground configuration file")

	return cmd
}

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show deployment status of the AWS organization foundation",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}

	return cmd
}

func runDeploy(configPath string, dryRun bool) error {
	fmt.Fprintf(os.Stderr, "ground v%s\n\n", version)

	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if dryRun {
		fmt.Println("Dry run — no changes will be made.")
		fmt.Printf("Would deploy foundation for organization: %s\n", cfg.Org.Name)
		fmt.Printf("  Region:   %s\n", cfg.Org.Region)
		fmt.Printf("  Layers:   accounts, network, identity, logging, security\n")
		return nil
	}

	fmt.Printf("Deploying foundation for organization: %s\n", cfg.Org.Name)
	fmt.Println("NOTE: Implementation pending — CDK stacks under construction.")
	return nil
}

func runValidate(configPath string) error {
	_, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Println("Configuration valid.")
	fmt.Println("Policy unit tests: run 'go test ./policies/...' to validate all policies.")
	return nil
}

func runStatus() error {
	fmt.Println("Status check requires AWS credentials.")
	fmt.Println("Implementation pending.")
	return nil
}
