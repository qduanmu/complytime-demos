package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	// Flags for policy conversion
	outputFile        string
	catalogPath       string
	scopeFilters      bool
	policySet         bool
	policySetName     string
	policySetDesc     string
	policySetVersion  string
	workspacePath     string
	forceOverwrite    bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "ampel_export <policy.yaml>",
	Short:   "Convert Gemara policies to Ampel verification policies",
	Version: "1.0.0",
	Long: `ampel_export converts Gemara Layer-3 policies to Ampel verification policy format.

Ampel policies use CEL (Common Expression Language) to verify attestations
in the in-toto format, ensuring supply chain security requirements are met.`,
	Example: `  # Generate a single Ampel policy (output: my-policy.json)
  ampel_export my-policy.yaml

  # Generate with custom output file
  ampel_export policy.yaml -o custom-name.json --catalog catalog.yaml

  # Generate a PolicySet
  ampel_export policy.yaml --policyset

  # Workspace mode: preserve manual CEL edits on regeneration
  ampel_export policy.yaml -w ./policies

  # Force regeneration, discarding manual changes
  ampel_export policy.yaml -w ./policies --force-overwrite`,
	Args: cobra.ExactArgs(1),
	RunE: runConvert,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Output and workspace flags
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path (default: input filename with .json extension)")
	rootCmd.Flags().StringVarP(&workspacePath, "workspace", "w", "", "workspace directory for policy management with merge support")
	rootCmd.Flags().BoolVar(&forceOverwrite, "force-overwrite", false, "force regeneration, discard manual changes (use with -w)")

	// Catalog and options
	rootCmd.Flags().StringVarP(&catalogPath, "catalog", "c", "", "catalog file path for enriching policy details")
	rootCmd.Flags().BoolVar(&scopeFilters, "scope-filters", false, "include scope-based CEL filters in tenets")

	// PolicySet flags
	rootCmd.Flags().BoolVar(&policySet, "policyset", false, "generate a PolicySet with imports as external references")
	rootCmd.Flags().StringVar(&policySetName, "policyset-name", "", "name for the PolicySet (only used with --policyset)")
	rootCmd.Flags().StringVar(&policySetDesc, "policyset-description", "", "description for the PolicySet (only used with --policyset)")
	rootCmd.Flags().StringVar(&policySetVersion, "policyset-version", "", "version for the PolicySet (only used with --policyset)")
}

func runConvert(cmd *cobra.Command, args []string) error {
	policyPath := args[0]

	// Import the export package functionality
	// We'll call the actual conversion logic here
	return convertPolicy(policyPath)
}
