// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package main is the entry point for the application

package main

import (
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cybrota/scharf/logging"
	nw "github.com/cybrota/scharf/network"
	sc "github.com/cybrota/scharf/scanner"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

const asciiLogo = `
_______ _______ _     _ _______  ______ _______
|______ |       |_____| |_____| |_____/ |______
______| |_____  |     | |     | |    \_ |

Prevent supply-chain attacks from your third-party GitHub actions!

Copyright (c) 2025 Naren Yellavula & Cybrota contributors - https://github.com/cybrota
`

var logger = logging.GetLogger(0)

var auditRepository = sc.AuditRepositoryResult
var findRepositories = sc.FindStructured
var upgradePinnedSHAs = sc.UpgradePinnedSHAs

const defaultUpgradeCooldownHours = 24

//go:embed version.json
var versionJSON []byte

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func cliVersion() string {
	info := versionInfo{
		Version: "dev",
		Commit:  "unknown",
		Date:    "unknown",
	}
	if err := json.Unmarshal(versionJSON, &info); err != nil {
		return "version: dev (commit: unknown, built: unknown)"
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return fmt.Sprintf("version: %s (commit: %s, built: %s)", info.Version, info.Commit, info.Date)
}

var actionSHAInputRegex = regexp.MustCompile(`^[\w.-]+/[\w.-]+@[a-f0-9]{40}$`)

func isSHAUpgradeInput(input string) bool {
	return actionSHAInputRegex.MatchString(input)
}

func splitActionRef(input string) (string, string, error) {
	parts := strings.SplitN(input, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid action format: %s. expected owner/repo@ref-or-sha", input)
	}

	return parts[0], parts[1], nil
}

func validateUpgradeInput(input string, fromVersion string) error {
	if _, _, err := splitActionRef(input); err != nil {
		return err
	}

	if isSHAUpgradeInput(input) && strings.TrimSpace(fromVersion) == "" {
		return fmt.Errorf("input %q looks like a pinned SHA; please provide --from-version to resolve the next upgrade", input)
	}

	return nil
}

func addSharedUpgradeFlags(cmd *cobra.Command) {
	cmd.Flags().Int("cooldown-hours", defaultUpgradeCooldownHours, "Warn when next version is under cooldown age in hours")
	cmd.Flags().Bool("dry-run", false, "Preview changes without writing files")
}

func writeToJSON(inv *sc.InventoryResult) error {
	f, err := os.Create("findings.json")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", " ")
	return enc.Encode(inv)
}

func WriteToCSV(inv *sc.InventoryResult) error {
	writeRows := [][]string{
		{
			"repository_name",
			"branch_name",
			"actions_file",
			"action",
			"scan_status",
			"row_kind",
			"line",
			"column",
			"action_repository",
			"subpath",
			"ref",
			"error",
		},
	}

	for _, ir := range inv.Records {
		for _, finding := range ir.Findings {
			writeRows = append(writeRows, []string{
				ir.Repository,
				ir.Branch,
				ir.FilePath,
				finding.Original,
				string(inv.Status),
				"finding",
				fmt.Sprintf("%d", finding.Line),
				fmt.Sprintf("%d", finding.Column),
				finding.Repository,
				finding.Subpath,
				finding.Ref,
				"",
			})
		}
	}
	for _, scanErr := range inv.Errors {
		writeRows = append(writeRows, []string{"", "", scanErr.FilePath, "", string(inv.Status), "error", "", "", "", "", "", scanErr.Message})
	}
	if len(inv.Records) == 0 && len(inv.Errors) == 0 {
		writeRows = append(writeRows, []string{"", "", "", "", string(inv.Status), "metadata", "", "", "", "", "", ""})
	}

	f, err := os.Create("findings.csv")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	csvWriter := csv.NewWriter(f)
	csvWriter.WriteAll(writeRows)
	return csvWriter.Error()
}

func newRootCmd() *cobra.Command {
	// list table configuration
	tw := tablewriter.NewWriter(os.Stdout)

	var cmdAudit = &cobra.Command{
		Use:   "audit",
		Short: "🥽 Audit a local or remote Git repository to identify vulnerable actions with mutable references: 'scharf audit <repo>|<url>'",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🥽 Audit the actions and raise error if any mutable references found. Good used with Ci/CD pipelines: 'scharf audit <repo>|<url>'`),
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			then := time.Now()
			rp, err := sc.BuildRepoPath("audit", args)
			if err != nil {
				return err
			}

			result, scanErr := auditRepository(*rp)
			if result == nil {
				return scanErr
			}

			now := time.Now()
			di := now.Sub(then)
			fmt.Fprintf(cmd.OutOrStdout(), "Scan status: %s\n", result.Status)
			if len(result.Workflows) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), sc.FormatAuditReport(result.Workflows))
			} else {
				if result.Complete {
					fmt.Fprintln(cmd.OutOrStdout(), "No mutable references found. Good job!")
				}
			}
			for _, fileErr := range result.Errors {
				fmt.Fprintf(cmd.ErrOrStderr(), "Scan error: %s\n", fileErr.Error())
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Total time: %.2f s\n", di.Seconds())

			if scanErr != nil {
				cmd.SilenceUsage = true
				return scanErr
			}
			shouldRaise, _ := cmd.Flags().GetBool("raise-error")
			if shouldRaise && len(result.Workflows) > 0 {
				cmd.SilenceUsage = true
				return errors.New("mutable GitHub Actions references found")
			}
			return nil
		},
	}
	cmdAudit.PersistentFlags().Bool("raise-error", false, "Raise error on any matches. Useful for interrupting CI pipelines")

	var cmdAutoFix = &cobra.Command{
		Use:   "autofix",
		Short: "🪄 Auto-fixes vulnerable third-party GitHub actions with mutable references: 'scharf autofix <repo>|<url>'",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🪄 Auto-fixes vulnerable third-party GitHub actions with mutable references: 'scharf audit <repo>|<url>'`),
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			isDryRun := cmd.Flag("dry-run")
			var isDR bool
			if isDryRun.Value.String() == "true" {
				isDR = true
			} else {
				isDR = false
			}
			then := time.Now()
			rp, err := sc.BuildRepoPath("autofix", args)
			if err != nil {
				return err
			}

			err = sc.AutoFixRepository(*rp, isDR)
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			now := time.Now()
			di := now.Sub(then)
			fmt.Printf("Total time: %.2f s\n", di.Seconds())
			return nil
		},
	}
	cmdAutoFix.PersistentFlags().Bool("dry-run", false, "Preview the fixes before actually making the changes")

	var cmdFind = &cobra.Command{
		Use:   "find",
		Short: "🔎 Find all GitHub actions with mutable references in a workspace. Should clone your Git repositories into the workspace",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🔎 Find all GitHub actions with mutable references in a workspace. Should clone your Git repositories into the workspace`),
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			root_path_flag := cmd.Flag("root")
			var ho bool
			head_only := cmd.Flag("head-only")
			if head_only.Value.String() == "true" {
				ho = true
			} else {
				ho = false
			}

			inv, scanErr := findRepositories(root_path_flag.Value.String(), ho)
			if inv == nil {
				return scanErr
			}

			out_fmt_flag := cmd.Flag("out")
			out_fmt := out_fmt_flag.Value.String()
			var outputErr error

			switch out_fmt {
			case "json":
				outputErr = writeToJSON(inv)
			case "csv":
				outputErr = WriteToCSV(inv)
			default:
				return fmt.Errorf("invalid --out value %q: valid values are json and csv", out_fmt)
			}
			if outputErr != nil {
				return outputErr
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Scan status: %s\n", inv.Status)
			for _, fileErr := range inv.Errors {
				fmt.Fprintf(cmd.ErrOrStderr(), "Scan error: %s\n", fileErr.Error())
			}
			if scanErr != nil {
				cmd.SilenceUsage = true
				return scanErr
			}
			return nil
		},
	}

	var cmdLookup = &cobra.Command{
		Use:   "lookup",
		Short: "👀 Look up the immutable commit-SHA of a given third-party GitHub action plus reference. Ex: scharf lookup actions/checkout@v4",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `👀 Look up the immutable commit-SHA of a given third-party GitHub action plus reference. Ex: scharf lookup actions/checkout@v4`),
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] != "" {
				s := nw.NewSHAResolver()
				sha, err := s.Resolve(args[0])
				if err != nil {
					logger.Error("problem while fetching action SHA. Please check the action again.", "action", args[0])
				}

				fmt.Println(sha)
			} else {
				logger.Error("Please give a GitHub action to look up SHA-commit. Ex: actions/checkout@v4")
			}
		},
	}

	var cmdUpgrade = &cobra.Command{
		Use:   "upgrade <owner/repo@ref-or-sha>",
		Short: "⬆️ Upgrade a pinned action to the next version and SHA",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `⬆️ Upgrade a pinned action to the next version and SHA. Ex: scharf upgrade actions/checkout@v4`),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := args[0]
			fromVersion, _ := cmd.Flags().GetString("from-version")
			cooldownHours, _ := cmd.Flags().GetInt("cooldown-hours")
			isDryRun, _ := cmd.Flags().GetBool("dry-run")

			if err := validateUpgradeInput(input, fromVersion); err != nil {
				cmd.SetOut(cmd.ErrOrStderr())
				_ = cmd.Usage()
				cmd.SilenceUsage = true
				return err
			}

			action, refOrSHA, err := splitActionRef(input)
			if err != nil {
				cmd.SetOut(cmd.ErrOrStderr())
				_ = cmd.Usage()
				cmd.SilenceUsage = true
				return err
			}

			currentVersion := refOrSHA
			if isSHAUpgradeInput(input) {
				currentVersion = fromVersion
			}

			resolver := nw.NewSHAResolver()
			result, err := resolver.ResolveNext(action, currentVersion, cooldownHours)
			if err != nil {
				return err
			}

			if result.UnderCooldown {
				fmt.Printf("%sWarning:%s %s@%s is under cooldown; proceeding with upgrade\n", sc.Yellow, sc.Reset, action, currentVersion)
			}

			upgradedPin := fmt.Sprintf("%s@%s # %s", action, result.NextSHA, result.NextVersion)
			if isDryRun {
				fmt.Printf("Dry-run: planned upgrade %s -> %s\n", input, upgradedPin)
				return nil
			}

			fmt.Println(upgradedPin)
			return nil
		},
	}

	var cmdUpgradeAllSHA = &cobra.Command{
		Use:   "upgrade-all-sha [repo|url]",
		Short: "⬆️ Upgrade all Scharf-formatted pinned SHAs in workflows",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `⬆️ Upgrade all Scharf-formatted pinned SHAs in workflows for a local repo or remote URL`),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cooldownHours, _ := cmd.Flags().GetInt("cooldown-hours")
			isDryRun, _ := cmd.Flags().GetBool("dry-run")

			then := time.Now()
			rp, err := sc.BuildRepoPath("upgrade-all-sha", args)
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}

			if err := upgradePinnedSHAs(*rp, cooldownHours, isDryRun); err != nil {
				cmd.SilenceUsage = true
				return err
			}

			now := time.Now()
			di := now.Sub(then)
			fmt.Printf("Total time: %.2f s\n", di.Seconds())
			return nil
		},
	}
	addSharedUpgradeFlags(cmdUpgrade)
	addSharedUpgradeFlags(cmdUpgradeAllSHA)
	cmdUpgrade.Flags().String("from-version", "", "Current version to upgrade from when input is owner/repo@<sha>")
	cmdFind.PersistentFlags().String("root", ".", "Absolute path of root directory of GitHub repositories")
	cmdFind.PersistentFlags().String("out", "json", "Output format of findings. Available options: json, csv")
	cmdFind.PersistentFlags().Bool("head-only", false, "Limit scan only to HEAD (Activated branch)")

	var cmdList = &cobra.Command{
		Use:   "list",
		Short: "📋 Lists available references and their SHA versions of a GitHub action. Ex: scharf list actions/checkout",
		Long:  "📋 Lists available references and their SHA versions of an action in tabular form. Ex: actions/checkout. Prints <Version | Commit SHA> as a table rows",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tw.SetHeader([]string{
				"Version",
				"Commit SHA",
			})
			tw.SetHeaderColor(
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor},
			)

			if args[0] != "" {
				list, err := nw.GetRefList(args[0])
				if err != nil {
					logger.Error("No tags found. Please check the action again.", "action", args[0])
				}

				for i := range list {
					tw.Append([]string{
						list[i].Name,
						list[i].Commit.Sha,
					})
				}

				tw.Render()
			} else {
				logger.Error("Please give a GitHub action to look up SHA-commit. Ex: actions/checkout@v4")
			}
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print Scharf version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), cliVersion())
		},
	}

	var rootCmd = &cobra.Command{
		Use:  "scharf",
		Long: asciiLogo,
		Run: func(cmd *cobra.Command, args []string) {
			showVersion, _ := cmd.Flags().GetBool("version")
			if showVersion {
				fmt.Fprintln(cmd.OutOrStdout(), cliVersion())
				return
			}
			_ = cmd.Help()
		},
	}
	rootCmd.Flags().BoolP("version", "V", false, "Print Scharf version information")
	rootCmd.AddCommand(cmdLookup, cmdFind, cmdList, cmdAudit, cmdAutoFix, cmdUpgrade, cmdUpgradeAllSHA, cmdVersion)

	return rootCmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
