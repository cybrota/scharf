// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package main is the entry point for the application

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"

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

func writeToJSON(inv *sc.Inventory) {
	f, _ := os.Create("findings.json")
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", " ")
	enc.Encode(inv)
}

func WriteToCSV(inv *sc.Inventory) {
	writeRows := [][]string{
		{
			"repository_name",
			"branch_name",
			"actions_file",
			"action",
		},
	}

	for _, ir := range inv.Records {
		for _, mat := range ir.Matches {
			writeRows = append(writeRows, []string{
				ir.Repository,
				ir.Branch,
				ir.FilePath,
				mat,
			})
		}
	}

	f, _ := os.Create("findings.csv")
	defer f.Close()
	csv_writer := csv.NewWriter(f)
	csv_writer.WriteAll(writeRows)
}

func main() {
	// list table configuration
	tw := tablewriter.NewWriter(os.Stdout)
	regex := regexp.MustCompile(`(\w*-?\w*)(\/)(\w+-?\w+)@((v\w+)|main|dev|master)`)

	var cmdAudit = &cobra.Command{
		Use:   "audit",
		Short: "🥽 Audit a given Git repository to identify vulnerable actions with mutable references. Must run from a Git repository",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🥽 Audit the actions and raise error if any mutable references found. Good used with Ci/CD pipelines.`),
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			inv, err := sc.AuditRepository(regex)
			if err != nil {
				fmt.Println("Not a git repository. Skipping checks!")
				return
			}

			if len(inv.Records) > 0 {
				tw.SetHeader([]string{
					"Match",
					"FilePath",
					"Replace with SHA",
				})
				tw.SetHeaderColor(
					tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor},
					tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor},
					tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor},
				)

				s := nw.NewSHAResolver()
				visited := map[string]bool{}

				for _, ir := range inv.Records {
					for _, mat := range ir.Matches {
						hashKey := mat + ir.FilePath
						if visited[hashKey] {
							// already reported, skip to next
							continue
						}
						sha, err := s.Resolve(mat)
						if err != nil {
							sha = "N/A"
						}
						tw.Append([]string{
							mat,
							ir.FilePath,
							sha,
						})
						visited[hashKey] = true
					}
				}
				fmt.Println("Mutable references found in your GitHub actions. Please replace them to secure your CI from supply chain attacks.")
				tw.Render()
				shouldRaise := cmd.Flag("raise-error")
				if shouldRaise.Value.String() == "true" {
					os.Exit(1)
				}

			} else {
				fmt.Println("No mutable references found. Good job!")
			}
		},
	}
	cmdAudit.PersistentFlags().Bool("raise-error", false, "Raise error on any matches. Useful for interrupting CI pipelines")

	var cmdAutoFix = &cobra.Command{
		Use:   "autofix",
		Short: "🪄 Auto-fixes vulnerable third-party GitHub actions with mutable references. Must run from a Git repository",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🪄 Auto-fixes vulnerable third-party GitHub actions with mutable references. Must run from a Git repository`),
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			err := sc.AutoFixRepository(regex)
			if err != nil {
				fmt.Println("Not a git repository. Skipping autofix!")
				return
			}
		},
	}

	var cmdFind = &cobra.Command{
		Use:   "find",
		Short: "🔎 Find all GitHub actions with mutable references in a workspace. Should clone your Git repositories into the workspace",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `🔎 Find all GitHub actions with mutable references in a workspace. Should clone your Git repositories into the workspace`),
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			sc := sc.Scanner{
				VCS:         sc.GitHubVCS{},
				FileScanner: sc.GitHubWorkFlowScanner{},
			}

			root_path_flag := cmd.Flag("root")
			var ho bool
			head_only := cmd.Flag("head-only")
			if head_only.Value.String() == "true" {
				ho = true
			} else {
				ho = false
			}
			inv, err := sc.ScanRepos(root_path_flag.Value.String(), regex, ho)

			if err != nil {
				log.Fatal(err.Error())
			}

			out_fmt_flag := cmd.Flag("out")
			out_fmt := out_fmt_flag.Value.String()

			switch out_fmt {
			case "json":
				writeToJSON(inv)
				break
			case "csv":
				WriteToCSV(inv)
				break
			default:
				logger.Error("The given value to --out flag is invalid. Valid values are json, csv.", "value", out_fmt)
			}
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

	var rootCmd = &cobra.Command{Use: "scharf", Long: asciiLogo}
	rootCmd.AddCommand(cmdLookup, cmdFind, cmdList, cmdAudit, cmdAutoFix)
	rootCmd.Execute()
}
