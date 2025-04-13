package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"regexp"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

const asciiLogo = `
_______ _______ _     _ _______  ______ _______
|______ |       |_____| |_____| |_____/ |______
______| |_____  |     | |     | |    \_ |

Copyright @ Cybrota (https://github.com/cybrota)
`

func writeToJSON(inv *Inventory) {
	f, _ := os.Create("findings.json")
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", " ")
	enc.Encode(inv)
}

func WriteToCSV(inv *Inventory) {
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

	var cmdFind = &cobra.Command{
		Use:   "find",
		Short: "Find all GitHub actions with mutable references in a workspace. The workspace should have cloned Git repositories.",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `Find all GitHub actions with mutable references in a workspace. The workspace should have cloned Git repositories.`),
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			sc := Scanner{
				VCS:         GitHubVCS{},
				FileScanner: GitHubWorkFlowScanner{},
			}

			root_path_flag := cmd.Flag("root")

			// Regex to find whether workflow has reference to vXY, main, dev or master
			regex, _ := regexp.Compile(`(\w*-?\w*)(\/)(\w+-?\w+)@((v\w+)|main|dev|master)`)
			inv, err := sc.ScanRepos(root_path_flag.Value.String(), ".github/workflows", regex)

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
				slog.Error("The given value to --out flag is invalid. Valid values are json, csv.", "value", out_fmt)
			}
		},
	}

	var cmdLookup = &cobra.Command{
		Use:   "lookup",
		Short: "Look up the immutable commit-SHA of a given GitHub 'action@version'. Ex: actions/checkout@v4",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `Look up the immutable commit-SHA of a given action & version string. Ex: actions/checkout@v4`),
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] != "" {
				s := SHAResolver{}
				sha, err := s.resolve(args[0])
				if err != nil {
					slog.Error("problem while fetching action SHA. Please check the action again.", "action", args[0])
				}

				fmt.Println(sha)
			} else {
				slog.Error("Please give a GitHub action to look up SHA-commit. Ex: actions/checkout@v4")
			}
		},
	}
	cmdFind.PersistentFlags().String("root", ".", "Absolute path of root directory of GitHub repositories")
	cmdFind.PersistentFlags().String("out", "json", "Output format of findings. Available options: json, csv")

	var cmdList = &cobra.Command{
		Use:   "list",
		Short: "Lists all tags and their SHA versions of a GitHub action. Ex: actions/checkout",
		Long:  "Lists all tags and their SHA versions of an action in tabular form. Ex: actions/checkout. Prints <Version | Commit SHA> as a table rows",
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
				list, err := GetRefList(args[0])
				if err != nil {
					slog.Error("No tags found. Please check the action again.", "action", args[0])
				}

				for i := range list {
					tw.Append([]string{
						list[i].Name,
						list[i].Commit.Sha,
					})
				}

				tw.Render()
			} else {
				slog.Error("Please give a GitHub action to look up SHA-commit. Ex: actions/checkout@v4")
			}
		},
	}

	var cmdAudit = &cobra.Command{
		Use:   "audit",
		Short: "Audit a given Git repository to identify actions with mutable references. Must run from a Git repository",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `Audit the actions and raise error if any mutable references found. Good used with Ci/CD pipelines.`),
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			regex, _ := regexp.Compile(`(\w*-?\w*)(\/)(\w+-?\w+)@((v\w+)|main|dev|master)`)
			inv, err := AuditRepository(regex)

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

				s := SHAResolver{}
				for _, ir := range inv.Records {
					for _, mat := range ir.Matches {
						sha, err := s.resolve(mat)
						if err != nil {
							sha = "N/A"
						}

						tw.Append([]string{
							mat,
							ir.FilePath,
							sha,
						})
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

	var rootCmd = &cobra.Command{Use: "scharf", Long: asciiLogo}
	rootCmd.AddCommand(cmdLookup, cmdFind, cmdList, cmdAudit)
	rootCmd.Execute()
}
