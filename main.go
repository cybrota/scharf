package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"regexp"

	"github.com/spf13/cobra"
)

const asciiLogo = `
_______ _______ _     _ _______  ______ _______
|______ |       |_____| |_____| |_____/ |______
______| |_____  |     | |     | |    \_ |
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
		[]string{
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

	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "Launches scharf with provided options for workspace root and output format",
		Long:  fmt.Sprintf("%s\n%s", asciiLogo, `Launches scharf with provided options for workspace root and output format`),
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

	cmdRun.PersistentFlags().String("root", ".", "Absolute path of root directory of GitHub repositories")
	cmdRun.PersistentFlags().String("out", "json", "Output format of findings. Available options: json, csv")

	var rootCmd = &cobra.Command{Use: "scharf", Long: asciiLogo}
	rootCmd.AddCommand(cmdRun)
	rootCmd.Execute()
}
