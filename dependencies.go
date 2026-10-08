// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"fmt"
	nw "github.com/cybrota/scharf/network"
	sc "github.com/cybrota/scharf/scanner"
	"github.com/spf13/cobra"
	"io"
	"os"
)

var dependencyAudit = func(root string) (*sc.DependencyReport, error) {
	return sc.AuditDependencies(root, nw.NewDependencyClient(), sc.DefaultDependencyLimits())
}

func runDependencyAudit(cmd *cobra.Command, root string) error {
	for _, flag := range []string{"policy", "policy-from-ref", "ignore", "baseline-ref", "changed-lines", "verify-provenance"} {
		if cmd.Flags().Changed(flag) {
			return fmt.Errorf("--dependencies does not support --%s; run the direct policy audit separately", flag)
		}
	}
	format, _ := cmd.Flags().GetString("out")
	if format != "human" && format != "json" && format != "sarif" {
		return fmt.Errorf("dependency output must be human, json, or sarif")
	}
	report, scanErr := dependencyAudit(root)
	if report == nil {
		return scanErr
	}
	var out io.Writer = cmd.OutOrStdout()
	dest, _ := cmd.Flags().GetString("output")
	if dest != "" {
		f, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	if err := sc.WriteDependencyReport(out, report, format); err != nil {
		return err
	}
	if scanErr != nil {
		return scanErr
	}
	raise, _ := cmd.Flags().GetBool("raise-error")
	if raise {
		for _, e := range report.Edges {
			if e.Mutable {
				return fmt.Errorf("mutable dependency references found")
			}
		}
	}
	return nil
}
