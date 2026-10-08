// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"strings"

	"github.com/cybrota/scharf/network"
)

// VerificationOptions keeps network provenance explicitly opt-in for every command.
type VerificationOptions struct {
	VerifyProvenance bool
}

type provenanceResolver interface {
	ResolveWithProvenance(action string) (string, *network.ProvenanceEvidence, error)
	Verify(repository, ref, sha string) *network.ProvenanceEvidence
}

var newAuditProvenanceResolver = func() provenanceResolver {
	return network.NewProvenanceResolver()
}

func provenanceAllowsSHA(evidence *network.ProvenanceEvidence, sha string) bool {
	// Canonical repository names may change; the resolver checks their stable IDs.
	return evidence != nil && evidence.AllowsUpdate() && evidence.Repository != "" &&
		evidence.RepositoryID > 0 && isFullSHA(sha) && strings.EqualFold(evidence.SHA, sha)
}

func requireProvenance(action string, evidence *network.ProvenanceEvidence) error {
	if evidence == nil {
		return fmt.Errorf("provenance unverified for %s: no evidence returned", action)
	}
	if !evidence.AllowsUpdate() {
		return fmt.Errorf("provenance %s for %s: %s; review required before updates", evidence.Status, action, evidence.Reason)
	}
	return nil
}

func provenanceSummary(evidence *network.ProvenanceEvidence) string {
	if evidence == nil {
		return "Provenance unverified: no evidence returned."
	}
	summary := fmt.Sprintf("Provenance %s for %s@%s (repository ID %d, checked %s).", evidence.Status, evidence.Repository, evidence.SHA, evidence.RepositoryID, evidence.CheckedAt)
	if len(evidence.SupportingRefs) > 0 {
		refs := make([]string, 0, len(evidence.SupportingRefs))
		for _, ref := range evidence.SupportingRefs {
			refs = append(refs, ref.Ref+"@"+ref.SHA)
		}
		summary += " Supported by " + strings.Join(refs, ", ") + "."
	}
	if evidence.Previous != nil {
		summary += fmt.Sprintf(" Previous observation: %s@%s (repository ID %d, checked %s).", evidence.Previous.Repository, evidence.Previous.SHA, evidence.Previous.RepositoryID, evidence.Previous.CheckedAt)
	}
	if evidence.Moved {
		summary += " Moved reference detected."
	}
	if evidence.RequiresReview {
		summary += " Review required before updates."
	}
	if evidence.Reason != "" {
		summary += " " + evidence.Reason
	}
	return summary
}

func analyzeWorkflowWithProvenance(res provenanceResolver, content []byte, filePath string) (*WorkflowAnalysis, error) {
	findings, scanErr := scanWorkflowReferences(content, filePath, true)
	issues := make([]Finding, 0, len(findings))
	for i := range findings {
		finding := &findings[i]
		lookup := fmt.Sprintf("%s@%s", finding.Repository, finding.Ref)
		var resolvedSHA string
		var evidence *network.ProvenanceEvidence
		var err error
		if finding.Pinned {
			resolvedSHA = finding.Ref
			// Comment hints are not proof of the currently pinned commit's origin.
			evidence = res.Verify(finding.Repository, finding.Ref, finding.Ref)
		} else {
			resolvedSHA, evidence, err = res.ResolveWithProvenance(lookup)
		}
		if evidence == nil {
			evidence = &network.ProvenanceEvidence{
				Status: "unverified", Repository: finding.Repository,
				OriginalRef: finding.Ref, SHA: resolvedSHA, Reason: "no provenance evidence returned",
			}
		}
		if evidence.AllowsUpdate() && (err != nil || !provenanceAllowsSHA(evidence, resolvedSHA)) {
			// A resolution failure or evidence for another target can never authorize an edit.
			// Preserve genuine unsafe statuses; resolution returns errors for those as well.
			copy := *evidence
			evidence = &copy
			evidence.Status = "unverified"
			evidence.RequiresReview = true
			if err != nil {
				evidence.Reason = err.Error()
			} else {
				evidence.Reason = "resolved target does not match complete provenance evidence"
			}
		}
		finding.Provenance = evidence
		finding.Description = provenanceSummary(evidence)
		if !finding.Pinned {
			finding.Description = fmt.Sprintf("Unpinned GitHub Action: uses `%s`. %s", finding.Original, finding.Description)
			finding.FixSHA = SHA256NotAvailable
			if evidence.AllowsUpdate() {
				finding.FixSHA = resolvedSHA
				finding.FixMessage = fmt.Sprintf("Pin `%s` to %s", finding.Original, resolvedSHA)
			} else {
				finding.FixMessage = "Review upstream identity, branch reachability, and reference history before pinning."
			}
		}
		if !finding.Pinned || !evidence.AllowsUpdate() {
			issues = append(issues, finding.legacy())
		}
	}
	return &WorkflowAnalysis{
		Workflow: Workflow{Name: filePath, FilePath: filePath, Issues: issues},
		Findings: findings,
	}, scanErr
}
