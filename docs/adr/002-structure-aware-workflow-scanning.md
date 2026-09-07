# Structure-Aware Workflow Scanning

## Context

Scharf previously searched every workflow line with a regular expression. That approach matched comments and unrelated strings, missed valid Git refs and repository subpaths, and did not provide a reliable source span for autofix. It also treated skipped files as clean scans.

## Decision

Parse workflow files with the maintained `go.yaml.in/yaml/v3` module and inspect only job-level `uses` values and `uses` values on job steps. Keep the original bytes and derive half-open byte spans from YAML scalar node locations instead of serializing the parsed document.

Represent repository scan state explicitly as `complete-clean`, `complete-with-findings`, or `incomplete`. File-level errors are retained beside successful findings, and incomplete scans return an aggregate error so command exit status cannot imply a clean result.

Mutable references are all syntactically valid external references except full 40-character hexadecimal commit SHAs. Local actions, Docker references, malformed references, and dynamic expressions are not candidates.

Preserve the v1 structs and function signatures as compatibility wrappers while exposing structured findings and completion state through new APIs. Treat mutable references expressed through YAML aliases, anchors, or block scalars as findings in an incomplete scan because their source spans are not safe to edit.

Scan all local branches directly from their Git commit trees without checking them out; `--head-only` continues to inspect the current working tree. Resolve GitHub references by exact tag name before exact branch name, matching GitHub's tag precedence while supporting branch names containing slashes.

## Consequences

- Comments, unrelated mappings, local actions, and Docker references are not reported.
- Quoting, formatting, action subpaths, reusable workflow paths, and existing comments survive autofix because only verified spans are edited.
- Unsupported scalar forms remain visible as findings but block autofix until the workflow is rewritten into a safely editable form.
- Malformed or unreadable workflow files make the result incomplete without discarding findings from other files.
- Scanning all branches does not mutate HEAD, the index, or working-tree files.
- Existing v1 callers keep their source and JSON compatibility while new callers can consume structured details.
- Callers must inspect scan status and handle a non-nil error together with a partial result.

## Alternatives Considered

- Expanding the regular expression was rejected because it still lacks YAML context and trustworthy edit boundaries.
- Reserializing the YAML AST was rejected because it would create unrelated formatting and comment changes.
- Checking out every branch was rejected because it mutates the repository being inspected and can overwrite or conflict with user changes.
- Maintaining a known branch and tag list was rejected because mutable Git references are open-ended.
