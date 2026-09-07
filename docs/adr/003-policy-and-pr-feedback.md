# Policy and PR Feedback

## Context

Teams need scoped enforcement, temporary exceptions, and gradual adoption without turning scan failures into false success. Pull requests also need precise feedback that GitHub can display or ingest through code scanning.

## Decision

Use a strict, versioned YAML policy with ordered rules. Require durable exceptions to identify an owner, rationale, approver, approval record, and inclusive UTC expiration date. Support transient exact or explicitly prefixed RE2 CLI ignores only when policy permits them. Active durable exceptions take precedence; expired exceptions remain violations and cannot be revived by CLI ignores.

Classify current findings against the merge base of a configured Git ref. Scan both Git trees, detect renames, compare repeated canonical references as a multiset, and track changed right-side lines. Reject dirty workflow files because committed diffs cannot classify uncommitted scanner input reliably.

Keep policy outcome separate from scanner completion. Emit human reports, escaped GitHub workflow annotations, and SARIF 2.1.0 from one evaluated model. SARIF carries stable rule IDs, precise regions, suppressions, baseline state, incomplete-analysis notifications, and replacements derived from the scanner's verified edit spans.

Do not automatically trust checkout policy during enforcing `--raise-error` audits. Use the secure default unless the caller supplies an explicit policy path or selects policy committed at a trusted Git revision.

## Consequences

- Invalid or expired exceptions never silently suppress findings.
- Existing violations can remain visible while new violations block adoption.
- Pure workflow renames preserve baseline identity; changed refs and added duplicates become new findings.
- Missing revisions, malformed baseline workflows, dirty workflow files, and diff errors make analysis incomplete.
- Repository policy is an accountability record, not an authorization boundary; branch protection or a trusted external policy must protect it.
- The existing scanner models and v1 output contracts remain unchanged.

## Alternatives Considered

- Unstructured ignore regexes alone were rejected because they lack ownership, scope, approval, and expiration.
- Line-number-only baselines were rejected because edits and renames make them unstable.
- Treating diff failures as new or unchanged was rejected because either choice can misrepresent enforcement.
- Posting PR review comments directly was deferred because fork permissions and rerun deduplication require a separate authenticated integration. GitHub annotations and SARIF fixes provide deterministic, token-free feedback.
