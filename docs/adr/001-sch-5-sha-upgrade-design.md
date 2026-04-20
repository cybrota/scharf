# SCH-5 SHA Upgrade Design

## Context

Scharf currently resolves mutable GitHub Action references to immutable SHAs (`autofix`) and can look up versions (`lookup`, `list`), but it does not provide a way to upgrade already pinned SHAs over time.

Goal: let developers automate pinned SHA refreshes with a configurable cool-down period (default 24h), while preserving the current separation of concerns:

- `autofix` handles mutable refs -> pinned SHAs.
- new upgrade commands handle pinned SHA refreshes only.

## Decisions

1. Add two commands:
   - `scharf upgrade <owner/repo@ref-or-sha>`
   - `scharf upgrade-all-sha [repo|url]`
2. Support cool-down policy on both commands:
   - default `--cooldown-hours=24`
   - configurable override via flag
3. Warn-and-continue behavior for fresh tags (< cool-down):
   - print warning in terminal output
   - continue with upgrade
4. `upgrade-all-sha` only processes Scharf-formatted pinned refs:
   - `owner/repo@<40hexsha> # <version>`
   - and also supports deterministic fallback for bare pinned refs: `owner/repo@<40hexsha>`
5. Add `--dry-run` support for both commands.
6. For `upgrade` with SHA input, require `--from-version` to disambiguate current version.
7. For `upgrade-all-sha` fallback inference (`owner/repo@<40hexsha>`):
   - exactly one tag points to SHA -> infer current version and upgrade in same run
   - zero tags point to SHA -> skip with reason
   - multiple tags point to SHA -> skip with reason (ambiguous)
8. Build a per-action in-memory tag index during a run to avoid repeated API calls.

## Non-Goals

- Bulk upgrade behavior inside `autofix`.
- Best-effort parsing for arbitrary comment formats.
- Best-effort inference when reverse lookup is ambiguous.

## CLI Design

### `scharf upgrade`

Input:

- `owner/repo@vX` (or branch-like ref)
- `owner/repo@<sha>` with required `--from-version <tag>`

Flags:

- `--cooldown-hours int` (default `24`)
- `--from-version string` (required only for SHA input)
- `--dry-run` (prints computed result only)

Output:

- Success: old -> new details and final upgraded pin (`owner/repo@<sha> # <next-version>`)
- Warning: cool-down threshold not met (still proceeds)
- Errors: invalid input, ambiguous SHA input without `--from-version`, unable to resolve refs

### `scharf upgrade-all-sha`

Input:

- Optional local path or remote URL (same path resolution behavior as `audit`/`autofix`)

Flags:

- `--cooldown-hours int` (default `24`)
- `--dry-run`

Behavior:

- Scans workflow files for Scharf-formatted pinned refs.
- Parses either:
  - `action@<sha> # <version>` (direct)
  - `action@<sha>` (fallback infer)
- Computes next version + next SHA.
- Applies replacement in-place unless `--dry-run`.

End summary includes:

- updated
- skipped_ambiguous_sha_tags
- skipped_no_tag_for_sha
- skipped_no_next
- warnings
- errors

## Architecture Changes

### `main.go`

- Add `upgrade` and `upgrade-all-sha` cobra commands.
- Add command flags and input validation.
- Wire to scanner/network helpers.

### `network/resolver.go`

- Extend resolver capabilities with methods to:
  - resolve specific `action@version` to SHA
  - list tags with metadata
  - resolve next version after a given version
  - evaluate cool-down by tag age
- Keep caching version-aware (`action@version`) to avoid stale lookups.

### `scanner` package

- Add scanner flow for pinned SHA upgrade candidates.
- Reuse line/column-safe replacement pattern from existing fix pipeline.
- Parse both strict hinted and bare pinned SHA formats.
- Infer current version via per-action reverse tag index (`sha -> []tags`).
- Skip with explicit reasons for zero-tag and multi-tag matches.

## Data Flow

### Single upgrade flow

1. Parse input (`action@ref-or-sha`).
2. Determine current version:
   - from input ref, or
   - from `--from-version` when input is SHA.
3. Fetch tags and compute immediate next version.
4. Resolve next version to SHA.
5. Check cool-down; warn if too fresh.
6. Print result (or dry-run result).

### Bulk upgrade flow

1. Resolve repo path (`BuildRepoPath`).
2. Enumerate workflow files.
3. Find upgrade candidates matching pinned SHA formats.
4. For each candidate:
   - use version hint if present, else infer from SHA via per-action tag index
   - skip when no tag matches or multiple tags match
   - compute next version
   - resolve next SHA
   - warn if cool-down not met
   - stage replacement or skip
5. Apply edits (unless dry-run).
6. Print per-file updates and aggregate summary.

## Error Handling

- Hard-fail command for:
  - invalid command input
  - invalid repository path
  - missing required `--from-version` for SHA input
- Soft-fail per candidate in `upgrade-all-sha`:
  - continue processing other entries
  - report warning/error in summary

## Testing Strategy

1. Resolver tests:
   - next-version selection
   - no-next-version path
   - cool-down warning behavior
   - SHA input with/without `--from-version`
2. Scanner tests:
   - parser for hinted and bare pinned SHA formats
   - reverse lookup inference behavior (1 match, 0 match, >1 match)
   - replacement correctness at line/column boundaries
   - dry-run behavior
   - explicit skip reasons in summary output
3. Command tests:
   - `upgrade` happy path, ambiguous path, and cool-down warning
   - `upgrade-all-sha` with mixed valid/invalid entries and summary counts

## Alternatives Considered

1. `upgrade-all-sha` only: lower scope, but weaker targeted UX.
2. Extend `autofix` for pinned upgrades: rejected due to responsibility overlap and higher accidental complexity.

## Rollout Notes

- Backward compatible with existing commands.
- New behavior is opt-in through new commands.
- Existing Scharf-formatted comments become the canonical source for bulk upgrade continuity.
