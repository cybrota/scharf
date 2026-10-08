# ADR 005: Opt-in upstream SHA provenance

## Context

A full SHA makes an action reference immutable. It does not establish that the
commit belongs to the intended upstream repository: GitHub can make fork-network
commits addressable through another repository's commit endpoint. Cached
ref-to-SHA lookups also cannot establish current identity or reachability.

## Decision

Keep existing immutability-only behavior by default. Add `--verify-provenance` to
audit, autofix, upgrade and upgrade-all-sha. These paths share one opt-in resolver.

A verified result requires fresh GitHub repository identity and proof that the
commit is equal to, or an ancestor of, at least one current branch tip returned by
the upstream repository's branches API. Store the canonical full name, numeric
repository ID, candidate SHA, check time, and exact supporting `refs/heads/*` tip
SHA. GitHub compare metadata must show `ahead` or `identical`, with the candidate
as the merge base. A successful commit lookup alone is never membership proof.
This is a deliberately conservative, documented upstream-ref set: tags,
release-only history, pull-request refs, fork refs, and deleted branches are not
independent membership evidence.

Resolve named refs using exact Git refs, tags before branches. Peel annotated tag
objects to commits, with an eight-object bound. Ref lists and comparisons use
fixed pagination/request/body/time bounds. Each verification has at most 128 API
calls, five branch pages of 100, 2 MiB per response, a 45-second overall deadline,
and a 15-second per-request timeout. Redirects are limited to three same-host
HTTPS GitHub API hops. Tag listing for upgrade selection has five pages of 100;
incomplete listing cannot choose an upgrade. Comparisons request one commit per
page because only ancestry metadata is used. The first supporting branch is
sufficient positive evidence; lack of proof is always unverified.

Use a separate versioned `~/.scharf/provenance.json` for historical observations,
not the ordinary resolution cache. First observations are trust-on-first-use,
not an independent identity authority. A changed repository ID at an observed
path blocks every ref, even a previously unseen version. A rename retaining the
ID is allowed. Ref movement remains visible in evidence:

- Forward branch/major-version-tag advancement is expected when ancestry and
  current upstream membership both verify. It is reported and may be used.
- Other tag movement, tag/branch namespace changes, non-forward history and identity changes require explicit
  review. They do not overwrite the previously accepted observation.
- Moved refs retain their old/new SHA evidence even if the new history cannot be
  reached. A removed ref, 404, API/rate limit or stale state is uncertainty, never
  a claim of compromise.

Observation writes are atomic and private to the user. A short exclusive write
lock plus comparison with the originally read state rejects concurrent changes
rather than silently losing historical evidence. Corrupt, unknown-version,
oversized, locked or unwritable state fails closed. No previous check, including
one from the same invocation, is silently reused as current verification.

Audit preserves evidence in JSON, SARIF and human output, including existing
pins. Autofix preflights evidence before writing; upgrades check the actual
existing pin separately from its comment hint and verify proposed targets.
Unknown or review-required evidence cannot authorize an edit.

## Alternatives and limitations

Commit addressability and matching tags alone are too weak. Fetching whole Git
histories would add storage and transport costs without making the trust
boundary clearer. GitHub's preview lockfile format is not adopted or depended on.

Proof is a point-in-time branch-history statement, not proof of benign code,
authentic release signing, immutable releases, or a trustworthy maintainer. API
limits, tag-only release commits, deleted branches, concurrent ref changes and
legitimate history rewrites may leave a valid commit unverified. Ref snapshots
are not an atomic snapshot of the entire repository. The local observation file
is not tamper-resistant against someone controlling the user's machine. Review
and deliberate re-baselining remain manual; this change adds no automatic
acceptance or state-reset command.

## Sources

- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub REST commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits)
- [GitHub REST Git tags](https://docs.github.com/en/rest/git/tags)
- [Issue #58](https://github.com/cybrota/scharf/issues/58)
