# Optional upstream provenance verification

By default Scharf checks whether workflow references use full commit SHAs and
resolves mutable refs for pinning. Immutability alone does not verify upstream
provenance. Add `--verify-provenance` when current upstream evidence is required:

```sh
scharf audit . --verify-provenance --out json
scharf audit . --verify-provenance --out sarif --output provenance.sarif
scharf autofix . --verify-provenance --dry-run
scharf upgrade actions/checkout@v4 --verify-provenance
scharf upgrade-all-sha . --verify-provenance --dry-run
```

This mode checks references directly present in the scanned workflow files.
Recursive/transitive dependency provenance is not included; combining this mode
with a dependency-graph audit requires a separate integration and is unsupported.

Verification uses fresh GitHub API responses, optionally authenticated with
`GITHUB_TOKEN`. It never downloads or executes action payloads. A commit must be
reachable from a current branch in the intended upstream repository. Evidence
records the canonical repository name, stable numeric repository ID, check time,
SHA and exact supporting branch tip. Tags are resolved through annotated tag
objects when needed; tags alone are not the membership-proof set.

Existing full-SHA pins are checked too. A fork-only commit being addressable
through `/repos/owner/repo/commits/<sha>` is not sufficient proof. Conversely,
removed branches, inaccessible history, rate limits and offline operation can
leave legitimate commits unverified. “Verified” does not mean benign code.

## Historical changes and review

The first successful check records a historical observation in
`~/.scharf/provenance.json`. It is a trust-on-first-use record, not a signed
identity authority and not a verification cache. All later checks contact
GitHub again. A renamed repository retaining the same ID can be verified; a
replacement with a different ID requires review, including when requesting a
new version. Expected forward movement of a branch or major tag such as `v4` is
reported as `moved-reference` with `requires_review: false`. A moved patch tag,
non-forward change, tag/branch namespace change, or uncheckable prior ancestry requires review.

Autofix and upgrades refuse unknown or review-required evidence before writing
workflow changes. Dry runs enforce the same checks. Audit includes the evidence
and reports unsafe provenance as a violation; use `--raise-error` to make audit
policy violations fail CI.

To review a suspicious change, inspect the upstream repository identity, old/new
commit histories and maintainer release information independently. Scharf does
not automatically accept the change. If you deliberately choose a new baseline,
back up the observation file and manually remove only the relevant reviewed
observation(s), then rerun verification. For an intentional repository identity
replacement, all observations binding that path to the prior repository ID must
be reviewed. Deleting the entire file discards identity and moved-reference
history for every repository and should not be a routine workaround. A leftover
`.lock` directory should be removed only after confirming no Scharf invocation is
writing the file.

## Bounds and conservative results

Each verification is bounded to 128 API calls, five branch-list pages of 100,
2 MiB per response, eight annotated-tag objects, 15 seconds per request and
45 seconds overall. Only same-host HTTPS GitHub API redirects are followed, at
most three. Upgrade tag listing is limited to five pages and fails if incomplete.
An exact positive branch proof can be returned before enumeration finishes;
exhausted limits without proof return unverified. Tag-only release histories,
deleted branches and history rewrites can therefore need manual investigation.
No cached or stale evidence is promoted to a current result.
