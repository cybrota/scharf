# ADR 006: Release through a reviewed version change

## Context

Scharf's old tag-triggered workflow required somebody to create a tag with a
separate authenticated client. Desktop/connector availability could block a
release, and a tag created with `GITHUB_TOKEN` would not trigger that workflow.
The chronological v0.5.1 release also followed v1.4.1; chronological latest is
therefore not a safe semantic-version baseline.

## Decision

A reviewed change to `release/version.txt` on main is the release intent. A main
push changing that file tests and builds its exact event SHA, creates signed
build provenance, verifies it, and publishes through one originating workflow.
The initial workflow PR includes v1.4.2: **merging it requests that release**.
Future release PRs change the version and matching `release/notes.md` together.
Opening a PR runs only read-only validation and existing Go/security checks.

The publisher accepts only `cybrota/scharf`, `push`, and `refs/heads/main`.
It compares numeric stable semantic versions against all fetched tags. It never
moves a tag, replaces an asset, rewrites history, or edits a published release.
A repeated event can resume a draft only if its tag still resolves to the same
commit and every existing asset matches the rebuilt bytes. A completed identical
release is a no-op. Mismatches fail closed for maintainer investigation.
Concurrency is serialized without canceling an active publication.

Only the trusted release job gets `contents: write`, `id-token: write`, and
`attestations: write`. Checkout does not persist credentials. GitHub's short-lived
OIDC identity signs provenance through Sigstore; there is no stored signing key,
new PAT, cross-repository token, environment change, or settings change.
Actions are pinned to full SHAs, Go comes from the exact go.mod version, and
GoReleaser is pinned to v2.16.0. Compilation uses deterministic version metadata,
trimmed paths and fixed archive timestamps. This reduces retry drift; identical
builds across future runner-image changes are not promised.

## Alternatives and limits

A PAT-created tag could trigger the old workflow but introduces persistent access.
A release dispatch would still depend on a client with dispatch support.
Publishing from a PR or `pull_request_target` would cross the trust boundary.
A fully automatic tap update needs cross-repository access; instead a separate
reviewed tap PR follows independently verified release assets.

GitHub's repository writers remain trusted. Concurrent edits outside this workflow
cannot be made transactional with the release API; immutable release settings
would provide additional protection but are not enabled by this change.
Attestation proves build identity and provenance, not software safety, code review,
or absence of vulnerabilities. Local/mocked tests do not establish that live OIDC
signing and publication work; the first authorized main run must verify that.

## Sources

- [Workflow triggering and GITHUB_TOKEN](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Attestation verification flags](https://cli.github.com/manual/gh_attestation_verify)
- [GoReleaser reproducible builds](https://goreleaser.com/customization/builds/builders/go/)
