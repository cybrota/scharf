# Releasing Scharf

## Reviewed release PR

1. Branch from current main. Set `release/version.txt` to one stable version such
   as `v1.4.2` (one line, no leading zeroes). It must exceed every other stable
   semantic tag, not merely the most recently published release. Preserve the
   historical misnumbered v0.5.1 tag/release.
2. Update `release/notes.md` with a matching `# Scharf v1.4.2` heading, capabilities,
   compatibility changes and limitations. Inspect the full diff and PR checks.
3. A maintainer merges the PR. **The initial pipeline PR also releases v1.4.2
   when merged.** Merely opening it publishes nothing. The trusted main push
   tests the exact merged commit, builds five Linux/macOS ZIPs, attests the ZIPs
   and checksum manifest, verifies provenance, then creates the tag and release.
4. Verify the run succeeded and the published tag resolves to that tested commit.
   A draft or a tag alone does not mean publication completed.

Unrelated main pushes and notes-only changes do not request releases. The old
arbitrary-tag trigger is removed. Tests run after generated version metadata and
before build; `go mod tidy` and arbitrary `go generate` are not release hooks.
There are no new secrets, persistent credentials or repository settings to set.
GitHub-hosted Ubuntu runners need the shipped `gh` attestation commands. If an
organization policy prevents OIDC/attestations, the run fails before publication;
resolve it with an explicit administrator decision, never bypass verification.

## Verification and Homebrew

Download release files from the exact tag, then verify both their SHA256 checksums
and their attestation identities. Example (substitute the tested merge commit):

```sh
gh release download v1.4.2 --repo cybrota/scharf --dir scharf-v1.4.2
cd scharf-v1.4.2
sha256sum -c scharf_1.4.2_checksums.txt
for artifact in *.zip *checksums.txt; do
  gh attestation verify "$artifact" --repo cybrota/scharf \
    --signer-workflow cybrota/scharf/.github/workflows/release.yml \
    --source-digest TESTED_MERGE_COMMIT --source-ref refs/heads/main \
    --deny-self-hosted-runners
done
```

On macOS use `shasum -a 256 -c` instead of `sha256sum -c`. Provenance is a
cryptographically signed attestation stored in GitHub's attestation service,
not an invented detached `.sig` file or a checksum renamed as a signature.
After verification, open a separate PR in `cybrota/homebrew-cybrota` changing
Scharf's four platform URLs/version/SHA256 values to those verified assets.
Retain `version_scheme 1` where already present. Homebrew's SHA256 fields verify
bytes; they do not themselves enforce the GitHub provenance verification above.
The release workflow does not push to the tap.

## Failure and retry

Re-run the original failed workflow run so the event SHA and version change stay
identical. Failures before publication leave either no tag, a same-commit tag,
or a draft with a subset of assets. Existing matching assets are kept; missing
ones are uploaded. `--clobber`, forced tag updates, release deletion and asset
replacement are deliberately absent. A completed identical release is a no-op.

If a tag points elsewhere, an unexpected/incomplete asset exists, or rebuilt
bytes differ, the run stops. Do not bypass the check or overwrite published bytes.
Inspect the original run and its commit/tool versions. A changed runner can make
a rebuild differ despite fixed timestamps. A maintainer must choose a new release
version, or explicitly authorize a separately reviewed recovery using verified
original bytes. No automated deletion or recovery credentials are provisioned.
An API authentication/rate-limit failure is not treated as an absent release.

The pipeline cannot guarantee atomicity against a separate administrator moving
tags or editing drafts while it runs. Restrict release writers operationally;
changing repository security settings is outside this PR.
