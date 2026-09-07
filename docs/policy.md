# Policy and PR Feedback

Scharf can enforce immutable GitHub Actions references with repository policy, accountable exceptions, gradual rollout, and CI-native reports.

## Policy File

Scharf discovers `.scharf-policy.yml` at the scanned repository root for advisory audits. Use `--policy <path>` to trust an explicit file. In enforcing `--raise-error` mode, Scharf does not automatically trust policy from the checkout; it applies the secure default policy unless you pass `--policy` or `--policy-from-ref <revision>`. The parser rejects unknown fields, unsupported versions, duplicate IDs, invalid patterns, and malformed exceptions.

```yaml
version: 1
allow_cli_ignores: false

rules:
  - id: SCHARF001
    requirement: full-commit-sha
    severity: error
    repositories:
      - "actions/*"
      - "github/*"
    paths:
      - ".github/workflows/*.yml"
      - ".github/workflows/*.yaml"

baseline:
  ref: origin/main
  mode: new

exceptions:
  - id: SEC-1234
    match:
      repository: example/internal-action
      subpath: deploy
      ref: main
      paths:
        - ".github/workflows/release.yml"
    owner: team-platform
    rationale: Migration to an immutable release is in progress
    approved_by: security-team
    approval: https://github.com/example/project/issues/1234
    expires: 2026-10-01
```

`version` must be `1`. When `rules` is absent, Scharf applies `SCHARF001` with `requirement: full-commit-sha` and `severity: error` to every parsed external reference.

Rules use ordered, first-match precedence. Empty `repositories` or `paths` match all findings. Patterns use Go path-match syntax: `*` does not cross `/`. Repository matching ignores case; path, subpath, and ref matching preserve case. Supported severities are `error`, `warning`, and `note`; only `error` findings block `--raise-error`.

## Exceptions

Policy exceptions require these fields:

- `id`
- `match.repository`
- `owner`
- `rationale`
- `approved_by`
- `approval`
- `expires`

Optional `subpath`, `ref`, and `paths` constraints are combined with the repository match. An exception therefore suppresses only the intended references. `expires` uses `YYYY-MM-DD` and remains active through that UTC date. It expires at the start of the following UTC date.

Malformed exceptions invalidate the complete policy. Scharf never skips an invalid exception and continues scanning.

Use repeatable `--ignore` flags for temporary local exceptions:

```sh
scharf audit . --ignore owner/repo --ignore owner/repo/subpath@release/2026
scharf audit . --ignore 'regex:owner/(action|workflow)@v[0-9]+'
```

Plain values use exact `owner/repo[/subpath][@ref]` matching. The ref and subpath are optional. `regex:` values use RE2 syntax and must match the complete canonical reference. Set `allow_cli_ignores: false` to reject all CLI ignores.

Scharf applies policy in this order:

1. Reject invalid policy and CLI matchers.
2. Select the first matching rule.
3. Apply a matching active policy exception.
4. Treat a matching expired exception as a violation. A CLI ignore cannot revive it.
5. Apply a permitted matching CLI ignore.
6. Apply baseline and changed-line rollout filters.

When multiple durable exceptions match, any active renewal wins over expired records.

Exception metadata records accountability; it does not prove authorization. Protect `.scharf-policy.yml` with branch protection and `CODEOWNERS`. In pull-request CI, prefer `--policy-from-ref origin/main`; Scharf reads the committed policy from that revision, so checkout changes cannot relax enforcement. Use `--policy` only when the supplied path is outside the untrusted checkout or otherwise protected.

## Baselines and Changed Lines

Set `baseline.ref` with `mode: new`, or pass `--baseline-ref <ref>`, to surface existing violations without blocking them. The CLI flag overrides the policy baseline and selects `new` mode.

Scharf compares `HEAD` with its merge base against the selected ref. It detects workflow renames, scans both revision trees, and compares duplicate references as a multiset. A pure rename remains an existing finding. A changed ref or additional duplicate becomes new.

Add `--changed-lines` to enforce only findings whose right-side workflow line changed since the merge base. This flag requires a baseline ref. Scharf rejects uncommitted workflow changes because the Git diff would not describe the bytes being audited. Missing refs, malformed baseline workflows, and diff failures make the scan incomplete; they never produce a clean result.

## Output Formats

`scharf audit` supports `--out human`, `--out github`, and `--out sarif`. Use `--output <path>` to write any format to a file.

GitHub output uses escaped workflow commands with rule ID, source location, current reference, exception state, and remediation. When Scharf resolves a safe pinned replacement, the annotation includes the exact replacement.

SARIF output follows SARIF 2.1.0. It includes stable rule IDs, Unicode code-point columns, baseline state, accepted suppressions, and directly applicable replacements for safely editable references. Incomplete scans set `invocations[].executionSuccessful` to `false`, emit `SCHARF_SCAN_INCOMPLETE` notifications and results, retain successful findings, and return a nonzero status.

Upload a report with GitHub's code-scanning action:

```yaml
- name: Audit actions
  run: scharf audit . --baseline-ref origin/main --out sarif --output scharf.sarif --raise-error
  continue-on-error: true

- name: Upload Scharf SARIF
  uses: github/codeql-action/upload-sarif@<full-commit-sha>
  with:
    sarif_file: scharf.sarif
```

`--raise-error` fails only for blocking policy findings. Incomplete scans always fail, regardless of `--raise-error`, after writing available human, GitHub, or SARIF output.
