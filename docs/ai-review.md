# Centralized-skills AI review (manual pilot)

The reviewer is a small, tool-free model runner, **not Scharf's scanner**. It reads
an open PR's changed-line patches and five centrally maintained skills, then
produces an advisory JSON artifact. It cannot run contributor code, write fixes,
post comments, approve PRs, merge or modify the skills repository. Normal builds
and tests do not need a model or API key.

## Enable after reviewing and merging this PR

1. In **Settings → Secrets and variables → Actions → New repository secret**, add
   **OPENAI_API_KEY** or **ANTHROPIC_API_KEY** for the provider you choose. Add the
   key yourself using GitHub's secure UI, never in a PR, configuration file or chat.
   Only the selected provider's secret is exposed to its review step. Use a
   dedicated restricted provider project/key, review provider data-handling terms,
   and configure provider-side spending controls. No keys are created or installed
   by this change.
2. In **Actions → Centralized skills AI review → Run workflow**, select **main**.
   Enter the open Scharf PR number, exact inspected head and base commit SHAs,
   provider (`openai` or `anthropic`) and an explicit model ID supported by your
   account. Obtain SHAs from the PR API, for example the read-only command:
   `gh api repos/cybrota/scharf/pulls/NUMBER --jq '{head: .head.sha, base: .base.sha}'`.
3. Inspect that exact diff for sensitive data, then check the transmission approval
   box. This authorizes sending the diff and skill text to the selected provider
   and making **one paid request**. No live request is made by merging alone.
4. Download the `ai-review-RUN-ATTEMPT` artifact. Open `ai-review-report.json` as
   plain text. Do not execute suggested commands or render its text as trusted
   HTML/Markdown. Confirm `freshness` is `current`, both SHAs still match and
   reproduce findings before acting. Suggestions are not a security verdict.

Provider keys are not interchangeable: other services need an explicitly reviewed
adapter with a fixed endpoint and tested request/response contract. There is no
custom endpoint, arbitrary plugin or model tool execution facility.

## Shared skills and project ownership

`.github/ai-review/skills.json` pins `narenaryan/agent-skills` at a full commit plus
SHA-256 for each selected file: AI bug patterns, RBVM applicability, priority
decisions, verified closure and security-gate rollout. The runner fetches only
those Markdown files directly from the pinned public revision; it never installs
or executes anything from the skills repository. A separate clone/cache is not
needed for five files. No floating branch or automatic skill update is accepted.

Update the commit and hashes in a reviewed PR. Skill suggestions cannot override
this project's rules or grant tool permissions. Agents improving shared guidance
should submit separate evidence-backed PRs to the central repository; this
reviewer does not do that automatically. Concurrent proposals remain independent
until reviewed; ordinary version-control conflict resolution and scenario tests
precede acceptance. A future triage agent is optional, not part of this pilot.

## Boundaries and limitations

- Manual dispatch on `main` only; trusted workflow revision, runner and config.
  PR files are fetched through GitHub's API, never checked out or executed. Fork
  PRs use the same data-only path. People who can modify trusted main/workflows or
  repository secrets remain trusted administrators; branch protections are not
  configured by this PR.
- GitHub permissions are only `contents: read` and `pull-requests: read`.
  Checkout does not persist credentials. No `pull_request_target`, PR comments,
  repository writes, persistent caches, package installs or background schedule.
- Maximum 60 changed files, 60,000 total prompt UTF-8 bytes, 4,096 output tokens,
  60-second HTTP timeout, five-minute job. At most one provider request, with no
  retries, redirects or fallback provider. These are resource limits, **not a
  dollar cap**. Re-dispatching can incur another charge; provider failures or
  timeouts may still be billed. Model rates/context limits vary.
- Missing/binary patches, mismatched additions/deletions, oversized inputs,
  altered skill digests and changed approved revisions fail closed. This is
  diff-only review, not whole-program analysis. GitHub patch completeness checks
  are conservative and not a replacement for inspecting the full diff.
- Sensitive-looking paths (including rename sources) and common private-key/API
  token patterns are rejected. This is deliberately **not a complete DLP/secret
  scanner**. Maintainers must inspect the approved diff; public repositories can
  still contain accidentally committed secrets. Known runtime keys are scrubbed
  from returned text, and raw provider responses/errors/prompts are not logged
  or uploaded. The report may quote source code from the already approved diff.
- Diff text, reference guidance and model findings are untrusted. Prompt injection
  can still distort review quality, but the model has no tools, credentials or
  write channel. Reports stay JSON strings, not workflow commands or PR comments.
- Base/head are checked before collection, before the paid call and afterward.
  Changes during a call mark the report stale; failed final checks preserve the
  paid result with `freshness: unknown` and fail the job. Freshness is a snapshot,
  not a lock: always check again before applying suggestions.
- OpenAI uses `store: false`; this is not a claim of zero provider retention.
  Anthropic account retention policies likewise apply. Artifact retention is
  seven days; access follows repository Actions permissions.

## Validation

Run `python3 -m unittest discover -s scripts -p 'ai_review_test.py'` without keys.
Tests mock every provider/GitHub call: input limits, missing/truncated patches,
rename filtering, injection-like filenames, pinned hashes, provider contracts,
redirect refusal, key redaction, revision mismatch and post-call uncertainty.
No live paid model quality, billing, secret setup or deployed Actions run is
claimed by these tests. Existing Go tests remain separate.

API references checked October 10, 2026:
- [OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create)
- [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create)
- [GitHub encrypted secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)
