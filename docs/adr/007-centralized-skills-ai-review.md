# ADR 007: Manual, tool-free centralized-skills review

## Context

Scharf should reuse institutional engineering/security guidance without giving
untrusted PRs, shared skill text or model outputs access to repository writes or
secrets. Provider choice must not force a new local agent installation.

## Decision

Use a manual main-branch Actions workflow and Python standard-library runner.
Fetch only commit/hash-pinned skill Markdown and PR API patches. Bind the
maintainer's transmission approval to exact base/head SHAs. Make at most one
bounded OpenAI Responses or Anthropic Messages request using the matching
Actions secret. Save untrusted findings as a JSON artifact, with provenance and
freshness; never execute model tools or contributor code. Require explicit model
selection and fail closed instead of truncating coverage silently.

## Alternatives and consequences

An autonomous coding agent has greater contextual reach but needs a much larger
execution/credential trust boundary. Automatic PR triggers and comments would
increase cost and permissions; defer them until the manual pilot proves useful.
Cloning all skills or adding a service/database/cache adds unnecessary state for
five pinned files. Shared guidance updates require reviewed pin/hash changes.

The trade-off is incomplete diff-only context and possible model errors. Human
validation and normal tests remain mandatory. Secrets and provider spending
controls are configured by the maintainer; merging this PR does not invoke AI.
See [operating instructions](../ai-review.md).
