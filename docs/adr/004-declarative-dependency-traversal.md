# ADR 004: Opt-in declarative dependency traversal

## Context
A SHA-pinned wrapper can call mutable children. The existing audit and autofix contracts concern direct workflow references; expanding them implicitly would add network access, change policy behavior and risk editing downloaded code.

## Decision
Add `audit --dependencies`, an independent read-only graph report (human, JSON or SARIF). The existing audit remains unchanged. Resolve each remote ref once per invocation, then read action metadata or reusable workflows at that full commit. Cache successful immutable content and retain every caller chain. `$/` is defining-repository-relative; workspace-relative `./` in remote composite actions is explicitly unresolved. Local reusable workflow calls retain their defining repository/commit.

Bound traversal to depth 12, 5,000 visited YAML structures/aliases/mapping keys (including repeated caller paths and invalid documents), 8 MiB of unique decoded metadata, 500 HTTP requests, 2 MiB per API response, 1 MiB per remote metadata file and 15 seconds per request. YAML merge keys, cycles, invalid references, inaccessible metadata and exhausted budgets produce incomplete reports. Structural work is charged even for run-only or malformed aliases; global node/byte exhaustion stops all remaining traversal. The depth boundary is checked before resolving or fetching a child. Files are never executed. Rooted file access keeps local symlinks inside the scanned repository, including concurrent symlink replacement; Unix opens also reject FIFOs without blocking; remote symlink objects are rejected. Redirects are refused, including for injected HTTP clients.

Graph mode rejects direct-policy, ignore and baseline flags rather than silently pretending those decisions cover transitive edges. `--raise-error` rejects mutable graph edges, and incomplete scans always return an error. JSON/SARIF carry source chains and incomplete status. There is no transitive autofix.

## Alternatives and limits
Do not recursively clone or execute third-party actions. Parsing declarative edges cannot discover runtime downloads, generated workflows, dependencies inside JS or Docker images, or establish source trust. Docker references are explicitly marked not traversed. A clean result means only that the traversed GitHub repository references were pinned. Provenance verification is separate work (#58).

Local root files are working-tree snapshots. API resolution uses GitHub.com content/commit endpoints and does not prove upstream reachability. Repository rename redirects intentionally remain unavailable. Conservative YAML merge handling may require manual review. `$/` requires GitHub runner 2.336.0+; Scharf reports its semantics without claiming the actual runner supports it.

## References
- https://docs.github.com/en/rest/repos/contents#get-repository-content
- https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
- https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/
- https://github.com/cybrota/scharf/issues/56
