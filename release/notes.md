# Scharf v1.4.2

## GitHub Actions provenance and dependency audits

This release includes merged PRs #61 and #62 and their AI bug-pattern regression fixes. Existing direct audit and autofix defaults remain unchanged.

### New opt-in capabilities
- `--verify-provenance` checks direct action SHAs against current upstream branch histories, records stable repository identity and prior ref observations, and reports unexpected identity/ref movement. Available for audit, autofix, upgrade and upgrade-all-sha.
- `scharf audit <repo> --dependencies --out human|json|sarif` follows declarative composite-action and reusable-workflow dependencies at resolved commits, exposing mutable children behind pinned wrappers. It preserves caller chains and explicitly reports incomplete scans.
- Bounded API/metadata traversal, conservative YAML handling, rooted filesystem reads, escaped diagnostics and fail-closed preflight checks cover adversarial and changing inputs.

### Compatibility and limits
- Provenance is point-in-time upstream reachability, not proof of benign code or trusted maintainers. Historical observations are local trust-on-first-use data.
- Dependency audit is read-only. It excludes runtime downloads, package dependencies and container contents; Docker references are not traversed. Policy/baseline flags, transitive autofix and combined dependency/provenance mode are unsupported.
- Self-repository `$/` action syntax requires runner 2.336.0 or later.
- GitHub responses are not an atomic snapshot; workflow checks do not lock the working tree or make multi-file writes transactional.

See [provenance documentation](https://github.com/cybrota/scharf/blob/main/docs/provenance.md) and [dependency traversal design](https://github.com/cybrota/scharf/blob/main/docs/adr/004-declarative-dependency-traversal.md).
