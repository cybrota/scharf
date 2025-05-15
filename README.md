# Scharf
[![Go Report Card](https://goreportcard.com/badge/github.com/cybrota/scharf)](https://goreportcard.com/report/github.com/cybrota/scharf)

<picture width="500">
  <source
    width="100%"
    media="(prefers-color-scheme: dark)"
    src="https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/logo.png"
    alt="Scharf logo (dark)"
  />
  <img
    width="100%"
    src="https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/logo.png"
    alt="Scharf logo (light)"
  />
</picture>


Secure your CI/CD pipeline against supply-chain attacks on third-party GitHub Actions.

Scharf scans your workflows, identifies mutable action references, and replaces them with immutable commit SHAs. It also generates comprehensive CSV or JSON reports across repositories and lets you inspect available tags and SHAs without leaving your terminal.

## Why Use Scharf?

By pinning every third-party action to a specific commit SHA, Scharf prevents unexpected or malicious changes from creeping into your CI/CD process. This ensures a stable and secure development lifecycle by eliminating risks tied to drifting dependencies and mutable tags.

third-party GitHub actions.

## Key Features

* Autofix Workflows: Detect and update mutable action tags to their corresponding SHAs in your workflow files.

* Quick SHA Lookup: Retrieve the latest commit SHA for any GitHub Action directly from the CLI.

* Actionable Reports: Produce JSON or CSV reports that highlight insecure references across one or many repositories.

* Custom Scopes: Choose to scan only the current HEAD or include all branches when you audit or find actions.


## Supported Platforms

* Linux
* Mac OSX

## Installation
**Option 1**: Install quickly via HomeBrew (Needs Brew installed)

```sh
# Tap brew formula
brew tap cybrota/cybrota

# Install scharf
brew install scharf
```

**Option 2**: Download Prebuilt Binary

Visit the releases page and download the binary for your OS:

https://github.com/cybrota/scharf/releases

**Option 3**: Install via Script

```sh
curl -sf https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/install.sh | sh
```

This script installs the latest version automatically (requires curl).

## Usage Examples

### 1. Autofix Mutable Actions

Point to a Git repository, run:
```sh
# Auto fix a local repository
scharf autofix git_repo
```

Note: By default audit looks for current directory (.) if repo is not passed.

Scharf rewrites your workflow file, replacing, for example:
```sh
actions/github-script@v7 ➔ actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7
```
Include --dry-run to preview changes without modifying files:
```sh
scharf autofix git_repo --dry-run
```

### 2. Audit a Single Repository
Scan for mutable references in your current repository:
```sh
# Audit a local repository
scharf audit git_repo

# Audit a remote repository. This automatically clones remote to /tmp location with scharf-* prefix
scharf audit https_or_git_url
```

The output lists each insecure tag, its file location, and the SHA you should pin. You can pass `--raise-error` flag to return a Non-zero error code.

### 3. Find Across Many Repos
Point Scharf at a directory of cloned repositories to scan multiple projects:
```sh
scharf find --root /path/to/workspace --out csv
```
Add `--head-only` flag to limit scanning to each repo’s current HEAD, or omit it to include all branches.

### 4. List Available Tags and SHAs
If you need to explore versions before pinning, run:
```sh
scharf list owner/repo
# Ex: scharf list tj-actions/changed-files
```
This command prints a table of tags and their corresponding commit SHAs.

### 5. Lookup a Specific SHA
When you know a tag and want its SHA, use:
```sh
scharf lookup owner/repo@version
# Ex: scharf lookup actions/checkout@v4
```

## CI Integration

Embed Scharf in your GitHub Actions workflow to enforce secure references automatically:

See this repository for more details:
[https://github.com/cybrota/scharf-action](https://github.com/cybrota/scharf-action)

```yaml
jobs:
  my-job:
    runs-on: ubuntu-22.04

    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Audit GitHub actions
        uses: cybrota/scharf-action@c0d0eb13ca383e5a3ec947d754f61c9e61fab5ba
        with:
          raise-error: true
```

## The Risk of Mutable Tags

Mutable tags (e.g., @v1 or @main) allow action authors to push new code without changing your workflow. If a tag gets compromised, your CI can run malicious code. Scharf eliminates this vulnerability by always pinning to a specific, audited commit.

## TODO for Scharf
Check Issues Tab on GitHub

## Further Reading:

Supply Chain Compromise of Third-Party tj-actions/changed-files:
- https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066

Whose code am I running in GitHub Actions?
- https://alexwlchan.net/2025/github-actions-audit/

GItHub CVE: tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs
* https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
