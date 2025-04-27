# Scharf
[![Go Report Card](https://goreportcard.com/badge/github.com/cybrota/scharf)](https://goreportcard.com/report/github.com/cybrota/scharf)

<picture width="500">
  <source
    width="100%"
    media="(prefers-color-scheme: dark)"
    src="https://github.com/cybrota/sharfer/blob/main/logo.png"
    alt="Scarfer logo (dark)"
  />
  <img
    width="100%"
    src="https://github.com/cybrota/sharfer/blob/main/logo.png"
    alt="Sharfer logo (light)"
  />
</picture>


Prevent supply-chain attacks from your third-party GitHub actions!


Scharf identifies & fixes all third-party CI/CD actions used in your Git repositories. It can also create an analytics-friendly report (CSV, JSON) about mutable tags across repositories. In addition, Scharf also provides a quick way to inspect third-party actions by listing available tags and associated commit SHA.

## Why Scharf?

Scharf is a CLI tool to detect and autofix third-party GitHub actions with mutable references.

Scharf helps you maintain a secure development lifecycle by ensuring that all third-party actions are pinned to a specific commit SHA. This approach minimizes risks associated with dependency drifting and unintentional code modifications to third-party GitHub actions.

## Key Features of Scharf

* **Autofix**: Identify & autofix mutable tags in workflows with GitHub third-party actions.
* **Easy SHA Lookup**: Fetch up-to-date SHA/s of a GitHub action without leaving your terminal.
* **Actionable Reports**: Generate detailed JSON & CSV reports to help you quickly identify and remediate insecure references. Works over multiple repositories.
* **Customization**: Look up either in HEAD reference or all branches while generating actionable reports.


## Supported Platforms
1. Linux (available)
2. Mac OSX (available)

## Installation

1. Download binary for your platform from release versions:

https://github.com/cybrota/scharf/releases

or

2. Easy install with below shell script (Requires `Curl` tool):

```sh
curl -sf https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/install.sh | sh
```

## Autofix: Auto-fixes vulnerable third-party GitHub actions in a GitHub repository

Navigate to a locally-cloned GitHub repository, and run:

Ex:
```sh
scharf autofix
```

```ascii
🪄 Fixing add-issue-header.yml:
  'actions/github-script@v7' -> 'actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7' ✅
🪄 Fixing build.yml:
  'actions/checkout@v4' -> 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4' ✅
  'actions/checkout@v4' -> 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4' ✅
  'actions/setup-python@v5' -> 'actions/setup-python@8d9ed9ac5c53483de85588cdf95a591a75ab9f55 # v5' ✅
  'actions/cache@v4' -> 'actions/cache@5a3ec84eff668545956fd18022155c47e93e2684 # v4' ✅
```

`Note`: This command may modify the file content which should be reviewed and committed to Git.

## Getting Started with other commands

Scharf comes with two types of commands to assist hardening of GitHub third-party actions.

1. Discovery Commands (audit, find)
2. Remediation Commands(list, lookup)

<hr />

## Discovery Commands

### Audit: Quickly check if your Git repository has any mutable references using `audit` command. This is useful for single repository
Ex:
```sh
scharf audit
```
Sample output:

```ascii
Mutable references found in your GitHub actions. Please replace them to secure your CI from supply chain attacks.
+---------------------+-------------------------------------------------------+------------------------------------------+
|        MATCH        |                       FILEPATH                        |             REPLACE WITH SHA             |
+---------------------+-------------------------------------------------------+------------------------------------------+
| actions/checkout@v4 | /Users/narenyellavula/scharf/.github/workflows/ci.yml | 11bd71901bbe5b1630ceea73d27597364c9af683 |
+---------------------+-------------------------------------------------------+------------------------------------------+
```

### Find:  Scan across multiple Git repositories and export results to a file. For example, clone all your organization GitHub repositories to a directory (Ex: workspace), and run:

This operation can include all branches in GitHub repositories (default). All branches excludes tags.

Ex Scan all branches:
```sh
scharf find --root=/path/to/workspace
```

This exports results to JSON. To export results to CSV, pass `--out csv` flag:

```sh
scharf find --root /path/to/workspace --out csv
```

Ex Only scan currently set HEAD in workspace repositories
```sh
scharf find --root=/path/to/workspace --head-only
```
<hr />

## Remediation Commands

### List: If you are unsure about a version, list all tags and Commit SHA of a given action (without version)
Ex:
```sh
scharf list tj-actions/changed-files
```

```ascii
+---------+------------------------------------------+
| VERSION |                COMMIT SHA                |
+---------+------------------------------------------+
| v46.0.3 | 823fcebdb31bb35fdf2229d9f769b400309430d0 |
| v46.0.2 | 26a38635fc1173cc5820336ce97be6188d0de9f5 |
| v46.0.1 | 2f7c5bfce28377bc069a65ba478de0a74aa0ca32 |
| v46.0.0 | 4cd184a1dd542b79cca1d4d7938e4154a6520ca7 |
| v46     | 823fcebdb31bb35fdf2229d9f769b400309430d0 |
| v45.0.9 | a284dc1814e3fd07f2e34267fc8f81227ed29fb8 |
| v45.0.8 | a284dc1814e3fd07f2e34267fc8f81227ed29fb8 |
| v45.0.7 | a284dc1814e3fd07f2e34267fc8f81227ed29fb8 |
| v45.0.6 | a284dc1814e3fd07f2e34267fc8f81227ed29fb8 |
| v45.0.5 | a284dc1814e3fd07f2e34267fc8f81227ed29fb8 |
| v45.0.4 | 4edd678ac3f81e2dc578756871e4d00c19191daf |
| v45.0.3 | c3a1bb2c992d77180ae65be6ae6c166cf40f857c |
| v45.0.2 | 48d8f15b2aaa3d255ca5af3eba4870f807ce6b3c |
| v45.0.1 | e9772d140489982e0e3704fea5ee93d536f1e275 |
| v45.0.0 | 40853de9f8ce2d6cfdc73c1b96f14e22ba44aec4 |
| v45     | 48d8f15b2aaa3d255ca5af3eba4870f807ce6b3c |
| v44.5.7 | c65cd883420fd2eb864698a825fc4162dd94482c |
| v44.5.6 | 6b2903bdce6310cfbddd87c418f253cf29b2dec9 |
| v44.5.5 | cc733854b1f224978ef800d29e4709d5ee2883e4 |
| v44.5.4 | cc3bbb0c526f8ee1d282f8c5f9f4e50745a5b457 |
| v44.5.3 | eaf854ef0c266753e1abec356dcf17d92695b251 |
| v44.5.2 | d6babd6899969df1a11d14c368283ea4436bca78 |
| v44.5.1 | 03334d095e2739fa9ac4034ec16f66d5d01e9eba |
| v44.5.0 | 1754cd4b9e661d1f0eced3b33545a8d8b3bc46d8 |
| v44.4.0 | a29e8b565651ce417abb5db7164b4a2ad8b6155c |
| v44.3.0 | 0874344d6ebbaa00a27da73276ae7162fadcaf69 |
| v44.2.0 | 4c5f5d698fbf2d763d5f13815ac7c2ccbef1ff7f |
| v44.1.0 | e052d30e1c0bdf27cd806b01ca3b393f47b50c62 |
| v44.0.1 | 635f118699dd888d737c15018cd30aff2e0274f8 |
| v44.0.0 | 2d756ea4c53f7f6b397767d8723b3a10a9f35bf2 |
+---------+------------------------------------------+
```

### Lookup: If you already know the version, qickly lookup SHA for a third-party GitHub action

Ex:
```sh
scharf lookup actions/checkout@v4 // 11bd71901bbe5b1630ceea73d27597364c9af683

scharf lookup actions/setup-java@main // 3b6c050358614dd082e53cdbc55580431fc4e437

scharf lookup hashicorp/setup-terraform // 852ca175a624bfb8d1f41b0dbcf92b3556fbc25f, pins main branch as default
```

## Integrating Scharf into GitHub Actions to continously audit workflows

Check the custom repository for adding Scharf as a third-party action auditor.

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
<hr />

## Why mutable tags in GitHub CI/CD workflows are bad ?

Using mutable references like tag-based or branch-based references in your CI/CD workflows can lead to unexpected changes or potential security vulnerabilities if the referenced action is compromised by malicious actors.

Scharf lets you identify and mitigate against supply-chain attacks similar to "tj-actions/changed-files" compromise occured in March 2025.

"GitHub's own official tutorials use tags instead of full commit shas. What a mess" - A YCombinator Hackernews Reader

"Github Actions is definitely a vector for abuse." - Another Hackernews Reader

## Further read:

Supply Chain Compromise of Third-Party tj-actions/changed-files:
- https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066

Whose code am I running in GitHub Actions?
- https://alexwlchan.net/2025/github-actions-audit/

GItHub CVE: tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs
* https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
