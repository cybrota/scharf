# Scharf
[![Go Report Card](https://goreportcard.com/badge/github.com/cybrota/scharf)](https://goreportcard.com/report/github.com/cybrota/scharf)

<picture width="500">
  <source
    width="600"
    media="(prefers-color-scheme: dark)"
    src="https://github.com/cybrota/sharfer/blob/main/scharf-logo-d.png"
    alt="Scarfer logo (dark)"
  />
  <img
    width="600"
    src="https://github.com/cybrota/sharfer/blob/main/scharf-logo-l.png"
    alt="Sharfer logo (light)"
  />
</picture>


Prevent supply-chain attacks for your third-party GitHub actions!


Scharf identifies all third-party CI/CD actions used in your Organization without pinned SHA-commits (Protect your CI/CD workflows from supply-chain attacks) creates a analytics-friendly report (CSV, JSON, Syslog) that can be passed to a SIEM system. In addition, Scharf also provides a quick way to inspect third-party actions by listing available tags and associated commit SHA.

## Why Scharf?

Scharf is a CLI tool to detect third-party GitHub actions with mutable references.

Scharf helps you maintain a secure development lifecycle by ensuring that all third-party actions are pinned to a specific commit SHA. This approach minimizes risks associated with dependency drifting and unintentional code modifications.

## Key Features of Scharf

* **Workflow Analysis**: Parse GitHub CI/CD workflows to identify usage of third-party actions.
* **Actionable Reports**: Generates detailed  JSON & CSV reports to help you quickly identify and remediate insecure references.
* **Easy SHA Lookup**: Fetch up-to-date SHA of a GitHub action to fix workflows found with mutable references.

## Installation

Install Scharf binary easily on Linux or Mac OS:

```sh
curl -sf https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/install.sh | sh
```

## Getting Started
Scharf comes with two types of commands to assist hardening of GitHub third-party actions.

1. Discovery Commands (audit, find)
2. Remediation Commands(lookup, list)

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
### Lookup: Qickly lookup SHA for a third-party GitHub action. Must include version
Ex:
```sh
scharf lookup actions/checkout@v4 // 11bd71901bbe5b1630ceea73d27597364c9af683

scharf lookup actions/setup-java@main // 3b6c050358614dd082e53cdbc55580431fc4e437

scharf lookup hashicorp/setup-terraform // 852ca175a624bfb8d1f41b0dbcf92b3556fbc25f, pins main branch as default
```

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

## Use Scharf in GitHub Actions to audit workflows

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
*  https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066

* https://alexwlchan.net/2025/github-actions-audit/

* https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
