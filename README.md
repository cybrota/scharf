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


Scharf identifies all third-party CI/CD actions used in your Organization without pinned SHA-commits (Protect your CI/CD workflows from supply-chain attacks) creates a analytics-friendly report (CSV, JSON, Syslog) that can be passed to a SIEM system. In addition, Scharf also provides an automatic SHA-commit recommendation for a given thrid-party action with version.

## Installation

Install Scharf binary easily on Linux or Mac OS:

```sh
curl -sf https://raw.githubusercontent.com/cybrota/scharf/refs/heads/main/install.sh | sh
```

## Getting Started
Scharf comes with two simple commands:
1. find
2. lookup

Clone all your organization GitHub repositories to a directory (Ex: workspace).

1. Find all actions (branches, tags) with mutable third-party action refereces.

```sh
scharf find --root=/path/to/workspace --out=json
```

To export results to CSV for analysis:

```sh
scharf find --root /path/to/workspace --out csv
```

2. Quickly lookup SHA for a given public, third-party GitHub action.
```sh
scharf lookup actions/checkout@v4 // 11bd71901bbe5b1630ceea73d27597364c9af683

scharf lookup actions/setup-java@main // 3b6c050358614dd082e53cdbc55580431fc4e437

scharf lookup hashicorp/setup-terraform // 852ca175a624bfb8d1f41b0dbcf92b3556fbc25f, pins main branch as default
```


## Why Scharf?

Scharf is a CLI tool to detect third-party GitHub actions with mutable references.

Scharf helps you maintain a secure development lifecycle by ensuring that all third-party actions are pinned to a specific commit SHA. This approach minimizes risks associated with dependency drifting and unintentional code modifications.

## Why mutable references in actions are bad for your GitHub CI/CD workflows ?

Using mutable references like version-based or branch-based references in your CI/CD workflows can lead to unexpected changes or potential security vulnerabilities if the referenced action is compromised by malicious actors.

Scharf lets you identify and mitigate against supply-chain attacks similar to "tj-actions/changed-files" compromise occured in March 2025.

"GitHub's own official tutorials use tags instead of full commit shas. What a mess" - A YCombinator Hackernews Reader

"Github Actions is definitely a vector for abuse." - Another Hackernews Reader

See:
- Supply Chain Compromise of Third-Party GitHub Action, CVE-2025-30066 https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066

- Whose code am I running in GitHub ? Actions?https://alexwlchan.net/2025/github-actions-audit/
- tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs.
https://github.com/advisories/ghsa-mrrh-fwg8-r2c3


Use Scharf to pro-actively avoid supply chain attacks which can exfiltrate sensitive data from CI/CD workflows and cause reputation damage.

## Key Features of Scharf

* **Workflow Analysis**: Parse GitHub CI/CD workflows to identify usage of third-party actions.
* **Actionable Reports**: Generates detailed CSv & JSON reports that help you quickly identify and remediate insecure references.
* **Easy SHA Lookup**: Fetch up-to-date SHA of a GitHub action to fix workflows found with mutable references.
