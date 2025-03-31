# Scharf
[![Go Report Card](https://goreportcard.com/badge/github.com/cybrota/sharfer)](https://goreportcard.com/report/github.com/cybrota/sharfer)

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


Scharf identifies all third-party CI/CD actions used in your Organization without pinned SHA-commits (Protect your CI/CD workflows from supply-chain attacks) creates a analytics-friendly report (CSV, JSON, Syslog) that can be passed to a SIEM system.

In addition, Scharf also provides an automatic SHA-commit recommendation for a given thrid-party action with version.

Install Scharf binary easily on Linux or Mac OS via gobinaries.com:

```sh
curl -sf https://gobinaries.com/cybrota/scharf | sh
```

and generate a CSV report of your Git workspace, where root is workspace folder that stores all GitHub repositories:

```sh
scharf run --root=/path/to/workspace --out=csv
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

* **Repository Discovery**: Automatically scan all repositories in a given GitHub organization.
* **Workflow Analysis**: Parse GitHub CI/CD workflows to identify usage of third-party actions.
* **Security Flags**: Detect and flag actions that reference versions via tags or branches instead of immutable SHA commits.
* **Customizable Scanning**: Specify organization and project filters to fine-tune your security audits.
* **Actionable Reports**: Generates detailed CSv & JSON reports that help you quickly identify and remediate insecure references.
* **Easy Integration**: Integrate Scharf into your CI/CD pipelines for continuous security validation of workflow files.


## Getting Started
TBD

### Installing Scharf
TBD
