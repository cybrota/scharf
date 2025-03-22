# Sharfer
![Logo](https://github.com/cybrota/sharfer/blob/main/sharfer-logo.png)

Identify all third-party CI/CD actions used in your Organization without pinned SHA-commits using Sharfer (SHA Rectifier for CI/CD workflows). Sharfer is a CLI tool designed to audit GitHub and GitLab repositories within a specified organization for action workflows that use third-party actions without SHA-based references.
In other words, Sharfer flags all actions those are version-based or branch-based, helping you enforce secure dependency pinning in your CI/CD pipelines.

## Key Features of Sharfer

* **Repository Discovery**: Automatically scan all repositories in a given GitHub or GitLab organization.
* **Workflow Analysis**: Parse GitHub and GitLab CI/CD configurations to identify usage of third-party actions.
* **Security Flags**: Detect and flag actions that reference versions via tags or branches instead of immutable SHA commits.
* **Customizable Scanning**: Specify organization and project filters to fine-tune your security audits.
* **Actionable Reports**: Generate detailed CSV report that help you quickly identify and remediate insecure references.
* **Bring your favorite VCS**: Works seamlessly with both GitHub and GitLab repositories.
* **Easy Integration**: Integrate Sharfer into your CI/CD pipelines for continuous security validation of workflow files.

## Why Use Sharfer?

Using version-based or branch-based references in your CI/CD workflows can lead to unexpected changes or potential security vulnerabilities if the referenced action is updated maliciously.
Sharfer helps you maintain a secure development lifecycle by ensuring that all third-party actions are pinned to a specific commit SHA. This approach minimizes risks associated with dependency drifting and unintentional code modifications.

Sharfer lets you identify and mitigate against supply-chain attacks like "tj-actions/changed-files". See:
- https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- https://github.com/advisories/ghsa-mrrh-fwg8-r2c3

for how supply chain attacks can exfiltrate sensitive data from CI/CD workflows.

## Getting Started
TBD

### Installing Sharfer
TBD
