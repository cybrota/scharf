# SCH-5 SHA Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `upgrade` and `upgrade-all-sha` commands to refresh pinned GitHub Action SHAs with a configurable cool-down period (default 24h).

**Architecture:** Extend the resolver to compute next versions and cool-down warnings, add strict scanning/replacement for Scharf-formatted pinned refs, and wire two new cobra commands in `main.go`. Keep `autofix` focused on mutable references and keep upgrade logic isolated.

**Tech Stack:** Go, Cobra CLI, existing scanner/network modules, `go test`, `go vet`.

---

### Task 1: Extend resolver with next-version and cool-down helpers

**Files:**
- Modify: `network/resolver.go`
- Test: `network/resolver_test.go`

- [ ] **Step 1: Write failing tests for next-version and cool-down behavior**

```go
func TestNextVersion(t *testing.T) {
    tags := []string{"v1.0.0", "v1.1.0", "v1.2.0"}
    got, found := nextVersion(tags, "v1.1.0")
    if !found || got != "v1.2.0" {
        t.Fatalf("got (%s,%v), want (v1.2.0,true)", got, found)
    }
}

func TestIsTagUnderCooldown(t *testing.T) {
    now := time.Now().UTC()
    fresh := now.Add(-2 * time.Hour)
    if !isUnderCooldown(fresh, 24) {
        t.Fatalf("expected fresh tag to be under cooldown")
    }
}
```

- [ ] **Step 2: Run targeted tests and confirm failure**

Run: `go test ./network -run "TestNextVersion|TestIsTagUnderCooldown"`
Expected: FAIL with undefined helper functions.

- [ ] **Step 3: Implement minimal helper functions in resolver**

```go
func nextVersion(tags []string, current string) (string, bool) {
    for i := range tags {
        if tags[i] == current && i+1 < len(tags) {
            return tags[i+1], true
        }
    }
    return "", false
}

func isUnderCooldown(tagTime time.Time, cooldownHours int) bool {
    if cooldownHours < 0 {
        cooldownHours = 0
    }
    return time.Since(tagTime) < time.Duration(cooldownHours)*time.Hour
}
```

- [ ] **Step 4: Add resolver APIs for upgrade use-cases**

```go
type UpgradeResult struct {
    Action         string
    CurrentVersion string
    CurrentSHA     string
    NextVersion    string
    NextSHA        string
    UnderCooldown  bool
}

func (s *SHAResolver) ResolveNext(action string, currentVersion string, cooldownHours int) (*UpgradeResult, error)
```

- [ ] **Step 5: Run resolver package tests**

Run: `go test ./network`
Expected: PASS

- [ ] **Step 6: Commit Task 1 changes**

```bash
git add network/resolver.go network/resolver_test.go
git commit -m "feat: add resolver helpers for sha upgrade flow"
```

### Task 2: Add pinned SHA parser and replacement flow for bulk upgrade

**Files:**
- Modify: `scanner/format.go`
- Modify: `scanner/audit.go`
- Create: `scanner/upgrade.go`
- Test: `scanner/audit_test.go`

- [ ] **Step 1: Write failing tests for strict Scharf pin parser**

```go
func TestParsePinnedRef(t *testing.T) {
    line := "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4"
    got, ok := ParsePinnedRef(line)
    if !ok {
        t.Fatalf("expected parse success")
    }
    if got.Action != "actions/checkout" || got.Version != "v4" {
        t.Fatalf("unexpected parse result: %+v", got)
    }
}
```

- [ ] **Step 2: Run scanner tests and confirm failure**

Run: `go test ./scanner -run TestParsePinnedRef`
Expected: FAIL with undefined `ParsePinnedRef`.

- [ ] **Step 3: Implement strict parser and candidate collection**

```go
var pinnedRefRegex = regexp.MustCompile(`([\w.-]+/[\w.-]+)@([a-f0-9]{40})\s+#\s+([^\s]+)`)

type PinnedRef struct {
    Action  string
    SHA     string
    Version string
}

func ParsePinnedRef(line string) (PinnedRef, bool)
func CollectPinnedRefs(content []byte) []Finding
```

- [ ] **Step 4: Implement upgrade replacement path with dry-run**

```go
func UpgradePinnedSHAs(path FilePath, cooldownHours int, isDryRun bool) error
```

Behavior in implementation:
- only process refs matching strict format
- compute next version/SHA via resolver
- print warning and continue when under cooldown
- skip ambiguous or no-next candidates with warning

- [ ] **Step 5: Run scanner package tests**

Run: `go test ./scanner`
Expected: PASS

- [ ] **Step 6: Commit Task 2 changes**

```bash
git add scanner/upgrade.go scanner/format.go scanner/audit.go scanner/audit_test.go
git commit -m "feat: add strict pinned sha scanning and upgrade flow"
```

### Task 3: Add CLI commands `upgrade` and `upgrade-all-sha`

**Files:**
- Modify: `main.go`
- Test: `network/resolver_test.go`
- Test: `scanner/audit_test.go`

- [ ] **Step 1: Write failing tests for single-upgrade input validation**

```go
func TestUpgradeRequiresFromVersionForSHAInput(t *testing.T) {
    err := validateUpgradeInput("actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
    if err == nil {
        t.Fatalf("expected error when --from-version missing")
    }
}
```

- [ ] **Step 2: Run targeted tests and confirm failure**

Run: `go test ./... -run TestUpgradeRequiresFromVersionForSHAInput`
Expected: FAIL with undefined validation helper.

- [ ] **Step 3: Implement command wiring and shared flags**

```go
var cmdUpgrade = &cobra.Command{
    Use:   "upgrade",
    Short: "Upgrade a pinned action SHA to next version",
}

var cmdUpgradeAllSHA = &cobra.Command{
    Use:   "upgrade-all-sha",
    Short: "Upgrade all Scharf-formatted pinned SHAs in workflows",
}
```

Flags to add:
- `--cooldown-hours` default `24`
- `--dry-run`
- `--from-version` on `upgrade`

- [ ] **Step 4: Run full test suite for command integration confidence**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 5: Commit Task 3 changes**

```bash
git add main.go network/resolver_test.go scanner/audit_test.go
git commit -m "feat: add upgrade and upgrade-all-sha commands"
```

### Task 4: Final validation, docs update, and safety checks

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README with new command usage examples**

```md
### Upgrade pinned SHA for one action
scharf upgrade actions/checkout@v4

### Upgrade all Scharf-formatted pinned SHAs in repo
scharf upgrade-all-sha . --cooldown-hours 24 --dry-run
```

- [ ] **Step 2: Run formatting/lint safety commands**

Run: `go test ./...`
Expected: PASS

Run: `go vet ./...`
Expected: PASS

Run: `govulncheck ./...`
Expected: PASS (or report if tool unavailable)

- [ ] **Step 3: Commit Task 4 changes**

```bash
git add README.md
git commit -m "docs: document sha upgrade commands"
```
