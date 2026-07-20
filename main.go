// clouddrift — Cloud IAM Drift Detector
//
// Compares two AWS IAM snapshots and flags unauthorized changes:
// new users/roles, privilege escalation, policy mutations, trust policy changes.
//
// Usage:
//   # 1. Capture baseline (store in version control or S3)
//   aws iam get-account-authorization-details > baseline.json
//
//   # 2. Later, capture current state
//   aws iam get-account-authorization-details > current.json
//
//   # 3. Detect drift
//   go run main.go baseline.json current.json
//
// Exits code 1 if CRITICAL or HIGH drift found (CI/CD safe).
// Zero external dependencies — stdlib only.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ── ANSI Colors ───────────────────────────────────────────────────────────────

const (
	colorRed    = "\033[91m"
	colorYellow = "\033[93m"
	colorGreen  = "\033[92m"
	colorCyan   = "\033[96m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

// ── Data Structures ───────────────────────────────────────────────────────────
//
// These mirror the output of:
//   aws iam get-account-authorization-details
//
// The JSON contains three lists: users, roles, and groups.
// Each has its own attached managed policies and inline policies.

type IAMSnapshot struct {
	UserDetailList  []UserDetail  `json:"UserDetailList"`
	RoleDetailList  []RoleDetail  `json:"RoleDetailList"`
	GroupDetailList []GroupDetail `json:"GroupDetailList"`
}

type UserDetail struct {
	UserName                string        `json:"UserName"`
	Arn                     string        `json:"Arn"`
	AttachedManagedPolicies []PolicyRef   `json:"AttachedManagedPolicies"`
	UserPolicyList          []InlinePolicy `json:"UserPolicyList"`
	GroupList               []string      `json:"GroupList"`
}

type RoleDetail struct {
	RoleName                string        `json:"RoleName"`
	Arn                     string        `json:"Arn"`
	AssumeRolePolicyDocument string       `json:"AssumeRolePolicyDocument"`
	AttachedManagedPolicies []PolicyRef   `json:"AttachedManagedPolicies"`
	RolePolicyList          []InlinePolicy `json:"RolePolicyList"`
}

type GroupDetail struct {
	GroupName               string        `json:"GroupName"`
	AttachedManagedPolicies []PolicyRef   `json:"AttachedManagedPolicies"`
	GroupPolicyList         []InlinePolicy `json:"GroupPolicyList"`
}

// PolicyRef is a reference to a managed policy by ARN.
type PolicyRef struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// InlinePolicy is an inline policy embedded directly on the principal.
type InlinePolicy struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument string `json:"PolicyDocument"`
}

// ── Findings ──────────────────────────────────────────────────────────────────

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var sevOrder = map[Severity]int{
	Critical: 0, High: 1, Medium: 2, Low: 3,
}

type Finding struct {
	Severity Severity
	Entity   string // e.g. User/alice, Role/LambdaExec
	Rule     string // e.g. NEW_IAM_USER
	Detail   string // human explanation
}

// ── Snapshot Loading ──────────────────────────────────────────────────────────

func loadSnapshot(path string) (*IAMSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var snap IAMSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}
	return &snap, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// policyMap converts a slice of PolicyRef into a map[arn]policyName
// so we can do O(1) lookups when comparing baseline vs current.
func policyMap(refs []PolicyRef) map[string]string {
	m := make(map[string]string, len(refs))
	for _, p := range refs {
		m[p.PolicyArn] = p.PolicyName
	}
	return m
}

// stringSet converts a string slice to a set for fast membership checks.
func stringSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// isAdminPolicy returns true for known AWS admin-level managed policies.
// Attaching these is an immediate privilege escalation signal.
func isAdminPolicy(arn string) bool {
	adminARNs := map[string]bool{
		"arn:aws:iam::aws:policy/AdministratorAccess": true,
		"arn:aws:iam::aws:policy/IAMFullAccess":       true,
		"arn:aws:iam::aws:policy/PowerUserAccess":     true,
	}
	return adminARNs[arn]
}

// ── Rules ─────────────────────────────────────────────────────────────────────

// compareUsers detects:
//   - New IAM users (especially ones immediately given admin rights)
//   - Deleted IAM users
//   - Newly attached/detached managed policies on existing users
//   - Group membership changes (users added to new groups)
func compareUsers(base, curr *IAMSnapshot) []Finding {
	var findings []Finding

	// Index both snapshots by username for fast lookup
	baseMap := make(map[string]UserDetail, len(base.UserDetailList))
	for _, u := range base.UserDetailList {
		baseMap[u.UserName] = u
	}
	currMap := make(map[string]UserDetail, len(curr.UserDetailList))
	for _, u := range curr.UserDetailList {
		currMap[u.UserName] = u
	}

	// Detect new users
	for name, u := range currMap {
		if _, existed := baseMap[name]; existed {
			continue
		}
		sev    := Medium
		detail := fmt.Sprintf("New IAM user %s created (%s)", name, u.Arn)
		// Escalate if new user immediately has an admin policy
		for _, p := range u.AttachedManagedPolicies {
			if isAdminPolicy(p.PolicyArn) {
				sev = Critical
				detail += fmt.Sprintf(" — immediately has admin policy %s", p.PolicyName)
				break
			}
		}
		findings = append(findings, Finding{
			Severity: sev,
			Entity:   "User/" + name,
			Rule:     "NEW_IAM_USER",
			Detail:   detail,
		})
	}

	// Detect deleted users (low severity — could be offboarding)
	for name := range baseMap {
		if _, exists := currMap[name]; !exists {
			findings = append(findings, Finding{
				Severity: Low,
				Entity:   "User/" + name,
				Rule:     "IAM_USER_DELETED",
				Detail:   fmt.Sprintf("IAM user %s was deleted — verify this was intentional", name),
			})
		}
	}

	// Detect policy and group changes on existing users
	for name, u := range currMap {
		b, existed := baseMap[name]
		if !existed {
			continue
		}

		basePolicies := policyMap(b.AttachedManagedPolicies)
		currPolicies := policyMap(u.AttachedManagedPolicies)

		// Newly attached policies
		for arn, pname := range currPolicies {
			if _, had := basePolicies[arn]; had {
				continue
			}
			sev := Medium
			if isAdminPolicy(arn) {
				sev = Critical
			}
			findings = append(findings, Finding{
				Severity: sev,
				Entity:   "User/" + name,
				Rule:     "POLICY_ATTACHED_TO_USER",
				Detail:   fmt.Sprintf("Policy %s (%s) newly attached to user %s", pname, arn, name),
			})
		}

		// Detached policies
		for arn, pname := range basePolicies {
			if _, still := currPolicies[arn]; !still {
				findings = append(findings, Finding{
					Severity: Low,
					Entity:   "User/" + name,
					Rule:     "POLICY_DETACHED_FROM_USER",
					Detail:   fmt.Sprintf("Policy %s detached from user %s", pname, name),
				})
			}
		}

		// Group membership changes
		baseGroups := stringSet(b.GroupList)
		for _, g := range u.GroupList {
			if !baseGroups[g] {
				findings = append(findings, Finding{
					Severity: Medium,
					Entity:   "User/" + name,
					Rule:     "USER_GROUP_ADDED",
					Detail:   fmt.Sprintf("User %s added to group %s — verify group permissions", name, g),
				})
			}
		}
	}

	return findings
}

// compareRoles detects:
//   - New IAM roles (especially those with admin rights at creation)
//   - Newly attached policies on existing roles
//   - Trust policy changes (who can assume this role)
func compareRoles(base, curr *IAMSnapshot) []Finding {
	var findings []Finding

	baseMap := make(map[string]RoleDetail, len(base.RoleDetailList))
	for _, r := range base.RoleDetailList {
		baseMap[r.RoleName] = r
	}
	currMap := make(map[string]RoleDetail, len(curr.RoleDetailList))
	for _, r := range curr.RoleDetailList {
		currMap[r.RoleName] = r
	}

	// Detect new roles
	for name, r := range currMap {
		if _, existed := baseMap[name]; existed {
			continue
		}
		sev    := Low
		detail := fmt.Sprintf("New IAM role %s created (%s)", name, r.Arn)
		for _, p := range r.AttachedManagedPolicies {
			if isAdminPolicy(p.PolicyArn) {
				sev = High
				detail += fmt.Sprintf(" — has admin policy %s at creation", p.PolicyName)
				break
			}
		}
		findings = append(findings, Finding{
			Severity: sev,
			Entity:   "Role/" + name,
			Rule:     "NEW_IAM_ROLE",
			Detail:   detail,
		})
	}

	// Detect policy and trust policy changes on existing roles
	for name, r := range currMap {
		b, existed := baseMap[name]
		if !existed {
			continue
		}

		basePolicies := policyMap(b.AttachedManagedPolicies)
		currPolicies := policyMap(r.AttachedManagedPolicies)

		for arn, pname := range currPolicies {
			if _, had := basePolicies[arn]; had {
				continue
			}
			sev := Medium
			if isAdminPolicy(arn) {
				sev = Critical
			}
			findings = append(findings, Finding{
				Severity: sev,
				Entity:   "Role/" + name,
				Rule:     "POLICY_ATTACHED_TO_ROLE",
				Detail:   fmt.Sprintf("Policy %s (%s) newly attached to role %s", pname, arn, name),
			})
		}

		// Trust policy controls who can call sts:AssumeRole on this role.
		// Any change here is high-severity — it means a new principal can now
		// impersonate this role, potentially crossing account or service boundaries.
		if r.AssumeRolePolicyDocument != b.AssumeRolePolicyDocument {
			findings = append(findings, Finding{
				Severity: High,
				Entity:   "Role/" + name,
				Rule:     "TRUST_POLICY_CHANGED",
				Detail: fmt.Sprintf(
					"Trust policy on role %s changed — verify who can now call sts:AssumeRole on it", name),
			})
		}
	}

	return findings
}

// ── Output ────────────────────────────────────────────────────────────────────

func sevColor(s Severity) string {
	switch s {
	case Critical:
		return colorRed + colorBold
	case High:
		return colorRed
	case Medium:
		return colorYellow
	default:
		return colorCyan
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func printFindings(findings []Finding) {
	if len(findings) == 0 {
		fmt.Printf("\n%s✓ No IAM drift detected%s\n\n", colorGreen, colorReset)
		return
	}

	// Sort by severity then entity name
	sort.Slice(findings, func(i, j int) bool {
		oi := sevOrder[findings[i].Severity]
		oj := sevOrder[findings[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return findings[i].Entity < findings[j].Entity
	})

	// Count by severity
	counts := make(map[Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	width := 72
	fmt.Printf("\n%s  CLOUDDRIFT  (%d finding%s)%s\n",
		colorBold, len(findings), pluralS(len(findings)), colorReset)
	fmt.Printf("  %s\n", strings.Repeat("─", width))
	fmt.Printf("  %-12s %-30s %s\n", "SEVERITY", "RULE", "ENTITY")
	fmt.Printf("  %s\n", strings.Repeat("─", width))

	for _, f := range findings {
		c := sevColor(f.Severity)
		fmt.Printf("  %s%-12s%s %-30s %s\n", c, f.Severity, colorReset, f.Rule, f.Entity)
		fmt.Printf("             %s↳ %s%s\n\n", colorCyan, f.Detail, colorReset)
	}

	fmt.Printf("  %s\n  Summary: ", strings.Repeat("─", width))
	for _, sev := range []Severity{Critical, High, Medium, Low} {
		if n, ok := counts[sev]; ok {
			fmt.Printf("%s%d %s%s  ", sevColor(sev), n, sev, colorReset)
		}
	}
	fmt.Println("\n")
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("\n%sclouddrift%s — Cloud IAM Drift Detector\n\n", colorBold, colorReset)
		fmt.Println("Usage:")
		fmt.Println("  # Capture baseline (store in S3 or git)")
		fmt.Println("  aws iam get-account-authorization-details > baseline.json")
		fmt.Println()
		fmt.Println("  # Capture current state")
		fmt.Println("  aws iam get-account-authorization-details > current.json")
		fmt.Println()
		fmt.Println("  # Detect drift")
		fmt.Println("  go run main.go baseline.json current.json")
		fmt.Println()
		fmt.Println("Exits code 1 if CRITICAL or HIGH drift found (CI/CD safe).")
		fmt.Println()
		os.Exit(0)
	}

	baseline, err := loadSnapshot(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError loading baseline: %v%s\n", colorRed, err, colorReset)
		os.Exit(2)
	}
	current, err := loadSnapshot(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError loading current: %v%s\n", colorRed, err, colorReset)
		os.Exit(2)
	}

	fmt.Printf("%sBaseline:%s %s\n", colorBold, colorReset, os.Args[1])
	fmt.Printf("%sCurrent: %s %s\n", colorBold, colorReset, os.Args[2])

	var findings []Finding
	findings = append(findings, compareUsers(baseline, current)...)
	findings = append(findings, compareRoles(baseline, current)...)

	printFindings(findings)

	// Exit 1 if any CRITICAL or HIGH — gates the CI/CD pipeline
	for _, f := range findings {
		if f.Severity == Critical || f.Severity == High {
			os.Exit(1)
		}
	}
}
