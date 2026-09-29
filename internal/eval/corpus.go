package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/use-assay/assay/internal/mechanics"
)

// metadataFile is the name of the machine-readable metadata file per subject.
const metadataFile = "metadata.json"

// metadata is the structure of the per-subject metadata JSON file.
type metadata struct {
	CaptureTimestamp string               `json:"capture_timestamp"`
	Sources          map[string]sourceInfo `json:"sources"`
	Expected         expectedInfo          `json:"expected"`
	PerCheck         map[string]checkInfo  `json:"per_check"`
	Why              string                `json:"why"`
}

type sourceInfo struct {
	URL        string `json:"url"`
	CapturedAt string `json:"captured_at"`
}

type expectedInfo struct {
	Base          string `json:"base"`
	Severity      string `json:"severity"`
	Escalated     bool   `json:"escalated"`
	Accountability string `json:"accountability"`
}

type checkInfo struct {
	Undetermined bool   `json:"undetermined"`
	Severity     string `json:"severity"`
	Escalation   bool   `json:"escalation"`
	Mechanics    string `json:"mechanics"`
}

// severityFromString converts a severity string ("clear", "low", "medium", "high", "critical")
// to a mechanics.Severity value.
func severityFromString(s string) mechanics.Severity {
	// Use json.Unmarshal to parse the severity string, which leverages the
	// existing UnmarshalJSON implementation on mechanics.Severity.
	var sev mechanics.Severity
	if err := json.Unmarshal([]byte(`"`+s+`"`), &sev); err != nil {
		panic(fmt.Sprintf("unknown severity: %s", s))
	}
	return sev
}

// mechanicFromString converts a mechanics name string (e.g. "auth_revocable")
// to a mechanics.Mechanic bit. It uses a mapping from metadata-style names
// (which use underscores and can be pipe-separated for multiple mechanics)
// to the code's Mechanic bit constants.
func mechanicFromString(s string) mechanics.Mechanic {
	// Map metadata mechanic names to the code's Mechanic bit constants.
	// Metadata uses underscores and can list multiple mechanics pipe-separated.
	nameMap := map[string]mechanics.Mechanic{
		"auth_required":                mechanics.MechAuthRequired,
		"auth_revocable":               mechanics.MechAuthRevocable,
		"clawback_enabled":             mechanics.MechClawbackEnabled,
		"auth_clawback_enabled":        mechanics.MechClawbackEnabled,
		"auth_immutable":               mechanics.MechFlagsLocked,
		"flags_locked":                 mechanics.MechFlagsLocked,
		"domain_unverified":            mechanics.MechDomainUnverified,
		"blocklisted":                  mechanics.MechBlocklisted,
		"trustline_clawback_enabled":   mechanics.MechTrustlineClawbackEnabled,
		"trustline_deauthorized":       mechanics.MechTrustlineDeauthorized,
	}

	// Handle pipe-separated multiple mechanics (bitwise OR)
	if strings.Contains(s, "|") {
		parts := strings.Split(s, "|")
		var result mechanics.Mechanic
		for _, part := range parts {
			bit, ok := nameMap[strings.TrimSpace(part)]
			if !ok {
				panic(fmt.Sprintf("unknown mechanic: %s", part))
			}
			result |= bit
		}
		return result
	}

	bit, ok := nameMap[s]
	if !ok {
		panic(fmt.Sprintf("unknown mechanic: %s", s))
	}
	return bit
}

// Label is the expected classification of one corpus subject.
// It carries the aggregate expectation (Base/Severity/Escalated/Accountability)
// and the per-check expectations (Checks) that #115 requires, so a wrong check
// cannot hide behind a right total.
//
// The rationale for each label is documented in docs/eval.md and repeated in the
// why field of each subject's metadata.json.
type Label struct {
	// Dir is the fixture directory under the corpus root.
	Dir string
	// Why states what the subject proves. It is printed on failure so a
	// maintainer learns what they broke rather than only seeing a number move.
	Why string

	Base           mechanics.Severity
	Severity       mechanics.Severity
	Escalated      bool
	Accountability mechanics.Accountability

	// Checks carries per-check expectations keyed by check ID. A subject with
	// an empty map is reported as partially evaluated rather than silently
	// passing.
	Checks map[string]CheckLabel
}

// CheckLabel is the expected output of one check on one subject.
//
// Undetermined and Severity are separate labels on purpose: a check that could
// not conclude is compared against an undetermined label, not against a
// severity, because an undetermined finding makes no severity claim and
// comparing it to one would measure a value the check never produced.
type CheckLabel struct {
	// Undetermined asserts whether the check could not conclude.
	Undetermined bool
	// Severity is the expected level for a determined check.
	Severity mechanics.Severity
	// Escalation pins the finding's escalation flag.
	Escalation bool
	// Mechanics pins the finding's mechanic bitset exactly.
	Mechanics mechanics.Mechanic
}

// LoadLabel reads the metadata.json for a subject and returns a Label.
// If the metadata file is missing or unreadable, it returns an error
// so the caller can fail the test explicitly.
func LoadLabel(dir string, fixturesDir string) (Label, error) {
	base := filepath.Join(fixturesDir, dir, metadataFile)

	data, err := os.ReadFile(base)
	if err != nil {
		return Label{}, fmt.Errorf("read %s: %w", base, err)
	}

	var md metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return Label{}, fmt.Errorf("parse %s: %w", base, err)
	}

	label := Label{
		Dir:       dir,
		Why:       md.Why,
		Base:      severityFromString(md.Expected.Base),
		Severity:  severityFromString(md.Expected.Severity),
		Escalated: md.Expected.Escalated,
	}

	// Map accountability string to enum
	acc := mechanics.AccountabilityUnverified
	switch strings.ToLower(md.Expected.Accountability) {
	case "verified":
		acc = mechanics.AccountabilityVerified
	case "unverified":
		acc = mechanics.AccountabilityUnverified
	}
	label.Accountability = acc

	// Build per-check labels
	label.Checks = make(map[string]CheckLabel)
	for checkID, cl := range md.PerCheck {
		checkLabel := CheckLabel{
			Undetermined: cl.Undetermined,
			Severity:     severityFromString(cl.Severity),
			Escalation:   cl.Escalation,
		}
		if cl.Mechanics != "" {
			checkLabel.Mechanics = mechanicFromString(cl.Mechanics)
		}
		label.Checks[checkID] = checkLabel
	}

	return label, nil
}

// Corpus is the labelled set. Every subject is a real pubnet asset; fixtures
// and provenance are under internal/mechanics/testdata, and each subject's
// metadata.json replaces the previously hardcoded labels in this package's
// Corpus() function returning a []Label.
//
// Per-file capture dates are recorded in each subject's metadata.json rather
// than one date for the whole set. A subject lacking metadata.json fails the
// eval, so the two cannot drift apart.
//
// fixturesDir is the directory containing subject subdirectories with
// metadata.json files; defaults to "../mechanics/testdata" when not provided.
func Corpus(fixturesDir ...string) []Label {
	// Known subjects (from the former hardcoded list). These are ordered
	// deliberately: TestEval and TestEvalPerCheck iterate this slice, and
	// the per-check evaluator uses the Checks map keys to identify which
	// checks a subject covers.
	subjects := []string{
		"aqua-clear-verified",
		"shx-clear-flagslocked",
		"xrp-clear-unlocked",
		"usdc-revocable-regulated",
		"berkshire-clawback-scam",
		"doge-noflags-scam",
// The per-check labels are derived from the same fixtures the aggregate labels
// are, so the two cannot describe different runs: TestEval and TestEvalPerCheck
// both iterate this corpus.
func Corpus() []Label {
	return []Label{
		{
			Dir: "aqua-clear-verified",
			Why: "no auth flags at all: the issuer has no power over holders, and a " +
				"reciprocal domain confirms who it is",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "shx-clear-flagslocked",
			Why: "no auth flags AND auth_immutable: the issuer can never add freeze " +
				"or clawback later",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear, Mechanics: mechanics.MechFlagsLocked},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "xrp-clear-unlocked",
			Why: "the unlocked counterpart to SHX: no auth flags, but auth_immutable " +
				"is UNSET. The mutability finding must report that without moving " +
				"base severity off clear.",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "usdz-clawback-regulated",
			Why: "the confirmed-legitimate clawback control asset (docs/eval.md " +
				"coverage-gaps). USDZ (Zeam Money, zeam.money) carries both " +
				"auth_revocable and auth_clawback_enabled, so capability alone " +
				"puts it at high — and it must NOT be escalated: the domain " +
				"publishes a reciprocal stellar.toml that names the exact issuer, " +
				"the directory tag is 'issuer' (not 'malicious'), and no " +
				"blocklist entry exists. The severity model's central claim is " +
				"that it treats legitimate clawback fairly; this subject is the " +
				"only one in the set that measures that claim.",
			Base:           mechanics.High,
			Severity:       mechanics.High,
			Escalated:      false,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability": {
					Severity:  mechanics.High,
					Mechanics: mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled,
				},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "usdc-revocable-regulated",
			Why: "a real regulated stablecoin that legitimately uses auth_revocable. It " +
				"must report freeze-capable (medium) on the strength of the flag alone.",
			Base:           mechanics.Medium,
			Severity:       mechanics.Medium,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability": {Severity: mechanics.Medium, Mechanics: mechanics.MechAuthRevocable},
				"mutability": {Severity: mechanics.Clear},
				// circle.com does not serve a stellar.toml, so the reciprocal
				// claim genuinely fails and the unverified bit is set.
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "berkshire-clawback-scam",
			Why: "impersonation asset with clawback: capability alone puts it at high, " +
				"and the curated malicious tag escalates it to critical",
			Base:           mechanics.High,
			Severity:       mechanics.Critical,
			Escalated:      true,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability": {
					Severity:  mechanics.High,
					Mechanics: mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled,
				},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation": {
					Severity:   mechanics.Critical,
					Escalation: true,
					Mechanics:  mechanics.MechBlocklisted,
				},
			},
		},
		{
			Dir: "doge-noflags-scam",
			Why: "the case that justifies keeping reputation as a separate upward-only " +
				"axis: a known scam asset carrying NO auth flags. Capability is honestly " +
				"clear, and escalation is the only thing that catches it. This is also " +
				"the fixture the check-suppression test uses, because it is the case " +
				"with the largest consequence.",
			Base:           mechanics.Clear,
			Severity:       mechanics.Critical,
			Escalated:      true,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation": {
					Severity:   mechanics.Critical,
					Escalation: true,
					Mechanics:  mechanics.MechBlocklisted,
				},
			},
		},
	}

	fd := "../mechanics/testdata"
	if len(fixturesDir) > 0 {
		fd = fixturesDir[0]
	}

	var labels []Label
	for _, dir := range subjects {
		ld, err := LoadLabel(dir, fd)
		if err != nil {
			// If a subject has no metadata, the test fails fast with a
			// clear message rather than silently passing or producing
			// garbage labels.
			panic(fmt.Sprintf("subject %s: %v", dir, err))
		}
		labels = append(labels, ld)
	}
	return labels
}