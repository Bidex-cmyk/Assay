package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The scanning commands whose flags usage() documents. A command that scans
// but is not here would be outside the drift check below.
var flagCheckedCommands = []string{"scan", "attestation", "history", "verify", "serve"}

var (
	// synopsisFlagRE finds -flags inside a synopsis line such as
	// `assay verify [-json] [-max-age SECS]`.
	synopsisFlagRE = regexp.MustCompile(`(?:^|[\s\[])-([A-Za-z0-9][A-Za-z0-9-]*)`)
	// sectionFlagRE finds a flag at the start of a usage section entry.
	sectionFlagRE = regexp.MustCompile(`^\s+-([A-Za-z0-9][A-Za-z0-9-]*)`)
	// printedFlagRE finds a flag in the flag package's help output.
	printedFlagRE = regexp.MustCompile(`^\s+-([A-Za-z0-9][A-Za-z0-9-]*)`)
	// assetListSectionRE reads the command list from the section heading
	// that names the commands consuming SEP-0042 lists.
	assetListSectionRE = regexp.MustCompile(`^Commands that consume SEP-0042 asset lists \(([^)]*)\)`)
)

// TestUsageFlagsAreRegistered holds usage() to the flags the commands actually
// register. The failure it prevents is the one #566 reported: the usage text
// and docs told an operator to pass -no-cache, but no command defined it, so
// every documented example exited 2 with "flag provided but not defined".
//
// The registered set is read from each command's own help output, so this test
// cannot drift from the code: a flag added to a FlagSet appears here, and a
// flag removed from one disappears.
func TestUsageFlagsAreRegistered(t *testing.T) {
	expected := flagsNamedInUsage(t)
	registered := registeredFlagsForCommands(t)

	for _, cmd := range flagCheckedCommands {
		want, ok := expected[cmd]
		if !ok {
			t.Fatalf("usage() names no flags for %s", cmd)
		}
		for name := range want {
			if !registered[cmd][name] {
				t.Errorf("usage() names -%s for %s, but the command does not register it", name, cmd)
			}
		}
	}
}

// TestCachingDocExamplesUseRegisteredFlags is the acceptance check for
// docs/caching.md: every command line in its examples names only flags the
// command registers, so copying an example cannot produce a usage error.
func TestCachingDocExamplesUseRegisteredFlags(t *testing.T) {
	registered := registeredFlagsForCommands(t)

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	docPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "caching.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	checked := 0
	for _, line := range strings.Split(string(doc), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.TrimPrefix(fields[0], "./") != "assay" {
			continue
		}
		cmd := fields[1]
		want, ok := registered[cmd]
		if !ok {
			continue
		}
		checked++
		for _, field := range fields[2:] {
			if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
				continue
			}
			name := strings.TrimPrefix(field, "-")
			if i := strings.Index(name, "="); i >= 0 {
				name = name[:i]
			}
			if !want[name] {
				t.Errorf("%s: example names -%s, which %s does not register", docPath, name, cmd)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("%s has no assay examples to check", docPath)
	}
}

// flagsNamedInUsage reads usage() and returns the flags it names for each
// command, drawn from the synopsis lines, the shared "Commands that scan"
// section, the SEP-0042 section, and each command's "additionally accepts"
// section.
func flagsNamedInUsage(t *testing.T) map[string]map[string]bool {
	t.Helper()

	var buf bytes.Buffer
	usage(&buf)

	expected := map[string]map[string]bool{}
	add := func(cmd, name string) {
		if expected[cmd] == nil {
			expected[cmd] = map[string]bool{}
		}
		expected[cmd][name] = true
	}

	var section []string
	for _, line := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			section = nil
			continue
		case strings.HasPrefix(line, "  assay "):
			fields := strings.Fields(line)
			cmd := fields[1]
			for _, m := range synopsisFlagRE.FindAllStringSubmatch(line, -1) {
				add(cmd, m[1])
			}
			continue
		case strings.HasPrefix(line, "Commands that scan also accept:"):
			section = append([]string(nil), flagCheckedCommands...)
			continue
		case assetListSectionRE.MatchString(line):
			section = nil
			for _, cmd := range strings.Split(assetListSectionRE.FindStringSubmatch(line)[1], ",") {
				section = append(section, strings.TrimSpace(cmd))
			}
			continue
		case strings.HasPrefix(line, "The ") && strings.Contains(line, " command additionally accepts:"):
			section = []string{strings.Fields(line)[1]}
			continue
		}

		if section == nil {
			continue
		}
		if m := sectionFlagRE.FindStringSubmatch(line); m != nil {
			for _, cmd := range section {
				add(cmd, m[1])
			}
		}
	}
	return expected
}

// registeredFlagsForCommands asks each command for its help output and parses
// the flags it printed. Passing -h makes the flag package print every
// registered flag and return before any work, so no command runs.
func registeredFlagsForCommands(t *testing.T) map[string]map[string]bool {
	t.Helper()

	old := flagSetOutput
	var buf bytes.Buffer
	flagSetOutput = &buf
	t.Cleanup(func() { flagSetOutput = old })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registered := map[string]map[string]bool{}
	for _, cmd := range flagCheckedCommands {
		buf.Reset()
		switch cmd {
		case "scan":
			_ = runScan([]string{"-h"}, commandDeps{})
		case "attestation":
			_ = runAttestation([]string{"-h"}, commandDeps{})
		case "history":
			_ = runHistory([]string{"-h"}, commandDeps{})
		case "verify":
			_ = runVerify([]string{"-h"})
		case "serve":
			_ = runServe([]string{"-h"}, logger)
		}
		flags := map[string]bool{}
		for _, line := range strings.Split(buf.String(), "\n") {
			if m := printedFlagRE.FindStringSubmatch(line); m != nil {
				flags[m[1]] = true
			}
		}
		if len(flags) == 0 {
			t.Fatalf("%s printed no flags on -h", cmd)
		}
		registered[cmd] = flags
	}
	return registered
}
