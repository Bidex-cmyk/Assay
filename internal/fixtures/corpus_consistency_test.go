package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

type corpusManifest struct {
	Subjects []struct {
		Fixture        string   `json:"fixture"`
		Asset          string   `json:"asset"`
		BaseSeverity   string   `json:"base_severity"`
		Severity       string   `json:"severity"`
		Accountability string   `json:"accountability"`
		Escalated      bool     `json:"escalated"`
		CaptureDate    string   `json:"capture_date"`
		SourceURLs     []string `json:"source_urls"`
	} `json:"subjects"`
	RegressionFixtures []struct {
		Fixture string `json:"fixture"`
		Purpose string `json:"purpose"`
	} `json:"regression_fixtures"`
}

type subjectMetadata struct {
	Subject string `json:"subject"`
	Files   []struct {
		File     string `json:"file"`
		URL      string `json:"url"`
		Captured string `json:"captured"`
	} `json:"files"`
	Expected struct {
		State          string `json:"state"`
		Base           string `json:"base"`
		Severity       string `json:"severity"`
		Accountability string `json:"accountability"`
		Escalated      bool   `json:"escalated"`
	} `json:"expected"`
}

var provenanceRow = regexp.MustCompile("(?m)^\\| `([^`]+)/([^`]+)` \\| (https?[^ |]+)")

func TestCorpusDirectoriesAndCrossFileConsistency(t *testing.T) {
	testdata := filepath.Join("..", "mechanics", "testdata")
	b, err := os.ReadFile(filepath.Join(testdata, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest corpusManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	accounted := make(map[string]bool)
	subjects := make(map[string]struct {
		Asset, BaseSeverity, Severity, Accountability string
		Escalated                                     bool
		CaptureDate                                   string
		SourceURLs                                    []string
	})
	for _, s := range manifest.Subjects {
		accounted[s.Fixture] = true
		subjects[s.Fixture] = struct {
			Asset, BaseSeverity, Severity, Accountability string
			Escalated                                     bool
			CaptureDate                                   string
			SourceURLs                                    []string
		}{s.Asset, s.BaseSeverity, s.Severity, s.Accountability, s.Escalated, s.CaptureDate, s.SourceURLs}
	}
	for _, r := range manifest.RegressionFixtures {
		if r.Purpose == "" {
			t.Errorf("regression fixture %q has no purpose", r.Fixture)
		}
		accounted[r.Fixture] = true
	}

	dirs, err := os.ReadDir(testdata)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if d.IsDir() && !accounted[d.Name()] {
			t.Errorf("fixture directory %q is neither a subject nor a regression_fixture", d.Name())
		}
	}

	provenance, err := os.ReadFile(filepath.Join(testdata, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	provenanceURLs := make(map[string][]string)
	for _, m := range provenanceRow.FindAllSubmatch(provenance, -1) {
		dir, url := string(m[1]), string(m[3])
		provenanceURLs[dir] = append(provenanceURLs[dir], url)
	}

	for subject, m := range subjects {
		b, err := os.ReadFile(filepath.Join(testdata, subject, "metadata.json"))
		if err != nil {
			t.Errorf("subject %q: %v", subject, err)
			continue
		}
		var md subjectMetadata
		if err := json.Unmarshal(b, &md); err != nil {
			t.Errorf("subject %q metadata: %v", subject, err)
			continue
		}
		if md.Subject != subject {
			t.Errorf("subject %q field subject: got %q", subject, md.Subject)
		}
		checkEqualString(t, subject, "base_severity", m.BaseSeverity, md.Expected.Base)
		checkEqualString(t, subject, "severity", m.Severity, md.Expected.Severity)
		checkEqualString(t, subject, "accountability", m.Accountability, md.Expected.Accountability)
		if m.Escalated != md.Expected.Escalated {
			t.Errorf("subject %q field escalated: manifest=%t metadata=%t", subject, m.Escalated, md.Expected.Escalated)
		}

		metadataURLs := make(map[string]bool)
		captureSeen := false
		for _, f := range md.Files {
			metadataURLs[f.URL] = true
			if f.Captured == m.CaptureDate {
				captureSeen = true
			}
		}
		if !captureSeen {
			t.Errorf("subject %q field capture_date: manifest %q does not appear in metadata.json file captures", subject, m.CaptureDate)
		}
		for _, u := range m.SourceURLs {
			if !metadataURLs[u] {
				t.Errorf("subject %q field source_urls: manifest URL missing from metadata.json: %s", subject, u)
			}
		}
		for u := range metadataURLs {
			found := false
			for _, mu := range m.SourceURLs {
				if u == mu {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("subject %q field source_urls: metadata URL missing from manifest: %s", subject, u)
			}
		}
		for _, u := range provenanceURLs[subject] {
			found := false
			for _, mu := range m.SourceURLs {
				if u == mu {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("subject %q field source_urls: PROVENANCE.md URL missing from manifest: %s", subject, u)
			}
		}

		assetFromFile, err := os.ReadFile(filepath.Join(testdata, subject, "asset.json"))
		if err != nil {
			t.Errorf("subject %q asset.json: %v", subject, err)
		} else {
			var asset struct {
				AssetCode   string `json:"asset_code"`
				AssetIssuer string `json:"asset_issuer"`
			}
			if err := json.Unmarshal(assetFromFile, &asset); err == nil {
				wantAsset := asset.AssetCode + "-" + asset.AssetIssuer
				if m.Asset != wantAsset {
					t.Errorf("subject %q field asset: manifest=%q asset.json=%q", subject, m.Asset, wantAsset)
				}
			}
		}
	}
}

func checkEqualString(t *testing.T, subject, field, manifest, metadata string) {
	t.Helper()
	if manifest != metadata {
		t.Errorf("subject %q field %s: manifest=%q metadata=%q", subject, field, manifest, metadata)
	}
}
