package attest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidVersion reports a scanner version string that is not valid semver.
var ErrInvalidVersion = errors.New("attest: invalid scanner version")

type parsedVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []prereleasePart
	hasPre     bool
}

type prereleasePart struct {
	isNum bool
	num   uint64
	str   string
}

func parseVersion(v string) (parsedVersion, error) {
	s := strings.TrimSpace(v)
	if !strings.HasPrefix(s, "v") {
		return parsedVersion{}, fmt.Errorf("%w: missing 'v' prefix in %q", ErrInvalidVersion, v)
	}
	s = s[1:]

	// Strip and validate build metadata if present.
	if plus := strings.IndexByte(s, '+'); plus >= 0 {
		build := s[plus+1:]
		s = s[:plus]
		if build == "" {
			return parsedVersion{}, fmt.Errorf("%w: empty build metadata in %q", ErrInvalidVersion, v)
		}
		for _, part := range strings.Split(build, ".") {
			if part == "" || !isAlphanumericOrHyphen(part) {
				return parsedVersion{}, fmt.Errorf("%w: invalid build metadata component %q in %q", ErrInvalidVersion, part, v)
			}
		}
	}

	var preParts []prereleasePart
	hasPre := false
	if dash := strings.IndexByte(s, '-'); dash >= 0 {
		pre := s[dash+1:]
		s = s[:dash]
		if pre == "" {
			return parsedVersion{}, fmt.Errorf("%w: empty prerelease in %q", ErrInvalidVersion, v)
		}
		hasPre = true
		for _, part := range strings.Split(pre, ".") {
			if part == "" || !isAlphanumericOrHyphen(part) {
				return parsedVersion{}, fmt.Errorf("%w: invalid prerelease component %q in %q", ErrInvalidVersion, part, v)
			}
			if isAllDigits(part) {
				if len(part) > 1 && part[0] == '0' {
					return parsedVersion{}, fmt.Errorf("%w: leading zero in numeric prerelease component %q in %q", ErrInvalidVersion, part, v)
				}
				num, err := strconv.ParseUint(part, 10, 64)
				if err != nil {
					return parsedVersion{}, fmt.Errorf("%w: %w in %q", ErrInvalidVersion, err, v)
				}
				preParts = append(preParts, prereleasePart{isNum: true, num: num, str: part})
			} else {
				preParts = append(preParts, prereleasePart{isNum: false, str: part})
			}
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return parsedVersion{}, fmt.Errorf("%w: expected 3 dot-separated integers in %q", ErrInvalidVersion, v)
	}

	nums := make([]uint64, 3)
	for i, p := range parts {
		if p == "" || !isAllDigits(p) {
			return parsedVersion{}, fmt.Errorf("%w: invalid version component %q in %q", ErrInvalidVersion, p, v)
		}
		if len(p) > 1 && p[0] == '0' {
			return parsedVersion{}, fmt.Errorf("%w: leading zero in version component %q in %q", ErrInvalidVersion, p, v)
		}
		num, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return parsedVersion{}, fmt.Errorf("%w: %w in %q", ErrInvalidVersion, err, v)
		}
		nums[i] = num
	}

	return parsedVersion{
		major:      nums[0],
		minor:      nums[1],
		patch:      nums[2],
		prerelease: preParts,
		hasPre:     hasPre,
	}, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isAlphanumericOrHyphen(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' {
			return false
		}
	}
	return true
}

// CompareVersions compares two semver version strings (e.g. "v1.0.0", "v0.1.0").
// It returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
// An error is returned if either version is not valid semver.
func CompareVersions(v1, v2 string) (int, error) {
	p1, err := parseVersion(v1)
	if err != nil {
		return 0, err
	}
	p2, err := parseVersion(v2)
	if err != nil {
		return 0, err
	}

	if p1.major != p2.major {
		if p1.major < p2.major {
			return -1, nil
		}
		return 1, nil
	}
	if p1.minor != p2.minor {
		if p1.minor < p2.minor {
			return -1, nil
		}
		return 1, nil
	}
	if p1.patch != p2.patch {
		if p1.patch < p2.patch {
			return -1, nil
		}
		return 1, nil
	}

	if !p1.hasPre && !p2.hasPre {
		return 0, nil
	}
	// Normal version has higher precedence than pre-release version.
	if !p1.hasPre && p2.hasPre {
		return 1, nil
	}
	if p1.hasPre && !p2.hasPre {
		return -1, nil
	}

	// Compare pre-release components from left to right.
	for i := 0; i < len(p1.prerelease) && i < len(p2.prerelease); i++ {
		a, b := p1.prerelease[i], p2.prerelease[i]
		if a.isNum && b.isNum {
			if a.num != b.num {
				if a.num < b.num {
					return -1, nil
				}
				return 1, nil
			}
		} else if a.isNum && !b.isNum {
			// Numeric identifiers always have lower precedence than non-numeric identifiers.
			return -1, nil
		} else if !a.isNum && b.isNum {
			return 1, nil
		} else {
			// Both are non-numeric; compare in ASCII sort order.
			if a.str != b.str {
				if a.str < b.str {
					return -1, nil
				}
				return 1, nil
			}
		}
	}

	if len(p1.prerelease) < len(p2.prerelease) {
		return -1, nil
	}
	if len(p1.prerelease) > len(p2.prerelease) {
		return 1, nil
	}
	return 0, nil
}
