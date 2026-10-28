// Package filter implements the include/exclude glob rules used when building
// a tree. The syntax is a small gitignore-like subset:
//
//   - a pattern with no "/" (other than a trailing one) matches the entry's
//     base name at any depth:                 "*.log", ".git"
//   - a pattern containing "/" is anchored at the watched root and matched
//     segment by segment:                     "var/cache/*", "etc/ssh/ssh_host_*"
//   - "**" as a whole segment matches zero or more directories:
//     "**/node_modules", "home/**/.cache"
//   - a trailing "/" restricts the pattern to directories: "tmp/"
//   - each segment uses path.Match syntax (*, ?, [a-z]).
//
// Exclude patterns apply to files and directories (an excluded directory is
// not descended into). Include patterns, if any, apply to non-directories only:
// a file is kept iff it matches at least one include pattern. Exclude wins.
package filter

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

type pattern struct {
	raw      string
	segs     []string
	anchored bool
	dirOnly  bool
}

// Rules is an immutable compiled include/exclude set. A nil *Rules skips nothing.
type Rules struct {
	include, exclude []pattern
	inRaw, exRaw     []string
}

func compile(raw string) (pattern, error) {
	p := pattern{raw: raw}
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, `\`, "/")
	if s == "" {
		return p, fmt.Errorf("empty pattern")
	}
	if strings.HasSuffix(s, "/") {
		p.dirOnly = true
		s = strings.TrimRight(s, "/")
	}
	s = strings.TrimPrefix(s, "./")
	if strings.HasPrefix(s, "/") {
		p.anchored = true
		s = strings.TrimLeft(s, "/")
	}
	if s == "" {
		return p, fmt.Errorf("pattern %q matches nothing", raw)
	}
	p.segs = strings.Split(s, "/")
	if len(p.segs) > 1 {
		p.anchored = true
	}
	for _, seg := range p.segs {
		if seg == "" {
			return p, fmt.Errorf("pattern %q has an empty path segment", raw)
		}
		if seg == "**" {
			continue
		}
		if strings.Contains(seg, "**") {
			return p, fmt.Errorf("pattern %q: ** must be a whole path segment", raw)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return p, fmt.Errorf("pattern %q: %w", raw, err)
		}
	}
	return p, nil
}

// New compiles include and exclude patterns.
func New(include, exclude []string) (*Rules, error) {
	r := &Rules{}
	for _, s := range include {
		p, err := compile(s)
		if err != nil {
			return nil, fmt.Errorf("include: %w", err)
		}
		r.include = append(r.include, p)
		r.inRaw = append(r.inRaw, s)
	}
	for _, s := range exclude {
		p, err := compile(s)
		if err != nil {
			return nil, fmt.Errorf("exclude: %w", err)
		}
		r.exclude = append(r.exclude, p)
		r.exRaw = append(r.exRaw, s)
	}
	if len(r.include) == 0 && len(r.exclude) == 0 {
		return nil, nil
	}
	return r, nil
}

// Lists returns the raw include and exclude patterns, sorted and de-duplicated,
// so they can be stored (and compared) canonically.
func (r *Rules) Lists() (include, exclude []string) {
	if r == nil {
		return nil, nil
	}
	return canon(r.inRaw), canon(r.exRaw)
}

func canon(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Equal reports whether two rule sets are the same canonical lists.
func Equal(a, b *Rules) bool {
	ai, ae := a.Lists()
	bi, be := b.Lists()
	return eq(ai, bi) && eq(ae, be)
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Skip reports whether the entry at rel (slash-separated, relative to the
// watched root, never empty) should be left out of the tree.
func (r *Rules) Skip(rel string, isDir bool) bool {
	if r == nil {
		return false
	}
	for _, p := range r.exclude {
		if p.match(rel, isDir) {
			return true
		}
	}
	if !isDir && len(r.include) > 0 {
		for _, p := range r.include {
			// include patterns are not dirOnly-restricted for files
			if p.matchPath(rel) {
				return false
			}
		}
		return true
	}
	return false
}

func (p pattern) match(rel string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	return p.matchPath(rel)
}

func (p pattern) matchPath(rel string) bool {
	if !p.anchored {
		return matchSeg(p.segs[0], rel[strings.LastIndex(rel, "/")+1:])
	}
	return matchSegs(p.segs, strings.Split(rel, "/"))
}

func matchSeg(pat, s string) bool {
	ok, _ := path.Match(pat, s)
	return ok
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegs(pat, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 || !matchSeg(pat[0], segs[0]) {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// Match reports whether a slash-separated absolute or relative path matches
// glob under the same syntax (always anchored when it contains "/"). It is
// used by the ATT&CK path map.
func Match(glob, p string) bool {
	pt, err := compile(glob)
	if err != nil {
		return false
	}
	return pt.matchPath(strings.TrimLeft(p, "/"))
}
