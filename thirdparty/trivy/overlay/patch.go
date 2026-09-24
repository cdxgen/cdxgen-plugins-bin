package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// filePatch is one file's section of a unified diff.
type filePatch struct {
	// path is the file's path relative to the vendor directory.
	path string
	// deleted means the patch removes the whole file.
	deleted bool
	hunks   []hunk
}

type hunk struct {
	// oldStart is the hunk's line in the original file, used only in errors.
	oldStart int
	oldLines []string
	newLines []string
}

// parsePatch reads a unified diff as `diff -u` writes it. Text before the first
// `--- ` header is a free-form description and is skipped. Only modifications
// and deletions are supported: every patched file must already be vendored.
// CRLF line endings, as a Windows checkout may produce, are read as LF: the
// vendored Go sources the hunks are matched against are LF-terminated.
func parsePatch(text string) ([]filePatch, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var patches []filePatch
	var cur *filePatch
	var h *hunk
	oldLeft, newLeft := 0, 0

	flushHunk := func() error {
		if h == nil {
			return nil
		}
		if oldLeft != 0 || newLeft != 0 {
			return fmt.Errorf("%s: hunk at line %d is truncated", cur.path, h.oldStart)
		}
		cur.hunks = append(cur.hunks, *h)
		h = nil
		return nil
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case h != nil && (oldLeft > 0 || newLeft > 0):
			if line == `\ No newline at end of file` {
				continue
			}
			if line == "" {
				// diff writes an empty context line as a lone space; tolerate
				// editors that strip it.
				line = " "
			}
			switch line[0] {
			case ' ':
				h.oldLines = append(h.oldLines, line[1:])
				h.newLines = append(h.newLines, line[1:])
				oldLeft--
				newLeft--
			case '-':
				h.oldLines = append(h.oldLines, line[1:])
				oldLeft--
			case '+':
				h.newLines = append(h.newLines, line[1:])
				newLeft--
			default:
				return nil, fmt.Errorf("%s: unexpected line %q in hunk at line %d", cur.path, line, h.oldStart)
			}
			if oldLeft < 0 || newLeft < 0 {
				return nil, fmt.Errorf("%s: hunk at line %d is longer than its header says", cur.path, h.oldStart)
			}
		case strings.HasPrefix(line, "--- "):
			if err := flushHunk(); err != nil {
				return nil, err
			}
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
				return nil, fmt.Errorf("line %d: `---` header without a `+++` header", i+1)
			}
			oldPath := headerPath(line[4:])
			newPath := headerPath(lines[i+1][4:])
			i++
			if oldPath == "/dev/null" {
				return nil, fmt.Errorf("line %d: new files are not supported (%s)", i+1, newPath)
			}
			patches = append(patches, filePatch{path: stripPrefix(oldPath), deleted: newPath == "/dev/null"})
			cur = &patches[len(patches)-1]
		case strings.HasPrefix(line, "@@ "):
			if cur == nil {
				return nil, fmt.Errorf("line %d: hunk before any file header", i+1)
			}
			if err := flushHunk(); err != nil {
				return nil, err
			}
			oldStart, oldCount, newCount, err := parseHunkHeader(line)
			if err != nil {
				return nil, fmt.Errorf("%s: line %d: %w", cur.path, i+1, err)
			}
			h = &hunk{oldStart: oldStart}
			oldLeft, newLeft = oldCount, newCount
		case cur != nil && h != nil && line == "":
			// Blank line after a complete hunk, e.g. the file's final newline.
		case cur != nil && strings.HasPrefix(line, "diff "), cur != nil && strings.HasPrefix(line, "index "):
			// git-style extended headers between file sections.
		case cur == nil:
			// Free-form description before the first file.
		default:
			return nil, fmt.Errorf("%s: unexpected line %d outside a hunk: %q", cur.path, i+1, line)
		}
	}
	if err := flushHunk(); err != nil {
		return nil, err
	}
	if len(patches) == 0 {
		return nil, errors.New("no file sections")
	}
	return patches, nil
}

// headerPath drops the timestamp diff appends after a tab.
func headerPath(s string) string {
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// stripPrefix drops the a/ or b/ prefix of git and `diff -u a/ b/` headers.
func stripPrefix(p string) string {
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

func parseHunkHeader(line string) (oldStart, oldCount, newCount int, err error) {
	// @@ -l[,s] +l[,s] @@ optional section heading
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[3] != "@@" || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, 0, fmt.Errorf("malformed hunk header %q", line)
	}
	oldStart, oldCount, err = parseRange(fields[1][1:])
	if err != nil {
		return 0, 0, 0, err
	}
	_, newCount, err = parseRange(fields[2][1:])
	return oldStart, oldCount, newCount, err
}

func parseRange(s string) (start, count int, err error) {
	startText, countText, found := strings.Cut(s, ",")
	if start, err = strconv.Atoi(startText); err != nil {
		return 0, 0, fmt.Errorf("malformed hunk range %q", s)
	}
	if !found {
		return start, 1, nil
	}
	if count, err = strconv.Atoi(countText); err != nil {
		return 0, 0, fmt.Errorf("malformed hunk range %q", s)
	}
	return start, count, nil
}

// apply applies the file's hunks to its original content. Each hunk's original
// lines must occur exactly once in the file: a hunk that no longer matches, or
// that could match in two places, is an error rather than a guess, so a Trivy
// upgrade that touches patched code fails the build instead of shipping a
// silently mis-patched binary.
func (fp filePatch) apply(original string) (string, error) {
	lines := strings.Split(original, "\n")
	if fp.deleted {
		if len(fp.hunks) != 1 || !equalLines(fp.hunks[0].oldLines, trimFinalEmpty(lines)) {
			return "", fmt.Errorf("%s: the vendored file no longer matches the content the patch deletes", fp.path)
		}
		return "", nil
	}
	for _, h := range fp.hunks {
		if len(h.oldLines) == 0 {
			return "", fmt.Errorf("%s: hunk at line %d has no context to anchor it", fp.path, h.oldStart)
		}
		var at []int
		for i := 0; i+len(h.oldLines) <= len(lines); i++ {
			if equalLines(lines[i:i+len(h.oldLines)], h.oldLines) {
				at = append(at, i)
			}
		}
		switch len(at) {
		case 0:
			return "", fmt.Errorf("%s: hunk at line %d no longer matches the vendored file", fp.path, h.oldStart)
		case 1:
		default:
			return "", fmt.Errorf("%s: hunk at line %d matches %d places; add context to the patch", fp.path, h.oldStart, len(at))
		}
		i := at[0]
		patched := make([]string, 0, len(lines)-len(h.oldLines)+len(h.newLines))
		patched = append(patched, lines[:i]...)
		patched = append(patched, h.newLines...)
		patched = append(patched, lines[i+len(h.oldLines):]...)
		lines = patched
	}
	return strings.Join(lines, "\n"), nil
}

func trimFinalEmpty(lines []string) []string {
	if n := len(lines); n > 0 && lines[n-1] == "" {
		return lines[:n-1]
	}
	return lines
}

func equalLines(a, b []string) bool {
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
