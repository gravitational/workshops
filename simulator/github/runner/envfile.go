package runner

import (
	"fmt"
	"strings"
)

// ParseEnvFile parses a $GITHUB_ENV or $GITHUB_OUTPUT file as written by
// @actions/core: `NAME=value` lines and `NAME<<DELIM` … `DELIM` heredocs.
// Blank lines between entries are ignored and later entries override earlier
// ones.
func ParseEnvFile(data []byte) (map[string]string, error) {
	vars := map[string]string{}
	lines := splitLines(data)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		eq := strings.Index(line, "=")
		heredoc := strings.Index(line, "<<")
		switch {
		case eq >= 0 && (heredoc < 0 || eq < heredoc):
			name := line[:eq]
			if name == "" {
				return nil, fmt.Errorf("line %d: missing variable name: %q", i+1, line)
			}
			vars[name] = line[eq+1:]
		case heredoc >= 0:
			name, delim := line[:heredoc], line[heredoc+2:]
			if name == "" {
				return nil, fmt.Errorf("line %d: missing variable name: %q", i+1, line)
			}
			if delim == "" {
				return nil, fmt.Errorf("line %d: missing heredoc delimiter: %q", i+1, line)
			}
			start := i + 1
			end := start
			for end < len(lines) && lines[end] != delim {
				end++
			}
			if end == len(lines) {
				return nil, fmt.Errorf("line %d: heredoc for %s is missing closing delimiter %q", i+1, name, delim)
			}
			vars[name] = strings.Join(lines[start:end], "\n")
			i = end
		default:
			return nil, fmt.Errorf("line %d: expected NAME=value or NAME<<DELIMITER: %q", i+1, line)
		}
	}
	return vars, nil
}

// ParsePathFile parses a $GITHUB_PATH file: one directory per non-empty line.
func ParsePathFile(data []byte) []string {
	var paths []string
	for _, line := range splitLines(data) {
		if p := strings.TrimSpace(line); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// splitLines splits data on "\n", dropping a trailing "\r" from each line.
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}
