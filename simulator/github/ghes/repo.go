package ghes

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"simulator/github/workflow"
)

var errBadPath = errors.New("invalid repository path")

// repo is read-only access to a simulated repository's files.
// Every lookup goes through os.Root, so ".." components, absolute paths and
// symlinks pointing outside dir all fail.
type repo struct{ dir string }

// entry is one item of a directory listing.
type entry struct {
	Name string
	Path string // repo-relative, slash-separated
	Dir  bool
}

// workflowFile is a workflow under .github/workflows.
type workflowFile struct {
	File         string // base name, e.g. deploy.yaml
	Path         string // repo-relative path
	Name         string // the YAML `name:`, or Path if it doesn't parse
	Err          string // parse error, if any
	Dispatchable bool   // has a workflow_dispatch trigger
}

// clean turns a request path into an os.Root name: "" is the root, and
// anything fs.ValidPath rejects ("..", absolute paths, empty elements) is
// an error.
func clean(rel string) (string, error) {
	rel = strings.TrimSuffix(rel, "/")
	if rel == "" {
		return ".", nil
	}
	if !fs.ValidPath(rel) {
		return "", errBadPath
	}
	return rel, nil
}

func (r repo) fs() (fs.FS, func(), error) {
	root, err := os.OpenRoot(r.dir)
	if err != nil {
		return nil, nil, err
	}
	return root.FS(), func() { root.Close() }, nil
}

// stat returns information about the file or directory at rel.
func (r repo) stat(rel string) (fs.FileInfo, error) {
	name, err := clean(rel)
	if err != nil {
		return nil, err
	}
	fsys, done, err := r.fs()
	if err != nil {
		return nil, err
	}
	defer done()
	return fs.Stat(fsys, name)
}

// read returns the contents of the file at rel.
func (r repo) read(rel string) ([]byte, error) {
	name, err := clean(rel)
	if err != nil {
		return nil, err
	}
	fsys, done, err := r.fs()
	if err != nil {
		return nil, err
	}
	defer done()
	return fs.ReadFile(fsys, name)
}

// list returns the directory at rel, directories first, each group sorted
// by name.
func (r repo) list(rel string) ([]entry, error) {
	name, err := clean(rel)
	if err != nil {
		return nil, err
	}
	fsys, done, err := r.fs()
	if err != nil {
		return nil, err
	}
	defer done()
	des, err := fs.ReadDir(fsys, name)
	if err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(des))
	for _, de := range des {
		p := path.Join(name, de.Name())
		dir := de.IsDir()
		if de.Type()&fs.ModeSymlink != 0 {
			// Show a symlink as what it points to; one that escapes the
			// repo can't be stat'ed and is listed as a file (which 404s).
			if fi, err := fs.Stat(fsys, p); err == nil {
				dir = fi.IsDir()
			}
		}
		out = append(out, entry{Name: de.Name(), Path: p, Dir: dir})
	}
	slices.SortFunc(out, func(a, b entry) int {
		if a.Dir != b.Dir {
			if a.Dir {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out, nil
}

// isWorkflowFile reports whether file is a name GitHub picks up as a
// workflow in .github/workflows.
func isWorkflowFile(file string) bool {
	return file == path.Base(file) && !strings.HasPrefix(file, ".") &&
		(strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml"))
}

// workflows lists .github/workflows/*.yml|*.yaml, sorted by file name.
// Workflows that fail to parse are included with their error.
func (r repo) workflows() []workflowFile {
	entries, err := r.list(workflowsDir)
	if err != nil {
		return nil
	}
	var out []workflowFile
	for _, e := range entries {
		if e.Dir || !isWorkflowFile(e.Name) {
			continue
		}
		if wf, ok := r.workflow(e.Name); ok {
			out = append(out, wf)
		}
	}
	return out
}

// workflow loads .github/workflows/{file}; false if it isn't a workflow
// file or can't be read.
func (r repo) workflow(file string) (workflowFile, bool) {
	if !isWorkflowFile(file) {
		return workflowFile{}, false
	}
	p := path.Join(workflowsDir, file)
	data, err := r.read(p)
	if err != nil {
		return workflowFile{}, false
	}
	wf := workflowFile{File: file, Path: p, Name: p}
	parsed, err := workflow.Parse(p, data)
	if err != nil {
		// GitHub still lists a broken workflow under its path. If it has
		// a workflow_dispatch trigger it can still be run, so the run
		// fails with the parse error, as on GitHub.
		wf.Err = err.Error()
		wf.Dispatchable = hasDispatchTrigger(data)
		return wf, true
	}
	wf.Name = parsed.Name
	wf.Dispatchable = parsed.Dispatchable()
	return wf, true
}

// hasDispatchTrigger reports whether workflow YAML that workflow.Parse
// rejected still declares a workflow_dispatch trigger.
func hasDispatchTrigger(data []byte) bool {
	var doc struct {
		On yaml.Node `yaml:"on"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return false
	}
	on := doc.On
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == "workflow_dispatch"
	case yaml.SequenceNode:
		for _, n := range on.Content {
			if n.Value == "workflow_dispatch" {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			if on.Content[i].Value == "workflow_dispatch" {
				return true
			}
		}
	}
	return false
}
