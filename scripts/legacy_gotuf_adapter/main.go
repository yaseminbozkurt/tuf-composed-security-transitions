// legacygotuf-conformance-adapter: a minimal tuf-conformance CLIENT-CLI
// adapter for pre-fix go-tuf v0.2.0 (legacy github.com/theupdateframework/go-tuf
// API, predating the GHSA-66x3-6cw3-v5gj / CVE-2022-29173 fix in v0.3.0).
//
// Purpose: this study's own TIMESTAMP_REPLAY / SNAPSHOT_REPLAY executors
// (scripts/run_full_pair_matrix.py) already exercise rollback-protection
// (P3) against python-tuf, go-tuf v2, and tuf-js. This adapter lets the
// exact same rollback scenario be executed against a real, historically
// vulnerable go-tuf release, as a positive-control test of whether the
// oracle can flag a known-vulnerable implementation, not only self-caught
// construction bugs.
//
// Protocol: matches tuf-conformance's CLIENT-CLI contract exactly as
// implemented by tuf-conformance/clients/go-tuf/cmd/*.go (the go-tuf v2
// adapter already used by this study), verified directly against that
// adapter's source before writing this one:
//   init     <trusted-root-path> --metadata-dir DIR
//   refresh  --metadata-url URL --metadata-dir DIR
//   download --metadata-url URL --metadata-dir DIR --target-name NAME
//            [--target-name NAME ...] --target-dir DIR --target-base-url URL
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	tuf "github.com/theupdateframework/go-tuf/client"
)

// fileLocalStore is a plain-JSON-file LocalStore, deliberately not the
// upstream leveldbstore package: tuf-conformance's own test helpers
// (client_runner.py's version()/trusted_roles()) read trusted metadata
// directly as "<metadata-dir>/<role>.json" files, matching what
// python-tuf/go-tuf-v2/tuf-js already write. Using an opaque LevelDB
// store would still satisfy this study's own exit-code-only executors,
// but would make the artifact inconsistent with, and unreadable by, the
// rest of this study's tooling.
type fileLocalStore struct{ dir string }

func newFileLocalStore(dir string) *fileLocalStore { return &fileLocalStore{dir: dir} }

func (f *fileLocalStore) GetMeta() (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		result[e.Name()] = json.RawMessage(b)
	}
	return result, nil
}

func (f *fileLocalStore) SetMeta(name string, meta json.RawMessage) error {
	return os.WriteFile(filepath.Join(f.dir, name), meta, 0644)
}

func (f *fileLocalStore) DeleteMeta(name string) error {
	err := os.Remove(filepath.Join(f.dir, name))
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f *fileLocalStore) Close() error { return nil }

// dualRemoteStore exists because legacy go-tuf's built-in HTTPRemoteStore
// takes exactly one base URL plus metadata/targets sub-paths under it, but
// tuf-conformance's CLIENT-CLI protocol passes --metadata-url and
// --target-base-url as two independent, already-fully-qualified base URLs
// (confirmed by direct inspection of
// tuf_conformance/_internal/simulator_server.py's new_test(): distinct
// ".../metadata/" and ".../targets/" URLs). A custom two-base-URL store is
// simpler and less fragile than reconstructing a shared prefix.
type dualRemoteStore struct {
	metadataBaseURL string
	targetsBaseURL  string
	cli             *http.Client
}

func (d *dualRemoteStore) fetch(base, name string) (io.ReadCloser, int64, error) {
	url := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(name, "/")
	res, err := d.cli.Get(url)
	if err != nil {
		return nil, 0, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, 0, tuf.ErrNotFound{File: name}
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, 0, fmt.Errorf("unexpected HTTP status %d for %s", res.StatusCode, url)
	}
	return res.Body, res.ContentLength, nil
}

func (d *dualRemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	return d.fetch(d.metadataBaseURL, name)
}

func (d *dualRemoteStore) GetTarget(name string) (io.ReadCloser, int64, error) {
	return d.fetch(d.targetsBaseURL, name)
}

// fileDestination implements client.Destination (io.Writer + Delete).
type fileDestination struct {
	*os.File
	path string
}

func (fd *fileDestination) Delete() error {
	fd.Close()
	return os.Remove(fd.path)
}

type flags struct {
	verbose       bool
	metadataURL   string
	metadataDir   string
	targetDir     string
	targetNames   []string
	targetBaseURL string
}

func parseArgs(args []string) (*flags, string, []string) {
	f := &flags{}
	var command string
	var positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--verbose":
			f.verbose = true
			i++
		case "--metadata-url":
			f.metadataURL = args[i+1]
			i += 2
		case "--metadata-dir":
			f.metadataDir = args[i+1]
			i += 2
		case "--target-dir":
			f.targetDir = args[i+1]
			i += 2
		case "--target-name":
			f.targetNames = append(f.targetNames, args[i+1])
			i += 2
		case "--target-base-url":
			f.targetBaseURL = args[i+1]
			i += 2
		default:
			if command == "" {
				command = a
			} else {
				positional = append(positional, a)
			}
			i++
		}
	}
	return f, command, positional
}

func buildClient(f *flags) *tuf.Client {
	local := newFileLocalStore(f.metadataDir)
	remote := &dualRemoteStore{
		metadataBaseURL: f.metadataURL,
		targetsBaseURL:  f.targetBaseURL,
		cli:             http.DefaultClient,
	}
	return tuf.NewClient(local, remote)
}

func main() {
	f, command, positional := parseArgs(os.Args[1:])

	switch command {
	case "init":
		if len(positional) != 1 {
			fmt.Fprintln(os.Stderr, "init requires exactly one argument: path to trusted root.json")
			os.Exit(1)
		}
		rootBytes, err := os.ReadFile(positional[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error reading trusted root:", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(f.metadataDir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, "error creating metadata dir:", err)
			os.Exit(1)
		}
		// Deliberately a raw byte copy, not client.InitLocal() (which would
		// verify eagerly): matches the go-tuf-v2 adapter's own init.go,
		// which also just copies bytes and defers verification to refresh.
		if err := os.WriteFile(filepath.Join(f.metadataDir, "root.json"), rootBytes, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "error writing root.json:", err)
			os.Exit(1)
		}
		fmt.Println("legacy-go-tuf(v0.2.0, pre-fix) test client: initialized in", f.metadataDir)

	case "refresh":
		if f.metadataURL == "" || f.metadataDir == "" {
			fmt.Fprintln(os.Stderr, "Error: required flag(s): \"metadata-url\" or \"metadata-dir\" not set")
			os.Exit(1)
		}
		client := buildClient(f)
		if _, err := client.Update(); err != nil {
			fmt.Fprintln(os.Stderr, "refresh failed:", err)
			os.Exit(1)
		}
		fmt.Println("legacy-go-tuf(v0.2.0, pre-fix) test client: refreshed metadata in", f.metadataDir)

	case "download":
		if f.metadataURL == "" || f.metadataDir == "" || len(f.targetNames) == 0 {
			fmt.Fprintln(os.Stderr, "Error: required flag(s): \"metadata-url\" or \"metadata-dir\" not set")
			os.Exit(1)
		}
		client := buildClient(f)
		if _, err := client.Update(); err != nil {
			fmt.Fprintln(os.Stderr, "refresh (pre-download) failed:", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(f.targetDir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, "error creating target dir:", err)
			os.Exit(1)
		}
		for _, name := range f.targetNames {
			destPath := filepath.Join(f.targetDir, name)
			out, err := os.Create(destPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error creating dest file:", err)
				os.Exit(1)
			}
			dest := &fileDestination{File: out, path: destPath}
			if err := client.Download(name, dest); err != nil {
				fmt.Fprintln(os.Stderr, "download failed:", name, err)
				os.Exit(1)
			}
			fmt.Println("legacy-go-tuf(v0.2.0, pre-fix) test client: downloaded", name)
		}

	default:
		fmt.Fprintln(os.Stderr, "unknown command:", command)
		os.Exit(1)
	}
}
