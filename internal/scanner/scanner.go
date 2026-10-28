// Package scanner runs the monitoring loop.
//
// Two triggers drive re-scans:
//
//   - filesystem events (fsnotify), debounced, for near-real-time alerts;
//     these use the stat-based rehash cache, so only touched files are read.
//   - a periodic interval, which does a FULL verify (no cache) and so also
//     catches anything the event path missed (queue overflow, mtime games).
package scanner

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/DakodaStemen/hashdog/internal/merkle"
	"github.com/fsnotify/fsnotify"
)

// Event is a single alert.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // MODIFIED | ADDED | REMOVED
	Path    string    `json:"path"`
	OldHash string    `json:"old_hash,omitempty"`
	NewHash string    `json:"new_hash,omitempty"`
	Source  string    `json:"source"` // baseline | event | periodic
}

// Sink receives alerts.
type Sink func(Event)

// Config controls how the monitor behaves.
type Config struct {
	Root      string
	Interval  time.Duration // periodic full verify; <=0 disables
	Watch     bool          // enable fsnotify event-driven scans
	Debounce  time.Duration // event coalescing window (default 200ms)
	Baseline  *merkle.Node  // optional trusted starting snapshot
	Sinks     []Sink
	Quiet     bool // suppress informational logs
	OnScanned func(source string, changes int)
}

// Monitor holds the current snapshot and runs the loops.
type Monitor struct {
	cfg      Config
	snapshot *merkle.Node
	watcher  *fsnotify.Watcher
}

// New establishes the starting snapshot: cfg.Baseline if given, otherwise a
// fresh scan of the directory.
func New(cfg Config) (*Monitor, error) {
	if cfg.Debounce <= 0 {
		cfg.Debounce = 200 * time.Millisecond
	}
	m := &Monitor{cfg: cfg}
	if cfg.Baseline != nil {
		m.snapshot = cfg.Baseline
		return m, nil
	}
	m.logf("building baseline snapshot of %s", cfg.Root)
	snap, err := merkle.Build(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("initial scan failed: %w", err)
	}
	m.logf("baseline ready root=%s", snap.HexHash())
	m.snapshot = snap
	return m, nil
}

func (m *Monitor) logf(f string, a ...any) {
	if !m.cfg.Quiet {
		log.Printf("[hashdog] "+f, a...)
	}
}

// Snapshot returns the current snapshot.
func (m *Monitor) Snapshot() *merkle.Node { return m.snapshot }

// Scan rebuilds the tree, diffs against the current snapshot, emits alerts
// and advances the snapshot. full=true bypasses the rehash cache.
func (m *Monitor) Scan(source string, full bool) []merkle.Change {
	opt := merkle.Options{}
	if !full {
		opt.Prev = m.snapshot
	}
	next, err := merkle.BuildWith(m.cfg.Root, opt)
	if err != nil {
		m.logf("scan error: %v", err)
		return nil
	}
	var changes []merkle.Change
	if next.Hash == m.snapshot.Hash {
		m.logf("clean (%s) root=%s", source, next.HexHash())
	} else {
		changes = merkle.Diff(m.snapshot, next)
		now := time.Now()
		for _, c := range changes {
			ev := Event{Time: now, Kind: string(c.Kind), Path: c.Path, Source: source}
			if c.Kind != merkle.Added {
				ev.OldHash = fmt.Sprintf("%x", c.OldHash)
			}
			if c.Kind != merkle.Removed {
				ev.NewHash = fmt.Sprintf("%x", c.NewHash)
			}
			for _, s := range m.cfg.Sinks {
				s(ev)
			}
		}
	}
	m.snapshot = next
	if m.cfg.OnScanned != nil {
		m.cfg.OnScanned(source, len(changes))
	}
	return changes
}

func (m *Monitor) addTree(dir string) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			if err := m.watcher.Add(p); err != nil {
				m.logf("watch %s: %v", p, err)
			}
		}
		return nil
	})
}

// Run blocks until done is closed.
func (m *Monitor) Run(done <-chan struct{}) error {
	var tick <-chan time.Time
	if m.cfg.Interval > 0 {
		t := time.NewTicker(m.cfg.Interval)
		defer t.Stop()
		tick = t.C
	}
	var events <-chan fsnotify.Event
	var werrs <-chan error
	if m.cfg.Watch {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			return err
		}
		defer w.Close()
		m.watcher = w
		m.addTree(m.cfg.Root)
		events, werrs = w.Events, w.Errors
	}
	m.logf("watching %s events=%v interval=%s", m.cfg.Root, m.cfg.Watch, m.cfg.Interval)

	if m.cfg.Baseline != nil {
		m.Scan("baseline", true) // compare disk against the trusted baseline now
	}

	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	for {
		select {
		case ev := <-events:
			if ev.Has(fsnotify.Create) {
				if fi, err := os.Lstat(ev.Name); err == nil && fi.IsDir() {
					m.addTree(ev.Name)
				}
			}
			debounce.Reset(m.cfg.Debounce)
		case err := <-werrs:
			// Typically an inotify queue overflow: events were lost, so do
			// a full verify rather than trusting the cache.
			m.logf("watcher error: %v (forcing full verify)", err)
			m.Scan("event", true)
		case <-debounce.C:
			m.Scan("event", false)
		case <-tick:
			m.Scan("periodic", true)
		case <-done:
			m.logf("stopped")
			return nil
		}
	}
}
