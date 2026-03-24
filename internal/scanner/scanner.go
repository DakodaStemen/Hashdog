// Package scanner runs the monitoring loop.
// It takes an initial Merkle snapshot of a directory, then re-scans on a
// fixed interval and fires an alert for every file that was added, removed,
// or modified since the last clean state.
package scanner

import (
	"fim/internal/merkle"
	"fmt"
	"log"
	"time"
)

// Alert is called once for each change detected during a scan.
// The default implementation prints to stdout; replace it to write to a log
// file, send a webhook, or integrate with an alerting system.
type Alert func(c merkle.Change)

// Config controls how the monitor behaves.
type Config struct {
	Root     string        // directory to watch
	Interval time.Duration // how often to re-scan
	Alert    Alert         // called for each detected change; defaults to DefaultAlert
}

// DefaultAlert writes a human-readable change report to stdout.
func DefaultAlert(c merkle.Change) {
	switch c.Kind {
	case merkle.Modified:
		fmt.Printf("[ALERT] MODIFIED  %s\n         old: %x\n         new: %x\n",
			c.Path, c.OldHash, c.NewHash)
	case merkle.Added:
		fmt.Printf("[ALERT] ADDED     %s\n         hash: %x\n", c.Path, c.NewHash)
	case merkle.Removed:
		fmt.Printf("[ALERT] REMOVED   %s\n         hash: %x\n", c.Path, c.OldHash)
	}
}

// Monitor holds the current clean snapshot and runs the scan loop.
// Create one with New, then call Run.
type Monitor struct {
	cfg      Config
	snapshot *merkle.Node
}

// New scans the directory once to establish the baseline snapshot.
// If the directory cannot be read it returns an error immediately.
func New(cfg Config) (*Monitor, error) {
	if cfg.Alert == nil {
		cfg.Alert = DefaultAlert
	}

	log.Printf("[hashwarden] building baseline snapshot of %s", cfg.Root)
	snap, err := merkle.Build(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("initial scan failed: %w", err)
	}
	log.Printf("[hashwarden] baseline ready  root=%s", snap.HexHash())
	return &Monitor{cfg: cfg, snapshot: snap}, nil
}

// Run blocks and re-scans the directory on every tick until done is closed.
// On each tick it rebuilds the Merkle tree, compares it to the last known
// clean state, and calls Alert once per changed file.
func (m *Monitor) Run(done <-chan struct{}) {
	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	log.Printf("[hashwarden] watching %s  interval=%s", m.cfg.Root, m.cfg.Interval)

	for {
		select {
		case <-ticker.C:
			m.scan()
		case <-done:
			log.Println("[hashwarden] stopped")
			return
		}
	}
}

func (m *Monitor) scan() {
	next, err := merkle.Build(m.cfg.Root)
	if err != nil {
		log.Printf("[hashwarden] scan error: %v", err)
		return
	}

	if next.Hash == m.snapshot.Hash {
		log.Printf("[hashwarden] clean  root=%s", next.HexHash())
		m.snapshot = next
		return
	}

	changes := merkle.Diff(m.snapshot, next)
	for _, c := range changes {
		m.cfg.Alert(c)
	}

	m.snapshot = next
}
