package scanner_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DakodaStemen/hashdog/internal/merkle"
	"github.com/DakodaStemen/hashdog/internal/scanner"
)

type collector struct {
	mu sync.Mutex
	ev []scanner.Event
}

func (c *collector) sink(e scanner.Event) { c.mu.Lock(); c.ev = append(c.ev, e); c.mu.Unlock() }
func (c *collector) snapshot() []scanner.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]scanner.Event(nil), c.ev...)
}

func waitFor(t *testing.T, c *collector, kind, suffix string) scanner.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range c.snapshot() {
			if e.Kind == kind && strings.HasSuffix(e.Path, suffix) {
				return e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s %s alert; got %+v", kind, suffix, c.snapshot())
	return scanner.Event{}
}

func TestScanDirect(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a"), []byte("1"), 0o644)
	c := &collector{}
	m, err := scanner.New(scanner.Config{Root: root, Sinks: []scanner.Sink{c.sink}, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.Scan("periodic", true)); n != 0 {
		t.Fatalf("clean scan reported %d", n)
	}
	os.WriteFile(filepath.Join(root, "a"), []byte("2"), 0o644)
	os.WriteFile(filepath.Join(root, "b"), []byte("n"), 0o644)
	if n := len(m.Scan("periodic", true)); n != 2 {
		t.Fatalf("want 2 changes, got %d", n)
	}
}

// Event-driven path: interval is disabled, so only fsnotify can trigger.
func TestEventDrivenAlerts(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "victim"), []byte("v1"), 0o644)
	os.WriteFile(filepath.Join(root, "doomed"), []byte("x"), 0o644)
	c := &collector{}
	m, _ := scanner.New(scanner.Config{Root: root, Watch: true, Debounce: 50 * time.Millisecond,
		Sinks: []scanner.Sink{c.sink}, Quiet: true})
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() { m.Run(done); close(stopped) }()
	defer func() { close(done); <-stopped }()
	time.Sleep(200 * time.Millisecond) // let watches register

	os.WriteFile(filepath.Join(root, "victim"), []byte("v2"), 0o644)
	if e := waitFor(t, c, "MODIFIED", "victim"); e.Source != "event" {
		t.Fatalf("source=%s", e.Source)
	}
	os.Remove(filepath.Join(root, "doomed"))
	waitFor(t, c, "REMOVED", "doomed")

	// A brand-new subdirectory must get its own watch.
	os.MkdirAll(filepath.Join(root, "new", "sub"), 0o755)
	time.Sleep(200 * time.Millisecond)
	os.WriteFile(filepath.Join(root, "new", "sub", "dropped"), []byte("evil"), 0o644)
	waitFor(t, c, "ADDED", "dropped")
}

// Periodic full verify catches a change made while events are off.
func TestPeriodicFallback(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("a"), 0o644)
	c := &collector{}
	m, _ := scanner.New(scanner.Config{Root: root, Interval: 100 * time.Millisecond,
		Sinks: []scanner.Sink{c.sink}, Quiet: true})
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() { m.Run(done); close(stopped) }()
	defer func() { close(done); <-stopped }()
	os.WriteFile(filepath.Join(root, "f"), []byte("b"), 0o644)
	if e := waitFor(t, c, "MODIFIED", "f"); e.Source != "periodic" {
		t.Fatalf("source=%s", e.Source)
	}
}

func TestStartsFromBaseline(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("a"), 0o644)
	base, _ := merkle.Build(root)
	os.WriteFile(filepath.Join(root, "f"), []byte("tampered while daemon was down"), 0o644)
	c := &collector{}
	m, _ := scanner.New(scanner.Config{Root: root, Baseline: base, Interval: time.Hour,
		Sinks: []scanner.Sink{c.sink}, Quiet: true})
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() { m.Run(done); close(stopped) }()
	defer func() { close(done); <-stopped }()
	if e := waitFor(t, c, "MODIFIED", "f"); e.Source != "baseline" {
		t.Fatalf("source=%s", e.Source)
	}
}

func TestJSONAndTextSinks(t *testing.T) {
	e := scanner.Event{Time: time.Unix(0, 0).UTC(), Kind: "MODIFIED", Path: "/x",
		OldHash: strings.Repeat("a", 64), NewHash: strings.Repeat("b", 64), Source: "event"}
	var jb bytes.Buffer
	scanner.JSONSink(&jb)(e)
	var back scanner.Event
	if err := json.Unmarshal(jb.Bytes(), &back); err != nil || back != e {
		t.Fatalf("json round trip: %v %+v", err, back)
	}
	var tb bytes.Buffer
	scanner.TextSink(&tb)(e)
	if !strings.Contains(tb.String(), "MODIFIED") || !strings.Contains(tb.String(), "/x") {
		t.Fatal(tb.String())
	}
	if l := scanner.FormatLine(e); !strings.Contains(l, `path="/x"`) {
		t.Fatal(l)
	}
}
