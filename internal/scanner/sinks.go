package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// TextSink writes human-readable alerts.
func TextSink(w io.Writer) Sink {
	var mu sync.Mutex
	return func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "[ALERT] %-8s %s  (%s)\n", e.Kind, e.Path, e.Source)
		if len(e.Changed) > 0 {
			fmt.Fprintf(w, "        changed: %s\n", strings.Join(e.Changed, ","))
		}
		if e.OldHash != "" {
			fmt.Fprintf(w, "        old: %s\n", e.OldHash[:16]+"…")
		}
		if e.NewHash != "" {
			fmt.Fprintf(w, "        new: %s\n", e.NewHash[:16]+"…")
		}
	}
}

// JSONSink writes one JSON object per line.
func JSONSink(w io.Writer) Sink {
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	return func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(e)
	}
}

// FormatLine renders an event as a single line (used for syslog).
func FormatLine(e Event) string {
	l := fmt.Sprintf("%s path=%q old=%s new=%s source=%s", e.Kind, e.Path, e.OldHash, e.NewHash, e.Source)
	if len(e.Changed) > 0 {
		l += " changed=" + strings.Join(e.Changed, ",")
	}
	return l
}
