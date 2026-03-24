// hashwarden — file integrity monitor
//
// Watches a directory tree for unauthorized changes by maintaining a
// Merkle tree of SHA-256 file hashes.  Any modification, addition, or
// deletion is printed to stdout as an alert.
//
// Usage:
//
//   hashwarden -dir /etc -interval 30s
//
// Press Ctrl-C to stop.
package main

import (
	"fim/internal/scanner"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	dir := flag.String("dir", ".", "directory to monitor")
	interval := flag.Duration("interval", 30*time.Second, "rescan interval (e.g. 10s, 1m)")
	flag.Parse()

	mon, err := scanner.New(scanner.Config{
		Root:     *dir,
		Interval: *interval,
	})
	if err != nil {
		log.Fatalf("failed to start monitor: %v", err)
	}

	done := make(chan struct{})

	// Catch SIGINT / SIGTERM for a clean shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		close(done)
	}()

	mon.Run(done)
}
