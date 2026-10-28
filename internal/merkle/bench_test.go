package merkle_test

import (
	"os"
	"testing"

	"github.com/DakodaStemen/hashdog/internal/merkle"
)

// Set HASHDOG_BENCH_DIR to a corpus directory to run these.
func benchDir(b *testing.B) string {
	d := os.Getenv("HASHDOG_BENCH_DIR")
	if d == "" {
		b.Skip("HASHDOG_BENCH_DIR not set")
	}
	return d
}

func BenchmarkFullBuild(b *testing.B) {
	d := benchDir(b)
	for i := 0; i < b.N; i++ {
		if _, err := merkle.Build(d); err != nil {
			b.Fatal(err)
		}
	}
}

// Rescan with the stat cache: what an event-triggered scan costs.
func BenchmarkCachedRescan(b *testing.B) {
	d := benchDir(b)
	prev, _ := merkle.Build(d)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := merkle.BuildWith(d, merkle.Options{Prev: prev}); err != nil {
			b.Fatal(err)
		}
	}
}
