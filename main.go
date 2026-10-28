// hashdog — Merkle-tree file integrity monitor.
//
//	hashdog keygen    -out hashdog              create ed25519 keypair
//	hashdog baseline  -dir D -key K -out B [-exclude G]... [-config F]  write a signed baseline
//	hashdog check     -dir D -baseline B -pub P one-shot verify (exit 1 = changes, 2 = tampered baseline, 4 = legacy/unsupported baseline format)
//	hashdog watch     -dir D [-baseline B -pub P] [-interval 5m] [-paranoid] [-json] [-syslog]
//	hashdog proof     -dir D -file REL          Merkle inclusion proof (JSON) + self-check
//	hashdog version                              print version and baseline format
//	hashdog verify-proof -proof F -root HEX     verify a proof offline
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DakodaStemen/hashdog/internal/baseline"
	"github.com/DakodaStemen/hashdog/internal/config"
	"github.com/DakodaStemen/hashdog/internal/filter"
	"github.com/DakodaStemen/hashdog/internal/merkle"
	"github.com/DakodaStemen/hashdog/internal/scanner"
)

// Set at release time by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(args)
	case "baseline":
		err = cmdBaseline(args)
	case "check":
		err = cmdCheck(args)
	case "watch":
		err = cmdWatch(args)
	case "proof":
		err = cmdProof(args)
	case "verify-proof":
		err = cmdVerifyProof(args)
	case "version", "-version", "--version":
		fmt.Println(versionString())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashdog:", err)
		if errors.Is(err, baseline.ErrTampered) {
			os.Exit(2)
		}
		if errors.Is(err, errChanges) {
			os.Exit(1)
		}
		if errors.Is(err, baseline.ErrLegacyFormat) || errors.Is(err, baseline.ErrUnsupportedVersion) {
			os.Exit(4)
		}
		os.Exit(3)
	}
}

var errChanges = errors.New("changes detected")

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ruleFlags are the -config/-include/-exclude flags shared by baseline, check
// and watch.
type ruleFlags struct {
	cfg              *string
	include, exclude multiFlag
}

func addRuleFlags(fs *flag.FlagSet) *ruleFlags {
	r := &ruleFlags{}
	r.cfg = fs.String("config", "", "YAML/JSON file with include/exclude glob rules")
	fs.Var(&r.exclude, "exclude", "glob to leave out of the tree (repeatable; e.g. '*.log', 'var/cache/**')")
	fs.Var(&r.include, "include", "glob allow-list for files (repeatable); if given, only matching files are monitored")
	return r
}

// rules merges the config file and flags into one compiled set (nil if none).
func (r *ruleFlags) rules() (*filter.Rules, error) {
	inc, exc := []string(r.include), []string(r.exclude)
	if *r.cfg != "" {
		c, err := config.Load(*r.cfg)
		if err != nil {
			return nil, err
		}
		inc, exc = append(c.Include, inc...), append(c.Exclude, exc...)
	}
	return filter.New(inc, exc)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hashdog <keygen|baseline|check|watch|proof|verify-proof> [flags]")
	os.Exit(64)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "hashdog", "key file prefix (writes PREFIX.key and PREFIX.pub)")
	fs.Parse(args)
	pub, priv, err := baseline.GenerateKey()
	if err != nil {
		return err
	}
	if err := baseline.WriteKeys(*out, pub, priv); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (private, 0600) and %s.pub\n", *out, *out)
	return nil
}

func cmdBaseline(args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to snapshot")
	key := fs.String("key", "hashdog.key", "private key file")
	out := fs.String("out", "baseline.json", "output file")
	rf := addRuleFlags(fs)
	fs.Parse(args)
	priv, err := baseline.ReadPrivateKey(*key)
	if err != nil {
		return err
	}
	rules, err := rf.rules()
	if err != nil {
		return err
	}
	tree, err := merkle.BuildWith(*dir, merkle.Options{Rules: rules})
	if err != nil {
		return err
	}
	if err := baseline.Save(*out, baseline.SignWith(tree, priv, time.Now(), rules)); err != nil {
		return err
	}
	fmt.Printf("signed baseline %s  root=%s\n", *out, tree.HexHash())
	return nil
}

// loadBaseline verifies the baseline and returns its tree and the include/
// exclude rules it was signed with. Rules given on the command line or in a
// config file must equal the signed ones: scanning with different rules would
// report phantom ADDED/REMOVED files, and letting an unsigned file widen the
// exclusions would let an attacker hide changes.
func loadBaseline(path, pubPath, dir string, rf *ruleFlags) (*merkle.Node, *filter.Rules, error) {
	pub, err := baseline.ReadPublicKey(pubPath)
	if err != nil {
		return nil, nil, err
	}
	f, tree, err := baseline.Load(path, pub, dir)
	if err != nil {
		return nil, nil, err
	}
	signed, err := f.Rules()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", baseline.ErrTampered, err)
	}
	given, err := rf.rules()
	if err != nil {
		return nil, nil, err
	}
	if given != nil && !filter.Equal(given, signed) {
		return nil, nil, errors.New("include/exclude rules differ from the ones signed into the baseline; " +
			"omit them to use the signed rules, or re-create the baseline with the new rules")
	}
	return tree, signed, nil
}

func sinks(jsonOut, sys bool) ([]scanner.Sink, error) {
	var s []scanner.Sink
	if jsonOut {
		s = append(s, scanner.JSONSink(os.Stdout))
	} else {
		s = append(s, scanner.TextSink(os.Stdout))
	}
	if sys {
		ss, err := scanner.SyslogSink()
		if err != nil {
			return nil, err
		}
		s = append(s, ss)
	}
	return s, nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to verify")
	bl := fs.String("baseline", "baseline.json", "signed baseline")
	pub := fs.String("pub", "hashdog.pub", "public key")
	js := fs.Bool("json", false, "JSON-lines alerts")
	sys := fs.Bool("syslog", false, "also send alerts to syslog")
	rf := addRuleFlags(fs)
	fs.Parse(args)
	tree, rules, err := loadBaseline(*bl, *pub, *dir, rf)
	if err != nil {
		return err
	}
	sk, err := sinks(*js, *sys)
	if err != nil {
		return err
	}
	m, err := scanner.New(scanner.Config{Root: *dir, Baseline: tree, Rules: rules, Sinks: sk, Quiet: true})
	if err != nil {
		return err
	}
	if n := len(m.Scan("baseline", true)); n > 0 {
		return fmt.Errorf("%w: %d file(s)", errChanges, n)
	}
	fmt.Println("OK: tree matches signed baseline root", tree.HexHash())
	return nil
}

func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to monitor")
	interval := fs.Duration("interval", 5*time.Minute, "periodic full-verify interval (0 disables)")
	events := fs.Bool("events", true, "react to filesystem events (fsnotify)")
	debounce := fs.Duration("debounce", 200*time.Millisecond, "event coalescing window")
	paranoid := fs.Bool("paranoid", false, "never use the stat cache: every scan (including event-triggered) rehashes every file")
	bl := fs.String("baseline", "", "signed baseline to start from (optional)")
	pub := fs.String("pub", "hashdog.pub", "public key for -baseline")
	js := fs.Bool("json", false, "JSON-lines alerts")
	sys := fs.Bool("syslog", false, "also send alerts to syslog")
	rf := addRuleFlags(fs)
	fs.Parse(args)

	cfg := scanner.Config{Root: *dir, Interval: *interval, Watch: *events, Debounce: *debounce, Paranoid: *paranoid}
	if *bl != "" {
		tree, rules, err := loadBaseline(*bl, *pub, *dir, rf)
		if err != nil {
			return err
		}
		cfg.Baseline, cfg.Rules = tree, rules
	} else {
		var err error
		if cfg.Rules, err = rf.rules(); err != nil {
			return err
		}
	}
	var err error
	if cfg.Sinks, err = sinks(*js, *sys); err != nil {
		return err
	}
	mon, err := scanner.New(cfg)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigs; close(done) }()
	return mon.Run(done)
}

func cmdProof(args []string) error {
	fs := flag.NewFlagSet("proof", flag.ExitOnError)
	dir := fs.String("dir", ".", "watched directory")
	file := fs.String("file", "", "file path relative to -dir")
	out := fs.String("out", "", "write proof JSON here (default: stdout)")
	rf := addRuleFlags(fs)
	fs.Parse(args)
	if *file == "" {
		return errors.New("-file is required")
	}
	rules, err := rf.rules()
	if err != nil {
		return err
	}
	tree, err := merkle.BuildWith(*dir, merkle.Options{Rules: rules})
	if err != nil {
		return err
	}
	p, err := merkle.Prove(tree, *file)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if *out != "" {
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			return err
		}
	} else {
		fmt.Println(string(b))
	}
	if err := p.Verify(tree.HexHash()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "proof for %s: %d levels, resolves to root %s ✔\n", *file, len(p.Steps), tree.HexHash())
	return nil
}

func cmdVerifyProof(args []string) error {
	fs := flag.NewFlagSet("verify-proof", flag.ExitOnError)
	pf := fs.String("proof", "", "proof JSON file")
	root := fs.String("root", "", "trusted root hash (hex)")
	content := fs.String("content", "", "optional: local file whose SHA-256 must equal the proof's leaf")
	fs.Parse(args)
	b, err := os.ReadFile(*pf)
	if err != nil {
		return err
	}
	var p merkle.Proof
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if *content != "" {
		f, err := os.Open(*content)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != p.ContentHash {
			return fmt.Errorf("file %s hashes to %s, proof is for content %s", filepath.Base(*content), got, p.ContentHash)
		}
		// Metadata is bound to the leaf by the proof itself (checked in Verify);
		// compare the live file against it so a chmod'ed copy is flagged.
		if fi, err := os.Lstat(*content); err == nil && merkle.ModeBits(fi.Mode()) != p.Mode {
			fmt.Fprintf(os.Stderr, "warning: %s has mode %o, proof recorded %o\n", filepath.Base(*content), merkle.ModeBits(fi.Mode()), p.Mode)
		}
	}
	if err := p.Verify(*root); err != nil {
		return err
	}
	fmt.Printf("VALID: %s is included under root %s\n", p.Path, *root)
	return nil
}

func init() { log.SetFlags(log.Ltime) }

func versionString() string {
	return fmt.Sprintf("hashdog %s (commit %s, built %s, baseline format v%d)", version, commit, date, baseline.Version)
}
