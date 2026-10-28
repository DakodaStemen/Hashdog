//go:build windows || plan9

package scanner

import "errors"

func SyslogSink() (Sink, error) { return nil, errors.New("syslog not supported on this platform") }
