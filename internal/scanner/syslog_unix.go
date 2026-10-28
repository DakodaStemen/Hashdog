//go:build !windows && !plan9

package scanner

import "log/syslog"

// SyslogSink sends alerts to the local syslog daemon (tag "hashdog").
func SyslogSink() (Sink, error) {
	w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_AUTH, "hashdog")
	if err != nil {
		return nil, err
	}
	return func(e Event) { w.Warning(FormatLine(e)) }, nil
}
