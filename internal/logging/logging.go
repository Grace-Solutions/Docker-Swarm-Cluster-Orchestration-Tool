package logging

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// level represents the minimum severity that will be emitted.
type level int

const (
	levelDebug level = iota
	levelInfo
	levelWarn
	levelError
)

// simpleLogger is a process-wide logger that writes plain-text lines to stderr
// in the format:
//   [utc-timestamp] - [LEVEL] - Message
//
// Structured key/value fields are intentionally ignored to keep logs concise and
// readable during cluster operations.
type simpleLogger struct {
	mu       sync.Mutex
	minLevel level
	file     *os.File
}

// logger is the global logger instance.
var logger *simpleLogger

// Init initialises the global logger. It is safe to call multiple times; the
// first successful call wins.
func Init() error {
	if logger != nil {
		return nil
	}

	lvl := parseLevel(os.Getenv("DSCOTCTL_LOG_LEVEL"))

	// Default to a local log file so operators can review history even when
	// stderr is ephemeral. The path can be overridden via DSCOTCTL_LOG_FILE.
	logPath := strings.TrimSpace(os.Getenv("DSCOTCTL_LOG_FILE"))
	if logPath == "" {
		logPath = "dscotctl.log"
	}

	var f *os.File
	if logPath != "" {
		file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			// We can't rely on the logger yet, so emit a best-effort warning
			// directly to stderr and continue with stderr-only logging.
			ts := time.Now().UTC().Format(time.RFC3339)
			fmt.Fprintf(os.Stderr, "[%s] - [WARN] - failed to open log file %s: %v\n", ts, logPath, err)
		} else {
			f = file
		}
	}

	logger = &simpleLogger{minLevel: lvl, file: f}
	return nil
}

func parseLevel(s string) level {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "debug":
		return levelDebug
	case "warn", "warning":
		return levelWarn
	case "error":
		return levelError
	default:
		return levelInfo
	}
}

func (l *simpleLogger) log(lvl level, name, msg string) {
	if l == nil || lvl < l.minLevel {
		return
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	l.mu.Lock()
	defer l.mu.Unlock()

	line := fmt.Sprintf("[%s] - [%s] - %s\n", ts, name, msg)
	_, _ = os.Stderr.WriteString(line)
	if l.file != nil {
		_, _ = l.file.WriteString(line)
	}
}

// Debugw logs a debug message. Key/value pairs are formatted inline.
func (l *simpleLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.log(levelDebug, "DEBUG", formatMessage(msg, keysAndValues...))
}

// Infow logs an info message. Key/value pairs are formatted inline.
func (l *simpleLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.log(levelInfo, "INFO", formatMessage(msg, keysAndValues...))
}

// Warnw logs a warning message. Key/value pairs are formatted inline.
func (l *simpleLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.log(levelWarn, "WARN", formatMessage(msg, keysAndValues...))
}

// Errorw logs an error message. Key/value pairs are formatted inline.
func (l *simpleLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.log(levelError, "ERROR", formatMessage(msg, keysAndValues...))
}

// formatMessage formats a message with key/value pairs inline.
func formatMessage(msg string, keysAndValues ...interface{}) string {
	if len(keysAndValues) == 0 {
		return msg
	}

	var parts []string
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			value := fmt.Sprintf("%v", keysAndValues[i+1])
			parts = append(parts, fmt.Sprintf("%s=%s", key, value))
		}
	}

	if len(parts) > 0 {
		return fmt.Sprintf("%s %s", msg, strings.Join(parts, " "))
	}
	return msg
}

// With returns the same logger; key/value context is ignored to keep output
// minimal.
func (l *simpleLogger) With(_ ...interface{}) *simpleLogger {
	return l
}

// L returns the process-wide logger, initialising it on first use if needed.
func L() *simpleLogger {
	if logger == nil {
		_ = Init()
	}
	return logger
}

// Sync flushes and closes the log file if one is open.
func Sync() {
	if logger == nil || logger.file == nil {
		return
	}

	logger.mu.Lock()
	defer logger.mu.Unlock()

	_ = logger.file.Sync()
	_ = logger.file.Close()
	logger.file = nil
}

// FormatNodeMessage formats a log message with node identifier.
// Format: "prefix [hostname - [newHostname] - role] message"
// If newHostname is blank: "prefix [hostname - role] message"
// If role is blank: "prefix [hostname - [newHostname]] message"
// If both blank: "prefix [hostname] message"
// Example: FormatNodeMessage("→", "192.168.1.1", "node1", "manager", "installing Docker")
//
//	-> "→ [192.168.1.1 - [node1] - manager] installing Docker"
func FormatNodeMessage(prefix, hostname, newHostname, role, message string) string {
	parts := []string{hostname}

	if newHostname != "" {
		parts = append(parts, fmt.Sprintf("[%s]", newHostname))
	}

	if role != "" {
		parts = append(parts, role)
	}

	identifier := strings.Join(parts, " - ")
	return fmt.Sprintf("%s [%s] %s", prefix, identifier, message)
}

