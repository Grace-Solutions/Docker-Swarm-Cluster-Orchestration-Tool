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

	lvl := parseLevel(os.Getenv("CLUSTERCTL_LOG_LEVEL"))

	// Default to a local log file so operators can review history even when
	// stderr is ephemeral. The path can be overridden via CLUSTERCTL_LOG_FILE.
	logPath := strings.TrimSpace(os.Getenv("CLUSTERCTL_LOG_FILE"))
	if logPath == "" {
		logPath = "clusterctl.log"
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

// Debugw logs a debug message. Extra key/value pairs are ignored.
func (l *simpleLogger) Debugw(msg string, _ ...interface{}) {
	l.log(levelDebug, "DEBUG", msg)
}

// Infow logs an info message. Extra key/value pairs are ignored.
func (l *simpleLogger) Infow(msg string, _ ...interface{}) {
	l.log(levelInfo, "INFO", msg)
}

// Warnw logs a warning message. Extra key/value pairs are ignored.
func (l *simpleLogger) Warnw(msg string, _ ...interface{}) {
	l.log(levelWarn, "WARN", msg)
}

// Errorw logs an error message. Extra key/value pairs are ignored.
func (l *simpleLogger) Errorw(msg string, _ ...interface{}) {
	l.log(levelError, "ERROR", msg)
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

