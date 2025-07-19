//go:build windows
// +build windows

package logging

import (
	"bytes"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// We will use this package to wrap log messages coming from libraries who have no interest
// in generating structured output.

var (
	ldapliblogmatcher = regexp.MustCompile(`^\d{4}\/\d{1,2}\/\d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2} `)

	// Buffer pool for string operations to reduce allocations
	bufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

func InitLogging(reqdebug bool, reqsyslog bool, reqstructlog bool) zerolog.Logger {
	var level zerolog.Level
	if reqdebug {
		level = zerolog.DebugLevel
	} else {
		level = zerolog.InfoLevel
	}

	var mainWriter io.Writer
	if reqstructlog {
		// Vroom vroom
		mainWriter = os.Stderr
		zerolog.TimeFieldFormat = time.RFC1123Z
	} else {
		// This is the inefficient writer
		mainWriter = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC1123Z}
	}

	logr := zerolog.New(mainWriter).Level(level).With().Timestamp().Logger()

	log.SetOutput(customWriter{logr: logr, structlog: reqstructlog})

	return logr
}

type customWriter struct {
	logr      zerolog.Logger
	structlog bool
}

// escapeJSONString efficiently escapes JSON strings without multiple allocations
func escapeJSONString(s string) string {
	if strings.IndexByte(s, '"') == -1 && strings.IndexByte(s, '\\') == -1 {
		return s
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			buf.WriteByte(s[i])
		}
	}
	return buf.String()
}

// extractMessage efficiently extracts the message from log output
func extractMessage(p []byte) string {
	// Quick check if we have a timestamp prefix
	if len(p) < 19 || p[4] != '/' || p[7] != '/' || p[10] != ' ' || p[13] != ':' || p[16] != ':' {
		// No timestamp prefix, return trimmed content
		return strings.TrimSpace(string(p))
	}

	// Check if it matches our timestamp pattern more efficiently
	if p[0] >= '0' && p[0] <= '9' && p[1] >= '0' && p[1] <= '9' && p[2] >= '0' && p[2] <= '9' && p[3] >= '0' && p[3] <= '9' {
		// Likely has timestamp, extract message part
		if len(p) > 19 {
			return strings.TrimSpace(string(p[19:]))
		}
	}

	return strings.TrimSpace(string(p))
}

func (e customWriter) Write(p []byte) (int, error) {
	msg := extractMessage(p)

	if e.structlog {
		// Use a more efficient approach for structured logging
		escapedMsg := escapeJSONString(msg)
		now := time.Now().Format(time.RFC1123Z)

		// Pre-allocate buffer with estimated size to avoid multiple allocations
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		buf.WriteString(`{"level":"info","time":"`)
		buf.WriteString(now)
		buf.WriteString(`","message":"`)
		buf.WriteString(escapedMsg)
		buf.WriteString(`"}`)
		buf.WriteByte('\n')

		_, err := os.Stderr.Write(buf.Bytes())
		return len(p), err
	} else {
		e.logr.Info().Msg(msg)
	}
	return len(p), nil
}
