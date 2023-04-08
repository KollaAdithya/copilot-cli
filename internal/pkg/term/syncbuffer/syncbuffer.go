// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package syncbuffer provides a goroutine safe bytes.Buffer as well printing functionality to the terminal.
package syncbuffer

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// FileWriter is the interface to write to a file.
type FileWriter interface {
	io.Writer
}

// SyncBuffer is a synchronized buffer that can be used to store output data and coordinate between multiple goroutines.
type SyncBuffer struct {
	Label string        // Label associated with the buffer.
	bufMu sync.Mutex    // bufMu is a mutex that can be used to protect access to the buffer.
	buf   bytes.Buffer  // buf is the buffer that stores the data.
	done  chan struct{} // done is a channel that can be used to signal when the operations are complete.
}

// NewSyncBuffer creates and returns a new SyncBuffer object with an initialized 'done' channel.
func NewSyncBuffer() *SyncBuffer {
	return &SyncBuffer{
		done: make(chan struct{}),
	}
}

// Write appends the given bytes to the buffer.
func (b *SyncBuffer) Write(p []byte) (n int, err error) {
	b.bufMu.Lock()
	defer b.bufMu.Unlock()
	return b.buf.Write(p)
}

// strings returns an empty slice if the buffer is empty.
// Otherwise, it returns a slice of all the lines stored in the buffer.
func (b *SyncBuffer) strings() []string {
	b.bufMu.Lock()
	defer b.bufMu.Unlock()
	lines := b.buf.String()
	if len(lines) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(lines), "\n")
}

// IsDone returns true if the Done channel has been closed, otherwise return false.
func (b *SyncBuffer) IsDone() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// MarkDone closes the Done channel.
func (b *SyncBuffer) MarkDone() {
	close(b.done)
}

// TermPrinter is a printer to display logs in the terminal.
type TermPrinter struct {
	term             FileWriter  // term writes logs to the terminal FileWriter.
	buf              *SyncBuffer // buf stores logs before writing to the terminal.
	PrevWrittenLines int         // number of lines written during the last call to writeLines.
	termWidth        int         // width of the terminal.
}

// NewTermPrinter returns a new instance of TermPrinter that writes logs to the given file writer and reads logs from a new synchronized buffer.
func NewTermPrinter(fw FileWriter, syncBuf *SyncBuffer) (*TermPrinter, error) {
	width, err := terminalWidth()
	if err != nil {
		return nil, fmt.Errorf("get terminal width: %w", err)
	}
	return &TermPrinter{
		term:      fw,
		buf:       syncBuf,
		termWidth: width,
	}, nil
}

// Print prints the label and the last N lines of logs to the termPrinter fileWriter.
func (tp *TermPrinter) Print(numLines int) {
	logs := tp.buf.strings()
	if len(logs) == 0 {
		return
	}
	outputLogs := tp.lastNLines(logs, numLines)
	tp.writeLines(tp.buf.Label, outputLogs)
}

// lastNLines returns the last N lines of the given logs where N is the value of numLines.
// If the logs slice contains fewer than N lines, all lines are returned.
func (tp *TermPrinter) lastNLines(logs []string, numLines int) []string {
	var start int
	if len(logs) > numLines {
		start = len(logs) - numLines
	}
	end := len(logs)

	// Extract the last N lines of fixed length.
	logLines := make([]string, numLines)
	idx := 0
	for start < end {
		logLines[idx] = strings.TrimSpace(logs[start])
		start++
		idx++
	}
	return logLines
}

// writeLines writes a label and output logs to the terminal associated with the TermPrinter.
func (tp *TermPrinter) writeLines(label string, outputLogs []string) {
	fmt.Fprintln(tp.term, label)
	for _, logLine := range outputLogs {
		fmt.Fprintln(tp.term, logLine)
	}
	tp.PrevWrittenLines = tp.calculateLinesCount(append(outputLogs, label))
}

// calculateLinesCount returns the number of lines needed to print the given string slice based on the terminal width.
func (tp *TermPrinter) calculateLinesCount(lines []string) int {
	var numLines float64
	for _, line := range lines {
		// Empty line should be considered as a new line
		if line == "" {
			numLines += 1
		}
		numLines += math.Ceil(float64(len(line)) / float64(tp.termWidth))
	}
	return int(numLines)
}

// PrintAll writes the entire contents of the buffer to the file writer.
func (tp *TermPrinter) PrintAll() {
	outputLogs := tp.buf.strings()
	for _, logLine := range outputLogs {
		fmt.Fprintln(tp.term, logLine)
	}
}

// terminalWidth returns the width of the terminal or an error if failed to get the width of terminal.
func terminalWidth() (int, error) {
	width, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil {
		return 0, err
	}
	return width, nil
}
