// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package syncbuffer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncBuffer_Write(t *testing.T) {
	testCases := map[string]struct {
		input        []byte
		wantedOutput string
	}{
		"append to custom buffer with simple input": {
			input:        []byte("hello world"),
			wantedOutput: "hello world",
		},
		"append to custom buffer with empty input": {
			input:        []byte(""),
			wantedOutput: "",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			sb := &SyncBuffer{}

			// WHEN
			sb.Write(tc.input)

			// THEN
			require.Equal(t, tc.wantedOutput, sb.buf.String())
		})
	}
}

func TestSyncBuffer_IsDone(t *testing.T) {
	testCases := map[string]struct {
		buffer     *SyncBuffer
		wantedDone bool
	}{
		"Buffer is done": {
			buffer:     &SyncBuffer{done: make(chan struct{}), buf: bytes.Buffer{}},
			wantedDone: true,
		},
		"Buffer is not done": {
			buffer: &SyncBuffer{done: make(chan struct{}), buf: bytes.Buffer{}},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			if tc.wantedDone {
				tc.buffer.MarkDone()
			}

			// WHEN
			actual := tc.buffer.IsDone()

			// THEN
			require.Equal(t, tc.wantedDone, actual)

		})
	}
}

func TestSyncBuffer_strings(t *testing.T) {
	testCases := map[string]struct {
		input  []byte
		wanted []string
	}{
		"single line in buffer": {
			input:  []byte("hello"),
			wanted: []string{"hello"},
		},
		"multiple lines in buffer": {
			input:  []byte("hello\nworld\n"),
			wanted: []string{"hello", "world"},
		},
		"empty buffer": {
			input: []byte(""),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			// GIVEN
			sb := &SyncBuffer{}
			sb.Write(tc.input)

			// WHEN
			actual := sb.strings()

			// THEN
			require.Equal(t, tc.wanted, actual)
		})
	}
}

func TestTermPrinter_lastNLines(t *testing.T) {
	testCases := map[string]struct {
		logs     []string
		wanted   []string
		numLines int
	}{
		"more than five lines": {
			logs:   []string{"line1", "line2", "line3", "line4", "line5", "line6", "line7"},
			wanted: []string{"line3", "line4", "line5", "line6", "line7"},
		},
		"less than five lines": {
			logs:   []string{"line1", "line2"},
			wanted: []string{"line1", "line2", "", "", ""},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			tp := &TermPrinter{}

			// WHEN
			actual := tp.lastNLines(tc.logs, 5)

			// THEN
			require.Equal(t, tc.wanted, actual)
		})
	}
}

func TestTermPrinter_Print(t *testing.T) {
	testCases := map[string]struct {
		logs       []string
		inNumLines int
		inLabel    string
		wanted     string
	}{
		"display label and last five log lines": {
			logs: []string{
				"line 1",
				"line 2",
				"line 3",
				"line 4",
				"line 5",
				"line 6",
				"line 7",
				"line 8",
			},
			inNumLines: 5,
			inLabel:    "docker build label",
			wanted: `docker build label
line 4
line 5
line 6
line 7
line 8
`,
		},
		"if input for number of lines is zero": {
			logs:       []string{"line 1", "line 2", "line 3", "line 4"},
			inNumLines: 0,
			wanted:     "\n",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			buf := &SyncBuffer{
				Label: tc.inLabel,
				buf:   bytes.Buffer{},
			}
			buf.buf.Write([]byte(strings.Join(tc.logs, "\n")))
			termOut := &bytes.Buffer{}
			printer := TermPrinter{
				buf:  buf,
				term: termOut,
			}

			// WHEN
			printer.Print(tc.inNumLines)

			// THEN
			require.Equal(t, tc.wanted, termOut.String())
		})
	}
}

func TestTermPrinter_PrintAll(t *testing.T) {
	testCases := map[string]struct {
		logs   []string
		wanted string
	}{
		"display all the output at once": {
			logs: []string{
				"label",
				"line 2",
				"line 3",
				"line 4",
				"line 5",
				"line 6",
				"line 7",
				"line 8",
			},
			wanted: `label
line 2
line 3
line 4
line 5
line 6
line 7
line 8
`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			buf := &SyncBuffer{
				buf: bytes.Buffer{},
			}
			buf.buf.Write([]byte(strings.Join(tc.logs, "\n")))
			termOut := &bytes.Buffer{}
			printer := TermPrinter{
				buf:  buf,
				term: termOut,
			}
			// WHEN
			printer.PrintAll()

			// THEN
			require.Equal(t, tc.wanted, termOut.String())
		})
	}
}
