package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadCommand(t *testing.T) {
	tests := []struct {
		in      string
		name    string
		wantErr error
	}{
		{"*3\r\n$3\r\nset\r\n$1\r\nk\r\n$1\r\nv\r\n", "SET", nil},
		{"*1\r\n$4\r\nPING\r\n", "PING", nil},
		{"*0\r\n", "", nil},
		{"PING\r\n", "", errInlineCommand},
	}
	for _, tt := range tests {
		br := bufio.NewReader(strings.NewReader(tt.in))
		name, raw, err := readCommand(br)
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("readCommand(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if name != tt.name {
			t.Errorf("readCommand(%q) name = %q, want %q", tt.in, name, tt.name)
		}
		if string(raw) != tt.in {
			t.Errorf("readCommand(%q) raw = %q, want the input unchanged", tt.in, raw)
		}
	}
}

func TestCopyRESP(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"simple string", "+OK\r\n"},
		{"error", "-ERR unknown command\r\n"},
		{"integer", ":42\r\n"},
		{"bulk string", "$5\r\nhello\r\n"},
		{"null bulk string", "$-1\r\n"},
		{"empty array", "*0\r\n"},
		{"null array", "*-1\r\n"},
		{"nested array", "*2\r\n*2\r\n$1\r\na\r\n:1\r\n$1\r\nb\r\n"},
		{"map", "%2\r\n$1\r\na\r\n:1\r\n$1\r\nb\r\n:2\r\n"},
		{"set", "~2\r\n:1\r\n:2\r\n"},
		{"double", ",3.14\r\n"},
		{"boolean", "#t\r\n"},
		{"big number", "(12345678901234567890\r\n"},
		{"null", "_\r\n"},
		{"verbatim string", "=15\r\ntxt:Some string\r\n"},
		{"bulk error", "!21\r\nSYNTAX invalid syntax\r\n"},
		{"attribute before value", "|1\r\n$3\r\nttl\r\n:100\r\n:1\r\n"},
		{"push before value", ">2\r\n$7\r\nmessage\r\n$2\r\nhi\r\n+OK\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tt.in + "+NEXT\r\n"))
			var out bytes.Buffer
			if err := copyRESP(&out, br); err != nil {
				t.Fatalf("copyRESP(%q) error = %v", tt.in, err)
			}
			if out.String() != tt.in {
				t.Errorf("copyRESP(%q) copied %q, want the value unchanged", tt.in, out.String())
			}
			// The next reply must remain unread.
			rest, _ := br.ReadString('\n')
			if rest != "+NEXT\r\n" {
				t.Errorf("copyRESP(%q) consumed too much, next read = %q", tt.in, rest)
			}
		})
	}
}

func TestReadCommandMalformed(t *testing.T) {
	for _, in := range []string{
		"*2\r\n:1\r\n:2\r\n",            // command elements must be bulk strings
		"*1\r\n$-1\r\n",                 // negative bulk length
		"*1\r\n$notanumber\r\nPING\r\n", // malformed bulk length
		"*notanumber\r\n",               // malformed array length
		"*2000000\r\n",                  // argument count over the protocol limit
		"*1\n$4\nPING\n",                // LF without CR
		"*1\r\n$4\r\nPI",                // truncated payload
	} {
		br := bufio.NewReader(strings.NewReader(in))
		if _, _, err := readCommand(br); err == nil {
			t.Errorf("readCommand(%q) expected an error", in)
		}
	}
}

func TestCopyRESPMalformed(t *testing.T) {
	for _, in := range []string{
		"?bogus\r\n",
		"$notanumber\r\n",
		"+no terminator",
		"*2\r\n:1\r\n",      // truncated array
		"$999999999999\r\n", // bulk length over the protocol limit
		"*2000000\r\n",      // array size over the protocol limit
		"%2000000\r\n",      // map size over the protocol limit
		"|2000000\r\n",      // attribute size over the protocol limit
		">2000000\r\n",      // push size over the protocol limit
		"$5\r\nhel",         // truncated bulk payload
	} {
		br := bufio.NewReader(strings.NewReader(in))
		if err := copyRESP(new(bytes.Buffer), br); err == nil {
			t.Errorf("copyRESP(%q) expected an error", in)
		}
	}
}
