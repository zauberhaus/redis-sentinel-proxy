package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Protocol limits, mirroring the redis maxima, so a malformed or malicious
// peer cannot make the proxy buffer unbounded amounts of memory.
const (
	maxRESPElements = 1024 * 1024
	maxBulkLen      = 512 * 1024 * 1024
	maxLineLen      = 64 * 1024
)

// errInlineCommand reports a client that speaks the inline (telnet-style)
// protocol instead of RESP arrays; the session falls back to a plain pipe.
var errInlineCommand = errors.New("inline command")

// readLine reads one CRLF-terminated line including the terminator.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		line = append(line, part...)
		if err == nil {
			break
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
		if len(line) > maxLineLen {
			return nil, errors.New("RESP line too long")
		}
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("malformed RESP line %q", line)
	}
	return line, nil
}

func parseRESPInt(b []byte) (int64, error) {
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed RESP length %q", b)
	}
	return n, nil
}

// readCommand reads one client command (a RESP array of bulk strings) and
// returns its uppercased name plus the raw bytes to forward. An empty name
// with nil error means an empty array, which redis treats as a no-op.
func readCommand(br *bufio.Reader) (string, []byte, error) {
	first, err := br.Peek(1)
	if err != nil {
		return "", nil, err
	}
	if first[0] != '*' {
		return "", nil, errInlineCommand
	}

	var raw bytes.Buffer
	line, err := readLine(br)
	if err != nil {
		return "", nil, err
	}
	raw.Write(line)

	n, err := parseRESPInt(line[1 : len(line)-2])
	if err != nil {
		return "", nil, err
	}
	if n > maxRESPElements {
		return "", nil, fmt.Errorf("command with %d arguments exceeds the protocol limit", n)
	}

	var name string
	for i := int64(0); i < n; i++ {
		line, err := readLine(br)
		if err != nil {
			return "", nil, err
		}
		raw.Write(line)
		if line[0] != '$' {
			return "", nil, fmt.Errorf("expected bulk string in command, got %q", line[0])
		}
		l, err := parseRESPInt(line[1 : len(line)-2])
		if err != nil {
			return "", nil, err
		}
		if l < 0 || l > maxBulkLen {
			return "", nil, fmt.Errorf("invalid bulk string length %d in command", l)
		}
		payload := make([]byte, l+2)
		if _, err := io.ReadFull(br, payload); err != nil {
			return "", nil, err
		}
		raw.Write(payload)
		if i == 0 {
			name = strings.ToUpper(string(payload[:l]))
		}
	}
	return name, raw.Bytes(), nil
}

// copyRESP streams exactly one RESP reply from br to w. RESP3 attribute
// sections and out-of-band push messages preceding the reply are passed
// through without counting as the reply itself.
func copyRESP(w io.Writer, br *bufio.Reader) error {
	remaining := int64(1)
	for remaining > 0 {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		payload := line[1 : len(line)-2]

		switch line[0] {
		case '+', '-', ':', ',', '#', '(', '_': // single-line types
			remaining--
		case '$', '=', '!': // length-prefixed blobs (-1 = null)
			n, err := parseRESPInt(payload)
			if err != nil {
				return err
			}
			if n > maxBulkLen {
				return fmt.Errorf("bulk string of %d bytes exceeds the protocol limit", n)
			}
			if n >= 0 {
				if _, err := io.CopyN(w, br, n+2); err != nil {
					return err
				}
			}
			remaining--
		case '*', '~': // array, set (-1 = null)
			n, err := parseRESPInt(payload)
			if err != nil {
				return err
			}
			if n > maxRESPElements {
				return fmt.Errorf("aggregate with %d elements exceeds the protocol limit", n)
			}
			remaining--
			if n > 0 {
				remaining += n
			}
		case '%': // map: n key-value pairs
			n, err := parseRESPInt(payload)
			if err != nil {
				return err
			}
			if n > maxRESPElements {
				return fmt.Errorf("map with %d entries exceeds the protocol limit", n)
			}
			remaining--
			if n > 0 {
				remaining += 2 * n
			}
		case '|': // attribute: precedes the value it annotates
			n, err := parseRESPInt(payload)
			if err != nil {
				return err
			}
			if n > maxRESPElements {
				return fmt.Errorf("attribute with %d entries exceeds the protocol limit", n)
			}
			if n > 0 {
				remaining += 2 * n
			}
		case '>': // push: out-of-band, does not consume the awaited reply
			n, err := parseRESPInt(payload)
			if err != nil {
				return err
			}
			if n > maxRESPElements {
				return fmt.Errorf("push with %d elements exceeds the protocol limit", n)
			}
			if n > 0 {
				remaining += n
			}
		default:
			return fmt.Errorf("unexpected RESP type %q", line[0])
		}
	}
	return nil
}
