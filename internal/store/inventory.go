package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	maxInventoryBytes      = 8 << 20 // same ceiling as the agent WebSocket frame
	maxInventoryDepth      = 32
	maxInventoryJSONTokens = 50000 // keys, values, and opening/closing containers
)

const (
	// maxReportedUptime bounds the uptime an inventory may report. A negative
	// value, a longer one or anything but a JSON number gives no boot time.
	maxReportedUptime = 20 * 365 * 24 * time.Hour
	// bootJitter is how far a new boot time must move before it is stored.
	// Each snapshot measures the uptime a little before the server receives
	// it, which would otherwise rewrite the row every few minutes. A real
	// reboot moves it by at least the uptime the device had before.
	bootJitter = 2 * time.Minute
)

// reportedUptime reads the uptime_sec an agent reports in its inventory.
func reportedUptime(data []byte) (time.Duration, bool) {
	var inv struct {
		UptimeSec json.RawMessage `json:"uptime_sec"`
	}
	if json.Unmarshal(data, &inv) != nil || len(inv.UptimeSec) == 0 {
		return 0, false
	}
	// A JSON number only: ParseFloat refuses a quoted string or null.
	sec, err := strconv.ParseFloat(string(inv.UptimeSec), 64)
	if err != nil || math.IsNaN(sec) || sec < 0 || sec > maxReportedUptime.Seconds() {
		return 0, false
	}
	return time.Duration(sec * float64(time.Second)), true
}

// prepareInventory removes actual NUL characters from collected text before
// PostgreSQL JSONB rejects the entire snapshot. Do this on the server so agents
// already installed can report without an upgrade. Decode strings rather than
// replacing raw \\u0000 sequences, which would corrupt literal paths/text.
func prepareInventory(data []byte) ([]byte, error) {
	if len(data) > maxInventoryBytes {
		return nil, errors.New("inventory exceeds size limit")
	}
	if !json.Valid(data) {
		return nil, errors.New("inventory must be valid JSON")
	}
	if err := validateInventoryStructure(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // hardware sizes and other integers must keep their precision
	var snapshot map[string]any
	if err := dec.Decode(&snapshot); err != nil || snapshot == nil {
		return nil, errors.New("inventory must be a JSON object")
	}
	if err := cleanInventoryText(snapshot); err != nil {
		return nil, err
	}
	return json.Marshal(snapshot)
}

// Check the structure as a stream before building maps and slices. A frame's
// byte limit alone permits hundreds of thousands of tiny objects to amplify
// heap usage, or thousands of nesting levels to grow the normalizer's stack.
func validateInventoryStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	depth, tokens := 0, 0
	for {
		token, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("inventory must be valid JSON")
		}
		tokens++
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth > maxInventoryDepth || tokens > maxInventoryJSONTokens {
			return errors.New("inventory exceeds structure limits")
		}
	}
}

func cleanInventoryText(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			// Collected field names are fixed. Renaming arbitrary keys could
			// overwrite another field, so refuse those instead.
			if strings.ContainsRune(key, '\x00') {
				return errors.New("inventory field names must not contain NUL")
			}
			if text, ok := item.(string); ok {
				v[key] = strings.ReplaceAll(text, "\x00", "")
			} else if err := cleanInventoryText(item); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if text, ok := item.(string); ok {
				v[i] = strings.ReplaceAll(text, "\x00", "")
			} else if err := cleanInventoryText(item); err != nil {
				return err
			}
		}
	}
	return nil
}
