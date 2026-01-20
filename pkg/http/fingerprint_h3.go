package http

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// GetHTTP3SettingName returns the name for a known HTTP/3 setting ID
func GetHTTP3SettingName(id uint64) string {
	switch id {
	case 0x1:
		return "SETTINGS_QPACK_MAX_TABLE_CAPACITY"
	case 0x6:
		return "SETTINGS_MAX_FIELD_SECTION_SIZE"
	case 0x7:
		return "SETTINGS_QPACK_BLOCKED_STREAMS"
	case 0x8:
		return "SETTINGS_ENABLE_CONNECT_PROTOCOL"
	case 0x33:
		return "SETTINGS_H3_DATAGRAM"
	default:
		// Check if it's a GREASE value (0x1f * N + 0x21)
		if (id-0x21)%0x1f == 0 {
			return "GREASE"
		}
		return fmt.Sprintf("UNKNOWN_%d", id)
	}
}

// GetHTTP3SettingsFingerprint generates a fingerprint string from HTTP/3 settings
// Format: "id:value;id:value;...|header_order"
func GetHTTP3SettingsFingerprint(settings []types.Http3SettingPair, headerOrder string) string {
	var parts []string
	for _, s := range settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	fp := strings.Join(parts, ";")
	if headerOrder != "" {
		fp += "|" + headerOrder
	}
	return fp
}

// GetHTTP3FingerprintHash returns MD5 hash of the fingerprint
func GetHTTP3FingerprintHash(fingerprint string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fingerprint)))
}

// GetHTTP3HeaderOrder extracts pseudo-header order from headers
// Headers are in format "key: value"
// Returns format like "m,a,s,p" for :method, :authority, :scheme, :path
func GetHTTP3HeaderOrder(headers []string) string {
	var order []string
	for _, h := range headers {
		if strings.HasPrefix(h, ":") {
			// Header format is ":name: value", extract name
			parts := strings.SplitN(h, ": ", 2)
			if len(parts) >= 1 {
				name := parts[0][1:] // Remove leading ":"
				if len(name) > 0 {
					order = append(order, string(name[0]))
				}
			}
		}
	}
	return strings.Join(order, ",")
}
