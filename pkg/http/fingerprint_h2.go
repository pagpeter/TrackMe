package http

import (
	"fmt"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// Based on https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
// Fingerprint format:
// S[;]|WU|P[,]#|PS[,]
// S: Settings param
// WU: Window Update
// P: Priority
// PS: Pseudo-header order (eg: "m,p,a,s")
func getSettingsFingerprint(frames []types.ParsedFrame) string {
	var sf string // SettingsFingerprint
	mapping := map[string]string{
		"HEADER_TABLE_SIZE":      "1",
		"ENABLE_PUSH":            "2",
		"MAX_CONCURRENT_STREAMS": "3",
		"INITIAL_WINDOW_SIZE":    "4",
		"MAX_FRAME_SIZE":         "5",
		"MAX_HEADER_LIST_SIZE":   "6",
		"NO_RFC7540_PRIORITIES":  "9",
	}

	for _, frame := range frames {
		if frame.Type == "SETTINGS" {
			for _, setting := range frame.Settings {
				parts := strings.Split(setting, " = ")
				if len(parts) != 2 {
					return "error"
				}
				sf += mapping[parts[0]] + ":" + parts[1] + ";"
			}
			break
		}
	}

	return strings.TrimRight(sf, ";")
}

func getWindowUpdateFingerprint(frames []types.ParsedFrame) string {
	// TODO: there might be multiple WINDOW_UPDATE frames, but I am not sure
	for _, frame := range frames {
		if frame.Type == "WINDOW_UPDATE" {
			return fmt.Sprintf("%d", frame.Increment)
		}
	}

	return "00"
}

func getPriorityFingerprint(frames []types.ParsedFrame) string {
	var pf string // PriorityFingerprint

	for _, frame := range frames {
		if frame.Type == "PRIORITY" {
			pf += fmt.Sprintf("%v:%v:%v:%v", frame.Stream, frame.Priority.Exclusive, frame.Priority.DependsOn, frame.Priority.Weight)
			pf += ","
		}
	}

	if pf != "" {
		return strings.TrimRight(pf, ",")
	}
	return "0"
}
func getHeaderOrderFingerprint(frames []types.ParsedFrame) string {
	var hofp string // HeaderOrderFingerprint

	for _, frame := range frames {
		if frame.Type == "HEADERS" {
			for c, header := range frame.Headers {
				if strings.HasPrefix(header, ":") {
					hofp += string(header[1])
					if c < 3 {
						hofp += ","
					}
				}
			}
			break
		}
	}

	return hofp
}

func GetAkamaiFingerprint(frames []types.ParsedFrame) string {
	var akamaiFingerprint string

	akamaiFingerprint += getSettingsFingerprint(frames) + "|"
	akamaiFingerprint += getWindowUpdateFingerprint(frames) + "|"
	akamaiFingerprint += getPriorityFingerprint(frames) + "|"
	akamaiFingerprint += getHeaderOrderFingerprint(frames)

	return akamaiFingerprint
}
