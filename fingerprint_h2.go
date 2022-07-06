package main

import (
	"fmt"
	"strings"
)

// based on https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
// Fingerprint format:
// S[;]|WU|P[,]#|PS[,]
// S: Settings param
// WU: Window Update
// P: Priority
// PS: Pseudo-header order (eg: "m,p,a,s")

func getSettingsFingerprint(frames []ParsedFrame) string {
	var sfp string
	mapping := map[string]string{
		"HEADER_TABLE_SIZE":      "1",
		"ENABLE_PUSH":            "2",
		"MAX_CONCURRENT_STREAMS": "3",
		"INITIAL_WINDOW_SIZE":    "4",
		"MAX_FRAME_SIZE":         "5",
		"MAX_HEADER_LIST_SIZE":   "6",
	}

	for _, frame := range frames {
		if frame.Type == "SETTINGS" {
			for _, setting := range frame.Settings {
				parts := strings.Split(setting, " = ")
				if len(parts) != 2 {
					return "error"
				}
				sfp += mapping[parts[0]] + ":" + parts[1] + ","
			}
			break
		}
	}

	return strings.TrimRight(sfp, ",")
}

func getWindowUpdateFingerprint(frames []ParsedFrame) string {
	for _, frame := range frames {
		if frame.Type == "WINDOW_UPDATE" {
			return fmt.Sprintf("%d", frame.Increment)
		}
	}

	return "00"
}

func getPriorityFingerprint(frames []ParsedFrame) string {
	var pfp string

	for _, frame := range frames {
		if frame.Type == "PRIORITY" {
			pfp += fmt.Sprintf("%v:%v:%v:%v", frame.Stream, frame.Priority.Exclusive, frame.Priority.DependsOn, frame.Priority.Weight)
			pfp += ","
		}
	}

	if pfp != "" {
		return strings.TrimRight(pfp, ",")
	}
	return "0"
}
func getHeaderOrderFingerprint(frames []ParsedFrame) string {
	var hofp string

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

func GetAkamaiFingerprint(frames []ParsedFrame) string {
	var akamaiFingerprint string

	akamaiFingerprint += getSettingsFingerprint(frames) + "|"
	akamaiFingerprint += getWindowUpdateFingerprint(frames) + "|"
	akamaiFingerprint += getPriorityFingerprint(frames) + "|"
	akamaiFingerprint += getHeaderOrderFingerprint(frames)

	return akamaiFingerprint
}
