package main

import (
	og "crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

func FingerprintMSG(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// https://pkg.go.dev/github.com/honeytrap/honeytrap/services/ja3/crypto/tls#ClientHelloInfo

	// Send the JA3 info to the channel
	go func() {
		var suites []string
		var suitesForJa3 []string

		// honeytrap doesnt account for GREASE
		// https://github.com/honeytrap/honeytrap/issues/511
		// So we need to filter out GREASE

		// Cipher suites
		for _, suite := range clientHello.CipherSuites {
			name := og.CipherSuiteName(suite)
			g := false
			if len(name) == 6 {
				if isGrease(name) {
					name = "TLS_GREASE (" + name + ")"
					g = true
				}
			}
			suites = append(suites, name)
			if !g {
				suitesForJa3 = append(suitesForJa3, fmt.Sprintf("%v", suite))
			}
		}

		// Supported Curves
		var curves []string
		var curvesForJa3 []string
		for _, curve := range clientHello.SupportedCurves {
			g := false
			name := GetCurveNameByID(uint16(curve))
			hex := strconv.FormatUint(uint64(curve), 16)
			hex = "0x" + strings.ToUpper(hex)
			if isGrease(hex) {
				g = true
				name = "TLS_GREASE (" + hex + ")"
			}
			curves = append(curves, name)
			if !g {
				curvesForJa3 = append(curvesForJa3, fmt.Sprintf("%v", curve))
			}
		}

		// Extensions
		var extensions []string
		var extensionsForJa3 []string

		for _, extension := range clientHello.Extensions {
			g := false
			hex := strconv.FormatUint(uint64(extension), 16)
			hex = "0x" + strings.ToUpper(hex)
			name := GetExtensionNameByID(extension)
			if isGrease(hex) {
				g = true
				name = "TLS_GREASE (" + hex + ")"
			}
			extensions = append(extensions, name)
			if !g {
				extensionsForJa3 = append(extensionsForJa3, fmt.Sprintf("%v", extension))
			}
		}

		var supported_points []string
		for _, point := range clientHello.SupportedPoints {
			name := fmt.Sprintf("%v", point)
			supported_points = append(supported_points, name)
		}

		version := fmt.Sprintf("%v", clientHello.Version)

		var pointsForJa3 string
		if strings.Join(supported_points, "-") != "0" {
			pointsForJa3 = strings.Join(supported_points, "-")
		}

		// Make the JA3 string
		ja3 := version + ","
		ja3 += strings.Join(suitesForJa3, "-") + ","
		ja3 += strings.Join(extensionsForJa3, "-") + ","
		ja3 += strings.Join(curvesForJa3, "-") + ","
		ja3 += pointsForJa3 + ","

		Channel <- TLS{
			Version:            version,
			CipherSuites:       suites,
			Extensions:         extensions,
			ServerName:         clientHello.ServerName,
			SupportedCurves:    curves,
			SupportedPoints:    supported_points,
			SupportedProtocols: clientHello.SupportedProtos,
			SupportedVersions:  clientHello.SupportedVersions,
			// SignatureSchemes:   clientHello.SignatureSchemes,

			JA3: JA3Info{
				JA3:      ja3,
				JA3_Hash: GetMD5Hash(ja3),
			},
		}
	}()
	return &cert, nil
}
