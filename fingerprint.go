package main

import (
	og "crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

func FingerprintMSG(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Send the JA3 info to the channel
	go func() {
		// we are calculating the ja3 ourseleves.
		// We need to account for GREASE and for padding.

		// Cipher suites
		var suites []string
		var suitesForJa3 []string
		for _, suite := range clientHello.CipherSuites {
			name := og.CipherSuiteName(suite)
			g := false
			// if the cipher isnt in the cipher list, its probably a GREASE cipher
			if len(name) == 6 {
				if isGrease(name) {
					name = "TLS_GREASE (" + name + ")"
					g = true
				}
			}
			suites = append(suites, name)
			// only add the cipher to the ja3 list if it isnt GREASE
			if !g {
				suitesForJa3 = append(suitesForJa3, fmt.Sprintf("%v", suite))
			}
		}

		// Supported Curves
		var curves []string
		var curvesForJa3 []string
		for _, curve := range clientHello.SupportedCurves {
			g := false
			// We get the curve name from the curve list
			name := GetCurveNameByID(uint16(curve))
			hex := strconv.FormatUint(uint64(curve), 16)
			hex = "0x" + strings.ToUpper(hex)
			// if the curve isnt in the curve list, its probably a GREASE curve
			if isGrease(hex) {
				g = true
				name = "TLS_GREASE (" + hex + ")"
			}
			curves = append(curves, name)
			// only add the curve to the ja3 list if it isnt GREASE
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
			if name == "padding (21)" {
				g = true
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

		// version := fmt.Sprintf("%v", clientHello.Conn.ConnectionState().Version)
		pointsForJa3 := strings.Join(supported_points, "-")

		// Make the JA3 string
		ja3 := "123" + ","
		ja3 += strings.Join(suitesForJa3, "-") + ","
		ja3 += strings.Join(extensionsForJa3, "-") + ","
		ja3 += strings.Join(curvesForJa3, "-") + ","
		ja3 += pointsForJa3
		// log.Println("JA3: " + ja3)

		Channel <- JA3Calculating{
			Version: "123",
		}
		// Channel <- TLS{
		// 	Version:            version,
		// 	CipherSuites:       suites,
		// 	Extensions:         extensions,
		// 	ServerName:         clientHello.ServerName,
		// 	SupportedCurves:    curves,
		// 	SupportedPoints:    supported_points,
		// 	SupportedProtocols: clientHello.SupportedProtos,
		// 	SupportedVersions:  clientHello.SupportedVersions,
		// 	// SignatureSchemes:   clientHello.SignatureSchemes,

		// 	JA3: JA3Info{
		// 		JA3:      ja3,
		// 		JA3_Hash: GetMD5Hash(ja3),
		// 	},
		// }
	}()
	return &cert, nil
}
