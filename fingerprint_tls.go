package main

import (
	// "crypto/tls"
	"fmt"
	"strconv"
	"strings"

	tls "github.com/wwhtrbbtt/utls"
	//"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

type JA3Calculating struct {
	AllCiphers      []uint16 `json:"-"`
	JA3Ciphers      []string `json:"-"`
	ReadableCiphers []string `json:"ciphers"`

	AllCurves      []int    `json:"-"`
	JA3Curves      []string `json:"-"`
	ReadableCurves []string `json:"curves"`

	AllExtensions      []int         `json:"-"`
	JA3Extensions      []string      `json:"-"`
	ReadableExtensions []interface{} `json:"extensions"`

	AllPoints      []uint8  `json:"-"`
	JA3Points      []string `json:"-"`
	ReadablePoints []string `json:"points"`

	Version           string   `json:"version"`
	ReadableProtocols []string `json:"protocols"`
	ReadableVersions  []string `json:"versions"`

	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`

	JA3Padding     string `json:"ja3_padding"`
	JA3HashPadding string `json:"ja3_hash_padding"`

	ClientRandom string `json:"client_random"`
	SessionID    string `json:"session_id"`
}

func (j *JA3Calculating) Parse(includePadding bool) {
	// Ciphers
	j.ReadableCiphers = []string{}
	j.ReadableCurves = []string{}
	j.ReadablePoints = []string{}

	j.JA3Ciphers = []string{}
	j.JA3Curves = []string{}
	j.JA3Extensions = []string{}
	j.JA3Points = []string{}

	for _, cipher := range j.AllCiphers {
		name := GetCipherSuiteName(cipher)
		g := false
		// if the cipher isnt in the cipher list, its probably a GREASE cipher
		if len(name) == 6 {
			if isGrease(name) {
				name = "TLS_GREASE (" + name + ")"
				g = true
			}
		}
		j.ReadableCiphers = append(j.ReadableCiphers, name)
		// only add the cipher to the ja3 list if it isnt GREASE
		if !g {
			j.JA3Ciphers = append(j.JA3Ciphers, fmt.Sprintf("%v", cipher))
		}
	}
	// Extensions
	for _, extension := range j.AllExtensions {
		g := false
		hex := strconv.FormatUint(uint64(extension), 16)
		hex = "0x" + strings.ToUpper(hex)
		name := GetExtensionNameByID(uint16(extension))
		if isGrease(hex) {
			g = true
			name = "TLS_GREASE (" + hex + ")"
		}
		if name == "padding (21)" && !includePadding {
			g = true
		}
		//	j.ReadableExtensions = append(j.ReadableExtensions, name)
		if !g {
			j.JA3Extensions = append(j.JA3Extensions, fmt.Sprintf("%v", extension))
		}
	}

	// Curves
	for _, curve := range j.AllCurves {
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
		j.ReadableCurves = append(j.ReadableCurves, name)
		// only add the curve to the ja3 list if it isnt GREASE
		if !g {
			j.JA3Curves = append(j.JA3Curves, fmt.Sprintf("%v", curve))
		}
	}

	// Points
	for _, point := range j.AllPoints {
		name := fmt.Sprintf("%v", point)
		j.ReadablePoints = append(j.ReadablePoints, name)
		j.JA3Points = append(j.JA3Points, name)
	}
}

func (j *JA3Calculating) Calculate(isWithPadding bool) {
	// Returns the ja3 and the ja3_hash
	// TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3 := j.Version + ","
	ja3 += strings.Join(j.JA3Ciphers, "-") + ","
	ja3 += strings.Join(j.JA3Extensions, "-") + ","
	ja3 += strings.Join(j.JA3Curves, "-") + ","
	ja3 += strings.Join(j.JA3Points, "-")
	if !isWithPadding {
		j.JA3 = ja3
		j.JA3Hash = GetMD5Hash(ja3)
	} else {
		j.JA3Padding = ja3
		j.JA3HashPadding = GetMD5Hash(ja3)
	}
}

func (j *JA3Calculating) Do() {
	// Get ja3 without padding
	j.Parse(false)
	j.Calculate(false)
	// Get ja3 with padding
	j.Parse(true)
	j.Calculate(true)
}

func FingerprintMSG(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// We need to start a new goroutine to calculate the ja3, because
	// we cant block the main thread.
	go func() {
		hexClientHello := fmt.Sprintf("%x", clientHello.Raw())
		parsed := ParseClientHello(hexClientHello)

		versions := []string{}
		for _, version := range clientHello.SupportedVersions {
			hex := strconv.FormatUint(uint64(version), 16)
			hex = "0x" + strings.ToUpper(hex)
			if !isGrease(hex) {
				versions = append(versions, fmt.Sprintf("%v", version))
			}
		}

		curves := []int{}
		for _, curve := range clientHello.SupportedCurves {
			curves = append(curves, int(curve))
		}

		j := JA3Calculating{
			AllCiphers:         clientHello.CipherSuites,
			AllCurves:          curves,
			AllPoints:          clientHello.SupportedPoints,
			AllExtensions:      parsed.AllExtensions,
			ReadableExtensions: parsed.Extensions,
			Version:            fmt.Sprint(parsed.Version),
			ReadableProtocols:  clientHello.SupportedProtos,
			ReadableVersions:   versions,
			SessionID:          parsed.SessionID,
			ClientRandom:       parsed.ClientRandom,
		}
		j.Do()
		Gja3 = j

	}()

	return &cert, nil
}
