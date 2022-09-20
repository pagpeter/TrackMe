package main

import (
	// "crypto/tls"
	"fmt"
	"strconv"
	"strings"
	//"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

type JA3Calculating struct {
	AllCiphers      []uint16 `json:"-"`
	JA3Ciphers      []string `json:"-"`
	ReadableCiphers []string `json:"ciphers"`

	AllCurves []uint8  `json:"-"`
	JA3Curves []string `json:"-"`

	AllExtensions []int    `json:"-"`
	JA3Extensions []string `json:"-"`

	AllPoints []uint8  `json:"-"`
	JA3Points []string `json:"-"`

	Version           string
	ReadableProtocols []string
	ReadableVersions  []string

	JA3     string
	JA3Hash string
}

func (j *JA3Calculating) Parse() {
	// Ciphers
	j.ReadableCiphers = []string{}

	j.JA3Ciphers = []string{}
	j.JA3Curves = []string{}
	j.JA3Extensions = []string{}
	j.JA3Points = []string{}

	for _, cipher := range j.AllCiphers {
		name := GetCipherSuiteName(cipher)
		if isGrease(name) {
			name = "TLS_GREASE (" + name + ")"
		} else {
			j.JA3Ciphers = append(j.JA3Ciphers, fmt.Sprintf("%v", cipher))
		}
		j.ReadableCiphers = append(j.ReadableCiphers, name)
	}
	// Extensions
	for _, extension := range j.AllExtensions {
		hex := strconv.FormatUint(uint64(extension), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !isGrease(hex) {
			j.JA3Extensions = append(j.JA3Extensions, fmt.Sprintf("%v", extension))
		}
	}

	// Curves
	for _, curve := range j.AllCurves {
		hex := strconv.FormatUint(uint64(curve), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !isGrease(hex) {
			j.JA3Curves = append(j.JA3Curves, fmt.Sprintf("%v", curve))
		}
	}

	// Points
	for _, point := range j.AllPoints {
		name := fmt.Sprintf("%v", point)
		j.JA3Points = append(j.JA3Points, name)
	}
}

func (j *JA3Calculating) Calculate() {
	// Returns the ja3 and the ja3_hash
	// TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3 := j.Version + ","
	ja3 += strings.Join(j.JA3Ciphers, "-") + ","
	ja3 += strings.Join(j.JA3Extensions, "-") + ","
	ja3 += strings.Join(j.JA3Curves, "-") + ","
	ja3 += strings.Join(j.JA3Points, "-")
	j.JA3 = ja3
	j.JA3Hash = GetMD5Hash(ja3)
}

func CalculateJA3(parsed ClientHello) JA3Calculating {
	versions := []string{}
	for _, version := range parsed.SupportedVersions {
		hex := strconv.FormatUint(uint64(version), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !isGrease(hex) {
			versions = append(versions, fmt.Sprintf("%v", version))
		}
	}

	j := JA3Calculating{
		AllCiphers:        parsed.CipherSuites,
		AllCurves:         parsed.SupportedCurves,
		AllPoints:         parsed.SupportedPoints,
		AllExtensions:     parsed.AllExtensions,
		Version:           fmt.Sprint(parsed.Version),
		ReadableProtocols: parsed.SupportedProtos,
		ReadableVersions:  versions,
	}
	j.Parse()
	j.Calculate()
	return j
}
