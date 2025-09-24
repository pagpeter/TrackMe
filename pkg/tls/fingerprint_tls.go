package tls

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

type JA3Calculating struct {
	AllCiphers      []uint16 `json:"-"`
	JA3Ciphers      []string `json:"-"`
	ReadableCiphers []string `json:"ciphers"`

	AllCurves []uint16 `json:"-"`
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

	// PeetPrint
	PeetPrintCiphers    []string
	PeetPrintExtensions []string
	PeetPrintCurves     []string
}

func (j *JA3Calculating) Parse() {
	// Ciphers
	j.ReadableCiphers = []string{}

	j.JA3Ciphers = []string{}
	j.JA3Curves = []string{}
	j.JA3Extensions = []string{}
	j.JA3Points = []string{}

	for _, cipher := range j.AllCiphers {
		name := types.GetCipherSuiteName(cipher)
		if types.IsGrease(name) {
			name = "TLS_GREASE (" + name + ")"
			j.PeetPrintCiphers = append(j.PeetPrintCiphers, "GREASE")
		} else {
			j.JA3Ciphers = append(j.JA3Ciphers, fmt.Sprintf("%v", cipher))
			j.PeetPrintCiphers = append(j.PeetPrintCiphers, fmt.Sprintf("%v", cipher))
		}
		j.ReadableCiphers = append(j.ReadableCiphers, name)
	}
	// Extensions
	for _, extension := range j.AllExtensions {
		hex := strconv.FormatUint(uint64(extension), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !types.IsGrease(hex) {
			j.JA3Extensions = append(j.JA3Extensions, fmt.Sprintf("%v", extension))
			j.PeetPrintExtensions = append(j.PeetPrintExtensions, fmt.Sprintf("%v", extension))
		} else {
			j.PeetPrintExtensions = append(j.PeetPrintExtensions, "GREASE")
		}
	}

	// Curves
	for _, curve := range j.AllCurves {
		hex := strconv.FormatUint(uint64(curve), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !types.IsGrease(hex) && curve != 6969 {
			j.JA3Curves = append(j.JA3Curves, fmt.Sprintf("%v", curve))
			j.PeetPrintCurves = append(j.PeetPrintCurves, fmt.Sprintf("%v", curve))
		} else {
			j.PeetPrintCurves = append(j.PeetPrintCurves, "GREASE")
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
	j.JA3Hash = utils.GetMD5Hash(ja3)
}

func CalculateJA3(parsed ClientHello) JA3Calculating {
	versions := []string{}
	for _, version := range parsed.SupportedVersions {
		hex := strconv.FormatUint(uint64(version), 16)
		hex = "0x" + strings.ToUpper(hex)
		if !types.IsGrease(hex) {
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

func joinInts(ints []int, seperator string) string {
	tmp := []string{}
	for _, v := range ints {
		tmp = append(tmp, fmt.Sprintf("%v", v))
	}
	return strings.Join(tmp, seperator)
}

func CalculatePeetPrint(parsed ClientHello, j JA3Calculating) (string, string) {
	tmp := []string{}
	for _, v := range parsed.SupportedProtocols {
		if strings.ToLower(v) == "h2" {
			tmp = append(tmp, "2")
		} else if strings.ToLower(v) == "http/1.1" {
			tmp = append(tmp, "1.1")
		} else if strings.ToLower(v) == "http/1.0" {
			tmp = append(tmp, "1.0")
		}
	}

	versions := []string{}
	for _, v := range parsed.SupportedTLSVersions {
		if v == -1 {
			versions = append(versions, "GREASE")
		} else {
			versions = append(versions, fmt.Sprintf("%v", v))
		}
	}

	// Sort extensions because the order is randomized
	sort.Strings(j.PeetPrintExtensions)

	tls_versions := strings.Join(versions, "-")                  // Comma seperated list of supported TLS versions as sent in the `supported_versions` extension. TODO
	protos := strings.Join(tmp, "-")                             // Comma seperated list of supported HTTP versions as sent in the `application_layer_protocol_negotiation` extension. http/1.0 => 1.0, http/1.1 => 1.1, http/2 => 2
	sig_als := joinInts(parsed.SignatureAlgorithms, "-")         // Comma seperated list of supported signatue algorithms as sent in the `signature_algorithms` extension.
	key_mode := fmt.Sprintf("%v", parsed.PSKKeyExchangeMode)     // The PSK key exchange mode as specified in the`psk_key_exchange_modes` extension. Usually 0 or 1.
	comp_algs := joinInts(parsed.CertCompressionAlgorithms, "-") // Comma seperated list of the certificate compression algorithms as sent in the `compress_certificate` extension
	groups := strings.Join(j.PeetPrintCurves, "-")               // Comma seperated list of supported elliptic curve groups as sent in the `supported_groups` extension.
	suites := strings.Join(j.PeetPrintCiphers, "-")              // Cipher suites
	extensions := strings.Join(j.PeetPrintExtensions, "-")       // Extensions

	//	if debug {
	//		fmt.Println("tls_versions:", tls_versions)
	//		fmt.Println("protos:", protos)
	//		fmt.Println("signature algs:", sig_als)
	//		fmt.Println("key_mode:", key_mode)
	//		fmt.Println("comp_algs:", comp_algs)
	//		fmt.Println("groups:", groups)
	//		fmt.Println("cipher suites:", suites)
	//		fmt.Println("extensions:", extensions)
	//	}

	fp := fmt.Sprintf("%v|%v|%v|%v|%v|%v|%v|%v", tls_versions, protos, groups, sig_als, key_mode, comp_algs, suites, extensions)
	return fp, utils.GetMD5Hash(fp)
}
