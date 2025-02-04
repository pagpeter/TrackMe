package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
)

type Extension struct {
	Type   string
	Length int
	Data   string
}

type ClientHello struct {
	Length             int
	Version            int // TLS version, always 1.2 because of middleboxes
	ClientRandom       string
	SessionID          string
	CipherSuites       []uint16
	CompressionMethods string
	AllExtensions      []int
	Extensions         []interface{}

	SupportedProtos   []string
	SupportedPoints   []uint8
	SupportedVersions []uint8
	SupportedCurves   []uint16

	// For the PeetPrint
	SupportedTLSVersions      []int
	SupportedProtocols        []string
	SignatureAlgorithms       []int
	PSKKeyExchangeMode        int
	CertCompressionAlgorithms []int
}

func hexToInt(hex string) int {
	value, _ := strconv.ParseInt(hex, 16, 64)
	return int(value)
}

func hexToString(in string) string {
	value, _ := hex.DecodeString(in)
	return string(value)
}

func parsePacketType(ch string, c int) (string, int) {
	pType := ch[c:2]
	if pType == "01" {
		return "CLIENT_HELLO", c + 2
	} else if pType == "02" {
		return "SERVER_HELLO", c + 2
	} else {
		return pType, c
	}
}

func parsePacketLength(ch string, c int) (int, int) {
	length := ch[c : c+6]
	return hexToInt(length), c + 6
}

func parseTLSVersion(ch string, c int) (int, int) {
	v := ch[c : c+4]
	return hexToInt(v), c + 4
}

func parseClientRandom(ch string, c int) (string, int) {
	cr := ch[c : c+64]
	return cr, c + 64
}

func parseSessionID(ch string, c int) (string, int) {
	length_raw := ch[c : c+2]
	c += 2
	length := hexToInt(length_raw) * 2
	sid := ch[c : c+length]
	return sid, c + length
}

func parseCipherSuites(ch string, c int) ([]uint16, int) {
	length_raw := ch[c : c+4]
	c += 4
	length := hexToInt(length_raw) * 2
	rawSuites := ch[c : c+length]
	suites := []uint16{}
	tmpC := 0
	for tmpC < len(rawSuites) {
		suites = append(suites, uint16(hexToInt(rawSuites[tmpC:tmpC+4])))
		tmpC += 4
	}

	return suites, c + length
}

func parseCompressionMethods(ch string, c int) (string, int) {
	length_raw := ch[c : c+2]
	length := hexToInt(length_raw) * 2
	c += 2
	return "0x" + ch[c:c+length], c + length
}

func parseExtensions(ch string, c int) ([]Extension, int) {
	length_raw := ch[c : c+4]
	length := hexToInt(length_raw) * 2
	c += 4

	rawExtensions := ch[c : c+length]
	extensions := []Extension{}
	tmpC := 0

	for {
		ext := Extension{}
		ext.Type = rawExtensions[tmpC : tmpC+4]
		tmpC += 4
		ext.Length = hexToInt(rawExtensions[tmpC:tmpC+4]) * 2
		tmpC += 4
		ext.Data = rawExtensions[tmpC : tmpC+ext.Length]
		tmpC += ext.Length
		extensions = append(extensions, ext)
		if tmpC >= len(rawExtensions) {
			break
		}
	}
	return extensions, c + length
}

// DEBUG
func PrettyPrintClientHello(ch ClientHello) {
	fmt.Println("\t======")
	fmt.Println("Packet length:\n\t", ch.Length)
	fmt.Println("TLS version:\n\t", ch.Version)
	fmt.Println("Client random:\n\t", ch.ClientRandom)
	fmt.Println("Session ID:\n\t", ch.SessionID)
	fmt.Println("Cipher suites:")
	for _, suite := range ch.CipherSuites {
		fmt.Println("\t", suite)
	}
	fmt.Println("Compression methods:\n\t", ch.CompressionMethods)
	fmt.Println("Extensions:")
	for _, ext := range ch.Extensions {
		fmt.Println("\t", ext)
	}
}

func getOrReturnOG(in string, arr map[string]string) string {
	if val, ok := arr[in]; ok {
		return val
	} else {
		return in
	}
}

func parseRawExtensions(exts []Extension, chp ClientHello) ([]interface{}, ClientHello) {
	var parsed []interface{}
	for _, ext := range exts {
		t := ext.Type
		l := ext.Length
		d := ext.Data

		var tmp interface{}
		switch t {
		case "0000": // server_name
			c := struct {
				Name                 string `json:"name"`
				ServerNameListLength int    `json:"-"`
				ServerNameType       string `json:"-"`
				ServerNameLength     int    `json:"-"`
				ServerName           string `json:"server_name"`
			}{}
			c.Name = "server_name (0)"
			c.ServerNameListLength = hexToInt(d[0:4])
			serverNameType := "host_name"
			if d[4:6] != "00" {
				serverNameType = "0x" + d[4:6]
			}
			c.ServerNameType = serverNameType
			c.ServerNameLength = hexToInt(d[6:10])
			c.ServerName = hexToString(d[10:])

			tmp = c
		case "0005", "0011": // status_request, status_request_v2
			type StatusRequest struct {
				CertificateStatusType   string `json:"certificate_status_type"`
				ResponderIDListLength   int    `json:"responder_id_list_length"`
				RequestExtensionsLength int    `json:"request_extensions_length"`
			}

			var name = "status_request (5)"
			if t == "0011" {
				name = "status_request_v2 (17)"
			}

			tmp = struct {
				Name          string        `json:"name"`
				StatusRequest StatusRequest `json:"status_request"`
			}{
				Name: name,
				StatusRequest: StatusRequest{
					CertificateStatusType:   fmt.Sprintf("OSCP (%d)", hexToInt(d[0:2])),
					ResponderIDListLength:   hexToInt(d[2:4]),
					RequestExtensionsLength: hexToInt(d[4:6]),
				},
			}
		case "000a": // supported_groups
			c := struct {
				Name            string   `json:"name"`
				SupportedGroups []string `json:"supported_groups"`
			}{}
			c.Name = "supported_groups (10)"
			length := hexToInt(d[0:4])
			tmpC := 4
			for tmpC <= length*2 {
				val := d[tmpC : tmpC+4]
				if isGrease("0x" + strings.ToUpper(val)) {
					chp.SupportedCurves = append(chp.SupportedCurves, 6969)
					c.SupportedGroups = append(c.SupportedGroups, "TLS_GREASE (0x"+val+")")
				} else {
					chp.SupportedCurves = append(chp.SupportedCurves, uint16(hexToInt(val)))
					c.SupportedGroups = append(c.SupportedGroups, GetCurveNameByID(uint16(hexToInt(val))))
				}
				tmpC += 4
			}
			tmp = c
		case "000b": // ec_point_formats
			c := struct {
				Name         string   `json:"name"`
				PointFormats []string `json:"elliptic_curves_point_formats"`
			}{}
			c.Name = "ec_point_formats (11)"
			// length := hexToInt(d[0:1])
			i := 2
			for {
				if len(d) >= i+2 {
					val := d[i : i+2]
					i += 2
					c.PointFormats = append(c.PointFormats, "0x"+val)
					chp.SupportedPoints = append(chp.SupportedPoints, uint8(hexToInt(val)))
				} else {
					break
				}
			}

			tmp = c
		case "000d", "0035": // signature_algorithms, signature_algorithms_cert
			c := struct {
				Name       string   `json:"name"`
				AlgsLength int      `json:"-"`
				Algorithms []string `json:"signature_algorithms"`
			}{
				Name:       "signature_algorithms (13)",
				AlgsLength: hexToInt(d[0:4]) / 2,
			}

			if t == "0035" {
				c.Name = "signature_algorithms_cert (50)"
			}

			tmpC := 4
			for tmpC <= (c.AlgsLength * 4) {
				asInt := uint16(hexToInt(d[tmpC : tmpC+4]))
				chp.SignatureAlgorithms = append(chp.SignatureAlgorithms, int(asInt))
				c.Algorithms = append(c.Algorithms, GetSignatureNameByID(asInt))
				tmpC += 4
			}
			tmp = c
		case "0010": // application_layer_protocol_negotiation
			c := struct {
				Name                string   `json:"name"`
				ALPNExtensionLength int      `json:"-"`
				Protocols           []string `json:"protocols"`
			}{
				Name:                "application_layer_protocol_negotiation (16)",
				ALPNExtensionLength: hexToInt(d[0:4]),
			}
			tmpC := 4
			for tmpC <= c.ALPNExtensionLength*2 {
				length := hexToInt(d[tmpC:tmpC+2]) * 2
				tmpC += 2
				proto := d[tmpC : tmpC+length]
				tmpC += length
				c.Protocols = append(c.Protocols, hexToString(proto))
				chp.SupportedProtocols = append(chp.SupportedProtocols, hexToString(proto))
			}

			tmp = c
		case "0012": // signed_certificate_timestamp
			tmp = struct {
				Name string `json:"name"`
			}{
				Name: "signed_certificate_timestamp (18)",
			}
		case "0015": // padding
			tmp = struct {
				Name              string `json:"name"`
				PaddingData       string `json:"-"`
				PaddingDataLength int    `json:"padding_data_length"`
			}{
				Name:              "padding (21)",
				PaddingData:       d,
				PaddingDataLength: len(d),
			}
		case "0017": // extended_master_secret
			c := struct {
				Name                     string `json:"name"`
				MasterSecretData         string `json:"master_secret_data"`
				ExtendedMasterSecretData string `json:"extended_master_secret_data"`
				Length                   int    `json:"-"`
			}{}
			c.Name = "extended_master_secret (23)"
			if l < 4 {
				tmp = c
				break
			}
			length := d[0:4]
			c.MasterSecretData = d[4:]
			if length == "" {
				c.Length = 0
			} else {
				c.Length = hexToInt(length)
			}
			tmp = c
		case "001b": // compress_certificate
			c := struct {
				Name       string   `json:"name"`
				AlgsLength int      `json:"-"`
				Algorithms []string `json:"algorithms"`
			}{}
			c.Name = "compress_certificate (27)"
			c.AlgsLength = hexToInt(d[:2])
			count := 2
			mapping := map[string]string{
				"0001": "zlib (1)",
				"0002": "brotli (2)",
				"0003": "zstd (3)",
			}
			for len(c.Algorithms)*2 < c.AlgsLength {
				chp.CertCompressionAlgorithms = append(chp.CertCompressionAlgorithms, hexToInt(d[count:count+4]))
				c.Algorithms = append(c.Algorithms, getOrReturnOG(d[count:count+4], mapping))
				count += 4
			}
			tmp = c
		case "0022": // delegated_credentials
			c := struct {
				Name                    string   `json:"name"`
				SignatureHashAlgorithms []string `json:"signature_hash_algorithms"`
			}{}
			c.Name = "delegated_credentials (34)"
			length := hexToInt(d[0:4]) * 2
			tmpC := 4
			for len(c.SignatureHashAlgorithms)*4 < length {
				name := uint16(hexToInt(d[tmpC : tmpC+4]))
				tmpC += 4
				c.SignatureHashAlgorithms = append(c.SignatureHashAlgorithms, GetSignatureNameByID(name))
			}
			tmp = c

		case "002b": // supported_versions
			c := struct {
				Name           string   `json:"name"`
				VersionsLength int      `json:"-"`
				Versions       []string `json:"versions"`
			}{}
			c.Name = "supported_versions (43)"
			c.VersionsLength = hexToInt(d[:2])
			count := 2
			mapping := map[string]string{
				"0304": "TLS 1.3",
				"0303": "TLS 1.2",
				"0302": "TLS 1.1",
				"0301": "TLS 1.0",
			}
			for len(c.Versions)*2 < c.VersionsLength {
				val := getOrReturnOG(d[count:count+4], mapping)
				if isGrease("0x" + strings.ToUpper(val)) {
					val = "TLS_GREASE (0x" + val + ")"
					chp.SupportedTLSVersions = append(chp.SupportedTLSVersions, -1)
				} else {
					chp.SupportedTLSVersions = append(chp.SupportedTLSVersions, hexToInt(d[count:count+4]))
				}
				c.Versions = append(c.Versions, val)
				count += 4
			}
			tmp = c
		case "002d": // psk_key_exchange_modes
			// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
			mapping := map[int]string{
				0: "PSK-only key establishment (psk) (0)",
				1: "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)",
			}

			c := struct {
				Name                      string `json:"name"`
				PSKKeyExchangeModesLength int    `json:"-"`
				PSKKeyExchangeMode        string `json:"PSK_Key_Exchange_Mode"`
			}{}
			c.Name = "psk_key_exchange_modes (45)"
			if len(d) < 4 {
				tmp = c
				break
			}

			c.PSKKeyExchangeModesLength = hexToInt(d[0:2])
			c.PSKKeyExchangeMode = mapping[hexToInt(d[2:4])]
			chp.PSKKeyExchangeMode = hexToInt(d[2:4])
			tmp = c
		case "0033": // key_share
			c := struct {
				Name       string              `json:"name"`
				SharedKeys []map[string]string `json:"shared_keys"`
			}{}
			c.Name = "key_share (51)"
			tmp = c
			if len(d) <= 4 {
				break
			}
			length := hexToInt(d[0:4]) * 2
			if len(d) < length+2 {
				break
			}

			tmpC := 4
			for tmpC < length {
				name := d[tmpC : tmpC+4]
				tmpC += 4
				keyLength := hexToInt(d[tmpC:tmpC+4]) * 2
				tmpC += 4
				data := d[tmpC : tmpC+keyLength]
				tmpC += keyLength

				if isGrease("0x" + strings.ToUpper(name)) {
					name = "TLS_GREASE (0x" + name + ")"
				} else {
					name = GetCurveNameByID(uint16(hexToInt(name)))
				}
				c.SharedKeys = append(c.SharedKeys, map[string]string{name: data})
			}
			tmp = c
		case "4469", "44cd": // application_settings
			c := struct {
				Name       string   `json:"name"`
				ALPSLength int      `json:"-"`
				Protocols  []string `json:"protocols"`
			}{}

			c.Name = "application_settings_old (17513)"
			if t == "44cd" {
				// https://chromestatus.com/feature/5149147365900288
				c.Name = "application_settings (17613)"
			}

			tmp = c
			if len(d) <= 4 {
				break
			}
			c.ALPSLength = hexToInt(d[0:4])
			if len(d) < c.ALPSLength*2+4 {
				break
			}
			tmpC := 4
			for tmpC < c.ALPSLength*2 {
				length := hexToInt(d[tmpC:tmpC+2]) * 2
				tmpC += 2
				c.Protocols = append(c.Protocols, hexToString(d[tmpC:tmpC+length]))
				tmpC += length
			}
			tmp = c
		default:
			if isGrease("0x" + strings.ToUpper(ext.Type)) {
				tmp = struct {
					Name string `json:"name"`
				}{
					Name: "TLS_GREASE (0x" + t + ")",
				}
			} else {

				tmp = struct {
					Name string `json:"name"`
					Data string `json:"data"`
				}{
					Name: GetExtensionNameByID(uint16(hexToInt(t))),
					Data: d,
				}
			}
		}
		parsed = append(parsed, tmp)
	}
	return parsed, chp
}

// Gets the ClientHello as hex bytes
func ParseClientHello(ch string) ClientHello {
	chp := ClientHello{}
	var c int = 0 // Cursor - current byte thats being read
	packetType, c := parsePacketType(ch, c)
	if packetType != "CLIENT_HELLO" {
		log.Println("Packet type not supported:", packetType)
		return chp
	}

	chp.Length, c = parsePacketLength(ch, c)
	chp.Version, c = parseTLSVersion(ch, c)
	if chp.Version != 771 && chp.Version != 772 {
		log.Println("TLS Version not supported:", chp.Version)
		return chp
	}
	chp.ClientRandom, c = parseClientRandom(ch, c)
	chp.SessionID, c = parseSessionID(ch, c)
	chp.CipherSuites, c = parseCipherSuites(ch, c)
	chp.CompressionMethods, c = parseCompressionMethods(ch, c)
	exts, _ := parseExtensions(ch, c)
	for _, ext := range exts {
		chp.AllExtensions = append(chp.AllExtensions, hexToInt(ext.Type))
	}
	parsed, chp := parseRawExtensions(exts, chp)
	chp.Extensions = parsed
	return chp
}
