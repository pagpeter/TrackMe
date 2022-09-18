package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
)

var debug = true

type Extension struct {
	Type   string
	Length int
	Data   string
}

type ClientHello struct {
	Length             int
	Version            int // TLS verion
	ClientRandom       string
	SessionID          string
	CipherSuites       []uint16
	CompressionMethods string
	AllExtensions      []int
	Extensions         []interface{}
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
	for {
		suites = append(suites, uint16(hexToInt(ch[tmpC:tmpC+4])))
		tmpC += 4
		if tmpC >= len(rawSuites) {
			break
		}
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

func parseRawExtensions(exts []Extension) []interface{} {
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
		case "0010": // application_layer_protocol_negotiation
			c := struct {
				Name                string   `json:"name"`
				ALPNExtensionLength int      `json:"-"`
				Protocols           []string `json:"protocols"`
			}{
				Name:                "application_layer_protocol_negotiation",
				ALPNExtensionLength: hexToInt(d[0:4]),
			}
			tmpC := 4
			for tmpC <= c.ALPNExtensionLength*2 {
				length := hexToInt(d[tmpC:tmpC+2]) * 2
				tmpC += 2
				proto := d[tmpC : tmpC+length]
				tmpC += length
				c.Protocols = append(c.Protocols, hexToString(proto))
			}

			tmp = c
		case "0015":
			tmp = struct {
				Name        string `json:"name"`
				PaddingData string `json:"data"`
			}{
				Name:        "padding (21)",
				PaddingData: d,
			}
		case "0017":
			c := struct {
				Name                     string `json:"name"`
				MasterSecretData         string `json:"master_secret_data"`
				ExtendedMasterSecretData string `json:"extended_master_secret_data"`
				Length                   int    `json:"-"`
			}{}
			c.Name = "extended_master_secret (23)"
			if l < 4 {
				tmp = c
				continue
			}
			length := d[0:4]
			c.MasterSecretData = d[4:]
			if length == "" {
				c.Length = 0
			} else {
				c.Length = hexToInt(length)
			}
			tmp = c
		case "001b":
			c := struct {
				Name       string   `json:"name"`
				AlgsLength int      `json:"-"`
				Algorithms []string `json:"algorithms"`
			}{}
			c.Name = "compress_certificate (27)"
			c.AlgsLength = hexToInt(d[:2])
			count := 2
			mapping := map[string]string{"0002": "brotli (2)"}
			for len(c.Algorithms)*2 < c.AlgsLength {
				c.Algorithms = append(c.Algorithms, getOrReturnOG(d[count:count+4], mapping))
				count += 4
			}
			tmp = c
		case "002b":
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
				}
				c.Versions = append(c.Versions, val)
				count += 4
			}
			tmp = c
		case "4469":
			c := struct {
				Name       string   `json:"name"`
				ALPSLength int      `json:"-"`
				Protocols  []string `json:"protocols"`
			}{}
			c.Name = "application_settings (17513)"
			c.ALPSLength = hexToInt(d[0:4])
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
	return parsed
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
	exts, c := parseExtensions(ch, c)
	for _, ext := range exts {
		chp.AllExtensions = append(chp.AllExtensions, hexToInt(ext.Type))
	}
	chp.Extensions = parseRawExtensions(exts)
	return chp
}
