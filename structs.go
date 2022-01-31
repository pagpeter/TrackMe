package main

import (
	"encoding/json"
	"log"
)

type JA3Info struct {
	JA3      string `json:"ja3"`
	JA3_Hash string `json:"ja3_hash"`
}

type TLS struct {
	Version            string   `json:"version"`
	CipherSuites       []string `json:"cipher_suites"`
	JA3                JA3Info  `json:"ja3"`
	ServerName         string   `json:"server_name"`
	SupportedCurves    []string `json:"supported_curves"`
	SupportedPoints    []string `json:"supported_points"`
	SupportedProtocols []string `json:"supported_protocols"`
	SupportedVersions  []uint16 `json:"supported_versions"`
	Extensions         []string `json:"extensions"`
	// SignatureSchemes   []uint16 `json:"signature_schemes"`
}

type Http1Details struct {
	Headers []string `json:"headers"`
}

type Http2Details struct {
	AkamaiFingerprint string        `json:"akamai_fingerprint"`
	SendFrames        []ParsedFrame `json:"sent_frames"`
}

type Response struct {
	HTTPVersion string        `json:"http_version"`
	Path        string        `json:"path"`
	Method      string        `json:"method"`
	TLS         TLS           `json:"tls"`
	Http1       *Http1Details `json:"http1,omitempty"`
	Http2       *Http2Details `json:"http2,omitempty"`
}

func (res Response) ToJson() string {
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Println("Error marshalling response", err)
		return ""
	}
	return string(j)
}

type SmallResponse struct {
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	Akamai  string `json:"akamai"`
}

func (res SmallResponse) ToJson() string {
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Println("Error marshalling response", err)
		return ""
	}
	return string(j)
}

type ParsedFrame struct {
	Type      string   `json:"frame_type,omitempty"`
	Stream    uint32   `json:"stream_id,omitempty"`
	Flags     uint8    `json:"flags,omitempty"`
	Length    uint32   `json:"length,omitempty"`
	Payload   []byte   `json:"payload,omitempty"`
	Headers   []string `json:"headers,omitempty"`
	Settings  []string `json:"settings,omitempty"`
	Increment uint32   `json:"increment,omitempty"`
	Weight    int      `json:"weight,omitempty"`
	DependsOn int      `json:"depends_on,omitempty"`
	Exclusive int      `json:"exclusive,omitempty"`
}
