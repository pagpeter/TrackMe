package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type Http1Details struct {
	Headers []string `json:"headers"`
}

type Http2Details struct {
	AkamaiFingerprint     string        `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string        `json:"akamai_fingerprint_hash"`
	SendFrames            []ParsedFrame `json:"sent_frames"`
}

type Response struct {
	IP          string         `json:"ip"`
	HTTPVersion string         `json:"http_version"`
	Path        string         `json:"path"`
	Method      string         `json:"method"`
	TLS         JA3Calculating `json:"tls"`
	Http1       *Http1Details  `json:"http1,omitempty"`
	Http2       *Http2Details  `json:"http2,omitempty"`
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
	JA3        string `json:"ja3"`
	JA3Hash    string `json:"ja3_hash"`
	Akamai     string `json:"akamai"`
	AkamaiHash string `json:"akamai_hash"`
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

type Config struct {
	LogToDB  bool   `json:"log_to_db"`
	TLSPort  string `json:"tls_port"`
	HTTPPort string `json:"http_port"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Host     string `json:"host"`
}

func (c *Config) LoadFromFile() error {
	data, err := ReadFile("config.json")
	fmt.Println(string(data))
	if err != nil {
		fmt.Println("No config file found: generating one", err)
		c.MakeDefault()
		return c.WriteToFile("config.json")
	}
	var tmp Config
	err = json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	c.LogToDB = tmp.LogToDB
	c.Host = tmp.Host
	c.TLSPort = tmp.TLSPort
	c.HTTPPort = tmp.HTTPPort
	c.CertFile = tmp.CertFile
	c.KeyFile = tmp.KeyFile

	return nil
}

func (c *Config) WriteToFile(file string) error {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Println("Error marshalling config", err)
		return err
	}
	return WriteToFile(file, j)
}

func (c *Config) MakeDefault() {
	c.LogToDB = true
	c.Host = ""
	c.TLSPort = ":443"
	c.HTTPPort = ":80"
	c.CertFile = "chain.pem"
	c.KeyFile = "key.pem"
}
