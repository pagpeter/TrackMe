package types

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type TLSDetails struct {
	Ciphers          []string      `json:"ciphers"`
	Extensions       []interface{} `json:"extensions"`
	RecordVersion    string        `json:"tls_version_record"`
	NegotiatedVesion string        `json:"tls_version_negotiated"`

	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`

	JA4   string `json:"ja4"`
	JA4_r string `json:"ja4_r"`

	PeetPrint     string `json:"peetprint"`
	PeetPrintHash string `json:"peetprint_hash"`

	ClientRandom string `json:"client_random"`
	SessionID    string `json:"session_id"`
	RawBytes     string `json:"-"`
	RawB64       string `json:"-"`
}

type Http1Details struct {
	Headers []string `json:"headers"`
}

type Http2Details struct {
	AkamaiFingerprint     string        `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string        `json:"akamai_fingerprint_hash"`
	SendFrames            []ParsedFrame `json:"sent_frames"`
}

type Http3Details struct {
	Used0RTT                           bool               `json:"used_0rtt"`
	SupportsDatagrams                  bool               `json:"supports_datagrams"`
	SupportsStreamResetPartialDelivery bool               `json:"supports_stream_reset_partial_delivery"`
	Version                            uint32             `json:"version"`
	GSO                                bool               `json:"gso"`
	Settings                           []Http3SettingPair `json:"settings"`
	AkamaiFingerprint                  string             `json:"akamai_fingerprint"`
	AkamaiFingerprintHash              string             `json:"akamai_fingerprint_hash"`
	Headers                            []string           `json:"headers,omitempty"`
}

// Http3SettingPair represents a single HTTP/3 setting for fingerprinting
type Http3SettingPair struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type Http3Settings struct {
	EnableDatagrams       bool               `json:"enable_datagrams"`
	EnableExtendedConnect bool               `json:"enable_extended_connect"`
	Other                 map[uint64]uint64  `json:"other,omitempty"`
	RawSettings           []Http3SettingPair `json:"settings,omitempty"`
}

type IPDetails struct {
	DF          int    `json:"df,omitempty"`
	HDRLength   int    `json:"hdr_length,omitempty"`
	ID          int    `json:"id,omitempty"`
	MF          int    `json:"mf,omitempty"`
	NXT         int    `json:"nxt,omitempty"`
	OFF         int    `json:"off,omitempty"`
	PLEN        int    `json:"plen,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	RF          int    `json:"rf,omitempty"`
	TOS         int    `json:"tos,omitempty"`
	TotalLength int    `json:"total_length,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	IPVersion   int    `json:"ip_version,omitempty"`
	DstIp       string `json:"dst_ip,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
}
type TCPDetails struct {
	Ack                int    `json:"ack,omitempty"`
	Checksum           int    `json:"checksum,omitempty"`
	Flags              int    `json:"flags,omitempty"`
	HeaderLength       int    `json:"header_length,omitempty"`
	MSS                int    `json:"mss,omitempty"`
	OFF                int    `json:"off,omitempty"`
	Options            string `json:"options,omitempty"`
	OptionsOrder       string `json:"options_order,omitempty"`
	Seq                int    `json:"seq,omitempty"`
	Timestamp          int    `json:"timestamp,omitempty"`
	TimestampEchoReply int    `json:"timestamp_echo_reply,omitempty"`
	URP                int    `json:"urp,omitempty"`
	Window             int    `json:"window,omitempty"`
}
type TCPIPDetails struct {
	CapLen    int        `json:"cap_length,omitempty"`
	DstPort   int        `json:"dst_port,omitempty"`
	SrcPort   int        `json:"src_port,omitempty"`
	HeaderLen int        `json:"header_length,omitempty"`
	TS        []int      `json:"ts,omitempty"`
	IP        IPDetails  `json:"ip,omitempty"`
	TCP       TCPDetails `json:"tcp,omitempty"`
}

type Response struct {
	Donate      string        `json:"donate"`
	IP          string        `json:"ip"`
	HTTPVersion string        `json:"http_version"`
	Path        string        `json:"-"`
	Method      string        `json:"method"`
	UserAgent   string        `json:"user_agent,omitempty"`
	TLS         *TLSDetails   `json:"tls"`
	Http1       *Http1Details `json:"http1,omitempty"`
	Http2       *Http2Details `json:"http2,omitempty"`
	Http3       *Http3Details `json:"http3,omitempty"`
	TCPIP       TCPIPDetails  `json:"tcpip,omitempty"`
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
	JA3           string `json:"ja3"`
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	JA4_r         string `json:"ja4_r"`
	Akamai        string `json:"akamai"`
	AkamaiHash    string `json:"akamai_hash"`
	PeetPrint     string `json:"peetprint"`
	PeetPrintHash string `json:"peetprint_hash"`
	HTTPVersion   string `json:"http_version"`
}

func (res SmallResponse) ToJson() string {
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Println("Error marshalling response", err)
		return ""
	}
	return string(j)
}

type Priority struct {
	Weight    int `json:"weight"`
	DependsOn int `json:"depends_on"`
	Exclusive int `json:"exclusive"`
}

type GoAway struct {
	LastStreamID uint32
	ErrCode      uint32
	DebugData    []byte
}

type ParsedFrame struct {
	Type      string    `json:"frame_type,omitempty"`
	Stream    uint32    `json:"stream_id,omitempty"`
	Length    uint32    `json:"length,omitempty"`
	Payload   []byte    `json:"payload,omitempty"`
	Headers   []string  `json:"headers,omitempty"`
	Settings  []string  `json:"settings,omitempty"`
	Increment uint32    `json:"increment,omitempty"`
	Flags     []string  `json:"flags,omitempty"`
	Priority  *Priority `json:"priority,omitempty"`
	GoAway    *GoAway   `json:"goaway,omitempty"`
}

type Config struct {
	TLSPort      string `json:"tls_port"`
	HTTPPort     string `json:"http_port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	Host         string `json:"host"`
	HTTPRedirect string `json:"http_redirect"`
	Device       string `json:"device"`
	CorsKey      string `json:"cors_key"`
	EnableQUIC   bool   `json:"enable_quic"`
}

func (c *Config) LoadFromFile() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("No config file found: generating one", err)
		c.MakeDefault()
		return c.WriteToFile("config.json")
	}

	var tmp Config
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("failed to parse config.json: %w", err)
	}

	c.Host = tmp.Host
	c.TLSPort = tmp.TLSPort
	c.HTTPPort = tmp.HTTPPort
	c.CertFile = tmp.CertFile
	c.KeyFile = tmp.KeyFile
	c.HTTPRedirect = tmp.HTTPRedirect
	c.Device = tmp.Device
	c.CorsKey = tmp.CorsKey
	c.EnableQUIC = tmp.EnableQUIC
	return nil
}

func (c *Config) WriteToFile(file string) error {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(file, j, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

func (c *Config) MakeDefault() {
	c.Host = ""
	c.TLSPort = "443"
	c.HTTPPort = "80"
	c.CertFile = "certs/chain.pem"
	c.KeyFile = "certs/key.pem"
	c.HTTPRedirect = "https://tls.peet.ws"
	c.CorsKey = "X-CORS"
	c.EnableQUIC = true
}
