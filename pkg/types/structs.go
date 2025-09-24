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
}

type Http1Details struct {
	Headers []string `json:"headers"`
}

type Http2Details struct {
	AkamaiFingerprint     string        `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string        `json:"akamai_fingerprint_hash"`
	SendFrames            []ParsedFrame `json:"sent_frames"`
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
	// WindowSize         int    `json:"window_size,omitempty"`
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
	TLS         TLSDetails    `json:"tls"`
	Http1       *Http1Details `json:"http1,omitempty"`
	Http2       *Http2Details `json:"http2,omitempty"`
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
	LogToDB      bool   `json:"log_to_db"`
	TLSPort      string `json:"tls_port"`
	HTTPPort     string `json:"http_port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	Host         string `json:"host"`
	MongoURL     string `json:"mongo_url"`
	Collection   string `json:"mongo_collection"`
	DB           string `json:"mongo_database"`
	LogIPs       bool   `json:"mongo_log_ips"`
	HTTPRedirect string `json:"http_redirect"`
	Device       string `json:"device"`
	CorsKey      string `json:"cors_key"`
}

func (c *Config) LoadFromFile() error {
	data, err := os.ReadFile("config.json")
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
	c.MongoURL = tmp.MongoURL
	c.Collection = tmp.Collection
	c.DB = tmp.DB
	c.LogIPs = tmp.LogIPs
	c.HTTPRedirect = tmp.HTTPRedirect
	c.Device = tmp.Device
	c.CorsKey = tmp.CorsKey
	return nil
}

func (c *Config) WriteToFile(file string) error {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Println("Error marshalling config", err)
		return err
	}
	return os.WriteFile(file, j, 0644)
}

func (c *Config) MakeDefault() {
	c.LogToDB = true
	c.Host = ""
	c.TLSPort = "443"
	c.HTTPPort = "80"
	c.CertFile = "certs/chain.pem"
	c.KeyFile = "certs/key.pem"
	c.MongoURL = ""
	c.Collection = "requests"
	c.DB = "TrackMe"
	c.LogIPs = false
	c.HTTPRedirect = "https://tls.peet.ws"
	c.CorsKey = "X-CORS"
}
