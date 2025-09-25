package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pagpeter/quic-go/http3"
	trackmehttp "github.com/pagpeter/trackme/pkg/http"
	"github.com/pagpeter/trackme/pkg/tls"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
	utls "github.com/wwhtrbbtt/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func parseHTTP1(request []byte) types.Response {
	// Split the request into lines
	lines := strings.Split(string(request), "\r\n")

	// Split the first line into the method, path and http version
	firstLine := strings.Split(lines[0], " ")

	// Split the headers into an array
	var headers []string
	var userAgent string
	for _, line := range lines {
		if strings.Contains(line, ":") {
			headers = append(headers, line)
			if strings.HasPrefix(strings.ToLower(line), "user-agent") {
				userAgent = strings.TrimSpace(strings.Split(line, ":")[1])
			}
		}
	}

	if len(firstLine) != 3 {
		return types.Response{
			HTTPVersion: "--",
			Method:      "--",
			Path:        "--",
		}
	}
	return types.Response{
		HTTPVersion: firstLine[2],
		Path:        firstLine[1],
		Method:      firstLine[0],
		UserAgent:   userAgent,
		Http1: &types.Http1Details{
			Headers: headers,
		},
	}
}

func parseHTTP2(f *http2.Framer, c chan types.ParsedFrame) {
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			r := "ERROR_CLOSE"
			if strings.HasSuffix(err.Error(), "unknown certificate") {
				r = "ERROR"
			}
			// log.Println("Error reading frame", err, r)
			c <- types.ParsedFrame{Type: r}
			return
		}

		p := types.ParsedFrame{}
		p.Type = frame.Header().Type.String()
		p.Stream = frame.Header().StreamID
		p.Length = frame.Header().Length
		p.Flags = utils.GetAllFlags(frame)

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			p.Settings = []string{}
			frame.ForeachSetting(func(s http2.Setting) error {
				setting := fmt.Sprintf("%q", s)
				setting = strings.Replace(setting, "\"", "", -1)
				setting = strings.Replace(setting, "[", "", -1)
				setting = strings.Replace(setting, "]", "", -1)

				// SETTINGS_NO_RFC7540_PRIORITIES
				// https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1
				// https://github.com/golang/go/issues/69917
				// TODO: when net/http2 is updated to support it, remove this as it won't be needed (this is ugly code too)
				if strings.HasPrefix(setting, "UNKNOWN_SETTING_9 = ") {
					setting = strings.ReplaceAll(setting, "UNKNOWN_SETTING_9", "NO_RFC7540_PRIORITIES")
				}

				p.Settings = append(p.Settings, setting)
				return nil
			})
		case *http2.HeadersFrame:
			d := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			d.SetEmitEnabled(true)
			h2Headers, err := d.DecodeFull(frame.HeaderBlockFragment())
			if err != nil {
				//log.Println("Error decoding headers", err)
				return
			}

			for _, h := range h2Headers {
				h := fmt.Sprintf("%q: %q", h.Name, h.Value)
				h = strings.Trim(h, "\"")
				h = strings.Replace(h, "\": \"", ": ", -1)
				p.Headers = append(p.Headers, h)
			}
			if frame.HasPriority() {
				prio := types.Priority{}
				p.Priority = &prio
				// 6.2: Weight: An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256
				p.Priority.Weight = int(frame.Priority.Weight) + 1
				p.Priority.DependsOn = int(frame.Priority.StreamDep)
				if frame.Priority.Exclusive {
					p.Priority.Exclusive = 1
				}
			}
		case *http2.DataFrame:
			p.Payload = frame.Data()
		case *http2.WindowUpdateFrame:
			p.Increment = frame.Increment
		case *http2.PriorityFrame:

			prio := types.Priority{}
			p.Priority = &prio
			// 6.3: Weight: An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256
			p.Priority.Weight = int(frame.PriorityParam.Weight) + 1
			p.Priority.DependsOn = int(frame.PriorityParam.StreamDep)
			if frame.PriorityParam.Exclusive {
				p.Priority.Exclusive = 1
			}
		case *http2.GoAwayFrame:
			p.GoAway = &types.GoAway{}
			p.GoAway.LastStreamID = frame.LastStreamID
			p.GoAway.ErrCode = uint32(frame.ErrCode)
			p.GoAway.DebugData = frame.DebugData()
		}

		c <- p
	}
}

func (srv *Server) HandleTLSConnection(conn net.Conn) bool {
	// Read the first line of the request
	// We only read the first line to determine if the connection is HTTP1 or HTTP2
	// If we know that it isnt HTTP2, we can read the rest of the request and then start processing it
	// If we know that it is HTTP2, we start the HTTP2 handler

	l := len([]byte(HTTP2_PREAMBLE))
	request := make([]byte, l)

	_, err := conn.Read(request)
	if err != nil {
		//log.Println("Error reading request", err)
		if strings.HasSuffix(err.Error(), "unknown certificate") && srv.IsLocal() {
			log.Println("Local error (probably developement) - not closing conn")
			return true
		}
		return false
	}

	hs := conn.(*utls.Conn).ClientHello

	parsedClientHello := tls.ParseClientHello(hs)
	JA3Data := tls.CalculateJA3(parsedClientHello)
	peetfp, peetprintHash := tls.CalculatePeetPrint(parsedClientHello, JA3Data)

	// Convert raw bytes to hex and base64
	rawBytes, _ := hex.DecodeString(hs)
	rawB64 := base64.StdEncoding.EncodeToString(rawBytes)

	tlsDetails := types.TLSDetails{
		Ciphers:          JA3Data.ReadableCiphers,
		Extensions:       parsedClientHello.Extensions,
		RecordVersion:    JA3Data.Version,
		NegotiatedVesion: fmt.Sprintf("%v", conn.(*utls.Conn).ConnectionState().Version),
		JA3:              JA3Data.JA3,
		JA3Hash:          JA3Data.JA3Hash,
		PeetPrint:        peetfp,
		PeetPrintHash:    peetprintHash,
		SessionID:        parsedClientHello.SessionID,
		ClientRandom:     parsedClientHello.ClientRandom,
		RawBytes:         hs,
		RawB64:           rawB64,
	}

	// Check if the first line is HTTP/2
	if string(request) == HTTP2_PREAMBLE {
		srv.handleHTTP2(conn, &tlsDetails)
	} else {
		// Read the rest of the request
		r2 := make([]byte, 1024-l)
		_, err := conn.Read(r2)
		if err != nil {
			log.Println(err)
			return true
		}
		// Append it to the first line
		request = append(request, r2...)

		// Parse and handle the request
		details := parseHTTP1(request)
		details.IP = conn.RemoteAddr().String()
		details.TLS = &tlsDetails
		srv.respondToHTTP1(conn, details)
	}
	return true
}

func (srv *Server) respondToHTTP1(conn net.Conn, resp types.Response) {
	// log.Println("Request:", resp.ToJson())
	// log.Println(len(resp.ToJson()))

	var isAdmin bool
	var res []byte
	var ctype = "text/plain"
	if resp.Method != "OPTIONS" {
		res, ctype = Router(resp.Path, resp, srv)
	} else {
		isAdmin = true
	}

	key, isKeySet := srv.GetAdmin()
	if isKeySet {
		for _, a := range resp.Http1.Headers {
			if strings.HasPrefix(a, key) {
				isAdmin = true
			}
		}
	}

	res1 := "HTTP/1.1 200 OK\r\n"
	res1 += "Content-Length: " + fmt.Sprintf("%v\r\n", len(res))
	res1 += "Content-Type: " + ctype + "; charset=utf-8\r\n"
	if isAdmin {
		res1 += "Access-Control-Allow-Origin: *\r\n"
		res1 += "Access-Control-Allow-Methods: *\r\n"
		res1 += "Access-Control-Allow-Headers: *\r\n"
	}
	res1 += "Server: TrackMe\r\n"
	res1 += "Alt-Svc: h3=\":443\"; ma=86400\r\n"
	res1 += "\r\n"
	res1 += string(res)
	res1 += "\r\n\r\n"

	_, err := conn.Write([]byte(res1))
	if err != nil {
		log.Println("Error writing HTTP/1 data", err)
		return
	}
	err = conn.Close()
	if err != nil {
		log.Println("Error closing HTTP/1 connection", err)
		return
	}
}

// https://stackoverflow.com/questions/52002623/golang-tcp-server-how-to-write-http2-data
func (srv *Server) handleHTTP2(conn net.Conn, tlsFingerprint *types.TLSDetails) {
	// make a new framer to encode/decode frames
	fr := http2.NewFramer(conn, conn)
	c := make(chan types.ParsedFrame)
	var frames []types.ParsedFrame

	// Same settings that google uses
	err := fr.WriteSettings(
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 1048576,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 100,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 65536,
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	var frame types.ParsedFrame
	var headerFrame types.ParsedFrame
	var isAdmin bool

	go parseHTTP2(fr, c)

	for {
		frame = <-c
		if frame.Type == "ERROR_CLOSE" {
			err = conn.Close()
			if err != nil {
				log.Println("Cant close connection", err)
			}
			return
		} else if frame.Type == "ERROR" {
			return
		}
		// log.Println(frame)
		frames = append(frames, frame)
		if frame.Type == "HEADERS" {
			headerFrame = frame
		}
		if len(frame.Flags) > 0 && frame.Flags[0] == "EndStream (0x1)" {
			break
		}
	}

	// get method, path and user-agent from the header frame
	var path string
	var method string
	var userAgent string
	key, isKeySet := srv.GetAdmin()

	for _, h := range headerFrame.Headers {
		if strings.HasPrefix(h, ":method") {
			method = strings.Split(h, ": ")[1]
		}
		if strings.HasPrefix(h, ":path") {
			path = strings.Split(h, ": ")[1]
		}
		if strings.HasPrefix(h, "user-agent") {
			userAgent = strings.Split(h, ": ")[1]
		}
		if isKeySet && strings.HasPrefix(h, key) {
			isAdmin = true
		}
	}

	resp := types.Response{
		IP:          conn.RemoteAddr().String(),
		HTTPVersion: "h2",
		Path:        path,
		Method:      method,
		UserAgent:   userAgent,
		Http2: &types.Http2Details{
			SendFrames:            frames,
			AkamaiFingerprint:     trackmehttp.GetAkamaiFingerprint(frames),
			AkamaiFingerprintHash: utils.GetMD5Hash(trackmehttp.GetAkamaiFingerprint(frames)),
		},
		TLS: tlsFingerprint,
	}

	var res []byte
	var ctype = "text/plain"
	if method != "OPTIONS" {
		res, ctype = Router(path, resp, srv)
	} else {
		isAdmin = true
	}

	// Prepare HEADERS
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	encoder.WriteField(hpack.HeaderField{Name: "server", Value: "TrackMe.peet.ws"})
	encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(res))})
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})
	encoder.WriteField(hpack.HeaderField{Name: "alt-svc", Value: "h3=\":443\"; ma=86400"})
	if isAdmin {
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: "*"})
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-methods", Value: "*"})
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-headers", Value: "*"})
	}

	// Write HEADERS frame
	err = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: headerFrame.Stream, BlockFragment: hbuf.Bytes(), EndHeaders: true})
	if err != nil {
		log.Println("could not write headers: ", err)
		return
	}

	chunks := utils.SplitBytesIntoChunks(res, 1024)
	for _, c := range chunks {
		fr.WriteData(headerFrame.Stream, false, c)
	}
	fr.WriteData(headerFrame.Stream, true, []byte{})
	fr.WriteGoAway(headerFrame.Stream, http2.ErrCodeNo, []byte{})

	time.Sleep(time.Millisecond * 500)
	conn.Close()
}

// HandleHTTP3 handles HTTP/3 requests and returns a simple "Hello, World!" response
func (srv *Server) HandleHTTP3() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if h3w, ok := w.(*http3.ResponseWriter); ok {
			h3c := h3w.Connection()
			h3state := h3c.ConnectionState()

			h3c.Settings()

			// Safely extract connection state and settings
			var used0RTT, supportsDatagrams, supportsStreamResetPartialDelivery bool
			var version uint32
			var gso bool
			var settings types.Http3Settings

			used0RTT = h3state.Used0RTT
			supportsDatagrams = h3state.SupportsDatagrams
			supportsStreamResetPartialDelivery = h3state.SupportsStreamResetPartialDelivery
			version = uint32(h3state.Version)
			gso = h3state.GSO
			if h3c != nil && h3c.Settings() != nil {
				settings = types.Http3Settings(*h3c.Settings())
			}

			resp := types.Response{
				IP:          r.RemoteAddr,
				HTTPVersion: "h3",
				Path:        r.URL.Path,
				Method:      r.Method,
				UserAgent:   r.Header.Get("User-Agent"),
				Http3: &types.Http3Details{
					Information:                        "HTTP/3 support is work-in-progress. Use https://fp.impersonate.pro/api/http3 in the meantime.",
					Used0RTT:                           used0RTT,
					SupportsDatagrams:                  supportsDatagrams,
					SupportsStreamResetPartialDelivery: supportsStreamResetPartialDelivery,
					Version:                            version,
					GSO:                                gso,
					Settings:                           settings,
				},
			}

			res, ctype := Router(r.URL.Path, resp, srv)

			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Server", "TrackMe")
			w.Write([]byte(res))
		}
	})

	return mux
}
