package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	tls "github.com/wwhtrbbtt/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func parseHTTP1(request []byte) Response {
	// Split the request into lines
	lines := strings.Split(string(request), "\r\n")

	// Split the first line into the method, path and http version
	firstLine := strings.Split(lines[0], " ")

	// Split the headers into an array
	var headers []string
	for _, line := range lines {
		if strings.Contains(line, ":") {
			headers = append(headers, line)
		}
	}

	if len(firstLine) != 3 {
		return Response{
			HTTPVersion: "--",
			Method:      "--",
			path:        "--",
		}
	}
	return Response{
		HTTPVersion: firstLine[2],
		path:        firstLine[1],
		Method:      firstLine[0],
		Http1: &Http1Details{
			Headers: headers,
		},
	}
}

func parseHTTP2(f *http2.Framer, c chan ParsedFrame) {
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			r := "ERROR_CLOSE"
			if strings.HasSuffix(err.Error(), "unknown certificate") {
				r = "ERROR"
			}
			log.Println("Error reading frame", err, r)
			c <- ParsedFrame{Type: r}
			return
		}

		p := ParsedFrame{}
		p.Type = frame.Header().Type.String()
		p.Stream = frame.Header().StreamID
		p.Length = frame.Header().Length
		p.Flags = GetAllFlags(frame)

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			p.Settings = []string{}
			frame.ForeachSetting(func(s http2.Setting) error {
				setting := fmt.Sprintf("%q", s)
				setting = strings.Replace(setting, "\"", "", -1)
				setting = strings.Replace(setting, "[", "", -1)
				setting = strings.Replace(setting, "]", "", -1)

				p.Settings = append(p.Settings, setting)
				return nil
			})
		case *http2.HeadersFrame:
			d := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			d.SetEmitEnabled(true)
			h2Headers, err := d.DecodeFull(frame.HeaderBlockFragment())
			if err != nil {
				log.Println("Error decoding headers", err)
				return
			}

			for _, h := range h2Headers {
				h := fmt.Sprintf("%q: %q", h.Name, h.Value)
				h = strings.Trim(h, "\"")
				h = strings.Replace(h, "\": \"", ": ", -1)
				p.Headers = append(p.Headers, h)
			}
			if frame.HasPriority() {
				prio := Priority{}
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

			prio := Priority{}
			p.Priority = &prio
			// 6.3: Weight: An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256
			p.Priority.Weight = int(frame.PriorityParam.Weight) + 1
			p.Priority.DependsOn = int(frame.PriorityParam.StreamDep)
			if frame.PriorityParam.Exclusive {
				p.Priority.Exclusive = 1
			}
		}

		c <- p
	}
}

func HandleTLSConnection(conn net.Conn) bool {
	// Read the first line of the request
	// We only read the first line to determine if the connection is HTTP1 or HTTP2
	// If we know that it isnt HTTP2, we can read the rest of the request and then start processing it
	// If we know that it is HTTP2, we start the HTTP2 handler

	l := len([]byte(HTTP2_PREAMBLE))
	request := make([]byte, l)

	_, err := conn.Read(request)
	if err != nil {
		log.Println("Error reading request", err)
		if strings.HasSuffix(err.Error(), "unknown certificate") && local {
			log.Println("Local error (probably developement) - not closing conn")
			return true
		}
		return false
	}

	hs := conn.(*tls.Conn).ClientHello

	parsedClientHello := ParseClientHello(hs)
	JA3Data := CalculateJA3(parsedClientHello)
	peetfp, peetfp_hash := CalculatePeetPrint(parsedClientHello, JA3Data)
	tlsDetails := TLSDetails{
		Ciphers:          JA3Data.ReadableCiphers,
		Extensions:       parsedClientHello.Extensions,
		RecordVersion:    JA3Data.Version,
		NegotiatedVesion: fmt.Sprintf("%v", conn.(*tls.Conn).ConnectionState().Version),
		JA3:              JA3Data.JA3,
		JA3Hash:          JA3Data.JA3Hash,
		PeetPrint:        peetfp,
		PeetPrintHash:    peetfp_hash,
		SessionID:        parsedClientHello.SessionID,
		ClientRandom:     parsedClientHello.ClientRandom,
	}

	// Check if the first line is HTTP/2
	if string(request) == HTTP2_PREAMBLE {
		handleHTTP2(conn, tlsDetails)
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
		details.TLS = tlsDetails
		respondToHTTP1(conn, details)
	}
	return true
}

func respondToHTTP1(conn net.Conn, resp Response) {
	// log.Println("Request:", resp.ToJson())
	// log.Println(len(resp.ToJson()))

	res1, ctype := Router(resp.path, resp)

	res := "HTTP/1.1 200 OK\r\n"
	res += "Content-Length: " + fmt.Sprintf("%v\r\n", len(res1))
	res += "Content-Type: " + ctype + "; charset=utf-8\r\n"
	res += "Server: TrackMe\r\n"
	res += "\r\n"
	res += string(res1)
	res += "\r\n\r\n"

	conn.Write([]byte(res))
	conn.Close()
}

// https://stackoverflow.com/questions/52002623/golang-tcp-server-how-to-write-http2-data
func handleHTTP2(conn net.Conn, tls_fingerprint TLSDetails) {
	// make a new framer to encode/decode frames
	fr := http2.NewFramer(conn, conn)
	c := make(chan ParsedFrame)
	var frames []ParsedFrame

	// Same settings that google uses
	fr.WriteSettings(
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

	var frame ParsedFrame
	go parseHTTP2(fr, c)

	for {
		frame = <-c
		if frame.Type == "ERROR_CLOSE" {
			conn.Close()
			return
		} else if frame.Type == "ERROR" {
			return
		}
		// log.Println(frame)
		frames = append(frames, frame)
		if frame.Type == "HEADERS" {
			break
		}
	}

	// get method and path from the first headers frame
	var path string
	var method string

	for _, h := range frame.Headers {
		if strings.HasPrefix(h, ":method") {
			method = strings.Split(h, ": ")[1]
		}
		if strings.HasPrefix(h, ":path") {
			path = strings.Split(h, ": ")[1]
		}
	}

	resp := Response{
		IP:          conn.RemoteAddr().String(),
		HTTPVersion: "h2",
		path:        path,
		Method:      method,
		Http2: &Http2Details{
			SendFrames:            frames,
			AkamaiFingerprint:     GetAkamaiFingerprint(frames),
			AkamaiFingerprintHash: GetMD5Hash(GetAkamaiFingerprint(frames)),
		},
		TLS: tls_fingerprint,
	}

	res, ctype := Router(path, resp)

	// Prepare HEADERS
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	encoder.WriteField(hpack.HeaderField{Name: "server", Value: "TrackMe.peet.ws"})
	encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(res))})
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})

	// Write HEADERS frame
	err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.Stream, BlockFragment: hbuf.Bytes(), EndHeaders: true})
	if err != nil {
		log.Println("could not write headers: ", err)
		return
	}

	chunks := splitBytesIntoChunks(res, 1024)
	for _, c := range chunks {
		fr.WriteData(frame.Stream, false, c)
	}
	fr.WriteData(frame.Stream, true, []byte{})
	fr.WriteGoAway(frame.Stream, http2.ErrCodeNo, []byte{})

	time.Sleep(time.Millisecond * 500)
	conn.Close()
}
