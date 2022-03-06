package main

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var debug = true

func readHTTP2Frames(f *http2.Framer, c chan ParsedFrame) {
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return
			}
			log.Println("Error reading frame", err)
			return
		}

		if debug {
			log.Println(frame)
		}

		p := ParsedFrame{}
		p.Type = frame.Header().Type.String()
		p.Stream = frame.Header().StreamID
		p.Length = frame.Header().Length

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			// SETTINGS
			// We parse the settings

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
			// HEADER
			// We need to parse the headers

			d := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			d.SetEmitEnabled(true)
			h2Headers, err := d.DecodeFull(frame.HeaderBlockFragment())
			if err != nil {
				log.Println("Error decoding headers", err)
				return
			}

			for _, h := range h2Headers {
				if debug {
					log.Println(h)
				}
				h := fmt.Sprintf("%q: %q", h.Name, h.Value)
				h = strings.Trim(h, "\"")
				h = strings.Replace(h, "\": \"", ": ", -1)
				p.Headers = append(p.Headers, h)

			}
		case *http2.DataFrame:
			// DATA
			// just append the data

			p.Payload = frame.Data()

		case *http2.WindowUpdateFrame:
			// WINDOW_UPDATE
			// Add the increment to the payload

			p.Increment = frame.Increment
		case *http2.PriorityFrame:
			// PRIORITY
			// We need this for the akamai fingerprinting

			// I really dont know why we need +1 here, but its one less than the actual value
			p.Weight = int(frame.PriorityParam.Weight + 1)
			p.DependsOn = int(frame.PriorityParam.StreamDep)
			if frame.PriorityParam.Exclusive {
				p.Exclusive = 1
			}
		}

		c <- p
	}
}
