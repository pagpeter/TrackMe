package main

import (
	"encoding/json"
	"fmt"
)

type TLSCollectorOutput struct {
	Ciphers    []string      `json:"ciphers"`
	Extensions []interface{} `json:"extensions"`
	PeetPrint  string        `json:"peetPrint"`
}
type HTTPCollectorOutput struct {
	Fingerprint string        `json:"fingerprint"`
	Frames      []ParsedFrame `json:"frames"`
}
type CollectorOutput struct {
	Received interface{}         `json:"jsFingerprint"`
	HTTP     HTTPCollectorOutput `json:"http"`
	TLS      TLSCollectorOutput  `json:"tls"`
	Time     int64               `json:"time"`
}

func HandleCollectedData(r Response, d string) {
	if r.Http2 == nil {
		return
	}
	var out CollectorOutput
	var recv interface{}
	json.Unmarshal([]byte(d), &recv)
	out.Received = recv
	out.TLS = TLSCollectorOutput{
		Ciphers:    r.TLS.Ciphers,
		Extensions: r.TLS.Extensions,
		PeetPrint:  r.TLS.PeetPrint,
	}
	out.HTTP = HTTPCollectorOutput{
		Fingerprint: r.Http2.AkamaiFingerprint,
		Frames:      r.Http2.SendFrames,
	}
	out.Time = getTime()
	j, _ := json.MarshalIndent(out, "", "\t")
	fmt.Println(string(j))
}
