package main

import (
	"fmt"
	"time"
)

func Log(msg string) {
	t := time.Now()
	formatted := t.Format("2006-02-01 15:04:05")
	fmt.Printf("[%v] %v\n", formatted, msg)
}

// returns bytes and content type that should be sent to the client
func Router(path string, res Response) ([]byte, string) {
	// res.Donate = "Please consider donating to keep this API running."
	Log(fmt.Sprintf("%v %v %v %v %v", res.IP, res.Method, res.HTTPVersion, res.path, res.TLS.JA3Hash))

	if GetUserAgent(res) == "" {
		return []byte("no useragent"), "text/html"
	}
	if c.LogToDB && res.path != "/favicon.ico" {
		SaveRequest(res)
	}
	switch path {
	case "/api/all":
		return []byte(res.ToJson()), "application/json"
	case "/api/tls":
		return []byte(Response{
			TLS: res.TLS,
		}.ToJson()), "application/json"
	case "/api/clean":
		akamai := "-"
		hash := "-"
		if res.HTTPVersion == "h2" {
			akamai = res.Http2.AkamaiFingerprint
			hash = GetMD5Hash(res.Http2.AkamaiFingerprint)
		}
		return []byte(SmallResponse{
			JA3:        res.TLS.JA3,
			JA3Hash:    res.TLS.JA3Hash,
			Akamai:     akamai,
			AkamaiHash: hash,
		}.ToJson()), "application/json"
	}
	b, _ := ReadFile("static/index.html")
	return b, "text/html"
}
