package main

import "log"

// returns bytes and content type that should be sent to the client
func Router(path string, res Response) ([]byte, string) {
	log.Println(res.IP, "-", res.HTTPVersion, res.Method, res.Path, res.TLS.JA3Hash)
	if c.LogToDB && res.Path != "/favicon.ico" {
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
