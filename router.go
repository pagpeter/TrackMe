package main

// returns bytes and content type that should be sent to the client
func Router(path string, res Response) ([]byte, string) {
	switch path {
	case "/":
		return ReadFile("static/index.html"), "text/html"
	case "/api/all":
		return []byte(res.ToJson()), "application/json"
	case "/api/tls":
		return []byte(Response{
			TLS: res.TLS,
		}.ToJson()), "application/json"
	case "/api/clean":
		akamai := "-"
		if res.HTTPVersion == "h2" {
			akamai = res.Http2.AkamaiFingerprint
		}
		return []byte(SmallResponse{
			JA3:     res.TLS.JA3,
			JA3Hash: res.TLS.JA3Hash,
			Akamai:  akamai,
		}.ToJson()), "application/json"
	}
	return ReadFile("static/index.html"), "text/html"
}
