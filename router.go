package main

// returns bytes that should be sent to the client
func Router(path string, res Response) []byte {
	switch path {
	case "/":
		return ReadFile("static/index.html")
	case "/api/all":
		return []byte(res.ToJson())
	case "/api/tls":
		return []byte(res.ToJson())
	}
	return ReadFile("static/index.html")
}
