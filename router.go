package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

func Log(msg string) {
	t := time.Now()
	formatted := t.Format("2006-01-02 15:04:05")
	fmt.Printf("[%v] %v\n", formatted, msg)
}

func cleanIP(ip string) string {
	return strings.Replace(strings.Replace(ip, "]", "", -1), "[", "", -1)
}

// Router returns bytes and content type that should be sent to the client
func Router(path string, res Response) ([]byte, string) {
	res.TCPIP = TCPFingerprints[cleanIP(res.IP)]
	// res.Donate = "Please consider donating to keep this API running."
	Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.path, res.TLS.JA3Hash))
	// if GetUserAgent(res) == "" {
	//	return []byte("{\"error\": \"No user-agent\"}"), "text/html"
	// }
	if c.LogToDB && res.path != "/favicon.ico" {
		SaveRequest(res)
	}

	u, _ := url.Parse("https://tls.peet.ws" + path)
	m, _ := url.ParseQuery(u.RawQuery)

	paths := getAllPaths()
	if val, ok := paths[u.Path]; ok {
		return val(res, m)
	}
	// 404
	b, _ := ReadFile("static/404.html")
	return b, "text/html"
}
