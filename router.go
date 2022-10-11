package main

import (
	"encoding/json"
	"fmt"
	"net/url"
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

	byParam := ""
	u, _ := url.Parse("https://tls.peet.ws" + path)
	m, _ := url.ParseQuery(u.RawQuery)
	if val, ok := m["by"]; ok {
		if len(val) != 0 {
			byParam = val[0]
		}
	}

	// Router
	switch u.Path {
	case "/":
		b, _ := ReadFile("static/index.html")
		return b, "text/html"
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
	case "/api/request-count":
		if !connectedToDB {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		return []byte(fmt.Sprintf(`{"total_requests": %v}`, GetTotalRequestCount())), "application/json"

	case "/api/search-ja3":
		if !connectedToDB {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		if byParam == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByJa3(byParam)
		j, _ := json.MarshalIndent(res, "    ", "")
		return []byte(j), "application/json"
	case "/api/search-h2":
		if !connectedToDB {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		if byParam == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByH2(byParam)
		j, _ := json.MarshalIndent(res, "    ", "")
		return []byte(j), "application/json"
	case "/api/search-peetprint":
		if !connectedToDB {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		if byParam == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByPeetPrint(byParam)
		j, _ := json.MarshalIndent(res, "    ", "")
		return []byte(j), "application/json"
	}

	b, _ := ReadFile("static/404.html")
	return b, "text/html"
}
