package main

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func staticFile(file string) func(Response, url.Values) ([]byte, string) {
	return func(Response, url.Values) ([]byte, string) {
		b, _ := ReadFile(file)
		return b, "text/html"
	}
}

func apiAll(res Response, _ url.Values) ([]byte, string) {
	return []byte(res.ToJson()), "application/json"
}

func apiTLS(res Response, _ url.Values) ([]byte, string) {
	return []byte(Response{
		TLS: res.TLS,
	}.ToJson()), "application/json"
}

func apiClean(res Response, _ url.Values) ([]byte, string) {
	akamai := "-"
	hash := "-"
	if res.HTTPVersion == "h2" {
		akamai = res.Http2.AkamaiFingerprint
		hash = GetMD5Hash(res.Http2.AkamaiFingerprint)
	}
	return []byte(SmallResponse{
		JA3:           res.TLS.JA3,
		JA3Hash:       res.TLS.JA3Hash,
		Akamai:        akamai,
		AkamaiHash:    hash,
		PeetPrint:     res.TLS.PeetPrint,
		PeetPrintHash: res.TLS.PeetPrintHash,
	}.ToJson()), "application/json"
}

func apiRequestCount(_ Response, _ url.Values) ([]byte, string) {
	if !connectedToDB {
		return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
	}
	return []byte(fmt.Sprintf(`{"total_requests": %v}`, GetTotalRequestCount())), "application/json"
}

func apiSearchJA3(_ Response, u url.Values) ([]byte, string) {
	if !connectedToDB {
		return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
	}
	by := getParam("by", u)
	if by == "" {
		return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
	}
	res := GetByJa3(by)
	j, _ := json.MarshalIndent(res, "", "\t")
	return j, "application/json"
}

func apiSearchH2(_ Response, u url.Values) ([]byte, string) {
	if !connectedToDB {
		return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
	}
	by := getParam("by", u)
	if by == "" {
		return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
	}
	res := GetByH2(by)
	j, _ := json.MarshalIndent(res, "", "\t")
	return j, "application/json"
}

func apiSearchPeetPrint(_ Response, u url.Values) ([]byte, string) {
	if !connectedToDB {
		return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
	}
	by := getParam("by", u)
	if by == "" {
		return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
	}
	res := GetByPeetPrint(by)
	j, _ := json.MarshalIndent(res, "", "\t")
	return j, "application/json"
}

func apiSearchUserAgent(_ Response, u url.Values) ([]byte, string) {
	if !connectedToDB {
		return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
	}
	by := getParam("by", u)
	if by == "" {
		return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
	}
	res := GetByUserAgent(by)
	j, _ := json.MarshalIndent(res, "", "\t")
	return j, "application/json"
}

func getAllPaths() map[string]func(Response, url.Values) ([]byte, string) {
	return map[string]func(Response, url.Values) ([]byte, string){
		"/":                     staticFile("static/index.html"),
		"/explore":              staticFile("static/explore.html"),
		"/api/all":              apiAll,
		"/api/tls":              apiTLS,
		"/api/clean":            apiClean,
		"/api/request-count":    apiRequestCount,
		"/api/search-ja3":       apiSearchJA3,
		"/api/search-h2":        apiSearchH2,
		"/api/search-peetprint": apiSearchPeetPrint,
		"/api/search-useragent": apiSearchUserAgent,
	}
}
